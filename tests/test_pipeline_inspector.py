"""Unit tests for Package 11: LLM-Assisted Pipeline Inspector.

Verifies:
1. Stage details match actual pipeline data (telemetry, inputs, outputs, status, module, function).
2. Existing Gemini insight is reused across stages without duplication.
3. Zero additional Gemini API requests occur when expanding or inspecting stages.
4. Missing Gemini insight is handled gracefully with deterministic explanations.
5. Unsupported claims remain visibly flagged with evidence limitation warnings.
6. No pipeline, incident, or audit state mutations occur during inspection.
7. UI works seamlessly without a Gemini API key configured.
"""

import unittest
import os
import shutil
import tempfile
from unittest.mock import MagicMock, patch

from ui.services.soc_service import SOCService
from ui.views.pipeline_flow_view import (
    render_pipeline_flow_view,
    render_pipeline_flow_component,
    get_stage_gemini_insight,
    get_stage_deterministic_explanation,
    get_alert_gemini_insight,
    get_stage_status_badge,
)
from modules.gemini_analyzer import GeminiAlertAnalyzer, AnalystInsight


class MockColumn:
    def __init__(self, parent):
        self.parent = parent

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def markdown(self, body, unsafe_allow_html=False):
        self.parent.markdown(body, unsafe_allow_html=unsafe_allow_html)

    def selectbox(self, label, options, index=0, **kwargs):
        return self.parent.selectbox(label, options, index=index, **kwargs)

    def expander(self, label, **kwargs):
        return self.parent.expander(label, **kwargs)

    def json(self, data):
        self.parent.json(data)


class MockStreamlitModule:
    """Mock Streamlit module capturing calls for headless verification."""

    def __init__(self):
        self.markdown_calls = []
        self.json_calls = []
        self.expander_calls = []
        self.session_state = {}

    def markdown(self, body, unsafe_allow_html=False):
        self.markdown_calls.append(body)

    def json(self, data):
        self.json_calls.append(data)

    def columns(self, spec):
        count = spec if isinstance(spec, int) else len(spec)
        return [MockColumn(self) for _ in range(count)]

    def selectbox(self, label, options, index=0, **kwargs):
        return options[index] if options else None

    def expander(self, label, **kwargs):
        self.expander_calls.append(label)
        return MockColumn(self)


class TestPipelineInspector(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="pipeline_inspector_test_")
        shutil.copytree("config", os.path.join(self.temp_dir, "config"))
        shutil.copytree("data", os.path.join(self.temp_dir, "data"))
        inc_file = os.path.join(self.temp_dir, "data", "incidents.json")
        if os.path.exists(inc_file):
            os.remove(inc_file)

        self.service = SOCService(base_dir=self.temp_dir)

        # Grounded synthetic insight
        self.sample_insight_data = {
            "executive_summary": "High-volume SSH brute force attack detected against enterprise VPN gateway from an external IP.",
            "alert_interpretation": "Observed 50 consecutive failed logins within 60s from 198.51.100.45 (alert.description). Analytically, this indicates automated credential stuffing rather than user error.",
            "why_suspicious": "The request frequency exceeds normal human login thresholds and matches known scanner behavioral signatures.",
            "relevant_risk_indicators": [
                "[alert.source_ip=198.51.100.45] Source IP flagged in local simulation TI DB (enrichment.threat_intel_match=true)",
                "[alert.description] 50 consecutive failed SSH/VPN logins in 60 seconds",
                "[alert.severity=HIGH] Alert classified as HIGH severity by event source"
            ],
            "recommended_investigation_steps": [
                "Verify whether any authentication attempts from 198.51.100.45 succeeded.",
                "Review VPN authentication logs for other targeted usernames.",
                "Note: TI match is local simulation only — seek external validation."
            ],
            "playbook_justification": "PB-CRIT-001 is triggered because the combined risk score (95) exceeds the critical threshold (>=80), appropriately queueing analyst escalation and host isolation.",
            "missing_information": [
                "Full NetFlow/PCAP telemetry for destination port 22/443 traffic.",
                "Multi-factor authentication (MFA) challenge logs for user tina.adams."
            ],
            "confidence_explanation": "HIGH confidence: threat-intel match from local simulation DB (enrichment.threat_intel_match=true), combined with 50 consecutive authentication failures."
        }

        alert_ident = self.service.get_alert_cache_identity("01_failed_logins_suspicious_ip.json")
        self.sample_gemini_result = {
            "status": "SUCCESS",
            "data": self.sample_insight_data,
            "model": "gemini-2.5-flash",
            "content_hash": alert_ident["content_hash"] if alert_ident else "",
            "cached": True,
            "timestamp": "2026-11-16T10:00:00Z",
            "has_unsupported_claims": False,
            "validation_warnings": []
        }

    def tearDown(self):
        if hasattr(self.service.pipeline, "audit_logger"):
            self.service.pipeline.audit_logger.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_stage_details_match_actual_pipeline_data(self):
        """Stage details must strictly match the actual pipeline data from the alert."""
        flow = self.service.get_pipeline_flow("01_failed_logins_suspicious_ip.json")

        self.assertEqual(flow["alert_id"], "ALT-2026-001")
        self.assertEqual(flow["risk_score"], 95)
        self.assertEqual(flow["risk_classification"], "CRITICAL")
        self.assertEqual(len(flow["stages"]), 9)

        # Stage 1: Ingestion
        s1 = flow["stages"][0]
        self.assertEqual(s1["stage_id"], "01_INGESTION")
        self.assertEqual(s1["details"]["alert_id"], "ALT-2026-001")
        self.assertEqual(s1["details"]["event_type"], "Failed Authentication Spike")
        self.assertEqual(s1["details"]["source_ip"], "198.51.100.45")

        # Stage 2: Validation
        s2 = flow["stages"][1]
        self.assertEqual(s2["stage_id"], "02_VALIDATION")
        self.assertIn(s2["status"], ["PREVIEW_EVALUATED", "COMPLETED"])
        self.assertEqual(s2["details"]["validation_issues_count"], 0)

        # Stage 3: Enrichment
        s3 = flow["stages"][2]
        self.assertEqual(s3["stage_id"], "03_ENRICHMENT")
        self.assertTrue(s3["details"]["threat_intel_match"])
        self.assertEqual(s3["details"]["source_ip"], "198.51.100.45")

        # Stage 4: Risk Scoring
        s4 = flow["stages"][3]
        self.assertEqual(s4["stage_id"], "04_RISK_SCORING")
        self.assertEqual(s4["details"]["total_risk_score"], 95)
        self.assertEqual(s4["details"]["risk_classification"], "CRITICAL")

        # Stage 5: Playbook Routing
        s5 = flow["stages"][4]
        self.assertEqual(s5["stage_id"], "05_PLAYBOOK_ROUTING")
        self.assertEqual(s5["details"]["playbook_id"], "PB-CRIT-001")

    def test_existing_gemini_insight_is_reused_across_stages(self):
        """Existing Gemini insight is correctly decomposed and mapped to all 9 stages."""
        # Test mapping for each stage
        for stage_id in [
            "01_INGESTION", "02_VALIDATION", "03_ENRICHMENT", "04_RISK_SCORING",
            "05_PLAYBOOK_ROUTING", "06_APPROVAL_GATE", "07_RESPONSE_SIMULATION",
            "08_INCIDENT_MANAGEMENT", "09_AUDIT_EXPORT"
        ]:
            insight = get_stage_gemini_insight(stage_id, self.sample_gemini_result)
            self.assertIsNotNone(insight, f"Stage {stage_id} should have mapped AI insight")
            self.assertIn("title", insight)
            self.assertIn("content", insight)
            self.assertIn("focus", insight)
            self.assertTrue(len(insight["content"]) > 0)

        # Specific content verifications
        s1 = get_stage_gemini_insight("01_INGESTION", self.sample_gemini_result)
        self.assertIn("198.51.100.45", s1["content"])

        s3 = get_stage_gemini_insight("03_ENRICHMENT", self.sample_gemini_result)
        self.assertIn("Verified Risk Indicators", s3["content"])

        s4 = get_stage_gemini_insight("04_RISK_SCORING", self.sample_gemini_result)
        self.assertIn("exceeds normal human login thresholds", s4["content"])

        s5 = get_stage_gemini_insight("05_PLAYBOOK_ROUTING", self.sample_gemini_result)
        self.assertIn("PB-CRIT-001", s5["content"])

        s6 = get_stage_gemini_insight("06_APPROVAL_GATE", self.sample_gemini_result)
        self.assertIn("Recommended Investigation Steps", s6["content"])

        s8 = get_stage_gemini_insight("08_INCIDENT_MANAGEMENT", self.sample_gemini_result)
        self.assertIn("Confidence Assessment", s8["content"])

    def test_no_additional_gemini_request_occurs_when_expanding_stages(self):
        """Expanding or inspecting stages must make ZERO additional Gemini API calls."""
        mock_analyzer = MagicMock(spec=GeminiAlertAnalyzer)
        mock_analyzer.is_configured = True
        mock_analyzer.model = "gemini-2.5-flash"
        mock_analyzer.api_key = "test_key"
        # If analyze_alert is called, we want to know
        mock_analyzer.analyze_alert.side_effect = AssertionError("analyze_alert was called unexpectedly!")

        svc = SOCService(base_dir=self.temp_dir, gemini_analyzer=mock_analyzer)

        # Pre-seed the cache with existing result
        svc._gemini_cache["ALT-2026-001:gemini-2.5-flash"] = self.sample_gemini_result

        mock_st = MockStreamlitModule()
        mock_st.session_state["pipeline_flow_target_select"] = "ALT-2026-001 — Failed Authentication Spike [AWAITING TRIAGE]"

        # Render full view
        render_pipeline_flow_view(svc, st_module=mock_st)

        # Render component
        render_pipeline_flow_component(svc, alert_id_or_file="01_failed_logins_suspicious_ip.json", st_module=mock_st)

        # Assert analyze_alert was never called
        mock_analyzer.analyze_alert.assert_not_called()

        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("AI Advisory Interpretation", all_md)
        self.assertIn("CACHED", all_md)

    def test_missing_insight_is_handled_gracefully(self):
        """When no Gemini insight exists, stage expanders render deterministic logic cleanly."""
        mock_st = MockStreamlitModule()

        # Service with no cached Gemini insights
        render_pipeline_flow_component(
            self.service,
            alert_id_or_file="01_failed_logins_suspicious_ip.json",
            st_module=mock_st
        )

        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("Deterministic Stage Logic", all_md)
        self.assertIn("AI Interpretation Not Active", all_md)
        self.assertNotIn("AI Advisory Interpretation", all_md)

    def test_unsupported_claims_remain_visibly_flagged(self):
        """When has_unsupported_claims is True, an evidence limitation banner is shown."""
        flagged_result = dict(self.sample_gemini_result)
        flagged_result["has_unsupported_claims"] = True
        flagged_result["validation_warnings"] = [
            "Numerical percentage confidence detected in confidence_explanation ('95%').",
            "Unsupported IP in relevant_risk_indicators: '1.2.3.4'."
        ]

        self.service._gemini_cache["ALT-2026-001:gemini-2.5-flash"] = flagged_result

        mock_st = MockStreamlitModule()
        render_pipeline_flow_component(
            self.service,
            alert_id_or_file="01_failed_logins_suspicious_ip.json",
            st_module=mock_st
        )

        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("Evidence Limitation", all_md)
        self.assertIn("95%", all_md)
        self.assertIn("AI Advisory Interpretation", all_md)

    def test_no_pipeline_or_incident_state_mutations(self):
        """Inspecting pipeline flow with or without Gemini must never mutate state."""
        baseline_incidents = len(self.service.list_incidents())
        baseline_history = len(self.service.get_audit_history())
        baseline_traces = len(self.service.get_execution_traces())

        # Inspect multiple times
        flow1 = self.service.get_pipeline_flow("01_failed_logins_suspicious_ip.json")
        flow2 = self.service.get_pipeline_flow(None)

        mock_st = MockStreamlitModule()
        render_pipeline_flow_view(self.service, st_module=mock_st)
        render_pipeline_flow_component(self.service, alert_id_or_file="01_failed_logins_suspicious_ip.json", st_module=mock_st)

        # State must remain 100% identical
        self.assertEqual(len(self.service.list_incidents()), baseline_incidents)
        self.assertEqual(len(self.service.get_audit_history()), baseline_history)
        self.assertEqual(len(self.service.get_execution_traces()), baseline_traces)

    def test_ui_works_without_gemini_api_key(self):
        """When Gemini API key is not configured, UI renders successfully with informative notes."""
        no_key_analyzer = GeminiAlertAnalyzer(api_key="")
        svc = SOCService(base_dir=self.temp_dir, gemini_analyzer=no_key_analyzer)

        self.assertFalse(svc.gemini_analyzer.is_configured)

        # 1. Blueprint mode (default in flow view)
        mock_st = MockStreamlitModule()
        render_pipeline_flow_view(svc, st_module=mock_st)

        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("Pipeline Flow Visualization & Architecture Map", all_md)
        self.assertIn("Architecture Specification", all_md)

        # 2. Specific alert inspection mode without Gemini
        mock_st2 = MockStreamlitModule()
        render_pipeline_flow_component(
            svc,
            alert_id_or_file="01_failed_logins_suspicious_ip.json",
            st_module=mock_st2
        )
        all_md2 = " ".join(mock_st2.markdown_calls)
        self.assertIn("Deterministic Stage Logic", all_md2)
        self.assertIn("Gemini API key is not configured", all_md2)

        # Ensure no lines have 4+ spaces across both renders
        for mock_mod in (mock_st, mock_st2):
            for call in mock_mod.markdown_calls:
                for line in call.splitlines():
                    self.assertFalse(line.startswith("    "), f"Indented line in markdown: {line[:40]}")

    def test_stage_deterministic_explanations_exist_for_all_9_stages(self):
        """Verify deterministic explanations are present for all 9 stages."""
        for stage_id in [
            "01_INGESTION", "02_VALIDATION", "03_ENRICHMENT", "04_RISK_SCORING",
            "05_PLAYBOOK_ROUTING", "06_APPROVAL_GATE", "07_RESPONSE_SIMULATION",
            "08_INCIDENT_MANAGEMENT", "09_AUDIT_EXPORT"
        ]:
            exp = get_stage_deterministic_explanation(stage_id, {})
            self.assertTrue(len(exp) > 20, f"Explanation for {stage_id} too short")

    def test_get_alert_gemini_insight_lookup(self):
        """Test cache and session state lookups in get_alert_gemini_insight."""
        # 1. None if no target
        self.assertIsNone(get_alert_gemini_insight(self.service, None))

        # 2. Lookup in service cache
        self.service._gemini_cache["ALT-2026-001:gemini-2.5-flash"] = self.sample_gemini_result
        res = get_alert_gemini_insight(self.service, "01_failed_logins_suspicious_ip.json")
        self.assertIsNotNone(res)
        self.assertEqual(res["data"]["executive_summary"], self.sample_insight_data["executive_summary"])

        # 3. Lookup in session_state if not in service cache
        self.service._gemini_cache.clear()
        mock_st = MockStreamlitModule()
        mock_st.session_state["gemini_insight_ALT-2026-001"] = self.sample_gemini_result

        res2 = get_alert_gemini_insight(self.service, "01_failed_logins_suspicious_ip.json", st_module=mock_st)
        self.assertIsNotNone(res2)
        self.assertEqual(res2["data"]["executive_summary"], self.sample_insight_data["executive_summary"])

    # -------------------------------------------------------------------------
    # Package 11.1 Remediation Regression Tests
    # -------------------------------------------------------------------------

    def test_cache_invalidation_on_alert_content_change(self):
        """Modifying alert content on disk must invalidate cached Gemini insights."""
        alert_file = os.path.join(self.temp_dir, "data", "alerts", "01_failed_logins_suspicious_ip.json")
        ident_before = self.service.get_alert_cache_identity(alert_file)
        self.assertIsNotNone(ident_before)

        # Populate cache with content_hash
        seeded_insight = dict(self.sample_gemini_result, content_hash=ident_before["content_hash"])
        self.service._gemini_cache[ident_before["cache_key"]] = seeded_insight

        # Pre-seed session state as well
        mock_st = MockStreamlitModule()
        mock_st.session_state[f"gemini_insight_{ident_before['alert_id']}"] = seeded_insight

        # Verify initial hit
        self.assertIsNotNone(self.service.get_gemini_insight_for_pipeline(alert_file))
        self.assertIsNotNone(get_alert_gemini_insight(self.service, alert_file, st_module=mock_st))

        # Modify alert content on disk (same alert_id, changed telemetry)
        import json
        with open(alert_file, "r") as f:
            raw = json.load(f)
        raw["source_ip"] = "203.0.113.99"
        raw["description"] = "Modified alert content for cache invalidation testing"
        with open(alert_file, "w") as f:
            json.dump(raw, f, indent=2)

        ident_after = self.service.get_alert_cache_identity(alert_file)
        self.assertNotEqual(ident_before["content_hash"], ident_after["content_hash"])
        self.assertNotEqual(ident_before["cache_key"], ident_after["cache_key"])

        # Cache accessor must now return None (stale insight invalidated)
        cached_after = self.service.get_gemini_insight_for_pipeline(alert_file)
        self.assertIsNone(cached_after)

        # Session state lookup must also invalidate and purge stale entry
        ui_insight_after = get_alert_gemini_insight(self.service, alert_file, st_module=mock_st)
        self.assertIsNone(ui_insight_after)
        self.assertNotIn(f"gemini_insight_{ident_before['alert_id']}", mock_st.session_state)

    def test_cache_reuse_for_identical_content(self):
        """Identical alert content must reuse cached insights without making API calls."""
        alert_file = os.path.join(self.temp_dir, "data", "alerts", "01_failed_logins_suspicious_ip.json")
        mock_analyzer = MagicMock()
        mock_analyzer.is_configured = True
        mock_analyzer.api_key = "test-api-key"
        mock_analyzer.model = "gemini-2.5-flash"
        mock_analyzer.analyze_alert.return_value = self.sample_gemini_result

        svc = SOCService(base_dir=self.temp_dir, gemini_analyzer=mock_analyzer)

        # First call triggers analyzer
        res1 = svc.analyze_alert_with_gemini(alert_file)
        self.assertEqual(res1["status"], "SUCCESS")
        self.assertEqual(mock_analyzer.analyze_alert.call_count, 1)

        # Second call reuses cache
        res2 = svc.analyze_alert_with_gemini(alert_file)
        self.assertEqual(res2["status"], "SUCCESS")
        self.assertTrue(res2.get("cached", False))
        self.assertEqual(mock_analyzer.analyze_alert.call_count, 1)

        # Pipeline lookup reuses cache without API calls
        p_res = svc.get_gemini_insight_for_pipeline(alert_file)
        self.assertIsNotNone(p_res)
        self.assertEqual(mock_analyzer.analyze_alert.call_count, 1)

    def test_automated_siem_ingestion_not_marked_analyst_confirmed(self):
        """Automated ingestion must display AUTOMATED_POLICY, never Analyst Confirmed."""
        # Process alert directly through pipeline (automated/system ingestion)
        res = self.service.process_alert_by_id("ALT-2026-001", show_trace=False)
        self.assertIsNotNone(res)

        flow = self.service.get_pipeline_flow("01_failed_logins_suspicious_ip.json")
        stage_06 = next(s for s in flow["stages"] if s["stage_id"] == "06_APPROVAL_GATE")

        self.assertEqual(stage_06["status"], "AUTOMATED_POLICY")
        self.assertEqual(stage_06["status_label"], "Automated Processing — Human Approval Not Recorded")
        self.assertNotEqual(stage_06["status"], "CONFIRMED")
        self.assertIn("Automated Policy Execution", stage_06["outputs"]["output"])

    def test_explicit_approval_displays_analyst_confirmed(self):
        """Explicit analyst confirmation through playbook workflow displays Analyst Confirmed."""
        workflow_res = self.service.execute_playbook_workflow(
            alert_id="ALT-2026-001",
            playbook_id="PB-CRIT-001",
            analyst_confirmed=True
        )
        self.assertTrue(workflow_res.get("success"), f"Workflow execution failed: {workflow_res}")

        flow = self.service.get_pipeline_flow("01_failed_logins_suspicious_ip.json")
        stage_06 = next(s for s in flow["stages"] if s["stage_id"] == "06_APPROVAL_GATE")

        self.assertEqual(stage_06["status"], "CONFIRMED")
        self.assertEqual(stage_06["status_label"], "Analyst Confirmed")
        self.assertIn("Confirmed for Controlled Dry-Run Containment", stage_06["outputs"]["output"])
        self.assertEqual(stage_06["details"]["approver"], "ANALYST")

    def test_failed_trace_status_propagates(self):
        """A failed execution trace step must propagate FAILED status to the UI stage."""
        # Process alert to create incident and trace
        self.service.process_alert_by_id("ALT-2026-001", show_trace=False)
        trace = self.service.get_trace_for_alert("ALT-2026-001")
        self.assertIsNotNone(trace)

        # Mutate trace step 06 (Response Simulation) to FAILED
        t06 = next((s for s in trace.steps if s.step_id == "06"), None)
        self.assertIsNotNone(t06)
        t06.status = "FAILED"

        flow = self.service.get_pipeline_flow("01_failed_logins_suspicious_ip.json")
        stage_07 = next(s for s in flow["stages"] if s["stage_id"] == "07_RESPONSE_SIMULATION")
        self.assertEqual(stage_07["status"], "FAILED")
        self.assertEqual(stage_07["status_label"], "Simulation Failed")

    def test_preview_stages_not_completed(self):
        """Untriaged preview stages must report PREVIEW_EVALUATED or PENDING, never COMPLETED."""
        flow = self.service.get_pipeline_flow("01_failed_logins_suspicious_ip.json")
        self.assertFalse(flow["is_triaged"])
        self.assertEqual(flow["target_type"], "NON_MUTATING_PREVIEW")

        for idx, stage in enumerate(flow["stages"]):
            self.assertNotEqual(
                stage["status"],
                "COMPLETED",
                f"Stage {stage['stage_id']} in preview mode reported COMPLETED"
            )
            if idx < 5:
                self.assertIn(stage["status"], ["PREVIEW_EVALUATED", "PREVIEW_WARNINGS"])
            else:
                self.assertEqual(stage["status"], "PENDING")

    def test_system_transparency_node_displayed(self):
        """Stage 07 details must incorporate System Transparency Node (tracer step 07 data)."""
        flow_preview = self.service.get_pipeline_flow("01_failed_logins_suspicious_ip.json")
        s7_preview = next(s for s in flow_preview["stages"] if s["stage_id"] == "07_RESPONSE_SIMULATION")
        self.assertIn("system_transparency_node", s7_preview["details"])
        node_prev = s7_preview["details"]["system_transparency_node"]
        self.assertEqual(node_prev["step_id"], "07")
        self.assertTrue(node_prev["details"]["unimplemented_feature"])

        # Triaged alert includes live tracer step 07
        self.service.process_alert_by_id("ALT-2026-001", show_trace=False)
        flow_triaged = self.service.get_pipeline_flow("01_failed_logins_suspicious_ip.json")
        s7_triaged = next(s for s in flow_triaged["stages"] if s["stage_id"] == "07_RESPONSE_SIMULATION")
        self.assertIn("system_transparency_node", s7_triaged["details"])
        node_triaged = s7_triaged["details"]["system_transparency_node"]
        self.assertEqual(node_triaged["step_id"], "07")
        self.assertEqual(node_triaged["status"], "NOT IMPLEMENTED")

    def test_missing_export_file_reports_unverified(self):
        """When dossier export file is missing from disk, Stage 09 must report EXPORT_UNVERIFIED."""
        res = self.service.process_alert_by_id("ALT-2026-001", show_trace=False)
        inc_id = res["incident_id"]

        dossier_path = os.path.join(self.temp_dir, "reports", f"incident_{inc_id}.json")
        if os.path.exists(dossier_path):
            os.remove(dossier_path)

        flow = self.service.get_pipeline_flow("01_failed_logins_suspicious_ip.json")
        stage_09 = next(s for s in flow["stages"] if s["stage_id"] == "09_AUDIT_EXPORT")
        self.assertEqual(stage_09["status"], "EXPORT_UNVERIFIED")
        self.assertEqual(stage_09["status_label"], "Export Not Verified on Disk")
        self.assertFalse(stage_09["details"]["dossier_verified_on_disk"])

    def test_stage_status_badges_all_valid(self):
        """All stage status codes must render styled HTML badges without exceptions."""
        statuses = [
            "PREVIEW_EVALUATED", "PREVIEW_WARNINGS", "COMPLETED", "COMPLETED_WITH_WARNINGS",
            "SIMULATED_SUCCESS", "CONFIRMED", "AUTOMATED_POLICY", "PROVENANCE_UNKNOWN",
            "EXPORT_UNVERIFIED", "PENDING", "SKIPPED", "FAILED", "ARCHITECTURE_SPEC"
        ]
        for st in statuses:
            badge = get_stage_status_badge(st)
            self.assertTrue(badge.startswith("<span"))
            self.assertIn(st.replace("_", " "), badge)

    # -------------------------------------------------------------------------
    # Package 11.3 Governance & Cache Hardening Regression Tests
    # -------------------------------------------------------------------------

    def test_approval_attribution_negative_and_pending_notes(self):
        """Negative and pending notes must never establish human approval."""
        incident = {
            "incident_id": "INC-TEST-001",
            "original_alert_id": "ALT-2026-001",
            "status": "OPEN",
            "priority": "HIGH",
            "raw_source": "manual_upload",
            "notes": [
                {"actor": "ANALYST_BOB", "note": "Approval rejected due to incomplete IOC validation."},
                {"actor": "ANALYST_ALICE", "note": "Do not approve execution until secondary host is checked."},
                {"actor": "ANALYST_CHARLIE", "note": "Awaiting approval from security lead."},
                {"actor": "ANALYST_DAVE", "note": "Pending approval of containment actions."}
            ],
            "history": []
        }
        raw_alert = {"alert_id": "ALT-2026-001", "event_source": "manual_test"}

        result = self.service._evaluate_approval_attribution("ALT-2026-001", incident, raw_alert)
        self.assertNotEqual(result["status"], "CONFIRMED")
        self.assertNotEqual(result["status_label"], "Analyst Confirmed")
        self.assertEqual(result["status"], "PROVENANCE_UNKNOWN")

    def test_approval_attribution_system_generated_notes_ignored(self):
        """System-generated approval-like notes must never establish human approval."""
        incident = {
            "incident_id": "INC-TEST-002",
            "original_alert_id": "ALT-2026-001",
            "status": "OPEN",
            "priority": "HIGH",
            "raw_source": "siem_feed",
            "notes": [
                {"actor": "SYSTEM", "note": "Playbook execution confirmed by analyst (DRY_RUN_SAFE_MODE)."},
                {"actor": "MOCK_SIEM", "note": "Execution approved by rule engine."}
            ],
            "history": [{"actor": "SYSTEM", "action": "INGESTED"}]
        }
        raw_alert = {"alert_id": "ALT-2026-001", "event_source": "siem_feed"}

        result = self.service._evaluate_approval_attribution("ALT-2026-001", incident, raw_alert)
        self.assertNotEqual(result["status"], "CONFIRMED")
        self.assertEqual(result["status"], "AUTOMATED_POLICY")
        self.assertEqual(result["status_label"], "Automated Processing — Human Approval Not Recorded")

    def test_approval_attribution_positive_human_evidence(self):
        """Explicit positive analyst approval via notes, history or audit establishes confirmation."""
        # 1. Via human note
        inc_note = {
            "incident_id": "INC-TEST-003",
            "original_alert_id": "ALT-2026-001",
            "status": "OPEN",
            "raw_source": "manual",
            "notes": [{"actor": "SEC_ANALYST", "note": "Playbook execution confirmed by analyst (DRY_RUN_SAFE_MODE)."}],
            "history": []
        }
        res_note = self.service._evaluate_approval_attribution("ALT-2026-001", inc_note, {})
        self.assertEqual(res_note["status"], "CONFIRMED")
        self.assertEqual(res_note["details"]["approver"], "SEC_ANALYST")

        # 2. Via structured history action
        inc_hist = {
            "incident_id": "INC-TEST-004",
            "original_alert_id": "ALT-2026-001",
            "status": "OPEN",
            "raw_source": "manual",
            "notes": [],
            "history": [{"actor": "LEAD_ANALYST", "action": "APPROVED", "details": "Approved containment"}]
        }
        res_hist = self.service._evaluate_approval_attribution("ALT-2026-001", inc_hist, {})
        self.assertEqual(res_hist["status"], "CONFIRMED")
        self.assertEqual(res_hist["details"]["approver"], "LEAD_ANALYST")

    def test_gemini_session_cache_invalidates_on_model_change(self):
        """Session-state insight must be invalidated if model name changes."""
        alert_file = os.path.join(self.temp_dir, "data", "alerts", "01_failed_logins_suspicious_ip.json")
        ident = self.service.get_alert_cache_identity(alert_file)
        self.assertIsNotNone(ident)

        # Insight cached with a different model ("gemini-1.5-pro")
        stale_model_insight = dict(self.sample_gemini_result)
        stale_model_insight["content_hash"] = ident["content_hash"]
        stale_model_insight["model"] = "gemini-1.5-pro"

        mock_st = MockStreamlitModule()
        mock_st.session_state[f"gemini_insight_{ident['alert_id']}"] = stale_model_insight

        # Lookup should detect mismatched model (ident['model'] is "gemini-2.5-flash")
        res = get_alert_gemini_insight(self.service, alert_file, st_module=mock_st)
        self.assertIsNone(res)
        self.assertNotIn(f"gemini_insight_{ident['alert_id']}", mock_st.session_state)

        # Insight cached with matching model and hash returns successfully
        valid_insight = dict(self.sample_gemini_result)
        valid_insight["content_hash"] = ident["content_hash"]
        valid_insight["model"] = ident["model"]
        mock_st.session_state[f"gemini_insight_{ident['alert_id']}"] = valid_insight

        res_valid = get_alert_gemini_insight(self.service, alert_file, st_module=mock_st)
        self.assertIsNotNone(res_valid)
        self.assertEqual(res_valid["model"], ident["model"])

    def test_stage_07_system_transparency_notice_rendered(self):
        """Stage 07 expander must render System Transparency Node notice with NOT IMPLEMENTED labels."""
        mock_st = MockStreamlitModule()
        mock_st.session_state["pipeline_flow_target_select"] = "ALT-2026-001 — Failed Authentication Spike [AWAITING TRIAGE]"

        # Render full view
        render_pipeline_flow_view(self.service, st_module=mock_st)
        # Render component
        render_pipeline_flow_component(self.service, alert_id_or_file="01_failed_logins_suspicious_ip.json", st_module=mock_st)

        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("System Transparency Node", all_md)
        self.assertIn("Advanced Integration Guardrails", all_md)
        self.assertIn("SMTP Email Dispatch", all_md)
        self.assertIn("ITSM Ticket Sync", all_md)
        self.assertIn("AI Root-Cause Triage", all_md)
        self.assertIn("[NOT IMPLEMENTED]", all_md)
        self.assertIn("Containment simulation outcome does not imply live external dispatch", all_md)

    # -------------------------------------------------------------------------
    # Package 11.5 Governance & Cache Remediation Tests
    # -------------------------------------------------------------------------

    def test_approval_gate_alone_never_confirms(self):
        """APPROVAL_GATE event type alone or with negative outcomes must never establish CONFIRMED."""
        incident = {"notes": [], "history": [], "assigned_to": None, "raw_source": "manual"}
        raw_alert = {"alert_id": "ALT-TEST-GATE", "event_source": "manual"}

        negative_cases = [
            {"event_type": "APPROVAL_GATE", "event_name": "APPROVAL_REJECTED", "actor": "ANALYST"},
            {"event_type": "APPROVAL_GATE", "event_name": "GATE_FAILED", "actor": "ANALYST"},
            {"event_type": "APPROVAL_GATE", "event_name": "GATE_PENDING", "actor": "ANALYST"},
            {"event_type": "APPROVAL_GATE", "event_name": "APPROVAL_CANCELLED", "actor": "ANALYST"},
            {"event_type": "APPROVAL_GATE", "event_name": "APPROVAL_DENIED", "actor": "ANALYST"},
            {"event_type": "APPROVAL_GATE", "event_name": "GATE_EVALUATION", "actor": "ANALYST", "details": {"analyst_confirmed": False}},
            {"event_type": "APPROVAL_GATE", "event_name": "GENERIC_GATE_STEP", "actor": "ANALYST"},
        ]

        for case in negative_cases:
            self.service.pipeline.audit_logger.get_alert_history = lambda aid, c=case: [c]
            res = self.service._evaluate_approval_attribution("ALT-TEST-GATE", incident, raw_alert)
            self.assertNotEqual(
                res["status"],
                "CONFIRMED",
                f"Failed for negative gate event: {case['event_name']}"
            )
            self.assertEqual(res["status"], "PROVENANCE_UNKNOWN")

        # Explicit positive gate event succeeds
        pos_event = {
            "event_type": "APPROVAL_GATE",
            "event_name": "ANALYST_CONFIRMATION",
            "actor": "ANALYST",
            "details": {"analyst_confirmed": True}
        }
        self.service.pipeline.audit_logger.get_alert_history = lambda aid: [pos_event]
        res_pos = self.service._evaluate_approval_attribution("ALT-TEST-GATE", incident, raw_alert)
        self.assertEqual(res_pos["status"], "CONFIRMED")
        self.assertEqual(res_pos["details"]["approver"], "ANALYST")

    def test_negative_phrase_matching_hold_collision_safe(self):
        """Words containing 'hold' (threshold, withhold, placeholder, uphold) must not invalidate confirmation."""
        positive_notes = [
            "Confirmed by analyst: risk threshold (80) exceeded.",
            "Do not withhold evidence; execution confirmed by analyst.",
            "Confirmed on placeholder host by analyst.",
            "Confirmed to uphold security policy by analyst."
        ]
        for note_txt in positive_notes:
            inc = {
                "incident_id": "INC-TEST-HOLD-1",
                "notes": [{"actor": "ANALYST", "note": note_txt, "timestamp": "2026-11-16T12:00:00Z"}],
                "history": [],
                "raw_source": "manual"
            }
            res = self.service._evaluate_approval_attribution("ALT-TEST", inc, {})
            self.assertEqual(res["status"], "CONFIRMED", f"False rejection for note: '{note_txt}'")

        # Actual negative / pending phrases with hold must still invalidate confirmation
        negative_notes = [
            "Put on hold for further review.",
            "Hold execution pending malware analysis.",
            "Placed on hold by analyst."
        ]
        for note_txt in negative_notes:
            inc = {
                "incident_id": "INC-TEST-HOLD-2",
                "notes": [{"actor": "ANALYST", "note": note_txt, "timestamp": "2026-11-16T12:00:00Z"}],
                "history": [],
                "raw_source": "manual"
            }
            res = self.service._evaluate_approval_attribution("ALT-TEST", inc, {})
            self.assertNotEqual(res["status"], "CONFIRMED", f"Failed to reject hold note: '{note_txt}'")
            self.assertEqual(res["status"], "PROVENANCE_UNKNOWN")

    def test_conflicting_and_chronological_evidence(self):
        """The latest valid human determination governs provenance; later rejection overrides earlier approval."""
        # Case A: Approval followed by later rejection
        inc_revoked = {
            "incident_id": "INC-TEST-CHRONO-1",
            "notes": [
                {"actor": "ANALYST", "note": "Playbook execution confirmed by analyst.", "timestamp": "2026-11-16T10:00:00Z"},
                {"actor": "ANALYST", "note": "Approval rejected: false positive verified upon deep-dive.", "timestamp": "2026-11-16T11:00:00Z"}
            ],
            "history": [],
            "raw_source": "manual"
        }
        res_revoked = self.service._evaluate_approval_attribution("ALT-TEST", inc_revoked, {})
        self.assertNotEqual(res_revoked["status"], "CONFIRMED")
        self.assertEqual(res_revoked["status"], "PROVENANCE_UNKNOWN")

        # Case B: Rejection followed by later approval
        inc_approved_later = {
            "incident_id": "INC-TEST-CHRONO-2",
            "notes": [
                {"actor": "ANALYST", "note": "Awaiting approval from secondary engineer.", "timestamp": "2026-11-16T09:00:00Z"},
                {"actor": "ANALYST", "note": "Secondary engineer approved: playbook execution confirmed by analyst.", "timestamp": "2026-11-16T10:30:00Z"}
            ],
            "history": [],
            "raw_source": "manual"
        }
        res_approved = self.service._evaluate_approval_attribution("ALT-TEST", inc_approved_later, {})
        self.assertEqual(res_approved["status"], "CONFIRMED")
        self.assertEqual(res_approved["details"]["approver"], "ANALYST")

    def test_actor_identity_validation_trusted_untrusted_system(self):
        """Unverified actors cannot establish confirmation; trusted analysts and automated pipelines are distinguished."""
        # 1. Trusted actors in registry
        for trusted in ["ANALYST", "SOC_LEAD", "TIER1_ANALYST"]:
            inc = {
                "incident_id": "INC-TEST-TRUST",
                "notes": [{"actor": trusted, "note": "Playbook execution confirmed by analyst.", "timestamp": "2026-11-16T10:00:00Z"}],
                "history": [],
                "raw_source": "manual"
            }
            res = self.service._evaluate_approval_attribution("ALT-TEST", inc, {})
            self.assertEqual(res["status"], "CONFIRMED", f"Failed for trusted actor: {trusted}")

        # 2. Assigned analyst on incident is trusted
        inc_assigned = {
            "incident_id": "INC-TEST-ASSIGNED",
            "assigned_to": "alice_specialist",
            "notes": [{"actor": "alice_specialist", "note": "Playbook execution confirmed by analyst.", "timestamp": "2026-11-16T10:00:00Z"}],
            "history": [],
            "raw_source": "manual"
        }
        res_assigned = self.service._evaluate_approval_attribution("ALT-TEST", inc_assigned, {})
        self.assertEqual(res_assigned["status"], "CONFIRMED")
        self.assertEqual(res_assigned["details"]["approver"], "alice_specialist")

        # 3. Untrusted / arbitrary actors cannot establish confirmation
        for untrusted in ["MALICIOUS_ACTOR", "ATTACKER", "GUEST", "UNKNOWN", "UNVERIFIED", "RANDOM_USER"]:
            inc_untrusted = {
                "incident_id": "INC-TEST-UNTRUSTED",
                "assigned_to": None,
                "notes": [{"actor": untrusted, "note": "Playbook execution confirmed by analyst.", "timestamp": "2026-11-16T10:00:00Z"}],
                "history": [],
                "raw_source": "manual"
            }
            res_untrusted = self.service._evaluate_approval_attribution("ALT-TEST", inc_untrusted, {})
            self.assertNotEqual(res_untrusted["status"], "CONFIRMED", f"Untrusted actor established confirmation: {untrusted}")
            self.assertEqual(res_untrusted["status"], "PROVENANCE_UNKNOWN")

        # 4. System actor cannot establish confirmation, preserves automated policy
        inc_system = {
            "incident_id": "INC-TEST-SYSTEM",
            "assigned_to": None,
            "raw_source": "siem_feed",
            "notes": [{"actor": "SYSTEM", "note": "Playbook execution confirmed by analyst.", "timestamp": "2026-11-16T10:00:00Z"}],
            "history": [{"actor": "SYSTEM", "action": "INGESTED"}]
        }
        res_sys = self.service._evaluate_approval_attribution("ALT-TEST", inc_system, {"event_source": "siem"})
        self.assertEqual(res_sys["status"], "AUTOMATED_POLICY")

    def test_gemini_legacy_cache_rejects_missing_content_hash(self):
        """Service cache must strictly reject entries missing a valid, non-empty content_hash."""
        alert_file = "01_failed_logins_suspicious_ip.json"
        ident = self.service.get_alert_cache_identity(alert_file)
        self.assertIsNotNone(ident)

        # Legacy entry without content_hash
        unhashed_entry = {
            "status": "SUCCESS",
            "data": self.sample_insight_data,
            "model": "gemini-2.5-flash",
            "cached": True
        }
        self.service._gemini_cache.clear()
        self.service._gemini_cache[f"{ident['alert_id']}:{ident['model']}"] = unhashed_entry

        # Must return None (unhashed legacy fallback rejected)
        self.assertIsNone(self.service.get_gemini_insight_for_pipeline(alert_file))

        # Entry with matching non-empty content_hash is returned
        hashed_entry = dict(unhashed_entry, content_hash=ident["content_hash"])
        self.service._gemini_cache[ident["cache_key"]] = hashed_entry
        res = self.service.get_gemini_insight_for_pipeline(alert_file)
        self.assertIsNotNone(res)
        self.assertEqual(res["content_hash"], ident["content_hash"])


if __name__ == "__main__":
    unittest.main()
