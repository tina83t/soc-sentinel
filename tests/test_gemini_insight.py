"""Unit tests for Gemini LLM Advisory Analyst Insight Integration.

Tests:
1. Missing API key handling.
2. Successful structured response parsing.
3. Invalid model response handling.
4. API failure and rate-limit handling.
5. Strict safety boundaries: no risk score changes, no incident state mutations, no playbook execution.
6. Caching behavior per alert and model.
7. Context sanitization and credential redaction.
8. UI rendering with and without Gemini configured (using MockStreamlitModule).
"""

import unittest
import os
import json
import shutil
import tempfile
from unittest.mock import MagicMock, patch

from modules.gemini_analyzer import (
    GeminiAlertAnalyzer,
    AnalystInsight,
    sanitize_alert_context,
    load_env_file,
    DEFAULT_GEMINI_MODEL,
    _classify_ip,
    _ip_scope_note,
    _validate_insight_against_context,
)
from ui.services.soc_service import SOCService
from ui.views.alerts_view import render_alerts_view, render_gemini_insight_section


class MockColumn:
    def __init__(self, parent):
        self.parent = parent

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def markdown(self, body, unsafe_allow_html=False):
        self.parent.markdown(body, unsafe_allow_html=unsafe_allow_html)

    def text_input(self, label, placeholder="", label_visibility="visible", **kwargs):
        return self.parent.text_input(label, placeholder=placeholder, label_visibility=label_visibility, **kwargs)

    def selectbox(self, label, options, index=0, label_visibility="visible", **kwargs):
        return self.parent.selectbox(label, options, index=index, label_visibility=label_visibility, **kwargs)

    def checkbox(self, label, value=False, **kwargs):
        return self.parent.checkbox(label, value=value, **kwargs)

    def button(self, label, key=None, use_container_width=False, **kwargs):
        return self.parent.button(label, key=key, use_container_width=use_container_width, **kwargs)

    def expander(self, label, **kwargs):
        return self.parent.expander(label, **kwargs)

    def json(self, data):
        self.parent.json(data)


class MockStreamlitModule:
    """Mock Streamlit module capturing calls for headless verification."""

    def __init__(self):
        self.markdown_calls = []
        self.info_calls = []
        self.warning_calls = []
        self.error_calls = []
        self.json_calls = []
        self.expander_calls = []
        self.session_state = {}

    def markdown(self, body, unsafe_allow_html=False):
        self.markdown_calls.append(body)

    def info(self, msg):
        self.info_calls.append(msg)

    def warning(self, msg):
        self.warning_calls.append(msg)

    def error(self, msg):
        self.error_calls.append(msg)

    def json(self, data):
        self.json_calls.append(data)

    def columns(self, spec):
        count = spec if isinstance(spec, int) else len(spec)
        return [MockColumn(self) for _ in range(count)]

    def text_input(self, label, placeholder="", label_visibility="visible", **kwargs):
        return ""

    def selectbox(self, label, options, index=0, label_visibility="visible", **kwargs):
        return options[index] if options else None

    def checkbox(self, label, value=False, **kwargs):
        return value

    def button(self, label, key=None, use_container_width=False, **kwargs):
        return False

    def expander(self, label, **kwargs):
        self.expander_calls.append(label)
        return MockColumn(self)

    def rerun(self):
        pass


class TestGeminiInsightIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="gemini_test_")
        shutil.copytree("config", os.path.join(self.temp_dir, "config"))
        shutil.copytree("data", os.path.join(self.temp_dir, "data"))

        # Ensure no persistent incident file leaks from previous runs
        inc_file = os.path.join(self.temp_dir, "data", "incidents.json")
        if os.path.exists(inc_file):
            os.remove(inc_file)

        self.service = SOCService(base_dir=self.temp_dir)

        # Sample synthetic insight payload conforming to AnalystInsight schema
        self.sample_insight_dict = {
            "executive_summary": "High-volume SSH brute force attack detected against enterprise VPN gateway from an external IP.",
            "alert_interpretation": "Observed 50 consecutive failed logins within 60s from 198.51.100.45. Analytically, this indicates automated credential stuffing rather than user error.",
            "why_suspicious": "The request frequency exceeds normal human login thresholds and matches known scanner behavioral signatures.",
            "relevant_risk_indicators": [
                "Matched Threat Intel IOC: 198.51.100.45 (Scanner / Brute Force)",
                "50 consecutive authentication failures within 60 seconds",
                "Target is mission-critical infrastructure asset: vpn-gateway-01"
            ],
            "recommended_investigation_steps": [
                "Verify whether any authentication attempts from 198.51.100.45 succeeded.",
                "Review VPN authentication logs for other targeted usernames.",
                "Cross-reference source IP in threat intelligence feeds for campaign correlation."
            ],
            "playbook_justification": "PB-CRIT-001 is triggered because the combined risk score (95) exceeds the critical threshold (>=80), appropriately queueing analyst escalation and host isolation.",
            "missing_information": [
                "Full NetFlow/PCAP telemetry for destination port 22/443 traffic.",
                "Multi-factor authentication (MFA) challenge logs for user tina.adams."
            ],
            "confidence_explanation": "HIGH confidence: threat-intel match from local simulation DB (enrichment.threat_intel_match=true), combined with 50 consecutive authentication failures (alert.description) and high-velocity login pattern exceeding normal human thresholds. External real-world TI validation is absent."
        }

    def tearDown(self):
        if hasattr(self.service.pipeline, "audit_logger"):
            self.service.pipeline.audit_logger.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_missing_api_key_returns_not_configured(self):
        analyzer = GeminiAlertAnalyzer(api_key="")
        self.assertFalse(analyzer.is_configured)

        res = analyzer.analyze_alert(alert_data={"alert_id": "ALT-TEST-001"})
        self.assertEqual(res["status"], "NOT_CONFIGURED")
        self.assertIsNone(res["data"])
        self.assertIn("GEMINI_API_KEY", res["error"])

    def test_context_sanitization_and_redaction(self):
        raw_alert = {
            "alert_id": "ALT-999",
            "event_type": "Suspicious Login",
            "severity": "HIGH",
            "password": "SuperSecretPassword123",
            "auth_token": "Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "description": "User login with password SuperSecretPassword123",
            "internal_file_path": "/var/log/secret/path.log"
        }
        enrichment = {
            "source_ip_context": {"classification": "PUBLIC", "is_public": True},
            "is_privileged_user": True
        }
        risk_data = {
            "total_risk_score": 85,
            "risk_classification": "CRITICAL",
            "base_score": 40,
            "triggered_factors": [{"description": "Threat Intel Match"}]
        }
        pb_data = {"playbook_id": "PB-CRIT-001", "name": "Critical Containment"}

        context = sanitize_alert_context(raw_alert, enrichment, risk_data, pb_data)

        # Credentials must be redacted
        self.assertNotIn("SuperSecretPassword123", json.dumps(context))
        # Internal non-whitelisted keys must not be top-level alert fields
        self.assertNotIn("internal_file_path", context["alert"])
        self.assertEqual(context["alert"]["alert_id"], "ALT-999")
        self.assertEqual(context["risk_evaluation"]["total_risk_score"], 85)

    def test_successful_structured_response_parsing(self):
        # Create mock client returning valid AnalystInsight
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.parsed = AnalystInsight(**self.sample_insight_dict)
        mock_response.text = json.dumps(self.sample_insight_dict)
        mock_client.models.generate_content.return_value = mock_response

        analyzer = GeminiAlertAnalyzer(api_key="test_fake_key", client=mock_client)
        self.assertTrue(analyzer.is_configured)

        res = analyzer.analyze_alert(
            alert_data={"alert_id": "ALT-2026-001", "severity": "HIGH"},
            enrichment_data={"source_ip_context": {"classification": "PUBLIC"}},
            risk_data={"total_risk_score": 95, "risk_classification": "CRITICAL"},
            playbook_data={"playbook_id": "PB-CRIT-001"}
        )

        self.assertEqual(res["status"], "SUCCESS")
        self.assertIsNotNone(res["data"])
        self.assertEqual(res["data"]["executive_summary"], self.sample_insight_dict["executive_summary"])
        self.assertEqual(len(res["data"]["relevant_risk_indicators"]), 3)
        self.assertEqual(len(res["data"]["recommended_investigation_steps"]), 3)

    def test_invalid_model_response_handled_gracefully(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.parsed = None
        mock_response.text = "This is not valid json at all!"
        mock_client.models.generate_content.return_value = mock_response

        analyzer = GeminiAlertAnalyzer(api_key="test_fake_key", client=mock_client)
        res = analyzer.analyze_alert(alert_data={"alert_id": "ALT-001"})

        self.assertEqual(res["status"], "INVALID_RESPONSE")
        self.assertIsNone(res["data"])
        self.assertIn("Failed to parse", res["error"])

    def test_rate_limit_and_quota_error_handling(self):
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = Exception("429 ResourceExhausted: Quota exceeded for model")

        analyzer = GeminiAlertAnalyzer(api_key="test_fake_key", client=mock_client)
        res = analyzer.analyze_alert(alert_data={"alert_id": "ALT-001"})

        self.assertEqual(res["status"], "RATE_LIMITED")
        self.assertIsNone(res["data"])
        self.assertIn("rate limit or quota", res["error"].lower())

    def test_strictly_advisory_no_risk_score_or_incident_mutations(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.parsed = AnalystInsight(**self.sample_insight_dict)
        mock_client.models.generate_content.return_value = mock_response

        mock_analyzer = GeminiAlertAnalyzer(api_key="test_fake_key", client=mock_client)
        svc = SOCService(base_dir=self.temp_dir, gemini_analyzer=mock_analyzer)

        # Baseline check: 0 incidents, 0 traces, 0 history
        self.assertEqual(len(svc.list_incidents()), 0)
        self.assertEqual(len(svc.get_execution_traces()), 0)
        baseline_history_len = len(svc.get_audit_history())

        # Baseline preview risk calculation for 01_failed_logins_suspicious_ip.json
        prev_before = svc.preview_alert_evaluation("01_failed_logins_suspicious_ip.json")
        score_before = prev_before["risk_evaluation"]["total_risk_score"]
        tier_before = prev_before["risk_evaluation"]["risk_classification"]
        self.assertEqual(score_before, 95)
        self.assertEqual(tier_before, "CRITICAL")

        # Execute Gemini analysis
        result = svc.analyze_alert_with_gemini("01_failed_logins_suspicious_ip.json")
        self.assertEqual(result["status"], "SUCCESS")

        # Verify state is 100% UNTOUCHED
        self.assertEqual(len(svc.list_incidents()), 0)
        self.assertEqual(len(svc.get_execution_traces()), 0)
        self.assertEqual(len(svc.get_audit_history()), baseline_history_len)

        # Verify risk score was not modified or overwritten
        prev_after = svc.preview_alert_evaluation("01_failed_logins_suspicious_ip.json")
        self.assertEqual(prev_after["risk_evaluation"]["total_risk_score"], 95)
        self.assertEqual(prev_after["risk_evaluation"]["risk_classification"], "CRITICAL")

    def test_caching_behavior(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.parsed = AnalystInsight(**self.sample_insight_dict)
        mock_client.models.generate_content.return_value = mock_response

        mock_analyzer = GeminiAlertAnalyzer(api_key="test_fake_key", client=mock_client)
        svc = SOCService(base_dir=self.temp_dir, gemini_analyzer=mock_analyzer)

        # Call 1: fresh
        res1 = svc.analyze_alert_with_gemini("01_failed_logins_suspicious_ip.json")
        self.assertEqual(res1["status"], "SUCCESS")
        self.assertFalse(res1["cached"])
        self.assertEqual(mock_client.models.generate_content.call_count, 1)

        # Call 2: should be returned from cache
        res2 = svc.analyze_alert_with_gemini("01_failed_logins_suspicious_ip.json")
        self.assertEqual(res2["status"], "SUCCESS")
        self.assertTrue(res2["cached"])
        # API call count must remain 1
        self.assertEqual(mock_client.models.generate_content.call_count, 1)

        # Call 3: with force_refresh=True
        res3 = svc.analyze_alert_with_gemini("01_failed_logins_suspicious_ip.json", force_refresh=True)
        self.assertEqual(res3["status"], "SUCCESS")
        self.assertFalse(res3["cached"])
        self.assertEqual(mock_client.models.generate_content.call_count, 2)

    def test_ui_rendering_without_api_key(self):
        # Service without API key
        no_key_analyzer = GeminiAlertAnalyzer(api_key="")
        svc = SOCService(base_dir=self.temp_dir, gemini_analyzer=no_key_analyzer)

        mock_st = MockStreamlitModule()
        mock_st.session_state["selected_alert_id"] = "ALT-2026-001"

        render_alerts_view(svc, st_module=mock_st)

        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("LLM Analyst Insight", all_md)
        self.assertIn("API KEY NOT SET", all_md)
        self.assertIn("Gemini API Key Not Configured", all_md)

        # Verify no lines start with 4+ spaces
        for call in mock_st.markdown_calls:
            for line in call.splitlines():
                self.assertFalse(line.startswith("    "), f"Indented line in Alerts view: {line[:40]}")

    def test_ui_rendering_with_mocked_insight(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.parsed = AnalystInsight(**self.sample_insight_dict)
        mock_client.models.generate_content.return_value = mock_response

        mock_analyzer = GeminiAlertAnalyzer(api_key="fake_key", client=mock_client)
        svc = SOCService(base_dir=self.temp_dir, gemini_analyzer=mock_analyzer)

        mock_st = MockStreamlitModule()
        mock_st.session_state["selected_alert_id"] = "ALT-2026-001"
        # Prepopulate session state with successful insight
        mock_st.session_state["gemini_insight_ALT-2026-001"] = {
            "status": "SUCCESS",
            "data": self.sample_insight_dict,
            "model": "gemini-2.5-flash",
            "cached": True,
            "timestamp": "2026-11-16T10:00:00Z"
        }

        render_alerts_view(svc, st_module=mock_st)

        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("AI-GENERATED ADVISORY ONLY — REQUIRES ANALYST VERIFICATION", all_md)
        self.assertIn("1. Executive Summary", all_md)
        self.assertIn("2. Alert Interpretation", all_md)
        self.assertIn("3. Why This Alert Is Suspicious", all_md)
        self.assertIn("4. Verified Risk Indicators", all_md)
        self.assertIn("5. Recommended Investigation Steps", all_md)
        self.assertIn("6. Why Existing Playbook Is Appropriate", all_md)
        self.assertIn("7. Missing Information / Uncertainty", all_md)
        self.assertIn("8. Confidence Assessment", all_md)

        # Verify no lines start with 4+ spaces
        for call in mock_st.markdown_calls:
            for line in call.splitlines():
                self.assertFalse(line.startswith("    "), f"Indented line in Alerts view: {line[:40]}")


class TestGeminiGroundingHardening(unittest.TestCase):
    """Tests for RFC 5737 IP classification, post-response validation, and grounding."""

    # ------------------------------------------------------------------ helpers

    def _make_grounded_insight(self, **overrides) -> dict:
        """Return a minimal fully-grounded insight dict with no unsupported claims."""
        base = {
            "executive_summary": "Brute-force authentication spike detected.",
            "alert_interpretation": (
                "Observed: 50 failed logins from alert.source_ip=198.51.100.45 "
                "(alert.description). Note: source IP is an RFC 5737 documentation "
                "address — not a real internet source."
            ),
            "why_suspicious": (
                "High-velocity authentication failures exceed normal human thresholds "
                "(alert.description: 50 attempts in 60s). "
                "Local simulation DB flags this IP (enrichment.threat_intel_match=true) "
                "but this is not verified external intelligence."
            ),
            "relevant_risk_indicators": [
                "[alert.source_ip=198.51.100.45] Source IP flagged in local simulation TI DB "
                "(enrichment.threat_intel_match=true)",
                "[alert.description] 50 consecutive failed SSH/VPN logins in 60 seconds",
                "[alert.severity=HIGH] Alert classified as HIGH severity by event source"
            ],
            "recommended_investigation_steps": [
                "Check if any authentication attempt from 198.51.100.45 succeeded.",
                "Review authentication logs for other targeted accounts.",
                "Note: TI match is local simulation only — seek external validation."
            ],
            "playbook_justification": (
                "Risk score (risk_evaluation.total_risk_score) exceeds critical threshold, "
                "triggering playbook.playbook_id escalation."
            ),
            "missing_information": [
                "External real-world threat intelligence validation for 198.51.100.45.",
                "Full NetFlow/PCAP telemetry.",
                "MFA challenge logs for the targeted account."
            ],
            "confidence_explanation": (
                "MEDIUM confidence: Local simulation TI match present "
                "(enrichment.threat_intel_match=true) and high authentication failure "
                "velocity observed (alert.description). Cannot achieve HIGH confidence "
                "without external verified TI and confirmed breach evidence."
            )
        }
        base.update(overrides)
        return base

    def _make_context(self, **alert_overrides) -> dict:
        """Return a minimal sanitized context dict for testing."""
        alert = {
            "alert_id": "ALT-2026-001",
            "event_type": "Failed Authentication Spike",
            "severity": "HIGH",
            "timestamp": "2026-11-02T08:14:22Z",
            "event_source": "FortiGate VPN",
            "source_ip": "198.51.100.45",
            "source_ip_scope": "RFC5737_DOCUMENTATION",
            "destination_ip": "10.0.1.50",
            "destination_ip_scope": "RFC1918_PRIVATE",
            "hostname": "vpn-gateway-01.corp.internal",
            "username": "tina.adams",
            "description": "50 consecutive failed SSH/VPN authentication attempts detected."
        }
        alert.update(alert_overrides)
        return {
            "alert": alert,
            "enrichment": {
                "source_ip_classification": "RFC5737_DOCUMENTATION",
                "is_public_ip": False,
                "threat_intel_match": True,
                "threat_intel_source": "LOCAL OFFLINE SIMULATION DATABASE ONLY",
                "threat_intel_details": {
                    "reputation": "malicious",
                    "threat_type": "Brute Force / Scanner",
                    "confidence": 95
                },
                "is_privileged_user": False,
                "is_critical_host": False,
                "suspicious_patterns_detected": []
            },
            "risk_evaluation": {
                "total_risk_score": 95,
                "risk_classification": "CRITICAL",
                "base_severity_score": 40,
                "triggered_risk_factors": ["Threat Intel Match", "High Severity"]
            },
            "playbook": {
                "playbook_id": "PB-CRIT-001",
                "playbook_name": "Critical Containment Protocol",
                "target_tier": "CRITICAL",
                "description": "Immediate escalation and host isolation."
            }
        }

    # ------------------------------------------------------------------ IP classification tests

    def test_classify_rfc5737_ips(self):
        """All three RFC 5737 ranges must be classified as RFC5737_DOCUMENTATION."""
        self.assertEqual(_classify_ip("192.0.2.1"), "RFC5737_DOCUMENTATION")
        self.assertEqual(_classify_ip("198.51.100.45"), "RFC5737_DOCUMENTATION")
        self.assertEqual(_classify_ip("203.0.113.88"), "RFC5737_DOCUMENTATION")

    def test_classify_private_ips(self):
        self.assertEqual(_classify_ip("10.0.1.50"), "RFC1918_PRIVATE")
        self.assertEqual(_classify_ip("172.16.5.1"), "RFC1918_PRIVATE")
        self.assertEqual(_classify_ip("192.168.1.100"), "RFC1918_PRIVATE")

    def test_classify_loopback(self):
        self.assertEqual(_classify_ip("127.0.0.1"), "LOOPBACK")

    def test_classify_public_ip(self):
        self.assertEqual(_classify_ip("8.8.8.8"), "PUBLIC")

    def test_classify_unknown_non_ip(self):
        self.assertEqual(_classify_ip("not-an-ip"), "UNKNOWN")
        self.assertEqual(_classify_ip("None"), "UNKNOWN")
        self.assertEqual(_classify_ip(""), "UNKNOWN")

    # ------------------------------------------------------------------ sanitize_alert_context grounding

    def test_documentation_ip_receives_grounding_note(self):
        """sanitize_alert_context must inject a grounding note for RFC 5737 IPs."""
        alert = {
            "alert_id": "ALT-2026-001",
            "source_ip": "198.51.100.45",
            "destination_ip": "10.0.1.50",
        }
        ctx = sanitize_alert_context(alert)

        self.assertIn("source_ip_grounding_note", ctx["alert"])
        note = ctx["alert"]["source_ip_grounding_note"]
        self.assertIn("RFC 5737", note)
        self.assertIn("NOT a real internet address", note)
        self.assertIn("LOCAL OFFLINE SIMULATED DATABASE", note)

    def test_private_ip_receives_scope_note(self):
        """sanitize_alert_context must inject a scope note for RFC 1918 destination IPs."""
        alert = {
            "alert_id": "ALT-TEST-002",
            "source_ip": "8.8.8.8",
            "destination_ip": "10.0.1.50",
        }
        ctx = sanitize_alert_context(alert)
        self.assertIn("destination_ip_grounding_note", ctx["alert"])
        self.assertIn("RFC 1918", ctx["alert"]["destination_ip_grounding_note"])

    def test_public_ip_has_no_grounding_note(self):
        """Public IPs must not receive a grounding note."""
        alert = {"alert_id": "ALT-TEST-003", "source_ip": "8.8.8.8"}
        ctx = sanitize_alert_context(alert)
        self.assertNotIn("source_ip_grounding_note", ctx["alert"])

    def test_local_ti_match_labeled_in_enrichment(self):
        """When TI match is present, threat_intel_source must say LOCAL OFFLINE."""
        enrich = {
            "source_ip_context": {"classification": "RFC5737_DOCUMENTATION", "is_public": False},
            "threat_intelligence": {"reputation": "malicious", "threat_type": "Scanner"}
        }
        ctx = sanitize_alert_context({"alert_id": "ALT-X"}, enrichment_data=enrich)
        self.assertIn("threat_intel_source", ctx["enrichment"])
        self.assertIn("LOCAL OFFLINE", ctx["enrichment"]["threat_intel_source"])

    def test_no_ti_match_has_null_source(self):
        """When no TI match, threat_intel_source must be None."""
        ctx = sanitize_alert_context({"alert_id": "ALT-X"}, enrichment_data={})
        self.assertIsNone(ctx["enrichment"]["threat_intel_source"])

    # ------------------------------------------------------------------ _validate_insight_against_context

    def test_grounded_response_passes_validation(self):
        """A fully grounded response must produce no warnings."""
        insight = self._make_grounded_insight()
        context = self._make_context()
        result = _validate_insight_against_context(insight, context)
        self.assertFalse(result["has_unsupported_claims"], result["warnings"])
        self.assertEqual(result["warnings"], [])

    def test_numerical_confidence_flagged(self):
        """Percentage confidence numbers in confidence_explanation must be flagged."""
        insight = self._make_grounded_insight(
            confidence_explanation="High confidence (95%) based on threat intel match."
        )
        result = _validate_insight_against_context(insight, self._make_context())
        self.assertTrue(result["has_unsupported_claims"])
        self.assertTrue(
            any("percentage" in w.lower() or "%" in w for w in result["warnings"]),
            f"Expected percentage warning, got: {result['warnings']}"
        )

    def test_invented_ip_in_indicators_flagged(self):
        """An IP not in the alert context found in indicators must be flagged."""
        insight = self._make_grounded_insight(
            relevant_risk_indicators=[
                "Threat actor IP 1.2.3.4 (not in context) scanned port 22",
                "[alert.source_ip=198.51.100.45] RFC5737 documentation IP flagged in local DB"
            ]
        )
        result = _validate_insight_against_context(insight, self._make_context())
        self.assertTrue(result["has_unsupported_claims"])
        self.assertTrue(
            any("1.2.3.4" in w for w in result["warnings"]),
            f"Expected invented IP warning, got: {result['warnings']}"
        )

    def test_external_ti_claim_flagged_when_local_only(self):
        """Claiming 'verified external threat intelligence' when only local DB was used must be flagged."""
        insight = self._make_grounded_insight(
            alert_interpretation=(
                "External threat intelligence confirms 198.51.100.45 is a known scanner."
            )
        )
        result = _validate_insight_against_context(insight, self._make_context())
        self.assertTrue(result["has_unsupported_claims"])
        self.assertTrue(
            any("external threat intel" in w.lower() for w in result["warnings"]),
            f"Expected external TI warning, got: {result['warnings']}"
        )

    def test_virustotal_claim_flagged(self):
        """Mentioning VirusTotal (or similar external feed) in indicators must be flagged."""
        insight = self._make_grounded_insight(
            why_suspicious="VirusTotal confirms 198.51.100.45 is malicious."
        )
        result = _validate_insight_against_context(insight, self._make_context())
        self.assertTrue(result["has_unsupported_claims"])
        self.assertTrue(
            any("external threat intel" in w.lower() for w in result["warnings"]),
            f"Expected external feed warning, got: {result['warnings']}"
        )

    def test_no_ti_match_no_external_ti_check(self):
        """When threat_intel_match is False, external TI claim check is skipped."""
        ctx = self._make_context()
        ctx["enrichment"]["threat_intel_match"] = False
        ctx["enrichment"]["threat_intel_details"] = None
        insight = self._make_grounded_insight(
            alert_interpretation="No external threat intelligence present for 198.51.100.45.",
            confidence_explanation="LOW confidence — no TI match and limited data."
        )
        result = _validate_insight_against_context(insight, ctx)
        self.assertFalse(result["has_unsupported_claims"], result["warnings"])

    # ------------------------------------------------------------------ analyze_alert integration

    def test_analyze_alert_success_includes_validation_fields(self):
        """SUCCESS response from analyze_alert must include validation_warnings and has_unsupported_claims."""
        grounded = self._make_grounded_insight()
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.parsed = AnalystInsight(**grounded)
        mock_response.text = json.dumps(grounded)
        mock_client.models.generate_content.return_value = mock_response

        analyzer = GeminiAlertAnalyzer(api_key="fake_key", client=mock_client)
        res = analyzer.analyze_alert(
            alert_data={
                "alert_id": "ALT-2026-001",
                "source_ip": "198.51.100.45",
                "destination_ip": "10.0.1.50",
                "hostname": "vpn-gateway-01.corp.internal",
                "username": "tina.adams",
                "severity": "HIGH"
            }
        )

        self.assertEqual(res["status"], "SUCCESS")
        self.assertIn("validation_warnings", res)
        self.assertIn("has_unsupported_claims", res)
        self.assertIsInstance(res["validation_warnings"], list)
        self.assertIsInstance(res["has_unsupported_claims"], bool)

    def test_state_untouched_after_hardened_analysis(self):
        """Gemini analysis with hardened prompt must still leave SOC pipeline state unmodified."""
        temp_dir = tempfile.mkdtemp(prefix="grounding_state_test_")
        svc = None
        try:
            shutil.copytree("config", os.path.join(temp_dir, "config"))
            shutil.copytree("data", os.path.join(temp_dir, "data"))
            inc_file = os.path.join(temp_dir, "data", "incidents.json")
            if os.path.exists(inc_file):
                os.remove(inc_file)

            grounded = self._make_grounded_insight()
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.parsed = AnalystInsight(**grounded)
            mock_client.models.generate_content.return_value = mock_response

            mock_analyzer = GeminiAlertAnalyzer(api_key="fake_key", client=mock_client)
            svc = SOCService(base_dir=temp_dir, gemini_analyzer=mock_analyzer)

            baseline_incident_count = len(svc.list_incidents())
            baseline_trace_count = len(svc.get_execution_traces())

            result = svc.analyze_alert_with_gemini("01_failed_logins_suspicious_ip.json")
            self.assertEqual(result["status"], "SUCCESS")

            self.assertEqual(len(svc.list_incidents()), baseline_incident_count)
            self.assertEqual(len(svc.get_execution_traces()), baseline_trace_count)

            prev = svc.preview_alert_evaluation("01_failed_logins_suspicious_ip.json")
            self.assertEqual(prev["risk_evaluation"]["total_risk_score"], 95)
            self.assertEqual(prev["risk_evaluation"]["risk_classification"], "CRITICAL")

        finally:
            if svc and hasattr(svc.pipeline, "audit_logger"):
                svc.pipeline.audit_logger.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_evidence_limitation_banner_rendered_when_unsupported_claims(self):
        """UI must render the evidence limitation banner when has_unsupported_claims=True."""
        temp_dir = tempfile.mkdtemp(prefix="grounding_ui_test_")
        svc = None
        try:
            shutil.copytree("config", os.path.join(temp_dir, "config"))
            shutil.copytree("data", os.path.join(temp_dir, "data"))
            inc_file = os.path.join(temp_dir, "data", "incidents.json")
            if os.path.exists(inc_file):
                os.remove(inc_file)

            flagged_insight = self._make_grounded_insight(
                confidence_explanation="High confidence (95%) based on threat intel."
            )
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.parsed = AnalystInsight(**flagged_insight)
            mock_client.models.generate_content.return_value = mock_response

            mock_analyzer = GeminiAlertAnalyzer(api_key="fake_key", client=mock_client)
            svc = SOCService(base_dir=temp_dir, gemini_analyzer=mock_analyzer)

            mock_st = MockStreamlitModule()
            mock_st.session_state["selected_alert_id"] = "ALT-2026-001"
            mock_st.session_state["gemini_insight_ALT-2026-001"] = {
                "status": "SUCCESS",
                "data": flagged_insight,
                "model": "gemini-2.5-flash",
                "cached": False,
                "timestamp": "2026-11-16T10:00:00Z",
                "has_unsupported_claims": True,
                "validation_warnings": [
                    "Numerical percentage confidence detected in confidence_explanation ('95%')."
                ]
            }

            render_alerts_view(svc, st_module=mock_st)
            all_md = " ".join(mock_st.markdown_calls)

            self.assertIn("Evidence Limitation", all_md)
            self.assertIn("95%", all_md)

        finally:
            if svc and hasattr(svc.pipeline, "audit_logger"):
                svc.pipeline.audit_logger.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
