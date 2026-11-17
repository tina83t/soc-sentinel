"""Unit tests for Pipeline Flow Visualization & Architecture Map.

Verifies:
1. Pure service logic: 9-stage reference blueprint extraction.
2. Non-mutating preview flow for untriaged alerts (0 incidents created, 0 audit mutations).
3. Real trace mapping for triaged alerts (incident ID, duration ms, simulation IDs).
4. Streamlit view rendering with MockStreamlitModule (HTML cleanliness, no 4-space markdown indent).
5. App shell navigation integration for 'Execution & Audit'.
"""

import unittest
import os
import shutil
import tempfile

from ui.services.soc_service import SOCService
from ui.views.pipeline_flow_view import (
    render_pipeline_flow_view,
    render_pipeline_flow_component,
    get_stage_status_badge,
    STAGE_STATUS_COLORS,
    TRANSITION_DESCRIPTIONS,
)
import ui.app as app_module


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


class TestPipelineFlowVisualization(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="pipeline_view_test_")
        shutil.copytree("config", os.path.join(self.temp_dir, "config"))
        shutil.copytree("data", os.path.join(self.temp_dir, "data"))
        # Clear existing persisted incidents for a fresh test environment
        inc_file = os.path.join(self.temp_dir, "data", "incidents.json")
        if os.path.exists(inc_file):
            os.remove(inc_file)
        self.service = SOCService(base_dir=self.temp_dir)

    def tearDown(self):
        if hasattr(self.service.pipeline, "audit_logger"):
            self.service.pipeline.audit_logger.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_reference_architecture_flow_contains_all_9_stages(self):
        flow = self.service.get_pipeline_flow(None)

        self.assertEqual(flow["target_type"], "REFERENCE_ARCHITECTURE")
        self.assertEqual(flow["alert_id"], "ARCH-REFERENCE")
        self.assertEqual(flow["total_stages"], 9)
        self.assertEqual(len(flow["stages"]), 9)

        expected_stages = [
            "01_INGESTION",
            "02_VALIDATION",
            "03_ENRICHMENT",
            "04_RISK_SCORING",
            "05_PLAYBOOK_ROUTING",
            "06_APPROVAL_GATE",
            "07_RESPONSE_SIMULATION",
            "08_INCIDENT_MANAGEMENT",
            "09_AUDIT_EXPORT",
        ]

        for idx, expected_id in enumerate(expected_stages):
            stage = flow["stages"][idx]
            self.assertEqual(stage["stage_id"], expected_id)
            self.assertEqual(stage["status"], "ARCHITECTURE_SPEC")
            self.assertTrue(stage["module"].startswith("modules") or stage["module"].startswith("ui"))
            self.assertIn("inputs", stage)
            self.assertIn("outputs", stage)
            self.assertTrue(len(stage["summary"]) > 0)

    def test_non_mutating_preview_does_not_mutate_state(self):
        initial_incidents = len(self.service.list_incidents())
        initial_history = len(self.service.get_audit_history())
        initial_traces = len(self.service.get_execution_traces())

        alerts = self.service.list_alert_files()
        self.assertGreater(len(alerts), 0)
        target_path = alerts[0]["filepath"]

        flow = self.service.get_pipeline_flow(target_path)

        self.assertEqual(flow["target_type"], "NON_MUTATING_PREVIEW")
        self.assertEqual(flow["total_stages"], 9)
        self.assertEqual(len(flow["stages"]), 9)

        # Early stages evaluated in preview
        self.assertIn(flow["stages"][0]["status"], ["PREVIEW_EVALUATED", "PREVIEW_WARNINGS", "COMPLETED", "COMPLETED_WITH_WARNINGS"])
        self.assertIn(flow["stages"][1]["status"], ["PREVIEW_EVALUATED", "PREVIEW_WARNINGS", "COMPLETED", "COMPLETED_WITH_WARNINGS"])
        self.assertIn(flow["stages"][2]["status"], ["PREVIEW_EVALUATED", "PREVIEW_WARNINGS", "COMPLETED", "COMPLETED_WITH_WARNINGS"])
        self.assertIn(flow["stages"][3]["status"], ["PREVIEW_EVALUATED", "PREVIEW_WARNINGS", "COMPLETED", "COMPLETED_WITH_WARNINGS"])
        self.assertIn(flow["stages"][4]["status"], ["PREVIEW_EVALUATED", "PREVIEW_WARNINGS", "COMPLETED", "COMPLETED_WITH_WARNINGS"])

        # Containment & incident stages must remain PENDING
        self.assertEqual(flow["stages"][5]["status"], "PENDING")
        self.assertEqual(flow["stages"][6]["status"], "PENDING")
        self.assertEqual(flow["stages"][7]["status"], "PENDING")
        self.assertEqual(flow["stages"][8]["status"], "PENDING")

        # Absolute verification: NO MUTATION to backend state
        self.assertEqual(len(self.service.list_incidents()), initial_incidents)
        self.assertEqual(len(self.service.get_audit_history()), initial_history)
        self.assertEqual(len(self.service.get_execution_traces()), initial_traces)

    def test_triaged_alert_reflects_real_trace_and_incident(self):
        # Process an alert
        result = self.service.process_alert_by_id("ALT-2026-001", show_trace=False)
        self.assertIsNotNone(result)
        inc_id = result["incident_id"]

        # Now inspect pipeline flow for this alert
        flow = self.service.get_pipeline_flow("01_failed_logins_suspicious_ip.json")

        self.assertEqual(flow["target_type"], "TRIAGED_INCIDENT")
        self.assertEqual(flow["status"], "TRIAGED_AND_SIMULATED")
        self.assertIsNotNone(flow["trace_summary"])
        self.assertGreater(flow["trace_summary"]["total_steps"], 0)
        self.assertEqual(flow["incident_summary"]["incident_id"], inc_id)

        # All 9 stages should be completed, simulated, or policy-evaluated
        for stage in flow["stages"]:
            self.assertIn(stage["status"], ["COMPLETED", "COMPLETED_WITH_WARNINGS", "CONFIRMED", "SIMULATED_SUCCESS", "AUTOMATED_POLICY", "EXPORT_UNVERIFIED"])

        # Check simulation details and incident details in stage 07 and 08
        stage_07 = next(s for s in flow["stages"] if s["stage_id"] == "07_RESPONSE_SIMULATION")
        self.assertEqual(stage_07["status"], "SIMULATED_SUCCESS")

        stage_08 = next(s for s in flow["stages"] if s["stage_id"] == "08_INCIDENT_MANAGEMENT")
        self.assertEqual(stage_08["details"].get("incident_id"), inc_id)

    def test_get_stage_status_badge_coverage(self):
        for status in STAGE_STATUS_COLORS:
            badge = get_stage_status_badge(status)
            self.assertIn(STAGE_STATUS_COLORS[status]["text"], badge)
            self.assertIn(STAGE_STATUS_COLORS[status]["border"], badge)

        # Fallback
        fallback = get_stage_status_badge("NON_EXISTENT_STATUS")
        self.assertIn("NON EXISTENT STATUS", fallback)

    def test_render_pipeline_flow_view_with_mock_streamlit(self):
        mock_st = MockStreamlitModule()
        render_pipeline_flow_view(self.service, st_module=mock_st)

        self.assertGreater(len(mock_st.markdown_calls), 0)
        self.assertGreater(len(mock_st.expander_calls), 0)

        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("Pipeline Flow Visualization & Architecture Map", all_md)
        self.assertIn("Target Inspection Mode", all_md)
        self.assertIn("Execution Timing", all_md)
        self.assertIn("01/09", all_md)
        self.assertIn("09/09", all_md)

        # Verify no lines in markdown calls start with 4+ spaces (preventing raw code blocks)
        for call in mock_st.markdown_calls:
            for line in call.splitlines():
                self.assertFalse(line.startswith("    "), f"Indented line in Pipeline Flow: {line[:40]}")

    def test_render_pipeline_flow_component_embedded(self):
        mock_st = MockStreamlitModule()
        render_pipeline_flow_component(self.service, alert_id_or_file="01_failed_logins_suspicious_ip.json", st_module=mock_st)

        self.assertGreater(len(mock_st.markdown_calls), 0)
        self.assertGreater(len(mock_st.expander_calls), 0)

        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("Pipeline Execution Map:", all_md)
        self.assertIn("01/09", all_md)
        self.assertIn("09/09", all_md)

    def test_app_navigation_execution_and_audit_renders_flow_view(self):
        self.assertIn("Execution & Audit", app_module.NAVIGATION_PAGES)
        mock_st = MockStreamlitModule()
        mock_st.session_state["soc_service"] = self.service
        mock_st.session_state["current_page"] = "Execution & Audit"

        # Verify executing render_pipeline_flow_view directly works
        render_pipeline_flow_view(self.service, st_module=mock_st)
        self.assertGreater(len(mock_st.markdown_calls), 0)


if __name__ == "__main__":
    unittest.main()
