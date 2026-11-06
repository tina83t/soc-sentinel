import unittest
import os
import shutil
import tempfile

from ui.services.soc_service import SOCService
from ui.views.overview_view import format_overview_metrics, render_overview_view
from ui.views.alerts_view import filter_alerts, render_alerts_view
import ui.app as app_module


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

    def expander(self, label):
        self.expander_calls.append(label)
        return MockContext(self)

    def rerun(self):
        pass


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

    def expander(self, label):
        return self.parent.expander(label)

    def json(self, data):
        self.parent.json(data)

    def info(self, msg):
        self.parent.info(msg)

    def warning(self, msg):
        self.parent.warning(msg)

    def error(self, msg):
        self.parent.error(msg)


class MockContext:
    def __init__(self, parent):
        self.parent = parent

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def json(self, data):
        self.parent.json(data)


class TestStep23AViews(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="views_test_")
        shutil.copytree("config", os.path.join(self.temp_dir, "config"))
        shutil.copytree("data", os.path.join(self.temp_dir, "data"))
        self.service = SOCService(base_dir=self.temp_dir)

    def tearDown(self):
        if hasattr(self.service.pipeline, "audit_logger"):
            self.service.pipeline.audit_logger.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_overview_metrics_formatting(self):
        raw_stats = {
            "total_alerts": 5,
            "critical_alerts": 2,
            "high_alerts": 1,
            "total_incidents": 1,
            "open_incidents": 1,
            "resolved_incidents": 0,
            "status_distribution": {"NEW": 1, "IN_PROGRESS": 0, "RESOLVED": 0, "CLOSED": 0},
            "priority_distribution": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "traces_count": 1,
            "audit_events_count": 4
        }
        metrics = format_overview_metrics(raw_stats)
        self.assertEqual(metrics["total_alerts"], 5)
        self.assertEqual(metrics["critical_alerts"], 2)
        self.assertEqual(metrics["high_alerts"], 1)
        self.assertEqual(metrics["total_incidents"], 1)
        self.assertEqual(metrics["open_incidents"], 1)
        self.assertEqual(metrics["resolved_incidents"], 0)
        self.assertEqual(metrics["status_distribution"]["NEW"], 1)

    def test_alert_filtering_and_search(self):
        alerts = self.service.list_alert_files()
        self.assertEqual(len(alerts), 5)

        # 1. Search by IP
        ip_results = filter_alerts(alerts, search_query="198.51.100.45")
        self.assertEqual(len(ip_results), 1)
        self.assertEqual(ip_results[0]["alert_id"], "ALT-2026-001")

        # 2. Search by Hostname
        host_results = filter_alerts(alerts, search_query="dc01.corp.internal")
        self.assertEqual(len(host_results), 1)
        self.assertEqual(host_results[0]["alert_id"], "ALT-2026-003")

        # 3. Filter by Severity
        crit_results = filter_alerts(alerts, severity_filter="CRITICAL")
        self.assertTrue(all(a["severity"] == "CRITICAL" for a in crit_results))
        self.assertGreater(len(crit_results), 0)

        # 4. Filter by Status (Unprocessed vs Processed)
        unproc = filter_alerts(alerts, status_filter="UNPROCESSED")
        self.assertEqual(len(unproc), 5)  # All are initially unprocessed

        # Process one alert
        self.service.process_alert_by_id("ALT-2026-001", show_trace=False)
        updated_alerts = self.service.list_alert_files()

        proc = filter_alerts(updated_alerts, status_filter="PROCESSED")
        self.assertEqual(len(proc), 1)
        self.assertEqual(proc[0]["alert_id"], "ALT-2026-001")

        unproc_after = filter_alerts(updated_alerts, status_filter="UNPROCESSED")
        self.assertEqual(len(unproc_after), 4)

    def test_selecting_and_viewing_alert_does_not_create_incident(self):
        # Initial incident count is 0
        self.assertEqual(len(self.service.list_incidents()), 0)

        # Inspect all alerts raw
        alerts = self.service.list_alert_files()
        for a in alerts:
            raw = self.service.get_alert_raw(a["filepath"])
            self.assertIsNotNone(raw)

        # Incident count must strictly remain 0
        self.assertEqual(len(self.service.list_incidents()), 0)
        self.assertEqual(len(self.service.get_execution_traces()), 0)

    def test_preview_evaluation_does_not_mutate_history_or_incidents(self):
        initial_history_len = len(self.service.get_audit_history())
        self.assertEqual(len(self.service.list_incidents()), 0)

        # Preview alert
        preview = self.service.preview_alert_evaluation("02_powershell_windows_endpoint.json")
        self.assertIsNotNone(preview)
        self.assertEqual(preview["risk_evaluation"]["total_risk_score"], 95)
        self.assertEqual(preview["candidate_playbook"]["playbook_id"], "PB-CRIT-001")

        # History and incidents must not be mutated
        self.assertEqual(len(self.service.get_audit_history()), initial_history_len)
        self.assertEqual(len(self.service.list_incidents()), 0)
        self.assertEqual(len(self.service.get_execution_traces()), 0)

    def test_missing_optional_alert_fields_handled_safely(self):
        # Scenario 5 has missing fields
        raw_5 = self.service.get_alert_raw("05_missing_fields_alert.json")
        self.assertIsNotNone(raw_5)

        # Preview evaluation of missing fields alert
        preview_5 = self.service.preview_alert_evaluation("05_missing_fields_alert.json")
        self.assertIsNotNone(preview_5)
        self.assertGreater(len(preview_5["validation_issues"]), 0)

        # Confirm filtering doesn't crash on alerts with missing/None fields
        alerts = self.service.list_alert_files()
        filtered = filter_alerts(alerts, search_query="nonexistent_needle")
        self.assertEqual(len(filtered), 0)

    def test_render_views_with_mock_streamlit(self):
        mock_st = MockStreamlitModule()

        # 1. Test Overview view rendering
        render_overview_view(self.service, st_module=mock_st)
        self.assertGreater(len(mock_st.markdown_calls), 0)

        # Verify donut chart and operational table are rendered in markdown calls
        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("<svg", all_md)
        self.assertIn("stroke-dasharray", all_md)
        self.assertIn("Operational Queue Metrics", all_md)
        self.assertIn("Discovered Alert Telemetry Queue", all_md)

        # Verify no lines in markdown calls start with 4+ spaces (which trigger raw code block rendering)
        for call in mock_st.markdown_calls:
            for line in call.splitlines():
                self.assertFalse(line.startswith("    "), f"Indented line in Overview: {line[:40]}")

        # 2. Test Alerts view rendering
        mock_st_alerts = MockStreamlitModule()
        mock_st_alerts.session_state["selected_alert_id"] = "ALT-2026-001"
        render_alerts_view(self.service, st_module=mock_st_alerts)
        self.assertGreater(len(mock_st_alerts.markdown_calls), 0)

        # Verify no lines in alerts markdown calls start with 4+ spaces
        for call in mock_st_alerts.markdown_calls:
            for line in call.splitlines():
                self.assertFalse(line.startswith("    "), f"Indented line in Alerts: {line[:40]}")

        alerts_md = " ".join(mock_st_alerts.markdown_calls)
        self.assertIn("soc-alert-card-active", alerts_md)
        self.assertIn("INSPECTING", alerts_md)
        self.assertIn("Schema Validation Passed", alerts_md)
        self.assertIn("Non-Mutating Evaluation Preview", alerts_md)
        self.assertIn("Calculated Risk", alerts_md)

    def test_render_overview_with_incidents_renders_lifecycle_bars(self):
        # Create an incident by processing one alert
        self.service.process_alert_by_id("ALT-2026-001", show_trace=False)
        self.assertEqual(len(self.service.list_incidents()), 1)

        mock_st = MockStreamlitModule()
        render_overview_view(self.service, st_module=mock_st)
        all_md = " ".join(mock_st.markdown_calls)

        self.assertIn("Formal Incidents by Lifecycle Status", all_md)
        self.assertIn("NEW", all_md)
        self.assertIn("width: 100.0%", all_md)

    def test_render_alerts_view_data_quality_warning(self):
        # Selecting scenario 5 should display data quality warning
        mock_st = MockStreamlitModule()
        mock_st.session_state["selected_alert_id"] = "ALT-2026-005"
        render_alerts_view(self.service, st_module=mock_st)
        all_md = " ".join(mock_st.markdown_calls)

        self.assertIn("Telemetry Data Quality Alert", all_md)
        self.assertIn("Non-Mutating Evaluation Preview", all_md)


if __name__ == "__main__":
    unittest.main()
