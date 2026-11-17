import unittest
import os
import shutil
import tempfile
import json

from modules.pipeline import SOCTriagePipeline
from modules.siem_connector import MockSIEMConnector
from modules.alert_processor import AlertProcessor
from ui.services.soc_service import SOCService


class TestMockSIEMConnector(unittest.TestCase):
    """Test suite for Phase 1, Package 4: Mock SIEM Integration."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="siem_test_")
        shutil.copytree("config", os.path.join(self.temp_dir, "config"))
        shutil.copytree("data", os.path.join(self.temp_dir, "data"))
        self.pipeline = SOCTriagePipeline(base_dir=self.temp_dir)
        self.connector = self.pipeline.siem_connector

    def tearDown(self):
        if hasattr(self.pipeline, "audit_logger") and self.pipeline.audit_logger:
            self.pipeline.audit_logger.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_sample_alert(self, alert_id: str, severity: str = "HIGH", **kwargs):
        alert = {
            "alert_id": alert_id,
            "timestamp": "2026-11-06T12:00:00Z",
            "event_type": "Suspicious Authentication",
            "source_ip": "198.51.100.50",
            "destination_ip": "10.0.1.10",
            "username": "svc_test",
            "hostname": "srv-app-01.corp.internal",
            "description": "Anomalous authentication observed from external IP.",
            "severity": severity,
            "event_source": "Mock SIEM Sensor",
            "additional_context": {"rule_id": "SIEM-RULE-99"}
        }
        alert.update(kwargs)
        return alert

    # 1. Successful mock SIEM ingestion
    def test_successful_mock_siem_ingestion(self):
        feed_path = os.path.join(self.temp_dir, "test_feed.json")
        alert = self._create_sample_alert("SIEM-TEST-001", severity="HIGH")
        with open(feed_path, "w", encoding="utf-8") as f:
            json.dump([alert], f)

        incidents = self.connector.ingest(self.pipeline, source_path=feed_path)
        self.assertEqual(len(incidents), 1)

        inc = incidents[0]
        self.assertEqual(inc["original_alert_id"], "SIEM-TEST-001")
        self.assertEqual(inc["status"], "NEW")
        self.assertEqual(inc["event_source"], "Mock SIEM Sensor")
        self.assertIn("INC-", inc["incident_id"])
        self.assertIn("PB-HIGH", inc["triggered_playbook"]["playbook_id"])

    # 2. Multiple alerts ingestion, routing, and deduplication
    def test_multiple_alerts_ingestion_and_deduplication(self):
        feed_path = os.path.join(self.temp_dir, "multi_feed.json")
        alerts = [
            self._create_sample_alert("SIEM-MULTI-01", severity="CRITICAL", hostname="wkst-target-01", username="admin"),
            self._create_sample_alert("SIEM-MULTI-02", severity="HIGH", source_ip="203.0.113.10"),
            self._create_sample_alert("SIEM-MULTI-03", severity="LOW", source_ip="10.0.0.1")
        ]
        with open(feed_path, "w", encoding="utf-8") as f:
            json.dump(alerts, f)

        # First ingestion run
        incidents = self.connector.ingest(self.pipeline, source_path=feed_path)
        self.assertEqual(len(incidents), 3)

        alert_ids = [inc["original_alert_id"] for inc in incidents]
        self.assertEqual(alert_ids, ["SIEM-MULTI-01", "SIEM-MULTI-02", "SIEM-MULTI-03"])

        # Second ingestion run without force (deduplication active)
        duplicate_run = self.connector.ingest(self.pipeline, source_path=feed_path, force=False)
        self.assertEqual(len(duplicate_run), 0)

        # Forced re-ingestion
        force_run = self.connector.ingest(self.pipeline, source_path=feed_path, force=True)
        self.assertEqual(len(force_run), 3)

    # 3. Malformed records handling
    def test_malformed_records_resilience(self):
        feed_path = os.path.join(self.temp_dir, "mixed_malformed_feed.json")
        valid_alert = self._create_sample_alert("SIEM-VALID-01")
        incomplete_alert = {"alert_id": "SIEM-INCOMPLETE-02", "severity": "MEDIUM"}  # missing fields
        payload = [
            valid_alert,
            "this-is-not-a-dict",
            None,
            12345,
            incomplete_alert
        ]
        with open(feed_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        alerts = self.connector.fetch_alerts(feed_path)
        self.assertEqual(len(alerts), 2)  # only dict records extracted

        # Valid record preserved
        self.assertEqual(alerts[0]["alert_id"], "SIEM-VALID-01")

        # Incomplete record normalized with data quality issues flagged
        self.assertEqual(alerts[1]["alert_id"], "SIEM-INCOMPLETE-02")
        self.assertTrue(alerts[1]["has_missing_data"])
        self.assertGreater(len(alerts[1]["data_quality_issues"]), 0)

        # Syntax error file
        broken_path = os.path.join(self.temp_dir, "broken.json")
        with open(broken_path, "w", encoding="utf-8") as f:
            f.write("{unclosed_json_syntax")

        broken_alerts = self.connector.fetch_alerts(broken_path)
        self.assertEqual(len(broken_alerts), 0)

    # 4. Missing or empty source
    def test_missing_or_empty_source(self):
        # Nonexistent path
        missing_res = self.connector.fetch_alerts(os.path.join(self.temp_dir, "does_not_exist.json"))
        self.assertEqual(missing_res, [])

        # Completely empty file
        empty_file = os.path.join(self.temp_dir, "empty.json")
        with open(empty_file, "w", encoding="utf-8") as f:
            f.write("")
        self.assertEqual(self.connector.fetch_alerts(empty_file), [])

        # Empty array file
        empty_array_file = os.path.join(self.temp_dir, "empty_array.json")
        with open(empty_array_file, "w", encoding="utf-8") as f:
            f.write("[]")
        self.assertEqual(self.connector.fetch_alerts(empty_array_file), [])

    # 5. Pipeline integration and reporting
    def test_pipeline_integration_and_reports(self):
        # Ingest via pipeline helper method
        default_feed = os.path.join(self.temp_dir, "data", "siem_feed.json")
        self.assertTrue(os.path.exists(default_feed))

        incidents = self.pipeline.ingest_from_siem(source_path=default_feed)
        self.assertEqual(len(incidents), 3)

        # Verify incidents stored in pipeline IncidentManager
        for inc in incidents:
            self.assertIsNotNone(self.pipeline.incident_manager.get_incident(inc["incident_id"]))

        # Verify reports generated
        all_inc_path = os.path.join(self.pipeline.reports_dir, "all_incidents.json")
        summary_csv = os.path.join(self.pipeline.reports_dir, "incidents_summary.csv")
        self.assertTrue(os.path.exists(all_inc_path))
        self.assertTrue(os.path.exists(summary_csv))

    # 6. Existing ingestion regression
    def test_existing_ingestion_regression(self):
        alert_file = os.path.join(self.temp_dir, "data", "alerts", "01_failed_logins_suspicious_ip.json")
        incidents = self.pipeline.process_file(alert_file, show_trace=False)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["original_alert_id"], "ALT-2026-001")

        # Directory batch processing
        batch_incs = self.pipeline.process_directory(os.path.join(self.temp_dir, "data", "alerts"), show_trace=False)
        self.assertEqual(len(batch_incs), 5)

        # Service facade integration
        service = SOCService(base_dir=self.temp_dir)
        svc_incs = service.ingest_from_siem(os.path.join(self.temp_dir, "data", "siem_feed.json"))
        self.assertGreater(len(svc_incs), 0)


if __name__ == "__main__":
    unittest.main()
