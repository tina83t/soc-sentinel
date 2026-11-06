import unittest
import os
import shutil
import tempfile

from ui.services.soc_service import SOCService, get_soc_service
from modules.pipeline import SOCTriagePipeline


class TestSOCServiceBridge(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="soc_service_test_")
        shutil.copytree("config", os.path.join(self.temp_dir, "config"))
        shutil.copytree("data", os.path.join(self.temp_dir, "data"))
        self.service = SOCService(base_dir=self.temp_dir)

    def tearDown(self):
        if hasattr(self.service.pipeline, "audit_logger"):
            self.service.pipeline.audit_logger.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_service_initialization_retains_single_pipeline(self):
        self.assertIsInstance(self.service.pipeline, SOCTriagePipeline)
        # Verify repeated access to pipeline returns the exact same instance
        p1 = self.service.pipeline
        p2 = self.service.pipeline
        self.assertIs(p1, p2)

        # Custom pipeline injection
        custom_pipeline = SOCTriagePipeline(base_dir=self.temp_dir)
        svc_custom = SOCService(base_dir=self.temp_dir, pipeline=custom_pipeline)
        self.assertIs(svc_custom.pipeline, custom_pipeline)
        custom_pipeline.audit_logger.close()

    def test_alert_discovery_does_not_create_incidents(self):
        # Discover alerts
        alerts = self.service.list_alert_files()
        self.assertEqual(len(alerts), 5)

        # Verify no incidents were created merely by discovering/listing
        incidents = self.service.list_incidents()
        self.assertEqual(len(incidents), 0)

        # Check structure of discovered alert metadata
        first_alert = alerts[0]
        self.assertIn("filename", first_alert)
        self.assertIn("alert_id", first_alert)
        self.assertIn("severity", first_alert)
        self.assertFalse(first_alert["is_processed"])
        self.assertIsNone(first_alert["incident_id"])

    def test_get_alert_raw_and_preview_does_not_mutate_state(self):
        # Raw retrieval by filename
        raw1 = self.service.get_alert_raw("01_failed_logins_suspicious_ip.json")
        self.assertIsNotNone(raw1)
        self.assertEqual(raw1["alert_id"], "ALT-2026-001")

        # Raw retrieval by alert_id
        raw2 = self.service.get_alert_raw("ALT-2026-001")
        self.assertIsNotNone(raw2)
        self.assertEqual(raw2["event_type"], "Failed Authentication Spike")

        # Preview evaluation
        preview = self.service.preview_alert_evaluation("01_failed_logins_suspicious_ip.json")
        self.assertIsNotNone(preview)
        self.assertEqual(preview["risk_evaluation"]["total_risk_score"], 95)
        self.assertEqual(preview["candidate_playbook"]["playbook_id"], "PB-CRIT-001")

        # Confirm zero incidents exist after raw access and preview
        self.assertEqual(len(self.service.list_incidents()), 0)
        self.assertEqual(len(self.service.get_execution_traces()), 0)

    def test_single_alert_processing_and_duplicate_prevention(self):
        alert_file = os.path.join(self.service.alerts_dir, "01_failed_logins_suspicious_ip.json")

        # 1. Process alert once
        inc1 = self.service.process_alert_file(alert_file, show_trace=False)
        self.assertIsNotNone(inc1)
        inc1_id = inc1["incident_id"]
        self.assertEqual(inc1["original_alert_id"], "ALT-2026-001")
        self.assertEqual(inc1["status"], "NEW")

        # Verify incident is recorded
        self.assertEqual(len(self.service.list_incidents()), 1)

        # 2. Process same alert again without force -> returns existing incident without duplicating
        inc2 = self.service.process_alert_file(alert_file, show_trace=False, force=False)
        self.assertEqual(inc2["incident_id"], inc1_id)
        self.assertEqual(len(self.service.list_incidents()), 1)

        # 3. Discovered alert metadata now flags is_processed=True
        alerts = self.service.list_alert_files()
        processed_meta = next(a for a in alerts if a["alert_id"] == "ALT-2026-001")
        self.assertTrue(processed_meta["is_processed"])
        self.assertEqual(processed_meta["incident_id"], inc1_id)

    def test_process_alert_by_id(self):
        inc = self.service.process_alert_by_id("ALT-2026-002", show_trace=False)
        self.assertIsNotNone(inc)
        self.assertEqual(inc["original_alert_id"], "ALT-2026-002")
        self.assertEqual(inc["priority"], "CRITICAL")

        # Verify trace and audit retrieval
        trace = self.service.get_trace_for_alert("ALT-2026-002")
        self.assertIsNotNone(trace)
        self.assertEqual(trace.alert_id, "ALT-2026-002")

        audit_events = self.service.get_audit_history("ALT-2026-002")
        self.assertGreater(len(audit_events), 0)

    def test_incident_lifecycle_operations_via_service(self):
        # Create incident
        inc = self.service.process_alert_by_id("ALT-2026-003", show_trace=False)
        inc_id = inc["incident_id"]

        # Assign
        assigned_inc = self.service.assign_incident(inc_id, "analyst_bob", actor="LEAD_ALICE")
        self.assertEqual(assigned_inc["assigned_to"], "analyst_bob")

        # Add note
        noted_inc = self.service.add_incident_note(inc_id, "Investigating logon anomaly", actor="analyst_bob")
        self.assertEqual(len(noted_inc["notes"]), 1)

        # Update status (NEW -> IN_PROGRESS)
        prog_inc = self.service.update_incident_status(inc_id, "IN_PROGRESS", actor="analyst_bob")
        self.assertEqual(prog_inc["status"], "IN_PROGRESS")

        # Resolve
        res_inc = self.service.resolve_incident(inc_id, resolution_reason="Legitimate admin change window", actor="analyst_bob")
        self.assertEqual(res_inc["status"], "RESOLVED")

        # Reopen
        reopened = self.service.reopen_incident(inc_id, reason="Unscheduled session resumed", actor="LEAD_ALICE")
        self.assertEqual(reopened["status"], "IN_PROGRESS")

    def test_playbook_catalog_and_summary_stats(self):
        # Playbook catalog inspection
        catalog = self.service.get_playbook_catalog()
        self.assertEqual(len(catalog), 4)
        pb_ids = [p["playbook_id"] for p in catalog]
        self.assertIn("PB-CRIT-001", pb_ids)
        self.assertIn("PB-HIGH-002", pb_ids)
        self.assertIn("PB-MED-003", pb_ids)
        self.assertIn("PB-LOW-004", pb_ids)

        # Summary stats before processing
        stats_before = self.service.get_summary_stats()
        self.assertEqual(stats_before["total_alerts"], 5)
        self.assertEqual(stats_before["total_incidents"], 0)

        # Process one critical and one medium
        self.service.process_alert_by_id("ALT-2026-001", show_trace=False)
        self.service.process_alert_by_id("ALT-2026-005", show_trace=False)

        stats_after = self.service.get_summary_stats()
        self.assertEqual(stats_after["total_incidents"], 2)
        self.assertEqual(stats_after["open_incidents"], 2)
        self.assertEqual(stats_after["priority_distribution"]["CRITICAL"], 1)
        self.assertEqual(stats_after["priority_distribution"]["MEDIUM"], 1)

    def test_factory_function(self):
        svc = get_soc_service(base_dir=self.temp_dir)
        self.assertIsInstance(svc, SOCService)
        svc.pipeline.audit_logger.close()


if __name__ == "__main__":
    unittest.main()
