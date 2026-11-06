import unittest
import os
import shutil
import tempfile
from main import SOCTriagePipeline


class TestEndToEndScenarios(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="soc_test_")
        # Copy config and data into temp base dir
        shutil.copytree("config", os.path.join(cls.temp_dir, "config"))
        shutil.copytree("data", os.path.join(cls.temp_dir, "data"))
        cls.pipeline = SOCTriagePipeline(base_dir=cls.temp_dir)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir)

    def test_scenario_01_failed_logins_suspicious_ip(self):
        alert_path = os.path.join(self.temp_dir, "data/alerts/01_failed_logins_suspicious_ip.json")
        incidents = self.pipeline.process_file(alert_path, show_trace=False)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        # In Scenario 1: Base HIGH (30) + Threat Intel (30) + Brute Force (25) + Public IP (10) = 95 -> CRITICAL
        self.assertEqual(inc["original_alert_id"], "ALT-2026-001")
        self.assertGreaterEqual(inc["risk_score"], 80)
        self.assertEqual(inc["priority"], "CRITICAL")
        self.assertIn("PB-CRIT", inc["triggered_playbook"]["playbook_id"])

    def test_scenario_02_powershell_windows_endpoint(self):
        alert_path = os.path.join(self.temp_dir, "data/alerts/02_powershell_windows_endpoint.json")
        incidents = self.pipeline.process_file(alert_path, show_trace=False)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        # Scenario 2: Base CRITICAL (40) + Suspicious PowerShell (25) + Dest TI match (30) = 95 -> CRITICAL
        self.assertEqual(inc["original_alert_id"], "ALT-2026-002")
        self.assertGreaterEqual(inc["risk_score"], 80)
        self.assertEqual(inc["priority"], "CRITICAL")
        self.assertIn("PB-CRIT", inc["triggered_playbook"]["playbook_id"])
        # Endpoint isolation action recommended
        rec_actions = [a["action_type"] for a in inc["recommended_responses"]]
        self.assertIn("ENDPOINT_ISOLATION", rec_actions)

    def test_scenario_03_privileged_account_anomaly(self):
        alert_path = os.path.join(self.temp_dir, "data/alerts/03_privileged_account_anomaly.json")
        incidents = self.pipeline.process_file(alert_path, show_trace=False)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        # Scenario 3: Base HIGH (30) + Privileged User (20) + Critical Host (15) = 65 -> HIGH
        self.assertEqual(inc["original_alert_id"], "ALT-2026-003")
        self.assertIn(inc["risk_score"], range(60, 80))
        self.assertEqual(inc["priority"], "HIGH")
        self.assertIn("PB-HIGH", inc["triggered_playbook"]["playbook_id"])

    def test_scenario_04_low_risk_info(self):
        alert_path = os.path.join(self.temp_dir, "data/alerts/04_low_risk_info.json")
        incidents = self.pipeline.process_file(alert_path, show_trace=False)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        # Scenario 4: Base LOW (10) -> score 10 -> LOW
        self.assertEqual(inc["original_alert_id"], "ALT-2026-004")
        self.assertLess(inc["risk_score"], 30)
        self.assertEqual(inc["priority"], "LOW")
        self.assertIn("PB-LOW", inc["triggered_playbook"]["playbook_id"])

    def test_scenario_05_missing_fields_alert(self):
        alert_path = os.path.join(self.temp_dir, "data/alerts/05_missing_fields_alert.json")
        incidents = self.pipeline.process_file(alert_path, show_trace=False)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        # Scenario 5: Base MEDIUM (20) + Missing Data penalty (15) = 35 -> MEDIUM
        self.assertEqual(inc["original_alert_id"], "ALT-2026-005")
        self.assertIn(inc["risk_score"], range(30, 60))
        self.assertEqual(inc["priority"], "MEDIUM")
        self.assertIn("PB-MED", inc["triggered_playbook"]["playbook_id"])
        self.assertTrue(any("Data Quality" in f for f in inc["analysis_findings"]))

    def test_batch_processing_and_report_generation(self):
        alerts_dir = os.path.join(self.temp_dir, "data/alerts")
        incidents = self.pipeline.process_directory(alerts_dir, show_trace=False)
        self.assertEqual(len(incidents), 5)

        # Check report files exist
        all_json = os.path.join(self.pipeline.reports_dir, "all_incidents.json")
        summary_csv = os.path.join(self.pipeline.reports_dir, "incidents_summary.csv")
        log_file = self.pipeline.audit_logger.log_filepath

        self.assertTrue(os.path.exists(all_json))
        self.assertTrue(os.path.exists(summary_csv))
        self.assertTrue(os.path.exists(log_file))


if __name__ == "__main__":
    unittest.main()
