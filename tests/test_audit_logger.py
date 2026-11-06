import unittest
import os
import shutil
import tempfile
import json
from modules.audit_logger import AuditLogger
from modules.enrichment import EnrichmentModule
from modules.risk_engine import RiskScoringEngine


class TestAuditLogger(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="audit_test_")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_log_event_and_history(self):
        logger = AuditLogger(log_dir=self.temp_dir, log_filename="test_audit.log")
        try:
            entry = logger.log_event("ALT-001", "INGESTION", "ALERT_TEST", {"info": "test"}, level="INFO")
            self.assertEqual(entry["alert_id"], "ALT-001")
            self.assertEqual(entry["action"], "ALERT_TEST")

            hist = logger.get_alert_history("ALT-001")
            self.assertEqual(len(hist), 1)

            # Verify file content
            with open(logger.log_filepath, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("ALERT_TEST", content)
            self.assertIn("ALT-001", content)
        finally:
            logger.close()

    def test_logger_instance_isolation(self):
        dir_a = os.path.join(self.temp_dir, "dir_a")
        dir_b = os.path.join(self.temp_dir, "dir_b")

        logger_a = AuditLogger(log_dir=dir_a, log_filename="a.log")
        logger_b = AuditLogger(log_dir=dir_b, log_filename="b.log")

        try:
            logger_a.log_event("ALT-A", "STAGE_A", "ACTION_A", {"data": "A"})
            logger_b.log_event("ALT-B", "STAGE_B", "ACTION_B", {"data": "B"})

            with open(logger_a.log_filepath, "r", encoding="utf-8") as f:
                content_a = f.read()
            with open(logger_b.log_filepath, "r", encoding="utf-8") as f:
                content_b = f.read()

            # Logger A file should contain ACTION_A but NOT ACTION_B
            self.assertIn("ACTION_A", content_a)
            self.assertNotIn("ACTION_B", content_a)

            # Logger B file should contain ACTION_B but NOT ACTION_A
            self.assertIn("ACTION_B", content_b)
            self.assertNotIn("ACTION_A", content_b)
        finally:
            logger_a.close()
            logger_b.close()

    def test_config_load_failure_handling_and_diagnostic_logging(self):
        # Create an invalid JSON config file
        bad_config = os.path.join(self.temp_dir, "corrupt_config.json")
        with open(bad_config, "w", encoding="utf-8") as f:
            f.write("{ invalid json")

        logger = AuditLogger(log_dir=self.temp_dir, log_filename="diag.log")
        try:
            # Test EnrichmentModule fallback on corrupt config
            enricher = EnrichmentModule(db_config_path=bad_config, audit_logger=logger)
            self.assertIn("root", enricher.db.get("privileged_accounts", []))  # Fallback loaded

            # Test RiskScoringEngine fallback on corrupt config
            risk_engine = RiskScoringEngine(rules_config_path=bad_config, audit_logger=logger)
            self.assertEqual(risk_engine.config["thresholds"]["critical"], 80)  # Defaults loaded

            # Check diagnostic events were recorded in audit logger
            history = logger.history
            actions = [h["action"] for h in history]
            self.assertIn("CONFIG_LOAD_FAILED", actions)
        finally:
            logger.close()


if __name__ == "__main__":
    unittest.main()
