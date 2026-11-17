import unittest
import os
import shutil
import tempfile

from modules.incident_manager import IncidentManager, VALID_VERDICTS
from modules.pipeline import SOCTriagePipeline
from ui.services.soc_service import SOCService


class TestIncidentGovernanceAndVerdicts(unittest.TestCase):
    """Regression test suite for Phase 1, Package 2 (Incident Governance & Structured Verdicts)."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="inc_gov_test_")
        shutil.copytree("config", os.path.join(self.temp_dir, "config"))
        shutil.copytree("data", os.path.join(self.temp_dir, "data"))
        self.service = SOCService(base_dir=self.temp_dir)
        self.mgr = self.service.pipeline.incident_manager

    def tearDown(self):
        if hasattr(self.service.pipeline, "audit_logger") and self.service.pipeline.audit_logger:
            self.service.pipeline.audit_logger.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_sample_incident(self, alert_id: str = "ALT-TEST-001"):
        alert = {
            "alert_id": alert_id,
            "severity": "HIGH",
            "event_type": "Unauthorized Access Attempt",
            "event_source": "Active Directory",
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "username": "test_user",
            "hostname": "wkst-01",
            "description": "Anomalous logon attempt observed."
        }
        enrichment = {
            "source_ip_context": {"is_public": False},
            "threat_intelligence": None,
            "is_privileged_user": False,
            "is_critical_host": False
        }
        risk = {
            "total_risk_score": 65,
            "risk_classification": "HIGH"
        }
        pb = {
            "playbook_id": "PB-HIGH-002",
            "playbook_name": "PB-HIGH-002: High-Priority Incident Review",
            "priority": "HIGH",
            "recommended_status": "PENDING_ANALYST_REVIEW",
            "steps_executed": [],
            "simulated_actions": []
        }
        return self.mgr.create_incident(alert, enrichment, risk, pb)

    # 1. Each of the four valid verdicts
    def test_each_of_the_four_valid_verdicts(self):
        parent_inc = self._create_sample_incident("ALT-PARENT")
        parent_id = parent_inc["incident_id"]

        for verdict in ["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_POSITIVE"]:
            inc = self._create_sample_incident(f"ALT-{verdict}")
            res = self.mgr.resolve_incident(
                incident_id=inc["incident_id"],
                resolution_reason=f"Resolved as {verdict}",
                verdict=verdict,
                actor="analyst_test"
            )
            self.assertEqual(res["status"], "RESOLVED")
            self.assertEqual(res["verdict"], verdict)
            self.assertIsNone(res["duplicate_of"])

        # DUPLICATE verdict referencing parent_id
        dup_inc = self._create_sample_incident("ALT-DUP")
        res_dup = self.mgr.resolve_incident(
            incident_id=dup_inc["incident_id"],
            resolution_reason="Duplicate of earlier alert",
            verdict="DUPLICATE",
            actor="analyst_test",
            duplicate_of_incident_id=parent_id
        )
        self.assertEqual(res_dup["status"], "RESOLVED")
        self.assertEqual(res_dup["verdict"], "DUPLICATE")
        self.assertEqual(res_dup["duplicate_of"], parent_id)

    # 2. Missing or invalid verdict rejection
    def test_missing_or_invalid_verdict_rejection(self):
        inc = self._create_sample_incident()
        inc_id = inc["incident_id"]

        # Missing verdict
        with self.assertRaises(ValueError):
            self.mgr.resolve_incident(inc_id, resolution_reason="Reason", verdict="")

        with self.assertRaises(ValueError):
            self.mgr.resolve_incident(inc_id, resolution_reason="Reason", verdict=None)

        # Invalid verdict
        with self.assertRaises(ValueError):
            self.mgr.resolve_incident(inc_id, resolution_reason="Reason", verdict="INVALID_VERDICT")

    # 3. Missing resolution reason rejection
    def test_missing_resolution_reason_rejection(self):
        inc = self._create_sample_incident()
        inc_id = inc["incident_id"]

        with self.assertRaises(ValueError):
            self.mgr.resolve_incident(inc_id, resolution_reason="", verdict="TRUE_POSITIVE")

        with self.assertRaises(ValueError):
            self.mgr.resolve_incident(inc_id, resolution_reason="   ", verdict="TRUE_POSITIVE")

    # 4. DUPLICATE without a parent incident rejection
    def test_duplicate_without_parent_incident_rejection(self):
        inc = self._create_sample_incident()
        inc_id = inc["incident_id"]

        with self.assertRaises(ValueError):
            self.mgr.resolve_incident(
                inc_id,
                resolution_reason="Duplicate reason",
                verdict="DUPLICATE",
                duplicate_of_incident_id=None
            )

        with self.assertRaises(ValueError):
            self.mgr.resolve_incident(
                inc_id,
                resolution_reason="Duplicate reason",
                verdict="DUPLICATE",
                duplicate_of_incident_id=""
            )

    # 5. Nonexistent parent incident rejection
    def test_nonexistent_parent_incident_rejection(self):
        inc = self._create_sample_incident()
        inc_id = inc["incident_id"]

        with self.assertRaises(ValueError):
            self.mgr.resolve_incident(
                inc_id,
                resolution_reason="Duplicate reason",
                verdict="DUPLICATE",
                duplicate_of_incident_id="INC-99999999-9999"
            )

    # 6. Self-reference rejection
    def test_self_reference_rejection(self):
        inc = self._create_sample_incident()
        inc_id = inc["incident_id"]

        with self.assertRaises(ValueError):
            self.mgr.resolve_incident(
                inc_id,
                resolution_reason="Cannot be duplicate of itself",
                verdict="DUPLICATE",
                duplicate_of_incident_id=inc_id
            )

    # 7. Successful duplicate relationship recording
    def test_successful_duplicate_relationship_recording(self):
        inc_orig = self._create_sample_incident("ALT-ORIGINAL")
        inc_dup = self._create_sample_incident("ALT-DUPLICATE")

        orig_id = inc_orig["incident_id"]
        dup_id = inc_dup["incident_id"]

        # Resolve dup_id referencing orig_id
        resolved_dup = self.mgr.resolve_incident(
            dup_id,
            resolution_reason="Identical C2 beacon from same host",
            verdict="DUPLICATE",
            actor="analyst_bob",
            duplicate_of_incident_id=orig_id
        )

        self.assertEqual(resolved_dup["status"], "RESOLVED")
        self.assertEqual(resolved_dup["verdict"], "DUPLICATE")
        self.assertEqual(resolved_dup["duplicate_of"], orig_id)
        self.assertEqual(resolved_dup["duplicate_of_incident_id"], orig_id)

        # Original incident remains untouched and active (never deleted or merged)
        fresh_orig = self.mgr.get_incident(orig_id)
        self.assertEqual(fresh_orig["status"], "NEW")
        self.assertIsNone(fresh_orig["verdict"])
        self.assertIsNone(fresh_orig["duplicate_of"])

    # 8. Non-DUPLICATE verdicts not requiring a parent
    def test_non_duplicate_verdicts_not_requiring_parent(self):
        for verdict in ["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_POSITIVE"]:
            inc = self._create_sample_incident(f"ALT-NOPARENT-{verdict}")
            res = self.mgr.resolve_incident(
                inc["incident_id"],
                resolution_reason=f"Standalone resolution for {verdict}",
                verdict=verdict,
                duplicate_of_incident_id=None
            )
            self.assertEqual(res["status"], "RESOLVED")
            self.assertEqual(res["verdict"], verdict)
            self.assertIsNone(res["duplicate_of"])

    # 9. Resolution history preservation after reopening
    def test_resolution_history_preservation_after_reopening(self):
        inc = self._create_sample_incident("ALT-HISTORY-01")
        inc_id = inc["incident_id"]

        # 1. Resolve with FALSE_POSITIVE
        self.mgr.resolve_incident(
            inc_id,
            resolution_reason="Vulnerability scanner test activity",
            verdict="FALSE_POSITIVE",
            actor="analyst_alice"
        )
        resolved_inc = self.mgr.get_incident(inc_id)
        self.assertEqual(resolved_inc["status"], "RESOLVED")
        self.assertEqual(resolved_inc["verdict"], "FALSE_POSITIVE")

        # 2. Reopen incident
        reopened_inc = self.mgr.reopen_incident(
            inc_id,
            reason="Scanner credentials used for privilege escalation",
            actor="lead_charlie"
        )
        self.assertEqual(reopened_inc["status"], "IN_PROGRESS")
        self.assertIsNone(reopened_inc["verdict"])
        self.assertEqual(reopened_inc["reopen_reason"], "Scanner credentials used for privilege escalation")

        # 3. Verify history preserves prior analyst verdict and resolution reason
        history = reopened_inc["history"]
        actions = [h["action"] for h in history]
        self.assertIn("VERDICT_ASSIGNED", actions)
        self.assertIn("REOPENED", actions)

        # Inspect VERDICT_ASSIGNED entry
        verdict_entry = next(h for h in history if h["action"] == "VERDICT_ASSIGNED")
        self.assertEqual(verdict_entry["details"]["verdict"], "FALSE_POSITIVE")
        self.assertEqual(verdict_entry["details"]["resolution_reason"], "Vulnerability scanner test activity")
        self.assertEqual(verdict_entry["actor"], "analyst_alice")

        # Inspect REOPENED entry
        reopened_entry = next(h for h in history if h["action"] == "REOPENED")
        self.assertEqual(reopened_entry["details"]["previous_verdict"], "FALSE_POSITIVE")
        self.assertEqual(reopened_entry["actor"], "lead_charlie")

    # 10. Re-resolution after reopening requiring a new verdict
    def test_re_resolution_after_reopening_requiring_new_verdict(self):
        inc = self._create_sample_incident("ALT-RERESOLVE")
        inc_id = inc["incident_id"]

        # Initial resolution
        self.mgr.resolve_incident(
            inc_id,
            resolution_reason="Initial triage",
            verdict="BENIGN_POSITIVE",
            actor="analyst_bob"
        )

        # Reopen
        self.mgr.reopen_incident(inc_id, reason="New indicators surfaced", actor="analyst_bob")
        reopened = self.mgr.get_incident(inc_id)
        self.assertEqual(reopened["status"], "IN_PROGRESS")

        # Re-resolve requires verdict
        with self.assertRaises(ValueError):
            self.mgr.resolve_incident(inc_id, resolution_reason="Secondary close", verdict="")

        # Re-resolve with new verdict TRUE_POSITIVE
        final_inc = self.mgr.resolve_incident(
            inc_id,
            resolution_reason="Confirmed credential misuse after review",
            verdict="TRUE_POSITIVE",
            actor="analyst_bob"
        )
        self.assertEqual(final_inc["status"], "RESOLVED")
        self.assertEqual(final_inc["verdict"], "TRUE_POSITIVE")

        # Both verdicts are preserved chronologically
        verdict_entries = [h for h in final_inc["history"] if h["action"] == "VERDICT_ASSIGNED"]
        self.assertEqual(len(verdict_entries), 2)
        self.assertEqual(verdict_entries[0]["details"]["verdict"], "BENIGN_POSITIVE")
        self.assertEqual(verdict_entries[1]["details"]["verdict"], "TRUE_POSITIVE")

    # 11. Existing CLI and pipeline compatibility
    def test_existing_cli_and_pipeline_compatibility(self):
        incidents = self.service.pipeline.process_directory(os.path.join(self.temp_dir, "data", "alerts"), show_trace=False)
        self.assertEqual(len(incidents), 5)

        for inc in incidents:
            self.assertEqual(inc["status"], "NEW")
            self.assertIsNone(inc["verdict"])
            self.assertIsNone(inc["duplicate_of"])

        # Resolve first incident via service bridge with verdict
        first_id = incidents[0]["incident_id"]
        res = self.service.resolve_incident(
            incident_id=first_id,
            resolution_reason="Perimeter mitigation confirmed",
            verdict="TRUE_POSITIVE",
            actor="lead_analyst"
        )
        self.assertEqual(res["status"], "RESOLVED")
        self.assertEqual(res["verdict"], "TRUE_POSITIVE")


if __name__ == "__main__":
    unittest.main()
