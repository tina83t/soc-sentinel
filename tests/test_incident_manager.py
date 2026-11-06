import unittest
import os
import shutil
import tempfile
from modules.incident_manager import IncidentManager, VALID_STATUSES, ALLOWED_TRANSITIONS
from modules.audit_logger import AuditLogger


class TestIncidentManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="inc_mgr_test_")
        self.audit_logger = AuditLogger(log_dir=self.temp_dir, log_filename="incident_test.log")
        self.mgr = IncidentManager(audit_logger=self.audit_logger)

        self.sample_alert = {
            "alert_id": "ALT-2026-TEST",
            "event_type": "Brute Force Attack",
            "severity": "HIGH",
            "source_ip": "198.51.100.45",
            "destination_ip": "10.0.0.1",
            "username": "tina.adams",
            "hostname": "vpn-gw.corp",
            "description": "50 failed logins"
        }
        self.sample_enrichment = {
            "is_privileged_user": False,
            "is_critical_host": False,
            "threat_intelligence": {"matched_ip": "198.51.100.45", "threat_category": "Scanner"}
        }
        self.sample_risk = {
            "total_risk_score": 75,
            "risk_classification": "HIGH"
        }
        self.sample_playbook = {
            "playbook_id": "PB-HIGH-002",
            "playbook_name": "High Priority Review",
            "priority": "HIGH",
            "recommended_status": "PENDING_ANALYST_REVIEW",
            "simulated_actions": [
                {"action_type": "ANALYST_NOTIFICATION", "target": "SOC_QUEUE"}
            ],
            "steps_executed": [
                {"step_id": "STEP-01", "step_name": "Notify"}
            ]
        }

    def tearDown(self):
        self.audit_logger.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _create_sample_incident(self) -> str:
        inc = self.mgr.create_incident(
            alert=self.sample_alert,
            enrichment=self.sample_enrichment,
            risk_evaluation=self.sample_risk,
            playbook_result=self.sample_playbook
        )
        return inc["incident_id"]

    def test_incident_creation_defaults_and_metadata(self):
        inc_id = self._create_sample_incident()
        inc = self.mgr.get_incident(inc_id)

        self.assertIsNotNone(inc)
        self.assertEqual(inc["incident_id"], inc_id)
        self.assertEqual(inc["status"], "NEW")
        self.assertEqual(inc["incident_status"], "NEW")
        self.assertEqual(inc["priority"], "HIGH")
        self.assertEqual(inc["risk_score"], 75)
        self.assertIsNone(inc["assigned_to"])
        self.assertEqual(len(inc["notes"]), 0)
        self.assertGreater(len(inc["history"]), 0)
        self.assertEqual(inc["history"][0]["action"], "CREATED")
        self.assertIn("Threat Intel", inc["analysis_findings"][0])

    def test_get_and_list_incidents_filtering(self):
        inc_id = self._create_sample_incident()
        all_incidents = self.mgr.list_incidents()
        self.assertEqual(len(all_incidents), 1)

        # Filter by status
        new_incidents = self.mgr.list_incidents(status="NEW")
        self.assertEqual(len(new_incidents), 1)

        resolved_incidents = self.mgr.list_incidents(status="RESOLVED")
        self.assertEqual(len(resolved_incidents), 0)

        # Filter by priority
        high_incidents = self.mgr.list_incidents(priority="HIGH")
        self.assertEqual(len(high_incidents), 1)

        crit_incidents = self.mgr.list_incidents(priority="CRITICAL")
        self.assertEqual(len(crit_incidents), 0)

        # Non-existent ID returns None
        self.assertIsNone(self.mgr.get_incident("NON-EXISTENT-ID"))

    def test_assignment_and_reassignment(self):
        inc_id = self._create_sample_incident()

        # Initial assignment
        inc = self.mgr.assign_incident(inc_id, "analyst_alice", actor="SOC_LEAD")
        self.assertEqual(inc["assigned_to"], "analyst_alice")
        self.assertEqual(inc["owner"], "analyst_alice")

        # Check history entry
        assign_history = [h for h in inc["history"] if h["action"] == "ASSIGNED"]
        self.assertEqual(len(assign_history), 1)
        self.assertEqual(assign_history[0]["actor"], "SOC_LEAD")
        self.assertEqual(assign_history[0]["details"]["assigned_to"], "analyst_alice")

        # Reassignment
        inc = self.mgr.assign_incident(inc_id, "analyst_bob", actor="analyst_alice")
        self.assertEqual(inc["assigned_to"], "analyst_bob")
        reassign_history = [h for h in inc["history"] if h["action"] == "REASSIGNED"]
        self.assertEqual(len(reassign_history), 1)
        self.assertEqual(reassign_history[0]["details"]["previous_assignee"], "analyst_alice")
        self.assertEqual(reassign_history[0]["details"]["assigned_to"], "analyst_bob")

        # Empty analyst ID raises ValueError
        with self.assertRaises(ValueError):
            self.mgr.assign_incident(inc_id, "   ")

    def test_add_analyst_note(self):
        inc_id = self._create_sample_incident()

        inc = self.mgr.add_note(inc_id, "Initial perimeter IP investigation completed.", actor="analyst_alice")
        self.assertEqual(len(inc["notes"]), 1)
        self.assertEqual(inc["notes"][0]["actor"], "analyst_alice")
        self.assertEqual(inc["notes"][0]["note"], "Initial perimeter IP investigation completed.")

        note_history = [h for h in inc["history"] if h["action"] == "NOTE_ADDED"]
        self.assertEqual(len(note_history), 1)

        # Empty note raises ValueError
        with self.assertRaises(ValueError):
            self.mgr.add_note(inc_id, "")

    def test_valid_lifecycle_transitions(self):
        inc_id = self._create_sample_incident()

        # NEW -> IN_PROGRESS
        self.mgr.update_status(inc_id, "IN_PROGRESS", actor="analyst_alice", reason="Beginning triage")
        inc = self.mgr.get_incident(inc_id)
        self.assertEqual(inc["status"], "IN_PROGRESS")

        # IN_PROGRESS -> RESOLVED
        self.mgr.resolve_incident(inc_id, resolution_reason="Threat IP blocked at firewall", actor="analyst_alice")
        inc = self.mgr.get_incident(inc_id)
        self.assertEqual(inc["status"], "RESOLVED")
        self.assertEqual(inc["resolution_reason"], "Threat IP blocked at firewall")
        self.assertIsNotNone(inc["resolved_at"])

        # RESOLVED -> CLOSED
        self.mgr.update_status(inc_id, "CLOSED", actor="SOC_LEAD", reason="Verified by lead")
        inc = self.mgr.get_incident(inc_id)
        self.assertEqual(inc["status"], "CLOSED")
        self.assertIsNotNone(inc["closed_at"])

        # CLOSED -> IN_PROGRESS (Reopen)
        self.mgr.reopen_incident(inc_id, reason="Recurrence of alerts from same subnet", actor="SOC_LEAD")
        inc = self.mgr.get_incident(inc_id)
        self.assertEqual(inc["status"], "IN_PROGRESS")
        self.assertEqual(inc["reopen_reason"], "Recurrence of alerts from same subnet")

    def test_direct_resolution_and_reopen_from_resolved(self):
        inc_id = self._create_sample_incident()

        # NEW -> RESOLVED (Direct resolution, e.g. false positive)
        self.mgr.resolve_incident(inc_id, resolution_reason="Confirmed false positive vulnerability scan")
        inc = self.mgr.get_incident(inc_id)
        self.assertEqual(inc["status"], "RESOLVED")

        # RESOLVED -> IN_PROGRESS (Reopen)
        self.mgr.reopen_incident(inc_id, reason="Reopening for secondary verification")
        inc = self.mgr.get_incident(inc_id)
        self.assertEqual(inc["status"], "IN_PROGRESS")

    def test_invalid_status_transitions_rejected(self):
        inc_id = self._create_sample_incident()

        # Transition to unknown status
        with self.assertRaises(ValueError):
            self.mgr.update_status(inc_id, "PENDING_ARBITRARY")

        # Same-status transition (NEW -> NEW)
        with self.assertRaises(ValueError):
            self.mgr.update_status(inc_id, "NEW")

        # Move to CLOSED directly from NEW
        self.mgr.update_status(inc_id, "CLOSED")

        # From CLOSED, cannot jump directly to RESOLVED without reopening first
        with self.assertRaises(ValueError):
            self.mgr.update_status(inc_id, "RESOLVED")

        # Cannot reopen when already in NEW or IN_PROGRESS
        inc2_id = self._create_sample_incident()
        with self.assertRaises(ValueError):
            self.mgr.reopen_incident(inc2_id, reason="Cannot reopen NEW incident")

    def test_audit_trail_recorded_for_all_lifecycle_events(self):
        inc_id = self._create_sample_incident()
        self.mgr.assign_incident(inc_id, "analyst_charlie")
        self.mgr.add_note(inc_id, "Adding analyst note")
        self.mgr.resolve_incident(inc_id, resolution_reason="Resolved")
        self.mgr.update_status(inc_id, "CLOSED")

        history = self.audit_logger.history
        actions = [h["action"] for h in history]

        self.assertIn("INCIDENT_RECORD_CREATED", actions)
        self.assertIn("INCIDENT_ASSIGNED", actions)
        self.assertIn("INCIDENT_NOTE_ADDED", actions)
        self.assertIn("INCIDENT_STATUS_UPDATED", actions)


if __name__ == "__main__":
    unittest.main()
