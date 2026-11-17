"""Tests for IncidentManager persistence and restart survival (Phase 1, Packages 6 & 6.2).

Verifies that incidents, verdicts, assignments, notes, duplicate relationships,
and lifecycle histories persist atomically to disk and survive restarts,
with transactional rollback on save failures, robust corruption handling,
and deep startup schema validation.
"""

import os
import json
import glob
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from modules.incident_manager import IncidentManager, VALID_VERDICTS
from modules.pipeline import SOCTriagePipeline
from ui.services.soc_service import SOCService


class TestIncidentPersistence(unittest.TestCase):
    """Test suite covering persistent incident storage, restart recovery, transactional rollback, and edge cases."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="soc_persist_test_")
        self.storage_path = os.path.join(self.temp_dir, "data", "incidents.json")
        # Ensure config and data dirs exist for tests that instantiate SOCTriagePipeline or SOCService
        config_src = os.path.abspath("config")
        if os.path.exists(config_src):
            shutil.copytree(config_src, os.path.join(self.temp_dir, "config"))

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def _sample_payload(self, alert_id: str = "ALT-TEST-001"):
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
        playbook = {
            "playbook_id": "PB-HIGH-002",
            "playbook_name": "PB-HIGH-002: High-Priority Incident Review",
            "priority": "HIGH",
            "recommended_status": "PENDING_ANALYST_REVIEW",
            "steps_executed": [],
            "simulated_actions": []
        }
        return alert, enrichment, risk, playbook

    # 1. Incident creation, assignment, note addition, status update, resolution survive restart
    def test_lifecycle_mutations_survive_restart(self):
        """Verify incident creation, assignment, note, status update, and resolution survive restart."""
        mgr = IncidentManager(storage_path=self.storage_path)
        alert, enrichment, risk, pb = self._sample_payload("ALT-SURVIVE-001")
        inc = mgr.create_incident(alert, enrichment, risk, pb)
        inc_id = inc["incident_id"]

        mgr.assign_incident(inc_id, analyst_id="analyst_alice")
        mgr.add_note(inc_id, note="Investigating anomalous authentication.", actor="analyst_alice")
        mgr.update_status(inc_id, new_status="IN_PROGRESS", actor="analyst_alice", reason="Starting deep dive")
        mgr.resolve_incident(
            inc_id,
            resolution_reason="Confirmed brute-force attack",
            verdict="TRUE_POSITIVE",
            actor="analyst_alice"
        )

        # Simulate application restart with a new manager instance pointing to the same storage path
        restarted_mgr = IncidentManager(storage_path=self.storage_path)
        restored = restarted_mgr.get_incident(inc_id)

        self.assertIsNotNone(restored)
        self.assertEqual(restored["incident_id"], inc_id)
        self.assertEqual(restored["status"], "RESOLVED")
        self.assertEqual(restored["assigned_to"], "analyst_alice")
        self.assertEqual(restored["verdict"], "TRUE_POSITIVE")
        self.assertEqual(restored["resolution_reason"], "Confirmed brute-force attack")
        self.assertEqual(restored["resolved_by"], "analyst_alice")
        self.assertIsNotNone(restored["resolved_at"])

        # Notes check
        self.assertEqual(len(restored["notes"]), 1)
        self.assertEqual(restored["notes"][0]["actor"], "analyst_alice")
        self.assertEqual(restored["notes"][0]["note"], "Investigating anomalous authentication.")

        # History check
        actions = [h["action"] for h in restored["history"]]
        self.assertIn("CREATED", actions)
        self.assertIn("ASSIGNED", actions)
        self.assertIn("NOTE_ADDED", actions)
        self.assertIn("STATUS_CHANGED", actions)
        self.assertIn("VERDICT_ASSIGNED", actions)

    # 2. Verdicts and duplicate relationships survive restart and remain queryable
    def test_verdicts_and_duplicate_relationships_survive_restart(self):
        """Verify verdicts and DUPLICATE relationships survive restart and can be queried."""
        mgr = IncidentManager(storage_path=self.storage_path)
        a1, e1, r1, p1 = self._sample_payload("ALT-PRIMARY")
        a2, e2, r2, p2 = self._sample_payload("ALT-DUPLICATE")

        inc1 = mgr.create_incident(a1, e1, r1, p1)
        inc2 = mgr.create_incident(a2, e2, r2, p2)
        inc1_id = inc1["incident_id"]
        inc2_id = inc2["incident_id"]

        # Resolve inc1 as TRUE_POSITIVE
        mgr.resolve_incident(
            inc1_id,
            resolution_reason="Primary root cause",
            verdict="TRUE_POSITIVE",
            actor="lead_analyst"
        )

        # Resolve inc2 as DUPLICATE of inc1
        mgr.resolve_incident(
            inc2_id,
            resolution_reason="Same attack campaign",
            verdict="DUPLICATE",
            actor="lead_analyst",
            duplicate_of_incident_id=inc1_id
        )

        # Restart manager
        restarted_mgr = IncidentManager(storage_path=self.storage_path)
        restored1 = restarted_mgr.get_incident(inc1_id)
        restored2 = restarted_mgr.get_incident(inc2_id)

        self.assertEqual(restored1["verdict"], "TRUE_POSITIVE")
        self.assertEqual(restored2["verdict"], "DUPLICATE")
        self.assertEqual(restored2["duplicate_of"], inc1_id)
        self.assertEqual(restored2["duplicate_of_incident_id"], inc1_id)

        # Query and filter via list_incidents
        resolved_incidents = restarted_mgr.list_incidents(status="RESOLVED")
        self.assertEqual(len(resolved_incidents), 2)
        duplicates = [i for i in resolved_incidents if i.get("verdict") == "DUPLICATE"]
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0]["incident_id"], inc2_id)
        self.assertEqual(duplicates[0]["duplicate_of"], inc1_id)

    # 3. Reopening and re-resolution survive restart with complete chronological history intact
    def test_reopen_and_reresolve_chronological_history_survive_restart(self):
        """Verify reopening and re-resolving an incident preserves full chronological audit history across restarts."""
        mgr = IncidentManager(storage_path=self.storage_path)
        a, e, r, p = self._sample_payload("ALT-REOPEN-001")
        inc = mgr.create_incident(a, e, r, p)
        inc_id = inc["incident_id"]

        # 1st resolution: FALSE_POSITIVE
        mgr.resolve_incident(
            inc_id,
            resolution_reason="Initial check looked benign",
            verdict="FALSE_POSITIVE",
            actor="junior_analyst"
        )

        # Reopen
        mgr.reopen_incident(
            inc_id,
            reason="New threat intel links host to active campaign",
            actor="senior_analyst"
        )

        # 2nd resolution: TRUE_POSITIVE
        mgr.resolve_incident(
            inc_id,
            resolution_reason="Confirmed malicious activity upon re-investigation",
            verdict="TRUE_POSITIVE",
            actor="senior_analyst"
        )

        # Restart manager
        restarted_mgr = IncidentManager(storage_path=self.storage_path)
        restored = restarted_mgr.get_incident(inc_id)

        self.assertEqual(restored["status"], "RESOLVED")
        self.assertEqual(restored["verdict"], "TRUE_POSITIVE")
        self.assertEqual(restored["resolved_by"], "senior_analyst")

        history = restored["history"]
        actions = [h["action"] for h in history]
        self.assertIn("CREATED", actions)
        self.assertIn("REOPENED", actions)
        self.assertEqual(actions.count("VERDICT_ASSIGNED"), 2)

        # Check REOPENED entry preserved previous resolution details
        reopened_entries = [h for h in history if h["action"] == "REOPENED"]
        self.assertEqual(len(reopened_entries), 1)
        reopened_entry = reopened_entries[0]
        self.assertEqual(reopened_entry["details"]["previous_verdict"], "FALSE_POSITIVE")
        self.assertEqual(reopened_entry["details"]["previous_resolution_reason"], "Initial check looked benign")
        self.assertEqual(reopened_entry["details"]["reopen_reason"], "New threat intel links host to active campaign")

    # 4. Sequence continuity across restarts on the same date
    def test_sequence_continuity_same_date(self):
        """Verify incident ID sequence continues monotonically on the same day without colliding or restarting at 1."""
        mgr = IncidentManager(storage_path=self.storage_path)
        a1, e1, r1, p1 = self._sample_payload("ALT-SEQ-1")
        a2, e2, r2, p2 = self._sample_payload("ALT-SEQ-2")
        a3, e3, r3, p3 = self._sample_payload("ALT-SEQ-3")

        inc1 = mgr.create_incident(a1, e1, r1, p1)
        inc2 = mgr.create_incident(a2, e2, r2, p2)
        inc3 = mgr.create_incident(a3, e3, r3, p3)

        today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        expected_prefix = f"INC-{today_str}-"

        self.assertTrue(inc1["incident_id"].startswith(expected_prefix))
        seq1 = int(inc1["incident_id"][len(expected_prefix):])
        seq2 = int(inc2["incident_id"][len(expected_prefix):])
        seq3 = int(inc3["incident_id"][len(expected_prefix):])
        self.assertEqual(seq2, seq1 + 1)
        self.assertEqual(seq3, seq2 + 1)

        # Restart manager
        restarted_mgr = IncidentManager(storage_path=self.storage_path)
        a4, e4, r4, p4 = self._sample_payload("ALT-SEQ-4")
        inc4 = restarted_mgr.create_incident(a4, e4, r4, p4)

        self.assertTrue(inc4["incident_id"].startswith(expected_prefix))
        seq4 = int(inc4["incident_id"][len(expected_prefix):])
        self.assertEqual(seq4, seq3 + 1)
        self.assertNotIn(inc4["incident_id"], [inc1["incident_id"], inc2["incident_id"], inc3["incident_id"]])

    # 5. Sequence continuity across date boundaries
    def test_sequence_continuity_across_date_boundaries(self):
        """Verify new date prefixes start with sequence 1 and do not collide with older date records."""
        # Pre-seed storage with an older date incident including valid schema
        old_date_str = "20250101"
        old_inc_id = f"INC-{old_date_str}-0042"
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        seed_data = {
            "version": 1,
            "last_date": old_date_str,
            "sequence": 43,
            "incidents": {
                old_inc_id: {
                    "incident_id": old_inc_id,
                    "original_alert_id": "ALT-OLD-01",
                    "status": "RESOLVED",
                    "verdict": "BENIGN_POSITIVE",
                    "history": [],
                    "notes": []
                }
            }
        }
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(seed_data, f)

        # Initialize manager with the pre-seeded store
        mgr = IncidentManager(storage_path=self.storage_path)
        self.assertIn(old_inc_id, mgr.incidents)

        # Generate a new incident today
        today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        a, e, r, p = self._sample_payload("ALT-NEW-DAY")
        new_inc = mgr.create_incident(a, e, r, p)
        new_id = new_inc["incident_id"]

        self.assertTrue(new_id.startswith(f"INC-{today_str}-"))
        # Should start from sequence 0001 for today's new date prefix
        self.assertEqual(new_id, f"INC-{today_str}-0001")
        self.assertNotEqual(new_id, old_inc_id)

    # 6. Missing storage file initializes cleanly without error
    def test_missing_storage_file_initializes_cleanly(self):
        """Verify configuring a non-existent storage path initializes empty without raising errors."""
        missing_path = os.path.join(self.temp_dir, "nonexistent", "deep", "incidents.json")
        self.assertFalse(os.path.exists(missing_path))

        mgr = IncidentManager(storage_path=missing_path)
        self.assertEqual(len(mgr.incidents), 0)
        self.assertEqual(mgr._sequence, 1)

        # Creating an incident creates the parent directory and saves successfully
        a, e, r, p = self._sample_payload("ALT-FIRST")
        inc = mgr.create_incident(a, e, r, p)
        self.assertIsNotNone(inc)
        self.assertTrue(os.path.exists(missing_path))

    # 7. Malformed or invalid JSON file is backed up to timestamped .corrupt file, audit warning emitted, and clean state initialized
    def test_corrupt_storage_backed_up_and_recovers_cleanly(self):
        """Verify corrupt JSON is moved to a timestamped .corrupt backup, audit warning emitted, and clean state loaded."""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        corrupted_content = "{\"version\": 1, \"incidents\": {TRUNCATED_GARBAGE..."
        with open(self.storage_path, "w", encoding="utf-8") as f:
            f.write(corrupted_content)

        mock_logger = MagicMock()
        mgr = IncidentManager(audit_logger=mock_logger, storage_path=self.storage_path)

        # Must initialize clean state without crashing
        self.assertEqual(mgr.incidents, {})
        self.assertEqual(mgr._sequence, 1)

        # Verify backup file created
        backup_files = glob.glob(f"{self.storage_path}.corrupt.*")
        self.assertEqual(len(backup_files), 1)
        with open(backup_files[0], "r", encoding="utf-8") as bf:
            self.assertEqual(bf.read(), corrupted_content)

        # Verify audit warning was logged
        mock_logger.log_event.assert_called_once()
        args, kwargs = mock_logger.log_event.call_args
        self.assertEqual(args[1], "INCIDENT_PERSISTENCE")
        self.assertEqual(args[2], "CORRUPT_STORAGE_RECOVERED")
        self.assertEqual(kwargs.get("level"), "WARNING")

        # Verify new incidents can now be saved without disturbing backup
        a, e, r, p = self._sample_payload("ALT-RECOVERED")
        mgr.create_incident(a, e, r, p)
        self.assertTrue(os.path.exists(self.storage_path))
        self.assertEqual(len(glob.glob(f"{self.storage_path}.corrupt.*")), 1)

    # 8. Failed write or atomic replacement does not corrupt existing valid storage file (partial write safety)
    def test_failed_save_does_not_corrupt_existing_storage(self):
        """Verify write failures or exceptions do not corrupt the authoritative storage file."""
        mgr = IncidentManager(storage_path=self.storage_path)
        a, e, r, p = self._sample_payload("ALT-BASE")
        inc = mgr.create_incident(a, e, r, p)
        inc_id = inc["incident_id"]

        with open(self.storage_path, "r", encoding="utf-8") as f:
            valid_content = json.load(f)
        self.assertIn(inc_id, valid_content["incidents"])

        # Simulate a crash/failure during json.dump in _save_state
        mock_logger = MagicMock()
        mgr.audit_logger = mock_logger
        with patch("json.dump", side_effect=IOError("Simulated disk full / write error")):
            # Attempt to add note which triggers _save_state
            with self.assertRaises(IOError):
                mgr.add_note(inc_id, note="Failed write note", actor="analyst")

        # Verify authoritative file was NOT corrupted or overwritten
        with open(self.storage_path, "r", encoding="utf-8") as f:
            preserved_content = json.load(f)
        self.assertEqual(preserved_content, valid_content)

        # Verify no orphan .tmp files remain in the storage directory
        storage_dir = os.path.dirname(self.storage_path)
        tmp_files = glob.glob(os.path.join(storage_dir, "incidents_*.tmp"))
        self.assertEqual(len(tmp_files), 0)

        # Verify error audit event logged
        mock_logger.log_event.assert_any_call(
            "SYSTEM",
            "INCIDENT_PERSISTENCE",
            "PERSISTENCE_SAVE_FAILED",
            {"storage_path": self.storage_path, "error": "Simulated disk full / write error"},
            level="ERROR"
        )

    # 9. Default / in-memory mode (storage_path=None) continues to work without touching disk
    def test_in_memory_mode_operates_without_disk(self):
        """Verify storage_path=None preserves completely in-memory behavior and creates no files."""
        mgr = IncidentManager(storage_path=None)
        self.assertIsNone(mgr.storage_path)

        a, e, r, p = self._sample_payload("ALT-MEM-001")
        inc = mgr.create_incident(a, e, r, p)
        inc_id = inc["incident_id"]

        mgr.assign_incident(inc_id, analyst_id="analyst_bob")
        mgr.add_note(inc_id, note="In-memory test note", actor="analyst_bob")
        resolved = mgr.resolve_incident(
            inc_id,
            resolution_reason="Testing in-memory behavior",
            verdict="BENIGN_POSITIVE",
            actor="analyst_bob"
        )

        self.assertEqual(resolved["status"], "RESOLVED")
        self.assertEqual(resolved["verdict"], "BENIGN_POSITIVE")
        self.assertEqual(len(mgr.incidents), 1)

        # Verify storage_path is still None and no files created in temp_dir
        self.assertFalse(os.path.exists(self.storage_path))

    # 10. SOCService properly restores _alert_to_incident lookup from persisted storage on restart
    def test_soc_service_restores_alert_mappings_on_restart(self):
        """Verify SOCService reconstructs _alert_to_incident lookup mapping from restored storage on startup."""
        service = SOCService(base_dir=self.temp_dir)
        os.makedirs(service.alerts_dir, exist_ok=True)
        alert_file = os.path.join(service.alerts_dir, "test_alert.json")
        alert_content = {
            "alert_id": "ALT-ALERT-MAP-99",
            "timestamp": "2026-11-13T10:00:00Z",
            "severity": "HIGH",
            "event_type": "Unauthorized Access Attempt",
            "event_source": "Active Directory",
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.10",
            "username": "test_user",
            "hostname": "wkst-01",
            "description": "Anomalous logon attempt observed."
        }
        with open(alert_file, "w", encoding="utf-8") as f:
            json.dump(alert_content, f)

        inc = service.process_alert_file(alert_file)
        self.assertIsNotNone(inc)
        inc_id = inc["incident_id"]

        # Ensure original service instance has the mapping
        self.assertEqual(service._alert_to_incident.get("ALT-ALERT-MAP-99"), inc_id)
        found_inc = service.get_incident_for_alert("ALT-ALERT-MAP-99")
        self.assertIsNotNone(found_inc)
        self.assertEqual(found_inc["incident_id"], inc_id)

        # Close audit logger to release file handles before restart
        if service.pipeline.audit_logger:
            service.pipeline.audit_logger.close()

        # Simulate application restart with a fresh SOCService instance pointing to the same base_dir
        restarted_service = SOCService(base_dir=self.temp_dir)
        try:
            # Check restored incident exists in incident manager
            restored_inc = restarted_service.pipeline.incident_manager.get_incident(inc_id)
            self.assertIsNotNone(restored_inc)

            # Check that _alert_to_incident was rebuilt on startup
            self.assertEqual(restarted_service._alert_to_incident.get("ALT-ALERT-MAP-99"), inc_id)
            restarted_found_inc = restarted_service.get_incident_for_alert("ALT-ALERT-MAP-99")
            self.assertIsNotNone(restarted_found_inc)
            self.assertEqual(restarted_found_inc["incident_id"], inc_id)
        finally:
            if restarted_service.pipeline.audit_logger:
                restarted_service.pipeline.audit_logger.close()

    # -------------------------------------------------------------------------
    # Package 6.2 Hardening Tests: Transactional Rollback, Corruption & Schema
    # -------------------------------------------------------------------------

    # 11. Failed creation restores memory and sequence
    def test_failed_creation_restores_memory_and_sequence(self):
        """Verify failed incident creation rolls back in-memory additions and sequence counter."""
        mgr = IncidentManager(storage_path=self.storage_path)
        self.assertEqual(len(mgr.incidents), 0)
        self.assertEqual(mgr._sequence, 1)

        alert, enrichment, risk, pb = self._sample_payload("ALT-FAIL-01")
        with patch("json.dump", side_effect=IOError("Simulated disk full")):
            with self.assertRaises(IOError):
                mgr.create_incident(alert, enrichment, risk, pb)

        # In-memory dictionary must not retain the failed incident
        self.assertEqual(len(mgr.incidents), 0)
        # Sequence counter must be restored to its pre-creation value
        self.assertEqual(mgr._sequence, 1)

        # Subsequent creation without error must succeed and receive sequence 0001
        today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        successful_inc = mgr.create_incident(alert, enrichment, risk, pb)
        self.assertEqual(successful_inc["incident_id"], f"INC-{today_str}-0001")
        self.assertEqual(len(mgr.incidents), 1)

    # 12. Failed status update restores original status and history
    def test_failed_status_update_restores_original_status_and_history(self):
        """Verify failed status update rolls back status and preserves pristine prior history."""
        mgr = IncidentManager(storage_path=self.storage_path)
        alert, enrichment, risk, pb = self._sample_payload("ALT-FAIL-STATUS")
        inc = mgr.create_incident(alert, enrichment, risk, pb)
        inc_id = inc["incident_id"]

        self.assertEqual(inc["status"], "NEW")
        initial_history_len = len(inc["history"])

        with patch("json.dump", side_effect=IOError("Simulated disk error")):
            with self.assertRaises(IOError):
                mgr.update_status(inc_id, new_status="IN_PROGRESS", actor="analyst_test")

        # Must be rolled back to NEW
        curr_inc = mgr.get_incident(inc_id)
        self.assertEqual(curr_inc["status"], "NEW")
        self.assertEqual(curr_inc["incident_status"], "NEW")
        self.assertEqual(len(curr_inc["history"]), initial_history_len)
        actions = [h["action"] for h in curr_inc["history"]]
        self.assertNotIn("STATUS_CHANGED", actions)

    # 13. Failed assignment, note, resolution, reopening and closing do not leave unsaved mutations
    def test_failed_mutations_rollback_cleanly(self):
        """Verify assign, note, resolve, reopen, and close rollback on persistence failure."""
        mgr = IncidentManager(storage_path=self.storage_path)
        alert, enrichment, risk, pb = self._sample_payload("ALT-MUT-ROLLBACK")
        inc = mgr.create_incident(alert, enrichment, risk, pb)
        inc_id = inc["incident_id"]

        # 1. Failed assignment
        with patch("json.dump", side_effect=IOError("Save failed")):
            with self.assertRaises(IOError):
                mgr.assign_incident(inc_id, analyst_id="alice")
        self.assertIsNone(mgr.get_incident(inc_id)["assigned_to"])
        self.assertEqual([h["action"] for h in mgr.get_incident(inc_id)["history"]], ["CREATED"])

        # 2. Failed note
        with patch("json.dump", side_effect=IOError("Save failed")):
            with self.assertRaises(IOError):
                mgr.add_note(inc_id, note="Unsaved note", actor="alice")
        self.assertEqual(len(mgr.get_incident(inc_id)["notes"]), 0)
        self.assertEqual([h["action"] for h in mgr.get_incident(inc_id)["history"]], ["CREATED"])

        # 3. Transition to IN_PROGRESS (succeeds)
        mgr.update_status(inc_id, "IN_PROGRESS", actor="system")

        # 4. Failed resolution
        with patch("json.dump", side_effect=IOError("Save failed")):
            with self.assertRaises(IOError):
                mgr.resolve_incident(
                    inc_id,
                    resolution_reason="Failed resolution",
                    verdict="TRUE_POSITIVE",
                    actor="alice"
                )
        rec = mgr.get_incident(inc_id)
        self.assertEqual(rec["status"], "IN_PROGRESS")
        self.assertIsNone(rec["verdict"])
        self.assertIsNone(rec["resolved_at"])
        actions = [h["action"] for h in rec["history"]]
        self.assertNotIn("VERDICT_ASSIGNED", actions)

        # 5. Resolve properly (succeeds)
        mgr.resolve_incident(
            inc_id,
            resolution_reason="Legitimate resolution",
            verdict="FALSE_POSITIVE",
            actor="alice"
        )
        self.assertEqual(mgr.get_incident(inc_id)["status"], "RESOLVED")

        # 6. Failed reopening
        with patch("json.dump", side_effect=IOError("Save failed")):
            with self.assertRaises(IOError):
                mgr.reopen_incident(inc_id, reason="Failed reopen", actor="bob")
        rec = mgr.get_incident(inc_id)
        self.assertEqual(rec["status"], "RESOLVED")
        self.assertEqual(rec["verdict"], "FALSE_POSITIVE")
        self.assertEqual(rec["resolution_reason"], "Legitimate resolution")
        actions = [h["action"] for h in rec["history"]]
        self.assertNotIn("REOPENED", actions)

        # 7. Reopen properly (succeeds)
        mgr.reopen_incident(inc_id, reason="Proper reopen", actor="bob")
        self.assertEqual(mgr.get_incident(inc_id)["status"], "IN_PROGRESS")

        # 8. Failed close
        with patch("json.dump", side_effect=IOError("Save failed")):
            with self.assertRaises(IOError):
                mgr.close_incident(inc_id, reason="Failed close", actor="bob")
        rec = mgr.get_incident(inc_id)
        self.assertEqual(rec["status"], "IN_PROGRESS")
        self.assertIsNone(rec.get("closed_at"))

    # 14. A backup filename collision never overwrites an existing backup
    def test_backup_collision_never_overwrites_existing_backup(self):
        """Verify unique backup creation prevents overwriting prior backups when timestamps collide."""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        # Pre-seed existing backup with distinct content
        fixed_time_str = "20261113_120000_123456"
        existing_backup_path = f"{self.storage_path}.corrupt.{fixed_time_str}"
        original_backup_data = "PRE_EXISTING_CORRUPT_BACKUP_DATA"
        with open(existing_backup_path, "w", encoding="utf-8") as f:
            f.write(original_backup_data)

        # Write new corrupt content into storage_path
        new_corrupt_data = "NEW_CORRUPT_CONTENT_THAT_MUST_NOT_OVERWRITE"
        with open(self.storage_path, "w", encoding="utf-8") as f:
            f.write(new_corrupt_data)

        # Mock datetime to produce the exact same timestamp string
        mock_dt = MagicMock()
        mock_dt.strftime.return_value = fixed_time_str
        with patch("modules.incident_manager.datetime") as mock_datetime:
            mock_datetime.now.return_value = mock_dt
            mgr = IncidentManager(storage_path=self.storage_path)

        # Original backup must not have been overwritten
        with open(existing_backup_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), original_backup_data)

        # A new unique backup file with suffix _1 must exist with the new corrupt content
        collision_resolved_path = f"{self.storage_path}.corrupt.{fixed_time_str}_1"
        self.assertTrue(os.path.exists(collision_resolved_path))
        with open(collision_resolved_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), new_corrupt_data)

        # Manager initialized clean state
        self.assertEqual(len(mgr.incidents), 0)

    # 15. Failed backup creation preserves the original corrupt file and prevents subsequent overwrite
    def test_failed_backup_creation_preserves_corrupt_file_and_raises(self):
        """Verify failed backup raises RuntimeError, preserves corrupt file on disk, and stops blank overwrite."""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        corrupt_content = "VALUABLE_CORRUPT_EVIDENCE_DO_NOT_DELETE"
        with open(self.storage_path, "w", encoding="utf-8") as f:
            f.write(corrupt_content)

        # Simulate OS failure when attempting to create the backup file
        with patch("os.open", side_effect=PermissionError("Read-only filesystem")):
            with self.assertRaises(RuntimeError) as ctx:
                IncidentManager(storage_path=self.storage_path)
            self.assertIn("Failed to preserve corrupt storage file", str(ctx.exception))

        # Authoritative storage file must still exist and retain its exact content
        self.assertTrue(os.path.exists(self.storage_path))
        with open(self.storage_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), corrupt_content)

    # 16. Structurally invalid but syntactically valid JSON is rejected and backed up
    def test_structurally_invalid_json_rejected_and_backed_up(self):
        """Verify structurally invalid incident records trigger safe corruption backup."""
        invalid_cases = [
            ("missing_history", {
                "version": 1,
                "incidents": {
                    "INC-20261113-0001": {
                        "incident_id": "INC-20261113-0001",
                        "status": "NEW",
                        "notes": []
                    }
                }
            }),
            ("history_not_list", {
                "version": 1,
                "incidents": {
                    "INC-20261113-0001": {
                        "incident_id": "INC-20261113-0001",
                        "status": "NEW",
                        "history": "not a list",
                        "notes": []
                    }
                }
            }),
            ("invalid_status", {
                "version": 1,
                "incidents": {
                    "INC-20261113-0001": {
                        "incident_id": "INC-20261113-0001",
                        "status": "NON_EXISTENT_STATUS",
                        "history": [],
                        "notes": []
                    }
                }
            }),
            ("invalid_verdict", {
                "version": 1,
                "incidents": {
                    "INC-20261113-0001": {
                        "incident_id": "INC-20261113-0001",
                        "status": "RESOLVED",
                        "verdict": "COMPLETELY_INVALID_VERDICT",
                        "history": [],
                        "notes": []
                    }
                }
            }),
            ("invalid_sequence_metadata", {
                "version": 1,
                "sequence": -99,
                "incidents": {}
            }),
            ("sequence_is_bool", {
                "version": 1,
                "sequence": True,
                "incidents": {}
            })
        ]

        for case_name, invalid_payload in invalid_cases:
            with self.subTest(case=case_name):
                # Clean temp directory
                test_file = os.path.join(self.temp_dir, f"invalid_{case_name}.json")
                with open(test_file, "w", encoding="utf-8") as f:
                    json.dump(invalid_payload, f)

                mgr = IncidentManager(storage_path=test_file)
                # Must initialize clean empty state
                self.assertEqual(len(mgr.incidents), 0)
                # Must have created backup file
                backup_files = glob.glob(f"{test_file}.corrupt.*")
                self.assertGreaterEqual(len(backup_files), 1)

    # 17. Valid existing persisted records still load correctly
    def test_valid_persisted_records_load_correctly(self):
        """Verify deeply structured valid records load cleanly into IncidentManager."""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        inc_id = f"INC-{today_str}-0001"
        valid_store = {
            "version": 1,
            "last_date": today_str,
            "sequence": 5,
            "incidents": {
                inc_id: {
                    "incident_id": inc_id,
                    "original_alert_id": "ALT-001",
                    "status": "RESOLVED",
                    "verdict": "TRUE_POSITIVE",
                    "resolution_reason": "Verified attack",
                    "resolved_by": "analyst_alice",
                    "resolved_at": f"{today_str[:4]}-{today_str[4:6]}-{today_str[6:]}T10:00:00Z",
                    "history": [
                        {"action": "CREATED", "timestamp": f"{today_str[:4]}-{today_str[4:6]}-{today_str[6:]}T09:00:00Z", "actor": "SYSTEM"},
                        {"action": "RESOLVED", "timestamp": f"{today_str[:4]}-{today_str[4:6]}-{today_str[6:]}T10:00:00Z", "actor": "analyst_alice"}
                    ],
                    "notes": [
                        {"note": "Analysis completed", "timestamp": f"{today_str[:4]}-{today_str[4:6]}-{today_str[6:]}T09:30:00Z", "actor": "analyst_alice"}
                    ]
                }
            }
        }
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(valid_store, f)

        mgr = IncidentManager(storage_path=self.storage_path)
        self.assertEqual(len(mgr.incidents), 1)
        inc = mgr.get_incident(inc_id)
        self.assertIsNotNone(inc)
        self.assertEqual(inc["verdict"], "TRUE_POSITIVE")
        self.assertEqual(inc["status"], "RESOLVED")
        self.assertEqual(len(inc["history"]), 2)
        self.assertEqual(len(inc["notes"]), 1)
        self.assertEqual(mgr._sequence, 5)

    # 18. storage_path=None remains unaffected
    def test_in_memory_mode_unaffected_by_transactional_wrappers(self):
        """Verify in-memory operations continue to function perfectly without filesystem interactions."""
        mgr = IncidentManager(storage_path=None)
        a, e, r, p = self._sample_payload("ALT-MEM-TRANS")
        inc = mgr.create_incident(a, e, r, p)
        inc_id = inc["incident_id"]

        mgr.assign_incident(inc_id, analyst_id="analyst_pure_memory")
        mgr.add_note(inc_id, note="In memory note", actor="analyst_pure_memory")
        mgr.update_status(inc_id, new_status="IN_PROGRESS", actor="analyst_pure_memory")
        mgr.resolve_incident(
            inc_id,
            resolution_reason="In memory resolution",
            verdict="BENIGN_POSITIVE",
            actor="analyst_pure_memory"
        )
        mgr.reopen_incident(inc_id, reason="In memory reopen", actor="analyst_pure_memory")
        mgr.close_incident(inc_id, reason="In memory close", actor="analyst_pure_memory")

        closed = mgr.get_incident(inc_id)
        self.assertEqual(closed["status"], "CLOSED")
        self.assertEqual(mgr.storage_path, None)


if __name__ == "__main__":
    unittest.main()
