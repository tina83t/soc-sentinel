import unittest
import os
import shutil
import tempfile

from ui.services.soc_service import SOCService, get_soc_service
from ui.views.playbook_view import render_playbook_center_view, filter_playbooks
from tests.test_views_step23a import MockStreamlitModule


class TestPlaybookCenter(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="pb_center_test_")
        shutil.copytree("config", os.path.join(self.temp_dir, "config"))
        shutil.copytree("data", os.path.join(self.temp_dir, "data"))
        self.service = SOCService(base_dir=self.temp_dir)

    def tearDown(self):
        if hasattr(self.service.pipeline, "audit_logger"):
            self.service.pipeline.audit_logger.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_playbook_catalog_retrieval_and_details(self):
        catalog = self.service.get_playbook_catalog()
        self.assertEqual(len(catalog), 4)

        pb_ids = [pb["playbook_id"] for pb in catalog]
        self.assertEqual(pb_ids, ["PB-CRIT-001", "PB-HIGH-002", "PB-MED-003", "PB-LOW-004"])

        # Check PB-CRIT-001 specifications
        crit_pb = self.service.get_playbook_by_id("PB-CRIT-001")
        self.assertIsNotNone(crit_pb)
        self.assertEqual(crit_pb["target_tier"], "CRITICAL")
        self.assertEqual(crit_pb["condition"], "risk_score >= 80")
        self.assertEqual(crit_pb["execution_mode"], "DRY_RUN_SAFE_MODE")
        self.assertGreater(len(crit_pb["ordered_steps"]), 0)
        self.assertGreater(len(crit_pb["required_attributes"]), 0)
        self.assertIn("DRY_RUN_SAFE_MODE", crit_pb["safety_requirements"])

        # Unknown playbook ID returns None
        unknown_pb = self.service.get_playbook_by_id("PB-INVALID-999")
        self.assertIsNone(unknown_pb)

    def test_playbook_filtering(self):
        catalog = self.service.get_playbook_catalog()

        # 1. Filter by Tier
        crit_pbs = filter_playbooks(catalog, tier_filter="CRITICAL")
        self.assertEqual(len(crit_pbs), 1)
        self.assertEqual(crit_pbs[0]["playbook_id"], "PB-CRIT-001")

        # 2. Filter by search text
        iso_pbs = filter_playbooks(catalog, search_query="isolation")
        self.assertEqual(len(iso_pbs), 1)
        self.assertEqual(iso_pbs[0]["playbook_id"], "PB-CRIT-001")

        fw_pbs = filter_playbooks(catalog, search_query="firewall")
        self.assertEqual(len(fw_pbs), 1)
        self.assertEqual(fw_pbs[0]["playbook_id"], "PB-HIGH-002")

        # 3. Non-matching query
        no_pbs = filter_playbooks(catalog, search_query="nonexistent_playbook_needle")
        self.assertEqual(len(no_pbs), 0)

    def test_alert_playbook_compatibility_validation(self):
        # ALT-2026-001 is a Critical alert (score 95)
        # Compatible case: PB-CRIT-001
        val_compat = self.service.validate_playbook_for_alert("ALT-2026-001", "PB-CRIT-001")
        self.assertTrue(val_compat["valid"])
        self.assertTrue(val_compat["is_compatible"])
        self.assertTrue(val_compat["can_execute"])
        self.assertFalse(val_compat["is_already_processed"])
        self.assertEqual(len(val_compat["unmet_conditions"]), 0)
        self.assertEqual(val_compat["risk_score"], 95)
        self.assertEqual(val_compat["candidate_playbook_id"], "PB-CRIT-001")

        # Incompatible case: PB-LOW-004 selected for ALT-2026-001
        val_incompat = self.service.validate_playbook_for_alert("ALT-2026-001", "PB-LOW-004")
        self.assertTrue(val_incompat["valid"])
        self.assertFalse(val_incompat["is_compatible"])
        self.assertFalse(val_incompat["can_execute"])
        self.assertGreater(len(val_incompat["unmet_conditions"]), 0)
        self.assertIn("PB-CRIT-001", val_incompat["unmet_conditions"][0])

    def test_invalid_playbook_or_alert_selection(self):
        # Invalid alert ID
        val_no_alert = self.service.validate_playbook_for_alert("ALT-NONEXISTENT", "PB-CRIT-001")
        self.assertFalse(val_no_alert["valid"])
        self.assertFalse(val_no_alert["can_execute"])

        # Invalid playbook ID
        val_no_pb = self.service.validate_playbook_for_alert("ALT-2026-001", "PB-NONEXISTENT")
        self.assertFalse(val_no_pb["valid"])
        self.assertFalse(val_no_pb["can_execute"])

    def test_explicit_analyst_confirmation_enforced(self):
        # Attempt execution without analyst confirmation
        res = self.service.execute_playbook_workflow(
            alert_id="ALT-2026-001",
            playbook_id="PB-CRIT-001",
            analyst_confirmed=False
        )
        self.assertFalse(res["success"])
        self.assertFalse(res["executed"])
        self.assertIn("confirmation required", res["error"].lower())

        # Verify no incident was created
        self.assertEqual(len(self.service.list_incidents()), 0)

    def test_execution_of_incompatible_playbook_blocked(self):
        # Attempt to force execution of PB-LOW-004 for Critical alert ALT-2026-001
        res = self.service.execute_playbook_workflow(
            alert_id="ALT-2026-001",
            playbook_id="PB-LOW-004",
            analyst_confirmed=True
        )
        self.assertFalse(res["success"])
        self.assertFalse(res["executed"])
        self.assertIn("incompatible", res["error"].lower())

        # Verify no incident was created
        self.assertEqual(len(self.service.list_incidents()), 0)

    def test_successful_execution_and_result_handling(self):
        # Execute PB-CRIT-001 on ALT-2026-001 with confirmation
        res = self.service.execute_playbook_workflow(
            alert_id="ALT-2026-001",
            playbook_id="PB-CRIT-001",
            analyst_confirmed=True
        )
        self.assertTrue(res["success"])
        self.assertTrue(res["executed"])
        self.assertEqual(res["execution_mode"], "DRY_RUN_SAFE_MODE")
        self.assertIsNotNone(res["incident_id"])
        self.assertEqual(res["priority"], "CRITICAL")
        self.assertEqual(res["status"], "NEW")

        # Verify simulated actions
        sim_actions = res["simulated_actions"]
        self.assertGreater(len(sim_actions), 0)
        self.assertTrue(all(a["execution_mode"] == "DRY_RUN_SAFE_MODE" for a in sim_actions))

        # Verify simulation IDs are formatted correctly (SIM-XXXXXX)
        sim_ids = res["simulation_ids"]
        self.assertTrue(all(s.startswith("SIM-") for s in sim_ids))

        # Verify execution trace
        trace = res["trace"]
        self.assertIsNotNone(trace)
        self.assertEqual(trace["playbook_id"], "PB-CRIT-001")
        self.assertEqual(len(trace["steps"]), 9)

    def test_duplicate_execution_prevention(self):
        # Execute first time
        res1 = self.service.execute_playbook_workflow(
            alert_id="ALT-2026-001",
            playbook_id="PB-CRIT-001",
            analyst_confirmed=True
        )
        self.assertTrue(res1["success"])
        inc_id1 = res1["incident_id"]
        self.assertEqual(len(self.service.list_incidents()), 1)

        # Attempt second execution of the same alert
        res2 = self.service.execute_playbook_workflow(
            alert_id="ALT-2026-001",
            playbook_id="PB-CRIT-001",
            analyst_confirmed=True
        )
        self.assertFalse(res2["success"])
        self.assertFalse(res2["executed"])
        self.assertIn("already triaged", res2["error"])

        # Incident count remains exactly 1
        self.assertEqual(len(self.service.list_incidents()), 1)

    def test_no_accidental_execution_during_preview_or_rendering(self):
        # Initial incident count is 0
        self.assertEqual(len(self.service.list_incidents()), 0)
        initial_history_len = len(self.service.get_audit_history())

        # Validate all alerts against all playbooks
        alerts = self.service.list_alert_files()
        catalog = self.service.get_playbook_catalog()
        for a in alerts:
            for pb in catalog:
                val = self.service.validate_playbook_for_alert(a["alert_id"], pb["playbook_id"])
                self.assertIsNotNone(val)

        # Render Playbook Center view with mock Streamlit
        mock_st = MockStreamlitModule()
        mock_st.session_state["selected_playbook_id"] = "PB-CRIT-001"
        mock_st.session_state["pb_center_alert_id"] = "ALT-2026-001"
        render_playbook_center_view(self.service, st_module=mock_st)

        # Zero incidents and zero audit events created
        self.assertEqual(len(self.service.list_incidents()), 0)
        self.assertEqual(len(self.service.get_audit_history()), initial_history_len)

    def test_render_playbook_center_view_formatting_and_no_code_blocks(self):
        mock_st = MockStreamlitModule()
        mock_st.session_state["selected_playbook_id"] = "PB-CRIT-001"
        mock_st.session_state["pb_center_alert_id"] = "ALT-2026-001"

        render_playbook_center_view(self.service, st_module=mock_st)
        self.assertGreater(len(mock_st.markdown_calls), 0)

        # Verify no lines in markdown calls start with 4+ spaces
        for call in mock_st.markdown_calls:
            for line in call.splitlines():
                self.assertFalse(line.startswith("    "), f"Indented line in Playbook Center: {line[:40]}")

        all_md = " ".join(mock_st.markdown_calls)
        self.assertIn("PB-CRIT-001", all_md)
        self.assertIn("COMPATIBLE & READY FOR EXECUTION", all_md)
        self.assertIn("DRY_RUN_SAFE_MODE", all_md)


if __name__ == "__main__":
    unittest.main()
