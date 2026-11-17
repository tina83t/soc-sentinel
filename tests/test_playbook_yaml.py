import unittest
import os
import shutil
import tempfile
import yaml

from modules.playbook_loader import PlaybookLoader, REQUIRED_FIELDS
from modules.playbook_engine import PlaybookEngine
from modules.response_simulator import ResponseSimulator
from ui.services.soc_service import SOCService


class TestPlaybookYAMLArchitecture(unittest.TestCase):
    """Test suite for Phase 1, Package 3: YAML Playbook Architecture."""

    def setUp(self):
        self.playbooks_dir = os.path.join(os.getcwd(), "config", "playbooks")
        self.temp_dir = tempfile.mkdtemp(prefix="pb_yaml_test_")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    # 1. All four playbooks loading correctly
    def test_all_four_playbooks_loading_correctly(self):
        playbooks = PlaybookLoader.load_playbooks_from_directory(self.playbooks_dir)
        self.assertEqual(len(playbooks), 4)

        expected_ids = ["PB-CRIT-001", "PB-HIGH-002", "PB-MED-003", "PB-LOW-004"]
        actual_ids = [pb["playbook_id"] for pb in playbooks]
        self.assertEqual(actual_ids, expected_ids)

        expected_tiers = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        actual_tiers = [pb["target_tier"] for pb in playbooks]
        self.assertEqual(actual_tiers, expected_tiers)

        # Confirm ordered sorting by min_risk_score descending
        scores = [pb["min_risk_score"] for pb in playbooks]
        self.assertEqual(scores, [80, 60, 30, 0])

    # 2. Unique IDs and required fields
    def test_unique_ids_and_required_fields(self):
        playbooks = PlaybookLoader.load_playbooks_from_directory(self.playbooks_dir)

        # Validate required fields on each playbook
        for pb in playbooks:
            for field in REQUIRED_FIELDS:
                self.assertIn(field, pb, f"Missing required field '{field}' in {pb.get('playbook_id')}")
            self.assertIsInstance(pb["ordered_steps"], list)
            self.assertIsInstance(pb["actions"], list)
            self.assertEqual(pb["execution_mode"], "DRY_RUN_SAFE_MODE")

        # Test duplicate ID detection
        dummy_dir = os.path.join(self.temp_dir, "dup_test")
        os.makedirs(dummy_dir, exist_ok=True)
        pb_content = (
            "playbook_id: 'PB-CRIT-001'\n"
            "name: 'Playbook 1'\n"
            "target_tier: 'CRITICAL'\n"
            "condition: 'risk_score >= 80'\n"
            "min_risk_score: 80\n"
            "recommended_status: 'URGENT'\n"
            "description: 'Test'\n"
            "execution_mode: 'DRY_RUN_SAFE_MODE'\n"
            "ordered_steps: []\n"
            "actions: []\n"
        )
        with open(os.path.join(dummy_dir, "pb1.yaml"), "w", encoding="utf-8") as f:
            f.write(pb_content)
        with open(os.path.join(dummy_dir, "pb2.yaml"), "w", encoding="utf-8") as f:
            f.write(pb_content)

        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbooks_from_directory(dummy_dir)
        self.assertIn("Duplicate playbook ID", str(ctx.exception))

    # 3. Invalid YAML and schema handling
    def test_invalid_yaml_and_schema_handling(self):
        bad_dir = os.path.join(self.temp_dir, "schema_tests")
        os.makedirs(bad_dir, exist_ok=True)

        # 3a. Malformed YAML
        bad_yaml_file = os.path.join(bad_dir, "bad.yaml")
        with open(bad_yaml_file, "w", encoding="utf-8") as f:
            f.write("playbook_id: [unclosed list\nname: broken")
        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbook_file(bad_yaml_file)
        self.assertIn("Malformed YAML", str(ctx.exception))
        os.remove(bad_yaml_file)

        # 3b. Non-dictionary YAML
        list_yaml_file = os.path.join(bad_dir, "list.yaml")
        with open(list_yaml_file, "w", encoding="utf-8") as f:
            f.write("- item1\n- item2\n")
        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbook_file(list_yaml_file)
        self.assertIn("must be a mapping/dictionary", str(ctx.exception))
        os.remove(list_yaml_file)

        # 3c. Missing required field
        missing_yaml_file = os.path.join(bad_dir, "missing.yaml")
        with open(missing_yaml_file, "w", encoding="utf-8") as f:
            f.write("playbook_id: 'PB-TEST-001'\nname: 'Incomplete'\n")
        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbook_file(missing_yaml_file)
        self.assertIn("missing required field", str(ctx.exception))
        os.remove(missing_yaml_file)

        # 3d. Invalid target tier
        tier_yaml_file = os.path.join(bad_dir, "bad_tier.yaml")
        tier_content = (
            "playbook_id: 'PB-TIER-001'\n"
            "name: 'Playbook Bad Tier'\n"
            "target_tier: 'SUPER_CRITICAL'\n"
            "condition: 'risk_score >= 100'\n"
            "min_risk_score: 100\n"
            "recommended_status: 'URGENT'\n"
            "description: 'Test'\n"
            "execution_mode: 'DRY_RUN_SAFE_MODE'\n"
            "ordered_steps: []\n"
            "actions: []\n"
        )
        with open(tier_yaml_file, "w", encoding="utf-8") as f:
            f.write(tier_content)
        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbook_file(tier_yaml_file)
        self.assertIn("Invalid 'target_tier'", str(ctx.exception))
        os.remove(tier_yaml_file)

        # 3e. Nonexistent directory
        with self.assertRaises(FileNotFoundError):
            PlaybookLoader.load_playbooks_from_directory("/path/does/not/exist/ever")

        # 3f. Empty directory
        empty_dir = os.path.join(self.temp_dir, "empty_dir")
        os.makedirs(empty_dir, exist_ok=True)
        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbooks_from_directory(empty_dir)
        self.assertIn("No playbook YAML files found", str(ctx.exception))

    # 4. Engine and UI catalog consistency
    def test_engine_and_ui_catalog_consistency(self):
        engine = PlaybookEngine(response_simulator=ResponseSimulator())
        engine_catalog = engine.get_catalog()

        service = SOCService()
        service_catalog = service.get_playbook_catalog()

        self.assertEqual(len(engine_catalog), len(service_catalog))
        self.assertEqual(len(engine_catalog), 4)

        for eng_pb, srv_pb in zip(engine_catalog, service_catalog):
            self.assertEqual(eng_pb["playbook_id"], srv_pb["playbook_id"])
            self.assertEqual(eng_pb["name"], srv_pb["name"])
            self.assertEqual(eng_pb["target_tier"], srv_pb["target_tier"])
            self.assertEqual(eng_pb["condition"], srv_pb["condition"])
            self.assertEqual(eng_pb["min_risk_score"], srv_pb["min_risk_score"])
            self.assertEqual(eng_pb["description"], srv_pb["description"])
            self.assertEqual(eng_pb["purpose"], srv_pb["purpose"])
            self.assertEqual(len(eng_pb["ordered_steps"]), len(srv_pb["ordered_steps"]))
            self.assertEqual(len(eng_pb["actions"]), len(srv_pb["actions"]))

    # 5. Existing playbook execution behavior remaining unchanged
    def test_existing_playbook_execution_behavior_unchanged(self):
        engine = PlaybookEngine(response_simulator=ResponseSimulator())

        # Test Critical routing (score 85)
        alert_crit = {
            "alert_id": "ALT-CRIT-99",
            "hostname": "wkst-target-01",
            "username": "admin_user",
            "source_ip": "198.51.100.22"
        }
        enrichment_crit = {"source_ip_context": {"is_public": True}}
        risk_crit = {"total_risk_score": 85, "risk_classification": "CRITICAL"}

        res_crit = engine.execute_playbook(alert_crit, enrichment_crit, risk_crit)
        self.assertEqual(res_crit["playbook_id"], "PB-CRIT-001")
        self.assertEqual(res_crit["priority"], "CRITICAL")
        self.assertEqual(res_crit["recommended_status"], "URGENT_ATTENTION_REQUIRED")
        self.assertIn("PB-CRIT-001", res_crit["playbook_name"])
        action_types_crit = [a["action_type"] for a in res_crit["simulated_actions"]]
        self.assertIn("ANALYST_NOTIFICATION", action_types_crit)
        self.assertIn("ENDPOINT_ISOLATION", action_types_crit)
        self.assertIn("ACCOUNT_SUSPENSION", action_types_crit)

        # Test High routing (score 70)
        alert_high = {
            "alert_id": "ALT-HIGH-99",
            "source_ip": "203.0.113.5"
        }
        enrichment_high = {
            "source_ip_context": {"is_public": True},
            "threat_intelligence": {"threat_category": "scanner"}
        }
        risk_high = {"total_risk_score": 70, "risk_classification": "HIGH"}

        res_high = engine.execute_playbook(alert_high, enrichment_high, risk_high)
        self.assertEqual(res_high["playbook_id"], "PB-HIGH-002")
        self.assertEqual(res_high["priority"], "HIGH")
        self.assertEqual(res_high["recommended_status"], "PENDING_ANALYST_REVIEW")
        action_types_high = [a["action_type"] for a in res_high["simulated_actions"]]
        self.assertIn("ANALYST_NOTIFICATION", action_types_high)
        self.assertIn("IP_BLOCK", action_types_high)

        # Test Medium routing (score 45)
        alert_med = {"alert_id": "ALT-MED-99"}
        enrichment_med = {}
        risk_med = {"total_risk_score": 45, "risk_classification": "MEDIUM"}

        res_med = engine.execute_playbook(alert_med, enrichment_med, risk_med)
        self.assertEqual(res_med["playbook_id"], "PB-MED-003")
        self.assertEqual(res_med["priority"], "MEDIUM")
        self.assertEqual(res_med["recommended_status"], "TRIAGE_QUEUE")
        action_types_med = [a["action_type"] for a in res_med["simulated_actions"]]
        self.assertEqual(action_types_med, ["SECURITY_REVIEW_QUEUE"])

        # Test Low routing (score 15)
        alert_low = {"alert_id": "ALT-LOW-99"}
        enrichment_low = {}
        risk_low = {"total_risk_score": 15, "risk_classification": "LOW"}

        res_low = engine.execute_playbook(alert_low, enrichment_low, risk_low)
        self.assertEqual(res_low["playbook_id"], "PB-LOW-004")
        self.assertEqual(res_low["priority"], "LOW")
        self.assertEqual(res_low["recommended_status"], "AUTO_RESOLVED_INFORMATIONAL")
        self.assertEqual(len(res_low["simulated_actions"]), 0)

    # 6. Action Type and Execution Step Validation
    def _write_playbook_yaml(self, file_path: str, data: dict) -> None:
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f)

    def _get_base_playbook_dict(self) -> dict:
        return {
            "playbook_id": "PB-TEST-VAL-001",
            "name": "Validation Test Playbook",
            "target_tier": "HIGH",
            "condition": "risk_score >= 60",
            "min_risk_score": 60,
            "recommended_status": "PENDING_ANALYST_REVIEW",
            "description": "Validation testing description",
            "execution_mode": "DRY_RUN_SAFE_MODE",
            "ordered_steps": [],
            "actions": [],
            "execution_steps": []
        }

    def test_unsupported_action_type(self):
        fpath = os.path.join(self.temp_dir, "bad_act.yaml")
        pb_data = self._get_base_playbook_dict()
        pb_data["actions"] = [{"type": "DROP_DATABASE_UNSUPPORTED", "name": "Dangerous Action"}]
        self._write_playbook_yaml(fpath, pb_data)

        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbook_file(fpath)
        self.assertIn("Unsupported action type 'DROP_DATABASE_UNSUPPORTED'", str(ctx.exception))

    def test_unsupported_execution_step_type(self):
        fpath = os.path.join(self.temp_dir, "bad_exec_step.yaml")
        pb_data = self._get_base_playbook_dict()
        pb_data["execution_steps"] = [{
            "step_id": "STEP-99",
            "step_name": "Bad Step",
            "action_type": "ARBITRARY_REMOTE_EXECUTION"
        }]
        self._write_playbook_yaml(fpath, pb_data)

        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbook_file(fpath)
        self.assertIn("Unsupported execution-step action_type 'ARBITRARY_REMOTE_EXECUTION'", str(ctx.exception))

    # 7. Threshold Validation (negative, >100, boolean, valid boundary 0 and 100)
    def test_threshold_negative_rejection(self):
        fpath = os.path.join(self.temp_dir, "neg_thresh.yaml")
        pb_data = self._get_base_playbook_dict()
        pb_data["min_risk_score"] = -5
        self._write_playbook_yaml(fpath, pb_data)

        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbook_file(fpath)
        self.assertIn("0 <= min_risk_score <= 100", str(ctx.exception))

    def test_threshold_above_100_rejection(self):
        fpath = os.path.join(self.temp_dir, "above_100.yaml")
        pb_data = self._get_base_playbook_dict()
        pb_data["min_risk_score"] = 105
        self._write_playbook_yaml(fpath, pb_data)

        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbook_file(fpath)
        self.assertIn("0 <= min_risk_score <= 100", str(ctx.exception))

    def test_threshold_boolean_rejection(self):
        fpath_true = os.path.join(self.temp_dir, "bool_true.yaml")
        pb_data_true = self._get_base_playbook_dict()
        pb_data_true["min_risk_score"] = True
        self._write_playbook_yaml(fpath_true, pb_data_true)

        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbook_file(fpath_true)
        self.assertIn("must be a numeric value and not boolean", str(ctx.exception))

        fpath_false = os.path.join(self.temp_dir, "bool_false.yaml")
        pb_data_false = self._get_base_playbook_dict()
        pb_data_false["min_risk_score"] = False
        self._write_playbook_yaml(fpath_false, pb_data_false)

        with self.assertRaises(ValueError) as ctx:
            PlaybookLoader.load_playbook_file(fpath_false)
        self.assertIn("must be a numeric value and not boolean", str(ctx.exception))

    def test_threshold_valid_boundary_values_0_and_100(self):
        fpath_0 = os.path.join(self.temp_dir, "boundary_0.yaml")
        pb_data_0 = self._get_base_playbook_dict()
        pb_data_0["min_risk_score"] = 0
        self._write_playbook_yaml(fpath_0, pb_data_0)
        loaded_0 = PlaybookLoader.load_playbook_file(fpath_0)
        self.assertEqual(loaded_0["min_risk_score"], 0)

        fpath_100 = os.path.join(self.temp_dir, "boundary_100.yaml")
        pb_data_100 = self._get_base_playbook_dict()
        pb_data_100["min_risk_score"] = 100
        self._write_playbook_yaml(fpath_100, pb_data_100)
        loaded_100 = PlaybookLoader.load_playbook_file(fpath_100)
        self.assertEqual(loaded_100["min_risk_score"], 100)


if __name__ == "__main__":
    unittest.main()
