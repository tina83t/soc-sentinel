import unittest
from modules.response_simulator import ResponseSimulator
from modules.playbook_engine import PlaybookEngine


class TestPlaybookEngine(unittest.TestCase):

    def setUp(self):
        self.simulator = ResponseSimulator()
        self.playbook_engine = PlaybookEngine(response_simulator=self.simulator)

    def test_critical_playbook_routing(self):
        alert = {
            "alert_id": "T-PB-01",
            "hostname": "wkst-victim",
            "username": "user1",
            "source_ip": "198.51.100.45"
        }
        enrichment = {"source_ip_context": {"is_public": True}}
        risk_eval = {"total_risk_score": 85, "risk_classification": "CRITICAL"}

        res = self.playbook_engine.execute_playbook(alert, enrichment, risk_eval)
        self.assertIn("PB-CRIT", res["playbook_id"])
        self.assertEqual(res["priority"], "CRITICAL")
        # Critical playbook should generate simulation actions including endpoint isolation
        action_types = [a["action_type"] for a in res["simulated_actions"]]
        self.assertIn("ANALYST_NOTIFICATION", action_types)
        self.assertIn("ENDPOINT_ISOLATION", action_types)
        self.assertIn("ACCOUNT_SUSPENSION", action_types)

        # Ensure all simulation IDs are unique and formatted correctly (SIM-XXXXXX)
        sim_ids = [a["simulation_id"] for a in res["simulated_actions"]]
        self.assertEqual(len(sim_ids), len(set(sim_ids)), f"Duplicate simulation IDs detected: {sim_ids}")
        for s_id in sim_ids:
            self.assertTrue(s_id.startswith("SIM-"))

    def test_low_risk_playbook_routing(self):
        alert = {
            "alert_id": "T-PB-02",
            "hostname": "wkst-hr-01",
            "username": "local_user"
        }
        enrichment = {"source_ip_context": {"is_public": False}}
        risk_eval = {"total_risk_score": 10, "risk_classification": "LOW"}

        res = self.playbook_engine.execute_playbook(alert, enrichment, risk_eval)
        self.assertIn("PB-LOW", res["playbook_id"])
        self.assertEqual(res["priority"], "LOW")
        self.assertEqual(len(res["simulated_actions"]), 0)


if __name__ == "__main__":
    unittest.main()
