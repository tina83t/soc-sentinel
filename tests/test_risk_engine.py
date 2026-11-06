import unittest
from modules.risk_engine import RiskScoringEngine


class TestRiskEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RiskScoringEngine(rules_config_path="config/rules.json")

    def test_classification_boundaries(self):
        self.assertEqual(self.engine._classify_score(100), "CRITICAL")
        self.assertEqual(self.engine._classify_score(80), "CRITICAL")
        self.assertEqual(self.engine._classify_score(79), "HIGH")
        self.assertEqual(self.engine._classify_score(60), "HIGH")
        self.assertEqual(self.engine._classify_score(59), "MEDIUM")
        self.assertEqual(self.engine._classify_score(30), "MEDIUM")
        self.assertEqual(self.engine._classify_score(29), "LOW")
        self.assertEqual(self.engine._classify_score(0), "LOW")

    def test_no_double_counting(self):
        alert = {
            "alert_id": "T-RISK-01",
            "severity": "MEDIUM",
            "username": "admin",
            "has_missing_data": False
        }
        enrichment = {
            "threat_intelligence": {"reputation": "malicious"},
            "is_privileged_user": True,
            "is_critical_host": False,
            "has_suspicious_process": False,
            "is_brute_force": False,
            "source_ip_context": {"is_public": False}
        }
        res = self.engine.calculate_score(alert, enrichment)
        # Base MEDIUM: 20
        # Threat intel: +30
        # Privileged user: +20
        # Expected: 70 -> HIGH
        factor_ids = [f["factor_id"] for f in res["triggered_factors"]]
        self.assertEqual(len(factor_ids), len(set(factor_ids)), "Factors must be strictly deduplicated")
        self.assertEqual(res["total_risk_score"], 70)
        self.assertEqual(res["risk_classification"], "HIGH")

    def test_score_clamping_at_100(self):
        alert = {
            "alert_id": "T-RISK-MAX",
            "severity": "CRITICAL",
            "username": "root",
            "hostname": "dc01.corp.internal",
            "has_missing_data": True,
            "data_quality_issues": ["Issue 1"]
        }
        enrichment = {
            "threat_intelligence": {"reputation": "malicious"},
            "is_privileged_user": True,
            "is_critical_host": True,
            "has_suspicious_process": True,
            "is_brute_force": True,
            "source_ip_context": {"is_public": True}
        }
        res = self.engine.calculate_score(alert, enrichment)
        self.assertEqual(res["total_risk_score"], 100)
        self.assertEqual(res["risk_classification"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
