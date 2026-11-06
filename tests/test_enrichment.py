import unittest
from modules.enrichment import EnrichmentModule


class TestEnrichmentModule(unittest.TestCase):

    def setUp(self):
        self.enricher = EnrichmentModule(db_config_path="config/enrichment_db.json")

    def test_ip_classification(self):
        # RFC1918 Private
        priv_res = self.enricher._analyze_ip("192.168.1.100")
        self.assertTrue(priv_res["is_private"])
        self.assertFalse(priv_res["is_public"])

        # Public IP
        pub_res = self.enricher._analyze_ip("198.51.100.45")
        self.assertFalse(pub_res["is_private"])
        self.assertTrue(pub_res["is_public"])

        # Invalid IP
        inv_res = self.enricher._analyze_ip("not-an-ip")
        self.assertFalse(inv_res["is_valid"])

        # Null IP
        null_res = self.enricher._analyze_ip(None)
        self.assertFalse(null_res["is_valid"])

    def test_threat_intel_match(self):
        alert = {
            "alert_id": "T-TI-01",
            "source_ip": "198.51.100.45",
            "destination_ip": "10.0.0.1",
            "username": "user1",
            "hostname": "wkst-01",
            "description": "Connection attempt"
        }
        res = self.enricher.enrich(alert)
        self.assertIsNotNone(res["threat_intelligence"])
        self.assertEqual(res["threat_intelligence"]["reputation"], "malicious")

    def test_privileged_user_and_critical_host(self):
        alert = {
            "alert_id": "T-PRIV-01",
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.2",
            "username": "administrator",
            "hostname": "dc01.corp.internal",
            "description": "Logon event"
        }
        res = self.enricher.enrich(alert)
        self.assertTrue(res["is_privileged_user"])
        self.assertTrue(res["is_critical_host"])


if __name__ == "__main__":
    unittest.main()
