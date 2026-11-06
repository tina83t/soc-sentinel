import unittest
import tempfile
import json
import os
from modules.alert_processor import AlertProcessor


class TestAlertProcessor(unittest.TestCase):

    def setUp(self):
        self.processor = AlertProcessor()

    def test_valid_alert_passes(self):
        valid = {
            "alert_id": "ALT-999",
            "timestamp": "2026-11-02T10:00:00Z",
            "event_type": "Test Event",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.1",
            "username": "user1",
            "hostname": "host-01",
            "description": "Standard test event description",
            "severity": "HIGH",
            "event_source": "Test SIEM"
        }
        normalized, issues = self.processor.validate_and_normalize(valid)
        self.assertEqual(len(issues), 0)
        self.assertFalse(normalized["has_missing_data"])
        self.assertEqual(normalized["severity"], "HIGH")

    def test_missing_and_empty_fields_detected(self):
        incomplete = {
            "alert_id": "ALT-INCOMPLETE",
            "severity": "LOW",
            "source_ip": "",
            "destination_ip": None
            # missing timestamp, event_type, username, hostname, description, event_source
        }
        normalized, issues = self.processor.validate_and_normalize(incomplete)
        self.assertTrue(normalized["has_missing_data"])
        self.assertTrue(any("Missing field: 'timestamp'" in issue for issue in issues))
        self.assertTrue(any("Empty string for required field: 'source_ip'" in issue for issue in issues))
        self.assertTrue(any("Null value for required field: 'destination_ip'" in issue for issue in issues))

    def test_invalid_json_handling(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            f.write("{ invalid_json: true, ")
            temp_path = f.name

        try:
            alert, errors = self.processor.load_alert_from_file(temp_path)
            self.assertIsNone(alert)
            self.assertTrue(any("Invalid JSON format" in e for e in errors))
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_file_not_found(self):
        alert, errors = self.processor.load_alert_from_file("non_existent_alert.json")
        self.assertIsNone(alert)
        self.assertTrue(any("File not found" in e for e in errors))

    def test_load_raw_alert_from_file(self):
        valid = {
            "alert_id": "ALT-RAW-01",
            "timestamp": "2026-11-02T10:00:00Z",
            "event_type": "Test Event",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "username": "user",
            "hostname": "host",
            "description": "Raw alert",
            "severity": "high",
            "event_source": "SIEM"
        }
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            json.dump(valid, f)
            temp_path = f.name

        try:
            raw_data, errors = self.processor.load_raw_alert_from_file(temp_path)
            self.assertEqual(len(errors), 0)
            self.assertIsNotNone(raw_data)
            self.assertNotIn("data_quality_issues", raw_data)
            self.assertEqual(raw_data["severity"], "high")  # Not yet normalized to uppercase
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_timestamp_validation_varieties(self):
        # Invalid string timestamp
        res1, issues1 = self.processor.validate_and_normalize({"timestamp": "invalid-time", "severity": "LOW"})
        self.assertTrue(any("Non-standard timestamp format" in i for i in issues1))

        # Non-string timestamp
        res2, issues2 = self.processor.validate_and_normalize({"timestamp": 12345678, "severity": "LOW"})
        self.assertTrue(any("Invalid timestamp type" in i for i in issues2))


if __name__ == "__main__":
    unittest.main()
