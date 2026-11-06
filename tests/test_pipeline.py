import unittest
import os
import shutil
import tempfile
from modules.pipeline import SOCTriagePipeline
from main import SOCTriagePipeline as MainSOCTriagePipeline


class TestPipelineModule(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="pipeline_test_")
        shutil.copytree("config", os.path.join(self.temp_dir, "config"))
        shutil.copytree("data", os.path.join(self.temp_dir, "data"))
        self.pipeline = SOCTriagePipeline(base_dir=self.temp_dir)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_import_compatibility_between_modules_and_main(self):
        # Verify that SOCTriagePipeline imported from modules.pipeline and from main are identical
        self.assertIs(SOCTriagePipeline, MainSOCTriagePipeline)

    def test_pipeline_process_single_file(self):
        alert_file = os.path.join(self.temp_dir, "data/alerts/01_failed_logins_suspicious_ip.json")
        incidents = self.pipeline.process_file(alert_file, show_trace=False)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc["status"], "NEW")
        self.assertEqual(inc["priority"], "CRITICAL")
        self.assertEqual(inc["risk_score"], 95)

    def test_pipeline_process_directory(self):
        alerts_dir = os.path.join(self.temp_dir, "data/alerts")
        incidents = self.pipeline.process_directory(alerts_dir, show_trace=False)
        self.assertEqual(len(incidents), 5)
        self.assertTrue(os.path.exists(os.path.join(self.pipeline.reports_dir, "all_incidents.json")))
        self.assertTrue(os.path.exists(os.path.join(self.pipeline.reports_dir, "incidents_summary.csv")))

    def test_pipeline_nonexistent_file_and_directory(self):
        incidents_file = self.pipeline.process_file("nonexistent.json", show_trace=False)
        self.assertEqual(incidents_file, [])

        incidents_dir = self.pipeline.process_directory("nonexistent_dir", show_trace=False)
        self.assertEqual(incidents_dir, [])


if __name__ == "__main__":
    unittest.main()
