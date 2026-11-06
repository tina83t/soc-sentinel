import unittest
import os
import tempfile
import shutil
from modules.execution_tracer import ExecutionTracer, PlaybookExecutionTrace
from main import SOCTriagePipeline


class TestExecutionTracer(unittest.TestCase):

    def setUp(self):
        self.tracer = ExecutionTracer()

    def test_trace_creation_and_steps_recording(self):
        trace = self.tracer.create_trace(alert_id="ALT-TEST-001", source_file="test.json")
        self.assertEqual(trace.alert_id, "ALT-TEST-001")
        self.assertEqual(trace.source_file, "test.json")

        trace.add_step(
            step_id="01",
            name="Alert Ingestion",
            module_fn="modules.alert_processor:AlertProcessor.load_alert_from_file",
            status="COMPLETED",
            start_time="2026-11-02T10:00:00Z",
            end_time="2026-11-02T10:00:00.001Z",
            duration_ms=1.25,
            result_summary="Successfully loaded alert",
            details={"raw_source": "test.json"},
            transition_reason="Proceed to schema validation"
        )
        trace.finish(playbook_id="PB-TEST-001", playbook_name="Test Playbook Workflow")

        self.assertEqual(len(trace.steps), 1)
        step = trace.steps[0]
        self.assertEqual(step.step_id, "01")
        self.assertEqual(step.module_fn, "modules.alert_processor:AlertProcessor.load_alert_from_file")
        self.assertEqual(step.duration_ms, 1.25)
        self.assertEqual(step.transition_reason, "Proceed to schema validation")

        rendered = trace.render_terminal()
        self.assertIn("PLAYBOOK EXECUTION TRACE: PB-TEST-001", rendered)
        self.assertIn("[01] Alert Ingestion", rendered)
        self.assertIn("Duration: 1.25ms", rendered)

    def test_pipeline_integration_produces_real_trace(self):
        temp_dir = tempfile.mkdtemp(prefix="tracer_pipeline_test_")
        try:
            shutil.copytree("config", os.path.join(temp_dir, "config"))
            shutil.copytree("data", os.path.join(temp_dir, "data"))
            pipeline = SOCTriagePipeline(base_dir=temp_dir)

            test_file = os.path.join(temp_dir, "data/alerts/01_failed_logins_suspicious_ip.json")
            incidents = pipeline.process_file(test_file, show_trace=False)
            self.assertEqual(len(incidents), 1)

            latest_trace = pipeline.tracer.get_latest_trace()
            self.assertIsNotNone(latest_trace)
            self.assertEqual(latest_trace.alert_id, "ALT-2026-001")
            self.assertEqual(latest_trace.playbook_id, "PB-CRIT-001")

            step_ids = [s.step_id for s in latest_trace.steps]
            self.assertIn("01", step_ids)
            self.assertIn("02", step_ids)
            self.assertIn("03", step_ids)
            self.assertIn("04", step_ids)
            self.assertIn("05", step_ids)
            self.assertIn("06", step_ids)
            self.assertIn("07", step_ids)
            self.assertIn("08", step_ids)
            self.assertIn("09", step_ids)

            # Check that Step 04 contains real risk scoring factors
            step_04 = next(s for s in latest_trace.steps if s.step_id == "04")
            self.assertEqual(step_04.details["risk_score"], 95)
            self.assertEqual(step_04.details["classification"], "CRITICAL")
            self.assertGreater(len(step_04.details["factors"]), 0)

            # Check that Step 07 marks unimplemented features
            step_07 = next(s for s in latest_trace.steps if s.step_id == "07")
            self.assertEqual(step_07.status, "NOT IMPLEMENTED")

            # Check rendered text
            rendered = latest_trace.render_terminal()
            self.assertIn("PB-CRIT-001", rendered)
            self.assertIn("threat_intel_match", rendered)
            self.assertIn("brute_force_failed_logins", rendered)
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    def test_pipeline_failed_file_trace(self):
        pipeline = SOCTriagePipeline()
        incidents = pipeline.process_file("non_existent_path.json", show_trace=False)
        self.assertEqual(len(incidents), 0)

        latest_trace = pipeline.tracer.get_latest_trace()
        self.assertIsNotNone(latest_trace)
        self.assertEqual(latest_trace.playbook_id, "ABORTED")
        self.assertEqual(latest_trace.steps[0].status, "FAILED")
        self.assertIn("File not found", latest_trace.steps[0].error)


if __name__ == "__main__":
    unittest.main()
