"""SOC Alert Triage and Response Orchestration Pipeline.

Coordinates the end-to-end alert processing lifecycle: ingestion, schema validation,
contextual enrichment, transparent risk scoring, conditional playbook execution,
dry-run containment simulation, incident management, and tamper-evident audit logging.
"""

import os
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from modules.audit_logger import AuditLogger
from modules.alert_processor import AlertProcessor
from modules.enrichment import EnrichmentModule
from modules.risk_engine import RiskScoringEngine
from modules.response_simulator import ResponseSimulator
from modules.playbook_engine import PlaybookEngine
from modules.incident_manager import IncidentManager
from modules.reporter import Reporter
from modules.execution_tracer import ExecutionTracer, PlaybookExecutionTrace


class SOCTriagePipeline:
    """End-to-End Orchestrator for SOC Alert Automation."""

    def __init__(self, base_dir: str = "."):
        self.base_dir = base_dir
        self.logs_dir = os.path.join(base_dir, "logs")
        self.reports_dir = os.path.join(base_dir, "reports")
        self.config_dir = os.path.join(base_dir, "config")

        self.audit_logger = AuditLogger(log_dir=self.logs_dir)
        self.alert_processor = AlertProcessor(audit_logger=self.audit_logger)
        self.enrichment = EnrichmentModule(
            db_config_path=os.path.join(self.config_dir, "enrichment_db.json"),
            audit_logger=self.audit_logger
        )
        self.risk_engine = RiskScoringEngine(
            rules_config_path=os.path.join(self.config_dir, "rules.json"),
            audit_logger=self.audit_logger
        )
        self.response_simulator = ResponseSimulator(audit_logger=self.audit_logger)
        self.playbook_engine = PlaybookEngine(
            response_simulator=self.response_simulator,
            audit_logger=self.audit_logger
        )
        self.incident_manager = IncidentManager(audit_logger=self.audit_logger)
        self.reporter = Reporter(reports_dir=self.reports_dir)
        self.tracer = ExecutionTracer()

    def process_single_alert(
        self,
        alert_data: Dict[str, Any],
        source_file: Optional[str] = None,
        show_trace: bool = False
    ) -> Dict[str, Any]:
        """Run full triage lifecycle with verifiable execution tracing for one alert."""
        raw_alert_id = alert_data.get("alert_id") or "UNKNOWN"
        trace = self.tracer.create_trace(alert_id=raw_alert_id, source_file=source_file)

        # Step 01: Ingestion / Data Source
        t0 = time.perf_counter()
        t_start = datetime.now(timezone.utc).isoformat()
        t_end = datetime.now(timezone.utc).isoformat()
        dur = (time.perf_counter() - t0) * 1000
        trace.add_step(
            step_id="01",
            name="Alert Ingestion",
            module_fn="modules.alert_processor:AlertProcessor.load_alert_from_file",
            status="COMPLETED",
            start_time=t_start,
            end_time=t_end,
            duration_ms=dur,
            result_summary=f"Ingested alert telemetry for '{raw_alert_id}'",
            details={
                "raw_source": source_file or "In-Memory Feed",
                "event_source": alert_data.get("event_source", "Unknown"),
                "event_timestamp": alert_data.get("timestamp", "N/A")
            },
            transition_reason="Proceed to schema validation and quality verification"
        )

        # Step 02: Schema Validation & Quality Check
        t0 = time.perf_counter()
        t_start = datetime.now(timezone.utc).isoformat()
        if "data_quality_issues" in alert_data:
            alert_norm = alert_data
            issues = alert_data.get("data_quality_issues", [])
        else:
            alert_norm, issues = self.alert_processor.validate_and_normalize(alert_data)
        t_end = datetime.now(timezone.utc).isoformat()
        dur = (time.perf_counter() - t0) * 1000

        status_02 = "COMPLETED" if not issues else "COMPLETED_WITH_WARNINGS"
        res_02 = "All 10 required schema fields valid" if not issues else f"{len(issues)} data quality issue(s) detected"
        trace.add_step(
            step_id="02",
            name="Schema Validation & Quality Check",
            module_fn="modules.alert_processor:AlertProcessor.validate_and_normalize",
            status=status_02,
            start_time=t_start,
            end_time=t_end,
            duration_ms=dur,
            result_summary=res_02,
            details={
                "issues_count": len(issues),
                "issues": issues
            },
            transition_reason="Proceed to context & threat intelligence enrichment"
        )

        # Step 03: Threat Intelligence & Context Enrichment
        t0 = time.perf_counter()
        t_start = datetime.now(timezone.utc).isoformat()
        enrichment_data = self.enrichment.enrich(alert_norm)
        t_end = datetime.now(timezone.utc).isoformat()
        dur = (time.perf_counter() - t0) * 1000

        ti = enrichment_data.get("threat_intelligence")
        res_03 = f"Enriched: Threat Intel MATCH ({ti.get('matched_ip')})" if ti else "Enriched: Clean / Unlisted IP"
        trace.add_step(
            step_id="03",
            name="Threat Intelligence & Context Enrichment",
            module_fn="modules.enrichment:EnrichmentModule.enrich",
            status="COMPLETED",
            start_time=t_start,
            end_time=t_end,
            duration_ms=dur,
            result_summary=res_03,
            details={
                "source_ip": alert_norm.get("source_ip"),
                "ip_classification": enrichment_data.get("source_ip_context", {}).get("classification"),
                "ti_match": bool(ti),
                "ti_details": ti,
                "privileged_user": enrichment_data.get("is_privileged_user"),
                "username": alert_norm.get("username"),
                "critical_host": enrichment_data.get("is_critical_host"),
                "hostname": alert_norm.get("hostname"),
                "detected_patterns": enrichment_data.get("suspicious_process_patterns_detected"),
                "failed_attempts_count": alert_norm.get("additional_context", {}).get("failed_attempts_count")
            },
            transition_reason="Proceed to transparent risk evaluation"
        )

        # Step 04: Risk Assessment & Rule Scoring
        t0 = time.perf_counter()
        t_start = datetime.now(timezone.utc).isoformat()
        risk_result = self.risk_engine.calculate_score(alert_norm, enrichment_data)
        t_end = datetime.now(timezone.utc).isoformat()
        dur = (time.perf_counter() - t0) * 1000

        score = risk_result["total_risk_score"]
        classification = risk_result["risk_classification"]
        trace.add_step(
            step_id="04",
            name="Risk Assessment & Rule Scoring",
            module_fn="modules.risk_engine:RiskScoringEngine.calculate_score",
            status="COMPLETED",
            start_time=t_start,
            end_time=t_end,
            duration_ms=dur,
            result_summary=f"Score: {score}/100 | Classification: {classification}",
            details={
                "base_severity": alert_norm.get("severity"),
                "base_score": risk_result.get("base_score"),
                "risk_score": score,
                "classification": classification,
                "factors": risk_result.get("triggered_factors", [])
            },
            transition_reason=f"Proceed to conditional playbook gate for '{classification}' tier"
        )

        # Step 05: Playbook Routing & Decision Gate
        t0 = time.perf_counter()
        t_start = datetime.now(timezone.utc).isoformat()
        playbook_result = self.playbook_engine.execute_playbook(alert_norm, enrichment_data, risk_result)
        t_end = datetime.now(timezone.utc).isoformat()
        dur = (time.perf_counter() - t0) * 1000

        pb_id = playbook_result.get("playbook_id")
        pb_name = playbook_result.get("playbook_name")

        trace.add_step(
            step_id="05",
            name="Playbook Routing & Decision Gate",
            module_fn="modules.playbook_engine:PlaybookEngine.execute_playbook",
            status="COMPLETED",
            start_time=t_start,
            end_time=t_end,
            duration_ms=dur,
            result_summary=f"Selected Playbook '{pb_id}'",
            details={
                "condition_evaluated": playbook_result.get("condition_evaluated"),
                "matched_condition": playbook_result.get("matched_condition"),
                "selected_playbook": pb_name,
                "selected_playbook_id": pb_id
            },
            transition_reason=f"Execute response workflow defined by {pb_id}"
        )

        # Step 06: Response Containment Simulation
        t0 = time.perf_counter()
        t_start = datetime.now(timezone.utc).isoformat()
        sim_actions = playbook_result.get("simulated_actions", [])
        t_end = datetime.now(timezone.utc).isoformat()
        dur = (time.perf_counter() - t0) * 1000

        res_06 = f"{len(sim_actions)} action(s) simulated in DRY_RUN_SAFE_MODE" if sim_actions else "No automated mitigation required (Standard / Informational)"
        status_06 = "SIMULATED / PENDING APPROVAL" if any(a.get("approval_required") for a in sim_actions) else "COMPLETED"
        trace.add_step(
            step_id="06",
            name="Response Containment Simulation",
            module_fn="modules.response_simulator:ResponseSimulator.simulate_action",
            status=status_06,
            start_time=t_start,
            end_time=t_end,
            duration_ms=dur,
            result_summary=res_06,
            details={
                "simulated_actions": sim_actions,
                "dry_run_mode": True
            },
            transition_reason="Review unintegrated capabilities and system safeguards"
        )

        # Step 07: System Transparency Node
        t_now = datetime.now(timezone.utc).isoformat()
        trace.add_step(
            step_id="07",
            name="Advanced Integration Guardrails",
            module_fn="N/A (System Transparency Node)",
            status="NOT IMPLEMENTED",
            start_time=t_now,
            end_time=t_now,
            duration_ms=0.0,
            result_summary="AI Triage, SMTP Dispatch, and ITSM Sync not implemented",
            details={
                "unimplemented_feature": True,
                "notice": "AI root-cause analysis, direct SMTP email dispatch, and ITSM ticketing sync are NOT IMPLEMENTED (offline standard library prototype)"
            },
            transition_reason="Assemble formal incident management entity"
        )

        # Step 08: Incident Creation & Record Management
        t0 = time.perf_counter()
        t_start = datetime.now(timezone.utc).isoformat()
        incident = self.incident_manager.create_incident(
            alert=alert_norm,
            enrichment=enrichment_data,
            risk_evaluation=risk_result,
            playbook_result=playbook_result
        )
        t_end = datetime.now(timezone.utc).isoformat()
        dur = (time.perf_counter() - t0) * 1000

        inc_id = incident.get("incident_id")
        trace.add_step(
            step_id="08",
            name="Incident Creation & Record Management",
            module_fn="modules.incident_manager:IncidentManager.create_incident",
            status="COMPLETED",
            start_time=t_start,
            end_time=t_end,
            duration_ms=dur,
            result_summary=f"Incident '{inc_id}' created with status '{incident.get('status')}'",
            details={
                "incident_id": inc_id,
                "priority": incident.get("priority"),
                "status": incident.get("status")
            },
            transition_reason="Export incident dossier and commit audit trail"
        )

        # Step 09: Audit Logging & Dossier Export
        t0 = time.perf_counter()
        t_start = datetime.now(timezone.utc).isoformat()
        json_path = self.reporter.export_incident_json(incident)
        alert_hist = self.audit_logger.get_alert_history(alert_norm.get("alert_id"))
        t_end = datetime.now(timezone.utc).isoformat()
        dur = (time.perf_counter() - t0) * 1000

        trace.add_step(
            step_id="09",
            name="Audit Trail & Dossier Export",
            module_fn="modules.reporter:Reporter.export_incident_json & modules.audit_logger",
            status="COMPLETED",
            start_time=t_start,
            end_time=t_end,
            duration_ms=dur,
            result_summary=f"Dossier exported to {os.path.basename(json_path)} | {len(alert_hist)} audit events",
            details={
                "audit_events_count": len(alert_hist),
                "log_file": self.audit_logger.log_filepath,
                "json_path": json_path
            },
            transition_reason="Workflow successfully terminated"
        )

        trace.finish(playbook_id=pb_id, playbook_name=pb_name)

        if show_trace:
            print(trace.render_terminal())

        return incident

    def process_file(self, filepath: str, show_trace: bool = True) -> List[Dict[str, Any]]:
        """Process a single alert file with end-to-end tracing."""
        if not os.path.exists(filepath):
            err_msg = f"File not found: {filepath}"
            trace = self.tracer.create_trace(alert_id="N/A", source_file=filepath)
            t_now = datetime.now(timezone.utc).isoformat()
            trace.add_step(
                step_id="01",
                name="Alert Ingestion",
                module_fn="modules.alert_processor:AlertProcessor.load_alert_from_file",
                status="FAILED",
                start_time=t_now,
                end_time=t_now,
                duration_ms=0.0,
                result_summary="File could not be found",
                details={"raw_source": filepath},
                error=err_msg,
                transition_reason="Pipeline aborted"
            )
            trace.finish("ABORTED", "Ingestion Failure")
            if show_trace:
                print(trace.render_terminal())
            print(f"[!] {err_msg}")
            return []

        alert, errors = self.alert_processor.load_raw_alert_from_file(filepath)
        if not alert:
            err_msg = errors[0] if errors else "Failed to parse alert JSON"
            trace = self.tracer.create_trace(alert_id="N/A", source_file=filepath)
            t_now = datetime.now(timezone.utc).isoformat()
            trace.add_step(
                step_id="01",
                name="Alert Ingestion",
                module_fn="modules.alert_processor:AlertProcessor.load_alert_from_file",
                status="FAILED",
                start_time=t_now,
                end_time=t_now,
                duration_ms=0.0,
                result_summary="Invalid JSON file",
                details={"raw_source": filepath},
                error=err_msg,
                transition_reason="Pipeline aborted"
            )
            trace.finish("ABORTED", "Ingestion Failure")
            if show_trace:
                print(trace.render_terminal())
            print(f"[!] Failed to parse alert file '{filepath}': {errors}")
            return []

        incident = self.process_single_alert(alert, source_file=filepath, show_trace=show_trace)
        return [incident]

    def process_directory(self, dirpath: str, show_trace: bool = True) -> List[Dict[str, Any]]:
        """Process all alert JSON files in a directory with execution tracing."""
        if not os.path.isdir(dirpath):
            print(f"[!] Directory not found: '{dirpath}'")
            return []

        alert_files = sorted([f for f in os.listdir(dirpath) if f.endswith(".json")])
        if not alert_files:
            print(f"[!] No JSON alert files found in '{dirpath}'")
            return []

        processed_incidents = []
        for filename in alert_files:
            filepath = os.path.join(dirpath, filename)
            incidents = self.process_file(filepath, show_trace=show_trace)
            processed_incidents.extend(incidents)

        # Export consolidated batch reports
        if processed_incidents:
            self.reporter.export_all_incidents_json(processed_incidents)
            self.reporter.export_summary_csv(processed_incidents)

        return processed_incidents
