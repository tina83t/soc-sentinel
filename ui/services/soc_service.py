"""SOC Service Bridge / Adapter for SOC Sentinel Dashboard.

Connects Streamlit views and UI components to the underlying SOCTriagePipeline
without modifying backend behavior, duplicating business logic, or executing
live response actions.
"""

import os
import re
import json
import hashlib
from typing import List, Dict, Any, Optional, Set

from modules.pipeline import SOCTriagePipeline
from modules.execution_tracer import PlaybookExecutionTrace


class SOCService:
    """Service adapter providing a clean, UI-ready facade over the SOC automation backend.

    Guarantees:
    - Retains a single SOCTriagePipeline instance.
    - Idempotent: Does not create duplicate incidents upon viewing alerts or page reruns.
    - Read-only alert discovery without automatic processing.
    - Safe execution strictly in DRY_RUN_SAFE_MODE.
    - Independent of Streamlit: fully testable with pure standard library.
    """

    DEFAULT_TRUSTED_ACTORS: Set[str] = {
        "ANALYST", "SOC_LEAD", "TIER1_ANALYST", "TIER2_ANALYST", "SEC_ANALYST", "LEAD_ANALYST"
    }

    def __init__(
        self,
        base_dir: str = ".",
        pipeline: Optional[SOCTriagePipeline] = None,
        gemini_analyzer: Optional[Any] = None,
        trusted_analysts: Optional[Any] = None
    ):
        self.base_dir = os.path.abspath(base_dir)
        self.alerts_dir = os.path.join(self.base_dir, "data", "alerts")
        self._pipeline = pipeline or SOCTriagePipeline(base_dir=self.base_dir)

        # Mapping of alert_id -> incident_id to prevent duplicate runs on page reruns
        self._alert_to_incident: Dict[str, str] = {}
        # Mapping of filepath -> alert_id
        self._file_to_alert_id: Dict[str, str] = {}

        self._rebuild_incident_mappings()

        # Trusted analyst identity registry
        if trusted_analysts is not None:
            self.trusted_analysts: Set[str] = {str(a).strip().upper() for a in trusted_analysts}
        else:
            self.trusted_analysts = set(self.DEFAULT_TRUSTED_ACTORS)

        # Optional LLM Advisory Analyzer (Gemini Developer API)
        if gemini_analyzer is not None:
            self.gemini_analyzer = gemini_analyzer
        else:
            from modules.gemini_analyzer import GeminiAlertAnalyzer
            self.gemini_analyzer = GeminiAlertAnalyzer()
        self._gemini_cache: Dict[str, Dict[str, Any]] = {}

    def is_trusted_analyst(self, actor: Optional[str], incident: Optional[Dict[str, Any]] = None) -> bool:
        """Validate whether an actor is a verified analyst.

        Rejects system actors, empty/unknown actors, and arbitrary unverified strings.
        Does not rely on naming pattern heuristics (e.g. prefix matching).
        Accepts explicitly configured trusted analysts or the designated assigned analyst on the incident.
        """
        if not actor or not isinstance(actor, str):
            return False
        clean = actor.strip()
        if not clean:
            return False
        clean_upper = clean.upper()

        # Reject known system / automation actors
        if clean_upper in ("SYSTEM", "MOCK_SIEM", "SIEM_CONNECTOR", "AUTOMATION", "CRON", "UNKNOWN", "GUEST", "ANONYMOUS", "UNVERIFIED"):
            return False

        # Match against assigned analyst on the incident if present
        if incident:
            assigned = str(incident.get("assigned_to") or incident.get("owner") or "").strip()
            if assigned and clean.lower() == assigned.lower():
                return True

        # Match against trusted analyst registry
        return clean_upper in self.trusted_analysts

    def _rebuild_incident_mappings(self) -> None:
        """Rebuild lookup caches from restored incidents in the pipeline."""
        if not hasattr(self.pipeline, "incident_manager") or not self.pipeline.incident_manager:
            return

        for inc in self.pipeline.incident_manager.list_incidents():
            alert_id = inc.get("original_alert_id")
            inc_id = inc.get("incident_id")
            if alert_id and inc_id and alert_id != "UNKNOWN":
                self._alert_to_incident[alert_id] = inc_id

            # Rebuild file mapping only if valid source information was persisted
            source_file = inc.get("source_file") or inc.get("raw_source")
            if source_file and isinstance(source_file, str) and alert_id and alert_id != "UNKNOWN":
                if os.path.exists(source_file):
                    self._file_to_alert_id[os.path.abspath(source_file)] = alert_id
                    self._file_to_alert_id[source_file] = alert_id

    @property
    def pipeline(self) -> SOCTriagePipeline:
        """Access the underlying SOCTriagePipeline instance."""
        return self._pipeline

    # -------------------------------------------------------------------------
    # Alert Discovery & Inspection (Non-Mutating)
    # -------------------------------------------------------------------------

    def list_alert_files(self, alerts_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """Discover available alert files without processing or creating incidents."""
        target_dir = alerts_dir or self.alerts_dir
        if not os.path.isdir(target_dir):
            return []

        files = sorted([f for f in os.listdir(target_dir) if f.endswith(".json")])
        alerts_meta = []

        for fname in files:
            fpath = os.path.join(target_dir, fname)
            raw_data = self.get_alert_raw(fpath)
            if not raw_data:
                continue

            alert_id = str(raw_data.get("alert_id") or "UNKNOWN")
            self._file_to_alert_id[fpath] = alert_id

            associated_inc_id = self._alert_to_incident.get(alert_id)
            if not associated_inc_id:
                # Check if incident already exists in incident_manager from prior runs
                for inc in self.pipeline.incident_manager.list_incidents():
                    if inc.get("original_alert_id") == alert_id:
                        associated_inc_id = inc.get("incident_id")
                        self._alert_to_incident[alert_id] = associated_inc_id
                        break

            alerts_meta.append({
                "filename": fname,
                "filepath": fpath,
                "alert_id": alert_id,
                "timestamp": raw_data.get("timestamp", "N/A"),
                "event_type": raw_data.get("event_type", "Unknown"),
                "severity": str(raw_data.get("severity", "UNKNOWN")).upper(),
                "source_ip": raw_data.get("source_ip"),
                "destination_ip": raw_data.get("destination_ip"),
                "username": raw_data.get("username"),
                "hostname": raw_data.get("hostname"),
                "event_source": raw_data.get("event_source", "Unknown"),
                "description": raw_data.get("description", ""),
                "is_processed": bool(associated_inc_id),
                "incident_id": associated_inc_id
            })

        return alerts_meta

    def get_alert_raw(self, filepath_or_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve raw alert JSON by file path or alert_id without mutating pipeline state."""
        # 1. Check if it's a direct valid file path
        if os.path.isfile(filepath_or_id):
            alert, _ = self.pipeline.alert_processor.load_raw_alert_from_file(filepath_or_id)
            return alert

        # 2. Check if it's a relative path in alerts_dir
        joined_path = os.path.join(self.alerts_dir, filepath_or_id)
        if os.path.isfile(joined_path):
            alert, _ = self.pipeline.alert_processor.load_raw_alert_from_file(joined_path)
            return alert

        # 3. Look up by alert_id in alerts_dir
        if os.path.isdir(self.alerts_dir):
            for fname in os.listdir(self.alerts_dir):
                if fname.endswith(".json"):
                    fpath = os.path.join(self.alerts_dir, fname)
                    alert, _ = self.pipeline.alert_processor.load_raw_alert_from_file(fpath)
                    if alert and alert.get("alert_id") == filepath_or_id:
                        return alert

        return None

    def preview_alert_evaluation(self, filepath_or_id: str) -> Optional[Dict[str, Any]]:
        """Perform a dry-run evaluation of an alert (validation, enrichment, risk score, playbook candidate)

        without executing actions, without modifying history, and without creating an incident.
        """
        raw_alert = self.get_alert_raw(filepath_or_id)
        if not raw_alert:
            return None

        # Perform non-mutating inspection without recording audit events
        from modules.alert_processor import AlertProcessor
        from modules.enrichment import EnrichmentModule
        from modules.risk_engine import RiskScoringEngine

        processor = AlertProcessor(audit_logger=None)
        enricher = EnrichmentModule(
            db_config_path=os.path.join(self.pipeline.config_dir, "enrichment_db.json"),
            audit_logger=None
        )
        risk_engine = RiskScoringEngine(
            rules_config_path=os.path.join(self.pipeline.config_dir, "rules.json"),
            audit_logger=None
        )

        alert_norm, issues = processor.validate_and_normalize(raw_alert)
        enrichment = enricher.enrich(alert_norm)
        risk_result = risk_engine.calculate_score(alert_norm, enrichment)

        # Predict candidate playbook based on risk score from loaded definitions
        score = risk_result["total_risk_score"]
        cand = self.pipeline.playbook_engine.get_playbook_for_score(score)
        candidate_pb = cand["playbook_id"]
        pb_name = cand.get("short_name", cand["name"])
        priority = cand["target_tier"]

        return {
            "alert": alert_norm,
            "validation_issues": issues,
            "enrichment": enrichment,
            "risk_evaluation": risk_result,
            "candidate_playbook": {
                "playbook_id": candidate_pb,
                "playbook_name": pb_name,
                "priority": priority
            }
        }

    # -------------------------------------------------------------------------
    # Pipeline Execution & Processing
    # -------------------------------------------------------------------------

    def process_alert_file(
        self,
        filepath: str,
        show_trace: bool = False,
        force: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Process a single alert file through the existing pipeline.

        If already processed and not force, returns the existing incident to prevent duplication.
        """
        raw_data = self.get_alert_raw(filepath)
        alert_id = raw_data.get("alert_id") if raw_data else None

        if not force and alert_id and alert_id in self._alert_to_incident:
            inc_id = self._alert_to_incident[alert_id]
            existing_inc = self.get_incident(inc_id)
            if existing_inc:
                return existing_inc

        incidents = self.pipeline.process_file(filepath, show_trace=show_trace)
        if incidents:
            incident = incidents[0]
            if alert_id:
                self._alert_to_incident[alert_id] = incident["incident_id"]
            return incident
        return None

    def process_alert_by_id(
        self,
        alert_id: str,
        show_trace: bool = False,
        force: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Locate an alert file by alert_id and execute it through the pipeline."""
        if not os.path.isdir(self.alerts_dir):
            return None

        for fname in sorted(os.listdir(self.alerts_dir)):
            if fname.endswith(".json"):
                fpath = os.path.join(self.alerts_dir, fname)
                raw = self.get_alert_raw(fpath)
                if raw and raw.get("alert_id") == alert_id:
                    return self.process_alert_file(fpath, show_trace=show_trace, force=force)
        return None

    def ingest_from_siem(
        self,
        source_path: Optional[str] = None,
        force: bool = False
    ) -> List[Dict[str, Any]]:
        """Ingest alerts from the mock SIEM feed through the pipeline."""
        return self.pipeline.ingest_from_siem(source_path=source_path, show_trace=False, force=force)

    # -------------------------------------------------------------------------
    # Incident Management Facade (Delegated to IncidentManager)
    # -------------------------------------------------------------------------

    def list_incidents(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List incidents with optional filtering."""
        return self.pipeline.incident_manager.list_incidents(status=status, priority=priority)

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an incident by its unique ID."""
        return self.pipeline.incident_manager.get_incident(incident_id)

    def get_incident_for_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Find the incident generated from a specific alert ID."""
        for inc in self.list_incidents():
            if inc.get("original_alert_id") == alert_id:
                return inc
        return None

    def assign_incident(
        self,
        incident_id: str,
        analyst_id: str,
        actor: Optional[str] = None
    ) -> Dict[str, Any]:
        """Assign or reassign an analyst to an incident."""
        return self.pipeline.incident_manager.assign_incident(
            incident_id=incident_id,
            analyst_id=analyst_id,
            actor=actor
        )

    def update_incident_status(
        self,
        incident_id: str,
        new_status: str,
        actor: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update incident lifecycle status adhering to ALLOWED_TRANSITIONS."""
        return self.pipeline.incident_manager.update_status(
            incident_id=incident_id,
            new_status=new_status,
            actor=actor,
            reason=reason
        )

    def add_incident_note(
        self,
        incident_id: str,
        note: str,
        actor: Optional[str] = None
    ) -> Dict[str, Any]:
        """Add an analyst note to the incident."""
        return self.pipeline.incident_manager.add_note(
            incident_id=incident_id,
            note=note,
            actor=actor
        )

    def resolve_incident(
        self,
        incident_id: str,
        resolution_reason: str,
        verdict: str,
        actor: Optional[str] = None,
        duplicate_of_incident_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Resolve an active incident with structured verdict and optional duplicate reference."""
        return self.pipeline.incident_manager.resolve_incident(
            incident_id=incident_id,
            resolution_reason=resolution_reason,
            verdict=verdict,
            actor=actor,
            duplicate_of_incident_id=duplicate_of_incident_id
        )

    def reopen_incident(
        self,
        incident_id: str,
        reason: str,
        actor: Optional[str] = None
    ) -> Dict[str, Any]:
        """Reopen a resolved or closed incident."""
        return self.pipeline.incident_manager.reopen_incident(
            incident_id=incident_id,
            reason=reason,
            actor=actor
        )

    # -------------------------------------------------------------------------
    # Execution Tracing & Audit History
    # -------------------------------------------------------------------------

    def get_execution_traces(self) -> List[PlaybookExecutionTrace]:
        """Retrieve all execution traces recorded in this pipeline session."""
        return list(self.pipeline.tracer.traces)

    def get_trace_for_alert(self, alert_id: str) -> Optional[PlaybookExecutionTrace]:
        """Retrieve execution trace for a specific alert ID."""
        for trace in reversed(self.pipeline.tracer.traces):
            if trace.alert_id == alert_id:
                return trace
        return None

    def get_audit_history(self, alert_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve audit events from the pipeline's audit logger."""
        if alert_id:
            return self.pipeline.audit_logger.get_alert_history(alert_id)
        return list(self.pipeline.audit_logger.history)

    # -------------------------------------------------------------------------
    # Playbook Catalog & Operational Metrics
    # -------------------------------------------------------------------------

    def get_playbook_catalog(self) -> List[Dict[str, Any]]:
        """Access defined playbook metadata loaded from centralized YAML definitions."""
        return self.pipeline.playbook_engine.get_catalog()

    def get_playbook_by_id(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve playbook details by playbook_id from centralized YAML definitions."""
        return self.pipeline.playbook_engine.get_playbook_by_id(playbook_id)

    def validate_playbook_for_alert(
        self,
        alert_id_or_file: str,
        playbook_id: str
    ) -> Dict[str, Any]:
        """Validate whether a selected playbook can be executed on a given alert.

        Non-mutating: does not create incidents or modify audit logs.
        Checks:
        1. Alert availability and raw payload validity.
        2. Whether the alert has already been processed into an incident.
        3. Evaluates alert risk score & classification via preview.
        4. Compares selected playbook against recommended candidate playbook.
        5. Reports compatibility, unmet conditions, attribute readiness, and execution eligibility.
        """
        raw_alert = self.get_alert_raw(alert_id_or_file)
        if not raw_alert:
            return {
                "valid": False,
                "error": f"Alert '{alert_id_or_file}' could not be found or loaded.",
                "can_execute": False,
                "is_compatible": False,
                "is_already_processed": False,
                "unmet_conditions": ["Alert file not found"],
                "validation_message": "Alert not found."
            }

        alert_id = raw_alert.get("alert_id") or alert_id_or_file
        preview = self.preview_alert_evaluation(alert_id_or_file)
        if not preview:
            return {
                "valid": False,
                "error": f"Evaluation preview failed for alert '{alert_id}'.",
                "can_execute": False,
                "is_compatible": False,
                "is_already_processed": False,
                "unmet_conditions": ["Preview evaluation failed"],
                "validation_message": "Evaluation preview failed."
            }

        pb = self.get_playbook_by_id(playbook_id)
        if not pb:
            return {
                "valid": False,
                "error": f"Playbook '{playbook_id}' is not recognized in catalog.",
                "can_execute": False,
                "is_compatible": False,
                "is_already_processed": False,
                "unmet_conditions": [f"Unrecognized playbook ID: {playbook_id}"],
                "validation_message": "Playbook not found."
            }

        # Check if already processed
        existing_inc = self.get_incident_for_alert(alert_id)
        is_already_processed = bool(existing_inc)
        incident_id = existing_inc.get("incident_id") if existing_inc else None

        score = preview["risk_evaluation"]["total_risk_score"]
        tier = preview["risk_evaluation"]["risk_classification"]
        candidate_pb_id = preview["candidate_playbook"]["playbook_id"]
        candidate_pb_name = preview["candidate_playbook"]["playbook_name"]

        is_compatible = (playbook_id == candidate_pb_id)
        unmet_conditions = []
        if not is_compatible:
            unmet_conditions.append(
                f"Evaluated risk score {score} ({tier}) requires {candidate_pb_id} ('{candidate_pb_name}'), but {playbook_id} requires condition '{pb['condition']}'."
            )

        # Attribute readiness check
        attribute_readiness = {}
        target_host = raw_alert.get("hostname")
        target_user = raw_alert.get("username")
        source_ip = raw_alert.get("source_ip")

        if playbook_id == "PB-CRIT-001":
            attribute_readiness["hostname"] = bool(target_host and target_host != "unknown-host")
            attribute_readiness["username"] = bool(target_user)
        elif playbook_id == "PB-HIGH-002":
            src_info = preview.get("enrichment", {}).get("source_ip_context", {})
            attribute_readiness["source_ip_external"] = bool(source_ip and (src_info.get("is_public") or preview.get("enrichment", {}).get("threat_intelligence")))

        # Execution feasibility
        can_execute = is_compatible and not is_already_processed

        if is_already_processed:
            validation_message = f"Alert '{alert_id}' has already been processed into incident {incident_id}. Duplicate execution blocked."
        elif not is_compatible:
            validation_message = f"Incompatible: Selected playbook {playbook_id} does not match evaluated risk tier ({tier}, score {score}). Recommended: {candidate_pb_id}."
        else:
            validation_message = f"Validated: Alert '{alert_id}' satisfies {playbook_id} trigger condition ('{pb['condition']}') at risk score {score} ({tier})."

        return {
            "valid": True,
            "alert_id": alert_id,
            "playbook_id": playbook_id,
            "playbook_name": pb["name"],
            "target_tier": pb["target_tier"],
            "condition": pb["condition"],
            "risk_score": score,
            "risk_tier": tier,
            "candidate_playbook_id": candidate_pb_id,
            "candidate_playbook_name": candidate_pb_name,
            "is_compatible": is_compatible,
            "is_already_processed": is_already_processed,
            "incident_id": incident_id,
            "can_execute": can_execute,
            "unmet_conditions": unmet_conditions,
            "attribute_readiness": attribute_readiness,
            "warnings": preview.get("validation_issues", []),
            "validation_message": validation_message,
            "preview": preview
        }

    def execute_playbook_workflow(
        self,
        alert_id: str,
        playbook_id: str,
        analyst_confirmed: bool = False
    ) -> Dict[str, Any]:
        """Execute a controlled playbook workflow for an alert after validation and confirmation.

        Guarantees:
        - Requires analyst confirmation.
        - Validates alert-to-playbook compatibility.
        - Prevents duplicate execution if already processed.
        - Preserves DRY_RUN_SAFE_MODE.
        - Returns structured execution results with real incident ID, simulation IDs, and trace steps.
        """
        if not analyst_confirmed:
            return {
                "success": False,
                "error": "Analyst confirmation required before executing response workflow.",
                "executed": False,
                "alert_id": alert_id,
                "playbook_id": playbook_id
            }

        validation = self.validate_playbook_for_alert(alert_id, playbook_id)
        if not validation.get("valid"):
            return {
                "success": False,
                "error": validation.get("error", "Validation failed"),
                "executed": False,
                "alert_id": alert_id,
                "playbook_id": playbook_id
            }

        if validation.get("is_already_processed"):
            return {
                "success": False,
                "error": f"Alert '{alert_id}' was already triaged into incident {validation['incident_id']}. Duplicate execution blocked.",
                "executed": False,
                "alert_id": alert_id,
                "playbook_id": playbook_id,
                "incident_id": validation["incident_id"]
            }

        if not validation.get("is_compatible"):
            return {
                "success": False,
                "error": f"Execution blocked: Incompatible playbook {playbook_id} selected for alert with risk tier {validation['risk_tier']}.",
                "executed": False,
                "alert_id": alert_id,
                "playbook_id": playbook_id,
                "unmet_conditions": validation.get("unmet_conditions", [])
            }

        # Safe execution through pipeline
        incident = self.process_alert_by_id(alert_id, show_trace=False)
        if not incident:
            return {
                "success": False,
                "error": f"Pipeline processing failed to create incident for alert '{alert_id}'.",
                "executed": False,
                "alert_id": alert_id,
                "playbook_id": playbook_id
            }

        # Record explicit human approval evidence in incident notes & audit trail
        inc_id = incident.get("incident_id")
        if inc_id and hasattr(self.pipeline, "incident_manager") and self.pipeline.incident_manager:
            try:
                self.pipeline.incident_manager.add_note(
                    incident_id=inc_id,
                    note=f"Playbook {playbook_id} execution confirmed by analyst (DRY_RUN_SAFE_MODE).",
                    actor="ANALYST"
                )
            except Exception:
                pass

        if hasattr(self.pipeline, "audit_logger") and self.pipeline.audit_logger:
            self.pipeline.audit_logger.log_event(
                alert_id,
                "APPROVAL_GATE",
                "ANALYST_CONFIRMATION",
                {
                    "incident_id": inc_id,
                    "playbook_id": playbook_id,
                    "analyst_confirmed": True,
                    "actor": "ANALYST"
                }
            )

        trace = self.get_trace_for_alert(alert_id)
        sim_actions = incident.get("recommended_responses", [])

        return {
            "success": True,
            "executed": True,
            "alert_id": alert_id,
            "playbook_id": playbook_id,
            "playbook_name": validation["playbook_name"],
            "incident_id": incident.get("incident_id"),
            "incident": incident,
            "status": incident.get("status", "NEW"),
            "priority": incident.get("priority", "LOW"),
            "risk_score": incident.get("risk_score", 0),
            "execution_status": "COMPLETED",
            "execution_mode": "DRY_RUN_SAFE_MODE",
            "trace": trace.to_dict() if trace else None,
            "simulated_actions": sim_actions,
            "simulation_ids": [a.get("simulation_id") for a in sim_actions if a.get("simulation_id")],
            "message": f"Playbook {playbook_id} successfully executed in DRY_RUN_SAFE_MODE. Incident {incident.get('incident_id')} created."
        }

    def get_summary_stats(self) -> Dict[str, Any]:
        """Calculate operational metrics based on discovered alerts and existing incidents."""
        alert_files = self.list_alert_files()
        incidents = self.list_incidents()

        total_alerts = len(alert_files)
        total_incidents = len(incidents)

        critical_alerts = sum(1 for a in alert_files if a.get("severity") == "CRITICAL")
        high_alerts = sum(1 for a in alert_files if a.get("severity") == "HIGH")

        open_incidents = sum(1 for i in incidents if i.get("status") in {"NEW", "IN_PROGRESS"})
        resolved_incidents = sum(1 for i in incidents if i.get("status") in {"RESOLVED", "CLOSED"})

        status_counts = {"NEW": 0, "IN_PROGRESS": 0, "RESOLVED": 0, "CLOSED": 0}
        for inc in incidents:
            st = inc.get("status", "NEW")
            status_counts[st] = status_counts.get(st, 0) + 1

        priority_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for inc in incidents:
            pr = inc.get("priority", "LOW")
            priority_counts[pr] = priority_counts.get(pr, 0) + 1

        return {
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "resolved_incidents": resolved_incidents,
            "status_distribution": status_counts,
            "priority_distribution": priority_counts,
            "traces_count": len(self.get_execution_traces()),
            "audit_events_count": len(self.get_audit_history())
        }

    # -------------------------------------------------------------------------
    # Pipeline Flow & Architecture Inspector
    # -------------------------------------------------------------------------

    def _build_architecture_reference_flow(self) -> Dict[str, Any]:
        """Construct the generic 9-stage reference architecture specification."""
        stages = [
            {
                "stage_num": 1,
                "stage_id": "01_INGESTION",
                "name": "Alert Ingestion",
                "short_explanation": "Loads raw alert telemetry payload from filesystem JSON or mock SIEM feed.",
                "module_component": "modules.alert_processor:AlertProcessor.load_alert_from_file",
                "main_input": "JSON alert file (data/alerts/*.json) or SIEM feed stream (data/siem_feed.json)",
                "main_output": "Raw alert telemetry dictionary (alert_data)",
                "status": "ARCHITECTURE_SPEC",
                "status_label": "Architecture Reference",
                "duration_ms": None,
                "transition_reason": "Proceed to schema validation and quality verification",
                "details": {
                    "source_types": ["Local JSON Files", "Mock SIEM Ingestion Feed"],
                    "data_format": "JSON UTF-8",
                    "error_handling": "File/syntax errors isolated without crashing pipeline"
                }
            },
            {
                "stage_num": 2,
                "stage_id": "02_VALIDATION",
                "name": "Parsing & Schema Validation",
                "short_explanation": "Parses payload attributes, validates 10 required schema fields, and normalizes severity to uppercase.",
                "module_component": "modules.alert_processor:AlertProcessor.validate_and_normalize",
                "main_input": "Raw alert telemetry dictionary",
                "main_output": "Normalized alert record (alert_norm) and data quality issues list",
                "status": "ARCHITECTURE_SPEC",
                "status_label": "Architecture Reference",
                "duration_ms": None,
                "transition_reason": "Proceed to context and threat intelligence enrichment",
                "details": {
                    "required_fields": [
                        "alert_id", "timestamp", "severity", "event_type", "event_source",
                        "source_ip", "destination_ip", "username", "hostname", "description"
                    ],
                    "schema_policy": "Missing fields trigger data quality penalty (-10 risk score)"
                }
            },
            {
                "stage_num": 3,
                "stage_id": "03_ENRICHMENT",
                "name": "Context & Threat Intel Enrichment",
                "short_explanation": "Performs RFC1918 private/public IP classification, queries offline threat intelligence IOCs, and checks identity/host criticality.",
                "module_component": "modules.enrichment:EnrichmentModule.enrich",
                "main_input": "Normalized alert record & offline threat database (config/enrichment_db.json)",
                "main_output": "Contextual enrichment dictionary (source_ip_context, threat_intelligence, is_privileged_user, is_critical_host)",
                "status": "ARCHITECTURE_SPEC",
                "status_label": "Architecture Reference",
                "duration_ms": None,
                "transition_reason": "Proceed to transparent risk evaluation",
                "details": {
                    "ip_classification": "Standard library ipaddress (RFC1918 private vs public routable)",
                    "threat_intel_source": "Offline IOC database matching Tor exit nodes, botnets, and scanner IPs",
                    "identity_checks": "Admin/privileged prefix detection and critical asset registry"
                }
            },
            {
                "stage_num": 4,
                "stage_id": "04_RISK_SCORING",
                "name": "Transparent Risk Scoring",
                "short_explanation": "Calculates additive risk score (0-100) combining base severity, IOC matches, asset sensitivity, and quality penalties.",
                "module_component": "modules.risk_engine:RiskScoringEngine.calculate_score",
                "main_input": "Normalized alert + contextual enrichment indicators (config/rules.json)",
                "main_output": "Risk evaluation dict (total_risk_score, risk_classification tier, triggered_factors)",
                "status": "ARCHITECTURE_SPEC",
                "status_label": "Architecture Reference",
                "duration_ms": None,
                "transition_reason": "Proceed to conditional playbook gate for matched risk tier",
                "details": {
                    "scoring_formula": "Base Score + Threat Intel (+35) + Privileged User (+20) + Critical Host (+25) + Suspicious Pattern (+20) - Data Quality (-10)",
                    "risk_tiers": "CRITICAL (>=80), HIGH (60-79), MEDIUM (30-59), LOW (<30)",
                    "score_bounds": "Deterministic clamp between 0 and 100"
                }
            },
            {
                "stage_num": 5,
                "stage_id": "05_PLAYBOOK_ROUTING",
                "name": "Playbook Selection & Decision Gate",
                "short_explanation": "Evaluates risk tier against declarative YAML playbook conditions (config/playbooks/) to select response workflow.",
                "module_component": "modules.playbook_engine:PlaybookEngine.execute_playbook (modules.playbook_loader:PlaybookLoader)",
                "main_input": "Calculated risk score & tier vs Declarative YAML playbook definitions",
                "main_output": "Matched playbook specification (playbook_id, priority, ordered_steps, simulated_actions)",
                "status": "ARCHITECTURE_SPEC",
                "status_label": "Architecture Reference",
                "duration_ms": None,
                "transition_reason": "Proceed to analyst approval and controlled response execution",
                "details": {
                    "defined_playbooks": ["PB-CRIT-001 (>=80)", "PB-HIGH-002 (60-79)", "PB-MED-003 (30-59)", "PB-LOW-004 (<30)"],
                    "format": "Declarative YAML playbooks loaded with safe PyYAML schema validation"
                }
            },
            {
                "stage_num": 6,
                "stage_id": "06_APPROVAL_GATE",
                "name": "Analyst Approval Gate",
                "short_explanation": "Enforces human-in-the-loop governance: blocks containment execution until an analyst reviews and explicitly confirms.",
                "module_component": "ui.services.soc_service:SOCService.execute_playbook_workflow",
                "main_input": "Target alert ID, selected playbook ID, analyst_confirmed flag",
                "main_output": "Execution authorization (can_execute flag, validation message)",
                "status": "ARCHITECTURE_SPEC",
                "status_label": "Architecture Reference",
                "duration_ms": None,
                "transition_reason": "Proceed to containment action simulation",
                "details": {
                    "governance_rule": "Actions marked approval_required: true in YAML require explicit analyst confirmation",
                    "safeguard": "Execution button in UI is disabled until analyst reviews conditions and confirms"
                }
            },
            {
                "stage_num": 7,
                "stage_id": "07_RESPONSE_SIMULATION",
                "name": "Response Containment Simulation",
                "short_explanation": "Simulates containment actions (firewall blocks, endpoint quarantine) in DRY_RUN_SAFE_MODE with verified command syntax.",
                "module_component": "modules.response_simulator:ResponseSimulator.simulate_action",
                "main_input": "Selected playbook action specifications & target entity parameters",
                "main_output": "Simulated containment actions list with simulation IDs (SIM-*) and CLI syntax",
                "status": "ARCHITECTURE_SPEC",
                "status_label": "Architecture Reference",
                "duration_ms": None,
                "transition_reason": "Assemble formal incident entity and commit record",
                "details": {
                    "supported_actions": ["ANALYST_NOTIFICATION", "ENDPOINT_ISOLATION", "ACCOUNT_SUSPENSION", "IP_BLOCK", "SECURITY_REVIEW_QUEUE"],
                    "safety_guarantee": "Zero live commands dispatched. Parameter validation and syntax modeling only."
                }
            },
            {
                "stage_num": 8,
                "stage_id": "08_INCIDENT_MANAGEMENT",
                "name": "Incident Synthesis & Governance",
                "short_explanation": "Synthesizes alert telemetry into formal incident record (INC-YYYYMMDD-XXXX), tracks 4-state lifecycle, and enforces verdicts.",
                "module_component": "modules.incident_manager:IncidentManager.create_incident",
                "main_input": "Triage results, risk classification, simulated actions, and playbook outcome",
                "main_output": "Persisted incident entity, assigned analyst, chronological history, atomic write to data/incidents.json",
                "status": "ARCHITECTURE_SPEC",
                "status_label": "Architecture Reference",
                "duration_ms": None,
                "transition_reason": "Export incident dossier and commit audit trail",
                "details": {
                    "lifecycle_states": ["NEW", "IN_PROGRESS", "RESOLVED", "CLOSED"],
                    "structured_verdicts": ["TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_POSITIVE", "DUPLICATE"],
                    "persistence": "Atomic standard-library JSON replacement with deep-copy rollback on write failure"
                }
            },
            {
                "stage_num": 9,
                "stage_id": "09_AUDIT_EXPORT",
                "name": "Audit Trail & Dossier Export",
                "short_explanation": "Recursively redacts sensitive credentials, appends to tamper-evident audit log (soc_automation.log), and exports JSON/CSV dossiers.",
                "module_component": "modules.audit_logger:AuditLogger.log_event & modules.reporter:Reporter.export_incident_json",
                "main_input": "Incident entity, execution trace timestamps, credential redaction filter",
                "main_output": "Structured log in logs/soc_automation.log, JSON dossier in reports/, CSV row in incidents_summary.csv",
                "status": "ARCHITECTURE_SPEC",
                "status_label": "Architecture Reference",
                "duration_ms": None,
                "transition_reason": "Workflow successfully terminated",
                "details": {
                    "redaction": "Recursive stripping of passwords, tokens, API keys, and Bearer/Basic headers",
                    "exports": ["Individual JSON Dossier (reports/incident_*.json)", "Consolidated JSON (reports/all_incidents.json)", "Tabular CSV (reports/incidents_summary.csv)"]
                }
            }
        ]

        for s in stages:
            s["summary"] = s.get("short_explanation", "")
            comp = s.get("module_component", "")
            s["module"] = comp.split(":")[0] if ":" in comp else comp
            s["function"] = comp.split(":")[1] if ":" in comp else ""
            s["inputs"] = {"input": s["main_input"]} if not isinstance(s.get("main_input"), dict) else s["main_input"]
            s["outputs"] = {"output": s["main_output"]} if not isinstance(s.get("main_output"), dict) else s["main_output"]

        return {
            "is_specific_alert": False,
            "target_type": "REFERENCE_ARCHITECTURE",
            "total_stages": len(stages),
            "status": "ACTIVE_ARCHITECTURE_SPEC",
            "alert_id": "ARCH-REFERENCE",
            "source_file": None,
            "event_type": "Generic Reference Architecture",
            "severity": "ARCHITECTURE",
            "is_triaged": False,
            "incident_id": None,
            "incident_status": None,
            "verdict": None,
            "risk_score": None,
            "risk_classification": None,
            "playbook_id": "PB-CRIT-001 through PB-LOW-004",
            "playbook_name": "Declarative YAML SOAR Playbook Suite",
            "stages": stages
        }

    def _evaluate_approval_attribution(
        self,
        alert_id: str,
        incident: Optional[Dict[str, Any]],
        raw_alert: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate approval attribution based on recorded evidence rather than assuming it.

        Returns a dictionary with status, status_label, output, and details.
        """
        if not incident:
            return {
                "status": "PENDING",
                "status_label": "Awaiting Analyst Confirmation",
                "output": "Requires Analyst Review & Confirmation",
                "details": {
                    "approval_status": "PENDING_REVIEW",
                    "governance_mode": "DRY_RUN_SAFE_MODE",
                    "approval_required": True
                }
            }

        # Check for explicit human approval evidence in structured events, history, and notes
        explicit_approval = False
        approver = None

        # 1. Structured audit history (prefer structured events with explicit positive outcome)
        # An event_type of APPROVAL_GATE alone must NEVER establish CONFIRMED.
        # Requires an explicit positive event outcome or analyst_confirmed=True with a verified analyst actor.
        # Rejected, failed, pending, and cancelled gate events must never establish confirmation.
        if hasattr(self.pipeline, "audit_logger") and self.pipeline.audit_logger:
            alert_audit = self.pipeline.audit_logger.get_alert_history(alert_id)
            negative_event_markers = ("REJECT", "FAIL", "PENDING", "CANCEL", "DENI", "HOLD", "DISAPPROV")
            positive_events = ("ANALYST_CONFIRMATION", "PLAYBOOK_APPROVED", "CONTAINMENT_CONFIRMED", "APPROVED", "CONFIRMED")
            for ev in alert_audit:
                ev_type = str(ev.get("event_type") or "").upper()
                ev_name = str(ev.get("event_name") or "").upper()
                ev_actor = str(ev.get("actor") or "").strip()
                ev_details = ev.get("details") if isinstance(ev.get("details"), dict) else {}

                # Actor must be a verified trusted analyst
                if not self.is_trusted_analyst(ev_actor, incident):
                    continue

                # Negative / failed / pending gate events never confirm
                if any(neg in ev_name for neg in negative_event_markers):
                    continue
                if ev_details.get("analyst_confirmed") is False:
                    continue

                is_positive = ev_name in positive_events
                has_confirmed_flag = ev_details.get("analyst_confirmed") is True

                if (ev_type == "APPROVAL_GATE" and (is_positive or has_confirmed_flag)) or is_positive:
                    explicit_approval = True
                    approver = ev_actor
                    break

        # 2. Structured incident history
        if not explicit_approval:
            for h in incident.get("history", []):
                h_actor = str(h.get("actor") or "").strip()
                h_action = str(h.get("action") or "").upper()
                if not self.is_trusted_analyst(h_actor, incident):
                    continue
                if h_action in ("APPROVED", "CONFIRMED", "ANALYST_CONFIRMATION"):
                    explicit_approval = True
                    approver = h_actor
                    break

        # 3. Incident notes evaluation (chronological & conflicting evidence resolution)
        # The latest valid human determination governs provenance.
        # A later rejection, cancellation or revocation must invalidate an earlier approval.
        # Safe word-boundary matching on 'hold' prevents collisions with 'threshold', 'withhold', 'placeholder', 'uphold'.
        negative_contextual_phrases = (
            "not approved", "do not approve", "don't approve", "rejected",
            "denied", "awaiting", "pending", "cancelled", "canceled",
            "disapproved", "declined", "on hold", "put on hold", "placed on hold"
        )
        positive_confirmation_phrases = (
            "confirmed by analyst", "analyst confirmed", "execution confirmed",
            "approved for containment", "playbook execution confirmed",
            "approved execution", "containment approved", "confirmed execution",
            "manually approved"
        )

        def check_note_sentiment(text: str) -> Optional[str]:
            """Classify note sentiment as REJECTED, APPROVED, or None."""
            # Word-boundary check for hold avoids collisions with threshold, withhold, placeholder, uphold
            if any(neg in text for neg in negative_contextual_phrases) or re.search(r"\bhold\b", text):
                return "REJECTED"
            if (
                any(pos in text for pos in positive_confirmation_phrases)
                or ("confirmed" in text and "analyst" in text)
                or ("approved" in text and "analyst" in text)
                or text.strip(". ") in ("confirmed", "approved")
            ):
                return "APPROVED"
            return None

        # Inspect notes in documented chronological order
        raw_notes = incident.get("notes", [])
        try:
            sorted_notes = sorted(raw_notes, key=lambda n: str(n.get("timestamp") or ""))
        except Exception:
            sorted_notes = raw_notes

        latest_determination = None
        latest_approver = None

        for note_entry in sorted_notes:
            note_actor = str(note_entry.get("actor") or "").strip()
            note_text = str(note_entry.get("note") or "").lower()

            if not self.is_trusted_analyst(note_actor, incident):
                continue

            sentiment = check_note_sentiment(note_text)
            if sentiment == "REJECTED":
                latest_determination = "REJECTED"
                latest_approver = None
            elif sentiment == "APPROVED":
                latest_determination = "APPROVED"
                latest_approver = note_actor

        if latest_determination == "APPROVED":
            explicit_approval = True
            approver = latest_approver
        elif latest_determination == "REJECTED":
            explicit_approval = False
            approver = None

        if explicit_approval:
            actor_label = f" ({approver})" if approver else ""
            return {
                "status": "CONFIRMED",
                "status_label": "Analyst Confirmed",
                "output": f"Confirmed for Controlled Dry-Run Containment by Analyst{actor_label}",
                "details": {
                    "approval_status": "EXPLICIT_HUMAN_APPROVAL",
                    "approver": approver or "ANALYST",
                    "governance_mode": "DRY_RUN_SAFE_MODE",
                    "approval_enforced": True
                }
            }

        # Check if automated ingestion signature is present
        raw_src = str(incident.get("raw_source") or incident.get("source_file") or "").lower()
        ev_src = str(raw_alert.get("event_source") or "").lower()
        history_actors = [str(h.get("actor") or "").upper() for h in incident.get("history", [])]

        is_automated = (
            "siem" in raw_src
            or "siem" in ev_src
            or "automated" in raw_src
            or (bool(history_actors) and all(a in ("SYSTEM", "MOCK_SIEM", "SIEM_CONNECTOR", "") for a in history_actors))
        )

        if is_automated:
            return {
                "status": "AUTOMATED_POLICY",
                "status_label": "Automated Processing — Human Approval Not Recorded",
                "output": "Automated Policy Execution (Dry-Run Safe Mode) — Interactive Approval Bypassed",
                "details": {
                    "approval_status": "AUTOMATED_PROCESSING",
                    "governance_mode": "DRY_RUN_SAFE_MODE",
                    "notice": "Automated ingestion pipeline — human analyst confirmation was not recorded for this execution."
                }
            }

        # Provenance cannot be established
        return {
            "status": "PROVENANCE_UNKNOWN",
            "status_label": "Approval Provenance Unknown",
            "output": "Incident Triaged — Approval Provenance Cannot Be Established",
            "details": {
                "approval_status": "PROVENANCE_UNKNOWN",
                "warning": "Neither explicit human approval evidence nor automated ingestion signature could be verified."
            }
        }

    def get_pipeline_flow(self, alert_id_or_file: Optional[str] = None) -> Dict[str, Any]:
        """Generate structured metadata for the 9-stage alert processing pipeline.

        Non-mutating: does not create incidents, execute playbooks, or record audit events.
        Can be queried for:
        1. A specific alert (providing real execution or preview status).
        2. Generic reference architecture specification (alert_id_or_file is None).
        """
        if not alert_id_or_file:
            return self._build_architecture_reference_flow()

        raw_alert = self.get_alert_raw(alert_id_or_file)
        if not raw_alert:
            return {
                "error": f"Alert '{alert_id_or_file}' could not be located.",
                "is_specific_alert": True,
                "alert_id": alert_id_or_file,
                "stages": []
            }

        alert_id = raw_alert.get("alert_id") or alert_id_or_file
        source_file = alert_id_or_file if os.path.exists(alert_id_or_file) else None

        incident = self.get_incident_for_alert(alert_id)
        is_triaged = incident is not None
        trace = self.get_trace_for_alert(alert_id)
        trace_steps = {s.step_id: s for s in trace.steps} if trace and hasattr(trace, "steps") else {}

        # Non-mutating evaluation preview
        preview = self.preview_alert_evaluation(alert_id_or_file)
        if preview:
            alert_norm = preview["alert"]
            validation_issues = preview["validation_issues"]
            enrichment = preview["enrichment"]
            risk_eval = preview["risk_evaluation"]
            candidate_pb = preview["candidate_playbook"]
        else:
            alert_norm = raw_alert
            validation_issues = []
            enrichment = {}
            risk_eval = {}
            candidate_pb = {}

        score = incident.get("risk_score", 0) if is_triaged else risk_eval.get("total_risk_score", 0)
        tier = incident.get("priority", "LOW") if is_triaged else risk_eval.get("risk_classification", "LOW")
        pb_id = incident.get("triggered_playbook", {}).get("playbook_id") if is_triaged else candidate_pb.get("playbook_id", "N/A")
        pb_name = incident.get("triggered_playbook", {}).get("playbook_name") if is_triaged else candidate_pb.get("playbook_name", "N/A")

        stages = []

        # Stage 01: Ingestion
        t01 = trace_steps.get("01")
        s1_dur = t01.duration_ms if t01 else None
        if is_triaged:
            s1_status = t01.status if t01 else "COMPLETED"
            s1_label = s1_status.replace("_", " ").title()
        else:
            s1_status = "PREVIEW_EVALUATED"
            s1_label = "Preview Evaluated"

        stages.append({
            "stage_num": 1,
            "stage_id": "01_INGESTION",
            "name": "Alert Ingestion",
            "short_explanation": "Loads raw alert telemetry payload from filesystem JSON or SIEM stream and verifies format.",
            "module_component": "modules.alert_processor:AlertProcessor.load_alert_from_file",
            "main_input": f"Source: {raw_alert.get('event_source', 'JSON File')}",
            "main_output": f"Raw alert telemetry dictionary ({len(raw_alert)} fields)",
            "status": s1_status,
            "status_label": s1_label,
            "duration_ms": s1_dur,
            "transition_reason": "Proceed to schema validation and quality verification",
            "details": {
                "alert_id": alert_id,
                "event_type": raw_alert.get("event_type", "Unknown"),
                "severity": raw_alert.get("severity", "UNKNOWN"),
                "event_source": raw_alert.get("event_source", "Unknown"),
                "timestamp": raw_alert.get("timestamp", "N/A"),
                "source_ip": raw_alert.get("source_ip", "N/A"),
                "destination_ip": raw_alert.get("destination_ip", "N/A"),
                "username": raw_alert.get("username", "N/A"),
                "hostname": raw_alert.get("hostname", "N/A")
            }
        })

        # Stage 02: Parsing & Schema Validation
        t02 = trace_steps.get("02")
        s2_dur = t02.duration_ms if t02 else None
        if is_triaged:
            if t02 and t02.status == "FAILED":
                s2_status = "FAILED"
                s2_label = "Validation Failed"
            elif validation_issues:
                s2_status = "COMPLETED_WITH_WARNINGS"
                s2_label = f"Completed ({len(validation_issues)} Quality Warnings)"
            else:
                s2_status = t02.status if t02 else "COMPLETED"
                s2_label = "Completed (Valid Schema)"
        else:
            if validation_issues:
                s2_status = "PREVIEW_WARNINGS"
                s2_label = f"Preview Evaluated ({len(validation_issues)} Quality Warnings)"
            else:
                s2_status = "PREVIEW_EVALUATED"
                s2_label = "Preview Evaluated (Valid Schema)"

        stages.append({
            "stage_num": 2,
            "stage_id": "02_VALIDATION",
            "name": "Parsing & Schema Validation",
            "short_explanation": "Parses payload attributes, validates 10 required schema fields, and normalizes severity to uppercase.",
            "module_component": "modules.alert_processor:AlertProcessor.validate_and_normalize",
            "main_input": "Raw alert dictionary",
            "main_output": f"Normalized alert record | {len(validation_issues)} quality issue(s)",
            "status": s2_status,
            "status_label": s2_label,
            "duration_ms": s2_dur,
            "transition_reason": "Proceed to context and threat intelligence enrichment",
            "details": {
                "required_schema_fields": 10,
                "validation_issues_count": len(validation_issues),
                "data_quality_issues": validation_issues,
                "normalized_severity": alert_norm.get("severity", "UNKNOWN")
            }
        })

        # Stage 03: Contextual Enrichment
        t03 = trace_steps.get("03")
        s3_dur = t03.duration_ms if t03 else None
        ti = enrichment.get("threat_intelligence")
        s3_output = f"Threat Intel MATCH ({ti.get('matched_ip')})" if ti else "Clean / Unlisted IP"
        if is_triaged:
            s3_status = t03.status if t03 else "COMPLETED"
            s3_label = s3_status.replace("_", " ").title()
        else:
            s3_status = "PREVIEW_EVALUATED"
            s3_label = "Preview Evaluated"

        stages.append({
            "stage_num": 3,
            "stage_id": "03_ENRICHMENT",
            "name": "Context & Threat Intel Enrichment",
            "short_explanation": "Performs RFC1918 private/public IP classification and matches offline IOC database, privileged accounts, and critical assets.",
            "module_component": "modules.enrichment:EnrichmentModule.enrich",
            "main_input": f"IP: {alert_norm.get('source_ip', 'N/A')}, User: {alert_norm.get('username', 'N/A')}, Host: {alert_norm.get('hostname', 'N/A')}",
            "main_output": f"{s3_output} | Classification: {enrichment.get('source_ip_context', {}).get('classification', 'Unknown')}",
            "status": s3_status,
            "status_label": s3_label,
            "duration_ms": s3_dur,
            "transition_reason": "Proceed to transparent risk evaluation",
            "details": {
                "source_ip": alert_norm.get("source_ip"),
                "ip_classification": enrichment.get("source_ip_context", {}).get("classification"),
                "is_public_ip": enrichment.get("source_ip_context", {}).get("is_public"),
                "threat_intel_match": bool(ti),
                "threat_intel_details": ti,
                "is_privileged_user": enrichment.get("is_privileged_user", False),
                "is_critical_host": enrichment.get("is_critical_host", False),
                "suspicious_process_patterns": enrichment.get("suspicious_process_patterns_detected")
            }
        })

        # Stage 04: Risk Assessment & Rule Scoring
        t04 = trace_steps.get("04")
        s4_dur = t04.duration_ms if t04 else None
        if is_triaged:
            s4_status = t04.status if t04 else "COMPLETED"
            s4_label = s4_status.replace("_", " ").title()
        else:
            s4_status = "PREVIEW_EVALUATED"
            s4_label = "Preview Evaluated"

        stages.append({
            "stage_num": 4,
            "stage_id": "04_RISK_SCORING",
            "name": "Transparent Risk Scoring",
            "short_explanation": "Calculates additive risk score (0-100) combining base severity, IOC matches, asset sensitivity, and quality penalties.",
            "module_component": "modules.risk_engine:RiskScoringEngine.calculate_score",
            "main_input": f"Base Severity: {alert_norm.get('severity')} + Enrichment Indicators",
            "main_output": f"Risk Score: {score}/100 | Tier: {tier}",
            "status": s4_status,
            "status_label": s4_label,
            "duration_ms": s4_dur,
            "transition_reason": f"Proceed to conditional playbook gate for '{tier}' tier",
            "details": {
                "base_score": risk_eval.get("base_score"),
                "total_risk_score": score,
                "risk_classification": tier,
                "triggered_factors": risk_eval.get("triggered_factors", [])
            }
        })

        # Stage 05: Playbook Selection & Routing
        t05 = trace_steps.get("05")
        s5_dur = t05.duration_ms if t05 else None
        if is_triaged:
            s5_status = t05.status if t05 else "COMPLETED"
            s5_label = "Executed" if s5_status == "COMPLETED" else s5_status.replace("_", " ").title()
        else:
            s5_status = "PREVIEW_EVALUATED"
            s5_label = "Candidate Selected"

        stages.append({
            "stage_num": 5,
            "stage_id": "05_PLAYBOOK_ROUTING",
            "name": "Playbook Selection & Decision Gate",
            "short_explanation": "Evaluates risk tier against declarative YAML playbook conditions (config/playbooks/) to select response workflow.",
            "module_component": "modules.playbook_engine:PlaybookEngine.execute_playbook",
            "main_input": f"Score {score} ({tier}) vs Playbook Threshold Conditions",
            "main_output": f"Selected Playbook: {pb_id} ({pb_name})",
            "status": s5_status,
            "status_label": s5_label,
            "duration_ms": s5_dur,
            "transition_reason": f"Execute response workflow defined by {pb_id}",
            "details": {
                "playbook_id": pb_id,
                "playbook_name": pb_name,
                "target_tier": tier,
                "min_risk_score": candidate_pb.get("min_risk_score"),
                "is_triaged": is_triaged
            }
        })

        # Stage 06: Analyst Approval Gate (Interactive Governance Gate)
        approval_attribution = self._evaluate_approval_attribution(alert_id, incident, raw_alert)
        stages.append({
            "stage_num": 6,
            "stage_id": "06_APPROVAL_GATE",
            "name": "Analyst Approval Gate",
            "short_explanation": "Enforces human-in-the-loop governance: blocks containment execution until an analyst reviews and explicitly confirms.",
            "module_component": "ui.services.soc_service:SOCService.execute_playbook_workflow",
            "main_input": f"Target: {alert_id}, Playbook: {pb_id}, Analyst Confirmation Flag",
            "main_output": approval_attribution["output"],
            "status": approval_attribution["status"],
            "status_label": approval_attribution["status_label"],
            "duration_ms": None,
            "transition_reason": "Proceed to containment action simulation",
            "details": approval_attribution["details"]
        })

        # Stage 07: Response Containment Simulation & System Transparency Node (Tracer Steps 06 & 07)
        t06 = trace_steps.get("06")
        s7_dur = t06.duration_ms if t06 else None
        if is_triaged:
            sim_actions = incident.get("recommended_responses", [])
            if t06 and t06.status == "FAILED":
                s7_status = "FAILED"
                s7_label = "Simulation Failed"
            else:
                s7_status = "SIMULATED_SUCCESS"
                s7_label = "Simulated Success"
            s7_output = f"{len(sim_actions)} action(s) simulated in DRY_RUN_SAFE_MODE (Zero live changes)"
        else:
            sim_actions = []
            s7_status = "PENDING"
            s7_label = "Pending Execution"
            s7_output = "Queued for dry-run simulation upon execution"

        # Integrate System Transparency Node (Tracer Step 07)
        if "07" in trace_steps:
            t07 = trace_steps["07"]
            transparency_node = {
                "step_id": "07",
                "name": t07.name,
                "status": t07.status,
                "module_fn": t07.module_fn,
                "summary": t07.result_summary,
                "details": t07.details
            }
        else:
            transparency_node = {
                "step_id": "07",
                "name": "Advanced Integration Guardrails",
                "status": "NOT IMPLEMENTED" if is_triaged else "ARCHITECTURE_SPEC",
                "module_fn": "N/A (System Transparency Node)",
                "summary": "AI Triage, SMTP Dispatch, and ITSM Sync not implemented",
                "details": {
                    "unimplemented_feature": True,
                    "notice": "AI root-cause analysis, direct SMTP email dispatch, and ITSM ticketing sync are NOT IMPLEMENTED (offline standard library prototype)"
                }
            }

        stages.append({
            "stage_num": 7,
            "stage_id": "07_RESPONSE_SIMULATION",
            "name": "Response Containment Simulation",
            "short_explanation": "Simulates containment actions (firewall blocks, endpoint quarantine) in DRY_RUN_SAFE_MODE with verified command syntax.",
            "module_component": "modules.response_simulator:ResponseSimulator.simulate_action",
            "main_input": f"Action specifications from {pb_id}",
            "main_output": s7_output,
            "status": s7_status,
            "status_label": s7_label,
            "duration_ms": s7_dur,
            "transition_reason": "Assemble formal incident entity and commit record",
            "details": {
                "dry_run_safe_mode": True,
                "tracer_step_id": "06",
                "simulated_actions_count": len(sim_actions),
                "simulated_actions": sim_actions,
                "system_transparency_node": transparency_node
            }
        })

        # Stage 08: Incident Synthesis & Governance (Tracer Step 08)
        t08 = trace_steps.get("08")
        s8_dur = t08.duration_ms if t08 else None
        if is_triaged:
            inc_id = incident.get("incident_id")
            inc_status = incident.get("status", "NEW")
            verdict = incident.get("verdict") or "UNRESOLVED"
            s8_status = t08.status if t08 else "COMPLETED"
            s8_label = f"Active ({inc_status})" if s8_status == "COMPLETED" else s8_status.replace("_", " ").title()
            s8_output = f"Incident: {inc_id} | Status: {inc_status} | Verdict: {verdict}"
        else:
            inc_id = None
            inc_status = None
            verdict = None
            s8_status = "PENDING"
            s8_label = "Pending Triage"
            s8_output = "Pending incident creation upon playbook execution"

        stages.append({
            "stage_num": 8,
            "stage_id": "08_INCIDENT_MANAGEMENT",
            "name": "Incident Synthesis & Governance",
            "short_explanation": "Synthesizes alert telemetry into formal incident record (INC-YYYYMMDD-XXXX), tracks 4-state lifecycle, and enforces verdicts.",
            "module_component": "modules.incident_manager:IncidentManager.create_incident",
            "main_input": "Triage results, risk classification, and containment outcomes",
            "main_output": s8_output,
            "status": s8_status,
            "status_label": s8_label,
            "duration_ms": s8_dur,
            "transition_reason": "Export incident dossier and commit audit trail",
            "details": {
                "tracer_step_id": "08",
                "incident_id": inc_id,
                "status": inc_status,
                "verdict": verdict,
                "duplicate_of": incident.get("duplicate_of") if is_triaged else None,
                "assigned_to": incident.get("assigned_to") if is_triaged else None,
                "history_count": len(incident.get("history", [])) if is_triaged else 0
            }
        })

        # Stage 09: Audit Logging & Dossier Export (Tracer Step 09)
        t09 = trace_steps.get("09")
        s9_dur = t09.duration_ms if t09 else None
        dossier_path = os.path.join(self.base_dir, "reports", f"incident_{inc_id}.json") if inc_id else None
        dossier_exists = os.path.isfile(dossier_path) if dossier_path else False
        audit_log_path = os.path.join(self.base_dir, "logs", "soc_automation.log")
        audit_log_exists = os.path.isfile(audit_log_path)

        if is_triaged:
            if t09 and t09.status == "FAILED":
                s9_status = "FAILED"
                s9_label = "Audit Export Failed"
                s9_output = "Audit logging and dossier export failed during execution"
            elif dossier_exists:
                s9_status = t09.status if t09 else "COMPLETED"
                s9_label = "Completed (Dossier Verified)"
                s9_output = f"Logged to soc_automation.log | Dossier: incident_{inc_id}.json (Verified) | CSV Updated"
            else:
                s9_status = "EXPORT_UNVERIFIED"
                s9_label = "Export Not Verified on Disk"
                s9_output = f"Logged to soc_automation.log | Dossier: incident_{inc_id}.json (NOT VERIFIED ON DISK)"
        else:
            s9_status = "PENDING"
            s9_label = "Pending Triage"
            s9_output = "Pending audit log entry and dossier export"

        stages.append({
            "stage_num": 9,
            "stage_id": "09_AUDIT_EXPORT",
            "name": "Audit Trail & Dossier Export",
            "short_explanation": "Recursively redacts sensitive credentials, appends to tamper-evident audit log (soc_automation.log), and exports JSON/CSV dossiers.",
            "module_component": "modules.audit_logger:AuditLogger.log_event & modules.reporter:Reporter.export_incident_json",
            "main_input": "Incident entity, execution trace timestamps, credential redaction filter",
            "main_output": s9_output,
            "status": s9_status,
            "status_label": s9_label,
            "duration_ms": s9_dur,
            "transition_reason": "Workflow successfully terminated",
            "details": {
                "tracer_step_id": "09",
                "audit_log_target": "logs/soc_automation.log",
                "audit_log_verified": audit_log_exists,
                "dossier_file": f"incident_{inc_id}.json" if inc_id else "N/A",
                "dossier_path": dossier_path,
                "dossier_verified_on_disk": dossier_exists,
                "secret_redaction_active": True
            }
        })

        for s in stages:
            s["summary"] = s.get("short_explanation", "")
            comp = s.get("module_component", "")
            s["module"] = comp.split(":")[0] if ":" in comp else comp
            s["function"] = comp.split(":")[1] if ":" in comp else ""
            s["inputs"] = {"input": s["main_input"]} if not isinstance(s.get("main_input"), dict) else s["main_input"]
            s["outputs"] = {"output": s["main_output"]} if not isinstance(s.get("main_output"), dict) else s["main_output"]

        target_type = "TRIAGED_INCIDENT" if is_triaged else "NON_MUTATING_PREVIEW"
        flow_status = "TRIAGED_AND_SIMULATED" if is_triaged else "PENDING_TRIAGE"

        trace_summary = None
        if trace and hasattr(trace, "steps") and trace.steps:
            total_dur = sum(s.duration_ms for s in trace.steps if getattr(s, "duration_ms", None) is not None)
            trace_summary = {
                "total_steps": len(trace.steps),
                "total_duration_ms": round(total_dur, 3),
                "success": getattr(trace, "success", True)
            }

        incident_summary = None
        if incident:
            incident_summary = {
                "incident_id": incident.get("incident_id"),
                "status": incident.get("status"),
                "assigned_analyst": incident.get("assigned_to", "Unassigned"),
                "verdict": incident.get("verdict", "UNRESOLVED")
            }

        return {
            "is_specific_alert": True,
            "target_type": target_type,
            "total_stages": len(stages),
            "status": flow_status,
            "alert_id": alert_id,
            "source_file": source_file,
            "event_type": raw_alert.get("event_type", "Unknown"),
            "severity": raw_alert.get("severity", "UNKNOWN"),
            "is_triaged": is_triaged,
            "trace_summary": trace_summary,
            "incident_summary": incident_summary,
            "incident_id": inc_id if is_triaged else None,
            "incident_status": inc_status if is_triaged else None,
            "verdict": verdict if is_triaged else None,
            "risk_score": score,
            "risk_classification": tier,
            "playbook_id": pb_id,
            "playbook_name": pb_name,
            "stages": stages
        }

    # -------------------------------------------------------------------------
    # Optional LLM Advisory Analyst Insights (Gemini Developer API)
    # -------------------------------------------------------------------------

    @staticmethod
    def compute_alert_content_hash(raw_alert: Optional[Dict[str, Any]]) -> str:
        """Compute deterministic SHA-256 fingerprint (first 16 hex chars) of raw alert content."""
        if not raw_alert or not isinstance(raw_alert, dict):
            return "empty"
        norm_json = json.dumps(raw_alert, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(norm_json.encode("utf-8")).hexdigest()[:16]

    def get_alert_cache_identity(self, alert_id_or_file: str) -> Optional[Dict[str, str]]:
        """Return cache identity dict containing alert_id, model, content_hash, and cache_key."""
        raw_alert = self.get_alert_raw(alert_id_or_file)
        if not raw_alert:
            return None
        alert_id = str(raw_alert.get("alert_id") or "UNKNOWN")
        content_hash = self.compute_alert_content_hash(raw_alert)
        model = self.gemini_analyzer.model if hasattr(self, "gemini_analyzer") and self.gemini_analyzer else "gemini-2.5-flash"
        cache_key = f"{alert_id}:{model}:{content_hash}"
        return {
            "alert_id": alert_id,
            "model": model,
            "content_hash": content_hash,
            "cache_key": cache_key
        }

    def get_gemini_status(self) -> Dict[str, Any]:
        """Return operational configuration status of the Gemini LLM advisor."""
        return {
            "is_configured": self.gemini_analyzer.is_configured,
            "api_key_configured": bool(self.gemini_analyzer.api_key),
            "model": self.gemini_analyzer.model
        }

    def get_gemini_insight_for_pipeline(self, alert_id_or_file: str) -> Optional[Dict[str, Any]]:
        """Return the cached Gemini insight for an alert without triggering a new API call.

        Returns the cached result dict if one exists for this alert and model, or None.
        This is a strictly read-only accessor — it never contacts the Gemini API.
        Enforces strict content-aware hashing: reuses cached results ONLY when a non-empty
        content_hash exactly matches the current alert content hash on disk.
        """
        ident = self.get_alert_cache_identity(alert_id_or_file)
        if not ident:
            return None

        # 1. Primary content-aware cache lookup
        if ident["cache_key"] in self._gemini_cache:
            res = self._gemini_cache[ident["cache_key"]]
            if res and isinstance(res, dict):
                rec_hash = str(res.get("content_hash") or "")
                if rec_hash and rec_hash == ident["content_hash"]:
                    return res

        # 2. Check direct key ONLY if a non-empty content_hash strictly matches
        legacy_key = f"{ident['alert_id']}:{ident['model']}"
        if legacy_key in self._gemini_cache:
            cached = self._gemini_cache[legacy_key]
            if cached and isinstance(cached, dict):
                rec_hash = str(cached.get("content_hash") or "")
                if rec_hash and rec_hash == ident["content_hash"]:
                    return cached

        return None

    def analyze_alert_with_gemini(
        self,
        alert_id_or_file: str,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """Perform an advisory LLM analysis for a given alert using Gemini.

        Non-mutating: does not create incidents, alter risk scores, or record audit events.
        Results are cached per alert content and model to prevent redundant API queries.
        """
        ident = self.get_alert_cache_identity(alert_id_or_file)
        if not ident:
            return {
                "status": "NOT_FOUND",
                "error": f"Alert '{alert_id_or_file}' could not be located.",
                "data": None,
                "model": self.gemini_analyzer.model,
                "cached": False
            }

        preview = self.preview_alert_evaluation(alert_id_or_file)
        if not preview:
            return {
                "status": "EVAL_FAILED",
                "error": f"Preview evaluation failed for alert '{alert_id_or_file}'.",
                "data": None,
                "model": self.gemini_analyzer.model,
                "cached": False
            }

        alert_norm = preview["alert"]
        enrichment = preview["enrichment"]
        risk_eval = preview["risk_evaluation"]
        candidate_pb = preview["candidate_playbook"]

        cache_key = ident["cache_key"]
        content_hash = ident["content_hash"]

        if not force_refresh and cache_key in self._gemini_cache:
            cached_res = dict(self._gemini_cache[cache_key])
            cached_res["cached"] = True
            return cached_res

        result = self.gemini_analyzer.analyze_alert(
            alert_data=alert_norm,
            enrichment_data=enrichment,
            risk_data=risk_eval,
            playbook_data=candidate_pb
        )

        if result.get("status") == "SUCCESS":
            result["cached"] = False
            result["content_hash"] = content_hash
            self._gemini_cache[cache_key] = result

        return result


def get_soc_service(base_dir: str = ".") -> SOCService:
    """Helper factory function to create a SOCService instance."""
    return SOCService(base_dir=base_dir)
