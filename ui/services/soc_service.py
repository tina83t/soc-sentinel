"""SOC Service Bridge / Adapter for SOC Sentinel Dashboard.

Connects Streamlit views and UI components to the underlying SOCTriagePipeline
without modifying backend behavior, duplicating business logic, or executing
live response actions.
"""

import os
import json
from typing import List, Dict, Any, Optional

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

    def __init__(self, base_dir: str = ".", pipeline: Optional[SOCTriagePipeline] = None):
        self.base_dir = os.path.abspath(base_dir)
        self.alerts_dir = os.path.join(self.base_dir, "data", "alerts")
        self._pipeline = pipeline or SOCTriagePipeline(base_dir=self.base_dir)

        # Mapping of alert_id -> incident_id to prevent duplicate runs on page reruns
        self._alert_to_incident: Dict[str, str] = {}
        # Mapping of filepath -> alert_id
        self._file_to_alert_id: Dict[str, str] = {}

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

        # Predict candidate playbook based on risk score
        score = risk_result["total_risk_score"]
        if score >= 80:
            candidate_pb = "PB-CRIT-001"
            pb_name = "Critical Threat Automated Containment & Escalation"
            priority = "CRITICAL"
        elif score >= 60:
            candidate_pb = "PB-HIGH-002"
            pb_name = "High-Priority Incident Review & Perimeter Defense"
            priority = "HIGH"
        elif score >= 30:
            candidate_pb = "PB-MED-003"
            pb_name = "Medium-Severity Triage & Telemetry Verification"
            priority = "MEDIUM"
        else:
            candidate_pb = "PB-LOW-004"
            pb_name = "Low-Risk Telemetry Noise Reduction & Auto-Archive"
            priority = "LOW"

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
        actor: Optional[str] = None
    ) -> Dict[str, Any]:
        """Resolve an active incident."""
        return self.pipeline.incident_manager.resolve_incident(
            incident_id=incident_id,
            resolution_reason=resolution_reason,
            actor=actor
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
        """Access defined playbook metadata, trigger conditions, required attributes, and simulated actions."""
        return [
            {
                "playbook_id": "PB-CRIT-001",
                "name": "PB-CRIT-001: Critical Threat Automated Containment & Escalation",
                "target_tier": "CRITICAL",
                "condition": "risk_score >= 80",
                "description": "Triggered by critical indicators (high-confidence TI match, brute force, C2). Dispatches on-call analyst, recommends automated host network isolation and account lock.",
                "purpose": "Rapidly contain confirmed high-risk endpoint compromises, isolate active threats, and escalate immediately to Tier-2 incident responders.",
                "execution_mode": "DRY_RUN_SAFE_MODE",
                "required_attributes": [
                    {"attribute": "hostname", "role": "Endpoint Isolation Target", "required": False, "fallback": "Isolation skipped if missing or unknown-host"},
                    {"attribute": "username", "role": "Account Suspension Target", "required": False, "fallback": "Suspension skipped if missing"},
                    {"attribute": "alert_id", "role": "Correlation Identifier", "required": True, "fallback": "Schema validation failure"}
                ],
                "ordered_steps": [
                    {"step_num": 1, "name": "Evaluate Risk Score & Routing Condition", "type": "AUTOMATED EVALUATION", "target": "Rule Engine", "approval_required": False, "description": "Verify risk score meets Critical threshold (>=80)."},
                    {"step_num": 2, "name": "Dispatch Critical Alert to On-Call Analyst", "type": "ANALYST DISPATCH", "target": "SOC_ON_CALL_TIER2", "approval_required": False, "description": "Trigger urgent pager notification to Tier-2 queue."},
                    {"step_num": 3, "name": "Simulate Host Endpoint Network Isolation", "type": "SIMULATED CONTAINMENT", "target": "alert.hostname", "approval_required": True, "description": "Simulate network isolation command via EDR console."},
                    {"step_num": 4, "name": "Simulate User Account Suspension", "type": "SIMULATED CONTAINMENT", "target": "alert.username", "approval_required": True, "description": "Simulate account lock and ticket revocation in Active Directory."}
                ],
                "safety_requirements": "DRY_RUN_SAFE_MODE active. Endpoint isolation and account suspension are simulated; live infrastructure is never modified.",
                "expected_outcome": "Critical incident generated with status 'NEW'. Tier-2 analyst notified. Host isolation and account suspension queued in SIMULATED_PENDING_APPROVAL status.",
                "actions": [
                    {"type": "ANALYST_NOTIFICATION", "name": "SOC Analyst Escalation Dispatch", "approval_required": False},
                    {"type": "ENDPOINT_ISOLATION", "name": "Simulated Endpoint Network Isolation", "approval_required": True},
                    {"type": "ACCOUNT_SUSPENSION", "name": "Simulated Account Lock / Revocation", "approval_required": True}
                ]
            },
            {
                "playbook_id": "PB-HIGH-002",
                "name": "PB-HIGH-002: High-Priority Incident Review & Perimeter Defense",
                "target_tier": "HIGH",
                "condition": "60 <= risk_score < 80",
                "description": "Triggered by high-severity anomalies, privileged account anomalies, or persistent inbound traffic. Requests Tier-1 review and perimeter firewall block.",
                "purpose": "Halt persistent external scanning or suspicious access by queuing perimeter firewall drop rules and enqueuing for prompt analyst triage.",
                "execution_mode": "DRY_RUN_SAFE_MODE",
                "required_attributes": [
                    {"attribute": "source_ip", "role": "Perimeter IP Block Target", "required": False, "fallback": "Block skipped if private RFC1918 or unlisted"},
                    {"attribute": "alert_id", "role": "Correlation Identifier", "required": True, "fallback": "Schema validation failure"}
                ],
                "ordered_steps": [
                    {"step_num": 1, "name": "Evaluate Risk Score & Routing Condition", "type": "AUTOMATED EVALUATION", "target": "Rule Engine", "approval_required": False, "description": "Verify risk score meets High threshold (60-79)."},
                    {"step_num": 2, "name": "Request Tier-1 Analyst Review", "type": "ANALYST DISPATCH", "target": "SOC_TIER1_QUEUE", "approval_required": False, "description": "Place alert in high-priority review queue for prompt analyst evaluation."},
                    {"step_num": 3, "name": "Simulate Perimeter Firewall IP Block", "type": "SIMULATED CONTAINMENT", "target": "alert.source_ip", "approval_required": True, "description": "Simulate perimeter firewall drop rule for external source IP (TTL: 86400s)."}
                ],
                "safety_requirements": "DRY_RUN_SAFE_MODE active. Perimeter firewall block simulated with TTL 86400s. Zero live firewall changes.",
                "expected_outcome": "High-priority incident generated with status 'NEW'. Analyst review queued. Firewall block recommendation queued.",
                "actions": [
                    {"type": "ANALYST_NOTIFICATION", "name": "Request Tier-1 Analyst Review", "approval_required": False},
                    {"type": "IP_BLOCK", "name": "Simulated Perimeter Firewall IP Block", "approval_required": True}
                ]
            },
            {
                "playbook_id": "PB-MED-003",
                "name": "PB-MED-003: Medium-Severity Triage & Telemetry Verification",
                "target_tier": "MEDIUM",
                "condition": "30 <= risk_score < 60",
                "description": "Triggered by suspicious but non-confirmed events or schema quality penalties. Enqueues for standard SLA investigation.",
                "purpose": "Route ambiguous or degraded-telemetry alerts to the standard triage queue for verification without initiating containment.",
                "execution_mode": "DRY_RUN_SAFE_MODE",
                "required_attributes": [
                    {"attribute": "alert_id", "role": "Correlation Identifier", "required": True, "fallback": "Schema validation failure"}
                ],
                "ordered_steps": [
                    {"step_num": 1, "name": "Evaluate Risk Score & Routing Condition", "type": "AUTOMATED EVALUATION", "target": "Rule Engine", "approval_required": False, "description": "Verify risk score meets Medium threshold (30-59)."},
                    {"step_num": 2, "name": "Place Alert in Standard Triage Queue", "type": "QUEUE ASSIGNMENT", "target": "STANDARD_INVESTIGATION_QUEUE", "approval_required": False, "description": "Assign alert to standard investigation queue (SLA: 4h)."}
                ],
                "safety_requirements": "Standard queue assignment. No containment or host modification simulated.",
                "expected_outcome": "Medium-severity incident generated with status 'NEW'. Enqueued for standard analyst investigation.",
                "actions": [
                    {"type": "SECURITY_REVIEW_QUEUE", "name": "Standard Queue Assignment", "approval_required": False}
                ]
            },
            {
                "playbook_id": "PB-LOW-004",
                "name": "PB-LOW-004: Low-Risk Telemetry Noise Reduction & Auto-Archive",
                "target_tier": "LOW",
                "condition": "risk_score < 30",
                "description": "Triggered by benign, routine, or low-severity events. Suppresses noise, auto-resolves, and writes to baseline audit logs.",
                "purpose": "Suppress alert fatigue by automatically verifying routine system activity and archiving telemetry to audit history.",
                "execution_mode": "DRY_RUN_SAFE_MODE",
                "required_attributes": [
                    {"attribute": "alert_id", "role": "Correlation Identifier", "required": True, "fallback": "Schema validation failure"}
                ],
                "ordered_steps": [
                    {"step_num": 1, "name": "Evaluate Risk Score & Routing Condition", "type": "AUTOMATED EVALUATION", "target": "Rule Engine", "approval_required": False, "description": "Verify risk score falls below 30."},
                    {"step_num": 2, "name": "Store Analysis Results & Update Telemetry Baselines", "type": "AUTO-LOGGING", "target": "Audit History", "approval_required": False, "description": "Store results in tamper-evident log and mark disposition AUTO_RESOLVED_INFORMATIONAL."}
                ],
                "safety_requirements": "Informational logging only. Zero response actions dispatched.",
                "expected_outcome": "Low-priority incident generated with disposition AUTO_RESOLVED_INFORMATIONAL.",
                "actions": []
            }
        ]

    def get_playbook_by_id(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve playbook details by playbook_id."""
        for pb in self.get_playbook_catalog():
            if pb["playbook_id"] == playbook_id:
                return pb
        return None

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


def get_soc_service(base_dir: str = ".") -> SOCService:
    """Helper factory function to create a SOCService instance."""
    return SOCService(base_dir=base_dir)
