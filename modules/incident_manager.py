from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set


VALID_STATUSES: Set[str] = {"NEW", "IN_PROGRESS", "RESOLVED", "CLOSED"}

# Valid status transitions for the SOC incident lifecycle
ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    "NEW": {"IN_PROGRESS", "RESOLVED", "CLOSED"},
    "IN_PROGRESS": {"RESOLVED", "CLOSED"},
    "RESOLVED": {"CLOSED", "IN_PROGRESS"},
    "CLOSED": {"IN_PROGRESS"},
}


class IncidentManager:
    """Manages creation, structuring, and lifecycle progression of SOC incidents."""

    def __init__(self, audit_logger=None):
        self.audit_logger = audit_logger
        self._sequence = 1
        self.incidents: Dict[str, Dict[str, Any]] = {}

    def generate_incident_id(self) -> str:
        """Generate structured incident ID formatted as INC-YYYYMMDD-XXXX."""
        today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        inc_id = f"INC-{today_str}-{self._sequence:04d}"
        self._sequence += 1
        return inc_id

    def create_incident(
        self,
        alert: Dict[str, Any],
        enrichment: Dict[str, Any],
        risk_evaluation: Dict[str, Any],
        playbook_result: Dict[str, Any],
        initial_status: str = "NEW",
        actor: Optional[str] = "SYSTEM"
    ) -> Dict[str, Any]:
        """Synthesize alert, enrichment, risk, and playbook results into a formal incident record."""
        incident_id = self.generate_incident_id()
        alert_id = alert.get("alert_id") or "UNKNOWN"
        created_at = datetime.now(timezone.utc).isoformat()

        status = initial_status.strip().upper() if initial_status else "NEW"
        if status not in VALID_STATUSES:
            status = "NEW"

        # Compile findings summary
        findings = []
        if alert.get("has_missing_data"):
            findings.append(f"Data Quality: {len(alert.get('data_quality_issues', []))} missing/unverified field(s)")
        if enrichment.get("threat_intelligence"):
            ti = enrichment["threat_intelligence"]
            findings.append(f"Threat Intel: Matched IP {ti.get('matched_ip')} ({ti.get('threat_category')})")
        if enrichment.get("is_privileged_user"):
            findings.append(f"Identity: Activity involves privileged account '{alert.get('username')}'")
        if enrichment.get("is_critical_host"):
            findings.append(f"Asset: Target host '{alert.get('hostname')}' is designated critical infrastructure")
        if enrichment.get("has_suspicious_process"):
            findings.append(f"Execution: Suspicious process / command pattern detected: {enrichment.get('suspicious_process_patterns_detected')}")
        if enrichment.get("is_brute_force"):
            findings.append(f"Behavior: Repeated authentication failures observed (Count: {enrichment.get('failed_attempts_count', 'multiple')})")
        if not findings:
            findings.append("No active indicators of compromise or policy violations detected.")

        priority = playbook_result.get("priority", "LOW")
        risk_score = risk_evaluation.get("total_risk_score", 0)

        incident_record: Dict[str, Any] = {
            "incident_id": incident_id,
            "original_alert_id": alert_id,
            "created_at": created_at,
            "updated_at": created_at,
            "status": status,
            "incident_status": status,
            "recommended_disposition": playbook_result.get("recommended_status", "N/A"),
            "assigned_to": None,
            "owner": None,
            "resolved_at": None,
            "resolution_reason": None,
            "closed_at": None,
            "reopen_reason": None,
            "notes": [],
            "history": [
                {
                    "timestamp": created_at,
                    "actor": actor or "SYSTEM",
                    "action": "CREATED",
                    "details": {
                        "status": status,
                        "priority": priority,
                        "risk_score": risk_score,
                        "playbook_id": playbook_result.get("playbook_id", "N/A")
                    }
                }
            ],
            "priority": priority,
            "risk_score": risk_score,
            "risk_classification": risk_evaluation.get("risk_classification", "LOW"),
            "event_type": alert.get("event_type"),
            "event_source": alert.get("event_source"),
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
            "username": alert.get("username"),
            "hostname": alert.get("hostname"),
            "analysis_findings": findings,
            "triggered_playbook": {
                "playbook_id": playbook_result.get("playbook_id"),
                "playbook_name": playbook_result.get("playbook_name"),
                "steps_executed_count": len(playbook_result.get("steps_executed", []))
            },
            "recommended_responses": playbook_result.get("simulated_actions", []),
            "playbook_steps": playbook_result.get("steps_executed", []),
            "raw_alert_summary": {
                "description": alert.get("description"),
                "timestamp": alert.get("timestamp"),
                "original_severity": alert.get("severity")
            }
        }

        self.incidents[incident_id] = incident_record

        if self.audit_logger:
            self.audit_logger.log_event(
                alert_id,
                "INCIDENT_MANAGEMENT",
                "INCIDENT_RECORD_CREATED",
                {
                    "incident_id": incident_id,
                    "priority": incident_record["priority"],
                    "risk_score": incident_record["risk_score"],
                    "status": incident_record["status"],
                    "actor": actor or "SYSTEM"
                }
            )

        return incident_record

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an incident by its unique ID."""
        return self.incidents.get(incident_id)

    def list_incidents(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all incidents, optionally filtered by status and/or priority."""
        result = list(self.incidents.values())
        if status:
            norm_status = status.strip().upper()
            result = [i for i in result if i.get("status") == norm_status or i.get("incident_status") == norm_status]
        if priority:
            norm_prio = priority.strip().upper()
            result = [i for i in result if str(i.get("priority", "")).upper() == norm_prio]
        return result

    def assign_incident(
        self,
        incident_id: str,
        analyst_id: str,
        actor: Optional[str] = None
    ) -> Dict[str, Any]:
        """Assign or reassign an incident to a designated analyst."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found")

        if not analyst_id or not isinstance(analyst_id, str) or analyst_id.strip() == "":
            raise ValueError("Analyst identifier cannot be empty")

        clean_analyst = analyst_id.strip()
        previous_assignee = incident.get("assigned_to")
        now = datetime.now(timezone.utc).isoformat()

        incident["assigned_to"] = clean_analyst
        incident["owner"] = clean_analyst
        incident["updated_at"] = now

        action = "REASSIGNED" if previous_assignee else "ASSIGNED"
        history_entry = {
            "timestamp": now,
            "actor": actor or clean_analyst,
            "action": action,
            "details": {
                "assigned_to": clean_analyst,
                "previous_assignee": previous_assignee
            }
        }
        incident["history"].append(history_entry)

        if self.audit_logger:
            self.audit_logger.log_event(
                incident.get("original_alert_id", "N/A"),
                "INCIDENT_LIFECYCLE",
                f"INCIDENT_{action}",
                {
                    "incident_id": incident_id,
                    "assigned_to": clean_analyst,
                    "previous_assignee": previous_assignee,
                    "actor": actor or clean_analyst
                }
            )

        return incident

    def update_status(
        self,
        incident_id: str,
        new_status: str,
        actor: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update incident lifecycle status with strict transition validation."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found")

        if not new_status or not isinstance(new_status, str):
            raise ValueError(f"Invalid status '{new_status}'. Allowed statuses: {', '.join(sorted(VALID_STATUSES))}")

        normalized_status = new_status.strip().upper()
        if normalized_status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status '{new_status}'. Allowed statuses are: {', '.join(sorted(VALID_STATUSES))}"
            )

        current_status = incident.get("status", "NEW")
        if current_status == normalized_status:
            raise ValueError(
                f"Incident '{incident_id}' is already in status '{normalized_status}'"
            )

        allowed = ALLOWED_TRANSITIONS.get(current_status, set())
        if normalized_status not in allowed:
            raise ValueError(
                f"Invalid status transition from '{current_status}' to '{normalized_status}'. "
                f"Allowed transitions from '{current_status}': {', '.join(sorted(allowed)) if allowed else 'None'}"
            )

        now = datetime.now(timezone.utc).isoformat()
        incident["status"] = normalized_status
        incident["incident_status"] = normalized_status
        incident["updated_at"] = now

        if normalized_status == "RESOLVED":
            incident["resolved_at"] = now
            if reason:
                incident["resolution_reason"] = reason
        elif normalized_status == "CLOSED":
            incident["closed_at"] = now
            if reason and not incident.get("resolution_reason"):
                incident["resolution_reason"] = reason

        history_entry = {
            "timestamp": now,
            "actor": actor or "SYSTEM",
            "action": "STATUS_CHANGED",
            "details": {
                "from_status": current_status,
                "to_status": normalized_status,
                "reason": reason
            }
        }
        incident["history"].append(history_entry)

        if self.audit_logger:
            self.audit_logger.log_event(
                incident.get("original_alert_id", "N/A"),
                "INCIDENT_LIFECYCLE",
                "INCIDENT_STATUS_UPDATED",
                {
                    "incident_id": incident_id,
                    "from_status": current_status,
                    "to_status": normalized_status,
                    "actor": actor or "SYSTEM",
                    "reason": reason
                }
            )

        return incident

    def add_note(
        self,
        incident_id: str,
        note: str,
        actor: Optional[str] = None
    ) -> Dict[str, Any]:
        """Add an analyst investigation note to the incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found")

        if not note or not isinstance(note, str) or note.strip() == "":
            raise ValueError("Analyst note cannot be empty")

        clean_note = note.strip()
        now = datetime.now(timezone.utc).isoformat()
        clean_actor = actor or "ANALYST"

        note_entry = {
            "timestamp": now,
            "actor": clean_actor,
            "note": clean_note
        }
        incident["notes"].append(note_entry)
        incident["updated_at"] = now

        history_entry = {
            "timestamp": now,
            "actor": clean_actor,
            "action": "NOTE_ADDED",
            "details": {
                "note_preview": clean_note[:80] + ("..." if len(clean_note) > 80 else "")
            }
        }
        incident["history"].append(history_entry)

        if self.audit_logger:
            self.audit_logger.log_event(
                incident.get("original_alert_id", "N/A"),
                "INCIDENT_LIFECYCLE",
                "INCIDENT_NOTE_ADDED",
                {
                    "incident_id": incident_id,
                    "actor": clean_actor,
                    "note_preview": clean_note[:80]
                }
            )

        return incident

    def resolve_incident(
        self,
        incident_id: str,
        resolution_reason: str,
        actor: Optional[str] = None
    ) -> Dict[str, Any]:
        """Resolve an active incident with a formal resolution reason."""
        if not resolution_reason or not isinstance(resolution_reason, str) or resolution_reason.strip() == "":
            raise ValueError("Resolution reason cannot be empty")

        incident = self.update_status(
            incident_id=incident_id,
            new_status="RESOLVED",
            actor=actor,
            reason=resolution_reason.strip()
        )
        return incident

    def reopen_incident(
        self,
        incident_id: str,
        reason: str,
        actor: Optional[str] = None
    ) -> Dict[str, Any]:
        """Reopen a resolved or closed incident back to IN_PROGRESS."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found")

        current_status = incident.get("status")
        if current_status not in {"RESOLVED", "CLOSED"}:
            raise ValueError(
                f"Cannot reopen incident in status '{current_status}'. "
                f"Reopening is only allowed from 'RESOLVED' or 'CLOSED'."
            )

        if not reason or not isinstance(reason, str) or reason.strip() == "":
            raise ValueError("Reopen reason cannot be empty")

        clean_reason = reason.strip()
        incident["reopen_reason"] = clean_reason

        return self.update_status(
            incident_id=incident_id,
            new_status="IN_PROGRESS",
            actor=actor,
            reason=f"Reopened: {clean_reason}"
        )
