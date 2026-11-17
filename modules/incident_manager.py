import os
import json
import copy
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set


VALID_STATUSES: Set[str] = {"NEW", "IN_PROGRESS", "RESOLVED", "CLOSED"}

# Valid structured verdicts for incident resolution
VALID_VERDICTS: Set[str] = {
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "BENIGN_POSITIVE",
    "DUPLICATE"
}

# Valid status transitions for the SOC incident lifecycle
ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    "NEW": {"IN_PROGRESS", "RESOLVED", "CLOSED"},
    "IN_PROGRESS": {"RESOLVED", "CLOSED"},
    "RESOLVED": {"CLOSED", "IN_PROGRESS"},
    "CLOSED": {"IN_PROGRESS"},
}


class IncidentManager:
    """Manages creation, structuring, and lifecycle progression of SOC incidents."""

    def __init__(self, audit_logger=None, storage_path: Optional[str] = None):
        self.audit_logger = audit_logger
        self.storage_path = os.path.abspath(storage_path) if storage_path else None
        self._sequence = 1
        self.incidents: Dict[str, Dict[str, Any]] = {}
        if self.storage_path:
            self._load_state()

    def generate_incident_id(self) -> str:
        """Generate structured incident ID formatted as INC-YYYYMMDD-XXXX with collision prevention."""
        today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        today_prefix = f"INC-{today_str}-"
        today_seqs = []
        for inc_id in self.incidents.keys():
            if inc_id.startswith(today_prefix):
                suffix = inc_id[len(today_prefix):]
                if suffix.isdigit():
                    today_seqs.append(int(suffix))

        max_today = max(today_seqs) if today_seqs else 0
        candidate_seq = max(self._sequence, max_today + 1)
        inc_id = f"INC-{today_str}-{candidate_seq:04d}"
        while inc_id in self.incidents:
            candidate_seq += 1
            inc_id = f"INC-{today_str}-{candidate_seq:04d}"

        self._sequence = candidate_seq + 1
        return inc_id

    def _validate_incident_record(self, inc_id: str, record: Any) -> Optional[str]:
        """Validate structural schema and essential field types of a persisted incident record."""
        if not isinstance(record, dict):
            return f"Incident record '{inc_id}' is not a dictionary"

        if record.get("incident_id") != inc_id or not isinstance(record.get("incident_id"), str) or not record.get("incident_id"):
            return f"Incident record '{inc_id}' has missing or mismatched 'incident_id'"

        status = record.get("status")
        if not isinstance(status, str) or status not in VALID_STATUSES:
            return f"Incident record '{inc_id}' has missing or invalid status '{status}'"

        history = record.get("history")
        if not isinstance(history, list):
            return f"Incident record '{inc_id}' 'history' field must be a list"
        for idx, h in enumerate(history):
            if not isinstance(h, dict):
                return f"Incident record '{inc_id}' history[{idx}] must be a dictionary"

        notes = record.get("notes")
        if not isinstance(notes, list):
            return f"Incident record '{inc_id}' 'notes' field must be a list"
        for idx, n in enumerate(notes):
            if not isinstance(n, dict):
                return f"Incident record '{inc_id}' notes[{idx}] must be a dictionary"

        verdict = record.get("verdict")
        if verdict is not None and (not isinstance(verdict, str) or verdict not in VALID_VERDICTS):
            return f"Incident record '{inc_id}' has invalid verdict '{verdict}'"

        for field in (
            "duplicate_of",
            "duplicate_of_incident_id",
            "resolution_reason",
            "resolved_by",
            "resolved_at",
            "closed_at",
            "reopen_reason",
            "assigned_to",
            "owner",
        ):
            val = record.get(field)
            if val is not None and not isinstance(val, str):
                return f"Incident record '{inc_id}' field '{field}' must be a string or None, got {type(val).__name__}"

        return None

    def _load_state(self) -> None:
        """Load and validate persisted incident state from storage_path.

        If the file is malformed or invalid, preserves it as a uniquely timestamped
        .corrupt backup, emits an audit warning, and initializes clean state.
        """
        if not self.storage_path or not os.path.exists(self.storage_path):
            self.incidents = {}
            self._sequence = 1
            return

        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    self._handle_corrupt_file("Storage file is empty")
                    return
                data = json.loads(content)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            self._handle_corrupt_file(f"JSON decode/read error: {e}")
            return

        if not isinstance(data, dict):
            self._handle_corrupt_file("Root object is not a dictionary mapping")
            return

        # Validate sequence metadata if present
        seq_val = data.get("sequence")
        if seq_val is not None:
            if not isinstance(seq_val, int) or isinstance(seq_val, bool) or seq_val < 1:
                self._handle_corrupt_file(f"Root 'sequence' metadata is invalid: {seq_val}")
                return

        incidents_data = data.get("incidents")
        if not isinstance(incidents_data, dict):
            self._handle_corrupt_file("'incidents' field is missing or not a dictionary")
            return

        for inc_id, inc_record in incidents_data.items():
            err = self._validate_incident_record(inc_id, inc_record)
            if err:
                self._handle_corrupt_file(err)
                return

        self.incidents = incidents_data

        # Restore sequence continuity for today's date
        today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        today_prefix = f"INC-{today_str}-"
        today_seqs = [
            int(k[len(today_prefix):])
            for k in self.incidents.keys()
            if k.startswith(today_prefix) and k[len(today_prefix):].isdigit()
        ]
        max_today = max(today_seqs) if today_seqs else 0
        if today_seqs:
            stored_seq = data.get("sequence", 1) if (isinstance(data.get("sequence"), int) and data.get("last_date") == today_str) else 1
            self._sequence = max(stored_seq, max_today + 1)
        else:
            self._sequence = 1

    def _handle_corrupt_file(self, reason: str) -> None:
        """Preserve a corrupt persistence file as a unique timestamped backup and initialize clean state.

        Guarantees:
        - Never overwrites an existing .corrupt backup file.
        - Preserves the original file until backup is verified on disk.
        - Raises a RuntimeError if backup creation fails, preventing subsequent overwrite.
        - Cleans up partial backup artifacts on failure.
        """
        base_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        counter = 0
        fd = None
        backup_path = None

        while True:
            candidate = (
                f"{self.storage_path}.corrupt.{base_timestamp}"
                if counter == 0
                else f"{self.storage_path}.corrupt.{base_timestamp}_{counter}"
            )
            try:
                fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                backup_path = candidate
                break
            except FileExistsError:
                counter += 1
            except OSError as e:
                if self.audit_logger:
                    self.audit_logger.log_event(
                        "SYSTEM",
                        "INCIDENT_PERSISTENCE",
                        "CORRUPT_STORAGE_BACKUP_FAILED",
                        {
                            "storage_path": self.storage_path,
                            "reason": reason,
                            "error": f"Failed to create backup file '{candidate}': {e}"
                        },
                        level="ERROR"
                    )
                raise RuntimeError(
                    f"Failed to preserve corrupt storage file '{self.storage_path}' before initialization: "
                    f"unable to create unique backup file ({e}). Original corrupt file preserved."
                ) from e

        try:
            with open(self.storage_path, "rb") as src_f, os.fdopen(fd, "wb") as dst_f:
                shutil.copyfileobj(src_f, dst_f)
                dst_f.flush()
                os.fsync(dst_f.fileno())
        except Exception as copy_err:
            if backup_path and os.path.exists(backup_path):
                try:
                    os.remove(backup_path)
                except OSError:
                    pass
            if self.audit_logger:
                self.audit_logger.log_event(
                    "SYSTEM",
                    "INCIDENT_PERSISTENCE",
                    "CORRUPT_STORAGE_BACKUP_FAILED",
                    {
                        "storage_path": self.storage_path,
                        "backup_path": backup_path,
                        "reason": reason,
                        "error": str(copy_err)
                    },
                    level="ERROR"
                )
            raise RuntimeError(
                f"Failed to preserve corrupt storage file '{self.storage_path}' to '{backup_path}': {copy_err}. "
                f"Original corrupt file preserved."
            ) from copy_err

        # Backup creation succeeded: remove the original corrupt file
        try:
            os.remove(self.storage_path)
        except OSError:
            pass

        if self.audit_logger:
            self.audit_logger.log_event(
                "SYSTEM",
                "INCIDENT_PERSISTENCE",
                "CORRUPT_STORAGE_RECOVERED",
                {
                    "storage_path": self.storage_path,
                    "backup_path": backup_path,
                    "reason": reason
                },
                level="WARNING"
            )

        self.incidents = {}
        self._sequence = 1

    def _save_state(self) -> None:
        """Atomically persist incident state to storage_path using standard-library JSON.

        NOTE: Operates under a single-process write assumption; does not provide
        distributed multi-process file locking.
        """
        if not self.storage_path:
            return

        storage_dir = os.path.dirname(self.storage_path)
        if storage_dir:
            os.makedirs(storage_dir, exist_ok=True)

        temp_fd, temp_path = tempfile.mkstemp(
            prefix="incidents_",
            suffix=".tmp",
            dir=storage_dir
        )
        try:
            today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
            state_data = {
                "version": 1,
                "last_date": today_str,
                "sequence": self._sequence,
                "incidents": self.incidents
            }
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                json.dump(state_data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_path, self.storage_path)
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            if self.audit_logger:
                self.audit_logger.log_event(
                    "SYSTEM",
                    "INCIDENT_PERSISTENCE",
                    "PERSISTENCE_SAVE_FAILED",
                    {"storage_path": self.storage_path, "error": str(e)},
                    level="ERROR"
                )
            raise IOError(f"Failed to persist incidents to '{self.storage_path}': {e}") from e

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
        prev_sequence = self._sequence
        incident_id = None
        try:
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
                "resolved_by": None,
                "verdict": None,
                "duplicate_of": None,
                "duplicate_of_incident_id": None,
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

            self._save_state()
            return incident_record
        except Exception:
            if incident_id:
                self.incidents.pop(incident_id, None)
            self._sequence = prev_sequence
            raise

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

        backup_incident = copy.deepcopy(incident)
        try:
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

            self._save_state()
            return incident
        except Exception:
            self.incidents[incident_id] = backup_incident
            raise

    def update_status(
        self,
        incident_id: str,
        new_status: str,
        actor: Optional[str] = None,
        reason: Optional[str] = None,
        _auto_save: bool = True
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

        backup_incident = copy.deepcopy(incident)
        try:
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

            if _auto_save:
                self._save_state()
            return incident
        except Exception:
            self.incidents[incident_id] = backup_incident
            raise

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

        backup_incident = copy.deepcopy(incident)
        try:
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

            self._save_state()
            return incident
        except Exception:
            self.incidents[incident_id] = backup_incident
            raise

    def resolve_incident(
        self,
        incident_id: str,
        resolution_reason: str,
        verdict: str,
        actor: Optional[str] = None,
        duplicate_of_incident_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Resolve an active incident with a verified verdict and formal resolution reason."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident '{incident_id}' not found")

        # 1. Validate structured verdict
        if not verdict or not isinstance(verdict, str):
            raise ValueError(
                f"Verdict cannot be empty. Allowed verdicts are: {', '.join(sorted(VALID_VERDICTS))}"
            )

        norm_verdict = verdict.strip().upper()
        if norm_verdict not in VALID_VERDICTS:
            raise ValueError(
                f"Invalid verdict '{verdict}'. Allowed verdicts are: {', '.join(sorted(VALID_VERDICTS))}"
            )

        # 2. Validate resolution reason
        if not resolution_reason or not isinstance(resolution_reason, str) or resolution_reason.strip() == "":
            raise ValueError("Resolution reason cannot be empty")
        clean_reason = resolution_reason.strip()

        # 3. Handle DUPLICATE relationships
        parent_id = None
        if norm_verdict == "DUPLICATE":
            if not duplicate_of_incident_id or not isinstance(duplicate_of_incident_id, str) or duplicate_of_incident_id.strip() == "":
                raise ValueError("Resolution with DUPLICATE verdict requires 'duplicate_of_incident_id'")
            parent_id = duplicate_of_incident_id.strip()
            if parent_id == incident_id:
                raise ValueError(f"Incident cannot be marked as duplicate of itself: '{incident_id}'")
            if parent_id not in self.incidents:
                raise ValueError(f"Referenced duplicate incident '{parent_id}' does not exist")

        clean_actor = actor or "ANALYST"
        now = datetime.now(timezone.utc).isoformat()

        backup_incident = copy.deepcopy(incident)
        try:
            # 4. Status transition
            self.update_status(
                incident_id=incident_id,
                new_status="RESOLVED",
                actor=clean_actor,
                reason=clean_reason,
                _auto_save=False
            )

            incident["verdict"] = norm_verdict
            incident["duplicate_of"] = parent_id
            incident["duplicate_of_incident_id"] = parent_id
            incident["resolved_by"] = clean_actor
            incident["resolution_reason"] = clean_reason
            incident["resolved_at"] = now
            incident["updated_at"] = now

            # Append resolution entry with verdict to history
            history_entry = {
                "timestamp": now,
                "actor": clean_actor,
                "action": "VERDICT_ASSIGNED",
                "details": {
                    "verdict": norm_verdict,
                    "resolution_reason": clean_reason,
                    "duplicate_of": parent_id
                }
            }
            incident["history"].append(history_entry)

            if self.audit_logger:
                self.audit_logger.log_event(
                    incident.get("original_alert_id", "N/A"),
                    "INCIDENT_LIFECYCLE",
                    "INCIDENT_RESOLVED_WITH_VERDICT",
                    {
                        "incident_id": incident_id,
                        "verdict": norm_verdict,
                        "reason": clean_reason,
                        "duplicate_of": parent_id,
                        "actor": clean_actor
                    }
                )

            self._save_state()
            return incident
        except Exception:
            self.incidents[incident_id] = backup_incident
            raise

    def reopen_incident(
        self,
        incident_id: str,
        reason: str,
        actor: Optional[str] = None
    ) -> Dict[str, Any]:
        """Reopen a resolved or closed incident back to IN_PROGRESS, preserving historical decisions."""
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
        clean_actor = actor or "ANALYST"
        now = datetime.now(timezone.utc).isoformat()

        # Capture prior resolution state for historical record
        prev_verdict = incident.get("verdict")
        prev_reason = incident.get("resolution_reason")
        prev_resolved_at = incident.get("resolved_at")
        prev_duplicate_of = incident.get("duplicate_of")

        backup_incident = copy.deepcopy(incident)
        try:
            # Update status back to IN_PROGRESS
            self.update_status(
                incident_id=incident_id,
                new_status="IN_PROGRESS",
                actor=clean_actor,
                reason=f"Reopened: {clean_reason}",
                _auto_save=False
            )

            # Reset active resolution state so re-resolution requires a new verdict
            incident["reopen_reason"] = clean_reason
            incident["verdict"] = None
            incident["duplicate_of"] = None
            incident["duplicate_of_incident_id"] = None
            incident["resolved_at"] = None
            incident["resolution_reason"] = None
            incident["resolved_by"] = None
            incident["updated_at"] = now

            # Append explicit REOPENED entry preserving prior verdict and resolution history
            history_entry = {
                "timestamp": now,
                "actor": clean_actor,
                "action": "REOPENED",
                "details": {
                    "from_status": current_status,
                    "to_status": "IN_PROGRESS",
                    "reopen_reason": clean_reason,
                    "previous_verdict": prev_verdict,
                    "previous_resolution_reason": prev_reason,
                    "previous_resolved_at": prev_resolved_at,
                    "previous_duplicate_of": prev_duplicate_of
                }
            }
            incident["history"].append(history_entry)

            self._save_state()
            return incident
        except Exception:
            self.incidents[incident_id] = backup_incident
            raise

    def close_incident(
        self,
        incident_id: str,
        reason: Optional[str] = None,
        actor: Optional[str] = None
    ) -> Dict[str, Any]:
        """Formally close an incident with full lifecycle validation and persistence."""
        return self.update_status(
            incident_id=incident_id,
            new_status="CLOSED",
            actor=actor,
            reason=reason
        )
