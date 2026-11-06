import json
import os
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime


REQUIRED_FIELDS = [
    "alert_id",
    "timestamp",
    "event_type",
    "source_ip",
    "destination_ip",
    "username",
    "hostname",
    "description",
    "severity",
    "event_source"
]

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}


class AlertProcessor:
    """Handles ingestion, parsing, and validation of incoming security alerts."""

    def __init__(self, audit_logger=None):
        self.audit_logger = audit_logger

    def load_raw_alert_from_file(self, filepath: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """Load raw alert dictionary from a JSON file without validation or normalization."""
        if not os.path.exists(filepath):
            err = f"File not found: {filepath}"
            if self.audit_logger:
                self.audit_logger.log_event("N/A", "INGESTION", "FILE_READ_ERROR", {"path": filepath, "error": err}, level="ERROR")
            return None, [err]

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            err = f"Invalid JSON format in {filepath}: {str(e)}"
            if self.audit_logger:
                self.audit_logger.log_event("N/A", "INGESTION", "JSON_DECODE_ERROR", {"path": filepath, "error": err}, level="ERROR")
            return None, [err]
        except (OSError, UnicodeDecodeError) as e:
            err = f"Error reading {filepath}: {str(e)}"
            if self.audit_logger:
                self.audit_logger.log_event("N/A", "INGESTION", "READ_EXCEPTION", {"path": filepath, "error": err}, level="ERROR")
            return None, [err]

        if not isinstance(data, dict):
            err = f"Invalid alert format in {filepath}: Expected JSON object, got {type(data).__name__}"
            if self.audit_logger:
                self.audit_logger.log_event("N/A", "INGESTION", "SCHEMA_ERROR", {"path": filepath, "error": err}, level="ERROR")
            return None, [err]

        return data, []

    def load_alert_from_file(self, filepath: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """Load and validate an alert from a single JSON file.
        Returns: (alert_dict, list_of_errors_or_warnings)
        """
        data, errors = self.load_raw_alert_from_file(filepath)
        if data is None:
            return None, errors
        return self.validate_and_normalize(data)

    def validate_and_normalize(self, raw_alert: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """Validate alert schema, flag missing fields, and normalize fields."""
        issues: List[str] = []
        normalized: Dict[str, Any] = dict(raw_alert)

        # Check required fields presence and emptiness
        for field in REQUIRED_FIELDS:
            if field not in raw_alert:
                issues.append(f"Missing field: '{field}'")
                normalized[field] = None
            elif raw_alert[field] is None:
                issues.append(f"Null value for required field: '{field}'")
            elif isinstance(raw_alert[field], str) and raw_alert[field].strip() == "":
                issues.append(f"Empty string for required field: '{field}'")

        # Validate severity
        sev = str(raw_alert.get("severity", "")).upper()
        if sev not in VALID_SEVERITIES:
            issues.append(f"Unrecognized severity '{raw_alert.get('severity')}', defaulting to 'MEDIUM'")
            normalized["severity"] = "MEDIUM"
        else:
            normalized["severity"] = sev

        # Validate timestamp format if present
        ts = raw_alert.get("timestamp")
        if ts is not None:
            if not isinstance(ts, str):
                issues.append(f"Invalid timestamp type: expected string, got '{type(ts).__name__}'")
            elif ts.strip() != "":
                try:
                    # Basic ISO format check
                    datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except (ValueError, AttributeError) as e:
                    issues.append(f"Non-standard timestamp format: '{ts}'")

        alert_id = str(normalized.get("alert_id") or "UNKNOWN")
        normalized["data_quality_issues"] = issues
        normalized["has_missing_data"] = len(issues) > 0

        if self.audit_logger:
            if issues:
                self.audit_logger.log_event(
                    alert_id,
                    "INGESTION",
                    "ALERT_INGESTED_WITH_DATA_ISSUES",
                    {"issues": issues, "event_type": normalized.get("event_type")},
                    level="WARNING"
                )
            else:
                self.audit_logger.log_event(
                    alert_id,
                    "INGESTION",
                    "ALERT_INGESTED_CLEAN",
                    {"event_type": normalized.get("event_type"), "severity": normalized.get("severity")}
                )

        return normalized, issues

    def load_alerts_from_directory(self, dirpath: str) -> List[Dict[str, Any]]:
        """Batch load all json alert files in a directory sorted by name."""
        if not os.path.isdir(dirpath):
            return []

        alerts = []
        for filename in sorted(os.listdir(dirpath)):
            if filename.endswith(".json"):
                filepath = os.path.join(dirpath, filename)
                alert, _ = self.load_alert_from_file(filepath)
                if alert:
                    alerts.append(alert)
        return alerts
