import json
import os
from typing import Dict, Any, List, Optional, Set

from modules.alert_processor import AlertProcessor


class MockSIEMConnector:
    """Vendor-agnostic mock SIEM connector.

    Reads alert records from a local mock SIEM feed (JSON array, envelope object,
    or directory), validates and normalizes alerts via AlertProcessor, and feeds
    them into the SOCTriagePipeline with in-memory deduplication.
    """

    def __init__(
        self,
        default_source: Optional[str] = None,
        alert_processor: Optional[AlertProcessor] = None,
        audit_logger=None
    ):
        self.default_source = default_source
        self.audit_logger = audit_logger
        self.alert_processor = alert_processor or AlertProcessor(audit_logger=audit_logger)
        self.processed_alert_ids: Set[str] = set()

    def fetch_raw_alerts(self, source_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Read and parse raw alert records from the specified local source.

        Supports:
        - JSON file containing a list of alert objects: [ {...}, {...} ]
        - JSON file with an envelope: {"alerts": [...]}, {"events": [...]}, or {"results": [...]}
        - JSON file containing a single alert object: { ... }
        - Directory containing individual .json alert files.

        Returns a list of raw dictionary records, skipping and safely logging malformed entries.
        """
        path = source_path or self.default_source
        if not path or not os.path.exists(path):
            if self.audit_logger:
                self.audit_logger.log_event(
                    "N/A",
                    "SIEM_CONNECTOR",
                    "SOURCE_NOT_FOUND",
                    {"source_path": path},
                    level="WARNING"
                )
            return []

        raw_records: List[Any] = []

        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if not content:
                        return []
                    data = json.loads(content)
            except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
                if self.audit_logger:
                    self.audit_logger.log_event(
                        "N/A",
                        "SIEM_CONNECTOR",
                        "SOURCE_PARSE_ERROR",
                        {"source_path": path, "error": str(e)},
                        level="ERROR"
                    )
                return []

            if isinstance(data, list):
                raw_records = data
            elif isinstance(data, dict):
                # Check for standard SIEM payload envelopes
                if "alerts" in data and isinstance(data["alerts"], list):
                    raw_records = data["alerts"]
                elif "events" in data and isinstance(data["events"], list):
                    raw_records = data["events"]
                elif "results" in data and isinstance(data["results"], list):
                    raw_records = data["results"]
                else:
                    raw_records = [data]
            else:
                if self.audit_logger:
                    self.audit_logger.log_event(
                        "N/A",
                        "SIEM_CONNECTOR",
                        "INVALID_PAYLOAD_TYPE",
                        {"source_path": path, "data_type": type(data).__name__},
                        level="ERROR"
                    )
                return []

        elif os.path.isdir(path):
            for fname in sorted(os.listdir(path)):
                if fname.endswith(".json"):
                    fpath = os.path.join(path, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            content = f.read().strip()
                            if not content:
                                continue
                            file_data = json.loads(content)
                    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
                        if self.audit_logger:
                            self.audit_logger.log_event(
                                "N/A",
                                "SIEM_CONNECTOR",
                                "DIRECTORY_FILE_PARSE_ERROR",
                                {"file_path": fpath, "error": str(e)},
                                level="WARNING"
                            )
                        continue

                    if isinstance(file_data, list):
                        raw_records.extend(file_data)
                    elif isinstance(file_data, dict):
                        if "alerts" in file_data and isinstance(file_data["alerts"], list):
                            raw_records.extend(file_data["alerts"])
                        elif "events" in file_data and isinstance(file_data["events"], list):
                            raw_records.extend(file_data["events"])
                        elif "results" in file_data and isinstance(file_data["results"], list):
                            raw_records.extend(file_data["results"])
                        else:
                            raw_records.append(file_data)

        # Filter out malformed, non-dict entries
        valid_records: List[Dict[str, Any]] = []
        for idx, rec in enumerate(raw_records):
            if not isinstance(rec, dict):
                if self.audit_logger:
                    self.audit_logger.log_event(
                        "N/A",
                        "SIEM_CONNECTOR",
                        "MALFORMED_RECORD_SKIPPED",
                        {"index": idx, "record_type": type(rec).__name__},
                        level="WARNING"
                    )
                continue
            valid_records.append(rec)

        return valid_records

    def fetch_alerts(self, source_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch raw alerts and apply existing validation and normalization.

        Preserves original fields while ensuring schema compliance and flagging data quality issues.
        """
        raw_list = self.fetch_raw_alerts(source_path)
        normalized_alerts: List[Dict[str, Any]] = []

        for raw_alert in raw_list:
            norm_alert, issues = self.alert_processor.validate_and_normalize(raw_alert)
            norm_alert["data_quality_issues"] = issues
            norm_alert["has_missing_data"] = bool(issues)
            normalized_alerts.append(norm_alert)

        return normalized_alerts

    def ingest(
        self,
        pipeline,
        source_path: Optional[str] = None,
        show_trace: bool = False,
        force: bool = False
    ) -> List[Dict[str, Any]]:
        """Ingest alerts from the mock SIEM source into the SOC Sentinel pipeline.

        Avoids duplicate processing of already handled alert IDs unless force is True.
        """
        path = source_path or self.default_source
        alerts = self.fetch_alerts(path)
        if not alerts:
            return []

        created_incidents: List[Dict[str, Any]] = []
        source_label = f"MockSIEM:{os.path.basename(path) if path else 'Feed'}"

        for alert in alerts:
            alert_id = alert.get("alert_id")

            # Deduplication check
            if not force and alert_id:
                if alert_id in self.processed_alert_ids:
                    continue

                if hasattr(pipeline, "incident_manager") and pipeline.incident_manager:
                    existing = [
                        inc for inc in pipeline.incident_manager.incidents.values()
                        if inc.get("original_alert_id") == alert_id
                    ]
                    if existing:
                        self.processed_alert_ids.add(alert_id)
                        continue

            incident = pipeline.process_single_alert(
                alert,
                source_file=source_label,
                show_trace=show_trace
            )

            if incident:
                if alert_id:
                    self.processed_alert_ids.add(alert_id)
                created_incidents.append(incident)

        # Export consolidated batch reports if multiple alerts processed
        if created_incidents and hasattr(pipeline, "reporter") and pipeline.reporter:
            pipeline.reporter.export_all_incidents_json(created_incidents)
            pipeline.reporter.export_summary_csv(created_incidents)

        return created_incidents
