import os
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class AuditLogger:
    """Provides structured audit logging for SOC automation lifecycle events."""

    def __init__(self, log_dir: str = "logs", log_filename: str = "soc_automation.log"):
        os.makedirs(log_dir, exist_ok=True)
        self.log_filepath = os.path.join(log_dir, log_filename)
        self.history: List[Dict[str, Any]] = []

        # Use an isolated logger instance per AuditLogger to prevent handler/state leakage across tests/runs
        logger_name = f"SOCAutomationAudit.{id(self)}"
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        self._file_handler = logging.FileHandler(self.log_filepath, encoding="utf-8")
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [STAGE:%(stage)s] [ALERT:%(alert_id)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ"
        )
        self._file_handler.setFormatter(formatter)
        self.logger.addHandler(self._file_handler)

    def log_event(
        self,
        alert_id: str,
        stage: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        level: str = "INFO"
    ) -> Dict[str, Any]:
        """Record a structured event in history and log file."""
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = {
            "timestamp": timestamp,
            "alert_id": alert_id or "UNKNOWN",
            "stage": stage,
            "action": action,
            "details": details or {}
        }
        self.history.append(entry)

        extra = {
            "stage": stage,
            "alert_id": alert_id or "N/A"
        }
        msg = f"{action} | Details: {details or {}}"
        if level.upper() == "WARNING":
            self.logger.warning(msg, extra=extra)
        elif level.upper() == "ERROR":
            self.logger.error(msg, extra=extra)
        else:
            self.logger.info(msg, extra=extra)

        return entry

    def get_alert_history(self, alert_id: str) -> List[Dict[str, Any]]:
        """Retrieve audit events related to a specific alert."""
        return [entry for entry in self.history if entry["alert_id"] == alert_id]

    def close(self):
        """Close handlers and release file resources."""
        if hasattr(self, "_file_handler") and self._file_handler in self.logger.handlers:
            self._file_handler.close()
            self.logger.removeHandler(self._file_handler)
