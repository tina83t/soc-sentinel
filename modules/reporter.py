import json
import csv
import os
from typing import List, Dict, Any


class Reporter:
    """Generates structured JSON incident dossiers and CSV summaries for SOC management."""

    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def export_incident_json(self, incident: Dict[str, Any], filename: str = None) -> str:
        """Save a single incident record as JSON."""
        if not filename:
            inc_id = incident.get("incident_id", "INC-UNKNOWN")
            filename = f"{inc_id.lower()}.json"

        path = os.path.join(self.reports_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(incident, f, indent=2)
        return path

    def export_all_incidents_json(self, incidents: List[Dict[str, Any]], filename: str = "all_incidents.json") -> str:
        """Save full list of incidents as consolidated JSON."""
        path = os.path.join(self.reports_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(incidents, f, indent=2)
        return path

    def export_summary_csv(self, incidents: List[Dict[str, Any]], filename: str = "incidents_summary.csv") -> str:
        """Export tabular summary for reporting, compliance, and analyst dashboarding."""
        path = os.path.join(self.reports_dir, filename)
        fieldnames = [
            "incident_id",
            "original_alert_id",
            "created_at",
            "priority",
            "risk_score",
            "risk_classification",
            "event_type",
            "source_ip",
            "destination_ip",
            "username",
            "hostname",
            "incident_status",
            "triggered_playbook",
            "simulated_actions_count"
        ]

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for inc in incidents:
                writer.writerow({
                    "incident_id": inc.get("incident_id"),
                    "original_alert_id": inc.get("original_alert_id"),
                    "created_at": inc.get("created_at"),
                    "priority": inc.get("priority"),
                    "risk_score": inc.get("risk_score"),
                    "risk_classification": inc.get("risk_classification"),
                    "event_type": inc.get("event_type"),
                    "source_ip": inc.get("source_ip"),
                    "destination_ip": inc.get("destination_ip"),
                    "username": inc.get("username"),
                    "hostname": inc.get("hostname"),
                    "incident_status": inc.get("incident_status"),
                    "triggered_playbook": inc.get("triggered_playbook", {}).get("playbook_id", "N/A"),
                    "simulated_actions_count": len(inc.get("recommended_responses", []))
                })

        return path
