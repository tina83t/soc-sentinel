from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class ResponseSimulator:
    """Simulates active security response containment and mitigation actions.

    SAFETY NOTICE: This module operates in DRY-RUN SIMULATION mode only.
    No live firewalls, Active Directory, cloud providers, or endpoints are modified.
    All actions require explicit SOC analyst review and confirmation.
    """

    _global_action_counter: int = 0

    def __init__(self, audit_logger=None):
        self.audit_logger = audit_logger

    def simulate_action(
        self,
        action_type: str,
        target: str,
        reason: str,
        alert_id: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Simulate a single response action and generate structured recommendation."""
        timestamp = datetime.now(timezone.utc).isoformat()
        action_type = action_type.upper()

        action_catalog = {
            "ENDPOINT_ISOLATION": {
                "name": "Simulated Endpoint Network Isolation",
                "risk_mitigation": "Isolate host from enterprise network to prevent lateral movement.",
                "approval_required": True,
                "reversibility": "Immediate (via EDR console)",
                "recommended_command": f"edr_cli isolate-host --hostname {target} --reason '{reason}'"
            },
            "ACCOUNT_SUSPENSION": {
                "name": "Simulated Account Lock / Revocation",
                "risk_mitigation": "Revoke active Kerberos tickets and disable user in Active Directory.",
                "approval_required": True,
                "reversibility": "Immediate (via IAM / AD)",
                "recommended_command": f"ad_cli disable-user --username {target} --revoke-tokens"
            },
            "IP_BLOCK": {
                "name": "Simulated Firewall Perimeter IP Block",
                "risk_mitigation": "Drop inbound and outbound traffic at perimeter firewall.",
                "approval_required": True,
                "reversibility": "Rule expiration / manual removal",
                "recommended_command": f"firewall_cli add-rule --action DROP --source-ip {target} --ttl 86400"
            },
            "ANALYST_NOTIFICATION": {
                "name": "SOC Analyst Escalation Dispatch",
                "risk_mitigation": "Page Tier-2 on-call analyst for immediate investigation.",
                "approval_required": False,
                "reversibility": "N/A",
                "recommended_command": f"pager_cli notify --queue 'SOC-TIER2' --alert {alert_id} --summary '{reason}'"
            },
            "SECURITY_REVIEW_QUEUE": {
                "name": "Standard Queue Assignment",
                "risk_mitigation": "Enqueue incident for standard SLA analyst triage.",
                "approval_required": False,
                "reversibility": "N/A",
                "recommended_command": f"ticketing_cli enqueue --queue 'SOC-TIER1' --id {alert_id}"
            }
        }

        template = action_catalog.get(action_type, {
            "name": f"Simulated Custom Action ({action_type})",
            "risk_mitigation": "Custom mitigation action simulated.",
            "approval_required": True,
            "reversibility": "Analyst manual review",
            "recommended_command": f"echo 'Simulate action {action_type} on {target}'"
        })

        ResponseSimulator._global_action_counter += 1
        record = {
            "simulation_id": f"SIM-{ResponseSimulator._global_action_counter:06d}",
            "action_type": action_type,
            "action_name": template["name"],
            "target": target,
            "reason": reason,
            "parameters": parameters or {},
            "status": "SIMULATED_PENDING_APPROVAL" if template["approval_required"] else "SIMULATED_AUTO_COMPLETED",
            "approval_required": template["approval_required"],
            "recommended_command": template["recommended_command"],
            "risk_mitigation_note": template["risk_mitigation"],
            "simulated_at": timestamp,
            "execution_mode": "DRY_RUN_SAFE_MODE"
        }

        if self.audit_logger:
            self.audit_logger.log_event(
                alert_id,
                "RESPONSE_SIMULATION",
                f"ACTION_SIMULATED_{action_type}",
                {"target": target, "status": record["status"]}
            )

        return record
