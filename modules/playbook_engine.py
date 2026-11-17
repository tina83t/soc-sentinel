import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from modules.response_simulator import ResponseSimulator
from modules.playbook_loader import PlaybookLoader


class PlaybookEngine:
    """FortiSOAR-inspired Playbook Execution Engine.

    Executes structured, conditional playbooks loaded dynamically from declarative
    YAML definitions with traceable steps and audit records.
    """

    def __init__(
        self,
        response_simulator: ResponseSimulator,
        audit_logger=None,
        playbooks_dir: Optional[str] = None
    ):
        self.response_simulator = response_simulator
        self.audit_logger = audit_logger

        resolved_dir = None
        if playbooks_dir and os.path.isdir(playbooks_dir):
            resolved_dir = playbooks_dir
        else:
            # Fallback to standard config location if custom dir not populated
            candidate = os.path.join(os.getcwd(), "config", "playbooks")
            if os.path.isdir(candidate):
                resolved_dir = candidate
            else:
                resolved_dir = os.path.abspath(
                    os.path.join(os.path.dirname(__file__), "..", "config", "playbooks")
                )

        self.playbooks_dir = resolved_dir
        self.playbooks: List[Dict[str, Any]] = PlaybookLoader.load_playbooks_from_directory(
            self.playbooks_dir
        )

    def get_catalog(self) -> List[Dict[str, Any]]:
        """Retrieve all active playbook specifications in catalog format."""
        return list(self.playbooks)

    def get_playbook_by_id(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve playbook definition matching a specific ID."""
        for pb in self.playbooks:
            if pb["playbook_id"] == playbook_id:
                return pb
        return None

    def get_playbook_for_score(self, risk_score: float) -> Dict[str, Any]:
        """Find the matching playbook based on descending risk score thresholds."""
        for pb in self.playbooks:
            if risk_score >= pb.get("min_risk_score", 0):
                return pb
        # Fallback to last (lowest priority) playbook if none matched
        return self.playbooks[-1]

    def execute_playbook(
        self,
        alert: Dict[str, Any],
        enrichment: Dict[str, Any],
        risk_evaluation: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate conditions and execute the matching SOC playbook workflow."""
        alert_id = alert.get("alert_id") or "UNKNOWN"
        risk_score = risk_evaluation.get("total_risk_score", 0)
        classification = risk_evaluation.get("risk_classification", "LOW")

        start_time = datetime.now(timezone.utc).isoformat()
        steps_executed: List[Dict[str, Any]] = []
        simulated_actions: List[Dict[str, Any]] = []

        # Step 0: Condition Evaluation Node (Decision Branch)
        condition_evaluated = "IF risk_score >= 80 THEN PB-CRIT-001 ELSE IF risk_score >= 60 THEN PB-HIGH-002 ELSE IF risk_score >= 30 THEN PB-MED-003 ELSE PB-LOW-004"
        decision_step = {
            "step_id": "STEP-01-CONDITION-EVAL",
            "step_name": "Evaluate Risk Score & Routing Condition",
            "status": "COMPLETED",
            "details": f"Evaluated risk score {risk_score} -> classified as {classification}"
        }
        steps_executed.append(decision_step)

        # Match playbook from loaded YAML definitions
        matched_pb = self.get_playbook_for_score(risk_score)
        playbook_name = matched_pb["name"]
        priority = matched_pb["target_tier"]
        recommended_status = matched_pb["recommended_status"]
        template = matched_pb.get(
            "matched_condition_template",
            f"risk_score ({risk_score}) matched {matched_pb['playbook_id']}"
        )
        matched_condition = template.format(risk_score=risk_score)

        # Context attributes for conditional execution steps
        target_host = alert.get("hostname")
        target_user = alert.get("username")
        src_ip = alert.get("source_ip")
        src_info = enrichment.get("source_ip_context", {})

        for exec_step in matched_pb.get("execution_steps", []):
            action_type = exec_step.get("action_type")
            if not action_type:
                # Informational / baseline logging step
                steps_executed.append({
                    "step_id": exec_step["step_id"],
                    "step_name": exec_step["step_name"],
                    "status": "COMPLETED",
                    "output": exec_step.get("output", "")
                })
                continue

            # Evaluate conditional guards
            cond = exec_step.get("condition")
            if cond == "valid_hostname":
                if not target_host or target_host == "unknown-host":
                    continue
            elif cond == "valid_username":
                if not target_user:
                    continue
            elif cond == "public_or_threat_ip":
                if not (src_ip and (src_info.get("is_public") or enrichment.get("threat_intelligence"))):
                    continue

            # Resolve target
            target_field = exec_step.get("target_field")
            if target_field:
                target_val = alert.get(target_field)
            else:
                target_val = exec_step.get("target", "")

            # Format step name and reason
            step_name = exec_step["step_name"].format(
                hostname=target_host or "",
                username=target_user or "",
                source_ip=src_ip or ""
            )
            reason = exec_step.get("reason_template", "").format(risk_score=risk_score)

            action_result = self.response_simulator.simulate_action(
                action_type=action_type,
                target=target_val,
                reason=reason,
                alert_id=alert_id
            )
            simulated_actions.append(action_result)
            steps_executed.append({
                "step_id": exec_step["step_id"],
                "step_name": step_name,
                "status": "COMPLETED",
                "output": action_result["action_name"]
            })

        end_time = datetime.now(timezone.utc).isoformat()

        execution_record = {
            "playbook_id": matched_pb["playbook_id"],
            "playbook_name": playbook_name,
            "condition_evaluated": condition_evaluated,
            "matched_condition": matched_condition,
            "trigger_condition": f"risk_score >= {risk_score} ({classification})",
            "priority": priority,
            "recommended_status": recommended_status,
            "start_time": start_time,
            "end_time": end_time,
            "steps_executed": steps_executed,
            "simulated_actions": simulated_actions
        }

        if self.audit_logger:
            self.audit_logger.log_event(
                alert_id,
                "PLAYBOOK_EXECUTION",
                "PLAYBOOK_COMPLETED",
                {
                    "playbook": playbook_name,
                    "steps_count": len(steps_executed),
                    "simulated_actions_count": len(simulated_actions)
                }
            )

        return execution_record
