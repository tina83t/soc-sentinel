from typing import Dict, Any, List
from datetime import datetime, timezone
from modules.response_simulator import ResponseSimulator


class PlaybookEngine:
    """FortiSOAR-inspired Playbook Execution Engine.

    Executes structured, conditional playbooks with traceable steps and
    audit records.
    """

    def __init__(self, response_simulator: ResponseSimulator, audit_logger=None):
        self.response_simulator = response_simulator
        self.audit_logger = audit_logger

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

        # Branching based on requirements
        if risk_score >= 80:
            matched_condition = f"risk_score ({risk_score}) >= 80 [MATCH: CRITICAL BRANCH]"
            playbook_name = "PB-CRIT-001: Critical Threat Automated Containment & Escalation"
            priority = "CRITICAL"
            recommended_status = "URGENT_ATTENTION_REQUIRED"

            # Step 1: Immediate Analyst Paging
            action_notify = self.response_simulator.simulate_action(
                action_type="ANALYST_NOTIFICATION",
                target="SOC_ON_CALL_TIER2",
                reason=f"Risk Score {risk_score} exceeding Critical threshold (>=80)",
                alert_id=alert_id
            )
            simulated_actions.append(action_notify)
            steps_executed.append({
                "step_id": "STEP-02-PAGE-ANALYST",
                "step_name": "Dispatch Critical Alert to On-Call Analyst",
                "status": "COMPLETED",
                "output": action_notify["action_name"]
            })

            # Step 2: Endpoint Isolation recommendation if hostname exists
            target_host = alert.get("hostname")
            if target_host and target_host != "unknown-host":
                action_iso = self.response_simulator.simulate_action(
                    action_type="ENDPOINT_ISOLATION",
                    target=target_host,
                    reason=f"High-confidence threat indicator on endpoint (Risk: {risk_score})",
                    alert_id=alert_id
                )
                simulated_actions.append(action_iso)
                steps_executed.append({
                    "step_id": "STEP-03-ISOLATE-ENDPOINT",
                    "step_name": f"Simulate Host Isolation for {target_host}",
                    "status": "COMPLETED",
                    "output": action_iso["action_name"]
                })

            # Step 3: Account lock recommendation if privileged or username given
            target_user = alert.get("username")
            if target_user:
                action_lock = self.response_simulator.simulate_action(
                    action_type="ACCOUNT_SUSPENSION",
                    target=target_user,
                    reason=f"Account involved in Critical risk event (Risk: {risk_score})",
                    alert_id=alert_id
                )
                simulated_actions.append(action_lock)
                steps_executed.append({
                    "step_id": "STEP-04-SUSPEND-ACCOUNT",
                    "step_name": f"Simulate Account Lock for {target_user}",
                    "status": "COMPLETED",
                    "output": action_lock["action_name"]
                })

        elif risk_score >= 60:
            matched_condition = f"60 <= risk_score ({risk_score}) < 80 [MATCH: HIGH BRANCH]"
            playbook_name = "PB-HIGH-002: High-Priority Incident Review & Perimeter Defense"
            priority = "HIGH"
            recommended_status = "PENDING_ANALYST_REVIEW"

            # Step 1: Enqueue for analyst review
            action_notify = self.response_simulator.simulate_action(
                action_type="ANALYST_NOTIFICATION",
                target="SOC_TIER1_QUEUE",
                reason=f"Risk Score {risk_score} classified as HIGH. Prompt analyst review required.",
                alert_id=alert_id
            )
            simulated_actions.append(action_notify)
            steps_executed.append({
                "step_id": "STEP-02-QUEUE-HIGH-PRIORITY",
                "step_name": "Request Tier-1 Analyst Review",
                "status": "COMPLETED",
                "output": action_notify["action_name"]
            })

            # Step 2: Recommend IP block if external source IP is present
            src_ip = alert.get("source_ip")
            src_info = enrichment.get("source_ip_context", {})
            if src_ip and (src_info.get("is_public") or enrichment.get("threat_intelligence")):
                action_block = self.response_simulator.simulate_action(
                    action_type="IP_BLOCK",
                    target=src_ip,
                    reason="Inbound suspicious / brute-force traffic from external IP",
                    alert_id=alert_id
                )
                simulated_actions.append(action_block)
                steps_executed.append({
                    "step_id": "STEP-03-BLOCK-IP",
                    "step_name": f"Simulate Perimeter IP Block for {src_ip}",
                    "status": "COMPLETED",
                    "output": action_block["action_name"]
                })

        elif risk_score >= 30:
            matched_condition = f"30 <= risk_score ({risk_score}) < 60 [MATCH: MEDIUM BRANCH]"
            playbook_name = "PB-MED-003: Medium-Severity Triage & Telemetry Verification"
            priority = "MEDIUM"
            recommended_status = "TRIAGE_QUEUE"

            action_queue = self.response_simulator.simulate_action(
                action_type="SECURITY_REVIEW_QUEUE",
                target="STANDARD_INVESTIGATION_QUEUE",
                reason=f"Risk score {risk_score} requires standard triage queue placement.",
                alert_id=alert_id
            )
            simulated_actions.append(action_queue)
            steps_executed.append({
                "step_id": "STEP-02-ENQUEUE-STANDARD",
                "step_name": "Place Alert in Standard Triage Queue",
                "status": "COMPLETED",
                "output": action_queue["action_name"]
            })

        else:
            matched_condition = f"risk_score ({risk_score}) < 30 [MATCH: LOW BRANCH]"
            playbook_name = "PB-LOW-004: Low-Risk Baseline Logging & Auto-Archive"
            priority = "LOW"
            recommended_status = "AUTO_RESOLVED_INFORMATIONAL"

            steps_executed.append({
                "step_id": "STEP-02-LOG-BASELINE",
                "step_name": "Store Analysis Results & Update Telemetry Baselines",
                "status": "COMPLETED",
                "output": "Archived as low-risk / informational event. No response actions required."
            })

        end_time = datetime.now(timezone.utc).isoformat()

        execution_record = {
            "playbook_id": playbook_name.split(":")[0],
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
