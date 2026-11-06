"""Execution Tracer for SOC Playbook Automation.

Provides FortiSOAR-inspired execution tracing for each alert lifecycle.
Records actual measured execution times, timestamps, called modules and functions,
decision branch conditions, transparent factor scoring, and transition reasons.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class TraceStep:
    """Represents a single verified step in the playbook execution trace."""

    def __init__(
        self,
        step_id: str,
        name: str,
        module_fn: str,
        status: str,
        start_time: str,
        end_time: str,
        duration_ms: float,
        result_summary: str,
        details: Dict[str, Any],
        error: Optional[str] = None,
        transition_reason: Optional[str] = None
    ):
        self.step_id = step_id
        self.name = name
        self.module_fn = module_fn
        self.status = status
        self.start_time = start_time
        self.end_time = end_time
        self.duration_ms = duration_ms
        self.result_summary = result_summary
        self.details = details
        self.error = error
        self.transition_reason = transition_reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "name": self.name,
            "module_fn": self.module_fn,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": round(self.duration_ms, 3),
            "result_summary": self.result_summary,
            "details": self.details,
            "error": self.error,
            "transition_reason": self.transition_reason
        }


class PlaybookExecutionTrace:
    """Collects and renders execution trace for a single alert triage lifecycle."""

    def __init__(self, alert_id: str, source_file: Optional[str] = None):
        self.alert_id = alert_id
        self.source_file = source_file
        self.start_timestamp = datetime.now(timezone.utc).isoformat()
        self.end_timestamp: Optional[str] = None
        self.playbook_id: Optional[str] = None
        self.playbook_name: Optional[str] = None
        self.steps: List[TraceStep] = []

    def add_step(
        self,
        step_id: str,
        name: str,
        module_fn: str,
        status: str,
        start_time: str,
        end_time: str,
        duration_ms: float,
        result_summary: str,
        details: Dict[str, Any],
        error: Optional[str] = None,
        transition_reason: Optional[str] = None
    ):
        step = TraceStep(
            step_id=step_id,
            name=name,
            module_fn=module_fn,
            status=status,
            start_time=start_time,
            end_time=end_time,
            duration_ms=duration_ms,
            result_summary=result_summary,
            details=details,
            error=error,
            transition_reason=transition_reason
        )
        self.steps.append(step)

    def finish(self, playbook_id: str, playbook_name: str):
        self.playbook_id = playbook_id
        self.playbook_name = playbook_name
        self.end_timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert trace to structured dictionary format."""
        return {
            "alert_id": self.alert_id,
            "source_file": self.source_file,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "total_duration_ms": round(sum(s.duration_ms for s in self.steps), 3),
            "steps": [s.to_dict() for s in self.steps]
        }

    def render_terminal(self) -> str:
        """Render a readable FortiSOAR-inspired execution trace to text."""
        total_duration = sum(s.duration_ms for s in self.steps)
        lines = []
        lines.append("=" * 80)
        lines.append(f"PLAYBOOK EXECUTION TRACE: {self.playbook_id or 'EVALUATION-PHASE'} - {self.playbook_name or 'SOC Triage Workflow'}")
        lines.append(f"Alert ID: {self.alert_id} | Source: {self.source_file or 'Direct Ingestion'} | Total Time: {total_duration:.2f}ms")
        lines.append("=" * 80)

        for step in self.steps:
            lines.append(f"\n[{step.step_id}] {step.name}")
            lines.append(f"     Module/Func : {step.module_fn}")
            lines.append(f"     Start / End : {step.start_time} -> {step.end_time}")
            lines.append(f"     Status      : {step.status} | Duration: {step.duration_ms:.2f}ms")
            lines.append(f"     Result      : {step.result_summary}")

            if step.error:
                lines.append(f"     Error       : [!] {step.error}")

            d = step.details

            # 1. Ingestion specific
            if "raw_source" in d:
                lines.append(f"     Event Source: {d.get('event_source')} | Timestamp: {d.get('event_timestamp')}")

            # 2. Validation specific
            if "issues_count" in d:
                if d["issues_count"] == 0:
                    lines.append("     Quality     : Clean (All 10 required schema fields valid)")
                else:
                    lines.append(f"     Quality     : Degraded ({d['issues_count']} issue(s) detected)")
                    for issue in d.get("issues", []):
                        lines.append(f"       [-] {issue}")

            # 3. Enrichment specific
            if "ip_classification" in d:
                lines.append(f"     Source IP   : {d.get('source_ip')} -> Classification: {d.get('ip_classification')}")
            if "ti_match" in d:
                if d["ti_match"]:
                    ti = d.get("ti_details", {})
                    cat = ti.get("threat_category", "Malicious")
                    conf = ti.get("confidence")
                    conf_str = f" | Confidence: {conf}%" if conf is not None else ""
                    lines.append(f"     Threat Intel: MATCH -> Matched IP {ti.get('matched_ip')} [{cat}{conf_str}]")
                else:
                    lines.append("     Threat Intel: NO MATCH (Clean internal or unlisted IP)")

            if "privileged_user" in d:
                priv = "YES (Privileged Account)" if d["privileged_user"] else "NO (Standard Account)"
                lines.append(f"     Identity    : User '{d.get('username')}' -> {priv}")
            if "critical_host" in d:
                crit = "YES (Critical Infrastructure)" if d["critical_host"] else "NO (Standard Asset)"
                lines.append(f"     Host Role   : Host '{d.get('hostname')}' -> {crit}")
            if "detected_patterns" in d and d["detected_patterns"]:
                lines.append(f"     Signatures  : Detected execution patterns: {d['detected_patterns']}")
            if "failed_attempts_count" in d and d["failed_attempts_count"]:
                lines.append(f"     Auth Telemetry: {d['failed_attempts_count']} consecutive failed attempts")

            # 4. Risk scoring breakdown
            if "risk_score" in d:
                lines.append(f"     Base Score  : Severity {d.get('base_severity')} -> {d.get('base_score')} pts")
                lines.append("     Factor Additions:")
                for f in d.get("factors", []):
                    lines.append(f"       [+] {f['factor_id']} (+{f['weight']} pts): {f['reason']}")
                if not d.get("factors"):
                    lines.append("       [ ] No additional risk factors triggered")
                lines.append(f"     Final Score : {d.get('risk_score')}/100 -> Classification: {d.get('classification')}")

            # 5. Playbook routing condition
            if "condition_evaluated" in d:
                lines.append(f"     Evaluated   : {d.get('condition_evaluated')}")
                lines.append(f"     Matched     : {d.get('matched_condition')}")
                lines.append(f"     Selected PB : {d.get('selected_playbook')}")

            # 6. Simulated response actions
            if "simulated_actions" in d:
                actions = d.get("simulated_actions", [])
                if actions:
                    lines.append(f"     Simulated Actions ({len(actions)}):")
                    for a in actions:
                        appr = "PENDING APPROVAL" if a.get("approval_required") else "AUTO COMPLETED"
                        lines.append(f"       • [{a.get('action_type')}] Target: {a.get('target')} | Status: SIMULATED / {appr}")
                        lines.append(f"         Command: {a.get('recommended_command')}")
                else:
                    lines.append("     Simulated Actions: None required (Informational / Baseline)")

            # 7. Unimplemented steps explanation
            if "unimplemented_feature" in d:
                lines.append(f"     Notice      : {d.get('notice')}")

            # 8. Incident creation
            if "incident_id" in d:
                lines.append(f"     Incident ID : {d.get('incident_id')} (Priority: {d.get('priority')}, Status: {d.get('status')})")

            # 9. Audit logging
            if "audit_events_count" in d:
                lines.append(f"     Audit Trail : {d.get('audit_events_count')} lifecycle events logged to {d.get('log_file')}")

            if step.transition_reason:
                lines.append(f"     Transition  : Next -> {step.transition_reason}")

        lines.append("=" * 80 + "\n")
        return "\n".join(lines)


class ExecutionTracer:
    """Factory and manager for Playbook Execution Traces."""

    def __init__(self):
        self.traces: List[PlaybookExecutionTrace] = []

    def create_trace(self, alert_id: str, source_file: Optional[str] = None) -> PlaybookExecutionTrace:
        trace = PlaybookExecutionTrace(alert_id=alert_id, source_file=source_file)
        self.traces.append(trace)
        return trace

    def get_latest_trace(self) -> Optional[PlaybookExecutionTrace]:
        return self.traces[-1] if self.traces else None
