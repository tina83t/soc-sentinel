"""Pipeline Flow Visualization & Architecture Map View for SOC Sentinel.

Provides an interactive, high-contrast visual inspector of the 9 real alert-processing
stages in SOC Sentinel, from ingestion through validation, enrichment, risk scoring,
playbook routing, approval gating, response simulation, incident management, and audit export.

Supports both reference architecture inspection and live/historical alert tracing
in non-mutating preview mode and triaged execution mode.

LLM-Assisted Stage Inspector:
- Reuses the existing alert-level Gemini Analyst Insight (no new API calls per stage).
- Each stage expander shows deterministic telemetry (always present) and an optional AI
  interpretation section drawn from the cached Gemini result for the same alert.
- AI interpretation is clearly labelled as advisory and separated from verified facts.
- If no cached Gemini result exists, a concise deterministic explanation is shown instead.
"""

from typing import Dict, Any, List, Optional
from ui.services.soc_service import SOCService
from ui.styles.theme import clean_html, get_severity_badge_html


STAGE_STATUS_COLORS = {
    "ARCHITECTURE_SPEC": {"text": "#93C5FD", "bg": "rgba(59, 130, 246, 0.15)", "border": "#2563EB"},
    "PREVIEW_EVALUATED": {"text": "#93C5FD", "bg": "rgba(59, 130, 246, 0.15)", "border": "#2563EB"},
    "PREVIEW_WARNINGS": {"text": "#FDE047", "bg": "rgba(245, 158, 11, 0.16)", "border": "#D97706"},
    "COMPLETED": {"text": "#86EFAC", "bg": "rgba(16, 185, 129, 0.16)", "border": "#059669"},
    "COMPLETED_WITH_WARNINGS": {"text": "#FDE047", "bg": "rgba(245, 158, 11, 0.16)", "border": "#D97706"},
    "SIMULATED_SUCCESS": {"text": "#86EFAC", "bg": "rgba(16, 185, 129, 0.16)", "border": "#059669"},
    "CONFIRMED": {"text": "#86EFAC", "bg": "rgba(16, 185, 129, 0.16)", "border": "#059669"},
    "AUTOMATED_POLICY": {"text": "#C084FC", "bg": "rgba(168, 85, 247, 0.15)", "border": "#9333EA"},
    "PROVENANCE_UNKNOWN": {"text": "#FCA5A5", "bg": "rgba(239, 68, 68, 0.16)", "border": "#DC2626"},
    "EXPORT_UNVERIFIED": {"text": "#FCA5A5", "bg": "rgba(239, 68, 68, 0.16)", "border": "#DC2626"},
    "PENDING": {"text": "#9CA3AF", "bg": "rgba(107, 114, 128, 0.15)", "border": "#4B5563"},
    "SKIPPED": {"text": "#6B7280", "bg": "rgba(75, 85, 99, 0.12)", "border": "#374151"},
    "FAILED": {"text": "#FCA5A5", "bg": "rgba(239, 68, 68, 0.16)", "border": "#DC2626"},
}

TRANSITION_DESCRIPTIONS = {
    "01_INGESTION": "Raw JSON Payload Loaded from Disk / Feed",
    "02_VALIDATION": "Validated 10-Field Telemetry & Quality Penalty Score",
    "03_ENRICHMENT": "Threat Context, RFC1918 Geo & Privileged Entity Flags",
    "04_RISK_SCORING": "Weighted Numeric Risk (0-100) & Operational Tier (CRITICAL/HIGH/MED/LOW)",
    "05_PLAYBOOK_ROUTING": "YAML Condition-Matched Incident Playbook & Action Plan",
    "06_APPROVAL_GATE": "Human-in-the-Loop Analyst Confirmation & Policy Authorization",
    "07_RESPONSE_SIMULATION": "DRY_RUN_SAFE_MODE Command Simulation & Audit Output Identifiers",
    "08_INCIDENT_MANAGEMENT": "Authoritative Incident Record (INC-YYYYMMDD-XXXX) Persisted to Disk",
    "09_AUDIT_EXPORT": "Redacted Audit Log Appended & Structured Case Dossier Exported",
}


def get_stage_status_badge(status: str) -> str:
    """Generate HTML badge for pipeline stage execution status."""
    st_upper = (status or "PENDING").upper()
    colors = STAGE_STATUS_COLORS.get(st_upper, STAGE_STATUS_COLORS["PENDING"])
    label = st_upper.replace("_", " ")
    return (
        f'<span style="background-color: {colors["bg"]}; color: {colors["text"]}; '
        f'border: 1px solid {colors["border"]}; padding: 0.18rem 0.55rem; '
        f'border-radius: 4px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.04em;">'
        f'{label}</span>'
    )


def get_stage_gemini_insight(stage_id: str, gemini_result: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Extract stage-relevant AI interpretation from an existing Gemini Analyst Insight result.

    Pure function that reads already-computed data. Never triggers an API call.
    Returns None if gemini_result is not a SUCCESS result or has no data.
    """
    if not gemini_result or gemini_result.get("status") != "SUCCESS":
        return None

    data = gemini_result.get("data")
    if not data or not isinstance(data, dict):
        return None

    _STAGE_MAPPING = {
        "01_INGESTION": {
            "title": "Observed Telemetry Interpretation",
            "content": data.get("alert_interpretation") or data.get("executive_summary") or "",
            "focus": "Distinguishes directly observed telemetry facts from analytical inferences.",
            "source_fields": ["alert_interpretation", "executive_summary"]
        },
        "02_VALIDATION": {
            "title": "Telemetry Completeness & Missing Fields",
            "content": (
                "Identified Information Gaps:\n" + "\n".join(f"• {item}" for item in data.get("missing_information", []))
                if data.get("missing_information")
                else (data.get("alert_interpretation") or "")
            ),
            "focus": "Identifies missing telemetry fields or telemetry gaps relevant to schema quality.",
            "source_fields": ["missing_information", "alert_interpretation"]
        },
        "03_ENRICHMENT": {
            "title": "Contextual Enrichment & Local Threat Indicators",
            "content": (
                "Verified Risk Indicators:\n" + "\n".join(f"• {item}" for item in data.get("relevant_risk_indicators", []))
                if data.get("relevant_risk_indicators")
                else (data.get("why_suspicious") or "")
            ),
            "focus": "Interprets verified enrichment indicators (local offline simulation DB only).",
            "source_fields": ["relevant_risk_indicators", "why_suspicious"]
        },
        "04_RISK_SCORING": {
            "title": "Risk Factor Reasoning & Threat Anomaly",
            "content": data.get("why_suspicious") or "",
            "focus": "Explains why the activity is considered anomalous without recalculating the deterministic score.",
            "source_fields": ["why_suspicious"]
        },
        "05_PLAYBOOK_ROUTING": {
            "title": "Playbook Routing Justification",
            "content": data.get("playbook_justification") or "",
            "focus": "Evaluates why the matched playbook is appropriate for this risk profile.",
            "source_fields": ["playbook_justification"]
        },
        "06_APPROVAL_GATE": {
            "title": "Analyst Triage & Pre-Approval Checks",
            "content": (
                "Recommended Investigation Steps Prior to Containment Approval:\n" +
                "\n".join(f"{i+1}. {step}" for i, step in enumerate(data.get("recommended_investigation_steps", [])))
                if data.get("recommended_investigation_steps")
                else ""
            ),
            "focus": "Provides actionable triage checklist for the analyst prior to approving containment.",
            "source_fields": ["recommended_investigation_steps"]
        },
        "07_RESPONSE_SIMULATION": {
            "title": "Containment Boundaries & Response Gaps",
            "content": (
                "Telemetry Gaps & Uncertainties for Response Actions:\n" +
                "\n".join(f"• {item}" for item in data.get("missing_information", []))
                if data.get("missing_information")
                else (data.get("playbook_justification") or "")
            ),
            "focus": "Highlights telemetry uncertainties before executing dry-run containment actions.",
            "source_fields": ["missing_information", "playbook_justification"]
        },
        "08_INCIDENT_MANAGEMENT": {
            "title": "Incident Dossier Assessment & Confidence",
            "content": (
                f"{data.get('executive_summary', '')}\n\nConfidence Assessment:\n{data.get('confidence_explanation', '')}".strip()
            ),
            "focus": "Synthesizes advisory overview and qualitative confidence for the formal incident record.",
            "source_fields": ["executive_summary", "confidence_explanation"]
        },
        "09_AUDIT_EXPORT": {
            "title": "Audit Evidence Completeness",
            "content": (
                "Evidence Gaps Noted for Audit Trail:\n" +
                "\n".join(f"• {item}" for item in data.get("missing_information", []))
                if data.get("missing_information")
                else "No significant evidence gaps reported by AI advisor."
            ),
            "focus": "Documents telemetry gaps and evidence limitations for the tamper-evident audit record.",
            "source_fields": ["missing_information"]
        }
    }

    mapping = _STAGE_MAPPING.get(stage_id)
    if not mapping or not mapping["content"].strip():
        return None

    return mapping


def get_stage_deterministic_explanation(stage_id: str, stage: Dict[str, Any]) -> str:
    """Provide a concise deterministic explanation for a stage when AI insight is absent or unmapped."""
    _DETERMINISTIC_EXPLANATIONS = {
        "01_INGESTION": "Telemetry payload loaded directly from source JSON or mock SIEM feed. Raw attributes are preserved without modification.",
        "02_VALIDATION": "Deterministic schema validation verifies 10 required fields and normalizes severity. Missing fields incur a -10 quality penalty.",
        "03_ENRICHMENT": "Deterministic classification evaluates RFC 1918/5737 IP scopes and queries offline IOC databases, privileged accounts, and critical assets.",
        "04_RISK_SCORING": "Additive rule scoring combines base severity, IOC matches (+35), privileged user (+20), critical host (+25), and penalties into a 0-100 score.",
        "05_PLAYBOOK_ROUTING": "Declarative YAML conditions match the verified risk score to a SOAR playbook (PB-CRIT-001, PB-HIGH-002, PB-MED-003, PB-LOW-004).",
        "06_APPROVAL_GATE": "Human-in-the-loop governance blocks containment execution until an analyst explicitly reviews conditions and confirms execution.",
        "07_RESPONSE_SIMULATION": "Response actions are modeled strictly in DRY_RUN_SAFE_MODE. Syntactically valid CLI commands are generated with zero live execution.",
        "08_INCIDENT_MANAGEMENT": "Authoritative incident record (INC-YYYYMMDD-XXXX) is created with 4-state lifecycle, structured verdict, and atomic disk persistence.",
        "09_AUDIT_EXPORT": "Audit event is redacted of sensitive credentials and appended to the immutable audit log; structured JSON/CSV case dossiers are exported."
    }
    return _DETERMINISTIC_EXPLANATIONS.get(stage_id, stage.get("summary") or "Pipeline stage execution.")


def get_alert_gemini_insight(
    service: SOCService,
    alert_id_or_file: Optional[str],
    st_module=None
) -> Optional[Dict[str, Any]]:
    """Retrieve existing cached Gemini insight for an alert without making any API calls."""
    if not alert_id_or_file:
        return None

    ident = service.get_alert_cache_identity(alert_id_or_file)
    if not ident:
        return None

    # 1. Check service cache
    insight = service.get_gemini_insight_for_pipeline(alert_id_or_file)
    if insight and insight.get("status") == "SUCCESS":
        return insight

    # 2. Check session state if available and ensure content hash and model match
    if st_module and hasattr(st_module, "session_state"):
        alert_id = ident["alert_id"]
        session_key = f"gemini_insight_{alert_id}"
        session_insight = st_module.session_state.get(session_key)
        if session_insight and isinstance(session_insight, dict) and session_insight.get("status") == "SUCCESS":
            sess_hash = session_insight.get("content_hash")
            sess_model = session_insight.get("model")
            if sess_hash and sess_hash != ident["content_hash"]:
                # Content changed on disk, session state is stale
                st_module.session_state.pop(session_key, None)
                return None
            if sess_model and sess_model != ident["model"]:
                # Model changed, session state is stale
                st_module.session_state.pop(session_key, None)
                return None
            return session_insight

    return None


def _render_system_transparency_notice(st, stage: Dict[str, Any]) -> None:
    """Render an explicit informational notice for Stage 07 System Transparency Node."""
    if stage.get("stage_id") != "07_RESPONSE_SIMULATION":
        return
    transparency_node = stage.get("details", {}).get("system_transparency_node")
    if not transparency_node:
        return

    stn_status = transparency_node.get("status", "NOT IMPLEMENTED")
    stn_html = f"""
    <div style="margin: 0.65rem 0; padding: 0.6rem 0.8rem; background-color: #0F172A; border-left: 3px solid #6366F1; border-radius: 4px; border: 1px solid #1E293B;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
            <span style="font-size: 0.74rem; font-weight: 700; color: #818CF8; text-transform: uppercase; letter-spacing: 0.03em;">
                🛡️ System Transparency Node &bull; Advanced Integration Guardrails
            </span>
            <span style="background-color: rgba(99, 102, 241, 0.15); color: #A5B4FC; border: 1px solid rgba(99, 102, 241, 0.4); padding: 0.12rem 0.45rem; border-radius: 4px; font-size: 0.65rem; font-weight: 700;">
                {stn_status}
            </span>
        </div>
        <div style="font-size: 0.74rem; color: #D1D5DB; line-height: 1.45; margin-bottom: 0.4rem;">
            <strong>Architectural Scope Notice:</strong> While containment actions (firewall block, quarantine) are modeled and verified in <code>DRY_RUN_SAFE_MODE</code>, live external integrations remain strictly non-operational:
        </div>
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.4rem; font-size: 0.70rem; margin-bottom: 0.4rem;">
            <div style="background-color: #0B0F19; padding: 0.35rem 0.5rem; border-radius: 4px; border: 1px solid #1E293B; color: #9CA3AF;">
                <span style="color: #F87171; font-weight: 600;">[NOT IMPLEMENTED]</span><br>
                SMTP Email Dispatch
            </div>
            <div style="background-color: #0B0F19; padding: 0.35rem 0.5rem; border-radius: 4px; border: 1px solid #1E293B; color: #9CA3AF;">
                <span style="color: #F87171; font-weight: 600;">[NOT IMPLEMENTED]</span><br>
                ITSM Ticket Sync
            </div>
            <div style="background-color: #0B0F19; padding: 0.35rem 0.5rem; border-radius: 4px; border: 1px solid #1E293B; color: #9CA3AF;">
                <span style="color: #F87171; font-weight: 600;">[NOT IMPLEMENTED]</span><br>
                AI Root-Cause Triage
            </div>
        </div>
        <div style="font-size: 0.68rem; color: #6B7280; font-style: italic;">
            Execution tracer step 07 records these guardrails explicitly. Containment simulation outcome does not imply live external dispatch.
        </div>
    </div>
    """
    st.markdown(clean_html(stn_html), unsafe_allow_html=True)


def _render_stage_ai_panel(
    st,
    stage_id: str,
    stage: Dict[str, Any],
    gemini_result: Optional[Dict[str, Any]],
    gemini_status: Dict[str, Any]
) -> None:
    """Render the AI-assisted explanation or deterministic fallback inside a stage expander.

    Guarantees:
    - Never triggers a Gemini API call.
    - Clearly distinguishes deterministic facts from AI-generated interpretation.
    - Shows evidence limitation warning if unsupported claims were flagged.
    - Falls back to concise deterministic explanation if no AI insight exists.
    """
    ai_insight = get_stage_gemini_insight(stage_id, gemini_result)
    is_spec = stage.get("status") == "ARCHITECTURE_SPEC"

    if is_spec:
        # In generic reference architecture mode
        det_text = get_stage_deterministic_explanation(stage_id, stage)
        spec_html = f"""
<div style="margin-top: 0.6rem; padding: 0.5rem 0.75rem; background-color: #0F172A; border-left: 3px solid #3B82F6; border-radius: 4px;">
<div style="font-size: 0.70rem; font-weight: 700; text-transform: uppercase; color: #93C5FD; margin-bottom: 0.25rem;">
📐 Architecture Specification
</div>
<div style="font-size: 0.74rem; color: #D1D5DB; line-height: 1.45;">
{det_text}
</div>
<div style="font-size: 0.68rem; color: #6B7280; margin-top: 0.25rem; font-style: italic;">
Generic blueprint mode &bull; Select a specific alert above to view execution telemetry and AI insights.
</div>
</div>
"""
        st.markdown(clean_html(spec_html), unsafe_allow_html=True)
        return

    # Alert mode: Check if Gemini insight is available
    if ai_insight and gemini_result:
        model_name = gemini_result.get("model", "gemini-2.5-flash")
        is_cached = gemini_result.get("cached", False)
        cache_badge = "CACHED" if is_cached else "FRESH"
        has_unsupported = gemini_result.get("has_unsupported_claims", False)
        validation_warnings = gemini_result.get("validation_warnings", [])

        # Evidence limitation warning if flagged
        evidence_warning_html = ""
        if has_unsupported:
            warnings_str = " | ".join(validation_warnings[:2]) if validation_warnings else "Contains statements not directly supported by telemetry."
            evidence_warning_html = f"""
<div style="background-color: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.35); border-radius: 4px; padding: 0.35rem 0.6rem; margin-bottom: 0.4rem; font-size: 0.70rem; color: #FDE047;">
⚠️ <strong>Evidence Limitation:</strong> {warnings_str}
</div>
"""

        content_escaped = ai_insight["content"]
        ai_html = f"""
<div style="margin-top: 0.65rem; padding: 0.6rem 0.75rem; background-color: #0F172A; border-left: 3px solid #8B5CF6; border-radius: 4px;">
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
<div style="display: flex; align-items: center; gap: 0.35rem;">
<span style="font-size: 0.72rem; font-weight: 700; color: #C4B5FD;">🤖 AI Advisory Interpretation:</span>
<span style="font-size: 0.72rem; font-weight: 600; color: #E5E7EB;">{ai_insight['title']}</span>
</div>
<div style="display: flex; gap: 0.35rem; align-items: center;">
<span style="background-color: rgba(139, 92, 246, 0.15); color: #C4B5FD; border: 1px solid rgba(139, 92, 246, 0.3); padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.62rem; font-weight: 600;">{cache_badge}</span>
<span style="font-size: 0.65rem; color: #9CA3AF; font-family: monospace;">{model_name}</span>
</div>
</div>
{evidence_warning_html}
<div style="font-size: 0.68rem; color: #A78BFA; margin-bottom: 0.35rem; font-style: italic;">
{ai_insight['focus']}
</div>
<div style="font-size: 0.75rem; color: #E5E7EB; line-height: 1.5; white-space: pre-wrap; background-color: #0B0F19; border: 1px solid #1E293B; border-radius: 4px; padding: 0.5rem 0.65rem;">
{content_escaped}
</div>
<div style="margin-top: 0.35rem; font-size: 0.65rem; color: #6B7280; text-align: right; font-style: italic;">
Advisory only &bull; Verified pipeline telemetry and deterministic scoring remain authoritative
</div>
</div>
"""
        st.markdown(clean_html(ai_html), unsafe_allow_html=True)
    else:
        # Deterministic fallback when Gemini is unconfigured or no insight exists
        det_text = get_stage_deterministic_explanation(stage_id, stage)
        api_key_configured = gemini_status.get("api_key_configured", False)

        if not api_key_configured:
            status_note = "Gemini API key is not configured. Advisory interpretations are disabled."
        else:
            status_note = "No Gemini analysis cached for this alert. (Generate one from the Alerts view using 'Analyze with Gemini' — no calls are triggered from this flow inspector.)"

        fallback_html = f"""
<div style="margin-top: 0.65rem; padding: 0.55rem 0.75rem; background-color: #0F172A; border-left: 3px solid #4B5563; border-radius: 4px;">
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
<span style="font-size: 0.70rem; font-weight: 700; text-transform: uppercase; color: #9CA3AF;">
⚙️ Deterministic Stage Logic
</span>
<span style="font-size: 0.65rem; color: #6B7280; font-style: italic;">
AI Interpretation Not Active
</span>
</div>
<div style="font-size: 0.74rem; color: #D1D5DB; line-height: 1.45; margin-bottom: 0.35rem;">
{det_text}
</div>
<div style="font-size: 0.68rem; color: #6B7280; font-style: italic; border-top: 1px dashed #1E293B; padding-top: 0.25rem;">
{status_note}
</div>
</div>
"""
        st.markdown(clean_html(fallback_html), unsafe_allow_html=True)


def render_pipeline_flow_component(
    service: SOCService,
    alert_id_or_file: Optional[str] = None,
    st_module=None
) -> None:
    """Render an embedded vertical pipeline visualization for a given alert or blueprint."""
    if st_module is None:
        try:
            import streamlit as st_module
        except ImportError:
            return

    st = st_module
    flow_data = service.get_pipeline_flow(alert_id_or_file)
    stages: List[Dict[str, Any]] = flow_data.get("stages", [])

    gemini_result = get_alert_gemini_insight(service, alert_id_or_file, st_module=st)
    gemini_status = service.get_gemini_status()

    # Overview header for embedded component
    target_type = flow_data.get("target_type", "UNKNOWN")
    alert_id = flow_data.get("alert_id") or "Generic"

    status_badge = get_stage_status_badge(flow_data.get("status", "ACTIVE"))

    header_html = f"""
    <div style="background-color: #111827; border: 1px solid #1E293B; border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 1rem; display: flex; justify-content: space-between; align-items: center;">
        <div>
            <span style="font-size: 0.78rem; text-transform: uppercase; color: #9CA3AF; font-weight: 600;">Pipeline Execution Map:</span>
            <span style="font-family: monospace; font-size: 0.95rem; font-weight: 700; color: #FFFFFF; margin-left: 0.35rem;">{alert_id}</span>
            <span style="font-size: 0.72rem; color: #60A5FA; margin-left: 0.5rem;">({target_type})</span>
        </div>
        <div>{status_badge}</div>
    </div>
    """
    st.markdown(clean_html(header_html), unsafe_allow_html=True)

    # Render stages sequentially
    for idx, stage in enumerate(stages, 1):
        stage_id = stage.get("stage_id", f"STAGE_{idx}")
        stage_name = stage.get("name", "Unknown Stage")
        stage_status = stage.get("status", "PENDING")
        module_path = stage.get("module", "modules")
        func_name = stage.get("function", "")
        summary = stage.get("summary", "")
        duration_ms = stage.get("duration_ms")
        badge_html = get_stage_status_badge(stage_status)

        timing_str = f"&bull; ⏱️ {duration_ms:.2f} ms" if duration_ms is not None else ""

        card_html = f"""
        <div class="soc-panel" style="margin-bottom: 0.35rem; border-left: 3px solid #3B82F6;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.35rem;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span style="background-color: #1E293B; color: #93C5FD; font-size: 0.72rem; font-weight: 700; padding: 0.15rem 0.45rem; border-radius: 4px; font-family: monospace;">{idx:02d}/09</span>
                    <strong style="color: #F3F4F6; font-size: 0.88rem;">{stage_name}</strong>
                </div>
                <div>{badge_html}</div>
            </div>
            <div style="font-size: 0.72rem; color: #9CA3AF; margin-bottom: 0.35rem; font-family: monospace;">
                <span style="color: #60A5FA;">{module_path}</span> &bull; <span>{func_name}</span> {timing_str}
            </div>
            <div style="font-size: 0.78rem; color: #D1D5DB; line-height: 1.4;">
                {summary}
            </div>
        </div>
        """
        st.markdown(clean_html(card_html), unsafe_allow_html=True)

        # Stage detail expander
        exp_title = f"Telemetry & State Details: {stage_name}"
        with st.expander(exp_title):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("<strong style='font-size: 0.75rem; color: #9CA3AF; text-transform: uppercase;'>Inputs Received</strong>", unsafe_allow_html=True)
                st.json(stage.get("inputs") or {})
            with c2:
                st.markdown("<strong style='font-size: 0.75rem; color: #9CA3AF; text-transform: uppercase;'>Outputs & State Transitions</strong>", unsafe_allow_html=True)
                st.json(stage.get("outputs") or {})

            if stage.get("details"):
                st.markdown("<strong style='font-size: 0.75rem; color: #9CA3AF; text-transform: uppercase;'>Internal Telemetry & Quality Checks</strong>", unsafe_allow_html=True)
                st.json(stage.get("details"))

            # Informational System Transparency Notice for Stage 07
            _render_system_transparency_notice(st, stage)

            # AI Advisory Section / Deterministic Fallback
            _render_stage_ai_panel(st, stage_id, stage, gemini_result, gemini_status)

        # Transition arrow between stages
        if idx < len(stages):
            transition_text = TRANSITION_DESCRIPTIONS.get(stage_id, "Data Pipeline Flow")
            arrow_html = f"""
            <div style="display: flex; align-items: center; justify-content: center; margin: 0.35rem 0; color: #4B5563;">
                <div style="display: flex; align-items: center; gap: 0.5rem; background-color: #0B0F19; border: 1px dashed #1E293B; border-radius: 12px; padding: 0.2rem 0.75rem; font-size: 0.68rem; color: #6B7280;">
                    <span>↓</span>
                    <span>{transition_text}</span>
                    <span>↓</span>
                </div>
            </div>
            """
            st.markdown(clean_html(arrow_html), unsafe_allow_html=True)


def render_pipeline_flow_view(service: SOCService, st_module=None) -> None:
    """Render the full interactive Pipeline Flow & Architecture Map view in Streamlit."""
    if st_module is None:
        try:
            import streamlit as st_module
        except ImportError:
            return

    st = st_module

    header_html = """
    <div class="soc-panel-header" style="margin-bottom: 0.25rem;">Pipeline Flow Visualization & Architecture Map</div>
    <div style="font-size: 0.80rem; color: #9CA3AF; margin-bottom: 1rem;">
        End-to-end interactive map of the 9 alert processing stages in SOC Sentinel, demonstrating
        precise module attribution, telemetry normalization, risk scoring, playbook selection, analyst gating,
        safe simulation, incident persistence, and audit logging.
    </div>
    """
    st.markdown(clean_html(header_html), unsafe_allow_html=True)

    # 1. Selector Bar: Blueprint vs Specific Alert
    alert_files = service.list_alert_files()
    options = ["ARCHITECTURE_BLUEPRINT (Generic 9-Stage Reference)"]
    file_map: Dict[str, Optional[str]] = {
        options[0]: None
    }

    for a in alert_files:
        aid = a.get("alert_id", "UNKNOWN")
        ev_type = a.get("event_type", "Event")
        is_proc = " [TRIAGED]" if a.get("is_processed") else " [AWAITING TRIAGE]"
        label = f"{aid} — {ev_type}{is_proc}"
        options.append(label)
        file_map[label] = a.get("filepath")

    # Column controls
    col_sel, col_mode_info = st.columns([2.5, 1.5])
    with col_sel:
        selected_option = st.selectbox(
            "Select Inspection Target",
            options=options,
            index=0,
            key="pipeline_flow_target_select"
        )
    with col_mode_info:
        st.markdown(
            clean_html("""
            <div style="background-color: #111827; border: 1px solid #1E293B; border-radius: 6px; padding: 0.45rem 0.75rem; font-size: 0.72rem; color: #9CA3AF;">
                <strong style="color: #E5E7EB;">Safety Guarantee:</strong> Pipeline inspection is strictly non-mutating. Selecting an alert generates an execution preview without modifying system state or audit files.
            </div>
            """),
            unsafe_allow_html=True
        )

    selected_target = file_map.get(selected_option)
    flow_data = service.get_pipeline_flow(selected_target)

    # Cached Gemini insight for selected alert (pure cache lookup, 0 API calls)
    gemini_result = get_alert_gemini_insight(service, selected_target, st_module=st)
    gemini_status = service.get_gemini_status()

    # 2. Key Metrics Bar
    m1, m2, m3, m4 = st.columns(4)

    target_type = flow_data.get("target_type", "UNKNOWN")
    total_stages = flow_data.get("total_stages", 9)
    status_str = flow_data.get("status", "ACTIVE")
    trace_summary = flow_data.get("trace_summary")
    incident_summary = flow_data.get("incident_summary")

    with m1:
        st.markdown(clean_html(f"""
        <div class="soc-metric-card">
            <div class="soc-metric-label">Target Inspection Mode</div>
            <div class="soc-metric-value" style="font-size: 1.15rem; color: #60A5FA;">{target_type.replace('_', ' ')}</div>
            <div class="soc-metric-hint">{flow_data.get('alert_id') or 'Generic Architecture'}</div>
        </div>
        """), unsafe_allow_html=True)

    with m2:
        st.markdown(clean_html(f"""
        <div class="soc-metric-card">
            <div class="soc-metric-label">Pipeline Architecture</div>
            <div class="soc-metric-value" style="font-size: 1.15rem; color: #86EFAC;">{total_stages} Sequential Stages</div>
            <div class="soc-metric-hint">Zero Missing Stages &bull; Gated Flow</div>
        </div>
        """), unsafe_allow_html=True)

    with m3:
        if trace_summary:
            duration_val = f"{trace_summary.get('total_duration_ms', 0):.2f} ms"
            dur_hint = f"{trace_summary.get('total_steps', 0)} trace steps recorded"
        else:
            duration_val = "Preview / Spec"
            dur_hint = "Theoretical latency < 5.0 ms"
        st.markdown(clean_html(f"""
        <div class="soc-metric-card">
            <div class="soc-metric-label">Execution Timing</div>
            <div class="soc-metric-value" style="font-size: 1.15rem; color: #FDE047;">{duration_val}</div>
            <div class="soc-metric-hint">{dur_hint}</div>
        </div>
        """), unsafe_allow_html=True)

    with m4:
        if incident_summary:
            inc_val = incident_summary.get("incident_id")
            inc_hint = f"Status: {incident_summary.get('status')} &bull; {incident_summary.get('assigned_analyst')}"
        elif selected_target:
            inc_val = "Untriaged Preview"
            inc_hint = "No incident record created yet"
        else:
            inc_val = "Reference Spec"
            inc_hint = "Blueprint architecture mode"
        st.markdown(clean_html(f"""
        <div class="soc-metric-card">
            <div class="soc-metric-label">Incident Lifecycle State</div>
            <div class="soc-metric-value" style="font-size: 1.15rem; color: #C084FC;">{inc_val}</div>
            <div class="soc-metric-hint">{inc_hint}</div>
        </div>
        """), unsafe_allow_html=True)

    # 3. Status Legend Bar
    legend_html = """
    <div style="display: flex; gap: 0.6rem; flex-wrap: wrap; align-items: center; margin: 0.75rem 0 1rem 0; padding: 0.5rem 0.75rem; background-color: #0B0F19; border: 1px solid #1E293B; border-radius: 6px; font-size: 0.70rem;">
        <span style="color: #6B7280; font-weight: 700; text-transform: uppercase;">Stage Status Legend:</span>
        <span style="display: flex; align-items: center; gap: 0.3rem;"><span style="width: 8px; height: 8px; border-radius: 50%; background-color: #3B82F6;"></span> <span style="color: #93C5FD;">ARCHITECTURE / PREVIEW</span></span>
        <span style="display: flex; align-items: center; gap: 0.3rem;"><span style="width: 8px; height: 8px; border-radius: 50%; background-color: #10B981;"></span> <span style="color: #86EFAC;">COMPLETED / CONFIRMED</span></span>
        <span style="display: flex; align-items: center; gap: 0.3rem;"><span style="width: 8px; height: 8px; border-radius: 50%; background-color: #A855F7;"></span> <span style="color: #C084FC;">AUTOMATED POLICY</span></span>
        <span style="display: flex; align-items: center; gap: 0.3rem;"><span style="width: 8px; height: 8px; border-radius: 50%; background-color: #F59E0B;"></span> <span style="color: #FDE047;">WARNINGS / DATA QUALITY</span></span>
        <span style="display: flex; align-items: center; gap: 0.3rem;"><span style="width: 8px; height: 8px; border-radius: 50%; background-color: #4B5563;"></span> <span style="color: #9CA3AF;">PENDING</span></span>
        <span style="display: flex; align-items: center; gap: 0.3rem;"><span style="width: 8px; height: 8px; border-radius: 50%; background-color: #EF4444;"></span> <span style="color: #FCA5A5;">FAILED / UNVERIFIED</span></span>
    </div>
    """
    st.markdown(clean_html(legend_html), unsafe_allow_html=True)

    # 4. Pipeline Stages Flow
    stages: List[Dict[str, Any]] = flow_data.get("stages", [])

    for idx, stage in enumerate(stages, 1):
        stage_id = stage.get("stage_id", f"STAGE_{idx}")
        stage_name = stage.get("name", "Unknown Stage")
        stage_status = stage.get("status", "PENDING")
        module_path = stage.get("module", "modules")
        func_name = stage.get("function", "")
        summary = stage.get("summary", "")
        duration_ms = stage.get("duration_ms")
        badge_html = get_stage_status_badge(stage_status)

        timing_str = f"&bull; ⏱️ {duration_ms:.2f} ms" if duration_ms is not None else ""

        card_html = f"""
        <div class="soc-panel" style="margin-bottom: 0.35rem; border-left: 3px solid #3B82F6;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.35rem;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span style="background-color: #1E293B; color: #93C5FD; font-size: 0.72rem; font-weight: 700; padding: 0.15rem 0.45rem; border-radius: 4px; font-family: monospace;">{idx:02d}/09</span>
                    <strong style="color: #F3F4F6; font-size: 0.92rem;">{stage_name}</strong>
                </div>
                <div>{badge_html}</div>
            </div>
            <div style="font-size: 0.74rem; color: #9CA3AF; margin-bottom: 0.4rem; font-family: monospace;">
                <span style="color: #60A5FA;">{module_path}</span> &bull; <span style="color: #E5E7EB;">{func_name}</span> {timing_str}
            </div>
            <div style="font-size: 0.80rem; color: #D1D5DB; line-height: 1.45;">
                {summary}
            </div>
        </div>
        """
        st.markdown(clean_html(card_html), unsafe_allow_html=True)

        # Stage detail expander
        exp_title = f"Inspect Stage {idx:02d} Telemetry, Inputs & Decisions ({stage_name})"
        with st.expander(exp_title):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("<strong style='font-size: 0.75rem; color: #9CA3AF; text-transform: uppercase;'>Stage Inputs & Contract</strong>", unsafe_allow_html=True)
                st.json(stage.get("inputs") or {})
            with c2:
                st.markdown("<strong style='font-size: 0.75rem; color: #9CA3AF; text-transform: uppercase;'>Stage Outputs & Transition Data</strong>", unsafe_allow_html=True)
                st.json(stage.get("outputs") or {})

            if stage.get("details"):
                st.markdown("<strong style='font-size: 0.75rem; color: #9CA3AF; text-transform: uppercase;'>Sub-system Metadata & Audit Flags</strong>", unsafe_allow_html=True)
                st.json(stage.get("details"))

            # Informational System Transparency Notice for Stage 07
            _render_system_transparency_notice(st, stage)

            # AI Advisory Section / Deterministic Fallback
            _render_stage_ai_panel(st, stage_id, stage, gemini_result, gemini_status)

        # Transition arrow between stages
        if idx < len(stages):
            transition_text = TRANSITION_DESCRIPTIONS.get(stage_id, "Data Pipeline Flow")
            arrow_html = f"""
            <div style="display: flex; align-items: center; justify-content: center; margin: 0.45rem 0; color: #4B5563;">
                <div style="display: flex; align-items: center; gap: 0.5rem; background-color: #0B0F19; border: 1px dashed #1E293B; border-radius: 12px; padding: 0.25rem 0.85rem; font-size: 0.70rem; color: #6B7280;">
                    <span>↓</span>
                    <span style="color: #9CA3AF; font-weight: 500;">{transition_text}</span>
                    <span>↓</span>
                </div>
            </div>
            """
            st.markdown(clean_html(arrow_html), unsafe_allow_html=True)
