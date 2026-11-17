"""Alert Management View for SOC Sentinel Dashboard.

Allows SOC analysts to discover, filter, inspect, and evaluate raw alert telemetry
prior to executing playbooks, with schema validation quality checks and non-mutating
risk score previews.
"""

from typing import List, Dict, Any, Optional
from ui.services.soc_service import SOCService
from ui.styles.theme import get_severity_badge_html, clean_html
from ui.views.pipeline_flow_view import render_pipeline_flow_component


def filter_alerts(
    alerts: List[Dict[str, Any]],
    search_query: str = "",
    severity_filter: str = "ALL",
    status_filter: str = "ALL"
) -> List[Dict[str, Any]]:
    """Pure filter function for discovered alerts based on query, severity, and processing status."""
    filtered = []
    q = (search_query or "").strip().lower()
    sev_filter = (severity_filter or "ALL").strip().upper()
    st_filter = (status_filter or "ALL").strip().upper()

    for a in alerts:
        # 1. Severity filter
        if sev_filter != "ALL" and str(a.get("severity", "")).upper() != sev_filter:
            continue

        # 2. Processed status filter
        if st_filter == "PROCESSED" and not a.get("is_processed"):
            continue
        if st_filter == "UNPROCESSED" and a.get("is_processed"):
            continue

        # 3. Text query search across multiple fields
        if q:
            searchable = " ".join([
                str(a.get("alert_id") or ""),
                str(a.get("event_type") or ""),
                str(a.get("description") or ""),
                str(a.get("source_ip") or ""),
                str(a.get("destination_ip") or ""),
                str(a.get("hostname") or ""),
                str(a.get("username") or ""),
                str(a.get("event_source") or "")
            ]).lower()
            if q not in searchable:
                continue

        filtered.append(a)

    return filtered


def render_gemini_insight_section(
    service: SOCService,
    alert_id: str,
    filepath: str,
    st_module
) -> None:
    """Render the optional LLM-powered advisory insight section using Gemini."""
    st = st_module
    status_info = service.get_gemini_status()
    api_key_configured = status_info.get("api_key_configured", False)
    model_name = status_info.get("model", "gemini-2.5-flash")

    insight_state_key = f"gemini_insight_{alert_id}"

    # Invalidate stale session state if alert content or model modified
    ident = service.get_alert_cache_identity(filepath)
    current_hash = ident["content_hash"] if ident else ""
    current_model = ident["model"] if ident else model_name
    if hasattr(st, "session_state"):
        existing_sess = st.session_state.get(insight_state_key)
        if existing_sess and isinstance(existing_sess, dict):
            sess_hash = existing_sess.get("content_hash")
            sess_model = existing_sess.get("model")
            if (sess_hash and current_hash and sess_hash != current_hash) or \
               (sess_model and current_model and sess_model != current_model):
                st.session_state.pop(insight_state_key, None)

    # Header Card
    if api_key_configured:
        cfg_pill = f'<span style="background-color: rgba(16, 185, 129, 0.15); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.68rem; font-weight: 600;">CONFIGURED ({model_name})</span>'
    else:
        cfg_pill = '<span style="background-color: rgba(245, 158, 11, 0.15); color: #FDE047; border: 1px solid rgba(245, 158, 11, 0.3); padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.68rem; font-weight: 600;">API KEY NOT SET</span>'

    header_html = f"""
    <div class="soc-panel" style="margin-bottom: 0.75rem;">
        <div class="soc-panel-header" style="display: flex; justify-content: space-between; align-items: center;">
            <div style="display: flex; align-items: center; gap: 0.4rem;">
                <span>🤖</span>
                <span>LLM Analyst Insight</span>
            </div>
            <div>{cfg_pill}</div>
        </div>
        <div style="font-size: 0.76rem; color: #9CA3AF; margin-top: 0.25rem;">
            Advisory threat interpretation powered by Google Gemini Developer API. Non-mutating analysis to assist human triage decisions.
        </div>
    </div>
    """
    st.markdown(clean_html(header_html), unsafe_allow_html=True)

    if not api_key_configured:
        unconfigured_html = f"""
        <div class="soc-panel" style="border-left: 3px solid #F59E0B; margin-bottom: 0.75rem; background-color: #0F172A;">
            <div style="font-size: 0.80rem; font-weight: 600; color: #FDE047; margin-bottom: 0.35rem;">
                ⚠️ Gemini API Key Not Configured
            </div>
            <div style="font-size: 0.75rem; color: #D1D5DB; line-height: 1.45; margin-bottom: 0.5rem;">
                LLM Analyst Insight requires a Google Gemini Developer API key. The rest of the SOC Sentinel pipeline remains fully functional without an LLM.
            </div>
            <div style="font-size: 0.72rem; color: #9CA3AF; background-color: #0B0F19; border: 1px solid #1E293B; border-radius: 4px; padding: 0.5rem; font-family: monospace;">
                # Option 1: Set environment variable in your terminal<br>
                export GEMINI_API_KEY="your_api_key_here"<br>
                # Option 2: Add to local project .env file<br>
                GEMINI_API_KEY="your_api_key_here"<br>
                # Optional: Override model (default: gemini-2.5-flash)<br>
                export GEMINI_MODEL="{model_name}"
            </div>
        </div>
        """
        st.markdown(clean_html(unconfigured_html), unsafe_allow_html=True)
        return

    # Trigger button & action
    c_btn, c_hint = st.columns([1.5, 2.5])
    has_existing = bool(st.session_state.get(insight_state_key)) if hasattr(st, "session_state") else False
    btn_label = "Refresh Analysis with Gemini" if has_existing else "Analyze with Gemini"

    with c_btn:
        trigger_clicked = st.button(
            f"🔍 {btn_label}",
            key=f"btn_gemini_{alert_id}",
            use_container_width=True
        )

    with c_hint:
        hint_html = f"""
        <div style="font-size: 0.72rem; color: #9CA3AF; padding-top: 0.35rem;">
            Analyzes synthesized telemetry via <code>{model_name}</code>. Advisory only &bull; Preserves official risk score.
        </div>
        """
        st.markdown(clean_html(hint_html), unsafe_allow_html=True)

    if trigger_clicked:
        if hasattr(st, "spinner"):
            with st.spinner(f"Requesting advisory analysis from Gemini ({model_name})..."):
                result = service.analyze_alert_with_gemini(filepath, force_refresh=True)
        else:
            result = service.analyze_alert_with_gemini(filepath, force_refresh=True)

        if hasattr(st, "session_state"):
            st.session_state[insight_state_key] = result

    # Render cached/stored insight if available
    insight_res = st.session_state.get(insight_state_key) if hasattr(st, "session_state") else None
    if not insight_res:
        return

    status = insight_res.get("status")
    if status != "SUCCESS":
        err_msg = insight_res.get("error", "Unknown Gemini API error occurred.")
        st.error(f"Gemini Analysis Error ({status}): {err_msg}")
        return

    data = insight_res.get("data")
    if not data:
        st.warning("No insight data returned from Gemini.")
        return

    # Extract all 8 fields
    exec_summary = data.get("executive_summary", "No summary provided.")
    alert_interp = data.get("alert_interpretation", "No interpretation provided.")
    why_susp = data.get("why_suspicious", "No suspicious reasoning provided.")
    risk_indicators = data.get("relevant_risk_indicators", [])
    investigation_steps = data.get("recommended_investigation_steps", [])
    pb_justification = data.get("playbook_justification", "No playbook justification provided.")
    missing_info = data.get("missing_information", [])
    confidence_expl = data.get("confidence_explanation", "No confidence explanation provided.")

    indicators_html = "".join(f"<li style='margin-bottom: 0.25rem;'>{ind}</li>" for ind in risk_indicators) if risk_indicators else "<li>No specific indicators listed.</li>"
    steps_html = "".join(f"<li style='margin-bottom: 0.3rem;'>{step}</li>" for step in investigation_steps) if investigation_steps else "<li>No steps listed.</li>"
    missing_html = "".join(f"<li style='margin-bottom: 0.25rem;'>{gap}</li>" for gap in missing_info) if missing_info else "<li>No missing telemetry noted.</li>"

    is_cached_pill = (
        '<span style="background-color: rgba(59, 130, 246, 0.15); color: #60A5FA; border: 1px solid rgba(59, 130, 246, 0.3); padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.65rem; font-weight: 600;">CACHED</span>'
        if insight_res.get("cached")
        else '<span style="background-color: rgba(16, 185, 129, 0.15); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.65rem; font-weight: 600;">FRESH</span>'
    )

    # Evidence limitation warning — shown when post-response validation detected unsupported claims
    has_unsupported_claims = insight_res.get("has_unsupported_claims", False)
    validation_warnings = insight_res.get("validation_warnings", [])
    if has_unsupported_claims:
        evidence_warning_html = """
        <div class="soc-panel" style="border-left: 3px solid #F59E0B; margin-bottom: 0.75rem; background-color: #0F172A;">
            <div style="font-size: 0.80rem; font-weight: 700; color: #FDE047; margin-bottom: 0.3rem;">
                ⚠️ Evidence Limitation — Analyst Verification Required
            </div>
            <div style="font-size: 0.74rem; color: #D1D5DB; line-height: 1.4; margin-bottom: 0.4rem;">
                This AI-generated response may contain one or more statements not directly
                supported by the supplied alert context. Review the warnings below before
                acting on this analysis.
            </div>
        """
        if validation_warnings:
            warnings_items = "".join(
                f"<li style='margin-bottom: 0.2rem; color: #FDE047;'>{w}</li>"
                for w in validation_warnings
            )
            evidence_warning_html += (
                f"<ul style='font-size: 0.72rem; padding-left: 1.1rem; margin: 0;'>"
                f"{warnings_items}"
                f"</ul>"
            )
        evidence_warning_html += "\n        </div>\n        "
        st.markdown(clean_html(evidence_warning_html), unsafe_allow_html=True)

    insight_html = f"""
    <div class="soc-panel" style="margin-bottom: 0.75rem; border-left: 3px solid #8B5CF6;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; border-bottom: 1px solid #1E293B; padding-bottom: 0.5rem;">
            <div style="display: flex; align-items: center; gap: 0.45rem;">
                <span style="background-color: rgba(139, 92, 246, 0.18); color: #C4B5FD; border: 1px solid #7C3AED; padding: 0.18rem 0.55rem; border-radius: 4px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.04em;">
                    AI-GENERATED ADVISORY ONLY — REQUIRES ANALYST VERIFICATION
                </span>
            </div>
            <div style="display: flex; gap: 0.4rem; align-items: center;">
                {is_cached_pill}
                <span style="font-size: 0.68rem; color: #9CA3AF; font-family: monospace;">{model_name}</span>
            </div>
        </div>

        <div style="background-color: #0B0F19; border: 1px solid #1E293B; border-radius: 4px; padding: 0.65rem 0.85rem; margin-bottom: 0.75rem;">
            <div style="font-size: 0.70rem; font-weight: 700; text-transform: uppercase; color: #8B5CF6; margin-bottom: 0.25rem;">
                1. Executive Summary
            </div>
            <div style="font-size: 0.82rem; color: #F3F4F6; line-height: 1.45;">
                {exec_summary}
            </div>
        </div>

        <div style="margin-bottom: 0.75rem;">
            <div style="font-size: 0.70rem; font-weight: 700; text-transform: uppercase; color: #9CA3AF; margin-bottom: 0.25rem;">
                2. Alert Interpretation (Observed Facts vs Inferences)
            </div>
            <div style="font-size: 0.78rem; color: #D1D5DB; line-height: 1.45;">
                {alert_interp}
            </div>
        </div>

        <div style="margin-bottom: 0.75rem;">
            <div style="font-size: 0.70rem; font-weight: 700; text-transform: uppercase; color: #9CA3AF; margin-bottom: 0.25rem;">
                3. Why This Alert Is Suspicious
            </div>
            <div style="font-size: 0.78rem; color: #D1D5DB; line-height: 1.45;">
                {why_susp}
            </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 0.75rem;">
            <div style="background-color: #0B0F19; border: 1px solid #1E293B; border-radius: 4px; padding: 0.5rem 0.75rem;">
                <div style="font-size: 0.70rem; font-weight: 700; text-transform: uppercase; color: #9CA3AF; margin-bottom: 0.35rem;">
                    4. Verified Risk Indicators
                </div>
                <ul style="font-size: 0.74rem; color: #D1D5DB; padding-left: 1.1rem; margin: 0;">
                    {indicators_html}
                </ul>
            </div>
            <div style="background-color: #0B0F19; border: 1px solid #1E293B; border-radius: 4px; padding: 0.5rem 0.75rem;">
                <div style="font-size: 0.70rem; font-weight: 700; text-transform: uppercase; color: #9CA3AF; margin-bottom: 0.35rem;">
                    5. Recommended Investigation Steps
                </div>
                <ol style="font-size: 0.74rem; color: #D1D5DB; padding-left: 1.1rem; margin: 0;">
                    {steps_html}
                </ol>
            </div>
        </div>

        <div style="margin-bottom: 0.75rem;">
            <div style="font-size: 0.70rem; font-weight: 700; text-transform: uppercase; color: #9CA3AF; margin-bottom: 0.25rem;">
                6. Why Existing Playbook Is Appropriate
            </div>
            <div style="font-size: 0.78rem; color: #D1D5DB; line-height: 1.45;">
                {pb_justification}
            </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 0.5rem;">
            <div>
                <div style="font-size: 0.70rem; font-weight: 700; text-transform: uppercase; color: #F59E0B; margin-bottom: 0.25rem;">
                    7. Missing Information / Uncertainty
                </div>
                <ul style="font-size: 0.74rem; color: #FDE047; padding-left: 1.1rem; margin: 0;">
                    {missing_html}
                </ul>
            </div>
            <div>
                <div style="font-size: 0.70rem; font-weight: 700; text-transform: uppercase; color: #10B981; margin-bottom: 0.25rem;">
                    8. Confidence Assessment
                </div>
                <div style="font-size: 0.74rem; color: #86EFAC; line-height: 1.4;">
                    {confidence_expl}
                </div>
            </div>
        </div>

        <div style="margin-top: 0.65rem; padding-top: 0.45rem; border-top: 1px dashed #1E293B; font-size: 0.68rem; color: #6B7280; text-align: right;">
            <em>Advisory only &bull; Preserves deterministic pipeline score &bull; Generated at {insight_res.get('timestamp', 'N/A')}</em>
        </div>
    </div>
    """
    st.markdown(clean_html(insight_html), unsafe_allow_html=True)


def render_alerts_view(service: SOCService, st_module=None) -> None:
    """Render the Alert Management console view in Streamlit."""
    if st_module is None:
        try:
            import streamlit as st_module
        except ImportError:
            return

    st = st_module
    all_alerts = service.list_alert_files()

    header_html = '<div class="soc-panel-header">Alert Discovery & Triage Queue</div>'
    st.markdown(clean_html(header_html), unsafe_allow_html=True)

    if not all_alerts:
        st.warning("No JSON alert telemetry files discovered in data/alerts.")
        return

    # Filter Bar
    c_search, c_sev, c_proc = st.columns([2.5, 1.2, 1.2])

    with c_search:
        search_query = st.text_input(
            "Search Telemetry",
            placeholder="Search by ID, IP, Hostname, User, or Description...",
            label_visibility="collapsed"
        )

    with c_sev:
        severity_options = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        selected_sev = st.selectbox(
            "Severity Filter",
            options=severity_options,
            index=0,
            label_visibility="collapsed"
        )

    with c_proc:
        proc_options = ["ALL", "UNPROCESSED", "PROCESSED"]
        selected_proc = st.selectbox(
            "Status Filter",
            options=proc_options,
            index=0,
            label_visibility="collapsed"
        )

    filtered_alerts = filter_alerts(
        alerts=all_alerts,
        search_query=search_query,
        severity_filter=selected_sev,
        status_filter=selected_proc
    )

    info_bar_html = f"""
    <div style="font-size: 0.76rem; color: #9CA3AF; margin-bottom: 0.85rem; display: flex; justify-content: space-between;">
        <span>Displaying <strong>{len(filtered_alerts)}</strong> of {len(all_alerts)} discovered alert scenarios</span>
        <span><em>Read-Only Telemetry &bull; Controlled Execution via Playbook Center</em></span>
    </div>
    """
    st.markdown(clean_html(info_bar_html), unsafe_allow_html=True)

    if not filtered_alerts:
        st.info("No alerts match the specified search or filter criteria.")
        return

    # Layout: Stable Two-Column Master List (Left) and Detail Dossier (Right)
    col_list, col_detail = st.columns([3.8, 6.2])

    # Session state for selected alert ID
    if "selected_alert_id" not in st.session_state:
        st.session_state["selected_alert_id"] = filtered_alerts[0]["alert_id"]

    # Ensure selected alert is within filtered list or fallback
    current_ids = [a["alert_id"] for a in filtered_alerts]
    selected_aid = st.session_state.get("selected_alert_id")
    if selected_aid not in current_ids:
        selected_aid = current_ids[0]
        st.session_state["selected_alert_id"] = selected_aid

    with col_list:
        list_header_html = '<div style="font-size: 0.76rem; font-weight: 600; text-transform: uppercase; color: #6B7280; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Alert Scenarios</div>'
        st.markdown(clean_html(list_header_html), unsafe_allow_html=True)

        for a in filtered_alerts:
            aid = a["alert_id"]
            is_active = (aid == selected_aid)
            sev = a.get("severity", "LOW")
            sev_badge = get_severity_badge_html(sev)

            card_class = "soc-alert-card soc-alert-card-active" if is_active else "soc-alert-card"
            status_indicator = "● Processed" if a.get("is_processed") else "○ Unprocessed"
            status_color = "#60A5FA" if a.get("is_processed") else "#6B7280"
            active_pill = '<span class="soc-inspecting-pill">INSPECTING</span>' if is_active else ""

            card_html = f"""
            <div class="{card_class}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-family: monospace; font-size: 0.82rem; font-weight: 700; color: #FFFFFF;">{aid}</span>
                    <div style="display: flex; gap: 0.35rem; align-items: center;">
                        {active_pill}
                        {sev_badge}
                    </div>
                </div>
                <div style="font-size: 0.78rem; font-weight: 500; color: #E5E7EB; margin-top: 0.25rem;">
                    {a.get("event_type")}
                </div>
                <div style="font-size: 0.72rem; color: #9CA3AF; display: flex; justify-content: space-between; margin-top: 0.25rem;">
                    <span>{a.get("source_ip") or a.get("hostname") or "No Host/IP"}</span>
                    <span style="color: {status_color};">{status_indicator}</span>
                </div>
            </div>
            """
            st.markdown(clean_html(card_html), unsafe_allow_html=True)

            # Button to select when not active
            if not is_active:
                if st.button(f"Inspect {aid}", key=f"btn_select_{aid}", use_container_width=True):
                    st.session_state["selected_alert_id"] = aid
                    st.rerun()

    # Right Column: Detail Dossier & Non-Mutating Evaluation Preview
    selected_meta = next((a for a in all_alerts if a["alert_id"] == selected_aid), None)

    with col_detail:
        if not selected_meta:
            st.info("Select an alert scenario from the left panel to inspect details.")
            return

        raw_alert = service.get_alert_raw(selected_meta["filepath"])
        if not raw_alert:
            st.error(f"Could not load alert payload for '{selected_aid}'.")
            return

        # Header panel for selected alert
        sev_badge = get_severity_badge_html(selected_meta.get("severity"))
        proc_status_html = (
            f'<span style="background-color: rgba(59, 130, 246, 0.15); color: #60A5FA; border: 1px solid #2563EB; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.70rem; font-weight: 600;">INCIDENT: {selected_meta.get("incident_id")}</span>'
            if selected_meta.get("is_processed")
            else '<span style="background-color: rgba(107, 114, 128, 0.15); color: #9CA3AF; border: 1px solid #4B5563; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.70rem; font-weight: 600;">AWAITING TRIAGE</span>'
        )

        detail_header_html = f"""
        <div class="soc-panel" style="margin-bottom: 0.75rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E293B; padding-bottom: 0.5rem; margin-bottom: 0.75rem;">
                <div>
                    <span style="font-family: monospace; font-size: 1.1rem; font-weight: 700; color: #FFFFFF;">{selected_aid}</span>
                    <span style="margin-left: 0.5rem;">{sev_badge}</span>
                </div>
                <div>{proc_status_html}</div>
            </div>
            <div style="font-size: 0.88rem; font-weight: 600; color: #F3F4F6;">{raw_alert.get("event_type", "Unknown Event")}</div>
            <div style="font-size: 0.80rem; color: #9CA3AF; margin-top: 0.25rem; line-height: 1.4; word-break: break-word;">{raw_alert.get("description", "No description provided.")}</div>
        </div>
        """
        st.markdown(clean_html(detail_header_html), unsafe_allow_html=True)

        # Telemetry Metadata Grid
        telemetry_html = f"""
        <div class="soc-panel" style="margin-bottom: 0.75rem; font-size: 0.78rem;">
            <div class="soc-panel-header" style="margin-bottom: 0.5rem;">Telemetry Attributes</div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; word-break: break-word;">
                <div><span style="color: #6B7280;">Timestamp:</span> <span style="color: #E5E7EB;">{raw_alert.get('timestamp') or 'N/A'}</span></div>
                <div><span style="color: #6B7280;">Event Source:</span> <span style="color: #E5E7EB;">{raw_alert.get('event_source') or 'N/A'}</span></div>
                <div><span style="color: #6B7280;">Source IP:</span> <code style="color: #93C5FD; font-size: 0.78rem; word-break: break-all;">{raw_alert.get('source_ip') or 'None'}</code></div>
                <div><span style="color: #6B7280;">Destination IP:</span> <code style="color: #93C5FD; font-size: 0.78rem; word-break: break-all;">{raw_alert.get('destination_ip') or 'None'}</code></div>
                <div><span style="color: #6B7280;">Target Host:</span> <span style="color: #E5E7EB;">{raw_alert.get('hostname') or 'None'}</span></div>
                <div><span style="color: #6B7280;">User Account:</span> <span style="color: #E5E7EB;">{raw_alert.get('username') or 'None'}</span></div>
            </div>
        </div>
        """
        st.markdown(clean_html(telemetry_html), unsafe_allow_html=True)

        # Data Quality & Schema Validation Panel
        norm_alert, quality_issues = service.pipeline.alert_processor.validate_and_normalize(raw_alert)
        if quality_issues:
            issue_items = "".join(f"<li style='margin-bottom: 0.2rem;'>{issue}</li>" for issue in quality_issues)
            quality_html = f"""
            <div class="soc-panel" style="border-left: 3px solid #F59E0B; margin-bottom: 0.75rem;">
                <div style="font-size: 0.8rem; font-weight: 600; color: #FDE047; margin-bottom: 0.35rem;">
                    ⚠️ Telemetry Data Quality Alert ({len(quality_issues)} issue(s) detected)
                </div>
                <ul style="font-size: 0.76rem; color: #FDE047; padding-left: 1.2rem; margin: 0;">
                    {issue_items}
                </ul>
            </div>
            """
        else:
            quality_html = """
            <div class="soc-panel" style="border-left: 3px solid #10B981; padding: 0.65rem 1rem; margin-bottom: 0.75rem;">
                <div style="font-size: 0.78rem; font-weight: 600; color: #86EFAC;">
                    ✓ Schema Validation Passed: All 10 required schema fields are valid.
                </div>
            </div>
            """
        st.markdown(clean_html(quality_html), unsafe_allow_html=True)

        # Non-Mutating Evaluation Preview Panel
        preview = service.preview_alert_evaluation(selected_meta["filepath"])
        if preview:
            risk_info = preview["risk_evaluation"]
            score = risk_info["total_risk_score"]
            classification = risk_info["risk_classification"]
            candidate_pb = preview["candidate_playbook"]

            score_color = "#EF4444" if score >= 80 else ("#F97316" if score >= 60 else ("#F59E0B" if score >= 30 else "#10B981"))

            factors_rows = []
            for f in risk_info.get("triggered_factors", []):
                factors_rows.append(
                    f"""<div style="display: flex; justify-content: space-between; padding: 0.25rem 0; border-bottom: 1px dashed #1E293B;">
<span style="color: #E5E7EB;">{f['factor_id']}</span>
<span style="color: #60A5FA; font-weight: 600;">+{f['weight']} pts</span>
</div>"""
                )
            factors_content = "".join(factors_rows) if factors_rows else '<div style="color: #6B7280; font-style: italic;">No additional risk factors triggered.</div>'

            preview_html = f"""
            <div class="soc-panel" style="margin-bottom: 0.75rem;">
                <div class="soc-panel-header" style="display: flex; justify-content: space-between; align-items: center;">
                    <span>Non-Mutating Evaluation Preview</span>
                    <span style="font-size: 0.70rem; color: #9CA3AF; text-transform: none;">Dry-run calculation &bull; No log mutations</span>
                </div>
                <div style="display: flex; gap: 1rem; align-items: center; margin-bottom: 0.75rem;">
                    <div style="text-align: center; background-color: #0B0F19; border: 1px solid #1E293B; border-radius: 6px; padding: 0.5rem 1rem;">
                        <div style="font-size: 0.70rem; color: #6B7280; text-transform: uppercase;">Calculated Risk</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: {score_color};">{score}<span style="font-size: 0.8rem; color: #6B7280;">/100</span></div>
                    </div>
                    <div style="flex: 1; font-size: 0.78rem;">
                        <div><strong style="color: #E5E7EB;">Risk Tier:</strong> <span style="color: {score_color}; font-weight: 600;">{classification}</span></div>
                        <div style="margin-top: 0.2rem;"><strong style="color: #E5E7EB;">Candidate Playbook:</strong> <code style="color: #93C5FD;">{candidate_pb['playbook_id']}</code></div>
                        <div style="font-size: 0.72rem; color: #9CA3AF;">{candidate_pb['playbook_name']}</div>
                    </div>
                </div>
                <div style="font-size: 0.74rem; font-weight: 600; text-transform: uppercase; color: #6B7280; margin-bottom: 0.35rem;">Triggered Risk Factors</div>
                <div style="font-size: 0.76rem; background-color: #0B0F19; border: 1px solid #1E293B; border-radius: 4px; padding: 0.5rem 0.75rem;">
                    {factors_content}
                </div>
            </div>
            """
            st.markdown(clean_html(preview_html), unsafe_allow_html=True)

        # Optional LLM Advisory Analyst Insight Section (Gemini Developer API)
        render_gemini_insight_section(service, selected_aid, selected_meta["filepath"], st)

        # Pipeline Flow Inspection Section
        with st.expander(f"Inspect Alert Processing Pipeline Flow ({selected_aid})"):
            render_pipeline_flow_component(service, selected_meta["filepath"], st)

        # Expandable Raw JSON Section
        with st.expander(f"Inspect Raw JSON Alert Telemetry ({selected_aid})"):
            st.json(raw_alert)

        footer_hint_html = """
        <div style="font-size: 0.74rem; color: #6B7280; text-align: right; margin-top: 0.5rem;">
            <em>To execute this alert through the playbook automation pipeline, proceed to <strong>Playbook Center</strong>. For full interactive architecture inspection, view <strong>Execution & Audit</strong>.</em>
        </div>
        """
        st.markdown(clean_html(footer_hint_html), unsafe_allow_html=True)
