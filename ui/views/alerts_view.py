"""Alert Management View for SOC Sentinel Dashboard.

Allows SOC analysts to discover, filter, inspect, and evaluate raw alert telemetry
prior to executing playbooks, with schema validation quality checks and non-mutating
risk score previews.
"""

from typing import List, Dict, Any, Optional
from ui.services.soc_service import SOCService
from ui.styles.theme import get_severity_badge_html, clean_html


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

        # Expandable Raw JSON Section
        with st.expander(f"Inspect Raw JSON Alert Telemetry ({selected_aid})"):
            st.json(raw_alert)

        footer_hint_html = """
        <div style="font-size: 0.74rem; color: #6B7280; text-align: right; margin-top: 0.5rem;">
            <em>To execute this alert through the playbook automation pipeline, proceed to <strong>Playbook Center</strong>.</em>
        </div>
        """
        st.markdown(clean_html(footer_hint_html), unsafe_allow_html=True)
