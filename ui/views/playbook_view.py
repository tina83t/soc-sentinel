"""Playbook Center View for SOC Sentinel Dashboard.

Enables SOC analysts to inspect defined FortiSOAR-inspired playbooks, review
trigger conditions and required attributes, validate playbook applicability against
discovered alerts, and trigger safe simulated execution with explicit analyst confirmation.
"""

from typing import List, Dict, Any, Optional
from ui.services.soc_service import SOCService
from ui.styles.theme import get_severity_badge_html, get_status_badge_html, clean_html


def filter_playbooks(
    playbooks: List[Dict[str, Any]],
    search_query: str = "",
    tier_filter: str = "ALL"
) -> List[Dict[str, Any]]:
    """Pure filter function for playbook catalog based on text search and target tier."""
    filtered = []
    q = (search_query or "").strip().lower()
    t_filter = (tier_filter or "ALL").strip().upper()

    for pb in playbooks:
        # Tier filter
        if t_filter != "ALL" and pb.get("target_tier") != t_filter:
            continue

        # Text search across id, name, description, actions
        if q:
            searchable = " ".join([
                pb.get("playbook_id", ""),
                pb.get("name", ""),
                pb.get("description", ""),
                pb.get("purpose", ""),
                " ".join(a.get("name", "") for a in pb.get("actions", [])),
                " ".join(a.get("type", "") for a in pb.get("actions", []))
            ]).lower()
            if q not in searchable:
                continue

        filtered.append(pb)

    return filtered


def render_playbook_center_view(service: SOCService, st_module=None) -> None:
    """Render the full Playbook Center console in Streamlit."""
    if st_module is None:
        try:
            import streamlit as st_module
        except ImportError:
            return

    st = st_module
    catalog = service.get_playbook_catalog()
    all_alerts = service.list_alert_files()

    header_html = '<div class="soc-panel-header">Playbook Catalog & Controlled Automation Center</div>'
    st.markdown(clean_html(header_html), unsafe_allow_html=True)

    # Filter Bar
    c_search, c_tier = st.columns([3, 2])

    with c_search:
        search_query = st.text_input(
            "Search Playbooks",
            placeholder="Search by ID, name, action, or description...",
            label_visibility="collapsed",
            key="pb_search_query"
        )

    with c_tier:
        tier_options = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
        selected_tier = st.selectbox(
            "Tier Filter",
            options=tier_options,
            index=0,
            label_visibility="collapsed",
            key="pb_tier_select"
        )

    filtered_playbooks = filter_playbooks(
        playbooks=catalog,
        search_query=search_query,
        tier_filter=selected_tier
    )

    info_bar_html = f"""
    <div style="font-size: 0.76rem; color: #9CA3AF; margin-bottom: 0.85rem; display: flex; justify-content: space-between;">
        <span>Displaying <strong>{len(filtered_playbooks)}</strong> of {len(catalog)} defined security playbooks</span>
        <span><em>Mode: DRY_RUN_SAFE_MODE &bull; Simulation Only &bull; Zero Live Infrastructure Impact</em></span>
    </div>
    """
    st.markdown(clean_html(info_bar_html), unsafe_allow_html=True)

    if not filtered_playbooks:
        st.info("No playbooks match the specified filter criteria.")
        return

    # Two-Column Console Layout: Catalog (Left) and Workspace / Execution (Right)
    col_cat, col_work = st.columns([3.8, 6.2])

    # Session state for selected playbook ID
    if "selected_playbook_id" not in st.session_state:
        st.session_state["selected_playbook_id"] = filtered_playbooks[0]["playbook_id"]

    current_pb_ids = [p["playbook_id"] for p in filtered_playbooks]
    selected_pbid = st.session_state.get("selected_playbook_id")
    if selected_pbid not in current_pb_ids:
        selected_pbid = current_pb_ids[0]
        st.session_state["selected_playbook_id"] = selected_pbid

    # -------------------------------------------------------------------------
    # LEFT COLUMN: Playbook Catalog List
    # -------------------------------------------------------------------------
    with col_cat:
        cat_hdr_html = '<div style="font-size: 0.76rem; font-weight: 600; text-transform: uppercase; color: #6B7280; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Playbook Catalog</div>'
        st.markdown(clean_html(cat_hdr_html), unsafe_allow_html=True)

        for pb in filtered_playbooks:
            pbid = pb["playbook_id"]
            is_active = (pbid == selected_pbid)
            tier_badge = get_severity_badge_html(pb.get("target_tier", "LOW"))
            card_class = "soc-alert-card soc-alert-card-active" if is_active else "soc-alert-card"
            active_pill = '<span class="soc-inspecting-pill">INSPECTING</span>' if is_active else ""
            actions_count = len(pb.get("actions", []))
            actions_label = f"{actions_count} simulated action(s)" if actions_count else "Noise suppression / Logging"

            card_html = f"""
            <div class="{card_class}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-family: monospace; font-size: 0.85rem; font-weight: 700; color: #FFFFFF;">{pbid}</span>
                    <div style="display: flex; gap: 0.35rem; align-items: center;">
                        {active_pill}
                        {tier_badge}
                    </div>
                </div>
                <div style="font-size: 0.78rem; font-weight: 600; color: #E5E7EB; margin-top: 0.25rem;">
                    {pb.get("name")}
                </div>
                <div style="font-size: 0.72rem; color: #9CA3AF; margin-top: 0.25rem;">
                    <strong>Trigger:</strong> <code style="color: #93C5FD;">{pb.get("condition")}</code>
                </div>
                <div style="font-size: 0.70rem; color: #6B7280; margin-top: 0.25rem; display: flex; justify-content: space-between;">
                    <span>{actions_label}</span>
                    <span style="color: #34D399;">DRY_RUN_SAFE</span>
                </div>
            </div>
            """
            st.markdown(clean_html(card_html), unsafe_allow_html=True)

            if not is_active:
                if st.button(f"Inspect {pbid}", key=f"btn_select_pb_{pbid}", use_container_width=True):
                    st.session_state["selected_playbook_id"] = pbid
                    st.rerun()

    # -------------------------------------------------------------------------
    # RIGHT COLUMN: Playbook Details & Controlled Execution Console
    # -------------------------------------------------------------------------
    selected_pb = service.get_playbook_by_id(selected_pbid)

    with col_work:
        if not selected_pb:
            st.info("Select a playbook from the left catalog to inspect specifications.")
            return

        tier_badge = get_severity_badge_html(selected_pb.get("target_tier", "LOW"))

        # Section A: Playbook Specification Card
        req_attrs = selected_pb.get("required_attributes", [])
        attr_rows = []
        for ra in req_attrs:
            attr_req_text = '<span style="color: #EF4444; font-weight: 600;">Required</span>' if ra["required"] else '<span style="color: #9CA3AF;">Optional</span>'
            attr_rows.append(
                f"""<tr>
                <td style="padding: 0.35rem 0.5rem; font-family: monospace; color: #93C5FD;">{ra['attribute']}</td>
                <td style="padding: 0.35rem 0.5rem; color: #E5E7EB;">{ra['role']}</td>
                <td style="padding: 0.35rem 0.5rem;">{attr_req_text}</td>
                <td style="padding: 0.35rem 0.5rem; color: #9CA3AF; font-size: 0.70rem;">{ra['fallback']}</td>
                </tr>"""
            )

        steps_rows = []
        for s in selected_pb.get("ordered_steps", []):
            step_type_color = "#3B82F6" if s['type'] == "AUTOMATED EVALUATION" else ("#F97316" if s['type'] == "ANALYST DISPATCH" else ("#EF4444" if s['type'] == "SIMULATED CONTAINMENT" else "#10B981"))
            approval_badge = '<span style="color: #FDE047; font-size: 0.68rem; font-weight: 600;">[APPROVAL GATED]</span>' if s.get('approval_required') else '<span style="color: #34D399; font-size: 0.68rem;">[AUTO]</span>'
            steps_rows.append(
                f"""<div style="border-left: 2px solid {step_type_color}; padding-left: 0.65rem; margin-bottom: 0.5rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 600; color: #F3F4F6; font-size: 0.78rem;">Step {s['step_num']}: {s['name']}</span>
                    <div>
                        <span style="font-size: 0.68rem; color: {step_type_color}; font-weight: 700; text-transform: uppercase;">[{s['type']}]</span>
                        {approval_badge}
                    </div>
                </div>
                <div style="font-size: 0.72rem; color: #9CA3AF; margin-top: 0.15rem;">{s['description']}</div>
                </div>"""
            )

        spec_card_html = f"""
        <div class="soc-panel" style="margin-bottom: 0.85rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E293B; padding-bottom: 0.5rem; margin-bottom: 0.65rem;">
                <div>
                    <span style="font-family: monospace; font-size: 1.05rem; font-weight: 700; color: #FFFFFF;">{selected_pb['playbook_id']}</span>
                    <span style="margin-left: 0.5rem;">{tier_badge}</span>
                </div>
                <span class="soc-status-pill">DRY_RUN_SAFE_MODE</span>
            </div>
            <div style="font-size: 0.88rem; font-weight: 600; color: #F3F4F6;">{selected_pb.get('name')}</div>
            <div style="font-size: 0.78rem; color: #9CA3AF; margin-top: 0.25rem; line-height: 1.4;">{selected_pb.get('purpose')}</div>
            <div style="background-color: #0B0F19; border: 1px solid #1E293B; border-radius: 4px; padding: 0.45rem 0.65rem; margin-top: 0.5rem; font-size: 0.76rem;">
                <span style="color: #6B7280; text-transform: uppercase; font-weight: 600; font-size: 0.70rem;">Trigger Gate:</span>
                <code style="color: #93C5FD; margin-left: 0.4rem;">{selected_pb.get('condition')}</code>
            </div>
        </div>
        """
        st.markdown(clean_html(spec_card_html), unsafe_allow_html=True)

        with st.expander("Inspect Playbook Architecture & Ordered Workflow"):
            steps_card_html = f"""
            <div style="font-size: 0.76rem;">
                <div style="font-weight: 600; color: #6B7280; text-transform: uppercase; font-size: 0.70rem; margin-bottom: 0.4rem;">Ordered Workflow Steps</div>
                {''.join(steps_rows)}
                <div style="font-weight: 600; color: #6B7280; text-transform: uppercase; font-size: 0.70rem; margin-top: 0.75rem; margin-bottom: 0.3rem;">Required Alert Attributes</div>
                <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.72rem;">
                    <thead>
                        <tr style="border-bottom: 1px solid #242E42; color: #6B7280;">
                            <th style="padding: 0.3rem 0.5rem;">Attribute</th>
                            <th style="padding: 0.3rem 0.5rem;">Role</th>
                            <th style="padding: 0.3rem 0.5rem;">Requirement</th>
                            <th style="padding: 0.3rem 0.5rem;">Fallback</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(attr_rows)}
                    </tbody>
                </table>
            </div>
            """
            st.markdown(clean_html(steps_card_html), unsafe_allow_html=True)

        # Section B: Alert-to-Playbook Controlled Execution Console
        st.markdown('<div class="soc-panel-header" style="margin-top: 0.5rem;">Alert Triage & Playbook Execution Workflow</div>', unsafe_allow_html=True)

        if not all_alerts:
            st.warning("No alert files available in data/alerts for execution.")
            return

        # Alert selection dropdown
        alert_options = [a["alert_id"] for a in all_alerts]
        alert_labels = {a["alert_id"]: f"{a['alert_id']} — {a['event_type']} ({a['severity']})" for a in all_alerts}

        if "pb_center_alert_id" not in st.session_state:
            st.session_state["pb_center_alert_id"] = alert_options[0]

        curr_aid = st.session_state.get("pb_center_alert_id")
        if curr_aid not in alert_options:
            curr_aid = alert_options[0]
            st.session_state["pb_center_alert_id"] = curr_aid

        selected_alert_id = st.selectbox(
            "Select Target Alert",
            options=alert_options,
            format_func=lambda x: alert_labels.get(x, x),
            index=alert_options.index(curr_aid),
            key="pb_target_alert_select"
        )
        st.session_state["pb_center_alert_id"] = selected_alert_id

        # Validate Alert against Selected Playbook (Non-mutating)
        validation = service.validate_playbook_for_alert(selected_alert_id, selected_pbid)

        score = validation.get("risk_score", 0)
        risk_tier = validation.get("risk_tier", "LOW")
        cand_id = validation.get("candidate_playbook_id", "N/A")
        cand_name = validation.get("candidate_playbook_name", "N/A")
        is_compat = validation.get("is_compatible", False)
        is_proc = validation.get("is_already_processed", False)
        inc_id = validation.get("incident_id")
        can_exec = validation.get("can_execute", False)

        score_color = "#EF4444" if score >= 80 else ("#F97316" if score >= 60 else ("#F59E0B" if score >= 30 else "#10B981"))

        # Evaluation & Compatibility Assessment Card
        if is_proc:
            status_box_html = f"""
            <div style="background-color: rgba(59, 130, 246, 0.12); border: 1px solid #2563EB; border-radius: 4px; padding: 0.6rem 0.85rem; margin-top: 0.5rem;">
                <div style="font-weight: 600; color: #93C5FD; font-size: 0.78rem;">
                    ℹ️ ALREADY PROCESSED INTO INCIDENT
                </div>
                <div style="font-size: 0.74rem; color: #D1D5DB; margin-top: 0.2rem;">
                    Alert <code>{selected_alert_id}</code> has already completed triage. Generated incident: <strong>{inc_id}</strong>. Duplicate execution is prevented.
                </div>
            </div>
            """
        elif is_compat:
            status_box_html = f"""
            <div style="background-color: rgba(16, 185, 129, 0.12); border: 1px solid #059669; border-radius: 4px; padding: 0.6rem 0.85rem; margin-top: 0.5rem;">
                <div style="font-weight: 600; color: #86EFAC; font-size: 0.78rem;">
                    ✓ COMPATIBLE & READY FOR EXECUTION
                </div>
                <div style="font-size: 0.74rem; color: #D1D5DB; margin-top: 0.2rem;">
                    Alert satisfies {selected_pbid} trigger condition (<code>{selected_pb['condition']}</code>) at risk score {score} ({risk_tier}).
                </div>
            </div>
            """
        else:
            unmet_desc = "".join(f"<div>• {u}</div>" for u in validation.get("unmet_conditions", []))
            status_box_html = f"""
            <div style="background-color: rgba(239, 68, 68, 0.12); border: 1px solid #DC2626; border-radius: 4px; padding: 0.6rem 0.85rem; margin-top: 0.5rem;">
                <div style="font-weight: 600; color: #FCA5A5; font-size: 0.78rem;">
                    ⚠️ INCOMPATIBLE PLAYBOOK SELECTION
                </div>
                <div style="font-size: 0.74rem; color: #FCA5A5; margin-top: 0.2rem;">
                    {unmet_desc}
                </div>
                <div style="font-size: 0.72rem; color: #9CA3AF; margin-top: 0.35rem;">
                    To execute this alert, select recommended playbook <strong>{cand_id}</strong> from the catalog.
                </div>
            </div>
            """

        eval_card_html = f"""
        <div class="soc-panel" style="margin-bottom: 0.75rem;">
            <div style="display: flex; gap: 1rem; align-items: center; border-bottom: 1px solid #1E293B; padding-bottom: 0.6rem;">
                <div style="text-align: center; background-color: #0B0F19; border: 1px solid #1E293B; border-radius: 6px; padding: 0.4rem 0.85rem;">
                    <div style="font-size: 0.68rem; color: #6B7280; text-transform: uppercase;">Calculated Risk</div>
                    <div style="font-size: 1.45rem; font-weight: 700; color: {score_color};">{score}<span style="font-size: 0.75rem; color: #6B7280;">/100</span></div>
                </div>
                <div style="flex: 1; font-size: 0.78rem;">
                    <div><strong style="color: #E5E7EB;">Risk Classification:</strong> <span style="color: {score_color}; font-weight: 600;">{risk_tier}</span></div>
                    <div style="margin-top: 0.2rem;"><strong style="color: #E5E7EB;">Recommended Playbook:</strong> <code style="color: #93C5FD;">{cand_id}</code></div>
                    <div style="font-size: 0.72rem; color: #9CA3AF;">{cand_name}</div>
                </div>
            </div>
            {status_box_html}
        </div>
        """
        st.markdown(clean_html(eval_card_html), unsafe_allow_html=True)

        # Proposed Simulated Actions Preview
        actions_list = selected_pb.get("actions", [])
        if actions_list:
            act_items = []
            for a in actions_list:
                appr_str = '<span style="color: #FDE047; font-weight: 600;">[ANALYST APPROVAL REQUIRED]</span>' if a.get("approval_required") else '<span style="color: #34D399;">[AUTO EXECUTABLE]</span>'
                act_items.append(
                    f"""<li style="margin-bottom: 0.35rem; color: #E5E7EB;">
                    <strong>{a.get('name')}</strong> ({a.get('type')}) &bull; {appr_str}
                    </li>"""
                )
            actions_preview_html = f"""
            <div class="soc-panel" style="margin-bottom: 0.75rem; font-size: 0.76rem;">
                <div style="font-weight: 600; text-transform: uppercase; color: #6B7280; font-size: 0.70rem; margin-bottom: 0.35rem;">Proposed Response Actions (Safe Simulation)</div>
                <ul style="padding-left: 1.1rem; margin: 0;">
                    {''.join(act_items)}
                </ul>
            </div>
            """
            st.markdown(clean_html(actions_preview_html), unsafe_allow_html=True)

        # Confirmation Gate & Execution Trigger
        gate_hint_html = """
        <div style="font-size: 0.72rem; color: #6B7280; margin-bottom: 0.35rem;">
            SAFETY GATE: Execution requires explicit analyst confirmation. Actions are simulated in DRY_RUN_SAFE_MODE.
        </div>
        """
        st.markdown(clean_html(gate_hint_html), unsafe_allow_html=True)

        analyst_confirmed = st.checkbox(
            f"I confirm simulated execution of {selected_pbid} for alert {selected_alert_id} in DRY_RUN_SAFE_MODE.",
            value=False,
            key="chk_playbook_confirmation",
            disabled=(not can_exec)
        )

        btn_label = f"▶ Execute {selected_pbid} Workflow"
        if st.button(
            btn_label,
            key=f"btn_run_{selected_alert_id}_{selected_pbid}",
            disabled=(not can_exec or not analyst_confirmed),
            use_container_width=True
        ):
            # Execute workflow via service
            exec_res = service.execute_playbook_workflow(
                alert_id=selected_alert_id,
                playbook_id=selected_pbid,
                analyst_confirmed=analyst_confirmed
            )
            st.session_state["last_playbook_execution"] = exec_res
            st.rerun()

        # Display Execution Results (if just executed or if alert was previously processed)
        last_exec = st.session_state.get("last_playbook_execution")
        display_inc = None
        display_trace = None

        if last_exec and last_exec.get("alert_id") == selected_alert_id and last_exec.get("success"):
            display_inc = last_exec.get("incident")
            display_trace = last_exec.get("trace")
        elif is_proc:
            display_inc = service.get_incident(inc_id)
            trace_obj = service.get_trace_for_alert(selected_alert_id)
            display_trace = trace_obj.to_dict() if trace_obj else None

        if display_inc:
            sim_ids = [a.get("simulation_id") for a in display_inc.get("recommended_responses", []) if a.get("simulation_id")]
            sim_ids_str = ", ".join(sim_ids) if sim_ids else "None (Logging Only)"
            inc_status = display_inc.get("status", "NEW")
            inc_priority = display_inc.get("priority", "LOW")
            st_badge = get_status_badge_html(inc_status)
            pr_badge = get_severity_badge_html(inc_priority)

            trace_steps = display_trace.get("steps", []) if display_trace else []
            step_table_rows = []
            for s in trace_steps:
                st_color = "#34D399" if s.get("status") in {"COMPLETED", "SIMULATED / PENDING APPROVAL"} else "#FDE047"
                step_table_rows.append(
                    f"""<tr style="border-bottom: 1px solid #1E293B;">
                    <td style="padding: 0.35rem 0.5rem; font-family: monospace; color: #93C5FD;">{s.get('step_id')}</td>
                    <td style="padding: 0.35rem 0.5rem; color: #E5E7EB; font-weight: 500;">{s.get('name')}</td>
                    <td style="padding: 0.35rem 0.5rem; color: {st_color};">{s.get('status')}</td>
                    <td style="padding: 0.35rem 0.5rem; font-family: monospace; color: #9CA3AF;">{s.get('duration_ms')}ms</td>
                    <td style="padding: 0.35rem 0.5rem; color: #9CA3AF; font-size: 0.70rem;">{s.get('result_summary')}</td>
                    </tr>"""
                )

            trace_table_html = f"""
            <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.72rem; margin-top: 0.4rem;">
                <thead>
                    <tr style="border-bottom: 2px solid #242E42; color: #6B7280; text-transform: uppercase;">
                        <th style="padding: 0.3rem 0.5rem;">Step</th>
                        <th style="padding: 0.3rem 0.5rem;">Operation</th>
                        <th style="padding: 0.3rem 0.5rem;">Status</th>
                        <th style="padding: 0.3rem 0.5rem;">Duration</th>
                        <th style="padding: 0.3rem 0.5rem;">Result Summary</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(step_table_rows)}
                </tbody>
            </table>
            """ if step_table_rows else '<div style="color: #6B7280; font-style: italic;">No trace steps recorded.</div>'

            result_card_html = f"""
            <div class="soc-panel" style="margin-top: 0.85rem; border: 1px solid #059669;">
                <div class="soc-panel-header" style="color: #86EFAC; display: flex; justify-content: space-between; align-items: center;">
                    <span>✓ Execution Workflow Results</span>
                    <span style="font-size: 0.70rem; color: #34D399; text-transform: none;">SIMULATION COMPLETED</span>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-size: 0.78rem; margin-bottom: 0.65rem;">
                    <div><span style="color: #6B7280;">Incident Reference:</span> <strong style="color: #FFFFFF; font-family: monospace;">{display_inc.get('incident_id')}</strong></div>
                    <div><span style="color: #6B7280;">Lifecycle Status:</span> {st_badge}</div>
                    <div><span style="color: #6B7280;">Priority:</span> {pr_badge}</div>
                    <div><span style="color: #6B7280;">Execution Mode:</span> <code style="color: #34D399;">DRY_RUN_SAFE_MODE</code></div>
                    <div style="grid-column: span 2;"><span style="color: #6B7280;">Simulated Action IDs:</span> <code style="color: #93C5FD;">{sim_ids_str}</code></div>
                </div>
                <div style="font-weight: 600; text-transform: uppercase; color: #6B7280; font-size: 0.70rem; margin-top: 0.5rem;">Step-by-Step Execution Trace</div>
                {trace_table_html}
            </div>
            """
            st.markdown(clean_html(result_card_html), unsafe_allow_html=True)
