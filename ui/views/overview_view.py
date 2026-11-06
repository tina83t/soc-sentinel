"""SOC Overview Dashboard View.

Presents operational queue metrics, severity distributions, incident lifecycle
breakdowns, and recent alert queues derived strictly from real SOCService data.
"""

from typing import Dict, Any, List, Optional
from ui.services.soc_service import SOCService
from ui.styles.theme import (
    get_severity_badge_html,
    get_status_badge_html,
    generate_svg_donut_chart,
    generate_horizontal_bar_html,
    clean_html,
    SEVERITY_COLORS,
    STATUS_COLORS,
)


def format_overview_metrics(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Format and compute derived metrics for the SOC overview cards and distributions."""
    total_alerts = stats.get("total_alerts", 0)
    total_incidents = stats.get("total_incidents", 0)

    # Incident status distribution
    status_dist = stats.get("status_distribution", {
        "NEW": 0, "IN_PROGRESS": 0, "RESOLVED": 0, "CLOSED": 0
    })

    return {
        "total_alerts": total_alerts,
        "critical_alerts": stats.get("critical_alerts", 0),
        "high_alerts": stats.get("high_alerts", 0),
        "total_incidents": total_incidents,
        "open_incidents": stats.get("open_incidents", 0),
        "resolved_incidents": stats.get("resolved_incidents", 0),
        "status_distribution": status_dist,
        "traces_count": stats.get("traces_count", 0),
        "audit_events_count": stats.get("audit_events_count", 0)
    }


def render_overview_view(service: SOCService, st_module=None) -> None:
    """Render the full SOC Overview dashboard in Streamlit."""
    if st_module is None:
        try:
            import streamlit as st_module
        except ImportError:
            return

    st = st_module
    stats = service.get_summary_stats()
    metrics = format_overview_metrics(stats)
    alerts = service.list_alert_files()
    incidents = service.list_incidents()

    # Section 1: Headline Operational Metrics (Alerts vs Incidents)
    header_html = '<div class="soc-panel-header">Operational Queue Metrics</div>'
    st.markdown(clean_html(header_html), unsafe_allow_html=True)
    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        card1 = f"""
        <div class="soc-metric-card">
            <div class="soc-metric-label">Discovered Alerts</div>
            <div class="soc-metric-value">{metrics["total_alerts"]}</div>
            <div class="soc-metric-hint">Fictional scenarios in data/alerts</div>
        </div>
        """
        st.markdown(clean_html(card1), unsafe_allow_html=True)

    with c2:
        card2 = f"""
        <div class="soc-metric-card" style="border-left: 3px solid #EF4444;">
            <div class="soc-metric-label" style="color: #EF4444;">Critical Alerts</div>
            <div class="soc-metric-value" style="color: #FCA5A5;">{metrics["critical_alerts"]}</div>
            <div class="soc-metric-hint">Urgent triage candidates</div>
        </div>
        """
        st.markdown(clean_html(card2), unsafe_allow_html=True)

    with c3:
        card3 = f"""
        <div class="soc-metric-card" style="border-left: 3px solid #F97316;">
            <div class="soc-metric-label" style="color: #F97316;">High-Risk Alerts</div>
            <div class="soc-metric-value" style="color: #FDBA74;">{metrics["high_alerts"]}</div>
            <div class="soc-metric-hint">Elevated risk telemetry</div>
        </div>
        """
        st.markdown(clean_html(card3), unsafe_allow_html=True)

    with c4:
        card4 = f"""
        <div class="soc-metric-card" style="border-left: 3px solid #3B82F6;">
            <div class="soc-metric-label" style="color: #60A5FA;">Open Incidents</div>
            <div class="soc-metric-value" style="color: #93C5FD;">{metrics["open_incidents"]}</div>
            <div class="soc-metric-hint">Status: NEW or IN_PROGRESS</div>
        </div>
        """
        st.markdown(clean_html(card4), unsafe_allow_html=True)

    with c5:
        card5 = f"""
        <div class="soc-metric-card" style="border-left: 3px solid #10B981;">
            <div class="soc-metric-label" style="color: #34D399;">Resolved / Closed</div>
            <div class="soc-metric-value" style="color: #86EFAC;">{metrics["resolved_incidents"]}</div>
            <div class="soc-metric-hint">Remediated & formally closed</div>
        </div>
        """
        st.markdown(clean_html(card5), unsafe_allow_html=True)

    spacer_html = "<div style='height: 10px;'></div>"
    st.markdown(clean_html(spacer_html), unsafe_allow_html=True)

    # Section 2: Distribution Analytics (Self-Contained Donut Chart & Lifecycle Bars)
    col_left, col_right = st.columns(2)

    with col_left:
        sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in alerts:
            s = str(a.get("severity") or "LOW").upper()
            if s in sev_counts:
                sev_counts[s] += 1
            else:
                sev_counts[s] = 1

        donut_svg = generate_svg_donut_chart(
            counts=sev_counts,
            total_label="ALERTS",
            size=120
        )

        total_a = len(alerts) or 1
        legend_rows = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev_counts.get(sev, 0)
            pct = (count / total_a) * 100
            badge = get_severity_badge_html(sev)
            legend_rows.append(
                f"""
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; border-bottom: 1px solid #1E293B;">
                    <div>{badge}</div>
                    <div style="font-size: 0.80rem; font-weight: 600; color: #E5E7EB;">
                        {count} <span style="font-weight: 400; color: #6B7280;">({pct:.0f}%)</span>
                    </div>
                </div>
                """
            )

        card_left_html = f"""
        <div class="soc-panel">
            <div class="soc-panel-header">Discovered Alerts by Severity</div>
            <div style="display: flex; align-items: center; justify-content: space-around; gap: 1.25rem; padding: 0.5rem 0;">
                <div style="flex-shrink: 0; text-align: center;">
                    {donut_svg}
                </div>
                <div style="flex: 1; max-width: 260px;">
                    {''.join(legend_rows)}
                </div>
            </div>
        </div>
        """
        st.markdown(clean_html(card_left_html), unsafe_allow_html=True)

    with col_right:
        if metrics["total_incidents"] == 0:
            lifecycle_content = """
            <div style="padding: 1.5rem 0.5rem; text-align: center; color: #9CA3AF; font-size: 0.82rem;">
                <div style="font-size: 1.4rem; margin-bottom: 0.35rem; color: #6B7280;">📋</div>
                <div style="font-weight: 600; color: #D1D5DB; margin-bottom: 0.25rem;">0 Incidents Triaged in Current Session</div>
                <div style="font-size: 0.74rem; color: #6B7280; max-width: 380px; margin: 0 auto;">
                    Discovered alerts remain in pre-triage state. Navigate to <strong>Playbook Center</strong> to execute automated triage and generate incident records.
                </div>
            </div>
            """
        else:
            st_counts = metrics["status_distribution"]
            total_i = metrics["total_incidents"] or 1
            bar_items = []
            for st_name in ["NEW", "IN_PROGRESS", "RESOLVED", "CLOSED"]:
                count = st_counts.get(st_name, 0)
                badge = get_status_badge_html(st_name)
                color = STATUS_COLORS[st_name]["bar"]
                bar_items.append(
                    generate_horizontal_bar_html(
                        label=st_name,
                        count=count,
                        total=total_i,
                        color=color,
                        badge_html=badge
                    )
                )
            lifecycle_content = f"<div style='padding: 0.25rem 0;'>{''.join(bar_items)}</div>"

        card_right_html = f"""
        <div class="soc-panel">
            <div class="soc-panel-header">Formal Incidents by Lifecycle Status</div>
            {lifecycle_content}
        </div>
        """
        st.markdown(clean_html(card_right_html), unsafe_allow_html=True)

    # Section 3: Discovered Alert Intake Queue Table
    queue_hdr = '<div class="soc-panel-header">Discovered Alert Telemetry Queue</div>'
    st.markdown(clean_html(queue_hdr), unsafe_allow_html=True)
    if not alerts:
        st.info("No alert JSON files currently found in data/alerts.")
        return

    sub_hdr = """
    <div style="font-size: 0.76rem; color: #9CA3AF; margin-bottom: 0.75rem; display: flex; justify-content: space-between;">
        <span>Listing realistic test scenarios available in local storage (<code>data/alerts</code>).</span>
        <span><em>Read-Only Queue &bull; No Automated Mutations</em></span>
    </div>
    """
    st.markdown(clean_html(sub_hdr), unsafe_allow_html=True)

    table_rows = []
    for a in alerts:
        sev_badge = get_severity_badge_html(a.get("severity"))
        if a.get("is_processed"):
            proc_badge = f'<span style="color: #60A5FA; font-weight: 600; font-size: 0.74rem;">● {a.get("incident_id")}</span>'
        else:
            proc_badge = '<span style="color: #6B7280; font-size: 0.74rem;">○ Unprocessed</span>'

        src_ip = a.get("source_ip") or "N/A"
        host = a.get("hostname") or "N/A"
        user = a.get("username") or "N/A"

        table_rows.append(
            f"""
            <tr style="border-bottom: 1px solid #1E293B; transition: background-color 0.1s ease;">
                <td style="padding: 0.5rem 0.6rem; font-family: monospace; font-size: 0.8rem; font-weight: 600; color: #F3F4F6;">{a.get("alert_id")}</td>
                <td style="padding: 0.5rem 0.6rem; font-size: 0.75rem; color: #9CA3AF;">{a.get("timestamp")}</td>
                <td style="padding: 0.5rem 0.6rem; font-size: 0.78rem; color: #E5E7EB; font-weight: 500;">{a.get("event_type")}</td>
                <td style="padding: 0.5rem 0.6rem;">{sev_badge}</td>
                <td style="padding: 0.5rem 0.6rem; font-size: 0.76rem; font-family: monospace; color: #93C5FD;">{src_ip}</td>
                <td style="padding: 0.5rem 0.6rem; font-size: 0.76rem; color: #9CA3AF;">{host}</td>
                <td style="padding: 0.5rem 0.6rem; font-size: 0.76rem; color: #9CA3AF;">{user}</td>
                <td style="padding: 0.5rem 0.6rem;">{proc_badge}</td>
            </tr>
            """
        )

    table_card_html = f"""
    <div class="soc-panel" style="padding: 0.5rem; overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; text-align: left;">
            <thead>
                <tr style="border-bottom: 2px solid #242E42; font-size: 0.70rem; text-transform: uppercase; color: #6B7280; letter-spacing: 0.05em;">
                    <th style="padding: 0.5rem 0.6rem;">Alert ID</th>
                    <th style="padding: 0.5rem 0.6rem;">Timestamp</th>
                    <th style="padding: 0.5rem 0.6rem;">Event Type</th>
                    <th style="padding: 0.5rem 0.6rem;">Severity</th>
                    <th style="padding: 0.5rem 0.6rem;">Source IP</th>
                    <th style="padding: 0.5rem 0.6rem;">Target Host</th>
                    <th style="padding: 0.5rem 0.6rem;">User</th>
                    <th style="padding: 0.5rem 0.6rem;">Session Status</th>
                </tr>
            </thead>
            <tbody>
                {''.join(table_rows)}
            </tbody>
        </table>
    </div>
    """
    st.markdown(clean_html(table_card_html), unsafe_allow_html=True)
