"""SOC Sentinel - Operations Console Application Shell.

Modular Streamlit web application providing a SOC operations console
for alert triage, risk evaluation, conditional playbook automation,
and incident lifecycle management.
"""

import sys
import os

# Ensure project root is available in module search path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import streamlit as st
    STREAMLIT_AVAILABLE = True
except ImportError:
    st = None
    STREAMLIT_AVAILABLE = False

from ui.services.soc_service import SOCService, get_soc_service
from ui.styles.theme import apply_soc_theme, clean_html
from ui.views.overview_view import render_overview_view
from ui.views.alerts_view import render_alerts_view
from ui.views.playbook_view import render_playbook_center_view


NAVIGATION_PAGES = [
    "SOC Overview",
    "Alert Management",
    "Playbook Center",
    "Incident Management",
    "Execution & Audit"
]


def init_session_state() -> None:
    """Initialize session state holding a single SOCService instance."""
    if "soc_service" not in st.session_state:
        st.session_state.soc_service = get_soc_service(base_dir=PROJECT_ROOT)

    if "current_page" not in st.session_state:
        st.session_state.current_page = "SOC Overview"


def render_header(active_page: str) -> None:
    """Render top application banner with operational state."""
    banner_html = f"""
    <div class="soc-header-banner">
        <div class="soc-title-container">
            <h1>SOC Sentinel</h1>
            <div class="soc-subtitle">
                Security Operations Center Alert Triage & Response Automation Console | <strong>{active_page}</strong>
            </div>
        </div>
        <div style="display: flex; gap: 0.5rem; align-items: center;">
            <span class="soc-status-pill">
                <span class="soc-status-dot"></span>
                DRY_RUN_SAFE_MODE
            </span>
            <span class="soc-status-pill" style="background-color: rgba(59, 130, 246, 0.12); color: #60A5FA; border-color: rgba(59, 130, 246, 0.3);">
                SESSION IN-MEMORY
            </span>
        </div>
    </div>
    """
    st.markdown(clean_html(banner_html), unsafe_allow_html=True)


def render_sidebar() -> str:
    """Render sidebar navigation and operations metadata."""
    with st.sidebar:
        brand_html = """
        <div class="soc-brand-block">
            <div class="soc-brand-title">
                <span>🛡️</span> SOC SENTINEL
            </div>
            <div class="soc-brand-subtitle">Operations & Automation Console</div>
        </div>
        """
        st.markdown(clean_html(brand_html), unsafe_allow_html=True)

        st.caption("NAVIGATION")
        selected_page = st.radio(
            label="Console Views",
            options=NAVIGATION_PAGES,
            index=NAVIGATION_PAGES.index(st.session_state.current_page),
            label_visibility="collapsed"
        )
        st.session_state.current_page = selected_page

        st.markdown("---")
        st.caption("OPERATIONAL ENVIRONMENT")
        env_html = """
        <div style="font-size: 0.76rem; color: #9CA3AF; line-height: 1.6;">
            <div><strong>Engine:</strong> FortiSOAR-Inspired Prototype</div>
            <div><strong>Response Mode:</strong> Safe Simulation Only</div>
            <div><strong>Containment:</strong> Analyst Approval Gated</div>
            <div><strong>Persistence:</strong> In-Memory (Session State)</div>
            <div><strong>Base Directory:</strong> <code>soc-automation</code></div>
        </div>
        """
        st.markdown(clean_html(env_html), unsafe_allow_html=True)

        st.markdown("---")
        st.caption("SAFETY GUARDRAILS")
        safety_html = """
        <div style="font-size: 0.74rem; color: #6B7280; line-height: 1.4;">
            Active containment recommendations (host isolation, account suspension, IP block)
            are strictly simulated. No commands are dispatched to live infrastructure.
        </div>
        """
        st.markdown(clean_html(safety_html), unsafe_allow_html=True)

    return selected_page


def render_page_placeholder(page_name: str) -> None:
    """Render clean, themed placeholder for views to be implemented in Step 2.3."""
    placeholders = {
        "SOC Overview": {
            "title": "SOC Executive & Queue Overview",
            "desc": "Real-time summary derived from live pipeline metrics: alert counts, severity distribution, active incident queues, and recent playbook executions.",
            "specs": "• Live Discovered Alert Metrics &bull; Open/Resolved Incident Counts &bull; Severity Breakdown &bull; Recent Triage Table"
        },
        "Alert Management": {
            "title": "Alert Ingestion & Triage Queue",
            "desc": "Browse discovered raw alert files, inspect schema validation and telemetry quality, filter by severity, and preview risk evaluation without mutating system state.",
            "specs": "• Discovered Alerts Table &bull; Severity & Keyword Filters &bull; Telemetry Quality Flags &bull; Pre-Execution Inspection"
        },
        "Playbook Center": {
            "title": "Playbook Catalog & Controlled Automation",
            "desc": "Inspect defined playbooks (PB-CRIT-001 through PB-LOW-004), review rule thresholds and condition gates, and trigger controlled single-alert triage through the existing backend.",
            "specs": "• Playbook Condition Gates &bull; Dry-Run Containment Preview &bull; Single-Alert Controlled Execution &bull; Execution Trace Linkage"
        },
        "Incident Management": {
            "title": "Incident Dossier & Lifecycle Progression",
            "desc": "Manage formal security incidents through verified lifecycle states (NEW, IN_PROGRESS, RESOLVED, CLOSED), assign analysts, record investigation notes, and enforce transition validation.",
            "specs": "• 4-State Lifecycle Control &bull; Transition Validation &bull; Analyst Assignment &bull; Timestamped Notes & Resolution History"
        },
        "Execution & Audit": {
            "title": "Playbook Execution Trace & Audit Trail",
            "desc": "Inspect granular step-by-step execution traces with real timing, module attribution, and decision gates, paired with structured tamper-evident audit history from soc_automation.log.",
            "specs": "• 9-Step Execution Traces &bull; Microsecond Durations &bull; Module Attribution &bull; Searchable Audit Event Log"
        }
    }

    info = placeholders.get(page_name, {
        "title": page_name,
        "desc": "This view will be connected to backend data in the next implementation stage.",
        "specs": "Implementation in Step 2.3"
    })

    placeholder_html = f"""
    <div class="soc-placeholder-box">
        <div class="soc-placeholder-title">{info["title"]}</div>
        <div class="soc-placeholder-desc">{info["desc"]}</div>
        <div class="soc-placeholder-specs">
            <strong>Target Capabilities (Step 2.3):</strong><br>
            {info["specs"]}
        </div>
        <div style="margin-top: 1.5rem; font-size: 0.75rem; color: #4B5563;">
            Shell & Layout Initialized &bull; Session State Connected &bull; Ready for Step 2.3 Component Injection
        </div>
    </div>
    """
    st.markdown(clean_html(placeholder_html), unsafe_allow_html=True)


def main() -> None:
    """Application main entry point."""
    if not STREAMLIT_AVAILABLE:
        print("[!] Streamlit is required to run the SOC Sentinel dashboard.")
        print("[!] Core CLI triage remains fully functional via: python3 main.py")
        print("[!] To install Streamlit: pip install 'streamlit>=1.30.0'")
        sys.exit(0)

    st.set_page_config(
        page_title="SOC Sentinel - Operations Console",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Inject dark console styling
    apply_soc_theme(st)

    # Initialize single SOCService in session state
    init_session_state()

    # Sidebar navigation
    active_page = render_sidebar()

    # Header banner
    render_header(active_page)

    # Page content container
    if active_page == "SOC Overview":
        render_overview_view(st.session_state.soc_service, st)
    elif active_page == "Alert Management":
        render_alerts_view(st.session_state.soc_service, st)
    elif active_page == "Playbook Center":
        render_playbook_center_view(st.session_state.soc_service, st)
    else:
        render_page_placeholder(active_page)


if __name__ == "__main__":
    main()
