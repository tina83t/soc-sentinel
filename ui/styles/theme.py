"""Centralized SOC Dark Theme and Styling for SOC Sentinel Dashboard.

Implements an information-dense, high-contrast dark operations console:
- Charcoal / dark navy background palette (#0B0F19, #111827, #1E293B)
- Subtle, clean panel borders (#242E42, #1E293B)
- High-contrast readable typography (#F3F4F6, #9CA3AF)
- Restrained severity colors: Red (Critical), Orange (High), Amber (Medium), Green (Low)
- Restrained lifecycle colors: Blue (New), Amber (In Progress), Green (Resolved), Slate (Closed)
- Clean HTML sanitization to prevent Markdown code block triggers
- Native zero-dependency SVG chart helpers for distributions
"""

import math
from typing import Dict, Any, Optional

SEVERITY_COLORS: Dict[str, Dict[str, str]] = {
    "CRITICAL": {
        "text": "#FCA5A5",
        "bg": "rgba(239, 68, 68, 0.16)",
        "border": "#DC2626",
        "dot": "#EF4444"
    },
    "HIGH": {
        "text": "#FDBA74",
        "bg": "rgba(249, 115, 22, 0.16)",
        "border": "#EA580C",
        "dot": "#F97316"
    },
    "MEDIUM": {
        "text": "#FDE047",
        "bg": "rgba(245, 158, 11, 0.16)",
        "border": "#D97706",
        "dot": "#F59E0B"
    },
    "LOW": {
        "text": "#86EFAC",
        "bg": "rgba(16, 185, 129, 0.16)",
        "border": "#059669",
        "dot": "#10B981"
    },
    "INFORMATIONAL": {
        "text": "#93C5FD",
        "bg": "rgba(59, 130, 246, 0.16)",
        "border": "#2563EB",
        "dot": "#3B82F6"
    },
    "UNKNOWN": {
        "text": "#D1D5DB",
        "bg": "rgba(107, 114, 128, 0.16)",
        "border": "#4B5563",
        "dot": "#9CA3AF"
    }
}

STATUS_COLORS: Dict[str, Dict[str, str]] = {
    "NEW": {
        "text": "#93C5FD",
        "bg": "rgba(59, 130, 246, 0.16)",
        "border": "#2563EB",
        "bar": "#3B82F6"
    },
    "IN_PROGRESS": {
        "text": "#FDE047",
        "bg": "rgba(245, 158, 11, 0.16)",
        "border": "#D97706",
        "bar": "#F59E0B"
    },
    "RESOLVED": {
        "text": "#86EFAC",
        "bg": "rgba(16, 185, 129, 0.16)",
        "border": "#059669",
        "bar": "#10B981"
    },
    "CLOSED": {
        "text": "#9CA3AF",
        "bg": "rgba(75, 85, 99, 0.16)",
        "border": "#4B5563",
        "bar": "#6B7280"
    }
}


def clean_html(html_str: str) -> str:
    """Strip leading and trailing whitespace on each line to prevent markdown code block trigger.

    In CommonMark/Markdown, any line indented with 4 or more spaces (or separated by blank
    lines) is parsed as an indented code block (<pre><code>). Stripping each line and removing
    blank lines ensures HTML is always rendered directly as raw markup in Streamlit.
    """
    if not html_str:
        return ""
    lines = [line.strip() for line in html_str.splitlines() if line.strip()]
    return "\n".join(lines)


def get_soc_theme_css() -> str:
    """Return the centralized CSS rules for the SOC operations console."""
    return """
/* --- SOC SENTINEL CONSOLE DARK PALETTE --- */
:root {
    --soc-bg-main: #0B0F19;
    --soc-bg-card: #111827;
    --soc-bg-elevated: #161F30;
    --soc-border: #242E42;
    --soc-border-subtle: #1E293B;
    --soc-text-main: #F3F4F6;
    --soc-text-muted: #9CA3AF;
    --soc-text-dim: #6B7280;
    --soc-accent: #3B82F6;
}

/* Main Background and Container Spacing */
.stApp {
    background-color: var(--soc-bg-main);
    color: var(--soc-text-main);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

/* --- Streamlit Top Header & Toolbar Customization --- */
header[data-testid="stHeader"],
[data-testid="stHeader"] {
    background-color: rgba(11, 15, 25, 0.95) !important;
    border-bottom: 1px solid var(--soc-border-subtle) !important;
    backdrop-filter: blur(8px);
    z-index: 99999;
}

[data-testid="stToolbar"] {
    right: 1.5rem !important;
    top: 0.5rem !important;
}

[data-testid="stToolbar"] button,
[data-testid="stActionButton"] {
    background-color: transparent !important;
    color: var(--soc-text-muted) !important;
    border: none !important;
}

[data-testid="stToolbar"] button:hover,
[data-testid="stActionButton"]:hover {
    background-color: var(--soc-bg-card) !important;
    color: var(--soc-text-main) !important;
}

/* Hide Streamlit deploy and decoration */
[data-testid="stAppDeployButton"],
.stAppDeployButton,
#MainMenu > li > a[href*="streamlit.io"],
footer {
    display: none !important;
}

/* Container Spacing with Top Header Clearance */
.block-container {
    padding-top: 3.5rem !important;
    padding-bottom: 2rem !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    max-width: 100% !important;
}

/* Sidebar Customization */
[data-testid="stSidebar"] {
    background-color: #080C14 !important;
    border-right: 1px solid var(--soc-border) !important;
}

[data-testid="stSidebar"] hr {
    margin: 1rem 0 !important;
    border-color: var(--soc-border) !important;
}

/* Card and Panel Styling */
.soc-panel {
    background-color: var(--soc-bg-card);
    border: 1px solid var(--soc-border);
    border-radius: 6px;
    padding: 1.15rem;
    margin-bottom: 1rem;
    box-sizing: border-box;
}

.soc-panel-header {
    font-size: 0.88rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--soc-text-muted);
    border-bottom: 1px solid var(--soc-border-subtle);
    padding-bottom: 0.5rem;
    margin-bottom: 0.85rem;
}

/* Operational Metric Card */
.soc-metric-card {
    background-color: var(--soc-bg-card);
    border: 1px solid var(--soc-border);
    border-radius: 6px;
    padding: 0.9rem 1rem;
    text-align: left;
    min-height: 95px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    box-sizing: border-box;
    transition: transform 0.15s ease, border-color 0.15s ease;
}

.soc-metric-card:hover {
    border-color: #334155;
}

.soc-metric-label {
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--soc-text-dim);
}

.soc-metric-value {
    font-size: 1.7rem;
    font-weight: 700;
    color: var(--soc-text-main);
    line-height: 1.2;
    margin-top: 0.2rem;
}

.soc-metric-hint {
    font-size: 0.72rem;
    color: var(--soc-text-muted);
    margin-top: 0.25rem;
}

/* Restrained Badges */
.soc-badge {
    display: inline-block;
    padding: 0.16rem 0.5rem;
    border-radius: 4px;
    font-size: 0.70rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    text-transform: uppercase;
    white-space: nowrap;
}

/* Header & Banner Styles */
.soc-header-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.85rem 1.25rem;
    background-color: var(--soc-bg-card);
    border: 1px solid var(--soc-border);
    border-radius: 6px;
    margin-bottom: 1.25rem;
    box-sizing: border-box;
}

.soc-title-container h1 {
    font-size: 1.35rem !important;
    font-weight: 700 !important;
    color: #FFFFFF !important;
    margin: 0 !important;
    padding: 0 !important;
    letter-spacing: -0.01em;
}

.soc-subtitle {
    font-size: 0.80rem;
    color: var(--soc-text-muted);
    margin-top: 0.15rem;
}

.soc-status-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.2rem 0.6rem;
    border-radius: 9999px;
    font-size: 0.70rem;
    font-weight: 600;
    background-color: rgba(16, 185, 129, 0.12);
    color: #34D399;
    border: 1px solid rgba(16, 185, 129, 0.3);
}

.soc-status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background-color: #10B981;
}

/* Sidebar Brand Block */
.soc-brand-block {
    padding: 0.5rem 0.25rem 1rem 0.25rem;
    border-bottom: 1px solid var(--soc-border);
    margin-bottom: 1rem;
}

.soc-brand-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: #FFFFFF;
    display: flex;
    align-items: center;
    gap: 0.4rem;
}

.soc-brand-subtitle {
    font-size: 0.72rem;
    color: var(--soc-text-dim);
    margin-top: 0.2rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* Alert Master-Detail Cards */
.soc-alert-card {
    border: 1px solid var(--soc-border-subtle);
    background-color: #0D1321;
    border-radius: 6px;
    padding: 0.65rem 0.75rem;
    margin-bottom: 0.35rem;
    box-sizing: border-box;
    transition: border-color 0.15s ease, background-color 0.15s ease;
}

.soc-alert-card:hover {
    border-color: var(--soc-border);
    background-color: #111827;
}

.soc-alert-card-active {
    border: 1px solid #3B82F6 !important;
    background-color: rgba(59, 130, 246, 0.09) !important;
    box-shadow: 0 0 0 1px rgba(59, 130, 246, 0.25);
}

.soc-inspecting-pill {
    display: inline-block;
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.04em;
    background-color: rgba(59, 130, 246, 0.2);
    color: #93C5FD;
    border: 1px solid #3B82F6;
    text-transform: uppercase;
}

/* Streamlit Buttons inside Dark SOC Console */
.stButton > button {
    background-color: #1E293B !important;
    color: #F3F4F6 !important;
    border: 1px solid #334155 !important;
    border-radius: 5px !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
    padding: 0.35rem 0.75rem !important;
    margin-bottom: 0.5rem !important;
    transition: all 0.15s ease !important;
}

.stButton > button:hover {
    background-color: #2D3748 !important;
    border-color: #4B5563 !important;
    color: #FFFFFF !important;
}

.stButton > button:active {
    background-color: #3B82F6 !important;
    border-color: #2563EB !important;
    color: #FFFFFF !important;
}

/* Inputs and Selectboxes */
.stTextInput > div > div > input,
.stSelectbox > div > div > div {
    background-color: #111827 !important;
    color: #F3F4F6 !important;
    border: 1px solid #242E42 !important;
    border-radius: 5px !important;
    font-size: 0.82rem !important;
}

.stTextInput > div > div > input:focus,
.stSelectbox > div > div > div:focus {
    border-color: #3B82F6 !important;
    box-shadow: 0 0 0 1px #3B82F6 !important;
}

/* Placeholder Container */
.soc-placeholder-box {
    background-color: var(--soc-bg-card);
    border: 1px dashed var(--soc-border);
    border-radius: 6px;
    padding: 2.5rem 1.5rem;
    text-align: center;
    margin-top: 1rem;
    box-sizing: border-box;
}

.soc-placeholder-title {
    font-size: 1.15rem;
    font-weight: 600;
    color: var(--soc-text-main);
    margin-bottom: 0.5rem;
}

.soc-placeholder-desc {
    font-size: 0.85rem;
    color: var(--soc-text-muted);
    max-width: 600px;
    margin: 0 auto 1.25rem auto;
    line-height: 1.5;
}

.soc-placeholder-specs {
    display: inline-block;
    text-align: left;
    background-color: var(--soc-bg-main);
    border: 1px solid var(--soc-border-subtle);
    border-radius: 4px;
    padding: 0.75rem 1rem;
    font-size: 0.78rem;
    color: var(--soc-text-dim);
}
"""


def apply_soc_theme(st_module=None) -> None:
    """Inject centralized dark console CSS into the Streamlit application."""
    if st_module is None:
        try:
            import streamlit as st_module
        except ImportError:
            return

    css = get_soc_theme_css()
    st_module.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def get_severity_badge_html(severity: str) -> str:
    """Render a styled HTML badge for alert or incident severity."""
    sev = str(severity or "UNKNOWN").strip().upper()
    colors = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["UNKNOWN"])
    return (
        f'<span class="soc-badge" style="background-color: {colors["bg"]}; '
        f'color: {colors["text"]}; border: 1px solid {colors["border"]};">'
        f'{sev}</span>'
    )


def get_status_badge_html(status: str) -> str:
    """Render a styled HTML badge for an incident lifecycle status."""
    st = str(status or "NEW").strip().upper()
    colors = STATUS_COLORS.get(st, STATUS_COLORS["NEW"])
    label = st.replace("_", " ")
    return (
        f'<span class="soc-badge" style="background-color: {colors["bg"]}; '
        f'color: {colors["text"]}; border: 1px solid {colors["border"]};">'
        f'{label}</span>'
    )


def generate_svg_donut_chart(
    counts: Dict[str, int],
    colors: Optional[Dict[str, str]] = None,
    total_label: str = "ALERTS",
    size: int = 130
) -> str:
    """Generate a zero-dependency SVG donut chart visualizing distribution proportions.

    Uses standard stroke-dasharray calculations to produce smooth circular arcs
    in pure SVG without requiring matplotlib, altair, or external JS libraries.
    """
    if colors is None:
        colors = {
            "CRITICAL": SEVERITY_COLORS["CRITICAL"]["dot"],
            "HIGH": SEVERITY_COLORS["HIGH"]["dot"],
            "MEDIUM": SEVERITY_COLORS["MEDIUM"]["dot"],
            "LOW": SEVERITY_COLORS["LOW"]["dot"],
            "INFORMATIONAL": SEVERITY_COLORS["INFORMATIONAL"]["dot"],
            "UNKNOWN": SEVERITY_COLORS["UNKNOWN"]["dot"]
        }

    total = sum(counts.values())
    radius = 42
    stroke_width = 14
    circ = 2 * math.pi * radius  # ~263.89

    if total == 0:
        return (
            f'<svg viewBox="0 0 130 130" width="{size}" height="{size}">'
            f'<circle cx="65" cy="65" r="{radius}" fill="none" stroke="#1E293B" stroke-width="{stroke_width}" />'
            f'<text x="65" y="69" text-anchor="middle" fill="#6B7280" font-size="12" font-weight="600">0</text>'
            f'</svg>'
        )

    # Base track circle
    elements = [
        f'<circle cx="65" cy="65" r="{radius}" fill="none" stroke="#1E293B" stroke-width="{stroke_width}" />'
    ]

    accum = 0.0
    for key, count in counts.items():
        if count <= 0:
            continue
        frac = count / total
        dash = frac * circ
        offset = -(accum * circ)
        color = colors.get(key, "#6B7280")
        elements.append(
            f'<circle cx="65" cy="65" r="{radius}" fill="none" stroke="{color}" stroke-width="{stroke_width}" '
            f'stroke-dasharray="{dash:.2f} {circ:.2f}" stroke-dashoffset="{offset:.2f}" '
            f'transform="rotate(-90 65 65)" stroke-linecap="butt" />'
        )
        accum += frac

    # Center summary text
    center_text = (
        f'<text x="65" y="63" text-anchor="middle" fill="#FFFFFF" font-size="16" font-weight="700">{total}</text>'
        f'<text x="65" y="77" text-anchor="middle" fill="#9CA3AF" font-size="9" font-weight="600" letter-spacing="0.05em">{total_label}</text>'
    )
    elements.append(center_text)

    return f'<svg viewBox="0 0 130 130" width="{size}" height="{size}">' + "".join(elements) + "</svg>"


def generate_horizontal_bar_html(
    label: str,
    count: int,
    total: int,
    color: str,
    badge_html: str = ""
) -> str:
    """Generate an accessible horizontal progress bar row for lifecycle states."""
    pct = (count / total * 100) if total > 0 else 0
    badge_part = badge_html if badge_html else f'<span style="font-size: 0.78rem; font-weight: 600; color: #E5E7EB;">{label}</span>'
    return f"""<div style="margin-bottom: 0.65rem;">
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
<div>{badge_part}</div>
<div style="font-size: 0.78rem; font-weight: 600; color: #E5E7EB;">{count} <span style="font-weight: 400; color: #6B7280;">({pct:.0f}%)</span></div>
</div>
<div style="background-color: #1E293B; height: 6px; border-radius: 3px; overflow: hidden;">
<div style="background-color: {color}; width: {pct:.1f}%; height: 100%; border-radius: 3px;"></div>
</div>
</div>"""
