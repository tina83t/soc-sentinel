import unittest

from ui.styles.theme import (
    get_soc_theme_css,
    get_severity_badge_html,
    get_status_badge_html,
    generate_svg_donut_chart,
    generate_horizontal_bar_html,
    clean_html,
    SEVERITY_COLORS,
    STATUS_COLORS,
)
import ui.app as app_module


class TestSOCThemeAndAppShell(unittest.TestCase):

    def test_theme_css_contains_core_tokens(self):
        css = get_soc_theme_css()
        self.assertIsInstance(css, str)
        self.assertIn("#0B0F19", css)  # Main dark background
        self.assertIn("#111827", css)  # Card background
        self.assertIn("soc-panel", css)
        self.assertIn("soc-badge", css)
        self.assertIn("soc-metric-card", css)
        self.assertIn("soc-header-banner", css)
        # Header and toolbar styling
        self.assertIn("stHeader", css)
        self.assertIn("stToolbar", css)
        self.assertIn("padding-top: 3.5rem", css)
        # Alert card selection styling
        self.assertIn("soc-alert-card", css)
        self.assertIn("soc-alert-card-active", css)
        self.assertIn("soc-inspecting-pill", css)

    def test_severity_colors_coverage(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]:
            self.assertIn(sev, SEVERITY_COLORS)
            colors = SEVERITY_COLORS[sev]
            self.assertIn("text", colors)
            self.assertIn("bg", colors)
            self.assertIn("border", colors)
            self.assertIn("dot", colors)

    def test_status_colors_coverage(self):
        for st in ["NEW", "IN_PROGRESS", "RESOLVED", "CLOSED"]:
            self.assertIn(st, STATUS_COLORS)
            colors = STATUS_COLORS[st]
            self.assertIn("text", colors)
            self.assertIn("bg", colors)
            self.assertIn("border", colors)
            self.assertIn("bar", colors)

    def test_badge_html_generation(self):
        crit_badge = get_severity_badge_html("CRITICAL")
        self.assertIn("soc-badge", crit_badge)
        self.assertIn("CRITICAL", crit_badge)
        self.assertIn(SEVERITY_COLORS["CRITICAL"]["text"], crit_badge)

        status_badge = get_status_badge_html("IN_PROGRESS")
        self.assertIn("soc-badge", status_badge)
        self.assertIn("IN PROGRESS", status_badge)
        self.assertIn(STATUS_COLORS["IN_PROGRESS"]["text"], status_badge)

        # Fallback for unknown
        unknown_badge = get_severity_badge_html("INVALID_SEV")
        self.assertIn("INVALID_SEV", unknown_badge)

    def test_app_shell_attributes_and_navigation(self):
        self.assertEqual(len(app_module.NAVIGATION_PAGES), 5)
        self.assertIn("SOC Overview", app_module.NAVIGATION_PAGES)
        self.assertIn("Alert Management", app_module.NAVIGATION_PAGES)
        self.assertIn("Playbook Center", app_module.NAVIGATION_PAGES)
        self.assertIn("Incident Management", app_module.NAVIGATION_PAGES)
        self.assertIn("Execution & Audit", app_module.NAVIGATION_PAGES)

    def test_svg_donut_chart_generation(self):
        counts = {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 1, "LOW": 1}
        svg = generate_svg_donut_chart(counts, total_label="ALERTS", size=120)
        self.assertIn("<svg", svg)
        self.assertIn("viewBox=\"0 0 130 130\"", svg)
        self.assertIn("stroke-dasharray", svg)
        self.assertIn("transform=\"rotate(-90", svg)
        self.assertIn(">5</text>", svg)
        self.assertIn(">ALERTS</text>", svg)

    def test_svg_donut_chart_empty(self):
        counts = {"CRITICAL": 0, "HIGH": 0}
        svg = generate_svg_donut_chart(counts, total_label="ALERTS")
        self.assertIn("<svg", svg)
        self.assertIn(">0</text>", svg)
        self.assertNotIn("stroke-dasharray", svg)

    def test_horizontal_bar_html_generation(self):
        bar_html = generate_horizontal_bar_html(
            label="NEW",
            count=3,
            total=4,
            color="#3B82F6",
            badge_html="<span class='soc-badge'>NEW</span>"
        )
        self.assertIn("NEW", bar_html)
        self.assertIn("3", bar_html)
        self.assertIn("75%", bar_html)
        self.assertIn("width: 75.0%", bar_html)
        self.assertIn("#3B82F6", bar_html)

    def test_clean_html_strips_indented_lines(self):
        indented = """
            <div class="soc-panel">
                <span>Test</span>
            </div>
        """
        cleaned = clean_html(indented)
        for line in cleaned.splitlines():
            self.assertFalse(line.startswith("    "), f"Line has 4+ leading spaces: {line}")
        self.assertIn('<div class="soc-panel">', cleaned)
        self.assertIn('<span>Test</span>', cleaned)


if __name__ == "__main__":
    unittest.main()
