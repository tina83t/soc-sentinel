"""Gemini LLM Advisory Analyst Insight Integration for SOC Sentinel.

Provides optional, advisory natural-language explanations of alert telemetry,
contextual enrichment, risk scores, and playbook routing using Google's official
GenAI SDK (google-genai).

Safety Guarantees:
- Strictly advisory: does not modify risk scores, incident verdicts, or playbooks.
- Non-mutating: zero containment actions, shell commands, or database writes.
- Credential-safe: never logs, exposes, or hardcodes API keys.
- Context-minimized: sends only sanitized synthetic alert telemetry and flags.
- Grounding-enforced: IP classification annotations prevent mislabeling documentation
  ranges (RFC 5737) as real internet sources; post-response validation flags unsupported
  factual claims before the caller receives the result.
"""

import sys
import os
import re
import json
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Ensure workspace .venv packages are discoverable even if invoked via system python
_VENV_SITE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", ".venv", "lib", "python3.14", "site-packages")
)
if os.path.exists(_VENV_SITE) and _VENV_SITE not in sys.path:
    sys.path.insert(0, _VENV_SITE)

try:
    from pydantic import BaseModel, Field
    PYDANTIC_AVAILABLE = True
except ImportError:
    class BaseModel:
        def model_dump(self):
            return dict(self.__dict__)
        @classmethod
        def model_validate(cls, data):
            return data
    def Field(*args, **kwargs):
        return None
    PYDANTIC_AVAILABLE = False

try:
    from google import genai
    from google.genai import types
    from google.genai.errors import APIError
    GENAI_AVAILABLE = True
except ImportError:
    genai = None
    types = None
    APIError = Exception
    GENAI_AVAILABLE = False

from modules.audit_logger import redact_sensitive_data


DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"

# RFC 5737 documentation IPv4 ranges — these are reserved for DOCUMENTATION and
# EXAMPLE purposes only (IETF RFC 5737). They are NEVER real internet addresses.
# Any threat-intel match against these IPs is local simulation data only.
_RFC5737_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
]
_RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _classify_ip(ip_str: str) -> str:
    """Classify an IP address string into a scope category.

    Returns one of:
        "RFC5737_DOCUMENTATION" — IETF RFC 5737 test/documentation range (not a real internet address)
        "RFC1918_PRIVATE"       — RFC 1918 private range (internal network address)
        "LOOPBACK"              — Loopback address (127.0.0.0/8 or ::1)
        "LINK_LOCAL"            — Link-local address (169.254.0.0/16 or fe80::/10)
        "PUBLIC"                — Globally routable public internet address
        "UNKNOWN"               — Could not parse as a valid IP address
    """
    if not ip_str or ip_str in ("None", "N/A", ""):
        return "UNKNOWN"
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return "UNKNOWN"

    if addr.is_loopback:
        return "LOOPBACK"
    if addr.is_link_local:
        return "LINK_LOCAL"
    for net in _RFC5737_NETWORKS:
        if addr in net:
            return "RFC5737_DOCUMENTATION"
    if isinstance(addr, ipaddress.IPv4Address):
        for net in _RFC1918_NETWORKS:
            if addr in net:
                return "RFC1918_PRIVATE"
    if addr.is_private:
        return "RFC1918_PRIVATE"
    return "PUBLIC"


def _ip_scope_note(ip_str: str, classification: str) -> str:
    """Return a mandatory grounding note for the given IP classification."""
    if classification == "RFC5737_DOCUMENTATION":
        return (
            f"MANDATORY GROUNDING NOTE: {ip_str} is from IETF RFC 5737 "
            f"({ip_str} belongs to a documentation-only range). "
            f"This is NOT a real internet address. "
            f"Any threat-intelligence match in this dataset is from a LOCAL OFFLINE "
            f"SIMULATED DATABASE for demonstration purposes only — it does NOT represent "
            f"verified external threat intelligence about this IP."
        )
    if classification == "RFC1918_PRIVATE":
        return (
            f"SCOPE NOTE: {ip_str} is an RFC 1918 private/internal network address. "
            f"It is not routable on the public internet."
        )
    if classification == "LOOPBACK":
        return f"SCOPE NOTE: {ip_str} is a loopback address (local machine only)."
    if classification == "LINK_LOCAL":
        return f"SCOPE NOTE: {ip_str} is a link-local address."
    return ""


def _validate_insight_against_context(insight: dict, context: dict) -> dict:
    """Validate the Gemini response against the supplied sanitized context.

    Checks for unsupported factual claims such as invented IPs, usernames,
    hostnames, and fabricated numerical confidence percentages.

    Args:
        insight: The parsed AnalystInsight dict returned by Gemini.
        context: The sanitized context dict produced by sanitize_alert_context().

    Returns:
        {
            "warnings": List[str],          # Human-readable warning messages
            "has_unsupported_claims": bool  # True if any unsupported claim was detected
        }
    """
    warnings: List[str] = []
    alert = context.get("alert", {})
    enrichment = context.get("enrichment", {})

    known_ips = set()
    for field in ("source_ip", "destination_ip"):
        v = alert.get(field, "None")
        if v and v not in ("None", "N/A", ""):
            known_ips.add(v.strip())

    known_usernames = set()
    un = alert.get("username", "None")
    if un and un not in ("None", "N/A", ""):
        known_usernames.add(un.strip().lower())

    known_hostnames = set()
    hn = alert.get("hostname", "None")
    if hn and hn not in ("None", "N/A", ""):
        known_hostnames.add(hn.strip().lower())

    # Collect all indicator text for scanning
    indicators = insight.get("relevant_risk_indicators", [])
    all_indicator_text = " ".join(indicators)

    # 1. Check for invented IP addresses in indicators
    ip_pattern = re.compile(
        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    )
    for match in ip_pattern.finditer(all_indicator_text):
        found_ip = match.group(1)
        if found_ip not in known_ips:
            try:
                ipaddress.ip_address(found_ip)  # confirm it parses
                warnings.append(
                    f"Unsupported IP in relevant_risk_indicators: '{found_ip}' "
                    f"was not present in the supplied alert context."
                )
            except ValueError:
                pass

    # 2. Check for invented hostnames in indicators
    # Match domain-like tokens (contain dots but are not IPs)
    hostname_pattern = re.compile(r'\b([\w\-]+\.[\w\-]+(?:\.[\w\-]+)+)\b')
    for match in hostname_pattern.finditer(all_indicator_text):
        token = match.group(1).lower()
        # Skip if it's an IP or already in known hostnames
        if token not in known_hostnames and not re.match(r'^\d+\.\d+\.\d+\.\d+$', token):
            warnings.append(
                f"Potentially unsupported hostname/domain in relevant_risk_indicators: "
                f"'{match.group(1)}' was not present in the supplied alert context."
            )

    # 3. Check for invented usernames in indicators
    # Heuristic: tokens that look like user accounts (email format or user.name style)
    # Explicitly exclude JSON field path citations like "alert.source_ip", "enrichment.threat_intel_match"
    _FIELD_PATH_PREFIXES = ("alert.", "enrichment.", "risk_evaluation.", "playbook.", "risk.")
    user_pattern = re.compile(r'\b([\w]{2,}[._@][\w]{2,})\b')
    for match in user_pattern.finditer(all_indicator_text):
        token = match.group(1).lower()
        if token not in known_usernames:
            # Skip JSON field path citations
            if any(token.startswith(pfx) for pfx in _FIELD_PATH_PREFIXES):
                continue
            # Only warn if it looks like a username (email or user.name format)
            # Skip if it already looks like a dotted hostname or IP fragment
            if "@" in token or (
                "." in token
                and not any(token.endswith(ext) for ext in (".json", ".log", ".txt", ".yaml", ".yml"))
                and not re.match(r'^\d+\.\d+', token)  # IP fragments like "198.51", "100.45"
                and not re.match(r'^[\w\-]+\.[\w\-]+(?:\.[\w\-]+)+$', token)  # multi-part hostnames
                and not any(token.startswith(pfx) for pfx in _FIELD_PATH_PREFIXES)
            ):
                warnings.append(
                    f"Potentially unsupported username in relevant_risk_indicators: "
                    f"'{match.group(1)}' was not found in the supplied alert context."
                )

    # 4. Detect fabricated numerical confidence percentages in confidence_explanation
    confidence_text = insight.get("confidence_explanation", "")
    pct_match = re.search(r'\b\d+\s*%', confidence_text)
    if pct_match:
        warnings.append(
            f"Numerical percentage confidence detected in confidence_explanation "
            f"('{pct_match.group(0)}'). Use qualitative levels (HIGH / MEDIUM / LOW) "
            f"with explicit reasoning instead of ungrounded percentage figures."
        )

    # 5. Detect unqualified external TI reputation claims when only local DB was used
    ti_match = enrichment.get("threat_intel_match", False)
    if ti_match:
        # The TI match is from a local offline simulation DB — check that the response
        # does not present it as verified external intelligence
        combined_text = " ".join([
            insight.get("alert_interpretation", ""),
            insight.get("why_suspicious", ""),
            all_indicator_text,
        ]).lower()
        external_claim_patterns = [
            r'\bexternal\s+threat\s+intel(ligence)?\b',
            r'\bverified\s+(by\s+)?(threat|ti)\b',
            r'\bglobal\s+threat\s+feed\b',
            r'\b(abuseipdb|virustotal|shodan|greynoise)\b',
        ]
        for pat in external_claim_patterns:
            if re.search(pat, combined_text):
                warnings.append(
                    "Response appears to claim verified external threat intelligence. "
                    "The threat-intel match in this context is from a local offline "
                    "simulation database only — not a real external TI feed."
                )
                break

    has_unsupported_claims = len(warnings) > 0
    return {"warnings": warnings, "has_unsupported_claims": has_unsupported_claims}


class AnalystInsight(BaseModel):
    """Structured schema for Gemini LLM advisory security analysis."""

    executive_summary: str = Field(
        description="Concise 1-2 sentence executive overview summarizing the security event."
    )
    alert_interpretation: str = Field(
        description=(
            "Technical analysis clearly distinguishing directly observed alert facts "
            "from model-derived interpretations. Must NOT invent IPs, usernames, hostnames, "
            "or external threat intelligence findings not present in the supplied JSON context."
        )
    )
    why_suspicious: str = Field(
        description="Detailed technical reasoning on why this alert activity is considered anomalous, hostile, or noteworthy."
    )
    relevant_risk_indicators: List[str] = Field(
        description=(
            "Specific risk indicators verified directly from the supplied alert attributes "
            "and enrichment data. Each indicator MUST cite the specific JSON field name from "
            "the context that supports it. Never reference IPs, usernames, or hostnames not "
            "present in the supplied JSON."
        )
    )
    recommended_investigation_steps: List[str] = Field(
        description="Actionable, prioritized investigation steps for a SOC Tier-1 or Tier-2 analyst to triage this scenario."
    )
    playbook_justification: str = Field(
        description="Technical assessment of why the recommended/candidate SOAR playbook is appropriate for this risk tier."
    )
    missing_information: List[str] = Field(
        description=(
            "Key telemetry gaps, missing logs, or uncertainties needed to confirm the true "
            "nature of the threat. If threat_intel_match is true but the source is a local "
            "offline database, this list MUST include an item about the absence of verified "
            "external real-world threat intelligence."
        )
    )
    confidence_explanation: str = Field(
        description=(
            "Qualitative confidence assessment (HIGH / MEDIUM / LOW) with explicit "
            "reasoning tied to observed facts. MUST NOT contain percentage numbers "
            "(e.g. '95%'). Use qualitative language only."
        )
    )


def load_env_file(env_path: Optional[str] = None) -> None:
    """Lightweight zero-dependency reader for local .env files.

    Safely populates os.environ without overwriting existing environment variables.
    """
    if env_path is None:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        env_path = os.path.join(base_dir, ".env")

    if not os.path.isfile(env_path):
        return

    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v
    except (OSError, UnicodeDecodeError):
        pass


def _scrub_text(text: Any) -> Any:
    """Scrub embedded secrets, passwords, tokens, and authorization headers from text."""
    if not isinstance(text, str):
        return text
    s = re.sub(r'(?i)\b(bearer\s+)[A-Za-z0-9_\-\.]{6,}', r'\1[REDACTED]', text)
    s = re.sub(r'(?i)\b(basic\s+)[A-Za-z0-9+/=]{6,}', r'\1[REDACTED]', s)
    s = re.sub(r'(?i)\b(password|passwd|pwd|secret|api_key|token)[=:\s]+[^\s,;]+', r'\1 [REDACTED]', s)
    return s


def sanitize_alert_context(
    alert_data: Dict[str, Any],
    enrichment_data: Optional[Dict[str, Any]] = None,
    risk_data: Optional[Dict[str, Any]] = None,
    playbook_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Extract and sanitize only the minimum synthetic context required for LLM analysis.

    Excludes local filesystem paths, credentials, tokens, session IDs, and unrelated records.
    """
    alert_clean = redact_sensitive_data(alert_data or {})
    enrich_clean = redact_sensitive_data(enrichment_data or {})
    risk_clean = risk_data or {}
    pb_clean = playbook_data or {}

    # Extract strictly relevant alert telemetry
    raw_src_ip = str(alert_clean.get("source_ip") or "None")
    raw_dst_ip = str(alert_clean.get("destination_ip") or "None")
    src_ip_class = _classify_ip(raw_src_ip)
    dst_ip_class = _classify_ip(raw_dst_ip)

    sanitized_alert = {
        "alert_id": alert_clean.get("alert_id", "UNKNOWN"),
        "event_type": _scrub_text(alert_clean.get("event_type", "Unknown Event")),
        "severity": alert_clean.get("severity", "UNKNOWN"),
        "timestamp": alert_clean.get("timestamp", "N/A"),
        "event_source": _scrub_text(alert_clean.get("event_source", "Unknown")),
        "source_ip": raw_src_ip,
        "source_ip_scope": src_ip_class,
        "destination_ip": raw_dst_ip,
        "destination_ip_scope": dst_ip_class,
        "hostname": alert_clean.get("hostname", "None"),
        "username": alert_clean.get("username", "None"),
        "description": _scrub_text(alert_clean.get("description", "No description provided."))
    }

    # Inject mandatory grounding notes for special IP ranges so the LLM cannot
    # misclassify documentation IPs as real internet sources
    src_note = _ip_scope_note(raw_src_ip, src_ip_class)
    if src_note:
        sanitized_alert["source_ip_grounding_note"] = src_note
    dst_note = _ip_scope_note(raw_dst_ip, dst_ip_class)
    if dst_note:
        sanitized_alert["destination_ip_grounding_note"] = dst_note

    # Extract strictly relevant enrichment indicators
    src_ctx = enrich_clean.get("source_ip_context") or {}
    ti_ctx = enrich_clean.get("threat_intelligence") or {}
    ti_match = bool(ti_ctx)
    sanitized_enrichment = {
        "source_ip_classification": src_ctx.get("classification", "Unknown"),
        "is_public_ip": src_ctx.get("is_public", False),
        "threat_intel_match": ti_match,
        "threat_intel_source": (
            "LOCAL OFFLINE SIMULATION DATABASE ONLY — not a verified external threat feed"
            if ti_match else None
        ),
        "threat_intel_details": {
            "reputation": ti_ctx.get("reputation"),
            "threat_type": ti_ctx.get("threat_type"),
            "confidence": ti_ctx.get("confidence")
        } if ti_ctx else None,
        "is_privileged_user": bool(enrich_clean.get("is_privileged_user")),
        "is_critical_host": bool(enrich_clean.get("is_critical_host")),
        "suspicious_patterns_detected": enrich_clean.get("suspicious_process_patterns_detected") or []
    }

    # Extract deterministic risk evaluation
    sanitized_risk = {
        "total_risk_score": risk_clean.get("total_risk_score", 0),
        "risk_classification": risk_clean.get("risk_classification", "LOW"),
        "base_severity_score": risk_clean.get("base_score", 0),
        "triggered_risk_factors": [
            f.get("description", f.get("factor_id", "Factor"))
            for f in risk_clean.get("triggered_factors", [])
        ]
    }

    # Extract recommended / triggered playbook
    sanitized_playbook = {
        "playbook_id": pb_clean.get("playbook_id", "N/A"),
        "playbook_name": pb_clean.get("playbook_name", pb_clean.get("name", "N/A")),
        "target_tier": pb_clean.get("target_tier", pb_clean.get("priority", "N/A")),
        "description": pb_clean.get("description", pb_clean.get("purpose", "N/A"))
    }

    return {
        "alert": sanitized_alert,
        "enrichment": sanitized_enrichment,
        "risk_evaluation": sanitized_risk,
        "playbook": sanitized_playbook
    }


class GeminiAlertAnalyzer:
    """Advisory LLM alert analyzer using Google's official GenAI SDK (google-genai)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        client: Optional[Any] = None
    ):
        # Auto-load .env if GEMINI_API_KEY is not already in environment
        if not os.environ.get("GEMINI_API_KEY"):
            load_env_file()

        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = model or os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
        self._client = client

    @property
    def is_configured(self) -> bool:
        """Return True if an API key is configured and GenAI SDK is available."""
        return bool(self.api_key and self.api_key.strip()) and GENAI_AVAILABLE

    def _get_client(self):
        """Lazy-initialize or return the official genai.Client instance."""
        if self._client is not None:
            return self._client
        if not GENAI_AVAILABLE:
            raise RuntimeError("The 'google-genai' SDK is not installed.")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not configured.")
        return genai.Client(api_key=self.api_key)

    def analyze_alert(
        self,
        alert_data: Dict[str, Any],
        enrichment_data: Optional[Dict[str, Any]] = None,
        risk_data: Optional[Dict[str, Any]] = None,
        playbook_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Perform an advisory analysis on the supplied alert context.

        Returns a dictionary with status, model metadata, and structured AnalystInsight.
        Never modifies any alert, incident, or risk state.
        """
        if not self.api_key or not self.api_key.strip():
            return {
                "status": "NOT_CONFIGURED",
                "error": "GEMINI_API_KEY environment variable is not configured.",
                "data": None,
                "model": self.model,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        if not GENAI_AVAILABLE:
            return {
                "status": "SDK_MISSING",
                "error": "The official 'google-genai' SDK is not installed in the Python environment.",
                "data": None,
                "model": self.model,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        sanitized_context = sanitize_alert_context(
            alert_data=alert_data,
            enrichment_data=enrichment_data,
            risk_data=risk_data,
            playbook_data=playbook_data
        )

        prompt_text = (
            f"Analyze the following synthetic security alert scenario and provide a structured advisory briefing.\n\n"
            f"=== SUPPLIED CONTEXT (treat this as the ONLY source of facts) ===\n"
            f"```json\n{json.dumps(sanitized_context, indent=2)}\n```\n\n"
            f"=== GROUNDING RULES (MANDATORY) ===\n"
            f"1. Only state facts that appear verbatim in the JSON context above.\n"
            f"2. If 'source_ip_grounding_note' or 'destination_ip_grounding_note' are present, "
            f"you MUST reproduce their content in your analysis — do NOT reclassify those IPs "
            f"as real internet addresses or real malicious sources.\n"
            f"3. Any 'threat_intel_match: true' in the context originates from a LOCAL OFFLINE "
            f"SIMULATION DATABASE as stated in 'threat_intel_source'. "
            f"Label it as such — never claim it is verified external threat intelligence.\n"
            f"4. NEVER invent IPs, usernames, hostnames, domain names, threat actor names, "
            f"campaign names, or CVE identifiers not present in the context.\n"
            f"5. NEVER use percentage confidence numbers (e.g. '95%'). "
            f"Use qualitative levels only: HIGH, MEDIUM, or LOW — with explicit reasoning.\n"
            f"6. Each item in 'relevant_risk_indicators' MUST cite the specific JSON field name "
            f"(e.g. 'alert.source_ip', 'enrichment.threat_intel_match') that supports it.\n"
            f"7. If external real-world threat intelligence validation is absent, include this "
            f"explicitly in 'missing_information'.\n"
        )

        system_instruction = (
            "You are SOC Sentinel's expert advisory AI security analyst. "
            "You analyze telemetry context to assist human security analysts. "
            "Your output is strictly advisory and will be reviewed by a human analyst before any decision is made. "
            "STRICT RULES:\n"
            "1. NEVER invent indicators, IP reputations, actor attribution, hostnames, usernames, "
            "domain names, or external facts absent from the supplied JSON context.\n"
            "2. If the context contains 'source_ip_grounding_note' or 'destination_ip_grounding_note', "
            "those notes are MANDATORY — you must reflect them accurately. "
            "An IP flagged as RFC5737_DOCUMENTATION is a documentation/test-range address, "
            "NOT a real internet source, even if threat_intel_match is true (the match is local simulation only).\n"
            "3. Any threat-intel match in the context is from a LOCAL OFFLINE SIMULATION DATABASE. "
            "Never state or imply it is verified external threat intelligence.\n"
            "4. Distinguish observed alert telemetry facts from analytical inferences. "
            "Label inferences explicitly as 'Inferred:' or 'Analytically:' in your text.\n"
            "5. NEVER use percentage confidence numbers. "
            "Use qualitative levels only: HIGH, MEDIUM, or LOW, with reasoning from observed facts.\n"
            "6. Do not attempt to overwrite or recalculate the official pipeline risk score.\n"
            "7. Do not generate executable containment scripts or live infrastructure commands.\n"
            "8. Provide your analysis in structured JSON conforming to the AnalystInsight schema."
        )

        try:
            client = self._get_client()
            config = types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=AnalystInsight,
                temperature=0.2,
                max_output_tokens=2048,
                system_instruction=system_instruction
            )

            response = client.models.generate_content(
                model=self.model,
                contents=prompt_text,
                config=config
            )

            # Extract structured response
            insight_dict = None
            if hasattr(response, "parsed") and response.parsed is not None:
                if isinstance(response.parsed, BaseModel):
                    insight_dict = response.parsed.model_dump()
                elif isinstance(response.parsed, dict):
                    insight_dict = AnalystInsight.model_validate(response.parsed).model_dump()

            if insight_dict is None and hasattr(response, "text") and response.text:
                raw_json = json.loads(response.text)
                insight_dict = AnalystInsight.model_validate(raw_json).model_dump()

            if not insight_dict:
                return {
                    "status": "INVALID_RESPONSE",
                    "error": "Gemini response did not contain valid structured insight data.",
                    "data": None,
                    "model": self.model,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }

            # Post-response validation: flag unsupported factual claims
            validation_result = _validate_insight_against_context(insight_dict, sanitized_context)

            return {
                "status": "SUCCESS",
                "data": insight_dict,
                "model": self.model,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": None,
                "validation_warnings": validation_result["warnings"],
                "has_unsupported_claims": validation_result["has_unsupported_claims"]
            }

        except Exception as e:
            err_str = str(e)
            err_lower = err_str.lower()

            # Classify error types for clean UI diagnostics
            if "429" in err_str or "quota" in err_lower or "resource_exhausted" in err_lower:
                status = "RATE_LIMITED"
                clean_err = f"Gemini API rate limit or quota exceeded: {err_str}"
            elif "timeout" in err_lower or "timed out" in err_lower or "connection" in err_lower:
                status = "NETWORK_ERROR"
                clean_err = f"Network communication error contacting Gemini API: {err_str}"
            elif isinstance(e, (json.JSONDecodeError, ValueError)) or "json" in err_lower or "validation" in err_lower:
                status = "INVALID_RESPONSE"
                clean_err = f"Failed to parse Gemini response schema: {err_str}"
            elif "api_key" in err_lower or "invalid_argument" in err_lower or "permission_denied" in err_lower:
                status = "AUTH_ERROR"
                clean_err = f"Gemini API authentication failed (check GEMINI_API_KEY): {err_str}"
            else:
                status = "API_ERROR"
                clean_err = f"Gemini API error ({type(e).__name__}): {err_str}"

            return {
                "status": status,
                "error": clean_err,
                "data": None,
                "model": self.model,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
