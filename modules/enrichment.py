import json
import ipaddress
import os
from typing import Dict, Any, List, Optional


class EnrichmentModule:
    """Enriches alert data with context: IP classification, mock Threat Intel, privileged status, and asset tier."""

    def __init__(self, db_config_path: str = "config/enrichment_db.json", audit_logger=None):
        self.audit_logger = audit_logger
        self.db = self._load_enrichment_db(db_config_path)

    def _load_enrichment_db(self, path: str) -> Dict[str, Any]:
        default_db = {
            "known_malicious_ips": {},
            "privileged_accounts": ["root", "administrator", "admin", "svc_backup", "domain_admin"],
            "critical_hosts": ["dc01.corp.internal", "dc02.corp.internal"],
            "suspicious_process_patterns": ["-enc", "iex", "bypass"]
        }
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
                if self.audit_logger:
                    self.audit_logger.log_event(
                        "SYSTEM",
                        "ENRICHMENT",
                        "CONFIG_LOAD_FAILED",
                        {"path": path, "error": f"{type(e).__name__}: {str(e)}"},
                        level="WARNING"
                    )
        return default_db

    def enrich(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Produce an enrichment dictionary analyzing context indicators."""
        alert_id = alert.get("alert_id") or "UNKNOWN"
        source_ip = alert.get("source_ip")
        dest_ip = alert.get("destination_ip")
        username = str(alert.get("username") or "").strip().lower()
        hostname = str(alert.get("hostname") or "").strip().lower()
        description = str(alert.get("description") or "").lower()
        additional_ctx = alert.get("additional_context") or {}

        # 1. IP Enrichment
        src_ip_info = self._analyze_ip(source_ip)
        dst_ip_info = self._analyze_ip(dest_ip)

        # 2. Threat Intel Match Check (Mocked)
        threat_intel = None
        if source_ip and source_ip in self.db.get("known_malicious_ips", {}):
            threat_intel = {
                "matched_ip": source_ip,
                **self.db["known_malicious_ips"][source_ip],
                "source": "Simulated SOC Threat Intelligence Feed (Local)"
            }
        elif dest_ip and dest_ip in self.db.get("known_malicious_ips", {}):
            threat_intel = {
                "matched_ip": dest_ip,
                **self.db["known_malicious_ips"][dest_ip],
                "source": "Simulated SOC Threat Intelligence Feed (Local)"
            }

        # 3. Privileged Account Check
        privileged_users = [u.lower() for u in self.db.get("privileged_accounts", [])]
        is_privileged_user = (username in privileged_users) or any(p in username for p in ["admin", "root", "svc_"])

        # 4. Critical Host Check
        critical_hosts = [h.lower() for h in self.db.get("critical_hosts", [])]
        is_critical_host = (hostname in critical_hosts) or any(ch in hostname for ch in ["dc0", "vault", "pki", "prod-primary"])

        # 5. Suspicious Process / PowerShell Patterns
        detected_patterns = []
        for pattern in self.db.get("suspicious_process_patterns", []):
            if pattern.lower() in description or pattern.lower() in str(additional_ctx).lower():
                detected_patterns.append(pattern)

        # 6. Failed Login Indicator
        failed_count = additional_ctx.get("failed_attempts_count", 0)
        is_brute_force = failed_count >= 10 or "failed" in description and "attempts" in description

        enrichment_result = {
            "source_ip_context": src_ip_info,
            "destination_ip_context": dst_ip_info,
            "threat_intelligence": threat_intel,
            "is_privileged_user": is_privileged_user,
            "is_critical_host": is_critical_host,
            "suspicious_process_patterns_detected": detected_patterns,
            "has_suspicious_process": len(detected_patterns) > 0,
            "is_brute_force": is_brute_force,
            "failed_attempts_count": failed_count,
            "enrichment_source": "Local Simulated Context Engine"
        }

        if self.audit_logger:
            self.audit_logger.log_event(
                alert_id,
                "ENRICHMENT",
                "ALERT_ENRICHED",
                {
                    "ti_match": bool(threat_intel),
                    "privileged_user": is_privileged_user,
                    "critical_host": is_critical_host,
                    "patterns": detected_patterns
                }
            )

        return enrichment_result

    def _analyze_ip(self, ip_str: Optional[str]) -> Dict[str, Any]:
        """Determine if IP is private (RFC1918 internal), public/external, loopback, or invalid/missing."""
        if not ip_str or not isinstance(ip_str, str) or ip_str.strip() == "":
            return {
                "ip": None,
                "is_valid": False,
                "is_private": False,
                "is_public": False,
                "classification": "Missing / Unspecified"
            }

        clean_ip = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            # RFC 1918 enterprise internal private networks
            rfc1918_networks = [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16")
            ]
            is_rfc1918 = any(ip_obj in net for net in rfc1918_networks)
            is_loopback = ip_obj.is_loopback
            # An IP is considered external/public if it is neither internal RFC1918 nor loopback
            is_external = not (is_rfc1918 or is_loopback)

            return {
                "ip": clean_ip,
                "is_valid": True,
                "is_private": is_rfc1918,
                "is_public": is_external,
                "classification": "Private (RFC1918)" if is_rfc1918 else ("Loopback" if is_loopback else "Public / External")
            }
        except ValueError:
            return {
                "ip": clean_ip,
                "is_valid": False,
                "is_private": False,
                "is_public": False,
                "classification": "Malformed IP"
            }
