import json
import os
from typing import Dict, Any, List, Tuple


class RiskScoringEngine:
    """Transparent rule-based risk calculation engine (0-100 scale).

    Guarantees idempotency and deduplication: each risk rule key can trigger
    at most once per evaluation.
    """

    def __init__(self, rules_config_path: str = "config/rules.json", audit_logger=None):
        self.audit_logger = audit_logger
        self.config = self._load_rules(rules_config_path)

    def _load_rules(self, path: str) -> Dict[str, Any]:
        defaults = {
            "base_severity_scores": {
                "CRITICAL": 40,
                "HIGH": 30,
                "MEDIUM": 20,
                "LOW": 10,
                "INFORMATIONAL": 5
            },
            "risk_factor_weights": {
                "threat_intel_match": {"weight": 30, "description": "Threat intelligence match"},
                "privileged_user": {"weight": 20, "description": "Privileged user account involved"},
                "critical_host": {"weight": 15, "description": "Target is a mission-critical asset"},
                "suspicious_process_powershell": {"weight": 25, "description": "Suspicious PowerShell command"},
                "brute_force_failed_logins": {"weight": 25, "description": "Repeated authentication failures"},
                "public_ip_inbound": {"weight": 10, "description": "Inbound connection from public IP"},
                "missing_critical_data": {"weight": 15, "description": "Missing telemetry / data quality defect"}
            },
            "thresholds": {
                "critical": 80,
                "high": 60,
                "medium": 30,
                "low": 0
            }
        }
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
                if self.audit_logger:
                    self.audit_logger.log_event(
                        "SYSTEM",
                        "RISK_ENGINE",
                        "CONFIG_LOAD_FAILED",
                        {"path": path, "error": f"{type(e).__name__}: {str(e)}"},
                        level="WARNING"
                    )
        return defaults

    def calculate_score(self, alert: Dict[str, Any], enrichment: Dict[str, Any]) -> Dict[str, Any]:
        """Compute the risk score, factors triggered, and classification."""
        alert_id = alert.get("alert_id") or "UNKNOWN"
        base_sev = str(alert.get("severity", "MEDIUM")).upper()
        base_scores = self.config.get("base_severity_scores", {})
        base_score = base_scores.get(base_sev, 20)

        triggered_factors: List[Dict[str, Any]] = []
        score = base_score

        weights = self.config.get("risk_factor_weights", {})

        # 1. Threat Intel Factor
        ti = enrichment.get("threat_intelligence")
        if ti and ti.get("reputation") in ["malicious", "suspicious"]:
            w = weights.get("threat_intel_match", {}).get("weight", 30)
            score += w
            triggered_factors.append({
                "factor_id": "threat_intel_match",
                "weight": w,
                "reason": f"Matched TI feed ({ti.get('threat_category', 'Malicious IP')})"
            })

        # 2. Privileged User Factor
        if enrichment.get("is_privileged_user"):
            w = weights.get("privileged_user", {}).get("weight", 20)
            score += w
            triggered_factors.append({
                "factor_id": "privileged_user",
                "weight": w,
                "reason": f"Privileged identity active: '{alert.get('username')}'"
            })

        # 3. Critical Host Factor
        if enrichment.get("is_critical_host"):
            w = weights.get("critical_host", {}).get("weight", 15)
            score += w
            triggered_factors.append({
                "factor_id": "critical_host",
                "weight": w,
                "reason": f"Target host designated critical asset: '{alert.get('hostname')}'"
            })

        # 4. Suspicious Process / PowerShell Factor
        if enrichment.get("has_suspicious_process"):
            w = weights.get("suspicious_process_powershell", {}).get("weight", 25)
            score += w
            patterns = enrichment.get("suspicious_process_patterns_detected", [])
            triggered_factors.append({
                "factor_id": "suspicious_process_powershell",
                "weight": w,
                "reason": f"Detected suspicious execution patterns: {patterns}"
            })

        # 5. Brute Force / Repeated Failed Logins
        if enrichment.get("is_brute_force"):
            w = weights.get("brute_force_failed_logins", {}).get("weight", 25)
            score += w
            triggered_factors.append({
                "factor_id": "brute_force_failed_logins",
                "weight": w,
                "reason": "Repeated authentication failures detected"
            })

        # 6. Inbound Public IP
        src_ctx = enrichment.get("source_ip_context", {})
        if src_ctx.get("is_public"):
            w = weights.get("public_ip_inbound", {}).get("weight", 10)
            score += w
            triggered_factors.append({
                "factor_id": "public_ip_inbound",
                "weight": w,
                "reason": f"Inbound traffic originating from external public address {src_ctx.get('ip')}"
            })

        # 7. Missing Critical Data (Quality penalty)
        if alert.get("has_missing_data"):
            w = weights.get("missing_critical_data", {}).get("weight", 15)
            score += w
            issues = alert.get("data_quality_issues", [])
            triggered_factors.append({
                "factor_id": "missing_critical_data",
                "weight": w,
                "reason": f"Telemetry contains {len(issues)} data quality/missing field defect(s)"
            })

        # Clamp score to 0 - 100 range
        final_score = max(0, min(100, score))

        # Classification
        classification = self._classify_score(final_score)

        result = {
            "base_severity": base_sev,
            "base_score": base_score,
            "triggered_factors": triggered_factors,
            "total_risk_score": final_score,
            "risk_classification": classification
        }

        if self.audit_logger:
            self.audit_logger.log_event(
                alert_id,
                "RISK_EVALUATION",
                "SCORE_CALCULATED",
                {
                    "final_score": final_score,
                    "classification": classification,
                    "factors_count": len(triggered_factors)
                }
            )

        return result

    def _classify_score(self, score: int) -> str:
        """Classify numerical risk score into standard severity tier."""
        thresholds = self.config.get("thresholds", {"critical": 80, "high": 60, "medium": 30, "low": 0})
        if score >= thresholds.get("critical", 80):
            return "CRITICAL"
        elif score >= thresholds.get("high", 60):
            return "HIGH"
        elif score >= thresholds.get("medium", 30):
            return "MEDIUM"
        else:
            return "LOW"
