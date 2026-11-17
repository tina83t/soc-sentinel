import os
from typing import Dict, Any, List, Set
import yaml


REQUIRED_FIELDS: List[str] = [
    "playbook_id",
    "name",
    "target_tier",
    "condition",
    "min_risk_score",
    "recommended_status",
    "description",
    "ordered_steps",
    "actions",
    "execution_mode"
]

VALID_TIERS: Set[str] = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

SUPPORTED_ACTION_TYPES: Set[str] = {
    "ANALYST_NOTIFICATION",
    "ENDPOINT_ISOLATION",
    "ACCOUNT_SUSPENSION",
    "IP_BLOCK",
    "SECURITY_REVIEW_QUEUE"
}


class PlaybookLoader:
    """Safely loads and validates declarative YAML playbook definitions."""

    @staticmethod
    def load_playbook_file(file_path: str) -> Dict[str, Any]:
        """Load and strictly validate a single YAML playbook definition file."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Playbook file not found: '{file_path}'")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Malformed YAML in playbook file '{file_path}': {e}") from e

        if not isinstance(data, dict):
            raise ValueError(f"Playbook definition in '{file_path}' must be a mapping/dictionary")

        # Validate required fields
        missing = [rf for rf in REQUIRED_FIELDS if rf not in data]
        if missing:
            raise ValueError(
                f"Playbook in '{file_path}' is missing required field(s): {', '.join(missing)}"
            )

        # Validate types and values
        p_id = data.get("playbook_id")
        if not isinstance(p_id, str) or not p_id.strip():
            raise ValueError(f"Invalid 'playbook_id' in '{file_path}': must be a non-empty string")

        tier = data.get("target_tier")
        if tier not in VALID_TIERS:
            raise ValueError(
                f"Invalid 'target_tier' in '{file_path}': '{tier}'. Allowed: {', '.join(sorted(VALID_TIERS))}"
            )

        # Validate min_risk_score
        min_score = data.get("min_risk_score")
        if isinstance(min_score, bool) or not isinstance(min_score, (int, float)):
            raise ValueError(
                f"Invalid 'min_risk_score' in '{file_path}': must be a numeric value and not boolean"
            )
        if not (0 <= min_score <= 100):
            raise ValueError(
                f"Invalid 'min_risk_score' in '{file_path}': {min_score}. Must satisfy 0 <= min_risk_score <= 100"
            )

        if not isinstance(data.get("ordered_steps"), list):
            raise ValueError(f"Invalid 'ordered_steps' in '{file_path}': must be a list")

        # Validate action catalog definitions
        actions = data.get("actions")
        if not isinstance(actions, list):
            raise ValueError(f"Invalid 'actions' in '{file_path}': must be a list")

        for act in actions:
            if not isinstance(act, dict):
                raise ValueError(f"Invalid action entry in '{file_path}': must be a dictionary")
            act_type = act.get("type")
            if not act_type or not isinstance(act_type, str):
                raise ValueError(f"Missing or invalid action 'type' in '{file_path}'")
            if act_type not in SUPPORTED_ACTION_TYPES:
                raise ValueError(
                    f"Unsupported action type '{act_type}' in '{file_path}'. "
                    f"Allowed action types: {', '.join(sorted(SUPPORTED_ACTION_TYPES))}"
                )

        # Validate execution steps if present
        if "execution_steps" in data:
            exec_steps = data.get("execution_steps")
            if not isinstance(exec_steps, list):
                raise ValueError(f"Invalid 'execution_steps' in '{file_path}': must be a list")

            for step in exec_steps:
                if not isinstance(step, dict):
                    raise ValueError(f"Invalid execution step entry in '{file_path}': must be a dictionary")
                step_act = step.get("action_type")
                if step_act is not None:
                    if not isinstance(step_act, str) or not step_act.strip():
                        raise ValueError(
                            f"Missing or invalid execution-step 'action_type' in '{file_path}'"
                        )
                    if step_act not in SUPPORTED_ACTION_TYPES:
                        raise ValueError(
                            f"Unsupported execution-step action_type '{step_act}' in '{file_path}'. "
                            f"Allowed action types: {', '.join(sorted(SUPPORTED_ACTION_TYPES))}"
                        )

        return data

    @classmethod
    def load_playbooks_from_directory(cls, directory_path: str) -> List[Dict[str, Any]]:
        """Load and validate all YAML playbook files from a directory.

        Ensures playbook IDs are globally unique and returns playbooks ordered
        by routing priority (descending min_risk_score).
        """
        if not os.path.isdir(directory_path):
            raise FileNotFoundError(f"Playbook directory does not exist: '{directory_path}'")

        yaml_files = sorted([
            f for f in os.listdir(directory_path)
            if f.endswith((".yaml", ".yml")) and not f.startswith(".")
        ])

        if not yaml_files:
            raise ValueError(f"No playbook YAML files found in directory: '{directory_path}'")

        playbooks: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()

        for yf in yaml_files:
            full_path = os.path.join(directory_path, yf)
            pb = cls.load_playbook_file(full_path)
            p_id = pb["playbook_id"]

            if p_id in seen_ids:
                raise ValueError(
                    f"Duplicate playbook ID '{p_id}' detected in '{full_path}'"
                )

            seen_ids.add(p_id)
            playbooks.append(pb)

        # Sort descending by minimum risk score for top-down conditional evaluation
        playbooks.sort(key=lambda p: p.get("min_risk_score", 0), reverse=True)
        return playbooks
