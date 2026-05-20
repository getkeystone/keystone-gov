"""
Tool registry and role-tool authorization matrix for KDAT-002.

Loads from api/agent/config/tools.yaml at import time. Tests that need a
custom path call load_registry(path) explicitly to reload.
"""
from pathlib import Path
import yaml

_CONFIG_PATH = Path(__file__).parent / "config" / "tools.yaml"

_REGISTRY: dict = {}
_ROLE_MATRIX: dict = {}

# Map severity tier name to integer precedence (higher = more restrictive).
_TIER_PRECEDENCE = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def load_registry(path: Path = _CONFIG_PATH) -> None:
    global _REGISTRY, _ROLE_MATRIX
    if not path.exists():
        _REGISTRY = {}
        _ROLE_MATRIX = {}
        return
    data = yaml.safe_load(path.read_text())
    _REGISTRY = {t["name"]: t for t in data.get("tools", [])}
    _ROLE_MATRIX = data.get("role_permitted_tools", {})


def tools() -> dict:
    """Return a copy of the full registry keyed by tool name."""
    return dict(_REGISTRY)


def role_can_call(role: str, tool_name: str) -> bool:
    """Return True if role is permitted to attempt calling tool_name."""
    return tool_name in _ROLE_MATRIX.get(role, [])


def severity_tier_for(tool_name: str) -> str | None:
    """Return the base severity tier for a tool, or None if not found."""
    t = _REGISTRY.get(tool_name)
    return t.get("severity_tier") if t else None


def effective_severity_tier(tool_name: str, params: dict | None = None) -> str | None:
    """
    Resolve effective severity tier, applying parameter-dependent rules.

    For queue_notification the tier is determined by the 'severity' param
    at runtime (spec Section 4.3). Falls back to the base severity_tier
    when params are absent or the tool is not parameter-dependent.
    Controller calls this in M3; M2 exposes it so tests can verify the
    mapping without exercising the controller path.
    """
    t = _REGISTRY.get(tool_name)
    if not t:
        return None
    if t.get("severity_parameter_dependent") and params:
        tier_map = t.get("severity_tier_map", {})
        param_name = t.get("severity_parameter")
        if param_name and param_name in params:
            key = params[param_name]
            resolved = tier_map.get(key) or tier_map.get(str(key))
            if resolved:
                return resolved
    return t.get("severity_tier")


def permitted_tools_for(role: str) -> list[dict]:
    """Return full tool dicts for all tools the role is permitted to call."""
    return [_REGISTRY[name] for name in _ROLE_MATRIX.get(role, []) if name in _REGISTRY]


# Load on import — the YAML path is embedded in the package.
load_registry()
