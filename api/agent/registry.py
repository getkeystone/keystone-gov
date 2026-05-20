"""
Tool registry and role-tool authorization matrix.

Loads from api/agent/config/tools.yaml. Real loading wired in M2.
Stage: M1 scaffold.
"""
from pathlib import Path
import yaml

_CONFIG_PATH = Path(__file__).parent / "config" / "tools.yaml"

_REGISTRY: dict = {}
_ROLE_MATRIX: dict = {}


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
    return dict(_REGISTRY)


def role_can_call(role: str, tool_name: str) -> bool:
    return tool_name in _ROLE_MATRIX.get(role, [])


def severity_tier_for(tool_name: str) -> str | None:
    t = _REGISTRY.get(tool_name)
    return t.get("severity_tier") if t else None
