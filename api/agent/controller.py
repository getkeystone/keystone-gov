"""
The Keystone controller. The only execution path for tool calls.

Per KDAT-002-SPEC v1.2 Section 1.5: the LLM does not execute tools.
The LLM emits structured plan objects. The controller is the only
execution path.

Stage: M1 scaffold. Real authorize() and execute_step() land in M3-M4.
"""
from .registry import role_can_call, severity_tier_for


def authorize(role: str, tool_name: str, severity_tier_override: str | None = None) -> dict:
    """
    Stub. M4 wires evidence threshold, HHEM consistency, severity tier
    resolution, HITL routing, audit chain extension.
    """
    if not role_can_call(role, tool_name):
        return {
            "allowed": False,
            "routed_to_hitl": False,
            "policy_reference": "P1.2",
            "severity_tier": severity_tier_override or severity_tier_for(tool_name) or "Unknown",
            "rationale": f"role '{role}' is not permitted to call tool '{tool_name}'",
        }
    return {
        "allowed": True,
        "routed_to_hitl": False,
        "policy_reference": "P1.2",
        "severity_tier": severity_tier_override or severity_tier_for(tool_name) or "Unknown",
        "rationale": "role-tool authorization check passed (stub)",
    }
