"""
The Keystone controller. The only execution path for tool calls.

Per KDAT-002-SPEC v1.2 Section 1.5: the LLM does not execute tools.
The LLM emits structured plan objects. The controller is the only
execution path.

M3: role-tool authorization check (P1.2) + effective severity tier
resolution. HITL routing (P5.1, P5.3) and evidence gating (P2.1, P2.2)
land in M4-M6.
"""
from .registry import role_can_call, effective_severity_tier


def authorize(role: str, tool_name: str, params: dict | None = None) -> dict:
    """
    Authorize a tool call for a role.

    Returns a decision dict consumed by plan_loop.execute_plan and the
    audit chain writer. Fields:
      allowed         bool
      routed_to_hitl  bool  (always False in M3; wired in M4-M6)
      policy_reference str  (the governance rule that produced this decision)
      severity_tier   str
      rationale       str
    """
    tier = effective_severity_tier(tool_name, params) or "Unknown"

    if not role_can_call(role, tool_name):
        return {
            "allowed": False,
            "routed_to_hitl": False,
            "policy_reference": "P1.2",
            "severity_tier": tier,
            "rationale": (
                f"role '{role}' is not in the permitted-tools list for '{tool_name}' (P1.2)"
            ),
        }

    return {
        "allowed": True,
        "routed_to_hitl": False,
        "policy_reference": "P1.2",
        "severity_tier": tier,
        "rationale": (
            f"role '{role}' authorized for '{tool_name}' at tier {tier} (P1.2)"
        ),
    }
