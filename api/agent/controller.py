"""
The Keystone controller. The only execution path for tool calls.

Per keystone-core/agent-spec v1.2 (formerly KDAT-002-SPEC v1.2) Section 1.5: the LLM does not execute tools.
The LLM emits structured plan objects. The controller is the only
execution path.

M3: role-tool authorization check (P1.2) + effective severity tier
resolution. HITL routing (P5.1, P5.3) and evidence gating (P2.1, P2.2)
land in M4-M6.

M4: injection check on tool parameters (P3.1) + hash-chained audit write
for every authorize() decision.
"""
from .hitl import requires_hitl
from .registry import role_can_call, effective_severity_tier


def _check_params_injection(params: dict) -> tuple[bool, str]:
    """
    Check all string values in params for prompt injection patterns.
    Returns (is_safe, reason). is_safe=False means injection detected.
    """
    try:
        from input_sanitizer import check_injection
    except ImportError:
        from api.input_sanitizer import check_injection

    for key, val in (params or {}).items():
        if isinstance(val, str):
            is_safe, reason = check_injection(val)
            if not is_safe:
                return False, f"param '{key}': {reason}"
    return True, ""


def authorize(
    role: str,
    tool_name: str,
    params: dict | None = None,
    plan_id: str | None = None,
    step_index: int = 0,
    db=None,
) -> dict:
    """
    Authorize a tool call for a role.

    When plan_id and db are provided, writes a hash-chained entry to
    agent_action_audit for every decision (allow, deny, or injection-deny).

    Returns a decision dict:
      allowed         bool
      routed_to_hitl  bool  (always False in M3-M4; wired in M5-M6)
      policy_reference str
      severity_tier   str
      rationale       str
    """
    params = params or {}
    tier = effective_severity_tier(tool_name, params) or "Unknown"

    def _audit(decision: str, policy_ref: str) -> None:
        if db is not None and plan_id is not None:
            from .audit import write_audit_entry
            write_audit_entry(
                plan_id=plan_id,
                step_index=step_index,
                tool_name=tool_name,
                params=params,
                auth_decision=decision,
                severity_tier=tier,
                policy_reference=policy_ref,
                role=role,
                db=db,
            )

    # ── P3.1: injection check — before role-tool check ──────────────────────
    is_safe, inj_reason = _check_params_injection(params)
    if not is_safe:
        _audit("deny", "P3.1")
        return {
            "allowed": False,
            "routed_to_hitl": False,
            "policy_reference": "P3.1",
            "severity_tier": tier,
            "rationale": f"injection detected in tool parameters — {inj_reason}",
        }

    # ── P1.2: role-tool authorization check ──────────────────────────────────
    if not role_can_call(role, tool_name):
        rationale = (
            f"role '{role}' is not in the permitted-tools list for '{tool_name}' (P1.2)"
        )
        _audit("deny", "P1.2")
        return {
            "allowed": False,
            "routed_to_hitl": False,
            "policy_reference": "P1.2",
            "severity_tier": tier,
            "rationale": rationale,
        }

    # ── P5.3: severity-tier-driven HITL routing ──────────────────────────────
    if requires_hitl(tier, role):
        # Resume path: check if an approval decision already exists for this
        # step. The approval endpoint writes the P5.1 audit entry; we do not
        # duplicate it here.
        if db is not None and plan_id is not None:
            from .models import AgentApprovalTask
            import uuid as _uuid
            approved = db.query(AgentApprovalTask).filter(
                AgentApprovalTask.plan_id == _uuid.UUID(plan_id),
                AgentApprovalTask.step_index == step_index,
                AgentApprovalTask.decision == "approve",
                AgentApprovalTask.status == "decided",
            ).first()
            if approved:
                return {
                    "allowed": True,
                    "routed_to_hitl": False,
                    "policy_reference": "P5.1",
                    "severity_tier": tier,
                    "rationale": (
                        f"step {step_index} approved by {approved.decided_by!r} (P5.1)"
                    ),
                }
        _audit("hitl", "P5.3")
        return {
            "allowed": False,
            "routed_to_hitl": True,
            "policy_reference": "P5.3",
            "severity_tier": tier,
            "rationale": (
                f"tier '{tier}' requires HITL approval for role '{role}' (P5.3)"
            ),
        }

    rationale = f"role '{role}' authorized for '{tool_name}' at tier {tier} (P1.2)"
    _audit("allow", "P1.2")
    return {
        "allowed": True,
        "routed_to_hitl": False,
        "policy_reference": "P1.2",
        "severity_tier": tier,
        "rationale": rationale,
    }
