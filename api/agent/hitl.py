"""
HITL approval queue logic. Severity-tier-driven routing per v1.2 spec P5.3.

M5: requires_hitl() determines whether a tool call must pause for human
approval. create_approval_task() writes the AgentApprovalTask row.

Routing rules (spec §4.5):
  Critical  → HITL for every role (no override)
  High      → HITL for operator and supervisor only; custodian/admin proceed
  Medium    → ALLOW (no HITL)
  Low       → ALLOW (no HITL)
"""
import uuid
from datetime import datetime


_HITL_ALL_ROLES = {"Critical"}
_HITL_CONDITIONAL_ROLES = {"High"}
_HITL_BYPASS_ROLES = {"custodian", "admin"}  # High tier allowed without HITL


def requires_hitl(severity_tier: str, role: str = "") -> bool:
    """Return True if this (tier, role) combination must route through HITL."""
    if severity_tier in _HITL_ALL_ROLES:
        return True
    if severity_tier in _HITL_CONDITIONAL_ROLES and role not in _HITL_BYPASS_ROLES:
        return True
    return False


def create_approval_task(
    plan_id: str,
    step_index: int,
    tool_name: str,
    proposed_params: dict,
    severity_tier: str,
    user_id: str,
    db,
):
    """
    Write a pending AgentApprovalTask row. Flushes without committing;
    caller controls the commit boundary (same pattern as write_audit_entry).
    """
    from .models import AgentApprovalTask

    task = AgentApprovalTask(
        plan_id=uuid.UUID(plan_id),
        step_index=step_index,
        tool_name=tool_name,
        proposed_params=proposed_params,
        severity_tier=severity_tier,
        requested_by=user_id,
        requested_at=datetime.utcnow(),
        status="pending",
    )
    db.add(task)
    db.flush()
    return task
