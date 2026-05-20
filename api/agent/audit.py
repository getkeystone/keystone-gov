"""
Action audit chain. HMAC-SHA256 hash chain over action events, reusing
AUDIT_HMAC_KEY scoped by event_type='agent_action' in the chain payload.

Mirrors the pattern in api/audit.py (query audit chain) but with action-shaped
fields. The two chains are independent; they share the secret but not the
sequence.

M4: write_audit_entry() and verify_plan_chain() wired into controller.
"""
import hashlib
import hmac as _hmac
import json
import os
import uuid
from datetime import datetime

_INSECURE_DEFAULTS = {"dev-insecure-change-in-production", "", "changeme", "secret"}
_MIN_KEY_LEN = 32


def _key() -> bytes:
    val = os.environ.get("AUDIT_HMAC_KEY", "")
    return val.encode()


def compute_action_entry_hash(
    action_id: str,
    plan_id: str,
    step_index: int,
    tool_name: str,
    params_hash: str,
    auth_decision: str,
    severity_tier: str,
    policy_reference: str,
    role: str,
    timestamp: str,
    prev_hash: str,
) -> str:
    payload = "|".join([
        "agent_action",
        action_id,
        plan_id,
        str(step_index),
        tool_name,
        params_hash,
        auth_decision,
        severity_tier,
        policy_reference,
        role,
        timestamp,
        prev_hash,
    ]).encode()
    return _hmac.new(_key(), payload, hashlib.sha256).hexdigest()


def canonical_params_hash(params: dict) -> str:
    canon = json.dumps(params, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canon).hexdigest()


def verify_action_entry(
    action_id: str,
    plan_id: str,
    step_index: int,
    tool_name: str,
    params_hash: str,
    auth_decision: str,
    severity_tier: str,
    policy_reference: str,
    role: str,
    timestamp: str,
    prev_hash: str,
    stored_hash: str,
) -> bool:
    expected = compute_action_entry_hash(
        action_id, plan_id, step_index, tool_name, params_hash,
        auth_decision, severity_tier, policy_reference, role, timestamp, prev_hash,
    )
    return _hmac.compare_digest(expected, stored_hash)


def write_audit_entry(
    plan_id: str,
    step_index: int,
    tool_name: str,
    params: dict,
    auth_decision: str,
    severity_tier: str,
    policy_reference: str,
    role: str,
    db,
):
    """
    Append a hash-chained audit entry to agent_action_audit.

    prev_hash is the entry_hash of the most recent entry for this plan_id,
    or "genesis" if this is the first entry. Flushes the row to the DB
    session without committing — the caller controls the commit boundary.
    """
    from .models import AgentActionAudit
    from sqlalchemy import text

    last = db.execute(
        text(
            "SELECT entry_hash FROM agent_action_audit"
            " WHERE plan_id = :pid"
            " ORDER BY timestamp DESC, step_index DESC LIMIT 1"
        ),
        {"pid": plan_id},
    ).fetchone()
    prev_hash = last[0] if last else "genesis"

    action_id = str(uuid.uuid4())
    ts = datetime.utcnow()
    ts_str = ts.isoformat()
    params_hash = canonical_params_hash(params)

    entry_hash = compute_action_entry_hash(
        action_id=action_id,
        plan_id=plan_id,
        step_index=step_index,
        tool_name=tool_name,
        params_hash=params_hash,
        auth_decision=auth_decision,
        severity_tier=severity_tier,
        policy_reference=policy_reference,
        role=role,
        timestamp=ts_str,
        prev_hash=prev_hash,
    )

    entry = AgentActionAudit(
        action_id=uuid.UUID(action_id),
        plan_id=uuid.UUID(plan_id),
        step_index=step_index,
        tool_name=tool_name,
        params_hash=params_hash,
        auth_decision=auth_decision,
        severity_tier=severity_tier,
        policy_reference=policy_reference,
        role=role,
        timestamp=ts,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(entry)
    db.flush()
    return entry


def verify_plan_chain(plan_id: str, db) -> dict:
    """
    Recompute and verify the hash chain for all audit entries in a plan.

    Returns:
        {
          "valid": bool,
          "entries_checked": int,
          "first_invalid_index": int | None,
        }
    """
    from .models import AgentActionAudit

    entries = (
        db.query(AgentActionAudit)
        .filter(AgentActionAudit.plan_id == uuid.UUID(plan_id))
        .order_by(AgentActionAudit.timestamp, AgentActionAudit.step_index)
        .all()
    )

    if not entries:
        return {"valid": True, "entries_checked": 0, "first_invalid_index": None}

    first_invalid = None
    for i, e in enumerate(entries):
        expected_prev = "genesis" if i == 0 else entries[i - 1].entry_hash
        if e.prev_hash != expected_prev:
            first_invalid = i
            break
        if not verify_action_entry(
            action_id=str(e.action_id),
            plan_id=str(e.plan_id),
            step_index=e.step_index,
            tool_name=e.tool_name,
            params_hash=e.params_hash,
            auth_decision=e.auth_decision,
            severity_tier=e.severity_tier,
            policy_reference=e.policy_reference,
            role=e.role,
            timestamp=e.timestamp.isoformat(),
            prev_hash=e.prev_hash,
            stored_hash=e.entry_hash,
        ):
            first_invalid = i
            break

    return {
        "valid": first_invalid is None,
        "entries_checked": len(entries),
        "first_invalid_index": first_invalid,
    }
