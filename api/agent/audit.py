"""
Action audit chain. HMAC-SHA256 hash chain over action events, reusing
AUDIT_HMAC_KEY scoped by event_type='agent_action' in the chain payload.

Mirrors the pattern in api/audit.py (query audit chain) but with action-shaped
fields. The two chains are independent; they share the secret but not the
sequence.

Stage: M1 scaffold. Real wiring lands in M4.
"""
import hashlib
import hmac as _hmac
import json
import os

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
