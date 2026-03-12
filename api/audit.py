import hashlib
import hmac as _hmac
import os


def _key() -> bytes:
    val = os.environ.get("AUDIT_HMAC_KEY", "dev-insecure-change-in-production")
    return val.encode()


def compute_entry_hash(
    query_id: str,
    timestamp: str,
    role_used: str,
    mode_used: str,
    policy_outcome: str,
    prev_hash: str,
) -> str:
    data = f"{query_id}|{timestamp}|{role_used}|{mode_used}|{policy_outcome}|{prev_hash}".encode()
    return _hmac.new(_key(), data, hashlib.sha256).hexdigest()


def verify_entry(
    query_id: str,
    timestamp: str,
    role_used: str,
    mode_used: str,
    policy_outcome: str,
    prev_hash: str,
    stored_hash: str,
) -> bool:
    expected = compute_entry_hash(
        query_id, timestamp, role_used, mode_used, policy_outcome, prev_hash
    )
    return _hmac.compare_digest(expected, stored_hash)
