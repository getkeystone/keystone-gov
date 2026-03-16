import hashlib
import hmac as _hmac
import os

_INSECURE_DEFAULTS = {"dev-insecure-change-in-production", "", "changeme", "secret"}
_MIN_KEY_LEN = 32


def validate_hmac_key() -> None:
    """Raise RuntimeError if AUDIT_HMAC_KEY is missing, too short, or a known insecure default.
    Call this from application startup so the process refuses to start with a weak key.
    """
    val = os.environ.get("AUDIT_HMAC_KEY", "")
    if not val or val in _INSECURE_DEFAULTS:
        raise RuntimeError(
            "AUDIT_HMAC_KEY is not set or is a known insecure default value. "
            "Set a random key of at least 32 characters before starting the service."
        )
    if len(val) < _MIN_KEY_LEN:
        raise RuntimeError(
            f"AUDIT_HMAC_KEY is too short ({len(val)} chars); "
            f"minimum required length is {_MIN_KEY_LEN} characters."
        )


def _key() -> bytes:
    val = os.environ.get("AUDIT_HMAC_KEY", "")
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
