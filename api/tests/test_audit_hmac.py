"""test_audit_hmac.py — Unit tests for AUDIT_HMAC_KEY startup validation.

Tests:
  T1  validate_hmac_key: missing key raises RuntimeError
  T2  validate_hmac_key: known insecure default raises RuntimeError
  T3  validate_hmac_key: 'changeme' raises RuntimeError
  T4  validate_hmac_key: 'secret' raises RuntimeError
  T5  validate_hmac_key: key shorter than 32 chars raises RuntimeError
  T6  validate_hmac_key: key of exactly 32 chars passes
  T7  validate_hmac_key: key longer than 32 chars passes
  T8  compute_entry_hash: uses key from environment (not insecure fallback)
  T9  validate_hmac_key: the literal .env.example placeholder is rejected,
      even though it is 32+ characters long

Run standalone:
    python3 api/tests/test_audit_hmac.py
"""

import os
import re
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import audit


# ---------------------------------------------------------------------------
# validate_hmac_key
# ---------------------------------------------------------------------------

def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    with pytest.raises(RuntimeError, match="not set or is a known insecure default"):
        audit.validate_hmac_key()


def test_insecure_default_raises(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "dev-insecure-change-in-production")
    with pytest.raises(RuntimeError, match="not set or is a known insecure default"):
        audit.validate_hmac_key()


def test_changeme_raises(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "changeme")
    with pytest.raises(RuntimeError, match="not set or is a known insecure default"):
        audit.validate_hmac_key()


def test_secret_raises(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "secret")
    with pytest.raises(RuntimeError, match="not set or is a known insecure default"):
        audit.validate_hmac_key()


def test_too_short_raises(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "x" * 31)
    with pytest.raises(RuntimeError, match="too short"):
        audit.validate_hmac_key()


def test_exactly_32_chars_passes(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "a" * 32)
    audit.validate_hmac_key()  # should not raise


def test_longer_key_passes(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "a" * 64)
    audit.validate_hmac_key()  # should not raise


def test_compute_hash_uses_env_key(monkeypatch):
    """compute_entry_hash must use the env key, not any hardcoded fallback."""
    monkeypatch.setenv("AUDIT_HMAC_KEY", "k" * 32)
    h1 = audit.compute_entry_hash("q1", "ts", "member", "operational", "APPROVED", "")
    monkeypatch.setenv("AUDIT_HMAC_KEY", "j" * 32)
    h2 = audit.compute_entry_hash("q1", "ts", "member", "operational", "APPROVED", "")
    assert h1 != h2, "Different keys must produce different HMACs"


def test_verify_entry_round_trip(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", "z" * 32)
    h = audit.compute_entry_hash("q", "t", "officer", "training", "REFUSED", "prev")
    assert audit.verify_entry("q", "t", "officer", "training", "REFUSED", "prev", h)
    assert not audit.verify_entry("q", "t", "officer", "training", "REFUSED", "WRONG", h)


# ---------------------------------------------------------------------------
# T9: the .env.example placeholder must never validate as a real secret
# ---------------------------------------------------------------------------

def _env_example_hmac_key() -> str:
    """Read the literal AUDIT_HMAC_KEY value shipped in api/.env.example.

    Reading the real file (rather than hardcoding the string here) means
    this test tracks whatever placeholder is actually in the shipped
    example, so it keeps failing correctly if someone changes the
    placeholder text later without also updating the denylist.
    """
    env_example_path = os.path.join(os.path.dirname(__file__), "..", ".env.example")
    with open(env_example_path) as fh:
        content = fh.read()
    match = re.search(r"^AUDIT_HMAC_KEY=(.*)$", content, re.MULTILINE)
    assert match, "AUDIT_HMAC_KEY not found in api/.env.example"
    return match.group(1).strip()


def test_env_example_placeholder_is_long_enough_to_be_a_trap(monkeypatch):
    """Sanity check on the fixture itself: the placeholder must be >= 32
    chars, or T9 below would pass for the wrong reason (length rejection
    instead of denylist rejection).
    """
    placeholder = _env_example_hmac_key()
    assert len(placeholder) >= 32, (
        f".env.example placeholder is only {len(placeholder)} chars; "
        "this test needs a placeholder long enough to clear the length "
        "check on its own, so a pass here proves the denylist (not the "
        "length check) is doing the rejecting."
    )


def test_env_example_placeholder_rejected(monkeypatch):
    """Copying .env.example unchanged must NOT produce a service that
    accepts a valid audit HMAC secret. This is the regression test for the
    gap where 'change-me-to-a-long-random-secret' (33 chars) cleared the
    length check and was not in the denylist.
    """
    placeholder = _env_example_hmac_key()
    monkeypatch.setenv("AUDIT_HMAC_KEY", placeholder)
    with pytest.raises(RuntimeError, match="not set or is a known insecure default"):
        audit.validate_hmac_key()


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import subprocess
    subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v"],
        cwd=os.path.dirname(__file__),
    )
