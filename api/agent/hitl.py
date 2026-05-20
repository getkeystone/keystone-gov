"""
HITL approval queue logic. Severity-tier-driven routing per v1.2 spec P5.3.

Stage: M1 scaffold. Real wiring lands in M5.
"""


def requires_hitl(severity_tier: str) -> bool:
    """Critical and High severity tiers route through HITL per v1.2 P5.3."""
    return severity_tier in {"Critical", "High"}
