"""
Tool implementations for KDAT-002. Three tools defined in the v1.2 spec
Section 4.3: lookup_procedure, queue_notification, draft_procedure_update.

Stage: M1 scaffold. Real bodies wired in M3 against the existing retrieval
and document infrastructure in api/.
"""


def lookup_procedure(query: str) -> dict:
    """Severity tier: Low. Reads from corpus. Stage M3."""
    return {"status": "not_implemented_m1", "tool": "lookup_procedure", "query": query}


def queue_notification(recipient: str, message: str) -> dict:
    """Severity tier: High. Side effect: queued notification row. Stage M3-M4."""
    return {"status": "not_implemented_m1", "tool": "queue_notification"}


def draft_procedure_update(procedure_id: str, proposed_change: str) -> dict:
    """Severity tier: Critical. HITL required. Stage M3-M5."""
    return {"status": "not_implemented_m1", "tool": "draft_procedure_update"}
