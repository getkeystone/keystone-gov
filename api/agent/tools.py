"""
Tool implementations for KDAT-002.

Three tools per spec Section 4.3:
  lookup_procedure      — hybrid retrieval, severity Low
  queue_notification    — write notification row, severity parameter-dependent
  draft_procedure_update — create draft DocumentVersion, severity Critical

All tool functions accept a sqlalchemy DBSession and write side effects to it
without committing. The caller (plan_loop.execute_plan) controls the commit
boundary so that all steps in a plan are committed as a unit.
"""
import logging
import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session as DBSession

log = logging.getLogger("keystone.agent.tools")


def lookup_procedure(topic: str, facility_type: str, db: DBSession) -> dict:
    """
    Retrieve regulatory procedure by topic and facility type.

    Runs hybrid FTS + vector retrieval against the Alberta OHS corpus.
    Returns content, citations, and evidence score. Fail-open for empty
    corpus (returns found=False); the controller treats that as evidence
    insufficient in M5.
    """
    from agent.retrieval import retrieve_for_topic
    return retrieve_for_topic(topic=topic, facility_type=facility_type, role="operator", db=db)


def queue_notification(
    severity: int,
    message: str,
    recipients: list,
    plan_id: str,
    step_index: int,
    db: DBSession,
) -> dict:
    """
    Propose a facility-wide notification.

    Writes an AgentNotification row (no actual dispatch in M3). Severity 1-4
    maps to Critical/High/Medium/Low per spec Section 4.3. The controller
    resolves the effective severity tier from this parameter before this
    function is called, so no tier logic lives here.
    """
    from agent.models import AgentNotification
    notif = AgentNotification(
        plan_id=uuid.UUID(plan_id),
        step_index=step_index,
        severity=severity,
        message=message,
        recipients=recipients,
    )
    db.add(notif)
    db.flush()
    return {
        "status": "queued",
        "notification_id": str(notif.notification_id),
        "severity": severity,
        "recipient_count": len(recipients),
    }


def draft_procedure_update(
    procedure_id: str,
    proposed_text: str,
    citations: list,
    plan_id: str,
    step_index: int,
    user_id: str,
    db: DBSession,
) -> dict:
    """
    Draft a procedure revision and route it to the review queue.

    procedure_id must match corpus_documents.rel_path. Creates a
    DocumentVersion row in status='draft' following the same pattern as
    POST /versions in api/main.py. No content_hash or file_path in M3
    (text-only draft).
    """
    # Resolve procedure_id → corpus_documents integer id.
    try:
        doc_row = db.execute(
            text("SELECT id FROM corpus_documents WHERE rel_path = :rel"),
            {"rel": procedure_id},
        ).fetchone()
    except Exception as exc:
        log.warning("draft_procedure_update: corpus lookup failed: %s", exc)
        db.rollback()
        return {"status": "error", "error": f"corpus lookup failed: {exc}"}

    if not doc_row:
        return {
            "status": "error",
            "error": f"procedure_id not found in corpus: {procedure_id!r}",
        }

    doc_id = doc_row[0]

    try:
        max_row = db.execute(
            text("SELECT MAX(version_number) FROM document_versions WHERE doc_id = :doc_id"),
            {"doc_id": doc_id},
        ).fetchone()
        next_version = (max_row[0] or 0) + 1

        change_summary = (
            f"Agent draft (plan={plan_id}, step={step_index}). "
            f"Citations: {citations}. "
            f"Proposed: {proposed_text[:500]}"
        )

        new_ver = db.execute(
            text("""
                INSERT INTO document_versions
                    (doc_id, version_number, status, change_summary, created_by, created_at)
                VALUES
                    (:doc_id, :ver, 'draft', :summary, :created_by, now())
                RETURNING id, doc_id, version_number, status
            """),
            {
                "doc_id": doc_id,
                "ver": next_version,
                "summary": change_summary,
                "created_by": user_id,
            },
        ).fetchone()
        db.flush()
    except Exception as exc:
        log.warning("draft_procedure_update: insert failed: %s", exc)
        db.rollback()
        return {"status": "error", "error": f"draft insert failed: {exc}"}

    # M6: Retrieve evidence for HHEM consistency check (P2.2).
    # Query the corpus using proposed_text so we surface the chunks most
    # relevant to the proposed revision; HHEM then verifies consistency.
    source_chunks = ""
    try:
        from agent.retrieval import retrieve_for_topic
        ev = retrieve_for_topic(
            topic=proposed_text[:200],
            facility_type="",
            role="operator",
            db=db,
            top_k=3,
        )
        source_chunks = ev.get("content", "")
    except Exception as exc:
        log.warning("draft_procedure_update: evidence retrieval failed: %s", exc)

    return {
        "status": "drafted",
        "version_id": new_ver[0],
        "doc_id": new_ver[1],
        "version_number": new_ver[2],
        "procedure_id": procedure_id,
        "citation_count": len(citations),
        "source_chunks": source_chunks,
    }
