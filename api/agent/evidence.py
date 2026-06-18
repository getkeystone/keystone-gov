"""
Per-step evidence gating for keystone-core/agent (formerly KDAT-002) M6.

Implements P2.1 (retrieval evidence threshold) and P2.2 (HHEM consistency).
Called by plan_loop.execute_plan AFTER each tool executes, implementing
controller-as-reflection per spec Section 4.7. The LLM does not self-assess;
the controller assesses deterministically via sensor readings.

Evidence-bound tools:
  lookup_procedure       — P2.1: evidence_score >= HHEM_THRESHOLD_DETERMINISTIC
  draft_procedure_update — P2.2: hhem_score(source_chunks, proposed_text) >= HHEM_THRESHOLD_LLM

Evidence-free tools:
  queue_notification — no evidence check; passes unconditionally if authorized.

Fail-closed semantics (spec §3.5.4 / P2.2):
  - HHEM model unavailable (score() → None): fail with P2.2
  - Empty source evidence (source_chunks == ""): fail with P2.2
"""
import logging
import os

log = logging.getLogger("keystone.agent.evidence")


def _evidence_threshold() -> float:
    """P2.1 minimum evidence score for retrieval tools."""
    try:
        from hhem_scorer import HHEM_THRESHOLD_DETERMINISTIC
        return HHEM_THRESHOLD_DETERMINISTIC
    except ImportError:
        pass
    try:
        from api.hhem_scorer import HHEM_THRESHOLD_DETERMINISTIC
        return HHEM_THRESHOLD_DETERMINISTIC
    except ImportError:
        pass
    return float(os.environ.get("HHEM_THRESHOLD_DETERMINISTIC", "0.5"))


def _hhem_threshold_llm() -> float:
    """P2.2 minimum HHEM consistency score for LLM-generated text."""
    try:
        from hhem_scorer import HHEM_THRESHOLD_LLM
        return HHEM_THRESHOLD_LLM
    except ImportError:
        pass
    try:
        from api.hhem_scorer import HHEM_THRESHOLD_LLM
        return HHEM_THRESHOLD_LLM
    except ImportError:
        pass
    return float(os.environ.get("HHEM_THRESHOLD_LLM", "0.20"))


def _run_hhem(premise: str, hypothesis: str) -> "float | None":
    """Call hhem_scorer.score(); returns None if model unavailable."""
    try:
        import hhem_scorer
    except ImportError:
        try:
            import api.hhem_scorer as hhem_scorer  # type: ignore[no-redef]
        except ImportError:
            log.warning("evidence: hhem_scorer not importable — P2.2 fail-closed")
            return None
    return hhem_scorer.score(premise, hypothesis)


def check_evidence(
    tool_name: str,
    params: dict,
    result: dict,
    plan_id: str,
    step_index: int,
    role: str,
    severity_tier: str,
    db,
) -> dict:
    """
    Post-execution evidence gating (P2.1 / P2.2).

    Writes a hash-chained audit entry for every evidence-bound tool call
    (allow or deny). Evidence-free tools (queue_notification) are skipped.

    Returns:
        {
            passed:           bool,
            policy_reference: str,   # "P2.1" | "P2.2" | "none"
            evidence_score:   float | None,
            hhem_score:       float | None,
            citation_count:   int,
            rationale:        str,
        }
    """
    def _audit(decision: str, policy_ref: str) -> None:
        if db is not None and plan_id is not None:
            try:
                from .audit import write_audit_entry
                write_audit_entry(
                    plan_id=plan_id,
                    step_index=step_index,
                    tool_name=tool_name,
                    params=params,
                    auth_decision=decision,
                    severity_tier=severity_tier,
                    policy_reference=policy_ref,
                    role=role,
                    db=db,
                )
            except Exception as exc:
                log.warning("check_evidence: audit write failed: %s", exc)

    # ── queue_notification: evidence-free ────────────────────────────────────
    if tool_name == "queue_notification":
        return {
            "passed": True,
            "policy_reference": "none",
            "evidence_score": None,
            "hhem_score": None,
            "citation_count": 0,
            "rationale": "no evidence check required for queue_notification",
        }

    # ── lookup_procedure: P2.1 evidence threshold ─────────────────────────────
    if tool_name == "lookup_procedure":
        evidence_score = float(result.get("evidence_score", 0.0))
        citations = result.get("citations", [])
        citation_count = len(citations)
        threshold = _evidence_threshold()

        if evidence_score < threshold:
            _audit("deny", "P2.1")
            return {
                "passed": False,
                "policy_reference": "P2.1",
                "evidence_score": evidence_score,
                "hhem_score": None,
                "citation_count": citation_count,
                "rationale": (
                    f"evidence_score {evidence_score:.4f} < threshold {threshold:.4f} "
                    f"(P2.1 evidence threshold not met)"
                ),
            }

        _audit("allow", "P2.1")
        return {
            "passed": True,
            "policy_reference": "P2.1",
            "evidence_score": evidence_score,
            "hhem_score": None,
            "citation_count": citation_count,
            "rationale": (
                f"evidence_score {evidence_score:.4f} >= threshold {threshold:.4f}"
            ),
        }

    # ── draft_procedure_update: P2.2 HHEM consistency ─────────────────────────
    if tool_name == "draft_procedure_update":
        proposed_text = params.get("proposed_text", "")
        source_chunks = result.get("source_chunks", "")
        citation_count = len(params.get("citations", []))
        threshold = _hhem_threshold_llm()

        hhem_score = _run_hhem(source_chunks, proposed_text)

        if hhem_score is None:
            _audit("deny", "P2.2")
            return {
                "passed": False,
                "policy_reference": "P2.2",
                "evidence_score": None,
                "hhem_score": None,
                "citation_count": citation_count,
                "rationale": (
                    "HHEM model unavailable or empty evidence — "
                    "proposed_text consistency unverifiable (P2.2 fail-closed)"
                ),
            }

        if hhem_score < threshold:
            _audit("deny", "P2.2")
            return {
                "passed": False,
                "policy_reference": "P2.2",
                "evidence_score": None,
                "hhem_score": hhem_score,
                "citation_count": citation_count,
                "rationale": (
                    f"HHEM score {hhem_score:.4f} < threshold {threshold:.4f} — "
                    f"proposed_text not sufficiently supported by evidence (P2.2)"
                ),
            }

        _audit("allow", "P2.2")
        return {
            "passed": True,
            "policy_reference": "P2.2",
            "evidence_score": None,
            "hhem_score": hhem_score,
            "citation_count": citation_count,
            "rationale": (
                f"HHEM score {hhem_score:.4f} >= threshold {threshold:.4f}"
            ),
        }

    # ── unknown tool: pass unconditionally ────────────────────────────────────
    return {
        "passed": True,
        "policy_reference": "none",
        "evidence_score": None,
        "hhem_score": None,
        "citation_count": 0,
        "rationale": f"no evidence check configured for tool '{tool_name}'",
    }
