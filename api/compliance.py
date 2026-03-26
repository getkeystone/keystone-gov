"""
COR Audit Readiness compliance module.

Endpoints
---------
POST /compliance/run        Run a checklist assessment (retrieval-only, no LLM).
GET  /compliance/runs       List past runs for the current user.
GET  /compliance/{run_id}   Retrieve a specific run result.

Retrieval strategy
------------------
For each checklist query, runs FTS (websearch_to_tsquery) and, when Ollama is
available, vector nearest-neighbour against corpus_chunks.  No reranker, no LLM
generation — the goal is evidence presence, not answer quality.

A query passes when:
  FTS ts_rank_cd  >= 0.05   (existing noise floor, same as main retrieval path)
  OR
  vector cosine_sim >= 0.30  (meaningful semantic match)

Element score  = (queries_passed / queries_total) * 100
Overall score  = weighted mean of element scores (equal weights by default)
Overall passed = overall_score >= 80.0 (COR standard threshold)
"""

import json
import uuid
from datetime import datetime, timezone

import ollama_client
from cf_identity import AppUser, get_current_user
from database import get_db
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session as DBSession

router = APIRouter(prefix="/compliance", tags=["compliance"])

# ---------------------------------------------------------------------------
# Default COR checklist — 14 elements, 50 queries
# ---------------------------------------------------------------------------

_DEFAULT_COR_CHECKLIST: dict = {
    "id": "cor-audit",
    "name": "COR Audit Readiness",
    "description": (
        "Certificate of Recognition (COR) audit readiness assessment — "
        "14 elements per the Alberta ACSA standard."
    ),
    "elements": [
        {
            "id": 1,
            "name": "Health and Safety Policy",
            "weight": 1.0,
            "queries": [
                "What is the health and safety policy statement?",
                "What are the health and safety goals and objectives?",
                "Who is responsible for health and safety in the workplace?",
                "How is the health and safety policy communicated to workers?",
            ],
        },
        {
            "id": 2,
            "name": "Hazard Assessment and Control",
            "weight": 1.0,
            "queries": [
                "How are workplace hazards identified and assessed?",
                "What is the process for conducting a formal hazard assessment?",
                "How are hazard controls selected using the hierarchy of controls?",
                "What are the requirements for hazard assessment before a new task?",
            ],
        },
        {
            "id": 3,
            "name": "Safe Work Practices and Procedures",
            "weight": 1.0,
            "queries": [
                "What safe work practices are required for high-risk activities?",
                "What are the lockout tagout requirements for hazardous energy control?",
                "What are the fall protection requirements when working at heights?",
                "What personal protective equipment is required for hazardous tasks?",
            ],
        },
        {
            "id": 4,
            "name": "Training and Competency",
            "weight": 1.0,
            "queries": [
                "What safety training is required for new workers?",
                "What are the requirements for worker competency verification?",
                "Who is responsible for delivering safety training?",
                "How are training records documented and maintained?",
            ],
        },
        {
            "id": 5,
            "name": "Workplace Inspections",
            "weight": 1.0,
            "queries": [
                "What are the requirements for conducting regular workplace inspections?",
                "How are inspection findings documented and tracked to completion?",
                "Who is responsible for conducting workplace safety inspections?",
            ],
        },
        {
            "id": 6,
            "name": "Incident Investigation",
            "weight": 1.0,
            "queries": [
                "What is the process for investigating a workplace incident?",
                "What incidents or near misses require a formal investigation?",
                "How are incident investigation findings documented and reported?",
                "What corrective actions are required following an incident investigation?",
            ],
        },
        {
            "id": 7,
            "name": "Emergency Preparedness",
            "weight": 1.0,
            "queries": [
                "What are the emergency response procedures for the workplace?",
                "What are the fire evacuation procedures and assembly points?",
                "What is the procedure for a confined space emergency rescue?",
                "How are emergency drills conducted and documented?",
            ],
        },
        {
            "id": 8,
            "name": "Health and Safety Communication",
            "weight": 1.0,
            "queries": [
                "How is health and safety information communicated to workers?",
                "What are the requirements for health and safety meetings?",
                "How are toolbox talks or safety briefings conducted and documented?",
            ],
        },
        {
            "id": 9,
            "name": "Workplace Health",
            "weight": 1.0,
            "queries": [
                "What are the requirements for managing worker exposure to hazardous substances?",
                "What are the procedures for controlling musculoskeletal injury hazards?",
                "How are worker fatigue and fitness-for-duty risks identified and controlled?",
            ],
        },
        {
            "id": 10,
            "name": "Management Review",
            "weight": 1.0,
            "queries": [
                "How does management review the effectiveness of the health and safety program?",
                "What performance indicators are used to evaluate the safety program?",
                "How are health and safety program deficiencies identified and corrected?",
            ],
        },
        {
            "id": 11,
            "name": "Return to Work",
            "weight": 1.0,
            "queries": [
                "What is the return to work program for injured workers?",
                "What modified duties are available for workers recovering from injury?",
                "How are return to work plans developed and monitored?",
            ],
        },
        {
            "id": 12,
            "name": "Records and Documentation",
            "weight": 1.0,
            "queries": [
                "What health and safety records must be maintained by the employer?",
                "How long must safety-related records be retained?",
                "Who is responsible for maintaining health and safety documentation?",
                "What documentation is required for controlled products and hazardous materials?",
            ],
        },
        {
            "id": 13,
            "name": "Legislation and Regulatory Compliance",
            "weight": 1.0,
            "queries": [
                "How does the organization stay current with OHS legislative requirements?",
                "What are the employer obligations under Alberta OHS legislation?",
                "How are regulatory changes communicated to supervisors and workers?",
            ],
        },
        {
            "id": 14,
            "name": "Management of Change",
            "weight": 1.0,
            "queries": [
                "What is the process for managing changes that affect worker safety?",
                "How are workers informed of changes to work procedures or equipment?",
                "What safety review is required before introducing new equipment or chemicals?",
                "How are contractors managed to ensure health and safety compliance on site?",
            ],
        },
    ],
}


def get_checklist_summaries() -> list[dict]:
    """
    Return checklist summary objects for the /config endpoint.
    Reads from deployment_config if a 'checklists' key is present;
    otherwise returns the built-in default.
    Each summary: {id, name, description, element_count}.
    """
    from deployment_config import CONFIG

    cfg = CONFIG.get("checklists")
    if cfg:
        return cfg  # operator-supplied summaries

    cl = _DEFAULT_COR_CHECKLIST
    return [
        {
            "id": cl["id"],
            "name": cl["name"],
            "description": cl["description"],
            "element_count": len(cl["elements"]),
        }
    ]


def _get_checklist(checklist_id: str) -> dict | None:
    """Return the full checklist dict for checklist_id, or None if not found."""
    from deployment_config import CONFIG

    # Operator may supply full checklist definitions under 'checklists_full'.
    for cl in CONFIG.get("checklists_full", []):
        if cl.get("id") == checklist_id:
            return cl

    if checklist_id == _DEFAULT_COR_CHECKLIST["id"]:
        return _DEFAULT_COR_CHECKLIST

    return None


# ---------------------------------------------------------------------------
# Retrieval helper — FTS + vector, no LLM, no reranker
# ---------------------------------------------------------------------------

_PASS_FTS_THRESHOLD = 0.05   # same noise floor as main retrieval path
_PASS_VEC_THRESHOLD = 0.30   # cosine similarity threshold for semantic match

_FTS_SQL = text("""
    SELECT
        cd.title,
        ts_rank_cd(cc.tsv, query) AS rank
    FROM corpus_chunks cc
    JOIN corpus_documents cd ON cd.id = cc.doc_id
    CROSS JOIN websearch_to_tsquery('english', :q) query
    WHERE cc.tsv @@ query
      AND CASE cd.min_role
            WHEN 'member'    THEN 0
            WHEN 'custodian' THEN 0
            WHEN 'officer'   THEN 1
            WHEN 'authority' THEN 2
            ELSE 0 END <= 0
      AND (cd.status_override IS DISTINCT FROM 'restricted')
      AND (cd.status_override IS DISTINCT FROM 'draft')
      AND (cd.status_override IS DISTINCT FROM 'superseded')
    ORDER BY rank DESC
    LIMIT 5
""")

_VEC_SQL = text("""
    SELECT
        cd.title,
        1.0 - (cc.embedding <=> CAST(:embedding AS vector)) AS cosine_sim
    FROM corpus_chunks cc
    JOIN corpus_documents cd ON cd.id = cc.doc_id
    WHERE cc.embedding IS NOT NULL
      AND CASE cd.min_role
            WHEN 'member'    THEN 0
            WHEN 'custodian' THEN 0
            WHEN 'officer'   THEN 1
            WHEN 'authority' THEN 2
            ELSE 0 END <= 0
      AND (cd.status_override IS DISTINCT FROM 'restricted')
      AND (cd.status_override IS DISTINCT FROM 'draft')
      AND (cd.status_override IS DISTINCT FROM 'superseded')
    ORDER BY cc.embedding <=> CAST(:embedding AS vector)
    LIMIT 5
""")


def _retrieve_for_query(
    question: str,
    db: DBSession,
) -> "tuple[str | None, float, bool]":
    """
    Run FTS + vector retrieval for a single compliance checklist question.

    Returns (top_chunk_title, top_score, passed).
      top_chunk_title — title of the best-matching document chunk, or None
      top_score       — best evidence score (FTS rank_cd or cosine_sim)
      passed          — True when either threshold is met
    """
    # ── FTS ──────────────────────────────────────────────────────────────────
    fts_title: str | None = None
    fts_score: float = 0.0
    try:
        fts_rows = db.execute(_FTS_SQL, {"q": question}).fetchall()
    except Exception:
        db.rollback()
        fts_rows = []
    if fts_rows:
        fts_title = fts_rows[0][0]
        fts_score = float(fts_rows[0][1])

    # ── Vector ───────────────────────────────────────────────────────────────
    vec_title: str | None = None
    vec_score: float = 0.0
    _query_vec = ollama_client.embed(question)
    if _query_vec is not None:
        _pg_vec = "[" + ",".join(str(v) for v in _query_vec) + "]"
        try:
            vec_rows = db.execute(_VEC_SQL, {"embedding": _pg_vec}).fetchall()
        except Exception:
            db.rollback()
            vec_rows = []
        if vec_rows:
            vec_title = vec_rows[0][0]
            vec_score = float(vec_rows[0][1])

    # ── Best evidence ─────────────────────────────────────────────────────────
    fts_pass = fts_score >= _PASS_FTS_THRESHOLD
    vec_pass = vec_score >= _PASS_VEC_THRESHOLD

    if vec_pass and vec_score >= fts_score:
        return vec_title, vec_score, True
    if fts_pass:
        return fts_title, fts_score, True
    # Neither threshold met — return best available score for diagnostics.
    if vec_score > fts_score:
        return vec_title, vec_score, False
    if fts_score > 0.0:
        return fts_title, fts_score, False
    return None, 0.0, False


# ---------------------------------------------------------------------------
# Pydantic request schema
# ---------------------------------------------------------------------------

class ComplianceRunRequest(BaseModel):
    checklist_id: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/run")
def run_compliance_check(
    req: ComplianceRunRequest,
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    """
    Run a compliance checklist assessment.

    Runs retrieval-only (FTS + vector) for each checklist query — no LLM
    generation.  Results are stored in compliance_runs and the run_id is
    returned immediately (status: "complete").
    """
    checklist = _get_checklist(req.checklist_id)
    if checklist is None:
        raise HTTPException(
            status_code=404,
            detail=f"Checklist '{req.checklist_id}' not found.",
        )

    # Detect whether the corpus has been ingested.
    try:
        corpus_count = db.execute(
            text("SELECT COUNT(*) FROM corpus_chunks LIMIT 1")
        ).scalar()
    except Exception:
        db.rollback()
        corpus_count = 0

    total_weight = sum(e["weight"] for e in checklist["elements"])
    weighted_sum = 0.0
    element_results = []

    for element in checklist["elements"]:
        passed_count = 0
        query_results = []

        for question in element["queries"]:
            if corpus_count:
                top_title, top_score, passed = _retrieve_for_query(question, db)
            else:
                top_title, top_score, passed = None, 0.0, False

            if passed:
                passed_count += 1

            query_results.append({
                "query": question,
                "top_chunk_title": top_title,
                "score": round(top_score, 4),
                "pass": passed,
            })

        total_queries = len(element["queries"])
        element_score = (passed_count / total_queries * 100.0) if total_queries else 0.0

        element_results.append({
            "element_id": element["id"],
            "name": element["name"],
            "weight": element["weight"],
            "score": round(element_score, 2),
            "passed": passed_count == total_queries,
            "queries_passed": passed_count,
            "queries_total": total_queries,
            "queries": query_results,
        })

        weighted_sum += element["weight"] * element_score

    overall_score = (weighted_sum / total_weight) if total_weight else 0.0
    overall_passed = overall_score >= 80.0  # COR standard pass threshold

    result = {
        "checklist_id": checklist["id"],
        "checklist_name": checklist["name"],
        "corpus_available": bool(corpus_count),
        "elements": element_results,
    }

    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    db.execute(
        text("""
            INSERT INTO compliance_runs
              (id, checklist_id, user_id, timestamp, overall_score, passed, result)
            VALUES
              (:id, :checklist_id, :user_id, :timestamp, :overall_score, :passed,
               CAST(:result AS jsonb))
        """),
        {
            "id": run_id,
            "checklist_id": checklist["id"],
            "user_id": current_user.user_id,
            "timestamp": now,
            "overall_score": round(overall_score, 2),
            "passed": overall_passed,
            "result": json.dumps(result),
        },
    )
    db.commit()

    return {"run_id": run_id, "status": "complete"}


@router.get("/runs")
def list_compliance_runs(
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
):
    """Return the 50 most recent compliance runs for the current user."""
    try:
        rows = db.execute(
            text("""
                SELECT id, checklist_id, timestamp, overall_score, passed
                FROM compliance_runs
                WHERE user_id = :user_id
                ORDER BY timestamp DESC
                LIMIT 50
            """),
            {"user_id": current_user.user_id},
        ).fetchall()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="Compliance runs table not available.",
        )

    return [
        {
            "run_id": str(r[0]),
            "checklist_id": r[1],
            "timestamp": r[2],
            "overall_score": float(r[3]) if r[3] is not None else None,
            "passed": r[4],
        }
        for r in rows
    ]


@router.get("/{run_id}")
def get_compliance_run(
    run_id: str,
    db: DBSession = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),  # noqa: ARG001
):
    """Return the full result for a compliance run."""
    try:
        row = db.execute(
            text("""
                SELECT id, checklist_id, user_id, timestamp,
                       overall_score, passed, result
                FROM compliance_runs
                WHERE id = :run_id
            """),
            {"run_id": run_id},
        ).fetchone()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="Compliance runs table not available.",
        )

    if row is None:
        raise HTTPException(status_code=404, detail="Run not found.")

    return {
        "run_id": str(row[0]),
        "checklist_id": row[1],
        "user_id": row[2],
        "timestamp": row[3],
        "overall_score": float(row[4]) if row[4] is not None else None,
        "passed": row[5],
        "result": row[6],
    }
