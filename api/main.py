import hashlib
import io
import json
import os
import re
import subprocess
import sys
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query as QueryParam, Response
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session as DBSession

from audit import compute_entry_hash, verify_entry
from auth import verify_password
from database import Base, SessionLocal, engine, get_db
from models import AuditEntry, Document, Query, Session, User
from schemas import (
    AuditResponse,
    AuditVerifyResponse,
    GuidanceResponse,
    LoginRequest,
    LoginResponse,
    QueryRequest,
    QueryResponse,
    SourceResponse,
)
from procedure_parse import parse_procedure, procedure_quality
from seed import DEMO_QUERIES, seed_demo_data
from text_clean import clean_lines, make_summary

# Maps scenario_key -> guidance template (from seeded data)
_GUIDANCE_TEMPLATES: dict = {q["scenario_key"]: q for q in DEMO_QUERIES}

# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------

_SCENARIO_MIN_LEVEL: dict[str, int] = {
    "restricted": 1,   # officer+ only
}
_ROLE_LEVEL: dict[str, int] = {
    "member": 0,
    "custodian": 0,
    "officer": 1,
    "admin": 2,
}

# Fail-closed refusal used when role is denied by ACL.
_ACL_REFUSAL_GUIDANCE = {
    "type": "refusal",
    "reasonCode": "ACCESS_RESTRICTED",
    "title": "Access restricted",
    "message": (
        "The system cannot provide this content for the current role. "
        "No restricted source details are shown."
    ),
    "safeNextStep": "Contact a supervisor or document custodian if you believe access should be granted.",
    "hiddenSource": True,
}

# ---------------------------------------------------------------------------
# Chunk reranker — penalizes TOC/front-matter, boosts procedural content
# ---------------------------------------------------------------------------

_TOC_SIGNAL = re.compile(
    r'\btable[\s\-_]*of[\s\-_]*contents\b|\bcontents\b',
    re.IGNORECASE,
)
_SECTION_NUM = re.compile(r'\b\d+(\.\d+)+\b')
_PROCEDURAL = re.compile(
    r'\b(?:operat(?:ion|e|ing|ional)|procedur(?:e|es|al)|steps?\b|start(?:ing|up)?'
    r'|shutdown|troubleshoot(?:ing)?|maintenanc(?:e|ing)|alarm|warning|caution'
    r'|danger|decontaminat|decon|rescue|hazmat|response|deploy|activat|emergency'
    r'|instruction|guidanc|protocol)\b',
    re.IGNORECASE,
)

# Front-matter signals: vendor name, city/state, copyright, URLs, "user manual"
_FRONT_MATTER_SIGNAL = re.compile(
    r'rescueintellitech|katy[\s,]+tx|copyright|all\s+rights\s+reserved'
    r'|user[\s\-_]*manual|www\.\S+\.\S+|https?://\S+',
    re.IGNORECASE,
)

# Numbered step pattern: "1." / "Step 1" / "1)" at line start (boost signal)
_NUMBERED_STEP = re.compile(
    r'(?:^|\n)\s*(?:step\s+\d+|(?:\d+)[.)]\s)',
    re.IGNORECASE,
)


def _rerank_score(chunk_index: int, text: str, fts_rank: float) -> float:
    """
    Deterministic reranker score (higher = prefer this chunk).

    Penalties:
      - "table of contents" / "contents" keyword  → ×0.10
      - Front-matter signals (vendor, city/state, copyright, URL, "user manual")
                                                   → ×0.05
      - Digit density > 8 %                        → ×(0.1 … 1.0)
      - Section-number density > 12 %              → ×0.20
      - First chunk of document (chunk_index == 0) → ×0.50

    Boosts:
      - Each procedural signal word                → ×(1.0 + min(n×0.25, 2.0))
      - Numbered-step patterns (Step 1, 1., 2))    → ×1.50
    """
    score = float(fts_rank)

    lower = text.lower()

    if _TOC_SIGNAL.search(lower):
        score *= 0.10

    if _FRONT_MATTER_SIGNAL.search(text):
        score *= 0.05

    n_chars = max(len(text), 1)
    digit_density = sum(1 for c in text if c.isdigit()) / n_chars
    if digit_density > 0.08:
        score *= max(0.10, 1.0 - digit_density * 4)

    n_words = max(len(text.split()), 1)
    n_section_nums = len(_SECTION_NUM.findall(text))
    if n_section_nums / n_words > 0.12:
        score *= 0.20

    if chunk_index == 0:
        score *= 0.50

    n_proc = len(_PROCEDURAL.findall(text))
    if n_proc > 0:
        score *= 1.0 + min(n_proc * 0.25, 2.0)

    if _NUMBERED_STEP.search(text):
        score *= 1.50

    return score


def _is_toc_like(chunk_index: int, text: str) -> bool:
    """Return True if chunk is almost certainly TOC or front-matter.

    Criteria (any one is sufficient):
      - Contains "table of contents" or bare "contents" heading
      - Section-number density > 12 % of words  (e.g. "1.1  Foo  1.2  Bar …")
      - Front-matter signals (vendor name, city/state, copyright, URL, user manual)
      - First chunk AND no procedural signals (title pages / cover sheets)
    """
    lower = text.lower()
    if _TOC_SIGNAL.search(lower):
        return True
    n_words = max(len(text.split()), 1)
    n_section_nums = len(_SECTION_NUM.findall(text))
    if n_section_nums / n_words > 0.12:
        return True
    if _FRONT_MATTER_SIGNAL.search(text):
        return True
    if chunk_index == 0 and not _PROCEDURAL.search(text):
        return True
    return False


# ---------------------------------------------------------------------------
# Retrieval engine (lexical scoring)
# ---------------------------------------------------------------------------

_STOP_WORDS = {
    '', 'a', 'an', 'the', 'is', 'are', 'our', 'what', 'how', 'show', 'me',
    'to', 'of', 'and', 'or', 'in', 'for', 'did', 'i', 'my', 'should',
    'right', 'now', 'do', 'does', 'it', 'this', 'that', 'be', 'was', 'were',
    'have', 'has', 'had', 'with', 'at', 'by', 'from', 'up', 'about', 'into',
    'on', 'if', 'no', 'not', 'so', 'as', 'we', 'you', 'they', 'their',
}

_EVIDENCE_THRESHOLD = 1


def _tokenize(text: str) -> set[str]:
    return {t for t in re.split(r'\W+', text.lower()) if t not in _STOP_WORDS and len(t) > 2}


def _lexical_score(terms: set[str], doc: Document) -> int:
    corpus = f"{doc.title} {doc.section} {doc.excerpt or ''}".lower()
    return sum(1 for t in terms if t in corpus)


def _corpus_fts_retrieve(
    question: str, mode: str, db: DBSession
) -> "tuple[dict, str, list, list] | None":
    """
    Postgres FTS retrieval from corpus_chunks.

    Returns None if corpus is empty — caller falls through to lexical fixtures.
    Returns a refusal tuple if corpus is non-empty but no FTS hits are found.
    All corpus docs are treated as role-0 (no per-doc ACL on corpus yet).
    """
    try:
        count = db.execute(text("SELECT COUNT(*) FROM corpus_chunks LIMIT 1")).scalar()
    except Exception:
        # Table may not exist on first startup before schema migration runs.
        # Must rollback: a failed SQL statement aborts the psycopg2 transaction,
        # which would cause every subsequent query in the same session to fail.
        db.rollback()
        return None

    if not count:
        return None  # corpus not yet ingested — fall through to lexical fixtures

    _FTS_SQL = """
        SELECT
            cd.rel_path,
            cd.title,
            cc.chunk_index,
            cc.text,
            ts_rank_cd(cc.tsv, query) AS rank,
            cc.page
        FROM corpus_chunks cc
        JOIN corpus_documents cd ON cd.id = cc.doc_id
        CROSS JOIN websearch_to_tsquery('english', :q) query
        WHERE cc.tsv @@ query
        ORDER BY rank DESC
        LIMIT 50
    """
    rows = db.execute(text(_FTS_SQL), {"q": question}).fetchall()

    # OR-expansion fallback: when AND-FTS returns nothing, retry with any matching term.
    # This handles equipment questions where brand/type keywords only appear in the
    # title/front-matter while operational content uses generic terms.
    _used_or_fts = False
    if not rows:
        tokens = [t for t in re.split(r'\W+', question.lower())
                  if t not in _STOP_WORDS and len(t) > 2]
        if tokens:
            or_question = " OR ".join(tokens[:8])
            try:
                rows = db.execute(text(_FTS_SQL), {"q": or_question}).fetchall()
                _used_or_fts = bool(rows)
            except Exception:
                db.rollback()

    if not rows:
        guidance = {
            "type": "refusal",
            "reasonCode": "INSUFFICIENT_EVIDENCE",
            "title": "No matching guidance",
            "message": "The system could not find a matching document for this question.",
            "safeNextStep": "Rephrase your question or consult your supervisor.",
            "hiddenSource": False,
        }
        return guidance, "refused", [], []

    # Rerank: penalize TOC/front-matter chunks, boost procedural content.
    reranked = sorted(
        rows,
        key=lambda r: _rerank_score(r[2], r[3], r[4]),
        reverse=True,
    )

    top_rel, top_title, top_chunk, top_text, _fts_rank, top_page = reranked[0]
    _toc_filtered = False
    _used_fallback = False

    # If the best candidate still looks like TOC, try a document-level fallback:
    # fetch the first procedural (non-TOC) chunks from the same matched docs.
    if _is_toc_like(top_chunk, top_text):
        _toc_filtered = True
        matched_docs = list({r[0] for r in reranked[:5]})
        fallback_rows = db.execute(
            text("""
                SELECT cd.rel_path, cd.title, cc.chunk_index, cc.text, cc.page
                FROM corpus_chunks cc
                JOIN corpus_documents cd ON cd.id = cc.doc_id
                WHERE cd.rel_path = ANY(:docs)
                  AND cc.chunk_index > 0
                ORDER BY cd.rel_path, cc.chunk_index ASC
                LIMIT 40
            """),
            {"docs": matched_docs},
        ).fetchall()

        # Rerank with a neutral base score; procedural boosts differentiate them.
        _BASE = 0.001
        fallback_reranked = sorted(
            fallback_rows,
            key=lambda r: _rerank_score(r[2], r[3], _BASE),
            reverse=True,
        )

        for fb_rel, fb_title, fb_chunk, fb_text, fb_page in fallback_reranked:
            if not _is_toc_like(fb_chunk, fb_text):
                top_rel, top_title, top_chunk, top_text, top_page = (
                    fb_rel, fb_title, fb_chunk, fb_text, fb_page
                )
                _used_fallback = True
                _fts_rank = _BASE
                break
        else:
            # All candidates — including fallback — look like TOC/front-matter.
            guidance = {
                "type": "refusal",
                "reasonCode": "NO_PROCEDURE_FOUND",
                "title": "No procedural section found",
                "message": (
                    "The documents matched your question but only returned "
                    "table-of-contents or front-matter sections. "
                    "Try a more specific question about the procedure or step you need."
                ),
                "safeNextStep": (
                    "Ask about a specific operation, step, or maintenance task "
                    "by name (e.g. 'decon machine startup steps')."
                ),
                "hiddenSource": False,
            }
            return guidance, "refused", [], []

    _clean_top = clean_lines(top_text)
    _eff_page = top_page if top_page is not None else top_chunk

    # ── Fetch adjacent chunks for structured procedure parsing ────────────────
    # Window: top_chunk ± 2 (up to 5 chunks ≈ 7 500 chars of context).
    # Run combined text through clean_lines before parsing.
    try:
        adj_rows = db.execute(
            text("""
                SELECT cc.text
                FROM corpus_chunks cc
                JOIN corpus_documents cd ON cd.id = cc.doc_id
                WHERE cd.rel_path = :rel
                  AND cc.chunk_index BETWEEN :lo AND :hi
                ORDER BY cc.chunk_index
            """),
            {"rel": top_rel, "lo": top_chunk - 2, "hi": top_chunk + 2},
        ).fetchall()
        _combined = clean_lines("\n".join(r[0] for r in adj_rows))
    except Exception:
        db.rollback()
        _combined = _clean_top
    proc = parse_procedure(_combined)
    _pq = procedure_quality(proc, _clean_top)

    # ── Fetch document-level metadata (owner/dates/status) ───────────────────
    try:
        _meta = db.execute(
            text("SELECT owner, effective_date, review_date, status_override"
                 " FROM corpus_documents WHERE rel_path = :rel"),
            {"rel": top_rel},
        ).fetchone()
    except Exception:
        db.rollback()
        _meta = None
    _owner     = (_meta[0] if _meta else "") or ""
    _eff_date  = (_meta[1] if _meta else "") or ""
    _rev_date  = (_meta[2] if _meta else "") or ""
    _status_ov = (_meta[3] if _meta else "") or ""

    # ── Prompt 2: Metadata-driven policy (status_override / review_date) ─────
    _today_str = datetime.now(timezone.utc).date().isoformat()
    if mode == "operational":
        if _status_ov in ("superseded", "draft"):
            refusal = {
                "type": "refusal",
                "reasonCode": "NO_ACTIVE_PROCEDURE",
                "title": "No active procedure found",
                "message": "The matched document is not in active status.",
                "safeNextStep": "Consult your training officer for the current version.",
                "hiddenSource": False,
            }
            return refusal, "refused", [], []

    # Notice accumulator for approved path
    _notice: str | None = None
    if mode == "operational":
        if _rev_date and _rev_date < _today_str:
            _notice = "REVIEW_OVERDUE: This document's review date has passed. Verify currency before acting."
    else:  # training mode
        if _status_ov in ("superseded", "draft"):
            _notice = f"TRAINING_ONLY: document status is {_status_ov}"

    # ── Confidence metadata ───────────────────────────────────────────────────
    _rerank_val = _rerank_score(top_chunk, top_text, _fts_rank)
    _reason_parts = [f"chunk {top_chunk} page {top_page}"]
    if _used_or_fts:
        _reason_parts.append("OR-expanded FTS (AND returned 0 hits)")
    if _used_fallback:
        _reason_parts.append(f"document fallback (initial top was TOC-like)")
    _reason_parts.append(f"FTS rank {_fts_rank:.4f}; rerank {_rerank_val:.4f}")

    # ── Prompt 3: Apply procedure quality decision ────────────────────────────
    _pq_notice: str | None = None
    _pq_steps    = proc["steps"]
    _pq_warnings = proc["warnings"]
    _pq_prereqs  = proc["prereqs"]
    _pq_troubles = proc["troubleshooting"]
    if _pq["decision"] == "reject":
        _pq_steps = []
        _pq_warnings = []
        _pq_prereqs = []
        _pq_troubles = []
        _pq_notice = "PROCEDURE_EXTRACT_REJECTED"
    elif _pq["decision"] == "weak":
        _pq_notice = "LOW_CONFIDENCE"

    # Merge notices: quality notice takes precedence; if both, combine.
    if _pq_notice and _notice:
        _final_notice: str | None = _pq_notice  # quality notice wins in text; both communicated
    elif _pq_notice:
        _final_notice = _pq_notice
    else:
        _final_notice = _notice

    guidance: dict = {
        "type": "approved",
        "summary": make_summary(_clean_top),
        "excerpt": _clean_top[:800],
        "document": {
            "documentId": top_rel,
            "title": top_title,
            "section": f"page {top_page}" if top_page is not None else f"chunk {top_chunk}",
            "page": _eff_page,
            "chunkIndex": top_chunk,
            "status": _status_ov if _status_ov else "active",
            "effectiveDate": _eff_date,
            "reviewDate": _rev_date,
            "owner": _owner,
        },
        # Top-level structured procedure fields (always present, may be empty lists)
        "steps":           _pq_steps,
        "warnings":        _pq_warnings,
        "prereqs":         _pq_prereqs,
        "troubleshooting": _pq_troubles,
        "confidence": {
            "rerank_reason": "; ".join(_reason_parts),
            "toc_filtered":  _toc_filtered,
            "used_fallback": _used_fallback,
        },
        "procedure_quality": _pq,
    }
    if _final_notice is not None:
        guidance["notice"] = _final_notice
    # Return top 5 reranked candidates as sources/citations.
    top5 = reranked[:5]
    sources = [
        {
            "documentId": rel_path,
            "title": title,
            "status": "active",
            "allowed": True,
            "page": pg if pg is not None else chunk_idx,
            "chunkIndex": chunk_idx,
            "section": f"page {pg}" if pg is not None else f"chunk {chunk_idx}",
            "note": f"FTS rank {rank:.4f}  rerank {_rerank_score(chunk_idx, _text, rank):.4f}",
        }
        for rel_path, title, chunk_idx, _text, rank, pg in top5
    ]
    citations = [
        {
            "documentId": rel_path,
            "chunkIndex": chunk_idx,
            "page": pg,
            "snippet": chunk_text_val[:300],
        }
        for rel_path, _title, chunk_idx, chunk_text_val, _rank, pg in top5
    ]
    return guidance, "allowed", sources, citations


def _retrieve(
    question: str, mode: str, role_level: int, db: DBSession
) -> tuple[dict, str, list, list]:
    """
    Primary retrieval dispatcher:
    - If corpus_chunks has rows: use Postgres FTS (websearch_to_tsquery).
    - Otherwise: lexical scoring against synthetic document fixtures.
    Fail-closed in both paths: INSUFFICIENT_EVIDENCE if nothing matches.
    """
    # FTS path — active whenever corpus has been ingested.
    fts_result = _corpus_fts_retrieve(question, mode, db)
    if fts_result is not None:
        return fts_result

    # Lexical fallback — used when corpus_chunks is empty (fresh DB / smoke tests).
    terms = _tokenize(question)

    all_docs = db.query(Document).all()

    # Mode filter: operational = active only; training = active + superseded
    if mode == "operational":
        candidates = [d for d in all_docs if d.status == "active"]
    else:
        candidates = [d for d in all_docs if d.status in ("active", "superseded")]

    scored = [(d, _lexical_score(terms, d)) for d in candidates]
    scored.sort(key=lambda x: -x[1])

    best_doc, best_score = (scored[0] if scored else (None, 0))

    if not best_doc or best_score < _EVIDENCE_THRESHOLD:
        guidance = {
            "type": "refusal",
            "reasonCode": "INSUFFICIENT_EVIDENCE",
            "title": "No matching guidance",
            "message": "The system could not find a matching policy document for this question.",
            "safeNextStep": "Rephrase your question or consult your supervisor.",
            "hiddenSource": False,
        }
        return guidance, "refused", [], []

    # ACL check: if best doc requires higher role level, fail closed — no title/citations leaked
    if best_doc.min_role_level > role_level:
        return _ACL_REFUSAL_GUIDANCE, "refused", [], []

    _clean_ex = clean_lines(best_doc.excerpt or "")
    guidance = {
        "type": "approved",
        "summary": make_summary(_clean_ex),
        "excerpt": _clean_ex[:800],
        "document": {
            "documentId": best_doc.document_id,
            "title": best_doc.title,
            "section": best_doc.section,
            "page": best_doc.page,
            "status": best_doc.status,
            "effectiveDate": best_doc.effective_date or "",
            "reviewDate": best_doc.review_date or "",
            "owner": best_doc.owner or "",
        },
    }
    sources = [{
        "documentId": best_doc.document_id,
        "title": best_doc.title,
        "status": best_doc.status,
        "allowed": True,
        "page": best_doc.page,
        "section": best_doc.section,
        "note": "Retrieved by lexical match.",
    }]
    citations = [{"documentId": best_doc.document_id, "page": best_doc.page, "section": best_doc.section}]
    return guidance, "allowed", sources, citations


def _scenario_key_from_guidance(guidance: dict) -> str:
    if guidance.get("type") == "approved":
        return "approved"
    code = guidance.get("reasonCode", "")
    if code == "ACCESS_RESTRICTED":
        return "restricted"
    return "refusal"


# ---------------------------------------------------------------------------
# Startup — DB init is non-fatal; /health reflects readiness
# ---------------------------------------------------------------------------

_db_ready = False

# Resolved once at startup; falls back to "0.1.0" when git is unavailable.
try:
    _VERSION: str = subprocess.check_output(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        stderr=subprocess.DEVNULL,
    ).decode().strip()
except Exception:
    _VERSION = "0.1.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db_ready
    try:
        # Tables are pre-created by initdb/00-schema.sql when connecting as
        # keystone_app.  create_all() is a no-op if tables already exist.
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            seed_demo_data(db)
        finally:
            db.close()
        _db_ready = True
    except Exception as exc:
        print(f"[startup] DB init failed: {exc}", file=sys.stderr, flush=True)
        print("[startup] API will serve /health as degraded until DB is available.",
              file=sys.stderr, flush=True)
    yield


app = FastAPI(title="Keystone Gov API", version="0.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


def get_current_session(
    authorization: str | None = Header(default=None),
    db: DBSession = Depends(get_db),
) -> Session:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.removeprefix("Bearer ")
    session = db.query(Session).filter(Session.token == token).first()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return session


# ---------------------------------------------------------------------------
# Health (no auth)
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    return {
        "status": "ok" if _db_ready else "degraded",
        "service": "keystone-gov-api",
        "db": _db_ready,
        "version": _VERSION,
        "time_utc": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Auth (no auth)
# ---------------------------------------------------------------------------


@app.post("/auth/login", response_model=LoginResponse)
def login(req: LoginRequest, db: DBSession = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = str(uuid.uuid4())
    db.add(Session(token=token, user_id=user.id, username=user.username, role=user.role))
    db.commit()
    return LoginResponse(token=token, username=user.username, role=user.role)


# ---------------------------------------------------------------------------
# Query (requires auth; role from token only)
# ---------------------------------------------------------------------------


@app.post("/query", response_model=QueryResponse)
def submit_query(
    req: QueryRequest,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    # Role is ALWAYS derived from the authenticated session — request body value ignored.
    role = current_session.role
    role_level = _ROLE_LEVEL.get(role, 0)

    # Admin override: scenario_key short-circuits retrieval for demo purposes.
    # "restricted" is handled first (its template contains the member-refused fixture,
    # not the officer/admin approved guidance, so it needs ACL-aware handling).
    if req.scenario_key and role_level >= _ROLE_LEVEL["admin"]:
        if req.scenario_key == "restricted":
            min_level = _SCENARIO_MIN_LEVEL.get("restricted", 1)
            if role_level >= min_level:
                guidance = {
                    "type": "approved",
                    "summary": "Restricted post-incident disciplinary information. Access granted for current role.",
                    "excerpt": (
                        "Post-incident review dated 2025-11-03: disciplinary action was taken per department "
                        "standard operating procedure section 7.4. Details are restricted to supervisory "
                        "and administrative personnel only."
                    ),
                    "note": "Restricted to officer and admin roles only.",
                    "document": {
                        "documentId": "demo-fd-restricted-001",
                        "title": "Demo FD Post-Incident Disciplinary Memo (2025-11-03)",
                        "section": "7.4",
                        "page": 1,
                        "status": "active",
                        "effectiveDate": "2025-11-03",
                        "reviewDate": "2026-11-03",
                        "owner": "Fire Chief",
                    },
                }
                policy_outcome = "allowed"
                sources = [{
                    "documentId": "demo-fd-restricted-001",
                    "title": "Demo FD Post-Incident Disciplinary Memo",
                    "status": "active",
                    "allowed": True,
                    "page": 1,
                    "section": "7.4",
                    "note": "Accessible to officer/admin only.",
                }]
                citations = [{"documentId": "demo-fd-restricted-001", "page": 1, "section": "7.4"}]
            else:
                guidance = _ACL_REFUSAL_GUIDANCE
                policy_outcome = "refused"
                sources = []
                citations = []
            stored_scenario_key = "restricted"
        elif req.scenario_key in _GUIDANCE_TEMPLATES:
            template = _GUIDANCE_TEMPLATES[req.scenario_key]
            guidance = template["guidance"]
            policy_outcome = "allowed" if guidance["type"] == "approved" else "refused"
            sources = template["audit"]["sourcesConsidered"]
            citations = template["audit"]["citationsReturned"]
            stored_scenario_key = req.scenario_key
        else:
            # Unknown scenario_key — fall through to retrieval
            guidance, policy_outcome, sources, citations = _retrieve(req.question, req.mode, role_level, db)
            stored_scenario_key = _scenario_key_from_guidance(guidance)
    else:
        # Real retrieval — scenario_key ignored for non-admins
        guidance, policy_outcome, sources, citations = _retrieve(req.question, req.mode, role_level, db)
        stored_scenario_key = _scenario_key_from_guidance(guidance)

    query_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    db.add(Query(
        id=query_id,
        question=req.question,
        role=role,
        mode=req.mode,
        scenario_key=stored_scenario_key,
        guidance_json=guidance,
        created_at=datetime.now(timezone.utc),
    ))

    last = db.query(AuditEntry).order_by(AuditEntry.timestamp.desc()).first()
    prev_hash = last.entry_hash if last else ""

    entry_hash = compute_entry_hash(
        query_id, now, role, req.mode, policy_outcome, prev_hash
    )

    db.add(AuditEntry(
        id=str(uuid.uuid4()),
        query_id=query_id,
        receipt_id=f"receipt-{query_id[:8]}",
        timestamp=now,
        role_used=role,
        mode_used=req.mode,
        policy_outcome=policy_outcome,
        sources_considered_json=sources,
        citations_returned_json=citations,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    ))
    db.commit()

    return QueryResponse(query_id=query_id, scenario_key=stored_scenario_key)


# ---------------------------------------------------------------------------
# Guidance (requires auth)
# ---------------------------------------------------------------------------


@app.get("/guidance/{query_id}", response_model=GuidanceResponse)
def get_guidance(
    query_id: str,
    db: DBSession = Depends(get_db),
    _session: Session = Depends(get_current_session),
):
    q = db.query(Query).filter(Query.id == query_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")
    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    audit = _build_audit_dict(entry) if entry else {}
    return GuidanceResponse(
        queryId=q.id,
        scenarioKey=q.scenario_key,
        question=q.question,
        mode=q.mode,
        guidance=q.guidance_json,
        audit=audit,
    )


# ---------------------------------------------------------------------------
# Source (requires auth; ACL enforced on document access)
# ---------------------------------------------------------------------------


@app.get("/source/{document_id}/{page}", response_model=SourceResponse)
def get_source(
    document_id: str,
    page: int,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    # ── Corpus lookup: check corpus_documents first ────────────────────────
    # document_id matches corpus_documents.rel_path; page is the chunk index.
    try:
        corpus_row = db.execute(
            text("""
                SELECT cd.rel_path, cd.title, cc.text
                FROM corpus_documents cd
                JOIN corpus_chunks cc ON cc.doc_id = cd.id
                WHERE cd.rel_path = :rel AND cc.chunk_index = :idx
            """),
            {"rel": document_id, "idx": page},
        ).fetchone()
    except Exception:
        db.rollback()
        corpus_row = None

    if corpus_row:
        rel_path, title, chunk_text = corpus_row
        return SourceResponse(
            documentId=rel_path,
            page=page,
            title=title,
            section=f"chunk {page}",
            status="active",
            effectiveDate="",
            reviewDate="",
            owner="",
            excerpt=(chunk_text or "")[:800],
            highlight="",
            notes=[],
        )

    # ── Seeded fixture lookup (existing behavior) ──────────────────────────
    key = f"{document_id}:{page}"
    doc = db.query(Document).filter(Document.key == key).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Source not found")

    role_level = _ROLE_LEVEL.get(current_session.role, 0)
    if doc.min_role_level > role_level:
        raise HTTPException(status_code=403, detail="Access restricted for current role")

    return SourceResponse(
        documentId=doc.document_id,
        page=doc.page,
        title=doc.title,
        section=doc.section,
        status=doc.status,
        effectiveDate=doc.effective_date or "",
        reviewDate=doc.review_date or "",
        owner=doc.owner or "",
        excerpt=doc.excerpt or "",
        highlight=doc.highlight or "",
        notes=doc.notes_json or [],
    )


# ---------------------------------------------------------------------------
# Source by chunk index (corpus only; used when page is null)
# ---------------------------------------------------------------------------


@app.get("/source-chunk/{document_id:path}", response_model=SourceResponse)
def get_source_chunk(
    document_id: str,
    chunk_index: int,
    db: DBSession = Depends(get_db),
    _session: Session = Depends(get_current_session),
):
    """Fetch a corpus source page by chunk_index instead of PDF page number.
    Used by the UI when guidance.document.chunkIndex is known but page is null.
    """
    try:
        corpus_row = db.execute(
            text("""
                SELECT cd.rel_path, cd.title, cc.text, cc.page
                FROM corpus_documents cd
                JOIN corpus_chunks cc ON cc.doc_id = cd.id
                WHERE cd.rel_path = :rel AND cc.chunk_index = :idx
            """),
            {"rel": document_id, "idx": chunk_index},
        ).fetchone()
    except Exception:
        db.rollback()
        corpus_row = None

    if not corpus_row:
        raise HTTPException(status_code=404, detail="Chunk not found")

    rel_path, title, chunk_text_val, page_num = corpus_row
    return SourceResponse(
        documentId=rel_path,
        page=page_num if page_num is not None else chunk_index,
        title=title,
        section=f"page {page_num}" if page_num is not None else f"chunk {chunk_index}",
        status="active",
        effectiveDate="",
        reviewDate="",
        owner="",
        excerpt=(chunk_text_val or "")[:800],
        highlight="",
        notes=[],
    )


# ---------------------------------------------------------------------------
# Document file download (requires auth; serves corpus active/ files)
# ---------------------------------------------------------------------------

_CORPUS_ROOT = Path(os.environ.get("CORPUS_ROOT", "/srv/keystone-corpus"))

_DOC_MEDIA_TYPES: dict[str, str] = {
    ".pdf":  "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


@app.get("/document/{document_id:path}")
def get_document(
    document_id: str,
    mode: str = QueryParam(default="operational", pattern="^(operational|training)$"),
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """
    Serve a corpus document file from CORPUS_ROOT/active/<document_id>.

    Mode gating:
      - operational: document must be present in corpus_documents (implicitly active)
      - training:    same (all ingested corpus docs are active; superseded is not
                     implemented at corpus level yet)
      - restricted docs: corpus_documents has no restricted concept — all served docs
                         are active. Seeded fixtures with min_role_level > 0 are NOT
                         served here; use /source for those.

    Security:
      - Path is resolved and checked to be under CORPUS_ROOT/active/ (no traversal).
      - Only .pdf and .docx are served; others return 415.
      - File must exist in corpus_documents table (existence not guessable).
    """
    # Validate document exists in DB (prevents guessing arbitrary filenames).
    try:
        doc_row = db.execute(
            text("SELECT rel_path FROM corpus_documents WHERE rel_path = :rel"),
            {"rel": document_id},
        ).fetchone()
    except Exception:
        db.rollback()
        doc_row = None

    if not doc_row:
        raise HTTPException(status_code=404, detail="Document not found")

    # Resolve filesystem path and prevent path traversal.
    active_root = (_CORPUS_ROOT / "active").resolve()
    target = (active_root / document_id).resolve()

    if not str(target).startswith(str(active_root) + "/") and target != active_root:
        raise HTTPException(status_code=400, detail="Invalid document path")

    if not target.exists():
        raise HTTPException(status_code=404, detail="Document file not found on disk")

    suffix = target.suffix.lower()
    media_type = _DOC_MEDIA_TYPES.get(suffix)
    if not media_type:
        raise HTTPException(status_code=415, detail=f"Unsupported document type: {suffix}")

    # PDFs: inline so browser renders in-tab; DOCX: attachment for download.
    disposition = "inline" if suffix == ".pdf" else "attachment"
    filename = target.name

    return FileResponse(
        path=str(target),
        media_type=media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


# ---------------------------------------------------------------------------
# Audit (requires auth)
# ---------------------------------------------------------------------------


@app.get("/audit/{query_id}", response_model=AuditResponse)
def get_audit(
    query_id: str,
    db: DBSession = Depends(get_db),
    _session: Session = Depends(get_current_session),
):
    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    q = db.query(Query).filter(Query.id == query_id).first()
    question = q.question if q else ""
    return AuditResponse(**_build_audit_dict(entry), queryId=query_id, question=question)


@app.get("/audit/{query_id}/verify", response_model=AuditVerifyResponse)
def verify_audit(
    query_id: str,
    db: DBSession = Depends(get_db),
    _session: Session = Depends(get_current_session),
):
    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Audit entry not found")

    valid = verify_entry(
        query_id=query_id,
        timestamp=entry.timestamp,
        role_used=entry.role_used,
        mode_used=entry.mode_used,
        policy_outcome=entry.policy_outcome,
        prev_hash=entry.prev_hash,
        stored_hash=entry.entry_hash,
    )
    return AuditVerifyResponse(
        queryId=query_id,
        valid=valid,
        detail="HMAC matches" if valid else "HMAC mismatch — record may have been tampered",
    )


# ---------------------------------------------------------------------------
# Evidence bundle export (admin only)
# ---------------------------------------------------------------------------


_ZIP_DATE = (1980, 1, 1, 0, 0, 0)  # deterministic ZipInfo date_time


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _zip_writestr_det(zf: zipfile.ZipFile, name: str, data: "bytes | str") -> bytes:
    """Write a file into zf with deterministic date_time; return the raw bytes written."""
    raw = data.encode() if isinstance(data, str) else data
    info = zipfile.ZipInfo(filename=name, date_time=_ZIP_DATE)
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, raw)
    return raw


def _build_evidence_data(
    query_id: str, db: DBSession
) -> "tuple[dict, dict, dict, str, bytes | None, bool, dict | None]":
    """
    Gather all evidence data for a query.

    Returns:
      (guidance, audit_dict, verify_dict, excerpt_text,
       cited_page_pdf, pdf_included, corpus_doc_meta)
    """
    q = db.query(Query).filter(Query.id == query_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")

    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    audit_dict = _build_audit_dict(entry) if entry else {}

    if entry:
        _valid = verify_entry(
            query_id=query_id,
            timestamp=entry.timestamp,
            role_used=entry.role_used,
            mode_used=entry.mode_used,
            policy_outcome=entry.policy_outcome,
            prev_hash=entry.prev_hash,
            stored_hash=entry.entry_hash,
        )
        verify_dict = {
            "queryId": query_id,
            "valid": _valid,
            "detail": "HMAC matches" if _valid else "HMAC mismatch — record may have been tampered",
        }
    else:
        verify_dict = {"queryId": query_id, "valid": False, "detail": "Audit entry not found"}

    guidance = q.guidance_json or {}
    excerpt_text = guidance.get("excerpt", "")
    cited_page_pdf: bytes | None = None
    corpus_doc_meta: dict | None = None

    if guidance.get("type") == "approved":
        doc = guidance.get("document", {})
        doc_id    = doc.get("documentId", "")
        chunk_idx = doc.get("chunkIndex")
        page_num  = doc.get("page")

        # Full chunk text from DB
        if doc_id and chunk_idx is not None:
            try:
                _chunk_row = db.execute(
                    text("""
                        SELECT cc.text FROM corpus_chunks cc
                        JOIN corpus_documents cd ON cd.id = cc.doc_id
                        WHERE cd.rel_path = :rel AND cc.chunk_index = :idx
                    """),
                    {"rel": doc_id, "idx": chunk_idx},
                ).fetchone()
                if _chunk_row:
                    excerpt_text = _chunk_row[0] or excerpt_text
            except Exception:
                db.rollback()

        # Corpus provenance
        if doc_id:
            try:
                _corp_row = db.execute(
                    text("""
                        SELECT rel_path, sha256, status_override, effective_date, review_date
                        FROM corpus_documents WHERE rel_path = :rel
                    """),
                    {"rel": doc_id},
                ).fetchone()
                if _corp_row:
                    corpus_doc_meta = {
                        "rel_path":        _corp_row[0],
                        "sha256":          _corp_row[1],
                        "status_override": _corp_row[2],
                        "effective_date":  _corp_row[3],
                        "review_date":     _corp_row[4],
                    }
            except Exception:
                db.rollback()

        # Single-page PDF extract
        if doc_id and isinstance(page_num, int):
            _doc_path = (_CORPUS_ROOT / "active" / doc_id).resolve()
            if _doc_path.exists() and _doc_path.suffix.lower() == ".pdf":
                try:
                    from pypdf import PdfReader, PdfWriter
                    _reader = PdfReader(str(_doc_path))
                    if 1 <= page_num <= len(_reader.pages):
                        _writer = PdfWriter()
                        _writer.add_page(_reader.pages[page_num - 1])
                        _pdf_buf = io.BytesIO()
                        _writer.write(_pdf_buf)
                        cited_page_pdf = _pdf_buf.getvalue()
                except Exception:
                    pass

    pdf_included = cited_page_pdf is not None
    return guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta


def _build_manifest(
    query_id: str,
    generated_utc: str,
    file_entries: list[dict],
    pdf_deterministic: bool,
    corpus_doc_meta: "dict | None",
) -> dict:
    return {
        "schema": "evidence-manifest/v1",
        "query_id": query_id,
        "generated_utc": generated_utc,
        "git": {
            "repo": "keystone-gov",
            "commit": _VERSION,
            "dirty": False,
        },
        "pdf_deterministic": pdf_deterministic,
        "files": file_entries,
        "corpus_document": corpus_doc_meta,
    }


@app.get("/evidence/{query_id}/manifest")
def get_evidence_manifest(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Return the evidence manifest JSON for a query (any authenticated role)."""
    guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta = \
        _build_evidence_data(query_id, db)

    # Build the same file list as the ZIP would contain, in sorted order.
    _files: list[tuple[str, bytes]] = []
    _guidance_bytes  = json.dumps(guidance,    sort_keys=True, indent=2).encode()
    _audit_bytes     = json.dumps(audit_dict,  sort_keys=True, indent=2).encode()
    _verify_bytes    = json.dumps(verify_dict, sort_keys=True, indent=2).encode()
    _excerpt_bytes   = excerpt_text.encode() if isinstance(excerpt_text, str) else excerpt_text

    _files.append(("audit.json",               _audit_bytes))
    _files.append(("cited_source_excerpt.txt", _excerpt_bytes))
    _files.append(("guidance.json",            _guidance_bytes))
    _files.append(("verify.json",              _verify_bytes))

    if cited_page_pdf is not None:
        page_label = guidance.get("document", {}).get("page", "0")
        _files.append((f"cited_page_{page_label}.pdf", cited_page_pdf))

    _files.sort(key=lambda x: x[0])

    file_entries = [
        {
            "name":   name,
            "sha256": _sha256_hex(data),
            "bytes":  len(data),
        }
        for name, data in _files
    ]

    generated_utc = datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(
        query_id=query_id,
        generated_utc=generated_utc,
        file_entries=file_entries,
        pdf_deterministic=not pdf_included,
        corpus_doc_meta=corpus_doc_meta,
    )
    return manifest


@app.get("/evidence/{query_id}.zip")
def get_evidence_zip(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """
    Build and return a deterministic ZIP bundle for a single query (admin only).

    Bundle contents (written in sorted alphabetical order):
      audit.json              — audit receipt fields
      cited_source_excerpt.txt — full text of the cited corpus chunk
      cited_page_<N>.pdf      — single-page PDF extract (if PDF + page known)
      guidance.json           — stored guidance_json for the query
      verify.json             — HMAC chain verification result
      manifest.json           — sha256 of all above files (written last)

    All ZipInfo entries use date_time=(1980,1,1,0,0,0) for determinism.
    JSON files use sort_keys=True for canonical form.
    """
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin token required")

    guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta = \
        _build_evidence_data(query_id, db)

    # Collect all non-manifest files as (name, bytes) then sort alphabetically.
    _guidance_bytes  = json.dumps(guidance,    sort_keys=True, indent=2).encode()
    _audit_bytes     = json.dumps(audit_dict,  sort_keys=True, indent=2).encode()
    _verify_bytes    = json.dumps(verify_dict, sort_keys=True, indent=2).encode()
    _excerpt_bytes   = excerpt_text.encode() if isinstance(excerpt_text, str) else excerpt_text

    _files: list[tuple[str, bytes]] = [
        ("audit.json",               _audit_bytes),
        ("cited_source_excerpt.txt", _excerpt_bytes),
        ("guidance.json",            _guidance_bytes),
        ("verify.json",              _verify_bytes),
    ]

    if cited_page_pdf is not None:
        page_label = guidance.get("document", {}).get("page", "0")
        _files.append((f"cited_page_{page_label}.pdf", cited_page_pdf))

    _files.sort(key=lambda x: x[0])

    # Build manifest using sha256 of each file's bytes.
    file_entries = [
        {
            "name":   name,
            "sha256": _sha256_hex(data),
            "bytes":  len(data),
        }
        for name, data in _files
    ]
    generated_utc = datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(
        query_id=query_id,
        generated_utc=generated_utc,
        file_entries=file_entries,
        pdf_deterministic=not pdf_included,
        corpus_doc_meta=corpus_doc_meta,
    )
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2).encode()

    # Assemble ZIP in memory — sorted files first, manifest last.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _files:
            _zip_writestr_det(zf, name, data)
        _zip_writestr_det(zf, "manifest.json", manifest_bytes)

    filename = f"evidence-{query_id[:8]}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Admin: tamper endpoint (demo proof — admin token required)
# ---------------------------------------------------------------------------


@app.post("/admin/tamper/{query_id}")
def tamper_audit_entry(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """
    Demo-only endpoint. Corrupts the stored policy_outcome for a given query,
    causing HMAC verification to return valid=false. Admin token required.
    Uses DB owner credentials (TAMPER_DATABASE_URL) to simulate a privileged
    insider threat — proving tamper-evidence holds even against owner-level edits.
    """
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin token required")

    # Verify the entry exists via runtime connection first.
    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    original_outcome = entry.policy_outcome

    # Perform the tamper using DB owner credentials (keystone_app cannot UPDATE).
    tamper_url = os.environ.get("TAMPER_DATABASE_URL", "")
    if not tamper_url:
        raise HTTPException(status_code=501, detail="TAMPER_DATABASE_URL not configured")

    tamper_engine = create_engine(tamper_url)
    try:
        with tamper_engine.connect() as conn:
            conn.execute(
                text("UPDATE audit_log SET policy_outcome='TAMPERED' WHERE query_id=:qid"),
                {"qid": query_id},
            )
            conn.commit()
    finally:
        tamper_engine.dispose()

    return {
        "tampered": True,
        "query_id": query_id,
        "original_outcome": original_outcome,
        "detail": "policy_outcome field corrupted; HMAC verification will now return valid=false",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_audit_dict(entry: AuditEntry) -> dict:
    return {
        "receiptId": entry.receipt_id,
        "timestamp": entry.timestamp,
        "roleUsed": entry.role_used,
        "modeUsed": entry.mode_used,
        "policyOutcome": entry.policy_outcome,
        "sourcesConsidered": entry.sources_considered_json,
        "citationsReturned": entry.citations_returned_json,
    }


# ---------------------------------------------------------------------------
# Document registry (requires auth)
# ---------------------------------------------------------------------------

_ALLOWED_STATUS_OVERRIDES = {"", "active", "superseded", "draft", "restricted"}
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class DocMetadataPatch(BaseModel):
    status_override: str | None = None
    owner: str | None = None
    effective_date: str | None = None
    review_date: str | None = None
    title_override: str | None = None


def _corpus_doc_to_dict(row: tuple, today: str) -> dict:
    """Convert a corpus_documents SELECT row to API dict.

    Expected columns (positional):
      0  id
      1  rel_path
      2  sha256
      3  size_bytes
      4  title
      5  owner
      6  effective_date
      7  review_date
      8  status_override
      9  created_utc
    """
    (_id, rel_path, sha256, _size, title,
     owner, eff_date, rev_date, status_ov, created_utc) = row
    status = status_ov if status_ov else "active"
    review_overdue = bool(rev_date and rev_date < today)
    return {
        "documentId":       rel_path,
        "title":            title or rel_path,
        "rel_path":         rel_path,
        "status":           status,
        "owner":            owner or "",
        "effectiveDate":    eff_date or "",
        "reviewDate":       rev_date or "",
        "reviewOverdue":    review_overdue,
        "sha256":           sha256 or "",
        "last_ingested_utc": created_utc.isoformat() if created_utc else "",
    }


_DOC_SELECT = """
    SELECT id, rel_path, sha256, size_bytes, title, owner,
           effective_date, review_date, status_override, created_utc
    FROM corpus_documents
"""


@app.get("/documents")
def list_documents(
    q:           str | None = QueryParam(default=None),
    status:      str | None = QueryParam(default=None),
    owner:       str | None = QueryParam(default=None),
    overdue_only: int        = QueryParam(default=0),
    limit:       int         = QueryParam(default=50, ge=1, le=200),
    offset:      int         = QueryParam(default=0, ge=0),
    db: DBSession = Depends(get_db),
    _session: Session = Depends(get_current_session),
):
    today = datetime.now(timezone.utc).date().isoformat()
    filters: list[str] = []
    params: dict = {}

    if q:
        filters.append("(rel_path ILIKE :q OR title ILIKE :q)")
        params["q"] = f"%{q}%"
    if status:
        if status == "active":
            filters.append("(status_override = '' OR status_override IS NULL)")
        else:
            filters.append("status_override = :status")
            params["status"] = status
    if owner:
        filters.append("owner ILIKE :owner")
        params["owner"] = f"%{owner}%"
    if overdue_only:
        filters.append("review_date != '' AND review_date < :today")
        params["today"] = today

    where = ("WHERE " + " AND ".join(filters)) if filters else ""

    try:
        rows = db.execute(text(f"""
            {_DOC_SELECT}
            {where}
            ORDER BY rel_path ASC
            LIMIT :limit OFFSET :offset
        """), {**params, "limit": limit, "offset": offset}).fetchall()
        total_row = db.execute(
            text(f"SELECT COUNT(*) FROM corpus_documents {where}"),
            params,
        ).fetchone()
        total = total_row[0] if total_row else 0
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error listing documents: {exc}")

    return {
        "total":  total,
        "offset": offset,
        "limit":  limit,
        "items":  [_corpus_doc_to_dict(r, today) for r in rows],
    }


@app.get("/documents/review-queue")
def get_review_queue(
    db: DBSession = Depends(get_db),
    _session: Session = Depends(get_current_session),
):
    today = datetime.now(timezone.utc).date().isoformat()
    try:
        all_rows = db.execute(
            text(f"{_DOC_SELECT} ORDER BY rel_path ASC")
        ).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error fetching review queue: {exc}")

    overdue_review: list[dict] = []
    missing_owner: list[dict] = []
    missing_review_date: list[dict] = []
    draft_or_superseded: list[dict] = []

    for row in all_rows:
        d = _corpus_doc_to_dict(row, today)
        if d["reviewOverdue"]:
            overdue_review.append(d)
        if not d["owner"]:
            missing_owner.append(d)
        if not d["reviewDate"]:
            missing_review_date.append(d)
        if d["status"] in ("draft", "superseded"):
            draft_or_superseded.append(d)

    return {
        "overdue_review":      overdue_review,
        "missing_owner":       missing_owner,
        "missing_review_date": missing_review_date,
        "draft_or_superseded": draft_or_superseded,
        "counts": {
            "overdue_review":      len(overdue_review),
            "missing_owner":       len(missing_owner),
            "missing_review_date": len(missing_review_date),
            "draft_or_superseded": len(draft_or_superseded),
        },
    }


@app.get("/documents/{document_id}")
def get_document_registry(
    document_id: str,
    db: DBSession = Depends(get_db),
    _session: Session = Depends(get_current_session),
):
    today = datetime.now(timezone.utc).date().isoformat()
    try:
        row = db.execute(
            text(f"{_DOC_SELECT} WHERE rel_path = :rel"),
            {"rel": document_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Document not found")

    d = _corpus_doc_to_dict(row, today)

    try:
        stats = db.execute(text("""
            SELECT
                COUNT(*)          AS chunk_count,
                COUNT(cc.page)    AS pages_indexed,
                COUNT(*) - COUNT(cc.page) AS pages_null,
                MAX(cc.page)      AS max_page
            FROM corpus_chunks cc
            JOIN corpus_documents cd ON cd.id = cc.doc_id
            WHERE cd.rel_path = :rel
        """), {"rel": document_id}).fetchone()
        d["chunk_count"]         = stats[0] if stats else 0
        d["pages_indexed_count"] = stats[1] if stats else 0
        d["pages_null_count"]    = stats[2] if stats else 0
        d["max_page"]            = stats[3] if stats else None
    except Exception:
        db.rollback()
        d["chunk_count"]         = None
        d["pages_indexed_count"] = None
        d["pages_null_count"]    = None
        d["max_page"]            = None

    return d


@app.patch("/documents/{document_id}/metadata")
def patch_document_metadata(
    document_id: str,
    patch: DocMetadataPatch,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if current_session.role not in ("custodian", "admin"):
        raise HTTPException(status_code=403, detail="custodian or admin role required")

    if patch.status_override is not None:
        if patch.status_override not in _ALLOWED_STATUS_OVERRIDES:
            raise HTTPException(
                status_code=422,
                detail=f"status_override must be one of {sorted(_ALLOWED_STATUS_OVERRIDES)}",
            )
    for field_name, field_val in [
        ("effective_date", patch.effective_date),
        ("review_date",    patch.review_date),
    ]:
        if field_val is not None and field_val != "" and not _DATE_RE.match(field_val):
            raise HTTPException(status_code=422, detail=f"{field_name} must be yyyy-mm-dd or empty")

    today = datetime.now(timezone.utc).date().isoformat()

    try:
        row = db.execute(
            text(f"{_DOC_SELECT} WHERE rel_path = :rel"),
            {"rel": document_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Document not found")

    before = _corpus_doc_to_dict(row, today)

    updates: dict = {}
    if patch.status_override is not None:
        updates["status_override"] = patch.status_override
    if patch.owner is not None:
        updates["owner"] = patch.owner
    if patch.effective_date is not None:
        updates["effective_date"] = patch.effective_date
    if patch.review_date is not None:
        updates["review_date"] = patch.review_date
    if patch.title_override is not None:
        updates["title"] = patch.title_override

    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)

    try:
        db.execute(
            text(f"UPDATE corpus_documents SET {set_clause} WHERE rel_path = :rel"),
            {**updates, "rel": document_id},
        )
        row_after = db.execute(
            text(f"{_DOC_SELECT} WHERE rel_path = :rel"),
            {"rel": document_id},
        ).fetchone()
        after = _corpus_doc_to_dict(row_after, today) if row_after else before

        db.execute(text("""
            INSERT INTO corpus_doc_events
                (ts_utc, actor_username, actor_role, document_id, action, before_json, after_json)
            VALUES
                (now(), :uname, :role, :doc_id, 'metadata_patch',
                 CAST(:before_j AS jsonb), CAST(:after_j AS jsonb))
        """), {
            "uname":    current_session.username,
            "role":     current_session.role,
            "doc_id":   document_id,
            "before_j": json.dumps(before, sort_keys=True),
            "after_j":  json.dumps(after,  sort_keys=True),
        })
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error during update: {exc}")

    return {"updated": True, "document": after}
