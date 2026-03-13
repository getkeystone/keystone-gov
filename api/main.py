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
from cryptography.hazmat.primitives import serialization as _crypto_ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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

# ---------------------------------------------------------------------------
# Governance config flags (read once at startup from environment)
# ---------------------------------------------------------------------------

_REQUIRE_DOC_CHANGE_APPROVAL = int(os.environ.get("REQUIRE_DOC_CHANGE_APPROVAL", "1"))
_REQUIRE_EVIDENCE_APPROVAL   = int(os.environ.get("REQUIRE_EVIDENCE_APPROVAL", "0"))
_TWO_PERSON_CONTROL          = int(os.environ.get("TWO_PERSON_CONTROL", "0"))
_EVIDENCE_APPROVAL_TTL_SECS  = int(os.environ.get("EVIDENCE_APPROVAL_TTL_SECONDS", "3600"))


# ---------------------------------------------------------------------------
# Evidence signing (Ed25519) — loaded once at startup
# ---------------------------------------------------------------------------

_SIGNING_KEY: "Ed25519PrivateKey | None" = None
_SIGNING_PUBKEY_PEM: "bytes | None" = None


def _load_signing_key() -> None:
    global _SIGNING_KEY, _SIGNING_PUBKEY_PEM
    key_path = os.environ.get("EVIDENCE_SIGNING_KEY_PATH", "").strip()
    if not key_path:
        print("[evidence] EVIDENCE_SIGNING_KEY_PATH not set — signing disabled",
              file=sys.stderr, flush=True)
        return
    p = Path(key_path)
    if not p.exists():
        print(f"[evidence] key not found at {key_path} — signing disabled",
              file=sys.stderr, flush=True)
        return
    try:
        raw = p.read_bytes()
        _SIGNING_KEY = _crypto_ser.load_pem_private_key(raw, password=None)  # type: ignore[assignment]
        _SIGNING_PUBKEY_PEM = _SIGNING_KEY.public_key().public_bytes(  # type: ignore[union-attr]
            encoding=_crypto_ser.Encoding.PEM,
            format=_crypto_ser.PublicFormat.SubjectPublicKeyInfo,
        )
        print(f"[evidence] signing key loaded from {key_path}", file=sys.stderr, flush=True)
    except Exception as exc:
        print(f"[evidence] failed to load signing key: {exc}", file=sys.stderr, flush=True)


def _require_signing_key() -> None:
    if _SIGNING_KEY is None:
        raise HTTPException(
            status_code=501,
            detail=(
                "Evidence signing not configured. "
                "Run scripts/gen-evidence-keys.sh and set EVIDENCE_SIGNING_KEY_PATH."
            ),
        )


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
    _load_signing_key()
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
    signed: bool = False,
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
        "signed": signed,
        "files": file_entries,
        "corpus_document": corpus_doc_meta,
    }


@app.get("/evidence/public-key")
def get_evidence_public_key():
    """Return the Ed25519 public key PEM used to sign evidence manifests.
    No authentication required — the public key is not sensitive.
    """
    _require_signing_key()
    return Response(
        content=_SIGNING_PUBKEY_PEM,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="evidence_ed25519_public.pem"'},
    )


def _build_evidence_files(
    guidance: dict,
    audit_dict: dict,
    verify_dict: dict,
    excerpt_text: str,
    cited_page_pdf: "bytes | None",
) -> "list[tuple[str, bytes]]":
    """Build sorted list of (filename, bytes) for all content files."""
    _guidance_bytes = json.dumps(guidance,    sort_keys=True, indent=2, separators=(',', ': ')).encode()
    _audit_bytes    = json.dumps(audit_dict,  sort_keys=True, indent=2, separators=(',', ': ')).encode()
    _verify_bytes   = json.dumps(verify_dict, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    _excerpt_bytes  = excerpt_text.encode() if isinstance(excerpt_text, str) else excerpt_text

    _files: list[tuple[str, bytes]] = [
        ("audit.json",               _audit_bytes),
        ("cited_source_excerpt.txt", _excerpt_bytes),
        ("guidance.json",            _guidance_bytes),
        ("verify.json",              _verify_bytes),
    ]
    if cited_page_pdf is not None:
        page_label = guidance.get("document", {}).get("page", "0")
        _files.append((f"cited_page_{page_label}.pdf", cited_page_pdf))

    # pubkey.pem is included so its hash is in the signed manifest
    if _SIGNING_PUBKEY_PEM is not None:
        _files.append(("pubkey.pem", _SIGNING_PUBKEY_PEM))

    _files.sort(key=lambda x: x[0])
    return _files


@app.get("/evidence/{query_id}/manifest")
def get_evidence_manifest(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Return the evidence manifest JSON for a query (any authenticated role)."""
    _require_signing_key()
    guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta = \
        _build_evidence_data(query_id, db)

    _files = _build_evidence_files(guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf)

    file_entries = [
        {"name": name, "sha256": _sha256_hex(data), "bytes": len(data)}
        for name, data in _files
    ]

    # Use audit timestamp as generated_utc so the manifest is deterministic
    # across multiple downloads (not tied to wall-clock time of the request).
    generated_utc = audit_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(
        query_id=query_id,
        generated_utc=generated_utc,
        file_entries=file_entries,
        pdf_deterministic=not pdf_included,
        corpus_doc_meta=corpus_doc_meta,
        signed=True,
    )
    # Sign the canonical manifest bytes
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    sig_bytes = _SIGNING_KEY.sign(manifest_bytes)  # type: ignore[union-attr]
    manifest["manifest_sig_hex"] = sig_bytes.hex()
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
    _require_signing_key()
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin token required")

    # ── Evidence approval gate ─────────────────────────────────────────────────
    _approval_row = None
    if _REQUIRE_EVIDENCE_APPROVAL:
        from datetime import timedelta
        now_utc = datetime.now(timezone.utc)
        try:
            _approval_row = db.execute(text("""
                SELECT id, requested_by, decided_by, decided_at, approved_ttl_seconds,
                       reason, decision_reason
                FROM evidence_export_requests
                WHERE query_id = :qid AND status = 'approved'
                ORDER BY decided_at DESC LIMIT 1
            """), {"qid": query_id}).fetchone()
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"DB error checking approval: {exc}")
        if not _approval_row:
            raise HTTPException(status_code=403, detail="APPROVAL_REQUIRED: No approved export request found for this query")
        _decided_at    = _approval_row[3]
        _ttl_secs      = _approval_row[4]
        _expires_at    = _decided_at + timedelta(seconds=_ttl_secs)
        if now_utc > _expires_at:
            raise HTTPException(status_code=403, detail=f"APPROVAL_EXPIRED: Approval expired at {_expires_at.isoformat()}")
        if _TWO_PERSON_CONTROL and _approval_row[1] == _approval_row[2]:
            raise HTTPException(status_code=403, detail="TWO_PERSON_REQUIRED: Requester and approver must be different users")

    guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta = \
        _build_evidence_data(query_id, db)

    _files = _build_evidence_files(guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf)

    # Include approval.json if approval workflow is active and approval exists
    if _REQUIRE_EVIDENCE_APPROVAL and _approval_row is not None:
        from datetime import timedelta as _td
        _dec_at = _approval_row[3]
        _ttl    = _approval_row[4]
        _approval_data = {
            "request_id":      str(_approval_row[0]),
            "query_id":        query_id,
            "requested_by":    _approval_row[1],
            "approved_by":     _approval_row[2],
            "approved_at":     _dec_at.isoformat() if _dec_at else None,
            "ttl_seconds":     _ttl,
            "expires_at":      (_dec_at + _td(seconds=_ttl)).isoformat() if _dec_at else None,
            "reason":          _approval_row[5],
            "decision_reason": _approval_row[6],
        }
        _approval_bytes = json.dumps(_approval_data, sort_keys=True, indent=2, separators=(',', ': ')).encode()
        _files.append(("approval.json", _approval_bytes))
        _files.sort(key=lambda x: x[0])

    # Build manifest using sha256 of each file's bytes.
    file_entries = [
        {"name": name, "sha256": _sha256_hex(data), "bytes": len(data)}
        for name, data in _files
    ]
    # Use audit timestamp as generated_utc so the manifest is deterministic
    # across multiple downloads (not tied to wall-clock time of the request).
    generated_utc = audit_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(
        query_id=query_id,
        generated_utc=generated_utc,
        file_entries=file_entries,
        pdf_deterministic=not pdf_included,
        corpus_doc_meta=corpus_doc_meta,
        signed=True,
    )
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    sig_bytes = _SIGNING_KEY.sign(manifest_bytes)  # type: ignore[union-attr]

    # Assemble ZIP in memory — sorted content files, manifest.json, manifest.sig last.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _files:
            _zip_writestr_det(zf, name, data)
        _zip_writestr_det(zf, "manifest.json", manifest_bytes)
        _zip_writestr_det(zf, "manifest.sig", sig_bytes)

    filename = f"evidence-{query_id[:8]}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Request body models (KDAT-005)
# ---------------------------------------------------------------------------

class ChangeRequestBody(BaseModel):
    patch: dict
    reason: str = ""

class DecisionBody(BaseModel):
    decision_reason: str = ""

class ExportRequestBody(BaseModel):
    reason: str = ""

class OperatorDecisionBody(BaseModel):
    decision: str  # followed | partial | overridden | no_action
    decision_reason: str = ""
    actions_taken: list = []
    notes: str = ""
    attachments: list = []

class ReviewBody(BaseModel):
    supervisor_reviewed: bool = True

class CreateCaseBody(BaseModel):
    title: str
    summary: str = ""
    severity: str = "low"
    assigned_to: "str | None" = None
    query_ids: list = []

class PatchCaseBody(BaseModel):
    title: "str | None" = None
    summary: "str | None" = None
    severity: "str | None" = None
    status: "str | None" = None
    assigned_to: "str | None" = None

class AddQueryBody(BaseModel):
    query_id: str


# ---------------------------------------------------------------------------
# Evidence export approval (KDAT-005)
# ---------------------------------------------------------------------------


def _export_req_to_dict(row: tuple) -> dict:
    (req_id, query_id, requested_by, requested_by_role, requested_at,
     reason, status, decided_by, decided_by_role, decided_at,
     decision_reason, approved_ttl_seconds) = row
    expires_at = None
    if status == "approved" and decided_at and approved_ttl_seconds:
        from datetime import timedelta
        expires_at = (decided_at + timedelta(seconds=approved_ttl_seconds)).isoformat()
    return {
        "request_id":         str(req_id),
        "query_id":           query_id,
        "requested_by":       requested_by,
        "requested_by_role":  requested_by_role,
        "requested_at":       requested_at.isoformat() if requested_at else None,
        "reason":             reason,
        "status":             status,
        "decided_by":         decided_by,
        "decided_by_role":    decided_by_role,
        "decided_at":         decided_at.isoformat() if decided_at else None,
        "decision_reason":    decision_reason,
        "approved_ttl_seconds": approved_ttl_seconds,
        "expires_at":         expires_at,
    }


@app.post("/evidence/{query_id}/export-requests")
def create_export_request(
    query_id: str,
    body: ExportRequestBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    # Verify query exists
    q = db.query(Query).filter(Query.id == query_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")
    try:
        result = db.execute(text("""
            INSERT INTO evidence_export_requests
                (query_id, requested_by, requested_by_role, reason, approved_ttl_seconds)
            VALUES (:qid, :uname, :role, :reason, :ttl)
            RETURNING id
        """), {
            "qid":    query_id,
            "uname":  current_session.username,
            "role":   current_session.role,
            "reason": body.reason,
            "ttl":    _EVIDENCE_APPROVAL_TTL_SECS,
        }).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"created": True, "request_id": str(result[0]), "status": "pending"}


@app.get("/evidence/{query_id}/export-requests")
def get_export_requests_for_query(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    try:
        rows = db.execute(text("""
            SELECT id, query_id, requested_by, requested_by_role, requested_at,
                   reason, status, decided_by, decided_by_role, decided_at,
                   decision_reason, approved_ttl_seconds
            FROM evidence_export_requests
            WHERE query_id = :qid
            ORDER BY requested_at DESC
        """), {"qid": query_id}).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"query_id": query_id, "requests": [_export_req_to_dict(r) for r in rows]}


@app.post("/evidence/export-requests/{req_id}/approve")
def approve_export_request(
    req_id: str,
    body: DecisionBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    try:
        row = db.execute(
            text("SELECT id, status, requested_by FROM evidence_export_requests WHERE id=:id"),
            {"id": req_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Export request not found")
    if row[1] != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {row[1]}")
    if _TWO_PERSON_CONTROL and row[2] == current_session.username:
        raise HTTPException(
            status_code=403,
            detail="TWO_PERSON_REQUIRED: The approver must differ from the requester",
        )
    try:
        db.execute(text("""
            UPDATE evidence_export_requests
            SET status='approved', decided_by=:uname, decided_by_role=:role,
                decided_at=now(), decision_reason=:reason
            WHERE id=:id
        """), {"id": req_id, "uname": current_session.username,
               "role": current_session.role, "reason": body.decision_reason})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"approved": True, "request_id": req_id}


@app.post("/evidence/export-requests/{req_id}/reject")
def reject_export_request(
    req_id: str,
    body: DecisionBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    try:
        row = db.execute(
            text("SELECT id, status FROM evidence_export_requests WHERE id=:id"),
            {"id": req_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Export request not found")
    if row[1] != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {row[1]}")
    try:
        db.execute(text("""
            UPDATE evidence_export_requests
            SET status='rejected', decided_by=:uname, decided_by_role=:role,
                decided_at=now(), decision_reason=:reason
            WHERE id=:id
        """), {"id": req_id, "uname": current_session.username,
               "role": current_session.role, "reason": body.decision_reason})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"rejected": True, "request_id": req_id}


# ---------------------------------------------------------------------------
# Operator decisions + incident pack (KDAT-006)
# ---------------------------------------------------------------------------

_DECISION_VALUES = {"followed", "partial", "overridden", "no_action"}


def _decision_to_dict(row: tuple) -> dict:
    (dec_id, query_id, created_at_utc, created_by_username, created_by_role,
     decision, decision_reason, actions_taken, notes, attachments,
     supervisor_reviewed, supervisor_username, supervisor_reviewed_at_utc) = row
    return {
        "id":                         str(dec_id),
        "query_id":                   query_id,
        "created_at_utc":             created_at_utc.isoformat() if created_at_utc else None,
        "created_by_username":        created_by_username,
        "created_by_role":            created_by_role,
        "decision":                   decision,
        "decision_reason":            decision_reason,
        "actions_taken":              actions_taken or [],
        "notes":                      notes,
        "attachments":                attachments or [],
        "supervisor_reviewed":        supervisor_reviewed,
        "supervisor_username":        supervisor_username,
        "supervisor_reviewed_at_utc": supervisor_reviewed_at_utc.isoformat() if supervisor_reviewed_at_utc else None,
    }


@app.post("/decisions/{query_id}")
def create_operator_decision(
    query_id: str,
    body: OperatorDecisionBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Record an operator decision for a query (member/officer/admin)."""
    if body.decision not in _DECISION_VALUES:
        raise HTTPException(
            status_code=422,
            detail=f"decision must be one of: {', '.join(sorted(_DECISION_VALUES))}",
        )
    if body.decision != "followed" and not body.decision_reason.strip():
        raise HTTPException(
            status_code=422,
            detail="decision_reason is required when decision is not 'followed'",
        )
    # Verify query exists
    q = db.query(Query).filter(Query.id == query_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")
    # One decision per query
    try:
        existing = db.execute(
            text("SELECT id FROM operator_decisions WHERE query_id = :qid"),
            {"qid": query_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if existing:
        raise HTTPException(status_code=409, detail="A decision already exists for this query")
    try:
        result = db.execute(text("""
            INSERT INTO operator_decisions
                (query_id, created_by_username, created_by_role,
                 decision, decision_reason, actions_taken, notes, attachments)
            VALUES (:qid, :uname, :role, :decision, :reason,
                    CAST(:actions AS jsonb), :notes, CAST(:attachments AS jsonb))
            RETURNING id
        """), {
            "qid":        query_id,
            "uname":      current_session.username,
            "role":       current_session.role,
            "decision":   body.decision,
            "reason":     body.decision_reason,
            "actions":    json.dumps(body.actions_taken),
            "notes":      body.notes,
            "attachments":json.dumps(body.attachments),
        }).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"created": True, "decision_id": str(result[0]), "query_id": query_id}


@app.get("/decisions/{query_id}")
def get_operator_decision(
    query_id: str,
    db: DBSession = Depends(get_db),
    _session: Session = Depends(get_current_session),
):
    """Return the operator decision for a query (any authenticated role)."""
    try:
        row = db.execute(text("""
            SELECT id, query_id, created_at_utc, created_by_username, created_by_role,
                   decision, decision_reason, actions_taken, notes, attachments,
                   supervisor_reviewed, supervisor_username, supervisor_reviewed_at_utc
            FROM operator_decisions WHERE query_id = :qid
        """), {"qid": query_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="No decision recorded for this query")
    return _decision_to_dict(row)


@app.patch("/decisions/{query_id}/review")
def review_operator_decision(
    query_id: str,
    body: ReviewBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Supervisor review sign-off (officer/admin)."""
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")
    try:
        row = db.execute(
            text("SELECT id FROM operator_decisions WHERE query_id = :qid"),
            {"qid": query_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="No decision recorded for this query")
    try:
        db.execute(text("""
            UPDATE operator_decisions
            SET supervisor_reviewed = :reviewed,
                supervisor_username = :uname,
                supervisor_reviewed_at_utc = CASE WHEN :reviewed THEN now() ELSE NULL END
            WHERE query_id = :qid
        """), {
            "reviewed": body.supervisor_reviewed,
            "uname":    current_session.username if body.supervisor_reviewed else None,
            "qid":      query_id,
        })
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"reviewed": True, "query_id": query_id, "supervisor": current_session.username}


def _build_incident_files(
    guidance: dict,
    audit_dict: dict,
    verify_dict: dict,
    excerpt_text: str,
    cited_page_pdf: "bytes | None",
    decision_dict: dict,
    approval_row: "tuple | None" = None,
) -> "list[tuple[str, bytes]]":
    """Build sorted (name, bytes) list for incident pack content files."""
    _files = _build_evidence_files(guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf)

    # operator_decision.json
    _dec_bytes = json.dumps(decision_dict, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    _files.append(("operator_decision.json", _dec_bytes))

    # approval.json if present
    if approval_row is not None:
        from datetime import timedelta as _td
        _dec_at = approval_row[3]
        _ttl    = approval_row[4]
        _appr_data = {
            "request_id":      str(approval_row[0]),
            "query_id":        audit_dict.get("queryId", ""),
            "requested_by":    approval_row[1],
            "approved_by":     approval_row[2],
            "approved_at":     _dec_at.isoformat() if _dec_at else None,
            "ttl_seconds":     _ttl,
            "expires_at":      (_dec_at + _td(seconds=_ttl)).isoformat() if _dec_at else None,
            "reason":          approval_row[5],
            "decision_reason": approval_row[6],
        }
        _appr_bytes = json.dumps(_appr_data, sort_keys=True, indent=2, separators=(',', ': ')).encode()
        _files.append(("approval.json", _appr_bytes))

    _files.sort(key=lambda x: x[0])
    return _files


@app.get("/incident/{query_id}/manifest")
def get_incident_manifest(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Return the incident pack manifest JSON (officer/admin)."""
    _require_signing_key()
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")

    # Require decision
    try:
        dec_row = db.execute(text("""
            SELECT id, query_id, created_at_utc, created_by_username, created_by_role,
                   decision, decision_reason, actions_taken, notes, attachments,
                   supervisor_reviewed, supervisor_username, supervisor_reviewed_at_utc
            FROM operator_decisions WHERE query_id = :qid
        """), {"qid": query_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not dec_row:
        raise HTTPException(status_code=409, detail="No operator decision recorded for this query — record a decision before exporting an incident pack")

    guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta = \
        _build_evidence_data(query_id, db)
    decision_dict = _decision_to_dict(dec_row)

    _files = _build_incident_files(
        guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, decision_dict
    )
    file_entries = [
        {"name": name, "sha256": _sha256_hex(data), "bytes": len(data)}
        for name, data in _files
    ]
    generated_utc = audit_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(
        query_id=query_id,
        generated_utc=generated_utc,
        file_entries=file_entries,
        pdf_deterministic=not pdf_included,
        corpus_doc_meta=corpus_doc_meta,
        signed=True,
    )
    manifest["schema"] = "incident-manifest/v1"
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    sig_bytes = _SIGNING_KEY.sign(manifest_bytes)  # type: ignore[union-attr]
    manifest["manifest_sig_hex"] = sig_bytes.hex()
    return manifest


def _build_incident_pack_zip(query_id: str, db: DBSession) -> bytes:
    """
    Core builder: deterministic signed incident pack ZIP bytes.
    Raises HTTPException(409) if no decision.
    Raises HTTPException(403) if REQUIRE_EVIDENCE_APPROVAL=1 and approval missing/expired.
    Called by both the HTTP handler and the case pack builder.
    """
    try:
        dec_row = db.execute(text("""
            SELECT id, query_id, created_at_utc, created_by_username, created_by_role,
                   decision, decision_reason, actions_taken, notes, attachments,
                   supervisor_reviewed, supervisor_username, supervisor_reviewed_at_utc
            FROM operator_decisions WHERE query_id = :qid
        """), {"qid": query_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not dec_row:
        raise HTTPException(
            status_code=409,
            detail=f"No operator decision recorded for query {query_id[:8]}… — record a decision first",
        )

    _approval_row = None
    if _REQUIRE_EVIDENCE_APPROVAL:
        from datetime import timedelta
        now_utc = datetime.now(timezone.utc)
        try:
            _approval_row = db.execute(text("""
                SELECT id, requested_by, decided_by, decided_at, approved_ttl_seconds,
                       reason, decision_reason
                FROM evidence_export_requests
                WHERE query_id = :qid AND status = 'approved'
                ORDER BY decided_at DESC LIMIT 1
            """), {"qid": query_id}).fetchone()
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"DB error checking approval: {exc}")
        if not _approval_row:
            raise HTTPException(
                status_code=403,
                detail=f"APPROVAL_REQUIRED: No approved export request for query {query_id[:8]}…",
            )
        _decided_at = _approval_row[3]
        _ttl_secs   = _approval_row[4]
        _expires_at = _decided_at + timedelta(seconds=_ttl_secs)
        if now_utc > _expires_at:
            raise HTTPException(
                status_code=403,
                detail=f"APPROVAL_EXPIRED: Approval for query {query_id[:8]}… expired at {_expires_at.isoformat()}",
            )

    guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf, pdf_included, corpus_doc_meta = \
        _build_evidence_data(query_id, db)
    decision_dict = _decision_to_dict(dec_row)
    _files = _build_incident_files(
        guidance, audit_dict, verify_dict, excerpt_text, cited_page_pdf,
        decision_dict, _approval_row,
    )

    file_entries = [
        {"name": name, "sha256": _sha256_hex(data), "bytes": len(data)}
        for name, data in _files
    ]
    generated_utc = audit_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    manifest = _build_manifest(
        query_id=query_id,
        generated_utc=generated_utc,
        file_entries=file_entries,
        pdf_deterministic=not pdf_included,
        corpus_doc_meta=corpus_doc_meta,
        signed=True,
    )
    manifest["schema"] = "incident-manifest/v1"
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    sig_bytes = _SIGNING_KEY.sign(manifest_bytes)  # type: ignore[union-attr]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _files:
            _zip_writestr_det(zf, name, data)
        _zip_writestr_det(zf, "manifest.json", manifest_bytes)
        _zip_writestr_det(zf, "manifest.sig", sig_bytes)
    return buf.getvalue()


@app.get("/incident/{query_id}/pack.zip")
def get_incident_pack(
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Build and return a signed incident pack ZIP (officer/admin)."""
    _require_signing_key()
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")
    zip_bytes = _build_incident_pack_zip(query_id, db)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="incident-{query_id[:8]}.zip"'},
    )


# ---------------------------------------------------------------------------
# Supervisor review queue + incident cases (KDAT-007)
# ---------------------------------------------------------------------------

_CASE_SEVERITIES = {"low", "med", "high", "critical"}
_CASE_STATUSES   = {"open", "closed"}


def _case_to_dict(row: tuple, query_count: int = 0) -> dict:
    (case_id, created_at_utc, created_by, status, severity, title,
     summary, assigned_to, closed_at_utc) = row[:9]
    return {
        "case_id":        str(case_id),
        "created_at_utc": created_at_utc.isoformat() if created_at_utc else None,
        "created_by":     created_by,
        "status":         status,
        "severity":       severity,
        "title":          title,
        "summary":        summary,
        "assigned_to":    assigned_to,
        "closed_at_utc":  closed_at_utc.isoformat() if closed_at_utc else None,
        "query_count":    query_count,
    }


# ── Review queue ──────────────────────────────────────────────────────────────

@app.get("/review-queue")
def get_supervisor_review_queue(
    limit: int = QueryParam(default=25, ge=1, le=200),
    offset: int = QueryParam(default=0, ge=0),
    decision: "str | None" = QueryParam(default=None),
    unreviewed_only: int = QueryParam(default=0),
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """
    List queries that have an operator decision, optionally filtered to
    those not yet reviewed by a supervisor (officer/admin only).
    """
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")

    where_clauses = []
    params: dict = {"limit": limit, "offset": offset}
    if unreviewed_only:
        where_clauses.append("od.supervisor_reviewed = FALSE")
    if decision:
        where_clauses.append("od.decision = :decision")
        params["decision"] = decision

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        rows = db.execute(text(f"""
            SELECT q.id, q.question, q.scenario_key, q.mode,
                   od.decision, od.decision_reason,
                   od.created_by_username, od.created_by_role, od.created_at_utc,
                   od.supervisor_reviewed, od.supervisor_username, od.supervisor_reviewed_at_utc,
                   al.role_used, al.policy_outcome, al.timestamp AS audit_ts
            FROM queries q
            JOIN operator_decisions od ON od.query_id = q.id
            LEFT JOIN audit_log al ON al.query_id = q.id
            {where_sql}
            ORDER BY od.created_at_utc DESC
            LIMIT :limit OFFSET :offset
        """), params).fetchall()

        count_row = db.execute(text(f"""
            SELECT COUNT(*)
            FROM queries q
            JOIN operator_decisions od ON od.query_id = q.id
            {where_sql}
        """), {k: v for k, v in params.items() if k not in ("limit", "offset")}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    total = count_row[0] if count_row else 0

    items = []
    for r in rows:
        items.append({
            "query_id":                   r[0],
            "question":                   r[1],
            "scenario_key":               r[2],
            "mode":                       r[3],
            "decision":                   r[4],
            "decision_reason":            r[5],
            "decision_by":                r[6],
            "decision_by_role":           r[7],
            "decision_at":                r[8].isoformat() if r[8] else None,
            "supervisor_reviewed":        r[9],
            "supervisor_username":        r[10],
            "supervisor_reviewed_at_utc": r[11].isoformat() if r[11] else None,
            "role_used":                  r[12],
            "policy_outcome":             r[13],
            "audit_timestamp":            r[14],
        })

    return {"total": total, "offset": offset, "limit": limit, "items": items}


# ── Cases CRUD ────────────────────────────────────────────────────────────────

@app.post("/cases")
def create_case(
    body: CreateCaseBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Create a new incident case (officer/admin)."""
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")
    if body.severity not in _CASE_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of: {', '.join(sorted(_CASE_SEVERITIES))}")

    try:
        result = db.execute(text("""
            INSERT INTO incident_cases (created_by, status, severity, title, summary, assigned_to)
            VALUES (:created_by, 'open', :severity, :title, :summary, :assigned_to)
            RETURNING case_id
        """), {
            "created_by":  current_session.username,
            "severity":    body.severity,
            "title":       body.title,
            "summary":     body.summary,
            "assigned_to": body.assigned_to,
        }).fetchone()
        case_id = str(result[0])

        for qid in body.query_ids:
            q = db.query(Query).filter(Query.id == qid).first()
            if q:
                db.execute(text("""
                    INSERT INTO incident_case_queries (case_id, query_id, added_by)
                    VALUES (:case_id, :qid, :uname)
                    ON CONFLICT DO NOTHING
                """), {"case_id": case_id, "qid": qid, "uname": current_session.username})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"created": True, "case_id": case_id}


@app.get("/cases")
def list_cases(
    status: "str | None" = QueryParam(default=None),
    severity: "str | None" = QueryParam(default=None),
    q: "str | None" = QueryParam(default=None),
    limit: int = QueryParam(default=25, ge=1, le=200),
    offset: int = QueryParam(default=0, ge=0),
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """List incident cases with optional filters (officer/admin)."""
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")

    where_clauses = []
    params: dict = {"limit": limit, "offset": offset}
    if status:
        where_clauses.append("ic.status = :status")
        params["status"] = status
    if severity:
        where_clauses.append("ic.severity = :severity")
        params["severity"] = severity
    if q:
        where_clauses.append("(ic.title ILIKE :q OR ic.summary ILIKE :q)")
        params["q"] = f"%{q}%"

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        rows = db.execute(text(f"""
            SELECT ic.case_id, ic.created_at_utc, ic.created_by, ic.status,
                   ic.severity, ic.title, ic.summary, ic.assigned_to, ic.closed_at_utc,
                   COUNT(icq.query_id) AS query_count
            FROM incident_cases ic
            LEFT JOIN incident_case_queries icq ON icq.case_id = ic.case_id
            {where_sql}
            GROUP BY ic.case_id
            ORDER BY ic.created_at_utc DESC
            LIMIT :limit OFFSET :offset
        """), params).fetchall()

        count_row = db.execute(text(f"""
            SELECT COUNT(*) FROM incident_cases ic {where_sql}
        """), {k: v for k, v in params.items() if k not in ("limit", "offset")}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    total = count_row[0] if count_row else 0
    items = [_case_to_dict(r, int(r[9])) for r in rows]
    return {"total": total, "offset": offset, "limit": limit, "items": items}


@app.get("/cases/{case_id}/timeline")
def get_case_timeline(
    case_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Return a merged, time-sorted timeline of events for a case (officer/admin)."""
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")

    try:
        query_rows = db.execute(text("""
            SELECT query_id FROM incident_case_queries WHERE case_id = :cid
        """), {"cid": case_id}).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    query_ids = [str(r[0]) for r in query_rows]
    if not query_ids:
        return {"case_id": case_id, "generated_at": datetime.now(timezone.utc).isoformat(), "events": []}

    # Build IN clause safely using numbered params
    in_params = {f"qid{i}": qid for i, qid in enumerate(query_ids)}
    in_clause = ", ".join(f":qid{i}" for i in range(len(query_ids)))

    events: list[dict] = []

    try:
        # Audit entries (query_created)
        audit_rows = db.execute(text(f"""
            SELECT query_id, timestamp, role_used, policy_outcome
            FROM audit_log WHERE query_id IN ({in_clause})
        """), in_params).fetchall()
        for r in audit_rows:
            events.append({
                "ts":         r[1],
                "event_type": "query_created",
                "actor":      r[2],
                "query_id":   r[0],
                "summary":    f"Query created (outcome: {r[3]})",
                "detail":     {"role_used": r[2], "policy_outcome": r[3]},
            })

        # Operator decisions
        dec_rows = db.execute(text(f"""
            SELECT query_id, created_at_utc, created_by_username, created_by_role,
                   decision, supervisor_reviewed, supervisor_username, supervisor_reviewed_at_utc
            FROM operator_decisions WHERE query_id IN ({in_clause})
        """), in_params).fetchall()
        for r in dec_rows:
            events.append({
                "ts":         r[1].isoformat() if r[1] else None,
                "event_type": "decision_recorded",
                "actor":      r[2],
                "query_id":   r[0],
                "summary":    f"Decision recorded: {r[4]}",
                "detail":     {"decision": r[4], "role": r[3]},
            })
            if r[5] and r[7]:
                events.append({
                    "ts":         r[7].isoformat() if r[7] else None,
                    "event_type": "supervisor_reviewed",
                    "actor":      r[6] or "",
                    "query_id":   r[0],
                    "summary":    f"Supervisor review by {r[6]}",
                    "detail":     {"supervisor": r[6]},
                })

        # Evidence export requests
        exp_rows = db.execute(text(f"""
            SELECT query_id, requested_by, requested_at, status, decided_by, decided_at
            FROM evidence_export_requests WHERE query_id IN ({in_clause})
        """), in_params).fetchall()
        for r in exp_rows:
            events.append({
                "ts":         r[2].isoformat() if r[2] else None,
                "event_type": "export_requested",
                "actor":      r[1],
                "query_id":   r[0],
                "summary":    f"Evidence export requested by {r[1]}",
                "detail":     {},
            })
            if r[3] in ("approved", "rejected") and r[5]:
                events.append({
                    "ts":         r[5].isoformat() if r[5] else None,
                    "event_type": f"export_{r[3]}",
                    "actor":      r[4] or "",
                    "query_id":   r[0],
                    "summary":    f"Export {r[3]} by {r[4]}",
                    "detail":     {"status": r[3]},
                })
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error building timeline: {exc}")

    # Sort by ts; nulls last
    events.sort(key=lambda e: (e["ts"] is None, e["ts"] or ""))

    return {
        "case_id":      case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events":       events,
    }


@app.get("/cases/{case_id}/pack.zip")
def get_case_pack(
    case_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """
    Build and return a deterministic signed case pack ZIP (officer/admin).

    Contents:
      case.json, timeline.json, pubkey.pem,
      incident/<query_id>/incident-<qid[:8]>.zip  (one per query, sorted),
      manifest.json (signed, schema=case-manifest/v1), manifest.sig
    """
    _require_signing_key()
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")

    try:
        case_row = db.execute(text("""
            SELECT case_id, created_at_utc, created_by, status, severity,
                   title, summary, assigned_to, closed_at_utc
            FROM incident_cases WHERE case_id = :cid
        """), {"cid": case_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not case_row:
        raise HTTPException(status_code=404, detail="Case not found")

    try:
        query_rows = db.execute(text("""
            SELECT query_id, added_at_utc, added_by
            FROM incident_case_queries
            WHERE case_id = :cid
            ORDER BY added_at_utc ASC
        """), {"cid": case_id}).fetchall()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    query_ids = [str(r[0]) for r in query_rows]

    # Fixed generation timestamp — derived from case creation time, never from now().
    # Every field that embeds this (timeline, manifest) uses the same value so
    # repeated downloads produce byte-identical ZIPs.
    case_created = case_row[1]
    generated_utc = case_created.isoformat() if case_created else datetime.now(timezone.utc).isoformat()

    # Build timeline for embedding.
    # Override generated_at with the fixed case creation timestamp for determinism.
    timeline_resp = get_case_timeline(case_id, db, current_session)
    timeline_resp["generated_at"] = generated_utc
    timeline_bytes = json.dumps(timeline_resp, sort_keys=True, indent=2, separators=(',', ': ')).encode()

    # Build case.json
    case_dict = _case_to_dict(case_row, len(query_ids))
    case_dict["queries"] = [
        {"query_id": str(r[0]), "added_at_utc": r[1].isoformat() if r[1] else None, "added_by": r[2]}
        for r in query_rows
    ]
    case_bytes = json.dumps(case_dict, sort_keys=True, indent=2, separators=(',', ': ')).encode()

    # Build one incident pack per query (sorted by query_id for determinism)
    incident_zips: list[tuple[str, bytes]] = []
    errors_for_queries: list[str] = []
    for qid in sorted(query_ids):
        try:
            zb = _build_incident_pack_zip(qid, db)
            incident_zips.append((f"incident/{qid}/incident-{qid[:8]}.zip", zb))
        except HTTPException as he:
            errors_for_queries.append(f"{qid[:8]}: {he.detail}")

    if errors_for_queries:
        raise HTTPException(
            status_code=409,
            detail="Cannot build case pack — some queries are missing decisions or approvals: "
                   + "; ".join(errors_for_queries),
        )

    # Case metadata files — covered by the manifest signature.
    # Incident packs are NOT hashed here: each carries its own Ed25519 signature
    # and is verified independently by the offline case pack verifier (KDAT-008).
    _signed_files: list[tuple[str, bytes]] = [
        ("case.json",     case_bytes),
        ("timeline.json", timeline_bytes),
    ]
    if _SIGNING_PUBKEY_PEM is not None:
        _signed_files.append(("pubkey.pem", _SIGNING_PUBKEY_PEM))
    _signed_files.sort(key=lambda x: x[0])

    file_entries = [
        {"name": name, "sha256": _sha256_hex(data), "bytes": len(data)}
        for name, data in _signed_files
    ]

    # All files written to the ZIP (metadata + incident packs, sorted alphabetically)
    _content_files = sorted(_signed_files + list(incident_zips), key=lambda x: x[0])
    manifest = {
        "schema":       "case-manifest/v1",
        "case_id":      case_id,
        "generated_utc": generated_utc,
        "git":          {"repo": "keystone-gov", "commit": _VERSION, "dirty": False},
        "signed":       True,
        "files":        file_entries,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, indent=2, separators=(',', ': ')).encode()
    sig_bytes = _SIGNING_KEY.sign(manifest_bytes)  # type: ignore[union-attr]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in _content_files:
            _zip_writestr_det(zf, name, data)
        _zip_writestr_det(zf, "manifest.json", manifest_bytes)
        _zip_writestr_det(zf, "manifest.sig", sig_bytes)

    filename = f"case-{case_id[:8]}.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/cases/{case_id}")
def get_case(
    case_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Return case detail including linked query list (officer/admin)."""
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")

    try:
        row = db.execute(text("""
            SELECT case_id, created_at_utc, created_by, status, severity,
                   title, summary, assigned_to, closed_at_utc
            FROM incident_cases WHERE case_id = :cid
        """), {"cid": case_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")

        query_rows = db.execute(text("""
            SELECT query_id, added_at_utc, added_by
            FROM incident_case_queries
            WHERE case_id = :cid
            ORDER BY added_at_utc ASC
        """), {"cid": case_id}).fetchall()
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    result = _case_to_dict(row, len(query_rows))
    result["queries"] = [
        {"query_id": str(r[0]), "added_at_utc": r[1].isoformat() if r[1] else None, "added_by": r[2]}
        for r in query_rows
    ]
    return result


@app.patch("/cases/{case_id}")
def patch_case(
    case_id: str,
    body: PatchCaseBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Update case fields (officer/admin). Setting status=closed sets closed_at_utc."""
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")
    if body.severity is not None and body.severity not in _CASE_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of: {', '.join(sorted(_CASE_SEVERITIES))}")
    if body.status is not None and body.status not in _CASE_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of: {', '.join(sorted(_CASE_STATUSES))}")

    try:
        row = db.execute(
            text("SELECT case_id FROM incident_cases WHERE case_id = :cid"),
            {"cid": case_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")

    updates: dict = {}
    if body.title     is not None: updates["title"]       = body.title
    if body.summary   is not None: updates["summary"]     = body.summary
    if body.severity  is not None: updates["severity"]    = body.severity
    if body.assigned_to is not None: updates["assigned_to"] = body.assigned_to
    if body.status    is not None:
        updates["status"] = body.status
        if body.status == "closed":
            updates["closed_at_utc"] = "now()"

    if not updates:
        raise HTTPException(status_code=422, detail="No updatable fields provided")

    set_parts = []
    params: dict = {"cid": case_id}
    for k, v in updates.items():
        if v == "now()":
            set_parts.append(f"{k} = now()")
        else:
            set_parts.append(f"{k} = :{k}")
            params[k] = v
    set_sql = ", ".join(set_parts)

    try:
        db.execute(text(f"UPDATE incident_cases SET {set_sql} WHERE case_id = :cid"), params)
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"updated": True, "case_id": case_id}


@app.post("/cases/{case_id}/queries")
def add_query_to_case(
    case_id: str,
    body: AddQueryBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Add a query to a case (officer/admin)."""
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["officer"]:
        raise HTTPException(status_code=403, detail="Officer or admin role required")
    try:
        case_row = db.execute(
            text("SELECT case_id FROM incident_cases WHERE case_id = :cid"),
            {"cid": case_id},
        ).fetchone()
        if not case_row:
            raise HTTPException(status_code=404, detail="Case not found")
        q = db.query(Query).filter(Query.id == body.query_id).first()
        if not q:
            raise HTTPException(status_code=404, detail="Query not found")
        db.execute(text("""
            INSERT INTO incident_case_queries (case_id, query_id, added_by)
            VALUES (:cid, :qid, :uname)
            ON CONFLICT DO NOTHING
        """), {"cid": case_id, "qid": body.query_id, "uname": current_session.username})
        db.commit()
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"added": True, "case_id": case_id, "query_id": body.query_id}


@app.delete("/cases/{case_id}/queries/{query_id}")
def remove_query_from_case(
    case_id: str,
    query_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    """Remove a query from a case (admin only)."""
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    try:
        db.execute(text("""
            DELETE FROM incident_case_queries
            WHERE case_id = :cid AND query_id = :qid
        """), {"cid": case_id, "qid": query_id})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"removed": True, "case_id": case_id, "query_id": query_id}


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


def _change_req_to_dict(row: tuple) -> dict:
    (req_id, document_id, requested_by, requested_by_role, requested_at,
     patch_json, reason, status, decided_by, decided_by_role, decided_at,
     decision_reason, applied_at, before_json, after_json) = row
    return {
        "request_id":        str(req_id),
        "document_id":       document_id,
        "requested_by":      requested_by,
        "requested_by_role": requested_by_role,
        "requested_at":      requested_at.isoformat() if requested_at else None,
        "patch":             patch_json if isinstance(patch_json, dict) else json.loads(patch_json or "{}"),
        "reason":            reason,
        "status":            status,
        "decided_by":        decided_by,
        "decided_by_role":   decided_by_role,
        "decided_at":        decided_at.isoformat() if decided_at else None,
        "decision_reason":   decision_reason,
        "applied_at":        applied_at.isoformat() if applied_at else None,
        "before_json":       before_json if isinstance(before_json, dict) else json.loads(before_json or "{}"),
        "after_json":        after_json if isinstance(after_json, dict) else (json.loads(after_json) if after_json else None),
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


@app.get("/documents/change-requests")
def list_change_requests(
    status:   str | None  = QueryParam(default=None),
    document_id: str | None = QueryParam(default=None),
    limit:    int          = QueryParam(default=50, ge=1, le=200),
    offset:   int          = QueryParam(default=0, ge=0),
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    filters: list[str] = []
    params: dict = {"limit": limit, "offset": offset}
    if status:
        filters.append("status = :status")
        params["status"] = status
    if document_id:
        filters.append("document_id = :document_id")
        params["document_id"] = document_id
    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    try:
        rows = db.execute(text(f"""
            SELECT id, document_id, requested_by, requested_by_role, requested_at,
                   patch, reason, status, decided_by, decided_by_role, decided_at,
                   decision_reason, applied_at, before_json, after_json
            FROM corpus_doc_change_requests
            {where}
            ORDER BY requested_at DESC
            LIMIT :limit OFFSET :offset
        """), params).fetchall()
        total = db.execute(
            text(f"SELECT COUNT(*) FROM corpus_doc_change_requests {where}"),
            {k: v for k, v in params.items() if k not in ("limit", "offset")},
        ).fetchone()[0]
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"total": total, "offset": offset, "limit": limit, "items": [_change_req_to_dict(r) for r in rows]}


@app.get("/documents/change-requests/{req_id}")
def get_change_request(
    req_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    try:
        row = db.execute(text("""
            SELECT id, document_id, requested_by, requested_by_role, requested_at,
                   patch, reason, status, decided_by, decided_by_role, decided_at,
                   decision_reason, applied_at, before_json, after_json
            FROM corpus_doc_change_requests WHERE id = :id
        """), {"id": req_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Change request not found")
    return _change_req_to_dict(row)


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
    # If approval workflow is enabled, custodians must use change requests
    if _REQUIRE_DOC_CHANGE_APPROVAL and current_session.role == "custodian":
        raise HTTPException(
            status_code=403,
            detail="APPROVAL_REQUIRED: Use POST /documents/{id}/change-requests instead",
        )

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


@app.post("/documents/{document_id}/change-requests")
def create_change_request(
    document_id: str,
    body: ChangeRequestBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if current_session.role not in ("custodian", "admin"):
        raise HTTPException(status_code=403, detail="custodian or admin role required")

    # Validate patch fields
    allowed_keys = {"owner", "status_override", "effective_date", "review_date", "title_override"}
    bad = set(body.patch.keys()) - allowed_keys
    if bad:
        raise HTTPException(status_code=422, detail=f"Unknown patch fields: {bad}")
    if not body.patch:
        raise HTTPException(status_code=422, detail="patch must have at least one field")

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

    try:
        result = db.execute(text("""
            INSERT INTO corpus_doc_change_requests
                (document_id, requested_by, requested_by_role, patch, reason, before_json)
            VALUES (:doc_id, :uname, :role, CAST(:patch AS jsonb), :reason, CAST(:before_j AS jsonb))
            RETURNING id
        """), {
            "doc_id":   document_id,
            "uname":    current_session.username,
            "role":     current_session.role,
            "patch":    json.dumps(body.patch, sort_keys=True),
            "reason":   body.reason,
            "before_j": json.dumps(before, sort_keys=True),
        }).fetchone()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")

    return {"created": True, "request_id": str(result[0]), "status": "pending"}


@app.post("/documents/change-requests/{req_id}/approve")
def approve_change_request(
    req_id: str,
    body: DecisionBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    try:
        row = db.execute(
            text("SELECT id, status FROM corpus_doc_change_requests WHERE id = :id"),
            {"id": req_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Change request not found")
    if row[1] != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {row[1]}")
    try:
        db.execute(text("""
            UPDATE corpus_doc_change_requests
            SET status='approved', decided_by=:uname, decided_by_role=:role,
                decided_at=now(), decision_reason=:reason
            WHERE id=:id
        """), {"id": req_id, "uname": current_session.username,
               "role": current_session.role, "reason": body.decision_reason})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"approved": True, "request_id": req_id}


@app.post("/documents/change-requests/{req_id}/reject")
def reject_change_request(
    req_id: str,
    body: DecisionBody,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")
    try:
        row = db.execute(
            text("SELECT id, status FROM corpus_doc_change_requests WHERE id = :id"),
            {"id": req_id},
        ).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Change request not found")
    if row[1] != "pending":
        raise HTTPException(status_code=409, detail=f"Request is already {row[1]}")
    try:
        db.execute(text("""
            UPDATE corpus_doc_change_requests
            SET status='rejected', decided_by=:uname, decided_by_role=:role,
                decided_at=now(), decision_reason=:reason
            WHERE id=:id
        """), {"id": req_id, "uname": current_session.username,
               "role": current_session.role, "reason": body.decision_reason})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    return {"rejected": True, "request_id": req_id}


@app.post("/documents/change-requests/{req_id}/apply")
def apply_change_request(
    req_id: str,
    db: DBSession = Depends(get_db),
    current_session: Session = Depends(get_current_session),
):
    if _ROLE_LEVEL.get(current_session.role, 0) < _ROLE_LEVEL["admin"]:
        raise HTTPException(status_code=403, detail="Admin role required")

    try:
        row = db.execute(text("""
            SELECT id, document_id, patch, status, before_json
            FROM corpus_doc_change_requests WHERE id = :id
        """), {"id": req_id}).fetchone()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {exc}")
    if not row:
        raise HTTPException(status_code=404, detail="Change request not found")

    _req_id, document_id, patch_json, status, before_json = row
    if status != "approved":
        raise HTTPException(status_code=409, detail=f"Request must be approved before apply (status={status})")

    patch = patch_json if isinstance(patch_json, dict) else json.loads(patch_json)

    # Validate patch fields
    if patch.get("status_override") is not None:
        if patch["status_override"] not in _ALLOWED_STATUS_OVERRIDES:
            raise HTTPException(status_code=422, detail="Invalid status_override in patch")
    for field_name in ("effective_date", "review_date"):
        val = patch.get(field_name)
        if val is not None and val != "" and not _DATE_RE.match(val):
            raise HTTPException(status_code=422, detail=f"{field_name} must be yyyy-mm-dd or empty")

    today = datetime.now(timezone.utc).date().isoformat()
    doc_row = db.execute(
        text(f"{_DOC_SELECT} WHERE rel_path = :rel"),
        {"rel": document_id},
    ).fetchone()
    if not doc_row:
        raise HTTPException(status_code=404, detail="Document not found")

    # Map patch keys to column names
    _patch_col_map = {
        "owner": "owner",
        "status_override": "status_override",
        "effective_date": "effective_date",
        "review_date": "review_date",
        "title_override": "title",
    }
    updates: dict = {}
    for k, v in patch.items():
        col = _patch_col_map.get(k)
        if col:
            updates[col] = v

    if not updates:
        raise HTTPException(status_code=422, detail="Patch has no applicable fields")

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
        after = _corpus_doc_to_dict(row_after, today) if row_after else {}

        db.execute(text("""
            INSERT INTO corpus_doc_events
                (ts_utc, actor_username, actor_role, document_id, action, before_json, after_json)
            VALUES
                (now(), :uname, :role, :doc_id, 'change_request_applied',
                 CAST(:before_j AS jsonb), CAST(:after_j AS jsonb))
        """), {
            "uname":    current_session.username,
            "role":     current_session.role,
            "doc_id":   document_id,
            "before_j": json.dumps(before_json if isinstance(before_json, dict) else json.loads(before_json), sort_keys=True),
            "after_j":  json.dumps(after, sort_keys=True),
        })

        db.execute(text("""
            UPDATE corpus_doc_change_requests
            SET status='applied', applied_at=now(),
                after_json=CAST(:after_j AS jsonb)
            WHERE id=:id
        """), {"id": req_id, "after_j": json.dumps(after, sort_keys=True)})
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error during apply: {exc}")

    return {"applied": True, "request_id": req_id, "document": after}
