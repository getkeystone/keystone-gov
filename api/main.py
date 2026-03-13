import os
import re
import subprocess
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query as QueryParam
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
    r'|instruction|manual|guidanc|protocol)\b',
    re.IGNORECASE,
)


def _rerank_score(chunk_index: int, text: str, fts_rank: float) -> float:
    """
    Deterministic reranker score (higher = prefer this chunk).

    Penalties:
      - "table of contents" / "contents" keyword  → ×0.10
      - Digit density > 8 %                        → ×(0.1 … 1.0)
      - Section-number density > 12 %              → ×0.20
      - First chunk of document (chunk_index == 0) → ×0.50

    Boosts:
      - Each procedural signal word                → ×(1.0 + min(n×0.25, 2.0))
    """
    score = float(fts_rank)

    lower = text.lower()

    if _TOC_SIGNAL.search(lower):
        score *= 0.10

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

    return score


def _is_toc_like(chunk_index: int, text: str) -> bool:
    """Return True if chunk is almost certainly TOC or front-matter.

    Criteria (any one is sufficient):
      - Contains "table of contents" or bare "contents" heading (matches _TOC_SIGNAL)
      - Section-number density > 12 % of words  (e.g. "1.1  Foo  1.2  Bar …")
      - First chunk of document AND no procedural signals
        (title pages / cover sheets are index-0 with no step/operation text)
    """
    lower = text.lower()
    if _TOC_SIGNAL.search(lower):
        return True
    n_words = max(len(text.split()), 1)
    n_section_nums = len(_SECTION_NUM.findall(text))
    if n_section_nums / n_words > 0.12:
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
    question: str, db: DBSession
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

    rows = db.execute(
        text("""
            SELECT
                cd.rel_path,
                cd.title,
                cc.chunk_index,
                cc.text,
                ts_rank_cd(cc.tsv, query) AS rank
            FROM corpus_chunks cc
            JOIN corpus_documents cd ON cd.id = cc.doc_id
            CROSS JOIN websearch_to_tsquery('english', :q) query
            WHERE cc.tsv @@ query
            ORDER BY rank DESC
            LIMIT 50
        """),
        {"q": question},
    ).fetchall()

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

    top_rel, top_title, top_chunk, top_text, _ = reranked[0]

    # If the best candidate still looks like TOC, try a document-level fallback:
    # fetch the first procedural (non-TOC) chunks from the same matched docs.
    if _is_toc_like(top_chunk, top_text):
        matched_docs = list({r[0] for r in reranked[:5]})
        fallback_rows = db.execute(
            text("""
                SELECT cd.rel_path, cd.title, cc.chunk_index, cc.text
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

        for fb_rel, fb_title, fb_chunk, fb_text in fallback_reranked:
            if not _is_toc_like(fb_chunk, fb_text):
                top_rel, top_title, top_chunk, top_text = fb_rel, fb_title, fb_chunk, fb_text
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
    guidance = {
        "type": "approved",
        "summary": make_summary(_clean_top),
        "excerpt": _clean_top[:800],
        "document": {
            "documentId": top_rel,
            "title": top_title,
            "section": f"chunk {top_chunk}",
            "page": top_chunk,
            "status": "active",
            "effectiveDate": "",
            "reviewDate": "",
            "owner": "",
        },
    }
    # Return top 5 reranked candidates as sources/citations.
    top5 = reranked[:5]
    sources = [
        {
            "documentId": rel_path,
            "title": title,
            "status": "active",
            "allowed": True,
            "page": chunk_idx,
            "section": f"chunk {chunk_idx}",
            "note": f"FTS rank {rank:.4f}  rerank {_rerank_score(chunk_idx, _text, rank):.4f}",
        }
        for rel_path, title, chunk_idx, _text, rank in top5
    ]
    citations = [
        {
            "documentId": rel_path,
            "chunkIndex": chunk_idx,
            "snippet": chunk_text[:300],
        }
        for rel_path, _title, chunk_idx, chunk_text, _rank in top5
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
    fts_result = _corpus_fts_retrieve(question, db)
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
