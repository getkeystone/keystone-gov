import os
import re
import subprocess
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
            LIMIT 5
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

    top_rel, top_title, top_chunk, top_text, _ = rows[0]

    guidance = {
        "type": "approved",
        "summary": top_text[:200],
        "excerpt": top_text[:800],
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
    sources = [
        {
            "documentId": rel_path,
            "title": title,
            "status": "active",
            "allowed": True,
            "page": chunk_idx,
            "section": f"chunk {chunk_idx}",
            "note": f"FTS rank {rank:.4f}",
        }
        for rel_path, title, chunk_idx, _text, rank in rows
    ]
    citations = [
        {
            "documentId": rel_path,
            "chunkIndex": chunk_idx,
            "snippet": chunk_text[:300],
        }
        for rel_path, _title, chunk_idx, chunk_text, _rank in rows
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

    guidance = {
        "type": "approved",
        "summary": (best_doc.excerpt or "")[:200],
        "excerpt": best_doc.excerpt or "",
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
