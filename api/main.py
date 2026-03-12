import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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

# Minimum role level required to receive non-refused guidance per scenario.
_SCENARIO_MIN_LEVEL: dict[str, int] = {
    "restricted": 1,   # officer+ only
}
_ROLE_LEVEL: dict[str, int] = {
    "member": 0,
    "custodian": 0,
    "officer": 1,
    "admin": 2,
}

# Guidance returned to officer/admin when they access the "restricted" scenario.
_RESTRICTED_OFFICER_GUIDANCE = {
    "type": "approved",
    "summary": "Restricted post-incident disciplinary information. Access granted for current role.",
    "excerpt": (
        "Post-incident review dated 2025-11-03: disciplinary action was taken per department SOP §7.4. "
        "Details are restricted to supervisory and administrative personnel only."
    ),
    "note": "This content is restricted to officer and admin roles. Not visible to member role.",
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
_RESTRICTED_OFFICER_SOURCES = [
    {
        "documentId": "demo-fd-restricted-001",
        "title": "Demo FD Post-Incident Disciplinary Memo",
        "status": "active",
        "allowed": True,
        "page": 1,
        "section": "7.4",
        "note": "Accessible to officer/admin only.",
    }
]
_RESTRICTED_OFFICER_CITATIONS = [
    {"documentId": "demo-fd-restricted-001", "page": 1, "section": "7.4"}
]

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Keystone Gov API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    return {"status": "ok", "service": "keystone-gov-api"}


# ---------------------------------------------------------------------------
# Auth
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
# Query  (creates a new audit-logged record each time)
# ---------------------------------------------------------------------------


@app.post("/query", response_model=QueryResponse)
def submit_query(req: QueryRequest, db: DBSession = Depends(get_db)):
    if req.scenario_key not in _GUIDANCE_TEMPLATES:
        raise HTTPException(status_code=400, detail=f"Unknown scenario_key: {req.scenario_key}")

    user_level = _ROLE_LEVEL.get(req.role, 0)
    min_level = _SCENARIO_MIN_LEVEL.get(req.scenario_key, 0)
    acl_denied = user_level < min_level

    # Resolve guidance and audit sources based on ACL outcome.
    if acl_denied:
        guidance = _ACL_REFUSAL_GUIDANCE
        policy_outcome = "refused"
        sources: list = []       # no source leakage for denied requests
        citations: list = []
    elif req.scenario_key == "restricted":
        # officer/admin accessing restricted content — approved
        guidance = _RESTRICTED_OFFICER_GUIDANCE
        policy_outcome = "allowed"
        sources = _RESTRICTED_OFFICER_SOURCES
        citations = _RESTRICTED_OFFICER_CITATIONS
    else:
        template = _GUIDANCE_TEMPLATES[req.scenario_key]
        guidance = template["guidance"]
        policy_outcome = "allowed" if guidance["type"] == "approved" else "refused"
        sources = template["audit"]["sourcesConsidered"]
        citations = template["audit"]["citationsReturned"]

    query_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    db.add(Query(
        id=query_id,
        question=req.question,
        role=req.role,
        mode=req.mode,
        scenario_key=req.scenario_key,
        guidance_json=guidance,
        created_at=datetime.now(timezone.utc),
    ))

    # HMAC chain: prev_hash = hash of the most-recent audit entry
    last = db.query(AuditEntry).order_by(AuditEntry.timestamp.desc()).first()
    prev_hash = last.entry_hash if last else ""

    entry_hash = compute_entry_hash(
        query_id, now, req.role, req.mode, policy_outcome, prev_hash
    )

    db.add(AuditEntry(
        id=str(uuid.uuid4()),
        query_id=query_id,
        receipt_id=f"receipt-{query_id[:8]}",
        timestamp=now,
        role_used=req.role,
        mode_used=req.mode,
        policy_outcome=policy_outcome,
        sources_considered_json=sources,
        citations_returned_json=citations,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    ))
    db.commit()

    return QueryResponse(query_id=query_id, scenario_key=req.scenario_key)


# ---------------------------------------------------------------------------
# Guidance
# ---------------------------------------------------------------------------


@app.get("/guidance/{query_id}", response_model=GuidanceResponse)
def get_guidance(query_id: str, db: DBSession = Depends(get_db)):
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
# Source
# ---------------------------------------------------------------------------


@app.get("/source/{document_id}/{page}", response_model=SourceResponse)
def get_source(document_id: str, page: int, db: DBSession = Depends(get_db)):
    key = f"{document_id}:{page}"
    doc = db.query(Document).filter(Document.key == key).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Source not found")
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
# Audit
# ---------------------------------------------------------------------------


@app.get("/audit/{query_id}", response_model=AuditResponse)
def get_audit(query_id: str, db: DBSession = Depends(get_db)):
    entry = db.query(AuditEntry).filter(AuditEntry.query_id == query_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Audit entry not found")
    return AuditResponse(**_build_audit_dict(entry), queryId=query_id)


@app.get("/audit/{query_id}/verify", response_model=AuditVerifyResponse)
def verify_audit(query_id: str, db: DBSession = Depends(get_db)):
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
