"""Seed demo fixtures into the database on startup if empty.

Synthetic demo fixtures. No real agency names, personnel, or incident data.
Do not substitute real agency names without written permission from that agency.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session as DBSession

from audit import compute_entry_hash
from auth import hash_password
from models import User, Document, Query, AuditEntry

# ---- demo fixture data (mirrors keystone-console/src/mock/data.ts) ----------

DEMO_QUERIES = [
    {
        "id": "demo-approved-001",
        "question": "What is our MAYDAY procedure?",
        "role": "member",
        "mode": "operational",
        "scenario_key": "approved",
        "guidance": {
            "type": "approved",
            "summary": "Declare MAYDAY immediately on the assigned tactical channel and provide a LUNAR report.",
            "excerpt": (
                "When a member is lost, trapped, or in immediate danger, the member shall declare MAYDAY "
                "on the assigned tactical channel and provide a LUNAR report: Location, Unit, Name, "
                "Assignment, Resources needed."
            ),
            "note": "This is an operationally approved answer because the source is active and visible to the current role.",
            "document": {
                "documentId": "demo-fd-mayday-v3",
                "title": "Demo FD MAYDAY Procedure v3",
                "section": "3.2",
                "page": 4,
                "status": "active",
                "effectiveDate": "2025-01-15",
                "reviewDate": "2026-01-15",
                "owner": "Training Officer",
            },
        },
        "audit": {
            "receiptId": "receipt-approved-001",
            "timestamp": "2026-03-10T12:10:00Z",
            "policyOutcome": "allowed",
            "roleUsed": "member",
            "modeUsed": "operational",
            "sourcesConsidered": [
                {
                    "documentId": "demo-fd-mayday-v3",
                    "title": "Demo FD MAYDAY Procedure v3",
                    "status": "active",
                    "allowed": True,
                    "page": 4,
                    "section": "3.2",
                    "note": "Returned as primary citation.",
                },
                {
                    "documentId": "demo-fd-radio-sop-v2",
                    "title": "Demo FD Radio SOP v2",
                    "status": "active",
                    "allowed": True,
                    "page": 7,
                    "section": "5.1",
                    "note": "Secondary support for radio channel reference.",
                },
            ],
            "citationsReturned": [
                {"documentId": "demo-fd-mayday-v3", "page": 4, "section": "3.2"},
            ],
        },
    },
    {
        "id": "demo-refusal-001",
        "question": "What medication dose should I administer right now?",
        "role": "member",
        "mode": "operational",
        "scenario_key": "refusal",
        "guidance": {
            "type": "refusal",
            "reasonCode": "OUT_OF_SCOPE",
            "title": "No guidance available",
            "message": "This question is outside the scope of the current demo operational retrieval system.",
            "safeNextStep": "Escalate to qualified medical direction and follow jurisdiction-approved protocols.",
            "hiddenSource": True,
        },
        "audit": {
            "receiptId": "receipt-refusal-001",
            "timestamp": "2026-03-10T12:14:00Z",
            "policyOutcome": "refused",
            "roleUsed": "member",
            "modeUsed": "operational",
            "sourcesConsidered": [],
            "citationsReturned": [],
        },
    },
    {
        "id": "demo-restricted-001",
        "question": "Show the restricted post-incident disciplinary memo.",
        "role": "member",
        "mode": "operational",
        "scenario_key": "restricted",
        "guidance": {
            "type": "refusal",
            "reasonCode": "ACCESS_RESTRICTED",
            "title": "Access restricted",
            "message": "The system cannot provide this content for the current role. No restricted source details are shown.",
            "safeNextStep": "Contact a supervisor or document custodian if you believe access should be granted.",
            "hiddenSource": True,
        },
        "audit": {
            "receiptId": "receipt-restricted-001",
            "timestamp": "2026-03-10T12:18:00Z",
            "policyOutcome": "refused",
            "roleUsed": "member",
            "modeUsed": "operational",
            "sourcesConsidered": [
                {
                    "documentId": None,
                    "title": "Restricted document",
                    "status": "restricted",
                    "allowed": False,
                    "page": None,
                    "section": None,
                    "note": "Source title redacted from member view.",
                },
            ],
            "citationsReturned": [],
        },
    },
    {
        "id": "demo-training-001",
        "question": "How did the older MAYDAY wording compare to the current procedure?",
        "role": "officer",
        "mode": "training",
        "scenario_key": "training",
        "guidance": {
            "type": "approved",
            "summary": "Training mode can show the prior MAYDAY wording with a superseded label and historical context.",
            "excerpt": (
                "Prior version wording required the member to declare MAYDAY and provide location and assignment. "
                "Current version strengthens the report structure by requiring full LUNAR details."
            ),
            "note": "This answer is allowed only in training mode. Operational mode should not treat superseded content as active guidance.",
            "document": {
                "documentId": "demo-fd-mayday-v2",
                "title": "Demo FD MAYDAY Procedure v2",
                "section": "2.4",
                "page": 3,
                "status": "superseded",
                "effectiveDate": "2023-04-10",
                "reviewDate": "2024-12-31",
                "owner": "Training Officer",
            },
        },
        "audit": {
            "receiptId": "receipt-training-001",
            "timestamp": "2026-03-10T12:24:00Z",
            "policyOutcome": "allowed",
            "roleUsed": "officer",
            "modeUsed": "training",
            "sourcesConsidered": [
                {
                    "documentId": "demo-fd-mayday-v2",
                    "title": "Demo FD MAYDAY Procedure v2",
                    "status": "superseded",
                    "allowed": True,
                    "page": 3,
                    "section": "2.4",
                    "note": "Visible in training mode only with superseded label.",
                },
                {
                    "documentId": "demo-fd-mayday-v3",
                    "title": "Demo FD MAYDAY Procedure v3",
                    "status": "active",
                    "allowed": True,
                    "page": 4,
                    "section": "3.2",
                    "note": "Used for comparison with current wording.",
                },
            ],
            "citationsReturned": [
                {"documentId": "demo-fd-mayday-v2", "page": 3, "section": "2.4"},
            ],
        },
    },
]

DEMO_SOURCES = [
    {
        "document_id": "demo-fd-restricted-001",
        "page": 1,
        "title": "Demo FD Post-Incident Disciplinary Memo (2025-11-03)",
        "section": "7.4",
        "status": "active",
        "effective_date": "2025-11-03",
        "review_date": "2026-11-03",
        "owner": "Fire Chief",
        "excerpt": (
            "Post-incident review dated 2025-11-03: disciplinary action was taken "
            "per department standard operating procedure section 7.4. "
            "Details are restricted to supervisory and administrative personnel only."
        ),
        "highlight": "disciplinary action per department SOP section 7.4",
        "notes": [
            "Restricted to officer and authority roles.",
            "Not visible to member role.",
        ],
        "min_role_level": 1,
    },
    {
        "document_id": "demo-fd-mayday-v3",
        "page": 4,
        "title": "Demo FD MAYDAY Procedure v3",
        "section": "3.2",
        "status": "active",
        "effective_date": "2025-01-15",
        "review_date": "2026-01-15",
        "owner": "Training Officer",
        "excerpt": (
            "When a member is lost, trapped, or in immediate danger, the member shall declare MAYDAY "
            "on the assigned tactical channel and provide a LUNAR report: Location, Unit, Name, "
            "Assignment, Resources needed."
        ),
        "highlight": "declare MAYDAY on the assigned tactical channel and provide a LUNAR report",
        "notes": [
            "Operationally approved source.",
            "Exact page and section shown for citation validation.",
        ],
        "min_role_level": 0,
    },
    {
        "document_id": "demo-fd-mayday-v2",
        "page": 3,
        "title": "Demo FD MAYDAY Procedure v2",
        "section": "2.4",
        "status": "superseded",
        "effective_date": "2023-04-10",
        "review_date": "2024-12-31",
        "owner": "Training Officer",
        "excerpt": (
            "In older procedure language, the member shall declare MAYDAY and report location and assignment. "
            "Current procedure expands the required structure to full LUNAR format."
        ),
        "highlight": "older procedure language, the member shall declare MAYDAY and report location and assignment",
        "notes": [
            "Training-only historical source.",
            "Must not be presented as active operational guidance.",
        ],
        "min_role_level": 0,
    },
]


def seed_demo_data(db: DBSession) -> None:
    """Idempotent: only seeds if no data exists."""
    if db.query(User).count() > 0:
        return

    # Demo users
    users = [
        User(id=str(uuid.uuid4()), username="demo", role="member", password_hash=hash_password("demo")),
        User(id=str(uuid.uuid4()), username="officer", role="officer", password_hash=hash_password("officer")),
        User(id=str(uuid.uuid4()), username="admin", role="authority", password_hash=hash_password("admin")),
    ]
    db.add_all(users)

    # Documents (source fixtures)
    for src in DEMO_SOURCES:
        key = f"{src['document_id']}:{src['page']}"
        db.add(Document(
            key=key,
            document_id=src["document_id"],
            page=src["page"],
            title=src["title"],
            section=src["section"],
            status=src["status"],
            effective_date=src["effective_date"],
            review_date=src["review_date"],
            owner=src["owner"],
            excerpt=src["excerpt"],
            highlight=src["highlight"],
            notes_json=src["notes"],
            min_role_level=src.get("min_role_level", 0),
        ))

    # Queries + audit log with HMAC chain
    prev_hash = ""
    for q in DEMO_QUERIES:
        audit = q["audit"]
        db.add(Query(
            id=q["id"],
            question=q["question"],
            role=q["role"],
            mode=q["mode"],
            scenario_key=q["scenario_key"],
            guidance_json=q["guidance"],
            created_at=datetime.now(timezone.utc),
        ))
        entry_hash = compute_entry_hash(
            q["id"],
            audit["timestamp"],
            audit["roleUsed"],
            audit["modeUsed"],
            audit["policyOutcome"],
            prev_hash,
        )
        db.add(AuditEntry(
            id=str(uuid.uuid4()),
            query_id=q["id"],
            receipt_id=audit["receiptId"],
            timestamp=audit["timestamp"],
            role_used=audit["roleUsed"],
            mode_used=audit["modeUsed"],
            policy_outcome=audit["policyOutcome"],
            sources_considered_json=audit["sourcesConsidered"],
            citations_returned_json=audit["citationsReturned"],
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        ))
        prev_hash = entry_hash

    db.commit()
