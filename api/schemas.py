from typing import Any, Literal, Optional
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    # Upper bounds prevent oversized payloads reaching auth logic.
    username: str = Field(..., max_length=128)
    password: str = Field(..., max_length=256)


class LoginResponse(BaseModel):
    token: str
    username: str
    role: str


class QueryRequest(BaseModel):
    # 2000-char limit prevents FTS/LLM abuse and controls DB storage size.
    question: str = Field(..., max_length=2000)
    mode: Literal["operational", "training", "medical_reference"]
    # role is accepted for backward-compat but ignored — server derives from token
    role: Optional[str] = None
    # scenario_key is an admin-only override; ignored for non-admin sessions
    scenario_key: Optional[str] = None
    # domain_filter restricts FTS to specific corpus domains (e.g. ["fire_ops"])
    domain_filter: Optional[list[str]] = None


class QueryResponse(BaseModel):
    query_id: str
    scenario_key: str


class GuidanceResponse(BaseModel):
    queryId: str
    scenarioKey: str
    question: str
    mode: str
    guidance: Any
    audit: Any


class SourceResponse(BaseModel):
    documentId: str
    page: int
    title: str
    section: str
    status: str
    effectiveDate: str
    reviewDate: str
    owner: str
    excerpt: str
    highlight: str
    notes: list[str]


class AuditResponse(BaseModel):
    queryId: str
    question: str = ""
    receiptId: str
    timestamp: str
    roleUsed: str
    modeUsed: str
    policyOutcome: str
    sourcesConsidered: Any
    citationsReturned: Any
    # Identity fields (present when CF Access or demo identity is available)
    userId: Optional[str] = None
    userEmail: Optional[str] = None
    userDisplayName: Optional[str] = None
    authSource: Optional[str] = None
    simulatedRoleUsed: Optional[str] = None


class AuditVerifyResponse(BaseModel):
    queryId: str
    valid: bool
    detail: str


class MeResponse(BaseModel):
    user_id: str
    email: str
    display_name: str
    assigned_role: str
    effective_role: str
    auth_source: str
    cf_enabled: bool
    sim_role: Optional[str] = None
    sim_enabled: bool = False
