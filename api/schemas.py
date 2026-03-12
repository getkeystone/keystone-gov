from typing import Any
from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    username: str
    role: str


class QueryRequest(BaseModel):
    question: str
    role: str
    mode: str
    scenario_key: str


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
    receiptId: str
    timestamp: str
    roleUsed: str
    modeUsed: str
    policyOutcome: str
    sourcesConsidered: Any
    citationsReturned: Any


class AuditVerifyResponse(BaseModel):
    queryId: str
    valid: bool
    detail: str
