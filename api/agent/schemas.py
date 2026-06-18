"""
Pydantic schemas for the agent extension.

Stage: M1 scaffold. Real shapes land in M2 (registry) and M3 (plan loop).
"""
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class AgentHealthResponse(BaseModel):
    status: str
    module_version: str
    spec_contract: str = Field(default="keystone-core/agent-spec v1.2 (formerly KDAT-002-SPEC v1.2) (keystone-kdat 4b12094)")
    tables_present: bool


class ToolDef(BaseModel):
    name: str
    description: str
    parameters_schema: dict[str, Any]
    severity_tier: str  # one of {"Critical", "High", "Medium", "Low"}
    requires_evidence: bool = True


class PlanStep(BaseModel):
    step_index: int
    tool_name: str
    proposed_params: dict[str, Any]


class Plan(BaseModel):
    plan_id: str
    steps: list[PlanStep]


class AuthDecision(BaseModel):
    allowed: bool
    routed_to_hitl: bool = False
    policy_reference: str
    severity_tier: str
    rationale: str


class ActionAuditEntry(BaseModel):
    action_id: str
    plan_id: str
    step_index: int
    tool_name: str
    params_hash: str
    auth_decision: str  # "allow" | "deny" | "hitl"
    severity_tier: str
    policy_reference: str
    role: str
    timestamp: datetime
    prev_hash: str
    entry_hash: str


class ApprovalTaskCreate(BaseModel):
    plan_id: str
    step_index: int
    tool_name: str
    proposed_params: dict[str, Any]
    severity_tier: str


class ApprovalTaskDecision(BaseModel):
    decision: str  # "approve" | "reject"
    rationale: Optional[str] = None


class PlanRequest(BaseModel):
    query: str
    role: str
    session_id: str = Field(default_factory=lambda: str(__import__("uuid").uuid4()))
    user_id: str = "agent-test-user"
    steps: Optional[list[dict[str, Any]]] = Field(
        default=None,
        description="Pre-formed steps; if provided, skips LLM plan generation.",
    )


class PlanStepResult(BaseModel):
    step_index: int
    tool_name: str
    auth_decision: str  # "allow" | "deny"
    severity_tier: str
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    # M6: per-step evidence sensor readings
    evidence_score: Optional[float] = None
    hhem_score: Optional[float] = None
    citation_count: Optional[int] = None
    evidence_passed: Optional[bool] = None


class PlanResponse(BaseModel):
    plan_id: str
    role: str
    status: str
    terminated_reason: Optional[str] = None
    step_results: list[PlanStepResult]
    validation_errors: list[str] = Field(default_factory=list)
    hitl_step_index: Optional[int] = None
    approval_id: Optional[str] = None
    # M6: plan-level evidence coverage metrics
    citation_coverage: int = Field(default=0)
    evidence_pass_rate: Optional[float] = None


class PlanDetailStep(BaseModel):
    step_index: int
    tool_name: str
    proposed_params: dict[str, Any]
    executed_params: Optional[dict[str, Any]] = None
    auth_decision: str
    severity_tier: Optional[str] = None
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    executed_at: Optional[datetime] = None
    # M6: evidence sensor readings persisted on the step record
    evidence_score: Optional[float] = None
    hhem_score: Optional[float] = None
    citation_count: Optional[int] = None
    evidence_passed: Optional[bool] = None


class PlanDetail(BaseModel):
    plan_id: str
    session_id: str
    user_id: str
    role: str
    status: str
    terminated_reason: Optional[str] = None
    plan_depth_cap: int
    created_at: datetime
    updated_at: datetime
    steps: list[PlanDetailStep]


class ToolRegistryResponse(BaseModel):
    tools: list[ToolDef]
    count: int


class RolePermittedToolsResponse(BaseModel):
    role: str
    permitted_tools: list[ToolDef]
    count: int


# ---------------------------------------------------------------------------
# M4: audit chain responses
# ---------------------------------------------------------------------------

class AuditEntryResponse(BaseModel):
    action_id: str
    plan_id: str
    step_index: int
    tool_name: str
    params_hash: str
    auth_decision: str
    severity_tier: str
    policy_reference: str
    role: str
    timestamp: datetime
    prev_hash: str
    entry_hash: str


class ChainVerifyResponse(BaseModel):
    valid: bool
    entries_checked: int
    first_invalid_index: Optional[int] = None


class AgentTamperResponse(BaseModel):
    tampered: bool
    plan_id: str
    action_id: str
    detail: str


# ---------------------------------------------------------------------------
# M5: HITL approval schemas
# ---------------------------------------------------------------------------

class ApprovalTaskResponse(BaseModel):
    approval_id: str
    plan_id: str
    step_index: int
    tool_name: str
    proposed_params: dict[str, Any]
    severity_tier: str
    requested_by: str
    requested_at: datetime
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    decision: Optional[str] = None
    decision_rationale: Optional[str] = None
    status: str  # "pending" | "decided"


class ApprovalDecision(BaseModel):
    approver_user_id: str
    approver_role: str
    rationale: Optional[str] = None
