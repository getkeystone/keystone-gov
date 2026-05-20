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
    spec_contract: str = Field(default="KDAT-002-SPEC v1.2 (keystone-kdat 4b12094)")
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
