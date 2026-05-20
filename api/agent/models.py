"""
SQLAlchemy models for the agent extension. Four new tables, zero ALTERs
on existing tables. Uses Base from api/database.py to share the metadata
registry with the existing models.
"""
from datetime import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.dialects.postgresql import UUID
import uuid

# Import Base via package-relative import; falls back to module path used by
# the rest of api/ which is a flat module layout (no api. prefix).
try:
    from database import Base  # type: ignore[import-not-found]
except ImportError:
    from api.database import Base  # type: ignore[no-redef]


class AgentPlan(Base):
    __tablename__ = "agent_plans"

    plan_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(String, nullable=False, index=True)
    user_id = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False)
    status = Column(String, nullable=False, default="proposed")
    # status in {"proposed", "executing", "completed", "failed", "hitl_pending", "terminated"}
    plan_depth_cap = Column(Integer, nullable=False, default=5)
    terminated_reason = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("ix_agent_plans_user_status", "user_id", "status"),
    )


class AgentPlanStep(Base):
    __tablename__ = "agent_plan_steps"

    step_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    plan_id = Column(UUID(as_uuid=True), ForeignKey("agent_plans.plan_id"), nullable=False, index=True)
    step_index = Column(Integer, nullable=False)
    tool_name = Column(String, nullable=False)
    proposed_params = Column(JSON, nullable=False)
    executed_params = Column(JSON, nullable=True)
    auth_decision = Column(String, nullable=False, default="pending")
    # auth_decision in {"pending", "allow", "deny", "hitl"}
    severity_tier = Column(String, nullable=True)
    executed_at = Column(DateTime, nullable=True)
    result = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_agent_plan_steps_plan_index", "plan_id", "step_index", unique=True),
    )


class AgentActionAudit(Base):
    """
    INSERT-only action audit chain. Hash-chained with HMAC-SHA256 using
    AUDIT_HMAC_KEY (same key as the existing query audit chain, scoped by
    event_type='agent_action' in the chain payload).
    """
    __tablename__ = "agent_action_audit"

    action_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    plan_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    step_index = Column(Integer, nullable=False)
    event_type = Column(String, nullable=False, default="agent_action")
    tool_name = Column(String, nullable=False)
    params_hash = Column(String, nullable=False)  # sha256 hex of canonicalized params JSON
    auth_decision = Column(String, nullable=False)  # "allow" | "deny" | "hitl"
    severity_tier = Column(String, nullable=False)
    policy_reference = Column(String, nullable=False)  # e.g. "P1.2", "P5.1", "P5.3"
    role = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    prev_hash = Column(String, nullable=False)
    entry_hash = Column(String, nullable=False)

    __table_args__ = (
        Index("ix_agent_audit_plan_step", "plan_id", "step_index"),
        Index("ix_agent_audit_timestamp", "timestamp"),
    )


class AgentApprovalTask(Base):
    __tablename__ = "agent_approval_tasks"

    approval_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    plan_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    step_index = Column(Integer, nullable=False)
    tool_name = Column(String, nullable=False)
    proposed_params = Column(JSON, nullable=False)
    severity_tier = Column(String, nullable=False)
    requested_by = Column(String, nullable=False)
    requested_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    decided_by = Column(String, nullable=True)
    decided_at = Column(DateTime, nullable=True)
    decision = Column(String, nullable=True)  # "approve" | "reject"
    decision_rationale = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="pending")  # "pending" | "decided"

    __table_args__ = (
        Index("ix_agent_approval_status", "status"),
        Index("ix_agent_approval_plan_step", "plan_id", "step_index", unique=True),
    )
