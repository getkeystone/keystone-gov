"""
FastAPI router mounted by api/main.py via:
    from agent.router import router as agent_router
    app.include_router(agent_router)

Milestones:
  M1: /agent/health
  M2: /agent/tools, /agent/registry/role/{role}
  M3: /agent/plans (POST create+execute, GET by plan_id)
  M5: /agent/approvals  (HITL approval queue)
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import inspect
from sqlalchemy.orm import Session as DBSession

try:
    from database import engine, get_db  # type: ignore[import-not-found]
except ImportError:
    from api.database import engine, get_db  # type: ignore[no-redef]

from .audit import verify_plan_chain, write_audit_entry
from .models import AgentActionAudit, AgentApprovalTask, AgentPlan, AgentPlanStep
from .plan_loop import execute_plan, generate_plan
from .registry import tools as _registry_tools, permitted_tools_for
from .schemas import (
    AgentHealthResponse,
    AgentTamperResponse,
    ApprovalDecision,
    ApprovalTaskResponse,
    AuditEntryResponse,
    ChainVerifyResponse,
    PlanDetail,
    PlanDetailStep,
    PlanRequest,
    PlanResponse,
    PlanStepResult,
    RolePermittedToolsResponse,
    ToolDef,
    ToolRegistryResponse,
)
from . import __version__

router = APIRouter(prefix="/agent", tags=["agent"])

_EXPECTED_TABLES = {
    "agent_plans",
    "agent_plan_steps",
    "agent_action_audit",
    "agent_approval_tasks",
}

_KNOWN_ROLES = {"operator", "supervisor", "custodian", "admin"}


def _tool_dict_to_def(t: dict) -> ToolDef:
    return ToolDef(
        name=t["name"],
        description=t["description"],
        parameters_schema=t["parameters_schema"],
        severity_tier=t["severity_tier"],
        requires_evidence=t.get("requires_evidence", True),
    )


# ---------------------------------------------------------------------------
# M1: health
# ---------------------------------------------------------------------------

@router.get("/health", response_model=AgentHealthResponse)
def agent_health(db: DBSession = Depends(get_db)) -> AgentHealthResponse:
    insp = inspect(engine)
    present = set(insp.get_table_names())
    tables_present = _EXPECTED_TABLES.issubset(present)
    return AgentHealthResponse(
        status="ok" if tables_present else "tables_missing",
        module_version=__version__,
        tables_present=tables_present,
    )


# ---------------------------------------------------------------------------
# M2: tool registry
# ---------------------------------------------------------------------------

@router.get("/tools", response_model=ToolRegistryResponse)
def list_tools() -> ToolRegistryResponse:
    """Return the full tool inventory with parameter schemas and severity tiers."""
    registry = _registry_tools()
    tool_defs = [_tool_dict_to_def(t) for t in registry.values()]
    return ToolRegistryResponse(tools=tool_defs, count=len(tool_defs))


@router.get("/registry/role/{role}", response_model=RolePermittedToolsResponse)
def role_registry(role: str) -> RolePermittedToolsResponse:
    """Return the tools a given role is permitted to call."""
    if role not in _KNOWN_ROLES:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown role '{role}'. Known roles: {sorted(_KNOWN_ROLES)}",
        )
    permitted = permitted_tools_for(role)
    tool_defs = [_tool_dict_to_def(t) for t in permitted]
    return RolePermittedToolsResponse(role=role, permitted_tools=tool_defs, count=len(tool_defs))


# ---------------------------------------------------------------------------
# M3: plan execution
# ---------------------------------------------------------------------------

@router.post("/plans", status_code=201, response_model=PlanResponse)
def create_plan(req: PlanRequest, db: DBSession = Depends(get_db)) -> PlanResponse:
    """
    Create and execute a governed agent plan.

    If `steps` is provided in the request body, those steps are used
    directly (skipping LLM generation). This is the primary path for
    tests and deterministic integrations. When `steps` is omitted, the
    LLM generates a plan from `query`.
    """
    if req.role not in _KNOWN_ROLES:
        raise HTTPException(status_code=400, detail=f"Unknown role: {req.role!r}")

    if req.steps is not None:
        raw_steps = req.steps
    else:
        raw_steps = generate_plan(req.query, req.role, _registry_tools())
        if raw_steps is None:
            raise HTTPException(
                status_code=503,
                detail="LLM plan generation failed — Ollama may be unavailable.",
            )

    plan_id = str(uuid.uuid4())
    plan = AgentPlan(
        plan_id=uuid.UUID(plan_id),
        session_id=req.session_id,
        user_id=req.user_id,
        role=req.role,
        status="proposed",
        raw_steps=raw_steps,
    )
    db.add(plan)
    db.flush()

    result = execute_plan(
        plan_id=plan_id,
        role=req.role,
        raw_steps=raw_steps,
        db=db,
        user_id=req.user_id,
    )

    step_results = [
        PlanStepResult(
            step_index=sr["step_index"],
            tool_name=sr["tool_name"],
            auth_decision=sr["auth_decision"],
            severity_tier=sr.get("severity_tier", "Unknown"),
            result=sr.get("result"),
            error=sr.get("error"),
        )
        for sr in result.get("step_results", [])
    ]

    return PlanResponse(
        plan_id=plan_id,
        role=req.role,
        status=result["status"],
        terminated_reason=result.get("terminated_reason"),
        step_results=step_results,
        validation_errors=result.get("validation_errors", []),
        hitl_step_index=result.get("hitl_step_index"),
        approval_id=result.get("approval_id"),
    )


# ---------------------------------------------------------------------------
# M4: audit chain
# ---------------------------------------------------------------------------

@router.get("/audit/{plan_id}", response_model=list[AuditEntryResponse])
def get_audit_chain(plan_id: str, db: DBSession = Depends(get_db)) -> list[AuditEntryResponse]:
    """Return all audit entries for a plan, ordered by timestamp then step_index."""
    try:
        plan_uuid = uuid.UUID(plan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid plan_id (not a UUID)")

    entries = (
        db.query(AgentActionAudit)
        .filter(AgentActionAudit.plan_id == plan_uuid)
        .order_by(AgentActionAudit.timestamp, AgentActionAudit.step_index)
        .all()
    )
    return [
        AuditEntryResponse(
            action_id=str(e.action_id),
            plan_id=str(e.plan_id),
            step_index=e.step_index,
            tool_name=e.tool_name,
            params_hash=e.params_hash,
            auth_decision=e.auth_decision,
            severity_tier=e.severity_tier,
            policy_reference=e.policy_reference,
            role=e.role,
            timestamp=e.timestamp,
            prev_hash=e.prev_hash,
            entry_hash=e.entry_hash,
        )
        for e in entries
    ]


@router.get("/audit/{plan_id}/verify", response_model=ChainVerifyResponse)
def verify_audit_chain(plan_id: str, db: DBSession = Depends(get_db)) -> ChainVerifyResponse:
    """Recompute and verify the HMAC hash chain for a plan's audit entries."""
    try:
        uuid.UUID(plan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid plan_id (not a UUID)")

    result = verify_plan_chain(plan_id, db)
    return ChainVerifyResponse(**result)


@router.post("/admin/agent-tamper/{plan_id}", response_model=AgentTamperResponse)
def tamper_agent_audit(plan_id: str, db: DBSession = Depends(get_db)) -> AgentTamperResponse:
    """
    Demo-only endpoint. Corrupts the entry_hash of the first audit entry
    for the given plan, causing verify to return valid=False. Uses
    TAMPER_DATABASE_URL (DB owner credentials) to bypass INSERT-only
    constraints on the audit table — proving tamper-evidence holds even
    against owner-level writes.
    """
    import os
    from sqlalchemy import create_engine, text as sa_text

    try:
        plan_uuid = uuid.UUID(plan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid plan_id (not a UUID)")

    entry = (
        db.query(AgentActionAudit)
        .filter(AgentActionAudit.plan_id == plan_uuid)
        .order_by(AgentActionAudit.timestamp, AgentActionAudit.step_index)
        .first()
    )
    if not entry:
        raise HTTPException(status_code=404, detail="No audit entries found for this plan")

    tamper_url = os.environ.get("TAMPER_DATABASE_URL", "")
    if not tamper_url:
        raise HTTPException(status_code=501, detail="TAMPER_DATABASE_URL not configured")

    action_id_str = str(entry.action_id)
    tamper_engine = create_engine(tamper_url)
    try:
        with tamper_engine.connect() as conn:
            conn.execute(
                sa_text(
                    "UPDATE agent_action_audit SET entry_hash = 'TAMPERED_BY_DEMO_ENDPOINT'"
                    " WHERE action_id = :aid"
                ),
                {"aid": action_id_str},
            )
            conn.commit()
    finally:
        tamper_engine.dispose()

    return AgentTamperResponse(
        tampered=True,
        plan_id=plan_id,
        action_id=action_id_str,
        detail=(
            "entry_hash corrupted for demo; "
            "GET /agent/audit/{plan_id}/verify will now return valid=false"
        ),
    )


# ---------------------------------------------------------------------------
# M5: HITL approval queue
# ---------------------------------------------------------------------------

_APPROVAL_AUTHORITY_ROLES = {"custodian", "admin"}


def _task_to_response(t: AgentApprovalTask) -> ApprovalTaskResponse:
    return ApprovalTaskResponse(
        approval_id=str(t.approval_id),
        plan_id=str(t.plan_id),
        step_index=t.step_index,
        tool_name=t.tool_name,
        proposed_params=t.proposed_params,
        severity_tier=t.severity_tier,
        requested_by=t.requested_by,
        requested_at=t.requested_at,
        decided_by=t.decided_by,
        decided_at=t.decided_at,
        decision=t.decision,
        decision_rationale=t.decision_rationale,
        status=t.status,
    )


@router.get("/approvals", response_model=list[ApprovalTaskResponse])
def list_approvals(
    status: str = "pending",
    db: DBSession = Depends(get_db),
) -> list[ApprovalTaskResponse]:
    """List approval tasks, filtered by status (default: pending)."""
    tasks = (
        db.query(AgentApprovalTask)
        .filter(AgentApprovalTask.status == status)
        .order_by(AgentApprovalTask.requested_at.desc())
        .all()
    )
    return [_task_to_response(t) for t in tasks]


@router.get("/approvals/{approval_id}", response_model=ApprovalTaskResponse)
def get_approval(approval_id: str, db: DBSession = Depends(get_db)) -> ApprovalTaskResponse:
    """Return a single approval task by ID."""
    try:
        approval_uuid = uuid.UUID(approval_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid approval_id (not a UUID)")

    task = db.query(AgentApprovalTask).filter(
        AgentApprovalTask.approval_id == approval_uuid
    ).first()
    if not task:
        raise HTTPException(status_code=404, detail="Approval task not found")
    return _task_to_response(task)


@router.post("/approvals/{approval_id}/approve", response_model=PlanResponse)
def approve_action(
    approval_id: str,
    body: ApprovalDecision,
    db: DBSession = Depends(get_db),
) -> PlanResponse:
    """
    Approve a pending HITL action.

    Authorization rules:
      - approver_role must be custodian or admin (P5.1)
      - approver_user_id must differ from the requesting user (no self-approval)

    On approval the plan resumes execution from the approved step. The response
    is the new plan state after resumption (may still be hitl_pending if a later
    step also requires HITL).
    """
    from datetime import datetime as _dt

    try:
        approval_uuid = uuid.UUID(approval_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid approval_id (not a UUID)")

    if body.approver_role not in _APPROVAL_AUTHORITY_ROLES:
        raise HTTPException(
            status_code=403,
            detail=f"Only {sorted(_APPROVAL_AUTHORITY_ROLES)} roles can approve (P5.1)",
        )

    task = db.query(AgentApprovalTask).filter(
        AgentApprovalTask.approval_id == approval_uuid
    ).first()
    if not task:
        raise HTTPException(status_code=404, detail="Approval task not found")

    if task.status == "decided":
        raise HTTPException(status_code=409, detail="Approval task already decided")

    if body.approver_user_id == task.requested_by:
        raise HTTPException(status_code=403, detail="Self-approval is not permitted (P5.1)")

    # Record decision.
    task.status = "decided"
    task.decision = "approve"
    task.decided_by = body.approver_user_id
    task.decided_at = _dt.utcnow()
    task.decision_rationale = body.rationale
    db.flush()

    # Write audit entry for the approval decision (P5.1).
    write_audit_entry(
        plan_id=str(task.plan_id),
        step_index=task.step_index,
        tool_name=task.tool_name,
        params=task.proposed_params,
        auth_decision="allow",
        severity_tier=task.severity_tier,
        policy_reference="P5.1",
        role=body.approver_role,
        db=db,
    )

    # Load plan for resume.
    plan = db.query(AgentPlan).filter(AgentPlan.plan_id == task.plan_id).first()
    if not plan or not plan.raw_steps:
        raise HTTPException(status_code=500, detail="Plan raw_steps missing; cannot resume")

    result = execute_plan(
        plan_id=str(task.plan_id),
        role=plan.role,
        raw_steps=plan.raw_steps,
        db=db,
        user_id=plan.user_id,
        plan_depth_cap=plan.plan_depth_cap,
        resume_from_step=task.step_index,
    )

    step_results = [
        PlanStepResult(
            step_index=sr["step_index"],
            tool_name=sr["tool_name"],
            auth_decision=sr["auth_decision"],
            severity_tier=sr.get("severity_tier", "Unknown"),
            result=sr.get("result"),
            error=sr.get("error"),
        )
        for sr in result.get("step_results", [])
    ]

    return PlanResponse(
        plan_id=str(task.plan_id),
        role=plan.role,
        status=result["status"],
        terminated_reason=result.get("terminated_reason"),
        step_results=step_results,
        validation_errors=result.get("validation_errors", []),
        hitl_step_index=result.get("hitl_step_index"),
        approval_id=result.get("approval_id"),
    )


@router.post("/approvals/{approval_id}/reject", response_model=PlanResponse)
def reject_action(
    approval_id: str,
    body: ApprovalDecision,
    db: DBSession = Depends(get_db),
) -> PlanResponse:
    """
    Reject a pending HITL action. Terminates the plan.

    Authorization rules same as approve.
    """
    from datetime import datetime as _dt

    try:
        approval_uuid = uuid.UUID(approval_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid approval_id (not a UUID)")

    if body.approver_role not in _APPROVAL_AUTHORITY_ROLES:
        raise HTTPException(
            status_code=403,
            detail=f"Only {sorted(_APPROVAL_AUTHORITY_ROLES)} roles can reject (P5.1)",
        )

    task = db.query(AgentApprovalTask).filter(
        AgentApprovalTask.approval_id == approval_uuid
    ).first()
    if not task:
        raise HTTPException(status_code=404, detail="Approval task not found")

    if task.status == "decided":
        raise HTTPException(status_code=409, detail="Approval task already decided")

    if body.approver_user_id == task.requested_by:
        raise HTTPException(status_code=403, detail="Self-rejection is not permitted (P5.1)")

    # Record decision.
    task.status = "decided"
    task.decision = "reject"
    task.decided_by = body.approver_user_id
    task.decided_at = _dt.utcnow()
    task.decision_rationale = body.rationale
    db.flush()

    # Write audit entry for the rejection decision (P5.1).
    write_audit_entry(
        plan_id=str(task.plan_id),
        step_index=task.step_index,
        tool_name=task.tool_name,
        params=task.proposed_params,
        auth_decision="deny",
        severity_tier=task.severity_tier,
        policy_reference="P5.1",
        role=body.approver_role,
        db=db,
    )

    # Terminate the plan.
    terminated_reason = (
        f"step_{task.step_index}_rejected_by_{body.approver_user_id}"
    )
    db.query(AgentPlan).filter(AgentPlan.plan_id == task.plan_id).update(
        {
            "status": "terminated",
            "terminated_reason": terminated_reason,
            "updated_at": _dt.utcnow(),
        },
        synchronize_session=False,
    )
    db.commit()

    return PlanResponse(
        plan_id=str(task.plan_id),
        role="",
        status="terminated",
        terminated_reason=terminated_reason,
        step_results=[],
        validation_errors=[],
    )


@router.get("/plans/{plan_id}", response_model=PlanDetail)
def get_plan(plan_id: str, db: DBSession = Depends(get_db)) -> PlanDetail:
    """Retrieve a plan record with all persisted steps."""
    try:
        plan_uuid = uuid.UUID(plan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid plan_id (not a UUID)")

    plan = db.query(AgentPlan).filter(AgentPlan.plan_id == plan_uuid).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    step_records = (
        db.query(AgentPlanStep)
        .filter(AgentPlanStep.plan_id == plan_uuid)
        .order_by(AgentPlanStep.step_index)
        .all()
    )

    steps = [
        PlanDetailStep(
            step_index=s.step_index,
            tool_name=s.tool_name,
            proposed_params=s.proposed_params,
            executed_params=s.executed_params,
            auth_decision=s.auth_decision,
            severity_tier=s.severity_tier,
            result=s.result,
            error=s.error,
            executed_at=s.executed_at,
        )
        for s in step_records
    ]

    return PlanDetail(
        plan_id=str(plan.plan_id),
        session_id=plan.session_id,
        user_id=plan.user_id,
        role=plan.role,
        status=plan.status,
        terminated_reason=plan.terminated_reason,
        plan_depth_cap=plan.plan_depth_cap,
        created_at=plan.created_at,
        updated_at=plan.updated_at,
        steps=steps,
    )
