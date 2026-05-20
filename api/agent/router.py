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

from .models import AgentPlan, AgentPlanStep
from .plan_loop import execute_plan, generate_plan
from .registry import tools as _registry_tools, permitted_tools_for
from .schemas import (
    AgentHealthResponse,
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
