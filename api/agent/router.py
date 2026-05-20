"""
FastAPI router mounted by api/main.py via:
    from agent.router import router as agent_router
    app.include_router(agent_router)

Milestones:
  M1: /agent/health
  M2: /agent/tools, /agent/registry/role/{role}
  M3: /agent/plans  (plan submission + execution)
  M5: /agent/approvals  (HITL approval queue)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import inspect
from sqlalchemy.orm import Session as DBSession

try:
    from database import engine, get_db  # type: ignore[import-not-found]
except ImportError:
    from api.database import engine, get_db  # type: ignore[no-redef]

from .registry import tools as _registry_tools, permitted_tools_for
from .schemas import (
    AgentHealthResponse,
    ToolDef,
    ToolRegistryResponse,
    RolePermittedToolsResponse,
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
