"""
FastAPI router mounted by api/main.py via:
    from agent.router import router as agent_router
    app.include_router(agent_router)

Stage: M1 scaffold. Only /agent/health is wired. Other endpoints land in
M2 (/agent/tools), M3 (/agent/plans), M5 (/agent/approvals).
"""
from fastapi import APIRouter, Depends
from sqlalchemy import inspect
from sqlalchemy.orm import Session as DBSession

try:
    from database import engine, get_db  # type: ignore[import-not-found]
except ImportError:
    from api.database import engine, get_db  # type: ignore[no-redef]

from .schemas import AgentHealthResponse
from . import __version__

router = APIRouter(prefix="/agent", tags=["agent"])

_EXPECTED_TABLES = {
    "agent_plans",
    "agent_plan_steps",
    "agent_action_audit",
    "agent_approval_tasks",
}


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
