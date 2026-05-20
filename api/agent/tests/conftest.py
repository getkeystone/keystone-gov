"""
pytest fixtures for the agent module tests.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def agent_module_version():
    from agent import __version__
    return __version__


@pytest.fixture(scope="module")
def client():
    """
    Minimal FastAPI test app with only the agent router mounted.

    Does not run the full main.py lifespan, so the database-dependent
    /agent/health endpoint is not under test here. The /agent/tools and
    /agent/registry/role/{role} endpoints read from the in-memory registry
    only and work without a live database.
    """
    from agent.router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)
