"""
pytest fixtures for the agent module tests.
"""
import os
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Set required env vars before any agent imports so modules that read them
# at import time (ollama_client, audit) get the right values.
os.environ.setdefault("AUDIT_HMAC_KEY", "kdat002-test-key-32-chars-for-unit-tests!")
os.environ.setdefault("DATABASE_URL", "postgresql://keystone:keystone@127.0.0.1:5433/keystone_dev")
os.environ.setdefault("TAMPER_DATABASE_URL", "postgresql://keystone:keystone@127.0.0.1:5433/keystone_dev")
os.environ.setdefault("OLLAMA_URL", "http://127.0.0.1:11434")


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


@pytest.fixture(scope="module")
def db_client():
    """
    TestClient backed by a real PostgreSQL session for M3 integration tests.

    Overrides get_db to inject a live session so plan execution, tool writes
    (notifications, document versions), and DB assertions all share the same
    connection. create_all() ensures the agent_notifications table exists.
    """
    from database import get_db, SessionLocal, Base, engine
    import agent.models  # register AgentNotification and other M3 models

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    def override_get_db():
        yield db

    from agent.router import router
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = override_get_db

    yield TestClient(app), db

    db.close()
