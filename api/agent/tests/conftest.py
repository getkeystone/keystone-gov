"""
pytest fixtures for the agent module tests.

Stage: M1 scaffold. Fixtures expand as tests are added in M2 through M7.
"""
import pytest


@pytest.fixture
def agent_module_version():
    from agent import __version__
    return __version__
