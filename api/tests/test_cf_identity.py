"""test_cf_identity.py — Unit tests for CF Access identity module.

Tests:
  T1  load_role_config: valid config loads all users
  T2  load_role_config: duplicate email raises ValueError
  T3  load_role_config: invalid role raises ValueError
  T4  load_role_config: missing email raises ValueError
  T5  load_role_config: display_name derived from email localpart when absent
  T6  get_current_user: demo path (CF disabled) returns AppUser from Bearer session
  T7  get_current_user: CF disabled, no Bearer → 401
  T8  get_current_user: CF enabled, no JWT → 401 CF_ASSERTION_MISSING
  T9  AppUser.role returns sim_role when set
  T10 AppUser.role returns assigned_role when sim_role is None
  T11 AppUser.username returns email
"""

import sys
import os
import io
import tempfile
import uuid

import pytest

# Allow imports from the api directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cf_identity
from cf_identity import AppUser, load_role_config, RoleEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_YAML = """
version: 1
users:
  - email: alice@lrfd.ca
    display_name: Alice Example
    role: admin
    status: active
  - email: bob@lrfd.ca
    display_name: Bob Member
    role: member
    status: active
  - email: carol@lrfd.ca
    display_name: Carol Officer
    role: officer
    status: active
"""

DUPE_EMAIL_YAML = """
version: 1
users:
  - email: alice@lrfd.ca
    display_name: Alice One
    role: admin
    status: active
  - email: ALICE@LRFD.CA
    display_name: Alice Two
    role: member
    status: active
"""

BAD_ROLE_YAML = """
version: 1
users:
  - email: dave@lrfd.ca
    display_name: Dave
    role: superuser
    status: active
"""

MISSING_EMAIL_YAML = """
version: 1
users:
  - display_name: No Email
    role: member
    status: active
"""

NO_DISPLAY_NAME_YAML = """
version: 1
users:
  - email: john.smith@lrfd.ca
    role: member
    status: active
"""


def _yaml_file(content: str) -> str:
    """Write YAML content to a temp file and return the path."""
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    fh.write(content)
    fh.flush()
    fh.close()
    return fh.name


# ---------------------------------------------------------------------------
# T1 — valid config loads all users
# ---------------------------------------------------------------------------

def test_load_role_config_valid():
    path = _yaml_file(VALID_YAML)
    result = load_role_config(path)
    assert len(result) == 3
    assert "alice@lrfd.ca" in result
    assert result["alice@lrfd.ca"].role == "admin"
    assert result["alice@lrfd.ca"].display_name == "Alice Example"
    assert result["bob@lrfd.ca"].role == "member"
    assert result["carol@lrfd.ca"].role == "officer"


# ---------------------------------------------------------------------------
# T2 — duplicate email (case-insensitive) raises ValueError
# ---------------------------------------------------------------------------

def test_load_role_config_duplicate_email():
    path = _yaml_file(DUPE_EMAIL_YAML)
    with pytest.raises(ValueError, match="Duplicate email"):
        load_role_config(path)


# ---------------------------------------------------------------------------
# T3 — invalid role raises ValueError
# ---------------------------------------------------------------------------

def test_load_role_config_invalid_role():
    path = _yaml_file(BAD_ROLE_YAML)
    with pytest.raises(ValueError, match="Invalid role"):
        load_role_config(path)


# ---------------------------------------------------------------------------
# T4 — missing email raises ValueError
# ---------------------------------------------------------------------------

def test_load_role_config_missing_email():
    path = _yaml_file(MISSING_EMAIL_YAML)
    with pytest.raises(ValueError, match="missing 'email'"):
        load_role_config(path)


# ---------------------------------------------------------------------------
# T5 — display_name derived from email localpart when absent
# ---------------------------------------------------------------------------

def test_load_role_config_display_name_derived():
    path = _yaml_file(NO_DISPLAY_NAME_YAML)
    result = load_role_config(path)
    entry = result["john.smith@lrfd.ca"]
    # localpart "john.smith" → "John Smith"
    assert entry.display_name == "John Smith"


# ---------------------------------------------------------------------------
# T6 — demo path: CF disabled, valid Bearer session → AppUser returned
# ---------------------------------------------------------------------------

def test_get_current_user_demo_path(monkeypatch):
    """When CF is disabled and a valid Bearer token exists, return AppUser."""
    # Patch CF enabled flag off
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", False)

    # Build a fake session and DB
    fake_session_id = str(uuid.uuid4())
    fake_token = "test-token-" + fake_session_id

    class FakeSession:
        user_id = fake_session_id
        username = "demo@lrfd.ca"
        role = "member"

    class FakeQuery:
        def filter(self, *a, **kw):
            return self
        def first(self):
            return FakeSession()

    class FakeDB:
        def query(self, model):
            return FakeQuery()

    user = cf_identity.get_current_user(
        cf_access_jwt_assertion=None,
        authorization=f"Bearer {fake_token}",
        db=FakeDB(),
    )

    assert user.auth_source == "demo_session"
    assert user.email == "demo@lrfd.ca"
    assert user.assigned_role == "member"
    assert user.role == "member"
    assert user.sim_role is None


# ---------------------------------------------------------------------------
# T7 — CF disabled, no Bearer token → 401
# ---------------------------------------------------------------------------

def test_get_current_user_no_auth(monkeypatch):
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", False)

    class FakeDB:
        def query(self, model):
            raise AssertionError("should not reach DB")

    from fastapi import HTTPException as FastHTTP
    with pytest.raises(FastHTTP) as exc_info:
        cf_identity.get_current_user(
            cf_access_jwt_assertion=None,
            authorization=None,
            db=FakeDB(),
        )
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# T8 — CF enabled, no JWT assertion → 401 CF_ASSERTION_MISSING
# ---------------------------------------------------------------------------

def test_get_current_user_cf_enabled_no_jwt(monkeypatch):
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", True)

    class FakeDB:
        def query(self, model):
            raise AssertionError("should not reach DB")

    from fastapi import HTTPException as FastHTTP
    with pytest.raises(FastHTTP) as exc_info:
        cf_identity.get_current_user(
            cf_access_jwt_assertion=None,
            authorization=None,
            db=FakeDB(),
        )
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail["reasonCode"] == "CF_ASSERTION_MISSING"


# ---------------------------------------------------------------------------
# T9 — AppUser.role returns sim_role when set
# ---------------------------------------------------------------------------

def test_app_user_sim_role_overrides():
    user = AppUser(
        user_id="u1",
        email="alice@lrfd.ca",
        display_name="Alice",
        assigned_role="admin",
        auth_source="cloudflare_access",
        sim_role="member",
    )
    assert user.role == "member"


# ---------------------------------------------------------------------------
# T10 — AppUser.role returns assigned_role when sim_role is None
# ---------------------------------------------------------------------------

def test_app_user_no_sim_role():
    user = AppUser(
        user_id="u1",
        email="alice@lrfd.ca",
        display_name="Alice",
        assigned_role="admin",
        auth_source="cloudflare_access",
        sim_role=None,
    )
    assert user.role == "admin"


# ---------------------------------------------------------------------------
# T11 — AppUser.username returns email
# ---------------------------------------------------------------------------

def test_app_user_username_is_email():
    user = AppUser(
        user_id="u1",
        email="alice@lrfd.ca",
        display_name="Alice",
        assigned_role="admin",
        auth_source="cloudflare_access",
    )
    assert user.username == "alice@lrfd.ca"
