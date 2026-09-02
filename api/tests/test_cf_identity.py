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

import json
import sys
import os
import io
import tempfile
import uuid

import pytest

# Allow imports from the api directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cf_identity
from cf_identity import AppUser, load_role_config, RoleEntry, validate_cf_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_YAML = """
version: 1
users:
  - email: alice@lrfd.ca
    display_name: Alice Example
    role: authority
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
    role: authority
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
    assert result["alice@lrfd.ca"].role == "authority"
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
        assigned_role="authority",
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
        assigned_role="authority",
        auth_source="cloudflare_access",
        sim_role=None,
    )
    assert user.role == "authority"


# ---------------------------------------------------------------------------
# T11 — AppUser.username returns email
# ---------------------------------------------------------------------------

def test_app_user_username_is_email():
    user = AppUser(
        user_id="u1",
        email="alice@lrfd.ca",
        display_name="Alice",
        assigned_role="authority",
        auth_source="cloudflare_access",
    )
    assert user.username == "alice@lrfd.ca"


# ---------------------------------------------------------------------------
# T12 — both pilot admin accounts load correctly; idempotency (no duplicates)
# ---------------------------------------------------------------------------

DUAL_ADMIN_YAML = """
version: 1
users:
  - email: testuser@example.com
    display_name: Arnaldo Sepulveda
    role: authority
    status: active
  - email: admin@example.com
    display_name: Arnaldo
    role: authority
    status: active
"""


def test_both_admin_emails_load():
    """Both testuser@example.com and admin@example.com must be present."""
    path = _yaml_file(DUAL_ADMIN_YAML)
    result = load_role_config(path)

    assert "testuser@example.com" in result
    e1 = result["testuser@example.com"]
    assert e1.role == "authority"
    assert e1.display_name == "Arnaldo Sepulveda"
    assert e1.status == "active"

    assert "admin@example.com" in result
    e2 = result["admin@example.com"]
    assert e2.role == "authority"
    assert e2.display_name == "Arnaldo"
    assert e2.status == "active"

    # Exactly 2 users — no duplicates, no phantom entries
    assert len(result) == 2


def test_both_admin_emails_idempotent():
    """Loading the same config twice must yield identical results (no mutation)."""
    path = _yaml_file(DUAL_ADMIN_YAML)
    first  = load_role_config(path)
    second = load_role_config(path)
    assert set(first.keys()) == set(second.keys())
    for email in first:
        assert first[email].role         == second[email].role
        assert first[email].display_name == second[email].display_name
        assert first[email].status       == second[email].status


def test_getkeystone_email_not_treated_as_duplicate_of_lrfd():
    """admin@example.com and testuser@example.com are distinct emails."""
    path = _yaml_file(DUAL_ADMIN_YAML)
    result = load_role_config(path)
    # If they were treated as duplicates, load_role_config would have raised.
    assert len(result) == 2


# ---------------------------------------------------------------------------
# T15-T17 — demo users (gmail member + protonmail officer)
# ---------------------------------------------------------------------------

DEMO_USERS_YAML = """
version: 1
users:
  - email: testuser@example.com
    display_name: Arnaldo Sepulveda
    role: authority
    status: active
  - email: admin@example.com
    display_name: Arnaldo
    role: authority
    status: active
  - email: testuser2@example.com
    display_name: Arnaldo Demo
    role: member
    status: active
  - email: otheruser@example.com
    display_name: Nature Uplift
    role: officer
    status: active
"""


def test_demo_users_load():
    """All four seed users load with correct roles and display names."""
    path = _yaml_file(DEMO_USERS_YAML)
    result = load_role_config(path)

    expected = {
        "testuser@example.com":    ("authority", "Arnaldo Sepulveda"),
        "admin@example.com":       ("authority", "Arnaldo"),
        "testuser2@example.com":   ("member",    "Arnaldo Demo"),
        "otheruser@example.com":  ("officer",    "Nature Uplift"),
    }
    assert len(result) == len(expected), (
        f"Expected {len(expected)} users, got {len(result)}: {set(result)}"
    )
    for email, (role, dn) in expected.items():
        assert email in result, f"Missing user: {email}"
        assert result[email].role         == role, f"{email}: wrong role {result[email].role!r}"
        assert result[email].display_name == dn,   f"{email}: wrong display_name {result[email].display_name!r}"
        assert result[email].status       == "active", f"{email}: not active"


def test_demo_users_idempotent():
    """Loading the config twice yields identical results — no state mutation."""
    path = _yaml_file(DEMO_USERS_YAML)
    first  = load_role_config(path)
    second = load_role_config(path)
    assert set(first.keys()) == set(second.keys())
    for email in first:
        assert first[email].role   == second[email].role
        assert first[email].status == second[email].status


def test_demo_users_cross_domain_no_duplicate():
    """Same local-part across different domains must not be treated as duplicate."""
    # testuser@example.com and testuser2@example.com must coexist.
    path = _yaml_file(DEMO_USERS_YAML)
    result = load_role_config(path)
    assert "testuser@example.com"  in result
    assert "testuser2@example.com" in result
    # Roles must differ — confirms they're separate entries
    assert result["testuser@example.com"].role  == "authority"
    assert result["testuser2@example.com"].role == "member"


# ---------------------------------------------------------------------------
# T18-T20: validate_cf_config(): mandatory team domain + audience when CF is enabled
# ---------------------------------------------------------------------------
#
# _validate_cf_jwt_inner() disables audience verification entirely when
# CLOUDFLARE_ACCESS_AUD is empty (options={"verify_aud": False}). That is a
# real acceptance gap if CF is enabled without an audience configured:
# any token Cloudflare signed for this team domain, not only this
# application, would pass. CLOUDFLARE_ACCESS_TEAM_DOMAIN is equally required
# for the enabled path (JWKS retrieval and issuer verification both depend
# on it); left unset, it previously surfaced only per-request as a 500
# CF_JWKS_ERROR rather than at startup. validate_cf_config() is the
# fail-closed startup guard for both, called from main.py's lifespan
# alongside validate_hmac_key().

def test_validate_cf_config_cf_disabled_does_not_raise(monkeypatch):
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", False)
    monkeypatch.setattr(cf_identity, "_CF_AUD", "")
    monkeypatch.setattr(cf_identity, "_CF_TEAM_DOMAIN", "")
    validate_cf_config()  # should not raise regardless of AUD/TEAM_DOMAIN


def test_validate_cf_config_cf_enabled_with_both_does_not_raise(monkeypatch):
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", True)
    monkeypatch.setattr(cf_identity, "_CF_AUD", "some-aud-tag")
    monkeypatch.setattr(cf_identity, "_CF_TEAM_DOMAIN", "team.example.com")
    validate_cf_config()  # should not raise


def test_validate_cf_config_cf_enabled_without_aud_raises(monkeypatch):
    """CF enabled, team domain present, audience missing -> startup failure."""
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", True)
    monkeypatch.setattr(cf_identity, "_CF_TEAM_DOMAIN", "team.example.com")
    monkeypatch.setattr(cf_identity, "_CF_AUD", "")
    with pytest.raises(SystemExit, match="CLOUDFLARE_ACCESS_AUD"):
        validate_cf_config()


def test_validate_cf_config_cf_enabled_without_team_domain_raises(monkeypatch):
    """CF enabled, audience present, team domain missing -> startup failure."""
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", True)
    monkeypatch.setattr(cf_identity, "_CF_AUD", "some-aud-tag")
    monkeypatch.setattr(cf_identity, "_CF_TEAM_DOMAIN", "")
    with pytest.raises(SystemExit, match="CLOUDFLARE_ACCESS_TEAM_DOMAIN"):
        validate_cf_config()


def test_validate_cf_config_cf_enabled_without_either_raises_and_names_both(monkeypatch):
    """Both missing -> the single startup failure message names both."""
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", True)
    monkeypatch.setattr(cf_identity, "_CF_AUD", "")
    monkeypatch.setattr(cf_identity, "_CF_TEAM_DOMAIN", "")
    with pytest.raises(SystemExit) as exc_info:
        validate_cf_config()
    message = str(exc_info.value)
    assert "CLOUDFLARE_ACCESS_TEAM_DOMAIN" in message
    assert "CLOUDFLARE_ACCESS_AUD" in message


# ---------------------------------------------------------------------------
# T21-T23: _validate_cf_jwt_inner(): issuer verification
# ---------------------------------------------------------------------------
#
# These build a real RS256-signed JWT and a matching JWK so the actual
# pyjwt.decode() call in cf_identity is exercised, not a mock of it.

def _rsa_keypair_and_jwk(kid: str = "test-kid"):
    """Generate an RSA keypair and the JWK dict cf_identity would fetch
    from Cloudflare's JWKS endpoint for the matching public key.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import jwt as pyjwt

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk["kid"] = kid
    return private_pem, jwk


def _sign_cf_token(private_pem, kid: str, claims: dict) -> str:
    import jwt as pyjwt
    return pyjwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def cf_jwt_fixture(monkeypatch):
    """Wires cf_identity._get_jwk() to a locally generated keypair, and
    sets a fixed team domain / audience, without any network access.
    """
    private_pem, jwk = _rsa_keypair_and_jwk()
    monkeypatch.setattr(cf_identity, "_CF_TEAM_DOMAIN", "team.example.com")
    monkeypatch.setattr(cf_identity, "_CF_AUD", "aud-123")
    monkeypatch.setattr(cf_identity, "_get_jwk", lambda kid: jwk)
    return private_pem


def test_validate_cf_jwt_accepts_correct_issuer_and_audience(cf_jwt_fixture):
    private_pem = cf_jwt_fixture
    token = _sign_cf_token(
        private_pem,
        "test-kid",
        {
            "iss": "https://team.example.com",
            "aud": "aud-123",
            "email": "alice@lrfd.ca",
        },
    )
    email = cf_identity._validate_cf_jwt_inner(token)
    assert email == "alice@lrfd.ca"


def test_validate_cf_jwt_rejects_wrong_issuer(cf_jwt_fixture):
    """A token signed by the same key but for a different team domain
    (a different Cloudflare Access org) must be rejected on issuer, not
    silently accepted because the signature still checks out.
    """
    private_pem = cf_jwt_fixture
    token = _sign_cf_token(
        private_pem,
        "test-kid",
        {
            "iss": "https://a-different-team.cloudflareaccess.com",
            "aud": "aud-123",
            "email": "alice@lrfd.ca",
        },
    )
    from fastapi import HTTPException as FastHTTP
    with pytest.raises(FastHTTP) as exc_info:
        cf_identity._validate_cf_jwt_inner(token)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail["reasonCode"] == "CF_TOKEN_ISS_MISMATCH"


def test_validate_cf_jwt_rejects_wrong_audience(cf_jwt_fixture):
    """Confirms audience is still enforced when CLOUDFLARE_ACCESS_AUD is
    set (this behavior predates this change; kept here alongside the new
    issuer test so both claims have direct coverage in one place).
    """
    private_pem = cf_jwt_fixture
    token = _sign_cf_token(
        private_pem,
        "test-kid",
        {
            "iss": "https://team.example.com",
            "aud": "some-other-application",
            "email": "alice@lrfd.ca",
        },
    )
    from fastapi import HTTPException as FastHTTP
    with pytest.raises(FastHTTP) as exc_info:
        cf_identity._validate_cf_jwt_inner(token)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail["reasonCode"] == "CF_TOKEN_AUD_MISMATCH"


# ---------------------------------------------------------------------------
# T24-T26: get_current_user() gates the CF JWT path on CLOUDFLARE_ACCESS_ENABLED
# ---------------------------------------------------------------------------
#
# Residual case this closes: with CLOUDFLARE_ACCESS_ENABLED=false and
# CLOUDFLARE_ACCESS_AUD unset (both allowed together, since AUD is only
# mandatory while CF is enabled), a correctly-signed token for a DIFFERENT
# Cloudflare Access application -- same team domain, wrong audience -- used
# to authenticate successfully as a real cloudflare_access user, because
# get_current_user() activated the CF path on header presence alone, and
# _validate_cf_jwt_inner() disables audience verification whenever _CF_AUD
# is empty. Reproduced directly against the pre-fix code (see the increment
# report) before writing this test.

class _FakeManagedUser:
    display_name = "Alice"
    role = "authority"
    status = "enabled"
    last_login = None


class _FakeCFUser:
    id = "u-alice"
    email = "alice@lrfd.ca"
    display_name = "Alice"
    assigned_role = "authority"
    status = "enabled"


class _FakeProvisioningDB:
    """Fakes just enough of the DB session for provision_cf_user() to
    succeed: an enabled ManagedUser row and a pre-existing CFUser row.
    """

    def query(self, model):
        import models
        name = getattr(model, "__name__", "")
        if model is models.ManagedUser or name == "ManagedUser":
            return _FakeQueryResult(_FakeManagedUser())
        if model is models.CFUser or name == "CFUser":
            return _FakeQueryResult(_FakeCFUser())
        raise AssertionError(f"Unexpected model queried: {model!r}")

    def commit(self):
        pass

    def refresh(self, obj):
        pass


class _FakeQueryResult:
    def __init__(self, result):
        self._result = result

    def filter(self, *a, **kw):
        return self

    def first(self):
        return self._result


def test_get_current_user_cf_disabled_ignores_cf_header_even_with_valid_signature(
    cf_jwt_fixture, monkeypatch,
):
    """The exact residual case: CF disabled, AUD empty, a correctly-signed
    token for a different application's audience must not authenticate.

    cf_jwt_fixture sets _CF_AUD to a non-empty value by default; override it
    back to empty here, matching the reported configuration
    (CLOUDFLARE_ACCESS_AUD unset is exactly what makes audience checking
    disabled in _validate_cf_jwt_inner when the CF path runs at all).
    """
    private_pem = cf_jwt_fixture
    monkeypatch.setattr(cf_identity, "_CF_AUD", "")
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", False)

    token = _sign_cf_token(
        private_pem,
        "test-kid",
        {
            "iss": "https://team.example.com",
            "aud": "some-completely-different-applications-aud",
            "email": "attacker@lrfd.ca",
        },
    )

    from fastapi import HTTPException as FastHTTP

    with pytest.raises(FastHTTP) as exc_info:
        cf_identity.get_current_user(
            cf_access_jwt_assertion=token,
            authorization=None,
            db=_FakeProvisioningDB(),
        )
    # Falls through to the demo path and is rejected there for lack of a
    # Bearer token -- not authenticated as cloudflare_access.
    assert exc_info.value.status_code == 401


def test_get_current_user_cf_disabled_cf_header_does_not_override_demo_bearer(
    cf_jwt_fixture, monkeypatch,
):
    """A CF header present alongside a valid demo Bearer session must not
    change which path wins: CF disabled means the demo path, full stop.
    """
    private_pem = cf_jwt_fixture
    monkeypatch.setattr(cf_identity, "_CF_AUD", "")
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", False)

    token = _sign_cf_token(
        private_pem,
        "test-kid",
        {
            "iss": "https://team.example.com",
            "aud": "some-completely-different-applications-aud",
            "email": "attacker@lrfd.ca",
        },
    )

    fake_token = "test-token-" + str(uuid.uuid4())

    class FakeSession:
        user_id = "demo-user"
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
        cf_access_jwt_assertion=token,
        authorization=f"Bearer {fake_token}",
        db=FakeDB(),
    )

    assert user.auth_source == "demo_session"
    assert user.email == "demo@lrfd.ca"
    assert user.assigned_role == "member"


def test_get_current_user_cf_enabled_accepts_correct_issuer_and_audience(
    cf_jwt_fixture, monkeypatch,
):
    """End-to-end through get_current_user() (not just _validate_cf_jwt_inner)
    with CF enabled and a token matching the configured issuer and audience.
    """
    private_pem = cf_jwt_fixture
    monkeypatch.setattr(cf_identity, "_CF_ENABLED", True)

    token = _sign_cf_token(
        private_pem,
        "test-kid",
        {
            "iss": "https://team.example.com",
            "aud": "aud-123",
            "email": "alice@lrfd.ca",
        },
    )

    user = cf_identity.get_current_user(
        cf_access_jwt_assertion=token,
        authorization=None,
        db=_FakeProvisioningDB(),
    )

    assert user.auth_source == "cloudflare_access"
    assert user.email == "alice@lrfd.ca"
    assert user.assigned_role == "authority"
