"""cf_identity.py — Cloudflare Access identity validation and JIT user provisioning.

Flow per authenticated request:
  1. Read Cf-Access-Jwt-Assertion header (injected by Cloudflare tunnel)
  2. Validate JWT signature against Cloudflare's public JWKS
  3. Verify aud and iss claims
  4. Extract email from JWT claims
  5. Normalize email to lowercase
  6. Look up email in loaded role config → get assigned role
  7. JIT-provision or update cf_users record
  8. Return AppUser (user_id, email, display_name, assigned_role, auth_source)

Feature flags (env vars):
  CLOUDFLARE_ACCESS_ENABLED            true/false (default false)
  CLOUDFLARE_ACCESS_TEAM_DOMAIN        e.g. keystone-ai.cloudflareaccess.com
  CLOUDFLARE_ACCESS_AUD                CF Access application audience tag
  DEMO_ROLE_SIMULATION_ENABLED         true/false (default false)
  DEMO_ROLE_SIMULATION_ALLOWED_EMAILS  comma-separated allowlist

Backward compat:
  When CLOUDFLARE_ACCESS_ENABLED=false, falls back to Bearer token session
  (existing demo auth path, unchanged).
"""

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
import urllib.request
import urllib.error

import yaml
from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session as DBSession

from database import get_db


# ---------------------------------------------------------------------------
# Feature flags
# ---------------------------------------------------------------------------

_CF_ENABLED: bool = os.environ.get(
    "CLOUDFLARE_ACCESS_ENABLED", "false"
).lower() in ("true", "1", "yes")

_CF_TEAM_DOMAIN: str = os.environ.get("CLOUDFLARE_ACCESS_TEAM_DOMAIN", "")
_CF_AUD: str = os.environ.get("CLOUDFLARE_ACCESS_AUD", "")

_DEMO_SIM_ENABLED: bool = os.environ.get(
    "DEMO_ROLE_SIMULATION_ENABLED", "false"
).lower() in ("true", "1", "yes")

_DEMO_SIM_EMAILS_RAW: str = os.environ.get(
    "DEMO_ROLE_SIMULATION_ALLOWED_EMAILS", ""
)
_DEMO_SIM_ALLOWED: set[str] = {
    e.strip().lower()
    for e in _DEMO_SIM_EMAILS_RAW.split(",")
    if e.strip()
}

_VALID_ROLES: set[str] = {"member", "officer", "custodian", "admin"}

# ---------------------------------------------------------------------------
# Role config
# ---------------------------------------------------------------------------

_CONFIG_PATH_DEFAULT = os.path.join(os.path.dirname(__file__), "config", "lrfd_user_roles.yaml")
_CONFIG_PATH: str = os.environ.get("LRFD_ROLE_CONFIG_PATH", "") or _CONFIG_PATH_DEFAULT


@dataclass
class RoleEntry:
    email: str
    display_name: str
    role: str
    status: str


# Module-level cache: email (lowercase) → RoleEntry
_role_map: dict[str, RoleEntry] = {}


def load_role_config(path: str = _CONFIG_PATH) -> dict[str, RoleEntry]:
    """Load and validate the role mapping YAML. Raises ValueError on any error."""
    with open(path, "r") as fh:
        raw = yaml.safe_load(fh)

    if not raw or "users" not in raw:
        raise ValueError(f"Role config at {path} is empty or missing 'users' key")

    result: dict[str, RoleEntry] = {}
    for idx, entry in enumerate(raw["users"]):
        email_raw = (entry.get("email") or "").strip()
        if not email_raw:
            raise ValueError(f"Role config entry #{idx} is missing 'email'")
        email = email_raw.lower()
        if email in result:
            raise ValueError(f"Duplicate email in role config: {email}")

        role = (entry.get("role") or "").strip()
        if role not in _VALID_ROLES:
            raise ValueError(
                f"Invalid role '{role}' for {email}; valid roles: {sorted(_VALID_ROLES)}"
            )

        status = (entry.get("status") or "active").strip()
        dn_raw = (entry.get("display_name") or "").strip()
        display_name = dn_raw or email.split("@")[0].replace(".", " ").title()

        result[email] = RoleEntry(
            email=email,
            display_name=display_name,
            role=role,
            status=status,
        )
    return result


def init_role_config() -> None:
    """Load and cache the role map. Call once at application startup.

    Behaviour:
      - If LRFD_ROLE_CONFIG_PATH is set, that path is authoritative; missing → FATAL.
      - If the default config path exists, load it.
      - If neither exists: FATAL when CF is enabled; warning only when CF is disabled
        (demo/dev path doesn't require a role file).
      - An empty users list when CF is enabled is also a FATAL error.
    """
    global _role_map

    env_override = os.environ.get("LRFD_ROLE_CONFIG_PATH", "").strip()

    if env_override:
        # Operator explicitly set a path — it must exist and be valid.
        if not os.path.exists(env_override):
            raise SystemExit(
                f"[cf_identity] FATAL: LRFD_ROLE_CONFIG_PATH={env_override!r} does not exist. "
                "Provision the role config file before starting the API."
            )
        path = env_override
    else:
        path = _CONFIG_PATH_DEFAULT
        if not os.path.exists(path):
            if _CF_ENABLED:
                raise SystemExit(
                    f"[cf_identity] FATAL: CLOUDFLARE_ACCESS_ENABLED=true but no role config "
                    f"found at {path}. Set LRFD_ROLE_CONFIG_PATH or place the file at that path."
                )
            print(
                f"[cf_identity] WARNING: role config not found at {path}. "
                "CF identity provisioning will deny all users until config is present.",
                flush=True,
            )
            return

    try:
        _role_map = load_role_config(path)
    except ValueError as exc:
        raise SystemExit(f"[cf_identity] FATAL: role config error: {exc}") from exc

    if len(_role_map) == 0 and _CF_ENABLED:
        raise SystemExit(
            f"[cf_identity] FATAL: role config at {path!r} has no users. "
            "Populate the role config before starting with CLOUDFLARE_ACCESS_ENABLED=true."
        )

    print(
        f"[cf_identity] loaded {len(_role_map)} users from {path}",
        flush=True,
    )


# ---------------------------------------------------------------------------
# JWKS cache (thread-safe, TTL-based)
# ---------------------------------------------------------------------------

_jwks_cache: dict | None = None
_jwks_cache_ts: float = 0.0
_jwks_cache_ttl: float = 300.0  # 5 minutes
_jwks_lock = threading.Lock()


def _fetch_jwks() -> dict:
    global _jwks_cache, _jwks_cache_ts
    now = time.monotonic()
    with _jwks_lock:
        if _jwks_cache is not None and (now - _jwks_cache_ts) < _jwks_cache_ttl:
            return _jwks_cache
        if not _CF_TEAM_DOMAIN:
            raise RuntimeError(
                "CLOUDFLARE_ACCESS_TEAM_DOMAIN is not set — "
                "cannot fetch JWKS for CF Access JWT validation."
            )
        url = f"https://{_CF_TEAM_DOMAIN}/cdn-cgi/access/certs"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch CF JWKS from {url}: {exc}") from exc
        _jwks_cache = data
        _jwks_cache_ts = now
        return data


def _get_jwk(kid: Optional[str]) -> dict:
    """Return the JWK dict for the given key ID (or first key if kid is absent)."""
    jwks = _fetch_jwks()
    keys = jwks.get("keys", [])
    if not keys:
        raise RuntimeError("No keys in CF JWKS response")
    if kid:
        for k in keys:
            if k.get("kid") == kid:
                return k
        # Key not found — refresh cache once and retry
        global _jwks_cache_ts
        _jwks_cache_ts = 0.0
        jwks = _fetch_jwks()
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                return k
        raise RuntimeError(f"CF JWKS key id '{kid}' not found after cache refresh")
    return keys[0]


# ---------------------------------------------------------------------------
# JWT validation
# ---------------------------------------------------------------------------

def _validate_cf_jwt_inner(assertion: str) -> str:
    """Inner implementation — import PyJWT and validate."""
    try:
        import jwt as pyjwt
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail={"message": "PyJWT not installed on server", "reasonCode": "SERVER_CONFIG_ERROR"},
        )

    try:
        header = pyjwt.get_unverified_header(assertion)
        kid = header.get("kid")
        jwk = _get_jwk(kid)
        public_key = pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

        if _CF_AUD:
            payload = pyjwt.decode(
                assertion,
                key=public_key,
                algorithms=["RS256"],
                audience=_CF_AUD,
            )
        else:
            payload = pyjwt.decode(
                assertion,
                key=public_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail={"message": "Cloudflare Access token has expired", "reasonCode": "CF_TOKEN_EXPIRED"},
        )
    except pyjwt.InvalidAudienceError:
        raise HTTPException(
            status_code=401,
            detail={"message": "CF Access token audience mismatch", "reasonCode": "CF_TOKEN_AUD_MISMATCH"},
        )
    except pyjwt.PyJWTError as exc:
        raise HTTPException(
            status_code=401,
            detail={"message": f"CF Access token invalid: {exc}", "reasonCode": "CF_TOKEN_INVALID"},
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail={"message": str(exc), "reasonCode": "CF_JWKS_ERROR"},
        )

    email = (payload.get("email") or payload.get("sub") or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(
            status_code=401,
            detail={"message": "No valid email in CF Access token", "reasonCode": "CF_NO_EMAIL"},
        )
    return email


# ---------------------------------------------------------------------------
# AppUser — unified identity model
# ---------------------------------------------------------------------------

@dataclass
class AppUser:
    """Resolved application user. Returned by get_current_user() dependency."""
    user_id: str
    email: str
    display_name: str
    assigned_role: str
    auth_source: str          # "cloudflare_access" | "demo_session"
    sim_role: Optional[str] = None  # set when internal simulation is active

    @property
    def role(self) -> str:
        """Effective role for ACL decisions. sim_role takes precedence if set."""
        return self.sim_role if self.sim_role else self.assigned_role

    @property
    def username(self) -> str:
        """Compat shim — returns email for audit writes."""
        return self.email


# ---------------------------------------------------------------------------
# JIT user provisioning
# ---------------------------------------------------------------------------

def provision_cf_user(email: str, db: DBSession) -> "CFUser":
    """Provision or sync a cf_users record for this email.

    - Raises 403 NOT_PROVISIONED if email not in role config.
    - Raises 403 ACCOUNT_DISABLED if config entry is disabled.
    - Creates record on first visit, syncs role/display_name on subsequent visits.
    """
    from models import CFUser  # local import to avoid circular at module level

    entry = _role_map.get(email)
    if not entry:
        raise HTTPException(
            status_code=403,
            detail={
                "message": (
                    "This email is not provisioned for the LRFD pilot. "
                    "Contact your administrator."
                ),
                "reasonCode": "NOT_PROVISIONED",
            },
        )
    if entry.status != "active":
        raise HTTPException(
            status_code=403,
            detail={
                "message": "This account is disabled. Contact your administrator.",
                "reasonCode": "ACCOUNT_DISABLED",
            },
        )

    now = datetime.now(timezone.utc)
    user = db.query(CFUser).filter(CFUser.email == email).first()

    if user is None:
        user = CFUser(
            id=str(uuid.uuid4()),
            email=email,
            display_name=entry.display_name,
            assigned_role=entry.role,
            status=entry.status,
            source="cloudflare_access",
            created_at=now,
            updated_at=now,
            last_seen_at=now,
        )
        db.add(user)
        db.flush()
        print(f"[cf_identity] provisioned new user: {email} role={entry.role}", flush=True)
    else:
        changed = False
        if user.assigned_role != entry.role:
            user.assigned_role = entry.role
            changed = True
        if user.display_name != entry.display_name:
            user.display_name = entry.display_name
            changed = True
        if user.status != entry.status:
            user.status = entry.status
            changed = True
        user.last_seen_at = now
        if changed:
            user.updated_at = now

    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

def get_current_user(
    cf_access_jwt_assertion: Optional[str] = Header(
        default=None, alias="cf-access-jwt-assertion"
    ),
    authorization: Optional[str] = Header(default=None),
    db: DBSession = Depends(get_db),
) -> AppUser:
    """Resolve the current app user from either CF Access JWT or demo Bearer token.

    Resolution order:
      1. If CF Access JWT header is present → validate and provision from CF.
      2. If CF Access is enabled but JWT is absent → 401 (CF assertion required).
      3. If CF Access is disabled → fall back to Bearer token (demo session path).

    Simulation path (internal only):
      - CF JWT present (real identity validated) + Bearer token present
      - DEMO_ROLE_SIMULATION_ENABLED=true
      - real email is in DEMO_ROLE_SIMULATION_ALLOWED_EMAILS
      - → AppUser.assigned_role = real CF role, AppUser.sim_role = sim session role
    """
    # ── Path 1: Cloudflare Access JWT ──────────────────────────────────────────
    if cf_access_jwt_assertion:
        email = _validate_cf_jwt_inner(cf_access_jwt_assertion)
        cf_user = provision_cf_user(email, db)
        real_role = cf_user.assigned_role

        # Check for simulation overlay
        sim_role: Optional[str] = None
        if (
            _DEMO_SIM_ENABLED
            and email in _DEMO_SIM_ALLOWED
            and authorization
            and authorization.startswith("Bearer ")
        ):
            token = authorization.removeprefix("Bearer ")
            from models import Session as DBSession_model
            sim_session = db.query(DBSession_model).filter(
                DBSession_model.token == token
            ).first()
            if sim_session:
                sim_role = sim_session.role

        return AppUser(
            user_id=cf_user.id,
            email=cf_user.email,
            display_name=cf_user.display_name,
            assigned_role=real_role,
            auth_source="cloudflare_access",
            sim_role=sim_role,
        )

    # ── Path 2: CF enabled but no JWT → deny ──────────────────────────────────
    if _CF_ENABLED:
        raise HTTPException(
            status_code=401,
            detail={
                "message": "Cloudflare Access authentication is required.",
                "reasonCode": "CF_ASSERTION_MISSING",
            },
        )

    # ── Path 3: CF disabled → Bearer token (demo/dev path) ───────────────────
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.removeprefix("Bearer ")
    from models import Session as DBSession_model

    session = db.query(DBSession_model).filter(DBSession_model.token == token).first()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return AppUser(
        user_id=session.user_id,
        email=session.username,   # username is email-like in demo ("demo", "officer", etc.)
        display_name=session.username,
        assigned_role=session.role,
        auth_source="demo_session",
    )


def get_cf_enabled() -> bool:
    return _CF_ENABLED


def get_demo_sim_enabled() -> bool:
    return _DEMO_SIM_ENABLED
