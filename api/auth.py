import hashlib
import hmac
import os

_ITERATIONS = 260_000


def _salt() -> bytes:
    # Production: set AUTH_PASSWORD_SALT to a 32+ character random value.
    # All existing password hashes are invalidated if this value changes.
    # Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
    return os.environ.get("AUTH_PASSWORD_SALT", "dev-salt-change-me").encode()


def hash_password(password: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), _salt(), _ITERATIONS)
    return dk.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password), stored_hash)
