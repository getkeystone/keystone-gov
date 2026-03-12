import hashlib
import hmac
import os

_ITERATIONS = 260_000


def _salt() -> bytes:
    return os.environ.get("AUTH_PASSWORD_SALT", "dev-salt-change-me").encode()


def hash_password(password: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), _salt(), _ITERATIONS)
    return dk.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password), stored_hash)
