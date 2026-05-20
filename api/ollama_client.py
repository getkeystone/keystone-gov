"""
Ollama integration for Keystone AI.

Provides embedding generation, answer synthesis, and health
checking against a local Ollama instance. All calls are
synchronous with explicit timeouts. Failures return None --
the governance layer decides whether to fail closed or fall
back to FTS-only.

Environment variables:
  OLLAMA_URL            Base URL (default: http://host.docker.internal:11434)
  OLLAMA_EMBED_MODEL    Embedding model (default: nomic-embed-text:latest)
  OLLAMA_GEN_MODEL      Generation model (default: qwen2.5:7b-instruct)
  OLLAMA_EMBED_TIMEOUT  Embedding timeout seconds (default: 15)
  OLLAMA_GEN_TIMEOUT    Generation timeout seconds (default: 45)
"""
import json
import logging
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

log = logging.getLogger("keystone.ollama")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://host.docker.internal:11434")
EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text:latest")
GEN_MODEL = os.environ.get("OLLAMA_GEN_MODEL", "qwen2.5:7b-instruct")
EMBED_TIMEOUT = float(os.environ.get("OLLAMA_EMBED_TIMEOUT", "15"))
GEN_TIMEOUT = float(os.environ.get("OLLAMA_GEN_TIMEOUT", "45"))


def _post(path: str, body: dict, timeout: float) -> dict | None:
    """POST JSON to Ollama. Returns parsed response or None on failure."""
    try:
        data = json.dumps(body).encode("utf-8")
        req = Request(
            f"{OLLAMA_URL}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        resp = urlopen(req, timeout=timeout)
        return json.loads(resp.read())
    except (URLError, HTTPError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        log.warning("Ollama %s failed: %s", path, exc)
        return None


def embed(text: str) -> list[float] | None:
    """Generate embedding vector. Returns list of floats or None on failure."""
    result = _post("/api/embeddings", {"model": EMBED_MODEL, "prompt": text}, EMBED_TIMEOUT)
    if result is None:
        return None
    emb = result.get("embedding")
    if not emb or not isinstance(emb, list):
        log.warning("Ollama embed returned invalid embedding")
        return None
    return emb


def generate(system_prompt: str, user_prompt: str) -> str | None:
    """Generate text from evidence. Returns string or None on failure."""
    result = _post("/api/generate", {
        "model": GEN_MODEL,
        "system": system_prompt,
        "prompt": user_prompt,
        "stream": False,
    }, GEN_TIMEOUT)
    if result is None:
        return None
    text = result.get("response", "").strip()
    return text if text else None


def generate_json(system_prompt: str, user_prompt: str) -> dict | None:
    """Generate a structured JSON response. Returns parsed dict or None on failure."""
    result = _post("/api/generate", {
        "model": GEN_MODEL,
        "system": system_prompt,
        "prompt": user_prompt,
        "stream": False,
        "format": "json",
    }, GEN_TIMEOUT)
    if result is None:
        return None
    raw = result.get("response", "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        log.warning("generate_json: failed to parse response: %s", exc)
        return None


def healthy() -> dict:
    """Check Ollama reachability and model availability.
    Returns a dict for the /health endpoint."""
    try:
        req = Request(f"{OLLAMA_URL}/api/tags")
        resp = urlopen(req, timeout=5)
        data = json.loads(resp.read())
        models = {m["name"] for m in data.get("models", [])}
        embed_ok = EMBED_MODEL in models
        gen_ok = GEN_MODEL in models
        return {
            "ollama_reachable": True,
            "embed_model": EMBED_MODEL,
            "embed_model_loaded": embed_ok,
            "gen_model": GEN_MODEL,
            "gen_model_loaded": gen_ok,
            "ollama_url": OLLAMA_URL,
        }
    except Exception as exc:
        log.warning("Ollama health check failed: %s", exc)
        return {
            "ollama_reachable": False,
            "embed_model": EMBED_MODEL,
            "embed_model_loaded": False,
            "gen_model": GEN_MODEL,
            "gen_model_loaded": False,
            "ollama_url": OLLAMA_URL,
        }
