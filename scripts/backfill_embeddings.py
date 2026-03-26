#!/usr/bin/env python3
"""
Backfill Ollama embeddings for corpus_chunks rows where embedding IS NULL.

Usage:
    python backfill_embeddings.py

Reads POSTGRES_PASSWORD from ~/keystone/keystone-dev/.env.
Connects to keystone_dev on localhost:5434.
Calls Ollama nomic-embed-text:latest at http://172.17.0.1:11434.
"""

import json
import os
import time
import urllib.request
import urllib.error

import psycopg2

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
ENV_FILE = os.path.expanduser("~/keystone/keystone-dev/.env")
DB_HOST = "localhost"
DB_PORT = 5434
DB_NAME = "keystone_dev"
DB_USER = "keystone"

OLLAMA_URL = "http://172.17.0.1:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text:latest"
BATCH_SIZE = 100


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_env(path: str) -> dict:
    """Parse a KEY=VALUE .env file and return a dict."""
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()
    return env


def get_embedding(text: str) -> list[float] | None:
    """Call Ollama embed endpoint. Returns a list of floats or None on error."""
    payload = json.dumps({"model": EMBED_MODEL, "prompt": text}).encode()
    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read())
            embedding = body.get("embedding")
            if not embedding:
                return None
            return embedding
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        print(f"  [warn] Ollama request failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # Read password
    env = load_env(ENV_FILE)
    password = env.get("POSTGRES_PASSWORD")
    if not password:
        raise SystemExit(
            f"POSTGRES_PASSWORD not found in {ENV_FILE}.\n"
            "Add it as:  POSTGRES_PASSWORD=<your-password>"
        )

    # Connect
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=password,
    )
    conn.autocommit = False

    with conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, text FROM corpus_chunks WHERE embedding IS NULL ORDER BY id"
            )
            rows = cur.fetchall()

    total = len(rows)
    if total == 0:
        print("No chunks with NULL embeddings found. Nothing to do.")
        conn.close()
        return

    print(f"Found {total} chunks to embed.")

    skipped = []
    start = time.monotonic()

    with conn:
        with conn.cursor() as cur:
            for i, (chunk_id, text) in enumerate(rows, start=1):
                embedding = get_embedding(text or "")

                if embedding is None:
                    print(f"  [skip] chunk id={chunk_id} — Ollama returned no embedding")
                    skipped.append(chunk_id)
                    continue

                # pgvector expects a list; psycopg2 will stringify it
                cur.execute(
                    "UPDATE corpus_chunks SET embedding = %s WHERE id = %s",
                    (embedding, chunk_id),
                )

                if i % BATCH_SIZE == 0:
                    conn.commit()
                    elapsed = time.monotonic() - start
                    pct = i / total * 100
                    rate = i / elapsed if elapsed > 0 else 0
                    eta = (total - i) / rate if rate > 0 else 0
                    print(
                        f"Embedded {i}/{total} ({pct:.1f}%) "
                        f"— {elapsed:.0f}s elapsed, ~{eta:.0f}s remaining"
                    )

            # Final partial batch
            conn.commit()

    elapsed = time.monotonic() - start
    done = total - len(skipped)
    print(f"\nDone. Embedded {done}/{total} chunks in {elapsed:.1f}s.")

    if skipped:
        print(f"Skipped {len(skipped)} chunk(s) due to Ollama errors: {skipped}")

    print("\nVerification query:")
    print("  SELECT COUNT(*) AS embedded FROM corpus_chunks WHERE embedding IS NOT NULL;")
    print(f"Expected: ~{done}")

    conn.close()


if __name__ == "__main__":
    main()
