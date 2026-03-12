#!/usr/bin/env python3
"""
ingest_corpus.py — Ingest published corpus files into PostgreSQL FTS.

Run inside the API container via corpus-ingest.sh:
  docker compose exec api python3 /app/ingest_corpus.py

Environment (all inherited from container):
  CORPUS_ROOT       — corpus root path (default: /srv/keystone-corpus)
  TAMPER_DATABASE_URL — DB owner credentials used for writes (preferred)
  DATABASE_URL      — fallback connection string

Reads:   $CORPUS_ROOT/active/
Writes:  corpus_documents + corpus_chunks tables (PostgreSQL)
         Skips files whose sha256 matches what is already stored.
         FAILS (no DB write) if extracted text length is 0.
Stdout:  JSON summary (shell wrapper writes receipt files on host).

Failure rules:
  - EXTRACTION_ERROR  : extraction raised an exception
  - NO_TEXT_EXTRACTED : all extractors ran without error but returned "" — this
                        includes image-only PDFs. Previous good data is preserved.
  In both cases: NO corpus_document row is inserted/updated and NO chunks are
  written. The file will be retried on the next ingest run.
"""

import hashlib
import json
import mimetypes
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2

# ── Configuration ─────────────────────────────────────────────────────────────

# Ingest uses owner credentials so it can DELETE stale chunks on re-ingest.
# keystone_app (runtime role) has SELECT only on corpus tables.
DATABASE_URL = (
    os.environ.get("INGEST_DATABASE_URL")
    or os.environ.get("TAMPER_DATABASE_URL")
    or os.environ.get("DATABASE_URL", "postgresql://keystone:keystone@postgres:5432/keystone")
)

CORPUS_ROOT = Path(os.environ.get("CORPUS_ROOT", "/srv/keystone-corpus"))
ACTIVE_DIR  = CORPUS_ROOT / "active"

CHUNK_SIZE    = 1500   # target characters per chunk
CHUNK_OVERLAP = 150    # overlap between consecutive chunks


# ── Text extraction ───────────────────────────────────────────────────────────

def extract_text_pdf(path: Path) -> str:
    """Try pypdf first; fall back to pdftotext (poppler-utils)."""
    text = ""
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        text = "\n".join(page.extract_text() or "" for page in reader.pages).strip()
    except Exception:
        pass
    if not text:
        try:
            result = subprocess.run(
                ["pdftotext", "-layout", str(path), "-"],
                capture_output=True, text=True, timeout=60,
            )
            text = result.stdout.strip()
        except Exception:
            pass
    return text


def extract_text_docx(path: Path) -> str:
    try:
        from docx import Document
        doc = Document(str(path))
        return "\n".join(p.text for p in doc.paragraphs).strip()
    except Exception:
        return ""


def extract_text(path: Path, mime: str) -> str:
    if mime == "application/pdf":
        return extract_text_pdf(path)
    if mime in (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/msword",
    ):
        return extract_text_docx(path)
    if mime and mime.startswith("text/"):
        return path.read_text(errors="replace")
    return ""


def mime_for(path: Path) -> str:
    mt, _ = mimetypes.guess_type(str(path))
    return mt or "application/octet-stream"


# ── Chunking ──────────────────────────────────────────────────────────────────

def chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    if not text:
        return []
    chunks, start = [], 0
    while start < len(text):
        chunks.append(text[start : start + size])
        start += size - overlap
    return chunks


# ── SHA-256 ───────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    if not ACTIVE_DIR.exists():
        print(json.dumps({"error": f"active/ not found: {ACTIVE_DIR}"}))
        sys.exit(1)

    conn = psycopg2.connect(DATABASE_URL)
    cur  = conn.cursor()

    stats: dict = {"added": 0, "updated": 0, "skipped": 0, "failed": 0, "docs": []}

    files = sorted(
        p for p in ACTIVE_DIR.rglob("*")
        if p.is_file() and not p.name.startswith(".")
    )

    for fpath in files:
        rel   = str(fpath.relative_to(ACTIVE_DIR))
        mime  = mime_for(fpath)
        sha   = sha256_file(fpath)
        stat  = fpath.stat()
        size  = stat.st_size
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        title = fpath.stem.replace("_", " ").replace("-", " ")

        # ── Check existing record ──────────────────────────────────────────────
        cur.execute("SELECT id, sha256 FROM corpus_documents WHERE rel_path = %s", (rel,))
        row = cur.fetchone()

        if row:
            doc_id, stored_sha = row
            if stored_sha == sha:
                stats["skipped"] += 1
                stats["docs"].append({"rel_path": rel, "action": "skipped"})
                continue
            action = "updated"
        else:
            doc_id = None
            action = "added"

        # ── Extract text BEFORE touching the DB ───────────────────────────────
        # This guarantees that if extraction fails, the previous good version
        # in the DB is never touched.

        try:
            text = extract_text(fpath, mime)
        except Exception as exc:
            stats["failed"] += 1
            stats["docs"].append({
                "rel_path": rel,
                "action":   "failed",
                "reason":   "EXTRACTION_ERROR",
                "error":    str(exc),
            })
            print(f"  WARN [{rel}] EXTRACTION_ERROR: {exc}", file=sys.stderr)
            continue

        if not text:
            # Image-only PDF, encrypted doc, or unsupported format.
            # Do NOT write placeholder chunks — that poisons FTS with noise.
            # Do NOT overwrite a previously ingested good version.
            stats["failed"] += 1
            stats["docs"].append({
                "rel_path": rel,
                "action":   "failed",
                "reason":   "NO_TEXT_EXTRACTED",
            })
            print(f"  WARN [{rel}] NO_TEXT_EXTRACTED — skipping DB write", file=sys.stderr)
            continue

        # ── Write to DB only after confirmed good text ────────────────────────

        chunks = chunk_text(text)

        if action == "updated":
            # doc_id is set (row existed); clear stale chunks first.
            cur.execute("DELETE FROM corpus_chunks WHERE doc_id = %s", (doc_id,))
            cur.execute(
                """UPDATE corpus_documents
                      SET sha256=%s, size_bytes=%s, mtime_utc=%s, mime=%s, title=%s
                    WHERE id=%s""",
                (sha, size, mtime, mime, title, doc_id),
            )
        else:
            cur.execute(
                """INSERT INTO corpus_documents (rel_path, sha256, size_bytes, mtime_utc, mime, title)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (rel, sha, size, mtime, mime, title),
            )
            doc_id = cur.fetchone()[0]

        for idx, chunk in enumerate(chunks):
            cur.execute(
                """INSERT INTO corpus_chunks (doc_id, chunk_index, text)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (doc_id, chunk_index) DO UPDATE SET text = EXCLUDED.text""",
                (doc_id, idx, chunk),
            )

        conn.commit()

        if action == "added":
            stats["added"] += 1
        else:
            stats["updated"] += 1

        stats["docs"].append({
            "rel_path": rel,
            "action":   action,
            "chunks":   len(chunks),
            "chars":    len(text),
        })

    cur.close()
    conn.close()

    if stats["failed"] > 0:
        failed_paths = [
            f'  {d["rel_path"]} ({d.get("reason","?")})'
            for d in stats["docs"] if d.get("action") == "failed"
        ]
        print(
            f"  WARNING: {stats['failed']} doc(s) produced no extractable text "
            f"and were NOT ingested:\n" + "\n".join(failed_paths),
            file=sys.stderr,
        )

    print(json.dumps(stats))


if __name__ == "__main__":
    main()
