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

Failure reasons (stable enums):
  EXTRACTION_ERROR  : extraction raised an exception
  NO_TEXT_EXTRACTED : supported type, all extractors ran without error but returned ""
  UNSUPPORTED_TYPE  : mime type is not handled by any extractor

Behavior rules:
  - New doc, empty/error extract: failed_docs entry written, NO DB rows.
  - Existing doc, sha changed, extract empty/error: skipped_keep_previous,
    old DB rows preserved, kept_previous_docs entry written.
  - Existing doc, sha changed, extract non-empty: replace chunks, update doc.
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

# ── Supported MIME types ───────────────────────────────────────────────────────

_SUPPORTED_MIMES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
}


def is_supported_mime(mime: str) -> bool:
    """Return True if we have an extractor for this mime type."""
    return mime in _SUPPORTED_MIMES or bool(mime and mime.startswith("text/"))


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


_EXT_MIME_OVERRIDES: dict[str, str] = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".docm": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc":  "application/msword",
    ".pdf":  "application/pdf",
    ".txt":  "text/plain",
    ".md":   "text/markdown",
    ".rst":  "text/x-rst",
}


def mime_for(path: Path) -> str:
    """Guess MIME type; use explicit extension fallbacks when stdlib mimetypes DB is incomplete."""
    suffix = path.suffix.lower()
    if suffix in _EXT_MIME_OVERRIDES:
        return _EXT_MIME_OVERRIDES[suffix]
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

    stats: dict = {
        "added": 0, "updated": 0, "skipped": 0,
        "skipped_keep_previous": 0, "failed": 0,
        "docs": [],
        "failed_docs": [],
        "kept_previous_docs": [],
    }

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

        # ── Unsupported mime type — no extractor available ────────────────────
        if not is_supported_mime(mime):
            reason = "UNSUPPORTED_TYPE"
            detail = f"mime={mime}"
            if action == "updated":
                stats["skipped_keep_previous"] += 1
                stats["docs"].append({
                    "rel_path": rel,
                    "action":   "skipped_keep_previous",
                    "reason":   reason,
                    "detail":   detail,
                })
                stats["kept_previous_docs"].append({"rel_path": rel, "reason": reason, "detail": detail})
                print(
                    f"  WARN [{rel}] UNSUPPORTED_TYPE (sha changed, mime={mime}) — "
                    f"preserving previous DB version",
                    file=sys.stderr,
                )
            else:
                stats["failed"] += 1
                stats["docs"].append({"rel_path": rel, "action": "failed", "reason": reason, "detail": detail})
                stats["failed_docs"].append({"rel_path": rel, "reason": reason, "detail": detail})
                print(f"  WARN [{rel}] UNSUPPORTED_TYPE mime={mime} — skipping DB write", file=sys.stderr)
            continue

        # ── Extract text BEFORE touching the DB ───────────────────────────────
        # This guarantees that if extraction fails, the previous good version
        # in the DB is never touched.

        try:
            text = extract_text(fpath, mime)
        except Exception as exc:
            reason = "EXTRACTION_ERROR"
            detail = str(exc)
            if action == "updated":
                stats["skipped_keep_previous"] += 1
                stats["docs"].append({
                    "rel_path": rel,
                    "action":   "skipped_keep_previous",
                    "reason":   reason,
                    "detail":   detail,
                })
                stats["kept_previous_docs"].append({"rel_path": rel, "reason": reason, "detail": detail})
                print(
                    f"  WARN [{rel}] EXTRACTION_ERROR (sha changed) — "
                    f"preserving previous DB version: {exc}",
                    file=sys.stderr,
                )
            else:
                stats["failed"] += 1
                stats["docs"].append({"rel_path": rel, "action": "failed", "reason": reason, "detail": detail})
                stats["failed_docs"].append({"rel_path": rel, "reason": reason, "detail": detail})
                print(f"  WARN [{rel}] EXTRACTION_ERROR: {exc}", file=sys.stderr)
            continue

        if not text:
            # Image-only PDF, encrypted doc, or supported format with no extractable content.
            # Do NOT write placeholder chunks — that poisons FTS with noise.
            reason = "NO_TEXT_EXTRACTED"
            if action == "updated":
                # A previous good version exists in the DB. Keep it intact.
                stats["skipped_keep_previous"] += 1
                stats["docs"].append({
                    "rel_path": rel,
                    "action":   "skipped_keep_previous",
                    "reason":   reason,
                    "warning":  "file sha256 changed but new extraction returned empty; previous DB version preserved",
                })
                stats["kept_previous_docs"].append({"rel_path": rel, "reason": reason})
                print(
                    f"  WARN [{rel}] NO_TEXT_EXTRACTED (sha changed) — "
                    f"preserving previous DB version",
                    file=sys.stderr,
                )
            else:
                # New doc, no text, nothing to fall back on.
                stats["failed"] += 1
                stats["docs"].append({"rel_path": rel, "action": "failed", "reason": reason})
                stats["failed_docs"].append({"rel_path": rel, "reason": reason})
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
        failed_lines = [
            f'  {d["rel_path"]} ({d.get("reason","?")})'
            for d in stats["failed_docs"]
        ]
        print(
            f"  WARNING: {stats['failed']} new doc(s) produced no extractable text "
            f"and were NOT ingested:\n" + "\n".join(failed_lines),
            file=sys.stderr,
        )
    if stats["skipped_keep_previous"] > 0:
        skp_lines = [
            f'  {d["rel_path"]} ({d.get("reason","?")})'
            for d in stats["kept_previous_docs"]
        ]
        print(
            f"  WARNING: {stats['skipped_keep_previous']} doc(s) had sha256 changes "
            f"but empty/errored extraction; previous DB version preserved:\n" + "\n".join(skp_lines),
            file=sys.stderr,
        )

    print(json.dumps(stats))


if __name__ == "__main__":
    main()
