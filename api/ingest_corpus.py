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
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2

# ── Domain auto-detection ─────────────────────────────────────────────────────
# Applied when the metadata sidecar does not set an explicit "domain" key.
# Matches filename stems / titles that are clearly medical/EMR in nature.

_MEDICAL_EMR_SIGNALS = re.compile(
    r'\b(?:cpr|first[\s\-]?aid|emr|emt|paramedic|medical|patient'
    r'|aed|defibrillat|emergency\s+care|emergency\s+medical'
    r'|vital\s+sign|bandage|airway|resuscitat|triage)\b',
    re.IGNORECASE,
)

_LRFD_SIGNALS = re.compile(
    r'\b(?:lrfd|structural[\s\-]?protocol|load[\s\-]?bearing|roof[\s\-]?load'
    r'|floor[\s\-]?collapse|structural[\s\-]?triage|collapse[\s\-]?zone'
    r'|truss[\s\-]?assessment|parapet|bowstring|i[\s\-]?joist)\b',
    re.IGNORECASE,
)

_VALID_DOMAINS = frozenset({"fire_ops", "medical_emr", "lrfd_protocol"})

_VALID_CONTENT_KINDS = frozenset({"procedure", "requirements", "reference"})


def _infer_domain(rel_path: str, title: str) -> str:
    """Return domain inferred from filename/title; medical_emr checked first, then lrfd_protocol."""
    stem = Path(rel_path).stem.lower().replace("_", " ").replace("-", " ")
    title_lower = title.lower()
    if _MEDICAL_EMR_SIGNALS.search(stem) or _MEDICAL_EMR_SIGNALS.search(title_lower):
        return "medical_emr"
    if _LRFD_SIGNALS.search(stem) or _LRFD_SIGNALS.search(title_lower):
        return "lrfd_protocol"
    return "fire_ops"

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

def _extract_pdf_by_page(path: Path) -> list[tuple[int, str]]:
    """
    Extract text per page from a PDF using pypdf.

    Returns a list of (page_num_1based, text) for pages that have extractable
    text.  Returns an empty list if pypdf is unavailable, raises, or yields no
    text on any page (image-only / encrypted PDF).
    """
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        result = []
        for i, pg in enumerate(reader.pages):
            t = (pg.extract_text() or "").strip()
            if t:
                result.append((i + 1, t))
        return result
    except Exception:
        return []


def extract_text_pdf(path: Path) -> str:
    """Full-document PDF extraction (whole text, no page tracking).

    Used as a fallback when pypdf per-page extraction yields nothing.
    Tries pdftotext (poppler-utils) only; pypdf whole-doc is skipped here
    because if it failed per-page it will fail again.
    """
    try:
        result = subprocess.run(
            ["pdftotext", "-layout", str(path), "-"],
            capture_output=True, text=True, timeout=60,
        )
        return result.stdout.strip()
    except Exception:
        return ""


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
        "added": 0, "updated": 0, "updated_metadata": 0,
        "skipped": 0, "skipped_keep_previous": 0, "failed": 0,
        "docs": [],
        "failed_docs": [],
        "kept_previous_docs": [],
    }

    files = sorted(
        p for p in ACTIVE_DIR.rglob("*")
        if p.is_file() and not p.name.startswith(".")
    )

    for fpath in files:
        # Skip metadata sidecar files — they are read as part of the parent doc.
        if fpath.name.endswith(".metadata.json"):
            continue

        rel   = str(fpath.relative_to(ACTIVE_DIR))
        mime  = mime_for(fpath)
        sha   = sha256_file(fpath)
        stat  = fpath.stat()
        size  = stat.st_size
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        title = fpath.stem.replace("_", " ").replace("-", " ")

        # ── Read optional metadata sidecar ────────────────────────────────────
        # Convention: <filename>.metadata.json  (e.g. report.pdf.metadata.json)
        meta_owner:        str = ""
        meta_eff:          str = ""
        meta_rev:          str = ""
        meta_status:       str = ""
        meta_domain:       str = ""
        meta_content_kind: str = ""
        meta_path = Path(str(fpath) + ".metadata.json")
        if meta_path.exists():
            try:
                _meta = json.loads(meta_path.read_text())
                meta_owner        = str(_meta.get("owner",        "") or "")
                meta_eff          = str(_meta.get("effectiveDate", "") or "")
                meta_rev          = str(_meta.get("reviewDate",    "") or "")
                meta_status       = str(_meta.get("status",        "") or "")
                meta_domain       = str(_meta.get("domain",        "") or "")
                meta_content_kind = str(_meta.get("content_kind",  "") or "")
                if meta_domain not in _VALID_DOMAINS:
                    if meta_domain:
                        print(f"  WARN [{rel}] unknown domain '{meta_domain}' — inferring", file=sys.stderr)
                    meta_domain = ""
                if meta_content_kind not in _VALID_CONTENT_KINDS:
                    if meta_content_kind:
                        print(f"  WARN [{rel}] unknown content_kind '{meta_content_kind}' — using 'procedure'", file=sys.stderr)
                    meta_content_kind = ""
            except Exception as _exc:
                print(f"  WARN [{rel}] metadata parse error: {_exc}", file=sys.stderr)

        # Fall back to filename-based domain detection when sidecar omits it.
        domain       = meta_domain or _infer_domain(rel, title)
        content_kind = meta_content_kind or "procedure"

        # ── Check existing record ──────────────────────────────────────────────
        cur.execute("SELECT id, sha256 FROM corpus_documents WHERE rel_path = %s", (rel,))
        row = cur.fetchone()

        if row:
            doc_id, stored_sha = row
            if stored_sha == sha:
                # SHA unchanged — check all sidecar-managed fields for changes.
                # Update any that differ so that a metadata-only edit is applied
                # without re-extracting or re-chunking the document.
                cur.execute(
                    "SELECT domain, content_kind, owner, effective_date, "
                    "review_date, status_override FROM corpus_documents WHERE id = %s",
                    (doc_id,),
                )
                _sr = cur.fetchone() or ("fire_ops", "procedure", "", "", "", "")
                _s_domain  = _sr[0] or ""
                _s_ck      = _sr[1] or ""
                _s_owner   = _sr[2] or ""
                _s_eff     = _sr[3] or ""
                _s_rev     = _sr[4] or ""
                _s_status  = _sr[5] or ""
                _updates: list[str] = []
                _update_vals: list  = []
                if _s_domain != domain:
                    _updates.append("domain=%s");          _update_vals.append(domain)
                if _s_ck != content_kind:
                    _updates.append("content_kind=%s");    _update_vals.append(content_kind)
                if _s_owner != meta_owner:
                    _updates.append("owner=%s");           _update_vals.append(meta_owner)
                if _s_eff != meta_eff:
                    _updates.append("effective_date=%s");  _update_vals.append(meta_eff)
                if _s_rev != meta_rev:
                    _updates.append("review_date=%s");     _update_vals.append(meta_rev)
                if _s_status != meta_status:
                    _updates.append("status_override=%s"); _update_vals.append(meta_status)
                if _updates:
                    _update_vals.append(doc_id)
                    cur.execute(
                        f"UPDATE corpus_documents SET {', '.join(_updates)} WHERE id=%s",
                        tuple(_update_vals),
                    )
                    conn.commit()
                    stats["updated_metadata"] += 1
                    stats["docs"].append({
                        "rel_path": rel, "action": "updated_metadata",
                        "domain": domain, "content_kind": content_kind,
                    })
                else:
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
        #
        # For PDFs we attempt per-page extraction (pypdf) so each chunk carries
        # its 1-based page number.  When that yields nothing we fall back to
        # whole-document pdftotext; page is then NULL for every chunk.
        # For DOCX / text files page is always NULL.
        #
        # chunks_data: list of (chunk_index, page_or_None, chunk_text)

        chunks_data: list[tuple[int, int | None, str]] = []

        if mime == "application/pdf":
            page_texts = _extract_pdf_by_page(fpath)
            if page_texts:
                idx = 0
                for page_num, page_text in page_texts:
                    for chunk_str in chunk_text(page_text):
                        chunks_data.append((idx, page_num, chunk_str))
                        idx += 1
            else:
                # pypdf per-page gave nothing; try pdftotext whole-doc fallback.
                try:
                    full_text = extract_text_pdf(fpath)
                except Exception as exc:
                    reason = "EXTRACTION_ERROR"
                    detail = str(exc)
                    if action == "updated":
                        stats["skipped_keep_previous"] += 1
                        stats["docs"].append({
                            "rel_path": rel, "action": "skipped_keep_previous",
                            "reason": reason, "detail": detail,
                        })
                        stats["kept_previous_docs"].append({"rel_path": rel, "reason": reason, "detail": detail})
                        print(
                            f"  WARN [{rel}] EXTRACTION_ERROR (sha changed) — "
                            f"preserving previous DB version: {exc}", file=sys.stderr,
                        )
                    else:
                        stats["failed"] += 1
                        stats["docs"].append({"rel_path": rel, "action": "failed", "reason": reason, "detail": detail})
                        stats["failed_docs"].append({"rel_path": rel, "reason": reason, "detail": detail})
                        print(f"  WARN [{rel}] EXTRACTION_ERROR: {exc}", file=sys.stderr)
                    continue
                for idx, chunk_str in enumerate(chunk_text(full_text)):
                    chunks_data.append((idx, None, chunk_str))
        else:
            # DOCX / text — no page tracking.
            try:
                full_text = extract_text(fpath, mime)
            except Exception as exc:
                reason = "EXTRACTION_ERROR"
                detail = str(exc)
                if action == "updated":
                    stats["skipped_keep_previous"] += 1
                    stats["docs"].append({
                        "rel_path": rel, "action": "skipped_keep_previous",
                        "reason": reason, "detail": detail,
                    })
                    stats["kept_previous_docs"].append({"rel_path": rel, "reason": reason, "detail": detail})
                    print(
                        f"  WARN [{rel}] EXTRACTION_ERROR (sha changed) — "
                        f"preserving previous DB version: {exc}", file=sys.stderr,
                    )
                else:
                    stats["failed"] += 1
                    stats["docs"].append({"rel_path": rel, "action": "failed", "reason": reason, "detail": detail})
                    stats["failed_docs"].append({"rel_path": rel, "reason": reason, "detail": detail})
                    print(f"  WARN [{rel}] EXTRACTION_ERROR: {exc}", file=sys.stderr)
                continue
            for idx, chunk_str in enumerate(chunk_text(full_text)):
                chunks_data.append((idx, None, chunk_str))

        if not chunks_data:
            # Image-only PDF, encrypted doc, or supported format with no extractable content.
            # Do NOT write placeholder chunks — that poisons FTS with noise.
            reason = "NO_TEXT_EXTRACTED"
            if action == "updated":
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
                stats["failed"] += 1
                stats["docs"].append({"rel_path": rel, "action": "failed", "reason": reason})
                stats["failed_docs"].append({"rel_path": rel, "reason": reason})
                print(f"  WARN [{rel}] NO_TEXT_EXTRACTED — skipping DB write", file=sys.stderr)
            continue

        # ── Write to DB only after confirmed good text ────────────────────────

        if action == "updated":
            cur.execute("DELETE FROM corpus_chunks WHERE doc_id = %s", (doc_id,))
            cur.execute(
                """UPDATE corpus_documents
                      SET sha256=%s, size_bytes=%s, mtime_utc=%s, mime=%s, title=%s,
                          owner=%s, effective_date=%s, review_date=%s, status_override=%s,
                          domain=%s, content_kind=%s
                    WHERE id=%s""",
                (sha, size, mtime, mime, title,
                 meta_owner, meta_eff, meta_rev, meta_status, domain, content_kind, doc_id),
            )
        else:
            cur.execute(
                """INSERT INTO corpus_documents
                       (rel_path, sha256, size_bytes, mtime_utc, mime, title,
                        owner, effective_date, review_date, status_override, domain,
                        content_kind)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                (rel, sha, size, mtime, mime, title,
                 meta_owner, meta_eff, meta_rev, meta_status, domain, content_kind),
            )
            doc_id = cur.fetchone()[0]

        for chunk_index, page_num, chunk_str in chunks_data:
            cur.execute(
                """INSERT INTO corpus_chunks (doc_id, chunk_index, page, text)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (doc_id, chunk_index)
                   DO UPDATE SET text = EXCLUDED.text, page = EXCLUDED.page""",
                (doc_id, chunk_index, page_num, chunk_str),
            )

        conn.commit()

        n_pages = len({pg for _, pg, _ in chunks_data if pg is not None})
        if action == "added":
            stats["added"] += 1
        else:
            stats["updated"] += 1

        stats["docs"].append({
            "rel_path": rel,
            "action":   action,
            "domain":   domain,
            "chunks":   len(chunks_data),
            "pages":    n_pages or None,
            "chars":    sum(len(c) for _, _, c in chunks_data),
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
