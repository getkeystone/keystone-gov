"""
ingest_lib.py — Shared extraction and chunking helpers.

Used by:
  ingest_corpus.py   — batch corpus ingest script
  main.py            — upload API endpoints (synchronous extraction)

All functions are pure / file-system-only.  No DB, no HTTP.
"""

import hashlib
import mimetypes
import re
import subprocess
from pathlib import Path


# ── Constants ─────────────────────────────────────────────────────────────────

CHUNK_SIZE    = 1500   # target characters per chunk
CHUNK_OVERLAP = 150    # overlap between consecutive chunks

_SUPPORTED_MIMES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/msword",
}

_EXT_MIME_OVERRIDES: dict[str, str] = {
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".docm": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc":  "application/msword",
    ".pdf":  "application/pdf",
    ".txt":  "text/plain",
    ".md":   "text/markdown",
    ".rst":  "text/x-rst",
}

# ── Domain / content-kind vocabularies ───────────────────────────────────────

VALID_DOMAINS       = frozenset({"fire_ops", "medical_emr", "lrfd_protocol"})
VALID_CONTENT_KINDS = frozenset({"procedure", "requirements", "reference"})

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


def infer_domain(rel_path: str, title: str) -> str:
    """Return domain inferred from filename/title; medical_emr checked first, then lrfd_protocol."""
    stem = Path(rel_path).stem.lower().replace("_", " ").replace("-", " ")
    title_lower = title.lower()
    if _MEDICAL_EMR_SIGNALS.search(stem) or _MEDICAL_EMR_SIGNALS.search(title_lower):
        return "medical_emr"
    if _LRFD_SIGNALS.search(stem) or _LRFD_SIGNALS.search(title_lower):
        return "lrfd_protocol"
    return "fire_ops"


# ── MIME helpers ───────────────────────────────────────────────────────────────

def mime_for(path: Path) -> str:
    """Guess MIME type; use explicit extension fallbacks when stdlib mimetypes DB is incomplete."""
    suffix = path.suffix.lower()
    if suffix in _EXT_MIME_OVERRIDES:
        return _EXT_MIME_OVERRIDES[suffix]
    mt, _ = mimetypes.guess_type(str(path))
    return mt or "application/octet-stream"


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


# ── Per-page chunk builder ────────────────────────────────────────────────────

def build_chunks_pdf(path: Path) -> list[tuple[int, int | None, str]]:
    """
    Extract and chunk a PDF, returning (chunk_index, page_or_None, text).

    Tries per-page extraction first (pypdf); falls back to whole-document
    pdftotext.  Raises ExtractionError on failure; returns empty list if the
    PDF has no extractable text (image-only, encrypted).
    """
    page_texts = _extract_pdf_by_page(path)
    chunks_data: list[tuple[int, int | None, str]] = []
    if page_texts:
        idx = 0
        for page_num, page_text in page_texts:
            for chunk_str in chunk_text(page_text):
                chunks_data.append((idx, page_num, chunk_str))
                idx += 1
    else:
        full_text = extract_text_pdf(path)
        for idx, chunk_str in enumerate(chunk_text(full_text)):
            chunks_data.append((idx, None, chunk_str))
    return chunks_data


def build_chunks_other(path: Path, mime: str) -> list[tuple[int, int | None, str]]:
    """Extract and chunk a non-PDF file, returning (chunk_index, None, text)."""
    full_text = extract_text(path, mime)
    return [(idx, None, chunk_str) for idx, chunk_str in enumerate(chunk_text(full_text))]
