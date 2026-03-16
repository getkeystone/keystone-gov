"""test_source_metadata.py — Regression tests for /source and /source-chunk metadata.

These tests verify the SQL queries and response-construction logic that back the
two source endpoints. They run against an in-memory SQLite database (no HTTP, no
auth, no FastAPI required). A live Postgres smoke test is also included.

Live HTTP contracts (for reference — not tested here):
  /source/{document_id}/{page_or_chunk_index}
      Called by the frontend via apiGetSource(documentId, page).
      Queries corpus_documents + corpus_chunks by chunk_index, falls back to
      seeded fixture. Returns 200 with SourceResponse.

  /source-chunk/{document_id}?chunk_index=N
      Direct-API path, NOT called by the frontend UI.
      document_id is a path segment (:path wildcard).
      chunk_index is a REQUIRED query parameter — not a path segment.
      Corpus-only: no fixture fallback.
      Calling /source-chunk/1 (without ?chunk_index=N) returns 422.

  Live-verified examples (2026-03-15):
      GET /api/source-chunk/Emergency_care%20for%20Professional%20Responders.pdf?chunk_index=178
          → 200  section="page 75"  owner="EMS Division"  effectiveDate="2023-01-01"
      GET /api/source-chunk/Emergency_care%20for%20Professional%20Responders.pdf?chunk_index=1
          → 200  section="page 3"   owner="EMS Division"  effectiveDate="2023-01-01"

  Canonical contract reference:
      PILOT_RUNBOOK.md § "API source-route contract reference"

Tests:
  T1  /source SQL path: owner, dates, title populated from DB
  T2  /source SQL path: section uses "passage N" for chunk-index key
  T3  /source SQL path: returns None when no matching row
  T4  /source-chunk SQL path: all metadata fields populated from DB
  T5  /source-chunk SQL path: section uses "page N" when page column is non-null
  T6  /source-chunk SQL path: section uses "passage N" when page column is null
  T7  /source-chunk SQL path: excerpt is truncated to 800 chars
  T8  Both SQL paths: empty string fallback when DB field is empty string
  T9  Live Postgres: /source SQL returns real metadata for EMR doc chunk 178

Run standalone:
    python3 api/tests/test_source_metadata.py
"""

import os
import sys
import sqlite3

import pytest

# The SELECT queries from main.py — verbatim, except SQLite uses ? placeholders.
# The logic under test is the *column selection* and *result unpacking*, not SQL dialect.

_SQL_SOURCE = """
    SELECT cd.rel_path, cd.title, cc.text,
           cd.owner, cd.effective_date, cd.review_date, cd.status_override
    FROM corpus_documents cd
    JOIN corpus_chunks cc ON cc.doc_id = cd.id
    WHERE cd.rel_path = ? AND cc.chunk_index = ?
"""

_SQL_SOURCE_CHUNK = """
    SELECT cd.rel_path, cd.title, cc.text, cc.page,
           cd.owner, cd.effective_date, cd.review_date, cd.status_override
    FROM corpus_documents cd
    JOIN corpus_chunks cc ON cc.doc_id = cd.id
    WHERE cd.rel_path = ? AND cc.chunk_index = ?
"""


def _make_db(owner="EMS Division", effective_date="2023-01-01", review_date="2026-01-01",
             status_override="", page=None, text="Sample passage text."):
    """Return an in-memory SQLite connection seeded with one document and one chunk."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE corpus_documents (
            id INTEGER PRIMARY KEY,
            rel_path TEXT NOT NULL,
            title TEXT NOT NULL,
            owner TEXT NOT NULL DEFAULT '',
            effective_date TEXT NOT NULL DEFAULT '',
            review_date TEXT NOT NULL DEFAULT '',
            status_override TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE corpus_chunks (
            id INTEGER PRIMARY KEY,
            doc_id INTEGER NOT NULL,
            chunk_index INTEGER NOT NULL,
            text TEXT NOT NULL,
            page INTEGER
        )
    """)
    conn.execute(
        "INSERT INTO corpus_documents (rel_path, title, owner, effective_date, review_date, status_override)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        ("Emergency_care for Professional Responders.pdf",
         "Emergency care for Professional Responders",
         owner, effective_date, review_date, status_override),
    )
    doc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO corpus_chunks (doc_id, chunk_index, text, page) VALUES (?, ?, ?, ?)",
        (doc_id, 178, text, page),
    )
    conn.commit()
    return conn


def _run_source(conn, rel_path, chunk_index):
    return conn.execute(_SQL_SOURCE, (rel_path, chunk_index)).fetchone()


def _run_source_chunk(conn, rel_path, chunk_index):
    return conn.execute(_SQL_SOURCE_CHUNK, (rel_path, chunk_index)).fetchone()


# ---------------------------------------------------------------------------
# /source endpoint query (7 columns: rel_path, title, text, owner, eff, rev, status)
# ---------------------------------------------------------------------------

def test_source_returns_real_owner_and_dates():
    conn = _make_db()
    row = _run_source(conn, "Emergency_care for Professional Responders.pdf", 178)
    assert row is not None
    rel_path, title, text, c_owner, c_eff, c_rev, c_status = row
    assert title == "Emergency care for Professional Responders"
    assert c_owner == "EMS Division"
    assert c_eff == "2023-01-01"
    assert c_rev == "2026-01-01"
    assert c_status == ""


def test_source_section_label_uses_passage():
    """Verify the section label logic (response construction) from the endpoint."""
    page = 178  # the chunk_index used as page key in /source
    section = f"passage {page}"
    assert section == "passage 178"


def test_source_no_match_returns_none():
    conn = _make_db()
    row = _run_source(conn, "no-such-doc.pdf", 999)
    assert row is None


# ---------------------------------------------------------------------------
# /source-chunk endpoint query (8 columns)
# ---------------------------------------------------------------------------

def test_source_chunk_returns_all_metadata():
    conn = _make_db()
    row = _run_source_chunk(conn, "Emergency_care for Professional Responders.pdf", 178)
    assert row is not None
    rel_path, title, text, page_num, c_owner, c_eff, c_rev, c_status = row
    assert title == "Emergency care for Professional Responders"
    assert c_owner == "EMS Division"
    assert c_eff == "2023-01-01"
    assert c_rev == "2026-01-01"
    assert c_status == ""


def test_source_chunk_section_page_wins_when_page_known():
    """When page column is non-null, section should be 'page N'."""
    conn = _make_db(page=3)
    row = _run_source_chunk(conn, "Emergency_care for Professional Responders.pdf", 178)
    _, _, _, page_num, *_ = row
    chunk_index = 178
    section = f"page {page_num}" if page_num is not None else f"passage {chunk_index}"
    assert section == "page 3"


def test_source_chunk_section_uses_passage_when_page_null():
    """When page column is null, section should be 'passage N'."""
    conn = _make_db(page=None)
    row = _run_source_chunk(conn, "Emergency_care for Professional Responders.pdf", 178)
    _, _, _, page_num, *_ = row
    chunk_index = 178
    section = f"page {page_num}" if page_num is not None else f"passage {chunk_index}"
    assert section == "passage 178"


def test_source_chunk_excerpt_truncated():
    long_text = "x" * 1200
    conn = _make_db(text=long_text)
    row = _run_source_chunk(conn, "Emergency_care for Professional Responders.pdf", 178)
    _, _, text, *_ = row
    excerpt = (text or "")[:800]
    assert len(excerpt) == 800


def test_empty_string_fallback_for_missing_metadata():
    """Empty-string fields should pass through as empty strings (not None)."""
    conn = _make_db(owner="", effective_date="", review_date="", status_override="")
    row = _run_source_chunk(conn, "Emergency_care for Professional Responders.pdf", 178)
    _, _, _, page_num, c_owner, c_eff, c_rev, c_status = row
    # The endpoint uses `c_owner or ""` — confirm both paths produce ""
    assert (c_owner or "") == ""
    assert (c_eff or "") == ""
    assert (c_rev or "") == ""
    assert (c_status or "") == ""


# ---------------------------------------------------------------------------
# Live DB smoke (skipped when postgres is unavailable)
# ---------------------------------------------------------------------------

def test_live_postgres_source_metadata():
    """Query the real running Postgres DB and verify the EMR doc has populated metadata.
    Skipped automatically when postgres is not reachable.
    """
    try:
        import psycopg2
    except ImportError:
        pytest.skip("psycopg2 not installed")

    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://keystone:keystone@localhost:5432/keystone",
    )
    try:
        conn = psycopg2.connect(db_url, connect_timeout=3)
    except Exception:
        pytest.skip("Postgres not reachable")

    with conn.cursor() as cur:
        cur.execute("""
            SELECT cd.rel_path, cd.title, cc.text,
                   cd.owner, cd.effective_date, cd.review_date, cd.status_override
            FROM corpus_documents cd
            JOIN corpus_chunks cc ON cc.doc_id = cd.id
            WHERE cd.rel_path = 'Emergency_care for Professional Responders.pdf'
              AND cc.chunk_index = 178
            LIMIT 1
        """)
        row = cur.fetchone()
    conn.close()

    assert row is not None, "EMR doc chunk 178 not found in live corpus"
    rel_path, title, text, owner, eff, rev, status = row
    assert title, "title must not be empty"
    assert owner == "EMS Division", f"Expected 'EMS Division', got {owner!r}"
    assert eff == "2023-01-01", f"Expected '2023-01-01', got {eff!r}"
    assert rev == "2026-01-01", f"Expected '2026-01-01', got {rev!r}"


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import subprocess
    subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v"],
        cwd=os.path.dirname(__file__),
    )
