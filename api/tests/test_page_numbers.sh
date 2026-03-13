#!/usr/bin/env bash
# tests/test_page_numbers.sh — Contract assertions for real PDF page numbers.
#
# Verifies that after ingest:
#   1. corpus_chunks.page is populated (>= 1) for PDF documents.
#   2. A live FTS query returns chunkIndex and page >= 1 in the guidance JSON.
#   3. Citations in the audit receipt include chunkIndex and page >= 1.
#   4. DOCX chunks have page = null (page tracking is PDF-only).
#
# Usage:
#   COMPOSE_DIR=/path/to/keystone-deploy bash tests/test_page_numbers.sh

set -euo pipefail

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-${_SCRIPT_DIR}/../../../keystone-deploy}"
BASE="${BASE:-http://localhost:8000}"

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

echo "=== Page Number Contract Tests ==="
echo "Base: ${BASE}   Compose: ${COMPOSE_DIR}"
echo ""

# ── Test 1: DB-level — PDF chunks have page >= 1 ─────────────────────────────
echo "-- 1. DB: PDF chunks have page >= 1 --"

DB_RESULT=$(cd "$COMPOSE_DIR" && docker compose exec -T postgres psql -U keystone -d keystone -t -c "
SELECT
    COUNT(*)                               AS total_chunks,
    COUNT(cc.page)                         AS chunks_with_page,
    COUNT(*) FILTER (WHERE cc.page IS NULL
                     AND   cd.mime = 'application/pdf') AS pdf_nulls
FROM corpus_chunks cc
JOIN corpus_documents cd ON cd.id = cc.doc_id;
" 2>/dev/null | tr -d ' ')

python3 - "$DB_RESULT" <<'PYEOF'
import sys
raw = sys.argv[1].strip()
parts = [p.strip() for p in raw.split('|')]
total, with_page, pdf_nulls = int(parts[0]), int(parts[1]), int(parts[2])
errors = []
if total == 0:
    errors.append("No chunks in DB — run corpus ingest first")
if with_page == 0:
    errors.append("No chunks have a page number — re-ingest required")
if pdf_nulls > 0:
    errors.append(f"{pdf_nulls} PDF chunks have page=null — ingest did not populate pages")
if errors:
    print("[FAIL] t1: " + "; ".join(errors))
    sys.exit(1)
pct = 100 * with_page // total
print(f"[PASS] t1: {with_page}/{total} chunks have page ({pct}%); 0 PDF nulls")
PYEOF
[ $? -eq 0 ] || fail "t1"

# ── Test 2: DB-level — DOCX chunks have page = null ──────────────────────────
echo "-- 2. DB: DOCX chunks have page = null --"

DOCX_RESULT=$(cd "$COMPOSE_DIR" && docker compose exec -T postgres psql -U keystone -d keystone -t -c "
SELECT
    COUNT(*) FILTER (WHERE cc.page IS NOT NULL
                     AND   cd.mime LIKE '%docx%') AS docx_with_page
FROM corpus_chunks cc
JOIN corpus_documents cd ON cd.id = cc.doc_id;
" 2>/dev/null | tr -d ' ')

python3 - "$DOCX_RESULT" <<'PYEOF'
import sys
docx_with_page = int(sys.argv[1].strip())
if docx_with_page > 0:
    print(f"[FAIL] t2: {docx_with_page} DOCX chunks have non-null page (expected null)")
    sys.exit(1)
print(f"[PASS] t2: DOCX chunks all have page=null")
PYEOF
[ $? -eq 0 ] || fail "t2"

# ── Test 3: API — guidance returns chunkIndex and page >= 1 for PDF doc ──────
echo "-- 3. API: guidance includes chunkIndex and page >= 1 for PDF citation --"

TOKEN=$(curl -sf -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

QID=$(curl -sf -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"question":"emergency medical response procedure","mode":"operational"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")

GUIDANCE_JSON=$(curl -sf "$BASE/guidance/$QID" -H "Authorization: Bearer $TOKEN")

python3 - "$GUIDANCE_JSON" <<'PYEOF'
import sys, json
data = json.loads(sys.argv[1])
g = data.get("guidance", {})
if g.get("type") != "approved":
    print(f"[FAIL] t3: expected approved, got {g.get('type')} — query may not match corpus")
    sys.exit(1)
doc = g.get("document", {})
errors = []
chunk_idx = doc.get("chunkIndex")
page = doc.get("page")
if chunk_idx is None:
    errors.append("document.chunkIndex is missing")
if page is None:
    errors.append("document.page is None (expected >= 1 for PDF)")
elif not isinstance(page, int) or page < 1:
    errors.append(f"document.page={page} is not a positive integer")
if doc.get("section", "").startswith("chunk ") and page is not None:
    errors.append(f"section says 'chunk' but page is set: section={doc['section']}")
if errors:
    print("[FAIL] t3: " + "; ".join(errors))
    sys.exit(1)
print(f"[PASS] t3: chunkIndex={chunk_idx} page={page} section={doc.get('section')}")
PYEOF
[ $? -eq 0 ] || fail "t3"

# ── Test 4: API — audit citations include chunkIndex and page ─────────────────
echo "-- 4. API: citations include chunkIndex and page >= 1 --"

AUDIT_JSON=$(curl -sf "$BASE/audit/$QID" -H "Authorization: Bearer $TOKEN")

python3 - "$AUDIT_JSON" <<'PYEOF'
import sys, json
data = json.loads(sys.argv[1])
cites = data.get("citationsReturned", [])
if not cites:
    print("[FAIL] t4: no citations returned")
    sys.exit(1)
errors = []
for i, c in enumerate(cites[:3]):
    if "chunkIndex" not in c:
        errors.append(f"cite[{i}] missing chunkIndex")
    pg = c.get("page")
    if pg is not None and (not isinstance(pg, int) or pg < 1):
        errors.append(f"cite[{i}] page={pg} is not a positive integer")
if errors:
    print("[FAIL] t4: " + "; ".join(errors))
    sys.exit(1)
sample = cites[0]
print(f"[PASS] t4: {len(cites)} citation(s); first: "
      f"chunkIndex={sample.get('chunkIndex')} page={sample.get('page')}")
PYEOF
[ $? -eq 0 ] || fail "t4"

echo ""
echo "All page number contract tests passed."
