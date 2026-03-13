#!/usr/bin/env bash
# tests/test_ingest_schema.sh — Ingest JSON contract assertions.
#
# Verifies:
#   1. Ingest output always includes failed_docs and kept_previous_docs keys.
#   2. failed/skipped_keep_previous counts match list lengths.
#   3. NO_TEXT_EXTRACTED: a new doc with no text appears in failed_docs.
#
# Does NOT write to the real corpus DB.
# Requires: API container running via docker compose in COMPOSE_DIR.
#
# Usage:
#   COMPOSE_DIR=/path/to/keystone-deploy bash tests/test_ingest_schema.sh

set -euo pipefail

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-${_SCRIPT_DIR}/../../../keystone-deploy}"

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

echo "=== Ingest Schema Contract Tests ==="
echo "Compose dir: ${COMPOSE_DIR}"
echo ""

# ── Test 1: valid txt file → added=1, failed=0, keys present ─────────────────
echo "-- 1. Valid text doc: keys present, counts consistent --"

INGEST_OUT=$(cd "$COMPOSE_DIR" && docker compose exec -T api bash -c "
  mkdir -p /tmp/schema-t1/active
  echo 'Cardiac arrest protocol: perform CPR immediately with 30 compressions to 2 breaths.' \
    > /tmp/schema-t1/active/cpr-protocol.txt
  CORPUS_ROOT=/tmp/schema-t1 python3 /app/ingest_corpus.py 2>/dev/null
  rm -rf /tmp/schema-t1
" 2>/dev/null)
INGEST_JSON=$(echo "$INGEST_OUT" | grep '^{' | tail -1)

python3 - "$INGEST_JSON" <<'PYEOF'
import sys, json
raw = sys.argv[1]
try:
    d = json.loads(raw)
except Exception as e:
    print(f"[FAIL] t1: could not parse JSON: {e}")
    sys.exit(1)
errors = []
for k in ("failed_docs", "kept_previous_docs"):
    if k not in d:
        errors.append(f"missing key '{k}'")
    elif not isinstance(d[k], list):
        errors.append(f"'{k}' is not a list")
if d.get("added", 0) != 1:
    errors.append(f"expected added=1, got {d.get('added')}")
if d.get("failed", 0) != 0:
    errors.append(f"expected failed=0, got {d.get('failed')}")
if len(d.get("failed_docs", [])) != 0:
    errors.append(f"expected empty failed_docs, got {d['failed_docs']}")
if errors:
    print("[FAIL] t1: " + "; ".join(errors))
    sys.exit(1)
print(f"[PASS] t1: failed_docs and kept_previous_docs present; added=1 failed=0")
PYEOF
[ $? -eq 0 ] || fail "t1"

# ── Test 2: empty docx → failed=1, failed_docs contains it with NO_TEXT_EXTRACTED ──
echo "-- 2. Empty docx: failed=1, failed_docs with NO_TEXT_EXTRACTED --"

INGEST_OUT2=$(cd "$COMPOSE_DIR" && docker compose exec -T api bash -c "
  mkdir -p /tmp/schema-t2/active
  python3 -c \"from docx import Document; d=Document(); d.save('/tmp/schema-t2/active/empty.docx')\"
  CORPUS_ROOT=/tmp/schema-t2 python3 /app/ingest_corpus.py 2>/dev/null
  rm -rf /tmp/schema-t2
" 2>/dev/null)
INGEST_JSON2=$(echo "$INGEST_OUT2" | grep '^{' | tail -1)

python3 - "$INGEST_JSON2" <<'PYEOF'
import sys, json
raw = sys.argv[1]
try:
    d = json.loads(raw)
except Exception as e:
    print(f"[FAIL] t2: could not parse JSON: {e}")
    sys.exit(1)
errors = []
for k in ("failed_docs", "kept_previous_docs"):
    if k not in d:
        errors.append(f"missing key '{k}'")
if d.get("failed", 0) != 1:
    errors.append(f"expected failed=1, got {d.get('failed')}")
fdocs = d.get("failed_docs", [])
if len(fdocs) != 1:
    errors.append(f"expected 1 entry in failed_docs, got {len(fdocs)}")
elif fdocs[0].get("reason") != "NO_TEXT_EXTRACTED":
    errors.append(f"expected reason=NO_TEXT_EXTRACTED, got {fdocs[0].get('reason')}")
elif fdocs[0].get("rel_path") != "empty.docx":
    errors.append(f"expected rel_path=empty.docx, got {fdocs[0].get('rel_path')}")
if len(d.get("kept_previous_docs", [])) != 0:
    errors.append("kept_previous_docs should be empty")
if errors:
    print("[FAIL] t2: " + "; ".join(errors))
    sys.exit(1)
print(f"[PASS] t2: empty.docx in failed_docs with NO_TEXT_EXTRACTED; failed=1 kept_previous_docs=[]")
PYEOF
[ $? -eq 0 ] || fail "t2"

# ── Test 3: no active files → counts all zero, keys present ──────────────────
echo "-- 3. Empty active dir: all zeros, both list keys present --"

INGEST_OUT3=$(cd "$COMPOSE_DIR" && docker compose exec -T api bash -c "
  mkdir -p /tmp/schema-t3/active
  CORPUS_ROOT=/tmp/schema-t3 python3 /app/ingest_corpus.py 2>/dev/null
  rm -rf /tmp/schema-t3
" 2>/dev/null)
INGEST_JSON3=$(echo "$INGEST_OUT3" | grep '^{' | tail -1)

python3 - "$INGEST_JSON3" <<'PYEOF'
import sys, json
raw = sys.argv[1]
try:
    d = json.loads(raw)
except Exception as e:
    print(f"[FAIL] t3: could not parse JSON: {e}")
    sys.exit(1)
errors = []
for k in ("failed_docs", "kept_previous_docs"):
    if k not in d:
        errors.append(f"missing key '{k}'")
    elif not isinstance(d[k], list) or len(d[k]) != 0:
        errors.append(f"expected empty list for '{k}'")
for cnt in ("added", "failed", "skipped_keep_previous"):
    if d.get(cnt, -1) != 0:
        errors.append(f"expected {cnt}=0, got {d.get(cnt)}")
if errors:
    print("[FAIL] t3: " + "; ".join(errors))
    sys.exit(1)
print("[PASS] t3: empty active dir returns zero counts, empty failed_docs and kept_previous_docs")
PYEOF
[ $? -eq 0 ] || fail "t3"

echo ""
echo "All ingest schema contract tests passed."
