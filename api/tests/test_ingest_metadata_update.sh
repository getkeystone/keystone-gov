#!/usr/bin/env bash
# test_ingest_metadata_update.sh
#
# Contract test: ingest_corpus.py must apply sidecar metadata changes even when
# the document SHA is unchanged (KDAT-016 "Metadata Sidecar Always Applies").
#
# Assertions:
#   1. After ingest with content_kind=procedure (baseline): DB row matches.
#   2. After sidecar change to content_kind=requirements: ingest reports
#      action=updated_metadata (not skipped) and DB reflects the new value.
#   3. Sidecar is restored to its original content at the end (cleanup).
#
# Requirements:
#   - Docker Compose stack running (postgres + api containers)
#   - /srv/keystone-corpus/active/ mounted and writable
#   - Target file: lrfd-001-roof-load-assessment.txt (content_kind defaults to procedure)
#
# Usage: bash api/tests/test_ingest_metadata_update.sh

set -euo pipefail

PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_ingest_metadata_update.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo ""
echo "    Verify: feat(kdat-016): metadata sidecar always applies on SHA-match"
echo ""

# ── Config ────────────────────────────────────────────────────────────────────
CORPUS_ROOT="/srv/keystone-corpus"
ACTIVE_DIR="${CORPUS_ROOT}/active"
TARGET_REL="lrfd-001-roof-load-assessment.txt"
SIDECAR="${ACTIVE_DIR}/${TARGET_REL}.metadata.json"
COMPOSE_SERVICE="api"

# DB query helper: runs psql inside the postgres container
dbq() {
  docker compose exec -T postgres psql -U keystone -d keystone -tAc "$1" 2>/dev/null
}

# Run ingest and capture stdout+stderr
run_ingest() {
  docker compose exec -T "$COMPOSE_SERVICE" \
    python3 /app/ingest_corpus.py 2>&1
}

# ── Preflight: ensure target doc exists in DB ─────────────────────────────────
echo "── Preflight"

if [[ ! -f "$SIDECAR" ]]; then
  fail "preflight: sidecar not found: $SIDECAR"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "preflight: sidecar exists at ${SIDECAR}"

ORIG_SIDECAR="$(cat "$SIDECAR")"
info "original sidecar: ${ORIG_SIDECAR}"

DB_CK_BEFORE="$(dbq "SELECT content_kind FROM corpus_documents WHERE rel_path='${TARGET_REL}';")"
if [[ -z "$DB_CK_BEFORE" ]]; then
  fail "preflight: target doc not found in DB (rel_path=${TARGET_REL})"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "preflight: doc found in DB, content_kind=${DB_CK_BEFORE}"

# ── Step 1: Baseline ingest (no sidecar change) ───────────────────────────────
echo ""
echo "── Step 1: baseline ingest (SHA unchanged, no sidecar mutation)"

# Ensure sidecar has no content_kind (defaults to procedure)
echo "$ORIG_SIDECAR" > "$SIDECAR"

OUT1="$(run_ingest)"
info "ingest output (last 3 lines): $(echo "$OUT1" | tail -3)"

# The doc should be skipped (no change at all)
if echo "$OUT1" | grep -q '"action": "skipped"'; then
  pass "step1: doc reported as skipped (SHA+metadata unchanged)"
elif echo "$OUT1" | grep -qi "skipped"; then
  pass "step1: doc reported as skipped (summary line)"
else
  fail "step1: expected skipped, got: $(echo "$OUT1" | grep -i 'lrfd-001' | head -3 || true)"
fi

DB_CK1="$(dbq "SELECT content_kind FROM corpus_documents WHERE rel_path='${TARGET_REL}';")"
if [[ "$DB_CK1" == "procedure" ]]; then
  pass "step1: DB content_kind=procedure after baseline ingest"
else
  fail "step1: expected content_kind=procedure, got '${DB_CK1}'"
fi

# ── Step 2: Mutate sidecar → content_kind=requirements ───────────────────────
echo ""
echo "── Step 2: mutate sidecar → content_kind=requirements, re-run ingest"

# Write a new sidecar adding content_kind=requirements
python3 -c "
import json, sys
orig = json.loads(sys.argv[1])
orig['content_kind'] = 'requirements'
print(json.dumps(orig, indent=2))
" "$ORIG_SIDECAR" > "$SIDECAR"

info "updated sidecar: $(cat "$SIDECAR")"

OUT2="$(run_ingest)"
info "ingest output (last 5 lines): $(echo "$OUT2" | tail -5)"

# Assert action=updated_metadata appears in output
if echo "$OUT2" | grep -q '"action": "updated_metadata"'; then
  pass "step2: action=updated_metadata reported by ingest"
else
  fail "step2: expected action=updated_metadata in output; got: $(echo "$OUT2" | grep -i 'lrfd-001' | head -3 || true)"
fi

# Assert updated_metadata counter > 0
if echo "$OUT2" | grep -qE '"updated_metadata":\s*[1-9]'; then
  pass "step2: updated_metadata counter > 0 in ingest summary"
else
  fail "step2: updated_metadata counter not incremented; summary: $(echo "$OUT2" | tail -10)"
fi

# Assert DB row updated
DB_CK2="$(dbq "SELECT content_kind FROM corpus_documents WHERE rel_path='${TARGET_REL}';")"
if [[ "$DB_CK2" == "requirements" ]]; then
  pass "step2: DB content_kind=requirements after metadata-only ingest"
else
  fail "step2: expected content_kind=requirements in DB, got '${DB_CK2}'"
fi

# Assert NOT reported as skipped
if echo "$OUT2" | grep -q '"action": "skipped"' && ! echo "$OUT2" | grep -q '"action": "updated_metadata"'; then
  fail "step2: doc was skipped instead of updated_metadata"
fi

# ── Step 3: Restore sidecar + verify DB reset ─────────────────────────────────
echo ""
echo "── Step 3: restore sidecar to original, re-run ingest"

echo "$ORIG_SIDECAR" > "$SIDECAR"
info "restored sidecar: $(cat "$SIDECAR")"

OUT3="$(run_ingest)"
info "ingest output (last 5 lines): $(echo "$OUT3" | tail -5)"

# After restore, content_kind key is gone → defaults to "procedure"
# This should again trigger updated_metadata (requirements → procedure)
if echo "$OUT3" | grep -q '"action": "updated_metadata"'; then
  pass "step3: action=updated_metadata on restore (requirements→procedure)"
elif echo "$OUT3" | grep -q '"action": "skipped"'; then
  fail "step3: got skipped on restore — DB not updated back to procedure"
else
  info "step3: no explicit action found in output (checking DB directly)"
fi

DB_CK3="$(dbq "SELECT content_kind FROM corpus_documents WHERE rel_path='${TARGET_REL}';")"
if [[ "$DB_CK3" == "procedure" ]]; then
  pass "step3: DB restored to content_kind=procedure"
else
  fail "step3: expected content_kind=procedure after restore, got '${DB_CK3}'"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_ingest_metadata_update.sh result"
echo "══════════════════════════════════════════════════════"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
