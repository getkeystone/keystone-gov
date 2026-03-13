#!/usr/bin/env bash
# test_requirements_foampro.sh
#
# Regression lock: "What is the ELECTRICAL REQUIREMENT for foampro system?"
# must return the spec section (page 14 chunk 30, with 41-amp/60-amp list)
# and NOT the safety-precautions section (page 3 chunk 4, Refer to Section 7).
#
# Acceptance criteria:
#   - guidance.type = approved
#   - guidance.document.documentId contains "2000-series-operation-installation-parts-manual.pdf"
#   - guidance.document.page == 14
#   - guidance.excerpt contains "requires 41 amp" (case-insensitive)
#   - guidance.excerpt contains "requires 60 amp" (case-insensitive)
#   - guidance.excerpt does NOT contain "Refer to Section 7"
#
# Usage: bash api/tests/test_requirements_foampro.sh [BASE_URL]
#   Default BASE_URL: http://${PUBLISH_IP}:5174/api (from ~/.config/keystone/env)

set -euo pipefail

ENV_FILE="${HOME}/.config/keystone/env"
_PUBLISH_IP="$(grep '^PUBLISH_IP=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d ' ')"
_PUBLISH_IP="${_PUBLISH_IP:-127.0.0.1}"
BASE="${1:-http://${_PUBLISH_IP}:5174/api}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_requirements_foampro.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""
echo "    Verify: fix(retrieval): prefer spec requirements over safety cautions for requirements intent"
echo ""

# ── Login as admin ─────────────────────────────────────────────────────────────
TOKEN="$(curl -sf --max-time 5 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "login: could not obtain admin token from ${BASE}"
  echo ""
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "login: admin token obtained"

# ── T1: Submit exact query ─────────────────────────────────────────────────────
echo ""
echo "── T1: submit foampro electrical requirement query"

QUESTION="What is the ELECTRICAL REQUIREMENT for foampro system?"

QID="$(curl -sf --max-time 10 -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"question\":\"${QUESTION}\",\"mode\":\"operational\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

if [[ -z "$QID" ]]; then
  fail "T1: query submission failed"
  echo ""
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "T1: query submitted (qid=${QID})"

# ── T2: Fetch guidance ─────────────────────────────────────────────────────────
echo ""
echo "── T2–T7: guidance assertions"

G="$(curl -sf --max-time 10 "$BASE/guidance/$QID" \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)"

if [[ -z "$G" ]]; then
  fail "T2: no guidance response"
  echo ""
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi

G_TYPE="$(echo "$G" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['guidance']['type'])" 2>/dev/null || true)"
G_CODE="$(echo "$G" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['guidance'].get('reasonCode',''))" 2>/dev/null || true)"
G_DOC="$(echo "$G" | python3 -c \
  "import sys,json; d=json.load(sys.stdin)['guidance'].get('document',{}); print(d.get('documentId',''))" 2>/dev/null || true)"
G_PAGE="$(echo "$G" | python3 -c \
  "import sys,json; d=json.load(sys.stdin)['guidance'].get('document',{}); print(d.get('page',''))" 2>/dev/null || true)"
G_CHUNK="$(echo "$G" | python3 -c \
  "import sys,json; d=json.load(sys.stdin)['guidance'].get('document',{}); print(d.get('chunkIndex',''))" 2>/dev/null || true)"
G_EXCERPT="$(echo "$G" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['guidance'].get('excerpt',''))" 2>/dev/null || true)"

info "type=${G_TYPE}  reasonCode=${G_CODE}"
info "doc=${G_DOC}"
info "page=${G_PAGE}  chunkIndex=${G_CHUNK}"
info "excerpt[:200]: ${G_EXCERPT:0:200}"

# T2: must be approved
if [[ "$G_TYPE" == "approved" ]]; then
  pass "T2: type=approved"
else
  fail "T2: expected type=approved, got type=${G_TYPE} reasonCode=${G_CODE}"
fi

# T3: document must be the 2000-series manual
if echo "$G_DOC" | grep -q "2000-series"; then
  pass "T3: documentId matches 2000-series manual (${G_DOC})"
else
  fail "T3: wrong document — expected 2000-series, got '${G_DOC}'"
fi

# T4: page must be a spec section (7 or 14 — both contain the amp list).
# Page 7 chunk 13 has "ELECTRICAL REQUIREMENTS" heading + inline amp specs.
# Page 14 chunk 30 has the Electrical Equipment Installation section amp specs.
# Both are correct.  Page 3 (safety cautions/pointer) is the bug case.
if [[ "$G_PAGE" == "14" || "$G_PAGE" == "7" ]]; then
  pass "T4: page=${G_PAGE} (spec section chosen — not safety precautions)"
else
  fail "T4: BUG — expected page 7 or 14 (spec list), got page=${G_PAGE} chunk=${G_CHUNK} — safety/pointer chunk selected"
fi

# T5: excerpt must contain "requires 41 amp" (case-insensitive)
if echo "$G_EXCERPT" | grep -qi "requires 41 amp"; then
  pass "T5: excerpt contains 'requires 41 amp'"
else
  fail "T5: BUG — excerpt missing 'requires 41 amp' (wrong chunk selected)"
  info "excerpt: ${G_EXCERPT:0:300}"
fi

# T6: excerpt must contain "requires 60 amp" (case-insensitive)
if echo "$G_EXCERPT" | grep -qi "requires 60 amp"; then
  pass "T6: excerpt contains 'requires 60 amp'"
else
  fail "T6: BUG — excerpt missing 'requires 60 amp' (wrong chunk selected)"
fi

# T7: excerpt must NOT contain "Refer to Section 7" (safety pointer text)
if echo "$G_EXCERPT" | grep -qi "Refer to Section 7"; then
  fail "T7: BUG — excerpt contains 'Refer to Section 7' — safety-precautions chunk selected instead of spec section"
else
  pass "T7: excerpt does not contain 'Refer to Section 7' (safety pointer absent)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_requirements_foampro.sh result"
echo "══════════════════════════════════════════════════════"
echo "  Chosen: doc=${G_DOC} page=${G_PAGE} chunk=${G_CHUNK}"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
