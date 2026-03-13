#!/usr/bin/env bash
# test_requirements_structured.sh
#
# Contract test: for the foampro electrical requirements query the API must
# return a structured requirements.items list with ≥5 model/voltage/amps
# entries, and wiring_notes containing "battery".
#
# Assertions:
#   T1: login as admin
#   T2: query submitted (foampro electrical)
#   T3: guidance type=approved
#   T4: guidance.requirements present
#   T5: requirements.items length >= 5
#   T6: entry {model:2001, voltage:12 VDC, amps:41} present
#   T7: entry {model:2024, voltage:24 VDC, amps:60} present
#   T8: wiring_notes length >= 1
#   T9: wiring_notes contains "battery" (at least one note)
#
# Usage: bash api/tests/test_requirements_structured.sh [BASE_URL]
#   Default BASE_URL: http://${PUBLISH_IP}:5174/api

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

echo "=== test_requirements_structured.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""
echo "    Verify: feat(kdat-012): structured requirements extraction"
echo ""

# ── T1: Login ─────────────────────────────────────────────────────────────────
TOKEN="$(curl -sf --max-time 5 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "T1: login failed (no token from ${BASE})"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "T1: admin token obtained"

# ── T2: Submit query ──────────────────────────────────────────────────────────
echo ""
echo "── T2: submit foampro electrical requirements query"

QID="$(curl -sf --max-time 10 -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"question":"What is the ELECTRICAL REQUIREMENT for foampro system?","mode":"operational"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

if [[ -z "$QID" ]]; then
  fail "T2: query submission failed"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "T2: query submitted (qid=${QID})"

# ── T3–T9: guidance assertions ────────────────────────────────────────────────
echo ""
echo "── T3–T9: requirements structure assertions"

G="$(curl -sf --max-time 10 "$BASE/guidance/$QID" \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)"

if [[ -z "$G" ]]; then
  fail "T3: no guidance response"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi

G_TYPE="$(echo "$G" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['guidance']['type'])" 2>/dev/null || true)"
G_CODE="$(echo "$G" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['guidance'].get('reasonCode',''))" 2>/dev/null || true)"

info "type=${G_TYPE}  reasonCode=${G_CODE}"

# T3: must be approved
if [[ "$G_TYPE" == "approved" ]]; then
  pass "T3: type=approved"
else
  fail "T3: expected type=approved, got type=${G_TYPE} reasonCode=${G_CODE}"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi

# T4: requirements field must be present
REQ_PRESENT="$(echo "$G" | python3 -c \
  "import sys,json; g=json.load(sys.stdin)['guidance']; print('yes' if 'requirements' in g else 'no')" \
  2>/dev/null || true)"

if [[ "$REQ_PRESENT" == "yes" ]]; then
  pass "T4: requirements field present"
else
  fail "T4: requirements field MISSING in guidance response"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi

# T5: items.length >= 5
ITEMS_LEN="$(echo "$G" | python3 -c \
  "import sys,json; g=json.load(sys.stdin)['guidance']; print(len(g.get('requirements',{}).get('items',[])))" \
  2>/dev/null || true)"

info "requirements.items length=${ITEMS_LEN}"

if [[ "$ITEMS_LEN" -ge 5 ]]; then
  pass "T5: requirements.items length=${ITEMS_LEN} >= 5"
else
  fail "T5: requirements.items length=${ITEMS_LEN} (expected >= 5)"
fi

# T6: entry for model=2001, voltage=12 VDC, amps=41
ITEM_2001_12="$(echo "$G" | python3 -c "
import sys, json
items = json.load(sys.stdin)['guidance'].get('requirements', {}).get('items', [])
found = any(
    it.get('model','').upper() == '2001'
    and '12' in it.get('voltage','')
    and it.get('amps') == 41
    for it in items
)
print('yes' if found else 'no')
" 2>/dev/null || true)"

if [[ "$ITEM_2001_12" == "yes" ]]; then
  pass "T6: item {model:2001, voltage:12 VDC, amps:41} present"
else
  fail "T6: item {model:2001, voltage:12 VDC, amps:41} NOT found"
  echo "$G" | python3 -c \
    "import sys,json; items=json.load(sys.stdin)['guidance'].get('requirements',{}).get('items',[]); [print(' ',it) for it in items]" \
    2>/dev/null || true
fi

# T7: entry for model=2024, voltage=24 VDC, amps=60
ITEM_2024_24="$(echo "$G" | python3 -c "
import sys, json
items = json.load(sys.stdin)['guidance'].get('requirements', {}).get('items', [])
found = any(
    it.get('model','').upper() == '2024'
    and '24' in it.get('voltage','')
    and it.get('amps') == 60
    for it in items
)
print('yes' if found else 'no')
" 2>/dev/null || true)"

if [[ "$ITEM_2024_24" == "yes" ]]; then
  pass "T7: item {model:2024, voltage:24 VDC, amps:60} present"
else
  fail "T7: item {model:2024, voltage:24 VDC, amps:60} NOT found"
fi

# T8: wiring_notes.length >= 1
WIRING_LEN="$(echo "$G" | python3 -c \
  "import sys,json; g=json.load(sys.stdin)['guidance']; print(len(g.get('requirements',{}).get('wiring_notes',[])))" \
  2>/dev/null || true)"

info "requirements.wiring_notes length=${WIRING_LEN}"

if [[ "$WIRING_LEN" -ge 1 ]]; then
  pass "T8: wiring_notes length=${WIRING_LEN} >= 1"
else
  fail "T8: wiring_notes empty (expected >= 1)"
fi

# T9: at least one wiring note contains "battery"
WIRING_BATTERY="$(echo "$G" | python3 -c "
import sys, json
notes = json.load(sys.stdin)['guidance'].get('requirements', {}).get('wiring_notes', [])
found = any('battery' in n.lower() for n in notes)
print('yes' if found else 'no')
" 2>/dev/null || true)"

if [[ "$WIRING_BATTERY" == "yes" ]]; then
  pass "T9: wiring_notes contains 'battery'"
else
  fail "T9: no wiring note contains 'battery'"
  echo "$G" | python3 -c \
    "import sys,json; notes=json.load(sys.stdin)['guidance'].get('requirements',{}).get('wiring_notes',[]); [print(' ',n) for n in notes]" \
    2>/dev/null || true
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_requirements_structured.sh result"
echo "══════════════════════════════════════════════════════"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
