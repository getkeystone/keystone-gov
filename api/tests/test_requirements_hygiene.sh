#!/usr/bin/env bash
# test_requirements_hygiene.sh
#
# Contract test: after hygiene filter, requirements notes must:
#   - wiring_notes <= 4 (cap)
#   - grounding_notes <= 2 (cap)
#   - no wiring_note is pointer-only ("refer to section") unless it also
#     contains a spec keyword (vdc, amp, battery, disconnect, contactor,
#     ground, strap, rfi, emi)
#   - items >= 5 (regression guard — hygiene must not strip items)
#
# Usage: bash api/tests/test_requirements_hygiene.sh [BASE_URL]
#   Default BASE_URL: http://${PUBLISH_IP}:8080/api (from ~/.config/keystone/env)

set -euo pipefail

ENV_FILE="${HOME}/.config/keystone/env"
_PUBLISH_IP="$(grep '^PUBLISH_IP=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d ' ')"
_PUBLISH_IP="${_PUBLISH_IP:-127.0.0.1}"
BASE="${1:-http://${_PUBLISH_IP}:8080/api}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_requirements_hygiene.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""
echo "    Verify: feat(kdat-013): requirements hygiene filter"
echo ""

# ── Login ─────────────────────────────────────────────────────────────────────
TOKEN="$(curl -sf --max-time 5 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "login: could not obtain admin token from ${BASE}"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "login: admin token obtained"

# ── Submit query ──────────────────────────────────────────────────────────────
echo ""
echo "── T1: submit foampro electrical requirements query"

QID="$(curl -sf --max-time 10 -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"question":"What is the ELECTRICAL REQUIREMENT for foampro system?","mode":"operational"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

if [[ -z "$QID" ]]; then
  fail "T1: query submission failed"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "T1: query submitted (qid=${QID})"

# ── Fetch guidance ────────────────────────────────────────────────────────────
echo ""
echo "── T2–T6: hygiene assertions"

G="$(curl -sf --max-time 10 "$BASE/guidance/$QID" \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)"

if [[ -z "$G" ]]; then
  fail "T2: no guidance response"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi

ITEMS_LEN="$(echo "$G" | python3 -c \
  "import sys,json; g=json.load(sys.stdin)['guidance']; print(len(g.get('requirements',{}).get('items',[])))" \
  2>/dev/null || true)"
WIRING_LEN="$(echo "$G" | python3 -c \
  "import sys,json; g=json.load(sys.stdin)['guidance']; print(len(g.get('requirements',{}).get('wiring_notes',[])))" \
  2>/dev/null || true)"
GROUNDING_LEN="$(echo "$G" | python3 -c \
  "import sys,json; g=json.load(sys.stdin)['guidance']; print(len(g.get('requirements',{}).get('grounding_notes',[])))" \
  2>/dev/null || true)"

info "items=${ITEMS_LEN}  wiring_notes=${WIRING_LEN}  grounding_notes=${GROUNDING_LEN}"

# T2: items regression guard
if [[ -n "$ITEMS_LEN" && "$ITEMS_LEN" -ge 5 ]]; then
  pass "T2: requirements.items=${ITEMS_LEN} >= 5 (hygiene did not strip items)"
else
  fail "T2: requirements.items=${ITEMS_LEN} (expected >= 5)"
fi

# T3: wiring_notes cap
if [[ -n "$WIRING_LEN" && "$WIRING_LEN" -le 4 ]]; then
  pass "T3: wiring_notes=${WIRING_LEN} <= 4"
else
  fail "T3: wiring_notes=${WIRING_LEN} (expected <= 4)"
fi

# T4: grounding_notes cap
if [[ -n "$GROUNDING_LEN" && "$GROUNDING_LEN" -le 2 ]]; then
  pass "T4: grounding_notes=${GROUNDING_LEN} <= 2"
else
  fail "T4: grounding_notes=${GROUNDING_LEN} (expected <= 2)"
fi

# T5: no wiring_note is pointer-only without spec keyword
POINTER_ONLY="$(echo "$G" | python3 -c "
import sys, json, re
g = json.load(sys.stdin)['guidance']
notes = g.get('requirements', {}).get('wiring_notes', [])
_POINTER = re.compile(
    r'\b(?:refer\s+to\s+(?:section|page)|see\s+(?:section|page)|'
    r'for\s+(?:complete|more|full|additional|detailed?)\s+'
    r'(?:information|details?|specifications?|requirements?))\b',
    re.IGNORECASE,
)
_SPEC_KW = re.compile(
    r'\b(?:vdc|volt|amp|battery|disconnect|contactor|pto|ground|strap|rfi|emi)\b',
    re.IGNORECASE,
)
bad = [n for n in notes if _POINTER.search(n) and not _SPEC_KW.search(n)]
if bad:
    print('BAD: ' + ' | '.join(bad[:3]))
else:
    print('OK')
" 2>/dev/null || true)"

if [[ "$POINTER_ONLY" == "OK" ]]; then
  pass "T5: no pointer-only wiring notes (all retain spec keyword)"
else
  fail "T5: pointer-only wiring note(s) found: ${POINTER_ONLY}"
fi

# T6: same check for grounding_notes
GROUNDING_POINTER="$(echo "$G" | python3 -c "
import sys, json, re
g = json.load(sys.stdin)['guidance']
notes = g.get('requirements', {}).get('grounding_notes', [])
_POINTER = re.compile(
    r'\b(?:refer\s+to\s+(?:section|page)|see\s+(?:section|page)|'
    r'for\s+(?:complete|more|full|additional|detailed?)\s+'
    r'(?:information|details?|specifications?|requirements?))\b',
    re.IGNORECASE,
)
_SPEC_KW = re.compile(
    r'\b(?:vdc|volt|amp|battery|disconnect|contactor|pto|ground|strap|rfi|emi)\b',
    re.IGNORECASE,
)
bad = [n for n in notes if _POINTER.search(n) and not _SPEC_KW.search(n)]
if bad:
    print('BAD: ' + ' | '.join(bad[:3]))
else:
    print('OK')
" 2>/dev/null || true)"

if [[ "$GROUNDING_POINTER" == "OK" ]]; then
  pass "T6: no pointer-only grounding notes"
else
  fail "T6: pointer-only grounding note(s) found: ${GROUNDING_POINTER}"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_requirements_hygiene.sh result"
echo "══════════════════════════════════════════════════════"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
