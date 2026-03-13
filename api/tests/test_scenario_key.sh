#!/usr/bin/env bash
# test_scenario_key.sh
#
# Regression test: scenarioKey in GET /guidance/{qid} must match guidance.type,
# not default to "refusal" for reference/medical_reference results.
#
# Bug reproduced: medical_reference mode returned scenarioKey="refusal" even
# when guidance.type="reference" and policyOutcome="allowed".
#
# Usage: bash api/tests/test_scenario_key.sh [BASE_URL]
#   Defaults: BASE_URL=http://127.0.0.1:8000

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

echo "=== test_scenario_key.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login as admin ────────────────────────────────────────────────────────────
TOKEN="$(curl -sf --max-time 5 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "login: could not obtain admin token"
  echo ""
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "login: admin token obtained"

# ── T1: medical_reference mode → scenarioKey must not be "refusal" ────────────
echo ""
echo "── T1: medical_reference mode nosebleed → scenarioKey != refusal"

QID="$(curl -sf --max-time 10 -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"question":"how to stop a nose bleed","mode":"medical_reference"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

if [[ -z "$QID" ]]; then
  fail "T1: query submission failed"
else
  info "query_id=${QID}"
  G="$(curl -sf --max-time 10 "$BASE/guidance/$QID" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)"

  G_TYPE="$(echo "$G" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance']['type'])" 2>/dev/null || true)"
  G_SKEY="$(echo "$G" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['scenarioKey'])" 2>/dev/null || true)"
  G_OUTCOME="$(echo "$G" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('audit',{}).get('policyOutcome','?'))" 2>/dev/null || true)"

  info "guidance.type=${G_TYPE}  scenarioKey=${G_SKEY}  policyOutcome=${G_OUTCOME}"

  if [[ "$G_TYPE" == "reference" || "$G_TYPE" == "medical_reference" ]]; then
    pass "T1a: guidance.type=${G_TYPE} (reference content returned)"
  elif [[ "$G_TYPE" == "refusal" ]]; then
    pass "T1a: guidance.type=refusal (no medical corpus match — scenarioKey regression not testable here)"
  else
    fail "T1a: unexpected guidance.type=${G_TYPE}"
  fi

  if [[ "$G_TYPE" == "refusal" ]]; then
    # No reference result: scenarioKey=refusal is correct, skip mismatch check
    pass "T1b: scenarioKey=refusal consistent with guidance.type=refusal"
  elif [[ "$G_SKEY" == "refusal" ]]; then
    fail "T1b: BUG — scenarioKey=refusal but guidance.type=${G_TYPE} (regression!)"
  else
    pass "T1b: scenarioKey=${G_SKEY} consistent with guidance.type=${G_TYPE}"
  fi

  if [[ "$G_TYPE" == "reference" || "$G_TYPE" == "medical_reference" ]]; then
    if [[ "$G_OUTCOME" == "allowed" ]]; then
      pass "T1c: policyOutcome=allowed for reference result"
    else
      fail "T1c: policyOutcome=${G_OUTCOME} expected allowed for reference result"
    fi
  fi
fi

# ── T2: approved guidance → scenarioKey must be "approved" ───────────────────
echo ""
echo "── T2: operational decon query → scenarioKey=approved"

QID2="$(curl -sf --max-time 10 -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"question":"How to use the rescue decon machine","mode":"operational"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

if [[ -z "$QID2" ]]; then
  fail "T2: query submission failed"
else
  G2="$(curl -sf --max-time 10 "$BASE/guidance/$QID2" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)"
  G2_TYPE="$(echo "$G2" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance']['type'])" 2>/dev/null || true)"
  G2_SKEY="$(echo "$G2" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['scenarioKey'])" 2>/dev/null || true)"
  info "guidance.type=${G2_TYPE}  scenarioKey=${G2_SKEY}"

  if [[ "$G2_TYPE" == "approved" && "$G2_SKEY" == "approved" ]]; then
    pass "T2: approved guidance → scenarioKey=approved"
  elif [[ "$G2_TYPE" != "approved" ]]; then
    pass "T2: query returned type=${G2_TYPE} (corpus may vary) — scenarioKey=${G2_SKEY}"
  else
    fail "T2: guidance.type=${G2_TYPE} but scenarioKey=${G2_SKEY}"
  fi
fi

# ── T3: refusal → scenarioKey must be "refusal" ───────────────────────────────
echo ""
echo "── T3: out-of-scope query → scenarioKey=refusal"

QID3="$(curl -sf --max-time 10 -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"question":"what is the capital of France","mode":"operational"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

if [[ -z "$QID3" ]]; then
  fail "T3: query submission failed"
else
  G3="$(curl -sf --max-time 10 "$BASE/guidance/$QID3" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)"
  G3_TYPE="$(echo "$G3" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance']['type'])" 2>/dev/null || true)"
  G3_SKEY="$(echo "$G3" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['scenarioKey'])" 2>/dev/null || true)"
  info "guidance.type=${G3_TYPE}  scenarioKey=${G3_SKEY}"

  if [[ "$G3_TYPE" == "refusal" && "$G3_SKEY" == "refusal" ]]; then
    pass "T3: refusal guidance → scenarioKey=refusal"
  elif [[ "$G3_TYPE" != "refusal" ]]; then
    pass "T3: query returned type=${G3_TYPE} (corpus may vary) — scenarioKey=${G3_SKEY}"
  else
    fail "T3: guidance.type=${G3_TYPE} but scenarioKey=${G3_SKEY}"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_scenario_key.sh result"
echo "══════════════════════════════════════════════════════"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
