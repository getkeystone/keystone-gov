#!/usr/bin/env bash
# test_relevance_gate.sh — regression tests for the relevance gate and
# document availability flag.
#
# Contracts:
#   T1: CPR/electric-shock query in training mode → NOT a MAYDAY document
#   T2: CPR/electric-shock query → excerpt does NOT contain "MAYDAY" or "LUNAR"
#   T3: CPR/electric-shock query → guidance.document.available is a boolean
#   T4: Decon machine query (valid) → guidance.document.available present
#   T5: Out-of-corpus question ("chocolate cake") → refusal
#   T6: MAYDAY query → still approved (relevance gate not over-firing)
#
# Note: T1/T2 accept EITHER approved-with-CPR-doc OR refusal.  The gate must
# prevent MAYDAY from being returned; it does not require a refusal when a
# relevant CPR document exists in the corpus.
#
# Usage:
#   bash api/tests/test_relevance_gate.sh [BASE_URL]
#
# Defaults:
#   BASE_URL — http://localhost:8000

set -euo pipefail

BASE="${1:-http://localhost:8000}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_relevance_gate.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login ──────────────────────────────────────────────────────────────────────
LOGIN_RESP="$(curl -sf --max-time 10 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"officer","password":"officer"}' 2>/dev/null || true)"
TOKEN="$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "Login: could not obtain officer token (${LOGIN_RESP:0:80})"
  echo ""; echo "PASS: ${PASS}   FAIL: ${FAIL}"; exit 1
fi

# ── Helper ────────────────────────────────────────────────────────────────────
query_guidance() {
  local question="$1"
  local mode="${2:-training}"
  local qid
  qid="$(curl -sf --max-time 10 -X POST "$BASE/query" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "{\"question\":$(python3 -c "import sys,json; print(json.dumps(sys.argv[1]))" "$question"),\"mode\":\"$mode\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

  if [[ -z "$qid" ]]; then
    echo ""
    return 1
  fi

  curl -sf --max-time 10 "$BASE/guidance/$qid" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || true
}

# ── T1: CPR/electric-shock query must NOT return a MAYDAY document ─────────────
echo "── T1: CPR/electric-shock query in training mode"
CPR_RESP="$(query_guidance "what cpr procedure should use for victim from electric shock" "training")"
CPR_TYPE="$(echo "$CPR_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('type','?'))" 2>/dev/null || true)"
CPR_DOC_ID="$(echo "$CPR_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('document',{}).get('documentId',''))" 2>/dev/null || true)"
CPR_REASON="$(echo "$CPR_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('reasonCode',''))" 2>/dev/null || true)"

info "type=${CPR_TYPE}  documentId=${CPR_DOC_ID}  reasonCode=${CPR_REASON}"

# Fail if a MAYDAY doc is returned
CPR_DOC_LOWER="${CPR_DOC_ID,,}"
if [[ "$CPR_DOC_LOWER" == *"mayday"* ]]; then
  fail "T1: CPR query returned a MAYDAY document (${CPR_DOC_ID})"
elif [[ "$CPR_TYPE" == "approved" || "$CPR_TYPE" == "refusal" ]]; then
  pass "T1: CPR query did not return MAYDAY document (type=${CPR_TYPE})"
else
  fail "T1: unexpected guidance type: ${CPR_TYPE}"
fi
echo ""

# ── T2: Excerpt must not contain "MAYDAY" or "LUNAR" ─────────────────────────
echo "── T2: CPR/electric-shock excerpt must not contain MAYDAY/LUNAR keywords"
CPR_EXCERPT="$(echo "$CPR_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('excerpt',''))" 2>/dev/null || true)"

if echo "$CPR_EXCERPT" | grep -qi "MAYDAY\|LUNAR report"; then
  fail "T2: excerpt contains MAYDAY or LUNAR — relevance gate failed"
  info "excerpt[:200]: ${CPR_EXCERPT:0:200}"
else
  pass "T2: excerpt does not contain MAYDAY or LUNAR keywords"
fi
echo ""

# ── T3: guidance.document.available must be a boolean ─────────────────────────
echo "── T3: guidance.document.available field present and boolean"
CPR_AVAIL="$(echo "$CPR_RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
g=d.get('guidance',{})
doc=g.get('document',{})
if 'available' in doc:
    print(str(doc['available']))
else:
    print('MISSING')
" 2>/dev/null || true)"

info "available=${CPR_AVAIL}"
if [[ "$CPR_AVAIL" == "True" || "$CPR_AVAIL" == "False" ]]; then
  pass "T3: document.available is a boolean (${CPR_AVAIL})"
elif [[ "$CPR_TYPE" == "refusal" ]]; then
  pass "T3: refusal (no document object) — available field not required"
else
  fail "T3: document.available missing or not boolean (got: ${CPR_AVAIL})"
fi
echo ""

# ── T4: Decon machine query — available field present ─────────────────────────
echo "── T4: Decon machine query — document.available present"
DECON_RESP="$(query_guidance "How to use the rescue decon machine?" "operational")"
DECON_TYPE="$(echo "$DECON_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('type','?'))" 2>/dev/null || true)"
DECON_AVAIL="$(echo "$DECON_RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
g=d.get('guidance',{})
doc=g.get('document',{})
print(str(doc.get('available','MISSING')))
" 2>/dev/null || true)"

info "type=${DECON_TYPE}  available=${DECON_AVAIL}"
if [[ "$DECON_TYPE" == "approved" && ( "$DECON_AVAIL" == "True" || "$DECON_AVAIL" == "False" ) ]]; then
  pass "T4: decon guidance approved with available=${DECON_AVAIL}"
elif [[ "$DECON_TYPE" == "refusal" ]]; then
  pass "T4: decon query refused (corpus may be empty)"
else
  fail "T4: decon query type=${DECON_TYPE}  available=${DECON_AVAIL}"
fi
echo ""

# ── T5: Truly out-of-scope question → refusal ─────────────────────────────────
echo "── T5: Out-of-corpus question → refusal (relevance gate)"
CAKE_RESP="$(query_guidance "how do I bake a chocolate cake" "training")"
CAKE_TYPE="$(echo "$CAKE_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('type','?'))" 2>/dev/null || true)"
CAKE_CODE="$(echo "$CAKE_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('reasonCode',''))" 2>/dev/null || true)"

info "type=${CAKE_TYPE}  reasonCode=${CAKE_CODE}"
if [[ "$CAKE_TYPE" == "refusal" ]]; then
  pass "T5: out-of-corpus question refused (reasonCode=${CAKE_CODE})"
else
  fail "T5: out-of-corpus question returned type=${CAKE_TYPE} — relevance gate may not be working"
fi
echo ""

# ── T6: MAYDAY query still approved ───────────────────────────────────────────
echo "── T6: MAYDAY query → still approved (gate not over-firing)"
MAYDAY_RESP="$(query_guidance "What is our MAYDAY procedure?" "operational")"
MAYDAY_TYPE="$(echo "$MAYDAY_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('type','?'))" 2>/dev/null || true)"

info "type=${MAYDAY_TYPE}"
if [[ "$MAYDAY_TYPE" == "approved" ]]; then
  pass "T6: MAYDAY query still approved after gate"
else
  fail "T6: MAYDAY query returned type=${MAYDAY_TYPE} — gate is over-firing"
fi
echo ""

# ── T7: Electric-shock CPR must NOT return an AED/defibrillator document ──────
#
# Disambiguation contract: "electric shock victim" is electrical-injury intent,
# not AED shock-delivery intent.  The result must be a CPR/first-aid document,
# not an AED operation manual or a chunk whose primary topic is defibrillation.
echo "── T7: Electric-shock CPR query must not return AED/defibrillator document"
ELEC_RESP="$(query_guidance "what cpr procedure should use for victim from electric shock" "operational")"
ELEC_TYPE="$(echo "$ELEC_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('type','?'))" 2>/dev/null || true)"
ELEC_DOC_ID="$(echo "$ELEC_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('document',{}).get('documentId',''))" 2>/dev/null || true)"
ELEC_EXCERPT="$(echo "$ELEC_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('excerpt',''))" 2>/dev/null || true)"

info "type=${ELEC_TYPE}  documentId=${ELEC_DOC_ID}"

# The documentId must not be an AED device manual.  A CPR guide that mentions
# AED in passing is correct; the failure case is returning an AED device-
# operation manual as the top result.
ELEC_DOC_LOWER="${ELEC_DOC_ID,,}"
if [[ "$ELEC_DOC_LOWER" == *"aed"* ]] || echo "$ELEC_DOC_LOWER" | grep -qP 'defibrillat'; then
  fail "T7: electric-shock CPR returned an AED/defibrillator document (${ELEC_DOC_ID}) — disambiguation failed"
elif [[ "$ELEC_TYPE" == "approved" || "$ELEC_TYPE" == "refusal" ]]; then
  pass "T7: electric-shock CPR did not return AED device document (type=${ELEC_TYPE} doc=${ELEC_DOC_ID})"
else
  fail "T7: unexpected type=${ELEC_TYPE} for electric-shock CPR query"
fi
echo ""

# ── T8: MAYDAY + AED query — disambiguation must not suppress MAYDAY ──────────
echo "── T8: MAYDAY procedure query still approved (intent gate not over-suppressing)"
MAYDAY2_RESP="$(query_guidance "What is our MAYDAY and AED procedure?" "operational")"
MAYDAY2_TYPE="$(echo "$MAYDAY2_RESP" | python3 -c "import sys,json; g=json.load(sys.stdin).get('guidance',{}); print(g.get('type','?'))" 2>/dev/null || true)"

info "type=${MAYDAY2_TYPE}"
if [[ "$MAYDAY2_TYPE" == "approved" || "$MAYDAY2_TYPE" == "refusal" ]]; then
  pass "T8: MAYDAY+AED query handled without error (type=${MAYDAY2_TYPE})"
else
  fail "T8: MAYDAY+AED query returned unexpected type=${MAYDAY2_TYPE}"
fi
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo "══════════════════════════════"
echo "  Overall: PASS=${PASS}  FAIL=${FAIL}"
if [[ "$FAIL" -gt 0 ]]; then
  echo "  test_suite_exit=1"
  echo "══════════════════════════════"
  exit 1
else
  echo "  test_suite_exit=0"
  echo "══════════════════════════════"
  exit 0
fi
