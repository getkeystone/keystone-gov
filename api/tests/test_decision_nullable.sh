#!/usr/bin/env bash
# test_decision_nullable.sh — Contract tests for nullable decision fetch mode.
#
# Tests:
#   T1: GET /decisions/<qid>           → 404 (legacy default, no decision yet)
#   T2: GET /decisions/<qid>?nullable=1 → 200, exists=false, decision=null
#   T3: POST /decisions/<qid>          → decision created
#   T4: GET /decisions/<qid>?nullable=1 → 200, exists=true, decision.decision=followed
#   T5: GET /decisions/<qid>           → 200 (legacy still works after decision recorded)
#
# Usage:
#   bash api/tests/test_decision_nullable.sh [BASE_URL]
#   BASE_URL defaults to http://127.0.0.1:8080/api
#
# Exit: 0 = all pass; 1 = one or more failures.

set -euo pipefail

BASE="${1:-http://127.0.0.1:8080/api}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_decision_nullable.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login ──────────────────────────────────────────────────────────────────────
_login() {
  curl -sf --max-time 10 -X POST "$BASE/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$1\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true
}

TOKEN=$(_login admin)
if [[ -z "$TOKEN" ]]; then echo "FATAL: could not obtain admin token"; exit 1; fi
info "token: ${TOKEN:0:8}…"
echo ""

# ── Create a fresh query ───────────────────────────────────────────────────────
QID="$(curl -sf --max-time 30 -X POST "$BASE/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"question":"nullable decision contract test","mode":"operational","stream":false}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" \
  2>/dev/null || true)"

if [[ -z "$QID" ]]; then echo "FATAL: could not create test query"; exit 1; fi
info "query_id: ${QID}"
echo ""

# ── T1: legacy GET → 404 before decision is recorded ──────────────────────────
echo "── T1: GET /decisions/<qid> (legacy) → 404 before decision"
T1_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/decisions/${QID}" 2>/dev/null || echo "000")"
if [[ "$T1_CODE" == "404" ]]; then
  pass "T1: legacy GET → 404 (no decision yet)"
else
  fail "T1: expected 404, got HTTP ${T1_CODE}"
fi

# ── T2: nullable GET → 200, exists=false, decision=null ───────────────────────
echo ""
echo "── T2: GET /decisions/<qid>?nullable=1 → 200 exists=false"
T2_BODY="$(curl -sf --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/decisions/${QID}?nullable=1" 2>/dev/null || true)"
T2_HTTP="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/decisions/${QID}?nullable=1" 2>/dev/null || echo "000")"
if [[ "$T2_HTTP" != "200" ]]; then
  fail "T2: expected HTTP 200, got ${T2_HTTP}"
else
  python3 - "$T2_BODY" <<'PYEOF'
import sys, json
try:
    d = json.loads(sys.argv[1])
    errs = []
    if d.get('exists') is not False:
        errs.append(f"exists={d.get('exists')!r} (expected false)")
    if d.get('decision') is not None:
        errs.append(f"decision={d.get('decision')!r} (expected null)")
    if errs:
        print("[FAIL] T2: " + "; ".join(errs)); sys.exit(1)
    print("[PASS] T2: nullable GET → exists=false, decision=null")
except Exception as e:
    print(f"[FAIL] T2: parse error: {e}"); sys.exit(1)
PYEOF
  if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
fi

# ── T3: POST a decision ────────────────────────────────────────────────────────
echo ""
echo "── T3: POST /decisions/<qid> → decision created"
T3_RESP="$(curl -sf --max-time 10 -X POST "$BASE/decisions/${QID}" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"decision":"followed","notes":"nullable contract test"}' \
  2>/dev/null || true)"
T3_CREATED="$(echo "$T3_RESP" | python3 -c \
  "import sys,json; print(json.load(sys.stdin).get('created',''))" 2>/dev/null || echo '')"
if [[ "$T3_CREATED" == "True" ]]; then
  pass "T3: POST decision → created=true"
else
  fail "T3: POST decision failed: ${T3_RESP:0:200}"
fi

# ── T4: nullable GET → 200, exists=true, decision present ─────────────────────
echo ""
echo "── T4: GET /decisions/<qid>?nullable=1 → 200 exists=true"
T4_BODY="$(curl -sf --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/decisions/${QID}?nullable=1" 2>/dev/null || true)"
T4_HTTP="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/decisions/${QID}?nullable=1" 2>/dev/null || echo "000")"
if [[ "$T4_HTTP" != "200" ]]; then
  fail "T4: expected HTTP 200, got ${T4_HTTP}"
else
  python3 - "$T4_BODY" <<'PYEOF'
import sys, json
try:
    d = json.loads(sys.argv[1])
    errs = []
    if d.get('exists') is not True:
        errs.append(f"exists={d.get('exists')!r} (expected true)")
    dec = d.get('decision')
    if dec is None:
        errs.append("decision is null (expected object)")
    elif dec.get('decision') != 'followed':
        errs.append(f"decision.decision={dec.get('decision')!r} (expected followed)")
    elif not dec.get('query_id'):
        errs.append("decision.query_id missing")
    elif not dec.get('created_by_username'):
        errs.append("decision.created_by_username missing")
    if errs:
        print("[FAIL] T4: " + "; ".join(errs)); sys.exit(1)
    print(f"[PASS] T4: nullable GET → exists=true, decision={dec['decision']}, by={dec['created_by_username']}")
except Exception as e:
    print(f"[FAIL] T4: parse error: {e}"); sys.exit(1)
PYEOF
  if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
fi

# ── T5: legacy GET still works after decision recorded ────────────────────────
echo ""
echo "── T5: GET /decisions/<qid> (legacy) → 200 after decision recorded"
T5_BODY="$(curl -sf --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/decisions/${QID}" 2>/dev/null || true)"
T5_DEC="$(echo "$T5_BODY" | python3 -c \
  "import sys,json; print(json.load(sys.stdin).get('decision',''))" 2>/dev/null || echo '')"
if [[ "$T5_DEC" == "followed" ]]; then
  pass "T5: legacy GET → 200, decision=followed (flat dict, no envelope)"
else
  fail "T5: legacy GET returned unexpected body: ${T5_BODY:0:200}"
fi

# ── Auth guard: unauthenticated request must be rejected ──────────────────────
echo ""
echo "── T6: unauthenticated GET ?nullable=1 → 401"
T6_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  "$BASE/decisions/${QID}?nullable=1" 2>/dev/null || echo "000")"
if [[ "$T6_CODE" == "401" ]]; then
  pass "T6: unauthenticated → 401 (auth unchanged by nullable param)"
else
  fail "T6: expected 401, got HTTP ${T6_CODE}"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_decision_nullable.sh"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]]
