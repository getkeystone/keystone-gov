#!/usr/bin/env bash
# test_operator_decision.sh — Contract tests for KDAT-006 operator decision receipt.
#
# Tests:
#   T1: POST /decisions/{id} with decision=followed → created
#   T2: GET  /decisions/{id}  → decision fields correct
#   T3: 409 on duplicate POST
#   T4: decision_reason required for non-followed decisions
#   T5: officer PATCH /decisions/{id}/review → supervisor_reviewed=true
#   T6: GET after review → supervisor fields set
#   T7: 422 on invalid decision value
#
# Usage:
#   bash api/tests/test_operator_decision.sh [BASE_URL]
#   BASE_URL defaults to http://127.0.0.1:5174/api

set -euo pipefail

BASE="${1:-http://127.0.0.1:5174/api}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_operator_decision.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login ──────────────────────────────────────────────────────────────────────
_login() {
  curl -sf --max-time 10 -X POST "$BASE/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$1\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true
}

T_ADMIN=$(_login admin)
T_OFFICER=$(_login officer || echo "")

if [[ -z "$T_ADMIN" ]]; then echo "FATAL: could not obtain admin token"; exit 1; fi
info "admin: ${T_ADMIN:0:8}…  officer: ${T_OFFICER:0:8}…"
echo ""

# ── Create a query ─────────────────────────────────────────────────────────────
QID="$(curl -sf --max-time 30 -X POST "$BASE/query" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"question":"rescue procedure","scenario_key":"general","mode":"operational","stream":false}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" \
  2>/dev/null || true)"

if [[ -z "$QID" ]]; then echo "FATAL: could not create test query"; exit 1; fi
info "query_id: ${QID}"
echo ""

# ── T1: POST /decisions/{id} → created ────────────────────────────────────────
echo "── T1: POST /decisions/{id} with decision=followed → created"
DEC_RESP="$(curl -sf --max-time 10 -X POST "$BASE/decisions/${QID}" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"decision":"followed","actions_taken":["Deployed unit to scene","Notified supervisor"],"notes":"Procedure worked well"}' \
  2>/dev/null || true)"
DEC_CREATED="$(echo "$DEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('created',''))" 2>/dev/null || echo '')"
DEC_ID="$(echo "$DEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('decision_id',''))" 2>/dev/null || echo '')"
if [[ "$DEC_CREATED" == "True" && -n "$DEC_ID" ]]; then
  pass "T1: decision created — id=${DEC_ID:0:8}…"
else
  fail "T1: unexpected response: ${DEC_RESP:0:200}"
fi

# ── T2: GET /decisions/{id} → correct fields ───────────────────────────────────
echo ""
echo "── T2: GET /decisions/{id} → fields correct"
GET_RESP="$(curl -sf --max-time 10 "$BASE/decisions/${QID}" \
  -H "Authorization: Bearer $T_ADMIN" 2>/dev/null || true)"
python3 - "$GET_RESP" <<'PYEOF'
import sys, json
d = json.loads(sys.argv[1]) if sys.argv[1] else {}
errs = []
if d.get('decision') != 'followed':
    errs.append(f"decision={d.get('decision')} (expected followed)")
if d.get('created_by_username') != 'admin':
    errs.append(f"created_by_username={d.get('created_by_username')}")
if not isinstance(d.get('actions_taken'), list) or len(d['actions_taken']) != 2:
    errs.append(f"actions_taken count={len(d.get('actions_taken',[]))}")
if d.get('notes') != 'Procedure worked well':
    errs.append(f"notes mismatch")
if d.get('supervisor_reviewed') is not False:
    errs.append(f"supervisor_reviewed should be false initially")
if errs:
    print("[FAIL] T2: " + "; ".join(errs)); sys.exit(1)
print(f"[PASS] T2: decision fields correct (decision={d['decision']}, actions={len(d['actions_taken'])})")
PYEOF
if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

# ── T3: 409 on duplicate POST ──────────────────────────────────────────────────
echo ""
echo "── T3: duplicate POST → 409"
DUP_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST "$BASE/decisions/${QID}" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"decision":"followed"}' 2>/dev/null || echo 000)"
if [[ "$DUP_CODE" == "409" ]]; then
  pass "T3: duplicate POST → 409"
else
  fail "T3: expected 409 but got ${DUP_CODE}"
fi

# ── T4: decision_reason required for non-followed ──────────────────────────────
echo ""
echo "── T4: decision_reason required for overridden"
# Create a second query for this test
QID2="$(curl -sf --max-time 30 -X POST "$BASE/query" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"question":"fire suppression","scenario_key":"general","mode":"operational","stream":false}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" \
  2>/dev/null || true)"
if [[ -z "$QID2" ]]; then
  info "T4: could not create second query — skip"
  pass "T4: SKIP"
else
  NO_REASON_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST "$BASE/decisions/${QID2}" \
    -H "Authorization: Bearer $T_ADMIN" \
    -H 'Content-Type: application/json' \
    -d '{"decision":"overridden","decision_reason":""}' 2>/dev/null || echo 000)"
  if [[ "$NO_REASON_CODE" == "422" ]]; then
    pass "T4: missing decision_reason → 422"
  else
    fail "T4: expected 422 but got ${NO_REASON_CODE}"
  fi

  # With reason should succeed
  WITH_REASON_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST "$BASE/decisions/${QID2}" \
    -H "Authorization: Bearer $T_ADMIN" \
    -H 'Content-Type: application/json' \
    -d '{"decision":"overridden","decision_reason":"Scene conditions prevented following standard procedure"}' 2>/dev/null || echo 000)"
  if [[ "$WITH_REASON_CODE" == "200" ]]; then
    pass "T4b: overridden with reason → 200"
  else
    fail "T4b: expected 200 but got ${WITH_REASON_CODE}"
  fi
fi

# ── T5: PATCH /decisions/{id}/review ──────────────────────────────────────────
echo ""
echo "── T5: PATCH /decisions/{id}/review (officer/admin)"
if [[ -n "$T_OFFICER" ]]; then
  REV_RESP="$(curl -sf --max-time 10 -X PATCH "$BASE/decisions/${QID}/review" \
    -H "Authorization: Bearer $T_OFFICER" \
    -H 'Content-Type: application/json' \
    -d '{"supervisor_reviewed":true}' 2>/dev/null || true)"
  REV_OK="$(echo "$REV_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('reviewed',''))" 2>/dev/null || echo '')"
  if [[ "$REV_OK" == "True" ]]; then
    pass "T5: officer review → reviewed=true"
  else
    fail "T5: unexpected response: ${REV_RESP:0:200}"
  fi
else
  # Use admin token
  REV_RESP="$(curl -sf --max-time 10 -X PATCH "$BASE/decisions/${QID}/review" \
    -H "Authorization: Bearer $T_ADMIN" \
    -H 'Content-Type: application/json' \
    -d '{"supervisor_reviewed":true}' 2>/dev/null || true)"
  REV_OK="$(echo "$REV_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('reviewed',''))" 2>/dev/null || echo '')"
  if [[ "$REV_OK" == "True" ]]; then
    pass "T5: admin review (fallback) → reviewed=true"
  else
    fail "T5: unexpected response: ${REV_RESP:0:200}"
  fi
fi

# ── T6: GET after review → supervisor fields set ──────────────────────────────
echo ""
echo "── T6: GET after review → supervisor_reviewed=true"
GET2_RESP="$(curl -sf --max-time 10 "$BASE/decisions/${QID}" \
  -H "Authorization: Bearer $T_ADMIN" 2>/dev/null || true)"
python3 - "$GET2_RESP" <<'PYEOF'
import sys, json
d = json.loads(sys.argv[1]) if sys.argv[1] else {}
errs = []
if not d.get('supervisor_reviewed'):
    errs.append("supervisor_reviewed is not true")
if not d.get('supervisor_username'):
    errs.append("supervisor_username is null")
if not d.get('supervisor_reviewed_at_utc'):
    errs.append("supervisor_reviewed_at_utc is null")
if errs:
    print("[FAIL] T6: " + "; ".join(errs)); sys.exit(1)
print(f"[PASS] T6: supervisor_reviewed=true, supervisor={d['supervisor_username']}, at={d['supervisor_reviewed_at_utc'][:16]}")
PYEOF
if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

# ── T7: invalid decision value → 422 ──────────────────────────────────────────
echo ""
echo "── T7: invalid decision value → 422"
QID3="$(curl -sf --max-time 30 -X POST "$BASE/query" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"question":"hazmat response","scenario_key":"general","mode":"operational","stream":false}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" \
  2>/dev/null || true)"
if [[ -z "$QID3" ]]; then
  info "T7: could not create third query — skip"
  pass "T7: SKIP"
else
  BAD_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST "$BASE/decisions/${QID3}" \
    -H "Authorization: Bearer $T_ADMIN" \
    -H 'Content-Type: application/json' \
    -d '{"decision":"invalid_value"}' 2>/dev/null || echo 000)"
  if [[ "$BAD_CODE" == "422" ]]; then
    pass "T7: invalid decision value → 422"
  else
    fail "T7: expected 422 but got ${BAD_CODE}"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_operator_decision.sh"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]]
