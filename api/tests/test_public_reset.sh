#!/usr/bin/env bash
# test_public_reset.sh — Contract tests for POST /public/reset
#
# Tests:
#   T1: endpoint returns 404 when PUBLIC_DEMO_RESET_TOKEN is not set
#   T2: endpoint returns 403 when wrong token supplied
#   T3: with correct token — creates decision + case, resets, verifies tables empty
#   T4: retention_hours present in response
#
# Behaviour contract:
#   - If PUBLIC_DEMO_RESET_TOKEN env var is empty/unset → 404 (endpoint disabled).
#   - If token supplied but wrong                        → 403 RESET_TOKEN_INVALID.
#   - If token correct                                   → 200 {"reset": true, ...}.
#
# Usage:
#   # With reset enabled (token must match what the running API has):
#   PUBLIC_DEMO_RESET_TOKEN=test-token bash api/tests/test_public_reset.sh [BASE_URL]
#
#   # Without token (tests 404 path):
#   bash api/tests/test_public_reset.sh [BASE_URL]
#
#   BASE_URL defaults to http://127.0.0.1:8080/api

set -euo pipefail

BASE="${1:-http://127.0.0.1:8080/api}"
TOKEN="${PUBLIC_DEMO_RESET_TOKEN:-}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_public_reset.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE  : ${BASE}"
echo "    TOKEN : ${TOKEN:0:8}${TOKEN:+…} (${#TOKEN} chars)"
echo ""

# ── T1: 404 when no token in header (token-disabled path) ────────────────────

if [[ -z "$TOKEN" ]]; then
  echo "── T1: endpoint disabled (no PUBLIC_DEMO_RESET_TOKEN)"
  STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE}/public/reset")"
  if [[ "$STATUS" == "404" ]]; then
    pass "T1: POST /public/reset → 404 (endpoint disabled when token not configured)"
  else
    fail "T1: expected 404, got ${STATUS}"
  fi

  echo ""
  echo "── T2: (skipped — token not configured)"
  echo "── T3: (skipped — token not configured)"
  echo "── T4: (skipped — token not configured)"
  echo ""
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  [[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
fi

# ── T1 (token path): wrong token → 403 ───────────────────────────────────────

echo "── T1: wrong token → 403"
STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE}/public/reset" \
  -H 'X-Reset-Token: definitely-wrong-token-xyzzy')"
if [[ "$STATUS" == "403" ]]; then
  pass "T1: POST /public/reset wrong token → 403"
else
  fail "T1: expected 403, got ${STATUS}"
fi
echo ""

# ── T2: no token header → 403 ────────────────────────────────────────────────

echo "── T2: no token header → 403"
STATUS="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE}/public/reset")"
if [[ "$STATUS" == "403" ]]; then
  pass "T2: POST /public/reset no header → 403"
else
  fail "T2: expected 403, got ${STATUS}"
fi
echo ""

# ── Setup: get officer token, create a decision and case ────────────────────

echo "── Setup: create demo data (decision + case)"
RESP_FILE="$(mktemp)"
trap 'rm -f "$RESP_FILE"' EXIT

jget() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)" 2>/dev/null || true; }

# Login as officer
curl -s -X POST "${BASE}/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"officer","password":"officer"}' > "$RESP_FILE"
OFFICER_TOKEN="$(cat "$RESP_FILE" | jget "['token']")"
if [[ -z "$OFFICER_TOKEN" ]]; then
  fail "Setup: officer login failed — $(cat "$RESP_FILE")"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi

# Login as admin (if available — admin is blocked in PUBLIC_DEMO_MODE=1, so fall back to officer).
curl -s -X POST "${BASE}/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' > "$RESP_FILE"
ADMIN_TOKEN="$(cat "$RESP_FILE" | jget "['token']" 2>/dev/null || true)"
# If admin is blocked (PUBLIC_DEMO_MODE=1), use officer token for case creation.
[[ -z "$ADMIN_TOKEN" ]] && ADMIN_TOKEN="$OFFICER_TOKEN" && info "admin blocked — using officer token for setup"

# Submit a query
curl -s -X POST "${BASE}/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OFFICER_TOKEN" \
  -d '{"question":"Reset test query — decon machine?","mode":"operational"}' > "$RESP_FILE"
QID="$(cat "$RESP_FILE" | jget "['query_id']")"
[[ -n "$QID" ]] || { fail "Setup: query submission failed"; exit 1; }
info "query_id: ${QID}"

# Record a decision
curl -s -X POST "${BASE}/decisions/${QID}" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OFFICER_TOKEN" \
  -d '{"decision":"followed","decision_reason":"reset test"}' > "$RESP_FILE"

# Create a case (may be blocked in PUBLIC_DEMO_MODE=1 — that's acceptable).
curl -s -X POST "${BASE}/cases" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "{\"title\":\"Reset test case\",\"severity\":\"low\",\"query_ids\":[\"${QID}\"]}" > "$RESP_FILE"
CASE_ID="$(cat "$RESP_FILE" | jget "['case_id']" 2>/dev/null || true)"
if [[ -n "$CASE_ID" ]]; then
  info "case_id: ${CASE_ID}"
else
  info "case creation skipped (blocked in PUBLIC_DEMO_MODE=1 or failed — OK)"
  CASE_ID=""
fi
echo ""

# ── T3: correct token → 200, tables cleared ──────────────────────────────────

echo "── T3: correct token → 200, deleted counts present"
curl -s -X POST "${BASE}/public/reset" \
  -H "X-Reset-Token: ${TOKEN}" \
  -H 'Content-Type: application/json' > "$RESP_FILE"
STATUS_RESET="$(cat "$RESP_FILE" | jget "['reset']")"
DELETED_CASES="$(cat "$RESP_FILE" | jget "['deleted']['incident_cases']")"
DELETED_DECISIONS="$(cat "$RESP_FILE" | jget "['deleted']['operator_decisions']")"
info "reset response: $(cat "$RESP_FILE")"

if [[ "$STATUS_RESET" == "True" ]]; then
  pass "T3: reset=true in response"
else
  fail "T3: expected reset=true, got: $(cat "$RESP_FILE")"
fi

if [[ -n "$CASE_ID" ]]; then
  if [[ "$DELETED_CASES" -ge 1 ]]; then
    pass "T3: incident_cases deleted=${DELETED_CASES} (>= 1)"
  else
    fail "T3: expected incident_cases >= 1 deleted, got ${DELETED_CASES}"
  fi
else
  # Cases table may already be empty — just check key is present.
  if python3 -c "import sys,json; d=json.loads(sys.stdin.read()); assert 'incident_cases' in d['deleted']" <<< "$(cat "$RESP_FILE")" 2>/dev/null; then
    pass "T3: incident_cases key present in deleted (no case was pre-created)"
  else
    fail "T3: incident_cases key missing from deleted"
  fi
fi

if [[ "$DELETED_DECISIONS" -ge 1 ]]; then
  pass "T3: operator_decisions deleted=${DELETED_DECISIONS} (>= 1)"
else
  fail "T3: expected operator_decisions >= 1 deleted, got ${DELETED_DECISIONS}"
fi

# Verify case is gone (only if we managed to create one).
if [[ -n "$CASE_ID" ]]; then
  STATUS_GET="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "${BASE}/cases/${CASE_ID}")"
  if [[ "$STATUS_GET" == "404" ]]; then
    pass "T3: GET /cases/${CASE_ID:0:8}… → 404 (case deleted by reset)"
  else
    fail "T3: expected GET /cases/{id} → 404 after reset, got ${STATUS_GET}"
  fi
else
  info "T3: case verification skipped (no case was created)"
fi

# Verify decision is gone
STATUS_DEC="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $OFFICER_TOKEN" \
  "${BASE}/decisions/${QID}")"
if [[ "$STATUS_DEC" == "404" ]]; then
  pass "T3: GET /decisions/${QID:0:8}… → 404 (decision deleted by reset)"
else
  fail "T3: expected GET /decisions/{id} → 404 after reset, got ${STATUS_DEC}"
fi
echo ""

# ── T4: retention_hours in response ──────────────────────────────────────────

echo "── T4: retention_hours in response"
RETENTION="$(cat "$RESP_FILE" | jget "['retention_hours']")"
if [[ -n "$RETENTION" && "$RETENTION" -gt 0 ]]; then
  pass "T4: retention_hours=${RETENTION} present in response"
else
  fail "T4: retention_hours missing or zero"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
