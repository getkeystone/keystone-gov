#!/usr/bin/env bash
# Smoke test for the keystone-gov API.
# Run after: docker compose -f keystone-deploy/docker-compose.yml up -d
# Usage: bash keystone-gov/api/smoke_test.sh [base_url]
set -euo pipefail

BASE=${1:-http://localhost:8000}

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

# ---- 1. Health (retry up to 30 s) -------------------------------------
echo "=== 1. Health ==="
STATUS=""
HEALTH_DEADLINE=30
HEALTH_ELAPSED=0
until [ "$STATUS" = "ok" ]; do
  if [ "$HEALTH_ELAPSED" -ge "$HEALTH_DEADLINE" ]; then
    fail "health check timed out after ${HEALTH_DEADLINE}s (last status='${STATUS}')"
  fi
  RESPONSE=$(curl -s "$BASE/health" 2>/dev/null || true)
  STATUS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null || true)
  if [ "$STATUS" != "ok" ]; then
    echo "  waiting for API... (${HEALTH_ELAPSED}s)"
    sleep 2
    HEALTH_ELAPSED=$((HEALTH_ELAPSED + 2))
  fi
done
pass "health: status=ok"

# ---- 2. Login ----------------------------------------------------------
echo "=== 2. Login ==="
LOGIN=$(curl -sf -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo"}')
TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ROLE=$(echo "$LOGIN"  | python3 -c "import sys,json; print(json.load(sys.stdin)['role'])")
[ -n "$TOKEN" ] && pass "login: got token" || fail "login: no token"
pass "login: role=$ROLE"

# ---- 3. Submit query ---------------------------------------------------
echo "=== 3. Submit query ==="
QRESP=$(curl -sf -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -d '{"question":"What is our MAYDAY procedure?","role":"member","mode":"operational","scenario_key":"approved"}')
QUERY_ID=$(echo "$QRESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")
[ -n "$QUERY_ID" ] && pass "query: got query_id=$QUERY_ID" || fail "query: no query_id"

# ---- 4. Get guidance ---------------------------------------------------
echo "=== 4. Get guidance ==="
GUIDANCE=$(curl -sf "$BASE/guidance/$QUERY_ID")
GTYPE=$(echo "$GUIDANCE" | python3 -c "import sys,json; print(json.load(sys.stdin)['guidance']['type'])")
[ "$GTYPE" = "approved" ] && pass "guidance: type=approved" || fail "guidance: unexpected type=$GTYPE"

# ---- 5. Get audit receipt ----------------------------------------------
echo "=== 5. Audit receipt ==="
AUDIT=$(curl -sf "$BASE/audit/$QUERY_ID")
OUTCOME=$(echo "$AUDIT" | python3 -c "import sys,json; print(json.load(sys.stdin)['policyOutcome'])")
[ "$OUTCOME" = "allowed" ] && pass "audit: policyOutcome=allowed" || fail "audit: outcome=$OUTCOME"

# ---- 6. Verify HMAC chain ----------------------------------------------
echo "=== 6. Audit verify ==="
VERIFY=$(curl -sf "$BASE/audit/$QUERY_ID/verify")
VALID=$(echo "$VERIFY" | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])")
[ "$VALID" = "True" ] && pass "audit verify: HMAC valid" || fail "audit verify: HMAC mismatch (valid=$VALID)"

# ---- 7. Source lookup --------------------------------------------------
echo "=== 7. Source lookup ==="
SOURCE=$(curl -sf "$BASE/source/demo-fd-mayday-v3/4")
STITLE=$(echo "$SOURCE" | python3 -c "import sys,json; print(json.load(sys.stdin)['title'])")
[ -n "$STITLE" ] && pass "source: title=$STITLE" || fail "source: empty title"
echo "$STITLE" | grep -qi "lrfd" && fail "source: title still contains LRFD: $STITLE" || true

# ---- 8. Seeded demo query ----------------------------------------------
echo "=== 8. Seeded demo query (demo-approved-001) ==="
DEMO=$(curl -sf "$BASE/guidance/demo-approved-001")
DID=$(echo "$DEMO" | python3 -c "import sys,json; print(json.load(sys.stdin)['queryId'])")
[ "$DID" = "demo-approved-001" ] && pass "seeded guidance: queryId=$DID" || fail "seeded guidance"

# ---- 9. ACL: member denied restricted content (no source leakage) ----------
echo "=== 9. ACL: member denied restricted content ==="
DENIED=$(curl -sf -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -d '{"question":"Show restricted memo","role":"member","mode":"operational","scenario_key":"restricted"}')
DENIED_TYPE=$(echo "$DENIED" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['guidance']['type'] if 'guidance' in d else 'missing')" 2>/dev/null || echo "error")
DENIED_QID=$(echo "$DENIED" | python3 -c "import sys,json; print(json.load(sys.stdin).get('query_id',''))" 2>/dev/null || echo "")
[ "$DENIED_TYPE" = "missing" ] && {
  # guidance is in the query response only via GET /guidance; fetch it
  DENIED_TYPE=$(curl -sf "$BASE/guidance/$DENIED_QID" | python3 -c "import sys,json; print(json.load(sys.stdin)['guidance']['type'])")
}
[ "$DENIED_TYPE" = "refusal" ] && pass "ACL denied: member gets refusal for restricted" || fail "ACL denied: expected refusal, got $DENIED_TYPE"

# Verify no source leakage in audit
DENIED_CITES=$(curl -sf "$BASE/audit/$DENIED_QID" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['citationsReturned']))")
[ "$DENIED_CITES" = "0" ] && pass "ACL denied: no citations returned (no source leakage)" || fail "ACL denied: citations leaked ($DENIED_CITES)"

# ---- 10. ACL: admin allowed restricted content --------------------------
echo "=== 10. ACL: admin allowed restricted content ==="
ALLOWED=$(curl -sf -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -d '{"question":"Show restricted memo","role":"admin","mode":"operational","scenario_key":"restricted"}')
ALLOWED_QID=$(echo "$ALLOWED" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")
ALLOWED_TYPE=$(curl -sf "$BASE/guidance/$ALLOWED_QID" | python3 -c "import sys,json; print(json.load(sys.stdin)['guidance']['type'])")
[ "$ALLOWED_TYPE" = "approved" ] && pass "ACL allowed: admin gets approved for restricted" || fail "ACL allowed: expected approved, got $ALLOWED_TYPE"

ALLOWED_OUTCOME=$(curl -sf "$BASE/audit/$ALLOWED_QID" | python3 -c "import sys,json; print(json.load(sys.stdin)['policyOutcome'])")
[ "$ALLOWED_OUTCOME" = "allowed" ] && pass "ACL allowed: audit shows allowed" || fail "ACL allowed: outcome=$ALLOWED_OUTCOME"

echo ""
echo "All smoke tests passed."
