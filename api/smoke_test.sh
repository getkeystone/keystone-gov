#!/usr/bin/env bash
# Smoke test for the keystone-gov API.
# Run after: docker compose -f keystone-deploy/docker-compose.yml up -d
# Usage: bash keystone-gov/api/smoke_test.sh [base_url]
set -euo pipefail

BASE=${1:-http://localhost:8000}

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

auth_header() { echo "Authorization: Bearer $1"; }

# ---- 1. Health (no auth required) ------------------------------------
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

# ---- 2. Login (member) ------------------------------------------------
echo "=== 2. Login (member) ==="
LOGIN=$(curl -sf -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo"}')
TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
ROLE=$(echo "$LOGIN"  | python3 -c "import sys,json; print(json.load(sys.stdin)['role'])")
[ -n "$TOKEN" ] && pass "login: got token" || fail "login: no token"
[ "$ROLE" = "member" ] && pass "login: role=member" || fail "login: expected member, got $ROLE"

# ---- 2b. Login (admin) ------------------------------------------------
echo "=== 2b. Login (admin) ==="
ADMIN_LOGIN=$(curl -sf -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}')
ADMIN_TOKEN=$(echo "$ADMIN_LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
[ -n "$ADMIN_TOKEN" ] && pass "login admin: got token" || fail "login admin: no token"

# ---- 3. Unauthenticated request is rejected ---------------------------
echo "=== 3. Unauthenticated rejection ==="
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/guidance/demo-approved-001")
[ "$HTTP_CODE" = "401" ] && pass "unauth: 401 returned" || fail "unauth: expected 401, got $HTTP_CODE"

# ---- 4. Submit query (member token, real retrieval) -------------------
echo "=== 4. Submit query ==="
QRESP=$(curl -sf -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "$(auth_header "$TOKEN")" \
  -d '{"question":"What is our MAYDAY procedure?","mode":"operational"}')
QUERY_ID=$(echo "$QRESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")
[ -n "$QUERY_ID" ] && pass "query: got query_id=$QUERY_ID" || fail "query: no query_id"

# ---- 5. Get guidance --------------------------------------------------
echo "=== 5. Get guidance ==="
GUIDANCE=$(curl -sf "$BASE/guidance/$QUERY_ID" -H "$(auth_header "$TOKEN")")
GTYPE=$(echo "$GUIDANCE" | python3 -c "import sys,json; print(json.load(sys.stdin)['guidance']['type'])")
[ "$GTYPE" = "approved" ] && pass "guidance: type=approved" || fail "guidance: unexpected type=$GTYPE"

# ---- 6. Get audit receipt ---------------------------------------------
echo "=== 6. Audit receipt ==="
AUDIT=$(curl -sf "$BASE/audit/$QUERY_ID" -H "$(auth_header "$TOKEN")")
OUTCOME=$(echo "$AUDIT" | python3 -c "import sys,json; print(json.load(sys.stdin)['policyOutcome'])")
[ "$OUTCOME" = "allowed" ] && pass "audit: policyOutcome=allowed" || fail "audit: outcome=$OUTCOME"

# ---- 7. Verify HMAC chain --------------------------------------------
echo "=== 7. Audit verify ==="
VERIFY=$(curl -sf "$BASE/audit/$QUERY_ID/verify" -H "$(auth_header "$TOKEN")")
VALID=$(echo "$VERIFY" | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])")
[ "$VALID" = "True" ] && pass "audit verify: HMAC valid" || fail "audit verify: HMAC mismatch (valid=$VALID)"

# ---- 8. Source lookup ------------------------------------------------
echo "=== 8. Source lookup ==="
SOURCE=$(curl -sf "$BASE/source/demo-fd-mayday-v3/4" -H "$(auth_header "$TOKEN")")
STITLE=$(echo "$SOURCE" | python3 -c "import sys,json; print(json.load(sys.stdin)['title'])")
[ -n "$STITLE" ] && pass "source: title=$STITLE" || fail "source: empty title"
echo "$STITLE" | grep -qi "lrfd" && fail "source: title contains forbidden string: $STITLE" || true

# ---- 9. Seeded demo query --------------------------------------------
echo "=== 9. Seeded demo query (demo-approved-001) ==="
DEMO=$(curl -sf "$BASE/guidance/demo-approved-001" -H "$(auth_header "$TOKEN")")
DID=$(echo "$DEMO" | python3 -c "import sys,json; print(json.load(sys.stdin)['queryId'])")
[ "$DID" = "demo-approved-001" ] && pass "seeded guidance: queryId=$DID" || fail "seeded guidance"

# ---- 10. ACL: member denied restricted content (no source leakage) ---
echo "=== 10. ACL: member denied restricted (no leakage) ==="
DENIED=$(curl -sf -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "$(auth_header "$TOKEN")" \
  -d '{"question":"Show the restricted post-incident disciplinary memo","mode":"operational"}')
DENIED_QID=$(echo "$DENIED" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")
DENIED_TYPE=$(curl -sf "$BASE/guidance/$DENIED_QID" -H "$(auth_header "$TOKEN")" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['guidance']['type'])")
[ "$DENIED_TYPE" = "refusal" ] && pass "ACL denied: member gets refusal" || fail "ACL denied: expected refusal, got $DENIED_TYPE"

DENIED_CITES=$(curl -sf "$BASE/audit/$DENIED_QID" -H "$(auth_header "$TOKEN")" \
  | python3 -c "import sys,json; print(len(json.load(sys.stdin)['citationsReturned']))")
[ "$DENIED_CITES" = "0" ] && pass "ACL denied: zero citations (no source leakage)" || fail "ACL denied: citations leaked ($DENIED_CITES)"

DENIED_REASON=$(curl -sf "$BASE/guidance/$DENIED_QID" -H "$(auth_header "$TOKEN")" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['guidance']['reasonCode'])")
[ "$DENIED_REASON" = "ACCESS_RESTRICTED" ] && pass "ACL denied: reasonCode=ACCESS_RESTRICTED" || fail "ACL denied: wrong reasonCode=$DENIED_REASON"

# ---- 11. ACL: admin allowed restricted content -----------------------
echo "=== 11. ACL: admin allowed restricted (scenario override) ==="
ALLOWED=$(curl -sf -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "$(auth_header "$ADMIN_TOKEN")" \
  -d '{"question":"Show restricted memo","mode":"operational","scenario_key":"restricted"}')
ALLOWED_QID=$(echo "$ALLOWED" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")
ALLOWED_TYPE=$(curl -sf "$BASE/guidance/$ALLOWED_QID" -H "$(auth_header "$ADMIN_TOKEN")" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['guidance']['type'])")
[ "$ALLOWED_TYPE" = "approved" ] && pass "ACL admin: approved for restricted" || fail "ACL admin: expected approved, got $ALLOWED_TYPE"

ALLOWED_OUTCOME=$(curl -sf "$BASE/audit/$ALLOWED_QID" -H "$(auth_header "$ADMIN_TOKEN")" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['policyOutcome'])")
[ "$ALLOWED_OUTCOME" = "allowed" ] && pass "ACL admin: audit shows allowed" || fail "ACL admin: outcome=$ALLOWED_OUTCOME"

# ---- 12. Tamper-evidence proof ---------------------------------------
echo "=== 12. Tamper-evidence proof ==="

# Create a fresh query as admin
TAMPER_QRESP=$(curl -sf -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "$(auth_header "$ADMIN_TOKEN")" \
  -d '{"question":"What is our MAYDAY procedure?","mode":"operational"}')
TAMPER_QID=$(echo "$TAMPER_QRESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")

# Verify before tamper: must be valid
PRE_VALID=$(curl -sf "$BASE/audit/$TAMPER_QID/verify" -H "$(auth_header "$ADMIN_TOKEN")" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])")
[ "$PRE_VALID" = "True" ] && pass "tamper proof: pre-tamper valid=True" || fail "tamper proof: pre-tamper HMAC invalid (=$PRE_VALID)"

# Tamper the audit entry (admin only)
TAMPER_RESP=$(curl -sf -X POST "$BASE/admin/tamper/$TAMPER_QID" \
  -H "$(auth_header "$ADMIN_TOKEN")")
TAMPERED=$(echo "$TAMPER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['tampered'])")
[ "$TAMPERED" = "True" ] && pass "tamper proof: tamper applied" || fail "tamper proof: tamper failed"

# Verify after tamper: must be invalid
POST_VALID=$(curl -sf "$BASE/audit/$TAMPER_QID/verify" -H "$(auth_header "$ADMIN_TOKEN")" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])")
[ "$POST_VALID" = "False" ] && pass "tamper proof: post-tamper valid=False (tamper detected)" || fail "tamper proof: HMAC did not detect tamper (valid=$POST_VALID)"

# Non-admin cannot tamper
NOAUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/tamper/$TAMPER_QID" \
  -H "$(auth_header "$TOKEN")")
[ "$NOAUTH_CODE" = "403" ] && pass "tamper proof: member gets 403 on tamper endpoint" || fail "tamper proof: expected 403, got $NOAUTH_CODE"

# ---- 13. Role spoofing is ignored ------------------------------------
echo "=== 13. Role spoofing is ignored ==="
# Submit query as member but include role="admin" in the request body.
# The server must derive role from the session token, not the request body.
SPOOF=$(curl -sf -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "$(auth_header "$TOKEN")" \
  -d '{"question":"Show the restricted post-incident disciplinary memo","mode":"operational","role":"admin"}')
SPOOF_QID=$(echo "$SPOOF" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")

SPOOF_GUIDANCE=$(curl -sf "$BASE/guidance/$SPOOF_QID" -H "$(auth_header "$TOKEN")")
SPOOF_TYPE=$(echo "$SPOOF_GUIDANCE" | python3 -c "import sys,json; print(json.load(sys.stdin)['guidance']['type'])")
[ "$SPOOF_TYPE" = "refusal" ] && pass "role spoof: member still gets refusal (role in body ignored)" \
  || fail "role spoof: expected refusal, got $SPOOF_TYPE (role from body was accepted)"

SPOOF_REASON=$(echo "$SPOOF_GUIDANCE" | python3 -c "import sys,json; print(json.load(sys.stdin)['guidance']['reasonCode'])")
[ "$SPOOF_REASON" = "ACCESS_RESTRICTED" ] && pass "role spoof: reasonCode=ACCESS_RESTRICTED" \
  || fail "role spoof: wrong reasonCode=$SPOOF_REASON"

SPOOF_CITES=$(curl -sf "$BASE/audit/$SPOOF_QID" -H "$(auth_header "$TOKEN")" \
  | python3 -c "import sys,json; print(len(json.load(sys.stdin)['citationsReturned']))")
[ "$SPOOF_CITES" = "0" ] && pass "role spoof: zero citations returned (no source leakage)" \
  || fail "role spoof: $SPOOF_CITES citation(s) leaked despite refusal"


# ---- 14. Corpus FTS ingest smoke test (optional) ----------------------
# Only runs when RUN_CORPUS_INGEST_TEST=1. Requires the stack to be up,
# docker compose reachable, and the real corpus already ingested.
# (set COMPOSE_DIR to keystone-deploy/ if needed)
#
# Checks:
#   a) Synthetic ingest: failed=0, added>0
#   b) Unique-token query: type=approved, citation references smoke-test.txt
#   c) Real corpus query: citation is a document file (.pdf or .docx)
#   d) Clean up synthetic doc from DB

if [[ "${RUN_CORPUS_INGEST_TEST:-0}" == "1" ]]; then
  echo "=== 14. Corpus FTS ingest smoke test ==="

  _SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  COMPOSE_DIR="${COMPOSE_DIR:-${_SCRIPT_DIR}/../../keystone-deploy}"
  UNIQUE_TOKEN="KEYSTONEFTSSMK$(date +%s)"

  # 14a. Create temp corpus inside the container and capture ingest JSON output.
  INGEST_OUT=$(cd "$COMPOSE_DIR" && docker compose exec -T api bash -c "
    mkdir -p /tmp/smoke-corpus/active /tmp/smoke-corpus/receipts
    printf '%s\n' 'The ${UNIQUE_TOKEN} emergency protocol requires all responders to acknowledge within thirty seconds.' \
      > /tmp/smoke-corpus/active/smoke-test.txt
    CORPUS_ROOT=/tmp/smoke-corpus python3 /app/ingest_corpus.py
    rm -rf /tmp/smoke-corpus
  " 2>/dev/null)

  # Parse the JSON line from ingest output (last line starting with '{')
  INGEST_JSON=$(echo "$INGEST_OUT" | grep '^{' | tail -1)

  INGEST_FAILED=$(echo "$INGEST_JSON" \
    | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('failed',1))" 2>/dev/null || echo "1")
  INGEST_ADDED=$(echo "$INGEST_JSON" \
    | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('added',0))" 2>/dev/null || echo "0")

  [ "$INGEST_FAILED" = "0" ] \
    && pass "corpus FTS: synthetic ingest failed=0" \
    || fail "corpus FTS: synthetic ingest failed=${INGEST_FAILED} (expected 0)"

  [ "$INGEST_ADDED" -gt 0 ] \
    && pass "corpus FTS: synthetic ingest added=${INGEST_ADDED}" \
    || fail "corpus FTS: synthetic ingest added=0 (expected >0)"

  # 14b. Query for the unique token
  FTS_Q=$(curl -sf -X POST "$BASE/query" \
    -H 'Content-Type: application/json' \
    -H "$(auth_header "$TOKEN")" \
    -d "{\"question\":\"${UNIQUE_TOKEN} emergency protocol\",\"mode\":\"operational\"}")
  FTS_QID=$(echo "$FTS_Q" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")
  FTS_GUIDANCE=$(curl -sf "$BASE/guidance/$FTS_QID" -H "$(auth_header "$TOKEN")")
  FTS_TYPE=$(echo "$FTS_GUIDANCE" | python3 -c "import sys,json; print(json.load(sys.stdin)['guidance']['type'])")
  [ "$FTS_TYPE" = "approved" ] \
    && pass "corpus FTS: unique token returns approved" \
    || fail "corpus FTS: expected approved, got $FTS_TYPE"

  FTS_CITE=$(curl -sf "$BASE/audit/$FTS_QID" -H "$(auth_header "$TOKEN")" \
    | python3 -c "import sys,json; cites=json.load(sys.stdin)['citationsReturned']; print(cites[0]['documentId'] if cites else '')")
  echo "$FTS_CITE" | grep -qF "smoke-test" \
    && pass "corpus FTS: citation references smoke-test.txt" \
    || fail "corpus FTS: unexpected citation documentId: $FTS_CITE"

  # 14c. Real corpus query: verify citation is a real document file.
  # Assumes the real corpus (PDFs/DOCX) has been ingested before this test runs.
  REAL_Q=$(curl -sf -X POST "$BASE/query" \
    -H 'Content-Type: application/json' \
    -H "$(auth_header "$TOKEN")" \
    -d '{"question":"emergency response procedure","mode":"operational"}')
  REAL_QID=$(echo "$REAL_Q" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")
  REAL_CITE=$(curl -sf "$BASE/audit/$REAL_QID" -H "$(auth_header "$TOKEN")" \
    | python3 -c "
import sys, json
cites = json.load(sys.stdin)['citationsReturned']
print(cites[0]['documentId'] if cites else '')
")
  echo "$REAL_CITE" | python3 -c "
import sys, re
cid = sys.stdin.read().strip()
if re.search(r'\.(pdf|docx)$', cid, re.IGNORECASE):
    sys.exit(0)
sys.exit(1)
" \
    && pass "corpus FTS: real corpus citation is a document file (${REAL_CITE})" \
    || fail "corpus FTS: real corpus citation not a .pdf/.docx: '${REAL_CITE}'"

  # 14d. Clean up smoke doc from DB (owner credentials already in container env)
  (cd "$COMPOSE_DIR" && docker compose exec -T api python3 -c "
import psycopg2, os
conn = psycopg2.connect(os.environ.get('TAMPER_DATABASE_URL', os.environ['DATABASE_URL']))
cur = conn.cursor()
cur.execute(\"DELETE FROM corpus_documents WHERE rel_path = 'smoke-test.txt'\")
conn.commit(); cur.close(); conn.close()
print('smoke corpus cleaned up')
  ")
fi

echo ""
echo "All smoke tests passed."
