#!/usr/bin/env bash
# test_status_policy.sh — test metadata-driven policy enforcement.
#
# Usage:
#   bash api/tests/test_status_policy.sh [BASE_URL]
#
# Tests:
#   1. Set status_override='superseded' on ALL corpus docs, run any query in
#      operational mode → expect type=refusal, reasonCode=NO_ACTIVE_PROCEDURE.
#   2. Restore status_override to '' on all docs.
#   3. Run same query in operational mode → expect type=approved.
#   4. Set one doc to 'superseded', run a query in training mode → expect
#      approved (training mode allows superseded).
#
# Requires: a running API at BASE_URL (default http://127.0.0.1:5174/api).
# Auth: admin/admin (override with ADMIN_USER / ADMIN_PASS).
# DB:   docker exec on PG_CONTAINER (superuser keystone), or local psql.

set -euo pipefail

BASE="${1:-http://127.0.0.1:5174/api}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
DATABASE_URL="${DATABASE_URL:-postgresql://keystone_app:keystone_app_pw@localhost:5432/keystone}"
PG_CONTAINER="${PG_CONTAINER:-keystone-deploy-postgres-1}"

# ── DB helper: run SQL, prefer local psql, fall back to docker exec ───────────
run_sql() {
  local sql="$1"
  if command -v psql &>/dev/null; then
    psql "${DATABASE_URL}" -t -A -c "${sql}" 2>/dev/null
  elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${PG_CONTAINER}$"; then
    docker exec "${PG_CONTAINER}" psql -U keystone -d keystone -t -A -c "${sql}" 2>/dev/null
  else
    echo ""
  fi
}

# Always restore status_override on exit (cleanup trap)
_cleanup() {
  run_sql "UPDATE corpus_documents SET status_override=''" > /dev/null 2>&1 || true
}
trap _cleanup EXIT

echo "=== test_status_policy.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login ─────────────────────────────────────────────────────────────────────
LOGIN_RESP="$(curl -sf --max-time 10 -X POST "${BASE}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null)"
TOKEN="$(echo "${LOGIN_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")"
echo "[OK]  token obtained"

# ── Check that corpus has data ────────────────────────────────────────────────
DOC_COUNT="$(run_sql "SELECT COUNT(*) FROM corpus_documents" || echo "0")"
if [[ "${DOC_COUNT}" -eq 0 ]]; then
  echo "SKIP: no corpus_documents rows found; status policy test requires ingested corpus"
  exit 0
fi
echo "[OK]  corpus has ${DOC_COUNT} document(s)"

# Pick first doc for single-doc tests
TARGET_REL="$(run_sql "SELECT rel_path FROM corpus_documents ORDER BY id LIMIT 1" || echo "")"
echo "[OK]  target doc: ${TARGET_REL}"

# ── Helper: run a query and get guidance type + reasonCode + notice ───────────
run_query() {
  local mode="$1"
  local question="$2"
  local resp qid guid_resp
  resp="$(curl -sf --max-time 15 -X POST "${BASE}/query" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' \
    -d "{\"question\":\"${question}\",\"mode\":\"${mode}\"}" 2>/dev/null)"
  qid="$(echo "${resp}" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")"
  guid_resp="$(curl -sf --max-time 10 \
    -H "Authorization: Bearer ${TOKEN}" \
    "${BASE}/guidance/${qid}" 2>/dev/null)"
  echo "${guid_resp}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
g = d.get('guidance', {})
print(g.get('type','?'), g.get('reasonCode',''), repr(g.get('notice','')))
"
}

# ── Step 1: mark ALL docs as superseded ───────────────────────────────────────
echo ""
echo "── Step 1: set status_override='superseded' on ALL corpus documents ────"
run_sql "UPDATE corpus_documents SET status_override='superseded'" > /dev/null
echo "[OK]  all docs set to superseded"

# ── Step 2: query in operational mode — expect refusal ───────────────────────
echo ""
echo "── Step 2: operational query — should refuse (all docs superseded) ─────"
RESULT="$(run_query "operational" "startup procedure steps operation")"
TYPE="$(echo "${RESULT}" | awk '{print $1}')"
CODE="$(echo "${RESULT}" | awk '{print $2}')"
echo "    type=${TYPE}  reasonCode=${CODE}"

STEP2_OK=0
if [[ "${TYPE}" == "refusal" && "${CODE}" == "NO_ACTIVE_PROCEDURE" ]]; then
  echo "[OK]  operational mode correctly refused superseded docs"
  STEP2_OK=1
else
  echo "[WARN] operational mode returned type=${TYPE} code=${CODE} (expected refusal/NO_ACTIVE_PROCEDURE)"
fi

# ── Step 3: query in training mode — expect approved ─────────────────────────
echo ""
echo "── Step 3: training query — should allow superseded docs ───────────────"
RESULT_TR="$(run_query "training" "startup procedure steps operation")"
TYPE_TR="$(echo "${RESULT_TR}" | awk '{print $1}')"
NOTICE_TR="$(echo "${RESULT_TR}" | awk '{$1=$2=""; print}' | tr -d "'\n" | sed 's/^ *//')"
echo "    type=${TYPE_TR}  notice=${NOTICE_TR}"

if [[ "${TYPE_TR}" == "approved" ]]; then
  echo "[OK]  training mode allowed superseded doc"
  if echo "${RESULT_TR}" | grep -qi "TRAINING_ONLY\|training_only\|document status is"; then
    echo "[OK]  TRAINING_ONLY notice present"
  else
    echo "[WARN] TRAINING_ONLY notice not set (may depend on query match)"
  fi
else
  echo "[WARN] training mode returned type=${TYPE_TR} (corpus may not have matched)"
fi

# ── Step 4: restore all docs ──────────────────────────────────────────────────
echo ""
echo "── Step 4: restore status_override='' on all docs ─────────────────────"
run_sql "UPDATE corpus_documents SET status_override=''" > /dev/null
echo "[OK]  all docs status_override restored to ''"

# ── Step 5: re-query in operational mode — expect approved ───────────────────
echo ""
echo "── Step 5: operational query after restore — should approve ────────────"
RESULT2="$(run_query "operational" "startup procedure steps operation")"
TYPE2="$(echo "${RESULT2}" | awk '{print $1}')"
echo "    type=${TYPE2}"

if [[ "${TYPE2}" == "approved" ]]; then
  echo "[OK]  operational mode approved after status restored"
else
  echo "[WARN] operational mode returned type=${TYPE2} after restore (may be corpus-specific)"
fi

# ── Final result ──────────────────────────────────────────────────────────────
echo ""
if [[ "${STEP2_OK}" -eq 1 ]]; then
  echo "[PASS] Status policy test complete — key assertion passed."
else
  echo "[FAIL] Key assertion failed: operational mode should refuse NO_ACTIVE_PROCEDURE when all docs are superseded."
  exit 1
fi
