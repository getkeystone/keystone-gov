#!/usr/bin/env bash
# test_doc_change_approval.sh — Contract tests for KDAT-005 document change approval.
#
# Tests:
#   T1: custodian cannot directly PATCH metadata when REQUIRE_DOC_CHANGE_APPROVAL=1 (403)
#   T2: admin can still directly PATCH metadata regardless of flag
#   T3: custodian can POST a change request → status=pending
#   T4: admin can GET /documents/change-requests and see the request
#   T5: admin can approve → status=approved
#   T6: admin can apply → document updated, corpus_doc_events row written
#   T7: applied request has correct before/after snapshots
#   T8: reject workflow — pending → rejected
#
# Usage:
#   bash api/tests/test_doc_change_approval.sh [BASE_URL]
#   BASE_URL defaults to http://127.0.0.1:5174/api

set -euo pipefail

BASE="${1:-http://127.0.0.1:5174/api}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_doc_change_approval.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login ──────────────────────────────────────────────────────────────────────
_login() {
  curl -sf --max-time 10 -X POST "$BASE/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$1\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true
}

T_CUSTODIAN=$(_login custodian)
T_ADMIN=$(_login admin)

if [[ -z "$T_ADMIN" ]]; then
  echo "FATAL: could not obtain admin token"; exit 1
fi
if [[ -z "$T_CUSTODIAN" ]]; then
  echo "WARN: custodian user not seeded — T1/T3 will be skipped"
fi
info "admin: ${T_ADMIN:0:8}…  custodian: ${T_CUSTODIAN:0:8}…"
echo ""

# Pick a document to operate on
DOC_LIST="$(curl -sf --max-time 10 "$BASE/documents" -H "Authorization: Bearer $T_ADMIN" 2>/dev/null || true)"
DOC_ID="$(echo "$DOC_LIST" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['items'][0]['documentId'] if d['items'] else '')" 2>/dev/null || true)"

if [[ -z "$DOC_ID" ]]; then
  echo "FATAL: no documents in corpus"; exit 1
fi
info "document: ${DOC_ID}"
ENC_DOC="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$DOC_ID")"
echo ""

# ── T1: custodian direct PATCH → 403 ──────────────────────────────────────────
echo "── T1: custodian direct PATCH /metadata → 403 (APPROVAL_REQUIRED)"
if [[ -n "$T_CUSTODIAN" ]]; then
  CUST_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -X PATCH "$BASE/documents/${ENC_DOC}/metadata" \
    -H "Authorization: Bearer $T_CUSTODIAN" \
    -H 'Content-Type: application/json' \
    -d '{"owner":"unauthorized-direct"}' 2>/dev/null || echo 000)"
  if [[ "$CUST_CODE" == "403" ]]; then
    pass "T1: custodian PATCH /metadata → 403"
  else
    fail "T1: custodian PATCH /metadata → ${CUST_CODE} (expected 403)"
  fi
else
  info "T1: SKIP (custodian user not seeded)"
fi

# ── T2: admin direct PATCH → 200 ──────────────────────────────────────────────
echo ""
echo "── T2: admin direct PATCH /metadata → 200"
ADMIN_PATCH="$(curl -sf --max-time 10 -X PATCH "$BASE/documents/${ENC_DOC}/metadata" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"owner":"AdminDirectPatch-T2"}' 2>/dev/null || true)"
if echo "$ADMIN_PATCH" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('updated')==True" 2>/dev/null; then
  pass "T2: admin PATCH /metadata → 200"
else
  fail "T2: admin PATCH /metadata unexpected response: ${ADMIN_PATCH:0:100}"
fi
# Restore
curl -sf --max-time 10 -X PATCH "$BASE/documents/${ENC_DOC}/metadata" \
  -H "Authorization: Bearer $T_ADMIN" -H 'Content-Type: application/json' \
  -d '{"owner":""}' > /dev/null

# ── T3: custodian POST change request → pending ────────────────────────────────
echo ""
echo "── T3: custodian POST /change-requests → pending"
REQ_ID=""
if [[ -n "$T_CUSTODIAN" ]]; then
  CR_RESP="$(curl -sf --max-time 10 -X POST "$BASE/documents/${ENC_DOC}/change-requests" \
    -H "Authorization: Bearer $T_CUSTODIAN" \
    -H 'Content-Type: application/json' \
    -d "{\"patch\":{\"owner\":\"CustodianProposed-T3\"},\"reason\":\"Test change request\"}" 2>/dev/null || true)"
  REQ_ID="$(echo "$CR_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('request_id',''))" 2>/dev/null || true)"
  STATUS="$(echo "$CR_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || true)"
  if [[ "$STATUS" == "pending" && -n "$REQ_ID" ]]; then
    pass "T3: change request created — id=${REQ_ID:0:8}… status=pending"
  else
    fail "T3: unexpected response: ${CR_RESP:0:200}"
  fi
else
  # Admin creates the request instead so we can test approve/apply
  info "T3: custodian not seeded — admin creates change request for T4-T7"
  CR_RESP="$(curl -sf --max-time 10 -X POST "$BASE/documents/${ENC_DOC}/change-requests" \
    -H "Authorization: Bearer $T_ADMIN" \
    -H 'Content-Type: application/json' \
    -d "{\"patch\":{\"owner\":\"AdminProposed-T3\"},\"reason\":\"Test fallback (no custodian user)\"}" 2>/dev/null || true)"
  REQ_ID="$(echo "$CR_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('request_id',''))" 2>/dev/null || true)"
  STATUS="$(echo "$CR_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || true)"
  if [[ "$STATUS" == "pending" && -n "$REQ_ID" ]]; then
    pass "T3: admin change request created (fallback) — id=${REQ_ID:0:8}…"
  else
    fail "T3: fallback change request failed: ${CR_RESP:0:200}"
  fi
fi

if [[ -z "$REQ_ID" ]]; then
  echo "FATAL: no request_id — cannot continue with T4-T7"; exit 1
fi

# ── T4: admin GET /documents/change-requests → sees the request ────────────────
echo ""
echo "── T4: GET /documents/change-requests → pending request visible"
LIST_RESP="$(curl -sf --max-time 10 "$BASE/documents/change-requests?status=pending" \
  -H "Authorization: Bearer $T_ADMIN" 2>/dev/null || true)"
FOUND="$(echo "$LIST_RESP" | python3 -c "
import sys,json; d=json.load(sys.stdin)
ids = [r['request_id'] for r in d.get('items',[])]
print('yes' if '$REQ_ID' in ids else 'no')
" 2>/dev/null || echo no)"
if [[ "$FOUND" == "yes" ]]; then
  pass "T4: request visible in GET /documents/change-requests"
else
  fail "T4: request ${REQ_ID:0:8}… not found in list"
fi

# ── T5: admin approve ─────────────────────────────────────────────────────────
echo ""
echo "── T5: POST /change-requests/{id}/approve → approved"
APR_RESP="$(curl -sf --max-time 10 -X POST "$BASE/documents/change-requests/${REQ_ID}/approve" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"decision_reason":"Looks correct"}' 2>/dev/null || true)"
APR_OK="$(echo "$APR_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('approved',''))" 2>/dev/null || echo '')"
if [[ "$APR_OK" == "True" ]]; then
  pass "T5: change request approved"
else
  fail "T5: unexpected approve response: ${APR_RESP:0:200}"
fi

# ── T6: admin apply → document updated ────────────────────────────────────────
echo ""
echo "── T6: POST /change-requests/{id}/apply → document updated"
APPLY_RESP="$(curl -sf --max-time 10 -X POST "$BASE/documents/change-requests/${REQ_ID}/apply" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{}' 2>/dev/null || true)"
APPLIED="$(echo "$APPLY_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('applied',''))" 2>/dev/null || echo '')"
NEW_OWNER="$(echo "$APPLY_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('document',{}).get('owner',''))" 2>/dev/null || echo '')"
if [[ "$APPLIED" == "True" ]]; then
  pass "T6: apply succeeded — new owner='${NEW_OWNER}'"
else
  fail "T6: unexpected apply response: ${APPLY_RESP:0:200}"
fi

# Verify document actually updated via GET
DOC_NOW="$(curl -sf --max-time 10 "$BASE/documents/${ENC_DOC}" -H "Authorization: Bearer $T_ADMIN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('owner',''))" 2>/dev/null || echo '')"
if [[ "$DOC_NOW" == "$NEW_OWNER" && -n "$NEW_OWNER" ]]; then
  pass "T6b: GET /documents/{id} confirms owner='${DOC_NOW}'"
else
  fail "T6b: document owner='${DOC_NOW}' doesn't match applied '${NEW_OWNER}'"
fi

# ── T7: applied request has before/after snapshots ────────────────────────────
echo ""
echo "── T7: GET /documents/change-requests/{id} has before/after"
REQ_DETAIL="$(curl -sf --max-time 10 "$BASE/documents/change-requests/${REQ_ID}" \
  -H "Authorization: Bearer $T_ADMIN" 2>/dev/null || true)"
python3 - "$REQ_DETAIL" <<'PYEOF'
import sys, json
d = json.loads(sys.argv[1]) if sys.argv[1] else {}
errs = []
if d.get('status') != 'applied':
    errs.append(f"status={d.get('status')} (expected applied)")
if not d.get('before_json'):
    errs.append("before_json missing or empty")
if not d.get('after_json'):
    errs.append("after_json missing or empty")
if d.get('applied_at') is None:
    errs.append("applied_at is null")
if errs:
    print("[FAIL] T7: " + "; ".join(errs)); sys.exit(1)
print(f"[PASS] T7: status=applied, before and after snapshots present, applied_at={d['applied_at'][:16]}")
PYEOF
if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

# Verify corpus_doc_events row via docker postgres
echo ""
echo "── T7b: corpus_doc_events row written for change_request_applied"
EVENT_COUNT="$(docker compose exec -T postgres psql -U keystone -d keystone -t \
  -c "SELECT COUNT(*) FROM corpus_doc_events WHERE document_id = '${DOC_ID}' AND action = 'change_request_applied';" \
  2>/dev/null | tr -d ' \n' || echo -1)"
if [[ "$EVENT_COUNT" -ge 1 ]]; then
  pass "T7b: corpus_doc_events has ${EVENT_COUNT} change_request_applied row(s)"
else
  fail "T7b: no change_request_applied event row (count=${EVENT_COUNT})"
fi

# Restore document owner
curl -sf --max-time 10 -X PATCH "$BASE/documents/${ENC_DOC}/metadata" \
  -H "Authorization: Bearer $T_ADMIN" -H 'Content-Type: application/json' \
  -d '{"owner":""}' > /dev/null

# ── T8: reject workflow ────────────────────────────────────────────────────────
echo ""
echo "── T8: reject workflow — pending → rejected"
REQ2_RESP="$(curl -sf --max-time 10 -X POST "$BASE/documents/${ENC_DOC}/change-requests" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"patch":{"owner":"ShouldBeRejected"},"reason":"T8 reject test"}' 2>/dev/null || true)"
REQ2_ID="$(echo "$REQ2_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('request_id',''))" 2>/dev/null || true)"

if [[ -n "$REQ2_ID" ]]; then
  REJ_RESP="$(curl -sf --max-time 10 -X POST "$BASE/documents/change-requests/${REQ2_ID}/reject" \
    -H "Authorization: Bearer $T_ADMIN" \
    -H 'Content-Type: application/json' \
    -d '{"decision_reason":"Not needed"}' 2>/dev/null || true)"
  REJ_OK="$(echo "$REJ_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rejected',''))" 2>/dev/null || echo '')"
  if [[ "$REJ_OK" == "True" ]]; then
    pass "T8: change request rejected"
  else
    fail "T8: reject failed: ${REJ_RESP:0:200}"
  fi
  # Verify status
  REJ_STATUS="$(curl -sf --max-time 10 "$BASE/documents/change-requests/${REQ2_ID}" \
    -H "Authorization: Bearer $T_ADMIN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo '')"
  if [[ "$REJ_STATUS" == "rejected" ]]; then
    pass "T8b: GET confirms status=rejected"
  else
    fail "T8b: status=${REJ_STATUS} (expected rejected)"
  fi
else
  fail "T8: could not create second request"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_doc_change_approval.sh"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]]
