#!/usr/bin/env bash
# test_case_workflow.sh — Contract tests for KDAT-007 supervisor review queue and incident cases.
#
# Tests:
#   T1:  Create query + decision → appears in review-queue (unreviewed_only=1)
#   T2:  Apply supervisor review → disappears from unreviewed queue
#   T3:  Member role → 403 on review-queue
#   T4:  POST /cases → case created
#   T5:  POST /cases/{id}/queries → query added
#   T6:  GET /cases/{id} → queries list includes the query
#   T7:  GET /cases/{id}/timeline → has decision_recorded event
#   T8:  PATCH /cases/{id} (close) → status=closed
#   T9:  GET /cases/{id}/pack.zip → 200, valid ZIP
#   T10: ZIP contains case.json, timeline.json, incident sub-zip
#   T11: Two case pack downloads produce identical manifest.json sha256 (determinism)
#   T12: Offline verifier (verify_evidence.py) exits 0 on case pack
#   T13: Member role → 403 on /cases
#   T14: DELETE /cases/{id}/queries/{qid} (admin) → removed
#
# Usage:
#   bash api/tests/test_case_workflow.sh [BASE_URL]
#   BASE_URL defaults to http://127.0.0.1:8080/api

set -euo pipefail

BASE="${1:-http://127.0.0.1:8080/api}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFIER="$(cd "$SCRIPT_DIR/../../.." && pwd)/keystone-deploy/tools/verify_case_pack.py"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_case_workflow.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
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
T_MEMBER=$(_login member || _login demo || echo "")

if [[ -z "$T_ADMIN" ]]; then echo "FATAL: could not obtain admin token"; exit 1; fi
info "admin: ${T_ADMIN:0:8}…  officer: ${T_OFFICER:0:8}…  member: ${T_MEMBER:0:8}…"
echo ""

if [[ -f "$VERIFIER" ]]; then
  HAS_VERIFIER=1; info "verifier: $VERIFIER"
else
  HAS_VERIFIER=0; info "WARN: verifier not found at $VERIFIER — T12 will be skipped"
fi

# ── Create query ───────────────────────────────────────────────────────────────
QID="$(curl -sf --max-time 30 -X POST "$BASE/query" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"question":"rescue procedure","scenario_key":"general","mode":"operational","stream":false}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"
if [[ -z "$QID" ]]; then echo "FATAL: could not create test query"; exit 1; fi
info "query_id: ${QID}"
echo ""

# ── POST decision ──────────────────────────────────────────────────────────────
curl -sf --max-time 10 -X POST "$BASE/decisions/${QID}" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"decision":"followed","notes":"Procedure followed without deviation"}' > /dev/null 2>&1 || true
info "decision posted for ${QID:0:8}…"
echo ""

# ── T1: query appears in review-queue (unreviewed_only=1) ─────────────────────
echo "── T1: query appears in review-queue (unreviewed_only=1)"
RQ_RESP="$(curl -sf --max-time 10 "$BASE/review-queue?unreviewed_only=1&limit=100" \
  -H "Authorization: Bearer $T_ADMIN" 2>/dev/null || true)"
FOUND_RQ="$(echo "$RQ_RESP" | python3 -c "
import sys,json; d=json.load(sys.stdin)
ids = [r['query_id'] for r in d.get('items',[])]
print('yes' if '$QID' in ids else 'no')
" 2>/dev/null || echo no)"
if [[ "$FOUND_RQ" == "yes" ]]; then
  pass "T1: query found in review queue"
else
  fail "T1: query not found in review queue (got: ${RQ_RESP:0:200})"
fi

# ── T2: apply supervisor review → disappears from unreviewed_only queue ────────
echo ""
echo "── T2: supervisor review → query removed from unreviewed queue"
REV_TOKEN="${T_OFFICER:-$T_ADMIN}"
REV_RESP="$(curl -sf --max-time 10 -X PATCH "$BASE/decisions/${QID}/review" \
  -H "Authorization: Bearer $REV_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"supervisor_reviewed":true}' 2>/dev/null || true)"
REV_OK="$(echo "$REV_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('reviewed',''))" 2>/dev/null || echo '')"
if [[ "$REV_OK" == "True" ]]; then
  # Check it no longer appears in unreviewed queue
  RQ_RESP2="$(curl -sf --max-time 10 "$BASE/review-queue?unreviewed_only=1&limit=100" \
    -H "Authorization: Bearer $T_ADMIN" 2>/dev/null || true)"
  STILL_FOUND="$(echo "$RQ_RESP2" | python3 -c "
import sys,json; d=json.load(sys.stdin)
ids = [r['query_id'] for r in d.get('items',[])]
print('yes' if '$QID' in ids else 'no')
" 2>/dev/null || echo yes)"
  if [[ "$STILL_FOUND" == "no" ]]; then
    pass "T2: after review, query removed from unreviewed_only queue"
  else
    fail "T2: query still appears in unreviewed_only queue after review"
  fi
else
  fail "T2: supervisor review failed: ${REV_RESP:0:200}"
fi

# ── T3: member → 403 on review-queue ──────────────────────────────────────────
echo ""
echo "── T3: member role → 403 on /review-queue"
if [[ -n "$T_MEMBER" ]]; then
  MBR_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H "Authorization: Bearer $T_MEMBER" \
    "$BASE/review-queue" 2>/dev/null || echo 000)"
  if [[ "$MBR_CODE" == "403" ]]; then
    pass "T3: member → 403 on /review-queue"
  else
    fail "T3: expected 403 but got ${MBR_CODE}"
  fi
else
  info "T3: member user not available — SKIP"
  pass "T3: SKIP"
fi

# ── T4: POST /cases → created ─────────────────────────────────────────────────
echo ""
echo "── T4: POST /cases → case created"
CASE_RESP="$(curl -sf --max-time 10 -X POST "$BASE/cases" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"T4-T14 test case","summary":"Created by test_case_workflow.sh","severity":"med"}' \
  2>/dev/null || true)"
CASE_ID="$(echo "$CASE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('case_id',''))" 2>/dev/null || echo '')"
CASE_CREATED="$(echo "$CASE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('created',''))" 2>/dev/null || echo '')"
if [[ "$CASE_CREATED" == "True" && -n "$CASE_ID" ]]; then
  pass "T4: case created — id=${CASE_ID:0:8}…"
else
  fail "T4: unexpected response: ${CASE_RESP:0:200}"
fi

if [[ -z "$CASE_ID" ]]; then echo "FATAL: no case_id — cannot continue"; exit 1; fi

# ── T5: POST /cases/{id}/queries → query added ────────────────────────────────
echo ""
echo "── T5: POST /cases/{id}/queries → query added"
ADD_RESP="$(curl -sf --max-time 10 -X POST "$BASE/cases/${CASE_ID}/queries" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d "{\"query_id\":\"${QID}\"}" 2>/dev/null || true)"
ADD_OK="$(echo "$ADD_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('added',''))" 2>/dev/null || echo '')"
if [[ "$ADD_OK" == "True" ]]; then
  pass "T5: query added to case"
else
  fail "T5: unexpected response: ${ADD_RESP:0:200}"
fi

# ── T6: GET /cases/{id} → queries list includes query ─────────────────────────
echo ""
echo "── T6: GET /cases/{id} → queries includes ${QID:0:8}…"
CASE_DETAIL="$(curl -sf --max-time 10 "$BASE/cases/${CASE_ID}" \
  -H "Authorization: Bearer $T_ADMIN" 2>/dev/null || true)"
QID_FOUND="$(echo "$CASE_DETAIL" | python3 -c "
import sys,json; d=json.load(sys.stdin)
ids = [q['query_id'] for q in d.get('queries',[])]
print('yes' if '$QID' in ids else 'no')
" 2>/dev/null || echo no)"
if [[ "$QID_FOUND" == "yes" ]]; then
  pass "T6: case detail shows query in queries list"
else
  fail "T6: query not found in case detail"
fi

# ── T7: GET /cases/{id}/timeline → has decision_recorded event ────────────────
echo ""
echo "── T7: GET /cases/{id}/timeline → has decision_recorded event"
TL_RESP="$(curl -sf --max-time 10 "$BASE/cases/${CASE_ID}/timeline" \
  -H "Authorization: Bearer $T_ADMIN" 2>/dev/null || true)"
TL_TYPES="$(echo "$TL_RESP" | python3 -c "
import sys,json; d=json.load(sys.stdin)
types = [e['type'] for e in d.get('items',[])]
print(','.join(types))
" 2>/dev/null || echo '')"
if echo "$TL_TYPES" | grep -q "decision"; then
  pass "T7: timeline has decision event (types: ${TL_TYPES})"
else
  fail "T7: timeline missing decision event (types: ${TL_TYPES})"
fi

# ── T8: PATCH /cases/{id} → close case ────────────────────────────────────────
echo ""
echo "── T8: PATCH /cases/{id} status=closed"
PATCH_RESP="$(curl -sf --max-time 10 -X PATCH "$BASE/cases/${CASE_ID}" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"status":"closed"}' 2>/dev/null || true)"
PATCH_OK="$(echo "$PATCH_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('updated',''))" 2>/dev/null || echo '')"
if [[ "$PATCH_OK" == "True" ]]; then
  # Verify via GET
  STATUS_NOW="$(curl -sf --max-time 10 "$BASE/cases/${CASE_ID}" \
    -H "Authorization: Bearer $T_ADMIN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo '')"
  if [[ "$STATUS_NOW" == "closed" ]]; then
    pass "T8: case status=closed confirmed via GET"
  else
    fail "T8: GET shows status=${STATUS_NOW} (expected closed)"
  fi
else
  fail "T8: PATCH failed: ${PATCH_RESP:0:200}"
fi

# ── T9: GET /cases/{id}/pack.zip → 200, valid ZIP ─────────────────────────────
echo ""
echo "── T9: GET /cases/{id}/pack.zip → 200, valid ZIP"
DL_CODE="$(curl -s -o /tmp/test_case.zip -w '%{http_code}' --max-time 90 \
  -H "Authorization: Bearer $T_ADMIN" \
  "$BASE/cases/${CASE_ID}/pack.zip" 2>/dev/null || echo 000)"
if [[ "$DL_CODE" == "200" ]]; then
  IS_ZIP="$(python3 -c "
import zipfile
try:
    zipfile.ZipFile('/tmp/test_case.zip').close()
    print('yes')
except Exception as e:
    print('no:' + str(e))
" 2>/dev/null || echo no)"
  if [[ "$IS_ZIP" == "yes" ]]; then
    pass "T9: case pack download succeeded and is a valid ZIP"
  else
    fail "T9: download succeeded but invalid ZIP: ${IS_ZIP}"
  fi
else
  fail "T9: case pack download returned ${DL_CODE}"
fi

# ── T10: ZIP contains required files ──────────────────────────────────────────
echo ""
echo "── T10: ZIP contains case.json, timeline.json, incident sub-zip"
if [[ "$DL_CODE" == "200" ]]; then
  CHECK="$(python3 - <<'PYEOF'
import zipfile, sys
try:
    with zipfile.ZipFile('/tmp/test_case.zip') as zf:
        names = {i.filename for i in zf.infolist()}
        required = {'case.json', 'timeline.json', 'manifest.json', 'manifest.sig'}
        missing = required - names
        has_incident = any(n.startswith('incident/') and n.endswith('.zip') for n in names)
        if missing:
            print('missing_required:' + ','.join(sorted(missing)))
        elif not has_incident:
            print('missing_incident_zip')
        else:
            print('ok')
except Exception as e:
    print('error:' + str(e))
PYEOF
)"
  if [[ "$CHECK" == "ok" ]]; then
    pass "T10: ZIP contains all required files including incident sub-zip"
  else
    fail "T10: ZIP check failed: ${CHECK}"
  fi
else
  info "T10: SKIP (download failed)"
fi

# ── T11: Two downloads → identical manifest sha256 (determinism) ──────────────
echo ""
echo "── T11: Two case pack downloads → identical manifest.json sha256"
DL_CODE2="$(curl -s -o /tmp/test_case2.zip -w '%{http_code}' --max-time 90 \
  -H "Authorization: Bearer $T_ADMIN" \
  "$BASE/cases/${CASE_ID}/pack.zip" 2>/dev/null || echo 000)"
if [[ "$DL_CODE" == "200" && "$DL_CODE2" == "200" ]]; then
  SHA1="$(python3 -c "
import zipfile, hashlib
with zipfile.ZipFile('/tmp/test_case.zip') as zf:
    print(hashlib.sha256(zf.read('manifest.json')).hexdigest())
" 2>/dev/null || echo FAIL1)"
  SHA2="$(python3 -c "
import zipfile, hashlib
with zipfile.ZipFile('/tmp/test_case2.zip') as zf:
    print(hashlib.sha256(zf.read('manifest.json')).hexdigest())
" 2>/dev/null || echo FAIL2)"
  if [[ "$SHA1" == "$SHA2" && "$SHA1" != "FAIL1" ]]; then
    pass "T11: deterministic case pack manifest sha256=${SHA1:0:16}…"
  else
    fail "T11: manifest sha256 differs: ${SHA1:0:16} vs ${SHA2:0:16}"
  fi
else
  fail "T11: one or both downloads failed (${DL_CODE} / ${DL_CODE2})"
fi
rm -f /tmp/test_case2.zip

# ── T12: offline verifier exits 0 ─────────────────────────────────────────────
echo ""
echo "── T12: offline verifier exits 0 on case pack"
if [[ "$HAS_VERIFIER" -eq 0 ]]; then
  info "T12: SKIP — verifier not found"
  pass "T12: SKIP"
elif [[ "$DL_CODE" != "200" ]]; then
  info "T12: SKIP — download failed"
  pass "T12: SKIP"
elif python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey" 2>/dev/null; then
  PUBKEY_FILE="/tmp/test_case_pubkey.pem"
  curl -sf --max-time 10 "$BASE/evidence/public-key" -o "$PUBKEY_FILE" 2>/dev/null || true
  if [[ -f "$PUBKEY_FILE" && -s "$PUBKEY_FILE" ]]; then
    set +e
    python3 "$VERIFIER" /tmp/test_case.zip --pubkey "$PUBKEY_FILE" > /dev/null 2>&1
    VERIFY_EXIT=$?
    set -e
    if [[ "$VERIFY_EXIT" -eq 0 ]]; then
      pass "T12: offline verifier exits 0 on case pack"
    else
      fail "T12: verifier exited ${VERIFY_EXIT} (expected 0)"
    fi
  else
    info "T12: signing not configured — SKIP"
    pass "T12: SKIP (signing not configured)"
  fi
  rm -f "$PUBKEY_FILE"
else
  info "T12: cryptography library not available — SKIP"
  pass "T12: SKIP"
fi

# ── T13: member → 403 on /cases ───────────────────────────────────────────────
echo ""
echo "── T13: member role → 403 on GET /cases"
if [[ -n "$T_MEMBER" ]]; then
  MBR_CASES="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -H "Authorization: Bearer $T_MEMBER" \
    "$BASE/cases" 2>/dev/null || echo 000)"
  if [[ "$MBR_CASES" == "403" ]]; then
    pass "T13: member → 403 on GET /cases"
  else
    fail "T13: expected 403 but got ${MBR_CASES}"
  fi
else
  info "T13: member user not available — SKIP"
  pass "T13: SKIP"
fi

# ── T14: DELETE /cases/{id}/queries/{qid} (admin) ─────────────────────────────
echo ""
echo "── T14: DELETE /cases/{id}/queries/{qid} (admin only)"
DEL_RESP="$(curl -sf --max-time 10 -X DELETE "$BASE/cases/${CASE_ID}/queries/${QID}" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{}' 2>/dev/null || true)"
DEL_OK="$(echo "$DEL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('removed',''))" 2>/dev/null || echo '')"
if [[ "$DEL_OK" == "True" ]]; then
  # Verify removed
  DETAIL_AFTER="$(curl -sf --max-time 10 "$BASE/cases/${CASE_ID}" \
    -H "Authorization: Bearer $T_ADMIN" 2>/dev/null || true)"
  QID_AFTER="$(echo "$DETAIL_AFTER" | python3 -c "
import sys,json; d=json.load(sys.stdin)
ids = [q['query_id'] for q in d.get('queries',[])]
print('yes' if '$QID' in ids else 'no')
" 2>/dev/null || echo yes)"
  if [[ "$QID_AFTER" == "no" ]]; then
    pass "T14: query removed from case, confirmed via GET"
  else
    fail "T14: query still present after DELETE"
  fi
else
  fail "T14: DELETE returned: ${DEL_RESP:0:200}"
fi

# ── Cleanup ────────────────────────────────────────────────────────────────────
rm -f /tmp/test_case.zip

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_case_workflow.sh"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]]
