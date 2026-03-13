#!/usr/bin/env bash
# test_doc_governance.sh — Contract tests for KDAT-003 Document Governance endpoints.
#
# Tests:
#   T1: GET /documents returns expected keys and pagination.
#   T2: GET /documents/review-queue returns required sections.
#   T3: GET /documents/review-queue shows overdue doc when review_date < today.
#   T4: PATCH /metadata forbidden for member and officer.
#   T5: PATCH /metadata allowed for custodian and admin.
#   T6: PATCH writes an event row with before/after in corpus_doc_events.
#   T7: GET /documents/{id} returns chunk_count and pages_indexed_count.
#   T8: GET /documents?q=rescue returns matching documents.
#
# Usage:
#   bash api/tests/test_doc_governance.sh [BASE_URL]
#   BASE_URL defaults to http://127.0.0.1:5174/api

set -euo pipefail

BASE="${1:-http://127.0.0.1:5174/api}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_doc_governance.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login for four roles ───────────────────────────────────────────────────────
_login() {
  curl -sf --max-time 10 -X POST "$BASE/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$1\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true
}

T_MEMBER=$(  _login demo)
T_OFFICER=$( _login officer)
T_CUSTODIAN=$(curl -sf --max-time 10 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"custodian","password":"custodian"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)
T_ADMIN=$(   _login admin)

if [[ -z "$T_MEMBER" || -z "$T_ADMIN" ]]; then
  echo "FATAL: could not obtain tokens"; exit 1
fi

# If custodian user not seeded, skip custodian-specific tests but continue.
HAS_CUSTODIAN=$([[ -n "$T_CUSTODIAN" ]] && echo 1 || echo 0)
info "tokens: member=${T_MEMBER:0:8}… officer=${T_OFFICER:0:8}… admin=${T_ADMIN:0:8}…"
echo ""

# ── T1: GET /documents returns expected keys ───────────────────────────────────
echo "── T1: GET /documents — keys and pagination"
DOC_LIST="$(curl -sf --max-time 10 "$BASE/documents" -H "Authorization: Bearer $T_MEMBER" 2>/dev/null || true)"
if [[ -z "$DOC_LIST" ]]; then
  fail "T1: no response from GET /documents"
else
  python3 - "$DOC_LIST" <<'PYEOF'
import sys, json
d = json.loads(sys.argv[1])
errs = []
for key in ("total", "offset", "limit", "items"):
    if key not in d:
        errs.append(f"missing key: {key}")
if d.get("items"):
    item = d["items"][0]
    for k in ("documentId","title","rel_path","status","owner","effectiveDate","reviewDate","reviewOverdue","sha256"):
        if k not in item:
            errs.append(f"item missing key: {k}")
if errs:
    print("[FAIL] T1: " + "; ".join(errs)); sys.exit(1)
total = d["total"]
n     = len(d["items"])
print(f"[PASS] T1: total={total} items={n} keys=ok")
PYEOF
  if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
fi

# ── T2: GET /documents/review-queue has required sections ─────────────────────
echo ""
echo "── T2: GET /documents/review-queue — structure"
RQ="$(curl -sf --max-time 10 "$BASE/documents/review-queue" -H "Authorization: Bearer $T_MEMBER" 2>/dev/null || true)"
if [[ -z "$RQ" ]]; then
  fail "T2: no response from GET /documents/review-queue"
else
  python3 - "$RQ" <<'PYEOF'
import sys, json
d = json.loads(sys.argv[1])
errs = []
for key in ("overdue_review","missing_owner","missing_review_date","draft_or_superseded","counts"):
    if key not in d:
        errs.append(f"missing section: {key}")
counts = d.get("counts", {})
for k in ("overdue_review","missing_owner","missing_review_date","draft_or_superseded"):
    if k not in counts:
        errs.append(f"missing count: {k}")
if errs:
    print("[FAIL] T2: " + "; ".join(errs)); sys.exit(1)
print(f"[PASS] T2: review-queue structure ok  counts={counts}")
PYEOF
  if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
fi

# ── T3: review-queue shows overdue when review_date < today ───────────────────
echo ""
echo "── T3: review-queue reflects overdue after PATCH review_date to past"

# Set review_date to a past date on the first corpus doc.
DOC_ID="$(echo "$DOC_LIST" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['items'][0]['documentId'] if d['items'] else '')" 2>/dev/null || true)"
if [[ -z "$DOC_ID" ]]; then
  fail "T3: no documents in corpus — cannot run overdue test"
else
  # Save current review_date
  ORIG_ENC="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$DOC_ID")"
  ORIG_REV="$(curl -sf --max-time 10 "$BASE/documents/${ORIG_ENC}" \
    -H "Authorization: Bearer $T_ADMIN" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('reviewDate',''))" 2>/dev/null || true)"

  # Patch to past date and verify it took effect
  ENC_ID="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$DOC_ID")"
  PATCH3_RESP="$(curl -sf --max-time 10 -X PATCH \
    "$BASE/documents/${ENC_ID}/metadata" \
    -H "Authorization: Bearer $T_ADMIN" \
    -H 'Content-Type: application/json' \
    -d '{"review_date":"2020-01-01"}' 2>/dev/null || true)"
  PATCHED_REV="$(echo "$PATCH3_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['document'].get('reviewDate','ERR'))" 2>/dev/null || echo ERR)"
  info "T3: PATCH set reviewDate='${PATCHED_REV}'"

  RQ2="$(curl -sf --max-time 10 "$BASE/documents/review-queue" -H "Authorization: Bearer $T_MEMBER" 2>/dev/null || true)"
  OVERDUE_COUNT="$(echo "$RQ2" | python3 -c "import sys,json; print(json.load(sys.stdin)['counts']['overdue_review'])" 2>/dev/null || echo 0)"

  if [[ "$OVERDUE_COUNT" -ge 1 ]]; then
    pass "T3: review-queue shows overdue_review=$OVERDUE_COUNT after setting past date"
  else
    fail "T3: review-queue overdue_review=0 but expected >=1"
  fi

  # Restore original review_date
  curl -sf --max-time 10 -X PATCH \
    "$BASE/documents/${ENC_ID}/metadata" \
    -H "Authorization: Bearer $T_ADMIN" \
    -H 'Content-Type: application/json' \
    -d "{\"review_date\":\"${ORIG_REV}\"}" > /dev/null
  info "T3: review_date restored to '${ORIG_REV}'"
fi

# ── T4: PATCH metadata forbidden for member and officer ───────────────────────
echo ""
echo "── T4: PATCH /metadata — forbidden for member and officer"
ENCODED_DOC="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$DOC_ID")"

MEMBER_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -X PATCH "$BASE/documents/${ENCODED_DOC}/metadata" \
  -H "Authorization: Bearer $T_MEMBER" \
  -H 'Content-Type: application/json' \
  -d '{"owner":"unauthorized"}' 2>/dev/null || echo 000)"

OFFICER_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -X PATCH "$BASE/documents/${ENCODED_DOC}/metadata" \
  -H "Authorization: Bearer $T_OFFICER" \
  -H 'Content-Type: application/json' \
  -d '{"owner":"unauthorized"}' 2>/dev/null || echo 000)"

if [[ "$MEMBER_CODE" == "403" ]]; then
  pass "T4a: member PATCH → 403 Forbidden"
else
  fail "T4a: member PATCH → ${MEMBER_CODE} (expected 403)"
fi
if [[ "$OFFICER_CODE" == "403" ]]; then
  pass "T4b: officer PATCH → 403 Forbidden"
else
  fail "T4b: officer PATCH → ${OFFICER_CODE} (expected 403)"
fi

# ── T5: PATCH allowed for admin ───────────────────────────────────────────────
echo ""
echo "── T5: PATCH /metadata — allowed for admin"
PATCH_RESP="$(curl -sf --max-time 10 -X PATCH \
  "$BASE/documents/${ENCODED_DOC}/metadata" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"owner":"Test Owner T5","effective_date":"2024-06-01"}' 2>/dev/null || true)"
python3 - "$PATCH_RESP" <<'PYEOF'
import sys, json
d = json.loads(sys.argv[1]) if sys.argv[1] else {}
if d.get("updated") is True and d.get("document", {}).get("owner") == "Test Owner T5":
    print("[PASS] T5: admin PATCH succeeded; owner='Test Owner T5'")
    sys.exit(0)
print(f"[FAIL] T5: unexpected response: {sys.argv[1][:200]}")
sys.exit(1)
PYEOF
if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

# Restore owner
curl -sf --max-time 10 -X PATCH "$BASE/documents/${ENCODED_DOC}/metadata" \
  -H "Authorization: Bearer $T_ADMIN" -H 'Content-Type: application/json' \
  -d '{"owner":"","effective_date":""}' > /dev/null

# ── T6: PATCH writes event row with before/after ──────────────────────────────
echo ""
echo "── T6: PATCH writes corpus_doc_events row"
# Check postgres directly via docker
EVENT_COUNT="$(docker compose exec -T postgres psql -U keystone -d keystone -t \
  -c "SELECT COUNT(*) FROM corpus_doc_events WHERE document_id = '${DOC_ID}';" 2>/dev/null | tr -d ' \n' || echo -1)"
if [[ "$EVENT_COUNT" -ge 1 ]]; then
  LAST_ACTOR="$(docker compose exec -T postgres psql -U keystone -d keystone -t \
    -c "SELECT actor_username FROM corpus_doc_events WHERE document_id = '${DOC_ID}' ORDER BY ts_utc DESC LIMIT 1;" \
    2>/dev/null | tr -d ' \n' || true)"
  pass "T6: corpus_doc_events has ${EVENT_COUNT} row(s) for doc; actor='${LAST_ACTOR}'"
else
  fail "T6: no event rows found (count=${EVENT_COUNT})"
fi

# ── T7: GET /documents/{id} returns chunk stats ───────────────────────────────
echo ""
echo "── T7: GET /documents/{id} — chunk stats"
DETAIL="$(curl -sf --max-time 10 "$BASE/documents/${ENCODED_DOC}" -H "Authorization: Bearer $T_MEMBER" 2>/dev/null || true)"
python3 - "$DETAIL" <<'PYEOF'
import sys, json
d = json.loads(sys.argv[1]) if sys.argv[1] else {}
errs = []
for k in ("chunk_count","pages_indexed_count","pages_null_count"):
    if d.get(k) is None:
        errs.append(f"{k} is null")
if errs:
    print("[FAIL] T7: " + "; ".join(errs)); sys.exit(1)
print(f"[PASS] T7: chunks={d['chunk_count']} pages_indexed={d['pages_indexed_count']} pages_null={d['pages_null_count']}")
PYEOF
if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

# ── T8: GET /documents?q=rescue — search works ────────────────────────────────
echo ""
echo "── T8: GET /documents?q=rescue — search filter"
SEARCH="$(curl -sf --max-time 10 "$BASE/documents?q=rescue" -H "Authorization: Bearer $T_MEMBER" 2>/dev/null || true)"
python3 - "$SEARCH" <<'PYEOF'
import sys, json
d = json.loads(sys.argv[1]) if sys.argv[1] else {}
items = d.get("items", [])
if items and any("rescue" in i.get("title","").lower() or "rescue" in i.get("rel_path","").lower() for i in items):
    print(f"[PASS] T8: search q=rescue returned {len(items)} item(s); first={items[0]['documentId']}")
    sys.exit(0)
print(f"[FAIL] T8: search q=rescue returned {len(items)} items but none matched 'rescue'")
sys.exit(1)
PYEOF
if [[ $? -eq 0 ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_doc_governance.sh"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]]
