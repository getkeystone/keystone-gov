#!/usr/bin/env bash
# test_doc_kind_domain_patch.sh
#
# Contract test: PATCH /documents/{id}/metadata must accept domain and
# content_kind, validate against allowed enums, persist to DB, and write
# a corpus_doc_events row with before/after JSON (KDAT-019).
#
# Usage: bash api/tests/test_doc_kind_domain_patch.sh [BASE_URL]
#   Default BASE_URL: http://${PUBLISH_IP}:8080/api (from ~/.config/keystone/env)

set -euo pipefail

ENV_FILE="${HOME}/.config/keystone/env"
_PUBLISH_IP="$(grep '^PUBLISH_IP=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d ' ')"
_PUBLISH_IP="${_PUBLISH_IP:-127.0.0.1}"
BASE="${1:-http://${_PUBLISH_IP}:8080/api}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_doc_kind_domain_patch.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""
echo "    Verify: feat(kdat-019): domain + content_kind patchable via metadata endpoint"
echo ""

# ── Login as admin ─────────────────────────────────────────────────────────────
TOKEN="$(curl -sf --max-time 5 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "login: could not obtain admin token"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"; exit 1
fi
pass "login: admin token obtained"

# ── Pick a known document ──────────────────────────────────────────────────────
TARGET_REL="lrfd-001-roof-load-assessment.txt"

ORIG_DOC="$(curl -sf --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/documents/$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$TARGET_REL")" \
  2>/dev/null || true)"

if [[ -z "$ORIG_DOC" ]]; then
  fail "preflight: could not fetch document '$TARGET_REL'"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"; exit 1
fi

ORIG_DOMAIN="$(echo "$ORIG_DOC" | python3 -c "import sys,json; print(json.load(sys.stdin).get('domain',''))" 2>/dev/null || echo '')"
ORIG_CK="$(echo "$ORIG_DOC" | python3 -c "import sys,json; print(json.load(sys.stdin).get('content_kind',''))" 2>/dev/null || echo '')"
info "original: domain=${ORIG_DOMAIN}  content_kind=${ORIG_CK}"
pass "preflight: document found in API (domain=${ORIG_DOMAIN} content_kind=${ORIG_CK})"

ENC_REL="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$TARGET_REL")"

# ── P1: Patch both fields ──────────────────────────────────────────────────────
echo ""
echo "── P1: PATCH domain=lrfd_protocol content_kind=requirements"

PATCH1="$(curl -sf --max-time 10 -X PATCH \
  "$BASE/documents/${ENC_REL}/metadata" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"domain":"lrfd_protocol","content_kind":"requirements"}' 2>/dev/null || true)"

P1_UPDATED="$(echo "$PATCH1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('updated',''))" 2>/dev/null || echo '')"
P1_DOMAIN="$(echo "$PATCH1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('document',{}).get('domain',''))" 2>/dev/null || echo '')"
P1_CK="$(echo "$PATCH1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('document',{}).get('content_kind',''))" 2>/dev/null || echo '')"
info "PATCH response: updated=${P1_UPDATED} domain=${P1_DOMAIN} content_kind=${P1_CK}"

if [[ "$P1_UPDATED" == "True" ]]; then
  pass "P1a: PATCH returned updated=True"
else
  fail "P1a: PATCH did not return updated=True (got '${P1_UPDATED}')"
fi

if [[ "$P1_DOMAIN" == "lrfd_protocol" ]]; then
  pass "P1b: PATCH response domain=lrfd_protocol"
else
  fail "P1b: PATCH response domain='${P1_DOMAIN}' (expected lrfd_protocol)"
fi

if [[ "$P1_CK" == "requirements" ]]; then
  pass "P1c: PATCH response content_kind=requirements"
else
  fail "P1c: PATCH response content_kind='${P1_CK}' (expected requirements)"
fi

# ── P2: GET /documents/{id} reflects changes ──────────────────────────────────
echo ""
echo "── P2: GET /documents/{id} reflects patched values"

GET2="$(curl -sf --max-time 10 \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/documents/${ENC_REL}" 2>/dev/null || true)"

G2_DOMAIN="$(echo "$GET2" | python3 -c "import sys,json; print(json.load(sys.stdin).get('domain',''))" 2>/dev/null || echo '')"
G2_CK="$(echo "$GET2" | python3 -c "import sys,json; print(json.load(sys.stdin).get('content_kind',''))" 2>/dev/null || echo '')"
info "GET response: domain=${G2_DOMAIN}  content_kind=${G2_CK}"

if [[ "$G2_DOMAIN" == "lrfd_protocol" ]]; then
  pass "P2a: GET domain=lrfd_protocol (persisted)"
else
  fail "P2a: GET domain='${G2_DOMAIN}' (expected lrfd_protocol — not persisted)"
fi

if [[ "$G2_CK" == "requirements" ]]; then
  pass "P2b: GET content_kind=requirements (persisted)"
else
  fail "P2b: GET content_kind='${G2_CK}' (expected requirements — not persisted)"
fi

# ── P3: corpus_doc_events row exists with before/after ────────────────────────
echo ""
echo "── P3: corpus_doc_events row exists with before/after JSON"

EVENTS="$(docker compose exec -T postgres psql -U keystone -d keystone -tAc \
  "SELECT action, before_json->>'content_kind', after_json->>'content_kind' \
   FROM corpus_doc_events \
   WHERE document_id='${TARGET_REL}' AND action='metadata_patch' \
   ORDER BY ts_utc DESC LIMIT 1;" 2>/dev/null || true)"

info "event row: ${EVENTS}"

if [[ -z "$EVENTS" ]]; then
  fail "P3: no corpus_doc_events row found for metadata_patch on '${TARGET_REL}'"
else
  EV_BEFORE_CK="$(echo "$EVENTS" | cut -d'|' -f2)"
  EV_AFTER_CK="$(echo "$EVENTS" | cut -d'|' -f3)"
  if [[ "$EV_AFTER_CK" == "requirements" ]]; then
    pass "P3a: corpus_doc_events after_json.content_kind=requirements"
  else
    fail "P3a: corpus_doc_events after_json.content_kind='${EV_AFTER_CK}' (expected requirements)"
  fi
  if [[ -n "$EV_BEFORE_CK" ]]; then
    pass "P3b: corpus_doc_events before_json.content_kind present ('${EV_BEFORE_CK}')"
  else
    fail "P3b: corpus_doc_events before_json.content_kind missing"
  fi
fi

# ── P4: Validation rejects unknown values ─────────────────────────────────────
echo ""
echo "── P4: validation rejects unknown domain/content_kind"

BAD_CODE="$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' \
  -X PATCH "$BASE/documents/${ENC_REL}/metadata" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"domain":"unknown_domain"}' 2>/dev/null || echo "000")"

if [[ "$BAD_CODE" == "422" ]]; then
  pass "P4a: unknown domain rejected with 422"
else
  fail "P4a: unknown domain got HTTP ${BAD_CODE} (expected 422)"
fi

BAD_CK_CODE="$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' \
  -X PATCH "$BASE/documents/${ENC_REL}/metadata" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"content_kind":"invalid_kind"}' 2>/dev/null || echo "000")"

if [[ "$BAD_CK_CODE" == "422" ]]; then
  pass "P4b: unknown content_kind rejected with 422"
else
  fail "P4b: unknown content_kind got HTTP ${BAD_CK_CODE} (expected 422)"
fi

# ── P5: Restore original values ───────────────────────────────────────────────
echo ""
echo "── P5: restore original values (cleanup)"

RESTORE_BODY="{\"domain\":\"${ORIG_DOMAIN}\",\"content_kind\":\"${ORIG_CK}\"}"
RESTORE="$(curl -sf --max-time 10 -X PATCH \
  "$BASE/documents/${ENC_REL}/metadata" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d "$RESTORE_BODY" 2>/dev/null || true)"

R_DOMAIN="$(echo "$RESTORE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('document',{}).get('domain',''))" 2>/dev/null || echo '')"
R_CK="$(echo "$RESTORE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('document',{}).get('content_kind',''))" 2>/dev/null || echo '')"

if [[ "$R_DOMAIN" == "$ORIG_DOMAIN" && "$R_CK" == "$ORIG_CK" ]]; then
  pass "P5: restored to original values (domain=${R_DOMAIN} content_kind=${R_CK})"
else
  fail "P5: restore failed (domain='${R_DOMAIN}' content_kind='${R_CK}' — expected domain='${ORIG_DOMAIN}' ck='${ORIG_CK}')"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_doc_kind_domain_patch.sh result"
echo "══════════════════════════════════════════════════════"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
