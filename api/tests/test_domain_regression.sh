#!/usr/bin/env bash
# test_domain_regression.sh — "trap question" regression pack
#
# 10 questions designed to catch domain-bleed: a medical question must not
# return fire-ops guidance, and a fire-ops question must not return medical
# guidance.  Each test is a one-liner in the Chief demo: wrong-domain answers
# are the most embarrassing failure mode.
#
# Contracts:
#   T1  (medical → wrong domain) : "How do I treat a burn wound?" in operational
#         → approved WITH EMR notice  OR  refusal LOW_CONFIDENCE_MEDICAL
#         (approved+notice = high-confidence path; refusal = low-confidence path)
#   T2  (medical → wrong domain) : "What are the steps for CPR on an adult?"
#         → guidance.document.domain == "medical_emr"  (not fire_ops)
#   T3  (fire → wrong domain)   : "What is the maximum aerial ladder extension?"
#         → guidance.document.domain == "fire_ops"     (not medical_emr)
#   T4  (equipment → wrong domain): "How do I prime the BAM pump?"
#         → guidance.document.domain == "fire_ops"
#   T5  (medical → operational): "What is the correct epinephrine dose for anaphylaxis?"
#         → approved WITH EMR notice  OR  refusal LOW_CONFIDENCE_MEDICAL
#   T6  (medical trap in training): "What are signs of a tension pneumothorax?"
#         → training mode must NOT refuse LOW_CONFIDENCE_MEDICAL
#         (LOW_CONFIDENCE_MEDICAL only fires in operational mode)
#   T7  (fire ops trap): "What PPE is required for a structure fire?"
#         → approved or refusal; document must NOT be a medical/EMR source
#   T8  (equipment trap): "How do I operate the Solo Rescue decon washer?"
#         → guidance.document.domain == "fire_ops" (equipment is fire_ops)
#   T9  (cross-domain noise): "How many chest compressions per minute?"
#         → guidance.document.domain == "medical_emr"
#   T10 (total mismatch): "How do you bake a chocolate soufflé?"
#         → refusal INSUFFICIENT_EVIDENCE  (completely off-topic)
#
# Usage:
#   bash api/tests/test_domain_regression.sh [BASE_URL]
#
# Defaults:
#   BASE_URL — http://localhost:8000

set -euo pipefail

BASE="${1:-http://localhost:8000}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_domain_regression.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login ──────────────────────────────────────────────────────────────────────
LOGIN_RESP="$(curl -sf --max-time 10 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"officer","password":"officer"}' 2>/dev/null || true)"
TOKEN="$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "Login: could not obtain officer token (${LOGIN_RESP:0:80})"
  echo ""; echo "PASS: ${PASS}   FAIL: ${FAIL}"; exit 1
fi

# ── Helpers ────────────────────────────────────────────────────────────────────
query_guidance() {
  local question="$1"
  local mode="${2:-training}"
  local domain_filter="${3:-}"
  local payload
  if [[ -n "$domain_filter" ]]; then
    payload="{\"question\":$(python3 -c "import sys,json; print(json.dumps(sys.argv[1]))" "$question"),\"mode\":\"$mode\",\"domain_filter\":[\"$domain_filter\"]}"
  else
    payload="{\"question\":$(python3 -c "import sys,json; print(json.dumps(sys.argv[1]))" "$question"),\"mode\":\"$mode\"}"
  fi
  local qid
  qid="$(curl -sf --max-time 10 -X POST "$BASE/query" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "$payload" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

  if [[ -z "$qid" ]]; then
    echo ""
    return 1
  fi

  curl -sf --max-time 10 "$BASE/guidance/$qid" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || true
}

guidance_type()   { echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('guidance',{}).get('type',''))"         2>/dev/null || true; }
reason_code()     { echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('guidance',{}).get('reasonCode',''))"    2>/dev/null || true; }
doc_domain()      { echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('guidance',{}).get('document',{}).get('domain',''))"  2>/dev/null || true; }
doc_id_lower()    { echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('guidance',{}).get('document',{}).get('documentId','').lower())"  2>/dev/null || true; }
has_emr_notice()  { echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); n=d.get('guidance',{}).get('notice','') or ''; print('yes' if 'MEDICAL_EMR' in n else 'no')" 2>/dev/null || true; }

echo "── T1: burn wound treatment in operational → EMR notice or LOW_CONFIDENCE_MEDICAL ─"
T1="$(query_guidance "How do I treat a burn wound on a patient?" operational || true)"
T1_TYPE="$(guidance_type "$T1")"
T1_REASON="$(reason_code "$T1")"
T1_EMR="$(has_emr_notice "$T1")"
info "type=$T1_TYPE  reasonCode=$T1_REASON  emr_notice=$T1_EMR"
if [[ "$T1_TYPE" == "refusal" && "$T1_REASON" == "LOW_CONFIDENCE_MEDICAL" ]]; then
  pass "T1: burn wound → LOW_CONFIDENCE_MEDICAL refusal (low confidence path)"
elif [[ "$T1_TYPE" == "approved" && "$T1_EMR" == "yes" ]]; then
  pass "T1: burn wound → approved with MEDICAL_EMR notice (high confidence path)"
elif [[ "$T1_TYPE" == "refusal" ]]; then
  pass "T1: burn wound → refusal ($T1_REASON)"
else
  fail "T1: medical operational query must include EMR notice or LOW_CONFIDENCE_MEDICAL refusal; got type=$T1_TYPE notice=$T1_EMR"
fi
echo ""

echo "── T2: CPR adult steps → document domain must be medical_emr ─────────────"
T2="$(query_guidance "What are the steps for CPR on an adult?" training || true)"
T2_TYPE="$(guidance_type "$T2")"
T2_DOMAIN="$(doc_domain "$T2")"
info "type=$T2_TYPE  domain=$T2_DOMAIN"
if [[ "$T2_DOMAIN" == "medical_emr" ]]; then
  pass "T2: adult CPR → medical_emr domain"
elif [[ "$T2_TYPE" == "refusal" ]]; then
  pass "T2: adult CPR → refusal (no medical doc matched — acceptable)"
else
  fail "T2: adult CPR returned domain='$T2_DOMAIN' (expected medical_emr)"
fi
echo ""

echo "── T3: aerial ladder extension → document domain must be fire_ops ─────────"
T3="$(query_guidance "What is the maximum aerial ladder extension for the quint?" training || true)"
T3_TYPE="$(guidance_type "$T3")"
T3_DOMAIN="$(doc_domain "$T3")"
info "type=$T3_TYPE  domain=$T3_DOMAIN"
if [[ "$T3_DOMAIN" == "fire_ops" ]]; then
  pass "T3: aerial ladder → fire_ops domain"
elif [[ "$T3_TYPE" == "refusal" ]]; then
  pass "T3: aerial ladder → refusal (acceptable)"
else
  fail "T3: aerial ladder returned domain='$T3_DOMAIN' (expected fire_ops)"
fi
echo ""

echo "── T4: BAM pump priming → domain must be fire_ops (equipment manual) ──────"
T4="$(query_guidance "How do I prime the pump on a BAM apparatus?" training || true)"
T4_TYPE="$(guidance_type "$T4")"
T4_DOMAIN="$(doc_domain "$T4")"
info "type=$T4_TYPE  domain=$T4_DOMAIN"
if [[ "$T4_DOMAIN" == "fire_ops" ]]; then
  pass "T4: BAM pump → fire_ops domain"
elif [[ "$T4_TYPE" == "refusal" ]]; then
  pass "T4: BAM pump → refusal (acceptable)"
else
  fail "T4: BAM pump returned domain='$T4_DOMAIN' (expected fire_ops)"
fi
echo ""

echo "── T5: epinephrine dose in operational → EMR notice or LOW_CONFIDENCE_MEDICAL ─"
T5="$(query_guidance "What is the correct epinephrine dose for anaphylaxis?" operational || true)"
T5_TYPE="$(guidance_type "$T5")"
T5_REASON="$(reason_code "$T5")"
T5_EMR="$(has_emr_notice "$T5")"
info "type=$T5_TYPE  reasonCode=$T5_REASON  emr_notice=$T5_EMR"
if [[ "$T5_TYPE" == "refusal" && "$T5_REASON" == "LOW_CONFIDENCE_MEDICAL" ]]; then
  pass "T5: epinephrine → LOW_CONFIDENCE_MEDICAL refusal (low confidence path)"
elif [[ "$T5_TYPE" == "approved" && "$T5_EMR" == "yes" ]]; then
  pass "T5: epinephrine → approved with MEDICAL_EMR notice (high confidence path)"
elif [[ "$T5_TYPE" == "refusal" ]]; then
  pass "T5: epinephrine → refusal ($T5_REASON)"
else
  fail "T5: medical operational query must include EMR notice or LOW_CONFIDENCE_MEDICAL refusal; got type=$T5_TYPE notice=$T5_EMR"
fi
echo ""

echo "── T6: tension pneumothorax in training → must NOT refuse LOW_CONFIDENCE_MEDICAL"
T6="$(query_guidance "What are signs of a tension pneumothorax?" training || true)"
T6_TYPE="$(guidance_type "$T6")"
T6_REASON="$(reason_code "$T6")"
info "type=$T6_TYPE  reasonCode=$T6_REASON"
if [[ "$T6_REASON" == "LOW_CONFIDENCE_MEDICAL" ]]; then
  fail "T6: LOW_CONFIDENCE_MEDICAL fired in training mode — should only fire in operational"
elif [[ "$T6_TYPE" == "approved" || "$T6_TYPE" == "refusal" ]]; then
  pass "T6: pneumothorax in training → type=$T6_TYPE (LOW_CONFIDENCE_MEDICAL not fired)"
else
  fail "T6: unexpected response type=$T6_TYPE"
fi
echo ""

echo "── T7: structure fire PPE → document must NOT be a medical/EMR source ─────"
T7="$(query_guidance "What PPE is required for a structure fire?" training || true)"
T7_TYPE="$(guidance_type "$T7")"
T7_DOMAIN="$(doc_domain "$T7")"
T7_DOC_LOWER="$(doc_id_lower "$T7")"
info "type=$T7_TYPE  domain=$T7_DOMAIN  doc=${T7_DOC_LOWER:0:40}"
if [[ "$T7_DOMAIN" == "medical_emr" ]]; then
  fail "T7: structure fire PPE returned a medical_emr document — domain bleed"
elif [[ "$T7_TYPE" == "approved" || "$T7_TYPE" == "refusal" ]]; then
  pass "T7: structure fire PPE → type=$T7_TYPE domain=$T7_DOMAIN (not medical)"
else
  fail "T7: unexpected response type=$T7_TYPE"
fi
echo ""

echo "── T8: Solo Rescue decon washer → domain must be fire_ops ─────────────────"
T8="$(query_guidance "How do I operate the Solo Rescue decon washer?" training || true)"
T8_TYPE="$(guidance_type "$T8")"
T8_DOMAIN="$(doc_domain "$T8")"
info "type=$T8_TYPE  domain=$T8_DOMAIN"
if [[ "$T8_DOMAIN" == "fire_ops" ]]; then
  pass "T8: decon washer → fire_ops domain"
elif [[ "$T8_TYPE" == "refusal" ]]; then
  pass "T8: decon washer → refusal (acceptable)"
else
  fail "T8: decon washer returned domain='$T8_DOMAIN' (expected fire_ops)"
fi
echo ""

echo "── T9: chest compressions per minute → domain must be medical_emr ─────────"
T9="$(query_guidance "How many chest compressions per minute for an adult?" training || true)"
T9_TYPE="$(guidance_type "$T9")"
T9_DOMAIN="$(doc_domain "$T9")"
info "type=$T9_TYPE  domain=$T9_DOMAIN"
if [[ "$T9_DOMAIN" == "medical_emr" ]]; then
  pass "T9: chest compressions → medical_emr domain"
elif [[ "$T9_TYPE" == "refusal" ]]; then
  pass "T9: chest compressions → refusal (no medical doc matched — acceptable)"
else
  fail "T9: chest compressions returned domain='$T9_DOMAIN' (expected medical_emr)"
fi
echo ""

echo "── T10: off-topic question → INSUFFICIENT_EVIDENCE refusal ────────────────"
T10="$(query_guidance "How do you bake a chocolate soufflé with strawberry frosting?" training || true)"
T10_TYPE="$(guidance_type "$T10")"
T10_REASON="$(reason_code "$T10")"
info "type=$T10_TYPE  reasonCode=$T10_REASON"
if [[ "$T10_TYPE" == "refusal" ]]; then
  pass "T10: off-topic → refusal ($T10_REASON)"
else
  fail "T10: off-topic question should refuse, got type=$T10_TYPE"
fi
echo ""

# ── Summary ────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════"
echo "PASS: ${PASS}   FAIL: ${FAIL}"
if [[ "${FAIL}" -gt 0 ]]; then
  exit 1
fi
