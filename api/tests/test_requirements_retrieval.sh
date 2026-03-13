#!/usr/bin/env bash
# test_requirements_retrieval.sh
#
# Contract test: when a query contains "requirement(s)", the retrieval engine
# must not return a LOW_CONFIDENCE refusal caused by a spec-less CAUTION/
# WARNING numbered list outscoring the actual requirements section.
#
# Specifically, "electrical requirements for the 2000-series" must return
# type=approved guidance from the 2000-series manual (not LOW_CONFIDENCE
# refusal) because the matched chunk contains structured electrical spec data
# (voltage/amperage requirements embedded in CAUTION items) and therefore
# passes the procedure quality gate.
#
# Usage: bash api/tests/test_requirements_retrieval.sh [BASE_URL]
#   Default BASE_URL: http://${PUBLISH_IP}:5174/api (from ~/.config/keystone/env)

set -euo pipefail

ENV_FILE="${HOME}/.config/keystone/env"
_PUBLISH_IP="$(grep '^PUBLISH_IP=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d ' ')"
_PUBLISH_IP="${_PUBLISH_IP:-127.0.0.1}"
BASE="${1:-http://${_PUBLISH_IP}:5174/api}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_requirements_retrieval.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login ─────────────────────────────────────────────────────────────────────
TOKEN="$(curl -sf --max-time 5 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"officer","password":"officer"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "login: could not obtain officer token"
  echo ""
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "login: officer token obtained"

# ── T1: Electrical requirements query must not produce LOW_CONFIDENCE refusal ─
echo ""
echo "── T1: 2000-series electrical requirements → type=approved, not LOW_CONFIDENCE"

QID="$(curl -sf --max-time 10 -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"question":"What are the electrical requirements for the 2000-series machine?","mode":"operational"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

if [[ -z "$QID" ]]; then
  fail "T1: query submission failed"
else
  G="$(curl -sf --max-time 10 "$BASE/guidance/$QID" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)"

  G_TYPE="$(echo "$G" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance']['type'])" 2>/dev/null || true)"
  G_CODE="$(echo "$G" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance'].get('reasonCode',''))" 2>/dev/null || true)"
  G_DOC="$(echo "$G" | python3 -c \
    "import sys,json; d=json.load(sys.stdin)['guidance'].get('document',{}); print(d.get('documentId',''))" 2>/dev/null || true)"
  G_EXCERPT="$(echo "$G" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance'].get('excerpt','')[:500])" 2>/dev/null || true)"

  info "type=${G_TYPE}  reasonCode=${G_CODE}"
  info "doc=${G_DOC}"
  info "excerpt[:120]: ${G_EXCERPT:0:120}"

  if [[ "$G_TYPE" == "approved" ]]; then
    pass "T1a: type=approved (no LOW_CONFIDENCE refusal)"
  elif [[ "$G_CODE" == "LOW_CONFIDENCE" ]]; then
    fail "T1a: BUG — requirements query returned LOW_CONFIDENCE refusal (caution-list rerank regression)"
  else
    fail "T1a: unexpected type=${G_TYPE} reasonCode=${G_CODE}"
  fi

  if [[ "$G_DOC" == *"2000-series"* ]]; then
    pass "T1b: matched 2000-series manual (correct document)"
  elif [[ "$G_TYPE" == "approved" ]]; then
    fail "T1b: matched wrong document: ${G_DOC}"
  fi

  # Excerpt must contain structured electrical spec data (VDC or amps)
  if echo "$G_EXCERPT" | grep -qiE '(VDC|VAC|amps?|volt|12|24)[^a-z]*'; then
    pass "T1c: excerpt contains electrical spec data"
  elif [[ "$G_TYPE" == "approved" ]]; then
    fail "T1c: excerpt missing electrical spec data — may have returned wrong chunk"
  fi
fi

# ── T2: Operational requirements query must not degrade to refusal ────────────
echo ""
echo "── T2: installation requirements query → type=approved (no regression)"

QID2="$(curl -sf --max-time 10 -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"question":"What are the installation requirements for the foam system?","mode":"operational"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

if [[ -z "$QID2" ]]; then
  fail "T2: query submission failed"
else
  G2="$(curl -sf --max-time 10 "$BASE/guidance/$QID2" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)"
  G2_TYPE="$(echo "$G2" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance']['type'])" 2>/dev/null || true)"
  G2_CODE="$(echo "$G2" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance'].get('reasonCode',''))" 2>/dev/null || true)"
  info "type=${G2_TYPE}  reasonCode=${G2_CODE}"

  if [[ "$G2_TYPE" == "approved" ]]; then
    pass "T2: installation requirements → type=approved"
  elif [[ "$G2_CODE" == "LOW_CONFIDENCE" ]]; then
    fail "T2: BUG — requirements query returned LOW_CONFIDENCE refusal (rerank regression)"
  else
    fail "T2: unexpected type=${G2_TYPE} reasonCode=${G2_CODE}"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_requirements_retrieval.sh result"
echo "══════════════════════════════════════════════════════"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
