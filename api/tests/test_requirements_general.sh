#!/usr/bin/env bash
# test_requirements_general.sh
#
# Contract test: spec/requirements retrieval must be consistent across
# documents — not special-cased to FoamPro.
#
# Assertions (per query):
#   - guidance.type = approved
#   - excerpt contains at least one quantitative spec token
#     (vdc, vac, amp, psi, gpm, bar, kpa, volt, V)
#   - selected page is not a front-matter page when a later spec section exists
#   - requirements_evidence present and well-formed
#
# Covers at least 4 queries across at least 2 different documents.
#
# Usage: bash api/tests/test_requirements_general.sh [BASE_URL]
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

echo "=== test_requirements_general.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""
echo "    Verify: feat(kdat-015): spec retrieval generalization"
echo ""

# ── Login ─────────────────────────────────────────────────────────────────────
TOKEN="$(curl -sf --max-time 5 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"officer","password":"officer"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "login: could not obtain officer token from ${BASE}"
  echo "  PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "login: officer token obtained"

# ── Helper: run one spec query and assert ─────────────────────────────────────
# Args: label question expected_doc_fragment min_page
run_spec_test() {
  local LABEL="$1"
  local QUESTION="$2"
  local EXPECTED_DOC="$3"   # substring of documentId (empty = any)
  local MIN_PAGE="$4"        # page must be >= this (0 = no assertion)

  echo ""
  echo "── ${LABEL}"
  info "question: ${QUESTION}"

  local QID
  QID="$(curl -sf --max-time 10 -X POST "$BASE/query" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"question\":$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$QUESTION"),\"mode\":\"operational\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

  if [[ -z "$QID" ]]; then
    fail "${LABEL}: query submission failed"
    return
  fi

  local G
  G="$(curl -sf --max-time 10 "$BASE/guidance/$QID" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || true)"

  if [[ -z "$G" ]]; then
    fail "${LABEL}: no guidance response"
    return
  fi

  # Extract fields
  local G_TYPE DOC_ID DOC_PAGE EXCERPT EV_HEADING EV_EXPLICIT EV_PTR_ONLY EV_SPEC_TABLE
  G_TYPE="$(echo "$G" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance']['type'])" 2>/dev/null || true)"
  DOC_ID="$(echo "$G" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance'].get('document',{}).get('documentId',''))" 2>/dev/null || true)"
  DOC_PAGE="$(echo "$G" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance'].get('document',{}).get('page',''))" 2>/dev/null || true)"
  EXCERPT="$(echo "$G" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance'].get('excerpt',''))" 2>/dev/null || true)"
  EV_HEADING="$(echo "$G" | python3 -c \
    "import sys,json; ev=json.load(sys.stdin)['guidance'].get('requirements_evidence',{}); print(ev.get('heading_hit',''))" 2>/dev/null || true)"
  EV_EXPLICIT="$(echo "$G" | python3 -c \
    "import sys,json; ev=json.load(sys.stdin)['guidance'].get('requirements_evidence',{}); print(ev.get('explicit_spec_lines',''))" 2>/dev/null || true)"
  EV_PTR_ONLY="$(echo "$G" | python3 -c \
    "import sys,json; ev=json.load(sys.stdin)['guidance'].get('requirements_evidence',{}); print(ev.get('pointer_only',''))" 2>/dev/null || true)"
  EV_SPEC_TABLE="$(echo "$G" | python3 -c \
    "import sys,json; ev=json.load(sys.stdin)['guidance'].get('requirements_evidence',{}); print(ev.get('spec_table_like',''))" 2>/dev/null || true)"

  info "type=${G_TYPE}  doc=${DOC_ID}  page=${DOC_PAGE}"
  info "evidence: heading=${EV_HEADING} explicit=${EV_EXPLICIT} ptr_only=${EV_PTR_ONLY} spec_table=${EV_SPEC_TABLE}"

  # T-a: type must be approved
  if [[ "$G_TYPE" == "approved" ]]; then
    pass "${LABEL}a: type=approved"
  else
    fail "${LABEL}a: expected type=approved, got type=${G_TYPE}"
    return
  fi

  # T-b: documentId should match expected fragment (if specified)
  if [[ -n "$EXPECTED_DOC" ]]; then
    if echo "$DOC_ID" | grep -qi "$EXPECTED_DOC"; then
      pass "${LABEL}b: document matches '${EXPECTED_DOC}' (got ${DOC_ID})"
    else
      fail "${LABEL}b: expected document containing '${EXPECTED_DOC}', got '${DOC_ID}'"
    fi
  fi

  # T-c: excerpt contains a quantitative spec token
  SPEC_TOKEN_FOUND="$(echo "$EXCERPT" | python3 -c "
import sys, re
text = sys.stdin.read()
_SPEC = re.compile(
    r'\b\d+\s*(?:vdc|vac|amps?|psi|gpm|kpa|bar|volt|\bv\b)',
    re.IGNORECASE,
)
m = _SPEC.search(text)
print('yes' if m else 'no')
print(m.group() if m else '')
" 2>/dev/null || echo "no")"
  SPEC_TOKEN_VALUE="$(echo "$SPEC_TOKEN_FOUND" | tail -1)"
  SPEC_TOKEN_FOUND="$(echo "$SPEC_TOKEN_FOUND" | head -1)"

  if [[ "$SPEC_TOKEN_FOUND" == "yes" ]]; then
    pass "${LABEL}c: excerpt contains spec token '${SPEC_TOKEN_VALUE}'"
  else
    fail "${LABEL}c: excerpt has no quantitative spec token (vdc/amp/psi/gpm/bar/volt)"
    info "excerpt[:200]: ${EXCERPT:0:200}"
  fi

  # T-d: page >= min_page (not front-matter)
  if [[ -n "$MIN_PAGE" && "$MIN_PAGE" -gt 0 && -n "$DOC_PAGE" && "$DOC_PAGE" != "None" ]]; then
    if [[ "$DOC_PAGE" -ge "$MIN_PAGE" ]]; then
      pass "${LABEL}d: page=${DOC_PAGE} >= ${MIN_PAGE} (not front-matter)"
    else
      fail "${LABEL}d: page=${DOC_PAGE} < ${MIN_PAGE} (front-matter chunk selected — spec section missed)"
    fi
  fi

  # T-e: requirements_evidence present and well-formed
  EV_PRESENT="$(echo "$G" | python3 -c \
    "import sys,json; g=json.load(sys.stdin)['guidance']; print('yes' if 'requirements_evidence' in g else 'no')" 2>/dev/null || echo "no")"
  if [[ "$EV_PRESENT" == "yes" ]]; then
    pass "${LABEL}e: requirements_evidence present"
  else
    fail "${LABEL}e: requirements_evidence MISSING from guidance"
  fi

  # T-f: pointer_only must be False (selected chunk must not be redirect-only)
  if [[ "$EV_PTR_ONLY" == "False" ]]; then
    pass "${LABEL}f: pointer_only=False (selected chunk is not redirect-only)"
  else
    fail "${LABEL}f: pointer_only=${EV_PTR_ONLY} (expected False — chunk is redirect-only)"
  fi
}

# ── Query 1: FoamPro 2000-series — electrical requirements ────────────────────
run_spec_test "Q1[foampro-electrical]" \
  "What is the ELECTRICAL REQUIREMENT for foampro system?" \
  "2000-series" \
  5

# ── Query 2: FoamPro 2000-series — model voltage/amps spec ───────────────────
run_spec_test "Q2[foampro-model-spec]" \
  "What is the voltage and amperage specification for foampro model 2002?" \
  "2000-series" \
  5

# ── Query 3: BAM unit — operational specifications (non-FoamPro doc) ─────────
run_spec_test "Q3[bam-operational-specs]" \
  "What are the BAM unit operational specifications?" \
  "bam" \
  5

# ── Query 4: BAM compressor — technical specifications (non-FoamPro doc) ─────
run_spec_test "Q4[bam-technical-specs]" \
  "What are the technical specifications of the BAM compressor unit?" \
  "bam" \
  5

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_requirements_general.sh result"
echo "══════════════════════════════════════════════════════"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
