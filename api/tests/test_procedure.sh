#!/usr/bin/env bash
# test_procedure.sh — contract tests for structured procedure output.
#
# Contracts:
#   T0: login as demo
#   T1: "How to use the rescue decon machine?" → guidance.type=approved
#   T2: guidance.steps length >= 4
#   T3: guidance.excerpt does NOT contain "CONTENTS" (not a TOC chunk)
#   T4: guidance.document.page != 0 (valid page when available)
#   T5: warnings length >= 1 OR prereqs length >= 1 (at least one non-empty)
#   T6: guidance.confidence keys present (rerank_reason, toc_filtered, used_fallback)
#   T7: troubleshooting key present (may be empty)
#
# Usage:
#   bash api/tests/test_procedure.sh [BASE_URL]
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

echo "=== test_procedure.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── T0: login ─────────────────────────────────────────────────────────────────
LOGIN_RESP="$(curl -sf --max-time 10 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo"}' 2>/dev/null || true)"
TOKEN="$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "T0: could not obtain demo token (${LOGIN_RESP:0:80})"
  echo ""; echo "PASS: ${PASS}   FAIL: ${FAIL}"; exit 1
fi
pass "T0: demo token obtained"

# ── T1: submit decon machine query ────────────────────────────────────────────
QID="$(curl -sf --max-time 10 -X POST "$BASE/query" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"question":"How to use the rescue decon machine?","mode":"operational"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

if [[ -z "$QID" ]]; then
  fail "T1: query submission failed"
  echo ""; echo "PASS: ${PASS}   FAIL: ${FAIL}"; exit 1
fi

GUIDANCE_JSON="$(curl -sf --max-time 10 "$BASE/guidance/$QID" \
  -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || true)"
G_TYPE="$(echo "$GUIDANCE_JSON" | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['guidance']['type'])" 2>/dev/null || true)"

info "guidance.type=${G_TYPE}"

if [[ "$G_TYPE" == "approved" ]]; then
  pass "T1: guidance.type=approved for 'How to use the rescue decon machine?'"
else
  fail "T1: expected approved, got ${G_TYPE:-empty} (${GUIDANCE_JSON:0:120})"
  echo ""; echo "PASS: ${PASS}   FAIL: ${FAIL}"; exit 1
fi

# ── T2–T7: structure assertions ───────────────────────────────────────────────
echo ""
python3 - "$GUIDANCE_JSON" <<'PYEOF'
import sys, json

data  = json.loads(sys.argv[1])
g     = data["guidance"]
passn = 0
failn = 0

def show_pass(label):
    global passn; passn += 1
    print(f"[PASS] {label}")

def show_fail(label):
    global failn; failn += 1
    print(f"[FAIL] {label}")

def info(label):
    print(f"       {label}")

# T2: steps >= 4
steps = g.get("steps", [])
if len(steps) >= 4:
    show_pass(f"T2: steps length={len(steps)} (>= 4)  sample: {steps[0][:60]!r}")
else:
    show_fail(f"T2: steps length={len(steps)} (need >= 4)  full: {steps}")

# T3: excerpt does NOT contain "CONTENTS"
excerpt = g.get("excerpt", "")
if "CONTENTS" not in excerpt.upper() or "CONTENTS" not in excerpt:
    show_pass(f"T3: excerpt does not contain 'CONTENTS'  len={len(excerpt)}")
else:
    show_fail(f"T3: excerpt contains 'CONTENTS' — likely a TOC chunk: {excerpt[:80]!r}")

# T4: page != 0 (or null is acceptable for non-PDF)
doc  = g.get("document", {})
page = doc.get("page")
if page is None:
    show_pass("T4: page=null (non-PDF, chunk-only; acceptable)")
elif isinstance(page, int) and page >= 1:
    show_pass(f"T4: page={page} (>= 1)")
else:
    show_fail(f"T4: page={page!r} is 0 or invalid")

# T5: warnings >= 1 OR prereqs >= 1
warnings = g.get("warnings", [])
prereqs  = g.get("prereqs",  [])
if len(warnings) >= 1 or len(prereqs) >= 1:
    show_pass(f"T5: warnings={len(warnings)}, prereqs={len(prereqs)} (at least one non-empty)")
else:
    show_fail(f"T5: both warnings and prereqs are empty")

# T6: confidence object
conf = g.get("confidence")
if (conf and isinstance(conf.get("rerank_reason"), str)
        and isinstance(conf.get("toc_filtered"), bool)
        and isinstance(conf.get("used_fallback"), bool)):
    show_pass(f"T6: confidence keys present  reason={conf['rerank_reason'][:60]!r}")
else:
    show_fail(f"T6: confidence malformed or missing: {conf!r}")

# T7: troubleshooting key present (may be empty list)
if "troubleshooting" in g and isinstance(g["troubleshooting"], list):
    show_pass(f"T7: troubleshooting present (length={len(g['troubleshooting'])})")
else:
    show_fail(f"T7: troubleshooting key missing or wrong type")

info(f"prereqs:         {prereqs}")
info(f"troubleshooting: {g.get('troubleshooting', [])}")
print(f"\nPASS: {passn}   FAIL: {failn}")
sys.exit(0 if failn == 0 else 1)
PYEOF
PYTEST_EXIT=$?

echo ""
echo "══════════════════════════════"
echo "  Overall: PASS=${PASS}  test_suite_exit=${PYTEST_EXIT}"
echo "══════════════════════════════"
[[ $PYTEST_EXIT -eq 0 ]] && exit 0 || exit 1
