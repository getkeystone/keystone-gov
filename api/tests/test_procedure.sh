#!/usr/bin/env bash
# test_procedure.sh — contract tests for structured procedure output.
#
# Contracts:
#   1. Approved guidance for a decon question includes guidance.procedure
#   2. procedure.steps   length >= 4
#   3. procedure.warnings length >= 1
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

echo "=== test_procedure.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── T0: login as demo ──────────────────────────────────────────────────────────
LOGIN_RESP="$(curl -sf --max-time 10 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo"}' 2>/dev/null || true)"
TOKEN="$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$TOKEN" ]]; then
  fail "T0: could not obtain demo token (${LOGIN_RESP:0:80})"
  echo ""
  echo "PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "T0: demo token obtained"

# ── T1: submit decon query, expect approved guidance ──────────────────────────
APPROVED_QID=""
GUIDANCE_JSON=""

for QUESTION in \
  "decontamination procedure for patient" \
  "How to use the rescue decon machine?" \
  "emergency decontamination steps"; do

  QID="$(curl -sf --max-time 10 -X POST "$BASE/query" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "{\"question\":\"${QUESTION}\",\"mode\":\"operational\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"

  if [[ -z "$QID" ]]; then
    echo "       query failed for: ${QUESTION}"
    continue
  fi

  GUIDANCE_JSON="$(curl -sf --max-time 10 "$BASE/guidance/$QID" \
    -H "Authorization: Bearer ${TOKEN}" 2>/dev/null || true)"
  G_TYPE="$(echo "$GUIDANCE_JSON" | python3 -c \
    "import sys,json; print(json.load(sys.stdin)['guidance']['type'])" 2>/dev/null || true)"

  echo "       '${QUESTION}' → type=${G_TYPE}"

  if [[ "$G_TYPE" == "approved" ]]; then
    APPROVED_QID="$QID"
    break
  fi
done

if [[ -z "$APPROVED_QID" ]]; then
  fail "T1: all decon questions returned non-approved guidance"
  echo ""
  echo "PASS: ${PASS}   FAIL: ${FAIL}"
  exit 1
fi
pass "T1: approved guidance found (qid=${APPROVED_QID})"

# ── T2–T4: procedure structure assertions ─────────────────────────────────────
echo ""
python3 - "$GUIDANCE_JSON" "$PASS" "$FAIL" <<'PYEOF'
import sys, json

data    = json.loads(sys.argv[1])
pass_in = int(sys.argv[2])
fail_in = int(sys.argv[3])

g    = data["guidance"]
proc = g.get("procedure")
passn = pass_in
failn = fail_in

def show_pass(label):
    global passn
    passn += 1
    print(f"[PASS] {label}")

def show_fail(label):
    global failn
    failn += 1
    print(f"[FAIL] {label}")

# T2: procedure key must be present
if proc is None:
    show_fail("T2: guidance.procedure key missing from approved response")
    print(f"\nPASS: {passn}   FAIL: {failn}")
    sys.exit(1)
show_pass("T2: guidance.procedure key present")

# T3: steps >= 4
steps = proc.get("steps", [])
if len(steps) >= 4:
    show_pass(f"T3: steps length={len(steps)} (>= 4)  sample: {steps[0][:60]!r}")
else:
    show_fail(f"T3: steps length={len(steps)} (need >= 4)  steps={steps}")

# T4: warnings >= 1
warnings = proc.get("warnings", [])
if len(warnings) >= 1:
    show_pass(f"T4: warnings length={len(warnings)} (>= 1)  sample: {warnings[0][:60]!r}")
else:
    show_fail(f"T4: warnings length={len(warnings)} (need >= 1)")

# Print prereqs and codes as info
print(f"       prereqs: {len(proc.get('prereqs',[]))}  codes: {len(proc.get('codes',[]))}")
print(f"\nPASS: {passn}   FAIL: {failn}")
sys.exit(0 if failn == fail_in else 1)
PYEOF
TEST_EXIT=$?

# Propagate final exit code
if [[ $TEST_EXIT -ne 0 || $FAIL -gt 0 ]]; then
  exit 1
fi
exit 0
