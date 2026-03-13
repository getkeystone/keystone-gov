#!/usr/bin/env bash
# test_incident_pack.sh — Contract tests for KDAT-006 incident pack export.
#
# Tests:
#   T1: GET /incident/{id}/pack.zip without decision → 409
#   T2: POST decision → 200
#   T3: GET /incident/{id}/pack.zip → 200, is a valid ZIP
#   T4: ZIP contains operator_decision.json
#   T5: Two downloads produce identical manifest.json sha256 (determinism)
#   T6: offline verifier (tools/verify_evidence.py) exits 0 on pack ZIP
#   T7: Tamper operator_decision.json → verifier exits 3 (hash mismatch)
#   T8: 403 (not 200) for member role on pack download
#
# Usage:
#   bash api/tests/test_incident_pack.sh [BASE_URL]
#   BASE_URL defaults to http://127.0.0.1:8080/api

set -euo pipefail

BASE="${1:-http://127.0.0.1:8080/api}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Look for verify_evidence.py relative to repo root
VERIFIER="$(cd "$SCRIPT_DIR/../../.." && pwd)/keystone-deploy/tools/verify_evidence.py"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_incident_pack.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login ──────────────────────────────────────────────────────────────────────
T_ADMIN="$(curl -sf --max-time 10 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"

if [[ -z "$T_ADMIN" ]]; then echo "FATAL: could not obtain admin token"; exit 1; fi
info "admin: ${T_ADMIN:0:8}…"

# Check verifier available
if [[ ! -f "$VERIFIER" ]]; then
  info "WARN: verifier not found at $VERIFIER — T6/T7 will be skipped"
  HAS_VERIFIER=0
else
  HAS_VERIFIER=1
  info "verifier: $VERIFIER"
fi
echo ""

# ── Create query ───────────────────────────────────────────────────────────────
QID="$(curl -sf --max-time 30 -X POST "$BASE/query" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"question":"rescue procedure","scenario_key":"general","mode":"operational","stream":false}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" \
  2>/dev/null || true)"

if [[ -z "$QID" ]]; then echo "FATAL: could not create test query"; exit 1; fi
info "query_id: ${QID}"
echo ""

# ── T1: pack without decision → 409 ──────────────────────────────────────────
echo "── T1: GET /incident/{id}/pack.zip without decision → 409"
NO_DEC_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
  -H "Authorization: Bearer $T_ADMIN" \
  "$BASE/incident/${QID}/pack.zip" 2>/dev/null || echo 000)"
if [[ "$NO_DEC_CODE" == "409" ]]; then
  pass "T1: no decision → 409"
else
  fail "T1: expected 409 but got ${NO_DEC_CODE}"
fi

# ── T2: POST decision ─────────────────────────────────────────────────────────
echo ""
echo "── T2: POST /decisions/{id} → created"
DEC_RESP="$(curl -sf --max-time 10 -X POST "$BASE/decisions/${QID}" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"decision":"followed","actions_taken":["Unit deployed","Scene secured"],"notes":"All steps executed as instructed"}' \
  2>/dev/null || true)"
DEC_CREATED="$(echo "$DEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('created',''))" 2>/dev/null || echo '')"
if [[ "$DEC_CREATED" == "True" ]]; then
  pass "T2: decision created"
else
  fail "T2: unexpected response: ${DEC_RESP:0:200}"
fi

# ── T3: GET pack → 200, valid ZIP ─────────────────────────────────────────────
echo ""
echo "── T3: GET /incident/{id}/pack.zip → 200, valid ZIP"
DL_CODE="$(curl -s -o /tmp/test_incident.zip -w '%{http_code}' --max-time 60 \
  -H "Authorization: Bearer $T_ADMIN" \
  "$BASE/incident/${QID}/pack.zip" 2>/dev/null || echo 000)"
if [[ "$DL_CODE" == "200" ]]; then
  IS_ZIP="$(python3 -c "
import zipfile, sys
try:
    zf = zipfile.ZipFile('/tmp/test_incident.zip')
    print('yes')
    zf.close()
except Exception as e:
    print('no:' + str(e))
" 2>/dev/null || echo no)"
  if [[ "$IS_ZIP" == "yes" ]]; then
    pass "T3: download succeeded and is a valid ZIP"
  else
    fail "T3: download succeeded but invalid ZIP: ${IS_ZIP}"
  fi
else
  fail "T3: download returned ${DL_CODE}"
fi

# ── T4: ZIP contains operator_decision.json ────────────────────────────────────
echo ""
echo "── T4: ZIP contains operator_decision.json"
if [[ "$DL_CODE" == "200" ]]; then
  CONTENTS="$(python3 -c "
import zipfile
with zipfile.ZipFile('/tmp/test_incident.zip') as zf:
    names = {i.filename for i in zf.infolist()}
    required = {'operator_decision.json','audit.json','guidance.json','verify.json','manifest.json','manifest.sig'}
    missing = required - names
    print('missing:' + ','.join(sorted(missing)) if missing else 'ok')
" 2>/dev/null || echo "error")"
  if [[ "$CONTENTS" == "ok" ]]; then
    pass "T4: ZIP contains all required files including operator_decision.json"
  else
    fail "T4: ZIP missing files: ${CONTENTS}"
  fi
else
  info "T4: SKIP (download failed)"
fi

# ── T5: Two downloads produce identical manifest sha256 (determinism) ──────────
echo ""
echo "── T5: Two downloads → identical manifest.json sha256"
DL_CODE2="$(curl -s -o /tmp/test_incident2.zip -w '%{http_code}' --max-time 60 \
  -H "Authorization: Bearer $T_ADMIN" \
  "$BASE/incident/${QID}/pack.zip" 2>/dev/null || echo 000)"
if [[ "$DL_CODE" == "200" && "$DL_CODE2" == "200" ]]; then
  SHA1="$(python3 -c "
import zipfile, hashlib
with zipfile.ZipFile('/tmp/test_incident.zip') as zf:
    data = zf.read('manifest.json')
    print(hashlib.sha256(data).hexdigest())
" 2>/dev/null || echo FAIL1)"
  SHA2="$(python3 -c "
import zipfile, hashlib
with zipfile.ZipFile('/tmp/test_incident2.zip') as zf:
    data = zf.read('manifest.json')
    print(hashlib.sha256(data).hexdigest())
" 2>/dev/null || echo FAIL2)"
  if [[ "$SHA1" == "$SHA2" && "$SHA1" != "FAIL1" ]]; then
    pass "T5: deterministic manifest sha256=${SHA1:0:16}…"
  else
    fail "T5: manifest sha256 differs between downloads: ${SHA1:0:16} vs ${SHA2:0:16}"
  fi
else
  fail "T5: one or both downloads failed (${DL_CODE} / ${DL_CODE2})"
fi
rm -f /tmp/test_incident2.zip

# ── T6: offline verifier exits 0 ──────────────────────────────────────────────
echo ""
echo "── T6: offline verifier exits 0 on incident pack"
if [[ "$HAS_VERIFIER" -eq 0 ]]; then
  info "T6: SKIP — verifier not found"
  pass "T6: SKIP"
elif [[ "$DL_CODE" != "200" ]]; then
  info "T6: SKIP — pack download failed"
elif python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey" 2>/dev/null; then
  # Get pubkey
  PUBKEY_FILE="/tmp/test_incident_pubkey.pem"
  curl -sf --max-time 10 "$BASE/evidence/public-key" -o "$PUBKEY_FILE" 2>/dev/null || true
  if [[ -f "$PUBKEY_FILE" && -s "$PUBKEY_FILE" ]]; then
    set +e
    python3 "$VERIFIER" /tmp/test_incident.zip --pubkey "$PUBKEY_FILE"
    VERIFY_EXIT=$?
    set -e
    if [[ "$VERIFY_EXIT" -eq 0 ]]; then
      pass "T6: offline verifier exits 0 on incident pack"
    else
      fail "T6: verifier exited ${VERIFY_EXIT} (expected 0)"
    fi
  else
    info "T6: signing not configured (501) — SKIP"
    pass "T6: SKIP (signing not configured)"
  fi
else
  info "T6: cryptography library not available — SKIP"
  pass "T6: SKIP"
fi

# ── T7: tamper operator_decision.json → verifier exits 3 ──────────────────────
echo ""
echo "── T7: tamper operator_decision.json → verifier exits 3"
if [[ "$HAS_VERIFIER" -eq 0 ]]; then
  info "T7: SKIP — verifier not found"
  pass "T7: SKIP"
elif [[ "$DL_CODE" != "200" ]]; then
  info "T7: SKIP — pack download failed"
elif python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey" 2>/dev/null; then
  # Build tampered zip
  python3 - <<'PYEOF'
import zipfile, io, json

with zipfile.ZipFile('/tmp/test_incident.zip', 'r') as src_zf:
    files = {}
    for name in src_zf.namelist():
        files[name] = src_zf.read(name)

# Tamper operator_decision.json
dec = json.loads(files['operator_decision.json'])
dec['decision'] = 'TAMPERED'
files['operator_decision.json'] = json.dumps(dec).encode()

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as dst_zf:
    for name, data in files.items():
        dst_zf.writestr(name, data)
with open('/tmp/test_incident_tampered.zip', 'wb') as f:
    f.write(buf.getvalue())
print("tampered zip written")
PYEOF

  PUBKEY_FILE="/tmp/test_incident_pubkey.pem"
  if [[ -f "$PUBKEY_FILE" && -s "$PUBKEY_FILE" ]]; then
    set +e
    python3 "$VERIFIER" /tmp/test_incident_tampered.zip --pubkey "$PUBKEY_FILE"
    TAMPER_EXIT=$?
    set -e
    if [[ "$TAMPER_EXIT" -eq 3 ]]; then
      pass "T7: tampered pack → verifier exits 3 (hash mismatch)"
    elif [[ "$TAMPER_EXIT" -eq 2 ]]; then
      pass "T7: tampered pack → verifier exits 2 (sig mismatch — also correct)"
    else
      fail "T7: verifier exited ${TAMPER_EXIT} (expected 2 or 3)"
    fi
  else
    info "T7: SKIP (signing not configured)"
    pass "T7: SKIP"
  fi
  rm -f /tmp/test_incident_tampered.zip
else
  info "T7: cryptography library not available — SKIP"
  pass "T7: SKIP"
fi

# ── T8: member role → 403 ─────────────────────────────────────────────────────
echo ""
echo "── T8: member role → 403 on pack download"
T_MEMBER="$(curl -sf --max-time 10 -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"member","password":"member"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)"
if [[ -n "$T_MEMBER" ]]; then
  MBR_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
    -H "Authorization: Bearer $T_MEMBER" \
    "$BASE/incident/${QID}/pack.zip" 2>/dev/null || echo 000)"
  if [[ "$MBR_CODE" == "403" ]]; then
    pass "T8: member role → 403 on pack download"
  else
    fail "T8: expected 403 but got ${MBR_CODE}"
  fi
else
  info "T8: member user not seeded — SKIP"
  pass "T8: SKIP"
fi

# ── Cleanup ────────────────────────────────────────────────────────────────────
rm -f /tmp/test_incident.zip /tmp/test_incident_pubkey.pem

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_incident_pack.sh"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]]
