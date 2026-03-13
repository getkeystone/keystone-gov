#!/usr/bin/env bash
# test_evidence_signature.sh — Contract tests for KDAT-004 signed evidence bundles.
#
# Tests:
#   T1: GET /evidence/public-key returns a PEM file (no auth required).
#   T2: GET /evidence/{id}.zip returns HTTP 200 for admin and contains manifest.sig.
#   T3: Two consecutive downloads of the same ZIP produce identical manifest.json sha256
#       and manifest.sig sha256 (determinism).
#   T4: Offline verifier exits 0 on the real bundle (signature + hashes valid).
#   T5: Tamper a content file → verifier exits 3 (hash mismatch).
#   T6: Tamper manifest.json → verifier exits 2 (signature invalid).
#
# Usage:
#   bash api/tests/test_evidence_signature.sh [BASE_URL]
#   BASE_URL defaults to http://127.0.0.1:8080/api
#
# Requires: python3, openssl, curl, sha256sum
#   python3 cryptography package must be installed for the offline verifier.

set -euo pipefail

BASE="${1:-http://127.0.0.1:8080/api}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFIER="${SCRIPT_DIR}/../../keystone-deploy/tools/verify_evidence.py"
# Fall back: look next to this script's project root
if [[ ! -f "$VERIFIER" ]]; then
  VERIFIER="$(dirname "$SCRIPT_DIR")/../../keystone-deploy/tools/verify_evidence.py"
fi
if [[ ! -f "$VERIFIER" ]]; then
  echo "FATAL: tools/verify_evidence.py not found (looked at ${VERIFIER})"
  exit 1
fi

echo "=== test_evidence_signature.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE:     ${BASE}"
echo "    verifier: ${VERIFIER}"
echo ""

# ── Login as admin ────────────────────────────────────────────────────────────
_login() {
  curl -sf --max-time 10 -X POST "$BASE/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$1\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true
}

T_ADMIN=$(_login admin)
if [[ -z "$T_ADMIN" ]]; then
  echo "FATAL: could not obtain admin token"; exit 1
fi
info "admin token: ${T_ADMIN:0:8}…"
echo ""

# ── Create a query to get a real query_id ─────────────────────────────────────
QID="$(curl -sf --max-time 30 -X POST "$BASE/query" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"question":"What is the rescue procedure?","scenario_key":"general","mode":"operational","stream":false}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" \
  2>/dev/null || true)"

if [[ -z "$QID" ]]; then
  echo "FATAL: could not create a test query — is the corpus indexed?"; exit 1
fi
info "using query_id: ${QID}"
echo ""

# ── T1: GET /evidence/public-key ──────────────────────────────────────────────
echo "── T1: GET /evidence/public-key (no auth)"
PUBKEY_TMP="$(mktemp /tmp/keystone_test_pubkey_XXXXXX.pem)"
PK_CODE="$(curl -sf --max-time 10 "$BASE/evidence/public-key" \
  -o "$PUBKEY_TMP" -w '%{http_code}' 2>/dev/null || echo 000)"

if [[ "$PK_CODE" == "200" ]] && grep -q "BEGIN PUBLIC KEY" "$PUBKEY_TMP"; then
  pass "T1: /evidence/public-key returned 200 with PEM content"
else
  fail "T1: /evidence/public-key returned HTTP ${PK_CODE} or bad content"
fi

# ── T2: GET /evidence/{id}.zip returns 200 and contains manifest.sig ──────────
echo ""
echo "── T2: GET /evidence/${QID:0:8}….zip — HTTP 200, manifest.sig present"
ZIP1="$(mktemp /tmp/keystone_test_ev1_XXXXXX.zip)"
ZIP_CODE="$(curl -sf --max-time 30 \
  -H "Authorization: Bearer $T_ADMIN" \
  "$BASE/evidence/${QID}.zip" \
  -o "$ZIP1" -w '%{http_code}' 2>/dev/null || echo 000)"

if [[ "$ZIP_CODE" != "200" ]]; then
  fail "T2: GET /evidence/${QID:0:8}.zip returned HTTP ${ZIP_CODE} (expected 200)"
  echo "FATAL: cannot continue without a valid ZIP"; exit 1
fi

HAS_SIG="$(python3 -c "
import zipfile, sys
with zipfile.ZipFile(sys.argv[1]) as zf:
    print('yes' if 'manifest.sig' in {i.filename for i in zf.infolist()} else 'no')
" "$ZIP1")"

if [[ "$HAS_SIG" == "yes" ]]; then
  pass "T2: ZIP downloaded and contains manifest.sig"
else
  fail "T2: manifest.sig missing from ZIP"
fi

# ── T3: Determinism — two runs produce identical manifest.json + manifest.sig ──
echo ""
echo "── T3: Determinism — two downloads produce identical manifest.json + manifest.sig"
sleep 1
ZIP2="$(mktemp /tmp/keystone_test_ev2_XXXXXX.zip)"
curl -sf --max-time 30 \
  -H "Authorization: Bearer $T_ADMIN" \
  "$BASE/evidence/${QID}.zip" \
  -o "$ZIP2" 2>/dev/null

python3 - "$ZIP1" "$ZIP2" <<'PYEOF'
import hashlib, sys, zipfile

def sha256_entry(zf, name):
    return hashlib.sha256(zf.read(name)).hexdigest()

errs = []
with zipfile.ZipFile(sys.argv[1]) as z1, zipfile.ZipFile(sys.argv[2]) as z2:
    for fname in ("manifest.json", "manifest.sig"):
        h1 = sha256_entry(z1, fname)
        h2 = sha256_entry(z2, fname)
        if h1 == h2:
            print(f"[OK]  {fname}: sha256 identical ({h1[:16]}…)")
        else:
            errs.append(fname)
            print(f"[FAIL] {fname}: sha256 differs")
            print(f"       run1: {h1}")
            print(f"       run2: {h2}")
if errs:
    sys.exit(1)
PYEOF
if [[ $? -eq 0 ]]; then
  pass "T3: manifest.json and manifest.sig are deterministic across two downloads"
else
  fail "T3: manifest.json or manifest.sig differ between downloads"
fi
rm -f "$ZIP2"

# ── T4: Offline verifier exits 0 on the real bundle ──────────────────────────
echo ""
echo "── T4: Offline verifier — expect exit 0 (all checks pass)"
python3 "$VERIFIER" "$ZIP1" "$PUBKEY_TMP"
VERIFY_EXIT=$?
if [[ $VERIFY_EXIT -eq 0 ]]; then
  pass "T4: offline verifier exited 0 (all checks passed)"
else
  fail "T4: offline verifier exited ${VERIFY_EXIT} (expected 0)"
fi

# ── T5: Tamper content file → verifier exits 3 ────────────────────────────────
echo ""
echo "── T5: Tamper audit.json → verifier should exit 3 (hash mismatch)"
TAMPER_ZIP="$(mktemp /tmp/keystone_test_tamper_XXXXXX.zip)"
python3 - "$ZIP1" "$TAMPER_ZIP" <<'PYEOF'
import io, json, zipfile, sys

src_path = sys.argv[1]
dst_path = sys.argv[2]

buf = io.BytesIO()
with zipfile.ZipFile(src_path, "r") as zin, zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
    for info in zin.infolist():
        data = zin.read(info.filename)
        if info.filename == "audit.json":
            # Inject a field — changes bytes without touching manifest
            d = json.loads(data)
            d["_tampered"] = True
            data = json.dumps(d, sort_keys=True, indent=2).encode()
        zout.writestr(info, data)

with open(dst_path, "wb") as fh:
    fh.write(buf.getvalue())
PYEOF

set +e; python3 "$VERIFIER" "$TAMPER_ZIP" "$PUBKEY_TMP" > /dev/null 2>&1; TAMPER_EXIT=$?; set -e
rm -f "$TAMPER_ZIP"
if [[ $TAMPER_EXIT -eq 3 ]]; then
  pass "T5: tampered content file detected — verifier exited 3"
else
  fail "T5: verifier exited ${TAMPER_EXIT} (expected 3 for hash mismatch)"
fi

# ── T6: Tamper manifest.json → verifier exits 2 ──────────────────────────────
echo ""
echo "── T6: Tamper manifest.json → verifier should exit 2 (signature invalid)"
TAMPER_MAN_ZIP="$(mktemp /tmp/keystone_test_tamperman_XXXXXX.zip)"
python3 - "$ZIP1" "$TAMPER_MAN_ZIP" <<'PYEOF'
import io, json, zipfile, sys

src_path = sys.argv[1]
dst_path = sys.argv[2]

buf = io.BytesIO()
with zipfile.ZipFile(src_path, "r") as zin, zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
    for info in zin.infolist():
        data = zin.read(info.filename)
        if info.filename == "manifest.json":
            d = json.loads(data)
            d["_tampered"] = True     # invalidates signature
            data = json.dumps(d, sort_keys=True, indent=2).encode()
        zout.writestr(info, data)

with open(dst_path, "wb") as fh:
    fh.write(buf.getvalue())
PYEOF

set +e; python3 "$VERIFIER" "$TAMPER_MAN_ZIP" "$PUBKEY_TMP" > /dev/null 2>&1; TAMPERMAN_EXIT=$?; set -e
rm -f "$TAMPER_MAN_ZIP"
if [[ $TAMPERMAN_EXIT -eq 2 ]]; then
  pass "T6: tampered manifest.json detected — verifier exited 2"
else
  fail "T6: verifier exited ${TAMPERMAN_EXIT} (expected 2 for invalid signature)"
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
rm -f "$ZIP1" "$PUBKEY_TMP"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_evidence_signature.sh"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]]
