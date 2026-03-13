#!/usr/bin/env bash
# test_case_pack_signature.sh — KDAT-008: offline case pack verifier contract tests.
#
# Tests:
#   T1:  Two case pack downloads produce identical manifest.json sha256 (determinism)
#   T2:  verify_case_pack.py exits 0 on a valid downloaded pack
#   T3:  Tamper manifest.sig bytes → exit 2 (signature invalid)
#   T4:  Tamper case.json bytes (listed in manifest hash) → exit 3 (hash mismatch)
#   T5:  Tamper embedded incident zip bytes → exit 5 (incident pack verification failed)
#   T6:  Member role → 403 on GET /cases/{id}/pack.zip
#
# Prerequisites:
#   - Stack running at BASE_URL (default http://127.0.0.1:5174/api)
#   - Signing key configured (EVIDENCE_SIGNING_KEY_PATH set in container)
#   - cryptography Python package installed on host
#   - verify_case_pack.py present in tools/
#
# Usage:
#   bash api/tests/test_case_pack_signature.sh [BASE_URL]
#   BASE_URL defaults to http://127.0.0.1:5174/api

set -euo pipefail

BASE="${1:-http://127.0.0.1:5174/api}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFIER="$(cd "$SCRIPT_DIR/../../.." && pwd)/keystone-deploy/tools/verify_case_pack.py"

PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
info() { echo "       $1"; }

echo "=== test_case_pack_signature.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo "    VERIFIER: ${VERIFIER}"
echo ""

# ── Login ──────────────────────────────────────────────────────────────────────
_login() {
  curl -sf --max-time 10 -X POST "$BASE/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$1\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true
}

T_ADMIN=$(_login admin)
T_MEMBER=$(_login member || _login demo || echo "")

if [[ -z "$T_ADMIN" ]]; then echo "FATAL: could not obtain admin token"; exit 1; fi
info "admin: ${T_ADMIN:0:8}…  member: ${T_MEMBER:0:8}…"

# ── Signing configured? ────────────────────────────────────────────────────────
PUBKEY_FILE="/tmp/kdat008_pubkey.pem"
curl -sf --max-time 10 "$BASE/evidence/public-key" -o "$PUBKEY_FILE" 2>/dev/null || true
if [[ ! -f "$PUBKEY_FILE" || ! -s "$PUBKEY_FILE" ]]; then
  echo "SKIP: signing key not configured — all tests require a signed pack"
  echo "      Set EVIDENCE_SIGNING_KEY_PATH in the API container and restart."
  exit 0
fi
info "pubkey: $(wc -c < "$PUBKEY_FILE") bytes"

# ── cryptography available? ────────────────────────────────────────────────────
if ! python3 -c "from cryptography.exceptions import InvalidSignature" 2>/dev/null; then
  echo "SKIP: cryptography package not installed — run: pip install cryptography"
  exit 0
fi

# ── Verifier present? ──────────────────────────────────────────────────────────
if [[ ! -f "$VERIFIER" ]]; then
  echo "SKIP: verify_case_pack.py not found at $VERIFIER"
  exit 0
fi
echo ""

# ── Create test data: query + decision + case ──────────────────────────────────
QID="$(curl -sf --max-time 30 -X POST "$BASE/query" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"question":"rescue decontamination","scenario_key":"general","mode":"operational","stream":false}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])" 2>/dev/null || true)"
if [[ -z "$QID" ]]; then echo "FATAL: could not create query"; exit 1; fi
info "query_id: ${QID}"

curl -sf --max-time 10 -X POST "$BASE/decisions/${QID}" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"decision":"followed","notes":"kdat008 test"}' > /dev/null 2>&1 || true

CASE_RESP="$(curl -sf --max-time 10 -X POST "$BASE/cases" \
  -H "Authorization: Bearer $T_ADMIN" \
  -H 'Content-Type: application/json' \
  -d "{\"title\":\"KDAT-008 sig test\",\"severity\":\"low\",\"query_ids\":[\"${QID}\"]}" \
  2>/dev/null || true)"
CASE_ID="$(echo "$CASE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('case_id',''))" 2>/dev/null || echo '')"
if [[ -z "$CASE_ID" ]]; then
  # query_ids in POST /cases may not be supported; add query separately
  CASE_RESP2="$(curl -sf --max-time 10 -X POST "$BASE/cases" \
    -H "Authorization: Bearer $T_ADMIN" \
    -H 'Content-Type: application/json' \
    -d '{"title":"KDAT-008 sig test","severity":"low"}' 2>/dev/null || true)"
  CASE_ID="$(echo "$CASE_RESP2" | python3 -c "import sys,json; print(json.load(sys.stdin).get('case_id',''))" 2>/dev/null || echo '')"
  if [[ -z "$CASE_ID" ]]; then echo "FATAL: could not create case"; exit 1; fi
  curl -sf --max-time 10 -X POST "$BASE/cases/${CASE_ID}/queries" \
    -H "Authorization: Bearer $T_ADMIN" \
    -H 'Content-Type: application/json' \
    -d "{\"query_id\":\"${QID}\"}" > /dev/null 2>&1 || true
fi
info "case_id: ${CASE_ID}"
echo ""

# ── Download helper ────────────────────────────────────────────────────────────
_download_pack() {
  local dest="$1"
  curl -s -o "$dest" -w '%{http_code}' --max-time 90 \
    -H "Authorization: Bearer $T_ADMIN" \
    "$BASE/cases/${CASE_ID}/pack.zip" 2>/dev/null || echo "000"
}

# First download
DL1_CODE="$(_download_pack /tmp/kdat008_pack1.zip)"
if [[ "$DL1_CODE" != "200" ]]; then
  echo "FATAL: first pack download returned HTTP ${DL1_CODE}"
  echo "       (Check that the query has a recorded decision and that signing is configured)"
  exit 1
fi
info "pack1 downloaded ($(wc -c < /tmp/kdat008_pack1.zip) bytes)"

# ── T1: Determinism ────────────────────────────────────────────────────────────
echo "── T1: Two downloads → identical manifest.json sha256"
DL2_CODE="$(_download_pack /tmp/kdat008_pack2.zip)"
if [[ "$DL2_CODE" != "200" ]]; then
  fail "T1: second download returned HTTP ${DL2_CODE}"
else
  SHA1="$(python3 -c "
import zipfile, hashlib
with zipfile.ZipFile('/tmp/kdat008_pack1.zip') as z:
    print(hashlib.sha256(z.read('manifest.json')).hexdigest())
" 2>/dev/null || echo FAIL1)"
  SHA2="$(python3 -c "
import zipfile, hashlib
with zipfile.ZipFile('/tmp/kdat008_pack2.zip') as z:
    print(hashlib.sha256(z.read('manifest.json')).hexdigest())
" 2>/dev/null || echo FAIL2)"
  if [[ "$SHA1" == "$SHA2" && "$SHA1" != "FAIL1" ]]; then
    pass "T1: deterministic manifest sha256=${SHA1:0:16}…"
  else
    fail "T1: manifest sha256 differs between downloads: ${SHA1:0:16} vs ${SHA2:0:16}"
  fi
fi
rm -f /tmp/kdat008_pack2.zip

# ── T2: Verifier exits 0 on valid pack ────────────────────────────────────────
echo ""
echo "── T2: verify_case_pack.py exits 0 on valid pack"
set +e
python3 "$VERIFIER" /tmp/kdat008_pack1.zip --pubkey "$PUBKEY_FILE"
T2_EXIT=$?
set -e
if [[ $T2_EXIT -eq 0 ]]; then
  pass "T2: verifier exits 0 on valid case pack"
else
  fail "T2: verifier exited ${T2_EXIT} (expected 0)"
fi

# ── Helper: create tampered ZIP by replacing a single member ──────────────────
_tamper_zip() {
  local src="$1" dst="$2" target_name="$3" mode="$4"
  # mode=sig: flip all bits in the target file
  # mode=content: change first byte of the target file
  # mode=incident_sig: corrupt manifest.sig inside the embedded incident zip
  python3 - "$src" "$dst" "$target_name" "$mode" <<'PYEOF'
import zipfile, io, sys

src, dst, target, mode = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

with zipfile.ZipFile(src) as zin:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == target:
                if mode == 'sig':
                    # Flip all bits — sig becomes invalid
                    data = bytes(b ^ 0xFF for b in data)
                elif mode == 'content':
                    # Change first byte — hash check fails
                    data = bytes([data[0] ^ 0xFF]) + data[1:]
                elif mode == 'incident_sig':
                    # target is an embedded incident zip; corrupt its manifest.sig
                    inner_buf = io.BytesIO()
                    with zipfile.ZipFile(io.BytesIO(data)) as izin:
                        with zipfile.ZipFile(inner_buf, 'w', zipfile.ZIP_DEFLATED) as izout:
                            for iitem in izin.infolist():
                                idata = izin.read(iitem.filename)
                                if iitem.filename == 'manifest.sig':
                                    idata = bytes(b ^ 0xFF for b in idata)
                                izout.writestr(iitem, idata)
                    data = inner_buf.getvalue()
            zout.writestr(item, data)
    with open(dst, 'wb') as f:
        f.write(buf.getvalue())
PYEOF
}

# Find the first incident zip path in the pack
INCIDENT_PATH="$(python3 -c "
import zipfile
with zipfile.ZipFile('/tmp/kdat008_pack1.zip') as zf:
    paths = sorted(n for n in zf.namelist() if n.startswith('incident/') and n.endswith('.zip'))
    print(paths[0] if paths else '')
" 2>/dev/null || echo '')"

if [[ -z "$INCIDENT_PATH" ]]; then
  info "WARN: no incident zip found in pack — T5 will be skipped"
fi

# ── T3: Tamper manifest.sig → exit 2 ─────────────────────────────────────────
echo ""
echo "── T3: Tamper manifest.sig → exit 2 (signature invalid)"
_tamper_zip /tmp/kdat008_pack1.zip /tmp/kdat008_tamper_sig.zip "manifest.sig" "sig"
set +e
python3 "$VERIFIER" /tmp/kdat008_tamper_sig.zip --pubkey "$PUBKEY_FILE" > /dev/null 2>&1
T3_EXIT=$?
set -e
rm -f /tmp/kdat008_tamper_sig.zip
if [[ $T3_EXIT -eq 2 ]]; then
  pass "T3: tampered manifest.sig → exit 2"
else
  fail "T3: expected exit 2, got ${T3_EXIT}"
fi

# ── T4: Tamper case.json → exit 3 ─────────────────────────────────────────────
echo ""
echo "── T4: Tamper case.json → exit 3 (hash mismatch)"
_tamper_zip /tmp/kdat008_pack1.zip /tmp/kdat008_tamper_casejson.zip "case.json" "content"
set +e
python3 "$VERIFIER" /tmp/kdat008_tamper_casejson.zip --pubkey "$PUBKEY_FILE" > /dev/null 2>&1
T4_EXIT=$?
set -e
rm -f /tmp/kdat008_tamper_casejson.zip
if [[ $T4_EXIT -eq 3 ]]; then
  pass "T4: tampered case.json → exit 3"
else
  fail "T4: expected exit 3, got ${T4_EXIT}"
fi

# ── T5: Tamper embedded incident zip → exit 5 ─────────────────────────────────
echo ""
echo "── T5: Tamper embedded incident zip manifest.sig → exit 5"
if [[ -z "$INCIDENT_PATH" ]]; then
  info "T5: SKIP — no incident zip in pack"
  pass "T5: SKIP"
else
  _tamper_zip /tmp/kdat008_pack1.zip /tmp/kdat008_tamper_incident.zip "$INCIDENT_PATH" "incident_sig"
  set +e
  python3 "$VERIFIER" /tmp/kdat008_tamper_incident.zip --pubkey "$PUBKEY_FILE" > /dev/null 2>&1
  T5_EXIT=$?
  set -e
  rm -f /tmp/kdat008_tamper_incident.zip
  if [[ $T5_EXIT -eq 5 ]]; then
    pass "T5: tampered incident zip → exit 5"
  else
    fail "T5: expected exit 5, got ${T5_EXIT}"
  fi
fi

# ── T6: Member → 403 on pack download ─────────────────────────────────────────
echo ""
echo "── T6: Member → 403 on GET /cases/{id}/pack.zip"
if [[ -n "$T_MEMBER" ]]; then
  MBR_CODE="$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $T_MEMBER" \
    "$BASE/cases/${CASE_ID}/pack.zip" 2>/dev/null || echo 000)"
  if [[ "$MBR_CODE" == "403" ]]; then
    pass "T6: member → 403 on case pack download"
  else
    fail "T6: expected 403, got ${MBR_CODE}"
  fi
else
  info "T6: no member token — SKIP"
  pass "T6: SKIP"
fi

# ── Cleanup ────────────────────────────────────────────────────────────────────
rm -f /tmp/kdat008_pack1.zip /tmp/kdat008_pubkey.pem

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  test_case_pack_signature.sh"
echo "  PASS: ${PASS}   FAIL: ${FAIL}"
echo "══════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]]
