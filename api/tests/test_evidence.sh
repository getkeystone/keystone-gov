#!/usr/bin/env bash
# test_evidence.sh — generate evidence for a live query twice and compare sha256 of files.
#
# Usage:
#   bash api/tests/test_evidence.sh [BASE_URL]
#
# Requires: a running API at BASE_URL (default http://127.0.0.1:8080/api).
# Auth: auto-logins as admin/admin (override with ADMIN_USER / ADMIN_PASS).

set -euo pipefail

BASE="${1:-http://127.0.0.1:8080/api}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"

REQUIRED_FILES=("guidance.json" "audit.json" "verify.json" "cited_source_excerpt.txt")

echo "=== test_evidence.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "    BASE: ${BASE}"
echo ""

# ── Login ─────────────────────────────────────────────────────────────────────
LOGIN_RESP="$(curl -sf --max-time 10 -X POST "${BASE}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null)"
TOKEN="$(echo "${LOGIN_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")"
echo "[OK]  token obtained"

# ── Submit a query to get a live query_id ─────────────────────────────────────
QUERY_RESP="$(curl -sf --max-time 15 -X POST "${BASE}/query" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"question":"decon machine startup steps","mode":"operational"}' 2>/dev/null)"
QID="$(echo "${QUERY_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin)['query_id'])")"
echo "[OK]  query_id: ${QID}"

# ── Download zip twice ────────────────────────────────────────────────────────
OUT1="/tmp/test-evidence-run1-${QID:0:8}.zip"
OUT2="/tmp/test-evidence-run2-${QID:0:8}.zip"

HTTP1="$(curl -sf --max-time 30 \
  -H "Authorization: Bearer ${TOKEN}" \
  "${BASE}/evidence/${QID}.zip" \
  -o "${OUT1}" -w '%{http_code}' 2>/dev/null || echo "000")"
if [[ "${HTTP1}" != "200" ]]; then
  echo "FAIL: first download returned HTTP ${HTTP1}"
  exit 1
fi
echo "[OK]  run 1 downloaded → ${OUT1}"

sleep 1

HTTP2="$(curl -sf --max-time 30 \
  -H "Authorization: Bearer ${TOKEN}" \
  "${BASE}/evidence/${QID}.zip" \
  -o "${OUT2}" -w '%{http_code}' 2>/dev/null || echo "000")"
if [[ "${HTTP2}" != "200" ]]; then
  echo "FAIL: second download returned HTTP ${HTTP2}"
  exit 1
fi
echo "[OK]  run 2 downloaded → ${OUT2}"
echo ""

# ── Extract and compare file sha256 values ───────────────────────────────────
TMPDIR1="/tmp/test-ev-r1-${QID:0:8}"
TMPDIR2="/tmp/test-ev-r2-${QID:0:8}"
rm -rf "${TMPDIR1}" "${TMPDIR2}"
mkdir -p "${TMPDIR1}" "${TMPDIR2}"

python3 -c "
import zipfile, sys
with zipfile.ZipFile(sys.argv[1]) as zf:
    zf.extractall(sys.argv[2])
" "${OUT1}" "${TMPDIR1}"

python3 -c "
import zipfile, sys
with zipfile.ZipFile(sys.argv[1]) as zf:
    zf.extractall(sys.argv[2])
" "${OUT2}" "${TMPDIR2}"

echo "── Checking required files are present ────────────────────────────────"
MISSING=0
for fname in "${REQUIRED_FILES[@]}"; do
  if [[ -f "${TMPDIR1}/${fname}" ]]; then
    echo "[OK]  ${fname} present"
  else
    echo "FAIL: ${fname} missing from zip"
    MISSING=$((MISSING+1))
  fi
done
if [[ "${MISSING}" -gt 0 ]]; then
  echo "FAIL: ${MISSING} required file(s) missing"
  exit 1
fi
echo ""

echo "── Comparing sha256 of deterministic files between runs ────────────────"
DIFF_COUNT=0
for fname in "${REQUIRED_FILES[@]}"; do
  H1="$(sha256sum "${TMPDIR1}/${fname}" | awk '{print $1}')"
  H2="$(sha256sum "${TMPDIR2}/${fname}" | awk '{print $1}')"
  if [[ "${H1}" == "${H2}" ]]; then
    echo "[OK]  ${fname}: sha256 identical (${H1:0:16}…)"
  else
    echo "FAIL: ${fname}: sha256 differs between runs"
    echo "      run1: ${H1}"
    echo "      run2: ${H2}"
    DIFF_COUNT=$((DIFF_COUNT+1))
  fi
done

if [[ "${DIFF_COUNT}" -gt 0 ]]; then
  echo ""
  echo "FAIL: ${DIFF_COUNT} file(s) differ between runs — determinism broken"
  exit 1
fi

echo ""
echo "── Checking manifest.json is present and has required keys ─────────────"
if [[ -f "${TMPDIR1}/manifest.json" ]]; then
  python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    m = json.load(f)
required = ['schema','query_id','generated_utc','git','pdf_deterministic','files']
missing = [k for k in required if k not in m]
if missing:
    print('FAIL: manifest.json missing keys:', missing)
    sys.exit(1)
files = {e['name'] for e in m['files']}
req_files = {'audit.json','verify.json','guidance.json','cited_source_excerpt.txt'}
missing_files = req_files - files
if missing_files:
    print('FAIL: manifest files[] missing:', missing_files)
    sys.exit(1)
print('[OK]  manifest.json valid, schema=', m['schema'])
print('[OK]  manifest files[] contains all required entries')
" "${TMPDIR1}/manifest.json"
else
  echo "FAIL: manifest.json missing from zip"
  exit 1
fi

echo ""
echo "[PASS] Determinism check complete — all required files match between runs."

# Cleanup
rm -rf "${TMPDIR1}" "${TMPDIR2}" "${OUT1}" "${OUT2}"
