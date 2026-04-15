#!/usr/bin/env bash
# Run authz integration tests against a real (or mock) kvmd instance.
# Exit code = number of failed test scripts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTS_DIR="$SCRIPT_DIR"
KVMD_BASE="${KVMD_BASE:-https://localhost}"

# ── Wait for kvmd to be reachable ─────────────────────────────────────────────
CURL_OPTS=(-s)
[[ "${CURL_INSECURE:-0}" == "1" ]] && CURL_OPTS+=(-k)

echo "Waiting for kvmd at ${KVMD_BASE}/api/auth/check ..."
until [[ "$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" "${KVMD_BASE}/api/auth/check" 2>/dev/null)" =~ ^(200|401|403)$ ]]; do
    sleep 2
done
echo "kvmd is reachable."
echo ""

# ── Validate required env vars ────────────────────────────────────────────────
for var in ADMIN_USER ADMIN_PASS OP_USER OP_PASS VIEWER_USER VIEWER_PASS; do
    if [[ -z "${!var:-}" ]]; then
        echo "ERROR: Required environment variable ${var} is not set."
        exit 1
    fi
done

# ── Run tests ─────────────────────────────────────────────────────────────────
PASS=0
FAIL=0

for test_script in "$TESTS_DIR"/[0-9]*.sh; do
    name="$(basename "$test_script")"
    echo "════════════════════════════════════════"
    echo "  $name"
    echo "════════════════════════════════════════"
    if bash "$test_script"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  ^^^ FAILED"
    fi
    echo ""
done

echo "════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "════════════════════════════════════════"

exit "$FAIL"
