#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTS_DIR="$SCRIPT_DIR/tests"
OPA_BASE="${OPA_BASE:-http://localhost:8181}"

# ── Wait for OPA ──────────────────────────────────────────────────────────────
echo "Waiting for OPA at ${OPA_BASE}/health ..."
until curl -sf "${OPA_BASE}/health" >/dev/null 2>&1; do
    sleep 1
done
echo "OPA is ready."

# ── Run tests ─────────────────────────────────────────────────────────────────
PASS=0
FAIL=0

for test_script in "$TESTS_DIR"/[0-9]*.sh; do
    name="$(basename "$test_script")"
    echo ""
    echo "════════════════════════════════════════"
    echo "  $name"
    echo "════════════════════════════════════════"
    if bash "$test_script"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "  ^^^ FAILED"
    fi
done

echo ""
echo "════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "════════════════════════════════════════"

exit "$FAIL"
