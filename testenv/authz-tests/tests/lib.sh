#!/usr/bin/env bash
# Shared helpers for authz tests.

OPA_BASE="${OPA_BASE:-http://localhost:8181}"
OPA_ALLOW="${OPA_BASE}/v1/data/kvmd/authz/allow"

PASS=0
FAIL=0

pass() { PASS=$((PASS+1)); echo "  [PASS] $*"; }
fail() { FAIL=$((FAIL+1)); echo "  [FAIL] $*"; }

summarise() {
    echo ""
    echo "  ${PASS} passed, ${FAIL} failed"
    [ "$FAIL" -eq 0 ]
}

# ── OPA query helpers ─────────────────────────────────────────────────────────
#
# authz_check USER DEVICE_ID ACTION RESOURCE_JSON
#
# RESOURCE_JSON is a raw JSON object passed as input.resource.  The shape
# differs by action:
#   Most actions:          '{"active_port": 1}'   or  '{"active_port": null}'
#   switch.port.activate:  '{"port": 2}'          (the target port to switch to)
#
# Returns "true" or "false".

authz_check() {
    local user="$1" device_id="$2" action="$3" resource="$4"
    local body
    body=$(jq -n \
        --arg      user      "$user" \
        --arg      device_id "$device_id" \
        --arg      action    "$action" \
        --argjson  resource  "$resource" \
        '{"input": {"user": $user, "device_id": $device_id,
                    "action": $action, "resource": $resource}}')
    curl -sf -X POST "$OPA_ALLOW" \
        -H "Content-Type: application/json" \
        -d "$body" \
        | jq -r '.result // false'
}

# assert_allowed LABEL USER DEVICE_ID ACTION RESOURCE_JSON
assert_allowed() {
    local label="$1"; shift
    local result; result=$(authz_check "$@")
    if [ "$result" = "true" ]; then
        pass "$label → allowed"
    else
        fail "$label → expected ALLOWED, got denied"
    fi
}

# assert_denied LABEL USER DEVICE_ID ACTION RESOURCE_JSON
assert_denied() {
    local label="$1"; shift
    local result; result=$(authz_check "$@")
    if [ "$result" = "false" ]; then
        pass "$label → denied"
    else
        fail "$label → expected DENIED, got allowed"
    fi
}
