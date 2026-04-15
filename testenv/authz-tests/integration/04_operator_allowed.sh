#!/usr/bin/env bash
# Operator role (permissions include switch.port.navigate, switch.atx, hid, streamer)
# must be allowed on navigation and ATX endpoints.
# Port-level ACLs are not tested here — that is covered by the OPA policy tests.

set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_switch_mode

echo "  → Operator: allowed on switch navigation"
api_call_as "$OP_USER" "$OP_PASS" POST /api/switch/set_active_prev >/dev/null
assert_authz_allowed "operator POST /switch/set_active_prev"

api_call_as "$OP_USER" "$OP_PASS" POST /api/switch/set_active_next >/dev/null
assert_authz_allowed "operator POST /switch/set_active_next"

echo "  → Operator: allowed on switch ATX"
api_call_as "$OP_USER" "$OP_PASS" POST /api/switch/atx/power >/dev/null
assert_authz_allowed "operator POST /switch/atx/power"

api_call_as "$OP_USER" "$OP_PASS" POST /api/switch/atx/click >/dev/null
assert_authz_allowed "operator POST /switch/atx/click"

echo "  → Operator: denied on port configuration (switch.port.configure not in operator permissions)"
api_call_as "$OP_USER" "$OP_PASS" POST /api/switch/set_port_params >/dev/null
assert_authz_denied "operator denied POST /switch/set_port_params"

summarise
