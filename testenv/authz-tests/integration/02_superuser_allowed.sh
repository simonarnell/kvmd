#!/usr/bin/env bash
# Superuser (admin role, permissions: ["*"]) must be allowed on every
# permission-gated endpoint regardless of device state.

set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "  → Superuser: switch navigation endpoints"
api_call_as "$ADMIN_USER" "$ADMIN_PASS" POST /api/switch/set_active_prev >/dev/null
assert_authz_allowed "admin POST /switch/set_active_prev"

api_call_as "$ADMIN_USER" "$ADMIN_PASS" POST /api/switch/set_active_next >/dev/null
assert_authz_allowed "admin POST /switch/set_active_next"

echo "  → Superuser: switch ATX endpoints"
api_call_as "$ADMIN_USER" "$ADMIN_PASS" POST /api/switch/atx/power >/dev/null
assert_authz_allowed "admin POST /switch/atx/power"

api_call_as "$ADMIN_USER" "$ADMIN_PASS" POST /api/switch/atx/click >/dev/null
assert_authz_allowed "admin POST /switch/atx/click"

echo "  → Superuser: switch port configuration"
api_call_as "$ADMIN_USER" "$ADMIN_PASS" POST /api/switch/set_port_params >/dev/null
assert_authz_allowed "admin POST /switch/set_port_params"

summarise
