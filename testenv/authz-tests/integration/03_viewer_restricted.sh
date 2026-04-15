#!/usr/bin/env bash
# Viewer role (permissions: ["streamer"]) must be denied on all
# permission-gated endpoints except those in the streamer namespace.
#
# Note on navigation: the policy unconditionally allows switch.port.navigate
# when active_port == null (no role check).  This is intentional — a user
# must be able to navigate in order to select a port before any port-level
# access control can apply.  On a device with no switch connected (or no port
# yet activated) active_port is always null, so navigation is always allowed
# for all authenticated users including viewer.

set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_switch_mode

echo "  → Viewer: navigation allowed when no port is active (active_port == null, no role check)"
api_call_as "$VIEWER_USER" "$VIEWER_PASS" POST /api/switch/set_active_prev >/dev/null
assert_authz_allowed "viewer POST /switch/set_active_prev (no active port)"

api_call_as "$VIEWER_USER" "$VIEWER_PASS" POST /api/switch/set_active_next >/dev/null
assert_authz_allowed "viewer POST /switch/set_active_next (no active port)"

echo "  → Viewer: denied on switch ATX"
api_call_as "$VIEWER_USER" "$VIEWER_PASS" POST /api/switch/atx/power >/dev/null
assert_authz_denied "viewer denied POST /switch/atx/power"

api_call_as "$VIEWER_USER" "$VIEWER_PASS" POST /api/switch/atx/click >/dev/null
assert_authz_denied "viewer denied POST /switch/atx/click"

echo "  → Viewer: denied on port configuration"
api_call_as "$VIEWER_USER" "$VIEWER_PASS" POST /api/switch/set_port_params >/dev/null
assert_authz_denied "viewer denied POST /switch/set_port_params"

echo "  → Viewer: allowed on endpoints without a permission annotation"
api_call_as "$VIEWER_USER" "$VIEWER_PASS" GET /api/auth/check >/dev/null
assert_authn_ok "viewer GET /auth/check (no authz gate)"

summarise
