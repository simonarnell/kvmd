#!/usr/bin/env bash
# Standalone PiKVM role tests (PIKVM_MODE=standalone).
#
# In standalone mode the device has no switch, so active_port is always null.
# The device data.json must have "standalone": true.
#
# Two important policy behaviours being tested here:
#
#   1. switch.port.navigate with active_port == null is UNCONDITIONALLY allowed
#      by the policy (no role check) — this applies to ALL roles including viewer.
#
#   2. All other permission-gated actions (switch.atx, etc.) go through the
#      standalone path: the role must have the relevant permission. Standalone
#      operator roles typically carry hid + streamer but NOT switch.atx, so
#      ATX endpoints remain denied for non-admins.

set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_standalone_mode

# ── Navigation (always allowed when active_port == null) ──────────────────────
echo "  → Viewer: navigation allowed (active_port == null, no role check)"
api_call_as "$VIEWER_USER" "$VIEWER_PASS" POST /api/switch/set_active_prev >/dev/null
assert_authz_allowed "viewer POST /switch/set_active_prev (standalone)"

api_call_as "$VIEWER_USER" "$VIEWER_PASS" POST /api/switch/set_active_next >/dev/null
assert_authz_allowed "viewer POST /switch/set_active_next (standalone)"

echo "  → Operator: navigation allowed (active_port == null, no role check)"
api_call_as "$OP_USER" "$OP_PASS" POST /api/switch/set_active_prev >/dev/null
assert_authz_allowed "operator POST /switch/set_active_prev (standalone)"

api_call_as "$OP_USER" "$OP_PASS" POST /api/switch/set_active_next >/dev/null
assert_authz_allowed "operator POST /switch/set_active_next (standalone)"

# ── ATX (denied for viewer and operator — neither has switch.atx) ─────────────
echo "  → Viewer: ATX denied (no switch.atx permission)"
api_call_as "$VIEWER_USER" "$VIEWER_PASS" POST /api/switch/atx/power >/dev/null
assert_authz_denied "viewer POST /switch/atx/power (standalone)"

api_call_as "$VIEWER_USER" "$VIEWER_PASS" POST /api/switch/atx/click >/dev/null
assert_authz_denied "viewer POST /switch/atx/click (standalone)"

echo "  → Operator: ATX denied (standalone operator role has hid+streamer, not switch.atx)"
api_call_as "$OP_USER" "$OP_PASS" POST /api/switch/atx/power >/dev/null
assert_authz_denied "operator POST /switch/atx/power (standalone)"

api_call_as "$OP_USER" "$OP_PASS" POST /api/switch/atx/click >/dev/null
assert_authz_denied "operator POST /switch/atx/click (standalone)"

# ── Port configuration (denied for all non-admins) ────────────────────────────
echo "  → Viewer: port configuration denied"
api_call_as "$VIEWER_USER" "$VIEWER_PASS" POST /api/switch/set_port_params >/dev/null
assert_authz_denied "viewer POST /switch/set_port_params (standalone)"

echo "  → Operator: port configuration denied"
api_call_as "$OP_USER" "$OP_PASS" POST /api/switch/set_port_params >/dev/null
assert_authz_denied "operator POST /switch/set_port_params (standalone)"

# ── Unannotated endpoints still work ─────────────────────────────────────────
echo "  → All users can reach unannotated endpoints"
api_call_as "$VIEWER_USER" "$VIEWER_PASS" GET /api/auth/check >/dev/null
assert_authn_ok "viewer GET /auth/check (standalone)"

api_call_as "$OP_USER" "$OP_PASS" GET /api/auth/check >/dev/null
assert_authn_ok "operator GET /auth/check (standalone)"

summarise
