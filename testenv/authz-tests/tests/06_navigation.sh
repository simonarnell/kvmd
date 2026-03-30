#!/usr/bin/env bash
# switch.port.navigate has two rules:
#   1. active_port == null → always allowed (no port selected yet, safe to navigate)
#   2. active_port != null → gated on role's permission for that port
#
# The null-port rule has no user check, so even unknown users can navigate
# when no port is active.

set -euo pipefail
source "$(dirname "$0")/lib.sh"

RACK_A="pikvm-rack-a"

echo "  → Navigate with no active port: allowed for any user (including unknown)"
assert_allowed "bob navigate null port"     bob     "$RACK_A" switch.port.navigate '{"active_port": null}'
assert_allowed "carol navigate null port"   carol   "$RACK_A" switch.port.navigate '{"active_port": null}'
assert_allowed "unknown navigate null port" unknown "$RACK_A" switch.port.navigate '{"active_port": null}'

echo "  → Navigate with active port: gated by port_permissions"
# operator port 0 on rack-a has only ["streamer"] — no navigate permission
assert_denied  "bob navigate active port 0"   bob "$RACK_A" switch.port.navigate '{"active_port": 0}'
# operator port 1 on rack-a includes switch.port.navigate
assert_allowed "bob navigate active port 1"   bob "$RACK_A" switch.port.navigate '{"active_port": 1}'
# operator port 2 includes switch.port.navigate
assert_allowed "bob navigate active port 2"   bob "$RACK_A" switch.port.navigate '{"active_port": 2}'

echo "  → viewer cannot navigate with an active port (viewer has no navigate permission)"
assert_denied  "carol navigate active port 0" carol "$RACK_A" switch.port.navigate '{"active_port": 0}'

summarise
