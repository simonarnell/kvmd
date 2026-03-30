#!/usr/bin/env bash
# alice has the superuser role (permissions: ["*"]).
# The "*" bypass rule should allow every action on every device
# without any port-level check.

set -euo pipefail
source "$(dirname "$0")/lib.sh"

RACK_A="pikvm-rack-a"
STANDALONE="standalone-example"

echo "  → Superuser can activate any port on switch device"
assert_allowed "alice activate port 0 on rack-a" \
    alice "$RACK_A" switch.port.activate '{"port": 0}'
assert_allowed "alice activate port 3 on rack-a (no role perms for that port)" \
    alice "$RACK_A" switch.port.activate '{"port": 3}'

echo "  → Superuser can use HID regardless of active port"
assert_allowed "alice hid on port 0" \
    alice "$RACK_A" hid.write '{"active_port": 0}'
assert_allowed "alice hid on port 3 (no operator perms here)" \
    alice "$RACK_A" hid.write '{"active_port": 3}'

echo "  → Superuser can use ATX"
assert_allowed "alice switch.atx on port 0" \
    alice "$RACK_A" switch.atx '{"active_port": 0}'

echo "  → Superuser can navigate"
assert_allowed "alice navigate with no active port" \
    alice "$RACK_A" switch.port.navigate '{"active_port": null}'
assert_allowed "alice navigate with active port" \
    alice "$RACK_A" switch.port.navigate '{"active_port": 0}'

echo "  → Superuser is also allowed on standalone device"
assert_allowed "alice hid on standalone" \
    alice "$STANDALONE" hid.write '{"active_port": null}'

summarise
