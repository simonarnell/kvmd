#!/usr/bin/env bash
# bob (operator) on pikvm-rack-b, which has NO port_permissions entry.
# With no per-port overrides the policy falls back to the role's global
# permissions, which include: switch.port.activate, switch.port.navigate,
# switch.atx, hid, streamer.  All ports should be equally accessible.

set -euo pipefail
source "$(dirname "$0")/lib.sh"

RACK_B="pikvm-rack-b"

echo "  → No port_permissions on rack-b: global role applies to all ports"
assert_allowed "bob hid port 0"        bob "$RACK_B" hid.write            '{"active_port": 0}'
assert_allowed "bob hid port 5"        bob "$RACK_B" hid.write            '{"active_port": 5}'
assert_allowed "bob atx port 0"        bob "$RACK_B" switch.atx           '{"active_port": 0}'
assert_allowed "bob activate port 0"   bob "$RACK_B" switch.port.activate '{"port": 0}'
assert_allowed "bob activate port 5"   bob "$RACK_B" switch.port.activate '{"port": 5}'
assert_allowed "bob streamer port 0"   bob "$RACK_B" streamer             '{"active_port": 0}'
assert_allowed "bob navigate port 0"   bob "$RACK_B" switch.port.navigate '{"active_port": 0}'

summarise
