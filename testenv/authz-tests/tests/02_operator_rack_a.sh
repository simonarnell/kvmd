#!/usr/bin/env bash
# bob has the operator role.  On pikvm-rack-a the operator role has per-port
# restrictions defined in port_permissions:
#   port 0 → streamer only
#   port 1 → streamer, hid, switch.atx, switch.port.activate, switch.port.navigate
#   port 2 → streamer, hid, switch.port.activate, switch.port.navigate
#   port 3 → no entry (operator not listed) → global role applies
#
# Global operator permissions: switch.port.activate, switch.port.navigate,
#                               switch.atx, hid, streamer

set -euo pipefail
source "$(dirname "$0")/lib.sh"

RACK_A="pikvm-rack-a"

echo "  → Port 0: only streamer permitted"
assert_allowed "bob streamer port 0"  bob "$RACK_A" streamer     '{"active_port": 0}'
assert_denied  "bob hid port 0"       bob "$RACK_A" hid.write    '{"active_port": 0}'
assert_denied  "bob atx port 0"       bob "$RACK_A" switch.atx   '{"active_port": 0}'
assert_denied  "bob activate port 0"  bob "$RACK_A" switch.port.activate '{"port": 0}'

echo "  → Port 1: full operator access"
assert_allowed "bob streamer port 1"  bob "$RACK_A" streamer               '{"active_port": 1}'
assert_allowed "bob hid port 1"       bob "$RACK_A" hid.write              '{"active_port": 1}'
assert_allowed "bob atx port 1"       bob "$RACK_A" switch.atx             '{"active_port": 1}'
assert_allowed "bob activate port 1"  bob "$RACK_A" switch.port.activate   '{"port": 1}'
assert_allowed "bob navigate port 1"  bob "$RACK_A" switch.port.navigate   '{"active_port": 1}'

echo "  → Port 2: streamer + hid + activate/navigate, no ATX"
assert_allowed "bob streamer port 2"  bob "$RACK_A" streamer               '{"active_port": 2}'
assert_allowed "bob hid port 2"       bob "$RACK_A" hid.write              '{"active_port": 2}'
assert_denied  "bob atx port 2"       bob "$RACK_A" switch.atx             '{"active_port": 2}'
assert_allowed "bob activate port 2"  bob "$RACK_A" switch.port.activate   '{"port": 2}'
assert_allowed "bob navigate port 2"  bob "$RACK_A" switch.port.navigate   '{"active_port": 2}'

echo "  → No active port selected: non-navigate actions denied"
assert_denied  "bob hid null port"    bob "$RACK_A" hid.write              '{"active_port": null}'
assert_denied  "bob atx null port"    bob "$RACK_A" switch.atx             '{"active_port": null}'

summarise
