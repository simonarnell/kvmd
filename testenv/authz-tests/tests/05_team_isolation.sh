#!/usr/bin/env bash
# pikvm-rack-a partitions ports between two teams:
#   wintel-admin (wbob)  → ports 0 and 1
#   lintel-admin (lcarol) → ports 2 and 3
#
# Each team should be able to use their own ports but be denied access
# to the other team's ports.  Also verifies that lintel-admin lacks ATX
# even on its own ports (not in the lintel-admin role's global permissions
# nor in the port_permissions entry for ports 2/3).

set -euo pipefail
source "$(dirname "$0")/lib.sh"

RACK_A="pikvm-rack-a"

echo "  → wintel-admin (wbob): access to wintel ports (0, 1)"
assert_allowed "wbob activate port 0"   wbob "$RACK_A" switch.port.activate   '{"port": 0}'
assert_allowed "wbob activate port 1"   wbob "$RACK_A" switch.port.activate   '{"port": 1}'
assert_allowed "wbob hid port 0"        wbob "$RACK_A" hid.write              '{"active_port": 0}'
assert_allowed "wbob hid port 1"        wbob "$RACK_A" hid.write              '{"active_port": 1}'
assert_allowed "wbob atx port 0"        wbob "$RACK_A" switch.atx             '{"active_port": 0}'
assert_allowed "wbob streamer port 0"   wbob "$RACK_A" streamer               '{"active_port": 0}'
assert_allowed "wbob navigate port 0"   wbob "$RACK_A" switch.port.navigate   '{"active_port": 0}'

echo "  → wintel-admin (wbob): denied on lintel ports (2, 3)"
assert_denied  "wbob activate port 2"   wbob "$RACK_A" switch.port.activate   '{"port": 2}'
assert_denied  "wbob activate port 3"   wbob "$RACK_A" switch.port.activate   '{"port": 3}'
assert_denied  "wbob hid port 2"        wbob "$RACK_A" hid.write              '{"active_port": 2}'
assert_denied  "wbob hid port 3"        wbob "$RACK_A" hid.write              '{"active_port": 3}'

echo "  → lintel-admin (lcarol): access to lintel ports (2, 3)"
assert_allowed "lcarol activate port 2" lcarol "$RACK_A" switch.port.activate '{"port": 2}'
assert_allowed "lcarol activate port 3" lcarol "$RACK_A" switch.port.activate '{"port": 3}'
assert_allowed "lcarol hid port 2"      lcarol "$RACK_A" hid.write            '{"active_port": 2}'
assert_allowed "lcarol hid port 3"      lcarol "$RACK_A" hid.write            '{"active_port": 3}'
assert_allowed "lcarol streamer port 2" lcarol "$RACK_A" streamer             '{"active_port": 2}'

echo "  → lintel-admin (lcarol): denied on wintel ports (0, 1)"
assert_denied  "lcarol activate port 0" lcarol "$RACK_A" switch.port.activate '{"port": 0}'
assert_denied  "lcarol activate port 1" lcarol "$RACK_A" switch.port.activate '{"port": 1}'
assert_denied  "lcarol hid port 0"      lcarol "$RACK_A" hid.write            '{"active_port": 0}'
assert_denied  "lcarol hid port 1"      lcarol "$RACK_A" hid.write            '{"active_port": 1}'

echo "  → lintel-admin has no ATX permission (not in role, not in port_permissions)"
assert_denied  "lcarol atx port 2"      lcarol "$RACK_A" switch.atx           '{"active_port": 2}'
assert_denied  "lcarol atx port 3"      lcarol "$RACK_A" switch.atx           '{"active_port": 3}'

summarise
