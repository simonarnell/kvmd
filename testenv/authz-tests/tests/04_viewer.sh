#!/usr/bin/env bash
# carol has the viewer role (permissions: ["streamer"]).
# On rack-a the viewer has a port_permissions entry for ports 0-3 that
# contains only "streamer", confirming stream-only access.
# Viewer cannot use HID, ATX, or activate/navigate ports.

set -euo pipefail
source "$(dirname "$0")/lib.sh"

RACK_A="pikvm-rack-a"
RACK_B="pikvm-rack-b"

echo "  → Viewer can stream on every port"
assert_allowed "carol streamer port 0 rack-a" carol "$RACK_A" streamer '{"active_port": 0}'
assert_allowed "carol streamer port 1 rack-a" carol "$RACK_A" streamer '{"active_port": 1}'
assert_allowed "carol streamer port 0 rack-b" carol "$RACK_B" streamer '{"active_port": 0}'

echo "  → Viewer cannot use HID"
assert_denied "carol hid port 0 rack-a" carol "$RACK_A" hid.write  '{"active_port": 0}'
assert_denied "carol hid port 1 rack-a" carol "$RACK_A" hid.write  '{"active_port": 1}'
assert_denied "carol hid port 0 rack-b" carol "$RACK_B" hid.write  '{"active_port": 0}'

echo "  → Viewer cannot use ATX"
assert_denied "carol atx port 0 rack-a" carol "$RACK_A" switch.atx '{"active_port": 0}'

echo "  → Viewer cannot activate ports"
assert_denied "carol activate port 0"   carol "$RACK_A" switch.port.activate '{"port": 0}'
assert_denied "carol activate port 1"   carol "$RACK_A" switch.port.activate '{"port": 1}'

summarise
