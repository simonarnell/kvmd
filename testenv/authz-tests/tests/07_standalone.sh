#!/usr/bin/env bash
# standalone-example has { "standalone": true }.
# active_port is always null (no switch).  The standalone rule gates actions
# on the user's global role permissions instead of denying everything.
#
# Also verifies that a switch device (rack-a) with active_port == null
# still denies non-navigate actions — the standalone flag must be explicit.

set -euo pipefail
source "$(dirname "$0")/lib.sh"

STANDALONE="standalone-example"
RACK_A="pikvm-rack-a"

echo "  → Standalone: operator can use HID and ATX (global role permits)"
assert_allowed "bob hid on standalone"     bob   "$STANDALONE" hid.write   '{"active_port": null}'
assert_allowed "bob atx on standalone"     bob   "$STANDALONE" switch.atx  '{"active_port": null}'
assert_allowed "bob streamer on standalone" bob  "$STANDALONE" streamer    '{"active_port": null}'

echo "  → Standalone: viewer can stream but not use HID"
assert_allowed "carol streamer on standalone" carol "$STANDALONE" streamer   '{"active_port": null}'
assert_denied  "carol hid on standalone"      carol "$STANDALONE" hid.write  '{"active_port": null}'

echo "  → Standalone: switch.port.activate is denied (no ports on a standalone device)"
assert_denied  "bob activate port on standalone" bob "$STANDALONE" switch.port.activate '{"port": 0}'

echo "  → Switch device without standalone flag denies non-navigate actions when active_port is null"
assert_denied  "bob hid null port on rack-a (switch mode)"    bob "$RACK_A" hid.write  '{"active_port": null}'
assert_denied  "bob atx null port on rack-a (switch mode)"    bob "$RACK_A" switch.atx '{"active_port": null}'

summarise
