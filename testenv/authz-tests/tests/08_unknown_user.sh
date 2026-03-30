#!/usr/bin/env bash
# A user not present in data.users should be denied everything except
# navigation with no active port (that rule has no user lookup).

set -euo pipefail
source "$(dirname "$0")/lib.sh"

RACK_A="pikvm-rack-a"
STANDALONE="standalone-example"

echo "  → Unknown user denied all normal actions"
assert_denied "unknown streamer"        unknown "$RACK_A"    streamer             '{"active_port": 0}'
assert_denied "unknown hid"             unknown "$RACK_A"    hid.write            '{"active_port": 0}'
assert_denied "unknown atx"             unknown "$RACK_A"    switch.atx           '{"active_port": 0}'
assert_denied "unknown activate"        unknown "$RACK_A"    switch.port.activate '{"port": 0}'
assert_denied "unknown hid standalone"  unknown "$STANDALONE" hid.write           '{"active_port": null}'

echo "  → Unknown user can still navigate when no port is active (rule has no user check)"
assert_allowed "unknown navigate null port" unknown "$RACK_A" switch.port.navigate '{"active_port": null}'

echo "  → Unknown user denied navigation when a port is active"
assert_denied  "unknown navigate port 0"    unknown "$RACK_A" switch.port.navigate '{"active_port": 0}'

summarise
