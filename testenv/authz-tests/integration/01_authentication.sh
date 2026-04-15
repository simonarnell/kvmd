#!/usr/bin/env bash
# Authentication baseline: verify that credentials are accepted/rejected
# before touching authz at all.  Uses GET /api/auth/check which has no
# permission annotation so authz is never consulted.

set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "  → Admin credentials are accepted"
api_call_as "$ADMIN_USER" "$ADMIN_PASS" GET /api/auth/check >/dev/null
assert_authn_ok "admin auth/check"

echo "  → Operator credentials are accepted"
api_call_as "$OP_USER" "$OP_PASS" GET /api/auth/check >/dev/null
assert_authn_ok "operator auth/check"

echo "  → Viewer credentials are accepted"
api_call_as "$VIEWER_USER" "$VIEWER_PASS" GET /api/auth/check >/dev/null
assert_authn_ok "viewer auth/check"

echo "  → Wrong password is rejected"
api_call_as "$ADMIN_USER" "definitely-wrong-password" GET /api/auth/check >/dev/null
assert_authn_rejected "wrong password rejected"

echo "  → Unknown user is rejected"
api_call_as "nobody-at-all" "password" GET /api/auth/check >/dev/null
assert_authn_rejected "unknown user rejected"

summarise
