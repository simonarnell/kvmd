#!/usr/bin/env bash
# Shared helpers for authz integration tests.
#
# These tests hit the real kvmd HTTP API (via nginx) and verify that the
# authz layer enforces OPA decisions correctly.  A 403 means OPA denied the
# request; anything else means OPA allowed it (the handler may still fail for
# unrelated reasons — no switch connected, bad params, etc. — and that is fine:
# we are testing authz, not functionality).
#
# Required environment variables (set in docker-compose or shell):
#   KVMD_BASE      — base URL of the device, e.g. https://pikvm.local
#   ADMIN_USER     — username with superuser/admin role
#   ADMIN_PASS     — password for ADMIN_USER
#   OP_USER        — username with operator role
#   OP_PASS        — password for OP_USER
#   VIEWER_USER    — username with viewer role
#   VIEWER_PASS    — password for VIEWER_USER
#   CURL_INSECURE  — set to 1 to skip TLS verification (self-signed cert)
#   DEVICE_ID      — device hostname / OPA device_id, used in test labels
#   PIKVM_MODE     — "switch" (default) or "standalone"
#                    switch:     PiKVM is connected to a KVM switch; active_port
#                                drives access; per-port ACLs apply.
#                    standalone: PiKVM has no switch; active_port is always null;
#                                device data.json must have "standalone": true.

KVMD_BASE="${KVMD_BASE:-https://localhost}"
DEVICE_ID="${DEVICE_ID:-pikvm}"
PIKVM_MODE="${PIKVM_MODE:-switch}"

PASS=0
FAIL=0

pass() { PASS=$((PASS+1)); echo "  [PASS] $*"; }
fail() { FAIL=$((FAIL+1)); echo "  [FAIL] $*"; }

summarise() {
    echo ""
    echo "  ${PASS} passed, ${FAIL} failed"
    [ "$FAIL" -eq 0 ]
}

# Bail out of the current test script if the device is not in switch mode.
require_switch_mode() {
    if [[ "$PIKVM_MODE" != "switch" ]]; then
        echo "  (skipped — switch mode only; PIKVM_MODE=${PIKVM_MODE})"
        exit 0
    fi
}

# Bail out of the current test script if the device is not in standalone mode.
require_standalone_mode() {
    if [[ "$PIKVM_MODE" != "standalone" ]]; then
        echo "  (skipped — standalone mode only; PIKVM_MODE=${PIKVM_MODE})"
        exit 0
    fi
}

# ── HTTP helpers ──────────────────────────────────────────────────────────────

_API_STATUS_FILE=$(mktemp)
_API_BODY_FILE=$(mktemp)
trap 'rm -f "$_API_STATUS_FILE" "$_API_BODY_FILE"' EXIT

_CURL_BASE=(-s)
[[ "${CURL_INSECURE:-0}" == "1" ]] && _CURL_BASE+=(-k)

# api_call_as USER PASS METHOD PATH [extra curl args...]
# Makes an authenticated API call.  Saves HTTP status to $_API_STATUS_FILE
# and body to $_API_BODY_FILE.  Prints the body.
api_call_as() {
    local user="$1" pass="$2" method="$3" path="$4"; shift 4
    curl "${_CURL_BASE[@]}" \
        -o "$_API_BODY_FILE" -w "%{http_code}" \
        -H "X-KVMD-User: ${user}" \
        -H "X-KVMD-Passwd: ${pass}" \
        -X "$method" \
        "${KVMD_BASE}${path}" "$@" \
        > "$_API_STATUS_FILE"
    cat "$_API_BODY_FILE"
}

# ── Authz-specific assertions ─────────────────────────────────────────────────
#
# The authz layer fires before the handler.  We distinguish three outcomes:
#   allowed  — OPA said yes; HTTP status is anything other than 401 or 403.
#              The handler may return 200, 422, 409, 500, etc. — all fine.
#   denied   — OPA said no; HTTP status is exactly 403.
#   unauthed — credentials were rejected; HTTP status is 401.

_get_status() { cat "$_API_STATUS_FILE"; }

assert_authz_allowed() {
    local label="$1"
    local status; status=$(_get_status)
    case "$status" in
        403)
            fail "${label} — expected ALLOWED, got 403 (authz denied)"
            echo "    body: $(cat "$_API_BODY_FILE")"
            ;;
        401)
            fail "${label} — got 401 (authentication failed — check credentials/htpasswd)"
            ;;
        *)
            pass "${label} — ALLOWED (HTTP ${status})"
            ;;
    esac
}

assert_authz_denied() {
    local label="$1"
    local status; status=$(_get_status)
    if [[ "$status" == "403" ]]; then
        pass "${label} — DENIED (HTTP 403)"
    elif [[ "$status" == "401" ]]; then
        fail "${label} — got 401 (authentication failed — check credentials/htpasswd)"
    else
        fail "${label} — expected 403 (authz denied), got HTTP ${status}"
        echo "    body: $(cat "$_API_BODY_FILE")"
    fi
}

assert_authn_ok() {
    local label="$1"
    local status; status=$(_get_status)
    if [[ "$status" == "200" ]]; then
        pass "${label} — authenticated (HTTP 200)"
    else
        fail "${label} — expected 200, got HTTP ${status}"
        echo "    body: $(cat "$_API_BODY_FILE")"
    fi
}

assert_authn_rejected() {
    local label="$1"
    local status; status=$(_get_status)
    # kvmd returns 403 (not 401) when X-KVMD-User/Passwd headers are present
    # but credentials are wrong — see api/auth.py _check_xhdr.
    # 401 is only returned when no credentials are provided at all.
    if [[ "$status" == "401" || "$status" == "403" ]]; then
        pass "${label} — rejected (HTTP ${status})"
    else
        fail "${label} — expected 401 or 403, got HTTP ${status}"
    fi
}
