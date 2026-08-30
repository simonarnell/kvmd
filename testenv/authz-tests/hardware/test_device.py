# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    Copyright (C) 2018-2024  Maxim Devaev <mdevaev@gmail.com>               #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
#    This program is distributed in the hope that it will be useful,         #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#    GNU General Public License for more details.                            #
#                                                                            #
#    You should have received a copy of the GNU General Public License       #
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                            #
# ========================================================================== #

# Authz integration tests against a REAL kvmd instance (physical PiKVM, or
# any HTTPS endpoint speaking the same API) — not a container we spin up
# ourselves, so testcontainers doesn't apply here: the device under test is
# remote hardware, reached over the network. This just drives it with
# httpx instead of curl/bash, so both authz test suites share one pytest
# entrypoint and neither depends on docker-compose.
#
# The authz layer fires before the handler. We distinguish three outcomes:
#   allowed  — OPA said yes; HTTP status is anything other than 401 or 403.
#              The handler may return 200, 422, 409, 500, etc. — all fine,
#              we're testing authz, not endpoint functionality.
#   denied   — OPA said no; HTTP status is exactly 403.
#   unauthed — credentials were rejected outright; HTTP status is 401.
#
# Prerequisites on the device:
#   - deploy-authz.sh has been run to push code, OPA binary, bundle, and service
#   - /etc/kvmd/override.yaml has authz enabled and device_id set:
#       kvmd:
#         authz:
#           enabled: true
#           device_id: <hostname>
#   - /etc/kvmd/authz/bundle/devices/<device_id>/data.json exists
#     (with "standalone": true if no switch is connected)
#   - kvmd-authz.service is running (OPA sidecar with bundle loaded)
#   - The following test users exist in BOTH /etc/kvmd/htpasswd AND in
#     /etc/kvmd/authz/bundle/data.json with the appropriate roles:
#       ADMIN_USER  → admin role  (permissions: ["*"])
#       OP_USER     → operator role
#       VIEWER_USER → viewer role
#
#   To add test users (note: use mount -o remount,rw, not the rw alias —
#   shell aliases don't work in non-interactive SSH sessions):
#     ssh root@pikvm 'mount -o remount,rw /'
#     ssh root@pikvm 'kvmd-htpasswd set <OP_USER>     <OP_PASS>'
#     ssh root@pikvm 'kvmd-htpasswd set <VIEWER_USER> <VIEWER_PASS>'
#     # Also add them to /etc/kvmd/authz/bundle/data.json
#     ssh root@pikvm 'systemctl restart kvmd-authz && mount -o remount,ro /'
#
# Required environment variables:
#   KVMD_BASE     — base URL of the device, e.g. https://pikvm.local (default: https://localhost)
#   PIKVM_MODE    — "switch" (default) or "standalone"
#   ADMIN_USER    — username with superuser/admin role  (default: admin)
#   ADMIN_PASS    — password for ADMIN_USER             (default: admin)
#   OP_USER       — username with operator role         (default: operator)
#   OP_PASS       — password for OP_USER                (default: operator)
#   VIEWER_USER   — username with viewer role            (default: viewer)
#   VIEWER_PASS   — password for VIEWER_USER             (default: viewer)
#   CURL_INSECURE — set to 1 to skip TLS verification (self-signed cert)
#
# Usage:
#   KVMD_BASE=https://pikvm.local PIKVM_MODE=switch \
#   ADMIN_USER=admin ADMIN_PASS=... OP_USER=operator OP_PASS=... \
#   VIEWER_USER=viewer VIEWER_PASS=... CURL_INSECURE=1 \
#       pytest testenv/authz-tests/hardware/test_device.py -v

import os

from typing import Any

import httpx
import pytest


KVMD_BASE = os.environ.get("KVMD_BASE", "https://localhost")
PIKVM_MODE = os.environ.get("PIKVM_MODE", "switch")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
OP_USER = os.environ.get("OP_USER", "operator")
OP_PASS = os.environ.get("OP_PASS", "operator")
VIEWER_USER = os.environ.get("VIEWER_USER", "viewer")
VIEWER_PASS = os.environ.get("VIEWER_PASS", "viewer")
VERIFY_TLS = (os.environ.get("CURL_INSECURE", "0") != "1")


@pytest.fixture(scope="module")
def client() -> Any:
    with httpx.Client(base_url=KVMD_BASE, verify=VERIFY_TLS, timeout=10.0) as client:
        for _ in range(30):
            try:
                if client.get("/api/auth/check").status_code in (200, 401, 403):
                    break
            except httpx.HTTPError:
                pass
        else:
            pytest.fail(f"kvmd not reachable at {KVMD_BASE}/api/auth/check")
        yield client


def _call(client: httpx.Client, user: str, passwd: str, method: str, path: str) -> httpx.Response:
    return client.request(method, path, headers={"X-KVMD-User": user, "X-KVMD-Passwd": passwd})


def _assert_authz_allowed(resp: httpx.Response, label: str) -> None:
    assert resp.status_code not in (401, 403), f"{label} — expected ALLOWED, got {resp.status_code}: {resp.text}"


def _assert_authz_denied(resp: httpx.Response, label: str) -> None:
    assert resp.status_code != 401, f"{label} — got 401 (authentication failed — check credentials)"
    assert resp.status_code == 403, f"{label} — expected DENIED (403), got {resp.status_code}: {resp.text}"


def _assert_authn_ok(resp: httpx.Response, label: str) -> None:
    assert resp.status_code == 200, f"{label} — expected 200, got {resp.status_code}: {resp.text}"


def _assert_authn_rejected(resp: httpx.Response, label: str) -> None:
    # kvmd returns 403 (not 401) when X-KVMD-User/Passwd are present but wrong
    # — see api/auth.py _check_xhdr. 401 is only returned with no credentials.
    assert resp.status_code in (401, 403), f"{label} — expected 401 or 403, got {resp.status_code}"


# =====
# 01_authentication.sh: baseline auth via GET /api/auth/check, which has no
# permission annotation so authz is never consulted.
# =====

class TestAuthentication:
    def test_admin_accepted(self, client: httpx.Client) -> None:
        _assert_authn_ok(_call(client, ADMIN_USER, ADMIN_PASS, "GET", "/api/auth/check"), "admin auth/check")

    def test_operator_accepted(self, client: httpx.Client) -> None:
        _assert_authn_ok(_call(client, OP_USER, OP_PASS, "GET", "/api/auth/check"), "operator auth/check")

    def test_viewer_accepted(self, client: httpx.Client) -> None:
        _assert_authn_ok(_call(client, VIEWER_USER, VIEWER_PASS, "GET", "/api/auth/check"), "viewer auth/check")

    def test_wrong_password_rejected(self, client: httpx.Client) -> None:
        _assert_authn_rejected(_call(client, ADMIN_USER, "definitely-wrong-password", "GET", "/api/auth/check"), "wrong password")

    def test_unknown_user_rejected(self, client: httpx.Client) -> None:
        _assert_authn_rejected(_call(client, "nobody-at-all", "password", "GET", "/api/auth/check"), "unknown user")


# =====
# 02_superuser_allowed.sh: superuser (admin role, permissions: ["*"]) must be
# allowed on every permission-gated endpoint regardless of device state.
# =====

class TestSuperuserAllowed:
    @pytest.mark.parametrize(("method", "path"), [
        ("POST", "/api/switch/set_active_prev"),
        ("POST", "/api/switch/set_active_next"),
        ("POST", "/api/switch/atx/power"),
        ("POST", "/api/switch/atx/click"),
        ("POST", "/api/switch/set_port_params"),
    ])
    def test_allowed(self, client: httpx.Client, method: str, path: str) -> None:
        _assert_authz_allowed(_call(client, ADMIN_USER, ADMIN_PASS, method, path), f"admin {method} {path}")


# =====
# 03_viewer_restricted.sh: viewer (permissions: ["streamer"]) is denied on
# every permission-gated endpoint except navigation with no active port
# (unconditionally allowed by the policy — no role check).
# =====

@pytest.mark.skipif(PIKVM_MODE != "switch", reason=f"switch mode only; PIKVM_MODE={PIKVM_MODE}")
class TestViewerRestrictedSwitch:
    @pytest.mark.parametrize("path", ["/api/switch/set_active_prev", "/api/switch/set_active_next"])
    def test_navigation_allowed_no_active_port(self, client: httpx.Client, path: str) -> None:
        _assert_authz_allowed(_call(client, VIEWER_USER, VIEWER_PASS, "POST", path), f"viewer POST {path} (no active port)")

    @pytest.mark.parametrize("path", ["/api/switch/atx/power", "/api/switch/atx/click", "/api/switch/set_port_params"])
    def test_denied(self, client: httpx.Client, path: str) -> None:
        _assert_authz_denied(_call(client, VIEWER_USER, VIEWER_PASS, "POST", path), f"viewer POST {path}")

    def test_unannotated_endpoint_reachable(self, client: httpx.Client) -> None:
        _assert_authn_ok(_call(client, VIEWER_USER, VIEWER_PASS, "GET", "/api/auth/check"), "viewer GET /auth/check")


# =====
# 04_operator_allowed.sh: operator (navigate, atx, hid, streamer) is allowed
# on navigation/ATX but denied on port configuration.
# =====

@pytest.mark.skipif(PIKVM_MODE != "switch", reason=f"switch mode only; PIKVM_MODE={PIKVM_MODE}")
class TestOperatorAllowedSwitch:
    @pytest.mark.parametrize("path", [
        "/api/switch/set_active_prev", "/api/switch/set_active_next",
        "/api/switch/atx/power", "/api/switch/atx/click",
    ])
    def test_allowed(self, client: httpx.Client, path: str) -> None:
        _assert_authz_allowed(_call(client, OP_USER, OP_PASS, "POST", path), f"operator POST {path}")

    def test_port_configure_denied(self, client: httpx.Client) -> None:
        _assert_authz_denied(_call(client, OP_USER, OP_PASS, "POST", "/api/switch/set_port_params"), "operator POST /switch/set_port_params")


# =====
# 05_standalone_roles.sh: no switch, active_port always null.
# Navigation is unconditionally allowed for every role; ATX and port
# configuration remain denied for non-admins (standalone roles carry
# hid+streamer, not switch.atx).
# =====

@pytest.mark.skipif(PIKVM_MODE != "standalone", reason=f"standalone mode only; PIKVM_MODE={PIKVM_MODE}")
class TestStandaloneRoles:
    @pytest.mark.parametrize(("user", "passwd"), [(VIEWER_USER, VIEWER_PASS), (OP_USER, OP_PASS)])
    @pytest.mark.parametrize("path", ["/api/switch/set_active_prev", "/api/switch/set_active_next"])
    def test_navigation_allowed(self, client: httpx.Client, user: str, passwd: str, path: str) -> None:
        _assert_authz_allowed(_call(client, user, passwd, "POST", path), f"{user} POST {path} (standalone)")

    @pytest.mark.parametrize(("user", "passwd"), [(VIEWER_USER, VIEWER_PASS), (OP_USER, OP_PASS)])
    @pytest.mark.parametrize("path", ["/api/switch/atx/power", "/api/switch/atx/click", "/api/switch/set_port_params"])
    def test_denied(self, client: httpx.Client, user: str, passwd: str, path: str) -> None:
        _assert_authz_denied(_call(client, user, passwd, "POST", path), f"{user} POST {path} (standalone)")

    @pytest.mark.parametrize(("user", "passwd"), [(VIEWER_USER, VIEWER_PASS), (OP_USER, OP_PASS)])
    def test_unannotated_endpoint_reachable(self, client: httpx.Client, user: str, passwd: str) -> None:
        _assert_authn_ok(_call(client, user, passwd, "GET", "/api/auth/check"), f"{user} GET /auth/check (standalone)")
