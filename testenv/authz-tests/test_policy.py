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

# Integration tests for the kvmd-authz OPA policy, run against a real OPA
# server started via testcontainers (not the fake in-process OPA used by
# testenv/tests/apps/kvmd/test_authz.py, which only covers AuthzManager's
# HTTP client behaviour).
#
# This exercises the actual bundle layout (policy + data.json + per-device
# data.json) exactly as it will be loaded from a real bundle server, so it
# catches bundle-structure mistakes that a mocked OPA can't.
#
# Run with: pytest testenv/authz-tests/test_policy.py
# Requires a working Docker daemon (see top-level `make authz-test`).

import pathlib
import time

from typing import Any

import httpx
import pytest

from testcontainers.core.container import DockerContainer


_HERE = pathlib.Path(__file__).parent
_REPO_ROOT = _HERE.parent.parent
_POLICY_DIR = _REPO_ROOT / "configs" / "kvmd" / "authz" / "bundle" / "policy"
_DATA_DIR = _HERE / "data"
# The real manifest, not a separate test copy -- a hand-maintained duplicate
# previously had no "roots" restriction at all, so it silently diverged from
# the real one and never caught data.json using a data root (group_roles)
# the real manifest didn't declare. That crashed kvmd-authz.service outright
# on any real deployment using group-derived roles, found only by testing
# against real hardware.
_MANIFEST = _REPO_ROOT / "configs" / "kvmd" / "authz" / "bundle" / ".manifest"

RACK_A = "pikvm-rack-a"
RACK_B = "pikvm-rack-b"
STANDALONE = "standalone-example"


@pytest.fixture(scope="module")
def opa_url() -> Any:
    container = (
        DockerContainer("openpolicyagent/opa:latest-static")
        .with_command("run --server --log-level error --addr :8181 --bundle /bundle")
        .with_volume_mapping(str(_POLICY_DIR), "/bundle/policy", "ro")
        .with_volume_mapping(str(_DATA_DIR / "data.json"), "/bundle/data.json", "ro")
        .with_volume_mapping(str(_DATA_DIR / "devices"), "/bundle/devices", "ro")
        .with_volume_mapping(str(_MANIFEST), "/bundle/.manifest", "ro")
        .with_exposed_ports(8181)
    )
    with container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(8181)
        health_url = f"http://{host}:{port}/health"
        for _ in range(50):
            try:
                if httpx.get(health_url, timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError(f"OPA did not become healthy at {health_url}")
        yield f"http://{host}:{port}/v1/data/kvmd/authz/allow"


@pytest.fixture(scope="module")
def package_url(opa_url: str) -> str:
    return opa_url.rsplit("/", 1)[0]


def _check(
    client: httpx.Client, opa_url: str, user: str, device_id: str, action: str, resource: dict,
    *, user_groups: list[str] | None = None,
) -> bool:
    input_data = {
        "user": user,
        "device_id": device_id,
        "action": action,
        "resource": resource,
    }
    if user_groups is not None:
        input_data["user_groups"] = user_groups
    resp = client.post(opa_url, json={"input": input_data})
    resp.raise_for_status()
    return bool(resp.json().get("result", False))


def _permissions(
    client: httpx.Client, package_url: str, user: str, device_id: str, resource: dict,
    *, user_groups: list[str] | None = None, candidate_ports: list[int] | None = None,
) -> dict:
    # effective_permissions()/activatable_ports() live in the same rego
    # package as allow -- query the bare package path, not .../allow, to
    # get both back in one response (mirrors AuthzManager.list_permissions()).
    input_data = {
        "user": user,
        "user_groups": (user_groups or []),
        "device_id": device_id,
        "action": "",
        "resource": resource,
        "candidate_ports": (candidate_ports or []),
    }
    resp = client.post(package_url, json={"input": input_data})
    resp.raise_for_status()
    result = resp.json().get("result", {})
    return {
        "permissions": sorted(result.get("effective_permissions", [])),
        "activatable_ports": sorted(result.get("activatable_ports", [])),
    }


@pytest.fixture(scope="module")
def client() -> Any:
    with httpx.Client(timeout=5.0) as client:
        yield client


# =====
# 01_superuser.sh: alice (superuser, permissions: ["*"]) bypasses all
# per-port checks on any device.
# =====

@pytest.mark.parametrize(("user", "device_id", "action", "resource"), [
    ("alice", RACK_A, "switch.port.activate", {"port": 0}),
    ("alice", RACK_A, "switch.port.activate", {"port": 3}),
    ("alice", RACK_A, "hid.write", {"active_port": 0}),
    ("alice", RACK_A, "hid.write", {"active_port": 3}),
    ("alice", RACK_A, "switch.atx", {"active_port": 0}),
    ("alice", RACK_A, "switch.port.navigate", {"active_port": None}),
    ("alice", RACK_A, "switch.port.navigate", {"active_port": 0}),
    ("alice", STANDALONE, "hid.write", {"active_port": None}),
])
def test_superuser_allowed(client: httpx.Client, opa_url: str, user: str, device_id: str, action: str, resource: dict) -> None:
    assert _check(client, opa_url, user, device_id, action, resource)


# =====
# 02_operator_rack_a.sh: bob (operator) on pikvm-rack-a, which restricts the
# operator role per-port via port_permissions.
# =====

@pytest.mark.parametrize(("action", "resource", "allowed"), [
    ("streamer.view", {"active_port": 0}, True),
    ("hid.write", {"active_port": 0}, False),
    ("switch.atx", {"active_port": 0}, False),
    ("switch.port.activate", {"port": 0}, False),

    ("streamer.view", {"active_port": 1}, True),
    ("hid.write", {"active_port": 1}, True),
    ("switch.atx", {"active_port": 1}, True),
    ("switch.port.activate", {"port": 1}, True),
    ("switch.port.navigate", {"active_port": 1}, True),

    ("streamer.view", {"active_port": 2}, True),
    ("hid.write", {"active_port": 2}, True),
    ("switch.atx", {"active_port": 2}, False),
    ("switch.port.activate", {"port": 2}, True),
    ("switch.port.navigate", {"active_port": 2}, True),

    ("hid.write", {"active_port": None}, False),
    ("switch.atx", {"active_port": None}, False),
])
def test_operator_rack_a(client: httpx.Client, opa_url: str, action: str, resource: dict, allowed: bool) -> None:
    assert _check(client, opa_url, "bob", RACK_A, action, resource) == allowed


# =====
# 03_operator_rack_b.sh: bob (operator) on pikvm-rack-b, which has NO
# port_permissions entry — falls back to the role's global permissions on
# every port.
# =====

@pytest.mark.parametrize(("action", "resource"), [
    ("hid.write", {"active_port": 0}),
    ("hid.write", {"active_port": 5}),
    ("switch.atx", {"active_port": 0}),
    ("switch.port.activate", {"port": 0}),
    ("switch.port.activate", {"port": 5}),
    ("streamer.view", {"active_port": 0}),
    ("switch.port.navigate", {"active_port": 0}),
])
def test_operator_rack_b_no_port_permissions(client: httpx.Client, opa_url: str, action: str, resource: dict) -> None:
    assert _check(client, opa_url, "bob", RACK_B, action, resource)


# =====
# 04_viewer.sh: carol (viewer, permissions: ["streamer.view"]) can only stream,
# on any device/port.
# =====

@pytest.mark.parametrize(("device_id", "action", "resource", "allowed"), [
    (RACK_A, "streamer.view", {"active_port": 0}, True),
    (RACK_A, "streamer.view", {"active_port": 1}, True),
    (RACK_B, "streamer.view", {"active_port": 0}, True),
    (RACK_A, "hid.write", {"active_port": 0}, False),
    (RACK_A, "hid.write", {"active_port": 1}, False),
    (RACK_B, "hid.write", {"active_port": 0}, False),
    (RACK_A, "switch.atx", {"active_port": 0}, False),
    (RACK_A, "switch.port.activate", {"port": 0}, False),
    (RACK_A, "switch.port.activate", {"port": 1}, False),
])
def test_viewer(client: httpx.Client, opa_url: str, device_id: str, action: str, resource: dict, allowed: bool) -> None:
    assert _check(client, opa_url, "carol", device_id, action, resource) == allowed


# =====
# 05_team_isolation.sh: pikvm-rack-a partitions ports between two teams —
# wintel-admin (wbob) on ports 0-1, lintel-admin (lcarol) on ports 2-3.
# Each team is denied the other team's ports; lintel-admin also lacks ATX
# entirely (not in its role nor its port_permissions entry).
# =====

@pytest.mark.parametrize(("user", "action", "resource", "allowed"), [
    ("wbob", "switch.port.activate", {"port": 0}, True),
    ("wbob", "switch.port.activate", {"port": 1}, True),
    ("wbob", "hid.write", {"active_port": 0}, True),
    ("wbob", "hid.write", {"active_port": 1}, True),
    ("wbob", "switch.atx", {"active_port": 0}, True),
    ("wbob", "streamer.view", {"active_port": 0}, True),
    ("wbob", "switch.port.navigate", {"active_port": 0}, True),
    ("wbob", "switch.port.activate", {"port": 2}, False),
    ("wbob", "switch.port.activate", {"port": 3}, False),
    ("wbob", "hid.write", {"active_port": 2}, False),
    ("wbob", "hid.write", {"active_port": 3}, False),

    ("lcarol", "switch.port.activate", {"port": 2}, True),
    ("lcarol", "switch.port.activate", {"port": 3}, True),
    ("lcarol", "hid.write", {"active_port": 2}, True),
    ("lcarol", "hid.write", {"active_port": 3}, True),
    ("lcarol", "streamer.view", {"active_port": 2}, True),
    ("lcarol", "switch.port.activate", {"port": 0}, False),
    ("lcarol", "switch.port.activate", {"port": 1}, False),
    ("lcarol", "hid.write", {"active_port": 0}, False),
    ("lcarol", "hid.write", {"active_port": 1}, False),
    ("lcarol", "switch.atx", {"active_port": 2}, False),
    ("lcarol", "switch.atx", {"active_port": 3}, False),
])
def test_team_isolation(client: httpx.Client, opa_url: str, user: str, action: str, resource: dict, allowed: bool) -> None:
    assert _check(client, opa_url, user, RACK_A, action, resource) == allowed


# =====
# 06_navigation.sh: switch.port.navigate has two rules — always allowed
# when no port is active (even for unknown users, no user lookup in that
# rule), otherwise gated on the role's port_permissions.
# =====

@pytest.mark.parametrize(("user", "resource", "allowed"), [
    ("bob", {"active_port": None}, True),
    ("carol", {"active_port": None}, True),
    ("unknown", {"active_port": None}, True),
    ("bob", {"active_port": 0}, False),   # operator port 0 on rack-a: streamer only
    ("bob", {"active_port": 1}, True),    # operator port 1: includes navigate
    ("bob", {"active_port": 2}, True),    # operator port 2: includes navigate
    ("carol", {"active_port": 0}, False),  # viewer has no navigate permission
])
def test_navigation(client: httpx.Client, opa_url: str, user: str, resource: dict, allowed: bool) -> None:
    assert _check(client, opa_url, user, RACK_A, "switch.port.navigate", resource) == allowed


# =====
# 07_standalone.sh: standalone-example has "standalone": true, so
# active_port == null gates on global role permissions instead of denying
# everything. A switch device without the flag still denies non-navigate
# actions when active_port is null.
# =====

@pytest.mark.parametrize(("user", "device_id", "action", "resource", "allowed"), [
    ("bob", STANDALONE, "hid.write", {"active_port": None}, True),
    ("bob", STANDALONE, "switch.atx", {"active_port": None}, True),
    ("bob", STANDALONE, "streamer.view", {"active_port": None}, True),
    ("carol", STANDALONE, "streamer.view", {"active_port": None}, True),
    ("carol", STANDALONE, "hid.write", {"active_port": None}, False),
    ("bob", STANDALONE, "switch.port.activate", {"port": 0}, False),
    ("bob", RACK_A, "hid.write", {"active_port": None}, False),
    ("bob", RACK_A, "switch.atx", {"active_port": None}, False),
])
def test_standalone(client: httpx.Client, opa_url: str, user: str, device_id: str, action: str, resource: dict, allowed: bool) -> None:
    assert _check(client, opa_url, user, device_id, action, resource) == allowed


# =====
# 08_unknown_user.sh: a user not present in data.users is denied everything
# except navigation with no active port (that rule has no user lookup).
# =====

@pytest.mark.parametrize(("device_id", "action", "resource", "allowed"), [
    (RACK_A, "streamer.view", {"active_port": 0}, False),
    (RACK_A, "hid.write", {"active_port": 0}, False),
    (RACK_A, "switch.atx", {"active_port": 0}, False),
    (RACK_A, "switch.port.activate", {"port": 0}, False),
    (STANDALONE, "hid.write", {"active_port": None}, False),
    (RACK_A, "switch.port.navigate", {"active_port": None}, True),
    (RACK_A, "switch.port.navigate", {"active_port": 0}, False),
])
def test_unknown_user(client: httpx.Client, opa_url: str, device_id: str, action: str, resource: dict, allowed: bool) -> None:
    assert _check(client, opa_url, "unknown", device_id, action, resource) == allowed


# =====
# Group-derived roles: an identity with no static data.users entry at all
# (e.g. an OIDC-only account) gets roles via data.group_roles[group] matched
# against input.user_groups from the caller's session — the mechanism that
# lets IdP group membership drive authz, not just per-user bundle entries.
# =====

@pytest.mark.parametrize(("user_groups", "action", "resource", "allowed"), [
    (["kvmd-operators"], "hid.write", {"active_port": 0}, True),
    (["kvmd-operators"], "switch.port.activate", {"port": 5}, True),
    (["kvmd-viewers"], "streamer.view", {"active_port": 0}, True),
    (["kvmd-viewers"], "hid.write", {"active_port": 0}, False),  # viewer role: no hid
    (["some-unmapped-group"], "streamer.view", {"active_port": 0}, False),
    ([], "streamer.view", {"active_port": 0}, False),
])
def test_group_derived_role(
    client: httpx.Client, opa_url: str, user_groups: list[str], action: str, resource: dict, allowed: bool,
) -> None:
    # "dave" has no data.users entry — access is entirely group-derived.
    assert _check(client, opa_url, "dave", RACK_B, action, resource, user_groups=user_groups) == allowed


def test_group_role_combines_with_static_role(client: httpx.Client, opa_url: str) -> None:
    # bob is statically an operator (data.users) AND in kvmd-viewers (group);
    # the union must not downgrade him to viewer-only.
    assert _check(client, opa_url, "bob", RACK_B, "switch.port.activate", {"port": 5}, user_groups=["kvmd-viewers"])


def test_group_role_absent_user_groups_key_still_works(client: httpx.Client, opa_url: str) -> None:
    # Omitting "user_groups" from input entirely (older kvmd client) must not
    # error — static per-user roles keep working exactly as before.
    assert _check(client, opa_url, "bob", RACK_B, "hid.write", {"active_port": 0})


# =====
# effective_permissions / activatable_ports: the frontend permission-
# discovery rules. These reuse `allow` itself via `with`, so a result here
# is exactly what a real per-action check would decide -- these tests exist
# to pin the *aggregation*, not re-litigate `allow`'s own logic (already
# covered above).
# =====

def test_effective_permissions_standalone(client: httpx.Client, package_url: str) -> None:
    # bob is a static operator: ["switch.port.activate", "switch.port.navigate",
    # "switch.atx", "hid", "streamer.view"]. switch.port.activate is excluded
    # (handled by activatable_ports instead).
    result = _permissions(client, package_url, "bob", STANDALONE, {"active_port": None})
    assert result["permissions"] == sorted(["switch.atx", "hid", "streamer.view", "switch.port.navigate"])


def test_effective_permissions_switch_mode_no_active_port(client: httpx.Client, package_url: str) -> None:
    # No port selected yet on a switch device: only the unconditional
    # navigate-when-null rule fires. operator has no device-global action
    # (gpio/log/export/...) in this fixture, so nothing else does either.
    result = _permissions(client, package_url, "bob", RACK_A, {"active_port": None})
    assert result["permissions"] == ["switch.port.navigate"]


def test_effective_permissions_switch_mode_active_port(client: httpx.Client, package_url: str) -> None:
    # RACK_A port 1: operator has ["streamer.view", "hid", "switch.atx",
    # "switch.port.activate", "switch.port.navigate"].
    result = _permissions(client, package_url, "bob", RACK_A, {"active_port": 1})
    assert result["permissions"] == sorted(["hid", "streamer.view", "switch.atx", "switch.port.navigate"])


def test_effective_permissions_superuser_gets_the_full_vocabulary(client: httpx.Client, package_url: str) -> None:
    result = _permissions(client, package_url, "alice", RACK_A, {"active_port": None})
    assert result["permissions"] == sorted([
        "hid", "gpio", "log", "export", "streamer.view", "snapshot",
        "switch.atx", "switch.port.navigate", "switch.port.configure",
        "switch.device.configure", "switch.device.reset",
        "msd.add", "msd.mount", "msd.delete", "msd.read", "msd.reset",
    ])


def test_activatable_ports_respects_the_port_permissions_allowlist(client: httpx.Client, package_url: str) -> None:
    # RACK_A operator: port 0 only grants "streamer.view" (no activate);
    # ports 1 and 2 grant "switch.port.activate"; port 3 isn't listed at all.
    result = _permissions(client, package_url, "bob", RACK_A, {"active_port": None}, candidate_ports=[0, 1, 2, 3])
    assert result["activatable_ports"] == [1, 2]


def test_activatable_ports_no_restriction_when_port_permissions_unconfigured(client: httpx.Client, package_url: str) -> None:
    # RACK_B has no port_permissions at all: operator's global
    # switch.port.activate permission applies to every candidate port.
    result = _permissions(client, package_url, "bob", RACK_B, {"active_port": None}, candidate_ports=[0, 1, 2, 99])
    assert result["activatable_ports"] == [0, 1, 2, 99]


def test_activatable_ports_empty_for_a_role_without_the_permission(client: httpx.Client, package_url: str) -> None:
    # RACK_A viewer entries only grant "streamer.view" per port, never
    # switch.port.activate.
    result = _permissions(client, package_url, "carol", RACK_A, {"active_port": None}, candidate_ports=[0, 1])
    assert result["activatable_ports"] == []


def test_activatable_ports_empty_on_standalone(client: httpx.Client, package_url: str) -> None:
    # switch.port.activate's own allow rule requires "not standalone" --
    # there are no ports to activate on a standalone device, regardless of
    # role or candidate_ports.
    result = _permissions(client, package_url, "bob", STANDALONE, {"active_port": None}, candidate_ports=[0, 1, 2])
    assert result["activatable_ports"] == []
