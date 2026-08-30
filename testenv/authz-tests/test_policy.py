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
_MANIFEST = _HERE / "bundle-test.manifest"

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


def _check(client: httpx.Client, opa_url: str, user: str, device_id: str, action: str, resource: dict) -> bool:
    resp = client.post(opa_url, json={
        "input": {
            "user": user,
            "device_id": device_id,
            "action": action,
            "resource": resource,
        },
    })
    resp.raise_for_status()
    return bool(resp.json().get("result", False))


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
    ("streamer", {"active_port": 0}, True),
    ("hid.write", {"active_port": 0}, False),
    ("switch.atx", {"active_port": 0}, False),
    ("switch.port.activate", {"port": 0}, False),

    ("streamer", {"active_port": 1}, True),
    ("hid.write", {"active_port": 1}, True),
    ("switch.atx", {"active_port": 1}, True),
    ("switch.port.activate", {"port": 1}, True),
    ("switch.port.navigate", {"active_port": 1}, True),

    ("streamer", {"active_port": 2}, True),
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
    ("streamer", {"active_port": 0}),
    ("switch.port.navigate", {"active_port": 0}),
])
def test_operator_rack_b_no_port_permissions(client: httpx.Client, opa_url: str, action: str, resource: dict) -> None:
    assert _check(client, opa_url, "bob", RACK_B, action, resource)


# =====
# 04_viewer.sh: carol (viewer, permissions: ["streamer"]) can only stream,
# on any device/port.
# =====

@pytest.mark.parametrize(("device_id", "action", "resource", "allowed"), [
    (RACK_A, "streamer", {"active_port": 0}, True),
    (RACK_A, "streamer", {"active_port": 1}, True),
    (RACK_B, "streamer", {"active_port": 0}, True),
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
    ("wbob", "streamer", {"active_port": 0}, True),
    ("wbob", "switch.port.navigate", {"active_port": 0}, True),
    ("wbob", "switch.port.activate", {"port": 2}, False),
    ("wbob", "switch.port.activate", {"port": 3}, False),
    ("wbob", "hid.write", {"active_port": 2}, False),
    ("wbob", "hid.write", {"active_port": 3}, False),

    ("lcarol", "switch.port.activate", {"port": 2}, True),
    ("lcarol", "switch.port.activate", {"port": 3}, True),
    ("lcarol", "hid.write", {"active_port": 2}, True),
    ("lcarol", "hid.write", {"active_port": 3}, True),
    ("lcarol", "streamer", {"active_port": 2}, True),
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
    ("bob", STANDALONE, "streamer", {"active_port": None}, True),
    ("carol", STANDALONE, "streamer", {"active_port": None}, True),
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
    (RACK_A, "streamer", {"active_port": 0}, False),
    (RACK_A, "hid.write", {"active_port": 0}, False),
    (RACK_A, "switch.atx", {"active_port": 0}, False),
    (RACK_A, "switch.port.activate", {"port": 0}, False),
    (STANDALONE, "hid.write", {"active_port": None}, False),
    (RACK_A, "switch.port.navigate", {"active_port": None}, True),
    (RACK_A, "switch.port.navigate", {"active_port": 0}, False),
])
def test_unknown_user(client: httpx.Client, opa_url: str, device_id: str, action: str, resource: dict, allowed: bool) -> None:
    assert _check(client, opa_url, "unknown", device_id, action, resource) == allowed
