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
# ========================================================================== #

# Integration test for kvmd's LDAP auth plugin against a REAL Active
# Directory-compatible server (Samba AD DC), started via testcontainers.
#
# Why AD and not plain OpenLDAP: kvmd/plugins/auth/ldap.py binds using
# "user@domain" as the identity and filters on userPrincipalName -- that's
# AD-specific UPN syntax. Plain OpenLDAP treats "user@domain" as an invalid
# DN and rejects the bind before ever checking credentials, so it wouldn't
# exercise the real code path at all. Samba AD DC actually speaks UPN bind,
# so this is the one test in this repo that runs kvmd's unmodified LDAP
# plugin against a server it could really be pointed at.
#
# Also requires simple bind over TLS (ldaps://) -- Samba AD DC's default
# "ldap server require strong auth" setting rejects plaintext simple bind
# with STRONG_AUTH_REQUIRED, matching what a real deployment would need too.
#
# Run with: pytest testenv/ldap-tests/test_ldap_client.py
# Requires a working Docker daemon. Samba provisioning + startup commonly
# takes 30-60s (longer under x86-on-arm64 emulation), so this is slower
# than the other testcontainers suites in this repo.

import socket
import ssl
import time

from typing import Any
from typing import AsyncGenerator

import pytest

from testcontainers.core.container import DockerContainer
from testcontainers.core.waiting_utils import wait_container_is_ready

from kvmd.plugins.auth.ldap import Plugin as LdapPlugin
from kvmd.plugins.auth import AuthIdentity


DOMAIN = "KVMDTEST.LOCAL"
DOMAIN_LOWER = "kvmdtest.local"
BASE_DN = "DC=kvmdtest,DC=local"
DOMAIN_PASS = "Passw0rd123!"

ADMINS_GROUP_DN = f"CN=kvmd-admins,CN=Users,{BASE_DN}"
VIEWERS_GROUP_DN = f"CN=kvmd-viewers,CN=Users,{BASE_DN}"

ALICE_PASS = "Alice-Pass123!"
BOB_PASS = "Bob-Pass123!"


@wait_container_is_ready(Exception)
def _wait_for_samba(container: DockerContainer) -> None:
    (exit_code, _) = container.exec(["samba-tool", "user", "list"])
    if exit_code != 0:
        raise RuntimeError("samba not ready yet")


def _wait_for_ldaps_port(port: int, timeout: float = 60.0) -> None:
    # samba-tool succeeding only proves the Samba process is up, not that
    # the LDAPS TLS listener has finished initializing -- do a real TLS
    # handshake (ignoring the self-signed cert) before trusting the port.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    deadline = time.monotonic() + timeout
    last_ex: Exception = RuntimeError("unreachable")
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname="127.0.0.1"):
                    return
        except Exception as ex:  # noqa: BLE001
            last_ex = ex
            time.sleep(1)
    raise RuntimeError(f"LDAPS port {port} never became ready") from last_ex


@pytest.fixture(scope="module")
def ldaps_port() -> Any:
    container = (
        DockerContainer("nowsci/samba-domain")
        .with_kwargs(privileged=True)
        .with_env("DOMAIN", DOMAIN)
        .with_env("DOMAINPASS", DOMAIN_PASS)
        .with_env("DNSFORWARDER", "8.8.8.8")
        .with_env("NOCOMPLEX", "true")
        .with_exposed_ports(636)
    )
    with container:
        _wait_for_samba(container)

        # Fixture: alice is in both groups, bob is in kvmd-viewers only.
        for cmd in [
            ["samba-tool", "user", "create", "alice", ALICE_PASS, "--given-name=Alice", "--surname=Test"],
            ["samba-tool", "user", "create", "bob", BOB_PASS, "--given-name=Bob", "--surname=Test"],
            ["samba-tool", "group", "add", "kvmd-admins"],
            ["samba-tool", "group", "add", "kvmd-viewers"],
            ["samba-tool", "group", "addmembers", "kvmd-admins", "alice"],
            ["samba-tool", "group", "addmembers", "kvmd-viewers", "alice"],
            ["samba-tool", "group", "addmembers", "kvmd-viewers", "bob"],
        ]:
            (exit_code, output) = container.exec(cmd)
            assert exit_code == 0, (cmd, output)

        port = int(container.get_exposed_port(636))
        _wait_for_ldaps_port(port)
        yield port


def _make_plugin(ldaps_port: int, *, group: str = ADMINS_GROUP_DN) -> LdapPlugin:
    return LdapPlugin(
        url=f"ldaps://127.0.0.1:{ldaps_port}",
        verify=False,  # Samba AD DC's default cert is self-signed
        base=BASE_DN,
        group=group,
        user_domain=DOMAIN_LOWER,
        timeout=10,
    )


# =====
@pytest.mark.asyncio
async def test_ok__correct_password_returns_identity_with_groups(ldaps_port: int) -> None:
    plugin = _make_plugin(ldaps_port, group=ADMINS_GROUP_DN)
    identity = await plugin.authorize("alice", ALICE_PASS)
    assert isinstance(identity, AuthIdentity)
    assert identity.user == "alice"
    # alice is in both groups -- both must be surfaced, not just the gate group.
    assert set(identity.groups) == {ADMINS_GROUP_DN, VIEWERS_GROUP_DN}


@pytest.mark.asyncio
async def test_fail__wrong_password(ldaps_port: int) -> None:
    plugin = _make_plugin(ldaps_port, group=ADMINS_GROUP_DN)
    assert (await plugin.authorize("alice", "wrong-password")) is None


@pytest.mark.asyncio
async def test_fail__unknown_user(ldaps_port: int) -> None:
    plugin = _make_plugin(ldaps_port, group=ADMINS_GROUP_DN)
    assert (await plugin.authorize("nobody", "whatever")) is None


@pytest.mark.asyncio
async def test_fail__correct_password_but_not_in_gate_group(ldaps_port: int) -> None:
    # bob's password is correct, but the plugin's configured "group" acts as
    # a hard gate: membership in it is required to authorize at all,
    # regardless of correct credentials.
    plugin = _make_plugin(ldaps_port, group=ADMINS_GROUP_DN)
    assert (await plugin.authorize("bob", BOB_PASS)) is None


@pytest.mark.asyncio
async def test_ok__bob_authorized_against_his_own_group(ldaps_port: int) -> None:
    plugin = _make_plugin(ldaps_port, group=VIEWERS_GROUP_DN)
    identity = await plugin.authorize("bob", BOB_PASS)
    assert isinstance(identity, AuthIdentity)
    assert identity.user == "bob"
    assert set(identity.groups) == {VIEWERS_GROUP_DN}
