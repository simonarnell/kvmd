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


import os
import asyncio
import base64
import contextlib

from typing import AsyncGenerator

from aiohttp.test_utils import make_mocked_request

import pytest

from kvmd.validators import ValidatorError

from kvmd.yamlconf import Section
from kvmd.yamlconf import Option
from kvmd.yamlconf import make_config

from kvmd.apps.kvmd.auth import AuthManager
from kvmd.apps.kvmd.api.auth import check_request_auth

from kvmd.plugins.auth import AuthIdentity

from kvmd.htserver import UnauthorizedError
from kvmd.htserver import ForbiddenError
from kvmd.htserver import get_request_groups

from kvmd.plugins.auth import get_auth_service_class

from kvmd.htserver import HttpExposed

from kvmd.crypto import KvmdHtpasswdFile


# =====
_E_AUTH = HttpExposed("GET", "/foo_auth", auth_required=True, allow_usc=True, handler=(lambda: None))
_E_UNAUTH = HttpExposed("GET", "/bar_unauth", auth_required=True, allow_usc=True, handler=(lambda: None))
_E_FREE = HttpExposed("GET", "/baz_free", auth_required=False, allow_usc=True, handler=(lambda: None))


def _make_service_config(path: str) -> Section:
    cls = get_auth_service_class("htpasswd")
    scheme = cls.get_plugin_options()
    scheme["type"] = Option("htpasswd")
    return make_config({}, {"file": path}, scheme)


def _make_stub_config(name: str) -> Section:
    config = Section()
    config["type"] = name
    return config


@contextlib.asynccontextmanager
async def _get_configured_manager(
    unauth_paths: list[str],
    int_path: str,
    ext_path: str="",
    force_int_users: (list[str] | None)=None,
    extend: bool=False,
) -> AsyncGenerator[AuthManager]:

    manager = AuthManager(
        enabled=True,
        expire=0,
        extend=extend,
        usc_users=[],
        usc_groups=[],
        unauth_paths=unauth_paths,

        int_c=_make_service_config(int_path),
        ext_c=(_make_service_config(ext_path) if ext_path else _make_stub_config("")),

        force_int_users=(force_int_users or []),

        totp_secret_path="",
    )

    await manager.sysprep()
    try:
        yield manager
    finally:
        await manager.cleanup()


# =====
@pytest.mark.asyncio
async def test_ok__request(tmpdir) -> None:  # type: ignore
    path = os.path.abspath(str(tmpdir.join("htpasswd")))

    htpasswd = KvmdHtpasswdFile(path, new=True)
    htpasswd.set_password("admin", "pass")
    htpasswd.save()

    async with _get_configured_manager([], path) as manager:
        async def check(exposed: HttpExposed, **kwargs) -> None:  # type: ignore
            await check_request_auth(manager, exposed, make_mocked_request(exposed.method, exposed.path, **kwargs))

        await check(_E_FREE)
        with pytest.raises(UnauthorizedError):
            await check(_E_AUTH)

        # ===

        with pytest.raises(ForbiddenError):
            await check(_E_AUTH, headers={"X-KVMD-User": "admin", "X-KVMD-Passwd": "foo"})
        with pytest.raises(ForbiddenError):
            await check(_E_AUTH, headers={"X-KVMD-User": "adminx", "X-KVMD-Passwd": "pass"})

        await check(_E_AUTH, headers={"X-KVMD-User": "admin", "X-KVMD-Passwd": "pass"})

        # ===

        with pytest.raises(UnauthorizedError):
            await check(_E_AUTH, headers={"Cookie": "auth_token="})
        with pytest.raises(ValidatorError):
            await check(_E_AUTH, headers={"Cookie": "auth_token=0"})
        with pytest.raises(ForbiddenError):
            await check(_E_AUTH, headers={"Cookie": f"auth_token={'0' * 64}"})

        token = await manager.login("admin", "pass", 0)
        assert token
        await check(_E_AUTH, headers={"Cookie": f"auth_token={token}"})
        manager.logout(token)
        with pytest.raises(ForbiddenError):
            await check(_E_AUTH, headers={"Cookie": f"auth_token={token}"})

        # ===

        with pytest.raises(ForbiddenError):
            await check(_E_AUTH, headers={"Authorization": "basic " + base64.b64encode(b"admin:foo").decode()})
        with pytest.raises(ForbiddenError):
            await check(_E_AUTH, headers={"Authorization": "basic " + base64.b64encode(b"adminx:pass").decode()})

        await check(_E_AUTH, headers={"Authorization": "basic " + base64.b64encode(b"admin:pass").decode()})


@pytest.mark.asyncio
async def test_ok__expire(tmpdir) -> None:  # type: ignore
    path = os.path.abspath(str(tmpdir.join("htpasswd")))

    htpasswd = KvmdHtpasswdFile(path, new=True)
    htpasswd.set_password("admin", "pass")
    htpasswd.save()

    async with _get_configured_manager([], path) as manager:
        assert manager.is_auth_enabled()
        assert manager.is_auth_required(_E_AUTH)
        assert manager.is_auth_required(_E_UNAUTH)
        assert not manager.is_auth_required(_E_FREE)

        assert manager.check("xxx") is None
        manager.logout("xxx")

        assert (await manager.login("user", "foo", 3)) is None
        assert (await manager.login("admin", "foo", 3)) is None
        assert (await manager.login("user", "pass", 3)) is None

        token1 = await manager.login("admin", "pass", 3)
        assert isinstance(token1, str)
        assert len(token1) == 64

        token2 = await manager.login("admin", "pass", 3)
        assert isinstance(token2, str)
        assert len(token2) == 64
        assert token1 != token2

        assert manager.check(token1) == "admin"
        assert manager.check(token2) == "admin"
        assert manager.check("foobar") is None

        manager.logout(token1)

        assert manager.check(token1) is None
        assert manager.check(token2) is None
        assert manager.check("foobar") is None

        token3 = await manager.login("admin", "pass", 3)
        assert isinstance(token3, str)
        assert len(token3) == 64
        assert token1 != token3
        assert token2 != token3

        token4 = await manager.login("admin", "pass", 6)
        assert isinstance(token4, str)
        assert len(token4) == 64
        assert token1 != token4
        assert token2 != token4
        assert token3 != token4

        await asyncio.sleep(4)

        assert manager.check(token1) is None
        assert manager.check(token2) is None
        assert manager.check(token3) is None
        assert manager.check(token4) == "admin"

        await asyncio.sleep(3)

        assert manager.check(token1) is None
        assert manager.check(token2) is None
        assert manager.check(token3) is None
        assert manager.check(token4) is None


@pytest.mark.asyncio
async def test_ok__internal(tmpdir) -> None:  # type: ignore
    path = os.path.abspath(str(tmpdir.join("htpasswd")))

    htpasswd = KvmdHtpasswdFile(path, new=True)
    htpasswd.set_password("admin", "pass")
    htpasswd.save()

    async with _get_configured_manager([], path) as manager:
        assert manager.is_auth_enabled()
        assert manager.is_auth_required(_E_AUTH)
        assert manager.is_auth_required(_E_UNAUTH)
        assert not manager.is_auth_required(_E_FREE)

        assert manager.check("xxx") is None
        manager.logout("xxx")

        assert (await manager.login("user", "foo", 0)) is None
        assert (await manager.login("admin", "foo", 0)) is None
        assert (await manager.login("user", "pass", 0)) is None

        token1 = await manager.login("admin", "pass", 0)
        assert isinstance(token1, str)
        assert len(token1) == 64

        token2 = await manager.login("admin", "pass", 0)
        assert isinstance(token2, str)
        assert len(token2) == 64
        assert token1 != token2

        assert manager.check(token1) == "admin"
        assert manager.check(token2) == "admin"
        assert manager.check("foobar") is None

        manager.logout(token1)

        assert manager.check(token1) is None
        assert manager.check(token2) is None
        assert manager.check("foobar") is None

        token3 = await manager.login("admin", "pass", 0)
        assert isinstance(token3, str)
        assert len(token3) == 64
        assert token1 != token3
        assert token2 != token3


@pytest.mark.asyncio
async def test_ok__external(tmpdir) -> None:  # type: ignore
    path1 = os.path.abspath(str(tmpdir.join("htpasswd1")))
    path2 = os.path.abspath(str(tmpdir.join("htpasswd2")))

    htpasswd1 = KvmdHtpasswdFile(path1, new=True)
    htpasswd1.set_password("admin", "pass1")
    htpasswd1.set_password("local", "foobar")
    htpasswd1.save()

    htpasswd2 = KvmdHtpasswdFile(path2, new=True)
    htpasswd2.set_password("admin", "pass2")
    htpasswd2.set_password("user", "foobar")
    htpasswd2.save()

    async with _get_configured_manager([], path1, path2, ["admin"]) as manager:
        assert manager.is_auth_enabled()
        assert manager.is_auth_required(_E_AUTH)
        assert manager.is_auth_required(_E_UNAUTH)
        assert not manager.is_auth_required(_E_FREE)

        assert (await manager.login("local", "foobar", 0)) is None
        assert (await manager.login("admin", "pass2", 0)) is None

        token = await manager.login("admin", "pass1", 0)
        assert token is not None

        assert manager.check(token) == "admin"
        manager.logout(token)
        assert manager.check(token) is None

        token = await manager.login("user", "foobar", 0)
        assert token is not None

        assert manager.check(token) == "user"
        manager.logout(token)
        assert manager.check(token) is None


@pytest.mark.asyncio
async def test_ok__unauth(tmpdir) -> None:  # type: ignore
    path = os.path.abspath(str(tmpdir.join("htpasswd")))

    htpasswd = KvmdHtpasswdFile(path, new=True)
    htpasswd.set_password("admin", "pass")
    htpasswd.save()

    async with _get_configured_manager([
        "", " ",
        "foo_auth", "/foo_auth ", " /foo_auth",
        "/foo_authx", "/foo_auth/", "/foo_auth/x",
        "/bar_unauth",  # Only this one is matching
    ], path) as manager:

        assert manager.is_auth_enabled()
        assert manager.is_auth_required(_E_AUTH)
        assert not manager.is_auth_required(_E_UNAUTH)
        assert not manager.is_auth_required(_E_FREE)


@pytest.mark.asyncio
async def test_ok__login_external_groups(tmpdir) -> None:  # type: ignore
    path = os.path.abspath(str(tmpdir.join("htpasswd")))

    htpasswd = KvmdHtpasswdFile(path, new=True)
    htpasswd.set_password("admin", "pass")
    htpasswd.save()

    async with _get_configured_manager([], path, extend=True) as manager:
        # Password-based login still works and carries no groups by default.
        token1 = await manager.login("admin", "pass", 0)
        assert token1 is not None
        assert manager.check(token1) == "admin"
        assert manager.get_session_groups(token1) == ()

        # login_external() mints a session without a password, carrying
        # whatever groups the identity provider (OIDC, or an LDAP-style
        # plugin) attached to the identity.
        identity = AuthIdentity(user="bob", groups=("admins", "ops"))
        token2 = await manager.login_external(identity, 0)
        assert manager.check(token2) == "bob"
        assert set(manager.get_session_groups(token2)) == {"admins", "ops"}

        # Groups must survive a WS-session renewal cycle (start/stop), since
        # __renew_ws_session() rebuilds the frozen _Session on every connect
        # and disconnect.
        manager.start_ws_session(token2)
        assert set(manager.get_session_groups(token2)) == {"admins", "ops"}
        manager.stop_ws_session(token2)
        assert set(manager.get_session_groups(token2)) == {"admins", "ops"}

        # Unknown token has no groups.
        assert manager.get_session_groups("nope") == ()


class _GroupsAuthManager(AuthManager):
    """
    Stands in for any auth backend that surfaces group membership (LDAP's
    memberOf being the real-world case). Overriding authorize_identity()
    covers login() and the xhdr/basic checkers alike, since they all funnel
    through it — proving group-carrying is a property of AuthManager's
    contract, not something each plugin has to get right independently.
    """

    async def authorize_identity(self, user: str, passwd: str) -> (AuthIdentity | None):
        if user == "admin" and passwd == "pass":
            return AuthIdentity(user="admin", groups=("admins", "ops"))
        return None


@pytest.mark.asyncio
async def test_ok__groups_reach_request_every_auth_channel() -> None:
    # Regression test: xhdr and basic auth used to call AuthManager.authorize(),
    # which discards the AuthIdentity down to a bool and never touched groups.
    # Any backend that carries real group data (LDAP's memberOf, in practice)
    # had that data silently dropped for those two channels, even though
    # AuthzManager.check() gates access on exactly this. All three channels
    # below must agree.
    manager = _GroupsAuthManager(
        enabled=True, expire=0, extend=False,
        usc_users=[], usc_groups=[], unauth_paths=[],
        int_c=_make_service_config("/nonexistent"), force_int_users=[],
        ext_c=_make_stub_config(""),
        totp_secret_path="",
    )
    try:
        async def check_groups(**kwargs) -> tuple[str, ...]:  # type: ignore
            req = make_mocked_request(_E_AUTH.method, _E_AUTH.path, **kwargs)
            await check_request_auth(manager, _E_AUTH, req)
            return get_request_groups(req)

        # xhdr
        assert set(await check_groups(headers={"X-KVMD-User": "admin", "X-KVMD-Passwd": "pass"})) == {"admins", "ops"}

        # basic
        assert set(await check_groups(
            headers={"Authorization": "basic " + base64.b64encode(b"admin:pass").decode()},
        )) == {"admins", "ops"}

        # cookie/token, via login()
        token = await manager.login("admin", "pass", 0)
        assert token is not None
        assert set(await check_groups(headers={"Cookie": f"auth_token={token}"})) == {"admins", "ops"}

        # A backend with no groups (the htpasswd/PAM/RADIUS/HTTP-plugin case)
        # must still authenticate fine and simply carry no groups — static
        # data.users-based authz is unaffected either way.
        with pytest.raises(ForbiddenError):
            await check_groups(headers={"X-KVMD-User": "nobody", "X-KVMD-Passwd": "x"})
    finally:
        await manager.cleanup()


@pytest.mark.asyncio
async def test_ok__disabled() -> None:
    try:
        manager = AuthManager(
            enabled=False,
            expire=0,
            extend=False,
            usc_users=[],
            usc_groups=[],
            unauth_paths=[],

            int_c=_make_stub_config("foobar"),
            ext_c=_make_stub_config(""),

            force_int_users=[],

            totp_secret_path="",
        )
        await manager.sysprep()

        assert not manager.is_auth_enabled()
        assert not manager.is_auth_required(_E_AUTH)
        assert not manager.is_auth_required(_E_UNAUTH)
        assert not manager.is_auth_required(_E_FREE)

        with pytest.raises(AssertionError):
            await manager.authorize("admin", "admin")

        with pytest.raises(AssertionError):
            await manager.login("admin", "admin", 0)

        with pytest.raises(AssertionError):
            manager.logout("xxx")

        with pytest.raises(AssertionError):
            manager.check("xxx")
    finally:
        await manager.cleanup()
