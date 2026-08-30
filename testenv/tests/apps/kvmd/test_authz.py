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


import contextlib
import logging

from typing import Any
from typing import AsyncGenerator

from aiohttp import web

import pytest

from kvmd.apps.kvmd.authz import AuthzManager
from kvmd.htserver import ForbiddenError


# =====
# Minimal fake OPA server: returns {"result": <allow>} unconditionally.

def _make_opa_app(allow: bool) -> web.Application:
    app = web.Application()

    async def handler(_: web.Request) -> web.Response:
        return web.json_response({"result": allow})

    app.router.add_post("/v1/data/kvmd/authz/allow", handler)
    return app


@contextlib.asynccontextmanager
async def _opa_server(aiohttp_server: Any, allow: bool) -> AsyncGenerator[str, None]:
    server = await aiohttp_server(_make_opa_app(allow))
    yield f"http://localhost:{server.port}/v1/data/kvmd/authz/allow"


@contextlib.asynccontextmanager
async def _manager(opa_url: str, *, fail_open: bool = True) -> AsyncGenerator[AuthzManager, None]:
    mgr = AuthzManager(
        enabled=True,
        opa_url=opa_url,
        opa_timeout=2.0,
        device_id="test-device",
        fail_open=fail_open,
    )
    await mgr.sysprep()
    try:
        yield mgr
    finally:
        await mgr.cleanup()


# =====

@pytest.mark.asyncio
async def test_disabled() -> None:
    mgr = AuthzManager(
        enabled=False,
        opa_url="http://localhost:0/unreachable",
        opa_timeout=0.1,
        device_id="test-device",
        fail_open=False,
    )
    assert not mgr.is_authz_enabled()
    assert await mgr.check("alice", "hid.write", {})
    assert await mgr.check("bob", "switch.port.activate", {"port": 3})
    await mgr.cleanup()


@pytest.mark.asyncio
async def test_allow(aiohttp_server) -> None:  # type: ignore
    async with _opa_server(aiohttp_server, allow=True) as url:
        async with _manager(url) as mgr:
            assert await mgr.check("alice", "hid.write", {"active_port": 1})


@pytest.mark.asyncio
async def test_deny(aiohttp_server) -> None:  # type: ignore
    async with _opa_server(aiohttp_server, allow=False) as url:
        async with _manager(url) as mgr:
            assert not await mgr.check("bob", "hid.write", {"active_port": 0})


@pytest.mark.asyncio
async def test_check_or_raise_allow(aiohttp_server) -> None:  # type: ignore
    async with _opa_server(aiohttp_server, allow=True) as url:
        async with _manager(url) as mgr:
            await mgr.check_or_raise("alice", "streamer", {})


@pytest.mark.asyncio
async def test_check_or_raise_deny(aiohttp_server) -> None:  # type: ignore
    async with _opa_server(aiohttp_server, allow=False) as url:
        async with _manager(url) as mgr:
            with pytest.raises(ForbiddenError):
                await mgr.check_or_raise("bob", "hid.write", {"active_port": 0})


@pytest.mark.asyncio
async def test_fail_open_on_opa_unreachable() -> None:
    mgr = AuthzManager(
        enabled=True,
        opa_url="http://localhost:1/no-such-server",
        opa_timeout=0.1,
        device_id="test-device",
        fail_open=True,
    )
    await mgr.sysprep()
    try:
        assert await mgr.check("alice", "hid.write", {})
    finally:
        await mgr.cleanup()


@pytest.mark.asyncio
async def test_fail_closed_on_opa_unreachable() -> None:
    mgr = AuthzManager(
        enabled=True,
        opa_url="http://localhost:1/no-such-server",
        opa_timeout=0.1,
        device_id="test-device",
        fail_open=False,
    )
    await mgr.sysprep()
    try:
        assert not await mgr.check("alice", "hid.write", {})
    finally:
        await mgr.cleanup()


@pytest.mark.asyncio
async def test_audit_log_emitted(aiohttp_server, caplog) -> None:  # type: ignore
    async with _opa_server(aiohttp_server, allow=False) as url:
        async with _manager(url) as mgr:
            with caplog.at_level(logging.INFO, logger="kvmd.audit"):
                await mgr.check("carol", "switch.port.activate", {"port": 2},
                                source_ip="10.0.0.1", user_agent="test-agent")

    records = [r for r in caplog.records if r.name == "kvmd.audit"]
    assert len(records) == 1
    msg = records[0].getMessage()
    assert "carol" in msg
    assert "switch.port.activate" in msg
    assert "test-device" in msg
    assert "allowed=False" in msg
    assert "10.0.0.1" in msg


@pytest.mark.asyncio
async def test_debug_trace_shows_raw_opa_request_and_response(aiohttp_server, caplog) -> None:  # type: ignore
    # The audit log only ever records the final decision; debugging a
    # policy issue needs the raw input OPA was actually asked with and the
    # raw response it gave back, at debug level.
    async with _opa_server(aiohttp_server, allow=True) as url:
        async with _manager(url) as mgr:
            with caplog.at_level(logging.DEBUG, logger="kvmd.apps.kvmd.authz"):
                await mgr.check("dave", "hid.write", {"active_port": 2}, groups=("kvmd-operators",))

    messages = [r.getMessage() for r in caplog.records if r.name == "kvmd.apps.kvmd.authz"]
    assert any("request to" in m and "'user': 'dave'" in m and "'user_groups': ['kvmd-operators']" in m for m in messages)
    assert any("OPA responded" in m and "'result': True" in m for m in messages)


@pytest.mark.asyncio
async def test_audit_log_on_opa_error(caplog) -> None:  # type: ignore
    mgr = AuthzManager(
        enabled=True,
        opa_url="http://localhost:1/no-such-server",
        opa_timeout=0.1,
        device_id="test-device",
        fail_open=True,
    )
    await mgr.sysprep()
    try:
        with caplog.at_level(logging.INFO, logger="kvmd.audit"):
            await mgr.check("alice", "hid.write", {})
        records = [r for r in caplog.records if r.name == "kvmd.audit"]
        assert len(records) == 1
        assert "opa_error=True" in records[0].getMessage()
    finally:
        await mgr.cleanup()
