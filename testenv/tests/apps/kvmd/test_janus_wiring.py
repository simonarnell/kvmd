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

# Real end-to-end WS integration test for JanusApi's proxy relay.
#
# testenv/tests/apps/kvmd/test_authz_wiring.py tests __maybe_strip_webcam()
# as a pure function, and the connect-time authz check in isolation -- it
# never actually opens a WebSocket through the handler, so it can't catch
# bugs in the relay loops themselves (asyncio.gather wiring, aiohttp API
# usage, subprotocol negotiation, connection cleanup). This file drives a
# real WebSocket client through the real, unmodified __ws_proxy_handler,
# against a real (if minimal) fake Janus backend listening on a real unix
# socket -- proving the whole relay actually moves bytes, not just that the
# string-mutation logic is correct in isolation.

import asyncio
import json
import os
import tempfile

from typing import Any
from typing import AsyncGenerator

import aiohttp
import pytest
import pytest_asyncio

from aiohttp import web

import kvmd.htserver as htserver

from kvmd.apps.kvmd.api.janus import JanusApi


class _FakeAuthz:
    def __init__(self, allow: bool) -> None:
        self.allow = allow
        self.calls: list[tuple] = []

    async def check(self, user: str, action: str, resource: dict, *, groups: tuple = (), **_: Any) -> bool:
        self.calls.append((user, action, resource, groups))
        return self.allow


class _FakeSwitch:
    def get_active_port(self) -> int:
        return -1


class _FakeJanusBackend:
    """A minimal real WS server standing in for the real Janus gateway, on a real unix socket."""

    def __init__(self) -> None:
        self.received: list[dict] = []
        self.socket_path = tempfile.mktemp(suffix=".sock")
        self.__runner: (web.AppRunner | None) = None

    async def start(self) -> None:
        app = web.Application()
        app.router.add_get("/", self.__handler)
        self.__runner = web.AppRunner(app)
        await self.__runner.setup()
        site = web.UnixSite(self.__runner, self.socket_path)
        await site.start()

    async def stop(self) -> None:
        assert self.__runner is not None
        await self.__runner.cleanup()
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

    async def __handler(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(protocols=("janus-protocol",))
        await ws.prepare(request)
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                self.received.append(json.loads(msg.data))
                await ws.send_str(json.dumps({"janus": "ack", "echo": True}))
            elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR):
                break
        return ws


def _auth_middleware(user: str, groups: tuple[str, ...]) -> Any:
    @web.middleware
    async def middleware(request: web.Request, handler: Any) -> web.StreamResponse:
        htserver.set_request_auth_info(request, "test", user=user, groups=groups)
        return await handler(request)
    return middleware


@pytest_asyncio.fixture(name="backend")
async def _backend_fixture() -> AsyncGenerator[_FakeJanusBackend]:
    backend = _FakeJanusBackend()
    await backend.start()
    try:
        yield backend
    finally:
        await backend.stop()


async def _drive_watch_request(
    aiohttp_client: Any,
    backend: _FakeJanusBackend,
    *,
    webcam_allowed: bool,
    user: str = "carol",
    groups: tuple[str, ...] = ("viewers",),
) -> dict:
    authz = _FakeAuthz(allow=webcam_allowed)
    janus_api = JanusApi(authz=authz, switch=_FakeSwitch(), unix_path=backend.socket_path, timeout=5.0)  # type: ignore[arg-type]

    handler = janus_api._JanusApi__ws_proxy_handler  # type: ignore[attr-defined]  # pylint: disable=protected-access
    app = web.Application(middlewares=[_auth_middleware(user, groups)])
    app.router.add_get("/janus/ws", handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect("/janus/ws", protocols=("janus-protocol",))
    try:
        await ws.send_str(json.dumps({
            "janus": "message", "session_id": 1, "handle_id": 2, "transaction": "t",
            "body": {"request": "watch", "params": {"audio": True, "mic": True, "camera": True}},
        }))
        reply = await asyncio.wait_for(ws.receive(), timeout=5)
        assert reply.type == aiohttp.WSMsgType.TEXT
        assert json.loads(reply.data) == {"janus": "ack", "echo": True}
    finally:
        await ws.close()

    # Give the relay's client->upstream task a moment to land before asserting
    # on what the fake backend actually received.
    for _ in range(50):
        if backend.received:
            break
        await asyncio.sleep(0.02)

    assert len(backend.received) == 1
    return backend.received[0]


# =====
@pytest.mark.asyncio
async def test_ok__janus_relay_strips_webcam_over_the_wire(aiohttp_client: Any, backend: _FakeJanusBackend) -> None:
    received = await _drive_watch_request(aiohttp_client, backend, webcam_allowed=False)
    params = received["body"]["params"]
    assert params["mic"] is False
    assert params["camera"] is False
    assert params["audio"] is True  # view-direction untouched


@pytest.mark.asyncio
async def test_ok__janus_relay_passes_webcam_through_when_allowed(aiohttp_client: Any, backend: _FakeJanusBackend) -> None:
    received = await _drive_watch_request(aiohttp_client, backend, webcam_allowed=True)
    params = received["body"]["params"]
    assert params["mic"] is True
    assert params["camera"] is True
    assert params["audio"] is True


@pytest.mark.asyncio
async def test_ok__janus_relay_passes_non_watch_messages_through_unchanged(aiohttp_client: Any, backend: _FakeJanusBackend) -> None:
    authz = _FakeAuthz(allow=False)
    janus_api = JanusApi(authz=authz, switch=_FakeSwitch(), unix_path=backend.socket_path, timeout=5.0)  # type: ignore[arg-type]

    handler = janus_api._JanusApi__ws_proxy_handler  # type: ignore[attr-defined]  # pylint: disable=protected-access
    app = web.Application(middlewares=[_auth_middleware("carol", ("viewers",))])
    app.router.add_get("/janus/ws", handler)

    client = await aiohttp_client(app)
    ws = await client.ws_connect("/janus/ws", protocols=("janus-protocol",))
    try:
        await ws.send_str(json.dumps({"janus": "keepalive", "session_id": 1}))
        await asyncio.wait_for(ws.receive(), timeout=5)
    finally:
        await ws.close()

    for _ in range(50):
        if backend.received:
            break
        await asyncio.sleep(0.02)

    assert backend.received == [{"janus": "keepalive", "session_id": 1}]
