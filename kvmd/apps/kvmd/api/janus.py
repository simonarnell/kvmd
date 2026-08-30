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


import asyncio
import json

import aiohttp

from aiohttp.web import Request
from aiohttp.web import WebSocketResponse
from aiohttp import WSMsgType

from ....logging import get_logger

from ....htserver import UnavailableError
from ....htserver import exposed_http
from ....htserver import get_request_user
from ....htserver import get_request_groups
from ....htserver import get_request_is_usc

from ..authz import AuthzManager
from ..switch import Switch


# =====
# Janus's own WS wire protocol (core Janus Gateway, not PiKVM-specific) wraps
# every plugin message as {"janus": "message", ..., "body": {...}}. The
# ustreamer plugin's body schema (see pikvm/ustreamer:janus/src/plugin.c,
# _plugin_handle_message()) is {"request": "watch", "params": {"audio":
# bool, "mic": bool, "camera": bool, ...}} -- "audio" is view-direction
# (listening to the target's own audio via acap), while "mic"/"camera" are
# inject-direction (the operator's own mic/webcam played into the target as
# a USB gadget device via aplay/vplay). Only those two keys need touching.
_JANUS_SUBPROTOCOL = "janus-protocol"


class JanusApi:
    def __init__(self, authz: AuthzManager, switch: Switch, unix_path: str, timeout: float) -> None:
        self.__authz = authz
        self.__switch = switch
        self.__unix_path = unix_path
        self.__timeout = timeout

    # =====

    @exposed_http("GET", "/janus/ws", permission="streamer.view")
    async def __ws_proxy_handler(self, req: Request) -> WebSocketResponse:
        logger = get_logger(0)
        user = (get_request_user(req) if not get_request_is_usc(req) else "")

        webcam_allowed = True
        if user:
            active_port = self.__switch.get_active_port()  # -1 = no port active
            webcam_allowed = await self.__authz.check(
                user,
                "webcam",
                {"active_port": (active_port if active_port >= 0 else None)},
                groups=get_request_groups(req),
                source_ip=(req.remote or ""),
                user_agent=req.headers.get("User-Agent", ""),
            )
        logger.debug("janus: %s connecting to /janus/ws; webcam_allowed=%r", (user or "<usc>"), webcam_allowed)

        try:
            upstream_session = aiohttp.ClientSession(connector=aiohttp.UnixConnector(path=self.__unix_path))
            upstream_wsr = await upstream_session.ws_connect(
                "http://localhost/",
                protocols=(_JANUS_SUBPROTOCOL,),
                timeout=aiohttp.ClientWSTimeout(ws_close=self.__timeout),
            )
        except Exception as ex:
            logger.error("janus: can't connect to Janus WS backend at %r: %s", self.__unix_path, ex)
            raise UnavailableError()
        logger.debug("janus: connected to upstream WS backend at %r", self.__unix_path)

        client_wsr = WebSocketResponse(protocols=(_JANUS_SUBPROTOCOL,))
        await client_wsr.prepare(req)

        try:
            await asyncio.gather(
                self.__relay_client_to_upstream(client_wsr, upstream_wsr, webcam_allowed),
                self.__relay_upstream_to_client(upstream_wsr, client_wsr),
                return_exceptions=True,
            )
        finally:
            await upstream_wsr.close()
            await upstream_session.close()
            if not client_wsr.closed:
                await client_wsr.close()
            logger.debug("janus: connection for %s closed", (user or "<usc>"))

        return client_wsr

    async def __relay_client_to_upstream(
        self,
        client_wsr: WebSocketResponse,
        upstream_wsr: aiohttp.ClientWebSocketResponse,
        webcam_allowed: bool,
    ) -> None:

        async for msg in client_wsr:
            if msg.type == WSMsgType.TEXT:
                await upstream_wsr.send_str(self.__maybe_strip_webcam(msg.data, webcam_allowed))
            elif msg.type == WSMsgType.BINARY:
                await upstream_wsr.send_bytes(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                break

    async def __relay_upstream_to_client(
        self,
        upstream_wsr: aiohttp.ClientWebSocketResponse,
        client_wsr: WebSocketResponse,
    ) -> None:

        async for msg in upstream_wsr:
            if msg.type == WSMsgType.TEXT:
                await client_wsr.send_str(msg.data)
            elif msg.type == WSMsgType.BINARY:
                await client_wsr.send_bytes(msg.data)
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                break

    def __maybe_strip_webcam(self, data: str, webcam_allowed: bool) -> str:
        try:
            envelope = json.loads(data)
        except Exception:
            return data  # Not JSON at all -- pass through untouched, nothing for us to mutate
        if not isinstance(envelope, dict) or envelope.get("janus") != "message":
            return data
        body = envelope.get("body")
        if not isinstance(body, dict) or body.get("request") != "watch":
            return data
        params = body.get("params")
        if not isinstance(params, dict):
            return data

        requested = {key: bool(params.get(key)) for key in ("mic", "camera")}
        get_logger(0).debug("janus: saw a \"watch\" request; requested=%r webcam_allowed=%r", requested, webcam_allowed)

        if webcam_allowed or not any(requested.values()):
            return data

        for key in ("mic", "camera"):
            params[key] = False
        get_logger(0).info("janus: stripped webcam/mic negotiation from an unauthorized \"watch\" request")
        return json.dumps(envelope)
