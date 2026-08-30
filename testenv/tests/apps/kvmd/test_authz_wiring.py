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

# Regression tests for the specific gap this file exists to prevent
# recurring: testenv/authz-tests/test_policy.py and authz_test.rego only
# ever exercise the OPA *policy* by POSTing synthetic input at it -- they
# prove "if kvmd asks OPA about action X, the decision is correct", not
# "kvmd actually asks OPA before performing action X". hid.py and
# streamer.py shipped for a long time with the entire policy and test
# suite modeling "hid"/"streamer" role restrictions as if enforced, while
# no code path anywhere ever called AuthzManager.check() for them --
# nothing here would have caught that, because nothing tested the
# enforcement point itself.
#
# These tests call the real, unmodified handler methods (via the
# decorator machinery's own attribute mangling, not by asserting text
# patterns) with a fake AuthzManager/Switch, and prove the handler's
# underlying action either fires or doesn't depending on the (fake)
# authz decision -- i.e. they test that the wiring exists, not that the
# policy is correct (that's the other suite's job).

from typing import Any

import pytest

import kvmd.htserver as htserver

from kvmd.htserver import WsSession
from kvmd.htserver import ForbiddenError
from kvmd.htserver import _get_exposed_http  # pylint: disable=protected-access

from kvmd.apps.kvmd.api.hid import HidApi
from kvmd.apps.kvmd.api.auth import AuthApi


class _FakeAuthz:
    def __init__(self, allow: bool) -> None:
        self.allow = allow
        self.calls: list[tuple] = []

    async def check(self, user: str, action: str, resource: dict, *, groups: tuple = (), **_: Any) -> bool:
        self.calls.append((user, action, resource, groups))
        return self.allow

    async def check_or_raise(self, user: str, action: str, resource: dict, *, groups: tuple = (), **_: Any) -> None:
        if not (await self.check(user, action, resource, groups=groups)):
            raise ForbiddenError()


class _FakeSwitch:
    def __init__(self, active_port: int = 1) -> None:
        self.__active_port = active_port

    def get_active_port(self) -> int:
        return self.__active_port


class _FakeWsr:
    pass


def _make_ws(**kwargs: Any) -> WsSession:
    return WsSession(wsr=_FakeWsr(), token="tok", kwargs=kwargs)  # type: ignore[arg-type]


# =====
@pytest.mark.asyncio
async def test_ok__hid_ws_input_blocked_when_authz_denies() -> None:
    authz = _FakeAuthz(allow=False)
    switch = _FakeSwitch(active_port=1)
    hid_api = HidApi(hid=None, keymap_path="/nonexistent/default", authz=authz, switch=switch)  # type: ignore[arg-type]

    sent = []
    hid_api._HidApi__hid = type("FakeHid", (), {"send_key_event": staticmethod(lambda *a: sent.append(a))})()  # type: ignore

    ws = _make_ws(user="bob", groups=("ops",), is_usc=False)
    handler = hid_api._HidApi__ws_key_handler  # type: ignore[attr-defined]  # pylint: disable=protected-access
    await handler(ws, {"key": "KeyA", "state": True})

    assert sent == []  # blocked: the underlying HID action never fired
    assert authz.calls == [("bob", "hid", {"active_port": 1}, ("ops",))]


@pytest.mark.asyncio
async def test_ok__hid_ws_input_allowed_when_authz_allows() -> None:
    authz = _FakeAuthz(allow=True)
    switch = _FakeSwitch(active_port=1)
    hid_api = HidApi(hid=None, keymap_path="/nonexistent/default", authz=authz, switch=switch)  # type: ignore[arg-type]

    sent = []
    hid_api._HidApi__hid = type("FakeHid", (), {"send_key_event": staticmethod(lambda *a: sent.append(a))})()  # type: ignore

    ws = _make_ws(user="alice", groups=(), is_usc=False)
    handler = hid_api._HidApi__ws_key_handler  # type: ignore[attr-defined]  # pylint: disable=protected-access
    await handler(ws, {"key": "KeyA", "state": True})

    assert len(sent) == 1  # allowed: the underlying HID action fired


@pytest.mark.asyncio
async def test_ok__hid_ws_input_bypasses_authz_for_usc() -> None:
    authz = _FakeAuthz(allow=False)  # would deny if actually consulted
    switch = _FakeSwitch(active_port=1)
    hid_api = HidApi(hid=None, keymap_path="/nonexistent/default", authz=authz, switch=switch)  # type: ignore[arg-type]

    sent = []
    hid_api._HidApi__hid = type("FakeHid", (), {"send_key_event": staticmethod(lambda *a: sent.append(a))})()  # type: ignore

    ws = _make_ws(user="", groups=(), is_usc=True)  # USC connections carry no user, by design
    handler = hid_api._HidApi__ws_key_handler  # type: ignore[attr-defined]  # pylint: disable=protected-access
    await handler(ws, {"key": "KeyA", "state": True})

    assert len(sent) == 1  # USC bypasses authz entirely, same as everywhere else
    assert authz.calls == []  # and OPA is never even consulted


@pytest.mark.asyncio
async def test_ok__hid_ws_authz_decision_cached_per_port() -> None:
    # A mouse-move-frequency message stream must not hit OPA on every
    # message -- only when the active port actually changes.
    authz = _FakeAuthz(allow=True)
    switch = _FakeSwitch(active_port=1)
    hid_api = HidApi(hid=None, keymap_path="/nonexistent/default", authz=authz, switch=switch)  # type: ignore[arg-type]
    hid_api._HidApi__hid = type("FakeHid", (), {"send_mouse_move_event": staticmethod(lambda *a: None)})()  # type: ignore

    ws = _make_ws(user="alice", groups=(), is_usc=False)
    handler = hid_api._HidApi__ws_mouse_move_handler  # type: ignore[attr-defined]  # pylint: disable=protected-access

    for _ in range(5):
        await handler(ws, {"to": {"x": 100, "y": 100}})
    assert len(authz.calls) == 1  # same port every time -- cached after the first check

    switch._FakeSwitch__active_port = 2  # type: ignore[attr-defined]  # pylint: disable=protected-access
    await handler(ws, {"to": {"x": 100, "y": 100}})
    assert len(authz.calls) == 2  # port changed -- cache invalidated, OPA re-consulted


@pytest.mark.asyncio
async def test_ok__streamer_endpoint_calls_authz() -> None:
    authz_deny = _FakeAuthz(allow=False)
    switch = _FakeSwitch(active_port=3)
    auth_api = AuthApi(auth=None, authz=authz_deny, switch=switch, allow_redirects=[])  # type: ignore[arg-type]

    handler = auth_api._AuthApi__check_streamer_handler  # type: ignore[attr-defined]  # pylint: disable=protected-access

    class _FakeReq:
        headers: dict = {}
        remote = "127.0.0.1"

    req = _FakeReq()
    htserver.set_request_auth_info(req, "carol", user="carol", groups=("viewers",))  # type: ignore[arg-type]

    with pytest.raises(ForbiddenError):
        await handler(req)  # type: ignore[arg-type]
    assert authz_deny.calls == [("carol", "streamer.view", {"active_port": 3}, ("viewers",))]


# =====
# Route-inventory regression guard: the specific action strings the policy
# and its test suite model as enforced must actually carry a `permission=`
# annotation somewhere in the HTTP API surface (WS-based HID input is
# covered by the tests above, not by this static check).
# =====

def test_ok__expected_http_actions_are_still_wired() -> None:
    from kvmd.apps.kvmd.api.switch import SwitchApi
    from kvmd.apps.kvmd.api.atx import AtxApi
    from kvmd.apps.kvmd.api.streamer import StreamerApi
    from kvmd.apps.kvmd.api.msd import MsdApi
    from kvmd.apps.kvmd.api.ugpio import UserGpioApi
    from kvmd.apps.kvmd.api.log import LogApi
    from kvmd.apps.kvmd.api.export import ExportApi
    from kvmd.apps.kvmd.api.janus import JanusApi

    fake_authz = _FakeAuthz(allow=True)
    fake_switch = _FakeSwitch()

    apis: list[object] = [
        SwitchApi(switch=fake_switch, authz=fake_authz),  # type: ignore[arg-type]
        HidApi(hid=None, keymap_path="/nonexistent/default", authz=fake_authz, switch=fake_switch),  # type: ignore[arg-type]
        AtxApi(atx=None),  # type: ignore[arg-type]
        StreamerApi(streamer=None, ocr=None),  # type: ignore[arg-type]
        MsdApi(msd=None),  # type: ignore[arg-type]
        UserGpioApi(ugpio=None),  # type: ignore[arg-type]
        LogApi(log_reader=None),
        ExportApi(im=None, atx=None, ugpio=None),  # type: ignore[arg-type]
        JanusApi(authz=fake_authz, switch=fake_switch, unix_path="/nonexistent.sock", timeout=5.0),  # type: ignore[arg-type]
    ]

    permissions: set[str] = set()
    for obj in apis:
        for exposed in _get_exposed_http(obj):
            if exposed.permission:
                permissions.add(exposed.permission)

    expected = (
        "switch.port.navigate", "switch.port.configure", "switch.atx",
        "switch.device.configure", "switch.device.reset",
        "hid", "msd.add", "msd.mount", "msd.delete", "msd.read", "msd.reset",
        "gpio", "log", "export",
        "streamer.view", "snapshot",
        # NOT here: "switch.port.activate" and "webcam" are inline/manual
        # authz.check() calls inside their handlers (like set_active), not
        # permission= decorator annotations -- see the tests below for those.
    )
    for action in expected:
        assert action in permissions, f"{action!r} lost its permission= annotation"


# =====
# Janus WS proxy: kvmd strips mic/camera negotiation from an unauthorized
# user's "watch" request rather than blocking the connection outright, so
# viewing still works and only injection is denied. See kvmd/apps/kvmd/api/janus.py.
# =====

def test_ok__janus_strips_webcam_when_not_allowed() -> None:
    import json
    from kvmd.apps.kvmd.api.janus import JanusApi

    janus_api = JanusApi(authz=_FakeAuthz(allow=True), switch=_FakeSwitch(), unix_path="/nonexistent.sock", timeout=5.0)  # type: ignore[arg-type]
    strip = janus_api._JanusApi__maybe_strip_webcam  # type: ignore[attr-defined]  # pylint: disable=protected-access

    watch_msg = json.dumps({
        "janus": "message", "session_id": 1, "handle_id": 2, "transaction": "t",
        "body": {"request": "watch", "params": {"audio": True, "mic": True, "camera": True}},
    })

    stripped = json.loads(strip(watch_msg, False))
    assert stripped["body"]["params"]["mic"] is False
    assert stripped["body"]["params"]["camera"] is False
    assert stripped["body"]["params"]["audio"] is True  # view-direction untouched


def test_ok__janus_passes_watch_through_unchanged_when_allowed() -> None:
    import json
    from kvmd.apps.kvmd.api.janus import JanusApi

    janus_api = JanusApi(authz=_FakeAuthz(allow=True), switch=_FakeSwitch(), unix_path="/nonexistent.sock", timeout=5.0)  # type: ignore[arg-type]
    strip = janus_api._JanusApi__maybe_strip_webcam  # type: ignore[attr-defined]  # pylint: disable=protected-access

    watch_msg = json.dumps({
        "janus": "message", "session_id": 1, "handle_id": 2, "transaction": "t",
        "body": {"request": "watch", "params": {"mic": True, "camera": True}},
    })
    assert strip(watch_msg, True) == watch_msg


def test_ok__janus_leaves_non_watch_messages_untouched() -> None:
    from kvmd.apps.kvmd.api.janus import JanusApi

    janus_api = JanusApi(authz=_FakeAuthz(allow=True), switch=_FakeSwitch(), unix_path="/nonexistent.sock", timeout=5.0)  # type: ignore[arg-type]
    strip = janus_api._JanusApi__maybe_strip_webcam  # type: ignore[attr-defined]  # pylint: disable=protected-access

    for data in ('{"janus": "keepalive", "session_id": 1}', "not even json", ""):
        assert strip(data, False) == data


@pytest.mark.asyncio
async def test_ok__janus_connect_denies_webcam_permission_separately_from_streamer_view() -> None:
    from kvmd.apps.kvmd.api.janus import JanusApi

    authz = _FakeAuthz(allow=False)  # denies everything, including "webcam"
    switch = _FakeSwitch(active_port=1)
    janus_api = JanusApi(authz=authz, switch=switch, unix_path="/nonexistent.sock", timeout=5.0)  # type: ignore[arg-type]

    class _FakeReq:
        headers: dict = {}
        remote = "127.0.0.1"
        query: dict = {}

    req = _FakeReq()
    htserver.set_request_auth_info(req, "carol", user="carol", groups=("viewers",))  # type: ignore[arg-type]

    # The connection itself (streamer.view) is gated by the generic
    # permission= mechanism in server.py, not exercised here -- this proves
    # the *separate* manual webcam check fires with the right action name
    # and resource, independent of that.
    handler = janus_api._JanusApi__ws_proxy_handler  # type: ignore[attr-defined]  # pylint: disable=protected-access
    try:
        await handler(req)  # type: ignore[arg-type]
    except Exception:
        pass  # It'll fail trying to connect to the fake unix socket -- that's fine, we only care about the authz call below
    assert ("carol", "webcam", {"active_port": 1}, ("viewers",)) in authz.calls
