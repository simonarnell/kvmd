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

# Unit tests for OidcManager against a fake, in-process IdP (aiohttp test
# server) -- discovery, PKCE/state/nonce handling, token exchange, and
# id_token claim validation/rejection. Mirrors the fake-OPA pattern used for
# AuthzManager in test_authz.py: this exercises OidcManager's own logic in
# isolation, not a real IdP -- that's covered separately by the
# testcontainers-based Keycloak suite.

import contextlib
import time

from typing import Any
from typing import AsyncGenerator

from aiohttp import web

import pytest

from authlib.jose import JsonWebKey
from authlib.jose import jwt as jose_jwt

from kvmd.apps.kvmd.oidc import OidcManager
from kvmd.apps.kvmd.oidc import OidcError

from kvmd.plugins.auth import AuthIdentity


# =====
_CLIENT_ID = "kvmd-client"
_CLIENT_SECRET = "s3cret"


def _make_key() -> tuple[dict, dict]:
    key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    pub = key.as_dict(add_kid=True)
    priv = key.as_dict(is_private=True)
    priv["kid"] = pub["kid"]
    return (pub, priv)


def _make_idp_app(issuer_holder: dict, pub: dict, priv: dict, nonces: dict) -> web.Application:
    app = web.Application()

    async def discovery(_: web.Request) -> web.Response:
        issuer = issuer_holder["issuer"]
        return web.json_response({
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
        })

    async def jwks(_: web.Request) -> web.Response:
        return web.json_response({"keys": [pub]})

    async def token(req: web.Request) -> web.Response:
        data = await req.post()
        assert data["client_id"] == _CLIENT_ID
        assert data["client_secret"] == _CLIENT_SECRET
        assert data["grant_type"] == "authorization_code"

        code = str(data["code"])
        nonce = nonces.get(code, "unknown-nonce")
        now = int(time.time())
        payload = {
            "iss": issuer_holder["issuer"],
            "aud": _CLIENT_ID,
            "sub": "u1",
            "exp": now + 300,
            "iat": now,
            "nonce": nonce,
            "preferred_username": "alice",
            "groups": ["admins", "ops"],
        }
        header = {"alg": "RS256", "kid": pub["kid"]}
        id_token = jose_jwt.encode(header, payload, priv).decode()
        return web.json_response({"access_token": "at", "id_token": id_token, "token_type": "Bearer"})

    app.router.add_get("/.well-known/openid-configuration", discovery)
    app.router.add_get("/jwks", jwks)
    app.router.add_post("/token", token)
    return app


@contextlib.asynccontextmanager
async def _manager(aiohttp_server: Any) -> AsyncGenerator[tuple[OidcManager, dict], None]:
    (pub, priv) = _make_key()
    issuer_holder: dict = {}
    nonces: dict = {}

    server = await aiohttp_server(_make_idp_app(issuer_holder, pub, priv, nonces))
    issuer_holder["issuer"] = f"http://localhost:{server.port}"

    mgr = OidcManager(
        enabled=True,
        issuer=issuer_holder["issuer"],
        client_id=_CLIENT_ID,
        client_secret=_CLIENT_SECRET,
        redirect_uri="http://kvmd.local/api/auth/oidc/callback",
        scopes=["openid", "profile", "groups"],
        username_claim="preferred_username",
        groups_claim="groups",
        verify_ssl=True,
        timeout=5.0,
    )
    await mgr.sysprep()
    try:
        yield (mgr, nonces)
    finally:
        await mgr.cleanup()


def _extract_state_and_nonce(url: str) -> tuple[str, str]:
    from urllib.parse import urlparse
    from urllib.parse import parse_qs
    qs = parse_qs(urlparse(url).query)
    return (qs["state"][0], qs["nonce"][0])


# =====
@pytest.mark.asyncio
async def test_ok__happy_path(aiohttp_server: Any) -> None:
    async with _manager(aiohttp_server) as (mgr, nonces):
        url = mgr.build_authorize_url(redirect="/kvm")
        assert "response_type=code" in url
        assert "code_challenge=" in url
        assert "code_challenge_method=S256" in url

        (state, nonce) = _extract_state_and_nonce(url)
        nonces["code1"] = nonce

        (identity, redirect) = (await mgr.handle_callback("code1", state))
        assert isinstance(identity, AuthIdentity)
        assert identity.user == "alice"
        assert set(identity.groups) == {"admins", "ops"}
        assert redirect == "/kvm"


@pytest.mark.asyncio
async def test_fail__state_is_single_use(aiohttp_server: Any) -> None:
    async with _manager(aiohttp_server) as (mgr, nonces):
        url = mgr.build_authorize_url(redirect="/kvm")
        (state, nonce) = _extract_state_and_nonce(url)
        nonces["code1"] = nonce

        await mgr.handle_callback("code1", state)
        with pytest.raises(OidcError):
            await mgr.handle_callback("code1", state)


@pytest.mark.asyncio
async def test_fail__unknown_state(aiohttp_server: Any) -> None:
    async with _manager(aiohttp_server) as (mgr, _):
        with pytest.raises(OidcError):
            await mgr.handle_callback("some-code", "not-a-real-state")


@pytest.mark.asyncio
async def test_fail__nonce_mismatch(aiohttp_server: Any) -> None:
    async with _manager(aiohttp_server) as (mgr, nonces):
        url = mgr.build_authorize_url(redirect="/kvm")
        (state, _nonce) = _extract_state_and_nonce(url)
        nonces["code1"] = "a-completely-different-nonce"

        with pytest.raises(OidcError):
            await mgr.handle_callback("code1", state)


@pytest.mark.asyncio
async def test_ok__disabled() -> None:
    mgr = OidcManager(
        enabled=False,
        issuer="", client_id="", client_secret="", redirect_uri="",
        scopes=[], username_claim="preferred_username", groups_claim="groups",
        verify_ssl=True, timeout=5.0,
    )
    assert not mgr.is_oidc_enabled()
    await mgr.sysprep()  # No-op when disabled: must not try to reach an issuer
    await mgr.cleanup()
