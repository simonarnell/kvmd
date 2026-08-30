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


import base64
import dataclasses
import hashlib
import json
import logging
import secrets
import time
import urllib.parse
import warnings

import aiohttp

with warnings.catch_warnings():
    # authlib.jose is soft-deprecated in favor of joserfc, but joserfc isn't
    # packaged in Arch's official repos yet; authlib.jose remains functional
    # ("will be compatible before version 2.0.0") and python-authlib is
    # already available, so we use it deliberately for now.
    warnings.simplefilter("ignore")
    from authlib.jose import JsonWebKey
    from authlib.jose import KeySet
    from authlib.jose import jwt as jose_jwt
    from authlib.jose.errors import JoseError

from ...logging import get_logger

from ...plugins.auth import AuthIdentity


# =====
_audit_log = logging.getLogger("kvmd.audit")

_PENDING_TTL = 300.0  # Seconds a login attempt (state/nonce/PKCE verifier) stays valid.


class OidcError(Exception):
    pass


def _peek_jwt_header(token: str) -> dict:
    # Decodes the JWT header WITHOUT verifying the signature -- for logging
    # only (which kid/alg did the IdP actually use), never for a trust
    # decision. jose_jwt.decode() below is what actually verifies the token.
    try:
        segment = token.split(".", 1)[0]
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


@dataclasses.dataclass(frozen=True)
class _Pending:
    nonce:         str
    code_verifier: str
    redirect:      str
    created_ts:    float


class OidcManager:  # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        enabled: bool,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str],
        username_claim: str,
        groups_claim: str,
        verify_ssl: bool,
        timeout: float,
    ) -> None:

        self.__enabled = enabled
        self.__issuer = issuer.rstrip("/")
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__redirect_uri = redirect_uri
        self.__scopes = scopes
        self.__username_claim = username_claim
        self.__groups_claim = groups_claim
        self.__verify_ssl = verify_ssl
        self.__timeout = timeout

        self.__session: (aiohttp.ClientSession | None) = None
        self.__authorize_endpoint = ""
        self.__token_endpoint = ""
        self.__jwks: (KeySet | None) = None

        self.__pending: dict[str, _Pending] = {}

        logger = get_logger(0)
        if enabled:
            logger.info("OIDC enabled: issuer=%r client_id=%r", self.__issuer, client_id)
        else:
            logger.info("OIDC disabled")

    def is_oidc_enabled(self) -> bool:
        return self.__enabled

    async def sysprep(self) -> None:
        if not self.__enabled:
            return
        self.__session = aiohttp.ClientSession()
        await self.__refresh_discovery()

    async def cleanup(self) -> None:
        if self.__session is not None:
            await self.__session.close()
            self.__session = None

    async def __refresh_discovery(self) -> None:
        assert self.__session is not None
        timeout = aiohttp.ClientTimeout(total=self.__timeout)
        logger = get_logger(0)

        discovery_url = f"{self.__issuer}/.well-known/openid-configuration"
        logger.debug("oidc: fetching discovery document: %s", discovery_url)
        async with self.__session.get(discovery_url, ssl=self.__verify_ssl, timeout=timeout) as resp:
            resp.raise_for_status()
            discovery = await resp.json()

        self.__authorize_endpoint = discovery["authorization_endpoint"]
        self.__token_endpoint = discovery["token_endpoint"]
        logger.debug(
            "oidc: discovery resolved: authorize=%s token=%s jwks_uri=%s",
            self.__authorize_endpoint, self.__token_endpoint, discovery["jwks_uri"],
        )

        async with self.__session.get(discovery["jwks_uri"], ssl=self.__verify_ssl, timeout=timeout) as resp:
            resp.raise_for_status()
            jwks_data = await resp.json()
        self.__jwks = JsonWebKey.import_key_set(jwks_data)
        logger.debug(
            "oidc: JWKS refreshed: %d key(s), kid=%r",
            len(jwks_data.get("keys", [])), [k.get("kid") for k in jwks_data.get("keys", [])],
        )

    # =====

    def build_authorize_url(self, redirect: str) -> str:
        assert self.__enabled
        self.__sweep_pending()

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()

        self.__pending[state] = _Pending(
            nonce=nonce,
            code_verifier=code_verifier,
            redirect=redirect,
            created_ts=time.monotonic(),
        )

        params = {
            "response_type": "code",
            "client_id": self.__client_id,
            "redirect_uri": self.__redirect_uri,
            "scope": " ".join(self.__scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        url = f"{self.__authorize_endpoint}?{urllib.parse.urlencode(params)}"
        # code_verifier is deliberately omitted: it's the one secret in this
        # flow that never leaves kvmd, so it never goes in a log either.
        get_logger(0).debug("oidc: built authorize URL for redirect=%r state=%r: %s", redirect, state, url)
        return url

    def __sweep_pending(self) -> None:
        now = time.monotonic()
        for (key, pending) in list(self.__pending.items()):
            if now - pending.created_ts > _PENDING_TTL:
                del self.__pending[key]

    async def handle_callback(self, code: str, state: str) -> tuple[AuthIdentity, str]:
        assert self.__enabled
        assert self.__session is not None
        logger = get_logger(0)

        logger.debug("oidc: callback received: state=%r pending_count=%d", state, len(self.__pending))

        pending = self.__pending.pop(state, None)
        if pending is None or (time.monotonic() - pending.created_ts) > _PENDING_TTL:
            _audit_log.info("oidc: rejected callback: unknown or expired state")
            raise OidcError("Unknown or expired OIDC login attempt")

        try:
            timeout = aiohttp.ClientTimeout(total=self.__timeout)
            logger.debug("oidc: exchanging code at token endpoint: %s", self.__token_endpoint)
            async with self.__session.post(
                self.__token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.__redirect_uri,
                    "client_id": self.__client_id,
                    "client_secret": self.__client_secret,
                    "code_verifier": pending.code_verifier,
                },
                ssl=self.__verify_ssl,
                timeout=timeout,
            ) as resp:
                resp.raise_for_status()
                token_data = await resp.json()
        except Exception as ex:
            get_logger(0).error("oidc: token exchange failed: %s", ex)
            raise OidcError("Token exchange failed") from ex

        # Deliberately not logging token_data itself, even at debug: it holds
        # the bearer access_token (and the id_token, logged separately below
        # only as a header/claim-key summary, never the raw compact JWT).
        logger.debug("oidc: token endpoint responded with keys=%r", sorted(token_data.keys()))

        id_token = token_data.get("id_token")
        if not id_token:
            get_logger(0).error("oidc: token response did not include an id_token (keys present: %r)", sorted(token_data.keys()))
            raise OidcError("Token response did not include an id_token")

        identity = (await self.__validate_id_token(id_token, pending.nonce))
        _audit_log.info("oidc: user=%r groups=%r authenticated via issuer=%r",
                        identity.user, identity.groups, self.__issuer)
        return (identity, pending.redirect)

    async def __validate_id_token(self, id_token: str, nonce: str) -> AuthIdentity:
        logger = get_logger(0)
        claims_options = {
            "iss":   {"essential": True, "value": self.__issuer},
            "aud":   {"essential": True, "value": self.__client_id},
            "nonce": {"essential": True, "value": nonce},
        }

        header = _peek_jwt_header(id_token)
        logger.debug(
            "oidc: id_token header: alg=%r kid=%r; known JWKS kids=%r",
            header.get("alg"), header.get("kid"), self.__jwks_kids(),
        )

        try:
            claims = jose_jwt.decode(id_token, self.__jwks, claims_options=claims_options)
        except JoseError as ex:
            # The signing key may have rotated (unknown kid) since we last
            # fetched JWKS: refresh once and retry before giving up.
            get_logger(0).info("oidc: id_token validation failed, refreshing JWKS and retrying: %s", ex)
            try:
                await self.__refresh_discovery()
                logger.debug("oidc: JWKS kids after refresh: %r", self.__jwks_kids())
                claims = jose_jwt.decode(id_token, self.__jwks, claims_options=claims_options)
            except Exception as retry_ex:
                get_logger(0).error("oidc: id_token validation still failing after JWKS refresh: %s", retry_ex)
                raise OidcError("Invalid id_token") from retry_ex

        try:
            claims.validate(leeway=60)
        except JoseError as ex:
            get_logger(0).error("oidc: id_token claims validation failed (iss/aud/exp/nonce): %s", ex)
            raise OidcError("Invalid id_token claims") from ex

        logger.debug("oidc: id_token claims valid; claims present: %r", sorted(claims.keys()))

        user = claims.get(self.__username_claim)
        if not user or not str(user).strip():
            get_logger(0).error(
                "oidc: id_token missing username claim %r (claims present: %r)",
                self.__username_claim, sorted(claims.keys()),
            )
            raise OidcError(f"id_token is missing the configured username claim {self.__username_claim!r}")

        groups_raw = claims.get(self.__groups_claim) or []
        if not isinstance(groups_raw, list):
            logger.debug(
                "oidc: groups claim %r present but not a list (type=%s) -- treating as no groups",
                self.__groups_claim, type(groups_raw).__name__,
            )
            groups_raw = []
        groups = tuple(str(group) for group in groups_raw)

        return AuthIdentity(user=str(user).strip(), groups=groups)

    def __jwks_kids(self) -> list[str]:
        if self.__jwks is None:
            return []
        try:
            return [str(key.get("kid")) for key in self.__jwks.as_dict().get("keys", [])]
        except Exception:
            return ["<unavailable>"]
