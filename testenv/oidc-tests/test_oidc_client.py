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

# Integration test for OidcManager against a REAL Keycloak instance started
# via testcontainers (not docker-compose -- follows the same pattern as
# feature/authz-testcontainers' testenv/authz-tests/test_policy.py).
#
# Scope: this proves OidcManager's discovery and JWKS handling are genuinely
# wire-compatible with a real IdP's actual response formats -- the thing a
# fake/hand-rolled IdP in a unit test can't catch (a subtly wrong claim name,
# an unexpected JWKS shape, a discovery document field we assumed but Keycloak
# doesn't provide, etc).
#
# The full authorization-code + PKCE + nonce + claim-validation/rejection
# logic (replay protection, unknown state, bad nonce, ...) is already
# thoroughly covered against a fake IdP in
# testenv/tests/apps/kvmd/test_oidc.py, which can assert on exact error
# conditions that are impractical to provoke against a real IdP.
#
# Deferred, not in this suite: scripting Keycloak's actual login page and
# driving a full authorize -> login -> callback round trip without a real
# browser turned out to be fragile (Keycloak's login flow binds a restart
# cookie to server-side session state in ways that don't survive a scripted,
# non-browser HTTP client reliably). A true browser-driven E2E test (e.g. via
# Playwright) against a real kvmd + Keycloak stack is a reasonable follow-up
# but is out of scope here.
#
# Run with: pytest testenv/oidc-tests/test_oidc_client.py
# Requires a working Docker daemon.

import contextlib
import pathlib

from typing import Any
from typing import AsyncGenerator

import pytest

from testcontainers.community.keycloak import KeycloakContainer

from kvmd.apps.kvmd.oidc import OidcManager


_HERE = pathlib.Path(__file__).parent
_REALM_FILE = _HERE / "realm-kvmd-test.json"

_CLIENT_ID = "kvmd-client"
_CLIENT_SECRET = "s3cret"


@pytest.fixture(scope="module")
def keycloak_issuer() -> Any:
    container = KeycloakContainer().with_realm_import_file(str(_REALM_FILE))
    with container:
        yield f"{container.get_url()}/realms/kvmd-test"


@contextlib.asynccontextmanager
async def _manager(issuer: str) -> AsyncGenerator[OidcManager, None]:
    mgr = OidcManager(
        enabled=True,
        issuer=issuer,
        client_id=_CLIENT_ID,
        client_secret=_CLIENT_SECRET,
        redirect_uri="http://kvmd.local/api/auth/oidc/callback",
        post_logout_redirect_uri="",
        scopes=["openid", "profile"],
        username_claim="preferred_username",
        groups_claim="groups",
        verify_ssl=True,
        timeout=10.0,
    )
    await mgr.sysprep()
    try:
        yield mgr
    finally:
        await mgr.cleanup()


# =====
@pytest.mark.asyncio
async def test_ok__sysprep_against_real_keycloak(keycloak_issuer: str) -> None:
    async with _manager(keycloak_issuer) as mgr:
        # sysprep() must have fetched real discovery + real JWKS without error.
        url = mgr.build_authorize_url(redirect="/kvm")

        assert url.startswith(f"{keycloak_issuer}/protocol/openid-connect/auth?")
        assert "response_type=code" in url
        assert f"client_id={_CLIENT_ID}" in url
        assert "code_challenge=" in url
        assert "code_challenge_method=S256" in url
        assert "state=" in url
        assert "nonce=" in url
