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


from aiohttp.web import Request
from aiohttp.web import Response
from aiohttp.web import HTTPFound

from ....logging import get_logger

from ....htserver import ForbiddenError
from ....htserver import exposed_http
from ....htserver import make_json_response

from ....validators import check_string_in_list
from ....validators.basic import valid_bool

from ..auth import AuthManager
from ..oidc import OidcManager
from ..oidc import OidcError
from ..oidc import SILENT_AUTH_REQUIRED_ERRORS

from .auth import _COOKIE_AUTH_TOKEN


# =====
class OidcApi:
    def __init__(self, oidc: OidcManager, auth: AuthManager, allow_redirects: list[str]) -> None:
        self.__oidc = oidc
        self.__auth = auth
        self.__allow_redirects = set(["", *allow_redirects])

    # =====

    @exposed_http("GET", "/auth/oidc/config", auth_required=False, allow_usc=False)
    async def __config_handler(self, _: Request) -> Response:
        return make_json_response({"enabled": self.__oidc.is_oidc_enabled()})

    @exposed_http("GET", "/auth/oidc/login", auth_required=False, allow_usc=False)
    async def __login_handler(self, req: Request) -> Response:
        if not self.__oidc.is_oidc_enabled():
            raise ForbiddenError()
        redirect = check_string_in_list(
            arg=req.query.get("redirect", ""),
            name="login redirect",
            variants=self.__allow_redirects,
        )
        # silent=1: a walk-up-already-signed-in check (see login/main.js's
        # __trySilentOidc(), which drives this through a hidden iframe), not
        # the user clicking "Sign in with SSO" -- the IdP must not show that
        # user anything interactive, just say yes or no immediately.
        silent = valid_bool(req.query.get("silent", False))
        url = self.__oidc.build_authorize_url(redirect, silent=silent)
        raise HTTPFound(location=url)

    @exposed_http("GET", "/auth/oidc/callback", auth_required=False, allow_usc=False)
    async def __callback_handler(self, req: Request) -> Response:
        if not self.__oidc.is_oidc_enabled():
            raise ForbiddenError()

        idp_error = req.query.get("error")
        if idp_error in SILENT_AUTH_REQUIRED_ERRORS:
            # Expected, not a problem: the hidden silent-check iframe asked
            # the IdP to respond with no interactive page, and the IdP is
            # saying there's no existing session to use -- the normal case
            # for a user who hasn't signed in anywhere yet. Land back on
            # /login/ (a real page load, not another silent attempt) so
            # __trySilentOidc() sees "still here" as the signal to do
            # nothing and leave the ordinary login form showing.
            get_logger(0).debug("oidc: silent auth check found no existing session: error=%r", idp_error)
            raise HTTPFound(location="/login/")
        if idp_error:
            get_logger(0).error(
                "oidc: IdP returned an error on callback: error=%r description=%r",
                idp_error, req.query.get("error_description", ""),
            )
            raise ForbiddenError()

        code = req.query.get("code", "")
        state = req.query.get("state", "")
        if not code or not state:
            get_logger(0).error("oidc: callback missing code and/or state (code=%r, state=%r)", bool(code), bool(state))
            raise ForbiddenError()

        try:
            (identity, redirect, id_token) = (await self.__oidc.handle_callback(code, state))
        except OidcError as ex:
            get_logger(0).error("oidc: callback rejected: %s", ex)
            raise ForbiddenError()  # pylint: disable=raise-missing-from

        token = await self.__auth.login_external(identity, expire=0, oidc_id_token=id_token)

        # The whole OIDC flow is a full-page browser round trip (login page ->
        # IdP -> here), never an XHR/fetch call, so the callback must always
        # send the browser somewhere with a real HTTP redirect. An empty
        # `redirect` is the default/root case ("" is seeded into
        # __allow_redirects for exactly this), not "don't redirect" -- returning
        # bare JSON here left the browser stuck showing the raw API response.
        resp = HTTPFound(location=(redirect or "/"))
        resp.set_cookie(_COOKIE_AUTH_TOKEN, token, httponly=True, samesite="Strict")
        raise resp
