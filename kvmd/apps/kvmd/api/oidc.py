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

from ....htserver import ForbiddenError
from ....htserver import exposed_http
from ....htserver import make_json_response

from ....validators import check_string_in_list

from ..auth import AuthManager
from ..oidc import OidcManager
from ..oidc import OidcError

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
        url = self.__oidc.build_authorize_url(redirect)
        raise HTTPFound(location=url)

    @exposed_http("GET", "/auth/oidc/callback", auth_required=False, allow_usc=False)
    async def __callback_handler(self, req: Request) -> Response:
        if not self.__oidc.is_oidc_enabled():
            raise ForbiddenError()

        if req.query.get("error"):
            raise ForbiddenError()

        code = req.query.get("code", "")
        state = req.query.get("state", "")
        if not code or not state:
            raise ForbiddenError()

        try:
            (identity, redirect) = (await self.__oidc.handle_callback(code, state))
        except OidcError:
            raise ForbiddenError()  # pylint: disable=raise-missing-from

        token = await self.__auth.login_external(identity, expire=0)

        if redirect:
            ex = HTTPFound(location=redirect)
            ex.set_cookie(_COOKIE_AUTH_TOKEN, token, httponly=True, samesite="Strict")
            raise ex
        return make_json_response(set_cookies={_COOKIE_AUTH_TOKEN: token})
