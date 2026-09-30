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

from ....htserver import exposed_http
from ....htserver import make_json_response
from ....htserver import get_request_user
from ....htserver import get_request_groups

from ....validators.basic import valid_int_f0
from ....validators.basic import valid_string_list

from ..authz import AuthzManager
from ..switch import Switch


# =====
class AuthzApi:
    def __init__(self, authz: AuthzManager, switch: Switch) -> None:
        self.__authz = authz
        self.__switch = switch

    # =====

    # Lets the frontend hide/disable controls the caller can't use instead
    # of only discovering that on a failed click. Purely a UX hint -- see
    # AuthzManager.list_permissions() and authz.rego's effective_permissions/
    # activatable_ports for why this can never become the real enforcement
    # boundary. Returns the caller's own permissions only (derived from
    # their own session), so this needs no permission= of its own.
    @exposed_http("GET", "/authz/permissions", allow_usc=False)
    async def __permissions_handler(self, req: Request) -> Response:
        candidate_ports = valid_string_list(
            req.query.get("candidate_ports", ""),
            subval=valid_int_f0,
            name="candidate ports",
        )
        raw_active_port = self.__switch.get_active_port()  # -1 = no port active
        active_port = (raw_active_port if raw_active_port >= 0 else None)

        result = await self.__authz.list_permissions(
            get_request_user(req),
            groups=get_request_groups(req),
            active_port=active_port,
            candidate_ports=[int(port) for port in candidate_ports],
        )
        return make_json_response(result)
