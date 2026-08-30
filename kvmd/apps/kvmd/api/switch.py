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
from ....htserver import ForbiddenError
from ....htserver import get_request_user
from ....htserver import get_request_is_usc
from ....htserver import get_request_groups

from ....validators.basic import valid_bool
from ....validators.basic import valid_int_f0
from ....validators.basic import valid_float_f0
from ....validators.basic import valid_stripped_string_not_empty
from ....validators.kvm import valid_atx_power_action
from ....validators.kvm import valid_atx_button
from ....validators.switch import valid_switch_port_name
from ....validators.switch import valid_switch_edid_id
from ....validators.switch import valid_switch_edid_data
from ....validators.switch import valid_switch_color
from ....validators.switch import valid_switch_atx_click_delay

from ..switch import Switch
from ..switch import Colors
from ..authz import AuthzManager


# =====
class SwitchApi:
    def __init__(self, switch: Switch, authz: AuthzManager) -> None:
        self.__switch = switch
        self.__authz = authz

    # =====

    @exposed_http("GET", "/switch")
    async def __state_handler(self, _: Request) -> Response:
        return make_json_response(await self.__switch.get_state())

    @exposed_http("POST", "/switch/set_active_prev", permission="switch.port.navigate")
    async def __set_active_prev_handler(self, _: Request) -> Response:
        await self.__switch.set_active_prev()
        return make_json_response()

    @exposed_http("POST", "/switch/set_active_next", permission="switch.port.navigate")
    async def __set_active_next_handler(self, _: Request) -> Response:
        await self.__switch.set_active_next()
        return make_json_response()

    @exposed_http("POST", "/switch/set_active")
    async def __set_active_port_handler(self, req: Request) -> Response:
        port = valid_float_f0(req.query.get("port"))
        # Fine-grained port-level authz: USC (local tools) bypass, others checked per-port
        if not get_request_is_usc(req):
            user = get_request_user(req)
            if user:
                groups = get_request_groups(req)
                if not (await self.__authz.check(
                    user,
                    "switch.port.activate",
                    {"port": int(port)},
                    groups=groups,
                    source_ip=(req.remote or ""),
                    user_agent=req.headers.get("User-Agent", ""),
                )):
                    raise ForbiddenError()
        await self.__switch.set_active_port(port)
        return make_json_response()

    @exposed_http("POST", "/switch/set_beacon", permission="switch.port.configure")
    async def __set_beacon_handler(self, req: Request) -> Response:
        on = valid_bool(req.query.get("state"))
        if "port" in req.query:
            port = valid_float_f0(req.query.get("port"))
            await self.__switch.set_port_beacon(port, on)
        elif "uplink" in req.query:
            unit = valid_int_f0(req.query.get("uplink"))
            await self.__switch.set_uplink_beacon(unit, on)
        else:  # Downlink
            unit = valid_int_f0(req.query.get("downlink"))
            await self.__switch.set_downlink_beacon(unit, on)
        return make_json_response()

    @exposed_http("POST", "/switch/set_port_params", permission="switch.port.configure")
    async def __set_port_params(self, req: Request) -> Response:
        port = valid_float_f0(req.query.get("port"))
        params = {
            param: validator(req.query.get(param))  # type: ignore
            for (param, validator) in [
                ("edid_id", valid_switch_edid_id.mk(allow_default=True)),
                ("dummy",   valid_bool),
                ("name",    valid_switch_port_name),
                ("atx_click_power_delay",      valid_switch_atx_click_delay),
                ("atx_click_power_long_delay", valid_switch_atx_click_delay),
                ("atx_click_reset_delay",      valid_switch_atx_click_delay),
            ]
            if req.query.get(param) is not None
        }
        await self.__switch.set_port_params(port, **params)  # type: ignore
        return make_json_response()

    @exposed_http("POST", "/switch/set_colors", permission="switch.device.configure")
    async def __set_colors(self, req: Request) -> Response:
        params = {
            param: valid_switch_color(req.query.get(param), allow_default=True)
            for param in Colors.ROLES
            if req.query.get(param) is not None
        }
        await self.__switch.set_colors(**params)
        return make_json_response()

    # =====

    @exposed_http("POST", "/switch/reset", permission="switch.device.reset")
    async def __reset(self, req: Request) -> Response:
        unit = valid_int_f0(req.query.get("unit"))
        bootloader = valid_bool(req.query.get("bootloader", False))
        await self.__switch.reboot_unit(unit, bootloader)
        return make_json_response()

    # =====

    @exposed_http("POST", "/switch/edids/create", permission="switch.device.configure")
    async def __create_edid(self, req: Request) -> Response:
        name = valid_stripped_string_not_empty(req.query.get("name"))
        data_hex = valid_switch_edid_data(req.query.get("data"))
        edid_id = await self.__switch.create_edid(name, data_hex)
        return make_json_response({"id": edid_id})

    @exposed_http("POST", "/switch/edids/change", permission="switch.device.configure")
    async def __change_edid(self, req: Request) -> Response:
        edid_id = valid_switch_edid_id(req.query.get("id"), allow_default=False)
        params = {
            param: validator(req.query.get(param))
            for (param, validator) in [
                ("name", valid_switch_port_name),
                ("data", valid_switch_edid_data),
            ]
            if req.query.get(param) is not None
        }
        if params:
            await self.__switch.change_edid(edid_id, **params)
        return make_json_response()

    @exposed_http("POST", "/switch/edids/remove", permission="switch.device.configure")
    async def __remove_edid(self, req: Request) -> Response:
        edid_id = valid_switch_edid_id(req.query.get("id"), allow_default=False)
        await self.__switch.remove_edid(edid_id)
        return make_json_response()

    # =====

    @exposed_http("POST", "/switch/atx/power", permission="switch.atx")
    async def __power_handler(self, req: Request) -> Response:
        port = valid_float_f0(req.query.get("port"))
        action = valid_atx_power_action(req.query.get("action"))
        await ({
            "on":         self.__switch.atx_power_on,
            "off":        self.__switch.atx_power_off,
            "off_hard":   self.__switch.atx_power_off_hard,
            "reset_hard": self.__switch.atx_power_reset_hard,
        }[action])(port)
        return make_json_response()

    @exposed_http("POST", "/switch/atx/click", permission="switch.atx")
    async def __click_handler(self, req: Request) -> Response:
        port = valid_float_f0(req.query.get("port"))
        button = valid_atx_button(req.query.get("button"))
        await ({
            "power":      self.__switch.atx_click_power,
            "power_long": self.__switch.atx_click_power_long,
            "reset":      self.__switch.atx_click_reset,
        }[button])(port)
        return make_json_response()
