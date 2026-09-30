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


import logging
import socket

import aiohttp

from ...logging import get_logger

from ...htserver import ForbiddenError


# =====
_audit_log = logging.getLogger("kvmd.audit")


class AuthzManager:
    def __init__(
        self,
        enabled: bool,
        opa_url: str,
        opa_timeout: float,
        device_id: str,
        fail_open: bool,
    ) -> None:

        self.__enabled = enabled
        self.__opa_url = opa_url
        self.__opa_timeout = opa_timeout
        self.__device_id = (device_id or socket.gethostname())
        self.__fail_open = fail_open
        self.__session: (aiohttp.ClientSession | None) = None

        logger = get_logger(0)
        if enabled:
            logger.info(
                "Authz enabled: opa_url=%r device_id=%r fail_open=%r",
                opa_url, self.__device_id, fail_open,
            )
        else:
            logger.info("Authz disabled: all authenticated users have full access")

    def is_authz_enabled(self) -> bool:  # noqa vulture-ignore
        return self.__enabled

    async def sysprep(self) -> None:
        if self.__enabled:
            self.__session = aiohttp.ClientSession()

    async def cleanup(self) -> None:
        if self.__session is not None:
            await self.__session.close()
            self.__session = None

    async def check(
        self,
        user: str,
        action: str,
        resource: dict,
        *,
        groups: tuple[str, ...] = (),
        source_ip: str = "",
        user_agent: str = "",
    ) -> bool:
        if not self.__enabled:
            return True

        assert self.__session is not None

        input_data = {
            "user":        user,
            "user_groups": list(groups),
            "device_id":   self.__device_id,
            "action":      action,
            "resource":    resource,
        }

        allowed = self.__fail_open
        opa_error = False
        logger = get_logger(0)

        logger.debug("authz: request to %s: input=%r", self.__opa_url, input_data)

        try:
            async with self.__session.post(
                self.__opa_url,
                json={"input": input_data},
                timeout=aiohttp.ClientTimeout(total=self.__opa_timeout),
            ) as resp:
                data = await resp.json()
                allowed = bool(data.get("result", False))
                logger.debug("authz: OPA responded: %r", data)
        except Exception as ex:
            opa_error = True
            logger.error(
                "authz: OPA unavailable (failing %s): %s",
                ("open" if self.__fail_open else "closed"),
                ex,
            )

        _audit_log.info(
            "user=%r groups=%r action=%r resource=%r device=%r allowed=%r opa_error=%r source_ip=%r user_agent=%r",
            user, groups, action, resource, self.__device_id, allowed, opa_error, source_ip, user_agent,
        )

        return allowed

    async def list_permissions(
        self,
        user: str,
        *,
        groups: tuple[str, ...] = (),
        active_port: (int | None) = None,
        candidate_ports: (list[int] | None) = None,
    ) -> dict:
        # Cosmetic only -- see effective_permissions/activatable_ports in
        # authz.rego. A None field means "authz disabled or unavailable,
        # don't restrict anything in the UI" (real enforcement is untouched
        # either way); an empty list means "enabled, and you can't do any of
        # this". On any OPA error, fails to None/empty rather than honoring
        # the configured fail_open -- showing too little in the UI is just
        # an extra click of friction (still independently re-checked on the
        # real action), but showing too much on an outage would actively
        # mislead the user, which fail_open was never meant to control.
        candidate_ports = (candidate_ports or [])

        if not self.__enabled:
            return {"permissions": None, "activatable_ports": None}

        assert self.__session is not None
        logger = get_logger(0)

        input_data = {
            "user":            user,
            "user_groups":     list(groups),
            "device_id":       self.__device_id,
            "action":          "",
            "resource":        {"active_port": active_port},
            "candidate_ports": candidate_ports,
        }

        # opa_url points at a single rule (".../authz/allow" by default);
        # querying the bare package path instead returns every exported
        # rule in one round trip, including the two above.
        package_url = self.__opa_url.rsplit("/", 1)[0]

        result: dict = {"permissions": [], "activatable_ports": []}
        try:
            async with self.__session.post(
                package_url,
                json={"input": input_data},
                timeout=aiohttp.ClientTimeout(total=self.__opa_timeout),
            ) as resp:
                data = await resp.json()
                pkg = (data.get("result") or {})
                result = {
                    "permissions":       sorted(pkg.get("effective_permissions", [])),
                    "activatable_ports": sorted(pkg.get("activatable_ports", [])),
                }
                logger.debug("authz: listed permissions for user=%r: %r", user, result)
        except Exception as ex:
            logger.error("authz: OPA unavailable while listing permissions for user=%r: %s", user, ex)

        return result

    async def check_or_raise(
        self,
        user: str,
        action: str,
        resource: dict,
        *,
        groups: tuple[str, ...] = (),
        source_ip: str = "",
        user_agent: str = "",
    ) -> None:
        if not (await self.check(user, action, resource, groups=groups, source_ip=source_ip, user_agent=user_agent)):
            raise ForbiddenError()
