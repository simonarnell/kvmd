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
        source_ip: str = "",
        user_agent: str = "",
    ) -> bool:
        if not self.__enabled:
            return True

        assert self.__session is not None

        input_data = {
            "user":      user,
            "device_id": self.__device_id,
            "action":    action,
            "resource":  resource,
        }

        allowed = self.__fail_open
        opa_error = False

        try:
            async with self.__session.post(
                self.__opa_url,
                json={"input": input_data},
                timeout=aiohttp.ClientTimeout(total=self.__opa_timeout),
            ) as resp:
                data = await resp.json()
                allowed = bool(data.get("result", False))
        except Exception as ex:
            opa_error = True
            get_logger(0).error(
                "authz: OPA unavailable (failing %s): %s",
                ("open" if self.__fail_open else "closed"),
                ex,
            )

        _audit_log.info(
            "user=%r action=%r resource=%r device=%r allowed=%r opa_error=%r source_ip=%r user_agent=%r",
            user, action, resource, self.__device_id, allowed, opa_error, source_ip, user_agent,
        )

        return allowed

    async def check_or_raise(
        self,
        user: str,
        action: str,
        resource: dict,
        *,
        source_ip: str = "",
        user_agent: str = "",
    ) -> None:
        if not (await self.check(user, action, resource, source_ip=source_ip, user_agent=user_agent)):
            raise ForbiddenError()
