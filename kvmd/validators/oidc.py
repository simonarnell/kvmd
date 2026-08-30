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


from typing import Any
from urllib.parse import urlparse

from . import add_validator_magic
from . import check_not_none_string
from . import raise_error


# =====
@add_validator_magic(4096)
def valid_oidc_url(arg: Any, name: str="OIDC URL") -> str:
    arg = check_not_none_string(arg, name)
    parsed = urlparse(arg)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise_error(arg, name)
    return arg
