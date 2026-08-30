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


from typing import Any

import pytest

from kvmd.validators import ValidatorError
from kvmd.validators.logging import valid_log_level


# =====
@pytest.mark.parametrize("arg, result", [
    ("debug", "DEBUG"),
    ("DEBUG", "DEBUG"),
    ("  info  ", "INFO"),
    ("warning", "WARNING"),
    ("error", "ERROR"),
    ("critical", "CRITICAL"),
])
def test_ok(arg: Any, result: str) -> None:
    assert valid_log_level(arg) == result


@pytest.mark.parametrize("arg", [
    "",
    "verbose",
    "trace",
    "warn",  # not the canonical Python logging name
    None,
])
def test_fail(arg: Any) -> None:
    with pytest.raises(ValidatorError):
        valid_log_level(arg)
