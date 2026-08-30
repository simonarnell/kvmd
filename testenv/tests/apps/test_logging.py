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

# set_log_level() is the second half of the config-driven verbosity switch:
# init_logging() bootstraps the root logger at a fixed INFO level before
# config is even loaded (chicken-and-egg -- you need logging to report a
# config-loading error), and set_log_level() is applied afterward, once
# kvmd.logging.level is available. See kvmd/apps/__init__.py:init().

import logging

from kvmd.apps._logging import set_log_level


# =====
def test_ok__set_log_level_changes_effective_root_level() -> None:
    root = logging.getLogger()
    try:
        set_log_level("INFO")
        assert not root.isEnabledFor(logging.DEBUG)
        assert root.isEnabledFor(logging.INFO)

        set_log_level("DEBUG")
        assert root.isEnabledFor(logging.DEBUG)

        set_log_level("ERROR")
        assert not root.isEnabledFor(logging.WARNING)
        assert root.isEnabledFor(logging.ERROR)
    finally:
        root.setLevel(logging.INFO)  # don't leak state into other tests
