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

# kvmd.janus_proxy is new (see kvmd/apps/kvmd/api/janus.py) and has no test
# coverage anywhere else -- nothing exercises make_config_scheme() actually
# accepting it, so a typo'd option name here would only surface as a startup
# crash on a real device, never in CI.

from kvmd.apps._scheme import make_config_scheme
from kvmd.yamlconf import make_config


# =====
def test_ok__janus_proxy_scheme_has_sane_defaults() -> None:
    scheme = make_config_scheme()["kvmd"]["janus_proxy"]
    config = make_config({}, {}, scheme)
    assert config.unix_path == "/run/kvmd/janus-ws.sock"
    assert config.timeout == 5.0


def test_ok__janus_proxy_scheme_accepts_override() -> None:
    scheme = make_config_scheme()["kvmd"]["janus_proxy"]
    config = make_config({}, {"unix_path": "/custom/path.sock", "timeout": 2.5}, scheme)
    assert config.unix_path == "/custom/path.sock"
    assert config.timeout == 2.5
