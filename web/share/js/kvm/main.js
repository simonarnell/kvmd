/*****************************************************************************
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
*****************************************************************************/


"use strict";


import {tools, $} from "../tools.js";
import {checkBrowser} from "../bb.js";
import {wm, initWindowManager} from "../wm.js";

import {Session} from "./session.js";


export function main() {
	if (!checkBrowser("kvm/x-desktop.css", "kvm/x-mobile.css")) {
		return;
	}

	tools.radio.clickValue("page-ui-type-radio", tools.storage.get("page.ui.type", "auto"));
	tools.radio.setOnClick("page-ui-type-radio", function() {
		const ui = tools.radio.getValue("page-ui-type-radio");
		if (tools.storage.get("page.ui.type") !== ui) {
			tools.storage.set("page.ui.type", ui);
			window.onbeforeunload = null;
			window.location.href = window.location.href;
		}
	}, false);

	tools.storage.bindSimpleSwitch($("page-close-ask-switch"), "page.close.ask", true, function(value) {
		if (value) {
			window.onbeforeunload = function(ev) {
				let text = "Are you sure you want to close PiKVM session?";
				if (ev) {
					ev.returnValue = text;
				}
				return text;
			};
		} else {
			window.onbeforeunload = null;
		}
	});

	initWindowManager();

	tools.el.setOnClick($("open-log-button"), __clickOpenLogButton);

	tools.storage.bindSimpleSwitch(
		$("page-full-tab-stream-switch"),
		"page.full_tab_stream",
		tools.config.getBool("kvm--full-tab-stream", false));
	if ($("page-full-tab-stream-switch").checked) {
		wm.setFullTabWindow($("stream-window"), true);
	}

	wm.showWindow($("stream-window"));
	if (tools.browser.is_mobile) {
		wm.showWindow($("mouse-window"));
	}

	new Session();
}

function __clickOpenLogButton() {
	// The log button is shown to every role regardless of the "log"
	// permission (the frontend has no notion of per-role permissions to
	// hide it with), and the real log view opens in a new tab via a plain
	// navigation -- so a straight windowOpen() left a denied user staring
	// at a bare {"ok":false,...} JSON page with no explanation. Probe with
	// a cheap non-streaming request first (follow=0 returns immediately,
	// whether allowed or denied) and only open the real streaming tab on
	// success.
	tools.httpGet("api/log", {"seek": 0, "follow": 0}, function(http) {
		if (http.status === 200) {
			tools.windowOpen("api/log?seek=3600&follow=1");
		} else {
			wm.error("Can't open the log", http.responseText);
		}
	});
}
