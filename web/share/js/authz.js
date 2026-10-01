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


import {tools} from "./tools.js";


// Frontend permission discovery -- lets the UI hide/disable controls the
// caller can't use instead of only discovering that on a failed click.
// Purely cosmetic: every real action is still independently re-checked by
// OPA on the actual request (see kvmd/apps/kvmd/authz.py), so a wrong or
// stale answer here is a UX papercut, never a security hole.
//
// __permissions/__activatable_ports are null until the first refresh()
// resolves, and also null whenever authz is disabled server-side --
// isAllowed()/isPortActivatable() treat null as "don't restrict", matching
// what a real request would actually do in both of those cases.
export var authz = new function() {
	var self = this;

	var __permissions = null;
	var __activatable_ports = null;
	var __subscribers = [];

	// Every module with its own authz-driven UI state (atx.js, msd.js,
	// ocr.js, stream.js, switch.js, ...) subscribes its own re-apply
	// function once at init, instead of session.js having to remember to
	// call each one individually from every place a refresh can happen
	// (page load, a switch's port model changing, its active port
	// changing, ...). A refresh triggered from any one of those places
	// then correctly re-applies everyone, not just whoever triggered it --
	// found the hard way: switching the active port on a real switch-mode
	// device used to leave every OTHER module's UI (the HID "view only"
	// banner, Log/Screenshot buttons, ATX, MSD, GPIO) showing stale
	// permissions from whatever port was active at page load, since only
	// switch.js's own buttons were being re-applied on that refresh path.
	self.subscribe = function(cb) {
		__subscribers.push(cb);
	};

	self.refresh = function(candidate_ports, cb) {
		let params = null;
		if (candidate_ports && candidate_ports.length > 0) {
			params = {"candidate_ports": candidate_ports.join(",")};
		}
		tools.httpGet("api/authz/permissions", params, function(http) {
			if (http.status === 200) {
				try {
					let result = JSON.parse(http.responseText)["result"];
					__permissions = result["permissions"];
					__activatable_ports = result["activatable_ports"];
				} catch { /* Leave whatever we had before -- fail open on the UI hint itself */ }
			}
			for (let sub of __subscribers) {
				sub();
			}
			if (cb) {
				cb();
			}
		});
	};

	self.isAllowed = function(action) {
		return (__permissions === null || __permissions.includes(action));
	};

	self.isPortActivatable = function(port) {
		return (__activatable_ports === null || __activatable_ports.includes(port));
	};
};
