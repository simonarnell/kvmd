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
import {ROOT_PREFIX} from "../vars.js";


// How long __trySilentOidc() waits for the IdP before giving up and
// showing the ordinary login form anyway -- long enough for a real round
// trip to a real IdP, short enough that a genuinely unreachable IdP doesn't
// leave a visitor staring at a blank page for long.
const __SILENT_TIMEOUT_MS = 5000;


export function main() {
	if (checkBrowser(null, null)) {
		initWindowManager();

		// Radio is a string container
		tools.radio.clickValue("expire-radio", tools.storage.get("login.expire", 0));
		tools.radio.setOnClick("expire-radio", function() {
			let expire = parseInt(tools.radio.getValue("expire-radio"));
			tools.storage.setInt("login.expire", expire);
		}, false);

		tools.el.setOnClick($("login-button"), __login);
		$("user-input").onkeyup = $("passwd-input").onkeyup = $("code-input").onkeyup = function(ev) {
			if (ev.code === "Enter") {
				ev.preventDefault();
				$("login-button").click();
			}
		};

		tools.el.setOnClick($("login-oidc-button"), __loginOidc);
		tools.httpGet("api/auth/oidc/config", null, function(http) {
			let enabled = false;
			if (http.status === 200) {
				try {
					enabled = JSON.parse(http.responseText)["result"]["enabled"];
				} catch { /* Nah */ }
			}
			if (enabled) {
				$("login-oidc-row").hidden = false;
				$("login-oidc-row-2").hidden = false;
				__trySilentOidc();
			} else {
				// No check to wait for -- nothing kept the form hidden for.
				__revealLoginForm();
			}
		});

		$("user-input").focus();
	}
}

function __loginOidc() {
	tools.currentOpen("api/auth/oidc/login");
}

function __revealLoginForm() {
	// "visible", not "" -- the hidden state is a stylesheet rule
	// (index.html's inline <style>, applied before any script runs), not an
	// inline style this page ever set itself, so there's no inline value to
	// clear back to.
	$("login-box").style.visibility = "visible";
}

function __trySilentOidc() {
	// A walk-up-already-signed-in check: ask the IdP for an existing session
	// with no interactive page. The login form stays hidden (see index.html's
	// inline style) while this runs, so a user who's already signed in with
	// the IdP elsewhere never sees it flash up before this redirects them
	// away -- only a user it comes back negative for (or that takes long
	// enough to hit __SILENT_TIMEOUT_MS below) sees it at all.
	//
	// Driven through a hidden iframe, not a visible top-level redirect.
	// kvmd's callback sends a failed check back to /login/ (see
	// OidcApi.__callback_handler) -- a real page load, same origin as this
	// one, so its resulting location is readable directly once the iframe's
	// done, no postMessage needed. If it's anywhere else, the check
	// succeeded and the session cookie is already set: follow it with a
	// real top-level navigation, the same one a successful __loginOidc()
	// click would end up at.
	let revealed = false;
	let reveal = function() {
		if (!revealed) {
			revealed = true;
			__revealLoginForm();
		}
	};

	// Safety net: if the hidden iframe never fires load (a network hiccup
	// reaching the IdP, say), don't leave the page permanently blank --
	// show the ordinary form after a few seconds, same as if the check had
	// come back negative.
	setTimeout(reveal, __SILENT_TIMEOUT_MS);

	let iframe = $("login-oidc-silent");
	iframe.onload = function() {
		let dest;
		try {
			dest = iframe.contentWindow.location.href;
		} catch {
			reveal(); // Cross-origin somehow -- not expected same-origin, just show the login form.
			return;
		}
		if (dest.endsWith("/login/")) {
			reveal();
		} else {
			window.location.href = dest; // Already a fully resolved URL -- no ROOT_PREFIX to add back.
		}
	};
	iframe.src = `${ROOT_PREFIX}api/auth/oidc/login?silent=1`;
}

function __login() {
	let e_user = encodeURIComponent($("user-input").value);
	if (e_user.length === 0) {
		$("user-input").focus();
		return;
	}

	let e_passwd = encodeURIComponent($("passwd-input").value + $("code-input").value);
	let e_expire = encodeURIComponent(tools.radio.getValue("expire-radio"));
	let body = `user=${e_user}&passwd=${e_passwd}&expire=${e_expire}`;

	tools.httpPost("api/auth/login", null, function(http) {
		switch (http.status) {
			case 200:
				tools.currentOpen("");
				break;

			case 403:
				wm.error("Invalid username, password, or OTP").then(__tryAgain);
				break;

			default: {
				let error = "";
				if (http.status === 400) {
					try {
						error = JSON.parse(http.responseText)["result"]["error"];
					} catch { /* Nah */ }
				}
				if (error === "ValidatorError") {
					wm.error("Invalid characters in credentials").then(__tryAgain);
				} else {
					wm.error("Unexpected login error:", http.responseText).then(__tryAgain);
				}
			} break;
		}
	}, body, "application/x-www-form-urlencoded");

	__setEnabled(false);
}

function __setEnabled(enabled) {
	tools.el.setEnabled($("user-input"), enabled);
	tools.el.setEnabled($("passwd-input"), enabled);
	tools.el.setEnabled($("code-input"), enabled);
	tools.el.setEnabled($("login-button"), enabled);
}

function __tryAgain() {
	__setEnabled(true);
	let el = ($("code-input").value.length ? $("code-input") : $("passwd-input"));
	el.focus();
	el.select();
}
