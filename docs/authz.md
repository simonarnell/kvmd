# AuthZ Model

kvmd separates *who you are* (Authentication — `htpasswd`, LDAP, RADIUS, PAM, or [OIDC](oidc.md)) from *what you're allowed to do* (Authorisation). Authorisation is handled by [Open Policy Agent](https://www.openpolicyagent.org/) (OPA) running as a local sidecar service, `kvmd-authz`, evaluating a declarative policy against every permission-gated action kvmd receives.

This is entirely optional — if `kvmd.authz.enabled` is `false` (the default), every authenticated user has full access, exactly as kvmd has always behaved.

## Architecture

```
                     ┌─────────────┐
  browser ──HTTPS──► │    kvmd     │
                     │  (aiohttp)  │
                     └──────┬──────┘
                            │ POST /v1/data/kvmd/authz/allow
                            │ {"input": {user, user_groups, device_id,
                            │            action, resource}}
                            ▼
                     ┌─────────────┐
                     │  kvmd-authz │  (OPA, loopback only)
                     │  (sidecar)  │
                     └──────┬──────┘
                            │ loads
                            ▼
                     /etc/kvmd/authz/bundle/
                       policy/authz.rego
                       data.json
                       devices/<device-id>/data.json
```

`kvmd-authz` is a systemd unit running `opa run --server` against a local bundle directory, listening only on `localhost` — never exposed to the network. kvmd (the PDP client / PEP) calls it over HTTP for every action that has a `permission=` annotation on its endpoint, sending the authenticated user's name, group memberships (if any — see [Group-derived roles](#group-derived-roles)), the device's own ID, the requested action, and a resource object (currently just the active switch port, where relevant).

## What's actually enforced

| Action | Where | Mechanism |
|---|---|---|
| `switch.port.activate` | `POST /switch/set_active` | Checked inline in `api/switch.py` (not the generic mechanism below, since it needs the *target* port, not the currently active one). |
| `switch.port.navigate` | `POST /switch/set_active_prev`, `/set_active_next` | Generic `permission=` annotation, gated on the currently active port. |
| `switch.port.configure` | `POST /switch/set_port_params`, `/switch/set_beacon` | Generic `permission=` annotation. |
| `switch.atx` | `POST /switch/atx/power`, `/switch/atx/click` (switch-mediated), `POST /atx/power`, `/atx/click` (standalone) | Generic `permission=` annotation on both the switch-mediated and standalone endpoints — they're separate code paths and both need the annotation. |
| `switch.device.configure` | `POST /switch/set_colors`, `/switch/edids/create`, `/switch/edids/change`, `/switch/edids/remove` | Generic `permission=` annotation, device-global (not gated on the active port — see below). |
| `switch.device.reset` | `POST /switch/reset` | Generic `permission=` annotation, device-global. |
| `hid` | Live keyboard/mouse input over the `/ws` WebSocket, the HTTP fallback endpoints under `/hid/events/*` and `/hid/print`, and HID config/lifecycle (`/hid/set_params`, `/hid/set_connected`, `/hid/reset`) | WS: a per-connection, port-keyed decision cache (see below). HTTP: generic `permission=` annotation. |
| `msd.add` | `POST /msd/write`, `/msd/write_remote` | Generic `permission=` annotation. |
| `msd.mount` | `POST /msd/set_params`, `/msd/set_connected` | Generic `permission=` annotation. |
| `msd.delete` | `POST /msd/remove` | Generic `permission=` annotation. |
| `msd.read` | `GET /msd/read` | Generic `permission=` annotation. |
| `msd.reset` | `POST /msd/reset` | Generic `permission=` annotation, device-global. |
| `gpio` | `POST /gpio/switch`, `/gpio/pulse` | Generic `permission=` annotation, device-global. |
| `log` | `GET /log` | Generic `permission=` annotation, device-global. |
| `export` | `GET /export/prometheus/metrics` | Generic `permission=` annotation, device-global. Only applies while `kvmd.prometheus.auth.enabled` is `true` (the default) — if you've deliberately made metrics unauthenticated for a scraper, authz doesn't retroactively re-lock it. |
| `streamer.view` | The video stream itself (`/streamer`, proxied by nginx straight to `ustreamer`) and connecting to `/janus/ws` at all | A dedicated nginx `auth_request` for `/streamer`; for Janus, kvmd's own `permission=` annotation (see below). |
| `snapshot` | `GET/DELETE /streamer/snapshot` (this also covers OCR text extraction, which is a query param on the same endpoint) | Generic `permission=` annotation. |
| `webcam` | Injecting mic/camera audio-video into the target over `/janus/ws` (the webcam/mic USB gadget feature) | A manual, per-connection authz check inside kvmd's Janus WS broker (see below) — not a `permission=` annotation, since it's not a distinct HTTP endpoint. |

The **generic mechanism**: any `@exposed_http(..., permission="some.action")` endpoint is checked automatically by `KvmdServer._check_request_auth()` before the handler runs, using the currently active switch port as the resource. This is how most actions are wired — see `api/switch.py` for the pattern.

**Device-global actions** (`gpio`, `log`, `export`, `switch.device.configure`, `switch.device.reset`, `msd.reset`) are exempt from the active-port gating that applies to everything else. GPIO pins, the log/metrics streams, and resetting a whole subsystem (the switch controller, MSD) belong to the PiKVM board itself, not to whichever port happens to be selected — gating them on `active_port` would wrongly deny an admin from reading logs or resetting MSD on a switch-mode device before any port is selected, even though the action has nothing to do with a port. They're still gated on the role actually holding the permission, just not on port/standalone state.

**HID is different** because live input runs over a multiplexed WebSocket connection, not discrete HTTP requests, and there is no per-message authz mechanism on `exposed_ws` handlers by design (checking OPA on every single mouse-move message would add real, felt latency to interactive control). Instead, the decision is cached per-connection and only recomputed when the active port actually changes — a rare event compared to the message rate. **A practical consequence**: if you change a user's role or a device's ACLs while they have an open, already-HID-authorised WebSocket connection on the *same* port, that connection keeps its permission until it reconnects (page reload) or the active port changes. This mirrors how authentication itself already works (an open session isn't retroactively revoked either) — it is not a new class of staleness.

**The video stream is different** because it's served by `ustreamer` directly, proxied by nginx (`configs/nginx/kvmd.ctx-server.conf`) — kvmd's Python application, and therefore the generic mechanism above, never sees that traffic at all. nginx's `auth_request` directive calls `GET /auth/check_streamer` before allowing the proxy through, and that endpoint makes the same OPA call the generic mechanism would.

**Janus (`/janus/ws`) is different again**, and worth understanding in some depth given it now carries more than passive viewing:

- Historically, `/janus/ws` (WebRTC signaling for the low-latency video/audio path) was proxied by nginx straight to the Janus gateway, with no authz at all — only the server-wide default AuthN check applied. Since a PiKVM release added webcam/mic support (the operator's own browser mic/camera can be injected into the target as a USB gadget device, negotiated entirely inside Janus's own signaling protocol), that gap meant any authenticated user, regardless of role, could inject audio/video into the target.
- kvmd now brokers this connection itself (`kvmd/apps/kvmd/api/janus.py`, `GET /janus/ws`) rather than nginx proxying straight through, specifically so it can inspect and act on the one Janus message type that matters: `{"janus": "message", "body": {"request": "watch", "params": {"audio": ..., "mic": ..., "camera": ...}}}`. `audio` is view-direction (listening to the target's own audio); `mic`/`camera` are inject-direction.
- Connecting at all requires `streamer.view`, checked the normal way via the `permission=` annotation on the proxy endpoint.
- Whether `mic`/`camera` are allowed to actually negotiate is checked separately, once per connection (same pattern as HID's per-connection cache, for the same latency reason), against a distinct `webcam` permission. If the connecting user lacks it, kvmd doesn't reject the connection — it silently forces `mic`/`camera` to `false` in the outgoing `watch` request before relaying it to the real Janus backend, so viewing keeps working and only injection is denied.
- **Known limitation**: this is enforced at the level of "may this connection ever negotiate mic/camera," checked once at connect time. It does not (yet) re-check mid-connection if permissions change, the same staleness caveat as HID's cache above.

**USC (Unix Socket Credentials — kvmd's term for local tools authenticated via the kernel-verified PID/UID/GID on a UNIX domain socket connection, rather than a password or token)** bypass authz checks entirely, at every one of the points above — consistent with kvmd's existing UNIX-socket trust model (a local, already-privileged process identified this way has no meaningful "role" to check).

## Naming: why some actions share a prefix and some deliberately don't

`roles[role].permissions` entries are matched as **prefixes** against the action string OPA receives (`startswith(action, perm)`) — a role holding `"switch.port"` matches both `switch.port.activate` and `switch.port.navigate`. This is intentional headroom, but it has a sharp edge worth understanding before you invent your own action names: **a role holding a short/generic permission automatically covers every longer action that starts with it, with no separate grant and no warning.**

This is why `streamer.view`, `snapshot`, and `webcam` are three independent action names rather than `streamer.view`/`streamer.snapshot`/`streamer.webcam`. They used to be a single flat `streamer` action; splitting `snapshot` (persists a frame, optionally with OCR text extraction — a materially more sensitive capability than transient viewing) and `webcam` (injecting audio/video into the target, an input-like capability rather than a viewing one) out from under a shared `streamer.` prefix means a role holding only `streamer.view` can never accidentally gain `snapshot` or `webcam` just because they happen to share a namespace. If you're adding your own finer-grained actions on top of this bundle, apply the same rule: only nest a new action under an existing prefix if you're comfortable with every role that already holds that prefix silently gaining it too.

**If you're upgrading from a bundle that used the old flat `streamer` action**: kvmd no longer sends `"streamer"` as an action string at all — it's `streamer.view`, `snapshot`, or `webcam` now. Any role or `port_permissions` entry that still lists the literal `"streamer"` will simply never match anything going forward (prefix matching only ever mattered for the *new*, longer, kvmd-emitted actions — an old bare `"streamer"` permission was never a prefix of the new independent `snapshot`/`webcam` names, so there's no silent-escalation risk from the rename itself, only a silent-*loss*-of-access risk if you don't update it). Replace `"streamer"` with `"streamer.view"` in your `data.json`/`devices/*/data.json`, and add `"snapshot"`/`"webcam"` explicitly to any role that should have them.

## Configuration

`kvmd.authz` in `/etc/kvmd/override.yaml`:

| Option | Default | Description |
|---|---|---|
| `enabled` | `false` | Turn authz enforcement on. |
| `opa_url` | `http://localhost:8181/v1/data/kvmd/authz/allow` | Where kvmd sends decision requests. Only change this if you've reconfigured `kvmd-authz.service`'s listen address. |
| `opa_timeout` | `0.5` | Seconds to wait for an OPA response before treating it as unreachable. |
| `device_id` | `""` | Identifies *this* device in the policy (`data.devices[device_id]`, and the `device_id` field logged in every decision). Defaults to the system hostname if empty. |
| `fail_open` | `true` | What happens if OPA is unreachable or errors: `true` grants access (availability-favouring — a network hiccup doesn't lock you out of your own KVM), `false` denies it (security-favouring). Every decision, including the fail-open/closed outcome, is written to the audit log either way — see [Audit logging](#audit-logging). |

```yaml
# /etc/kvmd/override.yaml
kvmd:
    authz:
        enabled: true
        device_id: pikvm-rack-a   # matches data/devices/pikvm-rack-a/data.json in the bundle
        fail_open: true
```

`kvmd-authz.service` itself is configured separately, in `/etc/kvmd/authz/opa-config.yaml` — see [Deployment](#deployment).

## The policy bundle

An OPA *bundle* is just a directory tree. kvmd's bundle has three parts:

```
/etc/kvmd/authz/bundle/
├── policy/
│   └── authz.rego              # the decision logic (ships as-is; you don't normally edit this)
├── data.json                   # global: users, roles, group_roles
└── devices/
    └── <device-id>/
        └── data.json           # per-device: port_permissions, standalone
```

### `data.json` — users, roles, and group-derived roles

```json
{
    "users": {
        "admin": { "roles": ["admin"] }
    },
    "group_roles": {
        "kvmd-admins": ["admin"],
        "kvmd-operators": ["operator"]
    },
    "roles": {
        "admin":    { "permissions": ["*"] },
        "operator": { "permissions": ["switch.port.activate", "switch.port.navigate", "switch.atx", "hid", "streamer.view", "snapshot", "msd.add", "msd.mount", "gpio"] },
        "viewer":   { "permissions": ["streamer.view"] }
    }
}
```

- **`users`** grants roles to specific, statically-provisioned accounts (kvmd's own `htpasswd` users, or any backend where you're not relying on group claims).
- **`roles`** defines what each role can do. `permissions` is a list of action-name *prefixes* — `"msd"` would match `msd.add`, `msd.mount`, `msd.delete`, `msd.read`, and `msd.reset` all at once, since they all start with that string; the specific `msd.add`/`msd.mount`/etc. names are used in the example above deliberately, one per capability, rather than the shorter shared prefix — see [Naming](#naming-why-some-actions-share-a-prefix-and-some-deliberately-dont) for why some actions are grouped under a shared prefix like this and some (`streamer.view`/`snapshot`/`webcam`) are kept deliberately independent. `"*"` grants everything — a superuser role, under whatever name you like (`admin`, `superuser`, `root` — the name is not special-cased anywhere).
- **`group_roles`** (see [Group-derived roles](#group-derived-roles) below) grants roles by IdP group membership instead of a static per-user entry.

A user's effective roles are the **union** of both sources — a user can be listed in `users` *and* belong to a group in `group_roles` at the same time; nothing about one downgrades the other.

### `devices/<device-id>/data.json` — per-device ACLs

Two independent things live here, and most devices need at most one of them:

**Standalone devices** (no KVM switch attached) need:
```json
{ "standalone": true }
```
Without this flag, a switch-mode device with no port selected yet (`active_port == null`) denies every non-navigation action — correct for "nobody's picked a target yet," but a permanent lockout on a device that has no switch at all. `standalone: true` tells the policy to gate on the user's *global* role permissions instead of per-port ACLs, since there are no ports to restrict.

**Switch devices** can optionally restrict *which ports* a role may use, via `port_permissions`:
```json
{
    "port_permissions": {
        "operator": {
            "0": ["streamer.view"],
            "1": ["streamer.view", "hid", "switch.atx", "switch.port.activate"]
        }
    }
}
```
Note that device-global actions (`gpio`, `log`, `export`, `switch.device.configure`, `switch.device.reset`, `msd.reset` — see [What's actually enforced](#whats-actually-enforced)) ignore `port_permissions` entirely, by design: they aren't tied to any port, so there's nothing for a per-port allowlist to restrict.
This is an **allowlist**: the moment a role appears under `port_permissions` *at all*, it can only reach the ports explicitly listed there, with only the actions listed for each port — every other port is denied outright for that role, even if the role's global `permissions` would otherwise allow the action. A role with no entry under `port_permissions` for a given device falls back to its plain global `permissions` on every port. Omit `port_permissions` entirely (or leave a device's `data.json` as `{}`) to give every role full access to every port, gated only by role.

## Group-derived roles

Any identity that can surface a list of group names can drive access this way — today that's [OIDC](oidc.md) (via `kvmd.oidc.groups_claim`) and LDAP (via `memberOf`), and it's automatic once you configure `group_roles`: nothing else changes.

```json
{
    "group_roles": {
        "kvmd-admins": ["admin"],
        "kvmd-operators": ["operator"]
    }
}
```

A user authenticated via OIDC with an ID token `groups` claim of `["kvmd-operators"]` gets the `operator` role — with **no entry in `users` at all**. This is what makes fleet-wide access management practical: add someone to a group at your IdP, and every device whose bundle maps that group to a role picks it up on their next login, with no per-device or per-user edits anywhere in kvmd's own config.

If a user's groups don't match anything in `group_roles`, they simply get whatever their static `users` entry (if any) provides — falling all the way through to "no access" is a normal, safe outcome, not an error.

## Worked examples

### 1. Single standalone PiKVM, three static roles

No switch, no fleet, no OIDC — just local accounts with different levels of access.

`configs/kvmd/authz/bundle/data.json`:
```json
{
    "users": {
        "admin":    { "roles": ["admin"] },
        "operator": { "roles": ["operator"] },
        "guest":    { "roles": ["viewer"] }
    },
    "roles": {
        "admin":    { "permissions": ["*"] },
        "operator": { "permissions": ["hid", "streamer.view", "snapshot", "switch.atx", "msd.add", "msd.mount"] },
        "viewer":   { "permissions": ["streamer.view"] }
    }
}
```

`configs/kvmd/authz/bundle/devices/my-pikvm/data.json`:
```json
{ "standalone": true }
```

`/etc/kvmd/override.yaml`:
```yaml
kvmd:
    authz:
        enabled: true
        device_id: my-pikvm
```

Result: `admin` can do anything, including power-cycling the target via ATX; `operator` can drive HID and watch the stream but not touch ATX power; `guest` can only watch.

### 2. KVM switch with two isolated teams

A `pikvm-switch` device with 4 downstream ports. Team "wintel" should only ever touch ports 0-1; team "lintel" only ports 2-3 — and neither team should be able to activate, view, or send input to the other's ports, even though both hold otherwise-similar roles.

`data.json`:
```json
{
    "users": {
        "wbob":   { "roles": ["wintel-admin"] },
        "lcarol": { "roles": ["lintel-admin"] }
    },
    "roles": {
        "wintel-admin": { "permissions": ["switch.port.activate", "switch.port.navigate", "switch.atx", "hid", "streamer.view"] },
        "lintel-admin": { "permissions": ["switch.port.activate", "switch.port.navigate", "hid", "streamer.view"] }
    }
}
```

`devices/pikvm-switch/data.json`:
```json
{
    "port_permissions": {
        "wintel-admin": {
            "0": ["streamer.view", "hid", "switch.atx", "switch.port.activate", "switch.port.navigate"],
            "1": ["streamer.view", "hid", "switch.atx", "switch.port.activate", "switch.port.navigate"]
        },
        "lintel-admin": {
            "2": ["streamer.view", "hid", "switch.port.activate", "switch.port.navigate"],
            "3": ["streamer.view", "hid", "switch.port.activate", "switch.port.navigate"]
        }
    }
}
```

Because `port_permissions` is an allowlist, `wbob` (role `wintel-admin`) is now confined to ports 0-1 — the global role `permissions` list is irrelevant once a role appears here at all. `lcarol` is confined to ports 2-3, and additionally never gets `switch.atx` on *any* port, since that action isn't in her role's port entries — note it's also absent from her role's global permissions, so this isn't even doing extra work; it's consistent either way.

### 3. Fleet-wide roles via OIDC groups, no per-device edits

Twenty PiKVMs, all pulling policy from a central bundle server, all sharing the same two IdP groups for role assignment — see [OIDC: Registering kvmd as a client](oidc.md#registering-kvmd-as-a-client) for the IdP-side setup.

`data.json` (shared across the whole fleet):
```json
{
    "group_roles": {
        "kvmd-fleet-admins": ["admin"],
        "kvmd-fleet-operators": ["operator"]
    },
    "roles": {
        "admin":    { "permissions": ["*"] },
        "operator": { "permissions": ["hid", "streamer.view", "switch.atx", "switch.port.activate", "switch.port.navigate"] }
    }
}
```

Every device's own `devices/<device-id>/data.json` only needs device-specific ACLs (port restrictions, `standalone`) if any — role *assignment* itself lives entirely in the shared `group_roles` block, so adding a new engineer to the `kvmd-fleet-operators` group at the IdP gives them operator access to every device in the fleet the next time they log in, with zero kvmd-side config changes anywhere.

`configs/kvmd/authz/opa-config.yaml` on each device:
```yaml
services:
  bundle_server:
    url: https://policy.example.com
bundles:
  kvmd_remote:
    service: bundle_server
    resource: /bundles/kvmd.tar.gz
    polling:
      min_delay_seconds: 60
      max_delay_seconds: 120
```

Build the bundle to publish with `make bundle` from `configs/kvmd/authz/` (produces `kvmd-authz.tar.gz` — upload that to your bundle server's `/bundles/` directory). OPA polls for updates and merges the remote bundle over the device's local one, so the local bundle remains the fallback if the bundle server is briefly unreachable — a device never loses its policy just because the server's down.

## Deployment

For local iteration against a single device, `./deploy-authz.sh <host>` pushes the OPA binary (if missing), the local bundle, the `kvmd-authz.service` unit, and the Python source files this feature touches, over SSH — see the script's own header comment for exactly what it does and doesn't cover (notably: **not** the nginx config change for `/streamer`, which needs a full package rebuild or a manual copy).

For production, the bundle and `kvmd-authz.service` ship as part of the `kvmd` package build; only `kvmd.authz.enabled` and the bundle's `data.json`/`devices/*` need to be populated per-deployment.

## Testing your policy

- **`make test`** (from `configs/kvmd/authz/`) — runs the native `opa test` unit suite (`testenv/authz-tests/authz_test.rego`) against the policy directly, no containers, sub-second.
- **`make authz-test`** (from the repo root) — runs the same policy against a real, ephemeral OPA server via `testcontainers` (`testenv/authz-tests/test_policy.py`), the same way it'll actually be queried in production.
- **`make eval USER=bob DEVICE=my-pikvm ACTION=hid.write PORT=1`** (from `configs/kvmd/authz/`) — evaluates a single decision against the bundled data with no server running at all, useful for quickly checking what a specific user/device/action combination resolves to while editing `data.json`.

Before trusting a change to enforcement on any specific action, remember the [What's actually enforced](#whats-actually-enforced) table above: the policy test suites above only prove OPA's *decision* is correct for a given input — they don't exercise kvmd's HTTP/WebSocket layer at all. `testenv/tests/apps/kvmd/test_authz_wiring.py` is the one that proves kvmd's request path actually calls OPA in the first place, including a static regression guard (`test_ok__expected_http_actions_are_still_wired`) that fails if any endpoint listed in the table above ever loses its `permission=` annotation; run it (via `tox -e pytest`, or directly) after touching anything in `kvmd/apps/kvmd/api/*.py` or `server.py`'s permission-checking code.

## Permission-aware UI

By default, kvmd's web UI shows every control to every role and only discovers a denial when a click 403s. `GET /api/authz/permissions` lets the frontend ask in advance instead: it returns the caller's own effective permission set (and, for switch devices, which specific ports they may activate), and the UI disables controls the caller can't use rather than showing them as clickable. This is purely cosmetic — the response reuses the exact same policy evaluation as `allow` (via rego's `with` keyword), so it can never drift from what a real request would actually decide, but it is never itself the enforcement boundary; every action is still independently re-checked by OPA on the real request regardless of what the UI shows.

```
GET /api/authz/permissions?candidate_ports=0,1,2,3
→ {"permissions": ["hid", "streamer.view", ...] | null, "activatable_ports": [0, 2] | null}
```

`candidate_ports` is supplied by the caller — the switch's real port numbers, which the authz bundle has no independent knowledge of. A `null` field (rather than an array) means authz is disabled server-side, or the request failed — the UI treats that as "don't restrict anything," matching what a real request would do in both cases.

A role whose permissions follow the currently active port (most of them do — see [What's actually enforced](#whats-actually-enforced)) will see the UI update live as the active port changes, including when switched by someone else or something else entirely, not just by the logged-in user themselves. A role denied `hid` sees a "View only" banner across the video stream, since denied keyboard/mouse input is dropped silently server-side rather than erroring on every keystroke — the banner is the only user-facing signal that a session is view-only.

## Audit logging

Every authz decision — allowed or denied, including OPA-unreachable fail-open/fail-closed outcomes — is written to the `kvmd.audit` logger:
```
user='bob' groups=('kvmd-operators',) action='hid' resource={'active_port': 1} device='pikvm-rack-a' allowed=True opa_error=False source_ip='10.0.0.5' user_agent='Mozilla/5.0...'
```
This is a standard Python logger under kvmd's logging configuration — route it to a file, syslog, or a log-shipping pipeline the same way you would any other kvmd log stream.

## Debug logging

The audit log above records every *decision*, but not the raw request/response exchanged with OPA — for diagnosing why a decision came out the way it did (a `port_permissions` entry not matching the port you expected, a group not resolving to the role you thought it would), turn on debug logging:

```yaml
# /etc/kvmd/override.yaml
logging:
    level: debug
```

This is a top-level option (a sibling of `kvmd:`, not nested under it) and applies to the whole process, not just authz — expect more output from everything, not only this feature. `systemctl restart kvmd`, reproduce the request, then `journalctl -u kvmd`. At debug level you get the exact `input` document sent to OPA (`user`, `user_groups`, `device_id`, `action`, `resource`) and the raw `data` response it returned, in addition to the one-line audit record above — usually enough to tell whether the problem is on kvmd's side (wrong groups sent) or the policy's side (right input, wrong `data.json`).

## See also

- [OIDC authentication](oidc.md) — the primary source of group claims for fleet-wide role assignment.
