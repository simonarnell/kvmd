# kvmd authorization policy.
#
# This file is bundled and served by your central bundle server.
# Changes propagate to all fleet devices within the polling interval.
#
# Bundle structure (OPA requires data files named data.json; the directory
# path determines where the content lands in the data document):
#
#   policy/authz.rego                      <- this file
#   data/data.json                         <- global users + roles
#   data/devices/<device-id>/data.json     <- per-device config
#
#   data/data.json                        →  data.users, data.roles
#   data/devices/switch-example/data.json →  data.devices["switch-example"]
#
# Roles can be granted two ways: statically per-user (data.users[user].roles,
# for htpasswd/LDAP/RADIUS/PAM-backed accounts provisioned directly in the
# bundle), or via group membership (data.group_roles[group], matched against
# input.user_groups — the group claims from an OIDC ID token, or any auth
# backend that surfaces group membership). Both feed the same _user_roles set
# below, so a user can hold roles from either or both sources at once. See
# the _user_roles helper for details.
#
# ---------------------------------------------------------------------------
# Two deployment modes
# ---------------------------------------------------------------------------
#
# SWITCH MODE (default)
#   The PiKVM is connected to a KVM switch. kvmd injects the currently
#   selected port number as active_port (an integer). When no port has been
#   selected yet, active_port is null, and all non-navigate actions are
#   denied until the user activates a port — this prevents accidental access
#   before a target is chosen.
#
#   Per-device config: optionally add port_permissions to restrict which
#   roles can use which ports.  port_permissions acts as an allowlist: once
#   a role is listed, it may only access the ports explicitly named.
#
#     data/devices/switch-example/data.json:
#     { "port_permissions": { "operator": { "0": ["streamer.view"], ... } } }
#
# STANDALONE MODE
#   The PiKVM operates without a switch. There are no ports, so active_port
#   is always null. To allow non-superuser roles to use the device, add
#   "standalone": true to the device's data.json. Actions are then gated
#   on the user's global role permissions (per-port ACLs do not apply).
#
#     data/devices/my-standalone-pikvm/data.json:
#     { "standalone": true }
#
# Without the standalone flag, a device with active_port == null will deny
# all non-navigate actions for non-superuser roles. This is intentional for
# switch devices where a port must be selected first.

package kvmd.authz

import rego.v1

default allow := false

# =====
# Superuser bypass: any role whose permissions include "*" bypasses all
# per-port checks. Role names are entirely user-defined — there is no
# hardcoded "admin" name. Call it "admin", "superuser", "wintel-root",
# whatever fits your organisation.
# =====

allow if {
    some role in _user_roles
    "*" in data.roles[role].permissions
}

# =====
# Switch port activation: target port (input.resource.port) must be
# permitted for at least one of the user's roles.
# =====

allow if {
    input.action == "switch.port.activate"
    not data.devices[input.device_id].standalone
    some role in _user_roles
    _role_has_port_permission(role, input.resource.port, "switch.port.activate")
}

# =====
# Port navigation (prev/next): gated on the active port for the user's role.
# If no port is active yet, allow — there's nothing to restrict against.
# =====

allow if {
    input.action == "switch.port.navigate"
    input.resource.active_port == null
}

allow if {
    input.action == "switch.port.navigate"
    input.resource.active_port != null
    some role in _user_roles
    _role_has_port_permission(role, input.resource.active_port, "switch.port.navigate")
}

# =====
# All other actions (hid, streamer.view, snapshot, webcam, switch.atx,
# switch.port.configure, msd.add/mount/delete/read, etc.)
# are gated on the currently active port. kvmd injects active_port into
# input.resource automatically for every permission-annotated endpoint.
#
# active_port == null means no port has been selected yet (switch mode) or
# the device has no switch (standalone mode). The standalone rule below
# handles the latter case; this rule only fires when active_port is set.
# =====

allow if {
    input.action != "switch.port.activate"
    input.action != "switch.port.navigate"
    input.resource.active_port != null
    some role in _user_roles
    _role_has_port_permission(role, input.resource.active_port, input.action)
}

# =====
# Standalone PiKVM (no switch): active_port is always null because there is
# no switch port to select. Mark the device standalone: true in its
# data/devices/<device-id>/data.json to enable role-based access without
# per-port ACLs.
#
# Without this flag, active_port == null causes all non-navigate actions to
# be denied for non-superuser roles — correct for a switch device where no
# port has been selected yet, but a permanent lockout on standalone devices.
# =====

allow if {
    input.action != "switch.port.activate"
    input.action != "switch.port.navigate"
    input.resource.active_port == null
    data.devices[input.device_id].standalone == true
    some role in _user_roles
    _role_allows(role, input.action)
}

# =====
# Device-global actions: unlike hid/streamer.view/switch.atx/msd.add|mount|
# delete|read (which follow whichever port is currently active, same as the
# KVM switch's physical USB routing), these have no relationship to port
# selection at all -- GPIO pins, the log/metrics streams, and resetting a
# whole subsystem (switch controller, MSD) belong to the PiKVM board itself,
# not to any one port. Gating them on active_port would wrongly deny them on
# a switch-mode device before any port is selected, even though the action
# has nothing to do with a port. Still gated on the role actually holding
# the permission -- just not on active_port/standalone state.
# =====

allow if {
    input.action in {"gpio", "log", "export", "switch.device.configure", "switch.device.reset", "msd.reset"}
    some role in _user_roles
    _role_allows(role, input.action)
}

# =====
# Helpers
# =====

# The set of roles granted to the current request, from two sources:
#   1. Static per-user roles: data.users[input.user].roles (existing config,
#      e.g. htpasswd/LDAP/RADIUS/PAM users provisioned directly in the bundle).
#   2. Group-derived roles: for every group in input.user_groups (populated
#      by kvmd from the caller's session — OIDC ID token claims, or any auth
#      backend that surfaces group membership), any role listed in
#      data.group_roles[group] is granted too.
#
# input.user_groups is always present (kvmd sends [] when the session has no
# groups), so this is purely additive — existing per-user bundles work
# unchanged with no group_roles configured at all.
#
#   data/data.json:
#   { "group_roles": { "admins": ["superuser"], "operators": ["operator"] } }

_user_roles contains role if {
    some role in data.users[input.user].roles
}

_user_roles contains role if {
    some group in input.user_groups
    some role in data.group_roles[group]
}

# Check whether a role permits an action on a specific port.
#
# Two tiers:
#   1. If port_permissions[role] is configured for this device, the role may
#      ONLY access the ports explicitly listed there, with the permissions
#      listed for each port.  Unlisted ports are denied entirely.
#   2. If port_permissions[role] is NOT configured for this device at all,
#      fall back to the role's global permissions (from data.roles) for any
#      port.
#
# This means port_permissions acts as an allowlist of ports for a role:
# once you add any port_permissions entry for a role, that role loses access
# to all ports not explicitly listed.

_role_has_port_permission(role, port, action) if {
    port_str := sprintf("%d", [port])
    perms := data.devices[input.device_id].port_permissions[role][port_str]
    _action_matches_any(action, perms)
}

_role_has_port_permission(role, port, action) if {
    not data.devices[input.device_id].port_permissions[role]
    _role_allows(role, action)
}

_role_allows(role, action) if {
    "*" in data.roles[role].permissions
}

_role_allows(role, action) if {
    some perm in data.roles[role].permissions
    perm != "*"
    startswith(action, perm)
}

_action_matches_any(action, perms) if {
    "*" in perms
}

_action_matches_any(action, perms) if {
    some perm in perms
    perm != "*"
    startswith(action, perm)
}
