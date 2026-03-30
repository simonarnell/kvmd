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
#   data/data.json            →  data.users, data.roles
#   data/devices/pikvm-rack-a/data.json  →  data.devices["pikvm-rack-a"]
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
#   roles can use which ports.
#
#     data/devices/pikvm-rack-a/data.json:
#     { "port_permissions": { "operator": { "0": ["streamer"], ... } } }
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
    some role in data.users[input.user].roles
    "*" in data.roles[role].permissions
}

# =====
# Switch port activation: target port (input.resource.port) must be
# permitted for at least one of the user's roles.
# =====

allow if {
    input.action == "switch.port.activate"
    some role in data.users[input.user].roles
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
    some role in data.users[input.user].roles
    _role_has_port_permission(role, input.resource.active_port, "switch.port.navigate")
}

# =====
# All other actions (hid, streamer, switch.atx, switch.port.configure, etc.)
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
    some role in data.users[input.user].roles
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
    some role in data.users[input.user].roles
    _role_allows(role, input.action)
}

# =====
# Helpers
# =====

# Check whether a role permits an action on a specific port.
#
# Two tiers:
#   1. Device-level port_permissions[role][port] overrides the role's global
#      permissions for that port on that device.
#      If a per-port override exists, only those listed permissions apply.
#   2. If no per-port override exists for this role+port, fall back to the
#      role's global permissions (from data.roles).
#
# This means: adding port_permissions for a role RESTRICTS it per-port.
# Roles with no port_permissions entry retain their global permissions on all ports.

_role_has_port_permission(role, port, action) if {
    port_str := sprintf("%d", [port])
    perms := data.devices[input.device_id].port_permissions[role][port_str]
    _action_matches_any(action, perms)
}

_role_has_port_permission(role, port, action) if {
    port_str := sprintf("%d", [port])
    not data.devices[input.device_id].port_permissions[role][port_str]
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
