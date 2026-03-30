# OPA policy tests for kvmd authorization.
# Run with: opa test policy/ data/ -v
# (from the configs/kvmd/authz/ directory with policy/ and data/ subdirs,
#  or point opa test at the individual files)

package kvmd.authz_test

import rego.v1

# =====
# Shared test data
# =====

_users := {
    "users": {
        "alice":        {"roles": ["superuser"]},
        "bob":          {"roles": ["operator"]},
        "carol":        {"roles": ["viewer"]},
        "multirole":    {"roles": ["operator", "viewer"]},
        "wintel_bob":   {"roles": ["wintel-admin"]},
        "lintel_carol": {"roles": ["lintel-admin"]},
    },
    "roles": {
        "superuser":     {"permissions": ["*"]},
        "operator":      {"permissions": ["switch.port.activate", "switch.port.navigate", "hid", "switch.atx", "streamer"]},
        "viewer":        {"permissions": ["streamer"]},
        "wintel-admin":  {"permissions": ["switch.port.activate", "hid", "switch.atx", "streamer"]},
        "lintel-admin":  {"permissions": ["switch.port.activate", "hid", "streamer"]},
    },
}

# Device with per-port role restrictions on rack-a.
# On rack-b: no port_permissions → role permissions apply globally.
_devices := {
    "devices": {
        "rack-a": {
            "port_permissions": {
                "operator": {
                    "0": ["streamer"],
                    "1": ["streamer", "hid", "switch.atx", "switch.port.activate"],
                    "2": ["streamer", "hid", "switch.port.activate"],
                },
                "viewer": {
                    "0": ["streamer"],
                    "1": ["streamer"],
                },
            },
        },
        "rack-b": {},
    },
}

_data := object.union(_users, _devices)

# =====
# Superuser bypass: any role with "*" permission bypasses per-port ACLs.
# The role name is arbitrary — "superuser", "admin", "root", anything.
# =====

test_superuser_can_activate_any_port if {
    authz.allow with input as {"user": "alice", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 3}}
                 with data as _data
}

test_superuser_can_use_hid_on_any_port if {
    authz.allow with input as {"user": "alice", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 0}}
                 with data as _data
}

test_superuser_allowed_on_rack_b if {
    authz.allow with input as {"user": "alice", "device_id": "rack-b", "action": "hid.write", "resource": {"active_port": 0}}
                 with data as _data
}

# =====
# Custom roles: wintel-admin and lintel-admin with per-device port ACLs
# =====

_devices_with_teams := object.union(_devices, {"devices": {
    "rack-a": {"port_permissions": object.union(
        _devices.devices["rack-a"].port_permissions,
        {
            "wintel-admin": {
                "0": ["streamer", "hid", "switch.atx", "switch.port.activate"],
                "1": ["streamer", "hid", "switch.atx", "switch.port.activate"],
            },
            "lintel-admin": {
                "2": ["streamer", "hid", "switch.port.activate"],
                "3": ["streamer", "hid", "switch.port.activate"],
            },
        }
    )},
}})

_data_teams := object.union(_users, _devices_with_teams)

test_wintel_admin_can_activate_wintel_port if {
    authz.allow with input as {"user": "wintel_bob", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 0}}
                 with data as _data_teams
}

test_wintel_admin_cannot_activate_lintel_port if {
    not authz.allow with input as {"user": "wintel_bob", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 2}}
                    with data as _data_teams
}

test_lintel_admin_can_use_hid_on_lintel_port if {
    authz.allow with input as {"user": "lintel_carol", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 3}}
                 with data as _data_teams
}

test_lintel_admin_cannot_use_hid_on_wintel_port if {
    not authz.allow with input as {"user": "lintel_carol", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 0}}
                    with data as _data_teams
}

test_lintel_admin_no_atx_even_on_own_ports if {
    # lintel-admin role doesn't include switch.atx
    not authz.allow with input as {"user": "lintel_carol", "device_id": "rack-a", "action": "switch.atx", "resource": {"active_port": 2}}
                    with data as _data_teams
}

# =====
# Operator on rack-a: per-port restrictions apply
# =====

test_operator_streamer_on_port_0 if {
    authz.allow with input as {"user": "bob", "device_id": "rack-a", "action": "streamer", "resource": {"active_port": 0}}
                 with data as _data
}

test_operator_no_hid_on_port_0 if {
    not authz.allow with input as {"user": "bob", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 0}}
                    with data as _data
}

test_operator_hid_on_port_1 if {
    authz.allow with input as {"user": "bob", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 1}}
                 with data as _data
}

test_operator_hid_on_port_2 if {
    authz.allow with input as {"user": "bob", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 2}}
                 with data as _data
}

test_operator_no_atx_on_port_2 if {
    not authz.allow with input as {"user": "bob", "device_id": "rack-a", "action": "switch.atx", "resource": {"active_port": 2}}
                    with data as _data
}

test_operator_can_activate_port_1 if {
    authz.allow with input as {"user": "bob", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 1}}
                 with data as _data
}

test_operator_cannot_activate_port_0 if {
    not authz.allow with input as {"user": "bob", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 0}}
                    with data as _data
}

# =====
# Operator on rack-b: no port_permissions → global role permissions apply
# =====

test_operator_rack_b_hid_on_any_port if {
    authz.allow with input as {"user": "bob", "device_id": "rack-b", "action": "hid.write", "resource": {"active_port": 0}}
                 with data as _data
}

test_operator_rack_b_can_activate_any_port if {
    authz.allow with input as {"user": "bob", "device_id": "rack-b", "action": "switch.port.activate", "resource": {"port": 5}}
                 with data as _data
}

# =====
# Viewer: stream-only everywhere
# =====

test_viewer_can_stream if {
    authz.allow with input as {"user": "carol", "device_id": "rack-a", "action": "streamer", "resource": {"active_port": 0}}
                 with data as _data
}

test_viewer_no_hid if {
    not authz.allow with input as {"user": "carol", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 1}}
                    with data as _data
}

test_viewer_cannot_activate_port if {
    not authz.allow with input as {"user": "carol", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 1}}
                    with data as _data
}

# =====
# Navigation: allowed when no port active; gated by active port otherwise
# =====

test_navigate_allowed_with_no_active_port if {
    authz.allow with input as {"user": "bob", "device_id": "rack-a", "action": "switch.port.navigate", "resource": {"active_port": null}}
                 with data as _data
}

test_navigate_denied_when_active_port_has_no_navigate_perm if {
    # operator has no "switch.port.navigate" listed for port 0 on rack-a
    not authz.allow with input as {"user": "bob", "device_id": "rack-a", "action": "switch.port.navigate", "resource": {"active_port": 0}}
                    with data as _data
}

# =====
# Unknown user is always denied
# =====

test_unknown_user_denied if {
    not authz.allow with input as {"user": "unknown", "device_id": "rack-a", "action": "streamer", "resource": {"active_port": 0}}
                    with data as _data
}

# =====
# Switch mode: no active port → non-navigate actions denied (no port selected yet)
# =====

test_hid_denied_with_no_active_port if {
    not authz.allow with input as {"user": "bob", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": null}}
                    with data as _data
}

# =====
# Standalone mode: active_port is always null (no switch); standalone: true
# enables role-based access using global role permissions.
# =====

_standalone_data := object.union(_users, {"devices": {
    "standalone-pikvm": {"standalone": true},
    "switch-pikvm":     {},
}})

test_standalone_operator_can_use_hid if {
    authz.allow with input as {"user": "bob", "device_id": "standalone-pikvm", "action": "hid.write", "resource": {"active_port": null}}
                with data as _standalone_data
}

test_standalone_viewer_can_stream if {
    authz.allow with input as {"user": "carol", "device_id": "standalone-pikvm", "action": "streamer", "resource": {"active_port": null}}
                with data as _standalone_data
}

test_standalone_viewer_cannot_use_hid if {
    # viewer role has no hid permission — role still gates access
    not authz.allow with input as {"user": "carol", "device_id": "standalone-pikvm", "action": "hid.write", "resource": {"active_port": null}}
                    with data as _standalone_data
}

test_standalone_activate_denied if {
    # switch.port.activate makes no sense on a standalone device
    not authz.allow with input as {"user": "bob", "device_id": "standalone-pikvm", "action": "switch.port.activate", "resource": {"port": 0}}
                    with data as _standalone_data
}

test_switch_device_without_standalone_flag_still_denies if {
    # regression: non-standalone device + null active_port must still deny
    not authz.allow with input as {"user": "bob", "device_id": "switch-pikvm", "action": "hid.write", "resource": {"active_port": null}}
                    with data as _standalone_data
}
