# OPA policy unit tests for kvmd authorization.
# Run with: make test  (from configs/kvmd/authz/)
# Or directly: opa test configs/kvmd/authz/bundle/policy/authz.rego testenv/authz-tests/authz_test.rego --verbose
#
# All tests go through _eval(), which overrides the specific base-data paths
# the policy reads (data.users, data.roles, data.devices, data.group_roles)
# rather than `with data as <whole object>`. Replacing the entire data root
# from inside a rule that itself lives under `data` (every test rule here
# does — data.kvmd.authz_test.test_x) makes OPA's compiler treat the rule as
# depending on its own (about-to-be-replaced) output, which newer OPA
# versions correctly reject as a recursion error. Scoped `with data.<path>`
# overrides only replace those specific base documents and don't have this
# problem.

package kvmd.authz_test

import rego.v1
import data.kvmd.authz

_eval(users, roles, devices, group_roles, inp) := result if {
    result := authz.allow with data.users as users
                           with data.roles as roles
                           with data.devices as devices
                           with data.group_roles as group_roles
                           with input as inp
}

# =====
# Shared test data
# =====

_users := {
    "alice":        {"roles": ["superuser"]},
    "bob":          {"roles": ["operator"]},
    "carol":        {"roles": ["viewer"]},
    "multirole":    {"roles": ["operator", "viewer"]},
    "wintel_bob":   {"roles": ["wintel-admin"]},
    "lintel_carol": {"roles": ["lintel-admin"]},
}

_roles := {
    "superuser":     {"permissions": ["*"]},
    "operator":      {"permissions": ["switch.port.activate", "switch.port.navigate", "hid", "switch.atx", "streamer"]},
    "viewer":        {"permissions": ["streamer"]},
    "wintel-admin":  {"permissions": ["switch.port.activate", "hid", "switch.atx", "streamer"]},
    "lintel-admin":  {"permissions": ["switch.port.activate", "hid", "streamer"]},
}

# Device with per-port role restrictions on rack-a.
# On rack-b: no port_permissions → role permissions apply globally.
_devices := {
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
}

# =====
# Superuser bypass: any role with "*" permission bypasses per-port ACLs.
# The role name is arbitrary — "superuser", "admin", "root", anything.
# =====

test_superuser_can_activate_any_port if {
    _eval(_users, _roles, _devices, {}, {"user": "alice", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 3}})
}

test_superuser_can_use_hid_on_any_port if {
    _eval(_users, _roles, _devices, {}, {"user": "alice", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 0}})
}

test_superuser_allowed_on_rack_b if {
    _eval(_users, _roles, _devices, {}, {"user": "alice", "device_id": "rack-b", "action": "hid.write", "resource": {"active_port": 0}})
}

# =====
# Custom roles: wintel-admin and lintel-admin with per-device port ACLs
# =====

_devices_with_teams := object.union(_devices, {
    "rack-a": {"port_permissions": object.union(
        _devices["rack-a"].port_permissions,
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
})

test_wintel_admin_can_activate_wintel_port if {
    _eval(_users, _roles, _devices_with_teams, {}, {"user": "wintel_bob", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 0}})
}

test_wintel_admin_cannot_activate_lintel_port if {
    not _eval(_users, _roles, _devices_with_teams, {}, {"user": "wintel_bob", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 2}})
}

test_lintel_admin_can_use_hid_on_lintel_port if {
    _eval(_users, _roles, _devices_with_teams, {}, {"user": "lintel_carol", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 3}})
}

test_lintel_admin_cannot_use_hid_on_wintel_port if {
    not _eval(_users, _roles, _devices_with_teams, {}, {"user": "lintel_carol", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 0}})
}

test_lintel_admin_no_atx_even_on_own_ports if {
    # lintel-admin role doesn't include switch.atx
    not _eval(_users, _roles, _devices_with_teams, {}, {"user": "lintel_carol", "device_id": "rack-a", "action": "switch.atx", "resource": {"active_port": 2}})
}

# =====
# Operator on rack-a: per-port restrictions apply
# =====

test_operator_streamer_on_port_0 if {
    _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-a", "action": "streamer", "resource": {"active_port": 0}})
}

test_operator_no_hid_on_port_0 if {
    not _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 0}})
}

test_operator_hid_on_port_1 if {
    _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 1}})
}

test_operator_hid_on_port_2 if {
    _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 2}})
}

test_operator_no_atx_on_port_2 if {
    not _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-a", "action": "switch.atx", "resource": {"active_port": 2}})
}

test_operator_can_activate_port_1 if {
    _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 1}})
}

test_operator_cannot_activate_port_0 if {
    not _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 0}})
}

# =====
# Operator on rack-b: no port_permissions → global role permissions apply
# =====

test_operator_rack_b_hid_on_any_port if {
    _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-b", "action": "hid.write", "resource": {"active_port": 0}})
}

test_operator_rack_b_can_activate_any_port if {
    _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-b", "action": "switch.port.activate", "resource": {"port": 5}})
}

# =====
# Viewer: stream-only everywhere
# =====

test_viewer_can_stream if {
    _eval(_users, _roles, _devices, {}, {"user": "carol", "device_id": "rack-a", "action": "streamer", "resource": {"active_port": 0}})
}

test_viewer_no_hid if {
    not _eval(_users, _roles, _devices, {}, {"user": "carol", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": 1}})
}

test_viewer_cannot_activate_port if {
    not _eval(_users, _roles, _devices, {}, {"user": "carol", "device_id": "rack-a", "action": "switch.port.activate", "resource": {"port": 1}})
}

# =====
# Navigation: allowed when no port active; gated by active port otherwise
# =====

test_navigate_allowed_with_no_active_port if {
    _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-a", "action": "switch.port.navigate", "resource": {"active_port": null}})
}

test_navigate_denied_when_active_port_has_no_navigate_perm if {
    # operator has no "switch.port.navigate" listed for port 0 on rack-a
    not _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-a", "action": "switch.port.navigate", "resource": {"active_port": 0}})
}

# =====
# Unknown user is always denied
# =====

test_unknown_user_denied if {
    not _eval(_users, _roles, _devices, {}, {"user": "unknown", "device_id": "rack-a", "action": "streamer", "resource": {"active_port": 0}})
}

# =====
# Switch mode: no active port → non-navigate actions denied (no port selected yet)
# =====

test_hid_denied_with_no_active_port if {
    not _eval(_users, _roles, _devices, {}, {"user": "bob", "device_id": "rack-a", "action": "hid.write", "resource": {"active_port": null}})
}

# =====
# Standalone mode: active_port is always null (no switch); standalone: true
# enables role-based access using global role permissions.
# =====

_standalone_devices := {
    "standalone-pikvm": {"standalone": true},
    "switch-pikvm":     {},
}

test_standalone_operator_can_use_hid if {
    _eval(_users, _roles, _standalone_devices, {}, {"user": "bob", "device_id": "standalone-pikvm", "action": "hid.write", "resource": {"active_port": null}})
}

test_standalone_viewer_can_stream if {
    _eval(_users, _roles, _standalone_devices, {}, {"user": "carol", "device_id": "standalone-pikvm", "action": "streamer", "resource": {"active_port": null}})
}

test_standalone_viewer_cannot_use_hid if {
    # viewer role has no hid permission — role still gates access
    not _eval(_users, _roles, _standalone_devices, {}, {"user": "carol", "device_id": "standalone-pikvm", "action": "hid.write", "resource": {"active_port": null}})
}

test_standalone_activate_denied if {
    # switch.port.activate makes no sense on a standalone device
    not _eval(_users, _roles, _standalone_devices, {}, {"user": "bob", "device_id": "standalone-pikvm", "action": "switch.port.activate", "resource": {"port": 0}})
}

test_switch_device_without_standalone_flag_still_denies if {
    # regression: non-standalone device + null active_port must still deny
    not _eval(_users, _roles, _standalone_devices, {}, {"user": "bob", "device_id": "switch-pikvm", "action": "hid.write", "resource": {"active_port": null}})
}

# =====
# Group-derived roles: a user with no per-user data.users entry (e.g. an
# OIDC-only identity) gets roles via data.group_roles[group] matched against
# input.user_groups, on equal footing with statically-provisioned users.
# =====

_group_roles := {
    "kvmd-operators": ["operator"],
    "kvmd-viewers":   ["viewer"],
}

test_group_role_grants_operator_access if {
    # "dave" has no data.users entry at all — only an OIDC group claim.
    _eval(_users, _roles, _devices, _group_roles, {
        "user": "dave", "user_groups": ["kvmd-operators"],
        "device_id": "rack-b", "action": "hid.write", "resource": {"active_port": 0},
    })
}

test_group_role_respects_role_permissions if {
    # kvmd-viewers only grants the viewer role — still no hid access.
    not _eval(_users, _roles, _devices, _group_roles, {
        "user": "dave", "user_groups": ["kvmd-viewers"],
        "device_id": "rack-b", "action": "hid.write", "resource": {"active_port": 0},
    })
}

test_group_role_unmapped_group_denied if {
    # A group with no data.group_roles entry grants nothing.
    not _eval(_users, _roles, _devices, _group_roles, {
        "user": "dave", "user_groups": ["some-other-group"],
        "device_id": "rack-b", "action": "hid.write", "resource": {"active_port": 0},
    })
}

test_static_and_group_roles_combine if {
    # "bob" is statically an operator (data.users) AND in kvmd-viewers (group)
    # — he should still get full operator access; the union doesn't downgrade.
    _eval(_users, _roles, _devices, _group_roles, {
        "user": "bob", "user_groups": ["kvmd-viewers"],
        "device_id": "rack-b", "action": "switch.port.activate", "resource": {"port": 5},
    })
}

test_no_user_groups_in_input_does_not_error if {
    # input.user_groups entirely absent (e.g. an older kvmd client) must not
    # error — it should behave exactly like static-only per-user roles.
    _eval(_users, _roles, _devices, _group_roles, {"user": "bob", "device_id": "rack-b", "action": "hid.write", "resource": {"active_port": 0}})
}
