Global users and roles. Edit `data.json` to match your organisation.

Per-device config lives in `devices/<device-id>/data.json`. See `policy/authz.rego` for full
documentation of the policy logic, and `docs/authz.md` (repo root) for the full reference with
worked examples.

Roles can come from `users{}` (static, per-account) and/or `group_roles{}` (dynamic, via IdP
group membership claims e.g. from OIDC) — a user gets the union of both.

This file is deliberately **not** JSON (unlike `data.json`) — OPA's bundle loader only merges
`.json`/`.rego` files under the manifest's declared `roots` into the policy's `data` document,
so a stray top-level key (like an inline `_comment`) in `data.json` itself would violate that
and crash `kvmd-authz.service` outright. Put any explanatory notes here instead.
