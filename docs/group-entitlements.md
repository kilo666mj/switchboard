# Group entitlements and private MCP gateways

Switchboard can be the only MCP endpoint reachable by clients. Upstream MCP
servers need only be reachable from the Switchboard service network; they do
not need public DNS or public ingress.

```text
MCP clients
    |
    | OAuth access token or Cloudflare Access assertion
    v
Switchboard (the externally reachable MCP resource)
    |
    +-- private service identity --> Fleetglass MCP
    +-- private service identity --> Taskboard MCP
    +-- private service identity --> RillDNS MCP
    +-- delegated identity -------> user-scoped upstream, when required
```

Switchboard remains a curated gateway, not an open proxy. Operators configure
every upstream address, credential reference, profile, and tool decision.
Inbound identity tokens are never forwarded to an upstream.

## Composed policy mode

Identity providers default to `policy_mode: exclusive`: exactly one matching
policy is required. Set `policy_mode: composed` to combine all policies whose
subject/group matchers and required scopes are satisfied.

```json
{
  "profiles": {
    "workplace": ["fleetglass", "taskboard", "rilldns"]
  },
  "tool_policies": {
    "fleet-read": {
      "version": "v1",
      "profile": "workplace",
      "tools": {
        "fleetglass_fleet_overview": "allow",
        "fleetglass_get_host": "allow"
      }
    },
    "task-user": {
      "version": "v1",
      "profile": "workplace",
      "tools": {
        "taskboard_task_get": "allow",
        "taskboard_task_list": "allow",
        "taskboard_task_start": "allow",
        "taskboard_task_update": "allow"
      }
    },
    "dns-operator": {
      "version": "v1",
      "profile": "workplace",
      "tools": {
        "rilldns_dns_refresh_status": "allow",
        "rilldns_dns_plan_changes": "allow",
        "rilldns_dns_apply_changes": "require_approval"
      }
    }
  },
  "oauth": {
    "issuer": "https://id.example.com",
    "resource": "https://switchboard.example.com/mcp/sessions",
    "required_scopes": ["openid", "groups", "mcp:connect"],
    "group_claim": "groups",
    "group_source": "userinfo",
    "scope_claim": "scope",
    "policy_mode": "composed",
    "policies": {
      "fleet-readers": {
        "version": "v1",
        "groups": ["mcp-fleetglass-readers"],
        "required_scopes": ["tools:read"],
        "profile": "workplace",
        "tool_policy": "fleet-read",
        "discover": true,
        "execute": true
      },
      "task-users": {
        "version": "v1",
        "groups": ["mcp-taskboard-users"],
        "required_scopes": ["tools:read", "tools:write"],
        "profile": "workplace",
        "tool_policy": "task-user",
        "discover": true,
        "execute": true
      },
      "dns-operators": {
        "version": "v1",
        "groups": ["mcp-dns-operators"],
        "required_scopes": ["tools:read", "tools:write"],
        "profile": "workplace",
        "tool_policy": "dns-operator",
        "discover": true,
        "execute": true
      }
    }
  }
}
```

Composed policies deliberately have stricter validation:

- every identity policy must reference an explicit tool policy;
- every policy under one identity provider must use the same superset profile;
- matching policy names are sorted before composition;
- `discover`, `execute`, and `activate` are grants and combine by union;
- explicit initial-capability lists combine by union; an omitted list means all
  effectively allowed capabilities start active, while capabilities made
  unavailable by a stronger decision are removed from explicit initial lists;
- identity and exact-tool limits use the lowest configured positive value;
- decisions combine in the order `deny`, `require_approval`, then `allow`;
- a stronger capability decision is propagated to every tool owned by that
  capability; and
- the matched policies, versions, effective decisions, limits, and current tool
  ownership produce a deterministic SHA-256 effective-policy version used for
  session binding and audit.

An omitted decision still denies by default. Capability-level `allow` also
allows future tools imported from that upstream, so workplace policies should
normally enumerate exact tool names.

The group source must actually contain the configured group claim. Use the
default `group_source: "access_token"` when the authorization server places
groups directly in its resource access token. Pocket ID instead releases group
names from the standard UserInfo endpoint when the client requests its `groups`
OIDC scope, so use `group_source: "userinfo"` and include `groups` in both the
resource's required scopes and each client's authorization request before
removing a subject-based migration policy. UserInfo groups are accepted only
when its subject matches the already validated access token. Other identity
providers may emit group claims without a separate scope; follow the provider's
documented claim-release policy.

## Network deployment

For each upstream MCP:

1. Give Switchboard a private HTTPS route, private service name, or loopback
   route to the upstream.
2. Restrict the upstream firewall or ingress policy to Switchboard.
3. Retain normal TLS verification; use an internal CA or mutual TLS where
   appropriate.
4. Store the upstream credential only in Switchboard's secret manager or
   protected service environment.
5. Add the destination and resolved network to Switchboard's egress policy.
6. Remove public ingress only after a live call through Switchboard and a tested
   rollback path.

Cloudflare Tunnel may carry traffic to a private Switchboard origin. Do not
accidentally require both a Pocket ID OAuth token and a Cloudflare Access
assertion on the same MCP request: Switchboard rejects multiple inbound identity
credentials. Either use OAuth as the MCP identity boundary, or use the Access
assertion as the configured identity source.

Shared downstream service identities are suitable only where the upstream's
least-privilege policy and audit are sufficient. Consequential or user-scoped
operations should use delegated upstream identity, a separately authenticated
signed caller identity, or the upstream application's authoritative
plan/confirm workflow.

## Migration checklist

1. Inventory every upstream URL, listener, credential, owner, and caller.
2. Create the shared superset profile and exact per-group tool policies.
3. Configure identity-provider groups without enabling composed mode yet.
4. Test every single group and important group combination with synthetic or
   read-only calls.
5. Enable composed mode and verify effective-policy hashes in gateway audit.
6. Move upstream listeners behind private networking one at a time.
7. Verify gateway access, direct-access denial, monitoring, and rollback.
8. Retire static client and legacy gateway credentials separately.
