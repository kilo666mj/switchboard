# Unattended agents

Switchboard is a useful capability boundary for scheduled and autonomous agents,
but it is not a complete agent sandbox. Its identity, authorization, limits,
egress, and audit controls apply only to calls routed through Switchboard.

## Recommended boundary

```text
unattended agent
  |  unique workload credential
  v
Switchboard ---- exact tool policy ---- upstream application
  |                                      owns business authorization,
  | mandatory destination/CIDR policy   state, idempotency, and rollback
  v
reviewed upstreams only

host/container network policy: agent may reach Switchboard and explicitly
required model services, but not arbitrary internet or cloud metadata
```

Use infrastructure firewall or container-network policy as an independent
boundary. Switchboard prevents its own HTTP clients from dialing unapproved
destinations; it cannot constrain the agent's shell, browser, direct SDKs, cloud
credentials, or other network clients. An approved upstream can still receive
data, and tool results can still contain prompt injection.

## Workload identity and policy

Give every scheduled job or trust domain its own credential and identity. Do not
share the legacy `/mcp` bearer route between workloads. Prefer short-lived OAuth
workload identities when the provider supports them. An ingress protected by
Cloudflare Access may instead use one service token per workload. Switchboard
matches that token's signed Client ID as the exact policy subject
`service_token:<client-id>.access`; it never trusts the unsigned client-ID
request header and does not grant human group entitlements to service tokens.
Otherwise enable only the required named static clients with
`static_client_allowlist`.

For a Cloudflare migration, keep the origin private and expose a separate
Access-protected hostname through Cloudflare Tunnel. The existing private
static-client route may remain as an explicitly allowlisted rollback during a
canary period. Remove the shared credential after every workload has a distinct
service token and cross-principal session isolation has been verified.

Use a minimal profile and exact tool decisions. Disable discovery and activation
unless the job genuinely needs them, and apply identity and exact-tool limits:

```json
{
  "clients": {
    "daily-briefing": {
      "token_env": "SWITCHBOARD_CLIENT_DAILY_BRIEFING",
      "profile": "daily-briefing",
      "tool_policy": "daily-briefing-v1",
      "discover": false,
      "execute": true,
      "activate": false,
      "limits": {
        "requests_per_minute": 30,
        "burst": 5,
        "concurrency": 1
      }
    }
  },
  "profiles": {
    "daily-briefing": ["inventory"]
  },
  "tool_policies": {
    "daily-briefing-v1": {
      "version": "daily-briefing-v1",
      "profile": "daily-briefing",
      "tools": {
        "inventory_list_changes": "allow"
      },
      "tool_limits": {
        "inventory_list_changes": {
          "requests_per_minute": 20,
          "burst": 3,
          "concurrency": 1
        }
      }
    }
  }
}
```

Omitted and newly discovered tools deny by default. Capability-level `allow`
also authorizes future tools from that capability, so avoid it for unattended
workloads. A `require_approval` decision currently blocks and hides the tool; it
does not pause or create an approval request. Use `deny` when a workload must
never call a tool. Allow a mutation only when the upstream operation is narrowly
scoped and independently enforces revision checks, idempotency, bounded effects,
and recovery or rollback.

## Preflight and audit

Run permission inspection against the exact proposed configuration before each
deployment:

```sh
switchboard permissions lint -config proposed.json -strict
switchboard permissions explain -config proposed.json -client daily-briefing
switchboard permissions diff -config current.json -against proposed.json \
  -client daily-briefing
```

Confirm that only the intended tools are callable and that no capability-wide
allow or unavailable approval warning remains.

Switchboard logs the authenticated identity, policy versions, exact tool,
decision, outcome, duration, and a correlation identifier. It deliberately omits
arguments, results, and error text. REST and remote MCP calls receive the same
identifier in `X-Switchboard-Correlation-ID`. Ship process logs to durable
storage and alert on denied calls, unknown tools, rate or concurrency rejection,
repeated tool errors, and unexpected policy-hash changes. Retain the upstream
application's audit log as the authoritative record of business effects.

Limits are in-memory containment for bursts and runaway loops; they are not
durable daily action or spending budgets. Enforce durable quotas and consequential
approval in the authoritative upstream application or a dedicated policy service.
