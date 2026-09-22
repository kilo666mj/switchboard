# Switchboard

Switchboard is a private capability gateway for MCP. It gives an agent one
curated endpoint while applications keep ownership of their business rules,
authorization, durable state, auditing, and safety workflows.

Use it to compose internal APIs and existing MCP servers into profiles with
exact tool permissions, identity-aware sessions, bounded egress, and a single
client connection.

## Highlights

- Streamable HTTP and stdio MCP transports
- Declarative REST, remote MCP, and local module capabilities
- Profile and exact-tool authorization policies
- OAuth/OIDC or Cloudflare Access identity-bound sessions
- Capability discovery and dynamic activation
- Environment-backed credentials; manifests contain no secrets
- Mandatory fail-closed egress policy with exact destinations and CIDRs
- Structured audit events and Prometheus-compatible metrics

Switchboard is the composition layer, not a replacement for upstream safety.
A DNS change, publication, or destructive operation still uses the upstream
application's native plan, confirmation, revision, and rollback workflow.

## Place in the agent tooling stack

Switchboard is the front door when one agent needs a curated set of tools. It
can expose [Wayminder](https://github.com/kilo666mj/wayminder) for durable
cross-session knowledge and [Rendercase](https://github.com/kilo666mj/rendercase)
for immutable, reviewable web artifacts, alongside other independently secured
applications. Those services remain authoritative for their own data,
authorization, and audit records; Switchboard only authenticates the caller,
selects the permitted tools, and forwards calls through a bounded connection.

Use the services directly when a client needs only one of them. Use Switchboard
when a single identity-aware endpoint, exact-tool policy, discovery, or bounded
egress materially simplifies the client. Do not use Wayminder as an artifact
store, Rendercase as durable agent memory, or Switchboard as a second database
for either service.

## Quick start

Requirements: Go 1.27.1 or newer.

```sh
cp switchboard.example.json switchboard.json
cp capabilities/rilldns.example.json capabilities/rilldns.json

export RILLDNS_MCP_URL=https://rilldns.example.com/mcp
export RILLDNS_MCP_TOKEN=replace-me

go run ./cmd/switchboard -config switchboard.json
```

Connect an MCP client to `http://127.0.0.1:8090/mcp`. Health endpoints are
available at `/healthz`, `/readyz`, and `/metrics`.

The multi-architecture container image is published at
`ghcr.io/kilo666mj/switchboard`. Mount the configuration and capability
manifests read-only, pass secrets through a protected environment file, and set
the container configuration to listen on `0.0.0.0:8090`. Bind the published
port to loopback unless a trusted reverse proxy provides the external boundary.
See the [operator guide](docs/operator-guide.md#container) for an example.

Example profile:

```json
{
  "profile": "infrastructure-read",
  "tool_policy": "infrastructure-read",
  "profiles": {
    "infrastructure-read": ["rilldns", "fleetglass"],
    "publishing": ["rendercase"]
  }
}
```

Capability credentials are referenced by environment variable:

```json
{
  "headers": {
    "Authorization": {"env": "SERVICE_TOKEN", "prefix": "Bearer "}
  }
}
```

Do not put credential values in configuration or capability manifests.

An authenticated remote MCP can opt in to `"forward_session_id": true` when
it groups several tool calls into one presentation identity. Switchboard then
overwrites `agent_session_key` with its server-issued inbound session ID, but
only for upstream tools whose declared input schema contains that field. It
does not add the field to unrelated tools, and callers cannot spoof it through
Switchboard.

## Authentication and permissions

The stateless `/mcp` endpoint supports loopback-only unauthenticated use or a
static bearer credential of at least 32 bytes. The stateful `/mcp/sessions` endpoint supports unique
static clients, OAuth/OIDC resource-server authentication, and Cloudflare
Access assertions from a trusted ingress.

When workload identities must coexist with OAuth or Cloudflare Access, use the
provider's `static_client_allowlist` to enable only named entries from
`clients`. It is mutually exclusive with the global `allow_static_clients`
migration switch.

OAuth and Cloudflare identities map verified subjects and groups to profiles
and exact tool policies. Cloudflare Access service tokens map their signed
`common_name` to an exact `service_token:<client-id>.access` policy subject and
cannot inherit human group policies. Cloudflare Access is optional and is not
enabled by default. Its origin must reject bypass traffic, and the trusted proxy
must strip client-supplied assertion headers before injecting its verified
assertion.

Inspect effective authorization without changing it:

```sh
switchboard permissions report -config switchboard.json
switchboard permissions lint -config switchboard.json
switchboard permissions lint -config switchboard.json -strict
switchboard permissions explain -config switchboard.json \
  -provider oauth -policy readers
switchboard permissions diff -config switchboard.json \
  -against proposed.json -provider oauth -policy readers
```

## Security model

- Non-loopback stateless HTTP requires a bearer credential.
- Identity sessions fail closed when no policy matches.
- Requests containing both OAuth and Cloudflare Access credentials are rejected.
- Upstream secrets stay in the process environment.
- The mandatory egress policy restricts exact destinations and CIDRs and resists DNS
  rebinding by validating and directly dialing resolved addresses.
- TLS verification cannot be disabled for upstream MCP connections.
- Every gateway and identity binding names an explicit tool policy; omitted
  tools deny by default.
- Native mutating tools retain upstream approval and confirmation semantics.
- Audit events omit tool arguments, results, and error text.
- Never attach a debug MCP logger in a sensitive deployment because upstream
  SDK debug output may contain tool arguments.
- Do not expose `/metrics` publicly; restrict it to the monitoring path at the
  reverse proxy or network boundary.

Review the examples before exposing Switchboard outside a trusted network.

## Documentation

- [Operator guide](docs/operator-guide.md) — complete configuration,
  authentication, capability, bootstrap, and deployment reference
- [Group entitlements](docs/group-entitlements.md) — composable identity and
  exact-tool authorization
- [Pocket ID OAuth setup](docs/pocket-id.md) — resource-server and client setup
- [Dynamic MCP discovery](docs/dynamic-mcp.md) — catalog and activation design
- [Capability modules](docs/modules.md) — isolated local integration model
- [Workplace adoption](docs/workplace-adoption.md) — staged rollout guidance
- [Unattended agents](docs/unattended-agents.md) — workload identities,
  network containment, limits, and audit collection
- [Troubleshooting and recovery](docs/troubleshooting.md) — startup, identity,
  policy, upstream, and session diagnostics
- [Release archives](docs/releases.md) and
  [privacy gate](docs/privacy-release.md) — reproducible public release process

## Status

Switchboard is deployed and actively used, but its configuration surface may
continue to evolve before a stable 1.0 release. Releases and deployments should
use the repository's privacy, dependency, and archive-verification gates.

## License

[MIT](LICENSE)
