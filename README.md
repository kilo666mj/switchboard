# Switchboard

Switchboard is a private capability gateway: one curated MCP endpoint backed by
the canonical HTTP APIs of independently secured applications.

Applications keep their business rules, state, authorization, auditing, and
safety workflows. Switchboard owns MCP transport, profile-based capability
composition, API adaptation, and client-facing tool descriptions.

Switchboard can be the only client-reachable MCP endpoint while upstream MCPs
remain on loopback or private service networks. OAuth or Cloudflare Access group
claims can map callers to composable, exact-tool entitlements. See
[Group entitlements and private MCP gateways](docs/group-entitlements.md).

## Status

The initial implementation provides:

- stateless Streamable HTTP or stdio MCP transport;
- profile-based capability selection;
- profile-scoped capability search and descriptions;
- declarative REST capability manifests;
- federation of existing Streamable HTTP MCP servers;
- independently packaged stdio MCP modules with managed startup and shutdown;
- environment-referenced upstream URLs and credentials;
- read-only, mutating, and destructive MCP annotations;
- bounded upstream responses, timeouts, and redirect rejection for REST, MCP,
  and OAuth token requests;
- loopback-only unauthenticated HTTP, static bearer authentication, OAuth/OIDC
  JWT resource-server authentication, or Cloudflare Access assertions for
  identity-bound sessions;
- health, readiness, and Prometheus-compatible metrics endpoints.

Specialized integrations can run as local MCP modules when an operation needs
richer orchestration or lifecycle state than a safe HTTP mapping can express.
Compiled-in Go capabilities can still implement the small `Capability`
interface.

## Quick start

Copy the examples without committing local credentials or URLs:

```sh
cp switchboard.example.json switchboard.json
cp capabilities/rilldns.example.json capabilities/rilldns.json
export RILLDNS_MCP_URL=http://127.0.0.1:8053/mcp
export RILLDNS_MCP_TOKEN=replace-me
go run ./cmd/switchboard -config switchboard.json
```

Connect an MCP client to `http://127.0.0.1:8090/mcp`. The operational endpoints
are `/healthz`, `/readyz`, and `/metrics`.

For a non-loopback stateless `/mcp` listener,
`SWITCHBOARD_BEARER_TOKEN` is mandatory. The identity-bound `/mcp/sessions`
endpoint instead requires configured static clients, OAuth, or Cloudflare
Access. Capability credentials use only environment-variable references:

```json
{
  "headers": {
    "Authorization": {"env": "SERVICE_TOKEN", "prefix": "Bearer "}
  }
}
```

Do not place credential values in configuration or capability manifests.
When a trusted reverse proxy connects to a loopback listener while preserving
an external Host header, set `behind_loopback_proxy` only after ensuring that
untrusted clients cannot reach the listener directly.

## Profiles

Profiles limit tool exposure for a particular deployment:

```json
{
  "profile": "infrastructure-read",
  "profiles": {
    "infrastructure-read": ["rilldns", "fleetglass"],
    "publishing": ["rendercase"]
  }
}
```

Only selected manifests are loaded, so environment variables for disabled
capabilities are not required.

## Capability manifests

Each JSON file in `capabilities/` declares one capability. Declarative REST
manifests describe the API and its tools directly. Tool names are exposed as
`<capability>_<tool>`. Path arguments replace matching `{name}` segments using
URL escaping. Query arguments map MCP argument names to query parameter names.
Non-GET requests send unconsumed arguments as a JSON body, or the explicit
`body_arguments` subset when present.

Existing hosted MCP products use `"type": "mcp"`, an `endpoint_env`, and
environment-backed headers or OAuth client credentials. OAuth access tokens
are acquired and refreshed automatically; client secrets remain in the process
environment. Switchboard discovers upstream tools at startup,
preserves schemas and annotations, adds the capability prefix when absent, and
proxies calls without duplicating the product's tool definitions.

For HTTP deployments, a transient connection, process-start, or tool-list
failure degrades only that capability when at least one other capability is
available. Switchboard serves the healthy subset and retries each failed
capability after 5 seconds with exponential backoff capped at 5 minutes. A
recovered capability is included in new downstream sessions; existing sessions
keep their immutable tool registry and must reconnect to see it. Invalid
manifests, missing environment configuration, and egress-policy violations
remain fatal. Tool policy entries are validated immediately for available
capabilities and before a recovered capability is admitted. Stdio deployments
remain fail-fast.

Reviewed local integrations use `"type": "module"` and a clean absolute
`command`. Switchboard starts the executable over stdio, discovers its tools,
proxies calls, and closes it during shutdown. `environment` contains only names
of variables that may be copied into the otherwise isolated child environment;
it never contains credential values. Module manifests are operator-trusted code
configuration and must not point at downloaded or user-writable executables.
The first module is Log Watcher under `modules/log_watcher`.

When a global egress policy is configured, a module must declare
`"enforce_egress_policy": true`. Switchboard passes the non-secret network
boundary to the module, which must apply it to every outbound connection. The
Log Watcher module does so through the same guarded HTTP transport previously
used by its in-process REST capability. Application business rules and durable
state remain upstream.

An upstream that must retain its own per-user ownership or audit checks can set
`"forward_oauth_subject": true`. Switchboard then sends the exact subject from
the verified inbound OAuth session in `X-Switchboard-OAuth-Subject` on tool
calls. This option requires an authenticated upstream connection. The header is
absent during startup discovery and for legacy, static-client, and Cloudflare
Access sessions, and capability manifests cannot set the reserved header
directly. The upstream must trust it only when its bearer credential identifies
the configured Switchboard service client, map it to an existing principal,
and continue enforcing its own authorization. See
[the reviewed remaining-capability policies](docs/remaining-capability-policies.md).

When an upstream MCP omits or incorrectly applies behavior annotations, an
operator may supply `annotation_rules`. Each rule contains one or more exact
tool-name prefixes and a complete MCP `annotations` object. When rules are
present, every selected upstream tool must match exactly one rule; startup fails
for missing, empty, or overlapping classifications. This keeps annotation
corrections explicit and prevents newly added upstream tools from silently
receiving permissive metadata.

Generic manifests should expose the upstream application's safe operations,
not bypass them. A DNS mutation should still call an API operation that requires
the expected revision, dry-run/plan identifiers, and explicit confirmation.

## Production egress policy

An optional top-level `egress_policy` creates a fail-closed outbound boundary:

```json
{
  "egress_policy": {
    "allowed_destinations": [
      "inventory.example.internal:443",
      "id.example.internal:443"
    ],
    "allowed_cidrs": ["192.0.2.0/24"]
  }
}
```

When present, every REST base URL, remote MCP endpoint, and OAuth token URL must
use HTTPS and match an exact `host:port` entry. `insecure_skip_verify` is
prohibited. Before each new connection, Switchboard resolves the hostname itself,
rejects the complete DNS response if any address falls outside the configured
CIDRs, and dials a validated IP directly. Environment HTTP proxies are disabled
for these connections because they constitute a separate egress path. Include
every intentional proxy, tunnel, loopback, or private-network destination
explicitly. Omitting `egress_policy` preserves the existing operator-controlled
endpoint behavior for compatibility; workplace production should configure it
alongside infrastructure-level firewall rules.

## Catalog discovery

`capability_search` searches only capabilities selected by the active profile.
Pass optional `query`, `tags`, and `limit` arguments (default 20, maximum 100).
All query words must match the name, title, description, or tags; all requested
tags must match exactly, ignoring case. Results rank name matches ahead of
title, tag, and description matches, with alphabetical ties. Empty queries
list the catalog. `total` reports matches before the limit.

`capability_describe` takes an exact `name` and returns public metadata plus
exposed tool names, descriptions, and safety annotations. Remote MCP tool
summaries also include input schemas; native schemas remain available through
`tools/list`. Both discovery tools are read-only and preserve
the existing profile-selected tools and stateless transport.

REST, MCP, and module manifests accept optional `title`, `description`, `tags`,
and `risk` fields. Risk is `read_only`, `mutating`, `destructive`, or `unknown`;
omitted risk is displayed as `unknown`. It is operator-authored information,
not an authorization rule. Keep public metadata and upstream tool descriptions
free of secrets. Catalog responses use an explicit public-field allowlist and
exclude endpoint, header, OAuth, and environment configuration.

## Authenticated sessions and dynamic tools

Configure `clients` to enable the stateful `/mcp/sessions` endpoint. Every
installation needs a unique token of at least 32 bytes, referenced by environment
variable. For example, alongside the existing `profiles` configuration:

```json
{
  "clients": {
    "workstation": {
      "token_env": "SWITCHBOARD_CLIENT_WORKSTATION",
      "profile": "all",
      "tool_policy": "workplace-read",
      "limits": {
        "requests_per_minute": 120,
        "burst": 10,
        "concurrency": 4
      },
      "discover": true,
      "execute": true,
      "activate": false
    }
  },
  "tool_policies": {
    "workplace-read": {
      "version": "pilot-v1",
      "profile": "all",
      "capabilities": {
        "fleetglass": "allow"
      },
      "tools": {
        "wayminder_status": "allow"
      },
      "tool_limits": {
        "wayminder_status": {
          "requests_per_minute": 60,
          "burst": 5,
          "concurrency": 2
        }
      }
    }
  },
  "session_limit": 256,
  "session_idle_seconds": 1800
}
```

The server derives identity from the bearer credential on every request and
binds each MCP session to that identity. Profiles bound the available
capabilities. An optional named `tool_policy` authorizes whole capabilities with
optional exact tool overrides and an auditable policy version. Its decisions are
`allow`, `deny`, and `require_approval`; an exact tool decision overrides its
capability decision, and otherwise omitted tools default to deny. References to
capabilities outside the profile and stale explicit tool names fail startup.
Only tools whose effective decision is `allow` appear in native discovery or the
capability catalog. Denied tools remain blocked for stale client definitions and
compatibility calls. `require_approval` fails closed and remains undiscoverable
until a server-side approval workflow is configured.

Capability-level `allow` is an explicit decision to trust that upstream MCP's
current and future tool set. Switchboard still preserves the upstream tool
schemas, safety annotations, authorization, and plan/confirm workflows. Use
exact `tools` overrides to remove exceptional high-impact operations. Omitting
`tool_policy` retains whole-profile execution for compatibility. The three
permissions default to false: `discover`
exposes search/describe, `execute` permits native and read-only compatibility
calls, and `activate` permits session changes when execution is also allowed.
Omit `initial_capabilities` to expose the whole allowed profile immediately;
this is the recommended configuration when clients should use connected MCP
tools without a separate activation step. Set an explicit subset only when
reducing the initial tool catalog is worth requiring session activation.

Optional client `limits` apply across every session belonging to that
authenticated identity. A client may have a token-bucket rate limit and a
non-blocking concurrency limit. A tool policy may add stricter `tool_limits` to
an explicitly allowed tool. Limits use `requests_per_minute`, `burst`, and
`concurrency`; zero values disable the corresponding limit. Rejections do not
reach the upstream and are recorded by the same audit event as other calls.

### Permission inspection

The read-only `permissions` command explains the configured authorization
model without accepting credentials or changing policy:

```sh
# List identity bindings and flag operator hazards without contacting upstreams.
switchboard permissions report -config switchboard.json
switchboard permissions lint -config switchboard.json

# Expand one configured role through the live capability catalog.
switchboard permissions explain -config switchboard.json \
  -provider oauth -policy forgejo-users

# Simulate verified identity attributes using the same matcher as authentication.
switchboard permissions explain -config switchboard.json \
  -provider oauth -subject user-id \
  -group switchboard-rendercase-readers \
  -scope mcp:connect -scope tools:read

# Preview this identity's exact tool changes against a proposed configuration.
switchboard permissions diff -config switchboard.json \
  -against switchboard.proposed.json -provider oauth \
  -subject user-id -group switchboard-rendercase-readers \
  -scope mcp:connect -scope tools:read
```

Repeat `-policy`, `-group`, and `-scope` to inspect composed access. The report
distinguishes exact tool decisions, capability-wide decisions, implicit profile
access, approval-blocked tools, inactive capabilities, and unavailable
upstreams. `-json` is available on every action for review automation. `report`
and `lint` use configuration only; `explain` loads the relevant upstream
catalogs so its tool-level answer matches a new live session. Direct `-policy`
inspection deliberately bypasses subject, group, and scope matching; use
identity attributes when validating an actual assignment. `diff` loads both
catalogs and reports changes in tool decisions, decision sources, activation,
availability, and callability, followed by lint warnings for the proposed
configuration.

`GET /metrics` exposes Prometheus-compatible counters for authentication,
UserInfo, and authorization failures; session-capacity failures; active
sessions; per-capability availability and load-retry failures; tool-call counts and duration sums split by capability, tool,
decision, and outcome; and a numeric effective-policy hash for each composed
policy component set. The 52-bit hash value remains exact in Prometheus and
allows `changes()` alerts to detect policy or upstream catalog drift across
gateway restarts. Metrics deliberately omit identities, arguments, results,
and error text. Protect the endpoint at the reverse proxy or network layer
because policy names, tool names, and usage volumes may still be operationally
sensitive. Ready-to-install alert rules are in
[`monitoring/switchboard.rules.yml`](monitoring/switchboard.rules.yml).

### OAuth resource-server authentication

For short-lived user or workload identities, configure Switchboard as an OAuth
resource server on `/mcp/sessions`:

```json
{
  "oauth": {
    "issuer": "https://id.example.com",
    "resource": "https://switchboard.example.com/mcp/sessions",
    "required_scopes": ["mcp:connect"],
    "group_claim": "groups",
    "group_source": "access_token",
    "scope_claim": "scope",
    "jwt_type": "at+jwt",
    "allow_static_clients": true,
    "policies": {
      "workplace-readers": {
        "version": "pilot-v1",
        "groups": ["switchboard-readers"],
        "required_scopes": ["tools:read"],
        "profile": "all",
        "tool_policy": "workplace-read",
        "discover": true,
        "execute": true,
        "activate": false
      }
    }
  }
}
```

Switchboard discovers the configured issuer, verifies JWT signatures against
its JWKS, and requires exact issuer, expiry, and `aud` resource validation. It
then requires the configured scopes and maps the immutable `sub` plus exact
group claims to gateway policy. In the default exclusive mode, more than one
match is denied. When a policy contains both `subjects` and `groups`, both
dimensions must match; any listed group satisfies the group dimension. Policy-specific
scopes allow the authorization server's API permissions to constrain the local
tool policy.

`group_source` defaults to `access_token`. Set it to `userinfo` for providers
that release groups only from their standard OIDC UserInfo endpoint. Switchboard
first validates the access token, calls the discovered HTTPS UserInfo endpoint
with that token, and requires the returned `sub` to equal the validated token
subject before trusting the configured group claim. UserInfo lookup failures
fail closed. UserInfo mode requires `openid` in `required_scopes`.

Set `policy_mode` to `composed` when group memberships should contribute
multiple entitlements. Composed policies must share one superset profile and
must each reference an explicit tool policy. Effective decisions use
deny-before-approval-before-allow precedence, limits only become stricter, and
the deterministic effective-policy hash is bound to the session and audit. The
default `exclusive` mode retains the single-match fail-closed behavior.

For issuers such as Pocket ID 2.14 that identify access tokens with the protected
JWT header `typ: at+jwt`, configure `jwt_type: "at+jwt"`. Switchboard checks that
exact header value after verifying the signature, preventing ID-token substitution.
Issuers using a payload claim can instead use `token_type_claim` and
`token_type_value`; configuring both mechanisms requires both to match. If neither
is configured, token separation relies on distinct access-token audiences and scopes.

Validation is local JWT validation rather than token introspection. Individual
token revocation therefore takes effect when the token expires unless the
issuer removes its signing key; configure a short access-token lifetime.

The configured resource must be the canonical external MCP endpoint without a
trailing slash. Switchboard serves its RFC 9728 document at the corresponding
path-specific `/.well-known/oauth-protected-resource/...` URL and includes that
URL in authentication challenges. MCP clients must request the same `resource`
in authorization and token requests and send the access token—not an ID token—
on every MCP request.

`allow_static_clients` defaults to false whenever OAuth is configured. Set it
temporarily to migrate existing entries in `clients`, then remove those entries
or leave the switch disabled. The separate legacy `/mcp` endpoint remains
controlled by `SWITCHBOARD_BEARER_TOKEN`; unset that variable when migration is
complete. OAuth issuer discovery and JWKS requests also obey `egress_policy`, so
include every authorization-server destination they use.

For Pocket ID, create an API whose resource exactly matches `oauth.resource`,
define the scopes as API permissions, and grant user-delegated access to the
approved clients. Client ID Metadata Documents can be enabled for compatible
MCP clients; allowlist exact metadata-document URLs rather than wildcards. See
[Pocket ID OAuth setup](docs/pocket-id.md) for the rollout checklist.

### Cloudflare Access identity

An ingress protected by Cloudflare Access can authenticate the same dynamic
session endpoint using the edge-injected `Cf-Access-Jwt-Assertion` header. Set
`cloudflare_access.team_domain`, the exact Access application `audience`, and
subject/group policies that reference the same profiles and tool policies used
by OAuth identities. Switchboard verifies the assertion signature against the
team certs endpoint and requires its exact issuer, audience, expiry, `type: app`,
stable subject, and email. Root and `custom.groups` claims are combined for
exact policy matching. Audit identities are prefixed with
`cloudflare_access:` to prevent collisions with OAuth subjects.

Cloudflare Access is an additional inbound identity source; it is not advertised
as an MCP OAuth authorization server. When OAuth is also configured, requests
without an Access assertion retain the normal RFC 9728 OAuth challenge. A
request containing both an Authorization credential and an Access assertion is
rejected as ambiguous. Static clients stay enabled only when every configured
identity provider explicitly enables its migration switch.

Restrict the origin so clients cannot bypass Cloudflare, and configure the proxy
to remove any client-supplied assertion before injecting its verified header.
For the same agent path used by Rendercase, Cloudflare validates the client's
bearer credential at the edge, removes `Authorization`, and injects the Access
assertion for Switchboard. The Access team-domain certs URL is subject to
Switchboard's egress policy and redirect and response-size restrictions.

`capability_enable` and `capability_disable` take an exact capability `name`.
They change only the current session's tool registry and send
`notifications/tools/list_changed`; clients should refresh `tools/list`.
Disabled capabilities remain discoverable but cannot execute through either
native calls or the compatibility fallback. Disabling waits for admitted calls
to finish before returning. Upstream sessions are shared by the gateway;
configured remote capabilities can add the verified OAuth subject to each tool
call as described above.

Sessions expire after 30 minutes without a new HTTP request by default, or
after 24 hours regardless of activity. The default global limit is 256, with a
maximum of 32 sessions per client. DELETE, expiry, and service shutdown close
sessions and discard activation. An expired ID returns 404; a fresh initialize
starts from the operator's defaults. Configuration and token changes require a
service restart, which invalidates all previous sessions.

During migration, `/mcp` retains its static profile and legacy bearer credential.
When clients are configured, the legacy route is exposed only if
`SWITCHBOARD_BEARER_TOKEN` is set. Client tokens are accepted only at
`/mcp/sessions`. Persistent profile mutation is deliberately unavailable through
MCP; operators manage profiles through configuration and deployment.

The reverse proxy must support POST, GET, DELETE, and streaming responses at
`/mcp/sessions`. Keep response buffering disabled for tool-list notifications.

## Compatibility execution

`capability_execute` accepts `capability`, `tool`, and an `arguments` object.
Use the exact exposed tool name, including its prefix, from
`capability_describe`. For example:

```json
{"capability":"wayminder","tool":"wayminder_status","arguments":{}}
```

This fallback supports remote MCP capabilities in the active profile only.
It uses the same selected tool bindings and upstream session as native calls.
Only tools explicitly annotated read-only are eligible; destructive annotations,
missing safety annotations, excluded tools, REST capabilities, and local modules
are rejected.
Native mutating tools retain their existing upstream safety workflows.

Arguments are checked against the discovered input schema before forwarding.
Schemas that cannot be resolved locally disable compatibility execution for that
tool; Switchboard never fetches external schema references. Upstream tool errors,
content, and structured results are preserved. Calls have a two-minute deadline
and inherit caller cancellation. Remote HTTP response bodies (JSON or SSE,
including discovery and native calls) are limited to 8 MiB per response.

Structured audit events cover native and compatibility tool calls. They contain
the authenticated identity (or `legacy-shared`), profile, session and gateway
correlation identifiers, capability, exact exposed tool, policy version and
decision, outcome, and duration. They omit arguments, results, and error text.
The shared deployment credential still determines the active profile; this does
not introduce per-client identities or activation. Mutating compatibility calls
remain unavailable until an explicit confirmation workflow is designed.

## Architecture

```text
MCP client -> Switchboard profile -> capability adapter/module -> application API
                                                          application owns policy/state
```

Public products may retain their own product-scoped MCP endpoints. Switchboard
is the private composition layer for using those and internal APIs together.

The proposed path from a static tool union to searchable and dynamically
activated MCP capabilities is documented in
[Dynamic MCP discovery](docs/dynamic-mcp.md). The design keeps Switchboard as
the single client bootstrap endpoint while preserving profile restrictions,
upstream authorization, and application-owned safety workflows.

The executable provider-style boundary, lifecycle, state ownership, security
contract, packaging, and control-plane roadmap are documented in
[Capability module design](docs/modules.md).

## Managed client bootstrap

After deploying client policies and their environment-backed credentials, add
workstations to the `switchboard_clients` inventory group and run
`ansible-playbook bootstrap.yml` from `ansible/`. The playbook runs as each
workstation's user. Set `switchboard_client_home`, `switchboard_client_identity`,
and `switchboard_session_url` as shown in the example inventory.

The bootstrap verifies TLS and authentication, installs each installation's
gateway credential in a mode-0600 environment file, and updates its single
Switchboard connection. Supported clients are Codex, Claude Code, OpenCode,
Qwen Code, and pi. It preserves unrelated configuration and existing
approval settings, and writes a protected rollback copy before changes. New
entries use write approvals. An optional `switchboard_ca_file` installs an
operator-provided private root on Debian, Fedora/Red Hat, or Arch Linux; otherwise
existing system trust must validate the gateway. For Node-based clients that
need the OS trust bundle explicitly, set `switchboard_node_ca_bundle`; bootstrap
exports it as `NODE_EXTRA_CA_CERTS` without disabling certificate validation.
Python 3.11+ and curl are required.

This bootstrap is the static-token installation path. Codex can instead use its
native MCP OAuth login, and Pi can use an OAuth-capable local extension backed
by a Pocket ID public client and PKCE. Those client-specific flows are described
in [Pocket ID OAuth setup](docs/pocket-id.md#client-setup). Do not combine an
OAuth configuration with the bootstrap's bearer-token environment variable.

The helper can also be run directly:

```sh
python3 scripts/switchboard-connect.py --url https://switchboard.example.internal/mcp/sessions --check
```

Remove `--check` to apply. Use `--client claude`, `--client opencode`, or
`--client qwen` for their user-level configuration; JSON configuration must be
strict JSON (including a `.jsonc` file). Use `--token-env` to select the
installation-specific credential variable. Existing unrelated MCP entries are
preserved; retire direct downstream entries separately during migration.

For several clients on one workstation, set `switchboard_installations` in the
bootstrap inventory:

```yaml
switchboard_installations:
  - {client: codex, identity: workstation-codex}
  - {client: claude, identity: workstation-claude}
  - {client: opencode, identity: workstation-opencode}
  - {client: qwen, identity: workstation-qwen}
  - {client: pi, identity: workstation-pi}
```

Each identity must exist in `switchboard_clients` with its own credential.
The pi adapter uses pinned npm dependencies, discovers native tools, and
refreshes them after notifications. It preserves non-Switchboard pi tools and
requires UI approval for mutating or unannotated tools. Headless mutation calls
fail without forwarding. Its bootstrap archives the previous direct Wayminder
extension outside pi's extension discovery directory, retaining a rollback copy.
 Start a new login environment and restart the client
to pick up credentials and MCP configuration. The Codex settings follow the
[official MCP configuration documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).
Client formats follow [Claude Code's MCP documentation](https://code.claude.com/docs/en/mcp),
[OpenCode's MCP documentation](https://opencode.ai/docs/mcp-servers/), and
[Qwen Code's MCP documentation](https://qwenlm.github.io/qwen-code-docs/en/developers/tools/mcp-server/).
Native refresh support must be verified per installed client version. Clients without refresh support
can enable a capability and use `capability_execute` for read-only calls.

## Deployment

The `ansible/` playbook builds Switchboard and the Log Watcher module on the
controller, installs the capability manifests and a hardened systemd service,
and verifies readiness.
Copy `inventory.example.ini` to the ignored `inventory.ini` and
`private.yml.example` to the ignored `private.yml`, then populate deployment
URLs and secrets before running `ansible-playbook playbook.yml` from that
directory. Put TLS termination on the same host and proxy to
`http://127.0.0.1:8090`.

## Public release privacy

Switchboard and Agent Relay must pass the [privacy release gate](docs/privacy-release.md)
on their exact publication candidates. Original private history is not cleared
for publication. Run `python3 scripts/privacy-audit.py` and the documented secret
scan before release; the snapshot helper does not publish either repository.

## Agent Relay coordination

Agent Relay is a separate durable mailbox/task service. Copy
`capabilities/agent.example.json` to `capabilities/agent.json`, supply
`AGENT_RELAY_MCP_URL` and `AGENT_RELAY_MCP_TOKEN` in the gateway environment,
and select the `agent-relay` example profile or add `agent` to an intended
profile. For dynamic clients, include `agent` in `initial_capabilities` when
clients need its native tools immediately at startup.

The gateway exposes `agent_list`, `agent_send`, `agent_inbox`, `agent_read`,
`agent_reply`, `agent_claim`, `agent_complete`, `agent_cancel`, and
`agent_status`.
Relay owns identities, messages, task state, and audit history; Switchboard
continues to own capability access and transport composition.

Each upstream token represents one Relay identity. Distinct gateway client
credentials do not become distinct Relay identities on a shared upstream
connection. Use a separate gateway process/upstream credential per installation
when isolation is required, or connect directly to Relay. A client cannot
choose a different Relay sender through tool arguments in per-agent mode.
Compatibility execution remains read-only: use native tools for sending and
task transitions. The existing pi adapter exposes Relay without another
service-specific extension.

Agent Relay's `docs/clients.md` includes setup instructions and an opt-in
real-process integration test covering the gateway and mailbox task flow.

## License

Switchboard is licensed under the [MIT License](LICENSE). Third-party dependencies
retain their own licenses and attribution requirements.

## Release review archives

See [review archives](docs/releases.md) for reproducible Linux gateway builds,
dependency inventories, verbatim notices and native MCP startup verification.
The same guide includes pi source bundles with locked runtime dependency notices
and clean-install verification. Licensing and final distribution review remain
required. Nothing is published by the build commands.
