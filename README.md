# Switchboard

Switchboard is a private capability gateway: one curated MCP endpoint backed by
the canonical HTTP APIs of independently secured applications.

Applications keep their business rules, state, authorization, auditing, and
safety workflows. Switchboard owns MCP transport, profile-based capability
composition, API adaptation, and client-facing tool descriptions.

## Status

The initial implementation provides:

- stateless Streamable HTTP or stdio MCP transport;
- profile-based capability selection;
- profile-scoped capability search and descriptions;
- declarative REST capability manifests;
- federation of existing Streamable HTTP MCP servers;
- environment-referenced upstream URLs and credentials;
- read-only, mutating, and destructive MCP annotations;
- bounded upstream responses, timeouts, and redirect rejection;
- loopback-only unauthenticated HTTP, or bearer authentication when exposed;
- health and readiness endpoints.

Specialized Go capabilities can implement the small `Capability` interface when
an operation needs richer orchestration than a safe HTTP mapping can express.

## Quick start

Copy the examples without committing local credentials or URLs:

```sh
cp switchboard.example.json switchboard.json
cp capabilities/rilldns.example.json capabilities/rilldns.json
export RILLDNS_MCP_URL=http://127.0.0.1:8053/mcp
export RILLDNS_MCP_TOKEN=replace-me
go run ./cmd/switchboard -config switchboard.json
```

Connect an MCP client to `http://127.0.0.1:8090/mcp`. The health endpoints are
`/healthz` and `/readyz`.

For a non-loopback listener, `SWITCHBOARD_BEARER_TOKEN` is mandatory. Clients
must send it as an Authorization bearer token. Capability credentials use only
environment-variable references:

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

Each JSON file in `capabilities/` describes one API and its tools. Tool names
are exposed as `<capability>_<tool>`. Path arguments replace matching `{name}`
segments using URL escaping. Query arguments map MCP argument names to query
parameter names. Non-GET requests send unconsumed arguments as a JSON body, or
the explicit `body_arguments` subset when present.

Existing hosted MCP products use `"type": "mcp"`, an `endpoint_env`, and
environment-backed headers or OAuth client credentials. OAuth access tokens
are acquired and refreshed automatically; client secrets remain in the process
environment. Switchboard discovers upstream tools at startup,
preserves schemas and annotations, adds the capability prefix when absent, and
proxies calls without duplicating the product's tool definitions.

Generic manifests should expose the upstream application's safe operations,
not bypass them. A DNS mutation should still call an API operation that requires
the expected revision, dry-run/plan identifiers, and explicit confirmation.

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

REST and MCP manifests accept optional `title`, `description`, `tags`, and
`risk` fields. Risk is `read_only`, `mutating`, `destructive`, or `unknown`;
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
      "initial_capabilities": ["wayminder"],
      "discover": true,
      "execute": true,
      "activate": true
    }
  },
  "session_limit": 256,
  "session_idle_seconds": 1800
}
```

The server derives identity from the bearer credential on every request and
binds each MCP session to that identity. Profiles bound the searchable catalog
and executable capabilities. The three permissions default to false: `discover`
exposes search/describe, `execute` permits native and read-only compatibility
calls, and `activate` permits session changes when execution is also allowed.
Omit `initial_capabilities` to start with the whole allowed profile, or use `[]`
to start with management tools only.

`capability_enable` and `capability_disable` take an exact capability `name`.
They change only the current session's tool registry and send
`notifications/tools/list_changed`; clients should refresh `tools/list`.
Disabled capabilities remain discoverable but cannot execute through either
native calls or the compatibility fallback. Disabling waits for admitted calls
to finish before returning. Upstream sessions are shared by the gateway; signed
caller identity is not forwarded to upstream applications.

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
missing safety annotations, excluded tools, and REST capabilities are rejected.
Native mutating tools retain their existing upstream safety workflows.

Arguments are checked against the discovered input schema before forwarding.
Schemas that cannot be resolved locally disable compatibility execution for that
tool; Switchboard never fetches external schema references. Upstream tool errors,
content, and structured results are preserved. Calls have a two-minute deadline
and inherit caller cancellation. Remote HTTP response bodies (JSON or SSE,
including discovery and native calls) are limited to 8 MiB per response.

Structured `capability_execute` audit events contain the profile, capability,
exposed tool, outcome, and duration. They omit arguments, results, and error text.
The shared deployment credential still determines the active profile; this does
not introduce per-client identities or activation. Mutating compatibility calls
remain unavailable until an explicit confirmation workflow is designed.

## Architecture

```text
MCP client -> Switchboard profile -> capability adapter -> application API
                                                   application owns policy/state
```

Public products may retain their own product-scoped MCP endpoints. Switchboard
is the private composition layer for using those and internal APIs together.

The proposed path from a static tool union to searchable and dynamically
activated MCP capabilities is documented in
[Dynamic MCP discovery](docs/dynamic-mcp.md). The design keeps Switchboard as
the single client bootstrap endpoint while preserving profile restrictions,
upstream authorization, and application-owned safety workflows.

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

The `ansible/` playbook builds Switchboard on the controller, installs the eight
capability manifests and a hardened systemd service, and verifies readiness.
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

The gateway exposes `agent_send`, `agent_inbox`, `agent_claim`, `agent_start`,
`agent_reply`, `agent_complete`, `agent_fail`, and the other Relay tools.
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
