# Capability module design

Switchboard capability modules are independently executable API integrations.
They give the gateway a provider-style extension boundary without creating a
Switchboard-specific tool protocol: a module is an MCP server connected over
stdio, and Switchboard is its MCP client and process owner.

The initial implementation establishes the execution contract and converts Log
Watcher into the first module. Installation, dependency resolution, version
locking, upgrades, and automatic restart are later control-plane work.

## Goals

- Package an API integration independently from the gateway executable.
- Let the integration own its API client, tool schemas, annotations, and
  process-local connection state.
- Let Switchboard retain capability composition, caller policy, audit,
  rate-limiting, tool routing, and client-facing MCP transport.
- Use MCP as the language-neutral module protocol.
- Pass credentials by environment-variable reference without placing values in
  a capability manifest.
- Fail closed when a selected module cannot start, initialize, or provide its
  configured tools.
- Preserve the upstream application's authorization, validation, confirmation,
  rollback, auditing, and durable state.

## Non-goals

- Modules are not a place to recreate application business rules or durable
  domain state.
- The gateway does not install modules discovered from an unreviewed public
  catalog.
- A module process is not currently a strong operating-system security
  boundary. It runs as a child of Switchboard under the same service account
  and inherited systemd restrictions.
- The initial contract does not provide per-caller credentials or verified
  subject forwarding to a local module.
- Capability activation does not start and stop module processes on demand.

## Responsibility boundary

```text
MCP client
    |
    v
Switchboard core
  - caller authentication and profiles
  - exact capability/tool policy
  - rate and concurrency limits
  - audit and client-facing MCP transport
  - module process startup/shutdown
    |
    | stdio MCP, one gateway-owned session
    v
Capability module
  - tool definitions and safety annotations
  - API adaptation and protocol-specific client
  - process-local connection/runtime state
    |
    v
Upstream application
  - business rules and authorization
  - durable data and audit history
  - plan/confirmation/rollback workflows
```

Switchboard starts one process for each selected module while loading the union
of capabilities referenced by its configured profiles and identity policies.
That process and its upstream MCP session are shared by all applicable gateway
sessions. A profile or session can hide and block tools, but does not create an
additional module instance.

This shared-service model is appropriate for the current Log Watcher module,
which uses a Switchboard service credential. An integration requiring
user-specific ownership checks should remain an independently authenticated
remote MCP service until a reviewed local-module identity contract exists.

## Manifest contract

A local module uses a capability manifest with `"type": "module"`:

```json
{
  "version": 1,
  "type": "module",
  "name": "example",
  "title": "Example API",
  "description": "Use reviewed operations from the Example API.",
  "tags": ["example"],
  "risk": "mutating",
  "command": "/usr/local/libexec/switchboard/switchboard-module-example",
  "arguments": [],
  "environment": ["EXAMPLE_API_URL", "EXAMPLE_API_TOKEN"],
  "enforce_egress_policy": true,
  "include_tools": ["example_status", "example_update"]
}
```

Fields have the following meaning:

| Field | Contract |
| --- | --- |
| `version` | Module manifest format. The current value is `1`. |
| `type` | Must be `module`. Unknown capability types fail startup. |
| `name` | Capability namespace matching `^[a-z][a-z0-9_]{0,63}$`. |
| `title`, `description`, `tags`, `risk` | Public catalog metadata governed by the same rules as REST and remote MCP capabilities. |
| `command` | Clean absolute path to a regular executable. Symlinks and group/world-writable executables are rejected. No shell interprets this value. |
| `arguments` | Optional literal argument vector passed directly to the executable. |
| `environment` | Optional allowlist of environment-variable names copied from Switchboard. Empty or missing values fail startup. Reserved `SWITCHBOARD_MODULE_*` names cannot be selected. |
| `enforce_egress_policy` | Declares that the module understands and enforces Switchboard's egress-policy contract. It is required when the gateway has a global egress policy. |
| `include_tools` | Optional exact upstream tool allowlist. Missing, empty, or duplicate entries fail startup. Omitting it selects every tool advertised by the module. |

Credential values never appear in the manifest. Operators provision them in
Switchboard's protected environment, and only the names selected by the module
manifest enter the child environment.

## Process and MCP lifecycle

Manifest and policy validation is synchronous and fail-closed:

1. The loader selects manifests referenced by at least one active deployment,
   static-client, OAuth, or Cloudflare Access profile.
2. Switchboard validates the module manifest and executable before starting it.
3. The child working directory is the executable's directory. Its environment
   begins with `LANG=C.UTF-8`, `SWITCHBOARD_MODULE_NAME`, and only explicitly
   selected variables.
4. Switchboard starts the command without a shell and opens one MCP session over
   stdin/stdout. Module logs belong on stderr because stdout is the protocol.
5. Switchboard initializes MCP, lists tools, applies `include_tools`, prefixes
   unqualified names with `<capability>_`, and registers the resulting tools.
6. Any validation or selection failure closes opened sessions and prevents
   gateway startup. For HTTP transport, a process-start, initialization, or
   discovery availability failure is isolated when another capability loaded;
   Switchboard serves the healthy subset and retries after 5 seconds with
   exponential backoff capped at 5 minutes. Stdio transport remains fail-fast,
   and an HTTP deployment with no available capabilities does not start.

During operation, Switchboard forwards calls through the established module
session. Client profiles, exact-tool policy, limits, and audit middleware remain
in front of the module. The module's MCP annotations and input schemas are
preserved.

On normal gateway shutdown, Switchboard closes the MCP session. The stdio
transport closes the child's stdin, waits for an orderly exit, sends `SIGTERM`
if necessary, and finally kills an unresponsive process.

Switchboard retries modules that fail during initial startup. It does not yet
detect or restart a module that exits after a successful startup, refresh a
running module's tool list, or change `/readyz` after a runtime failure. Calls
through a closed session fail; runtime supervision is still required before
modules are fully self-healing.

## State model

Three kinds of state must remain distinct:

- **Application state** is authoritative, durable business data owned by the
  upstream service. For Log Watcher, this includes the exclusion list and its
  audit history.
- **Module runtime state** includes API connections, caches, negotiated MCP
  state, and other data bounded by the module process lifetime. A module may
  reconstruct it from the upstream application after restart.
- **Gateway session state** includes authenticated identity, active capability
  selection, policy, limits, and MCP session metadata. Switchboard owns this
  bounded state.

There is no module state directory or provider-style state file in version 1.
If a future module needs durable operational metadata, its ownership, schema,
migration, backup, and failure semantics must be designed explicitly. Durable
domain data should not move into Switchboard or its modules.

## Egress and trust

When a global egress policy is present, Switchboard serializes its non-secret
destination and CIDR boundary into `SWITCHBOARD_MODULE_EGRESS_POLICY`. A module
that declares `enforce_egress_policy` must parse this value and apply it to all
outbound connections. The Log Watcher module reconstructs the same guarded HTTP
transport used by its former in-process REST capability.

The declaration is a reviewed-code contract, not a kernel sandbox: a malicious
module could ignore it. Production deployments should continue to use
infrastructure firewall policy, root-owned executable paths, systemd hardening,
and source/artifact review. A stronger future module runner may add per-module
users, filesystem namespaces, syscall restrictions, and network namespaces.

Modules are trusted to describe tool behavior accurately. Profiles and
tool policies determine authorization, but incorrect read-only, destructive,
idempotent, or open-world annotations can still mislead clients and approval
interfaces. Module tests and review must cover every exported tool and newly
introduced tools must fail closed where an explicit allowlist is used.

## Packaging and deployment

The Log Watcher module is built as `switchboard-module-log-watcher`. Review
archives place it under `modules/`, embed the same release version as the
gateway, and include the union of both binaries' dependency and notice graphs.
The release smoke test initializes both native binaries and verifies the module
tool catalog without contacting Log Watcher.

The Ansible deployment builds the module for the target architecture, installs
it at `/usr/local/libexec/switchboard/switchboard-module-log-watcher`, installs
the matching manifest, and restarts Switchboard when either changes.

The current release bundle does not yet define a general installer. An operator
adding another module must build and install its executable at the reviewed
absolute path before selecting its manifest.

## Authoring a module

A module may be written in any language that can serve MCP over stdio. It must:

- reserve stdout exclusively for newline-delimited MCP messages;
- send operational logs to stderr;
- publish stable, capability-scoped tool names or accept Switchboard's prefix;
- provide complete JSON input schemas and accurate safety annotations;
- validate inputs again at the application boundary;
- preserve upstream authorization and safety workflows;
- read secrets only from explicitly provisioned inputs;
- honor the egress-policy contract when declaring support; and
- exit cleanly when stdin closes or the process receives a termination signal.

The module should be independently testable as an MCP server. Its acceptance
tests should verify initialization, exact tool inventory, schemas, annotations,
credential isolation, egress behavior, failure handling, and shutdown.

## Path to a provider-style subsystem

The execution contract is the first layer. A complete provider-style module
system should add, in order:

1. An artifact manifest containing module name, semantic version, supported
   protocol version, platform targets, source, and cryptographic checksum.
2. A lockfile recording the exact reviewed artifacts selected by a deployment.
3. A privileged operator control plane for install, validate, configure,
   enable, disable, upgrade, rollback, and remove operations. These operations
   must not be callable merely because an MCP client can invoke tools.
4. Runtime health monitoring, bounded restart/backoff, readiness degradation,
   and structured module logs and metrics.
5. Drain-and-replace upgrades that preserve in-flight call semantics and fail
   closed if schemas or safety annotations change unexpectedly.
6. A deliberate configuration and migration protocol for any module-owned
   operational state.
7. Artifact signing and stronger per-module operating-system isolation.

The management API is separate from the client-facing MCP data plane. Until it
exists, module installation and upgrade remain explicit deployment operations.

## Log Watcher conversion

Log Watcher's former top-level REST manifest is now split into:

- `capabilities/log_watcher.example.json`, which configures the installed module
  process and its allowed environment; and
- `modules/log_watcher/api.json`, which is embedded in the module executable and
  owns its API paths, input schemas, descriptions, and safety annotations.

The exposed tools remain `log_watcher_list_excludes`,
`log_watcher_add_exclude`, and `log_watcher_remove_exclude`. Log Watcher remains
the source of truth for exclusions and continues to enforce the canonical API
workflow.
