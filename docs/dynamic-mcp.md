# Dynamic MCP discovery

## Problem

Configuring every MCP server separately in Codex, Claude Code, OpenCode,
Qwen Code, and other clients creates repeated installation, credential, and
maintenance work on every computer.

MCP can centralize almost all of this work, but it cannot provide completely
automatic first contact. Every client must initially know about at least one
trusted MCP endpoint. After that bootstrap connection, a gateway can own server
discovery, credentials, policy, lifecycle, and routing.

Switchboard is already that bootstrap endpoint:

```text
agent client -> https://switchboard.example.com/mcp -> configured capabilities
```

The desired end state is to register only Switchboard in each client, then let
agents search a private catalog and activate capabilities through Switchboard.

## Registry and gateway are different

An MCP registry is a catalog. It answers questions such as:

- Which servers exist?
- What do they do?
- Which package or remote endpoint provides them?
- Which version and transport should a consumer use?

The official MCP Registry provides a standard REST API and supports compatible
private subregistries. It does not establish trust, supply credentials, enforce
local policy, start servers, or proxy tool calls.

An MCP gateway performs those operational functions. It is the one endpoint a
client connects to and may:

- Search one or more catalogs.
- Connect to remote MCP services.
- Start reviewed, packaged local MCP modules.
- Hold or obtain upstream credentials.
- Restrict servers and tools using profiles and policy.
- Expose downstream tools to clients.
- Audit and route tool calls.

Docker MCP Gateway demonstrates this model. Its experimental Dynamic MCP mode
provides management tools such as `mcp-find`, `mcp-add`, `mcp-config-set`,
`mcp-remove`, and `mcp-exec`. Docker also supports private custom catalogs.

References:

- <https://github.com/modelcontextprotocol/registry>
- <https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/registry-aggregators.mdx>
- <https://docs.docker.com/ai/mcp-catalog-and-toolkit/dynamic-mcp/>
- <https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/>

## Recommended Switchboard design

Extend Switchboard into a private registry-aware dynamic gateway rather than
deploying a second gateway. Continue to keep business state, authorization, and
safety workflows in upstream applications.

```text
Codex --------+
Claude Code --+
OpenCode -----+-- one MCP connection -> Switchboard
Qwen Code ----+                         |
pi adapter ---+                         +-- private capability catalog
                                        +-- profiles and policy
                                        +-- upstream credentials
                                        `-- local modules, remote MCP and REST adapters
```

The first catalog should be the capability manifests already managed in this
repository. A separate Registry deployment is unnecessary for the current
number of private services. A Registry-compatible API can be added later if
other consumers need to query the catalog directly.

Reviewed local executables use the separate
[capability module contract](modules.md). Catalog discovery and session
activation compose those modules, but do not install them or control their
process lifetime independently.

## Catalog metadata

Capability manifests need enough non-secret metadata for useful search and
policy decisions. For example:

```json
{
  "version": 1,
  "type": "mcp",
  "name": "agent",
  "title": "Agent Relay",
  "description": "Durable messaging and tasks between agents",
  "tags": ["agents", "messages", "tasks"],
  "risk": "mutating",
  "endpoint_env": "AGENT_RELAY_MCP_URL",
  "headers": {
    "Authorization": {
      "env": "AGENT_RELAY_MCP_TOKEN",
      "prefix": "Bearer "
    }
  }
}
```

Credentials must remain environment references. Catalog search must never
return credential values or other deployment secrets.

Suggested metadata fields are:

| Field | Purpose |
| --- | --- |
| `title` | Human-readable capability name |
| `description` | Searchable summary |
| `tags` | Search and grouping terms |
| `risk` | Highest expected risk class |
| `documentation_url` | Operator-facing documentation |
| `enabled_by_default` | Whether a profile includes it without discovery |

Profile membership should remain in the top-level Switchboard configuration so
one manifest does not decide where it is authorized.

## Management tool surface

Expose a small, stable tool set:

- `capability_search`: search available capabilities using text and tags.
- `capability_describe`: return metadata and downstream tool summaries.
- `capability_enable`: activate a capability for the current session or an
  authorized persistent profile.
- `capability_disable`: deactivate a capability.
- `capability_execute`: compatibility fallback for calling a discovered tool
  when the client cannot refresh its native tool list.

Search and describe are read-only. Enable and disable mutate gateway state and
must be annotated accordingly. Persistent profile changes are administrative
operations and should require a revision or confirmation flow rather than being
silently granted to an agent.

## Native dynamic tools

MCP servers can advertise the `listChanged` tools capability and send a
`notifications/tools/list_changed` notification. A compatible client then
requests `tools/list` again and learns the newly available native tool schemas.

This is the preferred experience because clients retain each downstream tool's
schema, description, and safety annotations. It requires:

- A stateful MCP session or another reliable session identity.
- Per-session capability state.
- Client support for tool-list change notifications.
- A client refresh after enabling or disabling a capability.

Switchboard retains stateless Streamable HTTP at `/mcp` and provides
authenticated stateful sessions at `/mcp/sessions`. Upstream schemas are
discovered at startup or after a degraded capability reconnects; each
downstream session owns its native tool registry. Recovered capabilities appear
in newly initialized sessions, while existing sessions reconnect to receive the
new registry.

Reference:

- <https://modelcontextprotocol.io/specification/latest/server/tools>

## Compatibility execution

Not all clients reliably refresh tools during a session. For those clients,
`capability_execute` can accept a capability name, downstream tool name, and
arguments, then route the call through an already established upstream MCP
session.

This fallback has important limitations:

- The model does not receive the downstream tool's native input schema as a
  first-class tool definition.
- Client approval interfaces see the generic execution tool rather than the
  precise downstream operation.
- Safety annotations may become less visible.
- A generic call could accidentally bypass carefully curated exposure rules.

Consequently, compatibility execution must:

- Operate only on capabilities and tools allowed by the active profile.
- Validate arguments against the discovered downstream schema.
- Preserve upstream errors and safety workflows.
- Reject destructive tools unless an explicit confirmation mechanism exists.
- Record the capability and downstream tool in structured audit logs.
- Never become an unrestricted HTTP request facility.

## Profiles and persistence

There are three useful activation scopes:

1. **Static profile:** tools are selected at Switchboard startup, matching the
   current behavior.
2. **Session activation:** an agent temporarily enables a catalog capability;
   the selection disappears when its MCP session ends.
3. **Persistent profile:** an administrator changes a named profile used across
   later sessions.

Start with static profiles plus discovery. Add session activation only when
Switchboard has stable session identity. Persistent mutations should come last
and use an explicit plan/confirm workflow.

## Identity and authorization

Dynamic capabilities make caller identity more important. A single shared
Switchboard bearer token cannot safely provide different catalogs or policies
to different agents.

The eventual model should provide:

- A credential per client installation or agent identity.
- Server-derived identity rather than identity supplied in tool arguments.
- An allowed profile for each identity.
- Separate permissions for discovery, session activation, execution, and
  persistent profile administration.
- Signed identity propagation only where an upstream service needs it.

Until then, dynamic activation should remain restricted to capabilities already
approved in the deployed profile. Discovery must not expand authority merely
because an agent found a server in a catalog.

## Client bootstrap

MCP itself cannot tell a client where its first MCP server lives. Provision the
single Switchboard connection outside MCP using one of:

- Ansible-managed client configuration.
- A version-controlled dotfiles configuration.
- A small `switchboard-connect` bootstrap command.
- An agent-specific setup command invoked by an installation script.

The bootstrap should install only:

- The Switchboard URL.
- The private CA trust required to reach it.
- A per-installation credential loaded from a secret store or protected
  environment file.

No downstream MCP credentials should be copied to clients.

## Implementation phases

### Phase 1: searchable static catalog (implemented)

1. Extend capability manifests with title, description, tags, and risk.
2. Add `capability_search` and `capability_describe`.
3. Search only capabilities allowed by the active deployment profile.
4. Add schema, redaction, authorization, and ranking tests.

This phase works with Switchboard's existing stateless transport. It adds the
two discovery tools while preserving the existing downstream tool union.
See the README for search arguments and ranking behavior.

### Phase 2: compatibility execution (read-only implementation complete)

1. Add `capability_execute` for remote MCP capabilities.
2. Validate calls against the discovered upstream schema.
3. Preserve include lists, annotations, timeouts, response bounds, and upstream
   safety workflows.
4. Initially permit read-only tools only.
5. Add an explicit confirmation design before allowing mutating operations
   (deferred; mutating compatibility calls remain rejected).

See the README for execution arguments, validation, bounds, and audit behavior.

### Phase 3: authenticated sessions (implemented)

1. Replace the shared-client assumption with per-client credentials.
2. Map identities to profiles and activation permissions.
3. Add stateful session lifecycle and bounded session storage.
4. Ensure reconnect and expiry behavior fails closed.

### Phase 4: native dynamic tool lists (implemented and deployed)

1. Add session-scoped `capability_enable` and `capability_disable`.
2. Advertise the MCP tool-list change capability.
3. Notify clients and verify refresh behavior across supported agents.
   SDK integration and installed-client results are recorded in
   [the rollout notes](rollout.md#verified-rollout-2026-09-05).
4. Use native tools on clients with verified refresh and read-only
   `capability_execute` on clients with cached or unqualified tool lists. The
   initial deployment keeps the fallback available to all execute-enabled clients.

### Phase 5: managed bootstrap (deployed); registry API conditional

1. Provision the one Switchboard connection on each managed computer using
   Ansible.
2. Add an official-Registry-compatible private API only if non-Switchboard
   consumers require it.
3. Consider OCI-distributed catalogs only if portable local MCP packages become
   part of the deployment model.

## Non-goals

- Installing arbitrary unreviewed MCP servers because an agent discovered
  them publicly.
- Returning or copying upstream credentials to clients.
- Moving application business rules into Switchboard.
- Replacing upstream authorization or confirmation workflows.
- Treating registry publication as proof that a server is safe.
- Removing the need for one initial trusted client configuration.
