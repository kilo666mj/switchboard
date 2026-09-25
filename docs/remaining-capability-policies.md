# Remaining capability policies

This document records the reviewed group boundaries for Rendercase, Tintwire,
Log Watcher, and Agent Relay. The names are the tools Switchboard exposes after
prefixing the upstream catalog. Policies should enumerate these names exactly;
capability-wide grants would also authorize tools added upstream later.

## Log Watcher

Log Watcher owns the exclusion rules and validates mutation inputs. Its shared
service credential is acceptable because Switchboard records the authenticated
caller and Log Watcher requires a reason on every change.

| Group | Required scopes | Exact tools |
| --- | --- | --- |
| `switchboard-log-watcher-readers` | `tools:read` | `log_watcher_list_excludes` |
| `switchboard-log-watcher-operators` | `tools:read`, `tools:write` | `log_watcher_list_excludes`, `log_watcher_add_exclude`, `log_watcher_remove_exclude` |

The operator policy includes the read tool because the upstream instructions
require inspecting the existing exclusions before a change. Both mutation
tools retain Log Watcher's exact-match behavior and mandatory reason field.

## Rendercase

Rendercase makes artifact ownership and share authority depend on its
authenticated user. These exact-tool policies are deployed, but their groups
remain unassigned until a distinct-user acceptance test proves that the
authenticated Switchboard subject resolves to the same existing Rendercase
user.

| Group | Required scopes | Exact tools |
| --- | --- | --- |
| `switchboard-rendercase-readers` | `tools:read` | `rendercase_get_branding`, `rendercase_list`, `rendercase_get` |
| `switchboard-rendercase-publishers` | `tools:write` | `rendercase_create_upload`, `rendercase_commit_upload`, `rendercase_publish` |
| `switchboard-rendercase-sharing` | `tools:write` | `rendercase_share`, `rendercase_set_visibility`, `rendercase_revoke_share` |

No Rendercase administrator tool belongs in these policies. Rendercase must
continue to enforce ownership, visibility, share expiry, and revocation. Client
approval remains required for writes; revocation keeps its destructive
annotation.

Rendercase already maps its verified Pocket ID `sub` claim to the user that
owns artifacts. Its upstream bearer still has to be a Rendercase-audience token,
so Switchboard must not forward the inbound Switchboard-audience token. The
reviewed handoff uses the dedicated Rendercase M2M bearer to authenticate
Switchboard and `X-Switchboard-OAuth-Subject` to carry the subject Switchboard
already verified. Rendercase must accept that header only when the bearer
subject is the configured Switchboard service client, require the delegated
user to exist, and continue every ownership check against that user.

## Tintwire

Tintwire maps the authenticated OAuth subject to an agent principal and uses
that principal for channel access, run attribution, and administration. These
exact-tool policies are deployed, but their groups remain unassigned until a
distinct-user acceptance test proves that the authenticated Switchboard subject
resolves to the same existing enabled Tintwire agent.

| Group | Required scopes | Exact tools |
| --- | --- | --- |
| `switchboard-tintwire-readers` | `tools:read` | `tintwire_channels.list.v1`, `tintwire_notifications.search.v1`, `tintwire_notifications.get.v1` |
| `switchboard-tintwire-users` | `tools:write` | `tintwire_notifications.publish.v1`, `tintwire_notifications.set_state.v1`, `tintwire_runs.start.v1`, `tintwire_runs.record.v1`, `tintwire_runs.finish.v1` |
| `switchboard-tintwire-action-invokers` | `tools:write` | `tintwire_notifications.invoke_action.v1` |

The action group is separate because action calls can reach an allowlisted
external target and carry a destructive annotation. The upstream
`tintwire_channels.create.v1` administrator tool is omitted. Tintwire remains
responsible for channel membership, state transitions, action target lookup,
SSRF protection, idempotency, and durable run history.

Tintwire likewise keeps its resource-audience M2M bearer as the gateway
credential. When that bearer resolves to the configured Switchboard service
agent, Tintwire may use `X-Switchboard-OAuth-Subject` to select an existing
OAuth-subject agent. It must reject unknown subjects and must ignore or reject
the header for every other bearer. This preserves Tintwire's channel grants and
run attribution without giving Switchboard authority to create agents or alter
their permissions.

Switchboard's `forward_oauth_subject` manifest option supplies this reserved
header only for sessions authenticated with a verified OAuth subject. It is not
set for legacy or static clients, cannot be populated from a capability
manifest, and requires an authenticated upstream connection. The upstream
service credential remains environment-backed.

## Agent Relay

Agent Relay currently authenticates one shared bearer token, while its tools
accept `from` or `agent` as caller supplied arguments. That is not an identity
boundary: a caller could select another logical identity. Do not add Relay to a
shared user profile until Relay derives the agent identity from authentication
and rejects conflicting identity arguments.

After that upstream change, use these exact groups:

| Group | Required scopes | Exact tools |
| --- | --- | --- |
| `switchboard-agent-relay-readers` | `tools:read` | `agent_list`, `agent_inbox`, `agent_status` |
| `switchboard-agent-relay-users` | `tools:write` | `agent_send`, `agent_read`, `agent_reply`, `agent_claim`, `agent_complete` |
| `switchboard-agent-relay-cancellers` | `tools:write` | `agent_cancel` |

Relay must authorize inbox and status reads against the authenticated agent,
derive the sender for send and reply, bind task transitions to the acting
agent, and keep its append-only event history. Cancellation stays in a
separate group because it is destructive.

## Taskboard

Taskboard keeps task visibility, lanes and lifecycle rules. Switchboard reaches
it with a dedicated Taskboard agent credential rather than the deployment-wide
bearer. With `forward_cloudflare_access_subject`, a person authenticated by
Cloudflare Access is sent in `X-Switchboard-Access-Subject`. Taskboard trusts
that header only when the bearer resolves to a principal listed in
`TASKBOARD_MCP_DELEGATION_PRINCIPALS` and `TASKBOARD_MCP_HUMAN_DELEGATION` is
enabled; it ignores the header otherwise. The forwarded person only affects
`task_create`, which records the task as that person with Taskboard's default
role. Every other tool keeps the Switchboard credential's agent authority.

## Activation order

1. Add only Log Watcher to the shared profile and validate reader, operator,
   denied caller, and combined-group sessions.
2. Implement and test the authenticated gateway-subject handoff above in
   Rendercase and Tintwire. Bind the resulting upstream principal to the exact
   validated Switchboard subject.
3. Add authenticated per-agent identities to Agent Relay and remove authority
   from tool arguments.
4. Add each gated capability to the shared profile only after its identity
   test proves that two Switchboard users remain distinct upstream.

For every rollout, capture the effective policy hash, verify that omitted and
administrator tools are absent from discovery, make one authorized read, and
confirm a caller without the group is denied.
