# Troubleshooting and recovery

Start with the narrowest failing boundary. Switchboard deliberately keeps
authentication, policy, egress, upstream availability, and client sessions
separate, so weakening several controls at once usually hides the real fault.

## Diagnostic sequence

1. Check process liveness at `/healthz` and readiness at `/readyz`.
2. Lint the current configuration without contacting upstream services:

   ```sh
   switchboard permissions lint -config switchboard.json -strict
   switchboard permissions report -config switchboard.json
   ```

3. Explain the affected identity or policy with `permissions explain`.
4. Check the upstream capability directly from the Switchboard host, using its
   normal authenticated health or discovery path.
5. Inspect Switchboard logs and the restricted `/metrics` endpoint.
6. Reconnect the MCP client after any policy, profile, capability, or deployment
   change. Existing stateful sessions keep the tool registry they received at
   initialization.

The permission inspection commands read configuration and the live capability
catalog. They do not accept client credentials, mutate policy, or call an
upstream tool.

## Common failures

### Startup rejects the configuration

Read the first configuration error rather than the later shutdown messages.
Common causes are a missing environment variable, an unknown profile or tool,
an omitted tool-policy binding, overlapping annotation rules, or an upstream
URL outside the mandatory egress policy.

Run the strict permission linter and validate every selected capability's
environment references. Do not add credential values to JSON while debugging.

### `/mcp` returns `401`

The stateless endpoint permits unauthenticated traffic only on a true loopback
listener. A non-loopback listener requires `SWITCHBOARD_BEARER_TOKEN` with at
least 32 bytes. Confirm that the client sends exactly one `Authorization:
Bearer ...` header and is connecting to the intended endpoint.

Do not enable unauthenticated non-loopback access as a workaround. When a
reverse proxy reaches a loopback listener, use `behind_loopback_proxy` only
after direct origin access is blocked.

### `/mcp/sessions` rejects login or returns `403`

First identify which provider should authenticate the request: a named static
client, OAuth/OIDC, or Cloudflare Access. Requests containing credentials from
both OAuth and Cloudflare Access fail closed.

For OAuth, verify the protected resource, issuer, audience, token type, required
scopes, and exact external MCP URL. If policy uses groups, verify that the
client requested the group scope and that the configured UserInfo response has
the same `sub` as the validated access token. Then use `permissions explain`
with the subject, groups, and scopes observed for that identity.

For Codex, inspect the configured server with `codex mcp get switchboard` and
repeat `codex mcp login switchboard` after changing OAuth registration or
scopes. Restart the client after changing its MCP configuration.

### A tool is absent

Check all four gates:

1. the capability is selected by the identity's profile;
2. the tool policy resolves the exact tool to `allow`;
3. the capability is currently available; and
4. when an explicit initial subset is configured, the session activated the
   capability.

Capability-wide `allow` intentionally includes current and future tools from
that upstream. Use exact tool decisions when that trust boundary is too broad.
Reconnect after correcting policy or after a degraded capability recovers;
existing sessions do not receive a replacement tool registry.

### A capability is unavailable

Remote HTTP capabilities retry transient connection, startup, and tool-list
failures with exponential backoff. Check the upstream service first, then the
configured URL, credentials, TLS trust, DNS answer, allowed destination, and
allowed CIDRs. Switchboard rejects the complete DNS response when any returned
address falls outside the configured network boundary.

Do not disable TLS verification, enable an environment proxy, or widen CIDRs to
silence the error. Add only the exact reviewed destination and network path.
Stdio deployments remain fail-fast because their lifecycle is local to the
Switchboard process.

### A call is denied even though the tool is visible

An old session can retain a formerly visible tool, but every call is checked
against its bound policy. Use `permissions explain` and `permissions diff` to
compare the active and proposed configurations. A `require_approval` decision
remains unavailable until a server-side approval workflow exists; client-side
approval alone does not convert it to `allow`.

## Recovery and rollback

Switchboard keeps MCP sessions in memory and does not own upstream business
state. A process restart invalidates sessions but does not roll back or replay
upstream operations. Restore the last reviewed configuration and environment,
restart Switchboard, verify readiness and the permission report, then reconnect
clients.

If a deployment introduced the failure, roll back the binary and configuration
together. Keep capability credentials in the environment or secret manager,
not in the rollback archive. Verify the affected upstream application's own
audit, revision, and rollback state separately; Switchboard never substitutes
for that recovery procedure.
