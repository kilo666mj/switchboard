# Pocket ID OAuth setup

Switchboard uses Pocket ID as an OAuth authorization server, not as an
interactive login page inside the gateway. The MCP client performs the
authorization-code and PKCE flow. Switchboard receives the resulting access
token on every `/mcp/sessions` request and acts only as the resource server.

The existing `oidcrp` browser-session helper is therefore not used by
Switchboard. It verifies ID tokens and issues application sessions, while an MCP
resource server must validate audience-bound access tokens and return OAuth
resource metadata and challenges.

## Pocket ID configuration

1. Create a Pocket ID API named `Switchboard MCP`.
2. Set its permanent resource to the canonical external endpoint, for example
   `https://switchboard.example.com/mcp/sessions`. Do not include a trailing
   slash.
3. Add narrowly named permissions. A read-only pilot can start with
   `mcp:connect` and `tools:read`.
4. Grant those permissions as user-delegated access only to reviewed MCP
   clients. Do not grant client access unless a workload genuinely needs M2M
   operation.
5. Restrict the OIDC client to the approved Pocket ID users or groups.
6. Configure a short access-token lifetime because Switchboard validates JWTs
   locally rather than introspecting each request.

For clients supporting Client ID Metadata Documents, enable CIMD in Pocket ID
and allowlist each exact HTTPS metadata-document URL. Avoid wildcard entries.
Other clients can use a pre-registered public client with authorization code and
PKCE.

## Client setup

### Codex

Codex supports Streamable HTTP MCP OAuth and Client ID Metadata Documents. In
Pocket ID, allowlist Codex's exact metadata-document URL:

```text
https://chatgpt.com/oauth/codex/client.json
```

Configure the server without a bearer-token environment variable:

```toml
[mcp_servers.switchboard]
url = "https://switchboard.example.com/mcp/sessions"
default_tools_approval_mode = "writes"
```

Then authorize the scopes required by the selected Switchboard policy:

```sh
codex mcp login switchboard \
  --scopes mcp:connect,tools:read,tools:write,groups \
  --oauth-client-registration cimd
```

Add `groups` to the requested and required scopes when Switchboard policies use
Pocket ID group membership. Pocket ID only releases non-empty group membership
to clients authorized for that OIDC scope.

Keep client-side approval enabled for writes. OAuth authenticates the person
and constrains the gateway policy; it does not replace confirmation for a
mutating tool call. See the
[official Codex MCP documentation](https://developers.openai.com/codex/mcp/).

### Pi

Pi does not have a native MCP transport. Its Switchboard extension must provide
the MCP SDK OAuth client and should use a separately registered Pocket ID public
client with authorization code, PKCE, and a fixed loopback redirect such as
`http://127.0.0.1:18104/callback`. Grant only user-delegated API permissions;
do not assign client or machine-to-machine access.

The local adapter's login helper can be run with:

```sh
npm --prefix ~/.pi/agent/extensions/switchboard run login
```

Store the resulting token set in a mode-0600 file outside the extension source,
preserve refresh tokens when Pocket ID rotates access tokens, and never write
tokens to Pi's configuration file. The extension should continue to require UI
approval for mutating or unannotated tools. Restart Pi or use `/reload` after
changing the extension.

These OAuth client setups are separate from the static-token managed bootstrap
described in the README. Keep static credentials available during migration and
retire them only as an explicit follow-up after fresh-process OAuth verification.

Pocket ID references:

- <https://pocket-id.org/docs/guides/apis>
- <https://pocket-id.org/docs/guides/client-id-metadata-documents>

## Switchboard configuration

```json
{
  "oauth": {
    "issuer": "https://id.example.com",
    "resource": "https://switchboard.example.com/mcp/sessions",
    "required_scopes": ["openid", "groups", "mcp:connect"],
    "group_claim": "groups",
    "group_source": "userinfo",
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

Pocket ID 2.14 access tokens carry the protected JWT header `typ: at+jwt`,
not a `type: access-token` payload claim. The `jwt_type` check is applied after
signature verification. Do not configure the older payload-claim example for
these tokens.

Pocket ID returns the `groups` claim in its ID token and UserInfo response, not
in the audience-bound API access token presented to Switchboard. Configure
`group_source: "userinfo"`; Switchboard validates the access token first, then
retrieves UserInfo and requires its `sub` to match the validated access-token
subject. Keep the issuer's UserInfo endpoint reachable through the same egress
controls as discovery and JWKS.

Use exact immutable Pocket ID `sub` values under `subjects` for workload or
individual exceptions. A policy may contain both `subjects` and `groups`; in
that case both dimensions must match. Matching more than one policy is rejected
instead of choosing a more privileged policy.

If outbound egress policy is enabled, allow the Pocket ID issuer and every host
used by its discovered JWKS and UserInfo URIs. Discovery, key, and UserInfo
responses are HTTPS-only, redirect-rejected, and bounded to 1 MiB.

## Verification

Before enabling a client, verify that:

- the protected-resource document is available at
  `/.well-known/oauth-protected-resource/mcp/sessions`;
- an unauthenticated MCP request returns `401` with a `resource_metadata`
  challenge;
- the access token's `aud` exactly matches the configured resource;
- the token contains the required permissions in the configured scope claim;
- the verified subject and groups select exactly one Switchboard policy;
- changing the mapped policy cannot reuse a session created under the previous
  policy; and
- an ID token, expired token, wrong-audience token, and static token with the
  migration switch disabled are all rejected.

### Private deployment status

The private pilot now uses Pocket ID UserInfo groups with composed policies.
Fresh OAuth sessions have verified the expected policy-component union,
effective-policy hash, representative read-only calls, and denial of a staged
capability whose group is absent. Rendercase and Tintwire now accept a reserved
per-call subject only when Switchboard authenticates with their configured
service client, and Switchboard forwards that subject only from a verified OAuth
session. Their exact-tool policies are deployed but remain unassigned pending
distinct-user and denied-caller tests. Static session clients and the legacy MCP
bearer remain enabled only as migration rollback paths until every installed
client has moved and the remaining entitlement and network-isolation checks
pass.

Prometheus deployment automation and alert rules live in
[`ansible/monitoring.yml`](../ansible/monitoring.yml) and
[`monitoring/switchboard.rules.yml`](../monitoring/switchboard.rules.yml). The
alerts cover repeated authentication failures, UserInfo validation failures,
and changes to a composed component set's effective-policy hash.

## Migration

### Read-only pilot expansion

Qualify one status-only connection before granting access to internal data.
Keep that connection separate from existing static-token clients until its
replacement policy is approved and tested.

A small next-stage candidate is to allow the read-only `fleetglass` capability
and add only `wayminder_status` from the mixed read/write Wayminder capability.
This enables fleet inspection without memory-content retrieval or mutations.
Fleet data still exposes internal host names, operational health, and attention
items: read-only does not mean non-sensitive. Review the upstream credential
scope and authorization before approval; a capability allow does not create
per-host data isolation and also authorizes future tools added to that MCP.

Before deploying an expanded policy:

- obtain approval for the capabilities, exact overrides, intended users, and
  exposed data;
- retain exact subject matching, existing scopes, and disabled activation;
- increment both identity-policy and tool-policy versions;
- verify a fresh OAuth session discovers only its effective allowed tools and
  can call representative tools from each approved capability;
- verify excluded reads and mutations are denied through both native and
  compatibility calls, without executing a production mutation;
- confirm the previous policy's session cannot be reused;
- verify audit records contain the expected identity, policy versions, and
  allow/deny outcomes; and
- verify an existing static client still works.

Do not enable this candidate merely because it is documented here. Keep
static-token retirement separate from expanding the pilot's tool permissions.

### Static-token retirement

1. Enable OAuth with `allow_static_clients: true` while existing
   `/mcp/sessions` clients are moved.
2. Verify individual identity and policy fields in gateway audit events.
3. Set `allow_static_clients: false` and restart Switchboard.
4. Unset `SWITCHBOARD_BEARER_TOKEN` to remove the separate legacy `/mcp` route.
5. Remove obsolete static client tokens from the secret store and configuration
   through the normal credential-revocation procedure.

MCP authorization reference:
<https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
