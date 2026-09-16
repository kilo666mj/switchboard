# Switchboard extension for pi

Exposes the native tools of one Switchboard session to pi and refreshes them when
the gateway's tool list changes. Node.js 22.19.0 or newer is required by the pinned
runtime dependencies. The pi host provides its extension API and TypeScript loader.

Install the reviewed source into a dedicated pi extension directory, then run:

```sh
npm ci --omit=dev --ignore-scripts --no-audit --no-fund
```

The source bundle includes the lockfile, not node_modules. Keep the installation
outside worker checkouts. Configure `SWITCHBOARD_PI_CONFIG` to an operator-owned
JSON file with the HTTPS session endpoint and Pi's registered public PKCE client:

```json
{
  "url": "https://gateway.example.com/mcp/sessions",
  "issuer": "https://identity.example.com",
  "client_id": "pi-switchboard",
  "redirect_url": "http://127.0.0.1:18104/callback",
  "scopes": ["openid", "groups", "mcp:connect", "tools:read", "tools:write", "offline_access"]
}
```

The default configuration path is `~/.pi/agent/switchboard.json`. Run
`npm --prefix ~/.pi/agent/extensions/switchboard run login` once to authorize
the client. Tokens are written atomically with mode `0600` to
`~/.pi/agent/switchboard-oauth.json`; `SWITCHBOARD_PI_TOKEN_FILE` overrides that
path for isolated testing. Optional
`SWITCHBOARD_CA_CERTS` selects a CA bundle. If set, it must point to a readable,
nonempty file; configuration failures stop the connection without falling back
to system trust. When unset, the adapter tries system bundles. Certificate
verification stays enabled. Reload pi after installation. Do not put tokens in
source, archives, client configuration, or gateway capability manifests.

The gateway profile must allow the intended capabilities. Native tools retain
their upstream authorization requirements. A Relay upstream credential represents
one Relay identity; different gateway tokens sharing it do not create different
Relay actors.

For development, use the repository checkout, run `npm ci --ignore-scripts`, and
then `npm test`. Development tests and their loader dependency are not included
in the source review bundle. Installed-client acceptance remains distinct from
adapter tests and must be verified in the intended pi runtime.

The extension is MIT licensed. The source review bundle includes the project
license and a runtime dependency inventory with verbatim notices collected from
a fresh locked installation. Review additional distribution obligations before
publishing. The package remains marked private to prevent accidental npm release.

## Installed-host verification

From a repository checkout with runtime dependencies installed:

```sh
SWITCHBOARD_PI_BINARY=/absolute/path/to/pi node clients/pi/host-smoke.mjs
```

Run that command from the repository root. The opt-in test starts the real pi CLI
in RPC mode with a temporary home/configuration directory, explicit extensions,
no session persistence and no skill discovery. A temporary HTTPS MCP fixture
provides synthetic tool metadata. A second extension observes pi's public tool
registry through its RPC notification API. The check verifies initial tool
registration, JSON schema preservation, tool additions/removals after upstream
notifications and preservation of built-in tools.

This passed locally with pi 0.84.4. It makes no model or upstream tool calls and
does not change installed pi configuration. Task execution, mutation approval in
the intended UI, live gateway identity and public deployment remain separate
acceptance requirements. The synthetic adapter test covers invocation and
approval behavior using a fixture extension context.

Add `--execute` to exercise the installed host's tool execution and RPC approval
protocol against an additional local synthetic model endpoint:

```sh
SWITCHBOARD_PI_BINARY=/absolute/path/to/pi node clients/pi/host-smoke.mjs --execute
```

The fixture requests three tool calls: read-only, denied mutation and approved
mutation. The test verifies that read-only execution needs no confirmation,
denial sends no upstream call, acceptance sends exactly one call, structured
results survive the host's tool pipeline, and the model receives the denied
outcome. All three turns settle. The check uses six synthetic model responses
and two synthetic MCP tool calls; no real provider or production gateway is used.
RPC dialog replies are supplied by that test. The separate interactive TUI
check below exercises real keyboard approval controls. Full Relay task flow through the deployed gateway is
also distinct from this host/adapter test.

Approval is tied to the tool catalog shown when execution begins. If a catalog
refresh or session shutdown occurs while a confirmation dialog is open, that
pending invocation is rejected before any upstream call, even if a tool with the
same name is activated again. Retry using the current tool definition and review
its new confirmation. This prevents an old approval from authorizing a replaced
or revoked tool.

When Switchboard announces a catalog change, its active tools are disabled until
a complete replacement list is available. A failed refresh leaves them disabled
and shows a generic notification without backend error text. Built-in and other
non-Switchboard tools remain active. A later valid catalog notification restores
Switchboard tools; an older delayed response cannot overwrite the newer catalog.
Calls already submitted upstream are not undone by a catalog refresh.

Session shutdown invalidates the old tools immediately, attempts gateway session
deletion with a two-second request deadline, then closes the MCP connection and
destroys the HTTP dispatcher. Repeated shutdown is harmless. A stalled gateway
cannot indefinitely prevent local cleanup or a session switch. Cancelling local
I/O does not prove that a mutation already submitted upstream was rolled back;
inspect its durable state before deciding whether to retry.

## Interactive pi approval check

On 6 September 2026, installed pi 0.84.4 passed a separate interactive terminal
check at 120 columns by 40 rows. The CLI used a temporary home and agent directory,
the real Switchboard adapter, local HTTPS MCP fixtures and a synthetic model.
Keystrokes were entered into the actual TUI; no RPC approval replies or replacement
UI methods were used.

| Turn | Terminal action | Total upstream calls after turn |
| --- | --- | ---: |
| Read-only tool | Submit read prompt; no dialog | 1 |
| Mutating tool denied | Down, Enter to select No | 1 |
| Mutating tool approved | Enter to select Yes | 2 |
| Mutating tool cancelled | Escape | 2 |

The dialog displayed the tool name and description. Eight synthetic model
requests completed four turns, including the denied/cancelled tool outcomes
returned to the model. Success and denial results were visible in the TUI. The
session exited normally with Ctrl+D, and the fixture processes and temporary
configuration were removed. No real provider or deployed gateway was contacted.

This checks the native approval controls on the installed client. Full Relay
task flow is now separately verified by Relay's opt-in
`TestSwitchboardRelayPiTUIWorkflow`: actual Relay/Switchboard processes, three
rendered native approvals, completed task and authenticated identity/audit checks.
Both RPC and terminal variants passed with race detection on pi 0.84.4.
Real-provider execution and public deployment remain separate.
