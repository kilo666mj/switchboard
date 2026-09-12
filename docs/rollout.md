# Dynamic MCP rollout and verification

## Gateway

1. Run `gofmt -w .`, `go test ./...`, and `go vet ./...`.
2. Run `go test -race ./internal/sessions ./internal/gateway ./internal/capability/remote`.
3. Validate the Ansible playbooks with `--syntax-check`.
4. Generate a unique random credential for each client installation in ignored
   `ansible/private.yml`. Map each identity to an existing profile, explicit
   permissions, and an initial capability selection. Keep the old gateway token
   during migration; it must differ from every client token.
5. Save a root-only rollback archive of `/etc/switchboard`,
   `/usr/local/bin/switchboard`, and the Switchboard systemd unit on the server.
6. Deploy with `ansible-playbook playbook.yml` from `ansible/`. For an existing
   deployment whose upstream credentials should remain on the server, add
   `-e switchboard_reuse_upstream_credentials=true`. This mode requires an
   existing root-owned mode-0600/0640 environment file and updates only a managed
   client-credential block. It neither retrieves nor replaces upstream secrets.
   Use the full deployment mode for first installation or upstream credential
   changes with their intended controller-side credential sources available.

Verify the deployed binary matches the controller build, the service is active,
and readiness returns 204. On `/mcp`, verify the legacy token still discovers
and executes a read-only upstream tool, and unauthenticated access returns 401.

On `/mcp/sessions`, verify with two distinct client credentials:

- Initialization returns a session ID and advertises tool-list changes.
- Discovery returns only the identity's approved profile.
- A configured tool policy removes denied capabilities and tools from native
  discovery and the compatibility catalog while stale calls still fail closed.
- Enable/disable changes the native tool list and emits notifications.
- Native and compatibility read-only calls return upstream results.
- Compatibility mutation and calls to disabled/excluded tools are rejected.
- A second session starts from configured defaults.
- A session ID cannot be reused by another credential.
- DELETE removes the session; later calls with that ID return 404.

Automated local tests cover idle expiry, session capacity, initialization
cleanup, argument validation, schema reference resolution, response bounds,
annotation handling, and structured results/errors. These do not replace the
live proxy and installed-client checks above.

## Client installations

Run `python3 -m unittest discover -s scripts -p 'test_*.py'`. For pi, run
`npm ci --ignore-scripts && npm test` in `clients/pi/`; its test uses a local
TLS MCP server and verifies tool refresh and mutation consent without an LLM.

Use a private inventory containing only the workstations selected for rollout:

```sh
ansible-playbook -i bootstrap-inventory.yml bootstrap.yml
```

The bootstrap supports a list of `switchboard_installations` for each host,
each with `client` and `identity`, and an optional native-client `config` path.
It installs environment references into client configuration, a protected
credential file, and optional CA trust. The pi adapter keeps the entire previous
Wayminder extension in a rollback directory rather than deleting it.

Restart each client in an environment containing the new credential variables.
Check connection and discovery without requesting model work first. Then verify
refresh behavior using the client's native tool list. Use read-only compatibility
execution when native refresh is unavailable, and document the observed behavior
for the installed version rather than assuming support from protocol compliance.

## Client compatibility checks

The client versions below were checked against a private test deployment.
Repeat these checks against the release candidate and your configured endpoint.

Live HTTPS SDK checks passed for authentication, discovery, native and
compatibility reads, mutation rejection, activation, notifications, session and
identity isolation, and session deletion. Run `node clients/pi/smoke.mjs` with
`SWITCHBOARD_SMOKE_A_TOKEN` and `SWITCHBOARD_SMOKE_B_TOKEN` containing distinct
client credentials to repeat these checks. The fixture expects Wayminder to be
initially enabled and RillDNS to be approved but initially disabled. It changes
only its temporary sessions. Set `SWITCHBOARD_SMOKE_URL` explicitly to the endpoint to test. Optional
`SWITCHBOARD_CA_CERTS` supplies a private CA bundle; otherwise the runtime
uses its normal certificate trust.

Installed-client checks used no model calls:

| Client | Version | Verified behavior |
| --- | --- | --- |
| Codex | 0.153.4 | Connected; native Wayminder read and compatibility RillDNS read passed. App-server tool status remained cached after activation. Use compatibility execution for newly enabled tools. |
| Claude Code | 2.1.260 | Connected; its running client fetched the updated native list after activation. |
| OpenCode | 1.18.27 | Connected; its running server fetched the updated native list after activation. |
| Qwen Code | 0.21.13 | Connection passed with the system CA bundle. Native refresh remains unqualified; use compatibility execution. |
| pi | Switchboard adapter 0.1.0 | Installed extension passed native discovery, read, activation refresh, and tool removal in the real agent runtime. |

Claude and OpenCode refresh was observed through a temporary loopback proxy
forwarding to the live gateway. Codex was checked through its app-server control
API, and pi through its installed agent runtime. Qwen's no-prompt control session
did not initialize the test connection; this is a verification limitation, not
evidence that its normal interactive sessions cannot refresh.

Client credentials are separate per installation and stored in the protected
`~/.config/environment.d/92-switchboard.conf`. Qwen needs
`NODE_EXTRA_CA_CERTS=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` on
Fedora systems; bootstrap installs that environment setting. Existing client
processes must restart with the updated environment. Legacy `/mcp` remains
available during migration. Read-only compatibility execution remains available
in the initial rollout, including clients whose native refresh was verified.

## Rollback

Stop Switchboard, restore the protected gateway archive to its original paths,
run `systemctl daemon-reload`, and start Switchboard. Confirm readiness and a
legacy read-only tool call. Restoring a previous configuration removes the new
credentials and session endpoint; previous session IDs never survive a restart.

For clients, restore the protected pre-Switchboard config and environment-file
backups and restart their login/client processes. For pi, move the archived
Wayminder extension back into `extensions/` and move the Switchboard adapter
outside that discovery directory. Keep archives protected because configuration
backups can contain pre-existing credentials.
