# Log Watcher module

This independently runnable stdio MCP module adapts Log Watcher's canonical
HTTP API. Switchboard owns its process and MCP transport lifecycle; Log Watcher
continues to own exclusions, authorization, auditing, and other durable state.

The module embeds `api.json`, so its API contract and MCP tool schemas ship with
the executable. Runtime URL and credential values are read from
`LOG_WATCHER_API_URL` and `LOG_WATCHER_API_TOKEN`. Switchboard passes only the
environment names allowlisted by the outer capability manifest.

Build it with:

```sh
go build -o switchboard-module-log-watcher ./modules/log_watcher
```

Install the executable at the absolute path named by
`capabilities/log_watcher.example.json`. The Ansible deployment and review
archive builder do this automatically. When Switchboard has a global egress
policy, the module receives and enforces the same non-secret destination and
CIDR boundary for its HTTP client.
