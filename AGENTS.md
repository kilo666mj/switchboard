# AGENTS.md

Switchboard is a private capability gateway. Keep MCP transport and capability
composition here; keep business rules, authorization, and durable state in the
upstream applications.

Capability manifests must not contain credentials. Reference environment
variables instead. Preserve upstream safety workflows rather than replacing
them with generic unrestricted HTTP calls.

For Forgejo repository, issue, pull request, release, and Actions operations,
prefer the connected `forgejo` Switchboard capability and its native
`forgejo_*` tools. Use `tea` only when the Forgejo capability is unavailable or
lacks the required operation.

After Go changes, run:

```sh
gofmt -w .
go test ./...
go vet ./...
```
