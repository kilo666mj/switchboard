# AGENTS.md

Switchboard is a private capability gateway. Keep MCP transport and capability
composition here; keep business rules, authorization, and durable state in the
upstream applications.

Capability manifests must not contain credentials. Reference environment
variables instead. Preserve upstream safety workflows rather than replacing
them with generic unrestricted HTTP calls.

After Go changes, run:

```sh
gofmt -w .
go test ./...
go vet ./...
```
