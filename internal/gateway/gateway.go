package gateway

import (
	"fmt"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func New(version, profile string, capabilities []capability.Capability) (*mcp.Server, error) {
	server, err := mcpkit.NewServer(mcpkit.ServerConfig{
		Name:         "switchboard",
		Version:      version,
		Instructions: "Switchboard exposes curated API capabilities for the active " + profile + " profile. Preserve plan, revision, confirmation, and rollback workflows exposed by tools.",
	})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, item := range capabilities {
		if seen[item.Name()] {
			return nil, fmt.Errorf("duplicate capability %q", item.Name())
		}
		seen[item.Name()] = true
		if err := item.Register(server); err != nil {
			return nil, fmt.Errorf("register capability %s: %w", item.Name(), err)
		}
	}
	registerCatalog(server, capabilities)
	registerExecutor(server, profile, capabilities)
	return server, nil
}
