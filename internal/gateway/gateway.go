package gateway

import (
	"fmt"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/observability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func New(version, profile, policyName string, policy config.ToolPolicy, capabilities []capability.Capability) (*mcp.Server, error) {
	return NewWithMetrics(version, profile, policyName, policy, capabilities, nil)
}

func NewWithMetrics(version, profile, policyName string, policy config.ToolPolicy, capabilities []capability.Capability, metrics *observability.Metrics) (*mcp.Server, error) {
	if policy.Version == "" {
		return nil, fmt.Errorf("explicit tool policy is required")
	}
	if policy.Profile != profile {
		return nil, fmt.Errorf("tool policy profile %q does not match gateway profile %q", policy.Profile, profile)
	}
	if err := ValidateToolPolicy(policy, capabilities); err != nil {
		return nil, err
	}
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
		if err := registerVisibleTools(server, item, policy); err != nil {
			return nil, fmt.Errorf("register capability %s: %w", item.Name(), err)
		}
	}
	registerCatalog(server, capabilities, policy)
	registerExecutor(server, capabilities)
	toolOwners := map[string]string{}
	for _, item := range capabilities {
		if describer, ok := item.(capability.Describer); ok {
			for _, tool := range describer.Describe().Tools {
				toolOwners[tool.Name] = item.Name()
			}
		}
	}
	registerAuditMiddleware(server, "legacy-shared", profile, "legacy", "", nil, "", toolOwners, policyName, policy, nil, metrics)
	return server, nil
}
