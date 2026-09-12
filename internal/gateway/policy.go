package gateway

import "github.com/kilo666mj/switchboard/internal/config"

func toolDecision(policy config.ToolPolicy, capabilityName, toolName string) string {
	if policy.Version == "" {
		return "allowed_by_profile"
	}
	if decision, ok := policy.Tools[toolName]; ok {
		return decision
	}
	if decision, ok := policy.Capabilities[capabilityName]; ok {
		return decision
	}
	return "deny"
}

// Only tools that can execute immediately are advertised to clients. Explicit
// denies and unimplemented server-side approval requirements remain enforceable
// for stale native definitions and compatibility calls, but are not discoverable.
func toolVisible(policy config.ToolPolicy, capabilityName, toolName string) bool {
	decision := toolDecision(policy, capabilityName, toolName)
	return decision == "allow" || decision == "allowed_by_profile"
}
