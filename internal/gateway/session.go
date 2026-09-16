package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/observability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewSession creates an isolated tool registry. The caller owns authentication,
// expiry, and session IDs; allowed capabilities have already been profile-filtered.
func NewSession(version, id, identity string, policy config.Client, toolPolicy config.ToolPolicy, controller *CallController, metrics *observability.Metrics, allowed []capability.Capability) (*mcp.Server, error) {
	if err := ValidateToolPolicy(toolPolicy, allowed); err != nil {
		return nil, err
	}
	if toolPolicy.Version != "" && toolPolicy.Profile != policy.Profile {
		return nil, fmt.Errorf("tool policy profile %q does not match client profile %q", toolPolicy.Profile, policy.Profile)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "switchboard", Version: version}, &mcp.ServerOptions{
		GetSessionID: func() string { return id },
		Instructions: "Prefer native tools from connected capabilities for external services before falling back to command-line clients. Use capability_search and capability_describe when you need to inspect the approved catalog. Preserve upstream plan, confirmation, and rollback workflows.",
	})
	var mu sync.RWMutex
	active := map[string]bool{}
	catalog := map[string]capability.Capability{}
	seenCapabilities := map[string]bool{}
	toolOwners := map[string]string{}
	toolNames := map[string][]string{}
	for _, item := range allowed {
		if seenCapabilities[item.Name()] {
			return nil, fmt.Errorf("duplicate capability %q", item.Name())
		}
		seenCapabilities[item.Name()] = true
		describer, ok := item.(capability.Describer)
		if !ok {
			return nil, fmt.Errorf("capability %s lacks session tool metadata", item.Name())
		}
		visibleCount := 0
		for _, tool := range describer.Describe().Tools {
			if toolOwners[tool.Name] != "" || tool.Name == "capability_search" || tool.Name == "capability_describe" || tool.Name == "capability_execute" || tool.Name == "capability_enable" || tool.Name == "capability_disable" {
				return nil, fmt.Errorf("duplicate or reserved tool %q", tool.Name)
			}
			toolOwners[tool.Name] = item.Name()
			if toolVisible(toolPolicy, item.Name(), tool.Name) {
				toolNames[item.Name()] = append(toolNames[item.Name()], tool.Name)
				visibleCount++
			}
		}
		if visibleCount > 0 {
			catalog[item.Name()] = item
		}
	}
	exposed := make([]capability.Capability, 0, len(catalog))
	for _, item := range allowed {
		if catalog[item.Name()] != nil {
			exposed = append(exposed, item)
		}
	}
	initial := policy.InitialCapabilities
	if initial == nil {
		for _, item := range exposed {
			initial = append(initial, item.Name())
		}
	}
	if policy.Execute {
		for _, name := range initial {
			item := catalog[name]
			if item == nil {
				return nil, fmt.Errorf("initial capability %q is not allowed", name)
			}
			if err := registerVisibleTools(server, item, toolPolicy); err != nil {
				return nil, err
			}
			active[name] = true
		}
	}
	if policy.Discover {
		registerCatalog(server, exposed, toolPolicy)
	}
	if policy.Execute {
		registerExecutor(server, exposed)
	}
	if policy.Activate && policy.Execute {
		for _, enable := range []bool{true, false} {
			name := "capability_disable"
			if enable {
				name = "capability_enable"
			}
			mcp.AddTool(server, &mcp.Tool{Name: name, Description: "Change capability activation in this authenticated session only. Only the operator-approved profile is available. Refresh tools/list after success. No persistent profile changes.", Annotations: mcpkit.Mutating(true, false)},
				func(ctx context.Context, _ *mcp.CallToolRequest, input struct {
					Name string `json:"name"`
				}) (*mcp.CallToolResult, map[string]any, error) {
					mu.Lock()
					defer mu.Unlock()
					item := catalog[input.Name]
					if item == nil {
						return nil, nil, fmt.Errorf("capability is not available in this profile")
					}
					if active[input.Name] != enable {
						if enable {
							if err := registerVisibleTools(server, item, toolPolicy); err != nil {
								return nil, nil, err
							}
						} else {
							server.RemoveTools(toolNames[input.Name]...)
						}
						active[input.Name] = enable
					}
					slog.InfoContext(ctx, "capability_activation", "identity", identity, "profile", policy.Profile, "capability", input.Name, "enabled", enable)
					return nil, map[string]any{"name": input.Name, "enabled": enable, "scope": "session"}, nil
				})
		}
	}
	// Serialize native calls against disable, including calls already looked up by
	// the SDK. A disabled tool cannot execute through a stale client definition.
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/call" {
				params, ok := req.GetParams().(*mcp.CallToolParamsRaw)
				if ok && params.Name == "capability_execute" {
					var input struct {
						Capability string `json:"capability"`
					}
					if err := json.Unmarshal(params.Arguments, &input); err != nil {
						return nil, err
					}
					mu.RLock()
					defer mu.RUnlock()
					if !active[input.Capability] {
						return nil, fmt.Errorf("capability is disabled in this session")
					}
				}
				if ok && toolOwners[params.Name] != "" {
					mu.RLock()
					defer mu.RUnlock()
					if !active[toolOwners[params.Name]] {
						return nil, fmt.Errorf("capability is disabled in this session")
					}
				}
			}
			return next(ctx, method, req)
		}
	})
	registerAuditMiddleware(server, identity, policy.Profile, policy.IdentityPolicy, policy.IdentityPolicyVersion, policy.IdentityPolicyComponents, id, toolOwners, policy.ToolPolicy, toolPolicy, controller, metrics)
	return server, nil
}

func registerVisibleTools(server *mcp.Server, item capability.Capability, policy config.ToolPolicy) error {
	if err := item.Register(server); err != nil {
		return err
	}
	if policy.Version == "" {
		return nil
	}
	describer := item.(capability.Describer)
	for _, tool := range describer.Describe().Tools {
		if !toolVisible(policy, item.Name(), tool.Name) {
			server.RemoveTools(tool.Name)
		}
	}
	return nil
}

// ValidateToolPolicy catches stale or misspelled explicit entries before use.
// Tools omitted from a configured policy remain valid configuration and deny at runtime.
func ValidateToolPolicy(policy config.ToolPolicy, allowed []capability.Capability) error {
	return ValidateToolPolicyAvailable(policy, allowed, nil)
}

// ValidateToolPolicyAvailable validates everything that can be checked while
// allowing entries owned by a configured but temporarily unavailable
// capability. Those entries are validated when the capability recovers.
func ValidateToolPolicyAvailable(policy config.ToolPolicy, allowed []capability.Capability, unavailable map[string]bool) error {
	if policy.Version == "" {
		return nil
	}
	available := map[string]bool{}
	capabilities := map[string]bool{}
	for _, item := range allowed {
		capabilities[item.Name()] = true
		describer, ok := item.(capability.Describer)
		if !ok {
			return fmt.Errorf("capability %s lacks session tool metadata", item.Name())
		}
		for _, tool := range describer.Describe().Tools {
			available[tool.Name] = true
		}
	}
	for name, decision := range policy.Capabilities {
		if !capabilities[name] && !unavailable[name] {
			return fmt.Errorf("tool policy references unavailable capability %q", name)
		}
		switch decision {
		case "allow", "deny", "require_approval":
		default:
			return fmt.Errorf("tool policy has invalid decision %q for capability %q", decision, name)
		}
	}
	for name := range policy.Tools {
		if !available[name] && !toolBelongsToUnavailable(name, capabilities, unavailable) {
			return fmt.Errorf("tool policy references unavailable tool %q", name)
		}
		switch policy.Tools[name] {
		case "allow", "deny", "require_approval":
		default:
			return fmt.Errorf("tool policy has invalid decision %q for tool %q", policy.Tools[name], name)
		}
	}
	return nil
}

func toolBelongsToUnavailable(tool string, available, unavailable map[string]bool) bool {
	owner := ""
	for name := range available {
		if strings.HasPrefix(tool, name+"_") && len(name) > len(owner) {
			owner = name
		}
	}
	for name := range unavailable {
		if strings.HasPrefix(tool, name+"_") && len(name) > len(owner) {
			owner = name
		}
	}
	return unavailable[owner]
}
