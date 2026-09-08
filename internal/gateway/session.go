package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewSession creates an isolated tool registry. The caller owns authentication,
// expiry, and session IDs; allowed capabilities have already been profile-filtered.
func NewSession(version, id, identity string, policy config.Client, allowed []capability.Capability) (*mcp.Server, error) {
	server := mcp.NewServer(&mcp.Implementation{Name: "switchboard", Version: version}, &mcp.ServerOptions{
		GetSessionID: func() string { return id },
		Instructions: "Use capability_search and capability_describe to discover approved capabilities. Enable tools for this session with capability_enable. Preserve upstream plan, confirmation, and rollback workflows.",
	})
	var mu sync.RWMutex
	active := map[string]bool{}
	catalog := map[string]capability.Capability{}
	toolOwners := map[string]string{}
	toolNames := map[string][]string{}
	for _, item := range allowed {
		if catalog[item.Name()] != nil {
			return nil, fmt.Errorf("duplicate capability %q", item.Name())
		}
		describer, ok := item.(capability.Describer)
		if !ok {
			return nil, fmt.Errorf("capability %s lacks session tool metadata", item.Name())
		}
		catalog[item.Name()] = item
		for _, tool := range describer.Describe().Tools {
			if toolOwners[tool.Name] != "" || tool.Name == "capability_search" || tool.Name == "capability_describe" || tool.Name == "capability_execute" || tool.Name == "capability_enable" || tool.Name == "capability_disable" {
				return nil, fmt.Errorf("duplicate or reserved tool %q", tool.Name)
			}
			toolOwners[tool.Name] = item.Name()
			toolNames[item.Name()] = append(toolNames[item.Name()], tool.Name)
		}
	}
	initial := policy.InitialCapabilities
	if initial == nil {
		for _, item := range allowed {
			initial = append(initial, item.Name())
		}
	}
	if policy.Execute {
		for _, name := range initial {
			item := catalog[name]
			if item == nil {
				return nil, fmt.Errorf("initial capability %q is not allowed", name)
			}
			if err := item.Register(server); err != nil {
				return nil, err
			}
			active[name] = true
		}
	}
	if policy.Discover {
		registerCatalog(server, allowed)
	}
	if policy.Execute {
		registerExecutor(server, policy.Profile, allowed)
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
							if err := item.Register(server); err != nil {
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
	return server, nil
}
