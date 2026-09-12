package gateway

import (
	"context"
	"errors"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerExecutor(server *mcp.Server, items []capability.Capability) {
	executors := map[string]capability.ReadOnlyExecutor{}
	for _, item := range items {
		if executor, ok := item.(capability.ReadOnlyExecutor); ok {
			executors[item.Name()] = executor
		}
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "capability_execute",
		Description: "Compatibility fallback for an explicitly read-only remote MCP tool allowed by the active profile. Use capability_describe for its exposed name and input schema. Mutating, destructive, and unannotated tools are rejected. Upstream authorization and safety workflows still apply.",
		Annotations: mcpkit.ReadOnly(true),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input struct {
		Capability string         `json:"capability"`
		Tool       string         `json:"tool" jsonschema:"Exact exposed tool name from capability_describe, including the capability prefix."`
		Arguments  map[string]any `json:"arguments"`
	}) (result *mcp.CallToolResult, _ any, err error) {
		executor, ok := executors[input.Capability]
		if !ok {
			return nil, nil, errors.New("remote capability is not available in the active profile")
		}
		result, err = executor.ExecuteReadOnly(ctx, input.Tool, input.Arguments)
		return result, nil, err
	})
}
