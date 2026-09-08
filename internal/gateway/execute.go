package gateway

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerExecutor(server *mcp.Server, profile string, items []capability.Capability) {
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
		started := time.Now()
		defer func() {
			outcome := "success"
			if err != nil {
				outcome = "rejected_or_failed"
			} else if result != nil && result.IsError {
				outcome = "upstream_error"
			}
			// Never log arguments, result bodies, or error strings, which may contain secrets.
			slog.InfoContext(ctx, "capability_execute", "profile", profile, "capability", input.Capability, "tool", input.Tool, "outcome", outcome, "duration_ms", time.Since(started).Milliseconds())
		}()
		executor, ok := executors[input.Capability]
		if !ok {
			return nil, nil, errors.New("remote capability is not available in the active profile")
		}
		result, err = executor.ExecuteReadOnly(ctx, input.Tool, input.Arguments)
		return result, nil, err
	})
}
