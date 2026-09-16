package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/observability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerAuditMiddleware(server *mcp.Server, identity, profile, identityPolicy, identityPolicyVersion string, identityPolicyComponents []string, sessionID string, toolOwners map[string]string, policyName string, policy config.ToolPolicy, controller *CallController, metrics *observability.Metrics) {
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			params, ok := req.GetParams().(*mcp.CallToolParamsRaw)
			if !ok {
				return next(ctx, method, req)
			}
			capabilityName, toolName := toolOwners[params.Name], params.Name
			if params.Name == "capability_execute" {
				var input struct {
					Capability string `json:"capability"`
					Tool       string `json:"tool"`
				}
				if json.Unmarshal(params.Arguments, &input) == nil && input.Capability != "" && input.Tool != "" {
					capabilityName = input.Capability
					toolName = input.Tool
				}
			}
			if capabilityName == "" {
				if isGatewayTool(params.Name) {
					capabilityName = "switchboard"
				} else {
					capabilityName = "unknown"
				}
			}

			started := time.Now()
			correlationID := rand.Text()
			decision, outcome := "allow", "success"
			var result mcp.Result
			var err error
			if capabilityName != "switchboard" {
				decision = toolDecision(policy, capabilityName, toolName)
			}
			switch decision {
			case "deny":
				outcome = "policy_denied"
				result = toolPolicyError("tool denied by operator policy")
			case "require_approval":
				outcome = "approval_required"
				result = toolPolicyError("tool requires server-side approval, which is not configured")
			case "allow":
				release, limited := controller.Admit(toolName)
				if limited != "" {
					outcome = limited
					result = toolPolicyError("tool call rejected by operator limits")
				} else {
					defer release()
					result, err = next(ctx, method, req)
					if err != nil {
						outcome = "protocol_error"
					} else if callResult, ok := result.(*mcp.CallToolResult); ok && callResult.IsError {
						outcome = "tool_error"
					}
				}
			default:
				decision = "invalid"
				outcome = "policy_denied"
				result = toolPolicyError("tool denied by invalid operator policy")
			}
			// Arguments, results, and error strings are intentionally excluded.
			duration := time.Since(started)
			slog.InfoContext(ctx, "tool_invocation",
				"identity", identity,
				"profile", profile,
				"identity_policy", identityPolicy,
				"identity_policy_version", identityPolicyVersion,
				"identity_policy_components", identityPolicyComponents,
				"session_id", sessionID,
				"correlation_id", correlationID,
				"policy", policyName,
				"policy_version", policy.Version,
				"capability", capabilityName,
				"tool", toolName,
				"decision", decision,
				"outcome", outcome,
				"duration_ms", duration.Milliseconds(),
			)
			metricCapability, metricTool := capabilityName, toolName
			if capabilityName == "unknown" || params.Name == "capability_execute" && toolOwners[toolName] != capabilityName {
				metricCapability, metricTool = "unknown", "unknown"
			}
			metrics.ObserveToolCall(metricCapability, metricTool, decision, outcome, duration)
			return result, err
		}
	})
}

func isGatewayTool(name string) bool {
	switch name {
	case "capability_search", "capability_describe", "capability_execute", "capability_enable", "capability_disable":
		return true
	default:
		return false
	}
}

func toolPolicyError(message string) *mcp.CallToolResult {
	result := new(mcp.CallToolResult)
	result.SetError(errors.New(message))
	return result
}
