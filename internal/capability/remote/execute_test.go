package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/mcpkit/mcpkittest"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCompatibilityExecution(t *testing.T) {
	upstream := mcpkit.MustServer(mcpkit.ServerConfig{Name: "upstream", Version: "test"})
	var calls atomic.Int32
	schema := map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "integer", "minimum": 1}}, "required": []string{"value"}, "additionalProperties": false}
	for _, tc := range []struct {
		name        string
		annotations *mcp.ToolAnnotations
	}{
		{"read", mcpkit.ReadOnly(false)}, {"mutate", mcpkit.Mutating(false, false)},
		{"destroy", mcpkit.Destructive(false, false)}, {"unknown", nil}, {"z_hidden", mcpkit.ReadOnly(false)},
	} {
		upstream.AddTool(&mcp.Tool{Name: tc.name, InputSchema: schema, Annotations: tc.annotations}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			calls.Add(1)
			if string(req.Params.Arguments) == `{"value":3}` {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "success"}}, StructuredContent: map[string]any{"value": 3}}, nil
			}
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "upstream policy denied"}}, StructuredContent: map[string]any{"reason": "policy"}}, nil
		})
	}
	handler, err := mcpkit.StatelessHTTP(func(*http.Request) *mcp.Server { return upstream }, mcpkit.HTTPOptions{DisableLocalhostProtection: true})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(handler)
	defer api.Close()
	item, err := New(t.Context(), Manifest{Version: 1, Type: "mcp", Name: "test", Endpoint: api.URL, IncludeTools: []string{"read", "mutate", "destroy", "unknown"}})
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	server, err := gateway.New("test", "restricted", []capability.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	for _, tc := range []struct {
		cap, tool string
		args      any
		forwarded bool
	}{
		{"test", "test_read", map[string]any{"value": 2}, true},
		{"test", "test_read", map[string]any{}, false},
		{"test", "test_read", map[string]any{"value": "secret-canary"}, false},
		{"test", "test_read", map[string]any{"value": 0}, false},
		{"test", "test_read", map[string]any{"value": 1, "extra": true}, false},
		{"test", "test_read", nil, false},
		{"test", "test_mutate", map[string]any{"value": 1}, false},
		{"test", "test_destroy", map[string]any{"value": 1}, false},
		{"test", "test_unknown", map[string]any{"value": 1}, false},
		{"test", "test_z_hidden", map[string]any{"value": 1}, false},
		{"hidden", "test_read", map[string]any{"value": 1}, false},
		{"test", "read", map[string]any{"value": 1}, false},
	} {
		before := calls.Load()
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "capability_execute", Arguments: map[string]any{"capability": tc.cap, "tool": tc.tool, "arguments": tc.args}})
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatalf("expected rejection or upstream error: %+v", tc)
		}
		forwarded := calls.Load() != before
		if forwarded != tc.forwarded {
			t.Fatalf("forwarded=%v: %+v", forwarded, tc)
		}
		if tc.forwarded {
			data, _ := json.Marshal(result)
			if !strings.Contains(string(data), "upstream policy denied") || !strings.Contains(string(data), `"reason":"policy"`) {
				t.Fatalf("lost upstream result: %s", data)
			}
		}
	}
	if !strings.Contains(logs.String(), `"profile":"restricted"`) || !strings.Contains(logs.String(), `"tool":"test_read"`) || !strings.Contains(logs.String(), `"outcome":"tool_error"`) {
		t.Fatalf("missing audit fields: %s", logs.String())
	}
	if strings.Contains(logs.String(), "secret-canary") || strings.Contains(logs.String(), "upstream policy denied") {
		t.Fatal("audit leaked payload")
	}
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "capability_execute", Arguments: map[string]any{"capability": "test", "tool": "test_read", "arguments": map[string]any{"value": 3}}})
	if err != nil || result.IsError {
		t.Fatalf("read-only execution failed: %v, %+v", err, result)
	}
	data, _ := json.Marshal(result)
	if !strings.Contains(string(data), `"value":3`) || !strings.Contains(string(data), "success") {
		t.Fatalf("lost successful result: %s", data)
	}
	// Native operations retain their original behavior and annotations.
	before := calls.Load()
	_, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "test_mutate", Arguments: map[string]any{"value": 1}})
	if err != nil || calls.Load() != before+1 {
		t.Fatalf("native execution changed: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := item.ExecuteReadOnly(ctx, "test_read", map[string]any{"value": 1}); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestCompatibilitySchemaResolution(t *testing.T) {
	for _, input := range []any{nil, map[string]any{"type": "object", "$ref": "https://example.invalid/schema"}, map[string]any{"type": "array"}} {
		if resolveInputSchema(input) != nil {
			t.Fatalf("unsupported schema accepted: %v", input)
		}
	}
	schema := resolveInputSchema(map[string]any{"type": "object", "$defs": map[string]any{"value": map[string]any{"type": "string", "enum": []string{"ok"}}}, "properties": map[string]any{"value": map[string]any{"$ref": "#/$defs/value"}}, "required": []string{"value"}})
	if schema == nil {
		t.Fatal("local reference not resolved")
	}
	if err := schema.Validate(map[string]any{"value": "wrong"}); err == nil {
		t.Fatal("local reference not enforced")
	}
	if err := schema.Validate(map[string]any{"value": "ok"}); err != nil {
		t.Fatal(err)
	}
}

func TestResponseBound(t *testing.T) {
	for _, size := range []int{maxResponseBytes - 1, maxResponseBytes, maxResponseBytes + 1} {
		body := &boundedBody{ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", size))), remaining: maxResponseBytes}
		data, err := io.ReadAll(body)
		if (err != nil) != (size > maxResponseBytes) {
			t.Fatalf("size=%d error=%v", size, err)
		}
		if size <= maxResponseBytes && len(data) != size {
			t.Fatalf("truncated valid response")
		}
	}
}

func TestCompatibilityRejectsUnusableBindings(t *testing.T) {
	for _, annotations := range []*mcp.ToolAnnotations{mcpkit.ReadOnly(false), {ReadOnlyHint: true, DestructiveHint: new(true)}} {
		item := &Capability{tools: []toolBinding{{definition: &mcp.Tool{Name: "test_read", Annotations: annotations}}}}
		if _, err := item.ExecuteReadOnly(t.Context(), "test_read", map[string]any{}); err == nil {
			t.Fatal("unusable binding accepted")
		}
	}
}
