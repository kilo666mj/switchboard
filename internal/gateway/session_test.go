package gateway_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kilo666mj/mcpkit/mcpkittest"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/capability/rest"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/kilo666mj/switchboard/internal/requestmeta"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSessionPermissions(t *testing.T) {
	item, err := rest.New(rest.Manifest{Version: 1, Name: "demo", BaseURL: "http://unused.invalid", Tools: []rest.Tool{{Name: "read", Path: "/", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		policy config.Client
		count  int
	}{
		{config.Client{}, 0},
		{config.Client{Discover: true}, 2},
		{config.Client{Execute: true}, 2},
		{config.Client{Activate: true}, 0},
		{config.Client{Discover: true, Execute: true, Activate: true, InitialCapabilities: []string{}}, 5},
	} {
		tc.policy.Profile = "read"
		tc.policy.ToolPolicy = "test"
		toolPolicy := config.ToolPolicy{Version: "test", Profile: "read", Capabilities: map[string]string{"demo": "allow"}}
		server, err := gateway.NewSession("test", "test", "identity", tc.policy, toolPolicy, nil, nil, []capability.Capability{item})
		if err != nil {
			t.Fatal(err)
		}
		session := mcpkittest.Connect(t, server)
		tools, err := session.ListTools(t.Context(), &mcp.ListToolsParams{})
		if err != nil {
			t.Fatal(err)
		}
		if len(tools.Tools) != tc.count {
			t.Fatalf("policy=%+v tools=%d", tc.policy, len(tools.Tools))
		}
	}
}

func TestSessionAuditsNativeToolWithoutPayloads(t *testing.T) {
	var upstreamCorrelationID atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCorrelationID.Store(r.Header.Get(requestmeta.CorrelationIDHeader))
		_, _ = w.Write([]byte("secret-result-canary"))
	}))
	defer upstream.Close()
	item, err := rest.New(rest.Manifest{Version: 1, Name: "demo", BaseURL: upstream.URL, Tools: []rest.Tool{{Name: "read", Path: "/", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	toolPolicy := config.ToolPolicy{Version: "pilot-v1", Profile: "read", Tools: map[string]string{"demo_read": "allow"}}
	server, err := gateway.NewSession("test", "session-1", "alice", config.Client{Profile: "read", Execute: true, ToolPolicy: "pilot", IdentityPolicy: "oauth:readers", IdentityPolicyVersion: "pilot-v1", IdentityPolicyComponents: []string{"fleet-readers"}}, toolPolicy, nil, nil, []capability.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "demo_read", Arguments: map[string]any{"query": "secret-argument-canary"}})
	if err != nil || result.IsError {
		t.Fatalf("native tool call failed: %v %+v", err, result)
	}
	audit := logs.String()
	for _, field := range []string{`"msg":"tool_invocation"`, `"identity":"alice"`, `"profile":"read"`, `"identity_policy":"oauth:readers"`, `"identity_policy_version":"pilot-v1"`, `"identity_policy_components":["fleet-readers"]`, `"session_id":"session-1"`, `"capability":"demo"`, `"tool":"demo_read"`, `"decision":"allow"`, `"outcome":"success"`, `"correlation_id":`} {
		if !strings.Contains(audit, field) {
			t.Fatalf("missing audit field %s: %s", field, audit)
		}
	}
	if strings.Contains(audit, "secret-argument-canary") || strings.Contains(audit, "secret-result-canary") {
		t.Fatalf("audit leaked tool payload: %s", audit)
	}
	correlationID, _ := upstreamCorrelationID.Load().(string)
	if correlationID == "" || !strings.Contains(audit, `"correlation_id":"`+correlationID+`"`) {
		t.Fatalf("upstream and audit correlation IDs differ: upstream=%q audit=%s", correlationID, audit)
	}
}

func TestSessionEnforcesExplicitToolPolicy(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	tools := []rest.Tool{}
	for _, name := range []string{"allowed", "denied", "approval", "omitted"} {
		tools = append(tools, rest.Tool{Name: name, Path: "/", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)})
	}
	item, err := rest.New(rest.Manifest{Version: 1, Name: "demo", BaseURL: upstream.URL, Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	policy := config.ToolPolicy{Version: "pilot-v1", Profile: "read", Tools: map[string]string{
		"demo_allowed":  "allow",
		"demo_denied":   "deny",
		"demo_approval": "require_approval",
	}}
	server, err := gateway.NewSession("test", "session-1", "alice", config.Client{Profile: "read", Execute: true, ToolPolicy: "pilot"}, policy, nil, nil, []capability.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	session := mcpkittest.Connect(t, server)
	for _, tc := range []struct {
		name    string
		allowed bool
	}{
		{"demo_allowed", true},
		{"demo_denied", false},
		{"demo_approval", false},
		{"demo_omitted", false},
	} {
		before := calls.Load()
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: tc.name, Arguments: map[string]any{}})
		if err != nil {
			t.Fatalf("%s returned protocol error: %v", tc.name, err)
		}
		if result.IsError == tc.allowed {
			t.Fatalf("%s error=%v, allowed=%v", tc.name, result.IsError, tc.allowed)
		}
		if got := calls.Load() - before; got != map[bool]int32{true: 1, false: 0}[tc.allowed] {
			t.Fatalf("%s forwarded %d calls", tc.name, got)
		}
	}
	audit := logs.String()
	for _, field := range []string{`"policy":"pilot"`, `"policy_version":"pilot-v1"`, `"decision":"allow"`, `"decision":"deny"`, `"decision":"require_approval"`, `"outcome":"policy_denied"`, `"outcome":"approval_required"`} {
		if !strings.Contains(audit, field) {
			t.Fatalf("missing audit field %s: %s", field, audit)
		}
	}
}

func TestSessionCapabilityPolicyFiltersDiscoveryAndSupportsToolOverrides(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	makeCapability := func(name string, tools ...string) capability.Capability {
		definitions := make([]rest.Tool, 0, len(tools))
		for _, tool := range tools {
			definitions = append(definitions, rest.Tool{Name: tool, Path: "/", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)})
		}
		item, err := rest.New(rest.Manifest{Version: 1, Name: name, BaseURL: upstream.URL, Tools: definitions})
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	demo := makeCapability("demo", "allowed", "denied", "approval")
	hidden := makeCapability("hidden", "read")
	policy := config.ToolPolicy{
		Version: "v2", Profile: "workstation",
		Capabilities: map[string]string{"demo": "allow", "hidden": "deny"},
		Tools:        map[string]string{"demo_denied": "deny", "demo_approval": "require_approval"},
	}
	server, err := gateway.NewSession("test", "session-1", "alice", config.Client{Profile: "workstation", Discover: true, Execute: true, ToolPolicy: "full"}, policy, nil, nil, []capability.Capability{demo, hidden})
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	listed, err := session.ListTools(t.Context(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range listed.Tools {
		names[tool.Name] = true
	}
	for _, name := range []string{"demo_allowed", "capability_search", "capability_describe", "capability_execute"} {
		if !names[name] {
			t.Fatalf("missing visible tool %q: %#v", name, names)
		}
	}
	for _, name := range []string{"demo_denied", "demo_approval", "hidden_read"} {
		if names[name] {
			t.Fatalf("unauthorized tool was discoverable: %q", name)
		}
	}
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "demo_allowed", Arguments: map[string]any{}})
	if err != nil || result.IsError || calls.Load() != 1 {
		t.Fatalf("capability-level allow failed: %v %+v calls=%d", err, result, calls.Load())
	}
	for _, name := range []string{"demo_denied", "demo_approval", "hidden_read"} {
		result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{}})
		if err != nil || !result.IsError || calls.Load() != 1 {
			t.Fatalf("blocked tool %q reached upstream: %v %+v calls=%d", name, err, result, calls.Load())
		}
	}
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "capability_describe", Arguments: map[string]any{"name": "hidden"}})
	if err != nil || !result.IsError {
		t.Fatalf("hidden capability was described: %v %+v", err, result)
	}
}

func TestSessionRejectsStaleToolPolicyEntry(t *testing.T) {
	item, err := rest.New(rest.Manifest{Version: 1, Name: "demo", BaseURL: "http://unused.invalid", Tools: []rest.Tool{{Name: "read", Path: "/", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	policy := config.ToolPolicy{Version: "pilot-v1", Profile: "read", Tools: map[string]string{"demo_typo": "allow"}}
	if _, err := gateway.NewSession("test", "session-1", "alice", config.Client{Profile: "read", Execute: true, ToolPolicy: "pilot"}, policy, nil, nil, []capability.Capability{item}); err == nil {
		t.Fatal("stale tool policy entry was accepted")
	}
}

func TestSessionAuditsAndBlocksIdentityRateLimit(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	item, err := rest.New(rest.Manifest{Version: 1, Name: "demo", BaseURL: upstream.URL, Tools: []rest.Tool{{Name: "read", Path: "/", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	client := config.Client{Profile: "read", ToolPolicy: "test", Execute: true, Limits: &config.CallLimits{RequestsPerMinute: 1, Burst: 1}}
	toolPolicy := config.ToolPolicy{Version: "test", Profile: "read", Tools: map[string]string{"demo_read": "allow"}}
	controller := gateway.NewCallController(client, toolPolicy)
	server, err := gateway.NewSession("test", "session-1", "alice", client, toolPolicy, controller, nil, []capability.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	session := mcpkittest.Connect(t, server)
	for call := 0; call < 2; call++ {
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "demo_read", Arguments: map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError != (call == 1) {
			t.Fatalf("call %d error=%v", call, result.IsError)
		}
	}
	if calls.Load() != 1 || !strings.Contains(logs.String(), `"outcome":"identity_rate_limited"`) {
		t.Fatalf("calls=%d logs=%s", calls.Load(), logs.String())
	}
}

func TestValidateToolPolicyAllowsOnlyConfiguredUnavailableCapabilityEntries(t *testing.T) {
	policy := config.ToolPolicy{
		Version:      "v1",
		Profile:      "all",
		Capabilities: map[string]string{"broken": "allow"},
		Tools:        map[string]string{"broken_status": "allow"},
	}
	if err := gateway.ValidateToolPolicyAvailable(policy, nil, map[string]bool{"broken": true}); err != nil {
		t.Fatal(err)
	}
	policy.Tools["misspelled_status"] = "allow"
	if err := gateway.ValidateToolPolicyAvailable(policy, nil, map[string]bool{"broken": true}); err == nil {
		t.Fatal("unrelated unavailable tool was accepted")
	}
}
