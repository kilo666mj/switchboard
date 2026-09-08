package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kilo666mj/mcpkit/mcpkittest"
	capbase "github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCapabilityCallsAPI(t *testing.T) {
	t.Parallel()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v1/zones/example.com/rrsets" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revision":"abc123"}`))
	}))
	defer api.Close()

	manifest := Manifest{
		Version: 1, Name: "rilldns", BaseURL: api.URL,
		Tools: []Tool{{
			Name: "get_zone", Description: "Get zone", Method: "GET",
			Path: "/v1/zones/{zone}/rrsets", Safety: "read_only",
			PathArguments: []string{"zone"},
			InputSchema:   json.RawMessage(`{"type":"object","properties":{"zone":{"type":"string"}},"required":["zone"]}`),
		}},
	}
	capability, err := New(manifest)
	if err != nil {
		t.Fatal(err)
	}
	server, err := gateway.New("test", "read", []capbase.Capability{capability})
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "rilldns_get_zone", Arguments: map[string]any{"zone": "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Content) != 1 || result.Content[0].(*mcp.TextContent).Text != `{"revision":"abc123"}` {
		t.Fatalf("unexpected result: %#v", result.Content)
	}
}

func TestManifestRejectsLiteralAndEnvironmentBaseURL(t *testing.T) {
	t.Setenv("TEST_API_URL", "https://example.com")
	manifest := Manifest{Version: 1, Name: "test", BaseURL: "https://example.com", BaseURLEnv: "TEST_API_URL", Tools: []Tool{{Name: "read", Description: "read", Path: "/", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)}}}
	if err := manifest.Validate(); err == nil {
		t.Fatal("Validate succeeded with two base URL sources")
	}
}

func TestManifestRejectsReadOnlyPost(t *testing.T) {
	manifest := Manifest{Version: 1, Name: "test", BaseURL: "https://example.com", Tools: []Tool{{Name: "read", Description: "read", Method: "POST", Path: "/", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)}}}
	if err := manifest.Validate(); err == nil {
		t.Fatal("Validate succeeded with a read-only POST")
	}
}
