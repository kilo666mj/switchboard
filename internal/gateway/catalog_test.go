package gateway_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kilo666mj/mcpkit/mcpkittest"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/kilo666mj/switchboard/internal/loader"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCatalogProfileRedactionAndSchemas(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CATALOG_TEST_TOKEN", "secret-canary")
	manifests := map[string]string{
		"dns":    `{"version":1,"name":"dns","title":"DNS","tags":["network"],"risk":"read_only","base_url":"https://private-canary.invalid","headers":{"Authorization":{"env":"CATALOG_TEST_TOKEN","prefix":"Bearer "}},"tools":[{"name":"status","description":"Check status","path":"/status","safety":"read_only","input_schema":{"type":"object"}}]}`,
		"hidden": `{"version":1,"name":"hidden","base_url_env":"UNSET_HIDDEN_URL"}`,
	}
	for name, data := range manifests {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	items, err := loader.Load(t.Context(), dir, []string{"dns"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := gateway.New("test", "restricted", items)
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	listed, err := session.ListTools(t.Context(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 4 {
		t.Fatalf("tools = %d", len(listed.Tools))
	}
	for _, tool := range listed.Tools {
		if strings.HasPrefix(tool.Name, "capability_") && (tool.Annotations == nil || !tool.Annotations.ReadOnlyHint) {
			t.Fatalf("missing read-only annotation: %s", tool.Name)
		}
	}
	for _, tc := range []struct {
		name string
		args map[string]any
		fail bool
	}{
		{"capability_search", map[string]any{}, false},
		{"capability_describe", map[string]any{"name": "dns"}, false},
		{"capability_describe", map[string]any{"name": "hidden"}, true},
		{"capability_describe", map[string]any{}, true},
		{"capability_search", map[string]any{"query": 42}, true},
		{"capability_search", map[string]any{"limit": 101}, true},
	} {
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: tc.name, Arguments: tc.args})
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError != tc.fail {
			t.Fatalf("%s(%v): %#v", tc.name, tc.args, result)
		}
		data, _ := json.Marshal(result)
		for _, secret := range []string{"secret-canary", "private-canary", "CATALOG_TEST_TOKEN", "UNSET_HIDDEN_URL", "hidden"} {
			if strings.Contains(string(data), secret) {
				t.Fatalf("catalog leaked %s", secret)
			}
		}
		if !tc.fail && !strings.Contains(string(data), `dns`) {
			t.Fatalf("missing capability: %s", data)
		}
		if tc.name == "capability_describe" && !tc.fail && !strings.Contains(string(data), "dns_status") {
			t.Fatalf("missing tool summary: %s", data)
		}
	}
}
