package gateway_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kilo666mj/mcpkit/mcpkittest"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/kilo666mj/switchboard/internal/loader"
	"github.com/kilo666mj/switchboard/internal/recommend"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeRecommender struct {
	candidates []recommend.Candidate
}

func (f *fakeRecommender) Recommend(_ context.Context, _ string, candidates []recommend.Candidate) (recommend.Result, error) {
	f.candidates = append([]recommend.Candidate(nil), candidates...)
	return recommend.Result{
		Choice: "forgejo", Probabilities: map[string]float64{"dns": 0.2, "forgejo": 0.8},
		Confidence: 0.5, LowConfidence: true, Model: "test-model",
	}, nil
}

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
	server, err := gateway.New("test", "restricted", "test", config.ToolPolicy{Version: "test", Profile: "restricted", Capabilities: map[string]string{"dns": "allow"}}, items)
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

func TestCapabilityRecommendUsesOnlyPolicyVisibleCatalog(t *testing.T) {
	dir := t.TempDir()
	manifests := map[string]string{
		"dns":     `{"version":1,"name":"dns","title":"DNS","description":"Manage DNS","risk":"read_only","base_url":"https://dns.invalid","tools":[{"name":"status","description":"Check status","path":"/status","safety":"read_only","input_schema":{"type":"object"}},{"name":"secret","description":"Hidden tool","path":"/secret","safety":"read_only","input_schema":{"type":"object"}}]}`,
		"forgejo": `{"version":1,"name":"forgejo","title":"Forgejo","description":"Repository work","risk":"read_only","base_url":"https://forgejo.invalid","tools":[{"name":"issues","description":"Find issues","path":"/issues","safety":"read_only","input_schema":{"type":"object"}}]}`,
	}
	for name, data := range manifests {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	items, err := loader.Load(t.Context(), dir, []string{"dns", "forgejo"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := config.ToolPolicy{Version: "test", Profile: "restricted", Tools: map[string]string{"dns_status": "allow", "forgejo_issues": "allow"}}
	fake := &fakeRecommender{}
	server, err := gateway.NewWithMetricsAndRecommender("test", "restricted", "test", policy, items, nil, fake)
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "capability_recommend", Arguments: map[string]any{"request": "find an issue"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("recommendation failed: %#v", result)
	}
	if len(fake.candidates) != 2 {
		t.Fatalf("candidates = %+v", fake.candidates)
	}
	for _, candidate := range fake.candidates {
		for _, tool := range candidate.Tools {
			if strings.Contains(tool, "secret") || strings.Contains(tool, "Hidden") {
				t.Fatalf("hidden tool reached recommender: %+v", fake.candidates)
			}
		}
	}
	data, _ := json.Marshal(result)
	for _, wanted := range []string{"forgejo", "capability_search", "low_confidence"} {
		if !strings.Contains(string(data), wanted) {
			t.Fatalf("missing %q in %s", wanted, data)
		}
	}
	if strings.Contains(string(data), "secret") || strings.Contains(string(data), "Hidden") {
		t.Fatalf("hidden catalog leaked: %s", data)
	}
}
