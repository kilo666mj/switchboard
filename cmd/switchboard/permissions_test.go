package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/sessions"
)

func permissionCommandFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	capabilityDir := filepath.Join(dir, "capabilities")
	if err := os.Mkdir(capabilityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"version": 1, "name": "demo", "title": "Demo", "base_url": "https://demo.example.test",
		"tools": []map[string]any{{"name": "status", "description": "Read status", "method": "GET", "path": "/status", "safety": "read_only", "input_schema": map[string]any{"type": "object"}}},
	}
	writeJSONFixture(t, filepath.Join(capabilityDir, "demo.json"), manifest)
	cfg := config.Config{
		Transport: "http", Listen: "127.0.0.1:0", Profile: "all", CapabilityDir: capabilityDir,
		Profiles:     map[string][]string{"all": {"demo"}},
		ToolPolicies: map[string]config.ToolPolicy{"read": {Version: "v1", Profile: "all", Tools: map[string]string{"demo_status": "allow"}}},
		OAuth: &config.OAuthConfig{
			Issuer: "https://id.example.test", Resource: "https://switchboard.example.test/mcp/sessions", RequiredScopes: []string{"mcp:connect"},
			Policies: map[string]config.OAuthPolicy{"readers": {Version: "v1", Groups: []string{"readers"}, RequiredScopes: []string{"tools:read"}, Profile: "all", ToolPolicy: "read", Discover: true, Execute: true}},
		},
	}
	path := filepath.Join(dir, "switchboard.json")
	writeJSONFixture(t, path, cfg)
	return path
}

func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPermissionsReportCommand(t *testing.T) {
	path := permissionCommandFixture(t)
	var output bytes.Buffer
	if err := runPermissionsWithWriter([]string{"report", "-config", path, "-json"}, &output); err != nil {
		t.Fatal(err)
	}
	var report permissionReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Providers) != 1 || len(report.Providers[0].Policies) != 1 || report.Providers[0].Policies[0].Name != "readers" {
		t.Fatalf("report = %#v", report)
	}
}

func TestPermissionsExplainCommand(t *testing.T) {
	path := permissionCommandFixture(t)
	var output bytes.Buffer
	if err := runPermissionsWithWriter([]string{"explain", "-config", path, "-provider", "oauth", "-policy", "readers", "-json"}, &output); err != nil {
		t.Fatal(err)
	}
	var inspection sessions.PermissionInspection
	if err := json.Unmarshal(output.Bytes(), &inspection); err != nil {
		t.Fatal(err)
	}
	if inspection.Status != "allowed" || len(inspection.Capabilities) != 1 || len(inspection.Capabilities[0].Tools) != 1 || !inspection.Capabilities[0].Tools[0].Callable {
		t.Fatalf("inspection = %#v", inspection)
	}
}

func TestPermissionsDiffCommand(t *testing.T) {
	beforePath := permissionCommandFixture(t)
	data, err := os.ReadFile(beforePath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	policy := cfg.ToolPolicies["read"]
	policy.Tools["demo_status"] = "deny"
	cfg.ToolPolicies["read"] = policy
	afterPath := filepath.Join(filepath.Dir(beforePath), "proposed.json")
	writeJSONFixture(t, afterPath, cfg)

	var output bytes.Buffer
	if err := runPermissionsWithWriter([]string{"diff", "-config", beforePath, "-against", afterPath, "-provider", "oauth", "-policy", "readers", "-json"}, &output); err != nil {
		t.Fatal(err)
	}
	var diff permissionDiff
	if err := json.Unmarshal(output.Bytes(), &diff); err != nil {
		t.Fatal(err)
	}
	if len(diff.Tools) != 1 || diff.Tools[0].Tool != "demo_status" || diff.Tools[0].Before == nil || !diff.Tools[0].Before.Callable || diff.Tools[0].After == nil || diff.Tools[0].After.Callable || diff.Tools[0].After.Decision != "deny" {
		t.Fatalf("diff = %#v", diff)
	}
}
