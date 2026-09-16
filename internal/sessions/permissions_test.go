package sessions

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/capability/rest"
	"github.com/kilo666mj/switchboard/internal/config"
)

func permissionFixture(t *testing.T) (config.Config, []capability.Capability) {
	t.Helper()
	item, err := rest.New(rest.Manifest{
		Version: 1, Name: "demo", BaseURL: "https://demo.example.test",
		Tools: []rest.Tool{
			{Name: "status", Path: "/status", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)},
			{Name: "change", Path: "/change", Method: "POST", Safety: "mutating", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Transport: "http", Profile: "all", ToolPolicy: "read", Profiles: map[string][]string{"all": {"demo"}}, EgressPolicy: &config.EgressPolicy{},
		ToolPolicies: map[string]config.ToolPolicy{
			"read":  {Version: "v1", Profile: "all", Tools: map[string]string{"demo_status": "allow"}},
			"block": {Version: "v1", Profile: "all", Tools: map[string]string{"demo_status": "deny"}},
		},
		OAuth: &config.OAuthConfig{
			Issuer: "https://id.example.test", Resource: "https://switchboard.example.test/mcp/sessions",
			RequiredScopes: []string{"mcp:connect"}, PolicyMode: config.IdentityPolicyModeComposed,
			Policies: map[string]config.OAuthPolicy{
				"reader":  {Version: "v1", Groups: []string{"readers"}, RequiredScopes: []string{"tools:read"}, Profile: "all", ToolPolicy: "read", Discover: true, Execute: true},
				"blocker": {Version: "v1", Groups: []string{"blocked"}, RequiredScopes: []string{"tools:read"}, Profile: "all", ToolPolicy: "block", Discover: true, Execute: true},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg, []capability.Capability{item}
}

func TestInspectPermissionsUsesEffectiveComposition(t *testing.T) {
	cfg, items := permissionFixture(t)
	inspection, err := InspectPermissions(cfg, PermissionInspectionInput{Provider: PermissionProviderOAuth, Policies: []string{"reader"}}, items, nil)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Status != "allowed" || inspection.Profile != "all" || len(inspection.Capabilities) != 1 {
		t.Fatalf("inspection = %#v", inspection)
	}
	tools := inspection.Capabilities[0].Tools
	if len(tools) != 2 || tools[0].Name != "demo_change" || tools[0].Decision != "deny" || tools[0].Callable || tools[1].Name != "demo_status" || !tools[1].Callable || tools[1].Source != "tool" {
		t.Fatalf("tools = %#v", tools)
	}

	inspection, err = InspectPermissions(cfg, PermissionInspectionInput{Provider: PermissionProviderOAuth, Policies: []string{"reader", "blocker"}}, items, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range inspection.Capabilities[0].Tools {
		if tool.Name == "demo_status" && (tool.Decision != "deny" || tool.Callable) {
			t.Fatalf("deny did not win composition: %#v", tool)
		}
	}
}

func TestInspectPermissionsExplainsMissingScopes(t *testing.T) {
	cfg, items := permissionFixture(t)
	inspection, err := InspectPermissions(cfg, PermissionInspectionInput{Provider: PermissionProviderOAuth, Subject: "person", Groups: []string{"readers"}, Scopes: []string{"mcp:connect"}}, items, nil)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Status != "insufficient_scope" || !slices.Equal(inspection.MissingScopes, []string{"mcp:connect", "tools:read"}) {
		t.Fatalf("inspection = %#v", inspection)
	}
}

func TestInspectPermissionsReportsPerClientStaticAllowlist(t *testing.T) {
	cfg, items := permissionFixture(t)
	cfg.Clients = map[string]config.Client{
		"allowed":  {TokenEnv: "ALLOWED", Profile: "all", ToolPolicy: "read", Execute: true},
		"disabled": {TokenEnv: "DISABLED", Profile: "all", ToolPolicy: "read", Execute: true},
	}
	cfg.OAuth.StaticClientAllowlist = []string{"allowed"}
	for name, want := range map[string]string{"allowed": "allowed", "disabled": "disabled"} {
		inspection, err := InspectPermissions(cfg, PermissionInspectionInput{Client: name}, items, nil)
		if err != nil {
			t.Fatal(err)
		}
		if inspection.Status != want {
			t.Fatalf("client %q status = %q, want %q", name, inspection.Status, want)
		}
	}
}

func TestLintPermissionsHighlightsOperatorHazards(t *testing.T) {
	cfg, _ := permissionFixture(t)
	cfg.Profiles["duplicate"] = []string{"demo"}
	cfg.ToolPolicies["broad"] = config.ToolPolicy{Version: "v1", Profile: "all", Capabilities: map[string]string{"demo": "allow"}}
	cfg.ToolPolicies["approval"] = config.ToolPolicy{Version: "v1", Profile: "all", Tools: map[string]string{"demo_change": "require_approval"}}
	cfg.Clients = map[string]config.Client{"retired": {TokenEnv: "RETIRED", Profile: "all"}}
	warnings := LintPermissions(cfg)
	codes := map[string]bool{}
	for _, warning := range warnings {
		if warning.Code == "unreferenced_tool_policy" && strings.Contains(warning.Message, `"read"`) {
			t.Fatalf("top-level tool policy reported as unreferenced: %#v", warnings)
		}
		codes[warning.Code] = true
	}
	for _, code := range []string{"approval_unavailable", "broad_capability_allow", "disabled_static_clients", "duplicate_profile"} {
		if !codes[code] {
			t.Fatalf("missing warning %q in %#v", code, warnings)
		}
	}
}
