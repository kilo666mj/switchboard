package module

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/mcpkit/mcpkittest"
	capbase "github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/egress"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCapabilityStartsModuleAndProxiesTools(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_SWITCHBOARD_MODULE_HELPER", "1")
	t.Setenv("MODULE_TEST_VALUE", "allowed")
	t.Setenv("MODULE_TEST_UNLISTED", "must-not-be-inherited")
	policy, err := egress.New(config.EgressPolicy{
		AllowedDestinations: []string{"api.example.internal:443"},
		AllowedCIDRs:        []string{"192.0.2.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	item, err := New(t.Context(), Manifest{
		Version: 1, Type: "module", Name: "example", Command: executable,
		Arguments:           []string{"-test.run=^TestModuleHelperProcess$"},
		Environment:         []string{"GO_WANT_SWITCHBOARD_MODULE_HELPER", "MODULE_TEST_VALUE"},
		EnforceEgressPolicy: true,
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	server, err := gateway.New("test", "all", []capbase.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "example_inspect", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || len(result.Content) != 1 {
		t.Fatalf("unexpected module result: %#v", result)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != `"example:allowed::egress"` {
		t.Fatalf("module environment = %q", text.Text)
	}
	description := item.Describe()
	if len(description.Tools) != 1 || description.Tools[0].Name != "example_inspect" {
		t.Fatalf("module description = %#v", description)
	}
}

func TestModuleHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SWITCHBOARD_MODULE_HELPER") != "1" {
		return
	}
	server := mcpkit.MustServer(mcpkit.ServerConfig{Name: "module-helper", Version: "test"})
	mcp.AddTool(server, &mcp.Tool{Name: "inspect", Description: "Inspect isolated module configuration", Annotations: mcpkit.ReadOnly(false)},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, string, error) {
			egressMarker := ""
			if os.Getenv(egressPolicyEnv) != "" {
				egressMarker = "egress"
			}
			return nil, strings.Join([]string{os.Getenv(moduleNameEnv), os.Getenv("MODULE_TEST_VALUE"), os.Getenv("MODULE_TEST_UNLISTED"), egressMarker}, ":"), nil
		})
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		t.Fatal(err)
	}
}

func TestManifestValidation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	valid := Manifest{Version: 1, Type: "module", Name: "example", Command: executable}
	if err := validateManifest(valid, nil); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Command = "relative/module"
	if err := validateManifest(invalid, nil); err == nil {
		t.Fatal("relative module command was accepted")
	}
	invalid = valid
	invalid.Environment = []string{moduleNameEnv}
	if err := validateManifest(invalid, nil); err == nil {
		t.Fatal("reserved environment variable was accepted")
	}
	policy, err := egress.New(config.EgressPolicy{
		AllowedDestinations: []string{"api.example.internal:443"},
		AllowedCIDRs:        []string{"192.0.2.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateManifest(valid, policy); err == nil {
		t.Fatal("module without egress enforcement declaration was accepted")
	}
}

func TestMissingEnvironmentFailsBeforeStartingModule(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const missing = "SWITCHBOARD_TEST_MISSING_MODULE_VALUE"
	t.Setenv(missing, "")
	_, err = New(t.Context(), Manifest{
		Version: 1, Type: "module", Name: "example", Command: executable,
		Environment: []string{missing},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("missing environment error = %v", err)
	}
}
