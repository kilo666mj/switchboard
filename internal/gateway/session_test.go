package gateway_test

import (
	"encoding/json"
	"testing"

	"github.com/kilo666mj/mcpkit/mcpkittest"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/capability/rest"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/gateway"
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
		server, err := gateway.NewSession("test", "test", "identity", tc.policy, []capability.Capability{item})
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
