package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/mcpkit/mcpkittest"
	capbase "github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCapabilityDiscoversAndProxiesTool(t *testing.T) {
	upstream := mcpkit.MustServer(mcpkit.ServerConfig{Name: "memory", Version: "test"})
	mcp.AddTool(upstream, &mcp.Tool{Name: "remember", Description: "Remember", Annotations: mcpkit.Mutating(false, false)},
		func(_ context.Context, _ *mcp.CallToolRequest, input struct {
			Text string `json:"text"`
		}) (*mcp.CallToolResult, map[string]string, error) {
			return nil, map[string]string{"stored": input.Text}, nil
		})
	upstreamHandler, err := mcpkit.StatelessHTTP(func(r *http.Request) *mcp.Server {
		if r.Header.Get("Authorization") != "Bearer upstream-secret" {
			return nil
		}
		return upstream
	}, mcpkit.HTTPOptions{DisableLocalhostProtection: true})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(upstreamHandler)
	defer api.Close()
	t.Setenv("UPSTREAM_TOKEN", "upstream-secret")

	item, err := New(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "wayminder", Endpoint: api.URL,
		Headers: map[string]HeaderValue{"Authorization": {Env: "UPSTREAM_TOKEN", Prefix: "Bearer "}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	server, err := gateway.New("test", "all", []capbase.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "wayminder_remember", Arguments: map[string]any{"text": "hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("tool returned error: %#v", result.Content)
	}
}

func TestExposedNameAvoidsDoublePrefix(t *testing.T) {
	if got := exposedName("parallaxd", "parallaxd_status"); got != "parallaxd_status" {
		t.Fatalf("exposedName = %q", got)
	}
	if got := exposedName("wayminder", "remember"); got != "wayminder_remember" {
		t.Fatalf("exposedName = %q", got)
	}
}

func TestCapabilityUsesOAuthClientCredentials(t *testing.T) {
	upstream := mcpkit.MustServer(mcpkit.ServerConfig{Name: "rendercase", Version: "test"})
	mcp.AddTool(upstream, &mcp.Tool{Name: "rendercase_list", Description: "List"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, map[string]bool, error) {
			return nil, map[string]bool{"ok": true}, nil
		})
	upstreamHandler, err := mcpkit.StatelessHTTP(func(r *http.Request) *mcp.Server {
		if r.Header.Get("Authorization") != "Bearer oauth-access-token" {
			return nil
		}
		return upstream
	}, mcpkit.HTTPOptions{DisableLocalhostProtection: true})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("client_id") != "switchboard" || r.Form.Get("resource") != "https://rendercase.example/mcp" {
			http.Error(w, "bad token request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 3600})
	})
	mux.Handle("POST /mcp", upstreamHandler)
	api := httptest.NewTLSServer(mux)
	defer api.Close()
	t.Setenv("OAUTH_CLIENT_ID", "switchboard")
	t.Setenv("OAUTH_CLIENT_SECRET", "secret")

	item, err := New(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "rendercase", Endpoint: api.URL + "/mcp", InsecureSkipVerify: true,
		OAuth: &OAuthClientCredentials{
			TokenURL: api.URL + "/token", ClientIDEnv: "OAUTH_CLIENT_ID", ClientSecretEnv: "OAUTH_CLIENT_SECRET",
			Scopes: []string{"rendercase:mcp"}, AuthStyle: "params",
			Parameters: map[string]ParameterValue{"resource": {Value: "https://rendercase.example/mcp"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	server, err := gateway.New("test", "all", []capbase.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "rendercase_list", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("OAuth-backed call failed: result=%#v error=%v", result, err)
	}
}

func TestCapabilityOverridesUpstreamHostFromEnvironment(t *testing.T) {
	upstream := mcpkit.MustServer(mcpkit.ServerConfig{Name: "rendercase", Version: "test"})
	mcp.AddTool(upstream, &mcp.Tool{Name: "list", Description: "List"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, map[string]bool, error) {
			return nil, map[string]bool{"ok": true}, nil
		})
	upstreamHandler, err := mcpkit.StatelessHTTP(func(r *http.Request) *mcp.Server {
		if r.Host != "rendercase.example.com" {
			return nil
		}
		return upstream
	}, mcpkit.HTTPOptions{DisableLocalhostProtection: true})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(upstreamHandler)
	defer api.Close()
	t.Setenv("UPSTREAM_HOST", "rendercase.example.com")

	item, err := New(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "rendercase", Endpoint: api.URL, HostEnv: "UPSTREAM_HOST",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	if len(item.tools) != 1 || item.tools[0].definition.Name != "rendercase_list" {
		t.Fatalf("discovered tools = %#v", item.tools)
	}
}

func TestIncludeToolsRemainRestrictedAfterLastMatch(t *testing.T) {
	upstream := mcpkit.MustServer(mcpkit.ServerConfig{Name: "test", Version: "test"})
	for _, name := range []string{"a_allowed", "z_hidden"} {
		mcp.AddTool(upstream, &mcp.Tool{Name: name}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, map[string]bool, error) {
			return nil, map[string]bool{"ok": true}, nil
		})
	}
	handler, err := mcpkit.StatelessHTTP(func(*http.Request) *mcp.Server { return upstream }, mcpkit.HTTPOptions{DisableLocalhostProtection: true})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(handler)
	defer api.Close()
	item, err := New(t.Context(), Manifest{Version: 1, Type: "mcp", Name: "test", Endpoint: api.URL, IncludeTools: []string{"a_allowed"}})
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	d := item.Describe()
	if len(d.Tools) != 1 || d.Tools[0].Name != "test_a_allowed" {
		t.Fatalf("include list leaked tools: %+v", d.Tools)
	}
	server, err := gateway.New("test", "test", []capbase.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "test_z_hidden", Arguments: map[string]any{}})
	if err == nil && !result.IsError {
		t.Fatal("excluded tool executable")
	}
}
