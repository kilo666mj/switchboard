package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/mcpkit/mcpkittest"
	capbase "github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/egress"
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
	api := httptest.NewTLSServer(upstreamHandler)
	defer api.Close()
	t.Setenv("UPSTREAM_TOKEN", "upstream-secret")

	item, err := newWithTransport(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "wayminder", Endpoint: api.URL,
		Headers: map[string]HeaderValue{"Authorization": {Env: "UPSTREAM_TOKEN", Prefix: "Bearer "}},
	}, nil, api.Client().Transport.(*http.Transport).Clone())
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	server, err := gateway.New("test", "all", "test", config.ToolPolicy{Version: "test", Profile: "all", Capabilities: map[string]string{item.Name(): "allow"}}, []capbase.Capability{item})
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

func TestAnnotationRules(t *testing.T) {
	falseValue := false
	rules := []AnnotationRule{
		{Prefixes: []string{"get_", "list_"}, Annotations: mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: &falseValue, IdempotentHint: true}},
		{Prefixes: []string{"create_"}, Annotations: mcp.ToolAnnotations{DestructiveHint: &falseValue}},
	}

	annotations, err := matchAnnotations("list_workflow_runs", rules)
	if err != nil {
		t.Fatal(err)
	}
	if !annotations.ReadOnlyHint || annotations.DestructiveHint == nil || *annotations.DestructiveHint {
		t.Fatalf("unexpected read annotations: %+v", annotations)
	}
	if _, err := matchAnnotations("delete_repo", rules); err == nil {
		t.Fatal("unclassified tool was accepted")
	}
	if _, err := matchAnnotations("list_create_conflict", []AnnotationRule{
		{Prefixes: []string{"list_"}}, {Prefixes: []string{"list_create_"}},
	}); err == nil {
		t.Fatal("overlapping rules were accepted")
	}
	if _, err := matchAnnotations("anything", []AnnotationRule{{Prefixes: []string{""}}}); err == nil {
		t.Fatal("empty prefix was accepted")
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

	item, err := newWithTransport(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "rendercase", Endpoint: api.URL + "/mcp",
		OAuth: &OAuthClientCredentials{
			TokenURL: api.URL + "/token", ClientIDEnv: "OAUTH_CLIENT_ID", ClientSecretEnv: "OAUTH_CLIENT_SECRET",
			Scopes: []string{"rendercase:mcp"}, AuthStyle: "params",
			Parameters: map[string]ParameterValue{"resource": {Value: "https://rendercase.example/mcp"}},
		},
	}, nil, api.Client().Transport.(*http.Transport).Clone())
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	server, err := gateway.New("test", "all", "test", config.ToolPolicy{Version: "test", Profile: "all", Capabilities: map[string]string{item.Name(): "allow"}}, []capbase.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "rendercase_list", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("OAuth-backed call failed: result=%#v error=%v", result, err)
	}
}

func TestCapabilityForwardsOnlyBoundOAuthSubject(t *testing.T) {
	var delegated atomic.Value
	upstream := mcpkit.MustServer(mcpkit.ServerConfig{Name: "rendercase", Version: "test"})
	mcp.AddTool(upstream, &mcp.Tool{Name: "list", Description: "List"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, map[string]bool, error) {
			return nil, map[string]bool{"ok": true}, nil
		})
	upstreamHandler, err := mcpkit.StatelessHTTP(func(r *http.Request) *mcp.Server {
		if r.Header.Get("Authorization") != "Bearer gateway-service-token" {
			return nil
		}
		if subject := r.Header.Get(delegatedOAuthSubjectHeader); subject != "" {
			delegated.Store(subject)
		}
		return upstream
	}, mcpkit.HTTPOptions{DisableLocalhostProtection: true})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewTLSServer(upstreamHandler)
	defer api.Close()
	t.Setenv("UPSTREAM_TOKEN", "gateway-service-token")

	item, err := newWithTransport(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "rendercase", Endpoint: api.URL, ForwardOAuthSubject: true,
		Headers: map[string]HeaderValue{"Authorization": {Env: "UPSTREAM_TOKEN", Prefix: "Bearer "}},
	}, nil, api.Client().Transport.(*http.Transport).Clone())
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	if delegated.Load() != nil {
		t.Fatal("startup request forwarded an OAuth subject")
	}
	bound, err := item.BindOAuthSubject("subject-alice")
	if err != nil {
		t.Fatal(err)
	}
	server, err := gateway.New("test", "all", "test", config.ToolPolicy{Version: "test", Profile: "all", Capabilities: map[string]string{bound.Name(): "allow"}}, []capbase.Capability{bound})
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "rendercase_list", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("delegated call failed: result=%#v error=%v", result, err)
	}
	if got, _ := delegated.Load().(string); got != "subject-alice" {
		t.Fatalf("delegated subject = %q", got)
	}
	if _, err := item.BindOAuthSubject("bad\r\nsubject"); err == nil {
		t.Fatal("unsafe delegated subject was accepted")
	}
}

func TestForwardOAuthSubjectRequiresAuthenticatedUpstream(t *testing.T) {
	if item, err := New(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "test", Endpoint: "https://127.0.0.1:1", ForwardOAuthSubject: true,
	}); err == nil {
		item.Close()
		t.Fatal("unauthenticated delegated identity configuration was accepted")
	}
	t.Setenv("UPSTREAM_SUBJECT", "caller-controlled")
	if item, err := New(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "test", Endpoint: "http://127.0.0.1:1", ForwardOAuthSubject: true,
		Headers: map[string]HeaderValue{delegatedOAuthSubjectHeader: {Env: "UPSTREAM_SUBJECT"}},
	}); err == nil {
		item.Close()
		t.Fatal("reserved delegated identity header was accepted from a manifest")
	}
}

func TestCapabilityRejectsRedirectBeforeSendingCredentialToDestination(t *testing.T) {
	var destinationRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationRequests.Add(1)
		http.Error(w, "credential destination reached", http.StatusInternalServerError)
	}))
	defer destination.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	t.Setenv("UPSTREAM_TOKEN", "redirect-canary")

	if item, err := newWithTransport(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "test", Endpoint: redirector.URL,
		Headers: map[string]HeaderValue{"Authorization": {Env: "UPSTREAM_TOKEN", Prefix: "Bearer "}},
	}, nil, redirector.Client().Transport.(*http.Transport).Clone()); err == nil {
		item.Close()
		t.Fatal("redirected MCP endpoint was accepted")
	}
	if got := destinationRequests.Load(); got != 0 {
		t.Fatalf("redirect destination received %d requests", got)
	}
}

func TestCapabilityRejectsCredentialOverPlainHTTP(t *testing.T) {
	t.Setenv("UPSTREAM_TOKEN", "secret")
	if item, err := New(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "test", Endpoint: "http://api.example.internal/mcp",
		Headers: map[string]HeaderValue{"Authorization": {Env: "UPSTREAM_TOKEN", Prefix: "Bearer "}},
	}); err == nil {
		item.Close()
		t.Fatal("credential-bearing plaintext MCP capability was accepted")
	}
}

func TestOAuthTokenRequestRejectsRedirect(t *testing.T) {
	var destinationRequests atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationRequests.Add(1)
		http.Error(w, "credential destination reached", http.StatusInternalServerError)
	}))
	defer destination.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	t.Setenv("OAUTH_CLIENT_ID", "switchboard")
	t.Setenv("OAUTH_CLIENT_SECRET", "redirect-canary")

	if item, err := newWithTransport(t.Context(), Manifest{
		Version: 1, Type: "mcp", Name: "test", Endpoint: redirector.URL,
		OAuth: &OAuthClientCredentials{
			TokenURL: redirector.URL, ClientIDEnv: "OAUTH_CLIENT_ID", ClientSecretEnv: "OAUTH_CLIENT_SECRET",
		},
	}, nil, redirector.Client().Transport.(*http.Transport).Clone()); err == nil {
		item.Close()
		t.Fatal("redirected OAuth token endpoint was accepted")
	}
	if got := destinationRequests.Load(); got != 0 {
		t.Fatalf("OAuth redirect destination received %d requests", got)
	}
}

func TestCapabilityRejectsInsecureSkipVerifyWithoutEgressPolicy(t *testing.T) {
	if item, err := New(t.Context(), Manifest{Version: 1, Type: "mcp", Name: "test", Endpoint: "https://api.example.internal/mcp", InsecureSkipVerify: true}); err == nil {
		item.Close()
		t.Fatal("insecure_skip_verify was accepted without an egress policy")
	}
}

func TestCapabilityEgressPolicyRejectsUnsafeConfiguration(t *testing.T) {
	policy, err := egress.New(config.EgressPolicy{
		AllowedDestinations: []string{"api.example.internal:443"},
		AllowedCIDRs:        []string{"192.0.2.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, manifest := range []Manifest{
		{Version: 1, Type: "mcp", Name: "test", Endpoint: "http://api.example.internal/mcp"},
		{Version: 1, Type: "mcp", Name: "test", Endpoint: "https://api.example.internal/mcp", InsecureSkipVerify: true},
		{Version: 1, Type: "mcp", Name: "test", Endpoint: "https://other.example.internal/mcp"},
		{Version: 1, Type: "mcp", Name: "test", Endpoint: "https://api.example.internal/mcp", OAuth: &OAuthClientCredentials{TokenURL: "https://id.example.internal/token", ClientIDEnv: "ID", ClientSecretEnv: "SECRET"}},
	} {
		t.Setenv("ID", "switchboard")
		t.Setenv("SECRET", "secret")
		if item, err := NewWithEgress(t.Context(), manifest, policy); err == nil {
			item.Close()
			t.Fatalf("unsafe manifest accepted: %+v", manifest)
		}
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
	server, err := gateway.New("test", "test", "test", config.ToolPolicy{Version: "test", Profile: "test", Capabilities: map[string]string{item.Name(): "allow"}}, []capbase.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "test_z_hidden", Arguments: map[string]any{}})
	if err == nil && !result.IsError {
		t.Fatal("excluded tool executable")
	}
}
