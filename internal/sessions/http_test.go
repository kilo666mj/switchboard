package sessions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kilo666mj/switchboard/internal/auth"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/capability/rest"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func secureTestConfig(cfg *config.Config) {
	cfg.EgressPolicy = &config.EgressPolicy{}
	if cfg.ToolPolicies == nil {
		cfg.ToolPolicies = map[string]config.ToolPolicy{}
	}
	for profile, capabilities := range cfg.Profiles {
		name := "test-" + profile
		decisions := map[string]string{}
		for _, capabilityName := range capabilities {
			decisions[capabilityName] = "allow"
		}
		cfg.ToolPolicies[name] = config.ToolPolicy{Version: "test", Profile: profile, Capabilities: decisions}
	}
	cfg.ToolPolicy = "test-" + cfg.Profile
	for name, client := range cfg.Clients {
		if client.ToolPolicy == "" {
			client.ToolPolicy = "test-" + client.Profile
			cfg.Clients[name] = client
		}
	}
	if cfg.OAuth != nil {
		for name, policy := range cfg.OAuth.Policies {
			if policy.ToolPolicy == "" {
				policy.ToolPolicy = "test-" + policy.Profile
				cfg.OAuth.Policies[name] = policy
			}
		}
	}
	if cfg.CloudflareAccess != nil {
		for name, policy := range cfg.CloudflareAccess.Policies {
			if policy.ToolPolicy == "" {
				policy.ToolPolicy = "test-" + policy.Profile
				cfg.CloudflareAccess.Policies[name] = policy
			}
		}
	}
}

func fixture(t *testing.T) (*Handler, *httptest.Server) {
	t.Helper()
	t.Setenv("CLIENT_A", strings.Repeat("a", 32))
	t.Setenv("CLIENT_B", strings.Repeat("b", 32))
	item, err := rest.New(rest.Manifest{Version: 1, Name: "demo", BaseURL: "http://unreachable.invalid", Tools: []rest.Tool{{Name: "status", Path: "/status", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Transport: "http", Profile: "all", Profiles: map[string][]string{"all": {"demo"}, "empty": {}}, SessionLimit: 2, Clients: map[string]config.Client{
		"alice": {TokenEnv: "CLIENT_A", Profile: "all", InitialCapabilities: []string{}, Discover: true, Execute: true, Activate: true},
		"bob":   {TokenEnv: "CLIENT_B", Profile: "empty", Discover: true, Execute: true, Activate: true},
	}}
	secureTestConfig(&cfg)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	h, err := New(ctx, "test", cfg, []capability.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(h)
	t.Cleanup(api.Close)
	t.Cleanup(h.Close)
	return h, api
}

func TestUnavailableCapabilityDoesNotBlockHandlerAndCanRecover(t *testing.T) {
	t.Setenv("CLIENT_A", strings.Repeat("a", 32))
	healthy, err := rest.New(rest.Manifest{Version: 1, Name: "healthy", BaseURL: "https://healthy.example.test", Tools: []rest.Tool{{Name: "status", Path: "/status", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := rest.New(rest.Manifest{Version: 1, Name: "broken", BaseURL: "https://broken.example.test", Tools: []rest.Tool{{Name: "status", Path: "/status", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Transport: "http", Profile: "all",
		Profiles:     map[string][]string{"all": {"healthy", "broken"}},
		Clients:      map[string]config.Client{"alice": {TokenEnv: "CLIENT_A", Profile: "all", InitialCapabilities: []string{"healthy", "broken"}, Discover: true, Execute: true}},
		ToolPolicies: map[string]config.ToolPolicy{},
	}
	secureTestConfig(&cfg)
	h, err := NewWithAuthUnavailable(t.Context(), "test", cfg, []capability.Capability{healthy}, []string{"broken"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	if h.capabilities["healthy"] == nil || h.capabilities["broken"] != nil {
		t.Fatalf("initial capabilities = %#v", h.capabilities)
	}
	filtered := policyForAvailableCapabilities(cfg.Clients["alice"], []capability.Capability{healthy})
	if len(filtered.InitialCapabilities) != 1 || filtered.InitialCapabilities[0] != "healthy" {
		t.Fatalf("filtered initial capabilities = %v", filtered.InitialCapabilities)
	}
	if err := h.AddCapability(recovered); err != nil {
		t.Fatal(err)
	}
	if h.capabilities["broken"] == nil || h.unavailable["broken"] {
		t.Fatalf("recovered capability not installed: capabilities=%#v unavailable=%#v", h.capabilities, h.unavailable)
	}
}

func request(t *testing.T, api *httptest.Server, method, token, id, body string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(method, api.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if id != "" {
		req.Header.Set(sessionHeader, id)
	}
	resp, err := api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header.Get(sessionHeader), string(data)
}

const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"test"}}}`

func TestIdentityCapacityExpiryAndReconnect(t *testing.T) {
	h, api := fixture(t)
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	status, _, _ := request(t, api, "POST", "wrong", "", initialize)
	if status != 401 {
		t.Fatalf("auth=%d", status)
	}
	status, id, body := request(t, api, "POST", a, "", initialize)
	if status != 200 || id == "" {
		t.Fatalf("init=%d %s", status, body)
	}
	status, _, _ = request(t, api, "POST", b, id, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if status != 404 {
		t.Fatalf("cross-identity=%d", status)
	}
	status, _, body = request(t, api, "POST", a, id, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"capability_enable","arguments":{"name":"demo"}}}`)
	if status != 200 || !strings.Contains(body, `"enabled":true`) {
		t.Fatalf("enable=%d %s", status, body)
	}
	status, id2, _ := request(t, api, "POST", a, "", initialize)
	if status != 200 || id2 == id {
		t.Fatal("second session failed")
	}
	status, _, _ = request(t, api, "POST", b, "", initialize)
	if status != 503 {
		t.Fatalf("limit=%d", status)
	}
	_, _, body = request(t, api, "POST", a, id2, `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`)
	if strings.Contains(body, "demo_status") {
		t.Fatal("activation leaked across sessions")
	}
	h.mu.Lock()
	h.entries[id].lastSeen = time.Now().Add(-time.Hour)
	h.mu.Unlock()
	h.expire(time.Now())
	status, _, _ = request(t, api, "POST", a, id, `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	if status != 404 {
		t.Fatalf("expired=%d", status)
	}
	status, newID, _ := request(t, api, "POST", b, "", initialize)
	if status != 200 {
		t.Fatal("capacity not released")
	}
	_, _, body = request(t, api, "POST", b, newID, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"capability_describe","arguments":{"name":"demo"}}}`)
	if strings.Contains(body, "demo_status") || !strings.Contains(body, `"isError":true`) {
		t.Fatalf("profile leaked: %s", body)
	}
	status, _, _ = request(t, api, "DELETE", a, id2, "")
	if status != 204 {
		t.Fatalf("delete=%d", status)
	}
	status, _, _ = request(t, api, "POST", a, id2, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
	if status != 404 {
		t.Fatal("deleted session remains")
	}
}

type bearerTransport struct{ token string }

func (t bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header = r.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(clone)
}

func TestNativeToolRefreshNotifications(t *testing.T) {
	_, api := fixture(t)
	changed := make(chan struct{}, 20)
	client := mcp.NewClient(&mcp.Implementation{Name: "refresh", Version: "test"}, &mcp.ClientOptions{ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) { changed <- struct{}{} }})
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: api.URL, HTTPClient: &http.Client{Transport: bearerTransport{strings.Repeat("a", 32)}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, enable := range []bool{true, false} {
		name := "capability_disable"
		if enable {
			name = "capability_enable"
		}
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{"name": "demo"}})
		if err != nil || result.IsError {
			t.Fatalf("activation failed: %v %+v", err, result)
		}
		select {
		case <-changed:
		case <-time.After(3 * time.Second):
			t.Fatal("no tools/list_changed notification")
		}
		tools, err := session.ListTools(t.Context(), &mcp.ListToolsParams{})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, tool := range tools.Tools {
			if tool.Name == "demo_status" {
				found = true
			}
		}
		if found != enable {
			t.Fatalf("native tool visibility=%v", found)
		}
	}
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "demo_status", Arguments: map[string]any{}})
	if err == nil && !result.IsError {
		t.Fatal("stale disabled tool executed")
	}
}

func TestInvalidInitializeDoesNotConsumeCapacity(t *testing.T) {
	h, api := fixture(t)
	for _, body := range []string{`{}`, `{"method":"initialize"}`, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`} {
		request(t, api, "POST", strings.Repeat("a", 32), "", body)
		h.mu.Lock()
		n := len(h.entries)
		h.mu.Unlock()
		if n != 0 {
			t.Fatalf("invalid initialize retained %d sessions", n)
		}
	}
}

func TestOriginProtection(t *testing.T) {
	_, api := fixture(t)
	req, _ := http.NewRequest("POST", api.URL, bytes.NewBufferString(initialize))
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	req.Header.Set("Origin", "https://untrusted.invalid")
	resp, err := api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("origin=%d", resp.StatusCode)
	}
}

func TestIdentityLimitsAreSharedAcrossSessions(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	item, err := rest.New(rest.Manifest{Version: 1, Name: "demo", BaseURL: upstream.URL, Tools: []rest.Tool{{Name: "status", Path: "/", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 32)
	t.Setenv("CLIENT_A", token)
	cfg := config.Config{Transport: "http", Profile: "all", Profiles: map[string][]string{"all": {"demo"}}, Clients: map[string]config.Client{
		"alice": {TokenEnv: "CLIENT_A", Profile: "all", Execute: true, Limits: &config.CallLimits{RequestsPerMinute: 1, Burst: 1}},
	}}
	secureTestConfig(&cfg)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	handler, err := New(ctx, "test", cfg, []capability.Capability{item})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	api := httptest.NewServer(handler)
	defer api.Close()
	status, firstID, body := request(t, api, http.MethodPost, token, "", initialize)
	if status != http.StatusOK {
		t.Fatalf("first initialize: %d %s", status, body)
	}
	status, secondID, body := request(t, api, http.MethodPost, token, "", initialize)
	if status != http.StatusOK {
		t.Fatalf("second initialize: %d %s", status, body)
	}
	for call, id := range []string{firstID, secondID} {
		_, _, body = request(t, api, http.MethodPost, token, id, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"demo_status","arguments":{}}}`)
		if strings.Contains(body, `"isError":true`) != (call == 1) {
			t.Fatalf("call %d body: %s", call, body)
		}
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("upstream calls = %d", upstreamCalls.Load())
	}
}

type fakeOAuthAuthenticator struct{}

type oauthSubjectCapability struct{ subject string }

func (c *oauthSubjectCapability) Name() string { return "subject" }

func (c *oauthSubjectCapability) Describe() capability.Description {
	return capability.Description{Name: c.Name(), Tools: []capability.ToolSummary{{Name: "subject_current"}}}
}

func (c *oauthSubjectCapability) BindOAuthSubject(subject string) (capability.Capability, error) {
	return &oauthSubjectCapability{subject: subject}, nil
}

func (c *oauthSubjectCapability) Register(server *mcp.Server) error {
	mcp.AddTool(server, &mcp.Tool{Name: "subject_current"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, map[string]string, error) {
			return nil, map[string]string{"subject": c.subject}, nil
		})
	return nil
}

func (fakeOAuthAuthenticator) Authenticate(r *http.Request) (auth.Principal, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer oauth-alice-read":
		return auth.Principal{Identity: "subject-alice", PolicyName: "readers", Policy: config.Client{Profile: "all", ToolPolicy: "test-all", Execute: true}}, nil
	case "Bearer oauth-alice-empty":
		return auth.Principal{Identity: "subject-alice", PolicyName: "empty", Policy: config.Client{Profile: "empty", ToolPolicy: "test-empty", Execute: true}}, nil
	default:
		return auth.Principal{}, auth.ErrInvalidToken
	}
}

func (fakeOAuthAuthenticator) WriteError(w http.ResponseWriter, err error) {
	status := http.StatusUnauthorized
	if !errors.Is(err, auth.ErrInvalidToken) {
		status = http.StatusForbidden
	}
	http.Error(w, http.StatusText(status), status)
}

type fakeAccessAuthenticator struct{}

func (fakeAccessAuthenticator) Authenticate(r *http.Request) (auth.Principal, error) {
	if r.Header.Get(auth.CloudflareAccessJWTHeader) != "signed-access-assertion" {
		return auth.Principal{}, auth.ErrInvalidAccessAssertion
	}
	return auth.Principal{Identity: "cloudflare_access:subject-alice", Source: "cloudflare_access", PolicyName: "people", Policy: config.Client{Profile: "empty", ToolPolicy: "test-empty"}}, nil
}

func (fakeAccessAuthenticator) WriteError(w http.ResponseWriter, _ error) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func TestCloudflareAccessSessionAuthenticationDoesNotRequireAuthorizationHeader(t *testing.T) {
	handler := &Handler{authenticator: fakeAccessAuthenticator{}}
	request := httptest.NewRequest(http.MethodPost, "/mcp/sessions", nil)
	request.Header.Set(auth.CloudflareAccessJWTHeader, "signed-access-assertion")
	client, err := handler.authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	if client.name != "cloudflare_access:subject-alice" || client.binding != "cloudflare_access:people" {
		t.Fatalf("client = %+v", client)
	}
	if client.oauthSubject != "" {
		t.Fatal("Cloudflare Access identity was marked for OAuth subject forwarding")
	}
	request.Header.Set("Authorization", "Bearer unexpected")
	if _, err := handler.authenticate(request); !errors.Is(err, auth.ErrAmbiguousCredential) {
		t.Fatalf("ambiguous credential error = %v", err)
	}
}

func TestOAuthSessionsBindSubjectAndMappedPolicy(t *testing.T) {
	item, err := rest.New(rest.Manifest{Version: 1, Name: "demo", BaseURL: "http://unreachable.invalid", Tools: []rest.Tool{{Name: "status", Path: "/status", Safety: "read_only", InputSchema: json.RawMessage(`{"type":"object"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Transport: "http", Profile: "all", Profiles: map[string][]string{"all": {"demo"}, "empty": {}},
		Clients: map[string]config.Client{"disabled-static": {TokenEnv: "UNSET_STATIC_TOKEN", Profile: "all"}},
		OAuth: &config.OAuthConfig{
			Issuer: "https://id.example.com", Resource: "https://switchboard.example.com/mcp/sessions", RequiredScopes: []string{"mcp:connect"},
			Policies: map[string]config.OAuthPolicy{
				"readers": {Version: "pilot-v1", Subjects: []string{"subject-alice"}, Profile: "all", Execute: true},
				"empty":   {Version: "pilot-v1", Subjects: []string{"subject-alice"}, Profile: "empty", Execute: true},
			},
		},
	}
	secureTestConfig(&cfg)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	handler, err := NewWithAuth(ctx, "test", cfg, []capability.Capability{item}, nil, fakeOAuthAuthenticator{})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	authRequest := httptest.NewRequest(http.MethodPost, "/mcp/sessions", nil)
	authRequest.Header.Set("Authorization", "Bearer oauth-alice-read")
	client, err := handler.authenticate(authRequest)
	if err != nil || client.oauthSubject != "subject-alice" {
		t.Fatalf("OAuth subject binding = %+v, %v", client, err)
	}
	api := httptest.NewServer(handler)
	defer api.Close()
	status, id, body := request(t, api, http.MethodPost, "oauth-alice-read", "", initialize)
	if status != http.StatusOK || id == "" {
		t.Fatalf("OAuth initialize: %d %s", status, body)
	}
	status, _, _ = request(t, api, http.MethodPost, "oauth-alice-empty", id, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if status != http.StatusNotFound {
		t.Fatalf("session accepted a changed OAuth policy: %d", status)
	}
	status, _, _ = request(t, api, http.MethodPost, strings.Repeat("a", 32), "", initialize)
	if status != http.StatusUnauthorized {
		t.Fatalf("disabled static token status: %d", status)
	}
}

func TestOAuthSessionBindsSubjectOnlyForOAuthClient(t *testing.T) {
	staticToken := strings.Repeat("s", 32)
	disabledToken := strings.Repeat("d", 32)
	t.Setenv("STATIC_TOKEN", staticToken)
	t.Setenv("DISABLED_TOKEN", disabledToken)
	cfg := config.Config{
		Transport: "http", Profile: "all", Profiles: map[string][]string{"all": {"subject"}},
		Clients: map[string]config.Client{
			"static":   {TokenEnv: "STATIC_TOKEN", Profile: "all", Execute: true},
			"disabled": {TokenEnv: "DISABLED_TOKEN", Profile: "all", Execute: true},
		},
		OAuth: &config.OAuthConfig{
			Issuer: "https://id.example.com", Resource: "https://switchboard.example.com/mcp/sessions", RequiredScopes: []string{"mcp:connect"}, StaticClientAllowlist: []string{"static"},
			Policies: map[string]config.OAuthPolicy{"readers": {Version: "pilot-v1", Subjects: []string{"subject-alice"}, Profile: "all", Execute: true}},
		},
	}
	secureTestConfig(&cfg)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	handler, err := NewWithAuth(ctx, "test", cfg, []capability.Capability{&oauthSubjectCapability{}}, nil, fakeOAuthAuthenticator{})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	api := httptest.NewServer(handler)
	defer api.Close()

	status, oauthID, body := request(t, api, http.MethodPost, "oauth-alice-read", "", initialize)
	if status != http.StatusOK || oauthID == "" {
		t.Fatalf("OAuth initialize: %d %s", status, body)
	}
	status, _, body = request(t, api, http.MethodPost, "oauth-alice-read", oauthID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"subject_current","arguments":{}}}`)
	if status != http.StatusOK || !strings.Contains(body, `"subject":"subject-alice"`) {
		t.Fatalf("OAuth delegated call: %d %s", status, body)
	}

	status, staticID, body := request(t, api, http.MethodPost, staticToken, "", initialize)
	if status != http.StatusOK || staticID == "" {
		t.Fatalf("static initialize: %d %s", status, body)
	}
	status, _, _ = request(t, api, http.MethodPost, disabledToken, "", initialize)
	if status != http.StatusUnauthorized {
		t.Fatalf("non-allowlisted static token status: %d", status)
	}
	status, _, body = request(t, api, http.MethodPost, staticToken, staticID, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"subject_current","arguments":{}}}`)
	if status != http.StatusOK || !strings.Contains(body, `"subject":""`) {
		t.Fatalf("static delegated call: %d %s", status, body)
	}
}

func TestOAuthIdentityLimitsShareControllerAcrossSessions(t *testing.T) {
	handler := &Handler{limit: 2, entries: map[string]*entry{}, controllers: map[string]identityController{}, toolPolicies: map[string]config.ToolPolicy{}}
	policy := config.Client{Limits: &config.CallLimits{RequestsPerMinute: 1, Burst: 1}}
	now := time.Now()
	first := handler.identityControllerFor("subject-1\x00oauth:readers", policy, config.ToolPolicy{}, now)
	second := handler.identityControllerFor("subject-1\x00oauth:readers", policy, config.ToolPolicy{}, now)
	if first != second {
		t.Fatal("same OAuth identity received different controllers")
	}
	release, outcome := first.Admit("demo_status")
	if outcome != "" {
		t.Fatal(outcome)
	}
	release()
	if _, outcome := second.Admit("demo_status"); outcome != "identity_rate_limited" {
		t.Fatalf("shared rate outcome = %q", outcome)
	}
}

func TestComposeIdentityPolicies(t *testing.T) {
	matches := []auth.PolicyMatch{
		{Name: "writers", Policy: config.OAuthPolicy{Version: "writer-v1", Profile: "all", ToolPolicy: "write", Execute: true, InitialCapabilities: []string{"taskboard"}, Limits: &config.CallLimits{RequestsPerMinute: 60, Burst: 5, Concurrency: 4}}},
		{Name: "readers", Policy: config.OAuthPolicy{Version: "reader-v1", Profile: "all", ToolPolicy: "read", Discover: true, InitialCapabilities: []string{"fleetglass"}, Limits: &config.CallLimits{RequestsPerMinute: 120, Burst: 10, Concurrency: 2}}},
	}
	policies := map[string]config.ToolPolicy{
		"read": {
			Version: "read-v1", Profile: "all", Capabilities: map[string]string{"fleetglass": "allow"},
			Tools:      map[string]string{"taskboard_task_list": "allow", "taskboard_task_update": "allow"},
			ToolLimits: map[string]config.CallLimits{"taskboard_task_list": {RequestsPerMinute: 60, Burst: 6, Concurrency: 3}},
		},
		"write": {
			Version: "write-v1", Profile: "all", Capabilities: map[string]string{"taskboard": "allow"},
			Tools:      map[string]string{"taskboard_task_list": "deny", "taskboard_task_update": "require_approval"},
			ToolLimits: map[string]config.CallLimits{"taskboard_task_list": {RequestsPerMinute: 30, Burst: 3, Concurrency: 1}},
		},
	}
	owners := map[string]string{"fleetglass_status": "fleetglass", "taskboard_task_get": "taskboard", "taskboard_task_list": "taskboard", "taskboard_task_update": "taskboard"}
	client, effective, name, err := composeIdentityPolicies(matches, policies, owners)
	if err != nil {
		t.Fatal(err)
	}
	if name == "" || client.ToolPolicy != name || client.IdentityPolicyVersion == "" || effective.Version != client.IdentityPolicyVersion {
		t.Fatalf("identity=%+v tool_policy=%+v name=%q", client, effective, name)
	}
	if strings.Join(client.IdentityPolicyComponents, ",") != "readers,writers" {
		t.Fatalf("identity policy components = %v", client.IdentityPolicyComponents)
	}
	if !client.Discover || !client.Execute || client.Activate || client.Profile != "all" {
		t.Fatalf("client = %+v", client)
	}
	if strings.Join(client.InitialCapabilities, ",") != "fleetglass,taskboard" {
		t.Fatalf("initial capabilities = %v", client.InitialCapabilities)
	}
	if client.Limits == nil || client.Limits.RequestsPerMinute != 60 || client.Limits.Burst != 5 || client.Limits.Concurrency != 2 {
		t.Fatalf("limits = %+v", client.Limits)
	}
	if effective.Capabilities["fleetglass"] != "allow" || effective.Capabilities["taskboard"] != "allow" || effective.Tools["taskboard_task_list"] != "deny" || effective.Tools["taskboard_task_update"] != "require_approval" {
		t.Fatalf("effective policy = %+v", effective)
	}
	if _, ok := effective.ToolLimits["taskboard_task_list"]; ok {
		t.Fatal("limit retained for an effectively denied tool")
	}
	_, _, reversedName, err := composeIdentityPolicies([]auth.PolicyMatch{matches[1], matches[0]}, policies, owners)
	if err != nil || reversedName != name {
		t.Fatalf("composition is not deterministic: %q %v", reversedName, err)
	}
	expandedOwners := map[string]string{}
	for tool, owner := range owners {
		expandedOwners[tool] = owner
	}
	expandedOwners["taskboard_task_new"] = "taskboard"
	_, _, expandedName, err := composeIdentityPolicies(matches, policies, expandedOwners)
	if err != nil || expandedName == name {
		t.Fatalf("tool catalog change did not change effective policy: %q %v", expandedName, err)
	}
}

func TestComposeIdentityPoliciesCapabilityDenyWins(t *testing.T) {
	matches := []auth.PolicyMatch{
		{Name: "grant", Policy: config.OAuthPolicy{Version: "v1", Profile: "all", ToolPolicy: "grant", InitialCapabilities: []string{"taskboard"}}},
		{Name: "restricted", Policy: config.OAuthPolicy{Version: "v1", Profile: "all", ToolPolicy: "restricted", InitialCapabilities: []string{"taskboard"}}},
	}
	policies := map[string]config.ToolPolicy{
		"grant":      {Version: "v1", Profile: "all", Capabilities: map[string]string{"taskboard": "allow"}, Tools: map[string]string{"taskboard_task_update": "allow"}},
		"restricted": {Version: "v1", Profile: "all", Capabilities: map[string]string{"taskboard": "deny"}},
	}
	client, effective, _, err := composeIdentityPolicies(matches, policies, map[string]string{"taskboard_task_update": "taskboard"})
	if err != nil {
		t.Fatal(err)
	}
	if effective.Capabilities["taskboard"] != "deny" || effective.Tools["taskboard_task_update"] != "deny" {
		t.Fatalf("capability deny did not win: %+v", effective)
	}
	if client.InitialCapabilities == nil || len(client.InitialCapabilities) != 0 {
		t.Fatalf("denied initial capability retained: %v", client.InitialCapabilities)
	}
}

func TestComposeIdentityPoliciesFailsClosed(t *testing.T) {
	policies := map[string]config.ToolPolicy{"read": {Version: "v1", Profile: "all"}}
	for name, matches := range map[string][]auth.PolicyMatch{
		"mixed profiles": {
			{Name: "one", Policy: config.OAuthPolicy{Version: "v1", Profile: "all", ToolPolicy: "read"}},
			{Name: "two", Policy: config.OAuthPolicy{Version: "v1", Profile: "other", ToolPolicy: "read"}},
		},
		"missing tool policy": {{Name: "one", Policy: config.OAuthPolicy{Version: "v1", Profile: "all", ToolPolicy: "missing"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := composeIdentityPolicies(matches, policies, nil); err == nil {
				t.Fatal("unsafe composition succeeded")
			}
		})
	}
}

func TestOAuthStaticClientMigrationSwitch(t *testing.T) {
	token := strings.Repeat("s", 32)
	t.Setenv("MIGRATION_TOKEN", token)
	cfg := config.Config{
		Transport: "http", Profile: "empty", Profiles: map[string][]string{"empty": {}},
		Clients: map[string]config.Client{"migration": {TokenEnv: "MIGRATION_TOKEN", Profile: "empty"}},
		OAuth: &config.OAuthConfig{
			Issuer: "https://id.example.com", Resource: "https://switchboard.example.com/mcp/sessions", RequiredScopes: []string{"mcp:connect"}, AllowStaticClients: true,
			Policies: map[string]config.OAuthPolicy{"reader": {Version: "pilot-v1", Subjects: []string{"subject-alice"}, Profile: "empty"}},
		},
	}
	secureTestConfig(&cfg)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	handler, err := NewWithAuth(ctx, "test", cfg, nil, nil, fakeOAuthAuthenticator{})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	request := httptest.NewRequest(http.MethodPost, "/mcp/sessions", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	client, err := handler.authenticate(request)
	if err != nil || client.binding != "static:migration" || client.oauthSubject != "" {
		t.Fatalf("migration authentication = %+v, %v", client, err)
	}
}
