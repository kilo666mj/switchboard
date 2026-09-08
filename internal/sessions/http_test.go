package sessions

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/capability/rest"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
