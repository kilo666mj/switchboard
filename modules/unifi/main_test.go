package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/egress"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.michaelspost.com/mcpkit/mcpkittest"
)

const testID = "00000000-0000-4000-8000-000000000001"

func testClient(t *testing.T, handler http.HandlerFunc) (*client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	api, err := newClient(server.URL, "test-api-key", ca, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.http.CloseIdleConnections)
	return api, server
}

func TestCatalogAndLocalRequests(t *testing.T) {
	expected := map[string]string{
		"unifi_get_info": "/v1/info", "unifi_list_sites": "/v1/sites",
		"unifi_list_networks": "/v1/sites/" + testID + "/networks", "unifi_get_network": "/v1/sites/" + testID + "/networks/" + testID,
		"unifi_list_wifi": "/v1/sites/" + testID + "/wifi/broadcasts", "unifi_get_wifi": "/v1/sites/" + testID + "/wifi/broadcasts/" + testID,
		"unifi_list_firewall_zones": "/v1/sites/" + testID + "/firewall/zones", "unifi_list_firewall_policies": "/v1/sites/" + testID + "/firewall/policies",
		"unifi_list_acl_rules": "/v1/sites/" + testID + "/acl-rules", "unifi_list_devices": "/v1/sites/" + testID + "/devices",
		"unifi_get_device": "/v1/sites/" + testID + "/devices/" + testID, "unifi_list_clients": "/v1/sites/" + testID + "/clients",
	}
	var calls atomic.Int32
	api, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.Header.Get("X-API-Key") != "test-api-key" || r.Header.Get("Cookie") != "" {
			t.Errorf("incorrect method or authentication")
		}
		if !strings.HasPrefix(r.URL.Path, integrationPath+"/v1/") {
			t.Errorf("wrong local prefix: %s", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "" && (r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("offset") != "3") {
			t.Errorf("pagination: %v", r.URL.Query())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"applicationVersion": "10.4.57", "id": testID, "data": []any{map[string]any{"id": testID, "name": "Test", "unexpectedSecret": "sentinel-secret"}}, "count": 1, "totalCount": 4, "limit": 2, "offset": 3, "unexpectedSecret": "sentinel-secret", "name": r.URL.Path})
	})
	server, err := newServer(api)
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	catalog, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("startup or discovery contacted upstream")
	}
	if len(catalog.Tools) != len(expected) {
		t.Fatalf("tool count: %d", len(catalog.Tools))
	}
	for _, tool := range catalog.Tools {
		path, ok := expected[tool.Name]
		if !ok {
			t.Fatalf("unexpected tool: %s", tool.Name)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || !tool.Annotations.IdempotentHint || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint {
			t.Fatalf("unsafe annotations: %s", tool.Name)
		}
		args := map[string]any{}
		if strings.Contains(path, "/sites/") {
			args["site_id"] = testID
		}
		if strings.HasPrefix(tool.Name, "unifi_get_") && tool.Name != "unifi_get_info" {
			args["id"] = testID
		}
		if strings.HasPrefix(tool.Name, "unifi_list_") {
			args["offset"] = 3
			args["limit"] = 2
		}
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: tool.Name, Arguments: args})
		if err != nil || result.IsError {
			t.Fatalf("%s: %v %#v", tool.Name, err, result)
		}
		raw, _ := json.Marshal(result)
		if strings.Contains(string(raw), "sentinel-secret") || strings.Contains(string(raw), "test-api-key") {
			t.Fatal("credential leaked")
		}
		if tool.Name != "unifi_get_info" && strings.HasPrefix(tool.Name, "unifi_get_") && !strings.Contains(string(raw), integrationPath+path) {
			t.Errorf("wrong route for %s: %s", tool.Name, raw)
		}
	}
	if calls.Load() != 12 {
		t.Fatalf("requests: %d", calls.Load())
	}
	for _, args := range []map[string]any{{"site_id": "../login"}, {"site_id": testID, "limit": 201}, {"site_id": testID, "offset": -1}, {"site_id": testID, "url": "https://example.com"}, {}} {
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "unifi_list_networks", Arguments: args})
		if err == nil && !result.IsError {
			t.Fatalf("accepted invalid arguments: %v", args)
		}
	}
	if calls.Load() != 12 {
		t.Fatal("invalid input reached the controller")
	}
}

func TestWiFiSecretsAndNestedSchemaChangesAreOmitted(t *testing.T) {
	api, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"`+testID+`","name":"Guest","securityConfiguration":{"type":"WPA2_PERSONAL","passphrase":"wifi-secret","presharedKeys":[{"key":"other-secret"}],"pmfMode":"REQUIRED","newField":"future-secret","radiusConfiguration":{"profileId":"profile","secret":"radius-secret"}},"broadcastingDeviceFilter":{"type":"DEVICES","deviceIds":[{"secret":"nested-secret"}]},"unknown":{"password":"new-secret"}}`)
	})
	server, err := newServer(api)
	if err != nil {
		t.Fatal(err)
	}
	session := mcpkittest.Connect(t, server)
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "unifi_get_wifi", Arguments: map[string]any{"site_id": testID, "id": testID}})
	if err != nil || result.IsError {
		t.Fatalf("call: %v %#v", err, result)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "secret") && (strings.Contains(string(raw), "wifi-secret") || strings.Contains(string(raw), "nested-secret") || strings.Contains(string(raw), "future-secret") || strings.Contains(string(raw), "radius-secret") || strings.Contains(string(raw), "other-secret") || strings.Contains(string(raw), "new-secret")) {
		t.Fatalf("leak: %s", raw)
	}
	if !strings.Contains(string(raw), "REQUIRED") || !strings.Contains(string(raw), "WPA2_PERSONAL") || !strings.Contains(string(raw), "profile") {
		t.Fatalf("lost useful config: %s", raw)
	}
}

func TestUpstreamFailuresAreBoundedAndSanitized(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body, want string
	}{
		{"unauthorized", 401, "secret-body", "denied access"}, {"forbidden", 403, "secret-body", "denied access"}, {"not found", 404, "secret-body", "not found"},
		{"upstream error", 500, "secret-body", "HTTP 500"}, {"html", 200, "<html>secret-body</html>", "invalid JSON"},
		{"null", 200, "null", "invalid JSON"}, {"trailing", 200, `{} {"password":"secret-body"}`, "trailing"},
		{"oversize", 200, strings.Repeat("x", maxResponseBytes+1), "4 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			_, err := api.get(t.Context(), "/v1/info", nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "secret-body") {
				t.Fatalf("error: %v", err)
			}
		})
	}
}

func TestRedirectTLSAndEgress(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	api, server := testClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) })
	if _, err := api.get(t.Context(), "/v1/info", nil); err == nil {
		t.Fatal("redirect accepted")
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect followed")
	}
	untrusted, err := newClient(server.URL, "key", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.http.CloseIdleConnections()
	if _, err := untrusted.get(t.Context(), "/v1/info", nil); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	policy, err := egress.New(config.EgressPolicy{AllowedDestinations: []string{strings.TrimPrefix(server.URL, "https://")}, AllowedCIDRs: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := newClient(server.URL, "key", "", "", policy)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.http.CloseIdleConnections()
	if _, err := blocked.get(t.Context(), "/v1/info", nil); err == nil {
		t.Fatal("egress CIDR bypass")
	}
	if _, err := newClient("https://unlisted.example.com", "key", "", "", policy); err == nil {
		t.Fatal("egress destination bypass")
	}
	for _, base := range []string{"http://example.com", "https://user:password@example.com", "https://example.com/path", "https://example.com?key=secret", "https://example.com/#fragment"} {
		if _, err := newClient(base, "key", "", "", nil); err == nil {
			t.Fatalf("accepted %s", base)
		}
	}
	for _, raw := range []string{"", `{"unknown":true}`, `{} {}`, `{"allowed_destinations":["example.com:443"],"allowed_cidrs":[]}`} {
		if _, err := moduleEgressPolicy(raw); err == nil {
			t.Fatalf("accepted policy %s", raw)
		}
	}
}

func TestProjectionPreservesArraysAndRejectsUnknownShapes(t *testing.T) {
	fields := projection{"data": {"id": nil, "addresses": nil}, "count": nil}
	input := map[string]any{"data": []any{map[string]any{"id": "one", "addresses": []any{"192.0.2.1"}, "password": "secret"}}, "count": json.Number("1"), "secret": "hidden"}
	got, ok := project(input, fields)
	want := map[string]any{"data": []any{map[string]any{"id": "one", "addresses": []any{"192.0.2.1"}}}, "count": json.Number("1")}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("projection: %#v", got)
	}
	if _, ok := project([]any{"unexpected"}, projection{"id": nil}); ok {
		t.Fatal("accepted malformed object array")
	}
}

func TestMalformedSuccessfulResponsesFailClosed(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":null}`, `{"data":["unexpected"]}`} {
		api, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, body)
		})
		server, err := newServer(api)
		if err != nil {
			t.Fatal(err)
		}
		session := mcpkittest.Connect(t, server)
		for _, name := range []string{"unifi_list_sites", "unifi_get_info"} {
			result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{}})
			if err == nil && !result.IsError {
				t.Fatalf("%s accepted %s", name, body)
			}
		}
	}
}

func TestModuleEOF(t *testing.T) {
	if os.Getenv("UNIFI_MODULE_TEST_PROCESS") == "1" {
		if err := run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestModuleEOF$")
	command.Env = []string{"UNIFI_MODULE_TEST_PROCESS=1", "UNIFI_URL=https://127.0.0.1:1", "UNIFI_API_KEY=test-key", "SWITCHBOARD_MODULE_NAME=unifi", `SWITCHBOARD_MODULE_EGRESS_POLICY={"allowed_destinations":["127.0.0.1:1"],"allowed_cidrs":["127.0.0.0/8"]}`}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("EOF shutdown: %v %s", err, output)
	}
}

func TestExplicitTLSIdentityStillVerifiesCertificate(t *testing.T) {
	_, server := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"applicationVersion":"10.6.106"}`)
	})
	ca := filepath.Join(t.TempDir(), "controller.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		wantOK bool
	}{{"example.com", true}, {"wrong.example.net", false}} {
		api, err := newClient(server.URL, "key", ca, tc.name, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = api.get(t.Context(), "/v1/info", nil)
		api.http.CloseIdleConnections()
		if (err == nil) != tc.wantOK {
			t.Fatalf("TLS identity %s: %v", tc.name, err)
		}
	}
	if _, err := newClient(server.URL, "key", "", "example.com", nil); err == nil {
		t.Fatal("TLS identity override without explicit certificate trust accepted")
	}
}
