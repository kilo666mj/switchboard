package main

import (
	"encoding/json"
	"strings"
	"testing"

	caprest "github.com/kilo666mj/switchboard/internal/capability/rest"
)

func TestEmbeddedAPIManifestPreservesTools(t *testing.T) {
	t.Setenv("LOG_WATCHER_API_URL", "http://127.0.0.1:1")
	t.Setenv("LOG_WATCHER_API_TOKEN", "test-token")
	var manifest caprest.Manifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestJSON)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	api, err := caprest.New(manifest)
	if err != nil {
		t.Fatal(err)
	}
	description := api.Describe()
	want := []string{
		"log_watcher_list_excludes",
		"log_watcher_add_exclude",
		"log_watcher_remove_exclude",
	}
	if len(description.Tools) != len(want) {
		t.Fatalf("tools = %#v", description.Tools)
	}
	for i, name := range want {
		if description.Tools[i].Name != name || description.Tools[i].Annotations == nil {
			t.Fatalf("tool %d = %#v", i, description.Tools[i])
		}
	}
	if !description.Tools[0].Annotations.ReadOnlyHint || description.Tools[1].Annotations.ReadOnlyHint || description.Tools[2].Annotations.ReadOnlyHint {
		t.Fatalf("safety annotations changed: %#v", description.Tools)
	}
}

func TestModuleEgressPolicy(t *testing.T) {
	t.Setenv("SWITCHBOARD_MODULE_EGRESS_POLICY", `{"allowed_destinations":["api.example.internal:443"],"allowed_cidrs":["192.0.2.0/24"]}`)
	policy, err := moduleEgressPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ValidateURL("https://api.example.internal/v1"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SWITCHBOARD_MODULE_EGRESS_POLICY", `{"unknown":true}`)
	if _, err := moduleEgressPolicy(); err == nil {
		t.Fatal("unknown egress policy field was accepted")
	}
}
