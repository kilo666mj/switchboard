package loader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAvailableIsolatesRecoverableModuleFailure(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "healthy.json", `{
  "version": 1,
  "name": "healthy",
  "base_url": "https://healthy.example.test",
  "tools": [{
    "name": "status",
    "description": "status",
    "path": "/status",
    "safety": "read_only",
    "input_schema": {"type": "object"}
  }]
}`)
	writeManifest(t, dir, "broken.json", `{
  "version": 1,
  "type": "module",
  "name": "broken",
  "command": "/bin/false"
}`)

	items, failures, err := LoadAvailable(t.Context(), dir, []string{"healthy", "broken"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name() != "healthy" {
		t.Fatalf("items = %#v", items)
	}
	if len(failures) != 1 || failures[0].Name != "broken" {
		t.Fatalf("failures = %#v", failures)
	}
}

func TestLoadAvailableKeepsConfigurationFailuresFatal(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "invalid.json", `{"version":1,"type":"mcp","name":"invalid","endpoint":"not-a-url"}`)
	items, failures, err := LoadAvailable(t.Context(), dir, []string{"invalid"}, nil)
	if err == nil || items != nil || failures != nil {
		t.Fatalf("items=%#v failures=%#v err=%v", items, failures, err)
	}
}

func writeManifest(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
