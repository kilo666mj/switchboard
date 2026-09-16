// Command switchboard-module-log-watcher exposes Log Watcher's canonical HTTP
// API as a self-contained stdio MCP module.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kilo666mj/mcpkit"
	caprest "github.com/kilo666mj/switchboard/internal/capability/rest"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/egress"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var version = "dev"

//go:embed api.json
var manifestJSON []byte

func main() {
	if err := run(); err != nil {
		slog.Error("log_watcher module stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	if name := os.Getenv("SWITCHBOARD_MODULE_NAME"); name != "" && name != "log_watcher" {
		return fmt.Errorf("module identity is %q, want log_watcher", name)
	}
	var manifest caprest.Manifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestJSON)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode embedded API manifest: %w", err)
	}
	policy, err := moduleEgressPolicy()
	if err != nil {
		return err
	}
	api, err := caprest.NewWithEgress(manifest, policy)
	if err != nil {
		return fmt.Errorf("configure Log Watcher API: %w", err)
	}
	server, err := mcpkit.NewServer(mcpkit.ServerConfig{
		Name:         "switchboard-module-log-watcher",
		Version:      version,
		Instructions: "Use Log Watcher's canonical exclusion workflow and preserve its safety checks.",
	})
	if err != nil {
		return err
	}
	if err := api.Register(server); err != nil {
		return fmt.Errorf("register Log Watcher tools: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return server.Run(ctx, &mcp.StdioTransport{})
}

func moduleEgressPolicy() (*egress.Policy, error) {
	raw := os.Getenv("SWITCHBOARD_MODULE_EGRESS_POLICY")
	if raw == "" {
		return nil, fmt.Errorf("SWITCHBOARD_MODULE_EGRESS_POLICY is required")
	}
	var cfg config.EgressPolicy
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode module egress policy: %w", err)
	}
	policy, err := egress.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure module egress policy: %w", err)
	}
	return policy, nil
}
