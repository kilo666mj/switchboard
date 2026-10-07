// Command switchboard-module-unifi exposes read-only UniFi OS Server Network configuration through a standalone stdio MCP module.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/egress"
	"go.michaelspost.com/mcpkit"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("unifi module stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	if name := os.Getenv("SWITCHBOARD_MODULE_NAME"); name != "" && name != "unifi" {
		return errors.New("module identity must be unifi")
	}
	policy, err := moduleEgressPolicy(os.Getenv("SWITCHBOARD_MODULE_EGRESS_POLICY"))
	if err != nil {
		return err
	}
	api, err := newClient(os.Getenv("UNIFI_URL"), os.Getenv("UNIFI_API_KEY"), os.Getenv("UNIFI_CA_FILE"), os.Getenv("UNIFI_TLS_SERVER_NAME"), policy)
	if err != nil {
		return err
	}
	defer api.http.CloseIdleConnections()
	server, err := newServer(api)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return mcpkit.RunStdio(ctx, server)
}

func moduleEgressPolicy(raw string) (*egress.Policy, error) {
	if raw == "" {
		return nil, errors.New("SWITCHBOARD_MODULE_EGRESS_POLICY is required")
	}
	var cfg config.EgressPolicy
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, errors.New("invalid module egress policy")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing module egress policy data")
	}
	policy, err := egress.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure module egress policy: %w", err)
	}
	return policy, nil
}
