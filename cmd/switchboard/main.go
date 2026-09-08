package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/kilo666mj/switchboard/internal/loader"
	"github.com/kilo666mj/switchboard/internal/sessions"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("switchboard stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "switchboard.json", "path to Switchboard configuration")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	selected := append([]string{}, cfg.Profiles[cfg.Profile]...)
	seen := map[string]bool{}
	for _, name := range selected {
		seen[name] = true
	}
	for _, client := range cfg.Clients {
		for _, name := range cfg.Profiles[client.Profile] {
			if !seen[name] {
				selected = append(selected, name)
				seen[name] = true
			}
		}
	}
	capabilities, err := loader.Load(ctx, cfg.CapabilityDir, selected)
	if err != nil {
		return err
	}
	defer closeCapabilities(capabilities)
	static := []capability.Capability{}
	for _, item := range capabilities {
		for _, name := range cfg.Profiles[cfg.Profile] {
			if item.Name() == name {
				static = append(static, item)
			}
		}
	}
	newServer := func() (*mcp.Server, error) { return gateway.New(version, cfg.Profile, static) }
	if cfg.Transport == "stdio" {
		server, err := newServer()
		if err != nil {
			return err
		}
		return mcpkit.RunStdio(ctx, server)
	}
	if len(cfg.Clients) > 0 {
		handler, err := sessions.New(ctx, version, cfg, capabilities)
		if err != nil {
			return err
		}
		defer handler.Close()
		return serveHTTPWithSessions(ctx, cfg, newServer, handler)
	}
	return serveHTTP(ctx, cfg, newServer)
}

func closeCapabilities(items []capability.Capability) {
	for _, item := range items {
		if closer, ok := item.(capability.Closer); ok {
			if err := closer.Close(); err != nil {
				slog.Warn("close capability", "name", item.Name(), "error", err)
			}
		}
	}
}

func serveHTTP(ctx context.Context, cfg config.Config, factory func() (*mcp.Server, error)) error {
	return serveHTTPWithSessions(ctx, cfg, factory, nil)
}

func serveHTTPWithSessions(ctx context.Context, cfg config.Config, factory func() (*mcp.Server, error), dynamic http.Handler) error {
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	token := os.Getenv("SWITCHBOARD_BEARER_TOKEN")
	if token == "" && host != "127.0.0.1" && host != "::1" && host != "localhost" && dynamic == nil {
		return errors.New("SWITCHBOARD_BEARER_TOKEN is required when listening beyond loopback")
	}
	handler, err := mcpkit.StatelessHTTP(func(_ *http.Request) *mcp.Server {
		server, createErr := factory()
		if createErr != nil {
			slog.Error("create MCP server", "error", createErr)
			return nil
		}
		return server
	}, mcpkit.HTTPOptions{TrustedOrigins: cfg.TrustedOrigins, DisableLocalhostProtection: cfg.BehindLoopbackProxy})
	if err != nil {
		return err
	}
	if token != "" {
		handler = bearer(token, handler)
	}
	mux := http.NewServeMux()
	if dynamic != nil {
		mux.Handle("/mcp/sessions", dynamic)
		// A deployment with client identities must never expose an unauthenticated legacy endpoint.
		if token != "" {
			mux.Handle("POST /mcp", handler)
		}
	} else {
		mux.Handle("POST /mcp", handler)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	server := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	slog.Info("switchboard listening", "address", cfg.Listen, "profile", cfg.Profile)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func bearer(token string, next http.Handler) http.Handler {
	expected := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := []byte(r.Header.Get("Authorization"))
		if len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
