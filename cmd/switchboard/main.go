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
	"github.com/kilo666mj/switchboard/internal/auth"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/egress"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/kilo666mj/switchboard/internal/loader"
	"github.com/kilo666mj/switchboard/internal/observability"
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
	if cfg.StaticClientsEnabled() {
		for _, client := range cfg.Clients {
			for _, name := range cfg.Profiles[client.Profile] {
				if !seen[name] {
					selected = append(selected, name)
					seen[name] = true
				}
			}
		}
	}
	if cfg.OAuth != nil {
		for _, policy := range cfg.OAuth.Policies {
			for _, name := range cfg.Profiles[policy.Profile] {
				if !seen[name] {
					selected = append(selected, name)
					seen[name] = true
				}
			}
		}
	}
	if cfg.CloudflareAccess != nil {
		for _, policy := range cfg.CloudflareAccess.Policies {
			for _, name := range cfg.Profiles[policy.Profile] {
				if !seen[name] {
					selected = append(selected, name)
					seen[name] = true
				}
			}
		}
	}
	var egressPolicy *egress.Policy
	if cfg.EgressPolicy != nil {
		egressPolicy, err = egress.New(*cfg.EgressPolicy)
		if err != nil {
			return fmt.Errorf("egress policy: %w", err)
		}
	}
	var oauthAuthenticator *auth.Authenticator
	if cfg.OAuth != nil {
		oauthAuthenticator, err = auth.New(ctx, *cfg.OAuth, egressPolicy)
		if err != nil {
			return fmt.Errorf("OAuth authentication: %w", err)
		}
	}
	var cloudflareAuthenticator *auth.CloudflareAccessAuthenticator
	if cfg.CloudflareAccess != nil {
		cloudflareAuthenticator, err = auth.NewCloudflareAccess(ctx, *cfg.CloudflareAccess, egressPolicy)
		if err != nil {
			return fmt.Errorf("Cloudflare Access authentication: %w", err)
		}
	}
	capabilities, err := loader.Load(ctx, cfg.CapabilityDir, selected, egressPolicy)
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
	metrics := observability.NewMetrics()
	newServer := func() (*mcp.Server, error) { return gateway.NewWithMetrics(version, cfg.Profile, static, metrics) }
	if cfg.Transport == "stdio" {
		server, err := newServer()
		if err != nil {
			return err
		}
		return mcpkit.RunStdio(ctx, server)
	}
	if len(cfg.Clients) > 0 || cfg.OAuth != nil || cfg.CloudflareAccess != nil {
		var sessionAuthenticator sessions.IdentityAuthenticator
		switch {
		case oauthAuthenticator != nil && cloudflareAuthenticator != nil:
			sessionAuthenticator = auth.NewCompositeAuthenticator(oauthAuthenticator, cloudflareAuthenticator)
		case oauthAuthenticator != nil:
			sessionAuthenticator = oauthAuthenticator
		case cloudflareAuthenticator != nil:
			sessionAuthenticator = cloudflareAuthenticator
		}
		handler, err := sessions.NewWithAuth(ctx, version, cfg, capabilities, metrics, sessionAuthenticator)
		if err != nil {
			return err
		}
		defer handler.Close()
		return serveHTTPWithSessions(ctx, cfg, newServer, handler, metrics, oauthAuthenticator)
	}
	return serveHTTP(ctx, cfg, newServer, metrics, oauthAuthenticator)
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

func serveHTTP(ctx context.Context, cfg config.Config, factory func() (*mcp.Server, error), metrics *observability.Metrics, oauth *auth.Authenticator) error {
	return serveHTTPWithSessions(ctx, cfg, factory, nil, metrics, oauth)
}

func serveHTTPWithSessions(ctx context.Context, cfg config.Config, factory func() (*mcp.Server, error), dynamic http.Handler, metrics *observability.Metrics, oauth *auth.Authenticator) error {
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
		handler = bearerWithMetrics(token, handler, metrics)
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
	mux.Handle("GET /metrics", metrics)
	if oauth != nil {
		mux.Handle("GET "+oauth.MetadataPath(), oauth)
	}
	server := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 32 << 10}
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
	return bearerWithMetrics(token, next, nil)
}

func bearerWithMetrics(token string, next http.Handler, metrics *observability.Metrics) http.Handler {
	expected := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := []byte(r.Header.Get("Authorization"))
		if len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
			metrics.AuthenticationFailure()
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
