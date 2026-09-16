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
	"sort"
	"strings"
	"sync"
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
	if len(os.Args) > 1 && os.Args[1] == "permissions" {
		return runPermissions(os.Args[2:])
	}
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
	for clientName, client := range cfg.Clients {
		if cfg.StaticClientEnabled(clientName) {
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
	metrics := observability.NewMetrics()
	if cfg.Transport == "stdio" {
		capabilities, loadErr := loader.Load(ctx, cfg.CapabilityDir, selected, egressPolicy)
		if loadErr != nil {
			return loadErr
		}
		defer closeCapabilities(capabilities)
		newServer := func() (*mcp.Server, error) {
			return gateway.NewWithMetrics(version, cfg.Profile, selectCapabilities(capabilities, cfg.Profiles[cfg.Profile]), metrics)
		}
		server, err := newServer()
		if err != nil {
			return err
		}
		return mcpkit.RunStdio(ctx, server)
	}
	capabilities, failures, err := loader.LoadAvailable(ctx, cfg.CapabilityDir, selected, egressPolicy)
	if err != nil {
		return err
	}
	if len(capabilities) == 0 && len(selected) > 0 {
		return fmt.Errorf("all configured capabilities are unavailable: %s", loadFailureSummary(failures))
	}
	store := newCapabilityStore(capabilities)
	defer store.Close()
	unavailable := make([]string, 0, len(failures))
	for _, name := range selected {
		metrics.SetCapabilityAvailable(name, store.Has(name))
	}
	for _, failure := range failures {
		unavailable = append(unavailable, failure.Name)
		metrics.CapabilityLoadFailure(failure.Name)
		slog.Warn("capability unavailable at startup", "name", failure.Name, "error", failure.Err)
	}
	newServer := func() (*mcp.Server, error) {
		return gateway.NewWithMetrics(version, cfg.Profile, selectCapabilities(store.Snapshot(), cfg.Profiles[cfg.Profile]), metrics)
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
		handler, err := sessions.NewWithAuthUnavailable(ctx, version, cfg, capabilities, unavailable, metrics, sessionAuthenticator)
		if err != nil {
			return err
		}
		defer handler.Close()
		retryUnavailableCapabilities(ctx, cfg.CapabilityDir, failures, egressPolicy, store, handler, metrics)
		return serveHTTPWithSessions(ctx, cfg, newServer, handler, metrics, oauthAuthenticator)
	}
	retryUnavailableCapabilities(ctx, cfg.CapabilityDir, failures, egressPolicy, store, nil, metrics)
	return serveHTTP(ctx, cfg, newServer, metrics, oauthAuthenticator)
}

type capabilityStore struct {
	mu     sync.RWMutex
	items  map[string]capability.Capability
	closed bool
}

func newCapabilityStore(items []capability.Capability) *capabilityStore {
	store := &capabilityStore{items: make(map[string]capability.Capability, len(items))}
	for _, item := range items {
		store.items[item.Name()] = item
	}
	return store
}

func (s *capabilityStore) Has(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.items[name] != nil
}

func (s *capabilityStore) Add(item capability.Capability) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("capability store is closed")
	}
	if s.items[item.Name()] != nil {
		return fmt.Errorf("duplicate capability %q", item.Name())
	}
	s.items[item.Name()] = item
	return nil
}

func (s *capabilityStore) Snapshot() []capability.Capability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]capability.Capability, 0, len(s.items))
	for _, item := range s.items {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name() < items[j].Name() })
	return items
}

func (s *capabilityStore) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	items := make([]capability.Capability, 0, len(s.items))
	for _, item := range s.items {
		items = append(items, item)
	}
	s.items = map[string]capability.Capability{}
	s.mu.Unlock()
	closeCapabilities(items)
}

func selectCapabilities(items []capability.Capability, names []string) []capability.Capability {
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	selected := make([]capability.Capability, 0, len(items))
	for _, item := range items {
		if wanted[item.Name()] {
			selected = append(selected, item)
		}
	}
	return selected
}

func loadFailureSummary(failures []loader.LoadFailure) string {
	parts := make([]string, 0, len(failures))
	for _, failure := range failures {
		parts = append(parts, failure.Error())
	}
	return strings.Join(parts, "; ")
}

type capabilityAdder interface {
	AddCapability(capability.Capability) error
}

func retryUnavailableCapabilities(ctx context.Context, dir string, failures []loader.LoadFailure, policy *egress.Policy, store *capabilityStore, sessions capabilityAdder, metrics *observability.Metrics) {
	for _, failure := range failures {
		name := failure.Name
		go func() {
			backoff := 5 * time.Second
			for {
				timer := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				items, retryFailures, err := loader.LoadAvailable(ctx, dir, []string{name}, policy)
				if err == nil && len(retryFailures) == 0 && len(items) == 1 {
					item := items[0]
					if sessions != nil {
						err = sessions.AddCapability(item)
					}
					if err == nil {
						err = store.Add(item)
					}
					if err == nil {
						metrics.SetCapabilityAvailable(name, true)
						slog.Info("capability recovered", "name", name)
						return
					}
					if closer, ok := item.(capability.Closer); ok {
						_ = closer.Close()
					}
				} else if err == nil && len(retryFailures) > 0 {
					err = errors.New(loadFailureSummary(retryFailures))
				} else if err == nil {
					err = fmt.Errorf("retry loaded %d capabilities, want 1", len(items))
				}
				metrics.CapabilityLoadFailure(name)
				backoff = min(backoff*2, 5*time.Minute)
				slog.Warn("capability retry failed", "name", name, "retry_in", backoff, "error", err)
			}
		}()
	}
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
		} else {
			mux.Handle("POST /mcp", retiredLegacyMCP(metrics))
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

func retiredLegacyMCP(metrics *observability.Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		metrics.AuthenticationFailure()
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
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
