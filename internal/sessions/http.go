// Package sessions owns authenticated, bounded downstream HTTP session lifetimes.
package sessions

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const sessionHeader = "Mcp-Session-Id"

type credential struct {
	name   string
	digest [32]byte
	policy config.Client
}
type entry struct {
	owner             string
	server            *mcp.Server
	lastSeen, created time.Time
	pending           bool
}

type Handler struct {
	mu           sync.Mutex
	credentials  []credential
	entries      map[string]*entry
	limit        int
	idle         time.Duration
	version      string
	capabilities map[string]capability.Capability
	profiles     map[string][]string
	transport    *mcp.StreamableHTTPHandler
	protected    http.Handler
	closed       bool
}

type serverKey struct{}

func New(ctx context.Context, version string, cfg config.Config, items []capability.Capability) (*Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	h := &Handler{entries: map[string]*entry{}, limit: cfg.SessionLimit, idle: time.Duration(cfg.SessionIdleSeconds) * time.Second, version: version, capabilities: map[string]capability.Capability{}, profiles: cfg.Profiles}
	if h.limit == 0 {
		h.limit = 256
	}
	if h.idle == 0 {
		h.idle = 30 * time.Minute
	}
	seen := map[[32]byte]bool{}
	for name, policy := range cfg.Clients {
		token := os.Getenv(policy.TokenEnv)
		if len(token) < 32 {
			return nil, fmt.Errorf("client %q token must contain at least 32 bytes", name)
		}
		digest := sha256.Sum256([]byte("Bearer " + token))
		if legacy := os.Getenv("SWITCHBOARD_BEARER_TOKEN"); legacy != "" && token == legacy {
			return nil, fmt.Errorf("client credentials must differ from the legacy bearer")
		}
		if seen[digest] {
			return nil, fmt.Errorf("client credentials must be unique")
		}
		seen[digest] = true
		h.credentials = append(h.credentials, credential{name, digest, policy})
	}
	if len(h.credentials) == 0 {
		return nil, fmt.Errorf("authenticated sessions require clients")
	}
	for _, item := range items {
		h.capabilities[item.Name()] = item
	}
	for _, client := range h.credentials {
		for _, name := range cfg.Profiles[client.policy.Profile] {
			if h.capabilities[name] == nil {
				return nil, fmt.Errorf("missing capability %q", name)
			}
		}
	}
	h.transport = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		server, _ := r.Context().Value(serverKey{}).(*mcp.Server)
		return server
	}, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: cfg.BehindLoopbackProxy})
	protection := http.NewCrossOriginProtection()
	for _, origin := range cfg.TrustedOrigins {
		if err := protection.AddTrustedOrigin(origin); err != nil {
			return nil, err
		}
	}
	h.protected = protection.Handler(http.HandlerFunc(h.serve))
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				h.Close()
				return
			case now := <-ticker.C:
				h.expire(now)
			}
		}
	}()
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.protected.ServeHTTP(w, r) }

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	digest := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	var client *credential
	for i := range h.credentials {
		if subtle.ConstantTimeCompare(digest[:], h.credentials[i].digest[:]) == 1 {
			client = &h.credentials[i]
		}
	}
	if client == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", 401)
		return
	}
	if len(r.Header.Values(sessionHeader)) > 1 {
		http.Error(w, "invalid session header", 400)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	id := r.Header.Get(sessionHeader)
	now := time.Now()
	h.expire(now)
	if id != "" {
		h.mu.Lock()
		record := h.entries[id]
		if record == nil || record.owner != client.name || h.closed {
			h.mu.Unlock()
			http.Error(w, "session not found", 404)
			return
		}
		record.lastSeen = now
		h.mu.Unlock()
		h.transport.ServeHTTP(w, r)
		if r.Method == http.MethodDelete {
			h.remove(id, record)
		}
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "session required", 400)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid or oversized request", 413)
		return
	}
	var envelope struct {
		JSONRPC string `json:"jsonrpc"`
		Params  struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"clientInfo"`
		} `json:"params"`
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.JSONRPC != "2.0" || envelope.Params.ProtocolVersion == "" || envelope.Params.ClientInfo.Name == "" || envelope.Params.ClientInfo.Version == "" || envelope.Method != "initialize" || len(envelope.ID) == 0 || string(envelope.ID) == "null" {
		http.Error(w, "initialize required", 400)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	h.mu.Lock()
	count := 0
	for _, record := range h.entries {
		if record.owner == client.name {
			count++
		}
	}
	if h.closed || len(h.entries) >= h.limit || count >= 32 {
		h.mu.Unlock()
		http.Error(w, "session capacity reached", 503)
		return
	}
	id = rand.Text()
	var allowed []capability.Capability
	for _, name := range h.profiles[client.policy.Profile] {
		allowed = append(allowed, h.capabilities[name])
	}
	server, err := gateway.NewSession(h.version, id, client.name, client.policy, allowed)
	if err != nil {
		h.mu.Unlock()
		http.Error(w, "session configuration error", 500)
		return
	}
	record := &entry{owner: client.name, server: server, lastSeen: now, created: now, pending: true}
	h.entries[id] = record
	h.mu.Unlock()
	h.transport.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), serverKey{}, server)))
	initialized := false
	for session := range server.Sessions() {
		if session.InitializeParams() != nil {
			initialized = true
		}
	}
	h.mu.Lock()
	record.pending = false
	closed := h.closed
	h.mu.Unlock()
	if !initialized || closed {
		h.remove(id, record)
	}
}

func closeEntry(record *entry) {
	for session := range record.server.Sessions() {
		_ = session.Close()
	}
}
func (h *Handler) remove(id string, record *entry) {
	h.mu.Lock()
	if h.entries[id] == record {
		delete(h.entries, id)
	}
	h.mu.Unlock()
	closeEntry(record)
}
func (h *Handler) expire(now time.Time) {
	var expired []*entry
	h.mu.Lock()
	for id, record := range h.entries {
		if !record.pending && (now.Sub(record.lastSeen) >= h.idle || now.Sub(record.created) >= 24*time.Hour) {
			delete(h.entries, id)
			expired = append(expired, record)
		}
	}
	h.mu.Unlock()
	for _, record := range expired {
		closeEntry(record)
	}
}
func (h *Handler) Close() {
	h.mu.Lock()
	h.closed = true
	entries := h.entries
	h.entries = map[string]*entry{}
	h.mu.Unlock()
	for _, record := range entries {
		closeEntry(record)
	}
}
