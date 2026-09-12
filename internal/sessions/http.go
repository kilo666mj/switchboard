// Package sessions owns authenticated, bounded downstream HTTP session lifetimes.
package sessions

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kilo666mj/switchboard/internal/auth"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/gateway"
	"github.com/kilo666mj/switchboard/internal/observability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const sessionHeader = "Mcp-Session-Id"

type credential struct {
	name       string
	digest     [32]byte
	policy     config.Client
	controller *gateway.CallController
}
type entry struct {
	owner             string
	binding           string
	controllerKey     string
	server            *mcp.Server
	lastSeen, created time.Time
	pending           bool
}

type requestClient struct {
	name, binding string
	policy        config.Client
	toolPolicy    config.ToolPolicy
	controller    *gateway.CallController
}

type identityController struct {
	controller *gateway.CallController
	lastSeen   time.Time
}

type IdentityAuthenticator interface {
	Authenticate(*http.Request) (auth.Principal, error)
	WriteError(http.ResponseWriter, error)
}

type Handler struct {
	mu            sync.Mutex
	credentials   []credential
	entries       map[string]*entry
	limit         int
	idle          time.Duration
	version       string
	capabilities  map[string]capability.Capability
	profiles      map[string][]string
	toolPolicies  map[string]config.ToolPolicy
	metrics       *observability.Metrics
	authenticator IdentityAuthenticator
	controllers   map[string]identityController
	transport     *mcp.StreamableHTTPHandler
	protected     http.Handler
	closed        bool
}

type serverKey struct{}

func New(ctx context.Context, version string, cfg config.Config, items []capability.Capability) (*Handler, error) {
	return NewWithMetrics(ctx, version, cfg, items, nil)
}

func NewWithMetrics(ctx context.Context, version string, cfg config.Config, items []capability.Capability, metrics *observability.Metrics) (*Handler, error) {
	return NewWithAuth(ctx, version, cfg, items, metrics, nil)
}

func NewWithAuth(ctx context.Context, version string, cfg config.Config, items []capability.Capability, metrics *observability.Metrics, authenticator IdentityAuthenticator) (*Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if (cfg.OAuth == nil && cfg.CloudflareAccess == nil) != (authenticator == nil) {
		return nil, errors.New("identity-provider configuration and authenticator must be supplied together")
	}
	h := &Handler{entries: map[string]*entry{}, limit: cfg.SessionLimit, idle: time.Duration(cfg.SessionIdleSeconds) * time.Second, version: version, capabilities: map[string]capability.Capability{}, profiles: cfg.Profiles, toolPolicies: cfg.ToolPolicies, metrics: metrics, authenticator: authenticator, controllers: map[string]identityController{}}
	if h.limit == 0 {
		h.limit = 256
	}
	if h.idle == 0 {
		h.idle = 30 * time.Minute
	}
	seen := map[[32]byte]bool{}
	staticEnabled := cfg.StaticClientsEnabled()
	for name, policy := range cfg.Clients {
		if !staticEnabled {
			continue
		}
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
		policy.IdentityPolicy = "static:" + name
		h.credentials = append(h.credentials, credential{name: name, digest: digest, policy: policy, controller: gateway.NewCallController(policy, cfg.ToolPolicies[policy.ToolPolicy])})
	}
	if len(h.credentials) == 0 && h.authenticator == nil {
		return nil, fmt.Errorf("authenticated sessions require clients")
	}
	for _, item := range items {
		h.capabilities[item.Name()] = item
	}
	for _, client := range h.credentials {
		var allowed []capability.Capability
		for _, name := range cfg.Profiles[client.policy.Profile] {
			if h.capabilities[name] == nil {
				return nil, fmt.Errorf("missing capability %q", name)
			}
			allowed = append(allowed, h.capabilities[name])
		}
		if err := gateway.ValidateToolPolicy(h.toolPolicies[client.policy.ToolPolicy], allowed); err != nil {
			return nil, fmt.Errorf("client %q tool policy: %w", client.name, err)
		}
	}
	if cfg.OAuth != nil {
		for name, oauthPolicy := range cfg.OAuth.Policies {
			var allowed []capability.Capability
			for _, capabilityName := range cfg.Profiles[oauthPolicy.Profile] {
				if h.capabilities[capabilityName] == nil {
					return nil, fmt.Errorf("missing capability %q", capabilityName)
				}
				allowed = append(allowed, h.capabilities[capabilityName])
			}
			if err := gateway.ValidateToolPolicy(h.toolPolicies[oauthPolicy.ToolPolicy], allowed); err != nil {
				return nil, fmt.Errorf("OAuth policy %q tool policy: %w", name, err)
			}
		}
	}
	if cfg.CloudflareAccess != nil {
		for name, identityPolicy := range cfg.CloudflareAccess.Policies {
			var allowed []capability.Capability
			for _, capabilityName := range cfg.Profiles[identityPolicy.Profile] {
				if h.capabilities[capabilityName] == nil {
					return nil, fmt.Errorf("missing capability %q", capabilityName)
				}
				allowed = append(allowed, h.capabilities[capabilityName])
			}
			if err := gateway.ValidateToolPolicy(h.toolPolicies[identityPolicy.ToolPolicy], allowed); err != nil {
				return nil, fmt.Errorf("Cloudflare Access policy %q tool policy: %w", name, err)
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

func (h *Handler) authenticate(r *http.Request) (*requestClient, error) {
	values := r.Header.Values("Authorization")
	if len(values) > 0 && len(r.Header.Values(auth.CloudflareAccessJWTHeader)) > 0 {
		return nil, auth.ErrAmbiguousCredential
	}
	if len(values) > 1 {
		return nil, auth.ErrInvalidToken
	}
	if len(values) == 1 {
		digest := sha256.Sum256([]byte(values[0]))
		var matched *credential
		for i := range h.credentials {
			if subtle.ConstantTimeCompare(digest[:], h.credentials[i].digest[:]) == 1 {
				matched = &h.credentials[i]
			}
		}
		if matched != nil {
			return &requestClient{name: matched.name, binding: "static:" + matched.name, policy: matched.policy, toolPolicy: h.toolPolicies[matched.policy.ToolPolicy], controller: matched.controller}, nil
		}
	}
	if h.authenticator == nil {
		if len(values) == 0 {
			return nil, auth.ErrMissingToken
		}
		return nil, auth.ErrInvalidToken
	}
	principal, err := h.authenticator.Authenticate(r)
	if err != nil {
		return nil, err
	}
	source := principal.Source
	if source == "" {
		source = "oauth"
	}
	policy, toolPolicy, policyName, err := h.resolvePrincipal(principal)
	if err != nil {
		return nil, err
	}
	policy.IdentityPolicy = source + ":" + policyName
	binding := policy.IdentityPolicy
	if policy.IdentityPolicyVersion != "" {
		binding += "\x00" + policy.IdentityPolicyVersion
	}
	return &requestClient{name: principal.Identity, binding: binding, policy: policy, toolPolicy: toolPolicy}, nil
}

func (h *Handler) resolvePrincipal(principal auth.Principal) (config.Client, config.ToolPolicy, string, error) {
	if !principal.Composed {
		return principal.Policy, h.toolPolicies[principal.Policy.ToolPolicy], principal.PolicyName, nil
	}
	toolOwners := map[string]string{}
	for _, match := range principal.PolicyMatches {
		for _, capabilityName := range h.profiles[match.Policy.Profile] {
			item := h.capabilities[capabilityName]
			describer, ok := item.(capability.Describer)
			if !ok {
				return config.Client{}, config.ToolPolicy{}, "", fmt.Errorf("capability %s lacks session tool metadata", capabilityName)
			}
			for _, tool := range describer.Describe().Tools {
				toolOwners[tool.Name] = capabilityName
			}
		}
	}
	return composeIdentityPolicies(principal.PolicyMatches, h.toolPolicies, toolOwners)
}

func composeIdentityPolicies(matches []auth.PolicyMatch, toolPolicies map[string]config.ToolPolicy, toolOwners map[string]string) (config.Client, config.ToolPolicy, string, error) {
	if len(matches) == 0 {
		return config.Client{}, config.ToolPolicy{}, "", auth.ErrPolicyDenied
	}
	matches = append([]auth.PolicyMatch{}, matches...)
	sort.Slice(matches, func(i, j int) bool { return matches[i].Name < matches[j].Name })
	profile := matches[0].Policy.Profile
	policy := config.Client{Profile: profile}
	toolPolicy := config.ToolPolicy{Profile: profile, Capabilities: map[string]string{}, Tools: map[string]string{}, ToolLimits: map[string]config.CallLimits{}}
	type component struct {
		Name              string `json:"name"`
		Version           string `json:"version"`
		ToolPolicy        string `json:"tool_policy"`
		ToolPolicyVersion string `json:"tool_policy_version"`
	}
	components := make([]component, 0, len(matches))
	initialAll := false
	initial := map[string]bool{}
	for _, match := range matches {
		if match.Policy.Profile != profile {
			return config.Client{}, config.ToolPolicy{}, "", fmt.Errorf("%w: composed policies reference different profiles", auth.ErrAmbiguousPolicy)
		}
		part, ok := toolPolicies[match.Policy.ToolPolicy]
		if !ok || part.Version == "" || part.Profile != profile {
			return config.Client{}, config.ToolPolicy{}, "", fmt.Errorf("%w: composed policy has an invalid tool policy", auth.ErrPolicyDenied)
		}
		components = append(components, component{Name: match.Name, Version: match.Policy.Version, ToolPolicy: match.Policy.ToolPolicy, ToolPolicyVersion: part.Version})
		policy.IdentityPolicyComponents = append(policy.IdentityPolicyComponents, match.Name)
		policy.Discover = policy.Discover || match.Policy.Discover
		policy.Execute = policy.Execute || match.Policy.Execute
		policy.Activate = policy.Activate || match.Policy.Activate
		policy.Limits = mergeCallLimits(policy.Limits, match.Policy.Limits)
		if match.Policy.InitialCapabilities == nil {
			initialAll = true
		} else {
			for _, name := range match.Policy.InitialCapabilities {
				initial[name] = true
			}
		}
		for name, decision := range part.Capabilities {
			toolPolicy.Capabilities[name] = saferDecision(toolPolicy.Capabilities[name], decision)
		}
		for name, decision := range part.Tools {
			toolPolicy.Tools[name] = saferDecision(toolPolicy.Tools[name], decision)
		}
		for name, limits := range part.ToolLimits {
			existing, exists := toolPolicy.ToolLimits[name]
			if !exists {
				toolPolicy.ToolLimits[name] = limits
				continue
			}
			toolPolicy.ToolLimits[name] = *mergeCallLimits(&existing, &limits)
		}
	}
	if !initialAll {
		for name := range initial {
			policy.InitialCapabilities = append(policy.InitialCapabilities, name)
		}
		sort.Strings(policy.InitialCapabilities)
	}
	for tool, capabilityName := range toolOwners {
		if decision := saferDecision(toolPolicy.Tools[tool], toolPolicy.Capabilities[capabilityName]); decision != "" {
			toolPolicy.Tools[tool] = decision
		}
	}
	if policy.InitialCapabilities != nil {
		visibleCapabilities := map[string]bool{}
		for tool, capabilityName := range toolOwners {
			if toolPolicy.Tools[tool] == "allow" {
				visibleCapabilities[capabilityName] = true
			}
		}
		filtered := policy.InitialCapabilities[:0]
		for _, capabilityName := range policy.InitialCapabilities {
			if visibleCapabilities[capabilityName] {
				filtered = append(filtered, capabilityName)
			}
		}
		policy.InitialCapabilities = filtered
	}
	for name := range toolPolicy.ToolLimits {
		if toolPolicy.Tools[name] != "allow" {
			delete(toolPolicy.ToolLimits, name)
		}
	}
	canonical, err := json.Marshal(struct {
		Components []component       `json:"components"`
		Policy     config.Client     `json:"policy"`
		ToolPolicy config.ToolPolicy `json:"tool_policy"`
	}{components, policy, toolPolicy})
	if err != nil {
		return config.Client{}, config.ToolPolicy{}, "", err
	}
	digest := sha256.Sum256(canonical)
	hash := fmt.Sprintf("%x", digest[:])
	name := "composed:" + hash[:16]
	version := "sha256:" + hash
	policy.ToolPolicy = name
	policy.IdentityPolicyVersion = version
	toolPolicy.Version = version
	return policy, toolPolicy, name, nil
}

func saferDecision(current, next string) string {
	priority := map[string]int{"": 0, "allow": 1, "require_approval": 2, "deny": 3}
	if priority[next] > priority[current] {
		return next
	}
	return current
}

func mergeCallLimits(current, next *config.CallLimits) *config.CallLimits {
	if current == nil && next == nil {
		return nil
	}
	if current == nil {
		copy := *next
		return &copy
	}
	if next == nil {
		copy := *current
		return &copy
	}
	return &config.CallLimits{
		RequestsPerMinute: minPositive(current.RequestsPerMinute, next.RequestsPerMinute),
		Burst:             minPositive(current.Burst, next.Burst),
		Concurrency:       minPositive(current.Concurrency, next.Concurrency),
	}
}

func minPositive(a, b int) int {
	if a == 0 {
		return b
	}
	if b == 0 || a < b {
		return a
	}
	return b
}

// identityControllerFor is called with h.mu held. It keeps identity limits shared
// across concurrent sessions while bounding retained identities to session_limit.
func (h *Handler) identityControllerFor(key string, policy config.Client, toolPolicy config.ToolPolicy, now time.Time) *gateway.CallController {
	if existing, ok := h.controllers[key]; ok {
		existing.lastSeen = now
		h.controllers[key] = existing
		return existing.controller
	}
	if len(h.controllers) >= h.limit {
		active := map[string]bool{}
		for _, record := range h.entries {
			active[record.controllerKey] = true
		}
		oldestKey := ""
		var oldest time.Time
		for candidate, existing := range h.controllers {
			if active[candidate] || oldestKey != "" && !existing.lastSeen.Before(oldest) {
				continue
			}
			oldestKey, oldest = candidate, existing.lastSeen
		}
		if oldestKey != "" {
			delete(h.controllers, oldestKey)
		}
	}
	controller := gateway.NewCallController(policy, toolPolicy)
	h.controllers[key] = identityController{controller: controller, lastSeen: now}
	return controller
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	client, authErr := h.authenticate(r)
	if authErr != nil {
		if errors.Is(authErr, auth.ErrInsufficientScope) || errors.Is(authErr, auth.ErrPolicyDenied) || errors.Is(authErr, auth.ErrAmbiguousPolicy) {
			h.metrics.AuthorizationFailure()
		} else {
			h.metrics.AuthenticationFailure()
		}
		if h.authenticator != nil {
			h.authenticator.WriteError(w, authErr)
		} else {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
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
		if record == nil || record.owner != client.name || record.binding != client.binding || h.closed {
			h.mu.Unlock()
			http.Error(w, "session not found", 404)
			return
		}
		record.lastSeen = now
		if record.controllerKey != "" {
			controller := h.controllers[record.controllerKey]
			controller.lastSeen = now
			h.controllers[record.controllerKey] = controller
		}
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
		h.metrics.SessionCapacityFailure()
		h.mu.Unlock()
		http.Error(w, "session capacity reached", 503)
		return
	}
	id = rand.Text()
	var allowed []capability.Capability
	for _, name := range h.profiles[client.policy.Profile] {
		allowed = append(allowed, h.capabilities[name])
	}
	controller := client.controller
	controllerKey := ""
	if !strings.HasPrefix(client.binding, "static:") {
		controllerKey = client.name + "\x00" + client.binding
		controller = h.identityControllerFor(controllerKey, client.policy, client.toolPolicy, now)
	}
	server, err := gateway.NewSession(h.version, id, client.name, client.policy, client.toolPolicy, controller, h.metrics, allowed)
	if err != nil {
		h.mu.Unlock()
		http.Error(w, "session configuration error", 500)
		return
	}
	record := &entry{owner: client.name, binding: client.binding, controllerKey: controllerKey, server: server, lastSeen: now, created: now, pending: true}
	h.entries[id] = record
	h.metrics.SessionOpened()
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
		h.metrics.SessionClosed()
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
			h.metrics.SessionClosed()
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
	for range entries {
		h.metrics.SessionClosed()
	}
	h.mu.Unlock()
	for _, record := range entries {
		closeEntry(record)
	}
}
