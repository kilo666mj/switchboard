package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type Config struct {
	Clients             map[string]Client       `json:"clients,omitempty"`
	ToolPolicies        map[string]ToolPolicy   `json:"tool_policies,omitempty"`
	EgressPolicy        *EgressPolicy           `json:"egress_policy,omitempty"`
	OAuth               *OAuthConfig            `json:"oauth,omitempty"`
	CloudflareAccess    *CloudflareAccessConfig `json:"cloudflare_access,omitempty"`
	SessionLimit        int                     `json:"session_limit,omitempty"`
	SessionIdleSeconds  int                     `json:"session_idle_seconds,omitempty"`
	Listen              string                  `json:"listen"`
	Transport           string                  `json:"transport"`
	Profile             string                  `json:"profile"`
	CapabilityDir       string                  `json:"capability_dir"`
	Profiles            map[string][]string     `json:"profiles"`
	TrustedOrigins      []string                `json:"trusted_origins,omitempty"`
	BehindLoopbackProxy bool                    `json:"behind_loopback_proxy,omitempty"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8090"
	}
	if cfg.Transport == "" {
		cfg.Transport = "http"
	}
	if cfg.CapabilityDir == "" {
		cfg.CapabilityDir = "capabilities"
	}
	if !filepath.IsAbs(cfg.CapabilityDir) {
		cfg.CapabilityDir = filepath.Join(filepath.Dir(path), cfg.CapabilityDir)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Transport != "http" && c.Transport != "stdio" {
		return fmt.Errorf("transport must be http or stdio, got %q", c.Transport)
	}
	if strings.TrimSpace(c.Profile) == "" {
		return errors.New("profile is required")
	}
	_, ok := c.Profiles[c.Profile]
	if !ok {
		return fmt.Errorf("profile %q is not defined", c.Profile)
	}
	for profile, selected := range c.Profiles {
		seen := make(map[string]bool, len(selected))
		for _, name := range selected {
			if name == "" {
				return fmt.Errorf("profile %q contains an empty capability name", profile)
			}
			if seen[name] {
				return fmt.Errorf("profile %q contains duplicate capability %q", profile, name)
			}
			seen[name] = true
		}
	}
	if len(c.Clients) > 0 && c.Transport != "http" {
		return errors.New("client identities require HTTP transport")
	}
	if c.SessionLimit < 0 || c.SessionLimit > 4096 {
		return errors.New("session_limit must be between 0 and 4096")
	}
	if c.SessionIdleSeconds < 0 || c.SessionIdleSeconds > 86400 {
		return errors.New("session_idle_seconds must be between 0 and 86400")
	}
	for name, client := range c.Clients {
		if strings.TrimSpace(name) == "" || client.TokenEnv == "" {
			return errors.New("client name and token_env are required")
		}
		allowed, ok := c.Profiles[client.Profile]
		if !ok {
			return fmt.Errorf("client %q references undefined profile", name)
		}
		if client.ToolPolicy != "" {
			policy, ok := c.ToolPolicies[client.ToolPolicy]
			if !ok {
				return fmt.Errorf("client %q references undefined tool policy %q", name, client.ToolPolicy)
			}
			if policy.Profile != client.Profile {
				return fmt.Errorf("client %q profile %q does not match tool policy %q profile %q", name, client.Profile, client.ToolPolicy, policy.Profile)
			}
		}
		if err := validateCallLimits(client.Limits); err != nil {
			return fmt.Errorf("client %q limits: %w", name, err)
		}
		seen := map[string]bool{}
		for _, n := range allowed {
			seen[n] = true
		}
		defaults := map[string]bool{}
		for _, n := range client.InitialCapabilities {
			if !seen[n] || defaults[n] {
				return fmt.Errorf("client %q has invalid initial capability %q", name, n)
			}
			defaults[n] = true
		}
	}
	for name, policy := range c.ToolPolicies {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(policy.Version) == "" {
			return errors.New("tool policy name and version are required")
		}
		if _, ok := c.Profiles[policy.Profile]; !ok {
			return fmt.Errorf("tool policy %q references undefined profile %q", name, policy.Profile)
		}
		profileCapabilities := make(map[string]bool, len(c.Profiles[policy.Profile]))
		for _, capabilityName := range c.Profiles[policy.Profile] {
			profileCapabilities[capabilityName] = true
		}
		for capabilityName, decision := range policy.Capabilities {
			if strings.TrimSpace(capabilityName) == "" || !profileCapabilities[capabilityName] {
				return fmt.Errorf("tool policy %q references unavailable capability %q", name, capabilityName)
			}
			if !validPolicyDecision(decision) {
				return fmt.Errorf("tool policy %q has invalid decision %q for capability %q", name, decision, capabilityName)
			}
		}
		for tool, decision := range policy.Tools {
			if strings.TrimSpace(tool) == "" {
				return fmt.Errorf("tool policy %q contains an empty tool name", name)
			}
			if !validPolicyDecision(decision) {
				return fmt.Errorf("tool policy %q has invalid decision %q for tool %q", name, decision, tool)
			}
		}
		for tool, limits := range policy.ToolLimits {
			if policy.Tools[tool] != "allow" {
				return fmt.Errorf("tool policy %q limits require an explicit allow decision for tool %q", name, tool)
			}
			if err := validateCallLimits(&limits); err != nil {
				return fmt.Errorf("tool policy %q tool %q limits: %w", name, tool, err)
			}
		}
	}
	if c.OAuth != nil {
		if c.Transport != "http" {
			return errors.New("OAuth authentication requires HTTP transport")
		}
		if err := validateHTTPSIdentifier(c.OAuth.Issuer, "OAuth issuer", false); err != nil {
			return err
		}
		if err := validateHTTPSIdentifier(c.OAuth.Resource, "OAuth resource", true); err != nil {
			return err
		}
		if len(c.OAuth.RequiredScopes) == 0 {
			return errors.New("OAuth required_scopes must not be empty")
		}
		if err := validateScopes(c.OAuth.RequiredScopes); err != nil {
			return fmt.Errorf("OAuth required_scopes: %w", err)
		}
		if claim := oauthClaimName(c.OAuth.GroupClaim, "groups"); !validClaimName(claim) {
			return errors.New("OAuth group_claim is invalid")
		}
		if c.OAuth.GroupSource != "" && c.OAuth.GroupSource != OAuthGroupSourceAccessToken && c.OAuth.GroupSource != OAuthGroupSourceUserInfo {
			return fmt.Errorf("OAuth group_source must be %q or %q", OAuthGroupSourceAccessToken, OAuthGroupSourceUserInfo)
		}
		if c.OAuth.GroupSource == OAuthGroupSourceUserInfo && !slices.Contains(c.OAuth.RequiredScopes, "openid") {
			return errors.New("OAuth group_source userinfo requires openid in required_scopes")
		}
		if claim := oauthClaimName(c.OAuth.ScopeClaim, "scope"); !validClaimName(claim) {
			return errors.New("OAuth scope_claim is invalid")
		}
		if c.OAuth.JWTType != "" {
			if err := validateMatcherValues([]string{c.OAuth.JWTType}); err != nil {
				return errors.New("OAuth jwt_type is invalid")
			}
		}
		if (c.OAuth.TokenTypeClaim == "") != (c.OAuth.TokenTypeValue == "") {
			return errors.New("OAuth token_type_claim and token_type_value must be configured together")
		}
		if c.OAuth.TokenTypeClaim != "" {
			if !validClaimName(c.OAuth.TokenTypeClaim) {
				return errors.New("OAuth token_type_claim is invalid")
			}
			if err := validateMatcherValues([]string{c.OAuth.TokenTypeValue}); err != nil {
				return errors.New("OAuth token_type_value is invalid")
			}
		}
		if len(c.OAuth.Policies) == 0 {
			return errors.New("OAuth policies must not be empty")
		}
		for name, policy := range c.OAuth.Policies {
			if err := c.validateIdentityPolicy("OAuth", name, policy, true); err != nil {
				return err
			}
		}
		if err := validateIdentityPolicyMode("OAuth", c.OAuth.PolicyMode, c.OAuth.Policies); err != nil {
			return err
		}
		if err := validateStaticClientSelection("OAuth", c.OAuth.AllowStaticClients, c.OAuth.StaticClientAllowlist, c.Clients); err != nil {
			return err
		}
	}
	if c.CloudflareAccess != nil {
		if c.Transport != "http" {
			return errors.New("Cloudflare Access authentication requires HTTP transport")
		}
		if err := validateHTTPSIdentifier(c.CloudflareAccess.TeamDomain, "Cloudflare Access team_domain", false); err != nil {
			return err
		}
		teamDomain, _ := url.Parse(c.CloudflareAccess.TeamDomain)
		if teamDomain.Path != "" {
			return errors.New("Cloudflare Access team_domain must not contain a path")
		}
		if err := validateMatcherValues([]string{c.CloudflareAccess.Audience}); err != nil {
			return errors.New("Cloudflare Access audience is invalid")
		}
		if len(c.CloudflareAccess.Policies) == 0 {
			return errors.New("Cloudflare Access policies must not be empty")
		}
		for name, policy := range c.CloudflareAccess.Policies {
			if err := c.validateIdentityPolicy("Cloudflare Access", name, policy, false); err != nil {
				return err
			}
		}
		if err := validateIdentityPolicyMode("Cloudflare Access", c.CloudflareAccess.PolicyMode, c.CloudflareAccess.Policies); err != nil {
			return err
		}
		if err := validateStaticClientSelection("Cloudflare Access", c.CloudflareAccess.AllowStaticClients, c.CloudflareAccess.StaticClientAllowlist, c.Clients); err != nil {
			return err
		}
	}
	return nil
}

func validateIdentityPolicyMode(provider, mode string, policies map[string]OAuthPolicy) error {
	if mode == "" || mode == IdentityPolicyModeExclusive {
		return nil
	}
	if mode != IdentityPolicyModeComposed {
		return fmt.Errorf("%s policy_mode must be %q or %q", provider, IdentityPolicyModeExclusive, IdentityPolicyModeComposed)
	}
	profile := ""
	for name, policy := range policies {
		if policy.ToolPolicy == "" {
			return fmt.Errorf("%s composed policy %q requires an explicit tool_policy", provider, name)
		}
		if profile == "" {
			profile = policy.Profile
		} else if policy.Profile != profile {
			return fmt.Errorf("%s composed policies must reference one shared profile", provider)
		}
	}
	return nil
}

func validateStaticClientSelection(provider string, allowAll bool, allowlist []string, clients map[string]Client) error {
	if allowAll && len(allowlist) > 0 {
		return fmt.Errorf("%s allow_static_clients and static_client_allowlist are mutually exclusive", provider)
	}
	seen := map[string]bool{}
	for _, name := range allowlist {
		if strings.TrimSpace(name) != name || name == "" {
			return fmt.Errorf("%s static_client_allowlist contains an invalid client name", provider)
		}
		if seen[name] {
			return fmt.Errorf("%s static_client_allowlist contains duplicate client %q", provider, name)
		}
		if _, ok := clients[name]; !ok {
			return fmt.Errorf("%s static_client_allowlist references unknown client %q", provider, name)
		}
		seen[name] = true
	}
	return nil
}

func validPolicyDecision(decision string) bool {
	return decision == "allow" || decision == "deny" || decision == "require_approval"
}

func (c Config) StaticClientEnabled(name string) bool {
	enabled := true
	if c.OAuth != nil {
		enabled = enabled && (c.OAuth.AllowStaticClients || contains(c.OAuth.StaticClientAllowlist, name))
	}
	if c.CloudflareAccess != nil {
		enabled = enabled && (c.CloudflareAccess.AllowStaticClients || contains(c.CloudflareAccess.StaticClientAllowlist, name))
	}
	return enabled
}

func (c Config) AnyStaticClientsEnabled() bool {
	for name := range c.Clients {
		if c.StaticClientEnabled(name) {
			return true
		}
	}
	return false
}

func (c Config) validateIdentityPolicy(provider, name string, policy OAuthPolicy, allowScopes bool) error {
	if err := validateMatcherValues([]string{name}); err != nil {
		return fmt.Errorf("%s policy name is invalid", provider)
	}
	if len(policy.Subjects) == 0 && len(policy.Groups) == 0 {
		return fmt.Errorf("%s policy %q requires subjects or groups", provider, name)
	}
	if err := validateMatcherValues([]string{policy.Version}); err != nil {
		return fmt.Errorf("%s policy %q version is invalid", provider, name)
	}
	if err := validateMatcherValues(policy.Subjects); err != nil {
		return fmt.Errorf("%s policy %q subjects: %w", provider, name, err)
	}
	if err := validateMatcherValues(policy.Groups); err != nil {
		return fmt.Errorf("%s policy %q groups: %w", provider, name, err)
	}
	if _, ok := c.Profiles[policy.Profile]; !ok {
		return fmt.Errorf("%s policy %q references undefined profile %q", provider, name, policy.Profile)
	}
	if policy.ToolPolicy != "" {
		toolPolicy, ok := c.ToolPolicies[policy.ToolPolicy]
		if !ok {
			return fmt.Errorf("%s policy %q references undefined tool policy %q", provider, name, policy.ToolPolicy)
		}
		if toolPolicy.Profile != policy.Profile {
			return fmt.Errorf("%s policy %q profile %q does not match tool policy %q profile %q", provider, name, policy.Profile, policy.ToolPolicy, toolPolicy.Profile)
		}
	}
	if err := validateCallLimits(policy.Limits); err != nil {
		return fmt.Errorf("%s policy %q limits: %w", provider, name, err)
	}
	if !allowScopes && len(policy.RequiredScopes) > 0 {
		return fmt.Errorf("%s policy %q must not require OAuth scopes", provider, name)
	}
	if allowScopes {
		if err := validateScopes(policy.RequiredScopes); err != nil {
			return fmt.Errorf("%s policy %q required_scopes: %w", provider, name, err)
		}
	}
	seenCapabilities := map[string]bool{}
	for _, capability := range policy.InitialCapabilities {
		if !contains(c.Profiles[policy.Profile], capability) || seenCapabilities[capability] {
			return fmt.Errorf("%s policy %q has invalid initial capability %q", provider, name, capability)
		}
		seenCapabilities[capability] = true
	}
	return nil
}

func validateHTTPSIdentifier(raw, name string, requirePath bool) error {
	if strings.TrimSpace(raw) != raw {
		return fmt.Errorf("%s must not contain surrounding whitespace", name)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.String() != raw || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return fmt.Errorf("%s must be an HTTPS URL without user information, query, or fragment", name)
	}
	if requirePath && (parsed.Path == "" || parsed.Path == "/") {
		return fmt.Errorf("%s must identify the MCP endpoint path", name)
	}
	if requirePath && strings.HasSuffix(parsed.Path, "/") {
		return fmt.Errorf("%s must not have a trailing slash", name)
	}
	return nil
}

func validateScopes(scopes []string) error {
	seen := map[string]bool{}
	for _, scope := range scopes {
		if !validScope(scope) {
			return fmt.Errorf("invalid scope %q", scope)
		}
		if seen[scope] {
			return fmt.Errorf("duplicate scope %q", scope)
		}
		seen[scope] = true
	}
	return nil
}

func validScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, b := range []byte(scope) {
		if b != 0x21 && (b < 0x23 || b > 0x5b) && (b < 0x5d || b > 0x7e) {
			return false
		}
	}
	return true
}

func validClaimName(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validateMatcherValues(values []string) error {
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || len(value) > 512 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("invalid value %q", value)
		}
		if seen[value] {
			return fmt.Errorf("duplicate value %q", value)
		}
		seen[value] = true
	}
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func oauthClaimName(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// Client policy is supplied by the operator, never by tool arguments.
type Client struct {
	TokenEnv                 string      `json:"token_env"`
	Profile                  string      `json:"profile"`
	InitialCapabilities      []string    `json:"initial_capabilities"`
	Discover                 bool        `json:"discover"`
	Execute                  bool        `json:"execute"`
	Activate                 bool        `json:"activate"`
	ToolPolicy               string      `json:"tool_policy,omitempty"`
	Limits                   *CallLimits `json:"limits,omitempty"`
	IdentityPolicy           string      `json:"-"`
	IdentityPolicyVersion    string      `json:"-"`
	IdentityPolicyComponents []string    `json:"-"`
}

// ToolPolicy authorizes whole capabilities with optional exact tool overrides.
// Missing entries default to deny.
type ToolPolicy struct {
	Version      string                `json:"version"`
	Profile      string                `json:"profile"`
	Capabilities map[string]string     `json:"capabilities,omitempty"`
	Tools        map[string]string     `json:"tools,omitempty"`
	ToolLimits   map[string]CallLimits `json:"tool_limits,omitempty"`
}

type CallLimits struct {
	RequestsPerMinute int `json:"requests_per_minute,omitempty"`
	Burst             int `json:"burst,omitempty"`
	Concurrency       int `json:"concurrency,omitempty"`
}

func validateCallLimits(limits *CallLimits) error {
	if limits == nil {
		return nil
	}
	if limits.RequestsPerMinute < 0 || limits.RequestsPerMinute > 1_000_000 {
		return errors.New("requests_per_minute must be between 0 and 1000000")
	}
	if limits.Burst < 0 || limits.Burst > 100_000 {
		return errors.New("burst must be between 0 and 100000")
	}
	if (limits.RequestsPerMinute == 0) != (limits.Burst == 0) {
		return errors.New("requests_per_minute and burst must both be zero or both be positive")
	}
	if limits.Concurrency < 0 || limits.Concurrency > 4096 {
		return errors.New("concurrency must be between 0 and 4096")
	}
	return nil
}

// EgressPolicy is opt-in. When present, every capability and OAuth token URL
// must use HTTPS, match an exact destination, and resolve only inside these CIDRs.
type EgressPolicy struct {
	AllowedDestinations []string `json:"allowed_destinations"`
	AllowedCIDRs        []string `json:"allowed_cidrs"`
}

// OAuthConfig describes an external authorization server. Switchboard remains
// the resource server and accepts only access tokens audience-bound to Resource.
type OAuthConfig struct {
	Issuer                string                 `json:"issuer"`
	Resource              string                 `json:"resource"`
	RequiredScopes        []string               `json:"required_scopes"`
	GroupClaim            string                 `json:"group_claim,omitempty"`
	GroupSource           string                 `json:"group_source,omitempty"`
	ScopeClaim            string                 `json:"scope_claim,omitempty"`
	JWTType               string                 `json:"jwt_type,omitempty"`
	TokenTypeClaim        string                 `json:"token_type_claim,omitempty"`
	TokenTypeValue        string                 `json:"token_type_value,omitempty"`
	AllowStaticClients    bool                   `json:"allow_static_clients,omitempty"`
	StaticClientAllowlist []string               `json:"static_client_allowlist,omitempty"`
	PolicyMode            string                 `json:"policy_mode,omitempty"`
	Policies              map[string]OAuthPolicy `json:"policies"`
}

const (
	OAuthGroupSourceAccessToken = "access_token"
	OAuthGroupSourceUserInfo    = "userinfo"
)

// CloudflareAccessConfig validates the assertion injected by Cloudflare Access
// at a trusted ingress. It shares the same identity policies as OAuth, without
// OAuth scopes because Access has already applied its edge policy.
type CloudflareAccessConfig struct {
	TeamDomain            string                 `json:"team_domain"`
	Audience              string                 `json:"audience"`
	AllowStaticClients    bool                   `json:"allow_static_clients,omitempty"`
	StaticClientAllowlist []string               `json:"static_client_allowlist,omitempty"`
	PolicyMode            string                 `json:"policy_mode,omitempty"`
	Policies              map[string]OAuthPolicy `json:"policies"`
}

const (
	IdentityPolicyModeExclusive = "exclusive"
	IdentityPolicyModeComposed  = "composed"
)

// OAuthPolicy maps verified subjects and groups to the same gateway controls
// used by a static client. Every configured matcher dimension must match.
type OAuthPolicy struct {
	Version             string      `json:"version"`
	Subjects            []string    `json:"subjects,omitempty"`
	Groups              []string    `json:"groups,omitempty"`
	RequiredScopes      []string    `json:"required_scopes,omitempty"`
	Profile             string      `json:"profile"`
	InitialCapabilities []string    `json:"initial_capabilities"`
	Discover            bool        `json:"discover"`
	Execute             bool        `json:"execute"`
	Activate            bool        `json:"activate"`
	ToolPolicy          string      `json:"tool_policy,omitempty"`
	Limits              *CallLimits `json:"limits,omitempty"`
}

func (p OAuthPolicy) Client() Client {
	return Client{
		Profile: p.Profile, InitialCapabilities: p.InitialCapabilities,
		Discover: p.Discover, Execute: p.Execute, Activate: p.Activate,
		ToolPolicy: p.ToolPolicy, Limits: p.Limits, IdentityPolicyVersion: p.Version,
	}
}
