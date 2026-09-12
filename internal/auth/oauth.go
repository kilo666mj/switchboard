// Package auth validates external identities for the HTTP MCP resource.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/egress"
	"golang.org/x/oauth2"
)

const (
	maxAccessTokenBytes = 16 << 10
	maxProviderResponse = 1 << 20
)

var (
	ErrMissingToken      = errors.New("OAuth access token is required")
	ErrInvalidToken      = errors.New("invalid OAuth access token")
	ErrInsufficientScope = errors.New("OAuth access token has insufficient scope")
	ErrPolicyDenied      = errors.New("OAuth identity is not mapped to a policy")
	ErrAmbiguousPolicy   = errors.New("OAuth identity maps to multiple policies")
)

type ScopeError struct{ Scopes []string }

func (e *ScopeError) Error() string { return ErrInsufficientScope.Error() }
func (e *ScopeError) Unwrap() error { return ErrInsufficientScope }

type verifiedToken struct {
	Subject string
	JWTType string
	Claims  map[string]json.RawMessage
}

type tokenVerifier interface {
	Verify(context.Context, string) (verifiedToken, error)
}

type groupResolver interface {
	Resolve(context.Context, string) (string, json.RawMessage, error)
}

type oidcVerifier struct {
	client   *http.Client
	verifier *oidc.IDTokenVerifier
}

func (v oidcVerifier) Verify(ctx context.Context, raw string) (verifiedToken, error) {
	token, err := v.verifier.Verify(oidc.ClientContext(ctx, v.client), raw)
	if err != nil {
		return verifiedToken{}, err
	}
	claims := map[string]json.RawMessage{}
	if err := token.Claims(&claims); err != nil {
		return verifiedToken{}, err
	}
	// Inspect the protected header only after verifying this exact compact JWS.
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return verifiedToken{}, ErrInvalidToken
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return verifiedToken{}, err
	}
	var protected struct {
		Type string `json:"typ"`
	}
	if err := json.Unmarshal(header, &protected); err != nil {
		return verifiedToken{}, err
	}
	return verifiedToken{Subject: token.Subject, JWTType: protected.Type, Claims: claims}, nil
}

type oidcUserInfoGroupResolver struct {
	provider *oidc.Provider
	client   *http.Client
	claim    string
}

func (r oidcUserInfoGroupResolver) Resolve(ctx context.Context, accessToken string) (string, json.RawMessage, error) {
	userInfo, err := r.provider.UserInfo(
		oidc.ClientContext(ctx, r.client),
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken, TokenType: "Bearer"}),
	)
	if err != nil {
		return "", nil, err
	}
	claims := map[string]json.RawMessage{}
	if err := userInfo.Claims(&claims); err != nil {
		return "", nil, err
	}
	return userInfo.Subject, claims[r.claim], nil
}

type Principal struct {
	Identity      string
	Source        string
	PolicyName    string
	Policy        config.Client
	PolicyMatches []PolicyMatch
	Composed      bool
}

type PolicyMatch struct {
	Name   string
	Policy config.OAuthPolicy
}

type Authenticator struct {
	cfg         config.OAuthConfig
	verifier    tokenVerifier
	groups      groupResolver
	metadataURL string
	metadata    []byte
}

func New(ctx context.Context, cfg config.OAuthConfig, policy *egress.Policy) (*Authenticator, error) {
	var transport http.RoundTripper = http.DefaultTransport.(*http.Transport).Clone()
	if policy != nil {
		transport = policy.Transport()
	}
	return newWithTransport(ctx, cfg, policy, transport)
}

func newWithTransport(ctx context.Context, cfg config.OAuthConfig, policy *egress.Policy, transport http.RoundTripper) (*Authenticator, error) {
	if err := validateIssuerURL(cfg.Issuer); err != nil {
		return nil, fmt.Errorf("OAuth issuer: %w", err)
	}
	if err := validateResourceURL(cfg.Resource); err != nil {
		return nil, fmt.Errorf("OAuth resource: %w", err)
	}
	if policy != nil {
		if err := policy.ValidateURL(cfg.Issuer); err != nil {
			return nil, fmt.Errorf("OAuth issuer violates egress policy: %w", err)
		}
	}
	client := &http.Client{
		Transport:     boundedTransport{base: transport},
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OAuth issuer: %w", err)
	}
	var metadata struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("decode OAuth issuer metadata: %w", err)
	}
	if err := validateProviderURL(metadata.JWKSURI, policy); err != nil {
		return nil, fmt.Errorf("OAuth JWKS URI: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.Resource})
	authenticator, err := newAuthenticator(cfg, oidcVerifier{client: client, verifier: verifier})
	if err != nil {
		return nil, err
	}
	if cfg.GroupSource == config.OAuthGroupSourceUserInfo {
		if err := validateProviderURL(provider.UserInfoEndpoint(), policy); err != nil {
			return nil, fmt.Errorf("OAuth UserInfo endpoint: %w", err)
		}
		authenticator.groups = oidcUserInfoGroupResolver{
			provider: provider,
			client:   client,
			claim:    claimName(cfg.GroupClaim, "groups"),
		}
	}
	return authenticator, nil
}

func validateIssuerURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || strings.TrimSpace(raw) != raw || parsed.String() != raw || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return errors.New("must be an HTTPS URL without user information, query, or fragment")
	}
	return nil
}

func validateResourceURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || strings.TrimSpace(raw) != raw || parsed.String() != raw || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path == "" || parsed.Path == "/" || strings.HasSuffix(parsed.Path, "/") {
		return errors.New("must be a canonical HTTPS MCP endpoint without a trailing slash")
	}
	return nil
}

type boundedTransport struct{ base http.RoundTripper }

func (t boundedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.Body = &boundedBody{ReadCloser: response.Body, remaining: maxProviderResponse}
	return response, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(p)
	if int64(n) > b.remaining {
		return 0, fmt.Errorf("OAuth provider response exceeds %d bytes", maxProviderResponse)
	}
	b.remaining -= int64(n)
	return n, err
}

func validateProviderURL(raw string, policy *egress.Policy) error {
	parsed, err := url.Parse(raw)
	if err != nil || strings.TrimSpace(raw) != raw || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("must be an HTTPS URL without user information")
	}
	if policy != nil {
		return policy.ValidateURL(raw)
	}
	return nil
}

func newAuthenticator(cfg config.OAuthConfig, verifier tokenVerifier) (*Authenticator, error) {
	resource, err := url.Parse(cfg.Resource)
	if err != nil {
		return nil, err
	}
	metadataPath := "/.well-known/oauth-protected-resource" + resource.Path
	metadataURL := (&url.URL{Scheme: resource.Scheme, Host: resource.Host, Path: metadataPath}).String()
	scopes := allScopes(cfg)
	document := struct {
		Resource               string   `json:"resource"`
		AuthorizationServers   []string `json:"authorization_servers"`
		ScopesSupported        []string `json:"scopes_supported"`
		BearerMethodsSupported []string `json:"bearer_methods_supported"`
		ResourceName           string   `json:"resource_name"`
	}{cfg.Resource, []string{cfg.Issuer}, scopes, []string{"header"}, "Switchboard MCP"}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return &Authenticator{cfg: cfg, verifier: verifier, metadataURL: metadataURL, metadata: encoded}, nil
}

func allScopes(cfg config.OAuthConfig) []string {
	seen := map[string]bool{}
	for _, scope := range cfg.RequiredScopes {
		seen[scope] = true
	}
	for _, policy := range cfg.Policies {
		for _, scope := range policy.RequiredScopes {
			seen[scope] = true
		}
	}
	result := make([]string, 0, len(seen))
	for scope := range seen {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}

func (a *Authenticator) Authenticate(r *http.Request) (Principal, error) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return Principal{}, ErrMissingToken
	}
	if len(values) != 1 {
		return Principal{}, ErrInvalidToken
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > maxAccessTokenBytes {
		return Principal{}, ErrInvalidToken
	}
	verified, err := a.verifier.Verify(r.Context(), parts[1])
	if err != nil || !safeIdentity(verified.Subject) {
		return Principal{}, ErrInvalidToken
	}
	if a.cfg.JWTType != "" && verified.JWTType != a.cfg.JWTType {
		return Principal{}, ErrInvalidToken
	}
	if a.cfg.TokenTypeClaim != "" {
		var tokenType string
		if json.Unmarshal(verified.Claims[a.cfg.TokenTypeClaim], &tokenType) != nil || tokenType != a.cfg.TokenTypeValue {
			return Principal{}, ErrInvalidToken
		}
	}
	scopes, err := stringSetClaim(verified.Claims[claimName(a.cfg.ScopeClaim, "scope")], true)
	if err != nil || !containsAll(scopes, a.cfg.RequiredScopes) {
		slog.InfoContext(r.Context(), "oauth_authorization", "identity", verified.Subject, "outcome", "insufficient_scope")
		return Principal{}, &ScopeError{Scopes: append([]string{}, a.cfg.RequiredScopes...)}
	}
	groupClaim := verified.Claims[claimName(a.cfg.GroupClaim, "groups")]
	if a.cfg.GroupSource == config.OAuthGroupSourceUserInfo {
		if a.groups == nil {
			return Principal{}, ErrInvalidToken
		}
		userInfoSubject, resolved, resolveErr := a.groups.Resolve(r.Context(), parts[1])
		if resolveErr != nil || userInfoSubject != verified.Subject || !safeIdentity(userInfoSubject) {
			slog.InfoContext(r.Context(), "oauth_authorization", "identity", verified.Subject, "outcome", "userinfo_failed")
			return Principal{}, ErrInvalidToken
		}
		groupClaim = resolved
	}
	groups, err := stringSetClaim(groupClaim, false)
	if err != nil {
		slog.InfoContext(r.Context(), "oauth_authorization", "identity", verified.Subject, "outcome", "invalid_claim")
		return Principal{}, ErrInvalidToken
	}
	var matches []PolicyMatch
	missingScopes := map[string]bool{}
	for name, policy := range a.cfg.Policies {
		if !matchesPolicy(verified.Subject, groups, policy) {
			continue
		}
		if !containsAll(scopes, policy.RequiredScopes) {
			for _, scope := range a.cfg.RequiredScopes {
				missingScopes[scope] = true
			}
			for _, scope := range policy.RequiredScopes {
				missingScopes[scope] = true
			}
			continue
		}
		matches = append(matches, PolicyMatch{Name: name, Policy: policy})
	}
	if len(matches) == 0 {
		if len(missingScopes) > 0 {
			required := make([]string, 0, len(missingScopes))
			for scope := range missingScopes {
				required = append(required, scope)
			}
			sort.Strings(required)
			slog.InfoContext(r.Context(), "oauth_authorization", "identity", verified.Subject, "outcome", "insufficient_scope")
			return Principal{}, &ScopeError{Scopes: required}
		}
		slog.InfoContext(r.Context(), "oauth_authorization", "identity", verified.Subject, "outcome", "policy_denied")
		return Principal{}, ErrPolicyDenied
	}
	if a.cfg.PolicyMode != config.IdentityPolicyModeComposed && len(matches) != 1 {
		slog.InfoContext(r.Context(), "oauth_authorization", "identity", verified.Subject, "outcome", "ambiguous_policy")
		return Principal{}, ErrAmbiguousPolicy
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Name < matches[j].Name })
	return Principal{
		Identity: verified.Subject, Source: "oauth", PolicyName: matches[0].Name,
		Policy: matches[0].Policy.Client(), PolicyMatches: matches,
		Composed: a.cfg.PolicyMode == config.IdentityPolicyModeComposed,
	}, nil
}

func matchesPolicy(subject string, groups map[string]bool, policy config.OAuthPolicy) bool {
	if len(policy.Subjects) > 0 && !sliceContains(policy.Subjects, subject) {
		return false
	}
	if len(policy.Groups) > 0 {
		matched := false
		for _, group := range policy.Groups {
			if groups[group] {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return len(policy.Subjects) > 0 || len(policy.Groups) > 0
}

func stringSetClaim(raw json.RawMessage, allowSpaceDelimited bool) (map[string]bool, error) {
	result := map[string]bool{}
	if len(raw) == 0 || string(raw) == "null" {
		return result, nil
	}
	var values []string
	if raw[0] == '"' {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		if allowSpaceDelimited {
			values = strings.Fields(value)
		} else if value != "" {
			values = []string{value}
		}
	} else if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}
	if len(values) > 256 {
		return nil, errors.New("claim contains too many values")
	}
	for _, value := range values {
		if !safeClaimValue(value) {
			return nil, errors.New("claim contains an invalid value")
		}
		result[value] = true
	}
	return result, nil
}

func safeIdentity(value string) bool {
	return value != "" && len(value) <= 512 && safeClaimValue(value)
}

func safeClaimValue(value string) bool {
	if value == "" || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func containsAll(values map[string]bool, required []string) bool {
	for _, value := range required {
		if !values[value] {
			return false
		}
	}
	return true
}

func sliceContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func claimName(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (a *Authenticator) MetadataPath() string {
	parsed, _ := url.Parse(a.metadataURL)
	return parsed.Path
}

func (a *Authenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(a.metadata)
}

func (a *Authenticator) WriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrPolicyDenied) || errors.Is(err, ErrAmbiguousPolicy) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	status := http.StatusUnauthorized
	code := ""
	if !errors.Is(err, ErrMissingToken) {
		code = "invalid_token"
	}
	if errors.Is(err, ErrInsufficientScope) {
		status = http.StatusForbidden
		code = "insufficient_scope"
	}
	challenge := "Bearer resource_metadata=" + strconv.Quote(a.metadataURL)
	if code != "" {
		challenge += ", error=" + strconv.Quote(code)
	}
	requiredScopes := a.cfg.RequiredScopes
	var scopeError *ScopeError
	if errors.As(err, &scopeError) {
		requiredScopes = scopeError.Scopes
	}
	if scopes := strings.Join(requiredScopes, " "); scopes != "" {
		challenge += ", scope=" + strconv.Quote(scopes)
	}
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, http.StatusText(status), status)
}
