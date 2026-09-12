package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/egress"
)

const CloudflareAccessJWTHeader = "Cf-Access-Jwt-Assertion"

var (
	ErrMissingAccessAssertion = errors.New("Cloudflare Access assertion is required")
	ErrInvalidAccessAssertion = errors.New("invalid Cloudflare Access assertion")
	ErrAmbiguousCredential    = errors.New("multiple authentication credentials supplied")
)

type CloudflareAccessAuthenticator struct {
	cfg      config.CloudflareAccessConfig
	verifier tokenVerifier
}

func NewCloudflareAccess(ctx context.Context, cfg config.CloudflareAccessConfig, policy *egress.Policy) (*CloudflareAccessAuthenticator, error) {
	if err := validateIssuerURL(cfg.TeamDomain); err != nil {
		return nil, fmt.Errorf("Cloudflare Access team domain: %w", err)
	}
	parsed, _ := url.Parse(cfg.TeamDomain)
	if parsed.Path != "" {
		return nil, errors.New("Cloudflare Access team domain must not contain a path")
	}
	certsURL := cfg.TeamDomain + "/cdn-cgi/access/certs"
	if policy != nil {
		if err := policy.ValidateURL(certsURL); err != nil {
			return nil, fmt.Errorf("Cloudflare Access certs URL violates egress policy: %w", err)
		}
	}
	var transport http.RoundTripper = http.DefaultTransport.(*http.Transport).Clone()
	if policy != nil {
		transport = policy.Transport()
	}
	client := &http.Client{Transport: boundedTransport{base: transport}, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, client), certsURL)
	verifier := oidcVerifier{client: client, verifier: oidc.NewVerifier(cfg.TeamDomain, keys, &oidc.Config{ClientID: cfg.Audience})}
	return newCloudflareAccessAuthenticator(cfg, verifier), nil
}

func newCloudflareAccessAuthenticator(cfg config.CloudflareAccessConfig, verifier tokenVerifier) *CloudflareAccessAuthenticator {
	return &CloudflareAccessAuthenticator{cfg: cfg, verifier: verifier}
}

func (a *CloudflareAccessAuthenticator) Authenticate(r *http.Request) (Principal, error) {
	values := r.Header.Values(CloudflareAccessJWTHeader)
	if len(values) == 0 {
		return Principal{}, ErrMissingAccessAssertion
	}
	if len(values) != 1 || len(values[0]) > maxAccessTokenBytes || strings.TrimSpace(values[0]) != values[0] {
		return Principal{}, ErrInvalidAccessAssertion
	}
	verified, err := a.verifier.Verify(r.Context(), values[0])
	if err != nil || !safeIdentity(verified.Subject) {
		return Principal{}, ErrInvalidAccessAssertion
	}
	var tokenType, email string
	if json.Unmarshal(verified.Claims["type"], &tokenType) != nil || tokenType != "app" || json.Unmarshal(verified.Claims["email"], &email) != nil || !safeIdentity(email) {
		return Principal{}, ErrInvalidAccessAssertion
	}
	groups, err := stringSetClaim(verified.Claims["groups"], false)
	if err != nil {
		return Principal{}, ErrInvalidAccessAssertion
	}
	if raw := verified.Claims["custom"]; len(raw) > 0 && string(raw) != "null" {
		custom := map[string]json.RawMessage{}
		if json.Unmarshal(raw, &custom) != nil {
			return Principal{}, ErrInvalidAccessAssertion
		}
		customGroups, err := stringSetClaim(custom["groups"], false)
		if err != nil {
			return Principal{}, ErrInvalidAccessAssertion
		}
		for group := range customGroups {
			groups[group] = true
		}
	}
	matches := []PolicyMatch{}
	for name, policy := range a.cfg.Policies {
		if matchesPolicy(verified.Subject, groups, policy) {
			matches = append(matches, PolicyMatch{Name: name, Policy: policy})
		}
	}
	if len(matches) == 0 {
		return Principal{}, ErrPolicyDenied
	}
	if a.cfg.PolicyMode != config.IdentityPolicyModeComposed && len(matches) != 1 {
		return Principal{}, ErrAmbiguousPolicy
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Name < matches[j].Name })
	return Principal{
		Identity: "cloudflare_access:" + verified.Subject, Source: "cloudflare_access",
		PolicyName: matches[0].Name, Policy: matches[0].Policy.Client(), PolicyMatches: matches,
		Composed: a.cfg.PolicyMode == config.IdentityPolicyModeComposed,
	}, nil
}

func (a *CloudflareAccessAuthenticator) WriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrPolicyDenied) || errors.Is(err, ErrAmbiguousPolicy) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

type sourceError struct {
	source string
	err    error
}

func (e *sourceError) Error() string { return e.err.Error() }
func (e *sourceError) Unwrap() error { return e.err }

type CompositeAuthenticator struct {
	oauth      *Authenticator
	cloudflare *CloudflareAccessAuthenticator
}

func NewCompositeAuthenticator(oauth *Authenticator, cloudflare *CloudflareAccessAuthenticator) *CompositeAuthenticator {
	return &CompositeAuthenticator{oauth: oauth, cloudflare: cloudflare}
}

func (a *CompositeAuthenticator) Authenticate(r *http.Request) (Principal, error) {
	hasBearer := len(r.Header.Values("Authorization")) > 0
	hasAccess := len(r.Header.Values(CloudflareAccessJWTHeader)) > 0
	if hasBearer && hasAccess {
		return Principal{}, ErrAmbiguousCredential
	}
	if hasAccess {
		principal, err := a.cloudflare.Authenticate(r)
		if err != nil {
			return Principal{}, &sourceError{source: "cloudflare_access", err: err}
		}
		return principal, nil
	}
	principal, err := a.oauth.Authenticate(r)
	if err != nil {
		return Principal{}, &sourceError{source: "oauth", err: err}
	}
	return principal, nil
}

func (a *CompositeAuthenticator) WriteError(w http.ResponseWriter, err error) {
	var sourced *sourceError
	if errors.As(err, &sourced) && sourced.source == "cloudflare_access" {
		a.cloudflare.WriteError(w, sourced.err)
		return
	}
	a.oauth.WriteError(w, err)
}
