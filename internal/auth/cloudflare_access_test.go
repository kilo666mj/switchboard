package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kilo666mj/switchboard/internal/config"
)

func cloudflareFixture(token verifiedToken) *CloudflareAccessAuthenticator {
	return newCloudflareAccessAuthenticator(config.CloudflareAccessConfig{
		TeamDomain: "https://example.cloudflareaccess.com", Audience: "access-audience",
		Policies: map[string]config.OAuthPolicy{
			"people": {Version: "v1", Groups: []string{"people"}, Profile: "workstation", Discover: true, Execute: true},
		},
	}, fakeVerifier{token: token})
}

func TestCloudflareAccessVerifierChecksSignatureIssuerAudienceAndExpiry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://example.cloudflareaccess.com"
	const audience = "access-audience"
	verifier := oidcVerifier{
		client:   http.DefaultClient,
		verifier: oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{ClientID: audience}),
	}
	cfg := config.CloudflareAccessConfig{
		TeamDomain: issuer, Audience: audience,
		Policies: map[string]config.OAuthPolicy{"people": {Version: "v1", Subjects: []string{"subject-1"}, Profile: "workstation"}},
	}
	authenticator := newCloudflareAccessAuthenticator(cfg, verifier)
	now := time.Now()
	claims := map[string]any{"iss": issuer, "sub": "subject-1", "aud": audience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "type": "app", "email": "person@example.com"}
	request := cloudflareRequest()
	request.Header.Set(CloudflareAccessJWTHeader, signJWTWithType(t, key, claims, "JWT"))
	if _, err := authenticator.Authenticate(request); err != nil {
		t.Fatalf("valid signed assertion: %v", err)
	}
	claims["aud"] = "wrong-audience"
	request.Header.Set(CloudflareAccessJWTHeader, signJWTWithType(t, key, claims, "JWT"))
	if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrInvalidAccessAssertion) {
		t.Fatalf("wrong audience error = %v", err)
	}
	claims["aud"] = audience
	claims["exp"] = now.Add(-time.Minute).Unix()
	request.Header.Set(CloudflareAccessJWTHeader, signJWTWithType(t, key, claims, "JWT"))
	if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrInvalidAccessAssertion) {
		t.Fatalf("expired assertion error = %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims["exp"] = now.Add(time.Hour).Unix()
	request.Header.Set(CloudflareAccessJWTHeader, signJWTWithType(t, otherKey, claims, "JWT"))
	if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrInvalidAccessAssertion) {
		t.Fatalf("untrusted signature error = %v", err)
	}
}

func TestCloudflareAccessVerifierAcceptsSignedServiceTokenAssertion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://example.cloudflareaccess.com"
	const audience = "access-audience"
	const clientID = "0123456789abcdef0123456789abcdef.access"
	verifier := oidcVerifier{
		client:   http.DefaultClient,
		verifier: oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{ClientID: audience}),
	}
	authenticator := newCloudflareAccessAuthenticator(config.CloudflareAccessConfig{
		TeamDomain: issuer, Audience: audience,
		Policies: map[string]config.OAuthPolicy{
			"agent": {Version: "v1", Subjects: []string{"service_token:" + clientID}, Profile: "agents"},
		},
	}, verifier)
	now := time.Now()
	claims := map[string]any{
		"iss": issuer, "sub": "", "aud": audience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"type": "app", "common_name": clientID,
	}
	request := cloudflareRequest()
	request.Header.Set(CloudflareAccessJWTHeader, signJWTWithType(t, key, claims, "JWT"))
	principal, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatalf("valid signed service-token assertion: %v", err)
	}
	if principal.Identity != "cloudflare_access:service_token:"+clientID {
		t.Fatalf("principal = %+v", principal)
	}
}

func cloudflareRequest() *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://switchboard.example.com/mcp/sessions", nil)
	request.Header.Set(CloudflareAccessJWTHeader, "signed-access-assertion")
	return request
}

func TestCloudflareAccessMapsVerifiedIdentityAndGroups(t *testing.T) {
	authenticator := cloudflareFixture(verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{
		"type": "app", "email": "person@example.com", "groups": []string{"other"}, "custom": map[string]any{"groups": []string{"people"}},
	})})
	principal, err := authenticator.Authenticate(cloudflareRequest())
	if err != nil {
		t.Fatal(err)
	}
	if principal.Identity != "cloudflare_access:subject-1" || principal.Source != "cloudflare_access" || principal.PolicyName != "people" || principal.Policy.Profile != "workstation" {
		t.Fatalf("principal = %+v", principal)
	}
}

func TestCloudflareAccessMapsVerifiedServiceTokenIdentity(t *testing.T) {
	const clientID = "0123456789abcdef0123456789abcdef.access"
	authenticator := newCloudflareAccessAuthenticator(config.CloudflareAccessConfig{
		TeamDomain: "https://example.cloudflareaccess.com", Audience: "access-audience",
		Policies: map[string]config.OAuthPolicy{
			"agent": {Version: "v1", Subjects: []string{"service_token:" + clientID}, Profile: "agents", Execute: true},
		},
	}, fakeVerifier{token: verifiedToken{Claims: rawClaims(map[string]any{
		"type": "app", "common_name": clientID,
	})}})
	principal, err := authenticator.Authenticate(cloudflareRequest())
	if err != nil {
		t.Fatal(err)
	}
	if principal.Identity != "cloudflare_access:service_token:"+clientID || principal.Source != "cloudflare_access" || principal.PolicyName != "agent" || principal.Policy.Profile != "agents" {
		t.Fatalf("principal = %+v", principal)
	}
}

func TestCloudflareAccessServiceTokensRequireExactSubjectPolicy(t *testing.T) {
	const clientID = "0123456789abcdef0123456789abcdef.access"
	authenticator := cloudflareFixture(verifiedToken{Claims: rawClaims(map[string]any{
		"type": "app", "common_name": clientID, "groups": []string{"people"},
	})})
	if _, err := authenticator.Authenticate(cloudflareRequest()); !errors.Is(err, ErrInvalidAccessAssertion) {
		t.Fatalf("service token with user groups error = %v", err)
	}
	policies := map[string]config.OAuthPolicy{
		"agent-a": {Version: "v1", Subjects: []string{"service_token:" + clientID}, Profile: "agents"},
	}
	token := verifiedToken{Claims: rawClaims(map[string]any{"type": "app", "common_name": clientID})}
	authenticator = newCloudflareAccessAuthenticator(config.CloudflareAccessConfig{Policies: policies}, fakeVerifier{token: token})
	policies["agent-b"] = policies["agent-a"]
	if _, err := authenticator.Authenticate(cloudflareRequest()); !errors.Is(err, ErrAmbiguousPolicy) {
		t.Fatalf("ambiguous service-token policy error = %v", err)
	}
	delete(policies, "agent-a")
	delete(policies, "agent-b")
	policies["other"] = config.OAuthPolicy{Version: "v1", Subjects: []string{"service_token:other.access"}, Profile: "agents"}
	if _, err := authenticator.Authenticate(cloudflareRequest()); !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("unmapped service-token policy error = %v", err)
	}
}

func TestCloudflareAccessRejectsAmbiguousIdentityShapes(t *testing.T) {
	const clientID = "0123456789abcdef0123456789abcdef.access"
	tests := map[string]verifiedToken{
		"service token missing common name": {Claims: rawClaims(map[string]any{"type": "app"})},
		"service token with email": {Claims: rawClaims(map[string]any{
			"type": "app", "common_name": clientID, "email": "machine@example.com",
		})},
		"service token invalid common name": {Claims: rawClaims(map[string]any{
			"type": "app", "common_name": "bad\nclient.access",
		})},
		"human with common name": {Subject: "subject-1", Claims: rawClaims(map[string]any{
			"type": "app", "email": "person@example.com", "common_name": clientID, "groups": []string{"people"},
		})},
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := cloudflareFixture(token).Authenticate(cloudflareRequest()); !errors.Is(err, ErrInvalidAccessAssertion) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestCloudflareAccessIgnoresUnsignedServiceTokenHeaders(t *testing.T) {
	const clientID = "0123456789abcdef0123456789abcdef.access"
	request := cloudflareRequest()
	request.Header.Set("Cf-Access-Client-Id", clientID)
	authenticator := newCloudflareAccessAuthenticator(config.CloudflareAccessConfig{
		TeamDomain: "https://example.cloudflareaccess.com", Audience: "access-audience",
		Policies: map[string]config.OAuthPolicy{
			"agent": {Version: "v1", Subjects: []string{"service_token:" + clientID}, Profile: "agents"},
		},
	}, fakeVerifier{token: verifiedToken{Claims: rawClaims(map[string]any{"type": "app"})}})
	if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrInvalidAccessAssertion) {
		t.Fatalf("unsigned client ID error = %v", err)
	}
}

func TestCloudflareAccessReturnsComposablePolicyMatches(t *testing.T) {
	authenticator := cloudflareFixture(verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{
		"type": "app", "email": "person@example.com", "groups": []string{"people", "operators"},
	})})
	authenticator.cfg.PolicyMode = config.IdentityPolicyModeComposed
	authenticator.cfg.Policies["operators"] = config.OAuthPolicy{Version: "v1", Groups: []string{"operators"}, Profile: "workstation", ToolPolicy: "write"}
	principal, err := authenticator.Authenticate(cloudflareRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Composed || len(principal.PolicyMatches) != 2 || principal.PolicyMatches[0].Name != "operators" || principal.PolicyMatches[1].Name != "people" {
		t.Fatalf("principal = %+v", principal)
	}
}

func TestCloudflareAccessFailsClosed(t *testing.T) {
	valid := verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{"type": "app", "email": "person@example.com", "groups": []string{"people"}})}
	for name, mutate := range map[string]func(*http.Request, *verifiedToken){
		"missing assertion":   func(r *http.Request, _ *verifiedToken) { r.Header.Del(CloudflareAccessJWTHeader) },
		"multiple assertions": func(r *http.Request, _ *verifiedToken) { r.Header.Add(CloudflareAccessJWTHeader, "second") },
		"missing subject":     func(_ *http.Request, token *verifiedToken) { token.Subject = "" },
		"missing email":       func(_ *http.Request, token *verifiedToken) { delete(token.Claims, "email") },
		"wrong type": func(_ *http.Request, token *verifiedToken) {
			token.Claims["type"] = rawClaims(map[string]any{"v": "org"})["v"]
		},
		"invalid groups": func(_ *http.Request, token *verifiedToken) {
			token.Claims["groups"] = rawClaims(map[string]any{"v": 42})["v"]
		},
		"unmapped groups": func(_ *http.Request, token *verifiedToken) {
			token.Claims["groups"] = rawClaims(map[string]any{"v": []string{"other"}})["v"]
		},
	} {
		t.Run(name, func(t *testing.T) {
			token := verifiedToken{Subject: valid.Subject, Claims: map[string]json.RawMessage{}}
			for key, value := range valid.Claims {
				token.Claims[key] = value
			}
			request := cloudflareRequest()
			mutate(request, &token)
			_, err := cloudflareFixture(token).Authenticate(request)
			if err == nil {
				t.Fatal("invalid assertion accepted")
			}
		})
	}
}

func TestCompositeAuthenticatorRejectsAmbiguousCredentials(t *testing.T) {
	access := cloudflareFixture(verifiedToken{})
	oauth := oauthFixture(t, verifiedToken{})
	composite := NewCompositeAuthenticator(oauth, access)
	request := cloudflareRequest()
	request.Header.Set("Authorization", "Bearer token")
	if _, err := composite.Authenticate(request); !errors.Is(err, ErrAmbiguousCredential) {
		t.Fatalf("error = %v", err)
	}
	response := httptest.NewRecorder()
	access.WriteError(response, ErrInvalidAccessAssertion)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("response = %d, challenge = %q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
}
