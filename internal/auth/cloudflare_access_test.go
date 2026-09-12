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
