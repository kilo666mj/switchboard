package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kilo666mj/switchboard/internal/config"
)

type fakeVerifier struct {
	token verifiedToken
	err   error
}

func (f fakeVerifier) Verify(context.Context, string) (verifiedToken, error) {
	return f.token, f.err
}

type fakeGroupResolver struct {
	subject string
	groups  json.RawMessage
	err     error
	token   *string
}

func (f fakeGroupResolver) Resolve(_ context.Context, token string) (string, json.RawMessage, error) {
	if f.token != nil {
		*f.token = token
	}
	return f.subject, f.groups, f.err
}

func oauthFixture(t *testing.T, token verifiedToken) *Authenticator {
	t.Helper()
	authenticator, err := newAuthenticator(config.OAuthConfig{
		Issuer: "https://id.example.com", Resource: "https://switchboard.example.com/mcp/sessions",
		RequiredScopes: []string{"mcp:connect"},
		Policies: map[string]config.OAuthPolicy{
			"readers": {Version: "pilot-v1", Groups: []string{"switchboard-readers"}, RequiredScopes: []string{"tools:read"}, Profile: "read", Discover: true, Execute: true},
		},
	}, fakeVerifier{token: token})
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}

func rawClaims(values map[string]any) map[string]json.RawMessage {
	result := map[string]json.RawMessage{}
	for name, value := range values {
		result[name], _ = json.Marshal(value)
	}
	return result
}

func authenticatedRequest() *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://switchboard.example.com/mcp/sessions", nil)
	request.Header.Set("Authorization", "Bearer signed-access-token")
	return request
}

func TestAuthenticateMapsVerifiedSubjectAndGroups(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Unix()
	authenticator := oauthFixture(t, verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{
		"scope": "openid mcp:connect tools:read", "groups": []string{"switchboard-readers"}, "exp": expiry,
	})})
	principal, err := authenticator.Authenticate(authenticatedRequest())
	if err != nil {
		t.Fatal(err)
	}
	if principal.Identity != "subject-1" || principal.PolicyName != "readers" || principal.Policy.Profile != "read" || !principal.Policy.Execute {
		t.Fatalf("principal = %+v", principal)
	}
}

func TestAuthenticateMapsUserInfoGroups(t *testing.T) {
	authenticator := oauthFixture(t, verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{
		"scope": "openid groups mcp:connect tools:read", "groups": []string{"ignored-access-token-group"},
	})})
	authenticator.cfg.GroupSource = config.OAuthGroupSourceUserInfo
	var token string
	authenticator.groups = fakeGroupResolver{
		subject: "subject-1",
		groups:  rawClaims(map[string]any{"groups": []string{"switchboard-readers"}})["groups"],
		token:   &token,
	}
	principal, err := authenticator.Authenticate(authenticatedRequest())
	if err != nil {
		t.Fatal(err)
	}
	if principal.PolicyName != "readers" || token != "signed-access-token" {
		t.Fatalf("principal = %+v, token = %q", principal, token)
	}
}

func TestAuthenticateRejectsUntrustedUserInfo(t *testing.T) {
	for name, resolver := range map[string]groupResolver{
		"request failure": fakeGroupResolver{err: errors.New("provider unavailable")},
		"subject mismatch": fakeGroupResolver{
			subject: "subject-2",
			groups:  rawClaims(map[string]any{"groups": []string{"switchboard-readers"}})["groups"],
		},
		"invalid group claim": fakeGroupResolver{
			subject: "subject-1",
			groups:  rawClaims(map[string]any{"groups": 42})["groups"],
		},
	} {
		t.Run(name, func(t *testing.T) {
			authenticator := oauthFixture(t, verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{
				"scope": "openid groups mcp:connect tools:read",
			})})
			authenticator.cfg.GroupSource = config.OAuthGroupSourceUserInfo
			authenticator.groups = resolver
			if _, err := authenticator.Authenticate(authenticatedRequest()); !errors.Is(err, ErrInvalidToken) || !errors.Is(err, ErrUserInfo) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAuthenticateFailsClosed(t *testing.T) {
	for name, test := range map[string]struct {
		token  verifiedToken
		header string
		want   error
	}{
		"missing token":        {verifiedToken{}, "", ErrMissingToken},
		"missing subject":      {verifiedToken{Claims: rawClaims(map[string]any{"scope": "mcp:connect tools:read", "groups": []string{"switchboard-readers"}})}, "Bearer token", ErrInvalidToken},
		"missing base scope":   {verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{"scope": "tools:read", "groups": []string{"switchboard-readers"}})}, "Bearer token", ErrInsufficientScope},
		"missing policy scope": {verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{"scope": "mcp:connect", "groups": []string{"switchboard-readers"}})}, "Bearer token", ErrInsufficientScope},
		"unmapped group":       {verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{"scope": "mcp:connect tools:read", "groups": []string{"other"}})}, "Bearer token", ErrPolicyDenied},
		"invalid group claim":  {verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{"scope": "mcp:connect tools:read", "groups": 42})}, "Bearer token", ErrInvalidToken},
	} {
		t.Run(name, func(t *testing.T) {
			authenticator := oauthFixture(t, test.token)
			request := authenticatedRequest()
			if test.header == "" {
				request.Header.Del("Authorization")
			} else {
				request.Header.Set("Authorization", test.header)
			}
			_, err := authenticator.Authenticate(request)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAuthenticateRejectsAmbiguousPolicy(t *testing.T) {
	authenticator := oauthFixture(t, verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{
		"scope": "mcp:connect tools:read", "groups": []string{"switchboard-readers", "operators"},
	})})
	authenticator.cfg.Policies["operators"] = config.OAuthPolicy{Version: "pilot-v1", Groups: []string{"operators"}, Profile: "read"}
	if _, err := authenticator.Authenticate(authenticatedRequest()); !errors.Is(err, ErrAmbiguousPolicy) {
		t.Fatalf("error = %v", err)
	}
}

func TestAuthenticateReturnsComposablePolicyMatches(t *testing.T) {
	authenticator := oauthFixture(t, verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{
		"scope": "mcp:connect tools:read tools:write", "groups": []string{"switchboard-readers", "operators"},
	})})
	authenticator.cfg.PolicyMode = config.IdentityPolicyModeComposed
	authenticator.cfg.Policies["operators"] = config.OAuthPolicy{Version: "operator-v1", Groups: []string{"operators"}, RequiredScopes: []string{"tools:write"}, Profile: "read", ToolPolicy: "write"}
	principal, err := authenticator.Authenticate(authenticatedRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Composed || len(principal.PolicyMatches) != 2 || principal.PolicyMatches[0].Name != "operators" || principal.PolicyMatches[1].Name != "readers" {
		t.Fatalf("principal = %+v", principal)
	}
}

func TestAuthenticateRequiresConfiguredAccessTokenType(t *testing.T) {
	authenticator := oauthFixture(t, verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{
		"scope": "mcp:connect tools:read", "groups": []string{"switchboard-readers"}, "type": "id-token",
	})})
	authenticator.cfg.TokenTypeClaim = "type"
	authenticator.cfg.TokenTypeValue = "access-token"
	if _, err := authenticator.Authenticate(authenticatedRequest()); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("wrong token type error = %v", err)
	}
	authenticator.verifier = fakeVerifier{token: verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{
		"scope": "mcp:connect tools:read", "groups": []string{"switchboard-readers"}, "type": "access-token",
	})}}
	if _, err := authenticator.Authenticate(authenticatedRequest()); err != nil {
		t.Fatalf("access token type rejected: %v", err)
	}
}

func TestPolicyScopeChallengeRetainsBaseScopes(t *testing.T) {
	authenticator := oauthFixture(t, verifiedToken{Subject: "subject-1", Claims: rawClaims(map[string]any{
		"scope": "mcp:connect", "groups": []string{"switchboard-readers"},
	})})
	_, err := authenticator.Authenticate(authenticatedRequest())
	var scopeError *ScopeError
	if !errors.As(err, &scopeError) {
		t.Fatalf("error = %v", err)
	}
	response := httptest.NewRecorder()
	authenticator.WriteError(response, err)
	if challenge := response.Header().Get("WWW-Authenticate"); !strings.Contains(challenge, `scope="mcp:connect tools:read"`) {
		t.Fatalf("challenge = %q", challenge)
	}
}

func TestProtectedResourceMetadataAndChallenge(t *testing.T) {
	authenticator := oauthFixture(t, verifiedToken{})
	if got := authenticator.MetadataPath(); got != "/.well-known/oauth-protected-resource/mcp/sessions" {
		t.Fatalf("metadata path = %q", got)
	}
	response := httptest.NewRecorder()
	authenticator.ServeHTTP(response, httptest.NewRequest(http.MethodGet, authenticator.MetadataPath(), nil))
	body := response.Body.String()
	for _, value := range []string{`"resource":"https://switchboard.example.com/mcp/sessions"`, `"authorization_servers":["https://id.example.com"]`, `"mcp:connect"`, `"tools:read"`} {
		if !strings.Contains(body, value) {
			t.Fatalf("metadata missing %s: %s", value, body)
		}
	}
	response = httptest.NewRecorder()
	authenticator.WriteError(response, ErrInsufficientScope)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Header().Get("WWW-Authenticate"), `resource_metadata="https://switchboard.example.com/.well-known/oauth-protected-resource/mcp/sessions"`) {
		t.Fatalf("status=%d challenge=%q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
	response = httptest.NewRecorder()
	authenticator.WriteError(response, ErrMissingToken)
	if challenge := response.Header().Get("WWW-Authenticate"); response.Code != http.StatusUnauthorized || strings.Contains(challenge, "error=") || !strings.Contains(challenge, `scope="mcp:connect tools:read"`) {
		t.Fatalf("missing-token status=%d challenge=%q", response.Code, challenge)
	}
	response = httptest.NewRecorder()
	authenticator.WriteError(response, ErrPolicyDenied)
	if response.Code != http.StatusForbidden || response.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("policy-denied status=%d challenge=%q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
}

func TestVerifierFailureIsNotExposed(t *testing.T) {
	authenticator := oauthFixture(t, verifiedToken{})
	authenticator.verifier = fakeVerifier{err: errors.New("signature detail canary")}
	if _, err := authenticator.Authenticate(authenticatedRequest()); !errors.Is(err, ErrInvalidToken) || strings.Contains(err.Error(), "canary") {
		t.Fatalf("error = %v", err)
	}
}

func TestOIDCVerifierChecksSignatureIssuerAudienceAndExpiry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://id.example.com"
	resource := "https://switchboard.example.com/mcp/sessions"
	verifier := oidcVerifier{
		client: http.DefaultClient,
		verifier: oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{
			ClientID: resource,
		}),
	}
	cfg := config.OAuthConfig{
		Issuer: issuer, Resource: resource, RequiredScopes: []string{"mcp:connect"},
		JWTType:  "at+jwt",
		Policies: map[string]config.OAuthPolicy{"reader": {Version: "pilot-v1", Subjects: []string{"subject-1"}, Profile: "read"}},
	}
	authenticator, err := newAuthenticator(cfg, verifier)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := map[string]any{"iss": issuer, "sub": "subject-1", "aud": resource, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "scope": "mcp:connect"}
	request := authenticatedRequest()
	request.Header.Set("Authorization", "Bearer "+signJWT(t, key, claims))
	if _, err := authenticator.Authenticate(request); err != nil {
		t.Fatalf("valid signed token: %v", err)
	}
	for _, typ := range []any{"JWT", "id-token", "", nil, 42} {
		request.Header.Set("Authorization", "Bearer "+signJWTWithType(t, key, claims, typ))
		if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("signed token with typ %v error = %v", typ, err)
		}
	}
	// Relabeling a correctly signed ID token must not bypass signature validation.
	idToken := strings.Split(signJWTWithType(t, key, claims, "JWT"), ".")
	accessHeader, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "at+jwt"})
	idToken[0] = base64.RawURLEncoding.EncodeToString(accessHeader)
	request.Header.Set("Authorization", "Bearer "+strings.Join(idToken, "."))
	if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered protected type error = %v", err)
	}
	claims["aud"] = "https://other.example.com/mcp"
	request.Header.Set("Authorization", "Bearer "+signJWT(t, key, claims))
	if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("wrong audience error = %v", err)
	}
	claims["aud"] = resource
	claims["exp"] = now.Add(-time.Minute).Unix()
	request.Header.Set("Authorization", "Bearer "+signJWT(t, key, claims))
	if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired token error = %v", err)
	}
}

func signJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	return signJWTWithType(t, key, claims, "at+jwt")
}

func signJWTWithType(t *testing.T, key *rsa.PrivateKey, claims map[string]any, typ any) string {
	t.Helper()
	values := map[string]any{"alg": "RS256"}
	if typ != nil {
		values["typ"] = typ
	}
	header, _ := json.Marshal(values)
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestProviderResponsesAreBounded(t *testing.T) {
	body := &boundedBody{ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", maxProviderResponse+1))), remaining: maxProviderResponse}
	if _, err := io.ReadAll(body); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized provider response error = %v", err)
	}
}

func TestIssuerDiscoveryRejectsRedirect(t *testing.T) {
	var destinationRequests atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			destinationRequests.Add(1)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.Redirect(w, r, server.URL+"/redirected", http.StatusFound)
	}))
	defer server.Close()
	cfg := config.OAuthConfig{Issuer: server.URL, Resource: "https://switchboard.example.com/mcp/sessions"}
	if _, err := newWithTransport(t.Context(), cfg, nil, server.Client().Transport); err == nil {
		t.Fatal("redirected issuer discovery was accepted")
	}
	if destinationRequests.Load() != 0 {
		t.Fatal("issuer redirect destination received a request")
	}
}
