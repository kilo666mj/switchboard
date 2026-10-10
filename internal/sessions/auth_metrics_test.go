package sessions

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kilo666mj/switchboard/internal/auth"
	"github.com/kilo666mj/switchboard/internal/observability"
)

type rejectedAuthenticator struct {
	*auth.Authenticator
	err error
}

func (a rejectedAuthenticator) Authenticate(*http.Request) (auth.Principal, error) {
	return auth.Principal{}, a.err
}

func TestAuthenticationMetricsSeparateChallengesFromFailures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		header     []string
		challenges int
		failures   int
		denials    int
		userinfo   int
	}{
		{name: "missing bearer", challenges: 6},
		{name: "empty bearer header", header: []string{""}, failures: 6},
		{name: "malformed bearer", header: []string{"Basic invalid"}, failures: 6},
		{name: "duplicate bearer", header: []string{"Bearer one", "Bearer two"}, failures: 6},
		{name: "invalid static token", header: []string{"Bearer invalid"}, failures: 6},
		{name: "oauth discovery", err: auth.ErrMissingToken, challenges: 6},
		{name: "wrapped oauth discovery", err: fmt.Errorf("challenge: %w", auth.ErrMissingToken), challenges: 6},
		{name: "invalid or expired oauth token", err: auth.ErrInvalidToken, failures: 6},
		{name: "userinfo failure", err: auth.ErrUserInfo, failures: 6, userinfo: 6},
		{name: "insufficient scope", err: auth.ErrInsufficientScope, denials: 6},
		{name: "policy denial", err: auth.ErrPolicyDenied, denials: 6},
		{name: "ambiguous policy", err: auth.ErrAmbiguousPolicy, denials: 6},
		{name: "missing access assertion", err: auth.ErrMissingAccessAssertion, failures: 6},
		{name: "invalid access assertion", err: auth.ErrInvalidAccessAssertion, failures: 6},
		{name: "ambiguous credentials", err: auth.ErrAmbiguousCredential, failures: 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metrics := observability.NewMetrics()
			h := &Handler{metrics: metrics}
			wantResponse := httptest.NewRecorder()
			if tc.err != nil {
				a := rejectedAuthenticator{Authenticator: &auth.Authenticator{}, err: tc.err}
				h.authenticator = a
				a.WriteError(wantResponse, tc.err)
			} else {
				wantResponse.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(wantResponse, "unauthorized", http.StatusUnauthorized)
			}
			// A burst exceeding the alert's count threshold must retain the same
			// HTTP challenge/denial while incrementing only the correct counters.
			for i := 0; i < 6; i++ {
				method := []string{http.MethodPost, http.MethodGet, http.MethodDelete}[i%3]
				r := httptest.NewRequest(method, "/mcp/sessions", nil)
				for _, value := range tc.header {
					r.Header.Add("Authorization", value)
				}
				w := httptest.NewRecorder()
				h.serve(w, r)
				if w.Code != wantResponse.Code || w.Body.String() != wantResponse.Body.String() || w.Header().Get("WWW-Authenticate") != wantResponse.Header().Get("WWW-Authenticate") {
					t.Fatalf("authentication response changed: %d %v %s", w.Code, w.Header(), w.Body.String())
				}
			}
			w := httptest.NewRecorder()
			metrics.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			for name, count := range map[string]int{
				"authentication_challenges": tc.challenges,
				"authentication_failures":   tc.failures,
				"authorization_failures":    tc.denials,
				"oauth_userinfo_failures":   tc.userinfo,
			} {
				want := fmt.Sprintf("switchboard_%s_total %d\n", name, count)
				if !strings.Contains(w.Body.String(), want) {
					t.Errorf("missing %q in metrics:\n%s", want, w.Body.String())
				}
			}
			if len(h.entries) != 0 {
				t.Fatal("unauthenticated request created a session")
			}
		})
	}
}
