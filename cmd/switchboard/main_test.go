package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type deadlineWriter struct {
	header   http.Header
	deadline *time.Time
}

func (w *deadlineWriter) Header() http.Header                { return w.header }
func (w *deadlineWriter) Write([]byte) (int, error)          { return 0, nil }
func (w *deadlineWriter) WriteHeader(int)                    {}
func (w *deadlineWriter) SetWriteDeadline(v time.Time) error { w.deadline = &v; return nil }

func TestBearer(t *testing.T) {
	t.Parallel()
	handler := bearer("secret", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, test := range []struct {
		name   string
		header string
		want   int
	}{{"missing", "", http.StatusUnauthorized}, {"wrong", "Bearer nope", http.StatusUnauthorized}, {"valid", "Bearer secret", http.StatusNoContent}} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			request.Header.Set("Authorization", test.header)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestLegacyBearerEntropyFloor(t *testing.T) {
	for _, token := range []string{"", strings.Repeat("a", 32)} {
		if err := validateLegacyBearer(token); err != nil {
			t.Fatalf("valid token length %d rejected: %v", len(token), err)
		}
	}
	if err := validateLegacyBearer(strings.Repeat("a", 31)); err == nil {
		t.Fatal("short legacy bearer accepted")
	}
}

func TestHTTPServerTimeoutsPreserveSessionStream(t *testing.T) {
	server := newHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 30*time.Second || server.WriteTimeout != 6*time.Minute || server.IdleTimeout != 2*time.Minute || server.MaxHeaderBytes != 32<<10 {
		t.Fatalf("unexpected HTTP server bounds: %+v", server)
	}
	writer := &deadlineWriter{header: http.Header{}}
	request := httptest.NewRequest(http.MethodGet, "/mcp/sessions", nil)
	server.Handler.ServeHTTP(writer, request)
	if writer.deadline == nil || !writer.deadline.IsZero() {
		t.Fatalf("session stream deadline = %v, want cleared", writer.deadline)
	}
}

func TestRetiredLegacyMCP(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer retired-token")
	response := httptest.NewRecorder()

	retiredLegacyMCP(nil).ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if got := response.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
	}
}
