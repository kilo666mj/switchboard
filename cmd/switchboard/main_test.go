package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
