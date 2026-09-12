package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposeOperationalSignalsWithoutIdentity(t *testing.T) {
	metrics := NewMetrics()
	metrics.AuthenticationFailure()
	metrics.AuthorizationFailure()
	metrics.SessionCapacityFailure()
	metrics.SessionOpened()
	metrics.ObserveToolCall("demo", "demo_status", "allow", "success", 250*time.Millisecond)
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	metrics.ServeHTTP(response, request)
	body := response.Body.String()
	for _, value := range []string{
		"switchboard_authentication_failures_total 1",
		"switchboard_authorization_failures_total 1",
		"switchboard_session_capacity_rejections_total 1",
		"switchboard_sessions_active 1",
		`switchboard_tool_calls_total{capability="demo",tool="demo_status",decision="allow",outcome="success"} 1`,
		`switchboard_tool_call_duration_seconds_sum{capability="demo",tool="demo_status",decision="allow",outcome="success"} 0.25`,
	} {
		if !strings.Contains(body, value) {
			t.Fatalf("missing %q in %s", value, body)
		}
	}
	if strings.Contains(body, "alice") {
		t.Fatal("metrics exposed identity")
	}
	metrics.SessionClosed()
}
