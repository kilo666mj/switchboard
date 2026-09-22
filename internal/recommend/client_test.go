package recommend

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/switchboard/internal/config"
)

func TestRecommendTranslatesFiniteDecisionAndDerivesConfidence(t *testing.T) {
	t.Setenv("RECOMMENDER_TEST_KEY", "test-secret")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/decision" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
			t.Fatalf("Authorization = %q", got)
		}
		var request decisionRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Model != "decision-model" || request.Mode != "tree" || request.TreeMax != 255 || !request.CachePrompt {
			t.Fatalf("request = %+v", request)
		}
		field := request.Schema["capability"]
		if strings.Join(field.Choices, ",") != "dns,forgejo" || len(request.Contexts) != 1 || request.Contexts[0] != "Find a repository issue" {
			t.Fatalf("translated request = %+v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
          "object":"decision","model":"decision-model",
          "results":[{"fields":{"capability":{"value":"forgejo","probability":0.9,"probabilities":{"dns":0.1,"forgejo":0.9},"tree":true}}}],
          "usage":{"prompt_tokens":100,"cached_tokens":80,"context_tokens":20,"scored_rows":2},
          "timings":{"prefill_ms":10,"scoring_ms":5,"total_ms":15,"rounds":1,"per_decision_ms":15}
        }`))
	}))
	defer server.Close()
	client, err := New(config.CapabilityRecommenderConfig{
		Endpoint: server.URL + "/v1/decision", APIKeyEnv: "RECOMMENDER_TEST_KEY", Model: "decision-model", MinConfidence: 0.6,
	}, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Recommend(t.Context(), "Find a repository issue", []Candidate{
		{Name: "forgejo", Description: "Repository work", Tools: []string{"forgejo_search_issues"}},
		{Name: "dns", Description: "DNS records", Tools: []string{"rilldns_search"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Choice != "forgejo" || !result.LowConfidence || result.Usage.CachedTokens != 80 || result.Timings.TotalMS != 15 {
		t.Fatalf("result = %+v", result)
	}
	wantConfidence := 1 - (-0.9*math.Log(0.9)-0.1*math.Log(0.1))/math.Log(2)
	if math.Abs(result.Confidence-wantConfidence) > 1e-9 {
		t.Fatalf("confidence = %v, want %v", result.Confidence, wantConfidence)
	}
}

func TestRecommendCircuitBreaker(t *testing.T) {
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if hits <= breakerThreshold {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprint(w, `{"object":"decision","results":[{"fields":{"capability":{"value":"dns","probability":1,"probabilities":{"dns":1},"tree":true}}}]}`)
	}))
	defer server.Close()
	client, err := New(config.CapabilityRecommenderConfig{Endpoint: server.URL + "/v1/decision", Model: "model"}, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000, 0)
	client.now = func() time.Time { return now }
	for i := 0; i < breakerThreshold; i++ {
		if _, err := client.Recommend(t.Context(), "route this", []Candidate{{Name: "dns"}}); err == nil {
			t.Fatal("upstream failure accepted")
		}
	}
	if _, err := client.Recommend(t.Context(), "route this", []Candidate{{Name: "dns"}}); err == nil || !strings.Contains(err.Error(), "circuit is open") {
		t.Fatalf("open circuit error = %v", err)
	}
	if hits != breakerThreshold {
		t.Fatalf("upstream hits = %d, want %d", hits, breakerThreshold)
	}
	now = now.Add(breakerCooldown + time.Second)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.Recommend(cancelled, "route this", []Candidate{{Name: "dns"}}); err == nil {
		t.Fatal("cancelled recovery probe accepted")
	}
	if hits != breakerThreshold {
		t.Fatalf("cancelled probe reached upstream: hits = %d", hits)
	}
	if _, err := client.Recommend(t.Context(), "route this", []Candidate{{Name: "dns"}}); err != nil {
		t.Fatalf("recovery probe: %v", err)
	}
	if hits != breakerThreshold+1 {
		t.Fatalf("upstream hits after recovery = %d", hits)
	}
}

func TestRecommendRejectsIncompleteOrUnauthorizedResponses(t *testing.T) {
	for name, response := range map[string]string{
		"malformed-json":       `{not-json`,
		"missing-distribution": `{"object":"decision","results":[{"fields":{"capability":{"value":"dns","probability":1,"tree":true}}}]}`,
		"greedy":               `{"object":"decision","results":[{"fields":{"capability":{"value":"dns","probability":1,"probabilities":{"dns":1,"forgejo":0},"tree":false}}}]}`,
		"unauthorized":         `{"object":"decision","results":[{"fields":{"capability":{"value":"shell","probability":1,"probabilities":{"dns":0,"forgejo":1},"tree":true}}}]}`,
		"incomplete":           `{"object":"decision","results":[{"fields":{"capability":{"value":"dns","probability":1,"probabilities":{"dns":1},"tree":true}}}]}`,
		"not-argmax":           `{"object":"decision","results":[{"fields":{"capability":{"value":"dns","probability":0.4,"probabilities":{"dns":0.4,"forgejo":0.6},"tree":true}}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(response)) }))
			defer server.Close()
			client, err := New(config.CapabilityRecommenderConfig{Endpoint: server.URL + "/v1/decision", Model: "model"}, server.Client().Transport)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Recommend(t.Context(), "route this", []Candidate{{Name: "dns"}, {Name: "forgejo"}}); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}

func TestRecommendTimesOutWithoutLeakingRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	client, err := New(config.CapabilityRecommenderConfig{
		Endpoint: server.URL + "/v1/decision", Model: "model", TimeoutMS: 20,
	}, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Recommend(t.Context(), "secret-timeout-request-canary", []Candidate{{Name: "dns"}})
	if err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("timeout error = %v", err)
	}
	if strings.Contains(err.Error(), "secret-timeout-request-canary") {
		t.Fatalf("timeout leaked request: %v", err)
	}
}

func TestRecommendBackendDownOpensCircuit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	transport := server.Client().Transport
	client, err := New(config.CapabilityRecommenderConfig{Endpoint: server.URL + "/v1/decision", Model: "model"}, transport)
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	for range breakerThreshold {
		if _, err := client.Recommend(t.Context(), "route this", []Candidate{{Name: "dns"}}); err == nil {
			t.Fatal("unreachable backend accepted")
		}
	}
	if _, err := client.Recommend(t.Context(), "route this", []Candidate{{Name: "dns"}}); err == nil || !strings.Contains(err.Error(), "circuit is open") {
		t.Fatalf("open circuit error = %v", err)
	}
}

func TestRecommendBoundsAndSanitizesFailures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "secret-upstream-detail", http.StatusInternalServerError)
	}))
	defer server.Close()
	client, err := New(config.CapabilityRecommenderConfig{Endpoint: server.URL + "/v1/decision", Model: "model", MaxCandidates: 1}, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Recommend(t.Context(), "route this", []Candidate{{Name: "dns"}, {Name: "forgejo"}}); err == nil || !strings.Contains(err.Error(), "configured maximum") {
		t.Fatalf("candidate bound error = %v", err)
	}
	_, err = client.Recommend(t.Context(), "route this", []Candidate{{Name: "dns"}})
	if err == nil || strings.Contains(err.Error(), "secret-upstream-detail") {
		t.Fatalf("sanitized error = %v", err)
	}
}
