package gateway

import (
	"testing"

	"github.com/kilo666mj/switchboard/internal/config"
)

func TestCallControllerRateAndConcurrencyLimits(t *testing.T) {
	identityRate := NewCallController(config.Client{Limits: &config.CallLimits{RequestsPerMinute: 1, Burst: 1}}, config.ToolPolicy{})
	release, outcome := identityRate.Admit("demo_read")
	if outcome != "" {
		t.Fatal(outcome)
	}
	release()
	if _, outcome := identityRate.Admit("demo_read"); outcome != "identity_rate_limited" {
		t.Fatalf("identity rate outcome = %q", outcome)
	}

	toolRate := NewCallController(config.Client{}, config.ToolPolicy{ToolLimits: map[string]config.CallLimits{
		"demo_read": {RequestsPerMinute: 1, Burst: 1},
	}})
	release, outcome = toolRate.Admit("demo_read")
	if outcome != "" {
		t.Fatal(outcome)
	}
	release()
	if _, outcome := toolRate.Admit("demo_read"); outcome != "tool_rate_limited" {
		t.Fatalf("tool rate outcome = %q", outcome)
	}

	identityConcurrency := NewCallController(config.Client{Limits: &config.CallLimits{Concurrency: 1}}, config.ToolPolicy{})
	release, outcome = identityConcurrency.Admit("demo_read")
	if outcome != "" {
		t.Fatal(outcome)
	}
	if _, outcome := identityConcurrency.Admit("demo_other"); outcome != "identity_concurrency_limited" {
		t.Fatalf("identity concurrency outcome = %q", outcome)
	}
	release()

	toolConcurrency := NewCallController(config.Client{}, config.ToolPolicy{ToolLimits: map[string]config.CallLimits{
		"demo_read": {Concurrency: 1},
	}})
	release, outcome = toolConcurrency.Admit("demo_read")
	if outcome != "" {
		t.Fatal(outcome)
	}
	if _, outcome := toolConcurrency.Admit("demo_read"); outcome != "tool_concurrency_limited" {
		t.Fatalf("tool concurrency outcome = %q", outcome)
	}
	release()
}
