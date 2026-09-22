package main

import (
	"math"
	"testing"
)

func TestEntropyConfidence(t *testing.T) {
	for name, test := range map[string]struct {
		probabilities map[string]float64
		want          float64
	}{
		"certain": {map[string]float64{"a": 1, "b": 0}, 1},
		"uniform": {map[string]float64{"a": 0.5, "b": 0.5}, 0},
		"single":  {map[string]float64{"a": 1}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if got := entropyConfidence(test.probabilities); math.Abs(got-test.want) > 1e-12 {
				t.Fatalf("confidence = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSummarizeDecisionIncludesExpectedAbstentions(t *testing.T) {
	cases := []benchmarkCase{
		{ID: "right", Expected: "dns"},
		{ID: "abstain", ExpectAbstain: true},
		{ID: "confident-error", Expected: "dns"},
	}
	results := []caseResult{
		{ID: "right", Correct: true, Top3: true, LatencyNS: 10},
		{ID: "abstain", Correct: true, Abstained: true, LatencyNS: 20},
		{ID: "confident-error", ConfidentError: true, LatencyNS: 30},
	}
	report := summarizeDecision(results, cases)
	if report.Cases != 3 || report.RoutableCases != 2 || report.ExpectedAbstentions != 1 {
		t.Fatalf("case counts = %+v", report)
	}
	if report.Top1Correct != 2 || report.Top1Accuracy != 2.0/3 || report.Top3Coverage != 0.5 {
		t.Fatalf("accuracy = %+v", report)
	}
	if report.ConfidentErrors != 1 || report.ConfidentErrorRate != 1.0/3 {
		t.Fatalf("confident errors = %+v", report)
	}
	if report.ColdLatencyNS != 10 || report.MedianLatencyNS != 30 || report.P95LatencyNS != 30 {
		t.Fatalf("latencies = %+v", report)
	}
}
