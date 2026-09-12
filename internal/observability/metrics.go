package observability

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type callKey struct {
	capability string
	tool       string
	decision   string
	outcome    string
}

type callSample struct {
	count    uint64
	duration time.Duration
}

type Metrics struct {
	mu               sync.Mutex
	calls            map[callKey]callSample
	authFailures     atomic.Uint64
	authzFailures    atomic.Uint64
	capacityFailures atomic.Uint64
	activeSessions   atomic.Int64
}

func NewMetrics() *Metrics { return &Metrics{calls: map[callKey]callSample{}} }

func (m *Metrics) ObserveToolCall(capability, tool, decision, outcome string, duration time.Duration) {
	if m == nil {
		return
	}
	key := callKey{capability, tool, decision, outcome}
	m.mu.Lock()
	sample := m.calls[key]
	sample.count++
	sample.duration += duration
	m.calls[key] = sample
	m.mu.Unlock()
}

func (m *Metrics) AuthenticationFailure() {
	if m != nil {
		m.authFailures.Add(1)
	}
}

func (m *Metrics) AuthorizationFailure() {
	if m != nil {
		m.authzFailures.Add(1)
	}
}

func (m *Metrics) SessionCapacityFailure() {
	if m != nil {
		m.capacityFailures.Add(1)
	}
}

func (m *Metrics) SessionOpened() {
	if m != nil {
		m.activeSessions.Add(1)
	}
}

func (m *Metrics) SessionClosed() {
	if m != nil {
		m.activeSessions.Add(-1)
	}
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m.mu.Lock()
	keys := make([]callKey, 0, len(m.calls))
	for key := range m.calls {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j])
	})
	samples := make(map[callKey]callSample, len(m.calls))
	for key, sample := range m.calls {
		samples[key] = sample
	}
	m.mu.Unlock()
	var output strings.Builder
	output.WriteString("# TYPE switchboard_authentication_failures_total counter\n")
	fmt.Fprintf(&output, "switchboard_authentication_failures_total %d\n", m.authFailures.Load())
	output.WriteString("# TYPE switchboard_authorization_failures_total counter\n")
	fmt.Fprintf(&output, "switchboard_authorization_failures_total %d\n", m.authzFailures.Load())
	output.WriteString("# TYPE switchboard_session_capacity_rejections_total counter\n")
	fmt.Fprintf(&output, "switchboard_session_capacity_rejections_total %d\n", m.capacityFailures.Load())
	output.WriteString("# TYPE switchboard_sessions_active gauge\n")
	fmt.Fprintf(&output, "switchboard_sessions_active %d\n", m.activeSessions.Load())
	output.WriteString("# TYPE switchboard_tool_calls_total counter\n")
	output.WriteString("# TYPE switchboard_tool_call_duration_seconds summary\n")
	for _, key := range keys {
		sample := samples[key]
		labels := fmt.Sprintf("capability=%s,tool=%s,decision=%s,outcome=%s", strconv.Quote(key.capability), strconv.Quote(key.tool), strconv.Quote(key.decision), strconv.Quote(key.outcome))
		fmt.Fprintf(&output, "switchboard_tool_calls_total{%s} %d\n", labels, sample.count)
		fmt.Fprintf(&output, "switchboard_tool_call_duration_seconds_sum{%s} %g\n", labels, sample.duration.Seconds())
		fmt.Fprintf(&output, "switchboard_tool_call_duration_seconds_count{%s} %d\n", labels, sample.count)
	}
	_, _ = w.Write([]byte(output.String()))
}
