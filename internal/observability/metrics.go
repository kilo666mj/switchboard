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
	policyHashes     map[string]uint64
	capabilities     map[string]bool
	loadFailures     map[string]uint64
	authFailures     atomic.Uint64
	userInfoFailures atomic.Uint64
	authzFailures    atomic.Uint64
	capacityFailures atomic.Uint64
	activeSessions   atomic.Int64
}

func NewMetrics() *Metrics {
	return &Metrics{calls: map[callKey]callSample{}, policyHashes: map[string]uint64{}, capabilities: map[string]bool{}, loadFailures: map[string]uint64{}}
}

func (m *Metrics) SetCapabilityAvailable(name string, available bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.capabilities[name] = available
	m.mu.Unlock()
}

func (m *Metrics) CapabilityLoadFailure(name string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.loadFailures[name]++
	m.mu.Unlock()
}

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

func (m *Metrics) UserInfoFailure() {
	if m != nil {
		m.userInfoFailures.Add(1)
	}
}

// ObserveIdentityPolicy exposes the first 52 bits of a composed policy digest.
// That fits exactly in Prometheus's float64 sample value, allowing changes for
// the same component set to be detected across process restarts without an
// identity or full policy hash label.
func (m *Metrics) ObserveIdentityPolicy(components []string, version string) {
	if m == nil || len(components) == 0 || !strings.HasPrefix(version, "sha256:") {
		return
	}
	digest := strings.TrimPrefix(version, "sha256:")
	if len(digest) < 13 {
		return
	}
	value, err := strconv.ParseUint(digest[:13], 16, 64)
	if err != nil {
		return
	}
	key := strings.Join(components, ",")
	m.mu.Lock()
	m.policyHashes[key] = value
	m.mu.Unlock()
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
	policyComponents := make([]string, 0, len(m.policyHashes))
	policyHashes := make(map[string]uint64, len(m.policyHashes))
	for components, hash := range m.policyHashes {
		policyComponents = append(policyComponents, components)
		policyHashes[components] = hash
	}
	capabilityNames := make([]string, 0, len(m.capabilities))
	capabilities := make(map[string]bool, len(m.capabilities))
	loadFailures := make(map[string]uint64, len(m.loadFailures))
	for name, available := range m.capabilities {
		capabilityNames = append(capabilityNames, name)
		capabilities[name] = available
		loadFailures[name] = m.loadFailures[name]
	}
	m.mu.Unlock()
	sort.Strings(policyComponents)
	sort.Strings(capabilityNames)
	var output strings.Builder
	output.WriteString("# TYPE switchboard_authentication_failures_total counter\n")
	fmt.Fprintf(&output, "switchboard_authentication_failures_total %d\n", m.authFailures.Load())
	output.WriteString("# TYPE switchboard_oauth_userinfo_failures_total counter\n")
	fmt.Fprintf(&output, "switchboard_oauth_userinfo_failures_total %d\n", m.userInfoFailures.Load())
	output.WriteString("# TYPE switchboard_authorization_failures_total counter\n")
	fmt.Fprintf(&output, "switchboard_authorization_failures_total %d\n", m.authzFailures.Load())
	output.WriteString("# TYPE switchboard_session_capacity_rejections_total counter\n")
	fmt.Fprintf(&output, "switchboard_session_capacity_rejections_total %d\n", m.capacityFailures.Load())
	output.WriteString("# TYPE switchboard_sessions_active gauge\n")
	fmt.Fprintf(&output, "switchboard_sessions_active %d\n", m.activeSessions.Load())
	output.WriteString("# TYPE switchboard_capability_available gauge\n")
	output.WriteString("# TYPE switchboard_capability_load_failures_total counter\n")
	for _, name := range capabilityNames {
		available := 0
		if capabilities[name] {
			available = 1
		}
		fmt.Fprintf(&output, "switchboard_capability_available{capability=%s} %d\n", strconv.Quote(name), available)
		fmt.Fprintf(&output, "switchboard_capability_load_failures_total{capability=%s} %d\n", strconv.Quote(name), loadFailures[name])
	}
	output.WriteString("# TYPE switchboard_identity_policy_hash gauge\n")
	for _, components := range policyComponents {
		fmt.Fprintf(&output, "switchboard_identity_policy_hash{components=%s} %d\n", strconv.Quote(components), policyHashes[components])
	}
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
