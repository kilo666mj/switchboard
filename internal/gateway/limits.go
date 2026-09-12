package gateway

import (
	"github.com/kilo666mj/switchboard/internal/config"
	"golang.org/x/time/rate"
)

type callLimit struct {
	rate        *rate.Limiter
	concurrency chan struct{}
}

// CallController is shared by every session belonging to one authenticated
// identity. It therefore cannot be bypassed by creating additional sessions.
type CallController struct {
	identity *callLimit
	tools    map[string]*callLimit
}

func NewCallController(client config.Client, policy config.ToolPolicy) *CallController {
	controller := &CallController{identity: newCallLimit(client.Limits), tools: map[string]*callLimit{}}
	for tool, limits := range policy.ToolLimits {
		value := limits
		controller.tools[tool] = newCallLimit(&value)
	}
	if controller.identity == nil && len(controller.tools) == 0 {
		return nil
	}
	return controller
}

func newCallLimit(cfg *config.CallLimits) *callLimit {
	if cfg == nil || cfg.RequestsPerMinute == 0 && cfg.Concurrency == 0 {
		return nil
	}
	limit := new(callLimit)
	if cfg.RequestsPerMinute > 0 {
		limit.rate = rate.NewLimiter(rate.Limit(float64(cfg.RequestsPerMinute)/60), cfg.Burst)
	}
	if cfg.Concurrency > 0 {
		limit.concurrency = make(chan struct{}, cfg.Concurrency)
	}
	return limit
}

// Admit returns a release function on success, or a stable audit outcome on
// rejection. Rate tokens are deliberately not refunded after later rejection.
func (c *CallController) Admit(tool string) (func(), string) {
	if c == nil {
		return func() {}, ""
	}
	if !allowRate(c.identity) {
		return nil, "identity_rate_limited"
	}
	toolLimit := c.tools[tool]
	if !allowRate(toolLimit) {
		return nil, "tool_rate_limited"
	}
	identityRelease, ok := acquire(c.identity)
	if !ok {
		return nil, "identity_concurrency_limited"
	}
	toolRelease, ok := acquire(toolLimit)
	if !ok {
		identityRelease()
		return nil, "tool_concurrency_limited"
	}
	return func() {
		toolRelease()
		identityRelease()
	}, ""
}

func allowRate(limit *callLimit) bool {
	return limit == nil || limit.rate == nil || limit.rate.Allow()
}

func acquire(limit *callLimit) (func(), bool) {
	if limit == nil || limit.concurrency == nil {
		return func() {}, true
	}
	select {
	case limit.concurrency <- struct{}{}:
		return func() { <-limit.concurrency }, true
	default:
		return nil, false
	}
}
