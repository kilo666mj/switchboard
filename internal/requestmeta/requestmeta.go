package requestmeta

import "context"

// CorrelationIDHeader carries the gateway-generated identifier to HTTP upstreams.
// Capability manifests cannot override this header.
const CorrelationIDHeader = "X-Switchboard-Correlation-ID"

type correlationIDKey struct{}

// WithCorrelationID binds a gateway-generated identifier to one tool call.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, correlationIDKey{}, id)
}

// CorrelationID returns the identifier bound to the current tool call.
func CorrelationID(ctx context.Context) string {
	id, _ := ctx.Value(correlationIDKey{}).(string)
	return id
}
