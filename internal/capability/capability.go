package capability

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ErrUnavailable marks a capability startup failure caused by an upstream or
// local MCP process that may recover without a configuration change. Callers
// may keep serving other capabilities and retry these failures.
var ErrUnavailable = errors.New("capability unavailable")

type Capability interface {
	Name() string
	Register(*mcp.Server) error
}

type Closer interface {
	Close() error
}

// OAuthSubjectBinder returns a session-local capability view that can pass the
// already verified OAuth subject to a specifically configured upstream. Static
// clients and other identity sources are never bound through this interface.
type OAuthSubjectBinder interface {
	BindOAuthSubject(string) (Capability, error)
}

// SessionIdentityBinder returns a session-local capability view that may pass
// Switchboard's server-issued inbound session identity to an opted-in upstream.
type SessionIdentityBinder interface {
	BindSessionIdentity(string) (Capability, error)
}

// ReadOnlyExecutor is implemented by remote MCP capabilities that support the
// compatibility path. Implementations enforce tool-level safety and schemas.
type ReadOnlyExecutor interface {
	ExecuteReadOnly(context.Context, string, map[string]any) (*mcp.CallToolResult, error)
}
