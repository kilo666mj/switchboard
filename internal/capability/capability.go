package capability

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Capability interface {
	Name() string
	Register(*mcp.Server) error
}

type Closer interface {
	Close() error
}

// ReadOnlyExecutor is implemented by remote MCP capabilities that support the
// compatibility path. Implementations enforce tool-level safety and schemas.
type ReadOnlyExecutor interface {
	ExecuteReadOnly(context.Context, string, map[string]any) (*mcp.CallToolResult, error)
}
