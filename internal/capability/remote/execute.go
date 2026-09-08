package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxResponseBytes = 8 << 20

// ExecuteReadOnly uses the same curated bindings and established upstream session
// as native tools. No endpoint or upstream tool name is accepted from the caller.
func (c *Capability) ExecuteReadOnly(ctx context.Context, name string, arguments map[string]any) (*mcp.CallToolResult, error) {
	for _, binding := range c.tools {
		if binding.definition.Name != name {
			continue
		}
		a := binding.definition.Annotations
		if a == nil || !a.ReadOnlyHint || (a.DestructiveHint != nil && *a.DestructiveHint) {
			return nil, errors.New("compatibility execution requires an explicitly read-only, non-destructive tool")
		}
		if binding.schema == nil {
			return nil, errors.New("tool input schema cannot be validated for compatibility execution")
		}
		if arguments == nil {
			return nil, errors.New("arguments must be an object")
		}
		// Normalize numbers and nested Go values exactly as they will appear on the wire.
		data, err := json.Marshal(arguments)
		if err != nil {
			return nil, errors.New("arguments must be JSON")
		}
		var normalized any
		if err := json.Unmarshal(data, &normalized); err != nil {
			return nil, err
		}
		if err := binding.schema.Validate(normalized); err != nil {
			return nil, errors.New("arguments do not match the downstream input schema; consult capability_describe")
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		return c.session.CallTool(ctx, &mcp.CallToolParams{Name: binding.upstream, Arguments: arguments})
	}
	return nil, errors.New("tool is not available in this capability")
}

func resolveInputSchema(input any) *jsonschema.Resolved {
	data, err := json.Marshal(input)
	if err != nil {
		return nil
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil
	}
	if schema.Type != "object" {
		return nil
	}
	resolved, err := schema.Resolve(nil) // Never fetch external schema references.
	if err != nil {
		return nil
	}
	return resolved
}

// boundedBody rejects oversized JSON and SSE responses before the SDK can
// buffer an unbounded upstream payload. Closing still closes the real body.
type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(p)
	if int64(n) > b.remaining {
		return 0, fmt.Errorf("upstream response exceeds %d bytes", maxResponseBytes)
	}
	b.remaining -= int64(n)
	return n, err
}
