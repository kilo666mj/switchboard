package capability

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Metadata contains only operator-authored, non-secret catalog fields.
type Metadata struct {
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Risk        string   `json:"risk"`
}

type ToolSummary struct {
	InputSchema any                  `json:"input_schema,omitempty"`
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	Annotations *mcp.ToolAnnotations `json:"annotations,omitempty"`
}

type Description struct {
	Metadata
	Name  string        `json:"name"`
	Tools []ToolSummary `json:"tools"`
}

// Describer is optional so specialized capabilities can adopt discovery incrementally.
type Describer interface{ Describe() Description }

func ValidateRisk(risk string) error {
	switch risk {
	case "", "unknown", "read_only", "mutating", "destructive":
		return nil
	default:
		return fmt.Errorf("invalid capability risk %q", risk)
	}
}
