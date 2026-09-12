package gateway

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type searchInput struct {
	Query string   `json:"query,omitempty" jsonschema:"Case-insensitive text; all words must match name, title, description, or tags."`
	Tags  []string `json:"tags,omitempty" jsonschema:"Require all of these tags (case-insensitive exact matches)."`
	Limit int      `json:"limit,omitempty" jsonschema:"Maximum results; defaults to 20, maximum 100."`
}

type catalogSummary struct {
	capability.Metadata
	Name      string `json:"name"`
	ToolCount int    `json:"tool_count"`
}

type searchOutput struct {
	Capabilities []catalogSummary `json:"capabilities"`
	Total        int              `json:"total"`
}

func registerCatalog(server *mcp.Server, items []capability.Capability, policy config.ToolPolicy) {
	entries := make([]capability.Description, 0, len(items))
	for _, item := range items {
		d := capability.Description{Name: item.Name(), Tools: []capability.ToolSummary{}}
		if describer, ok := item.(capability.Describer); ok {
			d = describer.Describe()
		}
		d.Name = item.Name()
		if d.Risk == "" {
			d.Risk = "unknown"
		}
		if d.Title == "" {
			d.Title = d.Name
		}
		visible := make([]capability.ToolSummary, 0, len(d.Tools))
		for _, tool := range d.Tools {
			if toolVisible(policy, d.Name, tool.Name) {
				visible = append(visible, tool)
			}
		}
		d.Tools = visible
		sort.Slice(d.Tools, func(i, j int) bool { return d.Tools[i].Name < d.Tools[j].Name })
		entries = append(entries, d)
	}
	mcp.AddTool(server, &mcp.Tool{Name: "capability_search", Description: "Search capabilities allowed by the active profile. Returns public metadata only; does not enable capabilities or change authority.", Annotations: mcpkit.ReadOnly(false)},
		func(_ context.Context, _ *mcp.CallToolRequest, input searchInput) (*mcp.CallToolResult, searchOutput, error) {
			output, err := searchCatalog(entries, input)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "capability_describe", Description: "Describe an exact capability name allowed by the active profile, including exposed tool names, descriptions, and safety annotations. Risk metadata is descriptive, not authorization. Use tools/list for native schemas.", Annotations: mcpkit.ReadOnly(false)},
		func(_ context.Context, _ *mcp.CallToolRequest, input struct {
			Name string `json:"name"`
		}) (*mcp.CallToolResult, capability.Description, error) {
			for _, d := range entries {
				if d.Name == input.Name {
					return nil, d, nil
				}
			}
			return nil, capability.Description{}, fmt.Errorf("capability is not available in the active profile")
		})
}

func searchCatalog(entries []capability.Description, input searchInput) (searchOutput, error) {
	output := searchOutput{Capabilities: []catalogSummary{}}
	if input.Limit < 0 || input.Limit > 100 {
		return output, fmt.Errorf("limit must be between 0 and 100")
	}
	if input.Limit == 0 {
		input.Limit = 20
	}
	type match struct {
		entry capability.Description
		score int
	}
	matches := []match{}
	for _, d := range entries {
		tags := make(map[string]bool)
		for _, tag := range d.Tags {
			tags[strings.ToLower(strings.TrimSpace(tag))] = true
		}
		allowed := true
		for _, tag := range input.Tags {
			if !tags[strings.ToLower(strings.TrimSpace(tag))] {
				allowed = false
			}
		}
		if !allowed {
			continue
		}
		score := 0
		for _, word := range strings.Fields(strings.ToLower(input.Query)) {
			switch {
			case strings.ToLower(d.Name) == word:
				score += 100
			case strings.Contains(strings.ToLower(d.Name), word):
				score += 50
			case strings.Contains(strings.ToLower(d.Title), word):
				score += 30
			case tags[word]:
				score += 20
			case strings.Contains(strings.ToLower(d.Description+" "+strings.Join(d.Tags, " ")), word):
				score += 10
			default:
				allowed = false
			}
		}
		if allowed {
			matches = append(matches, match{d, score})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return matches[i].entry.Name < matches[j].entry.Name
	})
	output.Total = len(matches)
	for i, m := range matches {
		if i >= input.Limit {
			break
		}
		output.Capabilities = append(output.Capabilities, catalogSummary{Metadata: m.entry.Metadata, Name: m.entry.Name, ToolCount: len(m.entry.Tools)})
	}
	return output, nil
}
