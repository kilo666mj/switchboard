package gateway

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/recommend"
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

type recommendInput struct {
	Request string `json:"request" jsonschema:"User request to route. It is sent only to the configured private decision service."`
	Limit   int    `json:"limit,omitempty" jsonschema:"Maximum ranked candidates to return; defaults to 5, maximum 20."`
}

type rankedCapability struct {
	catalogSummary
	Probability float64 `json:"probability"`
}

type recommendOutput struct {
	Choice        string             `json:"choice"`
	Probabilities map[string]float64 `json:"probabilities"`
	Confidence    float64            `json:"confidence"`
	LowConfidence bool               `json:"low_confidence"`
	Fallback      string             `json:"fallback,omitempty"`
	Candidates    []rankedCapability `json:"candidates"`
	Model         string             `json:"model,omitempty"`
	Usage         recommend.Usage    `json:"usage"`
	Timings       recommend.Timings  `json:"timings"`
}

func registerCatalog(server *mcp.Server, items []capability.Capability, policy config.ToolPolicy, recommenders ...recommend.Service) {
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
		if len(d.Tools) == 0 {
			continue
		}
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
	if len(recommenders) == 0 || recommenders[0] == nil {
		return
	}
	recommender := recommenders[0]
	candidates := make([]recommend.Candidate, 0, len(entries))
	byName := make(map[string]capability.Description, len(entries))
	for _, entry := range entries {
		tools := make([]string, 0, len(entry.Tools))
		for _, tool := range entry.Tools {
			tools = append(tools, tool.Name)
		}
		candidates = append(candidates, recommend.Candidate{Name: entry.Name, Title: entry.Title, Description: entry.Description, Tags: entry.Tags, Tools: tools})
		byName[entry.Name] = entry
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "capability_recommend",
		Description: "Rank capabilities already allowed by the authenticated profile using the configured private decision service. Recommendation-only: never enables or executes a capability. If low_confidence is true, use capability_search or ask the user instead.",
		Annotations: mcpkit.ReadOnly(false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input recommendInput) (*mcp.CallToolResult, recommendOutput, error) {
		if input.Limit < 0 || input.Limit > 20 {
			return nil, recommendOutput{}, fmt.Errorf("limit must be between 0 and 20")
		}
		if input.Limit == 0 {
			input.Limit = 5
		}
		result, err := recommender.Recommend(ctx, input.Request, candidates)
		if err != nil {
			return nil, recommendOutput{}, err
		}
		ranked := make([]rankedCapability, 0, len(result.Probabilities))
		for name, probability := range result.Probabilities {
			entry, ok := byName[name]
			if !ok {
				return nil, recommendOutput{}, fmt.Errorf("recommender returned unavailable capability %q", name)
			}
			ranked = append(ranked, rankedCapability{catalogSummary: catalogSummary{Metadata: entry.Metadata, Name: entry.Name, ToolCount: len(entry.Tools)}, Probability: probability})
		}
		sort.Slice(ranked, func(i, j int) bool {
			if ranked[i].Probability != ranked[j].Probability {
				return ranked[i].Probability > ranked[j].Probability
			}
			return ranked[i].Name < ranked[j].Name
		})
		if len(ranked) > input.Limit {
			ranked = ranked[:input.Limit]
		}
		output := recommendOutput{
			Choice: result.Choice, Probabilities: result.Probabilities, Confidence: result.Confidence, LowConfidence: result.LowConfidence,
			Candidates: ranked, Model: result.Model, Usage: result.Usage, Timings: result.Timings,
		}
		if result.LowConfidence {
			output.Fallback = "capability_search"
		}
		return nil, output, nil
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
