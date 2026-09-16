package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/egress"
	"github.com/kilo666mj/switchboard/internal/requestmeta"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxResponseBytes = 8 << 20

type Capability struct {
	manifest Manifest
	headers  http.Header
	client   *http.Client
}

func New(manifest Manifest) (*Capability, error) {
	return NewWithEgress(manifest, nil)
}

func NewWithEgress(manifest Manifest, policy *egress.Policy) (*Capability, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	if policy != nil {
		if err := policy.ValidateURL(manifest.BaseURL); err != nil {
			return nil, fmt.Errorf("%s base URL violates egress policy: %w", manifest.Name, err)
		}
	}
	headers, err := manifest.ResolveHeaders()
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	if policy != nil {
		client.Transport = policy.Transport()
	}
	return &Capability{manifest: manifest, headers: headers, client: client}, nil
}

func (c *Capability) Name() string { return c.manifest.Name }

func (c *Capability) Register(server *mcp.Server) error {
	for i := range c.manifest.Tools {
		definition := c.manifest.Tools[i]
		var schema map[string]any
		if err := json.Unmarshal(definition.InputSchema, &schema); err != nil {
			return err
		}
		tool := &mcp.Tool{
			Name:        c.manifest.Name + "_" + definition.Name,
			Description: definition.Description,
			InputSchema: schema,
			Annotations: annotations(definition),
		}
		mcp.AddTool(server, tool, func(ctx context.Context, _ *mcp.CallToolRequest, arguments map[string]any) (*mcp.CallToolResult, any, error) {
			result, err := c.call(ctx, definition, arguments)
			return result, nil, err
		})
	}
	return nil
}

func annotations(tool Tool) *mcp.ToolAnnotations {
	switch tool.Safety {
	case "read_only":
		return mcpkit.ReadOnly(tool.OpenWorld)
	case "destructive":
		return mcpkit.Destructive(tool.Idempotent, tool.OpenWorld)
	default:
		return mcpkit.Mutating(tool.Idempotent, tool.OpenWorld)
	}
}

func (c *Capability) call(ctx context.Context, tool Tool, arguments map[string]any) (*mcp.CallToolResult, error) {
	path := tool.Path
	consumed := map[string]bool{}
	for _, name := range tool.PathArguments {
		value, ok := arguments[name]
		if !ok {
			return nil, fmt.Errorf("missing path argument %q", name)
		}
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("path argument %q must be a string", name)
		}
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(text))
		consumed[name] = true
	}
	endpoint, err := url.Parse(strings.TrimRight(c.manifest.BaseURL, "/") + path)
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	for argument, parameter := range tool.QueryArguments {
		if value, ok := arguments[argument]; ok {
			query.Set(parameter, fmt.Sprint(value))
			consumed[argument] = true
		}
	}
	endpoint.RawQuery = query.Encode()

	var body io.Reader
	if tool.Method != http.MethodGet && tool.Method != http.MethodHead {
		payload := map[string]any{}
		if len(tool.BodyArguments) > 0 {
			for _, name := range tool.BodyArguments {
				if value, ok := arguments[name]; ok {
					payload[name] = value
				}
			}
		} else {
			for name, value := range arguments {
				if !consumed[name] {
					payload[name] = value
				}
			}
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	if tool.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(tool.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	request, err := http.NewRequestWithContext(ctx, tool.Method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	request.Header = c.headers.Clone()
	if correlationID := requestmeta.CorrelationID(ctx); correlationID != "" {
		request.Header.Set(requestmeta.CorrelationIDHeader, correlationID)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s API request failed: %w", c.manifest.Name, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("%s API response exceeds %d bytes", c.manifest.Name, maxResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("%s API returned %s: %s", c.manifest.Name, response.Status, strings.TrimSpace(string(data)))
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}, nil
}

func (c *Capability) Describe() capability.Description {
	m := c.manifest
	d := capability.Description{Name: m.Name, Metadata: capability.Metadata{Title: m.Title, Description: m.Description, Tags: m.Tags, Risk: m.Risk}, Tools: []capability.ToolSummary{}}
	for _, t := range m.Tools {
		d.Tools = append(d.Tools, capability.ToolSummary{Name: m.Name + "_" + t.Name, Description: t.Description, Annotations: annotations(t)})
	}
	return d
}
