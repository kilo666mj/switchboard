package remote

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/egress"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var validName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type Manifest struct {
	Title              string                  `json:"title,omitempty"`
	Description        string                  `json:"description,omitempty"`
	Tags               []string                `json:"tags,omitempty"`
	Risk               string                  `json:"risk,omitempty"`
	Version            int                     `json:"version"`
	Type               string                  `json:"type"`
	Name               string                  `json:"name"`
	Endpoint           string                  `json:"endpoint,omitempty"`
	EndpointEnv        string                  `json:"endpoint_env,omitempty"`
	HostEnv            string                  `json:"host_env,omitempty"`
	Headers            map[string]HeaderValue  `json:"headers,omitempty"`
	OAuth              *OAuthClientCredentials `json:"oauth_client_credentials,omitempty"`
	IncludeTools       []string                `json:"include_tools,omitempty"`
	AnnotationRules    []AnnotationRule        `json:"annotation_rules,omitempty"`
	InsecureSkipVerify bool                    `json:"insecure_skip_verify,omitempty"`
}

type AnnotationRule struct {
	Prefixes    []string            `json:"prefixes"`
	Annotations mcp.ToolAnnotations `json:"annotations"`
}

type OAuthClientCredentials struct {
	TokenURL        string                    `json:"token_url,omitempty"`
	TokenURLEnv     string                    `json:"token_url_env,omitempty"`
	ClientIDEnv     string                    `json:"client_id_env"`
	ClientSecretEnv string                    `json:"client_secret_env"`
	Scopes          []string                  `json:"scopes,omitempty"`
	AuthStyle       string                    `json:"auth_style,omitempty"`
	Parameters      map[string]ParameterValue `json:"parameters,omitempty"`
}

type ParameterValue struct {
	Value string `json:"value,omitempty"`
	Env   string `json:"env,omitempty"`
}

type HeaderValue struct {
	Env    string `json:"env"`
	Prefix string `json:"prefix,omitempty"`
}

type Capability struct {
	metadata capability.Metadata
	name     string
	session  *mcp.ClientSession
	tools    []toolBinding
}

type toolBinding struct {
	definition *mcp.Tool
	upstream   string
	schema     *jsonschema.Resolved
}

func New(ctx context.Context, manifest Manifest) (*Capability, error) {
	return NewWithEgress(ctx, manifest, nil)
}

func NewWithEgress(ctx context.Context, manifest Manifest, policy *egress.Policy) (*Capability, error) {
	if err := capability.ValidateRisk(manifest.Risk); err != nil {
		return nil, err
	}
	if manifest.Version != 1 || manifest.Type != "mcp" {
		return nil, fmt.Errorf("unsupported remote MCP manifest version or type")
	}
	if !validName.MatchString(manifest.Name) {
		return nil, fmt.Errorf("invalid capability name %q", manifest.Name)
	}
	endpoint := strings.TrimSpace(manifest.Endpoint)
	if manifest.EndpointEnv != "" {
		if endpoint != "" {
			return nil, errors.New("set only one of endpoint and endpoint_env")
		}
		endpoint = strings.TrimSpace(os.Getenv(manifest.EndpointEnv))
		if endpoint == "" {
			return nil, fmt.Errorf("endpoint environment variable %s is not set", manifest.EndpointEnv)
		}
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid MCP endpoint %q", endpoint)
	}
	if policy != nil {
		if manifest.InsecureSkipVerify {
			return nil, errors.New("insecure_skip_verify is prohibited by the egress policy")
		}
		if err := policy.ValidateURL(endpoint); err != nil {
			return nil, fmt.Errorf("%s MCP endpoint violates egress policy: %w", manifest.Name, err)
		}
	}
	host := ""
	if manifest.HostEnv != "" {
		host = strings.TrimSpace(os.Getenv(manifest.HostEnv))
		parsedHost, hostErr := url.Parse("//" + host)
		if host == "" || hostErr != nil || parsedHost.Host != host || parsedHost.User != nil || parsedHost.Path != "" {
			return nil, fmt.Errorf("invalid upstream Host environment variable %s", manifest.HostEnv)
		}
	}
	headers := make(http.Header, len(manifest.Headers))
	for name, value := range manifest.Headers {
		secret := os.Getenv(value.Env)
		if value.Env == "" || secret == "" {
			return nil, fmt.Errorf("environment variable %s for header %q is not set", value.Env, name)
		}
		headers.Set(name, value.Prefix+secret)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if policy != nil {
		transport = policy.Transport()
	}
	if manifest.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit per-capability operator setting
	}
	var roundTripper http.RoundTripper = headerTransport{base: transport, headers: headers, host: host}
	if manifest.OAuth != nil {
		if headers.Get("Authorization") != "" {
			return nil, errors.New("set only one of Authorization header and oauth_client_credentials")
		}
		oauthConfig, err := oauthConfig(*manifest.OAuth)
		if err != nil {
			return nil, err
		}
		if policy != nil {
			if err := policy.ValidateURL(oauthConfig.TokenURL); err != nil {
				return nil, fmt.Errorf("%s OAuth token URL violates egress policy: %w", manifest.Name, err)
			}
		}
		tokenContext := context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: rejectRedirect})
		roundTripper = &oauth2.Transport{Source: oauthConfig.TokenSource(tokenContext), Base: roundTripper}
	}
	httpClient := &http.Client{Timeout: 2 * time.Minute, Transport: roundTripper, CheckRedirect: rejectRedirect}
	client := mcp.NewClient(&mcp.Implementation{Name: "switchboard", Version: "dev"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: httpClient}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to %s MCP: %w", manifest.Name, err)
	}
	allowed := make(map[string]bool, len(manifest.IncludeTools))
	for _, name := range manifest.IncludeTools {
		allowed[name] = true
	}
	var tools []toolBinding
	for tool, listErr := range session.Tools(ctx, nil) {
		if listErr != nil {
			_ = session.Close()
			return nil, fmt.Errorf("list %s tools: %w", manifest.Name, listErr)
		}
		if len(manifest.IncludeTools) > 0 && !allowed[tool.Name] {
			continue
		}
		copy := *tool
		if len(manifest.AnnotationRules) > 0 {
			annotations, annotationErr := matchAnnotations(tool.Name, manifest.AnnotationRules)
			if annotationErr != nil {
				_ = session.Close()
				return nil, fmt.Errorf("%s tool %q: %w", manifest.Name, tool.Name, annotationErr)
			}
			copy.Annotations = annotations
		}
		copy.Name = exposedName(manifest.Name, tool.Name)
		tools = append(tools, toolBinding{definition: &copy, upstream: tool.Name, schema: resolveInputSchema(tool.InputSchema)})
		delete(allowed, tool.Name)
	}
	if len(allowed) > 0 {
		_ = session.Close()
		missing, _ := json.Marshal(allowed)
		return nil, fmt.Errorf("%s include_tools not offered upstream: %s", manifest.Name, missing)
	}
	if len(tools) == 0 {
		_ = session.Close()
		return nil, fmt.Errorf("%s MCP offered no selected tools", manifest.Name)
	}
	return &Capability{name: manifest.Name, session: session, tools: tools, metadata: capability.Metadata{Title: manifest.Title, Description: manifest.Description, Tags: manifest.Tags, Risk: manifest.Risk}}, nil
}

func matchAnnotations(name string, rules []AnnotationRule) (*mcp.ToolAnnotations, error) {
	var matched *mcp.ToolAnnotations
	for _, rule := range rules {
		for _, prefix := range rule.Prefixes {
			if prefix == "" {
				return nil, errors.New("annotation rule prefix must not be empty")
			}
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			if matched != nil {
				return nil, errors.New("matches more than one annotation rule")
			}
			annotations := rule.Annotations
			matched = &annotations
			break
		}
	}
	if matched == nil {
		return nil, errors.New("matches no annotation rule")
	}
	return matched, nil
}

func oauthConfig(manifest OAuthClientCredentials) (*clientcredentials.Config, error) {
	tokenURL := strings.TrimSpace(manifest.TokenURL)
	if manifest.TokenURLEnv != "" {
		if tokenURL != "" {
			return nil, errors.New("set only one of token_url and token_url_env")
		}
		tokenURL = strings.TrimSpace(os.Getenv(manifest.TokenURLEnv))
	}
	parsed, err := url.Parse(tokenURL)
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid OAuth token URL %q: HTTPS is required", tokenURL)
	}
	clientID := strings.TrimSpace(os.Getenv(manifest.ClientIDEnv))
	clientSecret := os.Getenv(manifest.ClientSecretEnv)
	if manifest.ClientIDEnv == "" || clientID == "" {
		return nil, fmt.Errorf("OAuth client ID environment variable %s is not set", manifest.ClientIDEnv)
	}
	if manifest.ClientSecretEnv == "" || clientSecret == "" {
		return nil, fmt.Errorf("OAuth client secret environment variable %s is not set", manifest.ClientSecretEnv)
	}
	config := &clientcredentials.Config{ClientID: clientID, ClientSecret: clientSecret, TokenURL: tokenURL, Scopes: manifest.Scopes}
	switch manifest.AuthStyle {
	case "", "auto":
	case "header":
		config.AuthStyle = oauth2.AuthStyleInHeader
	case "params":
		config.AuthStyle = oauth2.AuthStyleInParams
	default:
		return nil, fmt.Errorf("unsupported OAuth auth_style %q", manifest.AuthStyle)
	}
	config.EndpointParams = make(url.Values, len(manifest.Parameters))
	for name, parameter := range manifest.Parameters {
		value := parameter.Value
		if parameter.Env != "" {
			if value != "" {
				return nil, fmt.Errorf("OAuth parameter %q sets both value and env", name)
			}
			value = os.Getenv(parameter.Env)
		}
		if name == "" || value == "" {
			return nil, fmt.Errorf("OAuth parameter %q has no value", name)
		}
		config.EndpointParams.Set(name, value)
	}
	return config, nil
}

func (c *Capability) Name() string { return c.name }

func (c *Capability) Register(server *mcp.Server) error {
	for _, binding := range c.tools {
		tool := *binding.definition
		upstreamName := binding.upstream
		server.AddTool(&tool, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return c.session.CallTool(ctx, &mcp.CallToolParams{Name: upstreamName, Arguments: request.Params.Arguments})
		})
	}
	return nil
}

func (c *Capability) Close() error { return c.session.Close() }

func exposedName(capability, upstream string) string {
	if strings.HasPrefix(upstream, capability+"_") {
		return upstream
	}
	return capability + "_" + upstream
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

type headerTransport struct {
	base    http.RoundTripper
	headers http.Header
	host    string
}

func (t headerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	for name, values := range t.headers {
		for _, value := range values {
			clone.Header.Add(name, value)
		}
	}
	if t.host != "" {
		clone.Host = t.host
	}
	response, err := t.base.RoundTrip(clone)
	if err != nil {
		return nil, err
	}
	response.Body = &boundedBody{ReadCloser: response.Body, remaining: maxResponseBytes}
	return response, nil
}

func (c *Capability) Describe() capability.Description {
	d := capability.Description{Name: c.name, Metadata: c.metadata, Tools: []capability.ToolSummary{}}
	for _, binding := range c.tools {
		t := binding.definition
		d.Tools = append(d.Tools, capability.ToolSummary{Name: t.Name, Description: t.Description, Annotations: t.Annotations, InputSchema: t.InputSchema})
	}
	return d
}
