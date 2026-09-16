// Package module adapts independently packaged stdio MCP processes into
// Switchboard capabilities.
package module

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/egress"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	egressPolicyEnv = "SWITCHBOARD_MODULE_EGRESS_POLICY"
	moduleNameEnv   = "SWITCHBOARD_MODULE_NAME"
)

var (
	validName    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	validEnvName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// Manifest describes a reviewed local module executable. Environment contains
// names only; values are resolved from the Switchboard process at startup and
// never belong in the manifest.
type Manifest struct {
	Title               string   `json:"title,omitempty"`
	Description         string   `json:"description,omitempty"`
	Tags                []string `json:"tags,omitempty"`
	Risk                string   `json:"risk,omitempty"`
	Version             int      `json:"version"`
	Type                string   `json:"type"`
	Name                string   `json:"name"`
	Command             string   `json:"command"`
	Arguments           []string `json:"arguments,omitempty"`
	Environment         []string `json:"environment,omitempty"`
	EnforceEgressPolicy bool     `json:"enforce_egress_policy,omitempty"`
	IncludeTools        []string `json:"include_tools,omitempty"`
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
}

func New(ctx context.Context, manifest Manifest, policy *egress.Policy) (*Capability, error) {
	if err := validateManifest(manifest, policy); err != nil {
		return nil, err
	}
	environment, err := resolveEnvironment(manifest, policy)
	if err != nil {
		return nil, err
	}
	command := exec.Command(manifest.Command, manifest.Arguments...)
	command.Dir = filepath.Dir(manifest.Command)
	command.Env = environment
	command.Stderr = os.Stderr

	client := mcp.NewClient(&mcp.Implementation{Name: "switchboard", Version: "dev"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: start %s module: %v", capability.ErrUnavailable, manifest.Name, err)
	}
	allowed := make(map[string]bool, len(manifest.IncludeTools))
	for _, name := range manifest.IncludeTools {
		if name == "" || allowed[name] {
			_ = session.Close()
			return nil, fmt.Errorf("invalid duplicate or empty include_tools entry %q", name)
		}
		allowed[name] = true
	}
	var tools []toolBinding
	for tool, listErr := range session.Tools(ctx, nil) {
		if listErr != nil {
			_ = session.Close()
			return nil, fmt.Errorf("%w: list %s module tools: %v", capability.ErrUnavailable, manifest.Name, listErr)
		}
		if len(manifest.IncludeTools) > 0 && !allowed[tool.Name] {
			continue
		}
		copy := *tool
		copy.Name = exposedName(manifest.Name, tool.Name)
		tools = append(tools, toolBinding{definition: &copy, upstream: tool.Name})
		delete(allowed, tool.Name)
	}
	if len(allowed) > 0 {
		_ = session.Close()
		missing, _ := json.Marshal(allowed)
		return nil, fmt.Errorf("%s module include_tools not offered: %s", manifest.Name, missing)
	}
	if len(tools) == 0 {
		_ = session.Close()
		return nil, fmt.Errorf("%s module offered no selected tools", manifest.Name)
	}
	return &Capability{
		name:    manifest.Name,
		session: session,
		tools:   tools,
		metadata: capability.Metadata{
			Title: manifest.Title, Description: manifest.Description,
			Tags: manifest.Tags, Risk: manifest.Risk,
		},
	}, nil
}

func validateManifest(manifest Manifest, policy *egress.Policy) error {
	if manifest.Version != 1 || manifest.Type != "module" {
		return errors.New("unsupported module manifest version or type")
	}
	if !validName.MatchString(manifest.Name) {
		return fmt.Errorf("invalid capability name %q", manifest.Name)
	}
	if err := capability.ValidateRisk(manifest.Risk); err != nil {
		return err
	}
	if !filepath.IsAbs(manifest.Command) || filepath.Clean(manifest.Command) != manifest.Command {
		return errors.New("module command must be a clean absolute path")
	}
	info, err := os.Lstat(manifest.Command)
	if err != nil {
		return fmt.Errorf("inspect module command: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("module command must be a non-group-writable, non-world-writable executable regular file")
	}
	if policy != nil && !manifest.EnforceEgressPolicy {
		return errors.New("module must declare enforce_egress_policy when the global egress policy is configured")
	}
	seen := map[string]bool{}
	for _, name := range manifest.Environment {
		if !validEnvName.MatchString(name) || strings.HasPrefix(name, "SWITCHBOARD_MODULE_") {
			return fmt.Errorf("invalid or reserved module environment name %q", name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate module environment name %q", name)
		}
		seen[name] = true
	}
	for _, argument := range manifest.Arguments {
		if strings.IndexByte(argument, 0) >= 0 {
			return errors.New("module argument contains a NUL byte")
		}
	}
	return nil
}

func resolveEnvironment(manifest Manifest, policy *egress.Policy) ([]string, error) {
	environment := []string{"LANG=C.UTF-8", moduleNameEnv + "=" + manifest.Name}
	for _, name := range manifest.Environment {
		value, ok := os.LookupEnv(name)
		if !ok || value == "" {
			return nil, fmt.Errorf("module environment variable %s is not set", name)
		}
		environment = append(environment, name+"="+value)
	}
	if policy != nil {
		encoded, err := json.Marshal(policy.Configuration())
		if err != nil {
			return nil, fmt.Errorf("encode module egress policy: %w", err)
		}
		environment = append(environment, egressPolicyEnv+"="+string(encoded))
	}
	return environment, nil
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

func (c *Capability) Describe() capability.Description {
	description := capability.Description{Name: c.name, Metadata: c.metadata, Tools: []capability.ToolSummary{}}
	for _, binding := range c.tools {
		tool := binding.definition
		description.Tools = append(description.Tools, capability.ToolSummary{
			Name: tool.Name, Description: tool.Description,
			Annotations: tool.Annotations, InputSchema: tool.InputSchema,
		})
	}
	return description
}

func exposedName(name, upstream string) string {
	if strings.HasPrefix(upstream, name+"_") {
		return upstream
	}
	return name + "_" + upstream
}
