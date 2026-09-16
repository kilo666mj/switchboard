package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/requestmeta"
)

var validName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type Manifest struct {
	Title       string                 `json:"title,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Risk        string                 `json:"risk,omitempty"`
	Version     int                    `json:"version"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	BaseURL     string                 `json:"base_url"`
	BaseURLEnv  string                 `json:"base_url_env,omitempty"`
	Headers     map[string]HeaderValue `json:"headers,omitempty"`
	Tools       []Tool                 `json:"tools"`
}

type HeaderValue struct {
	Env    string `json:"env"`
	Prefix string `json:"prefix,omitempty"`
}

type Tool struct {
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Safety         string            `json:"safety"`
	Idempotent     bool              `json:"idempotent,omitempty"`
	OpenWorld      bool              `json:"open_world,omitempty"`
	InputSchema    json.RawMessage   `json:"input_schema"`
	PathArguments  []string          `json:"path_arguments,omitempty"`
	QueryArguments map[string]string `json:"query_arguments,omitempty"`
	BodyArguments  []string          `json:"body_arguments,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

func (m *Manifest) Validate() error {
	if err := capability.ValidateRisk(m.Risk); err != nil {
		return err
	}
	if m.Version != 1 {
		return fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	if !validName.MatchString(m.Name) {
		return fmt.Errorf("invalid capability name %q", m.Name)
	}
	baseURL := m.BaseURL
	if m.BaseURLEnv != "" {
		if m.BaseURL != "" {
			return errors.New("set only one of base_url and base_url_env")
		}
		baseURL = os.Getenv(m.BaseURLEnv)
		if baseURL == "" {
			return fmt.Errorf("base URL environment variable %s is not set", m.BaseURLEnv)
		}
		m.BaseURL = baseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("invalid base URL %q", baseURL)
	}
	if parsed.Scheme != "https" && len(m.Headers) > 0 {
		return errors.New("credential-bearing REST capabilities require an HTTPS base URL")
	}
	if len(m.Tools) == 0 {
		return errors.New("at least one tool is required")
	}
	seen := map[string]bool{}
	for i := range m.Tools {
		tool := &m.Tools[i]
		if !validName.MatchString(tool.Name) {
			return fmt.Errorf("invalid tool name %q", tool.Name)
		}
		if seen[tool.Name] {
			return fmt.Errorf("duplicate tool name %q", tool.Name)
		}
		seen[tool.Name] = true
		tool.Method = strings.ToUpper(tool.Method)
		if tool.Method == "" {
			tool.Method = http.MethodGet
		}
		switch tool.Method {
		case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return fmt.Errorf("tool %q has unsupported HTTP method %q", tool.Name, tool.Method)
		}
		if tool.Safety != "read_only" && tool.Safety != "mutating" && tool.Safety != "destructive" {
			return fmt.Errorf("tool %q has invalid safety %q", tool.Name, tool.Safety)
		}
		if tool.Safety == "read_only" && tool.Method != http.MethodGet && tool.Method != http.MethodHead {
			return fmt.Errorf("tool %q declares read_only safety for %s", tool.Name, tool.Method)
		}
		if tool.Safety != "read_only" && (tool.Method == http.MethodGet || tool.Method == http.MethodHead) {
			return fmt.Errorf("tool %q declares %s safety for %s", tool.Name, tool.Safety, tool.Method)
		}
		if tool.Path == "" || !strings.HasPrefix(tool.Path, "/") {
			return fmt.Errorf("tool %q path must start with /", tool.Name)
		}
		var schema map[string]any
		if len(tool.InputSchema) == 0 || json.Unmarshal(tool.InputSchema, &schema) != nil || schema["type"] != "object" {
			return fmt.Errorf("tool %q input_schema must be a JSON object schema", tool.Name)
		}
		if tool.TimeoutSeconds < 0 || tool.TimeoutSeconds > int((5*time.Minute)/time.Second) {
			return fmt.Errorf("tool %q timeout_seconds must be between 0 and 300", tool.Name)
		}
	}
	return nil
}

func (m Manifest) ResolveHeaders() (http.Header, error) {
	headers := make(http.Header, len(m.Headers))
	for name, value := range m.Headers {
		if strings.EqualFold(name, requestmeta.CorrelationIDHeader) {
			return nil, fmt.Errorf("header %q is reserved for gateway correlation", requestmeta.CorrelationIDHeader)
		}
		if value.Env == "" {
			return nil, fmt.Errorf("header %q must reference an environment variable", name)
		}
		secret, ok := os.LookupEnv(value.Env)
		if !ok || secret == "" {
			return nil, fmt.Errorf("environment variable %s for header %q is not set", value.Env, name)
		}
		headers.Set(name, value.Prefix+secret)
	}
	return headers, nil
}
