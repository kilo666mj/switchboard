package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Clients             map[string]Client   `json:"clients,omitempty"`
	SessionLimit        int                 `json:"session_limit,omitempty"`
	SessionIdleSeconds  int                 `json:"session_idle_seconds,omitempty"`
	Listen              string              `json:"listen"`
	Transport           string              `json:"transport"`
	Profile             string              `json:"profile"`
	CapabilityDir       string              `json:"capability_dir"`
	Profiles            map[string][]string `json:"profiles"`
	TrustedOrigins      []string            `json:"trusted_origins,omitempty"`
	BehindLoopbackProxy bool                `json:"behind_loopback_proxy,omitempty"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8090"
	}
	if cfg.Transport == "" {
		cfg.Transport = "http"
	}
	if cfg.CapabilityDir == "" {
		cfg.CapabilityDir = "capabilities"
	}
	if !filepath.IsAbs(cfg.CapabilityDir) {
		cfg.CapabilityDir = filepath.Join(filepath.Dir(path), cfg.CapabilityDir)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Transport != "http" && c.Transport != "stdio" {
		return fmt.Errorf("transport must be http or stdio, got %q", c.Transport)
	}
	if strings.TrimSpace(c.Profile) == "" {
		return errors.New("profile is required")
	}
	_, ok := c.Profiles[c.Profile]
	if !ok {
		return fmt.Errorf("profile %q is not defined", c.Profile)
	}
	for profile, selected := range c.Profiles {
		seen := make(map[string]bool, len(selected))
		for _, name := range selected {
			if name == "" {
				return fmt.Errorf("profile %q contains an empty capability name", profile)
			}
			if seen[name] {
				return fmt.Errorf("profile %q contains duplicate capability %q", profile, name)
			}
			seen[name] = true
		}
	}
	if len(c.Clients) > 0 && c.Transport != "http" {
		return errors.New("client identities require HTTP transport")
	}
	if c.SessionLimit < 0 || c.SessionLimit > 4096 {
		return errors.New("session_limit must be between 0 and 4096")
	}
	if c.SessionIdleSeconds < 0 || c.SessionIdleSeconds > 86400 {
		return errors.New("session_idle_seconds must be between 0 and 86400")
	}
	for name, client := range c.Clients {
		if strings.TrimSpace(name) == "" || client.TokenEnv == "" {
			return errors.New("client name and token_env are required")
		}
		allowed, ok := c.Profiles[client.Profile]
		if !ok {
			return fmt.Errorf("client %q references undefined profile", name)
		}
		seen := map[string]bool{}
		for _, n := range allowed {
			seen[n] = true
		}
		defaults := map[string]bool{}
		for _, n := range client.InitialCapabilities {
			if !seen[n] || defaults[n] {
				return fmt.Errorf("client %q has invalid initial capability %q", name, n)
			}
			defaults[n] = true
		}
	}
	return nil
}

// Client policy is supplied by the operator, never by tool arguments.
type Client struct {
	TokenEnv            string   `json:"token_env"`
	Profile             string   `json:"profile"`
	InitialCapabilities []string `json:"initial_capabilities"`
	Discover            bool     `json:"discover"`
	Execute             bool     `json:"execute"`
	Activate            bool     `json:"activate"`
}
