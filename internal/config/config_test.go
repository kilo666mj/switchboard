package config

import "testing"

func TestValidateProfile(t *testing.T) {
	t.Parallel()
	cfg := Config{Transport: "http", Profile: "read", Profiles: map[string][]string{"read": {"rilldns", "fleetglass"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsDuplicateCapability(t *testing.T) {
	t.Parallel()
	cfg := Config{Transport: "http", Profile: "read", Profiles: map[string][]string{"read": {"rilldns", "rilldns"}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate succeeded with a duplicate capability")
	}
}

func TestClientPolicyValidation(t *testing.T) {
	for _, client := range []Client{
		{TokenEnv: "TOKEN", Profile: "missing"},
		{Profile: "all"},
		{TokenEnv: "TOKEN", Profile: "all", InitialCapabilities: []string{"hidden"}},
		{TokenEnv: "TOKEN", Profile: "all", InitialCapabilities: []string{"demo", "demo"}},
	} {
		cfg := Config{Transport: "http", Profile: "all", Profiles: map[string][]string{"all": {"demo"}}, Clients: map[string]Client{"test": client}}
		if cfg.Validate() == nil {
			t.Fatalf("invalid client accepted: %+v", client)
		}
	}
}

func TestToolPolicyValidation(t *testing.T) {
	valid := Config{
		Transport: "http",
		Profile:   "read",
		Profiles:  map[string][]string{"read": {"demo"}},
		ToolPolicies: map[string]ToolPolicy{"pilot": {
			Version: "v1", Profile: "read", Capabilities: map[string]string{"demo": "allow"}, Tools: map[string]string{"demo_status": "deny"},
		}},
		Clients: map[string]Client{"alice": {TokenEnv: "TOKEN", Profile: "read", ToolPolicy: "pilot"}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, policy := range map[string]ToolPolicy{
		"missing-version":         {Profile: "read"},
		"missing-profile":         {Version: "v1", Profile: "missing"},
		"bad-decision":            {Version: "v1", Profile: "read", Tools: map[string]string{"demo_status": "maybe"}},
		"empty-tool":              {Version: "v1", Profile: "read", Tools: map[string]string{"": "allow"}},
		"unknown-capability":      {Version: "v1", Profile: "read", Capabilities: map[string]string{"other": "allow"}},
		"bad-capability-decision": {Version: "v1", Profile: "read", Capabilities: map[string]string{"demo": "maybe"}},
	} {
		cfg := valid
		cfg.Clients = nil
		cfg.ToolPolicies = map[string]ToolPolicy{name: policy}
		if cfg.Validate() == nil {
			t.Fatalf("invalid tool policy %q accepted", name)
		}
	}
}

func TestCloudflareAccessConfigurationValidation(t *testing.T) {
	valid := Config{
		Transport: "http", Profile: "read", Profiles: map[string][]string{"read": {"demo"}},
		ToolPolicies: map[string]ToolPolicy{"full": {Version: "v1", Profile: "read", Capabilities: map[string]string{"demo": "allow"}}},
		CloudflareAccess: &CloudflareAccessConfig{
			TeamDomain: "https://example.cloudflareaccess.com", Audience: "access-audience",
			Policies: map[string]OAuthPolicy{"people": {Version: "v1", Groups: []string{"people"}, Profile: "read", ToolPolicy: "full", Discover: true, Execute: true}},
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	if valid.StaticClientsEnabled() {
		t.Fatal("static clients enabled by default with Cloudflare Access")
	}
	valid.CloudflareAccess.AllowStaticClients = true
	if !valid.StaticClientsEnabled() {
		t.Fatal("explicit Cloudflare Access migration switch ignored")
	}
	for name, mutate := range map[string]func(*Config){
		"http-team-domain":    func(c *Config) { c.CloudflareAccess.TeamDomain = "http://example.cloudflareaccess.com" },
		"missing-audience":    func(c *Config) { c.CloudflareAccess.Audience = "" },
		"missing-policies":    func(c *Config) { c.CloudflareAccess.Policies = nil },
		"unknown-policy-mode": func(c *Config) { c.CloudflareAccess.PolicyMode = "merge" },
		"scoped-policy": func(c *Config) {
			p := c.CloudflareAccess.Policies["people"]
			p.RequiredScopes = []string{"tools:read"}
			c.CloudflareAccess.Policies["people"] = p
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			access := *valid.CloudflareAccess
			access.Policies = map[string]OAuthPolicy{}
			for policyName, policy := range valid.CloudflareAccess.Policies {
				access.Policies[policyName] = policy
			}
			cfg.CloudflareAccess = &access
			mutate(&cfg)
			if cfg.Validate() == nil {
				t.Fatal("invalid Cloudflare Access configuration accepted")
			}
		})
	}
}

func TestCallLimitValidation(t *testing.T) {
	for _, limits := range []*CallLimits{
		{RequestsPerMinute: 1},
		{Burst: 1},
		{RequestsPerMinute: -1, Burst: 1},
		{RequestsPerMinute: 1, Burst: 1, Concurrency: -1},
	} {
		cfg := Config{Transport: "http", Profile: "read", Profiles: map[string][]string{"read": {}}, Clients: map[string]Client{
			"alice": {TokenEnv: "TOKEN", Profile: "read", Limits: limits},
		}}
		if cfg.Validate() == nil {
			t.Fatalf("invalid limits accepted: %+v", limits)
		}
	}
	valid := Config{
		Transport: "http", Profile: "read", Profiles: map[string][]string{"read": {"demo"}},
		ToolPolicies: map[string]ToolPolicy{"pilot": {Version: "v1", Profile: "read", Tools: map[string]string{"demo_read": "allow"}, ToolLimits: map[string]CallLimits{"demo_read": {RequestsPerMinute: 60, Burst: 2, Concurrency: 1}}}},
		Clients:      map[string]Client{"alice": {TokenEnv: "TOKEN", Profile: "read", ToolPolicy: "pilot", Limits: &CallLimits{RequestsPerMinute: 120, Burst: 4, Concurrency: 2}}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthConfigurationValidation(t *testing.T) {
	valid := Config{
		Transport: "http", Profile: "read", Profiles: map[string][]string{"read": {"demo"}},
		ToolPolicies: map[string]ToolPolicy{"pilot": {Version: "v1", Profile: "read", Tools: map[string]string{"demo_read": "allow"}}},
		OAuth: &OAuthConfig{
			Issuer: "https://id.example.com", Resource: "https://switchboard.example.com/mcp/sessions",
			RequiredScopes: []string{"mcp:connect"},
			Policies: map[string]OAuthPolicy{"readers": {
				Version: "pilot-v1", Groups: []string{"switchboard-readers"}, Profile: "read", ToolPolicy: "pilot", Discover: true, Execute: true,
			}},
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	userInfo := valid
	userInfoOAuth := *valid.OAuth
	userInfoOAuth.RequiredScopes = []string{"openid", "mcp:connect"}
	userInfoOAuth.GroupSource = OAuthGroupSourceUserInfo
	userInfo.OAuth = &userInfoOAuth
	if err := userInfo.Validate(); err != nil {
		t.Fatalf("valid UserInfo group source rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"http-issuer":      func(c *Config) { c.OAuth.Issuer = "http://id.example.com" },
		"resource-no-path": func(c *Config) { c.OAuth.Resource = "https://switchboard.example.com" },
		"missing-scopes":   func(c *Config) { c.OAuth.RequiredScopes = nil },
		"missing-policies": func(c *Config) { c.OAuth.Policies = nil },
		"missing-version": func(c *Config) {
			p := c.OAuth.Policies["readers"]
			p.Version = ""
			c.OAuth.Policies["readers"] = p
		},
		"missing-matchers": func(c *Config) { p := c.OAuth.Policies["readers"]; p.Groups = nil; c.OAuth.Policies["readers"] = p },
		"bad-profile": func(c *Config) {
			p := c.OAuth.Policies["readers"]
			p.Profile = "missing"
			c.OAuth.Policies["readers"] = p
		},
		"bad-tool-policy": func(c *Config) {
			p := c.OAuth.Policies["readers"]
			p.ToolPolicy = "missing"
			c.OAuth.Policies["readers"] = p
		},
		"duplicate-scope":    func(c *Config) { c.OAuth.RequiredScopes = []string{"mcp:connect", "mcp:connect"} },
		"partial-token-type": func(c *Config) { c.OAuth.TokenTypeClaim = "type" },
		"invalid-jwt-type":   func(c *Config) { c.OAuth.JWTType = "at+jwt\n" },
		"invalid-group-source": func(c *Config) {
			c.OAuth.GroupSource = "id_token"
		},
		"userinfo-without-openid": func(c *Config) {
			c.OAuth.GroupSource = OAuthGroupSourceUserInfo
		},
		"bad-initial-cap": func(c *Config) {
			p := c.OAuth.Policies["readers"]
			p.InitialCapabilities = []string{"missing"}
			c.OAuth.Policies["readers"] = p
		},
		"stdio": func(c *Config) { c.Transport = "stdio" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			oauth := *valid.OAuth
			oauth.RequiredScopes = append([]string{}, valid.OAuth.RequiredScopes...)
			oauth.Policies = map[string]OAuthPolicy{}
			for policyName, policy := range valid.OAuth.Policies {
				oauth.Policies[policyName] = policy
			}
			cfg.OAuth = &oauth
			mutate(&cfg)
			if cfg.Validate() == nil {
				t.Fatal("invalid OAuth configuration accepted")
			}
		})
	}
}

func TestComposedIdentityPolicyValidation(t *testing.T) {
	valid := Config{
		Transport: "http", Profile: "all", Profiles: map[string][]string{"all": {"demo"}},
		ToolPolicies: map[string]ToolPolicy{
			"read":  {Version: "read-v1", Profile: "all", Tools: map[string]string{"demo_status": "allow"}},
			"write": {Version: "write-v1", Profile: "all", Tools: map[string]string{"demo_update": "allow"}},
		},
		OAuth: &OAuthConfig{
			Issuer: "https://id.example.com", Resource: "https://switchboard.example.com/mcp/sessions",
			RequiredScopes: []string{"mcp:connect"}, PolicyMode: IdentityPolicyModeComposed,
			Policies: map[string]OAuthPolicy{
				"readers": {Version: "v1", Groups: []string{"readers"}, Profile: "all", ToolPolicy: "read"},
				"writers": {Version: "v1", Groups: []string{"writers"}, Profile: "all", ToolPolicy: "write"},
			},
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"unknown-mode": func(c *Config) { c.OAuth.PolicyMode = "merge" },
		"missing-tool-policy": func(c *Config) {
			policy := c.OAuth.Policies["writers"]
			policy.ToolPolicy = ""
			c.OAuth.Policies["writers"] = policy
		},
		"mixed-profiles": func(c *Config) {
			c.Profiles["other"] = []string{"demo"}
			c.ToolPolicies["other"] = ToolPolicy{Version: "v1", Profile: "other", Tools: map[string]string{"demo_status": "allow"}}
			policy := c.OAuth.Policies["writers"]
			policy.Profile, policy.ToolPolicy = "other", "other"
			c.OAuth.Policies["writers"] = policy
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			cfg.Profiles = map[string][]string{"all": {"demo"}}
			cfg.ToolPolicies = map[string]ToolPolicy{}
			for key, value := range valid.ToolPolicies {
				cfg.ToolPolicies[key] = value
			}
			oauth := *valid.OAuth
			oauth.Policies = map[string]OAuthPolicy{}
			for key, value := range valid.OAuth.Policies {
				oauth.Policies[key] = value
			}
			cfg.OAuth = &oauth
			mutate(&cfg)
			if cfg.Validate() == nil {
				t.Fatal("invalid composed identity policy accepted")
			}
		})
	}
}
