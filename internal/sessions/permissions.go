package sessions

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kilo666mj/switchboard/internal/auth"
	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/gateway"
)

const (
	PermissionProviderOAuth            = "oauth"
	PermissionProviderCloudflareAccess = "cloudflare_access"
	PermissionProviderStatic           = "static"
)

// PermissionInspectionInput describes either a simulated verified identity or
// an exact configured policy/client selection. It never accepts credentials.
type PermissionInspectionInput struct {
	Provider string
	Subject  string
	Groups   []string
	Scopes   []string
	Policies []string
	Client   string
}

type PermissionInspection struct {
	Status                    string                 `json:"status"`
	Provider                  string                 `json:"provider"`
	Subject                   string                 `json:"subject,omitempty"`
	Groups                    []string               `json:"groups,omitempty"`
	Scopes                    []string               `json:"scopes,omitempty"`
	MatchedPolicies           []string               `json:"matched_policies,omitempty"`
	MissingScopes             []string               `json:"missing_scopes,omitempty"`
	EffectivePolicy           string                 `json:"effective_policy,omitempty"`
	EffectivePolicyVersion    string                 `json:"effective_policy_version,omitempty"`
	Profile                   string                 `json:"profile,omitempty"`
	Discover                  bool                   `json:"discover"`
	Execute                   bool                   `json:"execute"`
	Activate                  bool                   `json:"activate"`
	InitialCapabilities       []string               `json:"initial_capabilities,omitempty"`
	AllAllowedInitiallyActive bool                   `json:"all_allowed_initially_active"`
	Limits                    *config.CallLimits     `json:"limits,omitempty"`
	Capabilities              []PermissionCapability `json:"capabilities,omitempty"`
	UnavailableCapabilities   []string               `json:"unavailable_capabilities,omitempty"`
}

type PermissionCapability struct {
	Name      string           `json:"name"`
	Available bool             `json:"available"`
	Active    bool             `json:"active"`
	Tools     []PermissionTool `json:"tools,omitempty"`
}

type PermissionTool struct {
	Name     string             `json:"name"`
	Decision string             `json:"decision"`
	Source   string             `json:"source"`
	Callable bool               `json:"callable"`
	Limits   *config.CallLimits `json:"limits,omitempty"`
}

// InspectPermissions calculates the same identity-policy composition and tool
// decisions used by authenticated sessions, then presents every known tool,
// including denied and approval-blocked entries.
func InspectPermissions(cfg config.Config, input PermissionInspectionInput, items []capability.Capability, unavailable []string) (PermissionInspection, error) {
	result := PermissionInspection{
		Status:                  "denied",
		Provider:                input.Provider,
		Subject:                 input.Subject,
		Groups:                  sortedUnique(input.Groups),
		Scopes:                  sortedUnique(input.Scopes),
		UnavailableCapabilities: sortedUnique(unavailable),
	}
	available, toolOwners, err := inspectionCatalog(items)
	if err != nil {
		return result, err
	}

	var client config.Client
	var toolPolicy config.ToolPolicy
	var policyName string

	if input.Client != "" {
		if input.Provider != "" && input.Provider != PermissionProviderStatic {
			return result, errors.New("client inspection cannot be combined with a non-static provider")
		}
		configured, ok := cfg.Clients[input.Client]
		if !ok {
			return result, fmt.Errorf("static client %q is not configured", input.Client)
		}
		result.Provider = PermissionProviderStatic
		result.MatchedPolicies = []string{"static:" + input.Client}
		if !cfg.StaticClientEnabled(input.Client) {
			result.Status = "disabled"
			return result, nil
		}
		client = configured
		toolPolicy = cfg.ToolPolicies[client.ToolPolicy]
		policyName = "static:" + input.Client
	} else {
		provider, policies, mode, globalScopes, enforceScopes, err := inspectionProvider(cfg, input.Provider)
		if err != nil {
			return result, err
		}
		result.Provider = provider
		groups := stringSet(input.Groups)
		scopes := stringSet(input.Scopes)
		if len(input.Policies) == 0 && enforceScopes && !containsAllStrings(scopes, globalScopes) {
			result.Status = "insufficient_scope"
			result.MissingScopes = missingStrings(scopes, globalScopes)
			return result, nil
		}
		matches, missing, err := selectInspectionPolicies(input, policies, enforceScopes, groups, scopes)
		if err != nil {
			return result, err
		}
		for _, match := range matches {
			result.MatchedPolicies = append(result.MatchedPolicies, match.Name)
		}
		if len(matches) == 0 {
			if len(missing) > 0 {
				result.Status = "insufficient_scope"
				result.MissingScopes = sortedUnique(append(append([]string{}, globalScopes...), missing...))
			}
			return result, nil
		}
		if mode != config.IdentityPolicyModeComposed && len(matches) != 1 {
			result.Status = "ambiguous"
			return result, nil
		}
		if mode == config.IdentityPolicyModeComposed {
			client, toolPolicy, policyName, err = composeIdentityPolicies(matches, cfg.ToolPolicies, toolOwners)
			if err != nil {
				return result, err
			}
		} else {
			client = matches[0].Policy.Client()
			toolPolicy = cfg.ToolPolicies[client.ToolPolicy]
			policyName = matches[0].Name
		}
	}

	result.Status = "allowed"
	result.EffectivePolicy = policyName
	result.EffectivePolicyVersion = client.IdentityPolicyVersion
	result.Profile = client.Profile
	result.Discover = client.Discover
	result.Execute = client.Execute
	result.Activate = client.Activate
	result.Limits = client.Limits
	result.AllAllowedInitiallyActive = client.InitialCapabilities == nil
	result.InitialCapabilities = append([]string{}, client.InitialCapabilities...)
	sort.Strings(result.InitialCapabilities)
	result.Capabilities = inspectCapabilities(cfg, client, toolPolicy, available)
	result.UnavailableCapabilities = unavailableForProfile(cfg.Profiles[client.Profile], result.UnavailableCapabilities)
	return result, nil
}

func inspectionProvider(cfg config.Config, requested string) (string, map[string]config.OAuthPolicy, string, []string, bool, error) {
	provider := requested
	if provider == "" {
		switch {
		case cfg.OAuth != nil && cfg.CloudflareAccess == nil:
			provider = PermissionProviderOAuth
		case cfg.OAuth == nil && cfg.CloudflareAccess != nil:
			provider = PermissionProviderCloudflareAccess
		case cfg.OAuth != nil && cfg.CloudflareAccess != nil:
			return "", nil, "", nil, false, errors.New("provider is required when OAuth and Cloudflare Access are both configured")
		default:
			return "", nil, "", nil, false, errors.New("no identity provider is configured")
		}
	}
	switch provider {
	case PermissionProviderOAuth:
		if cfg.OAuth == nil {
			return "", nil, "", nil, false, errors.New("OAuth is not configured")
		}
		return provider, cfg.OAuth.Policies, cfg.OAuth.PolicyMode, cfg.OAuth.RequiredScopes, true, nil
	case PermissionProviderCloudflareAccess:
		if cfg.CloudflareAccess == nil {
			return "", nil, "", nil, false, errors.New("Cloudflare Access is not configured")
		}
		return provider, cfg.CloudflareAccess.Policies, cfg.CloudflareAccess.PolicyMode, nil, false, nil
	default:
		return "", nil, "", nil, false, fmt.Errorf("unsupported provider %q", provider)
	}
}

func selectInspectionPolicies(input PermissionInspectionInput, policies map[string]config.OAuthPolicy, enforceScopes bool, groups, scopes map[string]bool) ([]auth.PolicyMatch, []string, error) {
	if len(input.Policies) == 0 {
		evaluation := auth.EvaluatePolicies(input.Subject, groups, scopes, policies, enforceScopes)
		return evaluation.Matches, evaluation.MissingScopes, nil
	}
	names := sortedUnique(input.Policies)
	matches := make([]auth.PolicyMatch, 0, len(names))
	for _, name := range names {
		policy, ok := policies[name]
		if !ok {
			return nil, nil, fmt.Errorf("identity policy %q is not configured", name)
		}
		matches = append(matches, auth.PolicyMatch{Name: name, Policy: policy})
	}
	return matches, nil, nil
}

func inspectionCatalog(items []capability.Capability) (map[string]capability.Description, map[string]string, error) {
	available := make(map[string]capability.Description, len(items))
	owners := map[string]string{}
	for _, item := range items {
		describer, ok := item.(capability.Describer)
		if !ok {
			return nil, nil, fmt.Errorf("capability %s lacks permission metadata", item.Name())
		}
		description := describer.Describe()
		description.Name = item.Name()
		available[item.Name()] = description
		for _, tool := range description.Tools {
			if existing := owners[tool.Name]; existing != "" {
				return nil, nil, fmt.Errorf("tool %q is owned by both %s and %s", tool.Name, existing, item.Name())
			}
			owners[tool.Name] = item.Name()
		}
	}
	return available, owners, nil
}

func inspectCapabilities(cfg config.Config, client config.Client, toolPolicy config.ToolPolicy, available map[string]capability.Description) []PermissionCapability {
	initial := stringSet(client.InitialCapabilities)
	allInitial := client.InitialCapabilities == nil
	result := make([]PermissionCapability, 0, len(cfg.Profiles[client.Profile]))
	for _, name := range cfg.Profiles[client.Profile] {
		description, ok := available[name]
		entry := PermissionCapability{Name: name, Available: ok}
		if !ok {
			result = append(result, entry)
			continue
		}
		entry.Active = client.Execute && (allInitial || initial[name])
		for _, tool := range description.Tools {
			decision := gateway.ToolDecision(toolPolicy, name, tool.Name)
			limits := toolPolicy.ToolLimits[tool.Name]
			var limitCopy *config.CallLimits
			if limits != (config.CallLimits{}) {
				copy := limits
				limitCopy = &copy
			}
			entry.Tools = append(entry.Tools, PermissionTool{
				Name: tool.Name, Decision: decision, Source: decisionSource(toolPolicy, name, tool.Name),
				Callable: entry.Active && (decision == "allow" || decision == "allowed_by_profile"), Limits: limitCopy,
			})
		}
		sort.Slice(entry.Tools, func(i, j int) bool { return entry.Tools[i].Name < entry.Tools[j].Name })
		result = append(result, entry)
	}
	return result
}

func decisionSource(policy config.ToolPolicy, capabilityName, toolName string) string {
	if policy.Version == "" {
		return "profile"
	}
	if _, ok := policy.Tools[toolName]; ok {
		return "tool"
	}
	if _, ok := policy.Capabilities[capabilityName]; ok {
		return "capability"
	}
	return "default"
}

func unavailableForProfile(profile, unavailable []string) []string {
	missing := stringSet(unavailable)
	result := make([]string, 0, len(unavailable))
	for _, name := range profile {
		if missing[name] {
			result = append(result, name)
		}
	}
	return sortedUnique(result)
}

type PermissionWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// LintPermissions reports safe-to-evaluate operator hazards without loading or
// contacting capabilities. Warnings never alter authorization.
func LintPermissions(cfg config.Config) []PermissionWarning {
	warnings := []PermissionWarning{}
	profileSignatures := map[string]string{}
	profileNames := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		profileNames = append(profileNames, name)
	}
	sort.Strings(profileNames)
	for _, name := range profileNames {
		members := append([]string{}, cfg.Profiles[name]...)
		sort.Strings(members)
		signature := strings.Join(members, "\x00")
		if previous := profileSignatures[signature]; previous != "" {
			warnings = append(warnings, PermissionWarning{Code: "duplicate_profile", Message: fmt.Sprintf("profiles %q and %q contain the same capabilities", previous, name)})
		} else {
			profileSignatures[signature] = name
		}
	}
	disabledStaticClients := 0
	for name := range cfg.Clients {
		if !cfg.StaticClientEnabled(name) {
			disabledStaticClients++
		}
	}
	if disabledStaticClients > 0 {
		warnings = append(warnings, PermissionWarning{Code: "disabled_static_clients", Message: fmt.Sprintf("%d static clients are configured but disabled by identity-provider static-client controls", disabledStaticClients)})
	}
	referencedToolPolicies := map[string]bool{}
	for _, client := range cfg.Clients {
		referencedToolPolicies[client.ToolPolicy] = true
	}
	for _, policy := range oauthPolicies(cfg) {
		referencedToolPolicies[policy.ToolPolicy] = true
	}
	for _, policy := range cloudflarePolicies(cfg) {
		referencedToolPolicies[policy.ToolPolicy] = true
	}
	policyNames := make([]string, 0, len(cfg.ToolPolicies))
	for name := range cfg.ToolPolicies {
		policyNames = append(policyNames, name)
	}
	sort.Strings(policyNames)
	for _, name := range policyNames {
		policy := cfg.ToolPolicies[name]
		if !referencedToolPolicies[name] {
			warnings = append(warnings, PermissionWarning{Code: "unreferenced_tool_policy", Message: fmt.Sprintf("tool policy %q is not referenced by any configured identity", name)})
		}
		capabilityNames := make([]string, 0, len(policy.Capabilities))
		for capabilityName := range policy.Capabilities {
			capabilityNames = append(capabilityNames, capabilityName)
		}
		sort.Strings(capabilityNames)
		for _, capabilityName := range capabilityNames {
			switch policy.Capabilities[capabilityName] {
			case "allow":
				warnings = append(warnings, PermissionWarning{Code: "broad_capability_allow", Message: fmt.Sprintf("tool policy %q allows every current and future tool from capability %q", name, capabilityName)})
			case "require_approval":
				warnings = append(warnings, PermissionWarning{Code: "approval_unavailable", Message: fmt.Sprintf("tool policy %q marks capability %q require_approval; it remains hidden and blocked until a server-side approval workflow exists", name, capabilityName)})
			}
		}
		toolNames := make([]string, 0, len(policy.Tools))
		for tool := range policy.Tools {
			toolNames = append(toolNames, tool)
		}
		sort.Strings(toolNames)
		for _, tool := range toolNames {
			if policy.Tools[tool] == "require_approval" {
				warnings = append(warnings, PermissionWarning{Code: "approval_unavailable", Message: fmt.Sprintf("tool policy %q marks tool %q require_approval; it remains hidden and blocked until a server-side approval workflow exists", name, tool)})
			}
		}
	}
	for provider, policies := range map[string]map[string]config.OAuthPolicy{
		"OAuth": oauthPolicies(cfg), "Cloudflare Access": cloudflarePolicies(cfg),
	} {
		names := make([]string, 0, len(policies))
		for name := range policies {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			policy := policies[name]
			if policy.ToolPolicy == "" {
				warnings = append(warnings, PermissionWarning{Code: "whole_profile_allow", Message: fmt.Sprintf("%s policy %q has no tool policy and therefore allows the whole profile %q", provider, name, policy.Profile)})
			}
		}
	}
	sort.Slice(warnings, func(i, j int) bool {
		if warnings[i].Code != warnings[j].Code {
			return warnings[i].Code < warnings[j].Code
		}
		return warnings[i].Message < warnings[j].Message
	})
	return warnings
}

func oauthPolicies(cfg config.Config) map[string]config.OAuthPolicy {
	if cfg.OAuth == nil {
		return nil
	}
	return cfg.OAuth.Policies
}

func cloudflarePolicies(cfg config.Config) map[string]config.OAuthPolicy {
	if cfg.CloudflareAccess == nil {
		return nil
	}
	return cfg.CloudflareAccess.Policies
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func containsAllStrings(values map[string]bool, required []string) bool {
	for _, value := range required {
		if !values[value] {
			return false
		}
	}
	return true
}

func missingStrings(values map[string]bool, required []string) []string {
	var result []string
	for _, value := range required {
		if !values[value] {
			result = append(result, value)
		}
	}
	return sortedUnique(result)
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
