package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/kilo666mj/switchboard/internal/config"
	"github.com/kilo666mj/switchboard/internal/egress"
	"github.com/kilo666mj/switchboard/internal/loader"
	"github.com/kilo666mj/switchboard/internal/sessions"
)

type repeatedStrings []string

func (values *repeatedStrings) String() string { return strings.Join(*values, ",") }
func (values *repeatedStrings) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return errors.New("value must not be empty")
		}
		*values = append(*values, part)
	}
	return nil
}

type permissionPolicySummary struct {
	Name           string   `json:"name"`
	Subjects       []string `json:"subjects,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	RequiredScopes []string `json:"required_scopes,omitempty"`
	Profile        string   `json:"profile"`
	ToolPolicy     string   `json:"tool_policy,omitempty"`
	Discover       bool     `json:"discover"`
	Execute        bool     `json:"execute"`
	Activate       bool     `json:"activate"`
}

type permissionProviderSummary struct {
	Name     string                    `json:"name"`
	Mode     string                    `json:"mode"`
	Policies []permissionPolicySummary `json:"policies"`
}

type permissionClientSummary struct {
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Profile    string `json:"profile"`
	ToolPolicy string `json:"tool_policy,omitempty"`
	Discover   bool   `json:"discover"`
	Execute    bool   `json:"execute"`
	Activate   bool   `json:"activate"`
}

type permissionReport struct {
	Providers []permissionProviderSummary  `json:"providers,omitempty"`
	Clients   []permissionClientSummary    `json:"static_clients,omitempty"`
	Warnings  []sessions.PermissionWarning `json:"warnings"`
}

type permissionInspectionSummary struct {
	Status                    string   `json:"status"`
	MatchedPolicies           []string `json:"matched_policies,omitempty"`
	EffectivePolicy           string   `json:"effective_policy,omitempty"`
	EffectivePolicyVersion    string   `json:"effective_policy_version,omitempty"`
	Profile                   string   `json:"profile,omitempty"`
	Discover                  bool     `json:"discover"`
	Execute                   bool     `json:"execute"`
	Activate                  bool     `json:"activate"`
	InitialCapabilities       []string `json:"initial_capabilities,omitempty"`
	AllAllowedInitiallyActive bool     `json:"all_allowed_initially_active"`
	UnavailableCapabilities   []string `json:"unavailable_capabilities,omitempty"`
}

type permissionToolState struct {
	Capability string `json:"capability"`
	Decision   string `json:"decision"`
	Source     string `json:"source"`
	Callable   bool   `json:"callable"`
	Available  bool   `json:"available"`
	Active     bool   `json:"active"`
}

type permissionToolChange struct {
	Tool   string               `json:"tool"`
	Before *permissionToolState `json:"before,omitempty"`
	After  *permissionToolState `json:"after,omitempty"`
}

type permissionDiff struct {
	Before   permissionInspectionSummary  `json:"before"`
	After    permissionInspectionSummary  `json:"after"`
	Tools    []permissionToolChange       `json:"tool_changes"`
	Warnings []sessions.PermissionWarning `json:"after_warnings"`
}

func runPermissions(args []string) error {
	return runPermissionsWithWriter(args, os.Stdout)
}

func runPermissionsWithWriter(args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("permissions requires report, lint, explain, or diff")
	}
	action := args[0]
	flags := flag.NewFlagSet("switchboard permissions "+action, flag.ContinueOnError)
	flags.SetOutput(output)
	configPath := flags.String("config", "switchboard.json", "path to Switchboard configuration")
	jsonOutput := flags.Bool("json", false, "write machine-readable JSON")
	if action == "report" || action == "lint" {
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		if action == "lint" {
			return writePermissionWarnings(output, sessions.LintPermissions(cfg), *jsonOutput)
		}
		return writePermissionReport(output, buildPermissionReport(cfg), *jsonOutput)
	}
	if action != "explain" && action != "diff" {
		return fmt.Errorf("unknown permissions action %q", action)
	}

	provider := flags.String("provider", "", "identity provider: oauth or cloudflare_access")
	subject := flags.String("subject", "", "verified immutable subject to simulate")
	client := flags.String("client", "", "configured static client to inspect")
	against := flags.String("against", "", "comparison configuration path for diff")
	var groups, scopes, policies repeatedStrings
	flags.Var(&groups, "group", "verified group to simulate; repeat or use comma-separated values")
	flags.Var(&scopes, "scope", "verified OAuth scope to simulate; repeat or use comma-separated values")
	flags.Var(&policies, "policy", "exact configured identity policy to inspect; repeat to compose")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *client != "" && (len(groups) > 0 || len(scopes) > 0 || len(policies) > 0 || *subject != "") {
		return errors.New("client cannot be combined with subject, group, scope, or policy")
	}
	if len(policies) > 0 && (len(groups) > 0 || len(scopes) > 0 || *subject != "") {
		return errors.New("policy cannot be combined with subject, group, or scope")
	}
	if *client == "" && len(policies) == 0 && *subject == "" && len(groups) == 0 {
		return fmt.Errorf("%s requires a client, policy, subject, or group", action)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	input := sessions.PermissionInspectionInput{
		Provider: *provider, Subject: *subject, Groups: groups, Scopes: scopes, Policies: policies, Client: *client,
	}
	inspection, items, err := inspectPermissionConfig(ctx, cfg, input)
	if err != nil {
		return err
	}
	defer closeCapabilities(items)
	if action == "explain" {
		return writePermissionInspection(output, inspection, *jsonOutput)
	}
	if *against == "" {
		return errors.New("diff requires -against")
	}
	afterConfig, err := config.Load(*against)
	if err != nil {
		return err
	}
	afterInspection, afterItems, err := inspectPermissionConfig(ctx, afterConfig, input)
	if err != nil {
		return err
	}
	defer closeCapabilities(afterItems)
	return writePermissionDiff(output, buildPermissionDiff(inspection, afterInspection, sessions.LintPermissions(afterConfig)), *jsonOutput)
}

func inspectPermissionConfig(ctx context.Context, cfg config.Config, input sessions.PermissionInspectionInput) (sessions.PermissionInspection, []capability.Capability, error) {
	items, unavailable, err := loadPermissionCapabilities(ctx, cfg)
	if err != nil {
		return sessions.PermissionInspection{}, nil, err
	}
	inspection, err := sessions.InspectPermissions(cfg, input, items, unavailable)
	if err != nil {
		closeCapabilities(items)
		return sessions.PermissionInspection{}, nil, err
	}
	return inspection, items, nil
}

func loadPermissionCapabilities(ctx context.Context, cfg config.Config) ([]capability.Capability, []string, error) {
	selectedSet := map[string]bool{}
	for _, names := range cfg.Profiles {
		for _, name := range names {
			selectedSet[name] = true
		}
	}
	selected := make([]string, 0, len(selectedSet))
	for name := range selectedSet {
		selected = append(selected, name)
	}
	sort.Strings(selected)
	var policy *egress.Policy
	var err error
	if cfg.EgressPolicy != nil {
		policy, err = egress.New(*cfg.EgressPolicy)
		if err != nil {
			return nil, nil, fmt.Errorf("egress policy: %w", err)
		}
	}
	items, failures, err := loader.LoadAvailable(ctx, cfg.CapabilityDir, selected, policy)
	if err != nil {
		return nil, nil, err
	}
	unavailable := make([]string, 0, len(failures))
	for _, failure := range failures {
		unavailable = append(unavailable, failure.Name)
	}
	return items, unavailable, nil
}

func buildPermissionReport(cfg config.Config) permissionReport {
	report := permissionReport{Warnings: sessions.LintPermissions(cfg)}
	if cfg.OAuth != nil {
		report.Providers = append(report.Providers, summarizeProvider("oauth", cfg.OAuth.PolicyMode, cfg.OAuth.Policies))
	}
	if cfg.CloudflareAccess != nil {
		report.Providers = append(report.Providers, summarizeProvider("cloudflare_access", cfg.CloudflareAccess.PolicyMode, cfg.CloudflareAccess.Policies))
	}
	clientNames := make([]string, 0, len(cfg.Clients))
	for name := range cfg.Clients {
		clientNames = append(clientNames, name)
	}
	sort.Strings(clientNames)
	for _, name := range clientNames {
		client := cfg.Clients[name]
		report.Clients = append(report.Clients, permissionClientSummary{Name: name, Enabled: cfg.StaticClientsEnabled(), Profile: client.Profile, ToolPolicy: client.ToolPolicy, Discover: client.Discover, Execute: client.Execute, Activate: client.Activate})
	}
	return report
}

func summarizeProvider(name, mode string, policies map[string]config.OAuthPolicy) permissionProviderSummary {
	if mode == "" {
		mode = config.IdentityPolicyModeExclusive
	}
	result := permissionProviderSummary{Name: name, Mode: mode}
	names := make([]string, 0, len(policies))
	for policyName := range policies {
		names = append(names, policyName)
	}
	sort.Strings(names)
	for _, policyName := range names {
		policy := policies[policyName]
		result.Policies = append(result.Policies, permissionPolicySummary{
			Name: policyName, Subjects: append([]string{}, policy.Subjects...), Groups: append([]string{}, policy.Groups...), RequiredScopes: append([]string{}, policy.RequiredScopes...),
			Profile: policy.Profile, ToolPolicy: policy.ToolPolicy, Discover: policy.Discover, Execute: policy.Execute, Activate: policy.Activate,
		})
	}
	return result
}

func writePermissionReport(output io.Writer, report permissionReport, asJSON bool) error {
	if asJSON {
		return writeJSON(output, report)
	}
	for _, provider := range report.Providers {
		fmt.Fprintf(output, "%s (%s)\n", provider.Name, provider.Mode)
		for _, policy := range provider.Policies {
			matcher := append([]string{}, policy.Groups...)
			matcher = append(matcher, policy.Subjects...)
			fmt.Fprintf(output, "  %-28s profile=%-16s tool_policy=%-24s match=%s scopes=%s\n", policy.Name, policy.Profile, valueOrDash(policy.ToolPolicy), valueOrDash(strings.Join(matcher, ",")), valueOrDash(strings.Join(policy.RequiredScopes, ",")))
		}
	}
	if len(report.Clients) > 0 {
		fmt.Fprintln(output, "static clients")
		for _, client := range report.Clients {
			fmt.Fprintf(output, "  %-28s enabled=%-5t profile=%-16s tool_policy=%s\n", client.Name, client.Enabled, client.Profile, valueOrDash(client.ToolPolicy))
		}
	}
	return writeWarningsText(output, report.Warnings)
}

func writePermissionWarnings(output io.Writer, warnings []sessions.PermissionWarning, asJSON bool) error {
	if asJSON {
		return writeJSON(output, struct {
			Warnings []sessions.PermissionWarning `json:"warnings"`
		}{warnings})
	}
	return writeWarningsText(output, warnings)
}

func writeWarningsText(output io.Writer, warnings []sessions.PermissionWarning) error {
	if len(warnings) == 0 {
		_, err := fmt.Fprintln(output, "warnings: none")
		return err
	}
	fmt.Fprintf(output, "warnings: %d\n", len(warnings))
	for _, warning := range warnings {
		fmt.Fprintf(output, "  [%s] %s\n", warning.Code, warning.Message)
	}
	return nil
}

func writePermissionInspection(output io.Writer, inspection sessions.PermissionInspection, asJSON bool) error {
	if asJSON {
		return writeJSON(output, inspection)
	}
	fmt.Fprintf(output, "status: %s\nprovider: %s\n", inspection.Status, inspection.Provider)
	if len(inspection.MatchedPolicies) > 0 {
		fmt.Fprintf(output, "matched policies: %s\n", strings.Join(inspection.MatchedPolicies, ", "))
	}
	if len(inspection.MissingScopes) > 0 {
		fmt.Fprintf(output, "missing scopes: %s\n", strings.Join(inspection.MissingScopes, ", "))
	}
	if inspection.Status != "allowed" {
		return nil
	}
	fmt.Fprintf(output, "effective policy: %s\nprofile: %s\nsession: discover=%t execute=%t activate=%t\n", inspection.EffectivePolicy, inspection.Profile, inspection.Discover, inspection.Execute, inspection.Activate)
	if inspection.AllAllowedInitiallyActive {
		fmt.Fprintln(output, "initial activation: all allowed capabilities")
	} else {
		fmt.Fprintf(output, "initial activation: %s\n", valueOrDash(strings.Join(inspection.InitialCapabilities, ", ")))
	}
	for _, item := range inspection.Capabilities {
		callable, blocked, denied := 0, 0, 0
		for _, tool := range item.Tools {
			switch {
			case tool.Callable:
				callable++
			case tool.Decision == "require_approval":
				blocked++
			default:
				denied++
			}
		}
		fmt.Fprintf(output, "\n%s available=%t active=%t callable=%d approval_blocked=%d denied=%d\n", item.Name, item.Available, item.Active, callable, blocked, denied)
		for _, tool := range item.Tools {
			state := tool.Decision
			if tool.Callable {
				state = "callable"
			}
			fmt.Fprintf(output, "  %-18s %-12s source=%s\n", state, tool.Name, tool.Source)
		}
	}
	if len(inspection.UnavailableCapabilities) > 0 {
		fmt.Fprintf(output, "\nunavailable capabilities: %s\n", strings.Join(inspection.UnavailableCapabilities, ", "))
	}
	return nil
}

func buildPermissionDiff(before, after sessions.PermissionInspection, warnings []sessions.PermissionWarning) permissionDiff {
	result := permissionDiff{Before: summarizeInspection(before), After: summarizeInspection(after), Warnings: warnings, Tools: []permissionToolChange{}}
	beforeTools := permissionToolStates(before)
	afterTools := permissionToolStates(after)
	names := map[string]bool{}
	for name := range beforeTools {
		names[name] = true
	}
	for name := range afterTools {
		names[name] = true
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		beforeState, beforeOK := beforeTools[name]
		afterState, afterOK := afterTools[name]
		if beforeOK && afterOK && beforeState == afterState {
			continue
		}
		change := permissionToolChange{Tool: name}
		if beforeOK {
			copy := beforeState
			change.Before = &copy
		}
		if afterOK {
			copy := afterState
			change.After = &copy
		}
		result.Tools = append(result.Tools, change)
	}
	return result
}

func summarizeInspection(inspection sessions.PermissionInspection) permissionInspectionSummary {
	return permissionInspectionSummary{
		Status: inspection.Status, MatchedPolicies: inspection.MatchedPolicies, EffectivePolicy: inspection.EffectivePolicy,
		EffectivePolicyVersion: inspection.EffectivePolicyVersion, Profile: inspection.Profile, Discover: inspection.Discover,
		Execute: inspection.Execute, Activate: inspection.Activate, InitialCapabilities: inspection.InitialCapabilities,
		AllAllowedInitiallyActive: inspection.AllAllowedInitiallyActive, UnavailableCapabilities: inspection.UnavailableCapabilities,
	}
}

func permissionToolStates(inspection sessions.PermissionInspection) map[string]permissionToolState {
	result := map[string]permissionToolState{}
	for _, item := range inspection.Capabilities {
		for _, tool := range item.Tools {
			result[tool.Name] = permissionToolState{
				Capability: item.Name, Decision: tool.Decision, Source: tool.Source, Callable: tool.Callable,
				Available: item.Available, Active: item.Active,
			}
		}
	}
	return result
}

func writePermissionDiff(output io.Writer, diff permissionDiff, asJSON bool) error {
	if asJSON {
		return writeJSON(output, diff)
	}
	fmt.Fprintf(output, "before: status=%s policy=%s profile=%s\n", diff.Before.Status, valueOrDash(diff.Before.EffectivePolicy), valueOrDash(diff.Before.Profile))
	fmt.Fprintf(output, "after:  status=%s policy=%s profile=%s\n", diff.After.Status, valueOrDash(diff.After.EffectivePolicy), valueOrDash(diff.After.Profile))
	if len(diff.Before.UnavailableCapabilities) > 0 || len(diff.After.UnavailableCapabilities) > 0 {
		fmt.Fprintf(output, "unavailable capabilities: %s -> %s\n", valueOrDash(strings.Join(diff.Before.UnavailableCapabilities, ",")), valueOrDash(strings.Join(diff.After.UnavailableCapabilities, ",")))
	}
	fmt.Fprintf(output, "tool changes: %d\n", len(diff.Tools))
	for _, change := range diff.Tools {
		fmt.Fprintf(output, "  %-36s %s -> %s\n", change.Tool, formatToolState(change.Before), formatToolState(change.After))
	}
	return writeWarningsText(output, diff.Warnings)
}

func formatToolState(state *permissionToolState) string {
	if state == nil {
		return "absent"
	}
	if !state.Available {
		return "unavailable"
	}
	if state.Callable {
		return "callable/" + state.Source
	}
	if !state.Active && (state.Decision == "allow" || state.Decision == "allowed_by_profile") {
		return "inactive/" + state.Source
	}
	return state.Decision + "/" + state.Source
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func valueOrDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
