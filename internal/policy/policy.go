// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

// Policy is a set of tool-call rules for an AI agent.
type Policy struct {
	APIVersion string     `yaml:"api_version"` // "v1"
	Kind       string     `yaml:"kind"`        // "Policy"
	Meta       PolicyMeta `yaml:"meta"`
	Agent      AgentScope `yaml:"agent"`
	Rules      []Rule     `yaml:"rules"`
}

// PolicyMeta holds policy metadata.
type PolicyMeta struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Authors     []string `yaml:"authors,omitempty"`
	Created     string   `yaml:"created"`
	Modified    string   `yaml:"modified"`
}

// AgentScope defines which agent this policy applies to.
type AgentScope struct {
	Name  string   `yaml:"name"`           // agent name or pattern
	Type  string   `yaml:"type,omitempty"` // "llm", "retrieval", "orchestrator"
	Tools []string `yaml:"tools,omitempty"`
}

// Rule is a single allow/deny/alert policy rule.
type Rule struct {
	ID          string      `yaml:"id"`
	Description string      `yaml:"description"`
	Effect      string      `yaml:"effect"`   // "deny", "allow", "alert"
	Priority    int         `yaml:"priority"` // higher = evaluated first
	Match       RuleMatch   `yaml:"match"`
	Conditions  []Condition `yaml:"conditions,omitempty"`
}

// RuleMatch defines what a rule applies to.
type RuleMatch struct {
	Tools   []string `yaml:"tools,omitempty"`   // tool names or glob patterns
	Tactics []string `yaml:"tactics,omitempty"` // tactic short names
	Actions []string `yaml:"actions,omitempty"` // "read", "write", "execute", "send", "query"
	Targets []string `yaml:"targets,omitempty"` // target URL/host patterns (glob)
}

// Condition adds constraints to when a rule fires.
type Condition struct {
	Field    string `yaml:"field"`    // "elevated", "technique", "tactic", "platform", "exec_type"
	Operator string `yaml:"operator"` // "eq", "ne", "in", "not_in", "matches"
	Value    string `yaml:"value"`
}

// EvalResult is the output of policy evaluation against a campaign.
type EvalResult struct {
	Policy      string
	Campaign    string
	Violations  []Violation
	Allowed     int
	Denied      int
	Alerted     int
	TotalStages int
}

// Violation is a policy rule violation found in a campaign stage.
type Violation struct {
	RuleID    string
	RuleDesc  string
	Effect    string // "deny", "alert"
	StageID   string
	StageName string
	Technique string
	Tactic    string
	Tool      string // the matched tool or action
	Reason    string // human-readable why this violated
}

// Valid effects for a rule.
var validEffects = map[string]bool{
	"deny":  true,
	"allow": true,
	"alert": true,
}

// Valid operators for conditions.
var validOperators = map[string]bool{
	"eq":      true,
	"ne":      true,
	"in":      true,
	"not_in":  true,
	"matches": true,
}

// Valid condition fields.
var validCondFields = map[string]bool{
	"elevated":  true,
	"technique": true,
	"tactic":    true,
	"platform":  true,
	"exec_type": true,
}

// telemetryToTool maps telemetry types to implied tool names.
var telemetryToTool = map[string]string{
	"tool_call":           "tool_call",
	"email_sent":          "send_email",
	"embedding_query":     "search_knowledge_base",
	"vector_store_write":  "write_knowledge_base",
	"inter_agent_message": "agent_message",
}

// execTypeToTool maps execute types to tool names.
var execTypeToTool = map[string]string{
	"http":       "http_request",
	"shell":      "shell_exec",
	"powershell": "shell_exec",
	"dns":        "dns_query",
	"file":       "file_access",
	"registry":   "registry_access",
	"service":    "service_control",
	"process":    "process_exec",
}

// execTypeToAction maps execute types to action categories.
var execTypeToAction = map[string]string{
	"http":       "send",
	"shell":      "execute",
	"powershell": "execute",
	"dns":        "query",
	"file":       "write",
	"registry":   "write",
	"service":    "execute",
	"process":    "execute",
}

// LoadPolicy reads and parses a policy from a YAML file or directory.
// If path is a directory, it looks for policy.yaml inside it.
func LoadPolicy(path string) (*Policy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("policy path %q: %w", path, err)
	}
	if info.IsDir() {
		path = filepath.Join(path, "policy.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}

	return &p, nil
}

// LoadDir loads all policies from a directory. Each subdirectory containing
// a policy.yaml is loaded. Subdirectories that fail to parse are skipped.
func LoadDir(dir string) ([]*Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading policy directory %q: %w", dir, err)
	}

	var policies []*Policy
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p, pErr := LoadPolicy(filepath.Join(dir, e.Name()))
		if pErr != nil {
			continue // skip non-policy subdirs
		}
		policies = append(policies, p)
	}
	return policies, nil
}

// ValidatePolicy checks a policy for structural and semantic errors.
// Returns a slice of issues; empty means valid.
func ValidatePolicy(p *Policy) []string {
	var errs []string

	if p.APIVersion == "" {
		errs = append(errs, "missing api_version")
	}
	if p.Kind == "" {
		errs = append(errs, "missing kind")
	} else if p.Kind != "Policy" {
		errs = append(errs, fmt.Sprintf("kind must be \"Policy\", got %q", p.Kind))
	}
	if p.Meta.Name == "" {
		errs = append(errs, "meta.name is required")
	}
	if p.Agent.Name == "" {
		errs = append(errs, "agent.name is required")
	}
	if len(p.Rules) == 0 {
		errs = append(errs, "policy must have at least one rule")
		return errs
	}

	ids := make(map[string]int)
	for i, r := range p.Rules {
		prefix := fmt.Sprintf("rules[%d] (%s)", i, r.ID)

		if r.ID == "" {
			errs = append(errs, fmt.Sprintf("rules[%d]: id is required", i))
			continue
		}
		if prev, dup := ids[r.ID]; dup {
			errs = append(errs, fmt.Sprintf("%s: duplicate id (first at rules[%d])", prefix, prev))
		}
		ids[r.ID] = i

		if r.Effect == "" {
			errs = append(errs, fmt.Sprintf("%s: effect is required", prefix))
		} else if !validEffects[r.Effect] {
			errs = append(errs, fmt.Sprintf("%s: effect %q is not valid (use deny/allow/alert)", prefix, r.Effect))
		}

		// At least one match criterion required.
		if len(r.Match.Tools) == 0 && len(r.Match.Tactics) == 0 &&
			len(r.Match.Actions) == 0 && len(r.Match.Targets) == 0 {
			errs = append(errs, fmt.Sprintf("%s: match must specify at least one of tools, tactics, actions, or targets", prefix))
		}

		for j, cond := range r.Conditions {
			cp := fmt.Sprintf("%s.conditions[%d]", prefix, j)
			if cond.Field == "" {
				errs = append(errs, fmt.Sprintf("%s: field is required", cp))
			} else if !validCondFields[cond.Field] {
				errs = append(errs, fmt.Sprintf("%s: field %q is not valid (use elevated/technique/tactic/platform/exec_type)", cp, cond.Field))
			}
			if cond.Operator == "" {
				errs = append(errs, fmt.Sprintf("%s: operator is required", cp))
			} else if !validOperators[cond.Operator] {
				errs = append(errs, fmt.Sprintf("%s: operator %q is not valid (use eq/ne/in/not_in/matches)", cp, cond.Operator))
			}
		}
	}

	return errs
}

// Evaluate checks a campaign against a policy and returns violations.
// Rules are evaluated in priority order (highest first). The first matching
// rule wins for each stage. Stages with no matching rule get implicit allow.
func Evaluate(p *Policy, c *campaign.Campaign) *EvalResult {
	result := &EvalResult{
		Policy:      p.Meta.Name,
		Campaign:    c.Meta.Name,
		TotalStages: len(c.Stages),
	}

	// Sort rules by priority descending.
	sorted := make([]Rule, len(p.Rules))
	copy(sorted, p.Rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})

	for _, stage := range c.Stages {
		tools := InferTools(stage)
		actions := inferActions(stage)
		target := stage.Execute.Target

		matched := false
		for _, rule := range sorted {
			matchedTool := matchTools(rule.Match.Tools, tools)
			matchedTactic := matchTactic(rule.Match.Tactics, stage.Tactic)
			matchedAction := matchActions(rule.Match.Actions, actions)
			matchedTarget := matchTarget(rule.Match.Targets, target)

			// A rule must match on at least one of its specified dimensions.
			// Only dimensions with entries participate.
			if !ruleMatchesStage(rule.Match, matchedTool, matchedTactic, matchedAction, matchedTarget) {
				continue
			}

			// Check conditions.
			if !conditionsPass(rule.Conditions, stage) {
				continue
			}

			matched = true

			// Determine which tool triggered the match for the violation report.
			triggerTool := identifyTrigger(rule.Match, tools, actions, stage.Tactic, target)

			switch rule.Effect {
			case "deny":
				result.Denied++
				result.Violations = append(result.Violations, Violation{
					RuleID:    rule.ID,
					RuleDesc:  rule.Description,
					Effect:    "deny",
					StageID:   stage.ID,
					StageName: stage.Name,
					Technique: stage.Technique,
					Tactic:    stage.Tactic,
					Tool:      triggerTool,
					Reason:    fmt.Sprintf("denied by rule %q: %s", rule.ID, rule.Description),
				})
			case "alert":
				result.Alerted++
				result.Violations = append(result.Violations, Violation{
					RuleID:    rule.ID,
					RuleDesc:  rule.Description,
					Effect:    "alert",
					StageID:   stage.ID,
					StageName: stage.Name,
					Technique: stage.Technique,
					Tactic:    stage.Tactic,
					Tool:      triggerTool,
					Reason:    fmt.Sprintf("alert from rule %q: %s", rule.ID, rule.Description),
				})
			case "allow":
				result.Allowed++
			}

			break // first matching rule wins
		}

		if !matched {
			// Implicit allow for stages with no matching rule.
			result.Allowed++
		}
	}

	return result
}

// InferTools extracts tool names from a campaign stage's execute type and telemetry.
func InferTools(s campaign.Stage) []string {
	seen := make(map[string]bool)
	var tools []string

	// From execute type.
	if tool, ok := execTypeToTool[s.Execute.Type]; ok {
		if !seen[tool] {
			seen[tool] = true
			tools = append(tools, tool)
		}
	}

	// From telemetry.
	for _, t := range s.Expect.Telemetry {
		if tool, ok := telemetryToTool[t]; ok {
			if !seen[tool] {
				seen[tool] = true
				tools = append(tools, tool)
			}
		}
	}

	return tools
}

// inferActions maps a stage's execute type to action categories.
func inferActions(s campaign.Stage) []string {
	if action, ok := execTypeToAction[s.Execute.Type]; ok {
		return []string{action}
	}
	return nil
}

// ruleMatchesStage checks whether the rule's match dimensions align with the stage.
// Each specified dimension must have at least one hit. Unspecified dimensions are ignored.
func ruleMatchesStage(m RuleMatch, tool, tactic, action, target bool) bool {
	if len(m.Tools) > 0 && !tool {
		return false
	}
	if len(m.Tactics) > 0 && !tactic {
		return false
	}
	if len(m.Actions) > 0 && !action {
		return false
	}
	if len(m.Targets) > 0 && !target {
		return false
	}
	// At least one dimension must be specified and matched.
	return (len(m.Tools) > 0 && tool) ||
		(len(m.Tactics) > 0 && tactic) ||
		(len(m.Actions) > 0 && action) ||
		(len(m.Targets) > 0 && target)
}

// matchTools checks if any rule tool pattern matches any inferred tool.
func matchTools(patterns, tools []string) bool {
	for _, p := range patterns {
		for _, t := range tools {
			if GlobMatch(p, t) {
				return true
			}
		}
	}
	return false
}

// matchTactic checks if any rule tactic matches the stage tactic.
func matchTactic(tactics []string, stageTactic string) bool {
	for _, t := range tactics {
		if t == stageTactic {
			return true
		}
	}
	return false
}

// matchActions checks if any rule action matches any inferred action.
func matchActions(ruleActions, stageActions []string) bool {
	for _, ra := range ruleActions {
		for _, sa := range stageActions {
			if ra == sa {
				return true
			}
		}
	}
	return false
}

// matchTarget checks if any rule target pattern matches the stage's execute target.
func matchTarget(patterns []string, target string) bool {
	if target == "" {
		return false
	}
	for _, p := range patterns {
		if GlobMatch(p, target) {
			return true
		}
	}
	return false
}

// conditionsPass checks whether all conditions on a rule are satisfied.
func conditionsPass(conds []Condition, s campaign.Stage) bool {
	for _, c := range conds {
		if !conditionPasses(c, s) {
			return false
		}
	}
	return true
}

// conditionPasses evaluates a single condition against a stage.
func conditionPasses(c Condition, s campaign.Stage) bool {
	fieldVal := fieldValue(c.Field, s)

	switch c.Operator {
	case "eq":
		return fieldVal == c.Value
	case "ne":
		return fieldVal != c.Value
	case "in":
		for _, v := range strings.Split(c.Value, ",") {
			if strings.TrimSpace(v) == fieldVal {
				return true
			}
		}
		return false
	case "not_in":
		for _, v := range strings.Split(c.Value, ",") {
			if strings.TrimSpace(v) == fieldVal {
				return false
			}
		}
		return true
	case "matches":
		matched, err := path.Match(c.Value, fieldVal)
		if err != nil {
			return false
		}
		return matched
	}
	return false
}

// fieldValue extracts a field value from a stage for condition evaluation.
func fieldValue(field string, s campaign.Stage) string {
	switch field {
	case "elevated":
		if s.Execute.Elevated {
			return "true"
		}
		return "false"
	case "technique":
		return s.Technique
	case "tactic":
		return s.Tactic
	case "platform":
		return strings.Join(s.Platform, ",")
	case "exec_type":
		return s.Execute.Type
	}
	return ""
}

// identifyTrigger picks the most descriptive trigger label for a violation.
func identifyTrigger(m RuleMatch, tools, actions []string, tactic, target string) string {
	if len(m.Tools) > 0 {
		for _, p := range m.Tools {
			for _, t := range tools {
				if GlobMatch(p, t) {
					return t
				}
			}
		}
	}
	if len(m.Targets) > 0 && target != "" {
		return target
	}
	if len(m.Tactics) > 0 {
		return tactic
	}
	if len(m.Actions) > 0 && len(actions) > 0 {
		return actions[0]
	}
	return ""
}

// GlobMatch performs simple wildcard matching. Supports * as a wildcard that
// matches any sequence of characters. Uses path.Match for patterns that
// contain no path separators, and a simple prefix/suffix check for URL-like targets.
func GlobMatch(pattern, name string) bool {
	// Exact match.
	if pattern == name {
		return true
	}
	// Try path.Match for simple glob patterns.
	if matched, err := path.Match(pattern, name); err == nil && matched {
		return true
	}
	// Handle URL-like patterns with wildcards that path.Match can't handle.
	if strings.Contains(pattern, "*") {
		return simpleGlob(pattern, name)
	}
	return false
}

// simpleGlob handles * wildcard matching for arbitrary strings including URLs.
func simpleGlob(pattern, s string) bool {
	// Split pattern on *; all non-* parts must appear in order.
	parts := strings.Split(pattern, "*")
	if len(parts) == 0 {
		return true
	}

	// First part must be a prefix.
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	// Middle parts must appear in order.
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}

	// Last part must be a suffix.
	return strings.HasSuffix(s, parts[len(parts)-1])
}
