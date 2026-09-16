// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// BindingResult holds the evaluation of an agent against a policy.
type BindingResult struct {
	AgentName         string           `json:"agent_name"`
	PolicyName        string           `json:"policy_name"`
	CoveredTools      []string         `json:"covered_tools"`
	UncoveredTools    []string         `json:"uncovered_tools"`
	ElevatedUncovered []string         `json:"elevated_uncovered"` // elevated tools with no deny rules
	Warnings          []BindingWarning `json:"warnings"`
	Score             float64          `json:"score"` // 0.0 (no coverage) to 1.0 (full coverage)
	Grade             string           `json:"grade"` // A/B/C/D/F
}

// BindingWarning represents a single issue found during binding evaluation.
type BindingWarning struct {
	Tool        string `json:"tool,omitempty"`
	Capability  string `json:"capability,omitempty"`
	Category    string `json:"category"` // "uncovered_tool", "elevated_uncovered", "missing_guardrail", "overpermissive", "rate_limit_missing"
	Severity    string `json:"severity"` // "low", "medium", "high", "critical"
	Description string `json:"description"`
}

// InventoryBindingReport evaluates ALL agents against a policy.
type InventoryBindingReport struct {
	PolicyName   string          `json:"policy_name"`
	Results      []BindingResult `json:"results"`
	TotalAgents  int             `json:"total_agents"`
	FullyCovered int             `json:"fully_covered"`
	Warnings     int             `json:"total_warnings"`
}

// EvaluateBinding checks how well a policy covers an agent's tools and capabilities.
// For each tool the agent declares, it checks whether any policy rule's Match.Tools
// contains a pattern matching the tool name. It also verifies that elevated tools
// have deny rules, and that agent capabilities have corresponding guardrails.
func EvaluateBinding(a *Agent, p *policy.Policy) *BindingResult {
	if a == nil || p == nil {
		return &BindingResult{
			AgentName:  agentNameOrEmpty(a),
			PolicyName: policyNameOrEmpty(p),
			Score:      0.0,
			Grade:      gradeBinding(0.0),
		}
	}

	br := &BindingResult{
		AgentName:  a.Meta.Name,
		PolicyName: p.Meta.Name,
	}

	// Evaluate tool coverage against policy rules.
	for _, tool := range a.Tools {
		covered := isToolCoveredByPolicy(tool.Name, p)
		if covered {
			br.CoveredTools = append(br.CoveredTools, tool.Name)
		} else {
			br.UncoveredTools = append(br.UncoveredTools, tool.Name)
			severity := "medium"
			if tool.Elevated {
				severity = "critical"
			}
			br.Warnings = append(br.Warnings, BindingWarning{
				Tool:        tool.Name,
				Category:    "uncovered_tool",
				Severity:    severity,
				Description: fmt.Sprintf("Tool %q is declared on agent %q but no policy rule covers it", tool.Name, a.Meta.Name),
			})
		}

		// Check elevated tools for deny rule coverage.
		if tool.Elevated && !hasMatchingDenyRule(tool.Name, p) {
			br.ElevatedUncovered = append(br.ElevatedUncovered, tool.Name)
			br.Warnings = append(br.Warnings, BindingWarning{
				Tool:        tool.Name,
				Category:    "elevated_uncovered",
				Severity:    "high",
				Description: fmt.Sprintf("Elevated tool %q has no deny rule — consider adding constraints", tool.Name),
			})
		}

		// Check elevated tools with only allow rules (no deny/alert) — overpermissive.
		if tool.Elevated && covered && !hasMatchingDenyOrAlertRule(tool.Name, p) {
			br.Warnings = append(br.Warnings, BindingWarning{
				Tool:        tool.Name,
				Category:    "overpermissive",
				Severity:    "high",
				Description: fmt.Sprintf("Elevated tool %q is only covered by allow rules with no deny or alert rules", tool.Name),
			})
		}

		// Check elevated tools with unlimited rate.
		if tool.Elevated && tool.RateLimit == 0 {
			br.Warnings = append(br.Warnings, BindingWarning{
				Tool:        tool.Name,
				Category:    "rate_limit_missing",
				Severity:    "medium",
				Description: fmt.Sprintf("Elevated tool %q has no rate limit configured", tool.Name),
			})
		}
	}

	// Check capability-guardrail coverage.
	checkCapabilityGuardrails(a, p, br)

	// Compute score.
	br.Score = computeScore(br)
	br.Grade = gradeBinding(br.Score)

	return br
}

// EvaluateAll evaluates all agents in the inventory against a single policy,
// producing a comprehensive binding report.
func (inv *Inventory) EvaluateAll(p *policy.Policy) *InventoryBindingReport {
	if inv == nil || p == nil {
		pName := ""
		if p != nil {
			pName = p.Meta.Name
		}
		return &InventoryBindingReport{
			PolicyName: pName,
		}
	}

	ibr := &InventoryBindingReport{
		PolicyName:  p.Meta.Name,
		TotalAgents: len(inv.Agents),
	}

	for _, a := range inv.Agents {
		result := EvaluateBinding(a, p)
		ibr.Results = append(ibr.Results, *result)

		if len(result.UncoveredTools) == 0 && len(result.ElevatedUncovered) == 0 {
			ibr.FullyCovered++
		}
		ibr.Warnings += len(result.Warnings)
	}

	return ibr
}

// isToolCoveredByPolicy returns true if any rule in the policy matches the tool name.
func isToolCoveredByPolicy(toolName string, p *policy.Policy) bool {
	for _, rule := range p.Rules {
		for _, pattern := range rule.Match.Tools {
			if policy.GlobMatch(pattern, toolName) {
				return true
			}
		}
	}
	return false
}

// hasMatchingDenyRule returns true if any deny rule in the policy matches the tool.
func hasMatchingDenyRule(toolName string, p *policy.Policy) bool {
	for _, rule := range p.Rules {
		if rule.Effect != "deny" {
			continue
		}
		for _, pattern := range rule.Match.Tools {
			if policy.GlobMatch(pattern, toolName) {
				return true
			}
		}
	}
	return false
}

// hasMatchingDenyOrAlertRule returns true if any deny or alert rule matches the tool.
func hasMatchingDenyOrAlertRule(toolName string, p *policy.Policy) bool {
	for _, rule := range p.Rules {
		if rule.Effect != "deny" && rule.Effect != "alert" {
			continue
		}
		for _, pattern := range rule.Match.Tools {
			if policy.GlobMatch(pattern, toolName) {
				return true
			}
		}
	}
	return false
}

// checkCapabilityGuardrails verifies that agent capabilities have corresponding
// guardrail and policy coverage.
func checkCapabilityGuardrails(a *Agent, p *policy.Policy, br *BindingResult) {
	// code_execution capability requires a "tool-call" guardrail.
	if a.Capabilities.CodeExecution {
		if !hasGuardrailType(a, "tool-call") {
			br.Warnings = append(br.Warnings, BindingWarning{
				Capability:  "code_execution",
				Category:    "missing_guardrail",
				Severity:    "high",
				Description: fmt.Sprintf("Agent %q has code_execution capability but no tool-call guardrail defined", a.Meta.Name),
			})
		}
	}

	// rag capability requires an "input" guardrail.
	if a.Capabilities.RAG {
		if !hasGuardrailType(a, "input") {
			br.Warnings = append(br.Warnings, BindingWarning{
				Capability:  "rag",
				Category:    "missing_guardrail",
				Severity:    "high",
				Description: fmt.Sprintf("Agent %q has rag capability but no input guardrail defined", a.Meta.Name),
			})
		}
	}

	// message_passing capability requires a policy rule mentioning "agent_message".
	if a.Capabilities.MessagePassing {
		if !policyMentionsAgentMessage(p) {
			br.Warnings = append(br.Warnings, BindingWarning{
				Capability:  "message_passing",
				Category:    "missing_guardrail",
				Severity:    "medium",
				Description: fmt.Sprintf("Agent %q has message_passing capability but no policy rule covers agent_message", a.Meta.Name),
			})
		}
	}
}

// hasGuardrailType returns true if the agent has a guardrail of the given type.
func hasGuardrailType(a *Agent, gType string) bool {
	for _, g := range a.Guardrails {
		if g.Type == gType {
			return true
		}
	}
	return false
}

// policyMentionsAgentMessage checks if any rule in the policy has "agent_message"
// (or a matching glob) in its Match.Tools.
func policyMentionsAgentMessage(p *policy.Policy) bool {
	for _, rule := range p.Rules {
		for _, pattern := range rule.Match.Tools {
			if policy.GlobMatch(pattern, "agent_message") {
				return true
			}
		}
	}
	return false
}

// computeScore calculates the binding coverage score.
// Starts at 1.0 and deducts penalties:
//   - Each uncovered tool: -0.1
//   - Each elevated uncovered tool: -0.15
//   - Each high/critical warning: -0.05
//
// The score is floored at 0.0.
func computeScore(br *BindingResult) float64 {
	score := 1.0

	score -= float64(len(br.UncoveredTools)) * 0.1
	score -= float64(len(br.ElevatedUncovered)) * 0.15

	for _, w := range br.Warnings {
		if w.Severity == "high" || w.Severity == "critical" {
			score -= 0.05
		}
	}

	if score < 0.0 {
		score = 0.0
	}
	return score
}

// gradeBinding converts a numeric coverage score to a letter grade.
//
//	A: score >= 0.9
//	B: score >= 0.7
//	C: score >= 0.5
//	D: score >= 0.3
//	F: score <  0.3
func gradeBinding(score float64) string {
	switch {
	case score >= 0.9:
		return "A"
	case score >= 0.7:
		return "B"
	case score >= 0.5:
		return "C"
	case score >= 0.3:
		return "D"
	default:
		return "F"
	}
}

// agentNameOrEmpty returns the agent's name or an empty string if nil.
func agentNameOrEmpty(a *Agent) string {
	if a == nil {
		return ""
	}
	return a.Meta.Name
}

// policyNameOrEmpty returns the policy's name or an empty string if nil.
func policyNameOrEmpty(p *policy.Policy) string {
	if p == nil {
		return ""
	}
	return p.Meta.Name
}

// FormatBinding renders a single BindingResult as a box-drawing report.
func FormatBinding(br *BindingResult) string {
	if br == nil {
		return "No binding result.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│             POLICY BINDING                      │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Agent:  %-40s │\n", truncate(br.AgentName, 40))
	fmt.Fprintf(&sb, "│ Policy: %-40s │\n", truncate(br.PolicyName, 40))
	fmt.Fprintf(&sb, "│ Score:  %-40s │\n", fmt.Sprintf("%.2f (%s)", br.Score, br.Grade))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Covered tools.
	if len(br.CoveredTools) > 0 {
		sb.WriteString("│ Covered Tools                                   │\n")
		for _, t := range br.CoveredTools {
			fmt.Fprintf(&sb, "│   [OK] %-41s │\n", truncate(t, 41))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Uncovered tools.
	if len(br.UncoveredTools) > 0 {
		sb.WriteString("│ Uncovered Tools                                 │\n")
		for _, t := range br.UncoveredTools {
			fmt.Fprintf(&sb, "│   [!!] %-41s │\n", truncate(t, 41))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Elevated uncovered.
	if len(br.ElevatedUncovered) > 0 {
		sb.WriteString("│ Elevated Without Deny Rules                     │\n")
		for _, t := range br.ElevatedUncovered {
			fmt.Fprintf(&sb, "│   [!!] %-41s │\n", truncate(t, 41))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Warnings.
	if len(br.Warnings) > 0 {
		sb.WriteString("│ Warnings                                        │\n")
		for _, w := range br.Warnings {
			label := w.Tool
			if label == "" {
				label = w.Capability
			}
			fmt.Fprintf(&sb, "│  [%-8s] %-36s │\n",
				truncate(w.Severity, 8),
				truncate(w.Category+": "+label, 36))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// FormatInventoryBinding renders a full InventoryBindingReport as a box-drawing report.
func FormatInventoryBinding(ibr *InventoryBindingReport) string {
	if ibr == nil {
		return "No inventory binding report.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│          INVENTORY BINDING REPORT               │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Policy:        %-33s │\n", truncate(ibr.PolicyName, 33))
	fmt.Fprintf(&sb, "│ Total Agents:  %-33d │\n", ibr.TotalAgents)
	fmt.Fprintf(&sb, "│ Fully Covered: %-33d │\n", ibr.FullyCovered)
	fmt.Fprintf(&sb, "│ Total Warnings:%-33d │\n", ibr.Warnings)
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Sort results by score ascending (worst first) for attention.
	sorted := make([]BindingResult, len(ibr.Results))
	copy(sorted, ibr.Results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score < sorted[j].Score
	})

	sb.WriteString("│ Agent Results (worst first)                     │\n")
	for _, r := range sorted {
		status := "[OK]"
		if len(r.UncoveredTools) > 0 || len(r.ElevatedUncovered) > 0 {
			status = "[!!]"
		}
		fmt.Fprintf(&sb, "│  %s %-20s  Score: %.2f (%s) %3dW │\n",
			status,
			truncate(r.AgentName, 20),
			r.Score,
			r.Grade,
			len(r.Warnings))
	}

	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Coverage summary.
	covPct := 0.0
	if ibr.TotalAgents > 0 {
		covPct = float64(ibr.FullyCovered) / float64(ibr.TotalAgents) * 100
	}
	fmt.Fprintf(&sb, "│ Coverage: %.0f%% of agents fully covered %9s│\n", covPct, "")

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}
