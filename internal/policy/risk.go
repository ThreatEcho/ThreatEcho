// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"sort"
	"strings"
)

// RiskAssessment is the result of analyzing a policy's risk posture.
type RiskAssessment struct {
	PolicyName      string          `json:"policy_name"`
	OverallScore    float64         `json:"overall_score"` // 0.0 (secure) to 1.0 (risky)
	OverallGrade    string          `json:"overall_grade"` // A/B/C/D/F
	Dimensions      []RiskDimension `json:"dimensions"`
	Findings        []RiskFinding   `json:"findings"`
	Recommendations []string        `json:"recommendations"`
}

// RiskDimension is one axis of risk evaluation.
type RiskDimension struct {
	Name        string  `json:"name"`
	Score       float64 `json:"score"`  // 0.0-1.0
	Weight      float64 `json:"weight"` // contribution weight
	Description string  `json:"description"`
}

// RiskFinding is a specific weakness found in the policy.
type RiskFinding struct {
	Severity    string `json:"severity"` // critical/high/medium/low/info
	Category    string `json:"category"` // coverage-gap, conflict, structural, missing-deny, excessive-allow
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// defaultRefTools is the canonical set of agent tools for coverage analysis
// when no reference set is provided.
var defaultRefTools = []string{
	"tool_call",
	"send_email",
	"search_knowledge_base",
	"write_knowledge_base",
	"agent_message",
	"http_request",
	"shell_exec",
	"dns_query",
	"file_access",
	"registry_access",
	"service_control",
	"process_exec",
}

// highRiskToolSet lists tools that should have explicit deny rules.
var highRiskToolSet = map[string]bool{
	"shell_exec":      true,
	"file_access":     true,
	"process_exec":    true,
	"service_control": true,
	"registry_access": true,
}

// severityRank maps severity levels to sort order (lower = more severe).
var severityRank = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}

// AssessRisk evaluates the risk posture of a policy using the default
// reference tool set.
func AssessRisk(p *Policy) *RiskAssessment {
	return AssessRiskWithCoverage(p, nil)
}

// AssessRiskWithCoverage evaluates risk including coverage against the
// given reference tools. When refTools is nil the default agent tool set
// is used.
func AssessRiskWithCoverage(p *Policy, refTools []string) *RiskAssessment {
	if refTools == nil {
		refTools = defaultRefTools
	}

	ra := &RiskAssessment{}

	// Nil policy — worst case.
	if p == nil {
		ra.PolicyName = "(nil)"
		ra.OverallScore = 1.0
		ra.OverallGrade = scoreToGrade(1.0)
		ra.Dimensions = worstCaseDimensions()
		ra.Findings = []RiskFinding{{
			Severity:    "critical",
			Category:    "structural",
			Title:       "No policy defined",
			Description: "No policy was provided for risk assessment.",
			Remediation: "Create a policy with deny and allow rules.",
		}}
		ra.Recommendations = []string{
			"Create a policy with both deny and allow rules.",
			"Define rules for high-risk tools: shell_exec, file_access, process_exec.",
		}
		return ra
	}

	ra.PolicyName = p.Meta.Name

	// Empty rules — still worst case.
	if len(p.Rules) == 0 {
		ra.OverallScore = 1.0
		ra.OverallGrade = scoreToGrade(1.0)
		ra.Dimensions = worstCaseDimensions()
		ra.Findings = []RiskFinding{{
			Severity:    "critical",
			Category:    "structural",
			Title:       "Policy has no rules",
			Description: "The policy exists but contains no rules, providing no protection.",
			Remediation: "Add deny and allow rules to define agent boundaries.",
		}}
		ra.Recommendations = []string{
			"Add rules to the policy — it currently provides no enforcement.",
			"Start with deny rules for high-risk tools: shell_exec, file_access.",
		}
		return ra
	}

	// Compute each risk dimension.
	var findings []RiskFinding
	var recommendations []string

	coverageScore, cf, cr := assessCoverageDim(p, refTools)
	findings = append(findings, cf...)
	recommendations = append(recommendations, cr...)

	conflictScore, cf, cr := assessConflictDim(p)
	findings = append(findings, cf...)
	recommendations = append(recommendations, cr...)

	denyScore, cf, cr := assessDenyDim(p)
	findings = append(findings, cf...)
	recommendations = append(recommendations, cr...)

	structScore, cf, cr := assessStructuralDim(p)
	findings = append(findings, cf...)
	recommendations = append(recommendations, cr...)

	elevatedScore, cf, cr := assessElevatedDim(p)
	findings = append(findings, cf...)
	recommendations = append(recommendations, cr...)

	ra.Dimensions = []RiskDimension{
		{Name: "Coverage", Score: coverageScore, Weight: 0.3,
			Description: "Tool and tactic coverage gaps"},
		{Name: "Conflict Density", Score: conflictScore, Weight: 0.2,
			Description: "Conflicting rule ratio"},
		{Name: "Deny Coverage", Score: denyScore, Weight: 0.2,
			Description: "Proportion of deny rules"},
		{Name: "Structural Quality", Score: structScore, Weight: 0.15,
			Description: "Rule IDs, priorities, conditions, effect mix"},
		{Name: "Elevated Access", Score: elevatedScore, Weight: 0.15,
			Description: "Elevated execution control"},
	}

	// Weighted sum.
	ra.OverallScore = 0
	for _, d := range ra.Dimensions {
		ra.OverallScore += d.Score * d.Weight
	}
	if ra.OverallScore > 1.0 {
		ra.OverallScore = 1.0
	}
	if ra.OverallScore < 0.0 {
		ra.OverallScore = 0.0
	}

	ra.OverallGrade = scoreToGrade(ra.OverallScore)

	// Sort findings by severity (critical first).
	sort.Slice(findings, func(i, j int) bool {
		si := severityRank[findings[i].Severity]
		sj := severityRank[findings[j].Severity]
		if si != sj {
			return si < sj
		}
		return findings[i].Title < findings[j].Title
	})
	ra.Findings = findings
	ra.Recommendations = dedupStrings(recommendations)

	return ra
}

// scoreToGrade converts a 0.0-1.0 score to a letter grade.
// A (0.0-0.2), B (0.2-0.4), C (0.4-0.6), D (0.6-0.8), F (0.8-1.0).
func scoreToGrade(score float64) string {
	switch {
	case score < 0.2:
		return "A"
	case score < 0.4:
		return "B"
	case score < 0.6:
		return "C"
	case score < 0.8:
		return "D"
	default:
		return "F"
	}
}

// ---------------------------------------------------------------------------
// Dimension assessors
// ---------------------------------------------------------------------------

// assessCoverageDim evaluates tool/tactic/action coverage (weight 0.3).
func assessCoverageDim(p *Policy, refTools []string) (float64, []RiskFinding, []string) {
	cov := AnalyzeCoverage(p, refTools)

	avg := (cov.ToolsCoveragePct + cov.TacticsCoveragePct + cov.ActionsCoveragePct) / 3.0
	score := clamp01(1.0 - avg/100.0)

	var findings []RiskFinding
	var recs []string

	for _, gap := range cov.Gaps {
		if gap.Risk != "high" {
			continue
		}
		sev := "high"
		if gap.Dimension == "tool" && highRiskToolSet[gap.Value] {
			sev = "critical"
		}
		findings = append(findings, RiskFinding{
			Severity:    sev,
			Category:    "coverage-gap",
			Title:       fmt.Sprintf("No rules cover %s %q", gap.Dimension, gap.Value),
			Description: fmt.Sprintf("The %s %q has no matching rules, leaving it uncontrolled.", gap.Dimension, gap.Value),
			Remediation: fmt.Sprintf("Add a deny or alert rule matching %s %q.", gap.Dimension, gap.Value),
		})
	}

	if len(cov.ToolsUncovered) > 0 {
		if len(cov.ToolsUncovered) <= 3 {
			recs = append(recs, fmt.Sprintf("Add rules for uncovered tools: %s.",
				strings.Join(cov.ToolsUncovered, ", ")))
		} else {
			recs = append(recs, fmt.Sprintf("Add rules for %d uncovered tools including %s.",
				len(cov.ToolsUncovered), cov.ToolsUncovered[0]))
		}
	}

	totalTactics := len(cov.TacticsCovered) + len(cov.TacticsUncovered)
	if len(cov.TacticsUncovered) > 3 {
		recs = append(recs, fmt.Sprintf("Add tactic coverage — %d of %d tactics have no rules.",
			len(cov.TacticsUncovered), totalTactics))
	}

	if len(cov.ActionsUncovered) > 0 {
		recs = append(recs, fmt.Sprintf("Add rules for uncovered actions: %s.",
			strings.Join(cov.ActionsUncovered, ", ")))
	}

	return score, findings, recs
}

// assessConflictDim evaluates conflict density (weight 0.2).
func assessConflictDim(p *Policy) (float64, []RiskFinding, []string) {
	conflicts := CheckConflicts(p)

	score := clamp01(float64(len(conflicts)) / float64(len(p.Rules)))

	var findings []RiskFinding
	var recs []string

	for _, c := range conflicts {
		findings = append(findings, RiskFinding{
			Severity:    "medium",
			Category:    "conflict",
			Title:       fmt.Sprintf("Conflicting rules on %s %q", c.Dimension, c.Overlap),
			Description: c.Description,
			Remediation: fmt.Sprintf("Adjust priorities or narrow match criteria to resolve the %s conflict between rules %q and %q.",
				c.Dimension, c.RuleA.ID, c.RuleB.ID),
		})
	}

	if len(conflicts) > 0 {
		recs = append(recs, fmt.Sprintf("Resolve %d conflicting rules that may cause unpredictable enforcement.",
			len(conflicts)))
	}

	return score, findings, recs
}

// assessDenyDim evaluates the proportion of deny rules (weight 0.2).
func assessDenyDim(p *Policy) (float64, []RiskFinding, []string) {
	denyCount := 0
	for _, r := range p.Rules {
		if r.Effect == "deny" {
			denyCount++
		}
	}

	denyRatio := float64(denyCount) / float64(len(p.Rules))
	score := clamp01(1.0 - denyRatio)

	var findings []RiskFinding
	var recs []string

	if denyCount == 0 {
		findings = append(findings, RiskFinding{
			Severity:    "critical",
			Category:    "missing-deny",
			Title:       "No deny rules in policy",
			Description: "The policy contains only allow/alert rules with no deny rules, providing no enforcement boundary.",
			Remediation: "Add deny rules for dangerous tools and actions to establish security boundaries.",
		})
		recs = append(recs, "Add deny rules to establish enforcement boundaries — allow-only policies provide no protection.")
	} else if denyRatio < 0.2 {
		findings = append(findings, RiskFinding{
			Severity:    "high",
			Category:    "missing-deny",
			Title:       fmt.Sprintf("Low deny rule ratio (%.0f%%)", denyRatio*100),
			Description: fmt.Sprintf("Only %d of %d rules are deny rules, providing weak enforcement.", denyCount, len(p.Rules)),
			Remediation: "Add more deny rules to improve the enforcement boundary.",
		})
		recs = append(recs, "Increase deny rule coverage to strengthen enforcement boundaries.")
	}

	return score, findings, recs
}

// assessStructuralDim evaluates structural quality (weight 0.15).
// Four checks, each contributing 0.25 to the dimension score.
func assessStructuralDim(p *Policy) (float64, []RiskFinding, []string) {
	penalty := 0.0
	var findings []RiskFinding
	var recs []string

	// Check 1: Do all rules have IDs?
	missingIDs := 0
	for _, r := range p.Rules {
		if r.ID == "" {
			missingIDs++
		}
	}
	if missingIDs > 0 {
		penalty += 0.25
		findings = append(findings, RiskFinding{
			Severity:    "medium",
			Category:    "structural",
			Title:       fmt.Sprintf("%d rules missing IDs", missingIDs),
			Description: "Rules without IDs are harder to reference in violations and audit logs.",
			Remediation: "Assign unique IDs to all rules.",
		})
		recs = append(recs, "Assign unique IDs to all rules for traceability.")
	}

	// Check 2: Are distinct priorities set?
	if len(p.Rules) > 1 {
		allSame := true
		first := p.Rules[0].Priority
		for _, r := range p.Rules[1:] {
			if r.Priority != first {
				allSame = false
				break
			}
		}
		if allSame {
			penalty += 0.25
			findings = append(findings, RiskFinding{
				Severity:    "low",
				Category:    "structural",
				Title:       "All rules share the same priority",
				Description: "Rules with identical priorities may be evaluated in undefined order.",
				Remediation: "Set distinct priorities to ensure deterministic evaluation order.",
			})
			recs = append(recs, "Set distinct priorities on rules to ensure deterministic evaluation order.")
		}
	}

	// Check 3: Are conditions used on any rules?
	hasConditions := false
	for _, r := range p.Rules {
		if len(r.Conditions) > 0 {
			hasConditions = true
			break
		}
	}
	if !hasConditions {
		penalty += 0.25
		findings = append(findings, RiskFinding{
			Severity:    "info",
			Category:    "structural",
			Title:       "No conditions used in any rules",
			Description: "Rules without conditions match broadly; conditions narrow matches for precision.",
			Remediation: "Add conditions to rules to narrow match scope (e.g., elevated, platform, technique).",
		})
		recs = append(recs, "Add conditions to rules to narrow match scope.")
	}

	// Check 4: Does the policy have both allow and deny rules?
	hasAllow, hasDeny := false, false
	for _, r := range p.Rules {
		switch r.Effect {
		case "allow":
			hasAllow = true
		case "deny":
			hasDeny = true
		}
	}
	if !hasAllow || !hasDeny {
		penalty += 0.25
		missing := "deny"
		if !hasAllow {
			missing = "allow"
		}
		findings = append(findings, RiskFinding{
			Severity:    "high",
			Category:    "structural",
			Title:       fmt.Sprintf("No %s rules in policy", missing),
			Description: fmt.Sprintf("The policy has no %s rules; a well-structured policy uses both allow and deny.", missing),
			Remediation: fmt.Sprintf("Add %s rules to create a balanced enforcement policy.", missing),
		})
		recs = append(recs, fmt.Sprintf("Add %s rules for a balanced policy with clear boundaries.", missing))
	}

	return clamp01(penalty), findings, recs
}

// assessElevatedDim evaluates elevated execution control (weight 0.15).
// Two sub-checks, each contributing up to 0.5.
func assessElevatedDim(p *Policy) (float64, []RiskFinding, []string) {
	penalty := 0.0
	var findings []RiskFinding
	var recs []string

	// Sub-check 1: Do any allow rules explicitly permit elevated execution?
	for _, r := range p.Rules {
		if r.Effect != "allow" {
			continue
		}
		for _, c := range r.Conditions {
			if c.Field == "elevated" && c.Operator == "eq" && c.Value == "true" {
				penalty += 0.5
				findings = append(findings, RiskFinding{
					Severity:    "critical",
					Category:    "excessive-allow",
					Title:       "Allow rule permits elevated execution",
					Description: fmt.Sprintf("Rule %q explicitly allows elevated execution, bypassing containment.", r.ID),
					Remediation: "Remove the elevated condition from allow rules, or add a higher-priority deny rule for elevated calls.",
				})
				recs = append(recs, "Restrict elevated execution with explicit deny rules.")
				goto denyCheck // only penalize once
			}
		}
	}

denyCheck:
	// Sub-check 2: Do deny rules cover high-risk tools?
	deniedTools := make(map[string]bool)
	for _, r := range p.Rules {
		if r.Effect == "deny" {
			for _, t := range r.Match.Tools {
				deniedTools[t] = true
			}
		}
	}

	var missing []string
	for tool := range highRiskToolSet {
		if !toolCovered(tool, deniedTools) {
			missing = append(missing, tool)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		fraction := float64(len(missing)) / float64(len(highRiskToolSet))
		penalty += 0.5 * fraction

		for _, tool := range missing {
			sev := "high"
			if tool == "shell_exec" || tool == "process_exec" {
				sev = "critical"
			}
			findings = append(findings, RiskFinding{
				Severity:    sev,
				Category:    "missing-deny",
				Title:       fmt.Sprintf("No deny rule for %s", tool),
				Description: fmt.Sprintf("The high-risk tool %q has no deny rule, allowing unrestricted use.", tool),
				Remediation: fmt.Sprintf("Add a deny rule for %s to prevent unauthorized use.", tool),
			})
		}
		recs = append(recs, fmt.Sprintf("Add deny rules for high-risk tools: %s.",
			strings.Join(missing, ", ")))
	}

	return clamp01(penalty), findings, recs
}

// ---------------------------------------------------------------------------
// Format
// ---------------------------------------------------------------------------

// FormatRiskAssessment returns a box-drawing formatted risk report.
func FormatRiskAssessment(ra *RiskAssessment) string {
	if ra == nil {
		return "No risk assessment.\n"
	}

	var b strings.Builder

	// Header.
	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│             Policy Risk Assessment                  │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Policy: %-43s │\n", truncStr(ra.PolicyName, 43)))
	b.WriteString(fmt.Sprintf("│ Grade:  %-43s │\n", ra.OverallGrade))
	b.WriteString(fmt.Sprintf("│ Score:  %-43s │\n",
		fmt.Sprintf("%.2f / 1.00", ra.OverallScore)))

	// Dimensions.
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	b.WriteString("│ Dimensions                                          │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	for _, d := range ra.Dimensions {
		name := truncStr(d.Name, 18)
		bar := riskBar(d.Score)
		line := fmt.Sprintf(" %-18s  %.2f  %s", name, d.Score, bar)
		b.WriteString(fmt.Sprintf("│%-53s│\n", line))
	}

	// Findings.
	if len(ra.Findings) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString(fmt.Sprintf("│ Findings (%d)%-41s│\n", len(ra.Findings), ""))
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for i, f := range ra.Findings {
			if i >= 15 {
				rem := fmt.Sprintf("   ... and %d more", len(ra.Findings)-15)
				b.WriteString(fmt.Sprintf("│%-53s│\n", rem))
				break
			}
			sev := fmt.Sprintf("[%s]", strings.ToUpper(f.Severity))
			maxTitle := 51 - len(sev) - 2 // 2 for leading space + space after sev
			title := truncStr(f.Title, maxTitle)
			line := fmt.Sprintf(" %-10s %s", sev, title)
			b.WriteString(fmt.Sprintf("│%-53s│\n", line))
		}
	}

	// Recommendations.
	if len(ra.Recommendations) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│ Recommendations                                     │\n")
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for i, r := range ra.Recommendations {
			if i >= 10 {
				break
			}
			line := fmt.Sprintf("  %d. %s", i+1, truncStr(r, 48))
			b.WriteString(fmt.Sprintf("│%-53s│\n", line))
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}

// riskBar renders a 20-char bar for a 0.0-1.0 risk score.
func riskBar(score float64) string {
	const barWidth = 20
	filled := int(score * float64(barWidth))
	if filled < 0 {
		filled = 0
	}
	if filled > barWidth {
		filled = barWidth
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled) + "]"
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// worstCaseDimensions returns all-1.0 dimensions for nil/empty policies.
func worstCaseDimensions() []RiskDimension {
	return []RiskDimension{
		{Name: "Coverage", Score: 1.0, Weight: 0.3, Description: "Tool and tactic coverage gaps"},
		{Name: "Conflict Density", Score: 1.0, Weight: 0.2, Description: "Conflicting rule ratio"},
		{Name: "Deny Coverage", Score: 1.0, Weight: 0.2, Description: "Proportion of deny rules"},
		{Name: "Structural Quality", Score: 1.0, Weight: 0.15, Description: "Rule IDs, priorities, conditions, effect mix"},
		{Name: "Elevated Access", Score: 1.0, Weight: 0.15, Description: "Elevated execution control"},
	}
}

// clamp01 constrains a value to [0.0, 1.0].
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// dedupStrings removes duplicate strings preserving order.
func dedupStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
