// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Lint severity and finding types
// ---------------------------------------------------------------------------

// LintSeverity classifies the importance of a lint finding.
type LintSeverity string

const (
	LintError   LintSeverity = "error"   // must fix — will cause incorrect behavior
	LintWarning LintSeverity = "warning" // should fix — likely unintended
	LintInfo    LintSeverity = "info"    // improvement opportunity
	LintStyle   LintSeverity = "style"   // cosmetic / convention
)

// LintCategory groups related findings.
type LintCategory string

const (
	LintCatSecurity     LintCategory = "security"      // rules guarding dangerous tools/actions
	LintCatCoverage     LintCategory = "coverage"      // gaps in what the policy protects
	LintCatRedundancy   LintCategory = "redundancy"    // duplicate or conflicting rules
	LintCatNaming       LintCategory = "naming"        // naming conventions and metadata
	LintCatComplexity   LintCategory = "complexity"    // overly complex rule sets
	LintCatBestPractice LintCategory = "best-practice" // general policy hygiene
)

// LintFinding is a single lint diagnostic.
type LintFinding struct {
	Rule       string       `json:"rule"` // machine-readable rule ID, e.g. "no-wildcard-deny"
	Severity   LintSeverity `json:"severity"`
	Category   LintCategory `json:"category"`
	Message    string       `json:"message"`
	RuleID     string       `json:"rule_id,omitempty"`    // policy rule ID this finding refers to
	Suggestion string       `json:"suggestion,omitempty"` // actionable fix
}

// LintReport is the aggregate result of linting a policy.
type LintReport struct {
	PolicyName   string        `json:"policy_name"`
	TotalRules   int           `json:"total_rules"`
	FindingCount int           `json:"finding_count"`
	ErrorCount   int           `json:"error_count"`
	WarningCount int           `json:"warning_count"`
	InfoCount    int           `json:"info_count"`
	StyleCount   int           `json:"style_count"`
	Findings     []LintFinding `json:"findings"`
	Score        float64       `json:"score"` // 0.0 (terrible) to 1.0 (perfect)
	Grade        string        `json:"grade"` // A/B/C/D/F
	Summary      string        `json:"summary"`
}

// ---------------------------------------------------------------------------
// Main lint entry point
// ---------------------------------------------------------------------------

// LintPolicy checks a policy for best-practice issues beyond structural
// validation. It returns a report with all findings grouped and scored.
func LintPolicy(p *Policy) *LintReport {
	if p == nil {
		return &LintReport{
			Summary: "No policy provided.",
			Grade:   "F",
		}
	}

	var findings []LintFinding

	// Run all lint checks.
	findings = append(findings, lintSecurity(p)...)
	findings = append(findings, lintCoverage(p)...)
	findings = append(findings, lintRedundancy(p)...)
	findings = append(findings, lintNaming(p)...)
	findings = append(findings, lintComplexity(p)...)
	findings = append(findings, lintBestPractice(p)...)

	// Sort by severity: error > warning > info > style.
	sort.SliceStable(findings, func(i, j int) bool {
		return lintSeverityRank(findings[i].Severity) > lintSeverityRank(findings[j].Severity)
	})

	// Count by severity.
	var errCount, warnCount, infoCount, styleCount int
	for _, f := range findings {
		switch f.Severity {
		case LintError:
			errCount++
		case LintWarning:
			warnCount++
		case LintInfo:
			infoCount++
		case LintStyle:
			styleCount++
		}
	}

	score := computeLintScore(errCount, warnCount, infoCount, styleCount, len(p.Rules))
	grade := gradeLint(score)

	report := &LintReport{
		PolicyName:   p.Meta.Name,
		TotalRules:   len(p.Rules),
		FindingCount: len(findings),
		ErrorCount:   errCount,
		WarningCount: warnCount,
		InfoCount:    infoCount,
		StyleCount:   styleCount,
		Findings:     findings,
		Score:        score,
		Grade:        grade,
	}
	report.Summary = summarizeLint(report)
	return report
}

// ---------------------------------------------------------------------------
// Security checks
// ---------------------------------------------------------------------------

func lintSecurity(p *Policy) []LintFinding {
	var findings []LintFinding

	// SEC-001: Wildcard deny rules are dangerous — block all tools.
	for _, r := range p.Rules {
		if r.Effect == "deny" {
			for _, t := range r.Match.Tools {
				if t == "*" {
					findings = append(findings, LintFinding{
						Rule:       "SEC-001",
						Severity:   LintWarning,
						Category:   LintCatSecurity,
						Message:    fmt.Sprintf("Rule %q uses wildcard deny on all tools — may be overly restrictive", r.ID),
						RuleID:     r.ID,
						Suggestion: "Consider denying specific tools instead of *, or add allow rules for known-good tools",
					})
				}
			}
		}
	}

	// SEC-002: No deny rules at all — policy is purely permissive.
	hasDeny := false
	for _, r := range p.Rules {
		if r.Effect == "deny" {
			hasDeny = true
			break
		}
	}
	if !hasDeny && len(p.Rules) > 0 {
		findings = append(findings, LintFinding{
			Rule:       "SEC-002",
			Severity:   LintWarning,
			Category:   LintCatSecurity,
			Message:    "Policy has no deny rules — all tool calls are implicitly permitted",
			Suggestion: "Add deny rules for dangerous tools (shell_exec, file_access, etc.)",
		})
	}

	// SEC-003: Allow rule with no conditions on elevated tools.
	elevatedPatterns := []string{"shell_exec", "admin_*", "root_*", "sudo_*", "database_write", "file_delete"}
	for _, r := range p.Rules {
		if r.Effect == "allow" && len(r.Conditions) == 0 {
			for _, t := range r.Match.Tools {
				for _, ep := range elevatedPatterns {
					if t == ep || (strings.HasSuffix(ep, "*") && strings.HasPrefix(t, ep[:len(ep)-1])) {
						findings = append(findings, LintFinding{
							Rule:       "SEC-003",
							Severity:   LintError,
							Category:   LintCatSecurity,
							Message:    fmt.Sprintf("Rule %q unconditionally allows elevated tool %q", r.ID, t),
							RuleID:     r.ID,
							Suggestion: "Add conditions (e.g., trust level, tactic) to restrict elevated tool access",
						})
					}
				}
			}
		}
	}

	// SEC-004: No alert rules — no monitoring visibility.
	hasAlert := false
	for _, r := range p.Rules {
		if r.Effect == "alert" {
			hasAlert = true
			break
		}
	}
	if !hasAlert && len(p.Rules) > 0 {
		findings = append(findings, LintFinding{
			Rule:       "SEC-004",
			Severity:   LintInfo,
			Category:   LintCatSecurity,
			Message:    "Policy has no alert rules — no monitoring or audit trail for tool calls",
			Suggestion: "Add alert rules for sensitive operations to maintain visibility",
		})
	}

	// SEC-005: Deny without description.
	for _, r := range p.Rules {
		if r.Effect == "deny" && r.Description == "" {
			findings = append(findings, LintFinding{
				Rule:       "SEC-005",
				Severity:   LintInfo,
				Category:   LintCatSecurity,
				Message:    fmt.Sprintf("Deny rule %q has no description — operators won't know why calls are blocked", r.ID),
				RuleID:     r.ID,
				Suggestion: "Add a description explaining the security rationale for this deny rule",
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Coverage checks
// ---------------------------------------------------------------------------

func lintCoverage(p *Policy) []LintFinding {
	var findings []LintFinding

	// COV-001: Few rules — policy may be under-specified.
	if len(p.Rules) > 0 && len(p.Rules) < 3 {
		findings = append(findings, LintFinding{
			Rule:       "COV-001",
			Severity:   LintInfo,
			Category:   LintCatCoverage,
			Message:    fmt.Sprintf("Policy has only %d rule(s) — consider broader coverage", len(p.Rules)),
			Suggestion: "A mature policy typically has 5+ rules covering deny, allow, and alert effects",
		})
	}

	// COV-002: Only one effect type used.
	effects := make(map[string]bool)
	for _, r := range p.Rules {
		effects[r.Effect] = true
	}
	if len(p.Rules) >= 3 && len(effects) == 1 {
		var only string
		for e := range effects {
			only = e
		}
		findings = append(findings, LintFinding{
			Rule:       "COV-002",
			Severity:   LintWarning,
			Category:   LintCatCoverage,
			Message:    fmt.Sprintf("All %d rules use %q effect — missing defense in depth", len(p.Rules), only),
			Suggestion: "Use a mix of deny, allow, and alert rules for defense in depth",
		})
	}

	// COV-003: No tactic-based rules.
	hasTacticRule := false
	for _, r := range p.Rules {
		if len(r.Match.Tactics) > 0 {
			hasTacticRule = true
			break
		}
	}
	if !hasTacticRule && len(p.Rules) >= 3 {
		findings = append(findings, LintFinding{
			Rule:       "COV-003",
			Severity:   LintInfo,
			Category:   LintCatCoverage,
			Message:    "No rules match by tactic — policy only covers specific tools, not attack patterns",
			Suggestion: "Add tactic-based rules (e.g., deny all tools in 'exfiltration' tactic) for broader coverage",
		})
	}

	// COV-004: No condition-based rules (all rules are unconditional).
	hasCondition := false
	for _, r := range p.Rules {
		if len(r.Conditions) > 0 {
			hasCondition = true
			break
		}
	}
	if !hasCondition && len(p.Rules) >= 5 {
		findings = append(findings, LintFinding{
			Rule:       "COV-004",
			Severity:   LintInfo,
			Category:   LintCatCoverage,
			Message:    "No rules use conditions — policy cannot distinguish context (e.g., trust level, platform)",
			Suggestion: "Add conditions to rules for context-aware policy evaluation",
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Redundancy checks
// ---------------------------------------------------------------------------

func lintRedundancy(p *Policy) []LintFinding {
	var findings []LintFinding

	// RED-001: Duplicate rule IDs.
	idCounts := make(map[string]int)
	for _, r := range p.Rules {
		idCounts[r.ID]++
	}
	for id, count := range idCounts {
		if count > 1 {
			findings = append(findings, LintFinding{
				Rule:       "RED-001",
				Severity:   LintError,
				Category:   LintCatRedundancy,
				Message:    fmt.Sprintf("Rule ID %q appears %d times — IDs must be unique", id, count),
				RuleID:     id,
				Suggestion: "Give each rule a unique ID",
			})
		}
	}

	// RED-002: Overlapping tool patterns in same-effect rules.
	type toolEffect struct {
		tool   string
		effect string
	}
	toolEffectRules := make(map[toolEffect][]string) // maps to rule IDs
	for _, r := range p.Rules {
		for _, t := range r.Match.Tools {
			key := toolEffect{tool: t, effect: r.Effect}
			toolEffectRules[key] = append(toolEffectRules[key], r.ID)
		}
	}
	reportedOverlaps := make(map[string]bool)
	for te, ruleIDs := range toolEffectRules {
		if len(ruleIDs) > 1 {
			key := te.tool + "|" + te.effect
			if !reportedOverlaps[key] {
				reportedOverlaps[key] = true
				findings = append(findings, LintFinding{
					Rule:     "RED-002",
					Severity: LintWarning,
					Category: LintCatRedundancy,
					Message: fmt.Sprintf("Tool %q with effect %q matched by multiple rules: %s",
						te.tool, te.effect, strings.Join(ruleIDs, ", ")),
					Suggestion: "Consolidate overlapping rules or differentiate with conditions/priorities",
				})
			}
		}
	}

	// RED-003: Conflicting rules — same tool has both allow and deny without priority difference.
	toolAllowDeny := make(map[string][]Rule)
	for _, r := range p.Rules {
		for _, t := range r.Match.Tools {
			toolAllowDeny[t] = append(toolAllowDeny[t], r)
		}
	}
	for tool, rules := range toolAllowDeny {
		hasAllow := false
		hasDenyRule := false
		for _, r := range rules {
			if r.Effect == "allow" {
				hasAllow = true
			}
			if r.Effect == "deny" {
				hasDenyRule = true
			}
		}
		if hasAllow && hasDenyRule {
			// Check if priorities differ (which is fine).
			allSamePriority := true
			first := rules[0].Priority
			for _, r := range rules[1:] {
				if r.Priority != first {
					allSamePriority = false
					break
				}
			}
			if allSamePriority {
				findings = append(findings, LintFinding{
					Rule:       "RED-003",
					Severity:   LintError,
					Category:   LintCatRedundancy,
					Message:    fmt.Sprintf("Tool %q has both allow and deny rules at the same priority — behavior is ambiguous", tool),
					Suggestion: "Set different priorities to make rule evaluation order explicit",
				})
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Naming checks
// ---------------------------------------------------------------------------

func lintNaming(p *Policy) []LintFinding {
	var findings []LintFinding

	// NAM-001: Policy has no name.
	if p.Meta.Name == "" {
		findings = append(findings, LintFinding{
			Rule:       "NAM-001",
			Severity:   LintWarning,
			Category:   LintCatNaming,
			Message:    "Policy has no name — will be difficult to identify in reports",
			Suggestion: "Add a descriptive meta.name to the policy",
		})
	}

	// NAM-002: Rule IDs should be kebab-case or snake_case.
	for _, r := range p.Rules {
		if r.ID != "" && !isKebabOrSnake(r.ID) {
			findings = append(findings, LintFinding{
				Rule:       "NAM-002",
				Severity:   LintStyle,
				Category:   LintCatNaming,
				Message:    fmt.Sprintf("Rule ID %q is not kebab-case or snake_case", r.ID),
				RuleID:     r.ID,
				Suggestion: "Use kebab-case (my-rule) or snake_case (my_rule) for consistency",
			})
		}
	}

	// NAM-003: Policy has no description.
	if p.Meta.Description == "" && p.Meta.Name != "" {
		findings = append(findings, LintFinding{
			Rule:       "NAM-003",
			Severity:   LintStyle,
			Category:   LintCatNaming,
			Message:    "Policy has no description",
			Suggestion: "Add meta.description explaining what this policy protects",
		})
	}

	// NAM-004: Rule IDs too short (less than 3 characters).
	for _, r := range p.Rules {
		if r.ID != "" && len(r.ID) < 3 {
			findings = append(findings, LintFinding{
				Rule:       "NAM-004",
				Severity:   LintStyle,
				Category:   LintCatNaming,
				Message:    fmt.Sprintf("Rule ID %q is very short — may be unclear in reports", r.ID),
				RuleID:     r.ID,
				Suggestion: "Use descriptive rule IDs like 'deny-shell-exec' or 'alert-exfiltration'",
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Complexity checks
// ---------------------------------------------------------------------------

func lintComplexity(p *Policy) []LintFinding {
	var findings []LintFinding

	// CPX-001: Very large rule set (> 50 rules).
	if len(p.Rules) > 50 {
		findings = append(findings, LintFinding{
			Rule:       "CPX-001",
			Severity:   LintWarning,
			Category:   LintCatComplexity,
			Message:    fmt.Sprintf("Policy has %d rules — consider splitting into multiple policies", len(p.Rules)),
			Suggestion: "Split into base policy + overlays, or use policy merge to compose smaller pieces",
		})
	}

	// CPX-002: Rule with many tool patterns (> 10).
	for _, r := range p.Rules {
		if len(r.Match.Tools) > 10 {
			findings = append(findings, LintFinding{
				Rule:       "CPX-002",
				Severity:   LintInfo,
				Category:   LintCatComplexity,
				Message:    fmt.Sprintf("Rule %q matches %d tools — consider using wildcards or splitting", r.ID, len(r.Match.Tools)),
				RuleID:     r.ID,
				Suggestion: "Use glob patterns (e.g., 'db_*') to simplify large tool lists",
			})
		}
	}

	// CPX-003: Rule with many conditions (> 5).
	for _, r := range p.Rules {
		if len(r.Conditions) > 5 {
			findings = append(findings, LintFinding{
				Rule:       "CPX-003",
				Severity:   LintInfo,
				Category:   LintCatComplexity,
				Message:    fmt.Sprintf("Rule %q has %d conditions — complex rules are hard to debug", r.ID, len(r.Conditions)),
				RuleID:     r.ID,
				Suggestion: "Break complex conditions into separate rules with clear priorities",
			})
		}
	}

	// CPX-004: Deep priority spread (max - min > 100).
	if len(p.Rules) > 1 {
		minPri := p.Rules[0].Priority
		maxPri := p.Rules[0].Priority
		for _, r := range p.Rules[1:] {
			if r.Priority < minPri {
				minPri = r.Priority
			}
			if r.Priority > maxPri {
				maxPri = r.Priority
			}
		}
		if maxPri-minPri > 100 {
			findings = append(findings, LintFinding{
				Rule:       "CPX-004",
				Severity:   LintInfo,
				Category:   LintCatComplexity,
				Message:    fmt.Sprintf("Priority range is %d to %d (spread %d) — large gaps make ordering hard to reason about", minPri, maxPri, maxPri-minPri),
				Suggestion: "Use a tighter priority range (e.g., 1-20) for easier maintenance",
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Best practice checks
// ---------------------------------------------------------------------------

func lintBestPractice(p *Policy) []LintFinding {
	var findings []LintFinding

	// BP-001: No default-deny or default-allow rule.
	hasDefaultRule := false
	for _, r := range p.Rules {
		for _, t := range r.Match.Tools {
			if t == "*" {
				hasDefaultRule = true
				break
			}
		}
		if hasDefaultRule {
			break
		}
	}
	if !hasDefaultRule && len(p.Rules) > 0 {
		findings = append(findings, LintFinding{
			Rule:       "BP-001",
			Severity:   LintWarning,
			Category:   LintCatBestPractice,
			Message:    "No default rule (matching *) — unmatched tool calls have no explicit disposition",
			Suggestion: "Add a low-priority default-deny or default-alert rule for unmatched tools",
		})
	}

	// BP-002: No authors listed (only relevant when policy has rules).
	if len(p.Meta.Authors) == 0 && len(p.Rules) > 0 {
		findings = append(findings, LintFinding{
			Rule:       "BP-002",
			Severity:   LintStyle,
			Category:   LintCatBestPractice,
			Message:    "No authors listed in policy metadata",
			Suggestion: "Add meta.authors for accountability and change tracking",
		})
	}

	// BP-003: Policy has agent scope but no type constraint.
	if p.Agent.Name != "" && p.Agent.Type == "" {
		findings = append(findings, LintFinding{
			Rule:       "BP-003",
			Severity:   LintInfo,
			Category:   LintCatBestPractice,
			Message:    "Policy targets agent by name but not type — may apply to wrong agent type",
			Suggestion: "Set agent.type to constrain policy to the correct agent category",
		})
	}

	// BP-004: All rules at same priority.
	if len(p.Rules) >= 3 {
		allSame := true
		first := p.Rules[0].Priority
		for _, r := range p.Rules[1:] {
			if r.Priority != first {
				allSame = false
				break
			}
		}
		if allSame {
			findings = append(findings, LintFinding{
				Rule:       "BP-004",
				Severity:   LintInfo,
				Category:   LintCatBestPractice,
				Message:    fmt.Sprintf("All %d rules share priority %d — evaluation order may be unpredictable", len(p.Rules), first),
				Suggestion: "Assign different priorities to establish a clear rule evaluation order",
			})
		}
	}

	// BP-005: No created/modified timestamps (only relevant when policy has rules).
	if p.Meta.Created == "" && p.Meta.Modified == "" && len(p.Rules) > 0 {
		findings = append(findings, LintFinding{
			Rule:       "BP-005",
			Severity:   LintStyle,
			Category:   LintCatBestPractice,
			Message:    "No created/modified timestamps in policy metadata",
			Suggestion: "Add meta.created and meta.modified for change tracking",
		})
	}

	return findings
}

// ---------------------------------------------------------------------------
// Scoring and formatting
// ---------------------------------------------------------------------------

// computeLintScore calculates a quality score from 0.0 to 1.0.
// Each finding type has a different weight penalty.
func computeLintScore(errors, warnings, infos, styles, totalRules int) float64 {
	if totalRules == 0 {
		return 1.0 // empty policy gets a perfect score
	}
	// Each finding subtracts from a perfect 1.0.
	penalty := float64(errors)*0.20 + float64(warnings)*0.10 + float64(infos)*0.03 + float64(styles)*0.01
	// Normalize against rule count to avoid penalizing large policies.
	normalized := penalty / float64(1+totalRules)
	score := 1.0 - normalized
	if score < 0 {
		score = 0
	}
	return score
}

// gradeLint converts a lint score to a letter grade.
func gradeLint(score float64) string {
	switch {
	case score >= 0.95:
		return "A"
	case score >= 0.85:
		return "B"
	case score >= 0.70:
		return "C"
	case score >= 0.50:
		return "D"
	default:
		return "F"
	}
}

func lintSeverityRank(s LintSeverity) int {
	switch s {
	case LintError:
		return 4
	case LintWarning:
		return 3
	case LintInfo:
		return 2
	case LintStyle:
		return 1
	default:
		return 0
	}
}

func isKebabOrSnake(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return len(s) > 0
}

func summarizeLint(r *LintReport) string {
	if r.FindingCount == 0 {
		return fmt.Sprintf("Policy %q: %d rules, no issues found — grade %s.",
			r.PolicyName, r.TotalRules, r.Grade)
	}
	return fmt.Sprintf("Policy %q: %d rules, %d findings (%d errors, %d warnings) — grade %s (%.0f%%).",
		r.PolicyName, r.TotalRules, r.FindingCount,
		r.ErrorCount, r.WarningCount, r.Grade, r.Score*100)
}

// FormatLintReport renders a lint report as a box-drawing formatted string.
func FormatLintReport(r *LintReport) string {
	if r == nil {
		return "No lint report.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│             POLICY LINT REPORT                  │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Policy:   %-38s │\n", truncate(r.PolicyName, 38))
	fmt.Fprintf(&sb, "│ Rules:    %-38d │\n", r.TotalRules)
	fmt.Fprintf(&sb, "│ Score:    %-38s │\n", fmt.Sprintf("%.0f%% (grade %s)", r.Score*100, r.Grade))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Errors:   %-38d │\n", r.ErrorCount)
	fmt.Fprintf(&sb, "│ Warnings: %-38d │\n", r.WarningCount)
	fmt.Fprintf(&sb, "│ Info:     %-38d │\n", r.InfoCount)
	fmt.Fprintf(&sb, "│ Style:    %-38d │\n", r.StyleCount)
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	if len(r.Findings) == 0 {
		sb.WriteString("│ ✓ No issues found                               │\n")
	} else {
		sb.WriteString("│ Findings                                        │\n")
		for _, f := range r.Findings {
			icon := lintIcon(f.Severity)
			fmt.Fprintf(&sb, "│ %s [%-7s] %-35s │\n",
				icon,
				truncate(string(f.Severity), 7),
				truncate(f.Rule, 35))
			msgLines := wrapText(f.Message, 45)
			for _, line := range msgLines {
				fmt.Fprintf(&sb, "│     %-44s │\n", line)
			}
			if f.Suggestion != "" {
				sugLines := wrapText("→ "+f.Suggestion, 45)
				for _, line := range sugLines {
					fmt.Fprintf(&sb, "│     %-44s │\n", line)
				}
			}
		}
	}

	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ %-48s │\n", truncate(r.Summary, 48))
	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// truncate shortens s to maxLen, appending "…" if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return "…"
	}
	return s[:maxLen-1] + "…"
}

// wrapText splits text into lines of at most maxLen characters, breaking at
// word boundaries when possible.
func wrapText(text string, maxLen int) []string {
	if maxLen <= 0 {
		return []string{text}
	}
	if len(text) <= maxLen {
		return []string{text}
	}

	var lines []string
	for len(text) > 0 {
		if len(text) <= maxLen {
			lines = append(lines, text)
			break
		}
		// Find the last space within maxLen.
		cut := maxLen
		for cut > 0 && text[cut] != ' ' {
			cut--
		}
		if cut == 0 {
			cut = maxLen // no space found, hard break
		}
		lines = append(lines, text[:cut])
		text = strings.TrimLeft(text[cut:], " ")
	}
	return lines
}

func lintIcon(s LintSeverity) string {
	switch s {
	case LintError:
		return "✗"
	case LintWarning:
		return "!"
	case LintInfo:
		return "·"
	case LintStyle:
		return "~"
	default:
		return " "
	}
}
