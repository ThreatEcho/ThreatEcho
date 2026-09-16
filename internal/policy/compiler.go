// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// CompiledPolicy is an indexed, analyzed form of a Policy ready for fast
// evaluation and conflict reporting.
type CompiledPolicy struct {
	Original      *Policy
	RulesByTool   map[string][]*Rule
	RulesByTactic map[string][]*Rule
	RulesByAction map[string][]*Rule
	RulesByTarget map[string][]*Rule
	SortedRules   []*Rule
	Conflicts     []Conflict
	Stats         CompileStats
}

// Conflict describes two rules whose match dimensions overlap but whose
// effects disagree, signalling a potential misconfiguration.
type Conflict struct {
	RuleA       *Rule
	RuleB       *Rule
	Dimension   string // "tool", "tactic", "action", "target"
	Overlap     string // the specific value or pattern that overlaps
	Description string // human-readable explanation
}

// CompileStats summarises compilation metrics.
type CompileStats struct {
	TotalRules    int
	DenyRules     int
	AllowRules    int
	AlertRules    int
	UniqueTools   int
	UniqueTactics int
	UniqueActions int
	UniqueTargets int
	ConflictCount int
	MaxPriority   int
	MinPriority   int
}

// CoverageReport describes what a policy covers and where gaps remain.
type CoverageReport struct {
	ToolsCovered     []string
	ToolsUncovered   []string
	ToolsCoveragePct float64

	TacticsCovered     []string
	TacticsUncovered   []string
	TacticsCoveragePct float64

	ActionsCovered     []string
	ActionsUncovered   []string
	ActionsCoveragePct float64

	Gaps []CoverageGap
}

// CoverageGap is a single uncovered item with a risk assessment.
type CoverageGap struct {
	Dimension string // "tool", "tactic", "action"
	Value     string
	Risk      string // "high", "medium", "low"
}

// referenceActions is the canonical set of agent actions.
var referenceActions = []string{
	"read", "write", "execute", "send", "query",
	"delete", "create", "modify",
}

// highRiskTactics are tactics commonly exploited in agent attacks.
var highRiskTactics = map[string]bool{
	"initial-access":       true,
	"execution":            true,
	"credential-access":    true,
	"exfiltration":         true,
	"impact":               true,
	"lateral-movement":     true,
	"privilege-escalation": true,
}

// highRiskActions are actions that carry the most risk when uncontrolled.
var highRiskActions = map[string]bool{
	"execute": true,
	"write":   true,
	"send":    true,
	"delete":  true,
}

// Compile validates, indexes, and analyses a policy. It returns a
// CompiledPolicy with rule indexes, sorted rules, detected conflicts,
// and compilation statistics. Nil or empty policies are handled gracefully.
func Compile(p *Policy) *CompiledPolicy {
	cp := &CompiledPolicy{
		Original:      p,
		RulesByTool:   make(map[string][]*Rule),
		RulesByTactic: make(map[string][]*Rule),
		RulesByAction: make(map[string][]*Rule),
		RulesByTarget: make(map[string][]*Rule),
	}

	if p == nil || len(p.Rules) == 0 {
		return cp
	}

	// Build sorted rules slice (priority descending).
	cp.SortedRules = make([]*Rule, len(p.Rules))
	for i := range p.Rules {
		cp.SortedRules[i] = &p.Rules[i]
	}
	sort.Slice(cp.SortedRules, func(i, j int) bool {
		return cp.SortedRules[i].Priority > cp.SortedRules[j].Priority
	})

	// Index rules and gather statistics.
	toolSet := make(map[string]bool)
	tacticSet := make(map[string]bool)
	actionSet := make(map[string]bool)
	targetSet := make(map[string]bool)

	for i := range p.Rules {
		r := &p.Rules[i]

		switch r.Effect {
		case "deny":
			cp.Stats.DenyRules++
		case "allow":
			cp.Stats.AllowRules++
		case "alert":
			cp.Stats.AlertRules++
		}

		for _, t := range r.Match.Tools {
			cp.RulesByTool[t] = append(cp.RulesByTool[t], r)
			toolSet[t] = true
		}
		for _, t := range r.Match.Tactics {
			cp.RulesByTactic[t] = append(cp.RulesByTactic[t], r)
			tacticSet[t] = true
		}
		for _, a := range r.Match.Actions {
			cp.RulesByAction[a] = append(cp.RulesByAction[a], r)
			actionSet[a] = true
		}
		for _, t := range r.Match.Targets {
			cp.RulesByTarget[t] = append(cp.RulesByTarget[t], r)
			targetSet[t] = true
		}
	}

	cp.Stats.TotalRules = len(p.Rules)
	cp.Stats.UniqueTools = len(toolSet)
	cp.Stats.UniqueTactics = len(tacticSet)
	cp.Stats.UniqueActions = len(actionSet)
	cp.Stats.UniqueTargets = len(targetSet)

	if len(p.Rules) > 0 {
		cp.Stats.MaxPriority = p.Rules[0].Priority
		cp.Stats.MinPriority = p.Rules[0].Priority
		for _, r := range p.Rules {
			if r.Priority > cp.Stats.MaxPriority {
				cp.Stats.MaxPriority = r.Priority
			}
			if r.Priority < cp.Stats.MinPriority {
				cp.Stats.MinPriority = r.Priority
			}
		}
	}

	// Detect conflicts.
	cp.Conflicts = CheckConflicts(p)
	cp.Stats.ConflictCount = len(cp.Conflicts)

	return cp
}

// CheckConflicts detects pairs of rules that match the same dimension
// but have different effects.
func CheckConflicts(p *Policy) []Conflict {
	if p == nil || len(p.Rules) < 2 {
		return nil
	}

	var conflicts []Conflict

	for i := 0; i < len(p.Rules); i++ {
		for j := i + 1; j < len(p.Rules); j++ {
			a := &p.Rules[i]
			b := &p.Rules[j]

			// Only flag conflicts between different effects.
			if a.Effect == b.Effect {
				continue
			}

			// Tool dimension.
			for _, ta := range a.Match.Tools {
				for _, tb := range b.Match.Tools {
					if patternsOverlap(ta, tb) {
						overlap := ta
						if ta != tb {
							overlap = ta + " ↔ " + tb
						}
						conflicts = append(conflicts, Conflict{
							RuleA:     a,
							RuleB:     b,
							Dimension: "tool",
							Overlap:   overlap,
							Description: fmt.Sprintf(
								"rules %q (%s) and %q (%s) both match tool %s",
								a.ID, a.Effect, b.ID, b.Effect, overlap,
							),
						})
					}
				}
			}

			// Tactic dimension.
			for _, ta := range a.Match.Tactics {
				for _, tb := range b.Match.Tactics {
					if ta == tb {
						conflicts = append(conflicts, Conflict{
							RuleA:     a,
							RuleB:     b,
							Dimension: "tactic",
							Overlap:   ta,
							Description: fmt.Sprintf(
								"rules %q (%s) and %q (%s) both match tactic %q",
								a.ID, a.Effect, b.ID, b.Effect, ta,
							),
						})
					}
				}
			}

			// Action dimension.
			for _, aa := range a.Match.Actions {
				for _, ab := range b.Match.Actions {
					if aa == ab {
						conflicts = append(conflicts, Conflict{
							RuleA:     a,
							RuleB:     b,
							Dimension: "action",
							Overlap:   aa,
							Description: fmt.Sprintf(
								"rules %q (%s) and %q (%s) both match action %q",
								a.ID, a.Effect, b.ID, b.Effect, aa,
							),
						})
					}
				}
			}

			// Target dimension.
			for _, ta := range a.Match.Targets {
				for _, tb := range b.Match.Targets {
					if patternsOverlap(ta, tb) {
						overlap := ta
						if ta != tb {
							overlap = ta + " ↔ " + tb
						}
						conflicts = append(conflicts, Conflict{
							RuleA:     a,
							RuleB:     b,
							Dimension: "target",
							Overlap:   overlap,
							Description: fmt.Sprintf(
								"rules %q (%s) and %q (%s) both match target %s",
								a.ID, a.Effect, b.ID, b.Effect, overlap,
							),
						})
					}
				}
			}
		}
	}

	return conflicts
}

// patternsOverlap checks whether two glob-style patterns could ever
// match the same string. It is conservative: when uncertain, it returns
// true to avoid hiding potential conflicts.
func patternsOverlap(a, b string) bool {
	// Exact match.
	if a == b {
		return true
	}

	// If either is the universal wildcard, they always overlap.
	if a == "*" || b == "*" {
		return true
	}

	// If either contains a wildcard, check if one could match the other.
	aHasWild := strings.Contains(a, "*")
	bHasWild := strings.Contains(b, "*")

	if aHasWild && bHasWild {
		// Both have wildcards — conservatively assume overlap.
		// Check for obviously disjoint prefixes.
		aPre := strings.SplitN(a, "*", 2)[0]
		bPre := strings.SplitN(b, "*", 2)[0]
		if aPre != "" && bPre != "" {
			if !strings.HasPrefix(aPre, bPre) && !strings.HasPrefix(bPre, aPre) {
				return false
			}
		}
		return true
	}

	if aHasWild {
		return GlobMatch(a, b)
	}
	if bHasWild {
		return GlobMatch(b, a)
	}

	// No wildcards — exact match only (already checked above).
	return false
}

// MergePolicies combines multiple policies into one. Rules from all
// policies are collected; duplicate IDs are prefixed with the source
// policy name. The first policy's meta and agent scope are used as the
// base. Returns nil when no policies are given.
func MergePolicies(policies ...*Policy) *Policy {
	if len(policies) == 0 {
		return nil
	}

	// Single policy passthrough.
	if len(policies) == 1 {
		return policies[0]
	}

	base := policies[0]
	merged := &Policy{
		APIVersion: base.APIVersion,
		Kind:       base.Kind,
		Meta: PolicyMeta{
			Name:        base.Meta.Name + " (merged)",
			Description: fmt.Sprintf("Merged from %d policies", len(policies)),
			Authors:     base.Meta.Authors,
			Created:     base.Meta.Created,
			Modified:    base.Meta.Modified,
		},
		Agent: base.Agent,
	}

	// Collect all rule IDs to detect duplicates.
	idCount := make(map[string]int)
	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, r := range p.Rules {
			idCount[r.ID]++
		}
	}

	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, r := range p.Rules {
			rule := r // copy
			if idCount[r.ID] > 1 {
				rule.ID = p.Meta.Name + ":" + r.ID
			}
			merged.Rules = append(merged.Rules, rule)
		}
	}

	// Sort by priority descending.
	sort.Slice(merged.Rules, func(i, j int) bool {
		return merged.Rules[i].Priority > merged.Rules[j].Priority
	})

	return merged
}

// AnalyzeCoverage examines a policy against reference tool/tactic/action
// sets and returns a coverage report with gaps and risk assessments.
func AnalyzeCoverage(p *Policy, refTools []string) *CoverageReport {
	cr := &CoverageReport{}

	if p == nil {
		cr.ToolsUncovered = refTools
		cr.TacticsUncovered = mitre.TacticShorts()
		cr.ActionsUncovered = append([]string{}, referenceActions...)
		fillGaps(cr)
		return cr
	}

	// Gather covered dimensions from rules.
	toolSet := make(map[string]bool)
	tacticSet := make(map[string]bool)
	actionSet := make(map[string]bool)

	for _, r := range p.Rules {
		for _, t := range r.Match.Tools {
			toolSet[t] = true
		}
		for _, t := range r.Match.Tactics {
			tacticSet[t] = true
		}
		for _, a := range r.Match.Actions {
			actionSet[a] = true
		}
	}

	// Tools coverage.
	for _, t := range refTools {
		if covered := toolCovered(t, toolSet); covered {
			cr.ToolsCovered = append(cr.ToolsCovered, t)
		} else {
			cr.ToolsUncovered = append(cr.ToolsUncovered, t)
		}
	}
	if len(refTools) > 0 {
		cr.ToolsCoveragePct = float64(len(cr.ToolsCovered)) / float64(len(refTools)) * 100
	}

	// Tactics coverage.
	allTactics := mitre.TacticShorts()
	for _, t := range allTactics {
		if tacticSet[t] {
			cr.TacticsCovered = append(cr.TacticsCovered, t)
		} else {
			cr.TacticsUncovered = append(cr.TacticsUncovered, t)
		}
	}
	if len(allTactics) > 0 {
		cr.TacticsCoveragePct = float64(len(cr.TacticsCovered)) / float64(len(allTactics)) * 100
	}

	// Actions coverage.
	for _, a := range referenceActions {
		if actionSet[a] {
			cr.ActionsCovered = append(cr.ActionsCovered, a)
		} else {
			cr.ActionsUncovered = append(cr.ActionsUncovered, a)
		}
	}
	if len(referenceActions) > 0 {
		cr.ActionsCoveragePct = float64(len(cr.ActionsCovered)) / float64(len(referenceActions)) * 100
	}

	fillGaps(cr)
	return cr
}

// toolCovered checks whether a reference tool is covered by any pattern
// in the policy's tool set.
func toolCovered(tool string, patterns map[string]bool) bool {
	if patterns[tool] {
		return true
	}
	for p := range patterns {
		if strings.Contains(p, "*") && GlobMatch(p, tool) {
			return true
		}
	}
	return false
}

// fillGaps populates the Gaps slice from the uncovered lists with risk
// assessments.
func fillGaps(cr *CoverageReport) {
	for _, t := range cr.ToolsUncovered {
		risk := "medium"
		// Tools related to execution/writing are high risk.
		lower := strings.ToLower(t)
		if strings.Contains(lower, "exec") || strings.Contains(lower, "write") ||
			strings.Contains(lower, "send") || strings.Contains(lower, "delete") {
			risk = "high"
		} else if strings.Contains(lower, "read") || strings.Contains(lower, "search") ||
			strings.Contains(lower, "query") || strings.Contains(lower, "list") {
			risk = "low"
		}
		cr.Gaps = append(cr.Gaps, CoverageGap{
			Dimension: "tool",
			Value:     t,
			Risk:      risk,
		})
	}

	for _, t := range cr.TacticsUncovered {
		risk := "medium"
		if highRiskTactics[t] {
			risk = "high"
		}
		cr.Gaps = append(cr.Gaps, CoverageGap{
			Dimension: "tactic",
			Value:     t,
			Risk:      risk,
		})
	}

	for _, a := range cr.ActionsUncovered {
		risk := "medium"
		if highRiskActions[a] {
			risk = "high"
		}
		cr.Gaps = append(cr.Gaps, CoverageGap{
			Dimension: "action",
			Value:     a,
			Risk:      risk,
		})
	}
}

// FormatCompileResult renders a compiled policy as a box-drawing report.
func FormatCompileResult(cp *CompiledPolicy) string {
	if cp == nil {
		return "No compilation result.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────┐\n")
	b.WriteString("│         Policy Compilation Report            │\n")
	b.WriteString("├─────────────────────────────────────────────┤\n")

	if cp.Original != nil {
		b.WriteString(fmt.Sprintf("│ Policy: %-36s│\n", cp.Original.Meta.Name))
	}

	b.WriteString("├─────────────────────────────────────────────┤\n")
	b.WriteString("│ Rules                                       │\n")
	b.WriteString(fmt.Sprintf("│   Total:   %-33d│\n", cp.Stats.TotalRules))
	b.WriteString(fmt.Sprintf("│   Deny:    %-33d│\n", cp.Stats.DenyRules))
	b.WriteString(fmt.Sprintf("│   Allow:   %-33d│\n", cp.Stats.AllowRules))
	b.WriteString(fmt.Sprintf("│   Alert:   %-33d│\n", cp.Stats.AlertRules))
	b.WriteString("├─────────────────────────────────────────────┤\n")
	b.WriteString("│ Dimensions                                  │\n")
	b.WriteString(fmt.Sprintf("│   Tools:   %-33d│\n", cp.Stats.UniqueTools))
	b.WriteString(fmt.Sprintf("│   Tactics: %-33d│\n", cp.Stats.UniqueTactics))
	b.WriteString(fmt.Sprintf("│   Actions: %-33d│\n", cp.Stats.UniqueActions))
	b.WriteString(fmt.Sprintf("│   Targets: %-33d│\n", cp.Stats.UniqueTargets))
	b.WriteString("├─────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Priority Range: %-28s│\n",
		fmt.Sprintf("%d – %d", cp.Stats.MinPriority, cp.Stats.MaxPriority)))

	if len(cp.Conflicts) > 0 {
		b.WriteString("├─────────────────────────────────────────────┤\n")
		b.WriteString(fmt.Sprintf("│ ⚠ Conflicts: %-30d│\n", len(cp.Conflicts)))
		for i, c := range cp.Conflicts {
			if i >= 10 {
				b.WriteString(fmt.Sprintf("│   ... and %d more                            │\n", len(cp.Conflicts)-10))
				break
			}
			desc := c.Description
			if len(desc) > 42 {
				desc = desc[:39] + "..."
			}
			b.WriteString(fmt.Sprintf("│   • %-39s│\n", desc))
		}
	} else {
		b.WriteString("├─────────────────────────────────────────────┤\n")
		b.WriteString("│ ✓ No conflicts detected                     │\n")
	}

	b.WriteString("└─────────────────────────────────────────────┘\n")
	return b.String()
}

// FormatCoverage renders a coverage report as a box-drawing report.
func FormatCoverage(cr *CoverageReport) string {
	if cr == nil {
		return "No coverage data.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────┐\n")
	b.WriteString("│           Policy Coverage Report             │\n")
	b.WriteString("├─────────────────────────────────────────────┤\n")

	// Tools.
	b.WriteString(fmt.Sprintf("│ Tools:   %5.1f%% (%d/%d)%s│\n",
		cr.ToolsCoveragePct,
		len(cr.ToolsCovered),
		len(cr.ToolsCovered)+len(cr.ToolsUncovered),
		pad(35-countDigits(len(cr.ToolsCovered))-countDigits(len(cr.ToolsCovered)+len(cr.ToolsUncovered))),
	))
	b.WriteString(coverageBar(cr.ToolsCoveragePct))

	// Tactics.
	b.WriteString(fmt.Sprintf("│ Tactics: %5.1f%% (%d/%d)%s│\n",
		cr.TacticsCoveragePct,
		len(cr.TacticsCovered),
		len(cr.TacticsCovered)+len(cr.TacticsUncovered),
		pad(35-countDigits(len(cr.TacticsCovered))-countDigits(len(cr.TacticsCovered)+len(cr.TacticsUncovered))),
	))
	b.WriteString(coverageBar(cr.TacticsCoveragePct))

	// Actions.
	b.WriteString(fmt.Sprintf("│ Actions: %5.1f%% (%d/%d)%s│\n",
		cr.ActionsCoveragePct,
		len(cr.ActionsCovered),
		len(cr.ActionsCovered)+len(cr.ActionsUncovered),
		pad(35-countDigits(len(cr.ActionsCovered))-countDigits(len(cr.ActionsCovered)+len(cr.ActionsUncovered))),
	))
	b.WriteString(coverageBar(cr.ActionsCoveragePct))

	// Gaps.
	highCount := 0
	for _, g := range cr.Gaps {
		if g.Risk == "high" {
			highCount++
		}
	}
	if highCount > 0 {
		b.WriteString("├─────────────────────────────────────────────┤\n")
		b.WriteString(fmt.Sprintf("│ ⚠ High-Risk Gaps: %-25d│\n", highCount))
		shown := 0
		for _, g := range cr.Gaps {
			if g.Risk != "high" {
				continue
			}
			if shown >= 8 {
				b.WriteString(fmt.Sprintf("│   ... and %d more                            │\n", highCount-8))
				break
			}
			label := fmt.Sprintf("[%s] %s", g.Dimension, g.Value)
			if len(label) > 40 {
				label = label[:37] + "..."
			}
			b.WriteString(fmt.Sprintf("│   ✗ %-39s│\n", label))
			shown++
		}
	}

	b.WriteString("└─────────────────────────────────────────────┘\n")
	return b.String()
}

// coverageBar renders an ASCII progress bar for a percentage.
func coverageBar(pct float64) string {
	const barWidth = 30
	filled := int(pct / 100 * barWidth)
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	return fmt.Sprintf("│   [%s]         │\n", bar)
}

// countDigits returns the number of decimal digits in an integer.
func countDigits(n int) int {
	if n == 0 {
		return 1
	}
	count := 0
	if n < 0 {
		n = -n
		count = 1
	}
	for n > 0 {
		count++
		n /= 10
	}
	return count
}

// pad returns n spaces, clamped to at least 0.
func pad(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(" ", n)
}
