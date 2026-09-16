// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"fmt"
	"sort"
	"strings"
)

// GuardrailGap identifies a missing or insufficient guardrail for an agent.
type GuardrailGap struct {
	AgentName   string `json:"agent_name"`
	GapType     string `json:"gap_type"`  // "missing", "unenforced", "insufficient", "redundant"
	Guardrail   string `json:"guardrail"` // type of guardrail (input, output, tool-call, content-filter)
	Severity    string `json:"severity"`  // "low", "medium", "high", "critical"
	Description string `json:"description"`
}

// GuardrailReport is the result of analyzing guardrail coverage for an agent.
type GuardrailReport struct {
	AgentName       string         `json:"agent_name"`
	AgentType       string         `json:"agent_type"`
	TrustLevel      string         `json:"trust_level"`
	TotalGuardrails int            `json:"total_guardrails"`
	EnforcedCount   int            `json:"enforced_count"`
	Gaps            []GuardrailGap `json:"gaps"`
	Score           float64        `json:"score"` // 0.0 to 1.0
	Grade           string         `json:"grade"` // A/B/C/D/F
}

// InventoryGuardrailReport summarizes guardrail coverage across all agents.
type InventoryGuardrailReport struct {
	TotalAgents       int               `json:"total_agents"`
	TotalGaps         int               `json:"total_gaps"`
	CriticalGaps      int               `json:"critical_gaps"`
	FullyCoveredCount int               `json:"fully_covered_count"`
	Reports           []GuardrailReport `json:"reports"`
	WorstAgents       []string          `json:"worst_agents"` // agents with grade D or F
}

// requiredGuardrails defines what guardrail types are required based on capabilities.
var requiredGuardrails = map[string][]string{
	// If agent has this capability, it needs these guardrail types.
	"tool_calling":    {"tool-call"},
	"rag":             {"input", "output"},
	"code_execution":  {"tool-call", "output"},
	"web_access":      {"input", "output", "content-filter"},
	"file_access":     {"tool-call"},
	"message_passing": {"input", "output"},
	"memory":          {"input", "output"},
	"autonomous":      {"tool-call", "input", "output", "content-filter"},
}

// trustLevelMinGuardrails defines the minimum number of enforced guardrails
// expected at each trust level.
var trustLevelMinGuardrails = map[string]int{
	TrustUntrusted: 4,
	TrustLow:       3,
	TrustStandard:  2,
	TrustElevated:  3, // higher trust = more responsibility = more guardrails
	TrustAdmin:     4,
}

// AnalyzeGuardrails evaluates the guardrail coverage for a single agent.
// It checks that all capabilities have corresponding guardrails, that
// the trust level has sufficient enforced guardrails, and that elevated
// tools have tool-call guardrails.
func AnalyzeGuardrails(a *Agent) *GuardrailReport {
	if a == nil {
		return &GuardrailReport{Score: 0.0, Grade: "F"}
	}

	report := &GuardrailReport{
		AgentName:  a.Meta.Name,
		AgentType:  a.Meta.Type,
		TrustLevel: a.Trust.Level,
	}

	// Count guardrails and enforced guardrails.
	guardTypes := make(map[string]bool)
	enforcedTypes := make(map[string]bool)
	for _, g := range a.Guardrails {
		report.TotalGuardrails++
		guardTypes[g.Type] = true
		if g.Enforced {
			report.EnforcedCount++
			enforcedTypes[g.Type] = true
		}
	}

	// Check capability-based requirements.
	checkCapabilityGuardrailGaps(a, guardTypes, enforcedTypes, report)

	// Check trust-level minimum enforced guardrails.
	checkTrustLevelGuardrails(a, report)

	// Check elevated tools without tool-call guardrails.
	checkElevatedToolGuardrails(a, guardTypes, report)

	// Check for unenforced guardrails (declared but not enforced).
	checkUnenforcedGuardrails(a, report)

	// Check for redundant guardrails (same type declared multiple times).
	checkRedundantGuardrails(a, report)

	// Compute score.
	report.Score = computeGuardrailScore(report)
	report.Grade = gradeGuardrail(report.Score)

	return report
}

// AnalyzeAllGuardrails evaluates guardrail coverage for the entire inventory.
func (inv *Inventory) AnalyzeAllGuardrails() *InventoryGuardrailReport {
	if inv == nil {
		return &InventoryGuardrailReport{}
	}

	igr := &InventoryGuardrailReport{
		TotalAgents: len(inv.Agents),
	}

	for _, a := range inv.Agents {
		report := AnalyzeGuardrails(a)
		igr.Reports = append(igr.Reports, *report)
		igr.TotalGaps += len(report.Gaps)

		for _, g := range report.Gaps {
			if g.Severity == "critical" {
				igr.CriticalGaps++
			}
		}

		if len(report.Gaps) == 0 {
			igr.FullyCoveredCount++
		}

		if report.Grade == "D" || report.Grade == "F" {
			igr.WorstAgents = append(igr.WorstAgents, a.Meta.Name)
		}
	}

	return igr
}

// checkCapabilityGuardrailGaps checks if each active capability has the
// required guardrail types.
func checkCapabilityGuardrailGaps(a *Agent, guardTypes, enforcedTypes map[string]bool, report *GuardrailReport) {
	caps := activeCapabilities(a)
	needed := make(map[string]bool)

	for _, cap := range caps {
		if reqs, ok := requiredGuardrails[cap]; ok {
			for _, req := range reqs {
				needed[req] = true
			}
		}
	}

	for gtype := range needed {
		if !guardTypes[gtype] {
			severity := "high"
			if a.Trust.Level == TrustAdmin || a.Trust.Level == TrustElevated {
				severity = "critical"
			}
			report.Gaps = append(report.Gaps, GuardrailGap{
				AgentName:   a.Meta.Name,
				GapType:     "missing",
				Guardrail:   gtype,
				Severity:    severity,
				Description: fmt.Sprintf("Agent %q capabilities require a %q guardrail but none is defined", a.Meta.Name, gtype),
			})
		} else if !enforcedTypes[gtype] {
			report.Gaps = append(report.Gaps, GuardrailGap{
				AgentName:   a.Meta.Name,
				GapType:     "unenforced",
				Guardrail:   gtype,
				Severity:    "medium",
				Description: fmt.Sprintf("Agent %q has a %q guardrail but it is not enforced", a.Meta.Name, gtype),
			})
		}
	}
}

// checkTrustLevelGuardrails verifies the agent meets the minimum enforced
// guardrail count for its trust level.
func checkTrustLevelGuardrails(a *Agent, report *GuardrailReport) {
	minRequired, ok := trustLevelMinGuardrails[a.Trust.Level]
	if !ok {
		return
	}

	if report.EnforcedCount < minRequired {
		severity := "medium"
		if a.Trust.Level == TrustAdmin || a.Trust.Level == TrustElevated {
			severity = "high"
		}

		report.Gaps = append(report.Gaps, GuardrailGap{
			AgentName: a.Meta.Name,
			GapType:   "insufficient",
			Guardrail: "all",
			Severity:  severity,
			Description: fmt.Sprintf("Agent %q at trust level %q has %d enforced guardrails but needs at least %d",
				a.Meta.Name, a.Trust.Level, report.EnforcedCount, minRequired),
		})
	}
}

// checkElevatedToolGuardrails verifies agents with elevated tools have
// a tool-call guardrail.
func checkElevatedToolGuardrails(a *Agent, guardTypes map[string]bool, report *GuardrailReport) {
	hasElevated := false
	for _, t := range a.Tools {
		if t.Elevated {
			hasElevated = true
			break
		}
	}

	if hasElevated && !guardTypes["tool-call"] {
		report.Gaps = append(report.Gaps, GuardrailGap{
			AgentName:   a.Meta.Name,
			GapType:     "missing",
			Guardrail:   "tool-call",
			Severity:    "critical",
			Description: fmt.Sprintf("Agent %q has elevated tools but no tool-call guardrail", a.Meta.Name),
		})
	}
}

// checkUnenforcedGuardrails flags guardrails that are declared but not enforced.
func checkUnenforcedGuardrails(a *Agent, report *GuardrailReport) {
	for _, g := range a.Guardrails {
		if !g.Enforced {
			report.Gaps = append(report.Gaps, GuardrailGap{
				AgentName:   a.Meta.Name,
				GapType:     "unenforced",
				Guardrail:   g.Type,
				Severity:    "low",
				Description: fmt.Sprintf("Guardrail %q (%s) on agent %q is not enforced", g.Name, g.Type, a.Meta.Name),
			})
		}
	}
}

// checkRedundantGuardrails detects duplicate guardrail type declarations.
func checkRedundantGuardrails(a *Agent, report *GuardrailReport) {
	typeCounts := make(map[string]int)
	for _, g := range a.Guardrails {
		typeCounts[g.Type]++
	}

	for gtype, count := range typeCounts {
		if count > 1 {
			report.Gaps = append(report.Gaps, GuardrailGap{
				AgentName:   a.Meta.Name,
				GapType:     "redundant",
				Guardrail:   gtype,
				Severity:    "low",
				Description: fmt.Sprintf("Agent %q declares %d guardrails of type %q — consider consolidating", a.Meta.Name, count, gtype),
			})
		}
	}
}

// activeCapabilities returns the names of all enabled capabilities on the agent.
func activeCapabilities(a *Agent) []string {
	var caps []string
	if a.Capabilities.ToolCalling {
		caps = append(caps, "tool_calling")
	}
	if a.Capabilities.RAG {
		caps = append(caps, "rag")
	}
	if a.Capabilities.CodeExecution {
		caps = append(caps, "code_execution")
	}
	if a.Capabilities.WebAccess {
		caps = append(caps, "web_access")
	}
	if a.Capabilities.FileAccess {
		caps = append(caps, "file_access")
	}
	if a.Capabilities.MessagePassing {
		caps = append(caps, "message_passing")
	}
	if a.Capabilities.Memory {
		caps = append(caps, "memory")
	}
	if a.Capabilities.Autonomous {
		caps = append(caps, "autonomous")
	}
	return caps
}

// computeGuardrailScore calculates a score based on gap analysis.
// Starts at 1.0 and deducts:
//   - critical gap: -0.20
//   - high gap:     -0.12
//   - medium gap:   -0.06
//   - low gap:      -0.03
//
// Score is floored at 0.0.
func computeGuardrailScore(report *GuardrailReport) float64 {
	score := 1.0
	for _, gap := range report.Gaps {
		switch gap.Severity {
		case "critical":
			score -= 0.20
		case "high":
			score -= 0.12
		case "medium":
			score -= 0.06
		case "low":
			score -= 0.03
		}
	}
	if score < 0.0 {
		score = 0.0
	}
	return score
}

// gradeGuardrail converts a score to a letter grade.
func gradeGuardrail(score float64) string {
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

// FormatGuardrailReport renders a single agent's guardrail analysis.
func FormatGuardrailReport(r *GuardrailReport) string {
	if r == nil {
		return "No guardrail report.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│           GUARDRAIL ANALYSIS                    │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Agent:       %-35s │\n", truncate(r.AgentName, 35))
	fmt.Fprintf(&sb, "│ Type:        %-35s │\n", truncate(r.AgentType, 35))
	fmt.Fprintf(&sb, "│ Trust:       %-35s │\n", truncate(r.TrustLevel, 35))
	fmt.Fprintf(&sb, "│ Guardrails:  %-35s │\n",
		fmt.Sprintf("%d total, %d enforced", r.TotalGuardrails, r.EnforcedCount))
	fmt.Fprintf(&sb, "│ Score:       %-35s │\n",
		fmt.Sprintf("%.2f (%s)", r.Score, r.Grade))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	if len(r.Gaps) == 0 {
		sb.WriteString("│ ✓ No guardrail gaps found                       │\n")
	} else {
		// Sort gaps by severity: critical > high > medium > low.
		sorted := make([]GuardrailGap, len(r.Gaps))
		copy(sorted, r.Gaps)
		sort.Slice(sorted, func(i, j int) bool {
			return severityRank(sorted[i].Severity) > severityRank(sorted[j].Severity)
		})

		sb.WriteString("│ Gaps                                            │\n")
		for _, gap := range sorted {
			icon := gapIcon(gap.Severity)
			fmt.Fprintf(&sb, "│  %s [%-8s] %-8s %-24s │\n",
				icon,
				truncate(gap.Severity, 8),
				truncate(gap.GapType, 8),
				truncate(gap.Guardrail, 24))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// FormatInventoryGuardrailReport renders the full inventory guardrail summary.
func FormatInventoryGuardrailReport(igr *InventoryGuardrailReport) string {
	if igr == nil {
		return "No inventory guardrail report.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│       INVENTORY GUARDRAIL REPORT                │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Total Agents:   %-32d │\n", igr.TotalAgents)
	fmt.Fprintf(&sb, "│ Fully Covered:  %-32d │\n", igr.FullyCoveredCount)
	fmt.Fprintf(&sb, "│ Total Gaps:     %-32d │\n", igr.TotalGaps)
	fmt.Fprintf(&sb, "│ Critical Gaps:  %-32d │\n", igr.CriticalGaps)
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Sort reports by score ascending (worst first).
	sorted := make([]GuardrailReport, len(igr.Reports))
	copy(sorted, igr.Reports)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score < sorted[j].Score
	})

	sb.WriteString("│ Agents (worst first)                            │\n")
	for _, r := range sorted {
		status := "✓"
		if len(r.Gaps) > 0 {
			status = "✗"
		}
		fmt.Fprintf(&sb, "│  %s %-20s  %.2f (%s)  %d gaps %6s│\n",
			status,
			truncate(r.AgentName, 20),
			r.Score, r.Grade,
			len(r.Gaps), "")
	}

	if len(igr.WorstAgents) > 0 {
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
		sb.WriteString("│ ⚠ Agents needing attention (grade D/F)          │\n")
		for _, name := range igr.WorstAgents {
			fmt.Fprintf(&sb, "│   • %-44s │\n", truncate(name, 44))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// severityRank returns a numeric rank for sorting severities.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// gapIcon returns an emoji indicator for the gap severity.
func gapIcon(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "⚪"
	}
}
