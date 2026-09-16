// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"strings"
)

// GuardrailConfig describes an expected guardrail setup.
type GuardrailConfig struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Category  string  `json:"category"` // injection, toxicity, pii, content, custom
	Position  string  `json:"position"` // input, output, both
	Action    string  `json:"action"`   // block, warn, log, redact
	Threshold float64 `json:"threshold"`
	Required  bool    `json:"required"`
}

// GuardrailAnalysis evaluates guardrail coverage against traces and policies.
type GuardrailAnalysis struct {
	Guardrails      []GuardrailConfig `json:"guardrails"`
	TraceResults    []GuardrailResult `json:"trace_results"`
	PolicyAlignment []AlignmentResult `json:"policy_alignment"`
	GapAnalysis     []GuardrailGap    `json:"gap_analysis"`
	Stats           GuardrailStats    `json:"stats"`
	Recommendations []string          `json:"recommendations"`
}

// GuardrailResult is the analysis of one guardrail's behavior across traces.
type GuardrailResult struct {
	GuardrailID    string   `json:"guardrail_id"`
	TriggerCount   int      `json:"trigger_count"`
	BlockCount     int      `json:"block_count"`
	WarnCount      int      `json:"warn_count"`
	AvgScore       float64  `json:"avg_score"`
	MaxScore       float64  `json:"max_score"`
	FalsePositives int      `json:"false_positives"`
	Categories     []string `json:"categories"`
}

// AlignmentResult checks whether a guardrail aligns with policy rules.
type AlignmentResult struct {
	GuardrailID     string `json:"guardrail_id"`
	Category        string `json:"category"`
	HasMatchingRule bool   `json:"has_matching_rule"`
	RuleID          string `json:"rule_id,omitempty"`
	Conflict        string `json:"conflict,omitempty"`
	Aligned         bool   `json:"aligned"`
}

// GuardrailGap is a missing guardrail.
type GuardrailGap struct {
	Category    string `json:"category"`
	Risk        string `json:"risk"`
	Description string `json:"description"`
}

// GuardrailStats summarizes guardrail posture.
type GuardrailStats struct {
	TotalGuardrails  int     `json:"total_guardrails"`
	InputGuardrails  int     `json:"input_guardrails"`
	OutputGuardrails int     `json:"output_guardrails"`
	RequiredCount    int     `json:"required_count"`
	CoverageScore    float64 `json:"coverage_score"`
	AlignmentScore   float64 `json:"alignment_score"`
}

// mandatoryCategories are guardrail categories required for production agents.
var mandatoryCategories = []string{"injection", "pii", "toxicity"}

// categoryRisk maps guardrail categories to their default risk level when missing.
var categoryRisk = map[string]string{
	"injection": "critical",
	"pii":       "high",
	"toxicity":  "high",
	"content":   "medium",
	"custom":    "low",
}

// categoryToolKeywords maps guardrail categories to keywords found in policy
// tool patterns that would indicate coverage.
var categoryToolKeywords = map[string][]string{
	"injection": {"inject*", "prompt*", "jailbreak*", "instruction*"},
	"pii":       {"pii*", "redact*", "credential*", "secret*", "leak*", "data_*"},
	"toxicity":  {"toxic*", "content*", "safety*", "filter*"},
	"content":   {"content*", "safety*", "filter*", "moderat*"},
}

// AnalyzeGuardrails evaluates guardrail setup against traces and a policy.
// It scans traces for guardrail events, checks alignment with policy rules,
// identifies gaps in coverage, and generates recommendations.
func AnalyzeGuardrails(guardrails []GuardrailConfig, traces []*Trace, p *Policy) *GuardrailAnalysis {
	ga := &GuardrailAnalysis{
		Guardrails: guardrails,
	}

	// 1. Analyze trace results for each guardrail.
	ga.TraceResults = analyzeTraceResults(guardrails, traces)

	// 2. Check alignment with policy rules.
	if p != nil {
		ga.PolicyAlignment = checkPolicyAlignment(guardrails, p)
	}

	// 3. Identify gaps.
	ga.GapAnalysis = identifyGaps(guardrails)

	// 4. Compute stats.
	ga.Stats = computeGuardrailStats(guardrails, ga.PolicyAlignment)

	// 5. Generate recommendations.
	ga.Recommendations = generateRecommendations(ga)

	return ga
}

// analyzeTraceResults scans traces for GuardrailEvent entries that match
// each configured guardrail's ID or category.
func analyzeTraceResults(guardrails []GuardrailConfig, traces []*Trace) []GuardrailResult {
	results := make([]GuardrailResult, 0, len(guardrails))

	for _, gr := range guardrails {
		r := GuardrailResult{
			GuardrailID: gr.ID,
		}

		var totalScore float64
		var scoreCount int
		catSet := make(map[string]bool)

		for _, tr := range traces {
			if tr == nil {
				continue
			}
			// Track whether this trace has any actual policy violations
			// (used to detect false positives).
			traceBenign := isTraceBenign(tr)

			for _, ev := range tr.Events {
				if ev.Type != "guardrail" || ev.Guardrail == nil {
					continue
				}
				gev := ev.Guardrail

				// Match by guardrail ID or by category.
				if gev.GuardrailID != gr.ID && gev.Category != gr.Category {
					continue
				}

				if gev.Category != "" {
					catSet[gev.Category] = true
				}

				if !gev.Triggered {
					continue
				}

				r.TriggerCount++
				totalScore += gev.Score
				scoreCount++
				if gev.Score > r.MaxScore {
					r.MaxScore = gev.Score
				}

				switch gev.Action {
				case "block":
					r.BlockCount++
				case "warn":
					r.WarnCount++
				}

				// A trigger on a benign trace is a false positive.
				if traceBenign {
					r.FalsePositives++
				}
			}
		}

		if scoreCount > 0 {
			r.AvgScore = totalScore / float64(scoreCount)
		}

		for cat := range catSet {
			r.Categories = append(r.Categories, cat)
		}

		results = append(results, r)
	}

	return results
}

// isTraceBenign returns true if a trace contains no guardrail triggers with
// blocking actions, suggesting the trace represents benign behavior.
func isTraceBenign(tr *Trace) bool {
	for _, ev := range tr.Events {
		if ev.Type != "guardrail" || ev.Guardrail == nil {
			continue
		}
		if ev.Guardrail.Triggered && ev.Guardrail.Action == "block" {
			return false
		}
	}
	return true
}

// checkPolicyAlignment checks each guardrail against the policy's rules to see
// if there is a corresponding rule covering the same area.
func checkPolicyAlignment(guardrails []GuardrailConfig, p *Policy) []AlignmentResult {
	results := make([]AlignmentResult, 0, len(guardrails))

	for _, gr := range guardrails {
		ar := AlignmentResult{
			GuardrailID: gr.ID,
			Category:    gr.Category,
		}

		matchingRule, conflict := findMatchingRule(gr, p.Rules)
		if matchingRule != nil {
			ar.HasMatchingRule = true
			ar.RuleID = matchingRule.ID
			ar.Conflict = conflict
			ar.Aligned = conflict == ""
		}

		results = append(results, ar)
	}

	return results
}

// findMatchingRule looks for a policy rule that covers the same category area
// as the guardrail. Returns the matching rule and any conflict description.
func findMatchingRule(gr GuardrailConfig, rules []Rule) (*Rule, string) {
	keywords, hasKeywords := categoryToolKeywords[gr.Category]

	for i := range rules {
		r := &rules[i]

		// Check if the rule's description or ID references the guardrail's category.
		rLower := strings.ToLower(r.ID + " " + r.Description)
		catMatch := strings.Contains(rLower, gr.Category)

		// Check if the rule's tool patterns match category keywords.
		toolMatch := false
		if hasKeywords {
			for _, tool := range r.Match.Tools {
				for _, kw := range keywords {
					if GlobMatch(kw, tool) || GlobMatch(tool, kw) || strings.Contains(strings.ToLower(tool), gr.Category) {
						toolMatch = true
						break
					}
				}
				if toolMatch {
					break
				}
			}
		}

		if !catMatch && !toolMatch {
			continue
		}

		// Found a matching rule. Check for conflicts.
		conflict := detectConflict(gr, r)
		return r, conflict
	}

	return nil, ""
}

// detectConflict checks whether a guardrail and a policy rule conflict.
func detectConflict(gr GuardrailConfig, r *Rule) string {
	// Guardrail blocks but policy allows.
	if gr.Action == "block" && r.Effect == "allow" {
		return "guardrail blocks but policy allows"
	}
	// Guardrail only warns but policy denies — less severe guardrail.
	if (gr.Action == "warn" || gr.Action == "log") && r.Effect == "deny" {
		return "guardrail only warns but policy denies"
	}
	// Guardrail redacts but policy allows through.
	if gr.Action == "redact" && r.Effect == "allow" {
		return "guardrail redacts but policy allows"
	}
	return ""
}

// identifyGaps finds mandatory categories that have no guardrail configured.
func identifyGaps(guardrails []GuardrailConfig) []GuardrailGap {
	covered := make(map[string]bool)
	for _, gr := range guardrails {
		covered[gr.Category] = true
	}

	var gaps []GuardrailGap
	for _, cat := range mandatoryCategories {
		if covered[cat] {
			continue
		}
		risk := categoryRisk[cat]
		if risk == "" {
			risk = "medium"
		}
		gaps = append(gaps, GuardrailGap{
			Category:    cat,
			Risk:        risk,
			Description: fmt.Sprintf("No guardrail configured for mandatory category %q", cat),
		})
	}

	return gaps
}

// computeGuardrailStats calculates aggregate guardrail statistics.
func computeGuardrailStats(guardrails []GuardrailConfig, alignment []AlignmentResult) GuardrailStats {
	stats := GuardrailStats{
		TotalGuardrails: len(guardrails),
	}

	for _, gr := range guardrails {
		switch gr.Position {
		case "input":
			stats.InputGuardrails++
		case "output":
			stats.OutputGuardrails++
		case "both":
			stats.InputGuardrails++
			stats.OutputGuardrails++
		}
		if gr.Required {
			stats.RequiredCount++
		}
	}

	// Coverage score: fraction of mandatory categories covered.
	if len(mandatoryCategories) > 0 {
		covered := 0
		coveredSet := make(map[string]bool)
		for _, gr := range guardrails {
			coveredSet[gr.Category] = true
		}
		for _, cat := range mandatoryCategories {
			if coveredSet[cat] {
				covered++
			}
		}
		stats.CoverageScore = float64(covered) / float64(len(mandatoryCategories))
	}

	// Alignment score: fraction of guardrails aligned with policy.
	if len(alignment) > 0 {
		aligned := 0
		for _, ar := range alignment {
			if ar.Aligned {
				aligned++
			}
		}
		stats.AlignmentScore = float64(aligned) / float64(len(alignment))
	}

	return stats
}

// generateRecommendations produces actionable suggestions based on the analysis.
func generateRecommendations(ga *GuardrailAnalysis) []string {
	var recs []string

	// Recommend filling coverage gaps.
	for _, gap := range ga.GapAnalysis {
		recs = append(recs, fmt.Sprintf("Add %s-risk %s guardrail: %s", gap.Risk, gap.Category, gap.Description))
	}

	// Recommend fixing alignment conflicts.
	for _, ar := range ga.PolicyAlignment {
		if ar.Conflict != "" {
			recs = append(recs, fmt.Sprintf("Resolve conflict for guardrail %q (category %s): %s", ar.GuardrailID, ar.Category, ar.Conflict))
		}
	}

	// Warn about guardrails with no matching policy rules.
	for _, ar := range ga.PolicyAlignment {
		if !ar.HasMatchingRule {
			recs = append(recs, fmt.Sprintf("Add policy rule for guardrail %q (category %s) to ensure enforcement consistency", ar.GuardrailID, ar.Category))
		}
	}

	// Flag high false positive rates.
	for _, tr := range ga.TraceResults {
		if tr.TriggerCount > 0 && tr.FalsePositives > 0 {
			rate := float64(tr.FalsePositives) / float64(tr.TriggerCount) * 100
			if rate > 50 {
				recs = append(recs, fmt.Sprintf("Guardrail %q has %.0f%% false positive rate — consider tuning threshold", tr.GuardrailID, rate))
			}
		}
	}

	// Recommend input guardrails if none present.
	if ga.Stats.InputGuardrails == 0 && ga.Stats.TotalGuardrails > 0 {
		recs = append(recs, "No input guardrails configured — add input-position guardrails for prompt injection defense")
	}

	// Recommend output guardrails if none present.
	if ga.Stats.OutputGuardrails == 0 && ga.Stats.TotalGuardrails > 0 {
		recs = append(recs, "No output guardrails configured — add output-position guardrails for content safety")
	}

	// Low coverage score.
	if ga.Stats.CoverageScore < 1.0 && ga.Stats.TotalGuardrails > 0 {
		recs = append(recs, fmt.Sprintf("Coverage score is %.0f%% — ensure all mandatory categories (injection, pii, toxicity) are covered", ga.Stats.CoverageScore*100))
	}

	return recs
}

// DefaultGuardrails returns a recommended set of guardrails for AI agents.
func DefaultGuardrails() []GuardrailConfig {
	return []GuardrailConfig{
		{
			ID:        "prompt-injection-detector",
			Name:      "Prompt Injection Detector",
			Category:  "injection",
			Position:  "input",
			Action:    "block",
			Threshold: 0.9,
			Required:  true,
		},
		{
			ID:        "output-toxicity-filter",
			Name:      "Output Toxicity Filter",
			Category:  "toxicity",
			Position:  "output",
			Action:    "block",
			Threshold: 0.85,
			Required:  true,
		},
		{
			ID:        "pii-detector",
			Name:      "PII Detector",
			Category:  "pii",
			Position:  "both",
			Action:    "redact",
			Threshold: 0.8,
			Required:  true,
		},
		{
			ID:        "content-safety-filter",
			Name:      "Content Safety Filter",
			Category:  "content",
			Position:  "output",
			Action:    "block",
			Threshold: 0.9,
			Required:  true,
		},
		{
			ID:        "jailbreak-detector",
			Name:      "Jailbreak Detector",
			Category:  "injection",
			Position:  "input",
			Action:    "block",
			Threshold: 0.85,
			Required:  true,
		},
		{
			ID:        "data-leakage-monitor",
			Name:      "Data Leakage Monitor",
			Category:  "pii",
			Position:  "output",
			Action:    "warn",
			Threshold: 0.7,
			Required:  false,
		},
		{
			ID:        "credential-filter",
			Name:      "Credential Filter",
			Category:  "pii",
			Position:  "output",
			Action:    "block",
			Threshold: 0.95,
			Required:  true,
		},
		{
			ID:        "instruction-hierarchy-enforcer",
			Name:      "Instruction Hierarchy Enforcer",
			Category:  "injection",
			Position:  "input",
			Action:    "block",
			Threshold: 0.9,
			Required:  true,
		},
	}
}

// FormatGuardrailAnalysis returns a box-drawing formatted guardrail report.
func FormatGuardrailAnalysis(ga *GuardrailAnalysis) string {
	if ga == nil {
		return "No guardrail analysis.\n"
	}

	var b strings.Builder

	// Header.
	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│             Guardrail Analysis                      │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Stats summary.
	b.WriteString(fmt.Sprintf("│ Total guardrails:  %-32d │\n", ga.Stats.TotalGuardrails))
	b.WriteString(fmt.Sprintf("│ Input guardrails:  %-32d │\n", ga.Stats.InputGuardrails))
	b.WriteString(fmt.Sprintf("│ Output guardrails: %-32d │\n", ga.Stats.OutputGuardrails))
	b.WriteString(fmt.Sprintf("│ Required:          %-32d │\n", ga.Stats.RequiredCount))
	b.WriteString(fmt.Sprintf("│ Coverage:          %-32s │\n", fmt.Sprintf("%.0f%%", ga.Stats.CoverageScore*100)))
	b.WriteString(fmt.Sprintf("│ Alignment:         %-32s │\n", fmt.Sprintf("%.0f%%", ga.Stats.AlignmentScore*100)))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Guardrail table.
	b.WriteString("│ Guardrails:                                         │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	for _, gr := range ga.Guardrails {
		req := " "
		if gr.Required {
			req = "*"
		}
		b.WriteString(fmt.Sprintf("│ %s %-20s %-10s %-7s %-6s │\n",
			req,
			truncStr(gr.ID, 20),
			truncStr(gr.Category, 10),
			truncStr(gr.Position, 7),
			truncStr(gr.Action, 6)))
	}

	// Trace results.
	if len(ga.TraceResults) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│ Trace Results:                                      │\n")
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for _, tr := range ga.TraceResults {
			b.WriteString(fmt.Sprintf("│ %-22s trig=%-3d blk=%-3d wrn=%-3d │\n",
				truncStr(tr.GuardrailID, 22),
				tr.TriggerCount, tr.BlockCount, tr.WarnCount))
			if tr.TriggerCount > 0 {
				b.WriteString(fmt.Sprintf("│   avg=%.2f max=%.2f fp=%d%s\n",
					tr.AvgScore, tr.MaxScore, tr.FalsePositives,
					strings.Repeat(" ", 19)+"│"))
			}
		}
	}

	// Alignment status.
	if len(ga.PolicyAlignment) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│ Policy Alignment:                                   │\n")
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for _, ar := range ga.PolicyAlignment {
			status := "✗ no rule"
			if ar.HasMatchingRule && ar.Aligned {
				status = "✓ aligned"
			} else if ar.HasMatchingRule {
				status = "⚠ conflict"
			}
			b.WriteString(fmt.Sprintf("│ %-22s %-10s %s\n",
				truncStr(ar.GuardrailID, 22),
				truncStr(ar.Category, 10),
				padRight(status, 17)+"│"))
			if ar.Conflict != "" {
				b.WriteString(fmt.Sprintf("│   %s\n", padRight(truncStr(ar.Conflict, 48), 49)+"│"))
			}
		}
	}

	// Gaps.
	if len(ga.GapAnalysis) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│ Coverage Gaps:                                      │\n")
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for _, gap := range ga.GapAnalysis {
			b.WriteString(fmt.Sprintf("│ [%s] %-10s %s\n",
				padRight(strings.ToUpper(gap.Risk), 8),
				truncStr(gap.Category, 10),
				padRight(truncStr(gap.Description, 27), 28)+"│"))
		}
	}

	// Recommendations.
	if len(ga.Recommendations) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│ Recommendations:                                    │\n")
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for i, rec := range ga.Recommendations {
			b.WriteString(fmt.Sprintf("│ %d. %s\n", i+1, truncStr(rec, 48)))
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}

// padRight pads a string to the given width with spaces on the right.
func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
