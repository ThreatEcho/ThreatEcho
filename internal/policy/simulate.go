// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

// ToolDecision records what a policy would decide for a specific tool call.
type ToolDecision struct {
	Tool   string `json:"tool"`
	Effect string `json:"effect"` // "allow", "deny", "alert"
	RuleID string `json:"rule_id,omitempty"`
	Reason string `json:"reason"`
}

// StageSimResult holds per-stage simulation output.
type StageSimResult struct {
	StageID   string         `json:"stage_id"`
	StageName string         `json:"stage_name"`
	Tactic    string         `json:"tactic"`
	Technique string         `json:"technique"`
	Tools     []string       `json:"tools"`
	Decisions []ToolDecision `json:"decisions"`
	Allowed   int            `json:"allowed"`
	Denied    int            `json:"denied"`
	Alerted   int            `json:"alerted"`
}

// SimulationReport aggregates the full simulation result.
type SimulationReport struct {
	Policy       string           `json:"policy"`
	Campaign     string           `json:"campaign"`
	Stages       []StageSimResult `json:"stages"`
	TotalAllowed int              `json:"total_allowed"`
	TotalDenied  int              `json:"total_denied"`
	TotalAlerted int              `json:"total_alerted"`
	TotalTools   int              `json:"total_tools"`
	CoveragePct  float64          `json:"coverage_pct"` // % of tools with an explicit rule
}

// SimulatePolicy walks all stages of a campaign, infers tool calls, and
// evaluates each against the policy without executing anything.
func SimulatePolicy(p *Policy, c *campaign.Campaign) *SimulationReport {
	report := &SimulationReport{
		Policy:   p.Meta.Name,
		Campaign: c.Meta.Name,
	}

	// Sort rules by priority descending for evaluation.
	sorted := make([]Rule, len(p.Rules))
	copy(sorted, p.Rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})

	coveredTools := 0

	for _, stage := range c.Stages {
		tools := InferTools(stage)
		actions := inferActions(stage)
		target := stage.Execute.Target

		sr := StageSimResult{
			StageID:   stage.ID,
			StageName: stage.Name,
			Tactic:    stage.Tactic,
			Technique: stage.Technique,
			Tools:     tools,
		}

		if len(tools) == 0 {
			// No tools inferred — implicit allow for the stage.
			sr.Decisions = append(sr.Decisions, ToolDecision{
				Tool:   "(none)",
				Effect: "allow",
				Reason: "no tools inferred from stage",
			})
			sr.Allowed++
			report.TotalAllowed++
			report.TotalTools++
			report.Stages = append(report.Stages, sr)
			continue
		}

		for _, tool := range tools {
			report.TotalTools++

			decision := ToolDecision{
				Tool: tool,
			}

			matched := false
			for _, rule := range sorted {
				matchedTool := matchTools(rule.Match.Tools, []string{tool})
				matchedTactic := matchTactic(rule.Match.Tactics, stage.Tactic)
				matchedAction := matchActions(rule.Match.Actions, actions)
				matchedTarget := matchTarget(rule.Match.Targets, target)

				if !ruleMatchesStage(rule.Match, matchedTool, matchedTactic, matchedAction, matchedTarget) {
					continue
				}

				if !conditionsPass(rule.Conditions, stage) {
					continue
				}

				matched = true
				coveredTools++

				decision.RuleID = rule.ID
				switch rule.Effect {
				case "deny":
					decision.Effect = "deny"
					decision.Reason = fmt.Sprintf("denied by rule %q: %s", rule.ID, rule.Description)
					sr.Denied++
					report.TotalDenied++
				case "alert":
					decision.Effect = "alert"
					decision.Reason = fmt.Sprintf("alert from rule %q: %s", rule.ID, rule.Description)
					sr.Alerted++
					report.TotalAlerted++
				case "allow":
					decision.Effect = "allow"
					decision.Reason = fmt.Sprintf("allowed by rule %q", rule.ID)
					sr.Allowed++
					report.TotalAllowed++
				}

				break // first matching rule wins
			}

			if !matched {
				// Implicit allow — no rule matched.
				decision.Effect = "allow"
				decision.Reason = "no matching rule (implicit allow)"
				sr.Allowed++
				report.TotalAllowed++
			}

			sr.Decisions = append(sr.Decisions, decision)
		}

		report.Stages = append(report.Stages, sr)
	}

	if report.TotalTools > 0 {
		report.CoveragePct = float64(coveredTools) * 100.0 / float64(report.TotalTools)
	}

	return report
}

// FormatSimulationReport renders a box-drawing formatted text report.
func FormatSimulationReport(r *SimulationReport) string {
	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────────────┐\n")
	b.WriteString("│ Policy Simulation Report                                    │\n")
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	writePaddedLine(&b, fmt.Sprintf("Policy:   %s", r.Policy))
	writePaddedLine(&b, fmt.Sprintf("Campaign: %s", r.Campaign))
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")

	for _, stage := range r.Stages {
		writePaddedLine(&b, fmt.Sprintf("Stage: %s — %s", stage.StageID, stage.StageName))
		writePaddedLine(&b, fmt.Sprintf("  Tactic: %s", stage.Tactic))
		writePaddedLine(&b, fmt.Sprintf("  Technique: %s", stage.Technique))
		if len(stage.Tools) > 0 {
			writePaddedLine(&b, fmt.Sprintf("  Tools: %s", strings.Join(stage.Tools, ", ")))
		}

		for _, d := range stage.Decisions {
			icon := "✓"
			if d.Effect == "deny" {
				icon = "✗"
			} else if d.Effect == "alert" {
				icon = "⚠"
			}
			writePaddedLine(&b, fmt.Sprintf("    %s %s → %s", icon, d.Tool, d.Effect))
			if d.RuleID != "" {
				writePaddedLine(&b, fmt.Sprintf("      Rule: %s", d.RuleID))
			}
		}
		b.WriteString("│                                                             │\n")
	}

	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	writePaddedLine(&b, fmt.Sprintf("Summary: %d allowed, %d denied, %d alerted", r.TotalAllowed, r.TotalDenied, r.TotalAlerted))
	writePaddedLine(&b, fmt.Sprintf("Total tool calls: %d  Coverage: %.0f%%", r.TotalTools, r.CoveragePct))
	b.WriteString("└─────────────────────────────────────────────────────────────┘\n")

	return b.String()
}

// writePaddedLine writes a box-drawing line padded to fill the box width.
func writePaddedLine(b *strings.Builder, content string) {
	const width = 59
	line := content
	if len(line) > width {
		line = line[:width]
	}
	fmt.Fprintf(b, "│ %-*s │\n", width, line)
}
