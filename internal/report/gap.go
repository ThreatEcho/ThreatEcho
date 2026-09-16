// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/gap"
)

// GapTextReport writes a formatted detection gap analysis report to w.
func GapTextReport(w io.Writer, r *gap.GapReport) {
	line := strings.Repeat("─", 64)

	// Header.
	fmt.Fprintf(w, "\n%s%s%s\n", bold, line, reset)
	fmt.Fprintf(w, "%s  ThreatEcho — Detection Gap Analysis%s\n", bold, reset)
	fmt.Fprintf(w, "%s%s%s\n\n", dim, line, reset)

	// Campaigns analyzed.
	fmt.Fprintf(w, "  %sCAMPAIGNS ANALYZED%s\n\n", bold, reset)
	for i, c := range r.Campaigns {
		fmt.Fprintf(w, "  %s[%d]%s %s%s%s (%s)\n", cyan, i+1, reset, bold, c.Name, reset, c.Adversary)

		parts := []string{
			fmt.Sprintf("Stages: %d completed, %d skipped", c.Completed, c.Skipped),
			fmt.Sprintf("Techniques: %d", c.TechniquesUsed),
		}
		if c.AttackTactics.Total > 0 {
			parts = append(parts, fmt.Sprintf("ATT&CK %d/%d", c.AttackTactics.Covered, c.AttackTactics.Total))
		}
		if c.AtlasTactics.Total > 0 {
			parts = append(parts, fmt.Sprintf("ATLAS %d/%d", c.AtlasTactics.Covered, c.AtlasTactics.Total))
		}
		fmt.Fprintf(w, "      %s\n", strings.Join(parts, "  │  "))
	}

	// Framework coverage.
	fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)
	fmt.Fprintf(w, "  %sFRAMEWORK COVERAGE%s\n\n", bold, reset)

	agg := r.Aggregate
	fwParts := []string{}
	if agg.Framework.ATTACKStages > 0 {
		fwParts = append(fwParts, fmt.Sprintf("MITRE ATT&CK:  %s%d stages%s", white, agg.Framework.ATTACKStages, reset))
	}
	if agg.Framework.ATLASStages > 0 {
		fwParts = append(fwParts, fmt.Sprintf("MITRE ATLAS:  %s%d stages%s", white, agg.Framework.ATLASStages, reset))
	}
	if agg.Framework.OWASPStages > 0 {
		fwParts = append(fwParts, fmt.Sprintf("OWASP LLM:  %s%d stages%s", white, agg.Framework.OWASPStages, reset))
	}
	if len(fwParts) > 0 {
		fmt.Fprintf(w, "  %s\n", strings.Join(fwParts, "    "))
	}

	// ATT&CK tactic coverage.
	if agg.AttackTactics.Total > 0 {
		fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)
		pct := 0
		if agg.AttackTactics.Total > 0 {
			pct = agg.AttackTactics.Covered * 100 / agg.AttackTactics.Total
		}
		fmt.Fprintf(w, "  %sATT&CK TACTIC COVERAGE: %d/%d (%d%%)%s\n\n",
			bold, agg.AttackTactics.Covered, agg.AttackTactics.Total, pct, reset)
		printTacticGrid(w, agg.AttackTactics)
	}

	// ATLAS tactic coverage.
	if agg.AtlasTactics.Total > 0 {
		fmt.Fprintln(w)
		pct := 0
		if agg.AtlasTactics.Total > 0 {
			pct = agg.AtlasTactics.Covered * 100 / agg.AtlasTactics.Total
		}
		fmt.Fprintf(w, "  %sATLAS TACTIC COVERAGE: %d/%d (%d%%)%s\n\n",
			bold, agg.AtlasTactics.Covered, agg.AtlasTactics.Total, pct, reset)
		printTacticGrid(w, agg.AtlasTactics)
	}

	// Detection gaps.
	fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)
	if len(r.Gaps) == 0 {
		fmt.Fprintf(w, "  %s✓ No detection gaps found%s\n", green, reset)
	} else {
		fmt.Fprintf(w, "  %sDETECTION GAPS (%d issues)%s\n", bold, len(r.Gaps), reset)
		printGapsByRisk(w, r.Gaps, "critical", "CRITICAL")
		printGapsByRisk(w, r.Gaps, "high", "HIGH")
		printGapsByRisk(w, r.Gaps, "medium", "MEDIUM")
		printGapsByRisk(w, r.Gaps, "low", "LOW")
	}

	// Risk summary.
	fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)
	fmt.Fprintf(w, "  %sRISK SUMMARY%s\n\n", bold, reset)

	rs := r.RiskSummary
	fmt.Fprintf(w, "    %sCritical:%s %s%-3d%s │  %sHigh:%s %s%-3d%s │  %sMedium:%s %s%-3d%s │  %sLow:%s %s%-3d%s\n",
		bold, reset, red+bold, rs.Critical, reset,
		bold, reset, red, rs.High, reset,
		bold, reset, yellow, rs.Medium, reset,
		bold, reset, green, rs.Low, reset)

	score := int(rs.Score)
	fmt.Fprintf(w, "    Risk Score: %s%d/100%s\n\n", bold, score, reset)

	// Progress bar (50 chars wide).
	printRiskBar(w, score)

	fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)
}

// printTacticGrid renders tactics in a 3-column grid with check/x marks.
func printTacticGrid(w io.Writer, tb gap.TacticBreakdown) {
	// Build a combined list: covered first, then missing.
	type entry struct {
		name    string
		covered bool
		stages  int
	}
	var entries []entry

	for _, d := range tb.Details {
		entries = append(entries, entry{name: d.Name, covered: true, stages: d.Stages})
	}
	for _, m := range tb.Missing {
		entries = append(entries, entry{name: m, covered: false})
	}

	col := 0
	for _, e := range entries {
		if e.covered {
			fmt.Fprintf(w, "    %s✓ %-22s%s (%d)", green, e.name, reset, e.stages)
		} else {
			fmt.Fprintf(w, "    %s✗ %-22s%s    ", red, e.name, reset)
		}
		col++
		if col%3 == 0 {
			fmt.Fprintln(w)
		}
	}
	if col%3 != 0 {
		fmt.Fprintln(w)
	}
}

// printGapsByRisk prints all gaps of a given risk level.
func printGapsByRisk(w io.Writer, gaps []gap.Gap, risk, label string) {
	var filtered []gap.Gap
	for _, g := range gaps {
		if g.Risk == risk {
			filtered = append(filtered, g)
		}
	}
	if len(filtered) == 0 {
		return
	}

	fmt.Fprintln(w)
	color := riskColor(risk)
	fmt.Fprintf(w, "  %s⚠ %s (%d)%s\n", color, label, len(filtered), reset)

	for _, g := range filtered {
		fmt.Fprintln(w)

		if g.Type == gap.GapTacticUncovered {
			// Tactic-level gap: no specific campaign or stage.
			tacticDisplay := g.Tactic
			if g.Description != "" {
				tacticDisplay = g.Description
			}
			fmt.Fprintf(w, "    %s⊘%s %s\n", yellow, reset, tacticDisplay)
		} else {
			// Stage-level gap: show campaign and stage context.
			fmt.Fprintf(w, "    %s[%s / %s]%s %s%s%s\n",
				dim, g.CampaignName, g.StageID, reset, bold, g.StageName, reset)

			techDisplay := g.Technique
			if g.TechniqueName != "" && g.TechniqueName != g.Technique {
				techDisplay = fmt.Sprintf("%s — %s", g.Technique, g.TechniqueName)
			}
			fmt.Fprintf(w, "      %s%s%s\n", white, techDisplay, reset)
			fmt.Fprintf(w, "      Gap: %s\n", gapTypeLabel(g.Type))
			if g.Description != "" {
				fmt.Fprintf(w, "      %s%s%s\n", dim, g.Description, reset)
			}
		}
	}
}

// printRiskBar renders a 50-char progress bar colored by risk score.
func printRiskBar(w io.Writer, score int) {
	const barWidth = 50
	filled := score * barWidth / 100
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}

	// Color the filled portion by score severity.
	barColor := green
	if score >= 70 {
		barColor = red + bold
	} else if score >= 40 {
		barColor = yellow
	}

	fmt.Fprintf(w, "    %s%s%s%s%s%s\n",
		barColor, strings.Repeat("▓", filled), reset,
		dim, strings.Repeat("░", barWidth-filled), reset)
}

func riskColor(risk string) string {
	switch risk {
	case "critical":
		return red + bold
	case "high":
		return red
	case "medium":
		return yellow
	case "low":
		return green
	default:
		return white
	}
}

func gapTypeLabel(t gap.GapType) string {
	switch t {
	case gap.GapDetectionMissing:
		return "No detection rules defined for this stage"
	case gap.GapTelemetryMissing:
		return "No expected telemetry defined for this stage"
	case gap.GapTacticUncovered:
		return "Tactic not covered by any campaign stage"
	default:
		return string(t)
	}
}
