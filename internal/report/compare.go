// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"math"

	"github.com/ThreatEcho/threatecho/internal/gap"
)

// CompareTextReport writes a human-readable delta report between two gap analyses.
func CompareTextReport(w io.Writer, cr *gap.CompareReport) {
	fmt.Fprintf(w, "\n%s╔══ Coverage Comparison ══╗%s\n", cyan, reset)

	// Direction banner.
	dir := cr.Direction()
	switch dir {
	case "improved":
		fmt.Fprintf(w, "  Direction: %s%s▲ IMPROVED%s\n", green, bold, reset)
	case "regressed":
		fmt.Fprintf(w, "  Direction: %s%s▼ REGRESSED%s\n", red, bold, reset)
	default:
		fmt.Fprintf(w, "  Direction: %s— UNCHANGED%s\n", yellow, reset)
	}

	// Score delta.
	fmt.Fprintf(w, "\n%s── Risk Score ──%s\n", cyan, reset)
	fmt.Fprintf(w, "  Before: %.1f    After: %.1f    Delta: ", cr.Before.Score, cr.After.Score)
	if cr.ScoreDelta < -0.5 {
		fmt.Fprintf(w, "%s%.1f%s\n", green, cr.ScoreDelta, reset)
	} else if cr.ScoreDelta > 0.5 {
		fmt.Fprintf(w, "%s+%.1f%s\n", red, cr.ScoreDelta, reset)
	} else {
		fmt.Fprintf(w, "%.1f\n", cr.ScoreDelta)
	}

	// Tactic delta.
	fmt.Fprintf(w, "\n%s── Tactic Coverage ──%s\n", cyan, reset)
	attackDelta := cr.TacticDelta.AttackAfter - cr.TacticDelta.AttackBefore
	atlasDelta := cr.TacticDelta.AtlasAfter - cr.TacticDelta.AtlasBefore

	fmt.Fprintf(w, "  ATT&CK: %d → %d", cr.TacticDelta.AttackBefore, cr.TacticDelta.AttackAfter)
	if attackDelta > 0 {
		fmt.Fprintf(w, "  %s(+%d)%s", green, attackDelta, reset)
	} else if attackDelta < 0 {
		fmt.Fprintf(w, "  %s(%d)%s", red, attackDelta, reset)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "  ATLAS:  %d → %d", cr.TacticDelta.AtlasBefore, cr.TacticDelta.AtlasAfter)
	if atlasDelta > 0 {
		fmt.Fprintf(w, "  %s(+%d)%s", green, atlasDelta, reset)
	} else if atlasDelta < 0 {
		fmt.Fprintf(w, "  %s(%d)%s", red, atlasDelta, reset)
	}
	fmt.Fprintln(w)

	// Gap counts.
	fmt.Fprintf(w, "\n%s── Gap Changes ──%s\n", cyan, reset)
	fmt.Fprintf(w, "  Gaps before: %d    Gaps after: %d\n",
		cr.Before.Total, cr.After.Total)

	if len(cr.ResolvedGaps) > 0 {
		fmt.Fprintf(w, "\n  %s✓ Resolved (%d):%s\n", green, len(cr.ResolvedGaps), reset)
		for _, g := range cr.ResolvedGaps {
			fmt.Fprintf(w, "    %s✓%s %s", green, reset, formatGapBrief(g))
			fmt.Fprintln(w)
		}
	}

	if len(cr.NewGaps) > 0 {
		fmt.Fprintf(w, "\n  %s✗ New (%d):%s\n", red, len(cr.NewGaps), reset)
		for _, g := range cr.NewGaps {
			fmt.Fprintf(w, "    %s✗%s %s", red, reset, formatGapBrief(g))
			fmt.Fprintln(w)
		}
	}

	if cr.Unchanged > 0 {
		fmt.Fprintf(w, "\n  — Unchanged: %d gap(s)\n", cr.Unchanged)
	}

	fmt.Fprintln(w)
}

// CompareJSONReport writes a JSON delta report.
func CompareJSONReport(w io.Writer, cr *gap.CompareReport) error {
	out := struct {
		Direction   string          `json:"direction"`
		Before      gap.RiskSummary `json:"before"`
		After       gap.RiskSummary `json:"after"`
		ScoreDelta  float64         `json:"score_delta"`
		TacticDelta struct {
			AttackBefore int `json:"attack_before"`
			AttackAfter  int `json:"attack_after"`
			AtlasBefore  int `json:"atlas_before"`
			AtlasAfter   int `json:"atlas_after"`
		} `json:"tactic_delta"`
		NewGaps      int `json:"new_gaps"`
		ResolvedGaps int `json:"resolved_gaps"`
		Unchanged    int `json:"unchanged"`
	}{
		Direction:    cr.Direction(),
		Before:       cr.Before,
		After:        cr.After,
		ScoreDelta:   math.Round(cr.ScoreDelta*10) / 10,
		NewGaps:      len(cr.NewGaps),
		ResolvedGaps: len(cr.ResolvedGaps),
		Unchanged:    cr.Unchanged,
	}
	out.TacticDelta.AttackBefore = cr.TacticDelta.AttackBefore
	out.TacticDelta.AttackAfter = cr.TacticDelta.AttackAfter
	out.TacticDelta.AtlasBefore = cr.TacticDelta.AtlasBefore
	out.TacticDelta.AtlasAfter = cr.TacticDelta.AtlasAfter

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// formatGapBrief returns a one-line summary of a gap for the compare report.
func formatGapBrief(g gap.Gap) string {
	switch g.Type {
	case gap.GapTacticUncovered:
		return fmt.Sprintf("[%s] tactic %q uncovered", g.Risk, g.Tactic)
	case gap.GapDetectionMissing:
		return fmt.Sprintf("[%s] %s: missing detection for %s", g.Risk, g.StageID, g.Technique)
	case gap.GapTelemetryMissing:
		return fmt.Sprintf("[%s] %s: no telemetry for %s", g.Risk, g.StageID, g.Technique)
	default:
		return fmt.Sprintf("[%s] %s", g.Risk, string(g.Type))
	}
}
