// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package gap

import (
	"math"
)

// CompareReport shows how detection coverage changed between two analyses.
type CompareReport struct {
	Before       RiskSummary
	After        RiskSummary
	ScoreDelta   float64 // negative = improved
	NewGaps      []Gap   // gaps in After that weren't in Before
	ResolvedGaps []Gap   // gaps in Before that aren't in After
	Unchanged    int     // gaps present in both
	TacticDelta  TacticDelta
}

// TacticDelta tracks changes in tactic coverage.
type TacticDelta struct {
	AttackBefore int
	AttackAfter  int
	AtlasBefore  int
	AtlasAfter   int
}

// Compare produces a delta between two gap reports (before and after).
// Shows what improved, what regressed, and what stayed the same.
func Compare(before, after *GapReport) *CompareReport {
	cr := &CompareReport{
		Before:     before.RiskSummary,
		After:      after.RiskSummary,
		ScoreDelta: after.RiskSummary.Score - before.RiskSummary.Score,
	}

	// Tactic delta.
	cr.TacticDelta = TacticDelta{
		AttackBefore: before.Aggregate.AttackTactics.Covered,
		AttackAfter:  after.Aggregate.AttackTactics.Covered,
		AtlasBefore:  before.Aggregate.AtlasTactics.Covered,
		AtlasAfter:   after.Aggregate.AtlasTactics.Covered,
	}

	// Build gap fingerprints for matching.
	beforeSet := make(map[string]Gap)
	for _, g := range before.Gaps {
		beforeSet[gapKey(g)] = g
	}
	afterSet := make(map[string]Gap)
	for _, g := range after.Gaps {
		afterSet[gapKey(g)] = g
	}

	// New gaps: in after but not in before.
	for k, g := range afterSet {
		if _, exists := beforeSet[k]; !exists {
			cr.NewGaps = append(cr.NewGaps, g)
		}
	}

	// Resolved gaps: in before but not in after.
	for k, g := range beforeSet {
		if _, exists := afterSet[k]; !exists {
			cr.ResolvedGaps = append(cr.ResolvedGaps, g)
		}
	}

	// Unchanged: present in both.
	for k := range beforeSet {
		if _, exists := afterSet[k]; exists {
			cr.Unchanged++
		}
	}

	return cr
}

// gapKey produces a stable string key for matching gaps across reports.
func gapKey(g Gap) string {
	switch g.Type {
	case GapTacticUncovered:
		return string(g.Type) + ":" + g.Tactic
	default:
		return string(g.Type) + ":" + g.CampaignName + ":" + g.StageID + ":" + g.Technique
	}
}

// Direction returns a human-readable direction indicator.
func (cr *CompareReport) Direction() string {
	if math.Abs(cr.ScoreDelta) < 0.5 {
		return "unchanged"
	}
	if cr.ScoreDelta < 0 {
		return "improved"
	}
	return "regressed"
}
