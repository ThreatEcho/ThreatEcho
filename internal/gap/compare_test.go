// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package gap

import (
	"testing"
)

func TestCompare_Improved(t *testing.T) {
	before := &GapReport{
		Gaps: []Gap{
			{Type: GapTacticUncovered, Tactic: "impact", Risk: "high"},
			{Type: GapTacticUncovered, Tactic: "reconnaissance", Risk: "medium"},
			{Type: GapDetectionMissing, CampaignName: "test", StageID: "s1", Technique: "T1566", Risk: "high"},
		},
		RiskSummary: RiskSummary{Critical: 0, High: 2, Medium: 1, Total: 3, Score: 40},
		Aggregate: AggregateCoverage{
			AttackTactics: TacticBreakdown{Total: 14, Covered: 8},
			AtlasTactics:  TacticBreakdown{Total: 7, Covered: 3},
		},
	}
	after := &GapReport{
		Gaps: []Gap{
			{Type: GapTacticUncovered, Tactic: "reconnaissance", Risk: "medium"},
		},
		RiskSummary: RiskSummary{Critical: 0, High: 0, Medium: 1, Total: 1, Score: 20},
		Aggregate: AggregateCoverage{
			AttackTactics: TacticBreakdown{Total: 14, Covered: 10},
			AtlasTactics:  TacticBreakdown{Total: 7, Covered: 5},
		},
	}

	cr := Compare(before, after)

	if cr.Direction() != "improved" {
		t.Errorf("direction = %q, want improved", cr.Direction())
	}
	if cr.ScoreDelta >= 0 {
		t.Errorf("score delta = %f, want negative (improved)", cr.ScoreDelta)
	}
	if len(cr.ResolvedGaps) != 2 {
		t.Errorf("resolved = %d, want 2", len(cr.ResolvedGaps))
	}
	if len(cr.NewGaps) != 0 {
		t.Errorf("new gaps = %d, want 0", len(cr.NewGaps))
	}
	if cr.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", cr.Unchanged)
	}
	if cr.TacticDelta.AttackBefore != 8 || cr.TacticDelta.AttackAfter != 10 {
		t.Errorf("attack tactic delta wrong: %d → %d", cr.TacticDelta.AttackBefore, cr.TacticDelta.AttackAfter)
	}
}

func TestCompare_Regressed(t *testing.T) {
	before := &GapReport{
		Gaps:        []Gap{},
		RiskSummary: RiskSummary{Score: 0, Total: 0},
		Aggregate: AggregateCoverage{
			AttackTactics: TacticBreakdown{Total: 14, Covered: 14},
		},
	}
	after := &GapReport{
		Gaps: []Gap{
			{Type: GapTacticUncovered, Tactic: "impact", Risk: "high"},
		},
		RiskSummary: RiskSummary{Score: 50, Total: 1, High: 1},
		Aggregate: AggregateCoverage{
			AttackTactics: TacticBreakdown{Total: 14, Covered: 13},
		},
	}

	cr := Compare(before, after)

	if cr.Direction() != "regressed" {
		t.Errorf("direction = %q, want regressed", cr.Direction())
	}
	if len(cr.NewGaps) != 1 {
		t.Errorf("new gaps = %d, want 1", len(cr.NewGaps))
	}
	if len(cr.ResolvedGaps) != 0 {
		t.Errorf("resolved = %d, want 0", len(cr.ResolvedGaps))
	}
}

func TestCompare_Unchanged(t *testing.T) {
	report := &GapReport{
		Gaps: []Gap{
			{Type: GapTacticUncovered, Tactic: "reconnaissance", Risk: "medium"},
		},
		RiskSummary: RiskSummary{Score: 20, Total: 1, Medium: 1},
		Aggregate: AggregateCoverage{
			AttackTactics: TacticBreakdown{Total: 14, Covered: 13},
		},
	}

	cr := Compare(report, report)

	if cr.Direction() != "unchanged" {
		t.Errorf("direction = %q, want unchanged", cr.Direction())
	}
	if cr.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", cr.Unchanged)
	}
	if len(cr.NewGaps) != 0 {
		t.Errorf("new gaps = %d, want 0", len(cr.NewGaps))
	}
	if len(cr.ResolvedGaps) != 0 {
		t.Errorf("resolved = %d, want 0", len(cr.ResolvedGaps))
	}
}

func TestCompare_GapKeyStability(t *testing.T) {
	g1 := Gap{Type: GapDetectionMissing, CampaignName: "c", StageID: "s", Technique: "T1566"}
	g2 := Gap{Type: GapDetectionMissing, CampaignName: "c", StageID: "s", Technique: "T1566", Risk: "different"}

	if gapKey(g1) != gapKey(g2) {
		t.Error("gap keys should match regardless of risk (risk can change between runs)")
	}

	g3 := Gap{Type: GapTacticUncovered, Tactic: "impact"}
	g4 := Gap{Type: GapTacticUncovered, Tactic: "reconnaissance"}

	if gapKey(g3) == gapKey(g4) {
		t.Error("different tactic gaps should have different keys")
	}
}
