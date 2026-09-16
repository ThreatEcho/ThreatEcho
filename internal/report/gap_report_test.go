// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/gap"
)

// helper to build a minimal gap report
func makeGapReport(campaigns int, gaps []gap.Gap) *gap.GapReport {
	r := &gap.GapReport{}
	for i := 0; i < campaigns; i++ {
		r.Campaigns = append(r.Campaigns, gap.CampaignCoverage{
			Name:           "test-campaign",
			Adversary:      "TestActor",
			Stages:         5,
			Completed:      4,
			Skipped:        1,
			TechniquesUsed: 3,
			AttackTactics: gap.TacticBreakdown{
				Total:   14,
				Covered: 6,
				Details: []gap.TacticDetail{
					{Short: "initial-access", Name: "Initial Access", Stages: 1},
					{Short: "execution", Name: "Execution", Stages: 2},
				},
				Missing: []string{"reconnaissance", "resource-development"},
			},
			AtlasTactics: gap.TacticBreakdown{Total: 7, Covered: 3},
		})
	}
	r.Aggregate = gap.AggregateCoverage{
		TotalCampaigns:   campaigns,
		TotalStages:      campaigns * 5,
		TotalCompleted:   campaigns * 4,
		TotalSkipped:     campaigns,
		UniqueTechniques: 3,
		AttackTactics: gap.TacticBreakdown{
			Total:   14,
			Covered: 6,
			Details: []gap.TacticDetail{
				{Short: "initial-access", Name: "Initial Access", Stages: 1},
			},
			Missing: []string{"reconnaissance"},
		},
		AtlasTactics: gap.TacticBreakdown{Total: 7, Covered: 3},
		Framework:    gap.FrameworkBreakdown{ATTACKStages: 3, ATLASStages: 1, OWASPStages: 1},
	}
	r.Gaps = gaps
	r.RiskSummary = gap.RiskSummary{
		Critical: 1, High: 2, Medium: 3, Low: 1, Total: 7, Score: 42.0,
	}
	return r
}

func TestGapTextReport_ContainsHeader(t *testing.T) {
	r := makeGapReport(1, nil)
	var buf bytes.Buffer
	GapTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "Detection Gap Analysis") {
		t.Error("missing header")
	}
}

func TestGapTextReport_ContainsCampaigns(t *testing.T) {
	r := makeGapReport(1, nil)
	var buf bytes.Buffer
	GapTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "test-campaign") {
		t.Error("missing campaign name")
	}
	if !strings.Contains(out, "TestActor") {
		t.Error("missing adversary name")
	}
}

func TestGapTextReport_ShowsFrameworkCoverage(t *testing.T) {
	r := makeGapReport(1, nil)
	var buf bytes.Buffer
	GapTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "ATT&CK") {
		t.Error("missing ATT&CK framework mention")
	}
}

func TestGapTextReport_ShowsGaps(t *testing.T) {
	gaps := []gap.Gap{
		{
			CampaignName: "test", StageID: "s1", StageName: "Stage 1",
			Technique: "T1059.001", TechniqueName: "PowerShell",
			Tactic: "execution", Type: gap.GapDetectionMissing, Risk: "critical",
			Description: "No detection rules",
		},
	}
	r := makeGapReport(1, gaps)
	var buf bytes.Buffer
	GapTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "T1059.001") {
		t.Error("missing technique in gap output")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("missing CRITICAL label")
	}
}

func TestGapTextReport_NoGaps(t *testing.T) {
	r := makeGapReport(1, nil)
	r.Gaps = nil
	r.RiskSummary = gap.RiskSummary{Score: 0}
	var buf bytes.Buffer
	GapTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "No detection gaps found") {
		t.Error("missing 'no gaps' message")
	}
}

func TestGapTextReport_RiskSummary(t *testing.T) {
	r := makeGapReport(1, nil)
	var buf bytes.Buffer
	GapTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "RISK SUMMARY") {
		t.Error("missing risk summary section")
	}
	if !strings.Contains(out, "/100") {
		t.Error("missing risk score")
	}
}

func TestGapTextReport_TacticGrid(t *testing.T) {
	r := makeGapReport(1, nil)
	var buf bytes.Buffer
	GapTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "TACTIC COVERAGE") {
		t.Error("missing tactic coverage section")
	}
}

func TestGapTextReport_TacticUncoveredGap(t *testing.T) {
	gaps := []gap.Gap{
		{
			Tactic: "reconnaissance", Type: gap.GapTacticUncovered,
			Risk: "medium", Description: "ATT&CK tactic not covered",
		},
	}
	r := makeGapReport(1, gaps)
	var buf bytes.Buffer
	GapTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "not covered") {
		t.Error("missing tactic uncovered description")
	}
}

func TestGapTextReport_TelemetryMissingGap(t *testing.T) {
	gaps := []gap.Gap{
		{
			CampaignName: "apt29", StageID: "s2", StageName: "Stage 2",
			Technique: "T1566.001", Tactic: "initial-access",
			Type: gap.GapTelemetryMissing, Risk: "medium",
			Description: "No expected telemetry",
		},
	}
	r := makeGapReport(1, gaps)
	var buf bytes.Buffer
	GapTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "MEDIUM") {
		t.Error("missing MEDIUM label")
	}
}

func TestGapTextReport_MultipleCampaigns(t *testing.T) {
	r := makeGapReport(3, nil)
	var buf bytes.Buffer
	GapTextReport(&buf, r)
	out := buf.String()
	// Should show campaign entries (indexed [1], [2], [3]).
	if !strings.Contains(out, "[1]") || !strings.Contains(out, "[3]") {
		t.Error("missing multi-campaign indices")
	}
}

func TestGapTextReport_RiskBar(t *testing.T) {
	var buf bytes.Buffer
	printRiskBar(&buf, 42)
	out := buf.String()
	if !strings.Contains(out, "▓") {
		t.Error("missing filled bar character")
	}
	if !strings.Contains(out, "░") {
		t.Error("missing empty bar character")
	}
}

func TestGapTextReport_RiskBar_Zero(t *testing.T) {
	var buf bytes.Buffer
	printRiskBar(&buf, 0)
	out := buf.String()
	if strings.Contains(out, "▓") {
		t.Error("zero score should have no filled chars")
	}
}

func TestGapTextReport_RiskBar_Hundred(t *testing.T) {
	var buf bytes.Buffer
	printRiskBar(&buf, 100)
	out := buf.String()
	if strings.Contains(out, "░") {
		t.Error("100 score should have no empty chars")
	}
}

func TestGapTypeLabel(t *testing.T) {
	tests := []struct {
		gapType gap.GapType
		want    string
	}{
		{gap.GapDetectionMissing, "No detection rules"},
		{gap.GapTelemetryMissing, "No expected telemetry"},
		{gap.GapTacticUncovered, "Tactic not covered"},
	}
	for _, tt := range tests {
		got := gapTypeLabel(tt.gapType)
		if !strings.Contains(got, tt.want) {
			t.Errorf("gapTypeLabel(%s) = %q, want to contain %q", tt.gapType, got, tt.want)
		}
	}
}

func TestRiskColor(t *testing.T) {
	// Just verify no panic and non-empty for known risk levels.
	for _, risk := range []string{"critical", "high", "medium", "low", "unknown"} {
		c := riskColor(risk)
		_ = c // just testing no crash
	}
}
