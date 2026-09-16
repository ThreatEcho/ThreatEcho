// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/gap"
)

func makeCompareReport(direction string) *gap.CompareReport {
	cr := &gap.CompareReport{
		Before: gap.RiskSummary{
			Critical: 2, High: 3, Medium: 4, Low: 1, Total: 10, Score: 55.0,
		},
		After: gap.RiskSummary{
			Critical: 1, High: 2, Medium: 4, Low: 1, Total: 8, Score: 42.0,
		},
		ScoreDelta: -13.0,
		TacticDelta: gap.TacticDelta{
			AttackBefore: 8, AttackAfter: 10,
			AtlasBefore: 3, AtlasAfter: 4,
		},
		Unchanged: 5,
	}

	if direction == "improved" {
		cr.ResolvedGaps = []gap.Gap{
			{StageID: "s1", Technique: "T1059.001", Risk: "critical", Type: gap.GapDetectionMissing},
			{StageID: "s2", Technique: "T1566.001", Risk: "high", Type: gap.GapDetectionMissing},
		}
	}
	if direction == "regressed" {
		cr.ScoreDelta = 10.0
		cr.After.Score = 65.0
		cr.NewGaps = []gap.Gap{
			{StageID: "s3", Technique: "T1190", Risk: "high", Type: gap.GapTelemetryMissing},
		}
	}

	return cr
}

func TestCompareTextReport_Improved(t *testing.T) {
	cr := makeCompareReport("improved")
	var buf bytes.Buffer
	CompareTextReport(&buf, cr)
	out := buf.String()
	if !strings.Contains(out, "IMPROVED") {
		t.Error("missing IMPROVED direction")
	}
	if !strings.Contains(out, "Resolved") {
		t.Error("missing resolved gaps section")
	}
}

func TestCompareTextReport_Regressed(t *testing.T) {
	cr := makeCompareReport("regressed")
	var buf bytes.Buffer
	CompareTextReport(&buf, cr)
	out := buf.String()
	if !strings.Contains(out, "REGRESSED") {
		t.Error("missing REGRESSED direction")
	}
	if !strings.Contains(out, "New") {
		t.Error("missing new gaps section")
	}
}

func TestCompareTextReport_Unchanged(t *testing.T) {
	cr := makeCompareReport("unchanged")
	cr.ScoreDelta = 0
	cr.After.Score = cr.Before.Score
	var buf bytes.Buffer
	CompareTextReport(&buf, cr)
	out := buf.String()
	if !strings.Contains(out, "UNCHANGED") {
		t.Error("missing UNCHANGED direction")
	}
}

func TestCompareTextReport_TacticDelta(t *testing.T) {
	cr := makeCompareReport("improved")
	var buf bytes.Buffer
	CompareTextReport(&buf, cr)
	out := buf.String()
	if !strings.Contains(out, "Tactic Coverage") {
		t.Error("missing tactic coverage section")
	}
	if !strings.Contains(out, "ATT&CK") {
		t.Error("missing ATT&CK tactic delta")
	}
}

func TestCompareJSONReport_Valid(t *testing.T) {
	cr := makeCompareReport("improved")
	var buf bytes.Buffer
	if err := CompareJSONReport(&buf, cr); err != nil {
		t.Fatalf("CompareJSONReport error: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["direction"] != "improved" {
		t.Errorf("direction = %v, want improved", result["direction"])
	}
	if result["resolved_gaps"].(float64) != 2 {
		t.Errorf("resolved_gaps = %v, want 2", result["resolved_gaps"])
	}
}

func TestCompareJSONReport_ContainsScoreDelta(t *testing.T) {
	cr := makeCompareReport("improved")
	var buf bytes.Buffer
	CompareJSONReport(&buf, cr)
	var result map[string]interface{}
	json.Unmarshal(buf.Bytes(), &result)
	if _, ok := result["score_delta"]; !ok {
		t.Error("missing score_delta field")
	}
}

func TestFormatGapBrief(t *testing.T) {
	tests := []struct {
		g    gap.Gap
		want string
	}{
		{
			gap.Gap{Type: gap.GapTacticUncovered, Tactic: "exfiltration", Risk: "critical"},
			"tactic",
		},
		{
			gap.Gap{Type: gap.GapDetectionMissing, StageID: "s1", Technique: "T1059", Risk: "high"},
			"missing detection",
		},
		{
			gap.Gap{Type: gap.GapTelemetryMissing, StageID: "s2", Technique: "T1566", Risk: "medium"},
			"no telemetry",
		},
	}
	for _, tt := range tests {
		got := formatGapBrief(tt.g)
		if !strings.Contains(got, tt.want) {
			t.Errorf("formatGapBrief(%v) = %q, want to contain %q", tt.g.Type, got, tt.want)
		}
	}
}
