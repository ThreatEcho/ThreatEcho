// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package matrix

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/gap"
)

func TestBuildMatrix_Empty(t *testing.T) {
	m := BuildMatrix()
	if len(m.Tactics) != 14 {
		t.Fatalf("expected 14 tactic columns, got %d", len(m.Tactics))
	}
	// All techniques should be Uncovered.
	for _, col := range m.Tactics {
		for _, tc := range col.Techniques {
			if tc.Coverage != Uncovered {
				t.Errorf("technique %s should be Uncovered, got %s", tc.ID, tc.Coverage)
			}
		}
	}
}

func TestBuildMatrix_SingleCampaign(t *testing.T) {
	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "test-campaign"},
		Stages: []campaign.Stage{
			{
				ID:        "s1",
				Technique: "T1566.001",
				Tactic:    "initial-access",
				Execute:   campaign.Execute{Type: "shell"},
				Expect: campaign.Expect{
					Telemetry:  []string{"file_create"},
					Detections: []string{"spearphish_detected"},
				},
			},
			{
				ID:        "s2",
				Technique: "T1059.001",
				Tactic:    "execution",
				Execute:   campaign.Execute{Type: "shell"},
				Expect: campaign.Expect{
					Telemetry: []string{"process_create"},
				},
			},
		},
	}

	result := &engine.RunResult{
		Campaign:  c,
		Mode:      "simulate",
		Completed: 2,
		Stages: []engine.StageResult{
			{Stage: c.Stages[0], Order: 1},
			{Stage: c.Stages[1], Order: 2},
		},
	}

	m := BuildMatrix(result)

	// Find the initial-access column.
	var iaCol *TacticColumn
	for i := range m.Tactics {
		if m.Tactics[i].Short == "initial-access" {
			iaCol = &m.Tactics[i]
			break
		}
	}
	if iaCol == nil {
		t.Fatal("missing initial-access column")
	}

	// T1566.001 should be Detected (has telemetry + detection, but single campaign).
	found := false
	for _, tc := range iaCol.Techniques {
		if tc.ID == "T1566.001" {
			found = true
			if tc.Coverage != Detected {
				t.Errorf("T1566.001: expected Detected, got %s", tc.Coverage)
			}
			if len(tc.Campaigns) != 1 || tc.Campaigns[0] != "test-campaign" {
				t.Errorf("T1566.001: unexpected campaigns: %v", tc.Campaigns)
			}
		}
	}
	if !found {
		t.Error("T1566.001 not found in initial-access column")
	}

	// Find execution column; T1059.001 should be Partial (telemetry only).
	var exCol *TacticColumn
	for i := range m.Tactics {
		if m.Tactics[i].Short == "execution" {
			exCol = &m.Tactics[i]
			break
		}
	}
	if exCol == nil {
		t.Fatal("missing execution column")
	}
	for _, tc := range exCol.Techniques {
		if tc.ID == "T1059.001" {
			if tc.Coverage != Partial {
				t.Errorf("T1059.001: expected Partial, got %s", tc.Coverage)
			}
		}
	}
}

func TestBuildMatrix_MultiCampaignFull(t *testing.T) {
	makeResult := func(name string) *engine.RunResult {
		c := &campaign.Campaign{
			Meta: campaign.Meta{Name: name},
			Stages: []campaign.Stage{
				{
					ID:        "s1",
					Technique: "T1566.001",
					Tactic:    "initial-access",
					Execute:   campaign.Execute{Type: "shell"},
					Expect: campaign.Expect{
						Telemetry:  []string{"file_create"},
						Detections: []string{"spearphish_detected"},
					},
				},
			},
		}
		return &engine.RunResult{
			Campaign:  c,
			Mode:      "simulate",
			Completed: 1,
			Stages:    []engine.StageResult{{Stage: c.Stages[0], Order: 1}},
		}
	}

	m := BuildMatrix(makeResult("campaign-a"), makeResult("campaign-b"))

	var iaCol *TacticColumn
	for i := range m.Tactics {
		if m.Tactics[i].Short == "initial-access" {
			iaCol = &m.Tactics[i]
			break
		}
	}
	if iaCol == nil {
		t.Fatal("missing initial-access column")
	}

	for _, tc := range iaCol.Techniques {
		if tc.ID == "T1566.001" {
			if tc.Coverage != Full {
				t.Errorf("T1566.001 with 2 campaigns: expected Full, got %s", tc.Coverage)
			}
			if len(tc.Campaigns) != 2 {
				t.Errorf("expected 2 campaigns, got %d", len(tc.Campaigns))
			}
		}
	}
}

func TestCoverageLevelFromExpect(t *testing.T) {
	tests := []struct {
		name         string
		hasTelemetry bool
		hasDetection bool
		campaigns    int
		want         CoverageLevel
	}{
		{"no coverage", false, false, 0, Uncovered},
		{"telemetry only", true, false, 1, Partial},
		{"detection only", false, true, 1, Detected},
		{"both single campaign", true, true, 1, Detected},
		{"both multi campaign", true, true, 2, Full},
		{"detection multi no telemetry", false, true, 3, Detected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CoverageFromExpect(tt.hasTelemetry, tt.hasDetection, tt.campaigns)
			if got != tt.want {
				t.Errorf("CoverageFromExpect(%v, %v, %d) = %s, want %s",
					tt.hasTelemetry, tt.hasDetection, tt.campaigns, got, tt.want)
			}
		})
	}
}

func TestRenderCompact_NoColor(t *testing.T) {
	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")

	m := BuildMatrix() // empty matrix
	var buf bytes.Buffer
	RenderCompact(&buf, m)

	output := buf.String()

	// Should contain the header.
	if !strings.Contains(output, "ATT&CK Tactic Coverage") {
		t.Error("missing header in compact output")
	}

	// Should contain all 14 tactic names.
	tacticNames := []string{
		"Reconnaissance", "Initial Access", "Execution", "Persistence",
		"Discovery", "Collection", "Exfiltration", "Impact",
	}
	for _, name := range tacticNames {
		if !strings.Contains(output, name) {
			t.Errorf("missing tactic name %q in compact output", name)
		}
	}

	// Should show 0/ ratios since nothing is exercised.
	if !strings.Contains(output, "0/") {
		t.Error("expected 0/ ratios in compact output for empty matrix")
	}

	// No ANSI codes should be present.
	if strings.Contains(output, "[") {
		t.Error("ANSI codes found in NO_COLOR output")
	}
}

func TestRender_NoColor(t *testing.T) {
	os.Setenv("NO_COLOR", "1")
	defer os.Unsetenv("NO_COLOR")

	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "test"},
		Stages: []campaign.Stage{
			{
				ID:        "s1",
				Technique: "T1566.001",
				Tactic:    "initial-access",
				Execute:   campaign.Execute{Type: "shell"},
				Expect: campaign.Expect{
					Telemetry:  []string{"file_create"},
					Detections: []string{"phish_detected"},
				},
			},
		},
	}
	result := &engine.RunResult{
		Campaign:  c,
		Mode:      "simulate",
		Completed: 1,
		Stages:    []engine.StageResult{{Stage: c.Stages[0], Order: 1}},
	}

	m := BuildMatrix(result)
	var buf bytes.Buffer
	Render(&buf, m)

	output := buf.String()
	if !strings.Contains(output, "MITRE ATT&CK Coverage Matrix") {
		t.Error("missing matrix header in full render")
	}
	if !strings.Contains(output, "T1566.001") {
		t.Error("T1566.001 not rendered in matrix")
	}
	if !strings.Contains(output, "Legend:") {
		t.Error("missing legend in full render")
	}
	if strings.Contains(output, "[") {
		t.Error("ANSI codes found in NO_COLOR output")
	}
}

func TestBuildFromGapReport(t *testing.T) {
	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "test"},
		Stages: []campaign.Stage{
			{
				ID:        "s1",
				Technique: "T1566.001",
				Tactic:    "initial-access",
				Execute:   campaign.Execute{Type: "shell"},
				Expect: campaign.Expect{
					Telemetry:  []string{"file_create"},
					Detections: []string{"phish_detected"},
				},
			},
			{
				ID:        "s2",
				Technique: "T1059.001",
				Tactic:    "execution",
				Execute:   campaign.Execute{Type: "shell"},
				Expect: campaign.Expect{
					Telemetry: []string{"process_create"},
					// No detections — gap!
				},
			},
		},
	}
	result := &engine.RunResult{
		Campaign:  c,
		Mode:      "simulate",
		Completed: 2,
		Stages: []engine.StageResult{
			{Stage: c.Stages[0], Order: 1},
			{Stage: c.Stages[1], Order: 2},
		},
	}

	gapReport := &gap.GapReport{
		Gaps: []gap.Gap{
			{
				CampaignName: "test",
				StageID:      "s2",
				Technique:    "T1059.001",
				Tactic:       "execution",
				Type:         gap.GapDetectionMissing,
			},
		},
	}

	m := BuildFromGapReport(gapReport, result)

	// T1059.001 should still be Partial (telemetry only, gap strips detection).
	var exCol *TacticColumn
	for i := range m.Tactics {
		if m.Tactics[i].Short == "execution" {
			exCol = &m.Tactics[i]
			break
		}
	}
	if exCol == nil {
		t.Fatal("missing execution column")
	}

	for _, tc := range exCol.Techniques {
		if tc.ID == "T1059.001" {
			if tc.Coverage != Partial {
				t.Errorf("T1059.001 with detection gap: expected Partial, got %s", tc.Coverage)
			}
		}
	}
}

func TestStageHasCoverage(t *testing.T) {
	tests := []struct {
		name  string
		stage campaign.Stage
		want  CoverageLevel
	}{
		{
			name: "no expect",
			stage: campaign.Stage{
				ID: "s1", Technique: "T1566", Tactic: "initial-access",
			},
			want: Uncovered,
		},
		{
			name: "telemetry only",
			stage: campaign.Stage{
				ID: "s2", Technique: "T1059",
				Expect: campaign.Expect{Telemetry: []string{"process_create"}},
			},
			want: Partial,
		},
		{
			name: "both",
			stage: campaign.Stage{
				ID: "s3", Technique: "T1566",
				Expect: campaign.Expect{
					Telemetry:  []string{"file_create"},
					Detections: []string{"det"},
				},
			},
			want: Detected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StageHasCoverage(tt.stage)
			if got != tt.want {
				t.Errorf("StageHasCoverage = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCoverageLevelString(t *testing.T) {
	tests := []struct {
		level CoverageLevel
		want  string
	}{
		{Uncovered, "uncovered"},
		{Partial, "partial"},
		{Detected, "detected"},
		{Full, "full"},
		{CoverageLevel(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.level.String()
		if got != tt.want {
			t.Errorf("CoverageLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestRender_Empty(t *testing.T) {
	m := &Matrix{}
	var buf bytes.Buffer
	Render(&buf, m)
	if !strings.Contains(buf.String(), "No ATT&CK data") {
		t.Error("expected 'No ATT&CK data' for empty matrix")
	}
}

func TestSkippedStagesExcluded(t *testing.T) {
	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "test"},
		Stages: []campaign.Stage{
			{
				ID:        "s1",
				Technique: "T1566.001",
				Tactic:    "initial-access",
				Execute:   campaign.Execute{Type: "shell"},
				Expect: campaign.Expect{
					Telemetry:  []string{"file_create"},
					Detections: []string{"det"},
				},
			},
		},
	}
	result := &engine.RunResult{
		Campaign: c,
		Mode:     "simulate",
		Skipped:  1,
		Stages: []engine.StageResult{
			{Stage: c.Stages[0], Order: 1, Skipped: true, SkipMsg: "platform"},
		},
	}

	m := BuildMatrix(result)

	// T1566.001 should be Uncovered since the stage was skipped.
	for _, col := range m.Tactics {
		for _, tc := range col.Techniques {
			if tc.ID == "T1566.001" {
				if tc.Coverage != Uncovered {
					t.Errorf("skipped stage T1566.001: expected Uncovered, got %s", tc.Coverage)
				}
			}
		}
	}
}
