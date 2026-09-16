// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package gap

import (
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/executor"
)

// --- helpers ---

func makeResult(c *campaign.Campaign, stages []engine.StageResult) *engine.RunResult {
	completed, skipped := 0, 0
	for _, sr := range stages {
		if sr.Skipped {
			skipped++
		} else {
			completed++
		}
	}
	return &engine.RunResult{
		Campaign:  c,
		Mode:      "simulate",
		Stages:    stages,
		Completed: completed,
		Skipped:   skipped,
	}
}

func simpleStageResult(s campaign.Stage, order int) engine.StageResult {
	return engine.StageResult{
		Stage: s,
		Order: order,
		Exec:  executor.Result{StageID: s.ID, Success: true},
	}
}

func attackCampaign() (*campaign.Campaign, *engine.RunResult) {
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "test-attack",
			Adversary: "TestActor",
			Severity:  "high",
		},
		Stages: []campaign.Stage{
			{
				ID: "recon", Name: "Recon", Technique: "T1016", Tactic: "discovery",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"process_create"}, Detections: []string{"recon_detected"}},
			},
			{
				ID: "access", Name: "Access", Technique: "T1190", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"network_connection"}, Detections: []string{"exploit_detected"}},
			},
		},
	}
	stages := []engine.StageResult{
		simpleStageResult(c.Stages[0], 1),
		simpleStageResult(c.Stages[1], 2),
	}
	return c, makeResult(c, stages)
}

func atlasCampaign() (*campaign.Campaign, *engine.RunResult) {
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "test-atlas",
			Adversary: "AgentAttacker",
			Severity:  "critical",
		},
		Stages: []campaign.Stage{
			{
				ID: "inject", Name: "Prompt Injection", Technique: "AML.T0051", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"prompt_log"}, Detections: []string{"prompt_injection_detected"}},
			},
			{
				ID: "jailbreak", Name: "Jailbreak", Technique: "AML.T0054", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"guardrail_trigger"}},
				// NO detections — this is a gap
			},
			{
				ID: "c2", Name: "C2 via Agent", Technique: "AML.T0050", Tactic: "impact",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"tool_call"}, Detections: []string{"agent_c2_detected"}},
			},
		},
	}
	stages := []engine.StageResult{
		simpleStageResult(c.Stages[0], 1),
		simpleStageResult(c.Stages[1], 2),
		simpleStageResult(c.Stages[2], 3),
	}
	return c, makeResult(c, stages)
}

// --- tests ---

func TestAnalyze_SingleCampaign_DetectionGaps(t *testing.T) {
	// Campaign where one stage has telemetry but no detections.
	c := &campaign.Campaign{
		APIVersion: "v1", Kind: "Campaign",
		Meta: campaign.Meta{Name: "gap-test", Adversary: "X", Severity: "medium"},
		Stages: []campaign.Stage{
			{
				ID: "s1", Name: "Stage 1", Technique: "T1566.001", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"file_create"}, Detections: []string{"rule_1"}},
			},
			{
				ID: "s2", Name: "Stage 2", Technique: "T1059.001", Tactic: "execution",
				Execute: campaign.Execute{Type: "shell"},
				Expect: campaign.Expect{
					Telemetry: []string{"process_create", "script_execution"},
					// No detections — gap!
				},
			},
		},
	}
	stages := []engine.StageResult{
		simpleStageResult(c.Stages[0], 1),
		simpleStageResult(c.Stages[1], 2),
	}
	r := makeResult(c, stages)

	report := Analyze(r)

	// Should find exactly one detection gap.
	detGaps := filterGaps(report.Gaps, GapDetectionMissing)
	if len(detGaps) != 1 {
		t.Fatalf("expected 1 detection gap, got %d", len(detGaps))
	}
	g := detGaps[0]
	if g.StageID != "s2" {
		t.Errorf("gap stage = %q, want %q", g.StageID, "s2")
	}
	if g.CampaignName != "gap-test" {
		t.Errorf("gap campaign = %q, want %q", g.CampaignName, "gap-test")
	}
	// Execution is a critical tactic, so detection gap → high.
	if g.Risk != "high" {
		t.Errorf("gap risk = %q, want %q", g.Risk, "high")
	}
}

func TestAnalyze_SingleCampaign_TelemetryGaps(t *testing.T) {
	c := &campaign.Campaign{
		APIVersion: "v1", Kind: "Campaign",
		Meta: campaign.Meta{Name: "telem-test", Adversary: "Y", Severity: "low"},
		Stages: []campaign.Stage{
			{
				ID: "s1", Name: "Stage 1", Technique: "T1566", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				// No telemetry AND no detections.
			},
			{
				ID: "s2", Name: "Stage 2", Technique: "T1082", Tactic: "discovery",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"process_create"}, Detections: []string{"d1"}},
			},
		},
	}
	stages := []engine.StageResult{
		simpleStageResult(c.Stages[0], 1),
		simpleStageResult(c.Stages[1], 2),
	}
	r := makeResult(c, stages)

	report := Analyze(r)

	telGaps := filterGaps(report.Gaps, GapTelemetryMissing)
	if len(telGaps) != 1 {
		t.Fatalf("expected 1 telemetry gap, got %d", len(telGaps))
	}
	if telGaps[0].StageID != "s1" {
		t.Errorf("gap stage = %q, want %q", telGaps[0].StageID, "s1")
	}
	if telGaps[0].Risk != "medium" {
		t.Errorf("telemetry gap risk = %q, want %q", telGaps[0].Risk, "medium")
	}
}

func TestAnalyze_TacticCoverage(t *testing.T) {
	_, attackR := attackCampaign()
	_, atlasR := atlasCampaign()

	report := Analyze(attackR, atlasR)
	agg := report.Aggregate

	// ATT&CK: should cover discovery + initial-access = 2/14.
	if agg.AttackTactics.Covered != 2 {
		t.Errorf("ATT&CK covered = %d, want 2", agg.AttackTactics.Covered)
	}
	if agg.AttackTactics.Total != 14 {
		t.Errorf("ATT&CK total = %d, want 14", agg.AttackTactics.Total)
	}
	if len(agg.AttackTactics.Missing) != 12 {
		t.Errorf("ATT&CK missing = %d, want 12", len(agg.AttackTactics.Missing))
	}

	// ATLAS: should cover initial-access + impact = 2/7.
	if agg.AtlasTactics.Covered != 2 {
		t.Errorf("ATLAS covered = %d, want 2", agg.AtlasTactics.Covered)
	}
	if agg.AtlasTactics.Total != 7 {
		t.Errorf("ATLAS total = %d, want 7", agg.AtlasTactics.Total)
	}
}

func TestAnalyze_MultiCampaign_Aggregate(t *testing.T) {
	_, r1 := attackCampaign()
	_, r2 := atlasCampaign()

	report := Analyze(r1, r2)
	agg := report.Aggregate

	if agg.TotalCampaigns != 2 {
		t.Errorf("total campaigns = %d, want 2", agg.TotalCampaigns)
	}
	if agg.TotalStages != 5 {
		t.Errorf("total stages = %d, want 5", agg.TotalStages)
	}
	if agg.TotalCompleted != 5 {
		t.Errorf("total completed = %d, want 5", agg.TotalCompleted)
	}
	// Unique techniques: T1016, T1190, AML.T0051, AML.T0054, AML.T0050 = 5.
	if agg.UniqueTechniques != 5 {
		t.Errorf("unique techniques = %d, want 5", agg.UniqueTechniques)
	}
	// ATT&CK: 2 stages, ATLAS: 3 stages.
	if agg.Framework.ATTACKStages != 2 {
		t.Errorf("ATT&CK stages = %d, want 2", agg.Framework.ATTACKStages)
	}
	if agg.Framework.ATLASStages != 3 {
		t.Errorf("ATLAS stages = %d, want 3", agg.Framework.ATLASStages)
	}
}

func TestAnalyze_FrameworkBreakdown(t *testing.T) {
	// Mixed campaign with ATT&CK, ATLAS, and OWASP stages.
	c := &campaign.Campaign{
		APIVersion: "v1", Kind: "Campaign",
		Meta: campaign.Meta{Name: "mixed", Adversary: "Multi", Severity: "high"},
		Stages: []campaign.Stage{
			{ID: "s1", Name: "ATT&CK Stage", Technique: "T1566", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"a"}, Detections: []string{"d"}}},
			{ID: "s2", Name: "ATLAS Stage", Technique: "AML.T0051", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"a"}, Detections: []string{"d"}}},
			{ID: "s3", Name: "OWASP Stage", Technique: "LLM01", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"a"}, Detections: []string{"d"}}},
			{ID: "s4", Name: "Another ATT&CK", Technique: "T1059", Tactic: "execution",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"a"}, Detections: []string{"d"}}},
		},
	}
	stages := make([]engine.StageResult, len(c.Stages))
	for i, s := range c.Stages {
		stages[i] = simpleStageResult(s, i+1)
	}
	r := makeResult(c, stages)

	report := Analyze(r)
	fw := report.Campaigns[0].Framework

	if fw.ATTACKStages != 2 {
		t.Errorf("ATT&CK = %d, want 2", fw.ATTACKStages)
	}
	if fw.ATLASStages != 1 {
		t.Errorf("ATLAS = %d, want 1", fw.ATLASStages)
	}
	if fw.OWASPStages != 1 {
		t.Errorf("OWASP = %d, want 1", fw.OWASPStages)
	}
}

func TestAnalyze_RiskScoring(t *testing.T) {
	// Campaign with known gaps to test risk assignment.
	c := &campaign.Campaign{
		APIVersion: "v1", Kind: "Campaign",
		Meta: campaign.Meta{Name: "risk-test", Adversary: "Risk", Severity: "high"},
		Stages: []campaign.Stage{
			{
				// Detection gap in a critical tactic → high risk.
				ID: "s1", Name: "Exec Gap", Technique: "T1059", Tactic: "execution",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"process_create"}}, // no detections
			},
			{
				// Detection gap in a non-critical tactic → medium risk.
				ID: "s2", Name: "Discovery Gap", Technique: "T1082", Tactic: "discovery",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"process_create"}}, // no detections
			},
			{
				// Telemetry gap → always medium.
				ID: "s3", Name: "No Telemetry", Technique: "T1566", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				// No expect at all.
			},
		},
	}
	stages := make([]engine.StageResult, len(c.Stages))
	for i, s := range c.Stages {
		stages[i] = simpleStageResult(s, i+1)
	}
	r := makeResult(c, stages)

	report := Analyze(r)

	// Per-stage gaps: s1 detection=high, s2 detection=medium, s3 telemetry=medium.
	stageGaps := filterGaps(report.Gaps, GapDetectionMissing)
	stageGaps = append(stageGaps, filterGaps(report.Gaps, GapTelemetryMissing)...)

	highCount := 0
	medCount := 0
	for _, g := range stageGaps {
		switch g.Risk {
		case "high":
			highCount++
		case "medium":
			medCount++
		}
	}
	if highCount < 1 {
		t.Errorf("expected at least 1 high-risk gap, got %d", highCount)
	}
	if medCount < 2 {
		t.Errorf("expected at least 2 medium-risk gaps, got %d", medCount)
	}

	// Risk summary score should be > 0.
	if report.RiskSummary.Score <= 0 {
		t.Errorf("risk score = %f, expected > 0", report.RiskSummary.Score)
	}
	if report.RiskSummary.Total == 0 {
		t.Error("risk total should not be 0")
	}
}

func TestClassifyTechnique(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"T1566", "attack"},
		{"T1566.001", "attack"},
		{"T1059", "attack"},
		{"AML.T0051", "atlas"},
		{"AML.T0054", "atlas"},
		{"LLM01", "owasp"},
		{"LLM10", "owasp"},
		{"UNKNOWN", "unknown"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := ClassifyTechnique(tt.id)
			if got != tt.want {
				t.Errorf("ClassifyTechnique(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestResolveTechniqueName(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"T1566.001", "Spearphishing Attachment"},
		{"T1059.001", "PowerShell"},
		{"AML.T0051", "LLM Prompt Injection"},
		{"AML.T0054", "LLM Jailbreaking"},
		{"LLM01", "Prompt Injection"},
		{"LLM06", "Excessive Agency"},
		// Unknown falls back to the ID.
		{"T9999", "T9999"},
		{"AML.T9999", "AML.T9999"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := ResolveTechniqueName(tt.id)
			if got != tt.want {
				t.Errorf("ResolveTechniqueName(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

// --- test helpers ---

func filterGaps(gaps []Gap, typ GapType) []Gap {
	var out []Gap
	for _, g := range gaps {
		if g.Type == typ {
			out = append(out, g)
		}
	}
	return out
}
