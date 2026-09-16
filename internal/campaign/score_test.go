// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper to build a minimal campaign for scoring tests.
func scoreCampaign(name, severity string, stages []Stage) *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:     name,
			Severity: severity,
		},
		Stages: stages,
	}
}

// --- ScoreCampaign basic tests ---

func TestScoreCampaign_Nil(t *testing.T) {
	result := ScoreCampaign(nil)
	if result != nil {
		t.Errorf("ScoreCampaign(nil) should return nil, got %+v", result)
	}
}

func TestScoreCampaign_EmptyCampaign(t *testing.T) {
	c := scoreCampaign("empty", "low", nil)
	sc := ScoreCampaign(c)
	if sc == nil {
		t.Fatal("ScoreCampaign returned nil for empty campaign")
	}
	if sc.CampaignName != "empty" {
		t.Errorf("expected name 'empty', got %q", sc.CampaignName)
	}
	if sc.StageCount != 0 {
		t.Errorf("expected 0 stages, got %d", sc.StageCount)
	}
	// Empty campaign should still have DetectionDifficulty = 100 (starts at max).
	if sc.Score.DetectionDifficulty != 100 {
		t.Errorf("expected detection difficulty 100 for empty campaign, got %.1f", sc.Score.DetectionDifficulty)
	}
	if sc.Score.TechniqueComplexity != 0 {
		t.Errorf("expected technique complexity 0 for empty campaign, got %.1f", sc.Score.TechniqueComplexity)
	}
}

func TestScoreCampaign_SingleStage(t *testing.T) {
	c := scoreCampaign("simple", "medium", []Stage{
		{
			ID:        "s1",
			Technique: "T1059.001",
			Tactic:    "execution",
			Execute:   Execute{Type: "shell", Commands: []string{"whoami"}},
		},
	})
	sc := ScoreCampaign(c)
	if sc == nil {
		t.Fatal("ScoreCampaign returned nil")
	}
	// 1 technique = 10 pts; has sub-technique = +15 = 25
	if sc.Score.TechniqueComplexity != 25 {
		t.Errorf("expected technique complexity 25, got %.1f", sc.Score.TechniqueComplexity)
	}
	// 1 tactic / 14 * 100 ~= 7.14
	expectedBreadth := (1.0 / 14.0) * 100.0
	if math.Abs(sc.Score.TacticBreadth-expectedBreadth) > 0.01 {
		t.Errorf("expected tactic breadth ~%.2f, got %.2f", expectedBreadth, sc.Score.TacticBreadth)
	}
}

// --- TechniqueComplexity dimension ---

func TestScore_TechniqueComplexity_Base(t *testing.T) {
	// 3 unique techniques -> 30 pts base.
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s2", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1082", Tactic: "discovery", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	// 3 techniques * 10 = 30, no sub-techniques, no cred/priv/lateral
	if sc.Score.TechniqueComplexity != 30 {
		t.Errorf("expected 30, got %.1f", sc.Score.TechniqueComplexity)
	}
}

func TestScore_TechniqueComplexity_CapAt50(t *testing.T) {
	// 6 unique techniques -> 60 pts base, but cap at 50.
	stages := []Stage{
		{ID: "s1", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s2", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1082", Tactic: "discovery", Execute: Execute{Type: "shell"}},
		{ID: "s4", Technique: "T1018", Tactic: "discovery", Execute: Execute{Type: "shell"}},
		{ID: "s5", Technique: "T1087", Tactic: "discovery", Execute: Execute{Type: "shell"}},
		{ID: "s6", Technique: "T1049", Tactic: "discovery", Execute: Execute{Type: "shell"}},
	}
	c := scoreCampaign("test", "low", stages)
	sc := ScoreCampaign(c)
	// 6*10=60 capped to 50, no sub-techniques, no cred/priv/lateral
	if sc.Score.TechniqueComplexity != 50 {
		t.Errorf("expected 50 (capped), got %.1f", sc.Score.TechniqueComplexity)
	}
}

func TestScore_TechniqueComplexity_SubTechniques(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	// 1 tech = 10, sub-technique = +15 = 25
	if sc.Score.TechniqueComplexity != 25 {
		t.Errorf("expected 25, got %.1f", sc.Score.TechniqueComplexity)
	}
}

func TestScore_TechniqueComplexity_CredentialAccess(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1003", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1110", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	// 2 tech * 10 = 20 (base) + 2 cred-access * 10 = 20 = total 40
	if sc.Score.TechniqueComplexity != 40 {
		t.Errorf("expected 40, got %.1f", sc.Score.TechniqueComplexity)
	}
}

func TestScore_TechniqueComplexity_LateralMovement(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1021", Tactic: "lateral-movement", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	// 1 tech * 10 = 10 (base) + 1 lateral * 5 = 5 = total 15
	if sc.Score.TechniqueComplexity != 15 {
		t.Errorf("expected 15, got %.1f", sc.Score.TechniqueComplexity)
	}
}

func TestScore_TechniqueComplexity_Capped100(t *testing.T) {
	// Build a campaign that would exceed 100 without capping.
	// 5 techniques (cap at 50) + sub-tech (15) + 3 cred (30) + 2 priv (20) + 1 lateral (5) = 120 -> 100.
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1110", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1552", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
		{ID: "s4", Technique: "T1055", Tactic: "privilege-escalation", Execute: Execute{Type: "shell"}},
		{ID: "s5", Technique: "T1068", Tactic: "privilege-escalation", Execute: Execute{Type: "shell"}},
		{ID: "s6", Technique: "T1021", Tactic: "lateral-movement", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	if sc.Score.TechniqueComplexity != 100 {
		t.Errorf("expected 100 (capped), got %.1f", sc.Score.TechniqueComplexity)
	}
}

// --- TacticBreadth dimension ---

func TestScore_TacticBreadth_Single(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	expected := (1.0 / 14.0) * 100.0
	if math.Abs(sc.Score.TacticBreadth-expected) > 0.01 {
		t.Errorf("expected ~%.2f, got %.2f", expected, sc.Score.TacticBreadth)
	}
}

func TestScore_TacticBreadth_FullKillChain(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s2", Technique: "T1041", Tactic: "exfiltration", Execute: Execute{Type: "http"}},
	})
	sc := ScoreCampaign(c)
	// 2/14 * 100 + 10 bonus
	expected := (2.0/14.0)*100.0 + 10.0
	if math.Abs(sc.Score.TacticBreadth-expected) > 0.01 {
		t.Errorf("expected ~%.2f, got %.2f", expected, sc.Score.TacticBreadth)
	}
}

func TestScore_TacticBreadth_Capped100(t *testing.T) {
	// 14 tactics covers all -> 100.0, plus bonus 10 if initial-access + exfiltration = 110 -> capped to 100.
	tactics := []string{
		"reconnaissance", "resource-development", "initial-access", "execution",
		"persistence", "privilege-escalation", "defense-evasion", "credential-access",
		"discovery", "lateral-movement", "collection", "command-and-control",
		"exfiltration", "impact",
	}
	var stages []Stage
	for i, tac := range tactics {
		stages = append(stages, Stage{
			ID:        fmt.Sprintf("s%d", i+1),
			Technique: "T1059",
			Tactic:    tac,
			Execute:   Execute{Type: "shell"},
		})
	}
	c := scoreCampaign("full-coverage", "critical", stages)
	sc := ScoreCampaign(c)
	if sc.Score.TacticBreadth != 100 {
		t.Errorf("expected 100 (capped), got %.1f", sc.Score.TacticBreadth)
	}
}

// --- DetectionDifficulty dimension ---

func TestScore_DetectionDifficulty_NoDefenses(t *testing.T) {
	// No detections, no telemetry, no cleanup, no defense-evasion -> 100.
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	if sc.Score.DetectionDifficulty != 100 {
		t.Errorf("expected 100, got %.1f", sc.Score.DetectionDifficulty)
	}
}

func TestScore_DetectionDifficulty_WithDetections(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"rule1"}}},
	})
	sc := ScoreCampaign(c)
	// 100 - 30 (has detections) = 70
	if sc.Score.DetectionDifficulty != 70 {
		t.Errorf("expected 70, got %.1f", sc.Score.DetectionDifficulty)
	}
}

func TestScore_DetectionDifficulty_WithTelemetry(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"},
			Expect: Expect{Telemetry: []string{"process_create"}}},
	})
	sc := ScoreCampaign(c)
	// 100 - 20 (has telemetry) = 80
	if sc.Score.DetectionDifficulty != 80 {
		t.Errorf("expected 80, got %.1f", sc.Score.DetectionDifficulty)
	}
}

func TestScore_DetectionDifficulty_WithCleanup(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution",
			Execute: Execute{Type: "shell", Cleanup: []string{"rm -f /tmp/x"}}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access",
			Execute: Execute{Type: "http", Cleanup: []string{"curl -X DELETE"}}},
	})
	sc := ScoreCampaign(c)
	// 100 - 10*2 (cleanup) = 80
	if sc.Score.DetectionDifficulty != 80 {
		t.Errorf("expected 80, got %.1f", sc.Score.DetectionDifficulty)
	}
}

func TestScore_DetectionDifficulty_DefenseEvasion(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1070", Tactic: "defense-evasion", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	// 100 + 15 (defense-evasion) = 115 -> capped at 100
	if sc.Score.DetectionDifficulty != 100 {
		t.Errorf("expected 100 (capped), got %.1f", sc.Score.DetectionDifficulty)
	}
}

func TestScore_DetectionDifficulty_Combined(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1070", Tactic: "defense-evasion",
			Execute: Execute{Type: "shell", Cleanup: []string{"rm evidence"}},
			Expect:  Expect{Detections: []string{"rule1"}, Telemetry: []string{"file_delete"}}},
	})
	sc := ScoreCampaign(c)
	// 100 - 30 (detections) - 20 (telemetry) - 10 (1 cleanup) + 15 (defense-evasion) = 55
	if sc.Score.DetectionDifficulty != 55 {
		t.Errorf("expected 55, got %.1f", sc.Score.DetectionDifficulty)
	}
}

// --- ExecutionComplexity dimension ---

func TestScore_ExecutionComplexity_Elevated(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution",
			Execute: Execute{Type: "shell", Elevated: true}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access",
			Execute: Execute{Type: "shell", Elevated: true}},
	})
	sc := ScoreCampaign(c)
	// 2 elevated * 15 = 30
	if sc.Score.ExecutionComplexity != 30 {
		t.Errorf("expected 30, got %.1f", sc.Score.ExecutionComplexity)
	}
}

func TestScore_ExecutionComplexity_Dependencies(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", DependsOn: []string{"s1"},
			Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	// +20 for dependencies
	if sc.Score.ExecutionComplexity != 20 {
		t.Errorf("expected 20, got %.1f", sc.Score.ExecutionComplexity)
	}
}

func TestScore_ExecutionComplexity_MultipleExecTypes(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s3", Technique: "T1112", Tactic: "defense-evasion", Execute: Execute{Type: "registry"}},
	})
	sc := ScoreCampaign(c)
	// 2 extra exec types * 10 = 20, http present = +15 = 35
	if sc.Score.ExecutionComplexity != 35 {
		t.Errorf("expected 35, got %.1f", sc.Score.ExecutionComplexity)
	}
}

func TestScore_ExecutionComplexity_HTTP(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
	})
	sc := ScoreCampaign(c)
	// 0 extra types + 15 for http = 15
	if sc.Score.ExecutionComplexity != 15 {
		t.Errorf("expected 15, got %.1f", sc.Score.ExecutionComplexity)
	}
}

func TestScore_ExecutionComplexity_Capped100(t *testing.T) {
	// Build scenario exceeding 100: 5 elevated (75) + deps (20) + 2 extra types (20) + http (15) = 130
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell", Elevated: true}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http", Elevated: true}, DependsOn: []string{"s1"}},
		{ID: "s3", Technique: "T1112", Tactic: "defense-evasion", Execute: Execute{Type: "registry", Elevated: true}},
		{ID: "s4", Technique: "T1055", Tactic: "privilege-escalation", Execute: Execute{Type: "shell", Elevated: true}},
		{ID: "s5", Technique: "T1003", Tactic: "credential-access", Execute: Execute{Type: "shell", Elevated: true}},
	})
	sc := ScoreCampaign(c)
	if sc.Score.ExecutionComplexity != 100 {
		t.Errorf("expected 100 (capped), got %.1f", sc.Score.ExecutionComplexity)
	}
}

// --- EvasionSophistication dimension ---

func TestScore_EvasionSophistication_DefenseEvasion(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1070", Tactic: "defense-evasion", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1027", Tactic: "defense-evasion", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	// 2 defense-evasion techs * 20 = 40
	if sc.Score.EvasionSophistication != 40 {
		t.Errorf("expected 40, got %.1f", sc.Score.EvasionSophistication)
	}
}

func TestScore_EvasionSophistication_PrivEsc(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1055", Tactic: "privilege-escalation", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	// 1 priv-esc * 15 = 15
	if sc.Score.EvasionSophistication != 15 {
		t.Errorf("expected 15, got %.1f", sc.Score.EvasionSophistication)
	}
}

func TestScore_EvasionSophistication_Cleanup(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution",
			Execute: Execute{Type: "shell", Cleanup: []string{"rm evidence"}}},
	})
	sc := ScoreCampaign(c)
	// +10 for cleanup
	if sc.Score.EvasionSophistication != 10 {
		t.Errorf("expected 10, got %.1f", sc.Score.EvasionSophistication)
	}
}

func TestScore_EvasionSophistication_Persistence(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1053", Tactic: "persistence", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	// +10 for persistence
	if sc.Score.EvasionSophistication != 10 {
		t.Errorf("expected 10, got %.1f", sc.Score.EvasionSophistication)
	}
}

func TestScore_EvasionSophistication_Capped100(t *testing.T) {
	// 4 defense-evasion (80) + 2 priv-esc (30) + cleanup (10) + persistence (10) = 130 -> 100
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1070", Tactic: "defense-evasion", Execute: Execute{Type: "shell", Cleanup: []string{"c"}}},
		{ID: "s2", Technique: "T1027", Tactic: "defense-evasion", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1036", Tactic: "defense-evasion", Execute: Execute{Type: "shell"}},
		{ID: "s4", Technique: "T1140", Tactic: "defense-evasion", Execute: Execute{Type: "shell"}},
		{ID: "s5", Technique: "T1055", Tactic: "privilege-escalation", Execute: Execute{Type: "shell"}},
		{ID: "s6", Technique: "T1068", Tactic: "privilege-escalation", Execute: Execute{Type: "shell"}},
		{ID: "s7", Technique: "T1053", Tactic: "persistence", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	if sc.Score.EvasionSophistication != 100 {
		t.Errorf("expected 100 (capped), got %.1f", sc.Score.EvasionSophistication)
	}
}

// --- Grade boundaries ---

func TestGradeFromScore(t *testing.T) {
	tests := []struct {
		score float64
		grade string
	}{
		{100, "A"},
		{80, "A"},
		{79.9, "B"},
		{60, "B"},
		{59.9, "C"},
		{40, "C"},
		{39.9, "D"},
		{20, "D"},
		{19.9, "F"},
		{0, "F"},
	}
	for _, tt := range tests {
		got := gradeFromScore(tt.score)
		if got != tt.grade {
			t.Errorf("gradeFromScore(%.1f) = %q, want %q", tt.score, got, tt.grade)
		}
	}
}

// --- Overall score ---

func TestScore_OverallWeightedAverage(t *testing.T) {
	// Build a campaign with known dimension scores and verify the weighted average.
	c := scoreCampaign("test", "high", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution",
			Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)

	// Manually compute expected overall.
	expected := sc.Score.TechniqueComplexity*0.25 +
		sc.Score.TacticBreadth*0.20 +
		sc.Score.DetectionDifficulty*0.25 +
		sc.Score.ExecutionComplexity*0.15 +
		sc.Score.EvasionSophistication*0.15
	expected = math.Round(expected*10) / 10

	if math.Abs(sc.Score.OverallScore-expected) > 0.01 {
		t.Errorf("expected overall %.1f, got %.1f", expected, sc.Score.OverallScore)
	}
}

// --- Factors ---

func TestScoreCampaign_FactorsPopulated(t *testing.T) {
	c := scoreCampaign("test", "high", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution",
			Execute: Execute{Type: "shell", Elevated: true, Cleanup: []string{"rm -f x"}},
			Expect:  Expect{Detections: []string{"rule1"}}},
	})
	sc := ScoreCampaign(c)
	if len(sc.Factors) == 0 {
		t.Error("expected factors to be populated")
	}
	// Verify at least one factor per dimension that contributes.
	dims := make(map[string]bool)
	for _, f := range sc.Factors {
		dims[f.Dimension] = true
	}
	expectedDims := []string{"TechniqueComplexity", "TacticBreadth", "DetectionDifficulty", "ExecutionComplexity", "EvasionSophistication"}
	for _, d := range expectedDims {
		if !dims[d] {
			t.Errorf("expected factor for dimension %q", d)
		}
	}
}

// --- High-severity campaign (complex, multi-tactic) ---

func TestScoreCampaign_HighSeverity(t *testing.T) {
	c := scoreCampaign("apt-complex", "critical", []Stage{
		{ID: "s1", Technique: "T1566.001", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s2", Technique: "T1059.001", Tactic: "execution", DependsOn: []string{"s1"}, Execute: Execute{Type: "shell", Elevated: true}},
		{ID: "s3", Technique: "T1055", Tactic: "privilege-escalation", DependsOn: []string{"s2"}, Execute: Execute{Type: "shell", Elevated: true}},
		{ID: "s4", Technique: "T1003.001", Tactic: "credential-access", DependsOn: []string{"s3"}, Execute: Execute{Type: "shell", Elevated: true}},
		{ID: "s5", Technique: "T1070.001", Tactic: "defense-evasion", Execute: Execute{Type: "shell", Cleanup: []string{"clear logs"}}},
		{ID: "s6", Technique: "T1021.002", Tactic: "lateral-movement", DependsOn: []string{"s4"}, Execute: Execute{Type: "shell"}},
		{ID: "s7", Technique: "T1041", Tactic: "exfiltration", DependsOn: []string{"s6"}, Execute: Execute{Type: "http"}},
		{ID: "s8", Technique: "T1053.005", Tactic: "persistence", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)

	if sc.Score.Grade != "A" && sc.Score.Grade != "B" {
		t.Errorf("expected high-severity campaign to get A or B grade, got %s (score=%.1f)", sc.Score.Grade, sc.Score.OverallScore)
	}
	if sc.Score.OverallScore < 50 {
		t.Errorf("expected high-severity campaign score > 50, got %.1f", sc.Score.OverallScore)
	}
	if sc.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", sc.Severity)
	}
}

// --- FormatScores ---

func TestFormatScores_Empty(t *testing.T) {
	output := FormatScores(nil)
	if output != "" {
		t.Errorf("FormatScores(nil) should return empty string, got %q", output)
	}
	output = FormatScores([]*ScoredCampaign{})
	if output != "" {
		t.Errorf("FormatScores([]) should return empty string, got %q", output)
	}
}

func TestFormatScores_Output(t *testing.T) {
	c := scoreCampaign("test-campaign", "high", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
	})
	sc := ScoreCampaign(c)
	output := FormatScores([]*ScoredCampaign{sc})

	checks := []string{
		"ThreatEcho Campaign Risk Scores",
		"test-campaign",
		"Score:",
		"Grade:",
		"Technique",
		"Tactic",
		"Detection",
		"Execution",
		"Evasion",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("FormatScores output missing %q", check)
		}
	}
}

// --- FormatScoreDetail ---

func TestFormatScoreDetail_Nil(t *testing.T) {
	output := FormatScoreDetail(nil)
	if output != "" {
		t.Errorf("FormatScoreDetail(nil) should return empty string, got %q", output)
	}
}

func TestFormatScoreDetail_Output(t *testing.T) {
	c := scoreCampaign("detailed-test", "medium", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution",
			Execute: Execute{Type: "shell", Elevated: true},
			Expect:  Expect{Detections: []string{"r1"}}},
	})
	sc := ScoreCampaign(c)
	output := FormatScoreDetail(sc)

	checks := []string{
		"Score Detail: detailed-test",
		"Overall Score:",
		"TechniqueComplexity",
		"TacticBreadth",
		"DetectionDifficulty",
		"ExecutionComplexity",
		"EvasionSophistication",
		"weight:",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("FormatScoreDetail output missing %q", check)
		}
	}
}

// --- ScoreDir ---

func TestScoreDir_TempDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create a campaign subdirectory.
	campDir := filepath.Join(dir, "test-campaign")
	if err := os.MkdirAll(campDir, 0o755); err != nil {
		t.Fatal(err)
	}

	yamlContent := `api_version: v1
kind: Campaign
meta:
  name: test-dir-campaign
  adversary: TestActor
  severity: medium
stages:
  - id: s1
    name: Stage 1
    technique: T1059.001
    tactic: execution
    execute:
      type: shell
      commands:
        - echo hello
    expect:
      telemetry: [process_create]
      detections: [test_rule]
`
	if err := os.WriteFile(filepath.Join(campDir, "campaign.yaml"), []byte(yamlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := ScoreDir(dir)
	if err != nil {
		t.Fatalf("ScoreDir failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 scored campaign, got %d", len(results))
	}
	if results[0].CampaignName != "test-dir-campaign" {
		t.Errorf("expected name 'test-dir-campaign', got %q", results[0].CampaignName)
	}
	if results[0].CampaignFile == "" {
		t.Error("expected CampaignFile to be set")
	}
}

func TestScoreDir_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	results, err := ScoreDir(dir)
	if err != nil {
		t.Fatalf("ScoreDir failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestScoreDir_NonExistentDirectory(t *testing.T) {
	_, err := ScoreDir("/no/such/directory/xyz")
	if err == nil {
		t.Error("expected error for non-existent directory")
	}
}

func TestScoreDir_MultipleCampaigns_SortedByScore(t *testing.T) {
	dir := t.TempDir()

	// Simple campaign (lower score).
	simple := filepath.Join(dir, "simple")
	if err := os.MkdirAll(simple, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(simple, "campaign.yaml"), []byte(`
api_version: v1
kind: Campaign
meta:
  name: simple-campaign
  severity: low
stages:
  - id: s1
    technique: T1059
    tactic: execution
    execute:
      type: shell
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Complex campaign (higher score).
	complex := filepath.Join(dir, "complex")
	if err := os.MkdirAll(complex, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(complex, "campaign.yaml"), []byte(`
api_version: v1
kind: Campaign
meta:
  name: complex-campaign
  severity: critical
stages:
  - id: s1
    technique: T1566.001
    tactic: initial-access
    execute:
      type: http
  - id: s2
    technique: T1059.001
    tactic: execution
    depends_on: [s1]
    execute:
      type: shell
      elevated: true
  - id: s3
    technique: T1003.001
    tactic: credential-access
    depends_on: [s2]
    execute:
      type: shell
      elevated: true
  - id: s4
    technique: T1070
    tactic: defense-evasion
    execute:
      type: shell
      cleanup: [rm -f evidence]
  - id: s5
    technique: T1041
    tactic: exfiltration
    depends_on: [s3]
    execute:
      type: http
`), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := ScoreDir(dir)
	if err != nil {
		t.Fatalf("ScoreDir failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// Results should be sorted by score descending.
	if results[0].Score.OverallScore < results[1].Score.OverallScore {
		t.Errorf("expected results sorted by score desc: first=%.1f, second=%.1f",
			results[0].Score.OverallScore, results[1].Score.OverallScore)
	}
}

// --- Helper function tests ---

func TestCap100(t *testing.T) {
	tests := []struct {
		in, want float64
	}{
		{0, 0},
		{50, 50},
		{100, 100},
		{150, 100},
		{-10, 0},
	}
	for _, tt := range tests {
		got := cap100(tt.in)
		if got != tt.want {
			t.Errorf("cap100(%.1f) = %.1f, want %.1f", tt.in, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s      string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a long name", 10, "this is..."},
		{"ab", 3, "ab"},
		{"abcd", 3, "abc"},
	}
	for _, tt := range tests {
		got := truncate(tt.s, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
		}
	}
}

func TestCountStagesInTactic(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
	})
	if got := countStagesInTactic(c, "execution"); got != 2 {
		t.Errorf("expected 2 execution stages, got %d", got)
	}
	if got := countStagesInTactic(c, "initial-access"); got != 1 {
		t.Errorf("expected 1 initial-access stage, got %d", got)
	}
	if got := countStagesInTactic(c, "defense-evasion"); got != 0 {
		t.Errorf("expected 0 defense-evasion stages, got %d", got)
	}
}

func TestCountUniqueTechniquesInTactic(t *testing.T) {
	c := scoreCampaign("test", "low", []Stage{
		{ID: "s1", Technique: "T1070", Tactic: "defense-evasion", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1070", Tactic: "defense-evasion", Execute: Execute{Type: "shell"}}, // duplicate
		{ID: "s3", Technique: "T1027", Tactic: "defense-evasion", Execute: Execute{Type: "shell"}},
		{ID: "s4", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
	})
	if got := countUniqueTechniquesInTactic(c, "defense-evasion"); got != 2 {
		t.Errorf("expected 2 unique defense-evasion techniques, got %d", got)
	}
}
