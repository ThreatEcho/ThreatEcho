// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"strings"
	"testing"
)

func TestProfileCampaign_Basic(t *testing.T) {
	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "test-campaign",
			Adversary: "TestActor",
			Severity:  "high",
		},
		Variables: map[string]string{"target": "10.0.0.1"},
		Stages: []Stage{
			{
				ID:        "recon",
				Technique: "T1016",
				Tactic:    "discovery",
				Execute:   Execute{Type: "shell", Commands: []string{"echo test"}},
				Expect:    Expect{Telemetry: []string{"process_create"}, Detections: []string{"scan_detected"}},
			},
			{
				ID:        "access",
				Technique: "T1190",
				Tactic:    "initial-access",
				DependsOn: []string{"recon"},
				Execute:   Execute{Type: "http", Target: "http://target"},
				Expect:    Expect{Telemetry: []string{"network_connection", "process_create"}},
			},
		},
	}

	p := ProfileCampaign(c)

	if p.Name != "test-campaign" {
		t.Errorf("Name = %q, want %q", p.Name, "test-campaign")
	}
	if p.StageCount != 2 {
		t.Errorf("StageCount = %d, want 2", p.StageCount)
	}
	if p.TechniqueCount != 2 {
		t.Errorf("TechniqueCount = %d, want 2", p.TechniqueCount)
	}
	if p.TacticCount != 2 {
		t.Errorf("TacticCount = %d, want 2", p.TacticCount)
	}
	if p.VariableCount != 1 {
		t.Errorf("VariableCount = %d, want 1", p.VariableCount)
	}
	if p.ShellStages != 1 {
		t.Errorf("ShellStages = %d, want 1", p.ShellStages)
	}
	if p.HTTPStages != 1 {
		t.Errorf("HTTPStages = %d, want 1", p.HTTPStages)
	}
	if p.DependencyEdges != 1 {
		t.Errorf("DependencyEdges = %d, want 1", p.DependencyEdges)
	}
}

func TestProfileCampaign_AttackTechniques(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "attack-test"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
			{ID: "s2", Technique: "T1566.001", Tactic: "initial-access", Execute: Execute{Type: "shell"}},
		},
	}
	p := ProfileCampaign(c)

	if len(p.AttackTechniques) != 2 {
		t.Errorf("AttackTechniques = %d, want 2", len(p.AttackTechniques))
	}
	if len(p.AtlasTechniques) != 0 {
		t.Errorf("AtlasTechniques = %d, want 0", len(p.AtlasTechniques))
	}
}

func TestProfileCampaign_AtlasTechniques(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "atlas-test"},
		Stages: []Stage{
			{ID: "s1", Technique: "AML.T0051", Tactic: "initial-access", Execute: Execute{Type: "http"}},
			{ID: "s2", Technique: "AML.T0043", Tactic: "reconnaissance", Execute: Execute{Type: "http"}},
		},
	}
	p := ProfileCampaign(c)

	if len(p.AtlasTechniques) != 2 {
		t.Errorf("AtlasTechniques = %d, want 2", len(p.AtlasTechniques))
	}
}

func TestProfileCampaign_OwaspTechniques(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "owasp-test"},
		Stages: []Stage{
			{ID: "s1", Technique: "LLM06", Tactic: "execution", Execute: Execute{Type: "http"}},
		},
	}
	p := ProfileCampaign(c)

	if len(p.OwaspTechniques) != 1 {
		t.Errorf("OwaspTechniques = %d, want 1", len(p.OwaspTechniques))
	}
}

func TestProfileCampaign_MultiFramework(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "multi-framework"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
			{ID: "s2", Technique: "AML.T0051", Tactic: "initial-access", Execute: Execute{Type: "http"}},
			{ID: "s3", Technique: "LLM06", Tactic: "execution", Execute: Execute{Type: "http"}},
		},
	}
	p := ProfileCampaign(c)

	if len(p.AttackTechniques) != 1 {
		t.Errorf("AttackTechniques = %d, want 1", len(p.AttackTechniques))
	}
	if len(p.AtlasTechniques) != 1 {
		t.Errorf("AtlasTechniques = %d, want 1", len(p.AtlasTechniques))
	}
	if len(p.OwaspTechniques) != 1 {
		t.Errorf("OwaspTechniques = %d, want 1", len(p.OwaspTechniques))
	}
	// Multi-framework should boost complexity
	if p.ComplexityScore < 10 {
		t.Errorf("multi-framework campaign should have non-trivial complexity, got %d", p.ComplexityScore)
	}
}

func TestProfileCampaign_DetectionCoverage(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "coverage-test"},
		Stages: []Stage{
			{ID: "s1", Execute: Execute{Type: "shell"}, Expect: Expect{Telemetry: []string{"process_create"}, Detections: []string{"det1"}}},
			{ID: "s2", Execute: Execute{Type: "shell"}, Expect: Expect{Telemetry: []string{"network_connection"}}},
			{ID: "s3", Execute: Execute{Type: "shell"}, Expect: Expect{Telemetry: []string{"file_create"}, Detections: []string{"det2"}}},
			{ID: "s4", Execute: Execute{Type: "shell"}},
		},
	}
	p := ProfileCampaign(c)

	// 2 out of 4 stages have detections = 50%
	if p.DetectionCoverage != 50 {
		t.Errorf("DetectionCoverage = %.0f, want 50", p.DetectionCoverage)
	}
	// 3 out of 4 stages have telemetry = 75%
	if p.TelemetryCoverage != 75 {
		t.Errorf("TelemetryCoverage = %.0f, want 75", p.TelemetryCoverage)
	}
}

func TestProfileCampaign_ElevatedStages(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "elevated-test"},
		Stages: []Stage{
			{ID: "s1", Execute: Execute{Type: "shell", Elevated: true}},
			{ID: "s2", Execute: Execute{Type: "shell", Elevated: false}},
			{ID: "s3", Execute: Execute{Type: "shell", Elevated: true}},
		},
	}
	p := ProfileCampaign(c)

	if p.ElevatedStages != 2 {
		t.Errorf("ElevatedStages = %d, want 2", p.ElevatedStages)
	}
}

func TestProfileCampaign_TelemetryUsageSorted(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "telemetry-sort"},
		Stages: []Stage{
			{ID: "s1", Execute: Execute{Type: "shell"}, Expect: Expect{Telemetry: []string{"process_create", "file_create"}}},
			{ID: "s2", Execute: Execute{Type: "shell"}, Expect: Expect{Telemetry: []string{"process_create", "network_connection"}}},
			{ID: "s3", Execute: Execute{Type: "shell"}, Expect: Expect{Telemetry: []string{"process_create"}}},
		},
	}
	p := ProfileCampaign(c)

	if len(p.MostUsedTelemetry) < 3 {
		t.Fatalf("MostUsedTelemetry should have 3 entries, got %d", len(p.MostUsedTelemetry))
	}
	// process_create used in all 3 stages
	if p.MostUsedTelemetry[0].Type != "process_create" {
		t.Errorf("most used telemetry should be process_create, got %q", p.MostUsedTelemetry[0].Type)
	}
	if p.MostUsedTelemetry[0].Count != 3 {
		t.Errorf("process_create count should be 3, got %d", p.MostUsedTelemetry[0].Count)
	}
}

func TestProfileCampaign_EmptyCampaign(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "empty"},
	}
	p := ProfileCampaign(c)

	if p.StageCount != 0 {
		t.Errorf("StageCount = %d, want 0", p.StageCount)
	}
	if p.ComplexityScore != 0 {
		t.Errorf("ComplexityScore = %d, want 0 for empty campaign", p.ComplexityScore)
	}
	if p.ComplexityGrade != "A" {
		t.Errorf("ComplexityGrade = %q, want A for empty campaign", p.ComplexityGrade)
	}
}

func TestProfileCampaign_GraphMetrics(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "graph-test"},
		Stages: []Stage{
			{ID: "a", Execute: Execute{Type: "shell"}},
			{ID: "b", DependsOn: []string{"a"}, Execute: Execute{Type: "shell"}},
			{ID: "c", DependsOn: []string{"a"}, Execute: Execute{Type: "shell"}},
			{ID: "d", DependsOn: []string{"b", "c"}, Execute: Execute{Type: "shell"}},
		},
	}
	p := ProfileCampaign(c)

	if p.EntryPoints != 1 {
		t.Errorf("EntryPoints = %d, want 1", p.EntryPoints)
	}
	if p.TerminalNodes != 1 {
		t.Errorf("TerminalNodes = %d, want 1", p.TerminalNodes)
	}
	if p.MaxDepth < 2 {
		t.Errorf("MaxDepth = %d, want >= 2", p.MaxDepth)
	}
	if p.ParallelWidth < 2 {
		t.Errorf("ParallelWidth = %d, want >= 2 (b and c are parallel)", p.ParallelWidth)
	}
}

func TestComplexityGrade(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{0, "A"},
		{10, "A"},
		{19, "A"},
		{20, "B"},
		{39, "B"},
		{40, "C"},
		{59, "C"},
		{60, "D"},
		{79, "D"},
		{80, "E"},
		{100, "E"},
	}
	for _, tt := range tests {
		got := complexityGrade(tt.score)
		if got != tt.grade {
			t.Errorf("complexityGrade(%d) = %q, want %q", tt.score, got, tt.grade)
		}
	}
}

func TestFormatProfile_NonEmpty(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "format-test", Adversary: "Test", Severity: "high"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"},
				Expect: Expect{Telemetry: []string{"process_create"}}},
		},
	}
	p := ProfileCampaign(c)
	out := FormatProfile(p)

	if len(out) < 100 {
		t.Error("FormatProfile output too short")
	}
	if !strings.Contains(out, "format-test") {
		t.Error("FormatProfile should contain campaign name")
	}
	if !strings.Contains(out, "Grade") {
		t.Error("FormatProfile should contain complexity grade")
	}
	if !strings.Contains(out, "Detection coverage") {
		t.Error("FormatProfile should contain detection coverage")
	}
}

func TestFormatProfileSummary_NonEmpty(t *testing.T) {
	profiles := []*Profile{
		{Name: "campaign-a", ComplexityGrade: "C", ComplexityScore: 45, StageCount: 8,
			TechniqueCount: 8, TacticCount: 6, DetectionCoverage: 75, TelemetryCoverage: 100,
			AttackTechniques: []string{"T1059"}},
		{Name: "campaign-b", ComplexityGrade: "B", ComplexityScore: 25, StageCount: 3,
			TechniqueCount: 3, TacticCount: 2, DetectionCoverage: 100, TelemetryCoverage: 100},
	}

	out := FormatProfileSummary(profiles)
	if !strings.Contains(out, "campaign-a") {
		t.Error("summary should contain campaign-a")
	}
	if !strings.Contains(out, "campaign-b") {
		t.Error("summary should contain campaign-b")
	}
	if !strings.Contains(out, "GRADE") {
		t.Error("summary should contain GRADE header")
	}
}

func TestProfileCampaign_ComplexCampaignGetsHighScore(t *testing.T) {
	// Build a complex campaign with many stages, techniques, tactics
	stages := make([]Stage, 12)
	tactics := []string{"initial-access", "execution", "persistence", "privilege-escalation",
		"defense-evasion", "credential-access", "discovery", "lateral-movement",
		"collection", "command-and-control", "exfiltration", "impact"}
	for i := range stages {
		stages[i] = Stage{
			ID:        fmt.Sprintf("stage-%d", i),
			Technique: fmt.Sprintf("T10%02d", i+59),
			Tactic:    tactics[i],
			Execute:   Execute{Type: "shell"},
			Expect:    Expect{Telemetry: []string{"process_create"}, Detections: []string{fmt.Sprintf("det-%d", i)}},
		}
		if i > 0 {
			stages[i].DependsOn = []string{fmt.Sprintf("stage-%d", i-1)}
		}
	}
	c := &Campaign{
		Meta:   Meta{Name: "complex-campaign", Adversary: "APT-X", Severity: "critical"},
		Stages: stages,
	}
	p := ProfileCampaign(c)

	if p.ComplexityScore < 50 {
		t.Errorf("complex campaign should have high complexity score, got %d", p.ComplexityScore)
	}
	if p.ComplexityGrade == "A" || p.ComplexityGrade == "B" {
		t.Errorf("complex campaign should not be graded A or B, got %s", p.ComplexityGrade)
	}
}
