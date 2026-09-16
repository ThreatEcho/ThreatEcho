// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper to build a minimal campaign for report tests.
func reportCampaign(name, adversary, severity string, stages []Stage) *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      name,
			Adversary: adversary,
			Severity:  severity,
		},
		Stages: stages,
	}
}

// --- GenerateReport tests ---

func TestGenerateReport_Nil(t *testing.T) {
	r := GenerateReport(nil)
	if r == nil {
		t.Fatal("GenerateReport(nil) should return a report, not nil")
	}
	if r.CampaignCount != 0 {
		t.Errorf("expected 0 campaigns, got %d", r.CampaignCount)
	}
	if r.Title == "" {
		t.Error("expected a title")
	}
	if r.GeneratedAt == "" {
		t.Error("expected a timestamp")
	}
	if r.ProjectStats == nil {
		t.Error("expected non-nil ProjectStats")
	}
	if len(r.Scores) != 0 {
		t.Errorf("expected 0 scores, got %d", len(r.Scores))
	}
}

func TestGenerateReport_Empty(t *testing.T) {
	r := GenerateReport([]*Campaign{})
	if r.CampaignCount != 0 {
		t.Errorf("expected 0 campaigns, got %d", r.CampaignCount)
	}
	if len(r.TopRisks) != 0 {
		t.Errorf("expected 0 risk items, got %d", len(r.TopRisks))
	}
}

func TestGenerateReport_NilCampaignInSlice(t *testing.T) {
	r := GenerateReport([]*Campaign{nil, nil})
	if r.CampaignCount != 2 {
		t.Errorf("expected campaign count 2 (including nils), got %d", r.CampaignCount)
	}
	if len(r.Scores) != 0 {
		t.Errorf("expected 0 scores for nil campaigns, got %d", len(r.Scores))
	}
}

func TestGenerateReport_SingleCampaign(t *testing.T) {
	c := reportCampaign("fin6-sim", "FIN6", "critical", []Stage{
		{
			ID:        "s1",
			Technique: "T1059.001",
			Tactic:    "execution",
			Execute:   Execute{Type: "shell", Commands: []string{"whoami"}},
			Expect:    Expect{Detections: []string{"rule1"}, Telemetry: []string{"proc_create"}},
		},
		{
			ID:        "s2",
			Technique: "T1003.001",
			Tactic:    "credential-access",
			Execute:   Execute{Type: "shell", Commands: []string{"mimikatz"}},
		},
	})

	r := GenerateReport([]*Campaign{c})

	if r.CampaignCount != 1 {
		t.Errorf("expected 1 campaign, got %d", r.CampaignCount)
	}
	if r.ProjectStats.TotalStages != 2 {
		t.Errorf("expected 2 stages, got %d", r.ProjectStats.TotalStages)
	}
	if len(r.Scores) != 1 {
		t.Fatalf("expected 1 score, got %d", len(r.Scores))
	}
	if r.Scores[0].CampaignName != "fin6-sim" {
		t.Errorf("expected campaign name 'fin6-sim', got %q", r.Scores[0].CampaignName)
	}
	if len(r.TopRisks) != 1 {
		t.Errorf("expected 1 risk item, got %d", len(r.TopRisks))
	}
}

func TestGenerateReport_MultipleCampaigns(t *testing.T) {
	c1 := reportCampaign("apt29", "APT29", "critical", []Stage{
		{ID: "s1", Technique: "T1566.001", Tactic: "initial-access", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
	})
	c2 := reportCampaign("simple", "TestActor", "low", []Stage{
		{ID: "s1", Technique: "T1082", Tactic: "discovery", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"d1"}, Telemetry: []string{"t1"}}},
	})

	r := GenerateReport([]*Campaign{c1, c2})

	if r.CampaignCount != 2 {
		t.Errorf("expected 2 campaigns, got %d", r.CampaignCount)
	}
	if r.ProjectStats.TotalStages != 4 {
		t.Errorf("expected 4 stages, got %d", r.ProjectStats.TotalStages)
	}
	if len(r.Scores) != 2 {
		t.Fatalf("expected 2 scores, got %d", len(r.Scores))
	}
	// Scores should be sorted descending.
	if r.Scores[0].Score.OverallScore < r.Scores[1].Score.OverallScore {
		t.Error("expected scores sorted descending by overall score")
	}
}

func TestGenerateReport_HasTimestamp(t *testing.T) {
	r := GenerateReport([]*Campaign{})
	if r.GeneratedAt == "" {
		t.Error("expected GeneratedAt to be set")
	}
	// Should be a valid ISO timestamp.
	if !strings.Contains(r.GeneratedAt, "T") {
		t.Errorf("expected ISO timestamp, got %q", r.GeneratedAt)
	}
}

func TestGenerateReport_ScoresSortedDescending(t *testing.T) {
	// Build campaigns with different complexity to produce different scores.
	cHigh := reportCampaign("high-risk", "APT", "critical", []Stage{
		{ID: "s1", Technique: "T1566.001", Tactic: "initial-access", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell", Elevated: true}},
		{ID: "s3", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "http"}},
		{ID: "s4", Technique: "T1070.001", Tactic: "defense-evasion", Execute: Execute{Type: "shell", Cleanup: []string{"clean"}}},
		{ID: "s5", Technique: "T1041", Tactic: "exfiltration", Execute: Execute{Type: "http"}},
	})
	cLow := reportCampaign("low-risk", "Script", "low", []Stage{
		{ID: "s1", Technique: "T1082", Tactic: "discovery", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"d1"}, Telemetry: []string{"t1"}}},
	})

	r := GenerateReport([]*Campaign{cLow, cHigh})

	if len(r.Scores) < 2 {
		t.Fatalf("expected at least 2 scores, got %d", len(r.Scores))
	}
	if r.Scores[0].CampaignName != "high-risk" {
		t.Errorf("expected highest-risk campaign first, got %q", r.Scores[0].CampaignName)
	}
}

// --- CoverageGaps tests ---

func TestBuildCoverageGaps_NilStats(t *testing.T) {
	gaps := buildCoverageGaps(nil)
	if len(gaps) != 0 {
		t.Errorf("expected 0 gaps for nil stats, got %d", len(gaps))
	}
}

func TestBuildCoverageGaps_AllMissing(t *testing.T) {
	stats := &ProjectStats{}
	gaps := buildCoverageGaps(stats)
	// All 14 tactics should be missing.
	if len(gaps) != 14 {
		t.Errorf("expected 14 gaps, got %d", len(gaps))
	}
}

func TestBuildCoverageGaps_SomeCovered(t *testing.T) {
	stats := &ProjectStats{
		TacticDistribution: []TacticDist{
			{Tactic: "execution", Count: 3},
			{Tactic: "discovery", Count: 2},
			{Tactic: "initial-access", Count: 1},
		},
	}
	gaps := buildCoverageGaps(stats)
	// 14 - 3 = 11 missing.
	if len(gaps) != 11 {
		t.Errorf("expected 11 gaps, got %d", len(gaps))
	}
	// Verify none of the covered tactics appear in gaps.
	for _, g := range gaps {
		if g.Tactic == "Execution" || g.Tactic == "Discovery" || g.Tactic == "Initial Access" {
			t.Errorf("covered tactic %q should not be in gaps", g.Tactic)
		}
	}
}

func TestBuildCoverageGaps_RiskLevels(t *testing.T) {
	// Cover everything except initial-access (critical) and discovery (medium).
	stats := &ProjectStats{
		TacticDistribution: []TacticDist{
			{Tactic: "reconnaissance", Count: 1},
			{Tactic: "resource-development", Count: 1},
			{Tactic: "execution", Count: 1},
			{Tactic: "persistence", Count: 1},
			{Tactic: "privilege-escalation", Count: 1},
			{Tactic: "defense-evasion", Count: 1},
			{Tactic: "credential-access", Count: 1},
			{Tactic: "lateral-movement", Count: 1},
			{Tactic: "collection", Count: 1},
			{Tactic: "command-and-control", Count: 1},
			{Tactic: "exfiltration", Count: 1},
			{Tactic: "impact", Count: 1},
		},
	}
	gaps := buildCoverageGaps(stats)
	if len(gaps) != 2 {
		t.Fatalf("expected 2 gaps, got %d", len(gaps))
	}
	// Verify risk classification.
	riskMap := make(map[string]string)
	for _, g := range gaps {
		riskMap[g.Tactic] = g.Risk
	}
	if riskMap["Initial Access"] != "critical" {
		t.Errorf("expected initial-access gap risk 'critical', got %q", riskMap["Initial Access"])
	}
	if riskMap["Discovery"] != "medium" {
		t.Errorf("expected discovery gap risk 'medium', got %q", riskMap["Discovery"])
	}
}

// --- TopRisks tests ---

func TestBuildTopRisks_Empty(t *testing.T) {
	items := buildTopRisks(nil)
	if len(items) != 0 {
		t.Errorf("expected 0 risk items, got %d", len(items))
	}
}

func TestBuildTopRisks_IncludesAllScored(t *testing.T) {
	scores := []*ScoredCampaign{
		{CampaignName: "c1", Score: ScoreBreakdown{OverallScore: 80, Grade: "A", DetectionDifficulty: 90}, Severity: "critical"},
		{CampaignName: "c2", Score: ScoreBreakdown{OverallScore: 30, Grade: "D"}, StageCount: 2, Severity: "low"},
	}
	items := buildTopRisks(scores)
	if len(items) != 2 {
		t.Fatalf("expected 2 risk items, got %d", len(items))
	}
	if items[0].Campaign != "c1" {
		t.Errorf("expected first item 'c1', got %q", items[0].Campaign)
	}
	if items[0].Grade != "A" {
		t.Errorf("expected grade A, got %q", items[0].Grade)
	}
}

func TestBuildRiskReason_CriticalSeverity(t *testing.T) {
	sc := &ScoredCampaign{
		CampaignName: "test",
		Severity:     "critical",
		StageCount:   3,
		Score:        ScoreBreakdown{DetectionDifficulty: 50, EvasionSophistication: 30, TechniqueComplexity: 20, TacticBreadth: 10},
	}
	reason := buildRiskReason(sc)
	if !strings.Contains(reason, "critical severity") {
		t.Errorf("expected reason to mention critical severity, got %q", reason)
	}
}

func TestBuildRiskReason_HardToDetect(t *testing.T) {
	sc := &ScoredCampaign{
		CampaignName: "test",
		Severity:     "medium",
		StageCount:   1,
		Score:        ScoreBreakdown{DetectionDifficulty: 85},
	}
	reason := buildRiskReason(sc)
	if !strings.Contains(reason, "very hard to detect") {
		t.Errorf("expected reason to mention 'very hard to detect', got %q", reason)
	}
}

func TestBuildRiskReason_FallbackReason(t *testing.T) {
	sc := &ScoredCampaign{
		CampaignName: "test",
		Severity:     "low",
		StageCount:   1,
		Score:        ScoreBreakdown{DetectionDifficulty: 10, EvasionSophistication: 5, TechniqueComplexity: 5, TacticBreadth: 5},
	}
	reason := buildRiskReason(sc)
	if !strings.Contains(reason, "1 stages") {
		t.Errorf("expected fallback reason with stage count, got %q", reason)
	}
}

// --- Recommendations tests ---

func TestBuildRecommendations_NilStats(t *testing.T) {
	recs := buildRecommendations(nil, nil, nil)
	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations for nil stats, got %d", len(recs))
	}
}

func TestBuildRecommendations_StagesWithoutCoverage(t *testing.T) {
	stats := &ProjectStats{
		StagesWithoutEither: 5,
	}
	recs := buildRecommendations(stats, nil, nil)
	found := false
	for _, rec := range recs {
		if strings.Contains(rec, "5 stages that lack coverage") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected recommendation about 5 uncovered stages, got %v", recs)
	}
}

func TestBuildRecommendations_ExpandTacticCoverage(t *testing.T) {
	stats := &ProjectStats{}
	gaps := []CoverageGapItem{
		{Tactic: "Exfiltration", Risk: "high"},
		{Tactic: "Impact", Risk: "medium"},
	}
	recs := buildRecommendations(stats, nil, gaps)
	found := false
	for _, rec := range recs {
		if strings.Contains(rec, "Expand tactic coverage") && strings.Contains(rec, "Exfiltration") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected recommendation about expanding tactic coverage, got %v", recs)
	}
}

func TestBuildRecommendations_HighRiskCampaign(t *testing.T) {
	stats := &ProjectStats{}
	scores := []*ScoredCampaign{
		{CampaignName: "apt-sim", Score: ScoreBreakdown{Grade: "A", OverallScore: 85}},
	}
	recs := buildRecommendations(stats, scores, nil)
	found := false
	for _, rec := range recs {
		if strings.Contains(rec, "apt-sim") && strings.Contains(rec, "Grade A") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected recommendation about high-risk campaign, got %v", recs)
	}
}

func TestBuildRecommendations_LowTechniqueCount(t *testing.T) {
	stats := &ProjectStats{
		TacticDistribution: []TacticDist{
			{Tactic: "execution", Count: 1},
		},
	}
	recs := buildRecommendations(stats, nil, nil)
	found := false
	for _, rec := range recs {
		if strings.Contains(rec, "Consider campaigns for") && strings.Contains(rec, "Execution") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected recommendation for low technique count tactic, got %v", recs)
	}
}

func TestBuildRecommendations_NoRecsWhenAllGood(t *testing.T) {
	stats := &ProjectStats{
		StagesWithoutEither: 0,
		TacticDistribution: []TacticDist{
			{Tactic: "execution", Count: 10},
			{Tactic: "discovery", Count: 5},
		},
	}
	scores := []*ScoredCampaign{
		{CampaignName: "ok", Score: ScoreBreakdown{Grade: "D", OverallScore: 25}},
	}
	recs := buildRecommendations(stats, scores, nil)
	// Should not have the stages-without-coverage or high-risk recs.
	for _, rec := range recs {
		if strings.Contains(rec, "lack coverage") {
			t.Errorf("unexpected coverage recommendation: %s", rec)
		}
		if strings.Contains(rec, "needs review") {
			t.Errorf("unexpected high-risk recommendation: %s", rec)
		}
	}
}

// --- OverallGrade tests ---

func TestComputeOverallGrade_Empty(t *testing.T) {
	grade := computeOverallGrade(nil)
	if grade != "N/A" {
		t.Errorf("expected 'N/A' for empty scores, got %q", grade)
	}
}

func TestComputeOverallGrade_Single(t *testing.T) {
	scores := []*ScoredCampaign{
		{Score: ScoreBreakdown{OverallScore: 85}},
	}
	grade := computeOverallGrade(scores)
	if grade != "A" {
		t.Errorf("expected grade A for score 85, got %q", grade)
	}
}

func TestComputeOverallGrade_Average(t *testing.T) {
	scores := []*ScoredCampaign{
		{Score: ScoreBreakdown{OverallScore: 90}},
		{Score: ScoreBreakdown{OverallScore: 30}},
	}
	// Average = 60.0 -> Grade B.
	grade := computeOverallGrade(scores)
	if grade != "B" {
		t.Errorf("expected grade B for average 60, got %q", grade)
	}
}

// --- FormatReportText tests ---

func TestFormatReportText_Nil(t *testing.T) {
	out := FormatReportText(nil)
	if out != "" {
		t.Errorf("expected empty string for nil report, got %q", out)
	}
}

func TestFormatReportText_ContainsSections(t *testing.T) {
	c := reportCampaign("test", "Actor", "medium", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"d1"}}},
		{ID: "s2", Technique: "T1082", Tactic: "discovery", Execute: Execute{Type: "shell"}},
	})
	r := GenerateReport([]*Campaign{c})
	text := FormatReportText(r)

	sections := []string{
		"Executive Summary",
		"Risk Assessment",
		"Coverage Overview",
		"Detection Readiness",
		"Recommendations",
	}
	for _, sec := range sections {
		if !strings.Contains(text, sec) {
			t.Errorf("text output missing section %q", sec)
		}
	}
}

func TestFormatReportText_ContainsTitle(t *testing.T) {
	r := GenerateReport([]*Campaign{})
	text := FormatReportText(r)
	if !strings.Contains(text, "ThreatEcho Executive Report") {
		t.Error("text output missing title")
	}
}

func TestFormatReportText_ContainsTimestamp(t *testing.T) {
	r := GenerateReport([]*Campaign{})
	text := FormatReportText(r)
	if !strings.Contains(text, "Generated:") {
		t.Error("text output missing timestamp line")
	}
}

func TestFormatReportText_ShowsCampaignData(t *testing.T) {
	c := reportCampaign("apt-test", "APT1", "high", []Stage{
		{ID: "s1", Technique: "T1566.001", Tactic: "initial-access", Execute: Execute{Type: "shell"}},
	})
	r := GenerateReport([]*Campaign{c})
	text := FormatReportText(r)

	if !strings.Contains(text, "apt-test") {
		t.Error("text output missing campaign name")
	}
	if !strings.Contains(text, "Campaigns:") {
		t.Error("text output missing campaigns count line")
	}
}

func TestFormatReportText_EmptyNoStages(t *testing.T) {
	r := GenerateReport([]*Campaign{})
	text := FormatReportText(r)
	if !strings.Contains(text, "No stages to analyze") {
		t.Error("expected 'No stages to analyze' for empty report")
	}
}

func TestFormatReportText_TacticChecklist(t *testing.T) {
	c := reportCampaign("test", "Actor", "medium", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
	})
	r := GenerateReport([]*Campaign{c})
	text := FormatReportText(r)

	// Should have both checked and unchecked tactics.
	if !strings.Contains(text, "[x]") {
		t.Error("expected at least one checked tactic")
	}
	if !strings.Contains(text, "[ ]") {
		t.Error("expected at least one unchecked tactic")
	}
}

// --- FormatReportMarkdown tests ---

func TestFormatReportMarkdown_Nil(t *testing.T) {
	out := FormatReportMarkdown(nil)
	if out != "" {
		t.Errorf("expected empty string for nil report, got %q", out)
	}
}

func TestFormatReportMarkdown_ContainsSections(t *testing.T) {
	c := reportCampaign("test", "Actor", "medium", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"d1"}}},
		{ID: "s2", Technique: "T1082", Tactic: "discovery", Execute: Execute{Type: "shell"}},
	})
	r := GenerateReport([]*Campaign{c})
	md := FormatReportMarkdown(r)

	sections := []string{
		"## Executive Summary",
		"## Risk Assessment",
		"## Coverage Overview",
		"## Detection Readiness",
		"## Recommendations",
	}
	for _, sec := range sections {
		if !strings.Contains(md, sec) {
			t.Errorf("markdown output missing section %q", sec)
		}
	}
}

func TestFormatReportMarkdown_ContainsTables(t *testing.T) {
	c := reportCampaign("test", "Actor", "medium", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"d1"}, Telemetry: []string{"t1"}}},
	})
	r := GenerateReport([]*Campaign{c})
	md := FormatReportMarkdown(r)

	// Should contain markdown table separators.
	if !strings.Contains(md, "|-----") {
		t.Error("markdown output missing table separators")
	}
}

func TestFormatReportMarkdown_TacticCheckboxes(t *testing.T) {
	c := reportCampaign("test", "Actor", "medium", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
	})
	r := GenerateReport([]*Campaign{c})
	md := FormatReportMarkdown(r)

	// Should have checkbox list items.
	if !strings.Contains(md, "- [x]") {
		t.Error("expected checked markdown checkbox")
	}
	if !strings.Contains(md, "- [ ]") {
		t.Error("expected unchecked markdown checkbox")
	}
}

func TestFormatReportMarkdown_ContainsTitle(t *testing.T) {
	r := GenerateReport([]*Campaign{})
	md := FormatReportMarkdown(r)
	if !strings.Contains(md, "# ThreatEcho Executive Report") {
		t.Error("markdown output missing title heading")
	}
}

func TestFormatReportMarkdown_ContainsTimestamp(t *testing.T) {
	r := GenerateReport([]*Campaign{})
	md := FormatReportMarkdown(r)
	if !strings.Contains(md, "_Generated:") {
		t.Error("markdown output missing timestamp")
	}
}

// --- GenerateReportDir tests ---

func TestGenerateReportDir_ValidDir(t *testing.T) {
	// Use the testdata directory that has a valid campaign.
	dir := filepath.Join("testdata")
	r, err := GenerateReportDir(dir)
	if err != nil {
		t.Fatalf("GenerateReportDir(%q): %v", dir, err)
	}
	if r == nil {
		t.Fatal("expected non-nil report")
	}
	if r.CampaignCount < 1 {
		t.Errorf("expected at least 1 campaign from testdata, got %d", r.CampaignCount)
	}
	if r.ProjectStats.TotalStages < 1 {
		t.Errorf("expected at least 1 stage, got %d", r.ProjectStats.TotalStages)
	}
}

func TestGenerateReportDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	r, err := GenerateReportDir(dir)
	if err != nil {
		t.Fatalf("GenerateReportDir for empty dir: %v", err)
	}
	if r.CampaignCount != 0 {
		t.Errorf("expected 0 campaigns for empty dir, got %d", r.CampaignCount)
	}
}

func TestGenerateReportDir_InvalidDir(t *testing.T) {
	_, err := GenerateReportDir("/nonexistent/path/that/should/not/exist")
	if err == nil {
		t.Error("expected error for non-existent directory")
	}
}

func TestGenerateReportDir_WithCampaignFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a campaign subdirectory with campaign.yaml.
	campDir := filepath.Join(dir, "test-campaign")
	if err := os.MkdirAll(campDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	yamlContent := `api_version: v1
kind: Campaign
meta:
  name: dir-test
  adversary: DirActor
  severity: medium
  description: "dir test"
  objective: test
  mitre_version: "15.1"
  created: "2026-01-01"
  modified: "2026-01-01"
stages:
  - id: s1
    name: Stage One
    technique: T1082
    tactic: discovery
    execute:
      type: shell
      commands:
        - 'hostname'
    expect:
      telemetry: [process_create]
`
	if err := os.WriteFile(filepath.Join(campDir, "campaign.yaml"), []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("write campaign.yaml: %v", err)
	}

	r, err := GenerateReportDir(dir)
	if err != nil {
		t.Fatalf("GenerateReportDir: %v", err)
	}
	if r.CampaignCount != 1 {
		t.Errorf("expected 1 campaign, got %d", r.CampaignCount)
	}
	if r.ProjectStats.TotalStages != 1 {
		t.Errorf("expected 1 stage, got %d", r.ProjectStats.TotalStages)
	}
	if len(r.Scores) != 1 {
		t.Errorf("expected 1 score, got %d", len(r.Scores))
	}
}

// --- TacticGapRisk tests ---

func TestTacticGapRisk_Critical(t *testing.T) {
	criticals := []string{"initial-access", "execution", "defense-evasion"}
	for _, tac := range criticals {
		risk := tacticGapRisk(tac)
		if risk != "critical" {
			t.Errorf("expected 'critical' risk for %q, got %q", tac, risk)
		}
	}
}

func TestTacticGapRisk_High(t *testing.T) {
	highs := []string{"credential-access", "privilege-escalation", "lateral-movement",
		"persistence", "exfiltration", "command-and-control"}
	for _, tac := range highs {
		risk := tacticGapRisk(tac)
		if risk != "high" {
			t.Errorf("expected 'high' risk for %q, got %q", tac, risk)
		}
	}
}

func TestTacticGapRisk_Medium(t *testing.T) {
	mediums := []string{"discovery", "collection"}
	for _, tac := range mediums {
		risk := tacticGapRisk(tac)
		if risk != "medium" {
			t.Errorf("expected 'medium' risk for %q, got %q", tac, risk)
		}
	}
}

func TestTacticGapRisk_Low(t *testing.T) {
	lows := []string{"reconnaissance", "resource-development", "impact"}
	for _, tac := range lows {
		risk := tacticGapRisk(tac)
		if risk != "low" {
			t.Errorf("expected 'low' risk for %q, got %q", tac, risk)
		}
	}
}

// --- Integration: full round-trip ---

func TestGenerateReport_FullRoundTrip(t *testing.T) {
	// Build a realistic multi-campaign scenario.
	c1 := reportCampaign("apt29-full", "APT29", "critical", []Stage{
		{ID: "s1", Technique: "T1566.001", Tactic: "initial-access", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell", Elevated: true}},
		{ID: "s3", Technique: "T1055", Tactic: "privilege-escalation", Execute: Execute{Type: "shell"}, DependsOn: []string{"s2"}},
		{ID: "s4", Technique: "T1070.001", Tactic: "defense-evasion", Execute: Execute{Type: "shell", Cleanup: []string{"clean"}}},
		{ID: "s5", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
		{ID: "s6", Technique: "T1082", Tactic: "discovery", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"d1"}, Telemetry: []string{"t1"}}},
		{ID: "s7", Technique: "T1021.001", Tactic: "lateral-movement", Execute: Execute{Type: "shell"}},
		{ID: "s8", Technique: "T1041", Tactic: "exfiltration", Execute: Execute{Type: "http"}},
	})
	c2 := reportCampaign("simple-recon", "Script", "low", []Stage{
		{ID: "s1", Technique: "T1082", Tactic: "discovery", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"d1"}, Telemetry: []string{"t1"}}},
	})

	r := GenerateReport([]*Campaign{c1, c2})

	// Verify report completeness.
	if r.CampaignCount != 2 {
		t.Errorf("expected 2 campaigns, got %d", r.CampaignCount)
	}
	if r.ProjectStats.TotalStages != 9 {
		t.Errorf("expected 9 stages, got %d", r.ProjectStats.TotalStages)
	}
	if len(r.Scores) != 2 {
		t.Errorf("expected 2 scores, got %d", len(r.Scores))
	}

	// Verify text formatting doesn't panic and produces output.
	text := FormatReportText(r)
	if len(text) < 100 {
		t.Errorf("text output seems too short: %d chars", len(text))
	}

	// Verify markdown formatting doesn't panic and produces output.
	md := FormatReportMarkdown(r)
	if len(md) < 100 {
		t.Errorf("markdown output seems too short: %d chars", len(md))
	}

	// Verify recommendations exist.
	if len(r.Recommendations) == 0 {
		t.Error("expected at least one recommendation for this scenario")
	}

	// Coverage gaps should exist (not all 14 tactics covered).
	if len(r.CoverageGaps) == 0 {
		t.Error("expected coverage gaps for incomplete tactic coverage")
	}
}
