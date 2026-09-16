// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helper to build a minimal campaign with adversary and variables.
func statsCampaign(name, adversary, severity string, stages []Stage, vars map[string]string) *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      name,
			Adversary: adversary,
			Severity:  severity,
		},
		Variables: vars,
		Stages:    stages,
	}
}

func TestComputeStats_Empty(t *testing.T) {
	stats := ComputeStats(nil)
	if stats.TotalCampaigns != 0 {
		t.Errorf("expected 0 campaigns, got %d", stats.TotalCampaigns)
	}
	if stats.TotalStages != 0 {
		t.Errorf("expected 0 stages, got %d", stats.TotalStages)
	}
	if stats.DetectionCoverage != 0 {
		t.Errorf("expected 0 coverage, got %f", stats.DetectionCoverage)
	}

	stats2 := ComputeStats([]*Campaign{})
	if stats2.TotalCampaigns != 0 {
		t.Errorf("expected 0 campaigns for empty slice, got %d", stats2.TotalCampaigns)
	}
}

func TestComputeStats_SingleCampaign(t *testing.T) {
	c := statsCampaign("fin6", "FIN6", "critical", []Stage{
		{
			ID:        "s1",
			Technique: "T1059.001",
			Tactic:    "execution",
			Execute:   Execute{Type: "shell", Commands: []string{"cmd1", "cmd2"}, Cleanup: []string{"rm -f tmp"}},
			Expect:    Expect{Detections: []string{"rule1"}, Telemetry: []string{"process_create"}},
		},
		{
			ID:        "s2",
			Technique: "T1566.001",
			Tactic:    "initial-access",
			DependsOn: []string{"s1"},
			Execute:   Execute{Type: "http", Elevated: true},
			Expect:    Expect{Telemetry: []string{"email_event"}},
		},
	}, map[string]string{"host": "10.0.0.1"})

	stats := ComputeStats([]*Campaign{c})

	if stats.TotalCampaigns != 1 {
		t.Errorf("expected 1 campaign, got %d", stats.TotalCampaigns)
	}
	if stats.TotalStages != 2 {
		t.Errorf("expected 2 stages, got %d", stats.TotalStages)
	}
	if stats.TotalUniqueTechniques != 2 {
		t.Errorf("expected 2 unique techniques, got %d", stats.TotalUniqueTechniques)
	}
	if stats.TotalCommands != 2 {
		t.Errorf("expected 2 commands, got %d", stats.TotalCommands)
	}
	if stats.ElevatedCount != 1 {
		t.Errorf("expected 1 elevated, got %d", stats.ElevatedCount)
	}
	if stats.TotalCleanupCmds != 1 {
		t.Errorf("expected 1 cleanup cmd, got %d", stats.TotalCleanupCmds)
	}
	if stats.TotalDependencies != 1 {
		t.Errorf("expected 1 dependency, got %d", stats.TotalDependencies)
	}
}

func TestComputeStats_MultipleCampaigns(t *testing.T) {
	c1 := statsCampaign("campaign-a", "APT28", "high", []Stage{
		{ID: "a1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "a2", Technique: "T1566.001", Tactic: "initial-access", Execute: Execute{Type: "http"}},
	}, nil)
	c2 := statsCampaign("campaign-b", "APT29", "critical", []Stage{
		{ID: "b1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "b2", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "b3", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c1, c2})

	if stats.TotalCampaigns != 2 {
		t.Errorf("expected 2 campaigns, got %d", stats.TotalCampaigns)
	}
	if stats.TotalStages != 5 {
		t.Errorf("expected 5 stages, got %d", stats.TotalStages)
	}
	// T1059.001 appears in both campaigns, T1566.001, T1190, T1003.001 each in one.
	if stats.TotalUniqueTechniques != 4 {
		t.Errorf("expected 4 unique techniques, got %d", stats.TotalUniqueTechniques)
	}
}

func TestComputeStats_TechniqueFrequency(t *testing.T) {
	c1 := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
	}, nil)
	c2 := statsCampaign("c2", "B", "low", []Stage{
		{ID: "s4", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c1, c2})

	if len(stats.TechniqueFrequency) != 2 {
		t.Fatalf("expected 2 technique entries, got %d", len(stats.TechniqueFrequency))
	}

	// T1059.001 should be first (count=3).
	top := stats.TechniqueFrequency[0]
	if top.TechniqueID != "T1059.001" {
		t.Errorf("expected top technique T1059.001, got %s", top.TechniqueID)
	}
	if top.Count != 3 {
		t.Errorf("expected count 3, got %d", top.Count)
	}
	if top.Name != "PowerShell" {
		t.Errorf("expected name PowerShell, got %q", top.Name)
	}
	if len(top.Campaigns) != 2 {
		t.Errorf("expected 2 campaigns for T1059.001, got %d", len(top.Campaigns))
	}
}

func TestComputeStats_TacticDistribution(t *testing.T) {
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1059.003", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if len(stats.TacticDistribution) != 2 {
		t.Fatalf("expected 2 tactics, got %d", len(stats.TacticDistribution))
	}
	// execution should be first (count=2).
	if stats.TacticDistribution[0].Tactic != "execution" {
		t.Errorf("expected top tactic execution, got %s", stats.TacticDistribution[0].Tactic)
	}
	if stats.TacticDistribution[0].Count != 2 {
		t.Errorf("expected count 2 for execution, got %d", stats.TacticDistribution[0].Count)
	}
}

func TestComputeStats_FrameworkBreakdown(t *testing.T) {
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s3", Technique: "AML.T0043", Tactic: "ml-attack", Execute: Execute{Type: "shell"}},
		{ID: "s4", Technique: "LLM01", Tactic: "llm-risk", Execute: Execute{Type: "http"}},
		{ID: "s5", Technique: "CUSTOM-001", Tactic: "custom", Execute: Execute{Type: "shell"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if stats.FrameworkBreakdown.ATTACKCount != 2 {
		t.Errorf("expected ATT&CK 2, got %d", stats.FrameworkBreakdown.ATTACKCount)
	}
	if stats.FrameworkBreakdown.ATLASCount != 1 {
		t.Errorf("expected ATLAS 1, got %d", stats.FrameworkBreakdown.ATLASCount)
	}
	if stats.FrameworkBreakdown.OWASPCount != 1 {
		t.Errorf("expected OWASP 1, got %d", stats.FrameworkBreakdown.OWASPCount)
	}
	if stats.FrameworkBreakdown.UnknownCount != 1 {
		t.Errorf("expected Unknown 1, got %d", stats.FrameworkBreakdown.UnknownCount)
	}
}

func TestComputeStats_SeverityCounting(t *testing.T) {
	c1 := statsCampaign("c1", "A", "critical", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
	}, nil)
	c2 := statsCampaign("c2", "B", "critical", []Stage{
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
	}, nil)
	c3 := statsCampaign("c3", "C", "high", []Stage{
		{ID: "s3", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c1, c2, c3})

	if stats.SeverityCounts["critical"] != 2 {
		t.Errorf("expected critical=2, got %d", stats.SeverityCounts["critical"])
	}
	if stats.SeverityCounts["high"] != 1 {
		t.Errorf("expected high=1, got %d", stats.SeverityCounts["high"])
	}
}

func TestComputeStats_AdversaryDedupAndSort(t *testing.T) {
	c1 := statsCampaign("c1", "FIN6", "low", nil, nil)
	c2 := statsCampaign("c2", "APT28", "low", nil, nil)
	c3 := statsCampaign("c3", "FIN6", "low", nil, nil) // duplicate
	c4 := statsCampaign("c4", "Lazarus", "low", nil, nil)

	stats := ComputeStats([]*Campaign{c1, c2, c3, c4})

	expected := []string{"APT28", "FIN6", "Lazarus"}
	if len(stats.AdversaryList) != len(expected) {
		t.Fatalf("expected %d adversaries, got %d: %v", len(expected), len(stats.AdversaryList), stats.AdversaryList)
	}
	for i, adv := range expected {
		if stats.AdversaryList[i] != adv {
			t.Errorf("adversary[%d]: expected %s, got %s", i, adv, stats.AdversaryList[i])
		}
	}
}

func TestComputeStats_ExecTypeCounting(t *testing.T) {
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1059.003", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s4", Technique: "T1070.004", Tactic: "defense-evasion", Execute: Execute{Type: "file"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if stats.ExecTypeCounts["shell"] != 2 {
		t.Errorf("expected shell=2, got %d", stats.ExecTypeCounts["shell"])
	}
	if stats.ExecTypeCounts["http"] != 1 {
		t.Errorf("expected http=1, got %d", stats.ExecTypeCounts["http"])
	}
	if stats.ExecTypeCounts["file"] != 1 {
		t.Errorf("expected file=1, got %d", stats.ExecTypeCounts["file"])
	}
}

func TestComputeStats_ElevatedStages(t *testing.T) {
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell", Elevated: true}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http", Elevated: false}},
		{ID: "s3", Technique: "T1055", Tactic: "privilege-escalation", Execute: Execute{Type: "shell", Elevated: true}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if stats.ElevatedCount != 2 {
		t.Errorf("expected 2 elevated, got %d", stats.ElevatedCount)
	}
}

func TestComputeStats_DetectionCoverage(t *testing.T) {
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"rule1"}, Telemetry: []string{"proc"}}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"},
			Expect: Expect{Telemetry: []string{"net"}}},
		{ID: "s3", Technique: "T1055", Tactic: "privilege-escalation", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"rule2"}}},
		{ID: "s4", Technique: "T1070", Tactic: "defense-evasion", Execute: Execute{Type: "shell"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if stats.StagesWithDetections != 2 {
		t.Errorf("expected 2 stages with detections, got %d", stats.StagesWithDetections)
	}
	if stats.StagesWithTelemetry != 2 {
		t.Errorf("expected 2 stages with telemetry, got %d", stats.StagesWithTelemetry)
	}
	if stats.StagesWithoutEither != 1 {
		t.Errorf("expected 1 stage without either, got %d", stats.StagesWithoutEither)
	}

	expectedDetPct := 50.0
	if stats.DetectionCoverage != expectedDetPct {
		t.Errorf("expected detection coverage %.1f%%, got %.1f%%", expectedDetPct, stats.DetectionCoverage)
	}
	expectedTelPct := 50.0
	if stats.TelemetryCoverage != expectedTelPct {
		t.Errorf("expected telemetry coverage %.1f%%, got %.1f%%", expectedTelPct, stats.TelemetryCoverage)
	}
}

func TestComputeStats_VariableCounting(t *testing.T) {
	c1 := statsCampaign("c1", "A", "low", nil, map[string]string{
		"host":   "10.0.0.1",
		"domain": "evil.com",
	})
	c2 := statsCampaign("c2", "B", "low", nil, map[string]string{
		"host":    "10.0.0.2",
		"payload": "/tmp/mal.exe",
	})

	stats := ComputeStats([]*Campaign{c1, c2})

	if stats.TotalVariables != 4 {
		t.Errorf("expected 4 total variables, got %d", stats.TotalVariables)
	}
	// Unique keys: domain, host, payload (sorted).
	if len(stats.UniqueVariableKeys) != 3 {
		t.Fatalf("expected 3 unique variable keys, got %d: %v", len(stats.UniqueVariableKeys), stats.UniqueVariableKeys)
	}
	expected := []string{"domain", "host", "payload"}
	for i, k := range expected {
		if stats.UniqueVariableKeys[i] != k {
			t.Errorf("variable key[%d]: expected %s, got %s", i, k, stats.UniqueVariableKeys[i])
		}
	}
}

func TestComputeStats_CleanupCounting(t *testing.T) {
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution",
			Execute: Execute{Type: "shell", Cleanup: []string{"rm -f /tmp/a", "rm -f /tmp/b"}}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access",
			Execute: Execute{Type: "http", Cleanup: []string{"curl -X DELETE"}}},
		{ID: "s3", Technique: "T1055", Tactic: "privilege-escalation",
			Execute: Execute{Type: "shell"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if stats.TotalCleanupCmds != 3 {
		t.Errorf("expected 3 cleanup commands, got %d", stats.TotalCleanupCmds)
	}
}

func TestComputeStats_TimeoutDelay(t *testing.T) {
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution",
			Execute: Execute{Type: "shell"},
			Timeout: Duration{30 * time.Second},
			Delay:   Duration{5 * time.Second}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access",
			Execute: Execute{Type: "http"},
			Timeout: Duration{60 * time.Second}},
		{ID: "s3", Technique: "T1055", Tactic: "privilege-escalation",
			Execute: Execute{Type: "shell"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if stats.StagesWithTimeout != 2 {
		t.Errorf("expected 2 stages with timeout, got %d", stats.StagesWithTimeout)
	}
	if stats.StagesWithDelay != 1 {
		t.Errorf("expected 1 stage with delay, got %d", stats.StagesWithDelay)
	}
}

func TestComputeStats_GraphDepth(t *testing.T) {
	// Linear chain: s1 -> s2 -> s3 -> s4 (depth 4).
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", DependsOn: []string{"s1"}, Execute: Execute{Type: "http"}},
		{ID: "s3", Technique: "T1055", Tactic: "privilege-escalation", DependsOn: []string{"s2"}, Execute: Execute{Type: "shell"}},
		{ID: "s4", Technique: "T1003.001", Tactic: "credential-access", DependsOn: []string{"s3"}, Execute: Execute{Type: "shell"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if stats.MaxGraphDepth != 4 {
		t.Errorf("expected max depth 4, got %d", stats.MaxGraphDepth)
	}
	if stats.TotalDependencies != 3 {
		t.Errorf("expected 3 dependencies, got %d", stats.TotalDependencies)
	}
}

func TestComputeStats_MultiCampaignGraphDepth(t *testing.T) {
	// c1: chain of 2 (depth 2).
	c1 := statsCampaign("c1", "A", "low", []Stage{
		{ID: "a1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "a2", Technique: "T1190", Tactic: "initial-access", DependsOn: []string{"a1"}, Execute: Execute{Type: "http"}},
	}, nil)
	// c2: chain of 5 (depth 5).
	c2 := statsCampaign("c2", "B", "low", []Stage{
		{ID: "b1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "b2", Technique: "T1190", Tactic: "initial-access", DependsOn: []string{"b1"}, Execute: Execute{Type: "http"}},
		{ID: "b3", Technique: "T1055", Tactic: "privilege-escalation", DependsOn: []string{"b2"}, Execute: Execute{Type: "shell"}},
		{ID: "b4", Technique: "T1003.001", Tactic: "credential-access", DependsOn: []string{"b3"}, Execute: Execute{Type: "shell"}},
		{ID: "b5", Technique: "T1041", Tactic: "exfiltration", DependsOn: []string{"b4"}, Execute: Execute{Type: "http"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c1, c2})

	if stats.MaxGraphDepth != 5 {
		t.Errorf("expected max depth 5, got %d", stats.MaxGraphDepth)
	}
	// Average: (2 + 5) / 2 = 3.5.
	if stats.AvgGraphDepth != 3.5 {
		t.Errorf("expected avg depth 3.5, got %.1f", stats.AvgGraphDepth)
	}
}

func TestFormatStats_NonEmpty(t *testing.T) {
	c := statsCampaign("fin6", "FIN6", "critical", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution",
			Execute: Execute{Type: "shell", Commands: []string{"cmd1"}, Cleanup: []string{"cleanup1"}, Elevated: true},
			Expect:  Expect{Detections: []string{"rule1"}, Telemetry: []string{"proc"}}},
		{ID: "s2", Technique: "T1566.001", Tactic: "initial-access",
			DependsOn: []string{"s1"},
			Execute:   Execute{Type: "http"},
			Expect:    Expect{Telemetry: []string{"email"}}},
	}, map[string]string{"host": "10.0.0.1"})

	stats := ComputeStats([]*Campaign{c})
	output := FormatStats(stats)

	if output == "" {
		t.Fatal("FormatStats returned empty string")
	}

	// Verify key sections are present.
	checks := []string{
		"ThreatEcho Project Statistics",
		"Campaigns: 1",
		"Technique Analysis",
		"Tactic Distribution",
		"Execution Profile",
		"Detection Readiness",
		"Dependency Graph",
		"Content Metrics",
		"T1059.001",
		"PowerShell",
		"FIN6",
		"shell:",
		"Elevated: 1",
		"Cleanup: 1",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("FormatStats output missing %q", check)
		}
	}
}

func TestFormatStats_Nil(t *testing.T) {
	output := FormatStats(nil)
	if output != "" {
		t.Errorf("FormatStats(nil) should return empty string, got %q", output)
	}
}

func TestComputeStatsDir_TempDirectory(t *testing.T) {
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

	stats, err := ComputeStatsDir(dir)
	if err != nil {
		t.Fatalf("ComputeStatsDir failed: %v", err)
	}

	if stats.TotalCampaigns != 1 {
		t.Errorf("expected 1 campaign, got %d", stats.TotalCampaigns)
	}
	if stats.TotalStages != 1 {
		t.Errorf("expected 1 stage, got %d", stats.TotalStages)
	}
	if stats.StagesWithDetections != 1 {
		t.Errorf("expected 1 stage with detections, got %d", stats.StagesWithDetections)
	}
}

func TestComputeStatsDir_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	stats, err := ComputeStatsDir(dir)
	if err != nil {
		t.Fatalf("ComputeStatsDir failed: %v", err)
	}
	if stats.TotalCampaigns != 0 {
		t.Errorf("expected 0 campaigns, got %d", stats.TotalCampaigns)
	}
}

func TestComputeStatsDir_NonExistentDirectory(t *testing.T) {
	_, err := ComputeStatsDir("/no/such/directory/xyz")
	if err == nil {
		t.Error("expected error for non-existent directory")
	}
}

func TestComputeStats_NilCampaignInSlice(t *testing.T) {
	c := statsCampaign("c1", "APT28", "high", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
	}, nil)

	// Nil entries in the slice should be skipped gracefully.
	stats := ComputeStats([]*Campaign{c, nil, nil})
	if stats.TotalCampaigns != 3 {
		t.Errorf("expected 3 (total slice length), got %d", stats.TotalCampaigns)
	}
	// Only 1 non-nil campaign contributes stages.
	if stats.TotalStages != 1 {
		t.Errorf("expected 1 stage, got %d", stats.TotalStages)
	}
}

func TestComputeStats_TechniqueFrequencySortOrder(t *testing.T) {
	// Three techniques: T1190 used 3 times, T1059.001 used 2 times, T1003.001 used 1 time.
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s3", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s4", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s5", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s6", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if len(stats.TechniqueFrequency) != 3 {
		t.Fatalf("expected 3 techniques, got %d", len(stats.TechniqueFrequency))
	}
	if stats.TechniqueFrequency[0].TechniqueID != "T1190" {
		t.Errorf("expected first technique T1190, got %s", stats.TechniqueFrequency[0].TechniqueID)
	}
	if stats.TechniqueFrequency[0].Count != 3 {
		t.Errorf("expected first count 3, got %d", stats.TechniqueFrequency[0].Count)
	}
	if stats.TechniqueFrequency[1].TechniqueID != "T1059.001" {
		t.Errorf("expected second technique T1059.001, got %s", stats.TechniqueFrequency[1].TechniqueID)
	}
	if stats.TechniqueFrequency[2].TechniqueID != "T1003.001" {
		t.Errorf("expected third technique T1003.001, got %s", stats.TechniqueFrequency[2].TechniqueID)
	}
}

func TestComputeStats_TacticDistributionSortOrder(t *testing.T) {
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1059.003", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1059.004", Tactic: "execution", Execute: Execute{Type: "shell"}},
		{ID: "s4", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s5", Technique: "T1566.001", Tactic: "initial-access", Execute: Execute{Type: "http"}},
		{ID: "s6", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if len(stats.TacticDistribution) != 3 {
		t.Fatalf("expected 3 tactics, got %d", len(stats.TacticDistribution))
	}
	if stats.TacticDistribution[0].Tactic != "execution" || stats.TacticDistribution[0].Count != 3 {
		t.Errorf("expected first tactic execution(3), got %s(%d)",
			stats.TacticDistribution[0].Tactic, stats.TacticDistribution[0].Count)
	}
	if stats.TacticDistribution[1].Tactic != "initial-access" || stats.TacticDistribution[1].Count != 2 {
		t.Errorf("expected second tactic initial-access(2), got %s(%d)",
			stats.TacticDistribution[1].Tactic, stats.TacticDistribution[1].Count)
	}
}

func TestComputeStats_FullCoverageScenario(t *testing.T) {
	// Every stage has both detections and telemetry.
	c := statsCampaign("c1", "A", "low", []Stage{
		{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"},
			Expect: Expect{Detections: []string{"r1"}, Telemetry: []string{"t1"}}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "http"},
			Expect: Expect{Detections: []string{"r2"}, Telemetry: []string{"t2"}}},
	}, nil)

	stats := ComputeStats([]*Campaign{c})

	if stats.DetectionCoverage != 100.0 {
		t.Errorf("expected 100%% detection coverage, got %.1f%%", stats.DetectionCoverage)
	}
	if stats.TelemetryCoverage != 100.0 {
		t.Errorf("expected 100%% telemetry coverage, got %.1f%%", stats.TelemetryCoverage)
	}
	if stats.StagesWithoutEither != 0 {
		t.Errorf("expected 0 stages without either, got %d", stats.StagesWithoutEither)
	}
}

func TestRenderBar(t *testing.T) {
	// Full bar.
	bar := renderBar(10, 10, 10)
	if len([]rune(bar)) != 10 {
		t.Errorf("expected 10 runes, got %d", len([]rune(bar)))
	}
	if !strings.Contains(bar, "█") {
		t.Error("full bar should contain filled blocks")
	}

	// Empty bar.
	bar = renderBar(0, 10, 10)
	if strings.Contains(bar, "█") {
		t.Error("empty bar should not contain filled blocks")
	}

	// Zero max.
	bar = renderBar(5, 0, 10)
	if len([]rune(bar)) != 10 {
		t.Errorf("expected 10 runes for zero max, got %d", len([]rune(bar)))
	}
}
