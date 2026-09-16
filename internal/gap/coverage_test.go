// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package gap

import (
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/engine"
)

func TestAnalyzeCoverage_Empty(t *testing.T) {
	cr := AnalyzeCoverage()

	if cr.TechniquesExercised != 0 {
		t.Errorf("expected 0 exercised, got %d", cr.TechniquesExercised)
	}
	if cr.TotalTechniquesInRegistry == 0 {
		t.Error("expected non-zero registry size")
	}
	if len(cr.TechniquesUncovered) != cr.TotalTechniquesInRegistry {
		t.Errorf("all %d techniques should be uncovered, got %d",
			cr.TotalTechniquesInRegistry, len(cr.TechniquesUncovered))
	}
	if cr.ByFramework.ATTACKTotal == 0 {
		t.Error("expected non-zero ATT&CK total")
	}
}

func TestAnalyzeCoverage_SingleCampaign(t *testing.T) {
	c, r := attackCoverageTestCampaign()
	_ = c
	cr := AnalyzeCoverage(r)

	if cr.TechniquesExercised != 2 {
		t.Errorf("expected 2 exercised techniques, got %d", cr.TechniquesExercised)
	}
	if cr.TechniquesWithDetections != 1 {
		t.Errorf("expected 1 technique with detections, got %d", cr.TechniquesWithDetections)
	}
	if cr.TechniquesWithTelemetry != 2 {
		t.Errorf("expected 2 techniques with telemetry, got %d", cr.TechniquesWithTelemetry)
	}

	// Check by-tactic map.
	if len(cr.TechniquesByTactic) != 2 {
		t.Errorf("expected 2 tactics with techniques, got %d", len(cr.TechniquesByTactic))
	}
	disc, ok := cr.TechniquesByTactic["discovery"]
	if !ok || len(disc) != 1 {
		t.Error("expected 1 technique under discovery tactic")
	}

	// Uncovered count should be total - 2.
	if len(cr.TechniquesUncovered) != cr.TotalTechniquesInRegistry-2 {
		t.Errorf("expected %d uncovered, got %d",
			cr.TotalTechniquesInRegistry-2, len(cr.TechniquesUncovered))
	}
}

func TestAnalyzeCoverage_MultiCampaign(t *testing.T) {
	_, r1 := attackCoverageTestCampaign()
	_, r2 := secondCoverageTestCampaign()

	cr := AnalyzeCoverage(r1, r2)

	// T1016 appears in both campaigns, T1190 in first only, T1059.001 in second only.
	if cr.TechniquesExercised != 3 {
		t.Errorf("expected 3 exercised techniques, got %d", cr.TechniquesExercised)
	}

	// T1016 should show 2 campaigns.
	found := false
	for _, tc := range cr.Techniques {
		if tc.TechniqueID == "T1016" {
			found = true
			if tc.CampaignCount != 2 {
				t.Errorf("T1016 should be in 2 campaigns, got %d", tc.CampaignCount)
			}
			if len(tc.Campaigns) != 2 {
				t.Errorf("T1016 should list 2 campaign names, got %d", len(tc.Campaigns))
			}
		}
	}
	if !found {
		t.Error("T1016 not found in coverage results")
	}
}

func TestAnalyzeCoverage_OverlappingTechniques(t *testing.T) {
	_, r1 := attackCoverageTestCampaign()
	_, r2 := secondCoverageTestCampaign()

	cr := AnalyzeCoverage(r1, r2)

	// T1016: first campaign has telemetry only, second adds detections.
	// Merged result should show both.
	for _, tc := range cr.Techniques {
		if tc.TechniqueID == "T1016" {
			if !tc.HasTelemetry {
				t.Error("T1016 should have telemetry (from both campaigns)")
			}
			if !tc.HasDetections {
				t.Error("T1016 should have detections (from second campaign)")
			}
			if tc.Status != "full" {
				t.Errorf("T1016 should be 'full', got %q", tc.Status)
			}
		}
	}
}

func TestTechniqueCoverageStatus(t *testing.T) {
	tests := []struct {
		tel  bool
		det  bool
		want string
	}{
		{true, true, "full"},
		{true, false, "telemetry-only"},
		{false, true, "partial"},
		{false, false, "uncovered"},
	}
	for _, tt := range tests {
		got := computeStatus(tt.tel, tt.det)
		if got != tt.want {
			t.Errorf("computeStatus(%v, %v) = %q, want %q", tt.tel, tt.det, got, tt.want)
		}
	}
}

func TestFrameworkCoverage(t *testing.T) {
	c := &campaign.Campaign{
		APIVersion: "v1", Kind: "Campaign",
		Meta: campaign.Meta{Name: "mixed", Adversary: "Test", Severity: "high"},
		Stages: []campaign.Stage{
			{ID: "s1", Name: "ATT&CK", Technique: "T1016", Tactic: "discovery",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"process_create"}}},
			{ID: "s2", Name: "ATLAS", Technique: "AML.T0051", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "http"},
				Expect:  campaign.Expect{Telemetry: []string{"prompt_log"}}},
			{ID: "s3", Name: "OWASP", Technique: "LLM06", Tactic: "ml-model-access",
				Execute: campaign.Execute{Type: "http"},
				Expect:  campaign.Expect{Telemetry: []string{"tool_call"}}},
		},
	}
	r := makeResult(c, makeCoverageStageResults(c.Stages))
	cr := AnalyzeCoverage(r)

	if cr.ByFramework.ATTACKCovered != 1 {
		t.Errorf("expected 1 ATT&CK covered, got %d", cr.ByFramework.ATTACKCovered)
	}
	if cr.ByFramework.ATLASCovered != 1 {
		t.Errorf("expected 1 ATLAS covered, got %d", cr.ByFramework.ATLASCovered)
	}
	if cr.ByFramework.OWASPCovered != 1 {
		t.Errorf("expected 1 OWASP covered, got %d", cr.ByFramework.OWASPCovered)
	}
}

func TestUncoveredContainsSpecificTechnique(t *testing.T) {
	// Exercise only T1016.
	c, r := attackCoverageTestCampaign()
	_ = c
	cr := AnalyzeCoverage(r)

	// T1190 should still be in the covered set (campaign has it).
	// T1059.001 should be uncovered.
	found := false
	for _, ref := range cr.TechniquesUncovered {
		if ref.ID == "T1059.001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("T1059.001 should be in uncovered list")
	}

	// T1016 should NOT be in uncovered.
	for _, ref := range cr.TechniquesUncovered {
		if ref.ID == "T1016" {
			t.Error("T1016 should not be in uncovered list")
		}
	}
}

func TestSetToSorted(t *testing.T) {
	m := map[string]bool{"c": true, "a": true, "b": true}
	got := setToSorted(m)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("expected [a b c], got %v", got)
	}
}

// --- test helpers ---

func attackCoverageTestCampaign() (*campaign.Campaign, *engine.RunResult) {
	c := &campaign.Campaign{
		APIVersion: "v1", Kind: "Campaign",
		Meta: campaign.Meta{Name: "cov-test-1", Adversary: "TestActor", Severity: "high"},
		Stages: []campaign.Stage{
			{
				ID: "recon", Name: "Recon", Technique: "T1016", Tactic: "discovery",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"process_create", "network_connection"}},
			},
			{
				ID: "access", Name: "Access", Technique: "T1190", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"network_connection"}, Detections: []string{"exploit_detected"}},
			},
		},
	}
	r := makeResult(c, makeCoverageStageResults(c.Stages))
	return c, r
}

func secondCoverageTestCampaign() (*campaign.Campaign, *engine.RunResult) {
	c := &campaign.Campaign{
		APIVersion: "v1", Kind: "Campaign",
		Meta: campaign.Meta{Name: "cov-test-2", Adversary: "TestActor2", Severity: "medium"},
		Stages: []campaign.Stage{
			{
				ID: "scan", Name: "Scan", Technique: "T1016", Tactic: "discovery",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"process_create"}, Detections: []string{"scan_detected"}},
			},
			{
				ID: "exec", Name: "Execute", Technique: "T1059.001", Tactic: "execution",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"process_create", "script_execution"}, Detections: []string{"powershell_detected"}},
			},
		},
	}
	r := makeResult(c, makeCoverageStageResults(c.Stages))
	return c, r
}

func makeCoverageStageResults(stages []campaign.Stage) []engine.StageResult {
	var srs []engine.StageResult
	for i, s := range stages {
		srs = append(srs, simpleStageResult(s, i+1))
	}
	return srs
}
