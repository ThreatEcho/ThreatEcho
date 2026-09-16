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

// enrichTestCampaign builds a campaign with mixed stages for enrichment tests.
func enrichTestCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "apt29-enrichment-test",
			Adversary: "APT29 Cozy Bear",
			Severity:  "critical",
			Tags:      []string{"espionage"},
		},
		Stages: []Stage{
			{
				ID:        "phish",
				Name:      "Spearphishing Attachment",
				Technique: "T1566.001",
				Tactic:    "initial-access",
				Platform:  []string{"windows"},
				Execute:   Execute{Type: "shell"},
			},
			{
				ID:        "exec-ps",
				Name:      "PowerShell Execution",
				Technique: "T1059.001",
				Tactic:    "execution",
				Platform:  []string{"windows"},
				Execute:   Execute{Type: "shell"},
			},
			{
				ID:        "persist",
				Name:      "Registry Run Key",
				Technique: "T1547.001",
				Tactic:    "persistence",
				Platform:  []string{"windows"},
				Execute:   Execute{Type: "registry"},
			},
			{
				ID:        "cred-dump",
				Name:      "LSASS Memory Dump",
				Technique: "T1003.001",
				Tactic:    "credential-access",
				Platform:  []string{"windows"},
				Execute:   Execute{Type: "shell"},
			},
			{
				ID:        "exfil",
				Name:      "C2 Exfiltration",
				Technique: "T1041",
				Tactic:    "exfiltration",
				Platform:  []string{"windows", "linux"},
				Execute:   Execute{Type: "http"},
			},
		},
	}
}

func TestEnrichStage_KnownTechnique(t *testing.T) {
	stage := Stage{
		ID:        "ps-exec",
		Name:      "PowerShell Execution",
		Technique: "T1059.001",
		Tactic:    "execution",
	}

	e := EnrichStage(stage)
	if e == nil {
		t.Fatal("expected enrichment for T1059.001, got nil")
	}
	if e.TechniqueName != "PowerShell" {
		t.Errorf("TechniqueName = %q, want %q", e.TechniqueName, "PowerShell")
	}
	if e.Tactic != "execution" {
		t.Errorf("Tactic = %q, want %q", e.Tactic, "execution")
	}
	if len(e.DataSources) == 0 {
		t.Error("expected DataSources for T1059.001")
	}
	if len(e.Mitigations) == 0 {
		t.Error("expected Mitigations for T1059.001")
	}
	if e.Severity == "" {
		t.Error("expected Severity to be set")
	}
}

func TestEnrichStage_PhishingAttachment(t *testing.T) {
	stage := Stage{
		ID:        "phish",
		Technique: "T1566.001",
		Tactic:    "initial-access",
	}

	e := EnrichStage(stage)
	if e == nil {
		t.Fatal("expected enrichment, got nil")
	}
	if e.TechniqueName != "Spearphishing Attachment" {
		t.Errorf("TechniqueName = %q, want %q", e.TechniqueName, "Spearphishing Attachment")
	}
	if e.Severity != "high" {
		t.Errorf("Severity = %q, want %q for initial-access", e.Severity, "high")
	}
	// Verify real data sources are present.
	foundFileCreation := false
	for _, ds := range e.DataSources {
		if ds == "File Creation" {
			foundFileCreation = true
		}
	}
	if !foundFileCreation {
		t.Errorf("DataSources %v should contain 'File Creation'", e.DataSources)
	}
}

func TestEnrichStage_EmptyTechnique(t *testing.T) {
	stage := Stage{
		ID:   "no-technique",
		Name: "Manual Step",
	}

	e := EnrichStage(stage)
	if e != nil {
		t.Errorf("expected nil for stage without technique, got %+v", e)
	}
}

func TestEnrichStage_UnknownTechnique(t *testing.T) {
	stage := Stage{
		ID:        "unknown",
		Technique: "T9999",
		Tactic:    "execution",
	}

	e := EnrichStage(stage)
	if e == nil {
		t.Fatal("expected fallback enrichment for unknown technique, got nil")
	}
	// Unknown technique: name falls back to the ID string.
	if e.TechniqueName != "T9999" {
		t.Errorf("TechniqueName = %q, want %q (fallback to ID)", e.TechniqueName, "T9999")
	}
	if e.Tactic != "execution" {
		t.Errorf("Tactic = %q, want %q (from stage)", e.Tactic, "execution")
	}
}

func TestEnrichStage_UnknownSubTechniqueInheritsParent(t *testing.T) {
	// T1059.007 is not in our map, but T1059 is — should inherit parent enrichment.
	stage := Stage{
		ID:        "jscript",
		Technique: "T1059.007",
		Tactic:    "execution",
	}

	e := EnrichStage(stage)
	if e == nil {
		t.Fatal("expected fallback enrichment, got nil")
	}
	// Name from registry won't resolve, so falls back to ID.
	// But data sources should be inherited from T1059.
	if len(e.DataSources) == 0 {
		t.Error("expected DataSources inherited from parent T1059")
	}
	if len(e.Mitigations) == 0 {
		t.Error("expected Mitigations inherited from parent T1059")
	}
}

func TestEnrichStage_TacticFromMITRE(t *testing.T) {
	// Stage has no tactic set — should resolve from MITRE registry.
	stage := Stage{
		ID:        "ps-no-tactic",
		Technique: "T1059.001",
	}

	e := EnrichStage(stage)
	if e == nil {
		t.Fatal("expected enrichment, got nil")
	}
	if e.Tactic != "execution" {
		t.Errorf("Tactic = %q, want %q (from MITRE registry)", e.Tactic, "execution")
	}
}

func TestEnrichStage_SeverityByTactic(t *testing.T) {
	tests := []struct {
		tactic   string
		expected string
	}{
		{"initial-access", "high"},
		{"execution", "high"},
		{"persistence", "medium"},
		{"privilege-escalation", "high"},
		{"defense-evasion", "medium"},
		{"credential-access", "high"},
		{"discovery", "low"},
		{"lateral-movement", "high"},
		{"collection", "medium"},
		{"command-and-control", "medium"},
		{"exfiltration", "high"},
		{"impact", "critical"},
		{"reconnaissance", "low"},
	}

	for _, tc := range tests {
		t.Run(tc.tactic, func(t *testing.T) {
			stage := Stage{
				ID:        "sev-test",
				Technique: "T9999",
				Tactic:    tc.tactic,
			}
			e := EnrichStage(stage)
			if e == nil {
				t.Fatal("expected enrichment, got nil")
			}
			if e.Severity != tc.expected {
				t.Errorf("Severity = %q for tactic %q, want %q", e.Severity, tc.tactic, tc.expected)
			}
		})
	}
}

func TestEnrichStage_Platforms(t *testing.T) {
	stage := Stage{
		ID:        "rdp",
		Technique: "T1021.001",
		Tactic:    "lateral-movement",
	}

	e := EnrichStage(stage)
	if e == nil {
		t.Fatal("expected enrichment, got nil")
	}
	if len(e.Platforms) == 0 {
		t.Error("expected Platforms for T1021.001")
	}
	found := false
	for _, p := range e.Platforms {
		if p == "Windows" {
			found = true
		}
	}
	if !found {
		t.Errorf("Platforms %v should contain 'Windows' for RDP", e.Platforms)
	}
}

func TestEnrichStage_DetectionNotes(t *testing.T) {
	stage := Stage{
		ID:        "lsass",
		Technique: "T1003.001",
		Tactic:    "credential-access",
	}

	e := EnrichStage(stage)
	if e == nil {
		t.Fatal("expected enrichment, got nil")
	}
	if e.DetectionNotes == "" {
		t.Error("expected DetectionNotes for T1003.001")
	}
	if !strings.Contains(e.DetectionNotes, "lsass") {
		t.Errorf("DetectionNotes should mention lsass, got %q", e.DetectionNotes)
	}
}

func TestEnrichStage_ImpactSeverity(t *testing.T) {
	stage := Stage{
		ID:        "ransomware",
		Technique: "T1486",
		Tactic:    "impact",
	}

	e := EnrichStage(stage)
	if e == nil {
		t.Fatal("expected enrichment, got nil")
	}
	if e.Severity != "critical" {
		t.Errorf("Severity = %q, want %q for impact", e.Severity, "critical")
	}
	if e.TechniqueName != "Data Encrypted for Impact" {
		t.Errorf("TechniqueName = %q, want %q", e.TechniqueName, "Data Encrypted for Impact")
	}
}

func TestEnrichCampaign_FullCampaign(t *testing.T) {
	c := enrichTestCampaign()
	result := EnrichCampaign(c)

	if result.CampaignName != "apt29-enrichment-test" {
		t.Errorf("CampaignName = %q, want %q", result.CampaignName, "apt29-enrichment-test")
	}
	if result.TotalStages != 5 {
		t.Errorf("TotalStages = %d, want 5", result.TotalStages)
	}
	if result.EnrichedCount != 5 {
		t.Errorf("EnrichedCount = %d, want 5", result.EnrichedCount)
	}
	if result.SkippedCount != 0 {
		t.Errorf("SkippedCount = %d, want 0", result.SkippedCount)
	}
	if len(result.Stages) != 5 {
		t.Fatalf("len(Stages) = %d, want 5", len(result.Stages))
	}

	// Verify each stage has enrichment.
	for i, es := range result.Stages {
		if es.Enrichment == nil {
			t.Errorf("stage %d (%s) has nil enrichment", i, es.Stage.ID)
		}
	}
}

func TestEnrichCampaign_WithSkippedStages(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "mixed"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059.001", Tactic: "execution"},
			{ID: "s2", Name: "Manual Step"},
			{ID: "s3", Technique: "T1041", Tactic: "exfiltration"},
		},
	}

	result := EnrichCampaign(c)
	if result.TotalStages != 3 {
		t.Errorf("TotalStages = %d, want 3", result.TotalStages)
	}
	if result.EnrichedCount != 2 {
		t.Errorf("EnrichedCount = %d, want 2", result.EnrichedCount)
	}
	if result.SkippedCount != 1 {
		t.Errorf("SkippedCount = %d, want 1", result.SkippedCount)
	}
	if result.Stages[1].Enrichment != nil {
		t.Error("stage s2 should have nil enrichment (no technique)")
	}
}

func TestEnrichCampaign_NilCampaign(t *testing.T) {
	result := EnrichCampaign(nil)
	if result == nil {
		t.Fatal("expected non-nil result for nil campaign")
	}
	if result.TotalStages != 0 {
		t.Errorf("TotalStages = %d, want 0", result.TotalStages)
	}
	if result.EnrichedCount != 0 {
		t.Errorf("EnrichedCount = %d, want 0", result.EnrichedCount)
	}
}

func TestEnrichCampaign_EmptyStages(t *testing.T) {
	c := &Campaign{
		Meta:   Meta{Name: "empty"},
		Stages: nil,
	}
	result := EnrichCampaign(c)
	if result.TotalStages != 0 {
		t.Errorf("TotalStages = %d, want 0", result.TotalStages)
	}
	if len(result.Stages) != 0 {
		t.Errorf("len(Stages) = %d, want 0", len(result.Stages))
	}
}

func TestEnrichCampaign_PreservesStageData(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "preserve"},
		Stages: []Stage{
			{
				ID:          "s1",
				Name:        "Test Stage",
				Description: "A test description",
				Technique:   "T1059.001",
				Tactic:      "execution",
				Platform:    []string{"windows"},
				Execute:     Execute{Type: "shell", Commands: []string{"whoami"}},
			},
		},
	}

	result := EnrichCampaign(c)
	es := result.Stages[0]
	if es.Stage.ID != "s1" {
		t.Errorf("Stage.ID = %q, want %q", es.Stage.ID, "s1")
	}
	if es.Stage.Name != "Test Stage" {
		t.Errorf("Stage.Name = %q, want %q", es.Stage.Name, "Test Stage")
	}
	if es.Stage.Description != "A test description" {
		t.Errorf("Stage.Description preserved incorrectly")
	}
	if len(es.Stage.Execute.Commands) != 1 || es.Stage.Execute.Commands[0] != "whoami" {
		t.Errorf("Stage.Execute.Commands not preserved")
	}
}

func TestEnrichDir(t *testing.T) {
	dir := t.TempDir()

	writeTestCampaignYAML(t, dir, "apt29", `
api_version: v1
kind: Campaign
meta:
  name: apt29-cozy-bear
  adversary: APT29
  severity: critical
  created: "2026-01-01"
  modified: "2026-01-01"
stages:
  - id: phish
    name: Spearphishing
    technique: T1566.001
    tactic: initial-access
    platform: [windows]
    execute:
      type: shell
  - id: exec
    name: PowerShell
    technique: T1059.001
    tactic: execution
    platform: [windows]
    execute:
      type: shell
`)

	writeTestCampaignYAML(t, dir, "lazarus", `
api_version: v1
kind: Campaign
meta:
  name: lazarus-group
  adversary: Lazarus Group
  severity: high
  created: "2026-01-01"
  modified: "2026-01-01"
stages:
  - id: supply-chain
    name: Supply Chain
    technique: T1195.002
    tactic: initial-access
    platform: [linux]
    execute:
      type: shell
`)

	results, err := EnrichDir(dir)
	if err != nil {
		t.Fatalf("EnrichDir error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Check total enriched stages across campaigns.
	totalEnriched := 0
	for _, r := range results {
		totalEnriched += r.EnrichedCount
	}
	if totalEnriched != 3 {
		t.Errorf("total enriched = %d, want 3", totalEnriched)
	}
}

func TestEnrichDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	results, err := EnrichDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty dir, got %d", len(results))
	}
}

func TestEnrichDir_NonexistentDir(t *testing.T) {
	_, err := EnrichDir("/nonexistent/path/for/enrich/test")
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

func TestEnrichDir_SkipsInvalidYAML(t *testing.T) {
	dir := t.TempDir()

	// Write a valid campaign.
	writeTestCampaignYAML(t, dir, "valid", `
api_version: v1
kind: Campaign
meta:
  name: valid-campaign
  created: "2026-01-01"
  modified: "2026-01-01"
stages:
  - id: s1
    name: Stage One
    technique: T1059.001
    tactic: execution
    execute:
      type: shell
`)

	// Write invalid YAML.
	invalidDir := filepath.Join(dir, "invalid")
	if err := os.MkdirAll(invalidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(invalidDir, "campaign.yaml"), []byte("{{invalid yaml"), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := EnrichDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should only get the valid campaign.
	if len(results) != 1 {
		t.Fatalf("expected 1 result (skipping invalid), got %d", len(results))
	}
	if results[0].CampaignName != "valid-campaign" {
		t.Errorf("CampaignName = %q, want %q", results[0].CampaignName, "valid-campaign")
	}
}

func TestFormatEnrichment_NonEmpty(t *testing.T) {
	c := enrichTestCampaign()
	result := EnrichCampaign(c)
	out := FormatEnrichment([]*EnrichResult{result})

	if len(out) == 0 {
		t.Fatal("FormatEnrichment returned empty string")
	}
	if !strings.Contains(out, "apt29-enrichment-test") {
		t.Error("output should contain campaign name")
	}
	if !strings.Contains(out, "T1059.001") {
		t.Error("output should contain technique ID")
	}
	if !strings.Contains(out, "PowerShell") {
		t.Error("output should contain technique name")
	}
	if !strings.Contains(out, "enriched") {
		t.Error("output should contain enriched count")
	}
	if !strings.Contains(out, "─") {
		t.Error("output should contain separator")
	}
}

func TestFormatEnrichment_Empty(t *testing.T) {
	out := FormatEnrichment(nil)
	if !strings.Contains(out, "No enrichment") {
		t.Errorf("empty results should say 'No enrichment', got %q", out)
	}
}

func TestFormatEnrichment_EmptySlice(t *testing.T) {
	out := FormatEnrichment([]*EnrichResult{})
	if !strings.Contains(out, "No enrichment") {
		t.Errorf("empty slice should say 'No enrichment', got %q", out)
	}
}

func TestFormatEnrichment_WithSkippedStages(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "mixed-format"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059.001", Tactic: "execution"},
			{ID: "s2", Name: "Manual"},
		},
	}
	result := EnrichCampaign(c)
	out := FormatEnrichment([]*EnrichResult{result})

	if !strings.Contains(out, "skipped") {
		t.Error("output should mention skipped stages")
	}
	if !strings.Contains(out, "no technique ID") {
		t.Error("output should explain why stage was skipped")
	}
}

func TestFormatEnrichment_MultiCampaign(t *testing.T) {
	c1 := &Campaign{
		Meta:   Meta{Name: "campaign-one"},
		Stages: []Stage{{ID: "s1", Technique: "T1059.001", Tactic: "execution"}},
	}
	c2 := &Campaign{
		Meta:   Meta{Name: "campaign-two"},
		Stages: []Stage{{ID: "s2", Technique: "T1041", Tactic: "exfiltration"}},
	}
	out := FormatEnrichment([]*EnrichResult{EnrichCampaign(c1), EnrichCampaign(c2)})

	if !strings.Contains(out, "campaign-one") {
		t.Error("output should contain campaign-one")
	}
	if !strings.Contains(out, "campaign-two") {
		t.Error("output should contain campaign-two")
	}
}

func TestFormatEnrichment_NilResult(t *testing.T) {
	// Should not panic on nil entries in the slice.
	out := FormatEnrichment([]*EnrichResult{nil})
	// Should produce something without panicking.
	if out == "" {
		t.Error("output should not be empty")
	}
}

func TestEnrichStage_DataSourcesCopied(t *testing.T) {
	stage := Stage{
		ID:        "copy-test",
		Technique: "T1059.001",
		Tactic:    "execution",
	}

	e1 := EnrichStage(stage)
	e2 := EnrichStage(stage)
	if e1 == nil || e2 == nil {
		t.Fatal("expected non-nil enrichments")
	}

	// Mutate one — the other should be unaffected.
	if len(e1.DataSources) > 0 {
		e1.DataSources[0] = "MUTATED"
	}
	if len(e2.DataSources) > 0 && e2.DataSources[0] == "MUTATED" {
		t.Error("DataSources slices should be independent copies")
	}
}

func TestEnrichStage_AllMapEntries(t *testing.T) {
	// Verify every entry in the enrichment map produces valid data.
	for id := range techniqueEnrichment {
		t.Run(id, func(t *testing.T) {
			stage := Stage{
				ID:        "map-" + id,
				Technique: id,
			}
			e := EnrichStage(stage)
			if e == nil {
				t.Fatal("expected enrichment, got nil")
			}
			if e.TechniqueName == "" {
				t.Error("TechniqueName should not be empty")
			}
			if e.Severity == "" {
				t.Error("Severity should not be empty")
			}
		})
	}
}

func TestParentTechnique(t *testing.T) {
	tests := []struct {
		id     string
		parent string
	}{
		{"T1059.001", "T1059"},
		{"T1566.001", "T1566"},
		{"T1059", ""},
		{"T1486", ""},
		{"", ""},
	}
	for _, tc := range tests {
		got := parentTechnique(tc.id)
		if got != tc.parent {
			t.Errorf("parentTechnique(%q) = %q, want %q", tc.id, got, tc.parent)
		}
	}
}

func TestInferSeverity(t *testing.T) {
	if got := inferSeverity("impact"); got != "critical" {
		t.Errorf("inferSeverity(impact) = %q, want %q", got, "critical")
	}
	if got := inferSeverity("discovery"); got != "low" {
		t.Errorf("inferSeverity(discovery) = %q, want %q", got, "low")
	}
	if got := inferSeverity("unknown-tactic"); got != "medium" {
		t.Errorf("inferSeverity(unknown) = %q, want %q (default)", got, "medium")
	}
}
