// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildBaseline_Empty(t *testing.T) {
	b := BuildBaseline(nil, "empty")
	if b.Campaigns != 0 {
		t.Errorf("expected 0 campaigns, got %d", b.Campaigns)
	}
	if b.Stages != 0 {
		t.Errorf("expected 0 stages, got %d", b.Stages)
	}
	if b.Label != "empty" {
		t.Errorf("expected label 'empty', got %q", b.Label)
	}
}

func TestBuildBaseline_SingleCampaign(t *testing.T) {
	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:     "test-campaign",
			Severity: "high",
			Tags:     []string{"ai-security", "llm"},
		},
		Stages: []Stage{
			{
				ID:        "s1",
				Technique: "T1059.001",
				Tactic:    "execution",
				Execute:   Execute{Type: "shell", Elevated: true},
				Expect:    Expect{Telemetry: []string{"process_create"}, Detections: []string{"powershell_exec"}},
			},
			{
				ID:        "s2",
				Technique: "T1071.001",
				Tactic:    "command-and-control",
				Execute:   Execute{Type: "http"},
				Platform:  []string{"windows", "linux"},
				Expect:    Expect{Telemetry: []string{"network_connection"}, Detections: []string{"c2_beacon"}},
			},
		},
	}

	b := BuildBaseline([]*Campaign{c}, "single-test")

	if b.Campaigns != 1 {
		t.Errorf("expected 1 campaign, got %d", b.Campaigns)
	}
	if b.Stages != 2 {
		t.Errorf("expected 2 stages, got %d", b.Stages)
	}
	if b.Elevated != 1 {
		t.Errorf("expected 1 elevated, got %d", b.Elevated)
	}
	if b.Tactics["execution"] != 1 {
		t.Errorf("expected execution tactic count 1, got %d", b.Tactics["execution"])
	}
	if b.Techniques["T1059.001"] != 1 {
		t.Errorf("expected T1059.001 count 1, got %d", b.Techniques["T1059.001"])
	}
	if b.ExecTypes["shell"] != 1 {
		t.Errorf("expected shell exec type count 1, got %d", b.ExecTypes["shell"])
	}
	if b.Severities["high"] != 1 {
		t.Errorf("expected high severity count 1, got %d", b.Severities["high"])
	}
	if b.Tags["ai-security"] != 1 {
		t.Errorf("expected ai-security tag count 1, got %d", b.Tags["ai-security"])
	}
	if b.Platforms["windows"] != 1 {
		t.Errorf("expected windows count 1, got %d", b.Platforms["windows"])
	}
	if b.Tools["shell_exec"] != 1 {
		t.Errorf("expected shell_exec count 1, got %d", b.Tools["shell_exec"])
	}
	if b.AvgStages != 2.0 {
		t.Errorf("expected avg stages 2.0, got %.1f", b.AvgStages)
	}
}

func TestBuildBaseline_MultipleCampaigns(t *testing.T) {
	c1 := &Campaign{
		Meta: Meta{Name: "camp1", Severity: "high"},
		Stages: []Stage{
			{ID: "s1", Tactic: "execution", Technique: "T1059", Execute: Execute{Type: "shell"}},
			{ID: "s2", Tactic: "discovery", Technique: "T1082", Execute: Execute{Type: "shell"}},
		},
	}
	c2 := &Campaign{
		Meta: Meta{Name: "camp2", Severity: "critical"},
		Stages: []Stage{
			{ID: "s1", Tactic: "execution", Technique: "T1059", Execute: Execute{Type: "shell"}},
			{ID: "s2", Tactic: "exfiltration", Technique: "T1041", Execute: Execute{Type: "http"}},
			{ID: "s3", Tactic: "impact", Technique: "T1486", Execute: Execute{Type: "shell"}},
		},
	}

	b := BuildBaseline([]*Campaign{c1, c2}, "multi")
	if b.Campaigns != 2 {
		t.Errorf("expected 2 campaigns, got %d", b.Campaigns)
	}
	if b.Stages != 5 {
		t.Errorf("expected 5 stages, got %d", b.Stages)
	}
	if b.MaxStages != 3 {
		t.Errorf("expected max 3 stages, got %d", b.MaxStages)
	}
	if b.MinStages != 2 {
		t.Errorf("expected min 2 stages, got %d", b.MinStages)
	}
	if b.Tactics["execution"] != 2 {
		t.Errorf("expected execution count 2, got %d", b.Tactics["execution"])
	}
	if b.AvgStages != 2.5 {
		t.Errorf("expected avg 2.5, got %.1f", b.AvgStages)
	}
}

func TestBuildBaseline_NilCampaignInSlice(t *testing.T) {
	c := &Campaign{
		Meta:   Meta{Name: "valid"},
		Stages: []Stage{{ID: "s1", Tactic: "execution"}},
	}
	b := BuildBaseline([]*Campaign{c, nil}, "with-nil")
	if b.Campaigns != 2 {
		t.Errorf("expected 2 campaigns (count includes nil), got %d", b.Campaigns)
	}
	if b.Stages != 1 {
		t.Errorf("expected 1 stage, got %d", b.Stages)
	}
}

func TestBuildBaseline_FingerprintsDeterministic(t *testing.T) {
	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       Meta{Name: "fp-test", Severity: "low"},
		Stages:     []Stage{{ID: "s1", Tactic: "discovery", Technique: "T1082", Execute: Execute{Type: "shell"}}},
	}

	b1 := BuildBaseline([]*Campaign{c}, "first")
	b2 := BuildBaseline([]*Campaign{c}, "second")

	if b1.Fingerprints["fp-test"] != b2.Fingerprints["fp-test"] {
		t.Error("fingerprints should be deterministic")
	}
	if b1.Fingerprints["fp-test"] == "" {
		t.Error("fingerprint should not be empty")
	}
}

func TestDetectDrift_NoDrift(t *testing.T) {
	campaigns := []*Campaign{
		{
			APIVersion: "v1",
			Kind:       "Campaign",
			Meta:       Meta{Name: "stable", Severity: "medium"},
			Stages: []Stage{
				{ID: "s1", Tactic: "execution", Technique: "T1059", Execute: Execute{Type: "shell"}},
			},
		},
	}

	baseline := BuildBaseline(campaigns, "baseline")
	dr := DetectDrift(baseline, campaigns)

	if dr.DriftScore != 0 {
		t.Errorf("expected drift score 0, got %.2f", dr.DriftScore)
	}
	if dr.DriftLevel != "none" {
		t.Errorf("expected drift level 'none', got %q", dr.DriftLevel)
	}
	if len(dr.NewCampaigns) != 0 {
		t.Errorf("expected no new campaigns, got %v", dr.NewCampaigns)
	}
	if len(dr.RemovedCampaigns) != 0 {
		t.Errorf("expected no removed campaigns, got %v", dr.RemovedCampaigns)
	}
}

func TestDetectDrift_NewCampaign(t *testing.T) {
	original := []*Campaign{
		{Meta: Meta{Name: "camp-a"}, Stages: []Stage{{ID: "s1", Tactic: "execution", Technique: "T1059"}}},
	}
	baseline := BuildBaseline(original, "v1")

	current := []*Campaign{
		{Meta: Meta{Name: "camp-a"}, Stages: []Stage{{ID: "s1", Tactic: "execution", Technique: "T1059"}}},
		{Meta: Meta{Name: "camp-b"}, Stages: []Stage{{ID: "s1", Tactic: "impact", Technique: "T1486"}}},
	}

	dr := DetectDrift(baseline, current)
	if len(dr.NewCampaigns) != 1 || dr.NewCampaigns[0] != "camp-b" {
		t.Errorf("expected new campaign 'camp-b', got %v", dr.NewCampaigns)
	}
	if dr.DriftScore == 0 {
		t.Error("expected non-zero drift score")
	}
}

func TestDetectDrift_RemovedCampaign(t *testing.T) {
	original := []*Campaign{
		{Meta: Meta{Name: "camp-a"}, Stages: []Stage{{ID: "s1", Tactic: "execution"}}},
		{Meta: Meta{Name: "camp-b"}, Stages: []Stage{{ID: "s1", Tactic: "impact"}}},
	}
	baseline := BuildBaseline(original, "v1")

	current := []*Campaign{
		{Meta: Meta{Name: "camp-a"}, Stages: []Stage{{ID: "s1", Tactic: "execution"}}},
	}

	dr := DetectDrift(baseline, current)
	if len(dr.RemovedCampaigns) != 1 || dr.RemovedCampaigns[0] != "camp-b" {
		t.Errorf("expected removed campaign 'camp-b', got %v", dr.RemovedCampaigns)
	}
}

func TestDetectDrift_ModifiedCampaign(t *testing.T) {
	original := []*Campaign{
		{
			APIVersion: "v1",
			Kind:       "Campaign",
			Meta:       Meta{Name: "camp-a", Severity: "low"},
			Stages:     []Stage{{ID: "s1", Tactic: "execution", Technique: "T1059", Execute: Execute{Type: "shell"}}},
		},
	}
	baseline := BuildBaseline(original, "v1")

	modified := []*Campaign{
		{
			APIVersion: "v1",
			Kind:       "Campaign",
			Meta:       Meta{Name: "camp-a", Severity: "high"}, // severity changed
			Stages:     []Stage{{ID: "s1", Tactic: "execution", Technique: "T1059", Execute: Execute{Type: "shell"}}},
		},
	}

	dr := DetectDrift(baseline, modified)
	if len(dr.ModifiedCampaigns) != 1 || dr.ModifiedCampaigns[0] != "camp-a" {
		t.Errorf("expected modified campaign 'camp-a', got %v", dr.ModifiedCampaigns)
	}
}

func TestDetectDrift_NewTechnique(t *testing.T) {
	original := []*Campaign{
		{Meta: Meta{Name: "c1"}, Stages: []Stage{{ID: "s1", Technique: "T1059", Tactic: "execution"}}},
	}
	baseline := BuildBaseline(original, "v1")

	current := []*Campaign{
		{Meta: Meta{Name: "c1"}, Stages: []Stage{
			{ID: "s1", Technique: "T1059", Tactic: "execution"},
			{ID: "s2", Technique: "AML.T0051", Tactic: "initial-access"},
		}},
	}

	dr := DetectDrift(baseline, current)
	if len(dr.NewTechniques) != 1 || dr.NewTechniques[0] != "AML.T0051" {
		t.Errorf("expected new technique AML.T0051, got %v", dr.NewTechniques)
	}
}

func TestDetectDrift_SeverityShift(t *testing.T) {
	original := []*Campaign{
		{Meta: Meta{Name: "c1", Severity: "low"}, Stages: []Stage{{ID: "s1"}}},
		{Meta: Meta{Name: "c2", Severity: "low"}, Stages: []Stage{{ID: "s1"}}},
	}
	baseline := BuildBaseline(original, "v1")

	current := []*Campaign{
		{Meta: Meta{Name: "c1", Severity: "critical"}, Stages: []Stage{{ID: "s1"}}},
		{Meta: Meta{Name: "c2", Severity: "low"}, Stages: []Stage{{ID: "s1"}}},
	}

	dr := DetectDrift(baseline, current)
	if len(dr.SeverityShifts) == 0 {
		t.Fatal("expected severity shifts")
	}
	found := false
	for _, ss := range dr.SeverityShifts {
		if ss.Severity == "critical" && ss.Delta == 1 {
			found = true
		}
	}
	if !found {
		t.Error("expected critical severity shift +1")
	}
}

func TestDetectDrift_StageCountDelta(t *testing.T) {
	original := []*Campaign{
		{Meta: Meta{Name: "c1"}, Stages: []Stage{{ID: "s1"}, {ID: "s2"}}},
	}
	baseline := BuildBaseline(original, "v1")

	current := []*Campaign{
		{Meta: Meta{Name: "c1"}, Stages: []Stage{{ID: "s1"}, {ID: "s2"}, {ID: "s3"}, {ID: "s4"}}},
	}

	dr := DetectDrift(baseline, current)
	if dr.StageCountDelta != 2 {
		t.Errorf("expected stage delta +2, got %d", dr.StageCountDelta)
	}
}

func TestDetectDrift_EmptyBaseline(t *testing.T) {
	baseline := BuildBaseline(nil, "empty")
	current := []*Campaign{
		{Meta: Meta{Name: "new"}, Stages: []Stage{{ID: "s1", Tactic: "execution"}}},
	}

	dr := DetectDrift(baseline, current)
	if len(dr.NewCampaigns) != 1 {
		t.Errorf("expected 1 new campaign, got %d", len(dr.NewCampaigns))
	}
	if dr.DriftLevel == "none" {
		t.Error("expected some drift from empty baseline")
	}
}

func TestDetectDrift_DriftScore_Ranges(t *testing.T) {
	tests := []struct {
		name  string
		score float64
		level string
	}{
		{"zero", 0.0, "none"},
		{"very-low", 0.05, "low"},
		{"low", 0.1, "low"},
		{"medium", 0.2, "medium"},
		{"high", 0.5, "high"},
		{"critical", 0.8, "critical"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyDrift(tt.score)
			if got != tt.level {
				t.Errorf("classifyDrift(%.2f) = %q, want %q", tt.score, got, tt.level)
			}
		})
	}
}

func TestBaselineJSON_RoundTrip(t *testing.T) {
	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       Meta{Name: "json-test", Severity: "high"},
		Stages: []Stage{
			{ID: "s1", Tactic: "execution", Technique: "T1059", Execute: Execute{Type: "shell", Elevated: true}},
		},
	}

	b := BuildBaseline([]*Campaign{c}, "json-roundtrip")

	data, err := BaselineToJSON(b)
	if err != nil {
		t.Fatalf("BaselineToJSON: %v", err)
	}

	restored, err := BaselineFromJSON(data)
	if err != nil {
		t.Fatalf("BaselineFromJSON: %v", err)
	}

	if restored.Label != b.Label {
		t.Errorf("label mismatch: %q vs %q", restored.Label, b.Label)
	}
	if restored.Campaigns != b.Campaigns {
		t.Errorf("campaigns mismatch: %d vs %d", restored.Campaigns, b.Campaigns)
	}
	if restored.Stages != b.Stages {
		t.Errorf("stages mismatch: %d vs %d", restored.Stages, b.Stages)
	}
	if restored.Elevated != b.Elevated {
		t.Errorf("elevated mismatch: %d vs %d", restored.Elevated, b.Elevated)
	}
	if restored.Fingerprints["json-test"] != b.Fingerprints["json-test"] {
		t.Error("fingerprint mismatch after round-trip")
	}
}

func TestBaselineFromJSON_InvalidJSON(t *testing.T) {
	_, err := BaselineFromJSON([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBaselineFile_RoundTrip(t *testing.T) {
	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       Meta{Name: "file-test"},
		Stages:     []Stage{{ID: "s1", Tactic: "discovery"}},
	}

	b := BuildBaseline([]*Campaign{c}, "file-roundtrip")
	data, err := BaselineToJSON(b)
	if err != nil {
		t.Fatalf("BaselineToJSON: %v", err)
	}

	tmp := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	restored, err := BaselineFromFile(tmp)
	if err != nil {
		t.Fatalf("BaselineFromFile: %v", err)
	}

	if restored.Label != "file-roundtrip" {
		t.Errorf("expected label 'file-roundtrip', got %q", restored.Label)
	}
}

func TestBaselineFromFile_NotFound(t *testing.T) {
	_, err := BaselineFromFile("/nonexistent/baseline.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestBuildBaselineDir(t *testing.T) {
	dir := t.TempDir()

	// Create a campaign subdirectory.
	campDir := filepath.Join(dir, "test-camp")
	os.MkdirAll(campDir, 0755)

	yaml := `api_version: v1
kind: Campaign
meta:
  name: dir-test
  severity: medium
stages:
  - id: s1
    name: test
    technique: T1059
    tactic: execution
    execute:
      type: shell
      commands: ["echo test"]
`
	os.WriteFile(filepath.Join(campDir, "campaign.yaml"), []byte(yaml), 0644)

	b, err := BuildBaselineDir(dir, "dir-baseline")
	if err != nil {
		t.Fatalf("BuildBaselineDir: %v", err)
	}
	if b.Campaigns != 1 {
		t.Errorf("expected 1 campaign, got %d", b.Campaigns)
	}
	if b.Label != "dir-baseline" {
		t.Errorf("expected label 'dir-baseline', got %q", b.Label)
	}
}

func TestFormatBaseline_ContainsSections(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "fmt-test", Severity: "high"},
		Stages: []Stage{
			{ID: "s1", Tactic: "execution", Technique: "T1059", Execute: Execute{Type: "shell", Elevated: true}},
			{ID: "s2", Tactic: "impact", Technique: "T1486", Execute: Execute{Type: "http"}},
		},
	}
	b := BuildBaseline([]*Campaign{c}, "format-test")
	out := FormatBaseline(b)

	checks := []string{
		"BEHAVIORAL BASELINE",
		"format-test",
		"Techniques",
		"Tactic Distribution",
		"Severity Distribution",
		"Execution Types",
		"execution",
		"shell",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("FormatBaseline missing %q", check)
		}
	}
}

func TestFormatDriftReport_ContainsSections(t *testing.T) {
	dr := &DriftReport{
		Baseline:          "v1-baseline",
		DriftScore:        0.35,
		DriftLevel:        "high",
		StageCountDelta:   3,
		NewCampaigns:      []string{"new-camp"},
		RemovedCampaigns:  []string{"old-camp"},
		ModifiedCampaigns: []string{"changed-camp"},
		NewTechniques:     []string{"AML.T0051"},
		NewTactics:        []string{"initial-access"},
		SeverityShifts: []SeverityShift{
			{Severity: "critical", BaselineCount: 0, CurrentCount: 1, Delta: 1},
		},
		Details: []DriftDetail{
			{Category: "campaign", Change: "added", Item: "new-camp", Description: "New campaign: new-camp", Risk: "info"},
		},
	}

	out := FormatDriftReport(dr)

	checks := []string{
		"DRIFT REPORT",
		"v1-baseline",
		"0.35",
		"high",
		"+3",
		"new-camp",
		"old-camp",
		"changed-camp",
		"AML.T0051",
		"initial-access",
		"critical",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("FormatDriftReport missing %q", check)
		}
	}
}

func TestDriftDetails_RiskLevels(t *testing.T) {
	dr := &DriftReport{
		NewTechniques:     []string{"AML.T0051"},    // should be high risk (AI technique)
		NewTactics:        []string{"exfiltration"}, // should be high risk
		RemovedCampaigns:  []string{"removed"},      // should be medium risk
		ModifiedCampaigns: []string{"modified"},     // should be low risk
		NewCampaigns:      []string{"new"},          // should be info risk
	}
	dr.Details = buildDriftDetails(dr)

	riskMap := make(map[string]string)
	for _, d := range dr.Details {
		riskMap[d.Item] = d.Risk
	}

	if riskMap["AML.T0051"] != "high" {
		t.Errorf("AI technique should be high risk, got %q", riskMap["AML.T0051"])
	}
	if riskMap["exfiltration"] != "high" {
		t.Errorf("exfiltration tactic should be high risk, got %q", riskMap["exfiltration"])
	}
	if riskMap["removed"] != "medium" {
		t.Errorf("removed campaign should be medium risk, got %q", riskMap["removed"])
	}
	if riskMap["new"] != "info" {
		t.Errorf("new campaign should be info risk, got %q", riskMap["new"])
	}
}

func TestHelpers_SetDiff(t *testing.T) {
	a := []string{"a", "b", "c"}
	b := []string{"b", "c", "d"}
	diff := setDiff(a, b)
	if len(diff) != 1 || diff[0] != "a" {
		t.Errorf("expected [a], got %v", diff)
	}
}

func TestHelpers_MergeKeySet(t *testing.T) {
	a := map[string]int{"x": 1, "y": 2}
	b := map[string]int{"y": 3, "z": 4}
	keys := mergeKeySet(a, b)
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestHelpers_FormatDelta(t *testing.T) {
	if formatDelta(5) != "+5" {
		t.Errorf("expected '+5', got %q", formatDelta(5))
	}
	if formatDelta(-3) != "-3" {
		t.Errorf("expected '-3', got %q", formatDelta(-3))
	}
	if formatDelta(0) != "0" {
		t.Errorf("expected '0', got %q", formatDelta(0))
	}
}

func TestHelpers_BaselineTruncate(t *testing.T) {
	if baselineTruncate("short", 10) != "short" {
		t.Errorf("short string should not be truncated")
	}
	got := baselineTruncate("a very long string indeed", 10)
	if len(got) != 10 {
		t.Errorf("expected truncated length 10, got %d (%q)", len(got), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected truncated string to end with '...', got %q", got)
	}
}

func TestHelpers_ClassifyDrift(t *testing.T) {
	if classifyDrift(0) != "none" {
		t.Error("0 should be none")
	}
	if classifyDrift(0.05) != "low" {
		t.Error("0.05 should be low")
	}
	if classifyDrift(0.2) != "medium" {
		t.Error("0.2 should be medium")
	}
	if classifyDrift(0.5) != "high" {
		t.Error("0.5 should be high")
	}
	if classifyDrift(0.9) != "critical" {
		t.Error("0.9 should be critical")
	}
}

func TestBaselineJSON_Structure(t *testing.T) {
	c := &Campaign{
		Meta:   Meta{Name: "struct-test", Severity: "medium"},
		Stages: []Stage{{ID: "s1", Tactic: "execution", Technique: "T1059", Execute: Execute{Type: "shell"}}},
	}
	b := BuildBaseline([]*Campaign{c}, "structure")

	data, err := BaselineToJSON(b)
	if err != nil {
		t.Fatal(err)
	}

	// Verify JSON structure has expected keys.
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}

	expectedKeys := []string{"version", "label", "campaigns", "stages", "tools", "tactics",
		"techniques", "severities", "platforms", "exec_types", "tags", "telemetry",
		"detections", "elevated", "avg_stages", "max_stages", "min_stages", "fingerprints"}
	for _, key := range expectedKeys {
		if _, ok := m[key]; !ok {
			t.Errorf("JSON missing key %q", key)
		}
	}
}
