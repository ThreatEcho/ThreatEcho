// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package navigator

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/executor"
	"github.com/ThreatEcho/threatecho/internal/gap"
)

// makeResult builds a RunResult from stage definitions for testing.
func makeResult(name string, stages []testStage) *engine.RunResult {
	var cStages []campaign.Stage
	var sResults []engine.StageResult

	for i, ts := range stages {
		s := campaign.Stage{
			ID:        ts.id,
			Name:      ts.name,
			Technique: ts.technique,
			Tactic:    ts.tactic,
			Expect: campaign.Expect{
				Telemetry:  ts.telemetry,
				Detections: ts.detections,
			},
		}
		cStages = append(cStages, s)
		sResults = append(sResults, engine.StageResult{
			Stage: s,
			Order: i,
			Exec: executor.Result{
				StageID: ts.id,
				Success: !ts.skipped,
				Skipped: ts.skipped,
			},
			Skipped: ts.skipped,
		})
	}

	c := &campaign.Campaign{
		Meta: campaign.Meta{
			Name:      name,
			Adversary: "Test",
		},
		Stages: cStages,
	}

	completed := 0
	skipped := 0
	for _, sr := range sResults {
		if sr.Skipped {
			skipped++
		} else {
			completed++
		}
	}

	return &engine.RunResult{
		Campaign:  c,
		Mode:      "dry-run",
		Stages:    sResults,
		Completed: completed,
		Skipped:   skipped,
	}
}

type testStage struct {
	id         string
	name       string
	technique  string
	tactic     string
	telemetry  []string
	detections []string
	skipped    bool
}

func TestFromRunResult_BasicCoverage(t *testing.T) {
	result := makeResult("test-campaign", []testStage{
		{
			id:         "s1",
			name:       "Spearphish",
			technique:  "T1566.001",
			tactic:     "initial-access",
			telemetry:  []string{"file_create", "process_create"},
			detections: []string{"spearphish_detected"},
		},
		{
			id:         "s2",
			name:       "PowerShell",
			technique:  "T1059.001",
			tactic:     "execution",
			telemetry:  []string{"process_create"},
			detections: nil, // detection gap
		},
		{
			id:        "s3",
			name:      "Cred Dump",
			technique: "T1003.001",
			tactic:    "credential-access",
			// no telemetry, no detections = telemetry gap
		},
	})

	layer := FromRunResult(result)

	if layer.Name != "ThreatEcho Coverage" {
		t.Errorf("expected name 'ThreatEcho Coverage', got %q", layer.Name)
	}

	if layer.Domain != "enterprise-attack" {
		t.Errorf("expected domain 'enterprise-attack', got %q", layer.Domain)
	}

	if len(layer.Techniques) != 3 {
		t.Fatalf("expected 3 techniques, got %d", len(layer.Techniques))
	}

	// Verify sorted order.
	ids := make([]string, len(layer.Techniques))
	for i, te := range layer.Techniques {
		ids[i] = te.TechniqueID
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] < ids[i-1] {
			t.Errorf("techniques not sorted: %v", ids)
			break
		}
	}

	// Find each technique and verify color.
	techMap := make(map[string]TechEntry)
	for _, te := range layer.Techniques {
		techMap[te.TechniqueID] = te
	}

	// T1566.001 should be green (has detections).
	if te := techMap["T1566.001"]; te.Color != ColorCovered {
		t.Errorf("T1566.001: expected color %s, got %s", ColorCovered, te.Color)
	}

	// T1059.001 should be yellow (telemetry but no detections).
	if te := techMap["T1059.001"]; te.Color != ColorDetectionGap {
		t.Errorf("T1059.001: expected color %s, got %s", ColorDetectionGap, te.Color)
	}

	// T1003.001 should be orange (no telemetry).
	if te := techMap["T1003.001"]; te.Color != ColorTelemetryGap {
		t.Errorf("T1003.001: expected color %s, got %s", ColorTelemetryGap, te.Color)
	}
}

func TestFromRunResult_SkipsNonATTACK(t *testing.T) {
	result := makeResult("atlas-campaign", []testStage{
		{
			id:         "s1",
			name:       "Prompt Injection",
			technique:  "AML.T0051",
			tactic:     "initial-access",
			telemetry:  []string{"prompt_log"},
			detections: []string{"prompt_injection_detected"},
		},
		{
			id:         "s2",
			name:       "Tool Abuse",
			technique:  "LLM06",
			tactic:     "ml-model-access",
			telemetry:  []string{"tool_call"},
			detections: []string{"tool_policy_violation"},
		},
		{
			id:         "s3",
			name:       "C2 Beacon",
			technique:  "T1071.001",
			tactic:     "command-and-control",
			telemetry:  []string{"network_connection"},
			detections: []string{"c2_beacon_detected"},
		},
	})

	layer := FromRunResult(result)

	if len(layer.Techniques) != 1 {
		t.Fatalf("expected 1 technique (only ATT&CK), got %d", len(layer.Techniques))
	}
	if layer.Techniques[0].TechniqueID != "T1071.001" {
		t.Errorf("expected T1071.001, got %s", layer.Techniques[0].TechniqueID)
	}
}

func TestFromRunResult_SkipsSkippedStages(t *testing.T) {
	result := makeResult("skip-test", []testStage{
		{
			id:         "s1",
			name:       "Active",
			technique:  "T1566.001",
			tactic:     "initial-access",
			telemetry:  []string{"file_create"},
			detections: []string{"phish_detected"},
		},
		{
			id:        "s2",
			name:      "Skipped",
			technique: "T1059.001",
			tactic:    "execution",
			telemetry: []string{"process_create"},
			skipped:   true,
		},
	})

	layer := FromRunResult(result)

	if len(layer.Techniques) != 1 {
		t.Fatalf("expected 1 technique (skipped excluded), got %d", len(layer.Techniques))
	}
}

func TestFromRunResult_MultiCampaignMerge(t *testing.T) {
	r1 := makeResult("campaign-a", []testStage{
		{
			id:        "s1",
			name:      "Phish",
			technique: "T1566.001",
			tactic:    "initial-access",
			telemetry: []string{"file_create"},
			// No detections → yellow.
		},
	})
	r2 := makeResult("campaign-b", []testStage{
		{
			id:         "s1",
			name:       "Phish Again",
			technique:  "T1566.001",
			tactic:     "initial-access",
			telemetry:  []string{"email_received"},
			detections: []string{"phish_rule"},
		},
	})

	layer := FromRunResult(r1, r2)

	if len(layer.Techniques) != 1 {
		t.Fatalf("expected 1 merged technique, got %d", len(layer.Techniques))
	}

	te := layer.Techniques[0]

	// With detections from campaign-b, should be green.
	if te.Color != ColorCovered {
		t.Errorf("expected merged color %s, got %s", ColorCovered, te.Color)
	}

	// Score should be 100 (best state wins).
	if te.Score != 100 {
		t.Errorf("expected score 100, got %d", te.Score)
	}

	// Comment should mention both campaigns.
	if !strings.Contains(te.Comment, "campaign-a") || !strings.Contains(te.Comment, "campaign-b") {
		t.Errorf("expected both campaigns in comment, got %q", te.Comment)
	}

	// Stages should be 2.
	if !strings.Contains(te.Comment, "stages: 2") {
		t.Errorf("expected 'stages: 2' in comment, got %q", te.Comment)
	}
}

func TestFromGapReport_DetectionGap(t *testing.T) {
	report := &gap.GapReport{
		Gaps: []gap.Gap{
			{
				CampaignName:  "test-campaign",
				StageID:       "s1",
				StageName:     "PowerShell Exec",
				Technique:     "T1059.001",
				TechniqueName: "PowerShell",
				Tactic:        "execution",
				Type:          gap.GapDetectionMissing,
				Risk:          "high",
				Description:   "Stage declares expected telemetry but no detection rules",
			},
			{
				CampaignName:  "test-campaign",
				StageID:       "s2",
				StageName:     "Cred Dump",
				Technique:     "T1003.001",
				TechniqueName: "LSASS Memory",
				Tactic:        "credential-access",
				Type:          gap.GapTelemetryMissing,
				Risk:          "medium",
				Description:   "Stage declares no expected telemetry",
			},
			// ATLAS technique should be excluded.
			{
				CampaignName:  "atlas-campaign",
				StageID:       "s3",
				StageName:     "Prompt Injection",
				Technique:     "AML.T0051",
				TechniqueName: "LLM Prompt Injection",
				Tactic:        "initial-access",
				Type:          gap.GapDetectionMissing,
				Risk:          "high",
			},
			// Tactic-level gap (no technique) should be excluded.
			{
				Tactic:      "lateral-movement",
				Type:        gap.GapTacticUncovered,
				Risk:        "high",
				Description: "ATT&CK tactic not covered",
			},
		},
	}

	layer := FromGapReport(report)

	if len(layer.Techniques) != 2 {
		t.Fatalf("expected 2 techniques (ATT&CK only, no tactic-level), got %d", len(layer.Techniques))
	}

	techMap := make(map[string]TechEntry)
	for _, te := range layer.Techniques {
		techMap[te.TechniqueID] = te
	}

	// T1059.001 should be yellow (detection gap).
	if te := techMap["T1059.001"]; te.Color != ColorDetectionGap {
		t.Errorf("T1059.001: expected color %s, got %s", ColorDetectionGap, te.Color)
	}

	// T1003.001 should be orange (telemetry gap, worse).
	if te := techMap["T1003.001"]; te.Color != ColorTelemetryGap {
		t.Errorf("T1003.001: expected color %s, got %s", ColorTelemetryGap, te.Color)
	}
}

func TestWriteLayer_ValidJSON(t *testing.T) {
	layer := FromRunResult(makeResult("json-test", []testStage{
		{
			id:         "s1",
			name:       "Spearphish",
			technique:  "T1566.001",
			tactic:     "initial-access",
			telemetry:  []string{"file_create"},
			detections: []string{"spearphish_detected"},
		},
	}))

	var buf bytes.Buffer
	if err := WriteLayer(&buf, layer); err != nil {
		t.Fatalf("WriteLayer error: %v", err)
	}

	output := buf.String()

	// Must be valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, output)
	}

	// Verify key fields.
	if v, ok := parsed["name"].(string); !ok || v != "ThreatEcho Coverage" {
		t.Errorf("unexpected name in JSON: %v", parsed["name"])
	}
	if v, ok := parsed["domain"].(string); !ok || v != "enterprise-attack" {
		t.Errorf("unexpected domain in JSON: %v", parsed["domain"])
	}

	versions, ok := parsed["versions"].(map[string]interface{})
	if !ok {
		t.Fatal("missing versions in JSON")
	}
	if versions["layer"] != "4.5" {
		t.Errorf("expected layer version 4.5, got %v", versions["layer"])
	}

	techs, ok := parsed["techniques"].([]interface{})
	if !ok || len(techs) != 1 {
		t.Fatalf("expected 1 technique in JSON, got %v", len(techs))
	}

	tech := techs[0].(map[string]interface{})
	if tech["techniqueID"] != "T1566.001" {
		t.Errorf("expected techniqueID T1566.001, got %v", tech["techniqueID"])
	}
	if tech["color"] != ColorCovered {
		t.Errorf("expected color %s, got %v", ColorCovered, tech["color"])
	}
}

func TestWriteLayer_PrettyPrinted(t *testing.T) {
	layer := FromRunResult(makeResult("pretty-test", []testStage{
		{
			id:         "s1",
			name:       "Test",
			technique:  "T1566",
			tactic:     "initial-access",
			telemetry:  []string{"file_create"},
			detections: []string{"phish"},
		},
	}))

	var buf bytes.Buffer
	if err := WriteLayer(&buf, layer); err != nil {
		t.Fatalf("WriteLayer error: %v", err)
	}

	// Pretty printed means it should contain newlines and indentation.
	output := buf.String()
	if !strings.Contains(output, "\n") {
		t.Error("expected pretty-printed JSON with newlines")
	}
	if !strings.Contains(output, "  ") {
		t.Error("expected pretty-printed JSON with indentation")
	}
}

func TestLayerMetadata(t *testing.T) {
	layer := FromRunResult(makeResult("meta-test", []testStage{
		{
			id:         "s1",
			name:       "Test",
			technique:  "T1566",
			tactic:     "initial-access",
			telemetry:  []string{"file_create"},
			detections: []string{"phish"},
		},
	}))

	// Verify standard fields.
	if layer.Versions.Attack != "15" {
		t.Errorf("expected ATT&CK version 15, got %s", layer.Versions.Attack)
	}
	if layer.Versions.Navigator != "4.5" {
		t.Errorf("expected Navigator version 4.5, got %s", layer.Versions.Navigator)
	}
	if layer.Versions.Layer != "4.5" {
		t.Errorf("expected Layer version 4.5, got %s", layer.Versions.Layer)
	}

	// Gradient.
	if len(layer.Gradient.Colors) != 4 {
		t.Errorf("expected 4 gradient colors, got %d", len(layer.Gradient.Colors))
	}
	if layer.Gradient.MaxValue != 100 {
		t.Errorf("expected gradient maxValue 100, got %d", layer.Gradient.MaxValue)
	}

	// Legend items.
	if len(layer.LegendItems) != 4 {
		t.Fatalf("expected 4 legend items, got %d", len(layer.LegendItems))
	}
	expectedLabels := []string{
		"Covered (detections defined)",
		"Detection gap (telemetry only)",
		"Telemetry gap (blind spot)",
		"Uncovered",
	}
	for i, li := range layer.LegendItems {
		if li.Label != expectedLabels[i] {
			t.Errorf("legend[%d]: expected label %q, got %q", i, expectedLabels[i], li.Label)
		}
	}

	// Metadata.
	if len(layer.Metadata) != 2 {
		t.Fatalf("expected 2 metadata entries, got %d", len(layer.Metadata))
	}
	if layer.Metadata[0].Name != "generated_by" || layer.Metadata[0].Value != "ThreatEcho" {
		t.Errorf("unexpected metadata[0]: %+v", layer.Metadata[0])
	}

	// Filters.
	if len(layer.Filters.Platforms) == 0 {
		t.Error("expected non-empty platform filters")
	}
}

func TestFromRunResult_EmptyInput(t *testing.T) {
	layer := FromRunResult()
	if len(layer.Techniques) != 0 {
		t.Errorf("expected 0 techniques for empty input, got %d", len(layer.Techniques))
	}
	if layer.Name == "" {
		t.Error("layer should have a name even with empty input")
	}
}

func TestFromGapReport_EmptyGaps(t *testing.T) {
	report := &gap.GapReport{
		Gaps: nil,
	}
	layer := FromGapReport(report)
	if len(layer.Techniques) != 0 {
		t.Errorf("expected 0 techniques for empty gaps, got %d", len(layer.Techniques))
	}
}

func TestFromGapReport_WorstGapWins(t *testing.T) {
	// Same technique appears with both detection gap and telemetry gap.
	// Telemetry gap is worse → should win.
	report := &gap.GapReport{
		Gaps: []gap.Gap{
			{
				CampaignName: "c1",
				StageID:      "s1",
				Technique:    "T1059.001",
				Tactic:       "execution",
				Type:         gap.GapDetectionMissing,
				Risk:         "high",
			},
			{
				CampaignName: "c1",
				StageID:      "s2",
				Technique:    "T1059.001",
				Tactic:       "execution",
				Type:         gap.GapTelemetryMissing,
				Risk:         "medium",
			},
		},
	}

	layer := FromGapReport(report)

	if len(layer.Techniques) != 1 {
		t.Fatalf("expected 1 technique, got %d", len(layer.Techniques))
	}

	// Telemetry gap (orange) should win over detection gap (yellow).
	if layer.Techniques[0].Color != ColorTelemetryGap {
		t.Errorf("expected color %s (telemetry gap wins), got %s",
			ColorTelemetryGap, layer.Techniques[0].Color)
	}
}

func TestIsATTACK(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"T1566", true},
		{"T1566.001", true},
		{"T1059.003", true},
		{"AML.T0051", false},
		{"LLM06", false},
		{"", false},
		{"X9999", false},
	}

	for _, tt := range tests {
		if got := isATTACK(tt.id); got != tt.want {
			t.Errorf("isATTACK(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{-5, "-5"},
		{999999, "999999"},
	}
	for _, tt := range tests {
		if got := itoa(tt.n); got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}
