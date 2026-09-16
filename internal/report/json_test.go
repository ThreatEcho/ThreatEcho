// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/executor"
)

func testRunResult() *engine.RunResult {
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:         "test-campaign",
			Adversary:    "TestActor",
			Description:  "Test description",
			Objective:    "Test objective",
			Severity:     "high",
			MitreVersion: "15.1",
			Tags:         []string{"test"},
			References:   []string{"https://example.com"},
		},
		Stages: []campaign.Stage{
			{
				ID:        "recon",
				Name:      "Recon",
				Technique: "T1016",
				Tactic:    "discovery",
				Execute:   campaign.Execute{Type: "shell", Commands: []string{"echo recon"}},
				Expect: campaign.Expect{
					Telemetry:  []string{"process_create"},
					Detections: []string{"recon_detected"},
				},
			},
			{
				ID:        "access",
				Name:      "Access",
				Technique: "T1190",
				Tactic:    "initial-access",
				DependsOn: []string{"recon"},
				Execute:   campaign.Execute{Type: "shell", Commands: []string{"echo access"}},
				Expect: campaign.Expect{
					Telemetry:  []string{"network_connection"},
					Detections: []string{"exploit_attempt"},
				},
			},
		},
	}
	return &engine.RunResult{
		Campaign:  c,
		Mode:      "simulate",
		Completed: 2,
		Skipped:   0,
		Failed:    0,
		Stages: []engine.StageResult{
			{
				Stage: c.Stages[0],
				Order: 1,
				Exec:  executor.Result{StageID: "recon", Success: true, Output: "would run 1 command(s)"},
			},
			{
				Stage: c.Stages[1],
				Order: 2,
				Exec:  executor.Result{StageID: "access", Success: true, Output: "would run 1 command(s)"},
			},
		},
	}
}

func TestJSONReport_BasicStructure(t *testing.T) {
	r := testRunResult()
	var buf bytes.Buffer
	if err := JSONReportWrite(&buf, r); err != nil {
		t.Fatalf("JSONReportWrite error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if report.Version != "1.0" {
		t.Errorf("version = %q, want %q", report.Version, "1.0")
	}
	if report.Mode != "simulate" {
		t.Errorf("mode = %q, want %q", report.Mode, "simulate")
	}
	if report.GeneratedAt == "" {
		t.Error("generated_at should not be empty")
	}
	if report.Campaign.Name != "test-campaign" {
		t.Errorf("campaign.name = %q, want %q", report.Campaign.Name, "test-campaign")
	}
	if report.Campaign.Adversary != "TestActor" {
		t.Errorf("campaign.adversary = %q, want %q", report.Campaign.Adversary, "TestActor")
	}
	if report.Campaign.Severity != "high" {
		t.Errorf("campaign.severity = %q, want %q", report.Campaign.Severity, "high")
	}
	if len(report.Stages) != 2 {
		t.Fatalf("got %d stages, want 2", len(report.Stages))
	}
	if report.Summary.StagesTotal != 2 {
		t.Errorf("summary.stages_total = %d, want 2", report.Summary.StagesTotal)
	}
	if report.Summary.StagesComplete != 2 {
		t.Errorf("summary.stages_completed = %d, want 2", report.Summary.StagesComplete)
	}
}

func TestJSONReport_TechniqueNameResolution(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		// ATT&CK
		{"T1566.001", "Spearphishing Attachment"},
		{"T1190", "Exploit Public-Facing Application"},
		{"T1016", "System Network Configuration Discovery"},
		// ATLAS
		{"AML.T0051", "LLM Prompt Injection"},
		{"AML.T0054", "LLM Jailbreaking"},
		// OWASP LLM
		{"LLM01", "Prompt Injection"},
		{"LLM06", "Excessive Agency"},
		// Unknown
		{"T9999", "T9999"},
		{"UNKNOWN", "UNKNOWN"},
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

func TestJSONReport_SkippedStages(t *testing.T) {
	r := testRunResult()
	// Make recon skipped.
	r.Stages[0].Skipped = true
	r.Stages[0].SkipMsg = "platform linux not in [windows]"
	r.Completed = 1
	r.Skipped = 1

	var buf bytes.Buffer
	if err := JSONReportWrite(&buf, r); err != nil {
		t.Fatalf("JSONReportWrite error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if !report.Stages[0].Skipped {
		t.Error("first stage should be skipped")
	}
	if report.Stages[0].SkipReason != "platform linux not in [windows]" {
		t.Errorf("skip_reason = %q", report.Stages[0].SkipReason)
	}
	if report.Stages[0].Result != "" {
		t.Error("skipped stage should have empty result")
	}
	if report.Summary.StagesSkipped != 1 {
		t.Errorf("summary.stages_skipped = %d, want 1", report.Summary.StagesSkipped)
	}
	if report.Summary.StagesComplete != 1 {
		t.Errorf("summary.stages_completed = %d, want 1", report.Summary.StagesComplete)
	}
}

func TestJSONReport_CoverageAccuracy(t *testing.T) {
	r := testRunResult()
	var buf bytes.Buffer
	if err := JSONReportWrite(&buf, r); err != nil {
		t.Fatalf("JSONReportWrite error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	cov := report.Coverage

	// 2 tactics covered out of 14.
	if cov.Tactics.Total != 14 {
		t.Errorf("tactics.total = %d, want 14", cov.Tactics.Total)
	}
	if cov.Tactics.Covered != 2 {
		t.Errorf("tactics.covered = %d, want 2", cov.Tactics.Covered)
	}
	if cov.Tactics.Percent != 14 { // 2/14 = 14%
		t.Errorf("tactics.percent = %d, want 14", cov.Tactics.Percent)
	}

	// Hit should contain discovery and initial-access.
	hitSet := make(map[string]bool)
	for _, h := range cov.Tactics.Hit {
		hitSet[h] = true
	}
	if !hitSet["discovery"] {
		t.Error("discovery should be in hit")
	}
	if !hitSet["initial-access"] {
		t.Error("initial-access should be in hit")
	}

	// Miss should have 12.
	if len(cov.Tactics.Miss) != 12 {
		t.Errorf("len(tactics.miss) = %d, want 12", len(cov.Tactics.Miss))
	}

	// 2 unique techniques.
	if cov.Techniques.Unique != 2 {
		t.Errorf("techniques.unique = %d, want 2", cov.Techniques.Unique)
	}
	if len(cov.Techniques.List) != 2 {
		t.Fatalf("techniques.list len = %d, want 2", len(cov.Techniques.List))
	}
	// Check name resolution.
	found := false
	for _, te := range cov.Techniques.List {
		if te.ID == "T1016" && te.Name == "System Network Configuration Discovery" {
			found = true
		}
	}
	if !found {
		t.Error("technique T1016 not resolved correctly in list")
	}

	// Telemetry and detections.
	if len(cov.Telemetry) != 2 {
		t.Errorf("telemetry_types len = %d, want 2", len(cov.Telemetry))
	}
	if len(cov.Detections) != 2 {
		t.Errorf("detection_rules len = %d, want 2", len(cov.Detections))
	}
}

func TestJSONReport_StageDetails(t *testing.T) {
	r := testRunResult()
	var buf bytes.Buffer
	if err := JSONReportWrite(&buf, r); err != nil {
		t.Fatalf("JSONReportWrite error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	s0 := report.Stages[0]
	if s0.ID != "recon" {
		t.Errorf("stage[0].id = %q, want %q", s0.ID, "recon")
	}
	if s0.TechniqueName != "System Network Configuration Discovery" {
		t.Errorf("stage[0].technique_name = %q", s0.TechniqueName)
	}
	if s0.TacticName != "Discovery" {
		t.Errorf("stage[0].tactic_name = %q", s0.TacticName)
	}
	if s0.ExecType != "shell" {
		t.Errorf("stage[0].exec_type = %q", s0.ExecType)
	}
	if s0.Result != "would run 1 command(s)" {
		t.Errorf("stage[0].result = %q", s0.Result)
	}

	s1 := report.Stages[1]
	if len(s1.DependsOn) != 1 || s1.DependsOn[0] != "recon" {
		t.Errorf("stage[1].depends_on = %v, want [recon]", s1.DependsOn)
	}
}

func TestClassifyTechnique(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"T1566", "attack"},
		{"T1566.001", "attack"},
		{"AML.T0051", "atlas"},
		{"LLM01", "owasp"},
		{"UNKNOWN", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := classifyTechnique(tt.id)
			if got != tt.want {
				t.Errorf("classifyTechnique(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestResolveTacticName(t *testing.T) {
	tests := []struct {
		short string
		want  string
	}{
		{"initial-access", "Initial Access"},
		{"discovery", "Discovery"},
		{"ml-attack-staging", "ML Attack Staging"},
		{"ml-model-access", "ML Model Access"},
		{"not-real", "not-real"},
	}
	for _, tt := range tests {
		t.Run(tt.short, func(t *testing.T) {
			got := ResolveTacticName(tt.short)
			if got != tt.want {
				t.Errorf("ResolveTacticName(%q) = %q, want %q", tt.short, got, tt.want)
			}
		})
	}
}
