// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

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

func TestCoverageTextReport_Output(t *testing.T) {
	cr := buildCoverageReport()

	var buf bytes.Buffer
	CoverageTextReport(&buf, cr)

	out := buf.String()

	// Check header.
	if !strings.Contains(out, "Technique Coverage Report") {
		t.Error("output should contain header")
	}

	// Check overall stats.
	if !strings.Contains(out, "Techniques exercised") {
		t.Error("output should contain overall stats")
	}

	// Check framework breakdown.
	if !strings.Contains(out, "MITRE ATT&CK") {
		t.Error("output should contain ATT&CK framework")
	}

	// Check tactic section.
	if !strings.Contains(out, "Discovery") {
		t.Error("output should contain Discovery tactic section")
	}

	// Check technique ID appears.
	if !strings.Contains(out, "T1016") {
		t.Error("output should contain technique ID T1016")
	}

	// Check coverage summary.
	if !strings.Contains(out, "COVERAGE SUMMARY") {
		t.Error("output should contain coverage summary")
	}
}

func TestCoverageTextReport_Empty(t *testing.T) {
	cr := gap.AnalyzeCoverage()

	var buf bytes.Buffer
	CoverageTextReport(&buf, cr)

	out := buf.String()
	if !strings.Contains(out, "Technique Coverage Report") {
		t.Error("empty report should still have header")
	}
	if !strings.Contains(out, "0") {
		t.Error("empty report should show zero exercised")
	}
}

func TestCoverageJSONReport_Valid(t *testing.T) {
	cr := buildCoverageReport()

	var buf bytes.Buffer
	if err := CoverageJSONReport(&buf, cr); err != nil {
		t.Fatalf("CoverageJSONReport failed: %v", err)
	}

	// Must be valid JSON.
	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check key fields.
	if _, ok := decoded["total_techniques_in_registry"]; !ok {
		t.Error("JSON should contain total_techniques_in_registry")
	}
	if _, ok := decoded["techniques"]; !ok {
		t.Error("JSON should contain techniques array")
	}
	if _, ok := decoded["by_framework"]; !ok {
		t.Error("JSON should contain by_framework")
	}
}

func TestCoverageJSONReport_TechniqueFields(t *testing.T) {
	cr := buildCoverageReport()

	var buf bytes.Buffer
	if err := CoverageJSONReport(&buf, cr); err != nil {
		t.Fatalf("CoverageJSONReport failed: %v", err)
	}

	var decoded struct {
		Techniques []struct {
			TechniqueID   string   `json:"technique_id"`
			TechniqueName string   `json:"technique_name"`
			Framework     string   `json:"framework"`
			Status        string   `json:"status"`
			Campaigns     []string `json:"campaigns"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(decoded.Techniques) == 0 {
		t.Fatal("expected at least one technique in JSON")
	}

	tc := decoded.Techniques[0]
	if tc.TechniqueID == "" {
		t.Error("technique_id should not be empty")
	}
	if tc.Framework == "" {
		t.Error("framework should not be empty")
	}
	if tc.Status == "" {
		t.Error("status should not be empty")
	}
}

func TestCoverageMarkdownReport(t *testing.T) {
	cr := buildCoverageReport()

	var buf bytes.Buffer
	if err := CoverageMarkdownReport(&buf, cr); err != nil {
		t.Fatalf("CoverageMarkdownReport failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "# Technique Coverage Report") {
		t.Error("markdown should contain header")
	}
	if !strings.Contains(out, "| Technique | Name |") {
		t.Error("markdown should contain technique table header")
	}
	if !strings.Contains(out, "T1016") {
		t.Error("markdown should contain T1016")
	}
}

// --- helper ---

func buildCoverageReport() *gap.CoverageReport {
	c := &campaign.Campaign{
		APIVersion: "v1", Kind: "Campaign",
		Meta: campaign.Meta{Name: "cov-test", Adversary: "TestActor", Severity: "high"},
		Stages: []campaign.Stage{
			{
				ID: "recon", Name: "Recon", Technique: "T1016", Tactic: "discovery",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"process_create"}, Detections: []string{"scan_detected"}},
			},
			{
				ID: "access", Name: "Access", Technique: "T1190", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "shell"},
				Expect:  campaign.Expect{Telemetry: []string{"network_connection"}},
			},
		},
	}

	var srs []engine.StageResult
	for i, s := range c.Stages {
		srs = append(srs, engine.StageResult{
			Stage: s, Order: i + 1,
			Exec: executor.Result{StageID: s.ID, Success: true},
		})
	}
	r := &engine.RunResult{Campaign: c, Mode: "simulate", Stages: srs, Completed: 2}

	return gap.AnalyzeCoverage(r)
}
