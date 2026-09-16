// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/gap"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// helper to build a gap report with varied gap types.
func testGapReport() *gap.GapReport {
	return &gap.GapReport{
		Gaps: []gap.Gap{
			{
				CampaignName: "fin6-sim",
				StageID:      "stage-1",
				StageName:    "Recon",
				Technique:    "T1016",
				Tactic:       "discovery",
				Type:         gap.GapDetectionMissing,
				Risk:         "medium",
				Description:  "Stage declares expected telemetry but no detection rules",
			},
			{
				CampaignName: "fin6-sim",
				StageID:      "stage-2",
				StageName:    "Access",
				Technique:    "T1190",
				Tactic:       "initial-access",
				Type:         gap.GapTelemetryMissing,
				Risk:         "high",
				Description:  "Stage declares no expected telemetry",
			},
			{
				Tactic:      "exfiltration",
				Type:        gap.GapTacticUncovered,
				Risk:        "critical",
				Description: "ATT&CK tactic \"Exfiltration\" has no stage coverage",
			},
		},
		RiskSummary: gap.RiskSummary{
			Critical: 1,
			High:     1,
			Medium:   1,
			Low:      0,
			Total:    3,
			Score:    56.67,
		},
	}
}

// helper to build a policy eval result with violations.
func testPolicyEvalResult() *policy.EvalResult {
	return &policy.EvalResult{
		Policy:      "agent-sandbox",
		Campaign:    "agent-escape-sim",
		TotalStages: 5,
		Allowed:     3,
		Denied:      1,
		Alerted:     1,
		Violations: []policy.Violation{
			{
				RuleID:    "no-shell",
				RuleDesc:  "Deny shell execution for retrieval agents",
				Effect:    "deny",
				StageID:   "stage-3",
				StageName: "Shell Escape",
				Technique: "T1059",
				Tactic:    "execution",
				Tool:      "shell_exec",
				Reason:    "denied by rule \"no-shell\": Deny shell execution for retrieval agents",
			},
			{
				RuleID:    "alert-exfil",
				RuleDesc:  "Alert on data exfiltration attempts",
				Effect:    "alert",
				StageID:   "stage-4",
				StageName: "Data Exfil",
				Technique: "T1041",
				Tactic:    "exfiltration",
				Tool:      "http_request",
				Reason:    "alert from rule \"alert-exfil\": Alert on data exfiltration attempts",
			},
			{
				RuleID:    "no-shell",
				RuleDesc:  "Deny shell execution for retrieval agents",
				Effect:    "deny",
				StageID:   "stage-5",
				StageName: "Shell Escape 2",
				Technique: "T1059.001",
				Tactic:    "execution",
				Tool:      "shell_exec",
				Reason:    "denied by rule \"no-shell\": Deny shell execution for retrieval agents",
			},
		},
	}
}

func TestGapSARIFReport_ValidJSON(t *testing.T) {
	r := testGapReport()
	var buf bytes.Buffer
	if err := GapSARIFReport(&buf, r, "campaigns/fin6.yaml"); err != nil {
		t.Fatalf("GapSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v\noutput:\n%s", err, buf.String())
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
	if log.Schema != sarifSchema {
		t.Errorf("$schema = %q, want SARIF 2.1.0 schema", log.Schema)
	}
}

func TestGapSARIFReport_CorrectResultCount(t *testing.T) {
	r := testGapReport()
	var buf bytes.Buffer
	if err := GapSARIFReport(&buf, r, "campaigns/fin6.yaml"); err != nil {
		t.Fatalf("GapSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}

	run := log.Runs[0]
	if len(run.Results) != 3 {
		t.Errorf("results = %d, want 3", len(run.Results))
	}
}

func TestGapSARIFReport_RuleIDs(t *testing.T) {
	r := testGapReport()
	var buf bytes.Buffer
	if err := GapSARIFReport(&buf, r, "campaigns/fin6.yaml"); err != nil {
		t.Fatalf("GapSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	run := log.Runs[0]

	// Verify the three fixed rules are present.
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(run.Tool.Driver.Rules))
	}

	wantRules := []struct {
		id    string
		level string
	}{
		{"TE-GAP-001", "warning"},
		{"TE-GAP-002", "error"},
		{"TE-GAP-003", "warning"},
	}
	for i, want := range wantRules {
		got := run.Tool.Driver.Rules[i]
		if got.ID != want.id {
			t.Errorf("rule[%d].id = %q, want %q", i, got.ID, want.id)
		}
		if got.DefaultConfig.Level != want.level {
			t.Errorf("rule[%d].level = %q, want %q", i, got.DefaultConfig.Level, want.level)
		}
	}
}

func TestGapSARIFReport_ResultLevels(t *testing.T) {
	r := testGapReport()
	var buf bytes.Buffer
	if err := GapSARIFReport(&buf, r, "campaigns/fin6.yaml"); err != nil {
		t.Fatalf("GapSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	results := log.Runs[0].Results

	// Gap 0: detection_missing -> warning
	if results[0].Level != "warning" {
		t.Errorf("result[0].level = %q, want %q", results[0].Level, "warning")
	}
	if results[0].RuleID != "TE-GAP-001" {
		t.Errorf("result[0].ruleId = %q, want %q", results[0].RuleID, "TE-GAP-001")
	}

	// Gap 1: telemetry_missing -> error
	if results[1].Level != "error" {
		t.Errorf("result[1].level = %q, want %q", results[1].Level, "error")
	}
	if results[1].RuleID != "TE-GAP-002" {
		t.Errorf("result[1].ruleId = %q, want %q", results[1].RuleID, "TE-GAP-002")
	}

	// Gap 2: tactic_uncovered -> warning
	if results[2].Level != "warning" {
		t.Errorf("result[2].level = %q, want %q", results[2].Level, "warning")
	}
	if results[2].RuleID != "TE-GAP-003" {
		t.Errorf("result[2].ruleId = %q, want %q", results[2].RuleID, "TE-GAP-003")
	}
}

func TestGapSARIFReport_RiskProperties(t *testing.T) {
	r := testGapReport()
	var buf bytes.Buffer
	if err := GapSARIFReport(&buf, r, "campaigns/fin6.yaml"); err != nil {
		t.Fatalf("GapSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	results := log.Runs[0].Results

	// Check properties on the first result.
	props := results[0].Properties
	if props["risk"] != "medium" {
		t.Errorf("result[0].properties.risk = %v, want %q", props["risk"], "medium")
	}
	if props["tactic"] != "discovery" {
		t.Errorf("result[0].properties.tactic = %v, want %q", props["tactic"], "discovery")
	}
	if props["technique"] != "T1016" {
		t.Errorf("result[0].properties.technique = %v, want %q", props["technique"], "T1016")
	}
	if props["campaign"] != "fin6-sim" {
		t.Errorf("result[0].properties.campaign = %v, want %q", props["campaign"], "fin6-sim")
	}

	// Check the critical-risk result.
	props2 := results[2].Properties
	if props2["risk"] != "critical" {
		t.Errorf("result[2].properties.risk = %v, want %q", props2["risk"], "critical")
	}
}

func TestGapSARIFReport_Location(t *testing.T) {
	r := testGapReport()
	var buf bytes.Buffer
	if err := GapSARIFReport(&buf, r, "campaigns/fin6.yaml"); err != nil {
		t.Fatalf("GapSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	for i, result := range log.Runs[0].Results {
		if len(result.Locations) != 1 {
			t.Errorf("result[%d].locations = %d, want 1", i, len(result.Locations))
			continue
		}
		uri := result.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if uri != "campaigns/fin6.yaml" {
			t.Errorf("result[%d].location.uri = %q, want %q", i, uri, "campaigns/fin6.yaml")
		}
	}
}

func TestGapSARIFReport_EmptyInput(t *testing.T) {
	r := &gap.GapReport{}
	var buf bytes.Buffer
	if err := GapSARIFReport(&buf, r, "empty.yaml"); err != nil {
		t.Fatalf("GapSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v\noutput:\n%s", err, buf.String())
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(log.Runs[0].Results))
	}
	// Rules are always present even with no results.
	if len(log.Runs[0].Tool.Driver.Rules) != 3 {
		t.Errorf("rules = %d, want 3", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestGapSARIFReport_ToolMetadata(t *testing.T) {
	r := &gap.GapReport{}
	var buf bytes.Buffer
	if err := GapSARIFReport(&buf, r, "test.yaml"); err != nil {
		t.Fatalf("GapSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	driver := log.Runs[0].Tool.Driver
	if driver.Name != "ThreatEcho" {
		t.Errorf("tool.name = %q, want %q", driver.Name, "ThreatEcho")
	}
	if driver.InformationURI != "https://github.com/ThreatEcho/threatecho" {
		t.Errorf("tool.informationUri = %q", driver.InformationURI)
	}
	// Version should be set (at least "dev" in test builds).
	if driver.Version == "" {
		t.Error("tool.version should not be empty")
	}
}

// --- Policy SARIF tests ---

func TestPolicySARIFReport_ValidJSON(t *testing.T) {
	r := testPolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicySARIFReport(&buf, r, "campaigns/agent-escape.yaml"); err != nil {
		t.Fatalf("PolicySARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v\noutput:\n%s", err, buf.String())
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
}

func TestPolicySARIFReport_CorrectResultCount(t *testing.T) {
	r := testPolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicySARIFReport(&buf, r, "campaigns/agent-escape.yaml"); err != nil {
		t.Fatalf("PolicySARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	run := log.Runs[0]
	if len(run.Results) != 3 {
		t.Errorf("results = %d, want 3 (one per violation)", len(run.Results))
	}
}

func TestPolicySARIFReport_UniqueRules(t *testing.T) {
	r := testPolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicySARIFReport(&buf, r, "campaigns/agent-escape.yaml"); err != nil {
		t.Fatalf("PolicySARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	rules := log.Runs[0].Tool.Driver.Rules
	// Two unique rule IDs: "no-shell" and "alert-exfil".
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2 (unique rule IDs)", len(rules))
	}
	if rules[0].ID != "no-shell" {
		t.Errorf("rule[0].id = %q, want %q", rules[0].ID, "no-shell")
	}
	if rules[1].ID != "alert-exfil" {
		t.Errorf("rule[1].id = %q, want %q", rules[1].ID, "alert-exfil")
	}
}

func TestPolicySARIFReport_DenyIsError(t *testing.T) {
	r := testPolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicySARIFReport(&buf, r, "campaigns/agent-escape.yaml"); err != nil {
		t.Fatalf("PolicySARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	results := log.Runs[0].Results

	// Violation 0: deny -> error
	if results[0].Level != "error" {
		t.Errorf("result[0].level = %q, want %q (deny -> error)", results[0].Level, "error")
	}
	// Violation 1: alert -> warning
	if results[1].Level != "warning" {
		t.Errorf("result[1].level = %q, want %q (alert -> warning)", results[1].Level, "warning")
	}
	// Violation 2: deny -> error
	if results[2].Level != "error" {
		t.Errorf("result[2].level = %q, want %q (deny -> error)", results[2].Level, "error")
	}
}

func TestPolicySARIFReport_RuleIndex(t *testing.T) {
	r := testPolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicySARIFReport(&buf, r, "campaigns/agent-escape.yaml"); err != nil {
		t.Fatalf("PolicySARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	results := log.Runs[0].Results

	// "no-shell" is rule index 0, "alert-exfil" is rule index 1.
	if results[0].RuleIndex != 0 {
		t.Errorf("result[0].ruleIndex = %d, want 0", results[0].RuleIndex)
	}
	if results[1].RuleIndex != 1 {
		t.Errorf("result[1].ruleIndex = %d, want 1", results[1].RuleIndex)
	}
	// Third violation reuses "no-shell" -> index 0.
	if results[2].RuleIndex != 0 {
		t.Errorf("result[2].ruleIndex = %d, want 0", results[2].RuleIndex)
	}
}

func TestPolicySARIFReport_Properties(t *testing.T) {
	r := testPolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicySARIFReport(&buf, r, "campaigns/agent-escape.yaml"); err != nil {
		t.Fatalf("PolicySARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	props := log.Runs[0].Results[0].Properties
	if props["stage_id"] != "stage-3" {
		t.Errorf("result[0].properties.stage_id = %v, want %q", props["stage_id"], "stage-3")
	}
	if props["technique"] != "T1059" {
		t.Errorf("result[0].properties.technique = %v, want %q", props["technique"], "T1059")
	}
	if props["tactic"] != "execution" {
		t.Errorf("result[0].properties.tactic = %v, want %q", props["tactic"], "execution")
	}
	if props["tool"] != "shell_exec" {
		t.Errorf("result[0].properties.tool = %v, want %q", props["tool"], "shell_exec")
	}
	if props["effect"] != "deny" {
		t.Errorf("result[0].properties.effect = %v, want %q", props["effect"], "deny")
	}
}

func TestPolicySARIFReport_EmptyInput(t *testing.T) {
	r := &policy.EvalResult{
		Policy:      "empty-policy",
		Campaign:    "empty-campaign",
		TotalStages: 0,
	}
	var buf bytes.Buffer
	if err := PolicySARIFReport(&buf, r, "empty.yaml"); err != nil {
		t.Fatalf("PolicySARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v\noutput:\n%s", err, buf.String())
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(log.Runs[0].Results))
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("rules = %d, want 0 (no violations, no rules)", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestPolicySARIFReport_Location(t *testing.T) {
	r := testPolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicySARIFReport(&buf, r, "campaigns/agent-escape.yaml"); err != nil {
		t.Fatalf("PolicySARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	for i, result := range log.Runs[0].Results {
		if len(result.Locations) != 1 {
			t.Errorf("result[%d].locations = %d, want 1", i, len(result.Locations))
			continue
		}
		uri := result.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if uri != "campaigns/agent-escape.yaml" {
			t.Errorf("result[%d].location.uri = %q, want %q", i, uri, "campaigns/agent-escape.yaml")
		}
	}
}

func TestPolicySARIFReport_RuleLevelMatchesEffect(t *testing.T) {
	r := testPolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicySARIFReport(&buf, r, "test.yaml"); err != nil {
		t.Fatalf("PolicySARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	rules := log.Runs[0].Tool.Driver.Rules
	// "no-shell" (deny) -> error
	if rules[0].DefaultConfig.Level != "error" {
		t.Errorf("rule no-shell default level = %q, want %q", rules[0].DefaultConfig.Level, "error")
	}
	// "alert-exfil" (alert) -> warning
	if rules[1].DefaultConfig.Level != "warning" {
		t.Errorf("rule alert-exfil default level = %q, want %q", rules[1].DefaultConfig.Level, "warning")
	}
}

func TestGapSARIFReport_EmptyCampaignFile(t *testing.T) {
	r := testGapReport()
	var buf bytes.Buffer
	if err := GapSARIFReport(&buf, r, ""); err != nil {
		t.Fatalf("GapSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	// With empty campaign file, results should have no locations.
	for i, result := range log.Runs[0].Results {
		if len(result.Locations) != 0 {
			t.Errorf("result[%d].locations = %d, want 0 (empty campaignFile)", i, len(result.Locations))
		}
	}
}

// ---------------------------------------------------------------------------
// Finding SARIF tests
// ---------------------------------------------------------------------------

func TestFindingSARIFReport_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := FindingSARIFReport(&buf, nil); err != nil {
		t.Fatalf("FindingSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v\noutput:\n%s", err, buf.String())
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(log.Runs[0].Results))
	}
}

func TestFindingSARIFReport_SingleFinding(t *testing.T) {
	findings := []Finding{
		{
			RuleID:   "CUSTOM-001",
			Level:    "error",
			Message:  "Something is wrong",
			FilePath: "config/agent.yaml",
			Line:     42,
			Category: "validation",
		},
	}

	var buf bytes.Buffer
	if err := FindingSARIFReport(&buf, findings); err != nil {
		t.Fatalf("FindingSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	run := log.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	if run.Results[0].RuleID != "CUSTOM-001" {
		t.Errorf("ruleId = %q, want %q", run.Results[0].RuleID, "CUSTOM-001")
	}
	if run.Results[0].Level != "error" {
		t.Errorf("level = %q, want %q", run.Results[0].Level, "error")
	}
	if run.Results[0].Message.Text != "Something is wrong" {
		t.Errorf("message = %q", run.Results[0].Message.Text)
	}
}

func TestFindingSARIFReport_MultipleFindings(t *testing.T) {
	findings := []Finding{
		{RuleID: "R-001", Level: "error", Message: "Error one", FilePath: "a.yaml"},
		{RuleID: "R-002", Level: "warning", Message: "Warn two", FilePath: "b.yaml"},
		{RuleID: "R-001", Level: "error", Message: "Error three", FilePath: "c.yaml"},
	}

	var buf bytes.Buffer
	if err := FindingSARIFReport(&buf, findings); err != nil {
		t.Fatalf("FindingSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	run := log.Runs[0]
	if len(run.Results) != 3 {
		t.Errorf("results = %d, want 3", len(run.Results))
	}
	// Rule deduplication: R-001 and R-002.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules = %d, want 2 (deduplicated)", len(run.Tool.Driver.Rules))
	}
}

func TestFindingSARIFReport_Location(t *testing.T) {
	findings := []Finding{
		{RuleID: "LOC-001", Level: "warning", Message: "test", FilePath: "policies/main.yaml", Line: 15},
	}

	var buf bytes.Buffer
	if err := FindingSARIFReport(&buf, findings); err != nil {
		t.Fatalf("FindingSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	result := log.Runs[0].Results[0]
	if len(result.Locations) != 1 {
		t.Fatalf("locations = %d, want 1", len(result.Locations))
	}
	loc := result.Locations[0]
	if loc.PhysicalLocation.ArtifactLocation.URI != "policies/main.yaml" {
		t.Errorf("uri = %q", loc.PhysicalLocation.ArtifactLocation.URI)
	}
	if loc.PhysicalLocation.Region == nil || loc.PhysicalLocation.Region.StartLine != 15 {
		t.Errorf("region startLine should be 15")
	}
}

func TestFindingSARIFReport_NoLocation(t *testing.T) {
	findings := []Finding{
		{RuleID: "NO-LOC", Level: "info", Message: "no file"},
	}

	var buf bytes.Buffer
	if err := FindingSARIFReport(&buf, findings); err != nil {
		t.Fatalf("FindingSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if len(log.Runs[0].Results[0].Locations) != 0 {
		t.Errorf("expected no locations for finding with empty file path")
	}
}

func TestFindingSARIFReport_LevelMapping(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"error", "error"},
		{"warning", "warning"},
		{"info", "note"},
		{"note", "note"},
		{"style", "none"},
		{"none", "none"},
		{"unknown", "warning"},
	}

	for _, tc := range cases {
		findings := []Finding{
			{RuleID: "LVL-" + tc.input, Level: tc.input, Message: "test"},
		}
		var buf bytes.Buffer
		if err := FindingSARIFReport(&buf, findings); err != nil {
			t.Fatalf("FindingSARIFReport error for level %q: %v", tc.input, err)
		}
		var log sarifLog
		if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
			t.Fatalf("JSON parse error for level %q: %v", tc.input, err)
		}
		got := log.Runs[0].Results[0].Level
		if got != tc.want {
			t.Errorf("level %q → %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestFindingSARIFReport_SchemaCompliance(t *testing.T) {
	findings := []Finding{
		{RuleID: "SCH-001", Level: "error", Message: "test"},
	}
	var buf bytes.Buffer
	if err := FindingSARIFReport(&buf, findings); err != nil {
		t.Fatalf("FindingSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if log.Schema != sarifSchema {
		t.Errorf("$schema = %q, want SARIF 2.1.0 schema", log.Schema)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
}

func TestFindingSARIFReport_RuleDeduplication(t *testing.T) {
	findings := []Finding{
		{RuleID: "DUP-001", Level: "error", Message: "first"},
		{RuleID: "DUP-001", Level: "error", Message: "second"},
		{RuleID: "DUP-001", Level: "error", Message: "third"},
	}

	var buf bytes.Buffer
	if err := FindingSARIFReport(&buf, findings); err != nil {
		t.Fatalf("FindingSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("rules = %d, want 1 (all same ruleId)", len(log.Runs[0].Tool.Driver.Rules))
	}
	if len(log.Runs[0].Results) != 3 {
		t.Errorf("results = %d, want 3", len(log.Runs[0].Results))
	}
}

// ---------------------------------------------------------------------------
// Lint SARIF tests
// ---------------------------------------------------------------------------

func testLintReport() *policy.LintReport {
	return &policy.LintReport{
		PolicyName:   "agent-sandbox",
		TotalRules:   10,
		FindingCount: 4,
		ErrorCount:   1,
		WarningCount: 1,
		InfoCount:    1,
		StyleCount:   1,
		Score:        0.85,
		Grade:        "B",
		Findings: []policy.LintFinding{
			{
				Rule:       "SEC-003",
				Severity:   policy.LintError,
				Category:   policy.LintCatSecurity,
				Message:    "Unconditionally allows elevated tool shell_exec",
				RuleID:     "allow-shell",
				Suggestion: "Add conditions to restrict elevated tool access",
			},
			{
				Rule:       "SEC-002",
				Severity:   policy.LintWarning,
				Category:   policy.LintCatSecurity,
				Message:    "Policy has no deny rules",
				Suggestion: "Add deny rules for dangerous tools",
			},
			{
				Rule:       "COV-001",
				Severity:   policy.LintInfo,
				Category:   policy.LintCatCoverage,
				Message:    "Policy has only 2 rules",
				Suggestion: "A mature policy typically has 5+ rules",
			},
			{
				Rule:       "NAM-002",
				Severity:   policy.LintStyle,
				Category:   policy.LintCatNaming,
				Message:    "Rule ID is not kebab-case or snake_case",
				RuleID:     "AllowShell",
				Suggestion: "Use kebab-case for consistency",
			},
		},
	}
}

func TestLintSARIFReport_ValidJSON(t *testing.T) {
	r := testLintReport()
	var buf bytes.Buffer
	if err := LintSARIFReport(&buf, r, "policies/sandbox.yaml"); err != nil {
		t.Fatalf("LintSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v\noutput:\n%s", err, buf.String())
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
}

func TestLintSARIFReport_CorrectResultCount(t *testing.T) {
	r := testLintReport()
	var buf bytes.Buffer
	if err := LintSARIFReport(&buf, r, "policies/sandbox.yaml"); err != nil {
		t.Fatalf("LintSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if len(log.Runs[0].Results) != 4 {
		t.Errorf("results = %d, want 4", len(log.Runs[0].Results))
	}
}

func TestLintSARIFReport_UniqueRules(t *testing.T) {
	r := testLintReport()
	var buf bytes.Buffer
	if err := LintSARIFReport(&buf, r, "policies/sandbox.yaml"); err != nil {
		t.Fatalf("LintSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	// 4 findings but 4 unique rule IDs: SEC-003, SEC-002, COV-001, NAM-002.
	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 4 {
		t.Errorf("rules = %d, want 4 unique", len(rules))
	}
}

func TestLintSARIFReport_LevelMapping(t *testing.T) {
	r := testLintReport()
	var buf bytes.Buffer
	if err := LintSARIFReport(&buf, r, "test.yaml"); err != nil {
		t.Fatalf("LintSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	results := log.Runs[0].Results
	// error → error, warning → warning, info → note, style → none.
	wantLevels := []string{"error", "warning", "note", "none"}
	for i, want := range wantLevels {
		if results[i].Level != want {
			t.Errorf("result[%d].level = %q, want %q", i, results[i].Level, want)
		}
	}
}

func TestLintSARIFReport_Location(t *testing.T) {
	r := testLintReport()
	var buf bytes.Buffer
	if err := LintSARIFReport(&buf, r, "policies/sandbox.yaml"); err != nil {
		t.Fatalf("LintSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	for i, result := range log.Runs[0].Results {
		if len(result.Locations) != 1 {
			t.Errorf("result[%d].locations = %d, want 1", i, len(result.Locations))
			continue
		}
		uri := result.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if uri != "policies/sandbox.yaml" {
			t.Errorf("result[%d].uri = %q", i, uri)
		}
	}
}

func TestLintSARIFReport_NoLocation(t *testing.T) {
	r := testLintReport()
	var buf bytes.Buffer
	if err := LintSARIFReport(&buf, r, ""); err != nil {
		t.Fatalf("LintSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	for i, result := range log.Runs[0].Results {
		if len(result.Locations) != 0 {
			t.Errorf("result[%d].locations = %d, want 0 (empty policyPath)", i, len(result.Locations))
		}
	}
}

func TestLintSARIFReport_Properties(t *testing.T) {
	r := testLintReport()
	var buf bytes.Buffer
	if err := LintSARIFReport(&buf, r, "test.yaml"); err != nil {
		t.Fatalf("LintSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	props := log.Runs[0].Results[0].Properties
	if props["category"] != "security" {
		t.Errorf("properties.category = %v, want %q", props["category"], "security")
	}
	if props["rule_id"] != "allow-shell" {
		t.Errorf("properties.rule_id = %v, want %q", props["rule_id"], "allow-shell")
	}
	if props["suggestion"] != "Add conditions to restrict elevated tool access" {
		t.Errorf("properties.suggestion = %v", props["suggestion"])
	}
}

func TestLintSARIFReport_EmptyFindings(t *testing.T) {
	r := &policy.LintReport{
		PolicyName: "clean",
		TotalRules: 5,
		Score:      1.0,
		Grade:      "A",
	}
	var buf bytes.Buffer
	if err := LintSARIFReport(&buf, r, "clean.yaml"); err != nil {
		t.Fatalf("LintSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(log.Runs[0].Results))
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("rules = %d, want 0", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestLintSARIFReport_RuleTags(t *testing.T) {
	r := testLintReport()
	var buf bytes.Buffer
	if err := LintSARIFReport(&buf, r, "test.yaml"); err != nil {
		t.Fatalf("LintSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	// First rule (SEC-003) should have tags including "policy-lint" and "security".
	rule := log.Runs[0].Tool.Driver.Rules[0]
	tags, ok := rule.Properties["tags"]
	if !ok {
		t.Fatal("rule has no tags property")
	}
	tagSlice, ok := tags.([]any)
	if !ok {
		t.Fatalf("tags type = %T, want []any", tags)
	}
	foundPolicyLint := false
	foundSecurity := false
	for _, tag := range tagSlice {
		if s, ok := tag.(string); ok {
			if s == "policy-lint" {
				foundPolicyLint = true
			}
			if s == "security" {
				foundSecurity = true
			}
		}
	}
	if !foundPolicyLint {
		t.Error("tags missing 'policy-lint'")
	}
	if !foundSecurity {
		t.Error("tags missing 'security'")
	}
}

// ---------------------------------------------------------------------------
// Threat model SARIF tests
// ---------------------------------------------------------------------------

func testThreatModel() *engine.ThreatModel {
	return &engine.ThreatModel{
		Name:        "Test Deployment",
		GeneratedAt: "2025-06-15T10:00:00Z",
		Threats: []engine.Threat{
			{
				ID:               "THR-001",
				Category:         engine.Spoofing,
				Title:            "Unattested agent identity",
				Description:      "Agent 'retrieval-bot' has no verified attestation.",
				AffectedAgent:    "retrieval-bot",
				Severity:         "high",
				Likelihood:       "likely",
				RiskScore:        5.6,
				MitigationStatus: "unmitigated",
			},
			{
				ID:               "THR-002",
				Category:         engine.Tampering,
				Title:            "Unauthorized write access",
				Description:      "Tool db_write allows tampering.",
				AffectedAgent:    "retrieval-bot",
				AffectedTool:     "db_write",
				Severity:         "critical",
				Likelihood:       "likely",
				RiskScore:        10.0,
				MitigationStatus: "partial",
			},
			{
				ID:               "THR-003",
				Category:         engine.Spoofing,
				Title:            "Delegating agent impersonation",
				Description:      "Orchestrator delegates to sub-agents.",
				AffectedAgent:    "orchestrator-main",
				Severity:         "medium",
				Likelihood:       "possible",
				RiskScore:        2.0,
				MitigationStatus: "mitigated",
			},
		},
		ThreatCount:   3,
		CriticalCount: 1,
		HighCount:     1,
		MediumCount:   1,
		OverallRisk:   5.9,
		CategoryBreakdown: map[engine.ThreatCategory]int{
			engine.Spoofing:  2,
			engine.Tampering: 1,
		},
	}
}

func TestThreatSARIFReport_ValidJSON(t *testing.T) {
	m := testThreatModel()
	var buf bytes.Buffer
	if err := ThreatSARIFReport(&buf, m); err != nil {
		t.Fatalf("ThreatSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v\noutput:\n%s", err, buf.String())
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", log.Version, "2.1.0")
	}
}

func TestThreatSARIFReport_CorrectResultCount(t *testing.T) {
	m := testThreatModel()
	var buf bytes.Buffer
	if err := ThreatSARIFReport(&buf, m); err != nil {
		t.Fatalf("ThreatSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if len(log.Runs[0].Results) != 3 {
		t.Errorf("results = %d, want 3", len(log.Runs[0].Results))
	}
}

func TestThreatSARIFReport_STRIDERuleDeduplication(t *testing.T) {
	m := testThreatModel()
	var buf bytes.Buffer
	if err := ThreatSARIFReport(&buf, m); err != nil {
		t.Fatalf("ThreatSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	// 3 threats but 2 unique categories: spoofing, tampering.
	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 2 {
		t.Errorf("rules = %d, want 2 (spoofing + tampering)", len(rules))
	}
}

func TestThreatSARIFReport_LevelMapping(t *testing.T) {
	m := testThreatModel()
	var buf bytes.Buffer
	if err := ThreatSARIFReport(&buf, m); err != nil {
		t.Fatalf("ThreatSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	results := log.Runs[0].Results
	// high → error, critical → error, medium → warning
	wantLevels := []string{"error", "error", "warning"}
	for i, want := range wantLevels {
		if results[i].Level != want {
			t.Errorf("result[%d].level = %q, want %q", i, results[i].Level, want)
		}
	}
}

func TestThreatSARIFReport_Properties(t *testing.T) {
	m := testThreatModel()
	var buf bytes.Buffer
	if err := ThreatSARIFReport(&buf, m); err != nil {
		t.Fatalf("ThreatSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	props := log.Runs[0].Results[0].Properties
	if props["threat_id"] != "THR-001" {
		t.Errorf("properties.threat_id = %v, want %q", props["threat_id"], "THR-001")
	}
	if props["severity"] != "high" {
		t.Errorf("properties.severity = %v, want %q", props["severity"], "high")
	}
	if props["affected_agent"] != "retrieval-bot" {
		t.Errorf("properties.affected_agent = %v", props["affected_agent"])
	}
	if props["mitigation_status"] != "unmitigated" {
		t.Errorf("properties.mitigation_status = %v", props["mitigation_status"])
	}
}

func TestThreatSARIFReport_MessageContent(t *testing.T) {
	m := testThreatModel()
	var buf bytes.Buffer
	if err := ThreatSARIFReport(&buf, m); err != nil {
		t.Fatalf("ThreatSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	msg := log.Runs[0].Results[0].Message.Text
	if !strings.Contains(msg, "Unattested agent identity") {
		t.Errorf("message %q should contain title", msg)
	}
	if !strings.Contains(msg, "retrieval-bot") {
		t.Errorf("message %q should contain agent name", msg)
	}
}

func TestThreatSARIFReport_EmptyModel(t *testing.T) {
	m := &engine.ThreatModel{
		Name:              "Empty",
		CategoryBreakdown: map[engine.ThreatCategory]int{},
	}
	var buf bytes.Buffer
	if err := ThreatSARIFReport(&buf, m); err != nil {
		t.Fatalf("ThreatSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(log.Runs[0].Results))
	}
}

func TestThreatSARIFReport_RuleIDs(t *testing.T) {
	m := testThreatModel()
	var buf bytes.Buffer
	if err := ThreatSARIFReport(&buf, m); err != nil {
		t.Fatalf("ThreatSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	rules := log.Runs[0].Tool.Driver.Rules
	// First rule is STRIDE-spoofing (first seen), second is STRIDE-tampering.
	if rules[0].ID != "STRIDE-spoofing" {
		t.Errorf("rule[0].id = %q, want %q", rules[0].ID, "STRIDE-spoofing")
	}
	if rules[1].ID != "STRIDE-tampering" {
		t.Errorf("rule[1].id = %q, want %q", rules[1].ID, "STRIDE-tampering")
	}
}

func TestThreatSARIFReport_RuleTags(t *testing.T) {
	m := testThreatModel()
	var buf bytes.Buffer
	if err := ThreatSARIFReport(&buf, m); err != nil {
		t.Fatalf("ThreatSARIFReport error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	rule := log.Runs[0].Tool.Driver.Rules[0]
	tags, ok := rule.Properties["tags"]
	if !ok {
		t.Fatal("rule has no tags property")
	}
	tagSlice, ok := tags.([]any)
	if !ok {
		t.Fatalf("tags type = %T, want []any", tags)
	}
	foundStride := false
	for _, tag := range tagSlice {
		if s, ok := tag.(string); ok && s == "stride" {
			foundStride = true
		}
	}
	if !foundStride {
		t.Error("tags missing 'stride'")
	}
}

// ---------------------------------------------------------------------------
// FormatSARIF / WriteSARIF tests
// ---------------------------------------------------------------------------

func TestFormatSARIF(t *testing.T) {
	log := &sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "ThreatEcho",
						Version:        "test",
						InformationURI: sarifInfoURI,
					},
				},
			},
		},
	}

	s, err := FormatSARIF(log)
	if err != nil {
		t.Fatalf("FormatSARIF error: %v", err)
	}

	if !strings.Contains(s, `"version": "2.1.0"`) {
		t.Error("formatted output missing version")
	}
	if !strings.Contains(s, `"$schema"`) {
		t.Error("formatted output missing $schema")
	}

	// Should be valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(s), &parsed); err != nil {
		t.Errorf("FormatSARIF output is not valid JSON: %v", err)
	}
}

func TestWriteSARIF(t *testing.T) {
	log := &sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "ThreatEcho",
						Version:        "test",
						InformationURI: sarifInfoURI,
					},
				},
			},
		},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "output.sarif")

	if err := WriteSARIF(log, path); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var parsed sarifLog
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Written SARIF is not valid JSON: %v", err)
	}
	if parsed.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", parsed.Version, "2.1.0")
	}
}

func TestWriteSARIF_BadPath(t *testing.T) {
	log := &sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
	}

	err := WriteSARIF(log, "/nonexistent/dir/file.sarif")
	if err == nil {
		t.Error("WriteSARIF should fail with bad path")
	}
}
