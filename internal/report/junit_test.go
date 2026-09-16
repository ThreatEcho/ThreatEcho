// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/gap"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func sampleGapReport() *gap.GapReport {
	return &gap.GapReport{
		Gaps: []gap.Gap{
			{
				Type:         gap.GapDetectionMissing,
				CampaignName: "fin6-sim",
				StageID:      "stage-1",
				StageName:    "Credential Dump",
				Technique:    "T1003",
				Tactic:       "credential-access",
				Risk:         "high",
				Description:  "Stage declares expected telemetry but no detection rules",
			},
			{
				Type:         gap.GapTelemetryMissing,
				CampaignName: "fin6-sim",
				StageID:      "stage-2",
				StageName:    "Lateral Move",
				Technique:    "T1021",
				Tactic:       "lateral-movement",
				Risk:         "medium",
				Description:  "Stage declares no expected telemetry",
			},
			{
				Type:        gap.GapTacticUncovered,
				Tactic:      "exfiltration",
				Risk:        "critical",
				Description: "ATT&CK tactic \"Exfiltration\" has no stage coverage across any analyzed campaign",
			},
		},
		RiskSummary: gap.RiskSummary{
			Critical: 1,
			High:     1,
			Medium:   1,
			Total:    3,
			Score:    56.7,
		},
	}
}

func samplePolicyEvalResult() *policy.EvalResult {
	return &policy.EvalResult{
		Policy:      "agent-sandbox-policy",
		Campaign:    "prompt-injection-sim",
		TotalStages: 5,
		Allowed:     3,
		Denied:      1,
		Alerted:     1,
		Violations: []policy.Violation{
			{
				RuleID:    "R-001",
				RuleDesc:  "block shell execution",
				Effect:    "deny",
				StageID:   "stage-3",
				StageName: "Shell Escape",
				Technique: "T1059",
				Tactic:    "execution",
				Tool:      "shell_exec",
				Reason:    "denied by rule \"R-001\": block shell execution",
			},
			{
				RuleID:    "R-005",
				RuleDesc:  "alert on external HTTP",
				Effect:    "alert",
				StageID:   "stage-4",
				StageName: "Exfil HTTP",
				Technique: "T1048",
				Tactic:    "exfiltration",
				Tool:      "http_request",
				Reason:    "alert from rule \"R-005\": alert on external HTTP",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// GapJUnitReport tests
// ---------------------------------------------------------------------------

func TestGapJUnitReport_ValidXML(t *testing.T) {
	r := sampleGapReport()
	var buf bytes.Buffer
	if err := GapJUnitReport(&buf, r); err != nil {
		t.Fatalf("GapJUnitReport error: %v", err)
	}

	output := buf.String()

	// Must start with XML header.
	if !strings.HasPrefix(output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>") {
		t.Error("output should start with XML declaration")
	}

	// Must unmarshal back cleanly.
	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}
}

func TestGapJUnitReport_SuiteAttributes(t *testing.T) {
	r := sampleGapReport()
	var buf bytes.Buffer
	if err := GapJUnitReport(&buf, r); err != nil {
		t.Fatalf("GapJUnitReport error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	if len(suites.Suites) != 1 {
		t.Fatalf("expected 1 suite, got %d", len(suites.Suites))
	}
	s := suites.Suites[0]

	if s.Name != "threatecho-gap-analysis" {
		t.Errorf("suite name = %q, want %q", s.Name, "threatecho-gap-analysis")
	}
	if s.Tests != 3 {
		t.Errorf("tests = %d, want 3", s.Tests)
	}
	if s.Failures != 3 {
		t.Errorf("failures = %d, want 3", s.Failures)
	}
	if s.Errors != 0 {
		t.Errorf("errors = %d, want 0", s.Errors)
	}
	if s.Skipped != 0 {
		t.Errorf("skipped = %d, want 0", s.Skipped)
	}
}

func TestGapJUnitReport_TestCaseNames(t *testing.T) {
	r := sampleGapReport()
	var buf bytes.Buffer
	if err := GapJUnitReport(&buf, r); err != nil {
		t.Fatalf("GapJUnitReport error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	cases := suites.Suites[0].Cases
	if len(cases) != 3 {
		t.Fatalf("expected 3 test cases, got %d", len(cases))
	}

	// detection_missing case.
	if cases[0].Name != "stage-1: detection for T1003" {
		t.Errorf("case[0].name = %q, want %q", cases[0].Name, "stage-1: detection for T1003")
	}
	if cases[0].ClassName != "fin6-sim" {
		t.Errorf("case[0].classname = %q, want %q", cases[0].ClassName, "fin6-sim")
	}

	// telemetry_missing case.
	if cases[1].Name != "stage-2: telemetry for T1021" {
		t.Errorf("case[1].name = %q, want %q", cases[1].Name, "stage-2: telemetry for T1021")
	}
	if cases[1].ClassName != "fin6-sim" {
		t.Errorf("case[1].classname = %q, want %q", cases[1].ClassName, "fin6-sim")
	}

	// tactic_uncovered case.
	if cases[2].Name != "tactic: exfiltration" {
		t.Errorf("case[2].name = %q, want %q", cases[2].Name, "tactic: exfiltration")
	}
	if cases[2].ClassName != "aggregate" {
		t.Errorf("case[2].classname = %q, want %q", cases[2].ClassName, "aggregate")
	}
}

func TestGapJUnitReport_FailureDetails(t *testing.T) {
	r := sampleGapReport()
	var buf bytes.Buffer
	if err := GapJUnitReport(&buf, r); err != nil {
		t.Fatalf("GapJUnitReport error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	cases := suites.Suites[0].Cases

	// Every gap should have a failure element.
	for i, tc := range cases {
		if tc.Failure == nil {
			t.Fatalf("case[%d] has no failure element", i)
		}
	}

	// Check failure types match gap types.
	if cases[0].Failure.Type != "detection_missing" {
		t.Errorf("case[0].failure.type = %q, want %q", cases[0].Failure.Type, "detection_missing")
	}
	if cases[1].Failure.Type != "telemetry_missing" {
		t.Errorf("case[1].failure.type = %q, want %q", cases[1].Failure.Type, "telemetry_missing")
	}
	if cases[2].Failure.Type != "tactic_uncovered" {
		t.Errorf("case[2].failure.type = %q, want %q", cases[2].Failure.Type, "tactic_uncovered")
	}

	// Failure messages should contain risk level.
	if !strings.Contains(cases[0].Failure.Message, "HIGH") {
		t.Errorf("case[0].failure.message should contain risk level HIGH, got %q", cases[0].Failure.Message)
	}
	if !strings.Contains(cases[2].Failure.Message, "CRITICAL") {
		t.Errorf("case[2].failure.message should contain risk level CRITICAL, got %q", cases[2].Failure.Message)
	}

	// Failure text should contain the gap description.
	if cases[0].Failure.Text == "" {
		t.Error("case[0].failure text should not be empty")
	}
}

func TestGapJUnitReport_EmptyReport(t *testing.T) {
	r := &gap.GapReport{}
	var buf bytes.Buffer
	if err := GapJUnitReport(&buf, r); err != nil {
		t.Fatalf("GapJUnitReport error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	if len(suites.Suites) != 1 {
		t.Fatalf("expected 1 suite, got %d", len(suites.Suites))
	}
	s := suites.Suites[0]
	if s.Tests != 0 {
		t.Errorf("tests = %d, want 0", s.Tests)
	}
	if s.Failures != 0 {
		t.Errorf("failures = %d, want 0", s.Failures)
	}
	if len(s.Cases) != 0 {
		t.Errorf("expected 0 cases, got %d", len(s.Cases))
	}
}

// ---------------------------------------------------------------------------
// PolicyJUnitReport tests
// ---------------------------------------------------------------------------

func TestPolicyJUnitReport_ValidXML(t *testing.T) {
	r := samplePolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicyJUnitReport(&buf, r); err != nil {
		t.Fatalf("PolicyJUnitReport error: %v", err)
	}

	output := buf.String()

	if !strings.HasPrefix(output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>") {
		t.Error("output should start with XML declaration")
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}
}

func TestPolicyJUnitReport_SuiteAttributes(t *testing.T) {
	r := samplePolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicyJUnitReport(&buf, r); err != nil {
		t.Fatalf("PolicyJUnitReport error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	if len(suites.Suites) != 1 {
		t.Fatalf("expected 1 suite, got %d", len(suites.Suites))
	}
	s := suites.Suites[0]

	if s.Name != "threatecho-policy-eval" {
		t.Errorf("suite name = %q, want %q", s.Name, "threatecho-policy-eval")
	}
	if s.Tests != 5 {
		t.Errorf("tests = %d, want 5 (TotalStages)", s.Tests)
	}
	if s.Failures != 2 {
		t.Errorf("failures = %d, want 2 (Denied+Alerted)", s.Failures)
	}
	if s.Errors != 0 {
		t.Errorf("errors = %d, want 0", s.Errors)
	}
}

func TestPolicyJUnitReport_TestCaseDetails(t *testing.T) {
	r := samplePolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicyJUnitReport(&buf, r); err != nil {
		t.Fatalf("PolicyJUnitReport error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	cases := suites.Suites[0].Cases
	if len(cases) != 2 {
		t.Fatalf("expected 2 test cases (violations only), got %d", len(cases))
	}

	// Denied stage.
	if cases[0].Name != "Shell Escape" {
		t.Errorf("case[0].name = %q, want %q", cases[0].Name, "Shell Escape")
	}
	if cases[0].ClassName != "prompt-injection-sim" {
		t.Errorf("case[0].classname = %q, want %q", cases[0].ClassName, "prompt-injection-sim")
	}
	if cases[0].Failure == nil {
		t.Fatal("case[0] should have a failure element")
	}
	if cases[0].Failure.Type != "deny" {
		t.Errorf("case[0].failure.type = %q, want %q", cases[0].Failure.Type, "deny")
	}

	// Alerted stage.
	if cases[1].Name != "Exfil HTTP" {
		t.Errorf("case[1].name = %q, want %q", cases[1].Name, "Exfil HTTP")
	}
	if cases[1].Failure == nil {
		t.Fatal("case[1] should have a failure element")
	}
	if cases[1].Failure.Type != "alert" {
		t.Errorf("case[1].failure.type = %q, want %q", cases[1].Failure.Type, "alert")
	}
}

func TestPolicyJUnitReport_FailureMessages(t *testing.T) {
	r := samplePolicyEvalResult()
	var buf bytes.Buffer
	if err := PolicyJUnitReport(&buf, r); err != nil {
		t.Fatalf("PolicyJUnitReport error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	cases := suites.Suites[0].Cases

	// Failure message should contain rule ID and description.
	msg0 := cases[0].Failure.Message
	if !strings.Contains(msg0, "R-001") {
		t.Errorf("case[0].failure.message should contain rule ID R-001, got %q", msg0)
	}
	if !strings.Contains(msg0, "block shell execution") {
		t.Errorf("case[0].failure.message should contain rule description, got %q", msg0)
	}
	if !strings.Contains(msg0, "DENY") {
		t.Errorf("case[0].failure.message should contain effect DENY, got %q", msg0)
	}

	msg1 := cases[1].Failure.Message
	if !strings.Contains(msg1, "R-005") {
		t.Errorf("case[1].failure.message should contain rule ID R-005, got %q", msg1)
	}
	if !strings.Contains(msg1, "ALERT") {
		t.Errorf("case[1].failure.message should contain effect ALERT, got %q", msg1)
	}

	// Failure text should contain the reason string.
	if !strings.Contains(cases[0].Failure.Text, "denied by rule") {
		t.Errorf("case[0].failure.text should contain reason, got %q", cases[0].Failure.Text)
	}
}

func TestPolicyJUnitReport_EmptyResult(t *testing.T) {
	r := &policy.EvalResult{
		Policy:      "empty-policy",
		Campaign:    "no-campaign",
		TotalStages: 0,
	}
	var buf bytes.Buffer
	if err := PolicyJUnitReport(&buf, r); err != nil {
		t.Fatalf("PolicyJUnitReport error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	if len(suites.Suites) != 1 {
		t.Fatalf("expected 1 suite, got %d", len(suites.Suites))
	}
	s := suites.Suites[0]
	if s.Tests != 0 {
		t.Errorf("tests = %d, want 0", s.Tests)
	}
	if s.Failures != 0 {
		t.Errorf("failures = %d, want 0", s.Failures)
	}
	if len(s.Cases) != 0 {
		t.Errorf("expected 0 cases, got %d", len(s.Cases))
	}
}

func TestPolicyJUnitReport_AllAllowed(t *testing.T) {
	r := &policy.EvalResult{
		Policy:      "permissive",
		Campaign:    "benign-campaign",
		TotalStages: 4,
		Allowed:     4,
		Denied:      0,
		Alerted:     0,
		Violations:  nil,
	}
	var buf bytes.Buffer
	if err := PolicyJUnitReport(&buf, r); err != nil {
		t.Fatalf("PolicyJUnitReport error: %v", err)
	}

	var suites junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("XML unmarshal error: %v", err)
	}

	s := suites.Suites[0]
	if s.Tests != 4 {
		t.Errorf("tests = %d, want 4", s.Tests)
	}
	if s.Failures != 0 {
		t.Errorf("failures = %d, want 0", s.Failures)
	}
	if len(s.Cases) != 0 {
		t.Errorf("expected 0 cases (no violations to list), got %d", len(s.Cases))
	}
}
