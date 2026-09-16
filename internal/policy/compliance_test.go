// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// EvaluateCompliance — single trace tests
// ---------------------------------------------------------------------------

func TestEvaluateCompliance_NilPolicy(t *testing.T) {
	trace := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
	)
	cr := EvaluateCompliance(nil, trace)
	if cr == nil {
		t.Fatal("expected non-nil result")
	}
	if !cr.Compliant {
		t.Error("expected compliant with nil policy")
	}
	if cr.Score != 1.0 {
		t.Errorf("expected score 1.0, got %.2f", cr.Score)
	}
	if cr.Grade != "A" {
		t.Errorf("expected grade A, got %s", cr.Grade)
	}
}

func TestEvaluateCompliance_NilTrace(t *testing.T) {
	pol := traceTestPolicy("test-pol",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
	)
	cr := EvaluateCompliance(pol, nil)
	if cr == nil {
		t.Fatal("expected non-nil result")
	}
	if !cr.Compliant {
		t.Error("expected compliant with nil trace")
	}
	if cr.PolicyName != "test-pol" {
		t.Errorf("expected policy name 'test-pol', got %q", cr.PolicyName)
	}
	if cr.Score != 1.0 {
		t.Errorf("expected score 1.0, got %.2f", cr.Score)
	}
}

func TestEvaluateCompliance_EmptyTrace(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
	)
	trace := makeTrace("t1", "agent") // no events
	cr := EvaluateCompliance(pol, trace)
	if !cr.Compliant {
		t.Error("expected compliant with empty trace")
	}
	if cr.Score != 1.0 {
		t.Errorf("expected score 1.0, got %.2f", cr.Score)
	}
	if cr.TraceName != "t1" {
		t.Errorf("expected trace name 't1', got %q", cr.TraceName)
	}
	if len(cr.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(cr.Violations))
	}
}

func TestEvaluateCompliance_AllAllowed(t *testing.T) {
	pol := traceTestPolicy("permissive",
		allowRule("allow-all", "Allow all tools", 10, []string{"*"}),
	)
	trace := makeTrace("t1", "agent",
		toolCallEvent("e1", "http_request", "send", ""),
		toolCallEvent("e2", "search_knowledge_base", "query", ""),
	)
	cr := EvaluateCompliance(pol, trace)
	if !cr.Compliant {
		t.Error("expected compliant when all allowed")
	}
	if cr.DenyCount != 0 {
		t.Errorf("expected 0 denies, got %d", cr.DenyCount)
	}
	if cr.AllowCount != 2 {
		t.Errorf("expected 2 allowed, got %d", cr.AllowCount)
	}
	if cr.Score != 1.0 {
		t.Errorf("expected score 1.0, got %.2f", cr.Score)
	}
	if cr.Grade != "A" {
		t.Errorf("expected grade A, got %s", cr.Grade)
	}
}

func TestEvaluateCompliance_SingleDeny(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell execution", 100, []string{"shell_exec"}),
	)
	trace := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
	)
	cr := EvaluateCompliance(pol, trace)
	if cr.Compliant {
		t.Error("expected non-compliant with deny")
	}
	if cr.DenyCount != 1 {
		t.Errorf("expected 1 deny, got %d", cr.DenyCount)
	}
	if len(cr.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(cr.Violations))
	}
	if cr.Violations[0].Effect != "deny" {
		t.Errorf("expected deny effect, got %q", cr.Violations[0].Effect)
	}
}

func TestEvaluateCompliance_MultipleDenies(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
		denyRule("deny-proc", "Block process", 95, []string{"process_exec"}),
	)
	trace := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
		toolCallEvent("e2", "process_exec", "execute", ""),
		toolCallEvent("e3", "http_request", "send", ""),
	)
	cr := EvaluateCompliance(pol, trace)
	if cr.Compliant {
		t.Error("expected non-compliant")
	}
	if cr.DenyCount != 2 {
		t.Errorf("expected 2 denies, got %d", cr.DenyCount)
	}
	if len(cr.Violations) != 2 {
		t.Errorf("expected 2 violations, got %d", len(cr.Violations))
	}
	// Score: 1.0 - 2*0.15 = 0.70
	if math.Abs(cr.Score-0.70) > 0.01 {
		t.Errorf("expected score ~0.70, got %.2f", cr.Score)
	}
}

func TestEvaluateCompliance_AlertsOnly(t *testing.T) {
	pol := traceTestPolicy("monitoring",
		alertRule("alert-http", "Alert on HTTP", 50, []string{"http_request"}),
		alertRule("alert-search", "Alert on search", 40, []string{"search_knowledge_base"}),
	)
	trace := makeTrace("t1", "agent",
		toolCallEvent("e1", "http_request", "send", ""),
		toolCallEvent("e2", "search_knowledge_base", "query", ""),
	)
	cr := EvaluateCompliance(pol, trace)
	if !cr.Compliant {
		t.Error("expected compliant — alerts should not cause non-compliance")
	}
	if cr.AlertCount != 2 {
		t.Errorf("expected 2 alerts, got %d", cr.AlertCount)
	}
	if cr.DenyCount != 0 {
		t.Errorf("expected 0 denies, got %d", cr.DenyCount)
	}
	// Score: 1.0 - 2*0.05 = 0.90
	if math.Abs(cr.Score-0.90) > 0.01 {
		t.Errorf("expected score ~0.90, got %.2f", cr.Score)
	}
}

func TestEvaluateCompliance_MixedResults(t *testing.T) {
	pol := traceTestPolicy("mixed",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
		alertRule("alert-http", "Alert HTTP", 50, []string{"http_request"}),
		allowRule("allow-search", "Allow search", 10, []string{"search_knowledge_base"}),
	)
	trace := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
		toolCallEvent("e2", "http_request", "send", ""),
		toolCallEvent("e3", "search_knowledge_base", "query", ""),
	)
	cr := EvaluateCompliance(pol, trace)
	if cr.Compliant {
		t.Error("expected non-compliant")
	}
	if cr.DenyCount != 1 {
		t.Errorf("expected 1 deny, got %d", cr.DenyCount)
	}
	if cr.AlertCount != 1 {
		t.Errorf("expected 1 alert, got %d", cr.AlertCount)
	}
	if cr.AllowCount != 1 {
		t.Errorf("expected 1 allow, got %d", cr.AllowCount)
	}
	// Score: 1.0 - 0.15 - 0.05 = 0.80
	if math.Abs(cr.Score-0.80) > 0.01 {
		t.Errorf("expected score ~0.80, got %.2f", cr.Score)
	}
}

func TestEvaluateCompliance_CoverageRatio(t *testing.T) {
	pol := traceTestPolicy("partial",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
	)
	trace := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
		toolCallEvent("e2", "http_request", "send", ""),
		promptEvent("e3", "user", "hello"),
		responseEvent("e4", "world"),
	)
	cr := EvaluateCompliance(pol, trace)
	// 1 matched event out of 4 total = 0.25
	if math.Abs(cr.CoverageRatio-0.25) > 0.01 {
		t.Errorf("expected coverage ratio ~0.25, got %.2f", cr.CoverageRatio)
	}
}

func TestEvaluateCompliance_ScoreCalculation(t *testing.T) {
	tests := []struct {
		name      string
		denies    int
		alerts    int
		wantScore float64
	}{
		{"no penalties", 0, 0, 1.0},
		{"one deny", 1, 0, 0.85},
		{"two denies", 2, 0, 0.70},
		{"one alert", 0, 1, 0.95},
		{"three alerts", 0, 3, 0.85},
		{"one deny one alert", 1, 1, 0.80},
		{"max penalties clamped", 7, 0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rules []Rule
			for i := 0; i < tt.denies; i++ {
				tool := fmt.Sprintf("deny_tool_%d", i)
				rules = append(rules, denyRule(
					fmt.Sprintf("deny-%d", i), "deny", 100-i, []string{tool},
				))
			}
			for i := 0; i < tt.alerts; i++ {
				tool := fmt.Sprintf("alert_tool_%d", i)
				rules = append(rules, alertRule(
					fmt.Sprintf("alert-%d", i), "alert", 50-i, []string{tool},
				))
			}

			// Need at least one rule if no events to avoid vacuous early return.
			if len(rules) == 0 {
				rules = append(rules, allowRule("allow-all", "allow", 1, []string{"*"}))
			}

			pol := traceTestPolicy("score-test", rules...)

			var events []TraceEvent
			for i := 0; i < tt.denies; i++ {
				events = append(events, toolCallEvent(
					fmt.Sprintf("de%d", i), fmt.Sprintf("deny_tool_%d", i), "execute", "",
				))
			}
			for i := 0; i < tt.alerts; i++ {
				events = append(events, toolCallEvent(
					fmt.Sprintf("ae%d", i), fmt.Sprintf("alert_tool_%d", i), "query", "",
				))
			}

			// Ensure at least one event so we don't hit the empty-trace early return.
			if len(events) == 0 {
				events = append(events, toolCallEvent("safe", "safe_tool", "read", ""))
			}

			trace := makeTrace("t1", "agent", events...)
			cr := EvaluateCompliance(pol, trace)
			if math.Abs(cr.Score-tt.wantScore) > 0.01 {
				t.Errorf("expected score %.2f, got %.2f", tt.wantScore, cr.Score)
			}
		})
	}
}

func TestEvaluateCompliance_GradeThresholds(t *testing.T) {
	// Verify that the correct grade flows through EvaluateCompliance for
	// various numbers of deny/alert events (which map to known scores).
	tests := []struct {
		denies int
		alerts int
		grade  string
	}{
		{0, 0, "A"}, // score 1.00
		{0, 2, "A"}, // score 0.90
		{1, 0, "B"}, // score 0.85
		{2, 0, "B"}, // score 0.70
		{2, 1, "C"}, // score 0.65
		{3, 1, "C"}, // score 0.50
		{4, 1, "D"}, // score 0.35
		{4, 3, "F"}, // score 0.25
		{7, 0, "F"}, // score 0.00
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%dd_%da", tt.denies, tt.alerts)
		t.Run(name, func(t *testing.T) {
			var rules []Rule
			var events []TraceEvent
			for i := 0; i < tt.denies; i++ {
				tool := fmt.Sprintf("dtool_%d", i)
				rules = append(rules, denyRule(
					fmt.Sprintf("d%d", i), "deny", 100-i, []string{tool},
				))
				events = append(events, toolCallEvent(
					fmt.Sprintf("de%d", i), tool, "execute", "",
				))
			}
			for i := 0; i < tt.alerts; i++ {
				tool := fmt.Sprintf("atool_%d", i)
				rules = append(rules, alertRule(
					fmt.Sprintf("a%d", i), "alert", 50-i, []string{tool},
				))
				events = append(events, toolCallEvent(
					fmt.Sprintf("ae%d", i), tool, "query", "",
				))
			}
			if len(rules) == 0 {
				rules = append(rules, allowRule("allow", "allow", 1, []string{"*"}))
			}
			if len(events) == 0 {
				events = append(events, toolCallEvent("safe", "safe_tool", "read", ""))
			}

			pol := traceTestPolicy("grade-test", rules...)
			trace := makeTrace("t1", "agent", events...)
			cr := EvaluateCompliance(pol, trace)
			if cr.Grade != tt.grade {
				t.Errorf("expected grade %s (score %.2f), got %s (score %.2f)",
					tt.grade, computeComplianceScore(tt.denies, tt.alerts),
					cr.Grade, cr.Score)
			}
		})
	}
}

func TestEvaluateCompliance_ViolationDetails(t *testing.T) {
	pol := traceTestPolicy("detail-test",
		denyRule("deny-shell", "Block shell execution", 100, []string{"shell_exec"}),
	)
	trace := makeTrace("t1", "agent",
		promptEvent("e0", "user", "run something"),
		toolCallEvent("e1", "shell_exec", "execute", "/bin/bash"),
	)
	cr := EvaluateCompliance(pol, trace)
	if len(cr.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(cr.Violations))
	}
	v := cr.Violations[0]
	if v.EventIndex != 1 {
		t.Errorf("expected EventIndex 1, got %d", v.EventIndex)
	}
	if v.Tool != "shell_exec" {
		t.Errorf("expected tool shell_exec, got %q", v.Tool)
	}
	if v.Action != "execute" {
		t.Errorf("expected action execute, got %q", v.Action)
	}
	if v.Effect != "deny" {
		t.Errorf("expected effect deny, got %q", v.Effect)
	}
	if v.Rule != "Block shell execution" {
		t.Errorf("expected rule desc 'Block shell execution', got %q", v.Rule)
	}
	if v.Severity == "" {
		t.Error("expected non-empty severity")
	}
}

// ---------------------------------------------------------------------------
// EvaluateComplianceBatch tests
// ---------------------------------------------------------------------------

func TestEvaluateComplianceBatch_Empty(t *testing.T) {
	pol := traceTestPolicy("test",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
	)
	report := EvaluateComplianceBatch(pol, nil)
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if report.TotalTraces != 0 {
		t.Errorf("expected 0 traces, got %d", report.TotalTraces)
	}
	if report.OverallGrade != "A" {
		t.Errorf("expected grade A for empty batch, got %s", report.OverallGrade)
	}
	if report.OverallScore != 1.0 {
		t.Errorf("expected score 1.0, got %.2f", report.OverallScore)
	}
}

func TestEvaluateComplianceBatch_AllCompliant(t *testing.T) {
	pol := traceTestPolicy("permissive",
		allowRule("allow-all", "Allow everything", 10, []string{"*"}),
	)
	traces := []*Trace{
		makeTrace("t1", "agent", toolCallEvent("e1", "http_request", "send", "")),
		makeTrace("t2", "agent", toolCallEvent("e1", "search_knowledge_base", "query", "")),
	}
	report := EvaluateComplianceBatch(pol, traces)
	if report.CompliantCount != 2 {
		t.Errorf("expected 2 compliant, got %d", report.CompliantCount)
	}
	if report.NonCompliantCount != 0 {
		t.Errorf("expected 0 non-compliant, got %d", report.NonCompliantCount)
	}
	if report.TotalViolations != 0 {
		t.Errorf("expected 0 violations, got %d", report.TotalViolations)
	}
	if report.OverallScore != 1.0 {
		t.Errorf("expected overall score 1.0, got %.2f", report.OverallScore)
	}
}

func TestEvaluateComplianceBatch_MixedCompliance(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
		allowRule("allow-http", "Allow HTTP", 10, []string{"http_request"}),
	)
	traces := []*Trace{
		makeTrace("t1", "agent", toolCallEvent("e1", "shell_exec", "execute", "")),
		makeTrace("t2", "agent", toolCallEvent("e1", "http_request", "send", "")),
		makeTrace("t3", "agent", toolCallEvent("e1", "shell_exec", "execute", "")),
	}
	report := EvaluateComplianceBatch(pol, traces)
	if report.CompliantCount != 1 {
		t.Errorf("expected 1 compliant, got %d", report.CompliantCount)
	}
	if report.NonCompliantCount != 2 {
		t.Errorf("expected 2 non-compliant, got %d", report.NonCompliantCount)
	}
	if report.TotalTraces != 3 {
		t.Errorf("expected 3 total, got %d", report.TotalTraces)
	}
}

func TestEvaluateComplianceBatch_SingleTrace(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
	)
	traces := []*Trace{
		makeTrace("t1", "agent", toolCallEvent("e1", "shell_exec", "execute", "")),
	}
	report := EvaluateComplianceBatch(pol, traces)
	if report.TotalTraces != 1 {
		t.Errorf("expected 1 total, got %d", report.TotalTraces)
	}
	if len(report.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(report.Results))
	}
	if report.CompliantCount != 0 {
		t.Errorf("expected 0 compliant, got %d", report.CompliantCount)
	}
	if report.NonCompliantCount != 1 {
		t.Errorf("expected 1 non-compliant, got %d", report.NonCompliantCount)
	}
}

func TestEvaluateComplianceBatch_ViolationCounts(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
		denyRule("deny-proc", "Block process", 95, []string{"process_exec"}),
	)
	traces := []*Trace{
		makeTrace("t1", "agent",
			toolCallEvent("e1", "shell_exec", "execute", ""),
			toolCallEvent("e2", "process_exec", "execute", ""),
		),
		makeTrace("t2", "agent",
			toolCallEvent("e1", "shell_exec", "execute", ""),
		),
	}
	report := EvaluateComplianceBatch(pol, traces)
	if report.TotalViolations != 3 {
		t.Errorf("expected 3 total violations, got %d", report.TotalViolations)
	}
}

func TestEvaluateComplianceBatch_OverallScore(t *testing.T) {
	pol := traceTestPolicy("mixed",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
		allowRule("allow-http", "Allow HTTP", 10, []string{"http_request"}),
	)
	traces := []*Trace{
		// Trace 1: 1 deny -> score 0.85
		makeTrace("t1", "agent", toolCallEvent("e1", "shell_exec", "execute", "")),
		// Trace 2: all allowed -> score 1.0
		makeTrace("t2", "agent", toolCallEvent("e1", "http_request", "send", "")),
	}
	report := EvaluateComplianceBatch(pol, traces)
	// Average: (0.85 + 1.0) / 2 = 0.925
	if math.Abs(report.OverallScore-0.925) > 0.01 {
		t.Errorf("expected overall score ~0.925, got %.3f", report.OverallScore)
	}
}

// ---------------------------------------------------------------------------
// Format tests
// ---------------------------------------------------------------------------

func TestFormatComplianceResult_Compliant(t *testing.T) {
	pol := traceTestPolicy("permissive",
		allowRule("allow-all", "Allow everything", 10, []string{"*"}),
	)
	trace := makeTrace("t1", "agent",
		toolCallEvent("e1", "http_request", "send", ""),
	)
	cr := EvaluateCompliance(pol, trace)
	output := FormatComplianceResult(cr)

	checks := []string{
		"Compliance Evaluation",
		"COMPLIANT",
		"No violations",
		"permissive",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q", check)
		}
	}
	if strings.Contains(output, "NON-COMPLIANT") {
		t.Error("compliant result should not contain NON-COMPLIANT")
	}
}

func TestFormatComplianceResult_NonCompliant(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell execution", 100, []string{"shell_exec"}),
	)
	trace := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
	)
	cr := EvaluateCompliance(pol, trace)
	output := FormatComplianceResult(cr)

	checks := []string{
		"NON-COMPLIANT",
		"DENY",
		"shell_exec",
		"Block shell execution",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestFormatComplianceResult_Nil(t *testing.T) {
	output := FormatComplianceResult(nil)
	if !strings.Contains(output, "No compliance result") {
		t.Errorf("expected 'No compliance result', got %q", output)
	}
}

func TestFormatComplianceReport_Output(t *testing.T) {
	pol := traceTestPolicy("test-policy",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
		allowRule("allow-http", "Allow HTTP", 10, []string{"http_request"}),
	)
	traces := []*Trace{
		makeTrace("t1", "agent", toolCallEvent("e1", "shell_exec", "execute", "")),
		makeTrace("t2", "agent", toolCallEvent("e1", "http_request", "send", "")),
	}
	report := EvaluateComplianceBatch(pol, traces)
	output := FormatComplianceReport(report)

	checks := []string{
		"Compliance Report",
		"test-policy",
		"Total Traces",
		"Compliant",
		"Non-Compliant",
		"Total Violations",
		"Overall Score",
		"Results",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q", check)
		}
	}
	// Box-drawing characters.
	if !strings.Contains(output, "┌") || !strings.Contains(output, "└") {
		t.Error("output missing box-drawing characters")
	}
}

func TestFormatComplianceReport_Nil(t *testing.T) {
	output := FormatComplianceReport(nil)
	if !strings.Contains(output, "No compliance report") {
		t.Errorf("expected 'No compliance report', got %q", output)
	}
}

func TestFormatComplianceReport_Empty(t *testing.T) {
	pol := traceTestPolicy("test-policy",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
	)
	report := EvaluateComplianceBatch(pol, nil)
	output := FormatComplianceReport(report)
	if !strings.Contains(output, "No traces evaluated") {
		t.Error("expected 'No traces evaluated' in output")
	}
}

// ---------------------------------------------------------------------------
// gradeCompliance — direct unit tests
// ---------------------------------------------------------------------------

func TestGradeCompliance(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{1.0, "A"},
		{0.95, "A"},
		{0.9, "A"},
		{0.899, "B"},
		{0.8, "B"},
		{0.7, "B"},
		{0.699, "C"},
		{0.6, "C"},
		{0.5, "C"},
		{0.499, "D"},
		{0.4, "D"},
		{0.3, "D"},
		{0.299, "F"},
		{0.1, "F"},
		{0.0, "F"},
	}
	for _, tt := range tests {
		got := gradeCompliance(tt.score)
		if got != tt.want {
			t.Errorf("gradeCompliance(%.3f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
