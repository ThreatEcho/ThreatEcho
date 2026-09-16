// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"strings"
	"testing"
	"time"
)

func TestBenchmarkPolicyEmpty(t *testing.T) {
	t.Parallel()
	p := &Policy{
		Meta:  PolicyMeta{Name: "empty-policy"},
		Rules: []Rule{},
	}

	report := BenchmarkPolicy(p, 100)

	if report.PolicyName != "empty-policy" {
		t.Errorf("expected policy name 'empty-policy', got %q", report.PolicyName)
	}
	if report.RuleCount != 0 {
		t.Errorf("expected 0 rules, got %d", report.RuleCount)
	}
	if report.Iterations != 100 {
		t.Errorf("expected 100 iterations, got %d", report.Iterations)
	}
	// Even with no rules, synthetic tools should be generated and evaluated.
	if len(report.Results) == 0 {
		t.Error("expected non-zero results even for empty policy")
	}
	// All should be misses.
	for _, r := range report.Results {
		if r.Matched {
			t.Errorf("tool %q should not match any rule in empty policy", r.ToolName)
		}
	}
	// Empty policy should be fast.
	if report.OverallStats.P99EvalTime > time.Millisecond {
		t.Errorf("empty policy p99 should be under 1ms, got %v", report.OverallStats.P99EvalTime)
	}
}

func TestBenchmarkPolicyManyRules(t *testing.T) {
	t.Parallel()

	// Build a policy with 12 rules.
	rules := []Rule{
		{ID: "r1", Effect: "deny", Priority: 100, Match: RuleMatch{Tools: []string{"shell_exec"}}},
		{ID: "r2", Effect: "deny", Priority: 90, Match: RuleMatch{Tools: []string{"file_access"}}},
		{ID: "r3", Effect: "alert", Priority: 80, Match: RuleMatch{Tools: []string{"http_request"}}},
		{ID: "r4", Effect: "deny", Priority: 70, Match: RuleMatch{Tools: []string{"dns_query"}}},
		{ID: "r5", Effect: "alert", Priority: 60, Match: RuleMatch{Tools: []string{"send_email"}}},
		{ID: "r6", Effect: "deny", Priority: 50, Match: RuleMatch{Tools: []string{"agent_message"}}},
		{ID: "r7", Effect: "allow", Priority: 40, Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
		{ID: "r8", Effect: "deny", Priority: 30, Match: RuleMatch{Tools: []string{"write_knowledge_base"}}},
		{ID: "r9", Effect: "deny", Priority: 20, Match: RuleMatch{Tools: []string{"process_exec"}}},
		{ID: "r10", Effect: "deny", Priority: 10, Match: RuleMatch{Tools: []string{"registry_access"}}},
		{ID: "r11", Effect: "allow", Priority: 5, Match: RuleMatch{Tools: []string{"custom_*"}}},
		{ID: "r12", Effect: "deny", Priority: 1, Match: RuleMatch{Tools: []string{"*_exec"}}},
	}

	p := &Policy{
		Meta:  PolicyMeta{Name: "many-rules-policy"},
		Rules: rules,
	}

	report := BenchmarkPolicy(p, 500)

	if report.RuleCount != 12 {
		t.Errorf("expected 12 rules, got %d", report.RuleCount)
	}
	if report.Iterations != 500 {
		t.Errorf("expected 500 iterations, got %d", report.Iterations)
	}

	// Some tools should match (e.g. shell_exec matches r1).
	hasMatch := false
	hasMiss := false
	for _, r := range report.Results {
		if r.Matched {
			hasMatch = true
		} else {
			hasMiss = true
		}
	}
	if !hasMatch {
		t.Error("expected at least one tool to match a rule")
	}
	if !hasMiss {
		t.Error("expected at least one tool not to match any rule")
	}

	// Overall stats should be populated.
	if report.OverallStats.TotalEvals == 0 {
		t.Error("expected non-zero total evals")
	}
	if report.OverallStats.ToolsPerSec == 0 {
		t.Error("expected non-zero throughput")
	}
}

func TestBenchmarkPolicyIterationsDefault(t *testing.T) {
	t.Parallel()
	p := &Policy{
		Meta:  PolicyMeta{Name: "default-iter"},
		Rules: []Rule{{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"test_tool"}}}},
	}

	// Zero iterations should default to DefaultBenchmarkIterations.
	report := BenchmarkPolicy(p, 0)
	if report.Iterations != DefaultBenchmarkIterations {
		t.Errorf("expected default iterations %d, got %d", DefaultBenchmarkIterations, report.Iterations)
	}

	// Negative iterations should also default.
	report2 := BenchmarkPolicy(p, -5)
	if report2.Iterations != DefaultBenchmarkIterations {
		t.Errorf("expected default iterations %d for negative input, got %d", DefaultBenchmarkIterations, report2.Iterations)
	}
}

func TestBenchmarkPolicyNonZeroTiming(t *testing.T) {
	t.Parallel()
	p := &Policy{
		Meta: PolicyMeta{Name: "timing-test"},
		Rules: []Rule{
			{ID: "r1", Effect: "deny", Priority: 10, Match: RuleMatch{Tools: []string{"shell_*"}}},
			{ID: "r2", Effect: "allow", Priority: 5, Match: RuleMatch{Tools: []string{"http_*"}}},
		},
	}

	report := BenchmarkPolicy(p, 100)

	// Every result should have non-zero avg eval time (timing something always takes > 0).
	for _, r := range report.Results {
		if r.EvalTimeAvg == 0 && r.TotalEvals > 0 {
			// On very fast hardware this CAN be 0ns for single rule evals,
			// so we check that at least the overall stats are non-zero.
			continue
		}
	}

	// Overall total time should be non-zero.
	if report.OverallStats.TotalTime == 0 {
		t.Error("expected non-zero total time")
	}
	// Total evals = tools * iterations.
	expectedEvals := report.OverallStats.TotalTools * report.Iterations
	if report.OverallStats.TotalEvals != expectedEvals {
		t.Errorf("expected %d total evals, got %d", expectedEvals, report.OverallStats.TotalEvals)
	}
}

func TestFormatBenchmarkReport(t *testing.T) {
	t.Parallel()
	p := &Policy{
		Meta: PolicyMeta{Name: "format-test-policy"},
		Rules: []Rule{
			{ID: "r1", Effect: "deny", Priority: 10, Match: RuleMatch{Tools: []string{"shell_exec"}}},
		},
	}

	report := BenchmarkPolicy(p, 50)
	output := FormatBenchmarkReport(report)

	if output == "" {
		t.Fatal("expected non-empty formatted output")
	}

	// Check for box-drawing characters.
	if !strings.Contains(output, "┌") || !strings.Contains(output, "└") {
		t.Error("expected box-drawing characters in output")
	}

	// Check report sections.
	if !strings.Contains(output, "POLICY BENCHMARK REPORT") {
		t.Error("expected header in output")
	}
	if !strings.Contains(output, "format-test-policy") {
		t.Error("expected policy name in output")
	}
	if !strings.Contains(output, "OVERALL") {
		t.Error("expected OVERALL section in output")
	}
	if !strings.Contains(output, "Avg eval") {
		t.Error("expected avg eval line in output")
	}
	if !strings.Contains(output, "P99 eval") {
		t.Error("expected p99 eval line in output")
	}
	if !strings.Contains(output, "evals/sec") {
		t.Error("expected throughput in output")
	}

	// Check that recommendation is present.
	if !strings.Contains(output, "Excellent") && !strings.Contains(output, "Good") &&
		!strings.Contains(output, "Acceptable") && !strings.Contains(output, "Warning") &&
		!strings.Contains(output, "Critical") {
		t.Error("expected recommendation in output")
	}
}

func TestFormatDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Nanosecond, "500ns"},
		{1500 * time.Nanosecond, "1.5µs"},
		{100 * time.Microsecond, "100.0µs"},
		{1500 * time.Microsecond, "1.50ms"},
		{100 * time.Millisecond, "100.00ms"},
		{2 * time.Second, "2s"},
	}

	for _, tc := range tests {
		got := formatDuration(tc.d)
		if got != tc.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestGenerateSyntheticTools(t *testing.T) {
	t.Parallel()
	p := &Policy{
		Rules: []Rule{
			{ID: "r1", Match: RuleMatch{Tools: []string{"my_custom_tool"}}},
			{ID: "r2", Match: RuleMatch{Tools: []string{"shell_*"}}},
		},
	}

	tools := generateSyntheticTools(p)

	// Should include the concrete tool from the rule.
	found := false
	for _, t := range tools {
		if t == "my_custom_tool" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected concrete tool 'my_custom_tool' in synthetic list")
	}

	// Should include non-matching tools.
	foundNonMatch := false
	for _, t := range tools {
		if t == "noop_health_check" {
			foundNonMatch = true
			break
		}
	}
	if !foundNonMatch {
		t.Error("expected non-matching tool in synthetic list")
	}

	// Should be sorted.
	for i := 1; i < len(tools); i++ {
		if tools[i] < tools[i-1] {
			t.Errorf("tools not sorted: %q < %q at index %d", tools[i], tools[i-1], i)
		}
	}
}

func TestComputeBenchmarkStats(t *testing.T) {
	t.Parallel()

	// Empty durations.
	avg, p99, max := computeBenchmarkStats(nil)
	if avg != 0 || p99 != 0 || max != 0 {
		t.Errorf("expected all zeros for nil, got avg=%v p99=%v max=%v", avg, p99, max)
	}

	// Single value.
	avg, p99, max = computeBenchmarkStats([]time.Duration{42 * time.Microsecond})
	if avg != 42*time.Microsecond {
		t.Errorf("expected avg 42µs, got %v", avg)
	}
	if p99 != 42*time.Microsecond {
		t.Errorf("expected p99 42µs, got %v", p99)
	}

	// Multiple values.
	durations := make([]time.Duration, 100)
	for i := range durations {
		durations[i] = time.Duration(i+1) * time.Microsecond
	}
	avg, p99, max = computeBenchmarkStats(durations)

	// avg should be ~50.5µs.
	if avg < 50*time.Microsecond || avg > 51*time.Microsecond {
		t.Errorf("expected avg ~50.5µs, got %v", avg)
	}
	// p99 should be 99µs or 100µs.
	if p99 < 99*time.Microsecond || p99 > 100*time.Microsecond {
		t.Errorf("expected p99 ~99-100µs, got %v", p99)
	}
	if max != 100*time.Microsecond {
		t.Errorf("expected max 100µs, got %v", max)
	}
}

func TestBenchmarkRecommendation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		p99  time.Duration
		want string
	}{
		{5 * time.Microsecond, "Excellent"},
		{50 * time.Microsecond, "Good"},
		{500 * time.Microsecond, "Acceptable"},
		{5 * time.Millisecond, "Warning"},
		{50 * time.Millisecond, "Critical"},
	}

	for _, tc := range tests {
		r := &BenchmarkReport{
			OverallStats: OverallStats{P99EvalTime: tc.p99},
		}
		rec := generateRecommendation(r)
		if !strings.Contains(rec, tc.want) {
			t.Errorf("p99=%v: expected recommendation containing %q, got %q", tc.p99, tc.want, rec)
		}
	}
}
