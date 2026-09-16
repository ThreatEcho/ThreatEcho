// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func testExportPolicy() *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta: PolicyMeta{
			Name:        "test-policy",
			Description: "A test policy for export",
			Authors:     []string{"tester"},
			Created:     "2026-01-01",
			Modified:    "2026-01-01",
		},
		Agent: AgentScope{
			Name: "*",
			Type: "llm",
		},
		Rules: []Rule{
			{
				ID:          "deny-shell",
				Description: "Block shell execution",
				Effect:      "deny",
				Priority:    100,
				Match: RuleMatch{
					Tools: []string{"shell_exec"},
				},
			},
			{
				ID:          "alert-exfil",
				Description: "Alert on exfiltration",
				Effect:      "alert",
				Priority:    50,
				Match: RuleMatch{
					Tactics: []string{"exfiltration"},
				},
			},
			{
				ID:          "allow-http",
				Description: "Allow HTTP requests",
				Effect:      "allow",
				Priority:    10,
				Match: RuleMatch{
					Tools: []string{"http_request"},
				},
				Conditions: []Condition{
					{Field: "exec_type", Operator: "eq", Value: "http"},
				},
			},
		},
	}
}

func TestExportPolicy_JSON(t *testing.T) {
	p := testExportPolicy()
	exp, err := ExportPolicy(p, FormatJSON)
	if err != nil {
		t.Fatalf("ExportPolicy JSON: %v", err)
	}

	if exp.Format != FormatJSON {
		t.Errorf("format = %q, want %q", exp.Format, FormatJSON)
	}

	// Rendered output should be valid JSON.
	if !json.Valid([]byte(exp.Rendered)) {
		t.Errorf("rendered JSON is not valid:\n%s", exp.Rendered)
	}

	// Round-trip: unmarshal the rendered JSON back into a Policy.
	var roundtrip Policy
	if err := json.Unmarshal([]byte(exp.Rendered), &roundtrip); err != nil {
		t.Fatalf("JSON roundtrip unmarshal: %v", err)
	}
	if roundtrip.Meta.Name != p.Meta.Name {
		t.Errorf("roundtrip name = %q, want %q", roundtrip.Meta.Name, p.Meta.Name)
	}
	if len(roundtrip.Rules) != len(p.Rules) {
		t.Errorf("roundtrip rules = %d, want %d", len(roundtrip.Rules), len(p.Rules))
	}
}

func TestExportPolicy_YAML(t *testing.T) {
	p := testExportPolicy()
	exp, err := ExportPolicy(p, FormatYAML)
	if err != nil {
		t.Fatalf("ExportPolicy YAML: %v", err)
	}

	if exp.Format != FormatYAML {
		t.Errorf("format = %q, want %q", exp.Format, FormatYAML)
	}

	// Should contain key fields.
	if !strings.Contains(exp.Rendered, "test-policy") {
		t.Error("YAML output should contain policy name")
	}
	if !strings.Contains(exp.Rendered, "deny-shell") {
		t.Error("YAML output should contain rule ID")
	}
}

func TestExportPolicy_Rego(t *testing.T) {
	p := testExportPolicy()
	exp, err := ExportPolicy(p, FormatRego)
	if err != nil {
		t.Fatalf("ExportPolicy Rego: %v", err)
	}

	if exp.Format != FormatRego {
		t.Errorf("format = %q, want %q", exp.Format, FormatRego)
	}

	rego := exp.Rendered

	// Must have package declaration.
	if !strings.Contains(rego, "package threatecho.policy") {
		t.Error("Rego should contain package declaration")
	}

	// Must have default allow.
	if !strings.Contains(rego, "default allow = false") {
		t.Error("Rego should contain default allow = false")
	}

	// Must have deny rule with tool name.
	if !strings.Contains(rego, "deny[msg]") {
		t.Error("Rego should contain deny[msg] rule")
	}
	if !strings.Contains(rego, `"shell_exec"`) {
		t.Error("Rego should reference shell_exec tool")
	}

	// Must have alert rule.
	if !strings.Contains(rego, "alert[msg]") {
		t.Error("Rego should contain alert[msg] rule")
	}

	// Must have allow rule with conditions.
	if !strings.Contains(rego, "allow {") {
		t.Error("Rego should contain allow rule")
	}
	if !strings.Contains(rego, `input.exec_type == "http"`) {
		t.Error("Rego allow rule should contain condition")
	}
}

func TestExportPolicy_Summary(t *testing.T) {
	p := testExportPolicy()
	exp, err := ExportPolicy(p, FormatSummary)
	if err != nil {
		t.Fatalf("ExportPolicy Summary: %v", err)
	}

	if exp.Format != FormatSummary {
		t.Errorf("format = %q, want %q", exp.Format, FormatSummary)
	}

	summary := exp.Rendered

	// Should contain policy name and agent.
	if !strings.Contains(summary, "test-policy") {
		t.Error("summary should contain policy name")
	}
	if !strings.Contains(summary, "agent: *") {
		t.Error("summary should contain agent name")
	}

	// Should contain rule counts.
	if !strings.Contains(summary, "rule_count: 3") {
		t.Error("summary should contain rule_count: 3")
	}
	if !strings.Contains(summary, "deny_rules: 1") {
		t.Error("summary should contain deny_rules: 1")
	}
	if !strings.Contains(summary, "allow_rules: 1") {
		t.Error("summary should contain allow_rules: 1")
	}
	if !strings.Contains(summary, "alert_rules: 1") {
		t.Error("summary should contain alert_rules: 1")
	}

	// Should list rules with IDs.
	if !strings.Contains(summary, "deny-shell") {
		t.Error("summary should list deny-shell rule")
	}
	if !strings.Contains(summary, "alert-exfil") {
		t.Error("summary should list alert-exfil rule")
	}
}

func TestExportPolicy_EmptyPolicy(t *testing.T) {
	p := &Policy{
		Meta:  PolicyMeta{Name: "empty"},
		Agent: AgentScope{Name: "none"},
	}

	// JSON should work with empty rules.
	exp, err := ExportPolicy(p, FormatJSON)
	if err != nil {
		t.Fatalf("ExportPolicy JSON empty: %v", err)
	}
	if !json.Valid([]byte(exp.Rendered)) {
		t.Error("empty policy JSON should be valid")
	}

	// Rego should produce valid output with no rules.
	exp, err = ExportPolicy(p, FormatRego)
	if err != nil {
		t.Fatalf("ExportPolicy Rego empty: %v", err)
	}
	if !strings.Contains(exp.Rendered, "package threatecho.policy") {
		t.Error("empty policy Rego should still have package declaration")
	}
	if !strings.Contains(exp.Rendered, "default allow = false") {
		t.Error("empty policy Rego should still have default allow")
	}

	// Summary should report zero counts.
	exp, err = ExportPolicy(p, FormatSummary)
	if err != nil {
		t.Fatalf("ExportPolicy Summary empty: %v", err)
	}
	if !strings.Contains(exp.Rendered, "rule_count: 0") {
		t.Error("empty policy summary should contain rule_count: 0")
	}
}

func TestExportPolicy_UnknownFormat(t *testing.T) {
	p := testExportPolicy()
	_, err := ExportPolicy(p, "xml")
	if err == nil {
		t.Fatal("ExportPolicy with unknown format should return error")
	}
	if !strings.Contains(err.Error(), "unknown export format") {
		t.Errorf("error should mention unknown format, got: %v", err)
	}
}

func TestExportToRego_StructureComplete(t *testing.T) {
	p := testExportPolicy()
	rego, err := ExportToRego(p)
	if err != nil {
		t.Fatalf("ExportToRego: %v", err)
	}

	// Verify structure: package, default, deny, alert, allow blocks.
	lines := strings.Split(rego, "\n")
	if len(lines) < 5 {
		t.Fatalf("Rego output too short: %d lines", len(lines))
	}
	if lines[0] != "package threatecho.policy" {
		t.Errorf("first line = %q, want package declaration", lines[0])
	}

	// Count rule blocks.
	denyCount := strings.Count(rego, "deny[msg] {")
	alertCount := strings.Count(rego, "alert[msg] {")
	allowCount := strings.Count(rego, "allow {")
	if denyCount < 1 {
		t.Error("expected at least 1 deny block")
	}
	if alertCount < 1 {
		t.Error("expected at least 1 alert block")
	}
	if allowCount < 1 {
		t.Error("expected at least 1 allow block")
	}
}

func TestExportToSummary_RuleCounts(t *testing.T) {
	p := testExportPolicy()
	// Add extra rules to verify counting.
	p.Rules = append(p.Rules, Rule{
		ID: "deny-extra", Effect: "deny", Priority: 80,
		Match: RuleMatch{Tools: []string{"dangerous_tool"}},
	})

	summary := ExportToSummary(p)
	if !strings.Contains(summary, "rule_count: 4") {
		t.Errorf("summary should show rule_count: 4, got:\n%s", summary)
	}
	if !strings.Contains(summary, "deny_rules: 2") {
		t.Errorf("summary should show deny_rules: 2, got:\n%s", summary)
	}
}

func TestFormatExport(t *testing.T) {
	exp := &PolicyExport{
		Rendered: "test output",
	}
	if got := FormatExport(exp); got != "test output" {
		t.Errorf("FormatExport = %q, want %q", got, "test output")
	}
}

func TestExportToRego_WithConditions(t *testing.T) {
	p := &Policy{
		Meta:  PolicyMeta{Name: "cond-test"},
		Agent: AgentScope{Name: "test"},
		Rules: []Rule{
			{
				ID: "deny-elevated", Effect: "deny", Priority: 100,
				Match: RuleMatch{Actions: []string{"execute"}},
				Conditions: []Condition{
					{Field: "elevated", Operator: "eq", Value: "true"},
				},
			},
		},
	}

	rego, err := ExportToRego(p)
	if err != nil {
		t.Fatalf("ExportToRego: %v", err)
	}

	if !strings.Contains(rego, `input.action == "execute"`) {
		t.Error("Rego should contain action match")
	}
	if !strings.Contains(rego, `input.elevated == "true"`) {
		t.Error("Rego should contain elevated condition")
	}
}

func TestExportToRego_WithTargets(t *testing.T) {
	p := &Policy{
		Meta:  PolicyMeta{Name: "target-test"},
		Agent: AgentScope{Name: "test"},
		Rules: []Rule{
			{
				ID: "deny-c2", Effect: "deny", Priority: 95,
				Match: RuleMatch{Targets: []string{"https://*.evil.com/*"}},
			},
		},
	}

	rego, err := ExportToRego(p)
	if err != nil {
		t.Fatalf("ExportToRego: %v", err)
	}

	if !strings.Contains(rego, "glob.match") {
		t.Error("Rego should use glob.match for target patterns")
	}
	if !strings.Contains(rego, "evil.com") {
		t.Error("Rego should contain the target pattern")
	}
}
