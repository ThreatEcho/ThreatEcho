// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"strings"
	"testing"
)

// --- Helpers ---

func lintTestPolicy(name string, rules ...Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: name, Description: "test policy"},
		Rules:      rules,
	}
}

func testRule(id, effect string, tools ...string) Rule {
	return Rule{
		ID:          id,
		Description: "test rule " + id,
		Effect:      effect,
		Match:       RuleMatch{Tools: tools},
	}
}

func testRuleWithPriority(id, effect string, priority int, tools ...string) Rule {
	r := testRule(id, effect, tools...)
	r.Priority = priority
	return r
}

func testRuleWithConditions(id, effect string, tools []string, conditions []Condition) Rule {
	r := testRule(id, effect, tools...)
	r.Conditions = conditions
	return r
}

func testRuleWithTactics(id, effect string, tactics ...string) Rule {
	return Rule{
		ID:          id,
		Description: "test rule " + id,
		Effect:      effect,
		Match:       RuleMatch{Tactics: tactics},
	}
}

// --- LintPolicy nil/empty ---

func TestLintPolicy_Nil(t *testing.T) {
	r := LintPolicy(nil)
	if r == nil {
		t.Fatal("expected non-nil report for nil policy")
	}
	if r.Grade != "F" {
		t.Errorf("Grade = %q, want F", r.Grade)
	}
}

func TestLintPolicy_EmptyRules(t *testing.T) {
	p := lintTestPolicy("empty")
	p.Rules = nil
	r := LintPolicy(p)
	if r.FindingCount != 0 {
		t.Errorf("empty policy should have 0 findings, got %d", r.FindingCount)
	}
	if r.Score != 1.0 {
		t.Errorf("Score = %f, want 1.0 for empty policy", r.Score)
	}
}

// --- SEC-001: Wildcard deny ---

func TestLintSEC001_WildcardDeny(t *testing.T) {
	p := lintTestPolicy("wild", testRule("deny-all", "deny", "*"))
	r := LintPolicy(p)
	found := findLintRule(r, "SEC-001")
	if found == nil {
		t.Fatal("expected SEC-001 finding for wildcard deny")
	}
	if found.Severity != LintWarning {
		t.Errorf("severity = %q, want warning", found.Severity)
	}
}

func TestLintSEC001_NoWildcardDeny(t *testing.T) {
	p := lintTestPolicy("specific", testRule("deny-shell", "deny", "shell_exec"))
	r := LintPolicy(p)
	if findLintRule(r, "SEC-001") != nil {
		t.Error("should not flag SEC-001 for specific tool deny")
	}
}

// --- SEC-002: No deny rules ---

func TestLintSEC002_NoDenyRules(t *testing.T) {
	p := lintTestPolicy("permissive",
		testRule("allow-all", "allow", "*"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "SEC-002") == nil {
		t.Error("expected SEC-002 finding for policy with no deny rules")
	}
}

func TestLintSEC002_HasDenyRule(t *testing.T) {
	p := lintTestPolicy("mixed",
		testRule("deny-shell", "deny", "shell_exec"),
		testRule("allow-search", "allow", "search"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "SEC-002") != nil {
		t.Error("should not flag SEC-002 when deny rules exist")
	}
}

// --- SEC-003: Unconditional allow on elevated tools ---

func TestLintSEC003_UnconditionalAllowElevated(t *testing.T) {
	p := lintTestPolicy("dangerous",
		testRule("allow-shell", "allow", "shell_exec"),
	)
	r := LintPolicy(p)
	found := findLintRule(r, "SEC-003")
	if found == nil {
		t.Fatal("expected SEC-003 finding for unconditional shell_exec allow")
	}
	if found.Severity != LintError {
		t.Errorf("severity = %q, want error", found.Severity)
	}
}

func TestLintSEC003_ConditionalAllowElevated(t *testing.T) {
	p := lintTestPolicy("conditional",
		testRuleWithConditions("allow-shell-admin", "allow",
			[]string{"shell_exec"},
			[]Condition{{Field: "elevated", Operator: "eq", Value: "true"}},
		),
	)
	r := LintPolicy(p)
	if findLintRule(r, "SEC-003") != nil {
		t.Error("should not flag SEC-003 when conditions are present")
	}
}

// --- SEC-004: No alert rules ---

func TestLintSEC004_NoAlertRules(t *testing.T) {
	p := lintTestPolicy("no-alerts",
		testRule("deny-shell", "deny", "shell_exec"),
		testRule("allow-search", "allow", "search"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "SEC-004") == nil {
		t.Error("expected SEC-004 for policy with no alert rules")
	}
}

func TestLintSEC004_HasAlertRules(t *testing.T) {
	p := lintTestPolicy("alerted",
		testRule("deny-shell", "deny", "shell_exec"),
		testRule("alert-http", "alert", "http_request"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "SEC-004") != nil {
		t.Error("should not flag SEC-004 when alert rules exist")
	}
}

// --- SEC-005: Deny without description ---

func TestLintSEC005_DenyNoDescription(t *testing.T) {
	r := Rule{
		ID:     "nodesc",
		Effect: "deny",
		Match:  RuleMatch{Tools: []string{"shell_exec"}},
		// No description
	}
	p := lintTestPolicy("nodesc", r)
	report := LintPolicy(p)
	if findLintRule(report, "SEC-005") == nil {
		t.Error("expected SEC-005 for deny rule without description")
	}
}

// --- COV-001: Few rules ---

func TestLintCOV001_FewRules(t *testing.T) {
	p := lintTestPolicy("tiny",
		testRule("one", "deny", "shell_exec"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "COV-001") == nil {
		t.Error("expected COV-001 for policy with 1 rule")
	}
}

func TestLintCOV001_EnoughRules(t *testing.T) {
	p := lintTestPolicy("enough",
		testRule("r1", "deny", "shell_exec"),
		testRule("r2", "allow", "search"),
		testRule("r3", "alert", "http"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "COV-001") != nil {
		t.Error("should not flag COV-001 with 3+ rules")
	}
}

// --- COV-002: Single effect type ---

func TestLintCOV002_SingleEffectType(t *testing.T) {
	p := lintTestPolicy("all-deny",
		testRule("r1", "deny", "shell_exec"),
		testRule("r2", "deny", "file_access"),
		testRule("r3", "deny", "http_request"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "COV-002") == nil {
		t.Error("expected COV-002 for all-deny policy")
	}
}

func TestLintCOV002_MixedEffects(t *testing.T) {
	p := lintTestPolicy("mixed",
		testRule("r1", "deny", "shell_exec"),
		testRule("r2", "allow", "search"),
		testRule("r3", "alert", "http"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "COV-002") != nil {
		t.Error("should not flag COV-002 with mixed effects")
	}
}

// --- COV-003: No tactic-based rules ---

func TestLintCOV003_NoTacticRules(t *testing.T) {
	p := lintTestPolicy("no-tactics",
		testRule("r1", "deny", "shell_exec"),
		testRule("r2", "allow", "search"),
		testRule("r3", "alert", "http"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "COV-003") == nil {
		t.Error("expected COV-003 for policy with no tactic-based rules")
	}
}

func TestLintCOV003_HasTacticRules(t *testing.T) {
	p := lintTestPolicy("tactic-aware",
		testRule("r1", "deny", "shell_exec"),
		testRule("r2", "allow", "search"),
		testRuleWithTactics("r3", "deny", "exfiltration"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "COV-003") != nil {
		t.Error("should not flag COV-003 when tactic rules exist")
	}
}

// --- RED-001: Duplicate rule IDs ---

func TestLintRED001_DuplicateIDs(t *testing.T) {
	p := lintTestPolicy("dupes",
		testRule("same-id", "deny", "shell_exec"),
		testRule("same-id", "allow", "search"),
	)
	r := LintPolicy(p)
	found := findLintRule(r, "RED-001")
	if found == nil {
		t.Fatal("expected RED-001 for duplicate rule IDs")
	}
	if found.Severity != LintError {
		t.Errorf("severity = %q, want error", found.Severity)
	}
}

func TestLintRED001_UniqueIDs(t *testing.T) {
	p := lintTestPolicy("unique",
		testRule("r1", "deny", "shell_exec"),
		testRule("r2", "allow", "search"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "RED-001") != nil {
		t.Error("should not flag RED-001 with unique IDs")
	}
}

// --- RED-002: Overlapping tool patterns ---

func TestLintRED002_OverlappingTools(t *testing.T) {
	p := lintTestPolicy("overlap",
		testRule("r1", "deny", "shell_exec"),
		testRule("r2", "deny", "shell_exec"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "RED-002") == nil {
		t.Error("expected RED-002 for overlapping tool patterns")
	}
}

// --- RED-003: Conflicting allow/deny same priority ---

func TestLintRED003_ConflictingSamePriority(t *testing.T) {
	p := lintTestPolicy("conflict",
		testRuleWithPriority("allow-shell", "allow", 10, "shell_exec"),
		testRuleWithPriority("deny-shell", "deny", 10, "shell_exec"),
	)
	r := LintPolicy(p)
	found := findLintRule(r, "RED-003")
	if found == nil {
		t.Fatal("expected RED-003 for conflicting rules at same priority")
	}
	if found.Severity != LintError {
		t.Errorf("severity = %q, want error", found.Severity)
	}
}

func TestLintRED003_ConflictingDifferentPriority(t *testing.T) {
	p := lintTestPolicy("ordered",
		testRuleWithPriority("deny-shell", "deny", 20, "shell_exec"),
		testRuleWithPriority("allow-shell", "allow", 10, "shell_exec"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "RED-003") != nil {
		t.Error("should not flag RED-003 when priorities differ")
	}
}

// --- NAM-001: No policy name ---

func TestLintNAM001_NoName(t *testing.T) {
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Rules:      []Rule{testRule("r1", "deny", "shell_exec")},
	}
	r := LintPolicy(p)
	if findLintRule(r, "NAM-001") == nil {
		t.Error("expected NAM-001 for policy with no name")
	}
}

// --- NAM-002: Non-kebab-case rule IDs ---

func TestLintNAM002_NonKebabCase(t *testing.T) {
	p := lintTestPolicy("casing",
		Rule{ID: "MyRule", Effect: "deny", Description: "test", Match: RuleMatch{Tools: []string{"x"}}},
	)
	r := LintPolicy(p)
	if findLintRule(r, "NAM-002") == nil {
		t.Error("expected NAM-002 for CamelCase rule ID")
	}
}

func TestLintNAM002_KebabCaseOK(t *testing.T) {
	p := lintTestPolicy("casing",
		testRule("my-rule", "deny", "shell_exec"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "NAM-002") != nil {
		t.Error("should not flag NAM-002 for kebab-case ID")
	}
}

func TestLintNAM002_SnakeCaseOK(t *testing.T) {
	p := lintTestPolicy("casing",
		testRule("my_rule", "deny", "shell_exec"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "NAM-002") != nil {
		t.Error("should not flag NAM-002 for snake_case ID")
	}
}

// --- NAM-004: Short rule IDs ---

func TestLintNAM004_ShortID(t *testing.T) {
	p := lintTestPolicy("short",
		Rule{ID: "x", Effect: "deny", Description: "test", Match: RuleMatch{Tools: []string{"y"}}},
	)
	r := LintPolicy(p)
	if findLintRule(r, "NAM-004") == nil {
		t.Error("expected NAM-004 for single-char rule ID")
	}
}

// --- CPX-001: Large rule set ---

func TestLintCPX001_LargeRuleSet(t *testing.T) {
	var rules []Rule
	for i := 0; i < 51; i++ {
		rules = append(rules, testRule(
			strings.Repeat("r", 3)+strings.Repeat("0", 3-len(string(rune('0'+i%10))))+string(rune('0'+i%10)),
			"deny", "tool_"+string(rune('a'+i%26))))
	}
	// Use unique IDs to avoid RED-001
	for i := range rules {
		rules[i].ID = fmt.Sprintf("rule-%03d", i)
	}
	p := lintTestPolicy("large", rules...)
	r := LintPolicy(p)
	if findLintRule(r, "CPX-001") == nil {
		t.Error("expected CPX-001 for >50 rule policy")
	}
}

func TestLintCPX001_NormalRuleSet(t *testing.T) {
	p := lintTestPolicy("normal",
		testRule("r1", "deny", "shell_exec"),
		testRule("r2", "allow", "search"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "CPX-001") != nil {
		t.Error("should not flag CPX-001 for small rule set")
	}
}

// --- CPX-004: Deep priority spread ---

func TestLintCPX004_DeepPrioritySpread(t *testing.T) {
	p := lintTestPolicy("deep-priority",
		testRuleWithPriority("low", "deny", 1, "shell_exec"),
		testRuleWithPriority("high", "allow", 200, "search"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "CPX-004") == nil {
		t.Error("expected CPX-004 for priority spread > 100")
	}
}

// --- BP-001: No default rule ---

func TestLintBP001_NoDefaultRule(t *testing.T) {
	p := lintTestPolicy("no-default",
		testRule("deny-shell", "deny", "shell_exec"),
		testRule("allow-search", "allow", "search"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "BP-001") == nil {
		t.Error("expected BP-001 for policy without default rule")
	}
}

func TestLintBP001_HasDefaultRule(t *testing.T) {
	p := lintTestPolicy("has-default",
		testRule("deny-shell", "deny", "shell_exec"),
		testRule("default-deny", "deny", "*"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "BP-001") != nil {
		t.Error("should not flag BP-001 when wildcard default exists")
	}
}

// --- BP-004: All rules same priority ---

func TestLintBP004_AllSamePriority(t *testing.T) {
	p := lintTestPolicy("flat",
		testRuleWithPriority("r1", "deny", 10, "shell_exec"),
		testRuleWithPriority("r2", "allow", 10, "search"),
		testRuleWithPriority("r3", "alert", 10, "http"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "BP-004") == nil {
		t.Error("expected BP-004 for all-same-priority rules")
	}
}

func TestLintBP004_DifferentPriorities(t *testing.T) {
	p := lintTestPolicy("ordered",
		testRuleWithPriority("r1", "deny", 20, "shell_exec"),
		testRuleWithPriority("r2", "allow", 15, "search"),
		testRuleWithPriority("r3", "alert", 10, "http"),
	)
	r := LintPolicy(p)
	if findLintRule(r, "BP-004") != nil {
		t.Error("should not flag BP-004 with different priorities")
	}
}

// --- Scoring and grading ---

func TestComputeLintScore_Perfect(t *testing.T) {
	score := computeLintScore(0, 0, 0, 0, 5)
	if score != 1.0 {
		t.Errorf("score = %f, want 1.0", score)
	}
}

func TestComputeLintScore_ErrorsDropScore(t *testing.T) {
	score := computeLintScore(3, 0, 0, 0, 5)
	if score >= 1.0 {
		t.Errorf("errors should reduce score, got %f", score)
	}
}

func TestComputeLintScore_EmptyPolicy(t *testing.T) {
	score := computeLintScore(0, 0, 0, 0, 0)
	if score != 1.0 {
		t.Errorf("empty policy score = %f, want 1.0", score)
	}
}

func TestGradeLint(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{1.0, "A"},
		{0.96, "A"},
		{0.95, "A"},
		{0.90, "B"},
		{0.85, "B"},
		{0.75, "C"},
		{0.70, "C"},
		{0.55, "D"},
		{0.50, "D"},
		{0.30, "F"},
		{0.0, "F"},
	}
	for _, tt := range tests {
		got := gradeLint(tt.score)
		if got != tt.want {
			t.Errorf("gradeLint(%f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// --- isKebabOrSnake ---

func TestIsKebabOrSnake(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"my-rule", true},
		{"my_rule", true},
		{"my-rule_123", true},
		{"", false},
		{"MyRule", false},
		{"my rule", false},
		{"my.rule", false},
		{"UPPER", false},
	}
	for _, tt := range tests {
		got := isKebabOrSnake(tt.input)
		if got != tt.want {
			t.Errorf("isKebabOrSnake(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// --- FormatLintReport ---

func TestFormatLintReport_Nil(t *testing.T) {
	out := FormatLintReport(nil)
	if out != "No lint report.\n" {
		t.Errorf("unexpected nil output: %q", out)
	}
}

func TestFormatLintReport_NoFindings(t *testing.T) {
	// Build a policy that passes all lint checks.
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta: PolicyMeta{
			Name:        "clean-policy",
			Description: "Fully specified policy",
			Authors:     []string{"test"},
			Created:     "2026-01-01",
			Modified:    "2026-01-01",
		},
	}
	r := LintPolicy(p)
	out := FormatLintReport(r)
	if !strings.Contains(out, "No issues found") {
		t.Errorf("expected 'No issues found' in clean report, got findings: %d", r.FindingCount)
		for _, f := range r.Findings {
			t.Logf("  %s [%s]: %s", f.Rule, f.Severity, f.Message)
		}
	}
	if !strings.Contains(out, "POLICY LINT REPORT") {
		t.Error("missing header")
	}
}

func TestFormatLintReport_WithFindings(t *testing.T) {
	p := lintTestPolicy("messy",
		testRule("allow-shell", "allow", "shell_exec"),
	)
	r := LintPolicy(p)
	out := FormatLintReport(r)
	if !strings.Contains(out, "SEC-003") {
		t.Error("expected SEC-003 in formatted output")
	}
	if !strings.Contains(out, "Findings") {
		t.Error("expected Findings section")
	}
}

func TestFormatLintReport_ContainsBoxDrawing(t *testing.T) {
	p := lintTestPolicy("boxed",
		testRule("r1", "deny", "shell_exec"),
	)
	r := LintPolicy(p)
	out := FormatLintReport(r)
	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Error("expected box-drawing characters")
	}
}

// --- Well-formed policy (minimal findings) ---

func TestLintPolicy_WellFormedPolicy(t *testing.T) {
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta: PolicyMeta{
			Name:        "production-policy",
			Description: "Main production AI agent policy",
			Authors:     []string{"security-team"},
			Created:     "2026-01-01",
			Modified:    "2026-09-14",
		},
		Agent: AgentScope{
			Name: "billing-agent",
			Type: "tool_calling",
		},
		Rules: []Rule{
			testRuleWithPriority("deny-shell", "deny", 20, "shell_exec"),
			testRuleWithPriority("deny-admin", "deny", 19, "admin_panel"),
			testRuleWithPriority("alert-http", "alert", 15, "http_request"),
			testRuleWithPriority("allow-search", "allow", 10, "search_knowledge_base"),
			testRuleWithPriority("default-deny", "deny", 1, "*"),
		},
	}
	// Add a tactic-based rule.
	p.Rules = append(p.Rules, Rule{
		ID:          "deny-exfil",
		Description: "Block all exfiltration tactics",
		Effect:      "deny",
		Priority:    18,
		Match:       RuleMatch{Tactics: []string{"exfiltration"}},
	})

	r := LintPolicy(p)

	// Should have very few findings — maybe just SEC-001 for wildcard deny.
	if r.ErrorCount > 0 {
		t.Errorf("well-formed policy has %d errors", r.ErrorCount)
		for _, f := range r.Findings {
			if f.Severity == LintError {
				t.Logf("  ERROR: %s: %s", f.Rule, f.Message)
			}
		}
	}
	if r.Grade != "A" && r.Grade != "B" {
		t.Errorf("well-formed policy grade = %q, expected A or B", r.Grade)
	}
}

// --- Severity ordering ---

func TestLintReport_FindingsOrderedBySeverity(t *testing.T) {
	p := lintTestPolicy("messy",
		// Will trigger various severity levels.
		testRule("same-id", "deny", "shell_exec"),
		testRule("same-id", "allow", "shell_exec"), // RED-001 error, RED-003 error
	)
	r := LintPolicy(p)

	if len(r.Findings) < 2 {
		t.Skipf("expected multiple findings, got %d", len(r.Findings))
	}

	// Verify ordering: errors before warnings before info before style.
	lastRank := 5
	for _, f := range r.Findings {
		rank := lintSeverityRank(f.Severity)
		if rank > lastRank {
			t.Errorf("findings not ordered by severity: %s (%q) appeared after lower severity",
				f.Rule, f.Severity)
		}
		lastRank = rank
	}
}

// --- Helper ---

func findLintRule(r *LintReport, ruleID string) *LintFinding {
	for _, f := range r.Findings {
		if f.Rule == ruleID {
			return &f
		}
	}
	return nil
}
