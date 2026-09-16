// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func testAgent(name string, tools []ToolAccess) *Agent {
	return &Agent{
		Meta:  AgentMeta{Name: name, Version: "1.0", Type: "tool-calling"},
		Tools: tools,
	}
}

func testAgentFull(name string, tools []ToolAccess, caps AgentCapabilities, guardrails []Guardrail) *Agent {
	return &Agent{
		APIVersion:   "v1",
		Kind:         "Agent",
		Meta:         AgentMeta{Name: name, Type: TypeToolCalling, Version: "1.0"},
		Capabilities: caps,
		Tools:        tools,
		Trust:        TrustConfig{Level: TrustStandard},
		Guardrails:   guardrails,
	}
}

func testPolicy(name string, rules []policy.Rule) *policy.Policy {
	return &policy.Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       policy.PolicyMeta{Name: name},
		Agent:      policy.AgentScope{Name: "*"},
		Rules:      rules,
	}
}

func allowRule(id string, tools ...string) policy.Rule {
	return policy.Rule{
		ID:          id,
		Description: "Allow rule " + id,
		Effect:      "allow",
		Priority:    10,
		Match:       policy.RuleMatch{Tools: tools},
	}
}

func denyRule(id string, tools ...string) policy.Rule {
	return policy.Rule{
		ID:          id,
		Description: "Deny rule " + id,
		Effect:      "deny",
		Priority:    10,
		Match:       policy.RuleMatch{Tools: tools},
	}
}

func alertRule(id string, tools ...string) policy.Rule {
	return policy.Rule{
		ID:          id,
		Description: "Alert rule " + id,
		Effect:      "alert",
		Priority:    10,
		Match:       policy.RuleMatch{Tools: tools},
	}
}

// approxEqual checks floating-point equality within a tolerance.
func approxEqual(a, b, tol float64) bool {
	return math.Abs(a-b) < tol
}

// hasWarning checks whether br contains a warning matching category and optionally tool/capability.
func hasWarning(br *BindingResult, category, toolOrCap string) bool {
	for _, w := range br.Warnings {
		if w.Category != category {
			continue
		}
		if toolOrCap == "" {
			return true
		}
		if w.Tool == toolOrCap || w.Capability == toolOrCap {
			return true
		}
	}
	return false
}

// countWarnings counts warnings matching the given category.
func countWarnings(br *BindingResult, category string) int {
	n := 0
	for _, w := range br.Warnings {
		if w.Category == category {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// 1-3: Nil / empty argument tests
// ---------------------------------------------------------------------------

func TestEvaluateBinding_NilAgent(t *testing.T) {
	p := testPolicy("test-policy", []policy.Rule{allowRule("r1", "*")})

	br := EvaluateBinding(nil, p)

	if br == nil {
		t.Fatal("expected non-nil result for nil agent")
	}
	if br.AgentName != "" {
		t.Errorf("AgentName = %q, want empty", br.AgentName)
	}
	if br.PolicyName != "test-policy" {
		t.Errorf("PolicyName = %q, want %q", br.PolicyName, "test-policy")
	}
	if br.Score != 0.0 {
		t.Errorf("Score = %f, want 0.0", br.Score)
	}
	if br.Grade != "F" {
		t.Errorf("Grade = %q, want %q", br.Grade, "F")
	}
}

func TestEvaluateBinding_NilPolicy(t *testing.T) {
	a := testAgent("agent-1", nil)

	br := EvaluateBinding(a, nil)

	if br == nil {
		t.Fatal("expected non-nil result for nil policy")
	}
	if br.AgentName != "agent-1" {
		t.Errorf("AgentName = %q, want %q", br.AgentName, "agent-1")
	}
	if br.PolicyName != "" {
		t.Errorf("PolicyName = %q, want empty", br.PolicyName)
	}
	if br.Score != 0.0 {
		t.Errorf("Score = %f, want 0.0", br.Score)
	}
	if br.Grade != "F" {
		t.Errorf("Grade = %q, want %q", br.Grade, "F")
	}
}

func TestEvaluateBinding_BothNil(t *testing.T) {
	br := EvaluateBinding(nil, nil)

	if br == nil {
		t.Fatal("expected non-nil result")
	}
	if br.AgentName != "" {
		t.Errorf("AgentName = %q, want empty", br.AgentName)
	}
	if br.PolicyName != "" {
		t.Errorf("PolicyName = %q, want empty", br.PolicyName)
	}
	if br.Score != 0.0 {
		t.Errorf("Score = %f, want 0.0", br.Score)
	}
	if br.Grade != "F" {
		t.Errorf("Grade = %q, want %q", br.Grade, "F")
	}
}

// ---------------------------------------------------------------------------
// 4-6: Basic coverage levels
// ---------------------------------------------------------------------------

func TestEvaluateBinding_FullCoverage(t *testing.T) {
	a := testAgent("full-agent", []ToolAccess{
		{Name: "web-search"},
		{Name: "database"},
		{Name: "email"},
	})
	p := testPolicy("full-policy", []policy.Rule{
		denyRule("r1", "*"),
	})

	br := EvaluateBinding(a, p)

	if len(br.CoveredTools) != 3 {
		t.Errorf("CoveredTools = %d, want 3", len(br.CoveredTools))
	}
	if len(br.UncoveredTools) != 0 {
		t.Errorf("UncoveredTools = %d, want 0", len(br.UncoveredTools))
	}
	if br.Score != 1.0 {
		t.Errorf("Score = %.2f, want 1.0", br.Score)
	}
	if br.Grade != "A" {
		t.Errorf("Grade = %q, want %q", br.Grade, "A")
	}
}

func TestEvaluateBinding_NoCoverage(t *testing.T) {
	// 10 non-elevated tools with no matching rules: Score = 1.0 - 10*0.1 = 0.0 => F.
	tools := make([]ToolAccess, 10)
	for i := range tools {
		tools[i] = ToolAccess{Name: fmt.Sprintf("tool-%d", i)}
	}
	a := testAgent("uncovered-agent", tools)
	p := testPolicy("empty-policy", []policy.Rule{
		denyRule("r1", "nonexistent"),
	})

	br := EvaluateBinding(a, p)

	if len(br.CoveredTools) != 0 {
		t.Errorf("CoveredTools = %d, want 0", len(br.CoveredTools))
	}
	if len(br.UncoveredTools) != 10 {
		t.Errorf("UncoveredTools = %d, want 10", len(br.UncoveredTools))
	}
	if br.Score != 0.0 {
		t.Errorf("Score = %.2f, want 0.0", br.Score)
	}
	if br.Grade != "F" {
		t.Errorf("Grade = %q, want %q", br.Grade, "F")
	}
}

func TestEvaluateBinding_PartialCoverage(t *testing.T) {
	a := testAgent("partial-agent", []ToolAccess{
		{Name: "web-search"},
		{Name: "database"},
		{Name: "email-send"},
	})
	p := testPolicy("partial-policy", []policy.Rule{
		allowRule("r1", "web-search"),
	})

	br := EvaluateBinding(a, p)

	if len(br.CoveredTools) != 1 {
		t.Errorf("CoveredTools = %d, want 1", len(br.CoveredTools))
	}
	if len(br.UncoveredTools) != 2 {
		t.Errorf("UncoveredTools = %d, want 2", len(br.UncoveredTools))
	}
	// Score = 1.0 - 2*0.1 = 0.8 (2 uncovered non-elevated; medium warnings only).
	if !approxEqual(br.Score, 0.8, 0.01) {
		t.Errorf("Score = %.4f, want ~0.8", br.Score)
	}
	if br.Grade != "B" {
		t.Errorf("Grade = %q, want %q", br.Grade, "B")
	}
}

// ---------------------------------------------------------------------------
// 7-10: Elevated tool scenarios
// ---------------------------------------------------------------------------

func TestEvaluateBinding_ElevatedUncovered(t *testing.T) {
	// Elevated tool with no matching rules at all.
	a := testAgent("elev-agent", []ToolAccess{
		{Name: "admin-delete", Elevated: true},
	})
	p := testPolicy("miss-policy", []policy.Rule{
		allowRule("r1", "other-tool"),
	})

	br := EvaluateBinding(a, p)

	if len(br.ElevatedUncovered) != 1 {
		t.Errorf("ElevatedUncovered = %d, want 1", len(br.ElevatedUncovered))
	}
	if !hasWarning(br, "elevated_uncovered", "admin-delete") {
		t.Error("expected elevated_uncovered warning for admin-delete")
	}
	if !hasWarning(br, "uncovered_tool", "admin-delete") {
		t.Error("expected uncovered_tool warning for admin-delete")
	}
}

func TestEvaluateBinding_ElevatedWithDeny(t *testing.T) {
	// Elevated tool with a deny rule — fully covered, no elevated_uncovered.
	a := testAgent("elev-deny-agent", []ToolAccess{
		{Name: "admin-tool", Elevated: true, RateLimit: 100},
	})
	p := testPolicy("deny-policy", []policy.Rule{
		denyRule("r1", "admin-tool"),
	})

	br := EvaluateBinding(a, p)

	if len(br.ElevatedUncovered) != 0 {
		t.Errorf("ElevatedUncovered = %d, want 0", len(br.ElevatedUncovered))
	}
	if len(br.CoveredTools) != 1 {
		t.Errorf("CoveredTools = %d, want 1", len(br.CoveredTools))
	}
	if hasWarning(br, "overpermissive", "") {
		t.Error("should not have overpermissive warning when deny rule covers the tool")
	}
	if br.Score != 1.0 {
		t.Errorf("Score = %.2f, want 1.0", br.Score)
	}
	if br.Grade != "A" {
		t.Errorf("Grade = %q, want %q", br.Grade, "A")
	}
}

func TestEvaluateBinding_Overpermissive(t *testing.T) {
	// Elevated tool covered only by allow rules (no deny/alert).
	a := testAgent("overperm-agent", []ToolAccess{
		{Name: "priv-tool", Elevated: true, RateLimit: 100},
	})
	p := testPolicy("allow-only", []policy.Rule{
		allowRule("r1", "priv-tool"),
	})

	br := EvaluateBinding(a, p)

	if !hasWarning(br, "overpermissive", "priv-tool") {
		t.Error("expected overpermissive warning for elevated tool with only allow rules")
	}
	// Also elevated_uncovered because no deny rule.
	if len(br.ElevatedUncovered) != 1 {
		t.Errorf("ElevatedUncovered = %d, want 1", len(br.ElevatedUncovered))
	}
}

func TestEvaluateBinding_ElevatedNoRateLimit(t *testing.T) {
	// Elevated tool with RateLimit=0 (properly denied, but no rate limit).
	a := testAgent("ratelimit-agent", []ToolAccess{
		{Name: "fast-tool", Elevated: true, RateLimit: 0},
	})
	p := testPolicy("deny-policy", []policy.Rule{
		denyRule("r1", "fast-tool"),
	})

	br := EvaluateBinding(a, p)

	if !hasWarning(br, "rate_limit_missing", "fast-tool") {
		t.Error("expected rate_limit_missing warning for elevated tool with RateLimit 0")
	}
	// Deny rule covers it, so no elevated_uncovered.
	if len(br.ElevatedUncovered) != 0 {
		t.Errorf("ElevatedUncovered = %d, want 0", len(br.ElevatedUncovered))
	}
	// rate_limit_missing is severity "medium", so no score deduction.
	if br.Score != 1.0 {
		t.Errorf("Score = %.2f, want 1.0 (rate_limit_missing is medium severity)", br.Score)
	}
}

// ---------------------------------------------------------------------------
// 11-16: Capability-guardrail coverage
// ---------------------------------------------------------------------------

func TestEvaluateBinding_CodeExecutionNoGuardrail(t *testing.T) {
	a := testAgentFull("code-agent", nil,
		AgentCapabilities{CodeExecution: true},
		nil, // no guardrails
	)
	p := testPolicy("some-policy", []policy.Rule{
		allowRule("r1", "*"),
	})

	br := EvaluateBinding(a, p)

	if !hasWarning(br, "missing_guardrail", "code_execution") {
		t.Error("expected missing_guardrail warning for code_execution without tool-call guardrail")
	}
}

func TestEvaluateBinding_CodeExecutionWithGuardrail(t *testing.T) {
	a := testAgentFull("code-guarded-agent", nil,
		AgentCapabilities{CodeExecution: true},
		[]Guardrail{{Name: "tc-guard", Type: "tool-call", Enforced: true}},
	)
	p := testPolicy("some-policy", []policy.Rule{
		allowRule("r1", "*"),
	})

	br := EvaluateBinding(a, p)

	if hasWarning(br, "missing_guardrail", "code_execution") {
		t.Error("should not have code_execution missing_guardrail warning when tool-call guardrail exists")
	}
}

func TestEvaluateBinding_RAGNoGuardrail(t *testing.T) {
	a := testAgentFull("rag-agent", nil,
		AgentCapabilities{RAG: true},
		nil,
	)
	p := testPolicy("rag-policy", []policy.Rule{
		allowRule("r1", "*"),
	})

	br := EvaluateBinding(a, p)

	if !hasWarning(br, "missing_guardrail", "rag") {
		t.Error("expected missing_guardrail warning for rag without input guardrail")
	}
}

func TestEvaluateBinding_RAGWithGuardrail(t *testing.T) {
	a := testAgentFull("rag-guarded", nil,
		AgentCapabilities{RAG: true},
		[]Guardrail{{Name: "input-guard", Type: "input", Enforced: true}},
	)
	p := testPolicy("rag-policy", []policy.Rule{
		allowRule("r1", "*"),
	})

	br := EvaluateBinding(a, p)

	if hasWarning(br, "missing_guardrail", "rag") {
		t.Error("should not have rag missing_guardrail warning when input guardrail exists")
	}
}

func TestEvaluateBinding_MessagePassingNoPolicy(t *testing.T) {
	a := testAgentFull("msg-agent", nil,
		AgentCapabilities{MessagePassing: true},
		nil,
	)
	p := testPolicy("no-msg-policy", []policy.Rule{
		allowRule("r1", "web-search"),
	})

	br := EvaluateBinding(a, p)

	if !hasWarning(br, "missing_guardrail", "message_passing") {
		t.Error("expected missing_guardrail warning for message_passing without agent_message rule")
	}
}

func TestEvaluateBinding_MessagePassingWithPolicy(t *testing.T) {
	a := testAgentFull("msg-covered-agent", nil,
		AgentCapabilities{MessagePassing: true},
		nil,
	)
	p := testPolicy("msg-policy", []policy.Rule{
		denyRule("r1", "agent_message"),
	})

	br := EvaluateBinding(a, p)

	if hasWarning(br, "missing_guardrail", "message_passing") {
		t.Error("should not have message_passing warning when agent_message rule exists")
	}
}

// ---------------------------------------------------------------------------
// 17: Glob pattern matching
// ---------------------------------------------------------------------------

func TestEvaluateBinding_GlobPattern(t *testing.T) {
	a := testAgent("glob-agent", []ToolAccess{
		{Name: "db-read"},
		{Name: "db-write"},
		{Name: "db-delete"},
		{Name: "api-call"},
	})
	p := testPolicy("glob-policy", []policy.Rule{
		denyRule("r1", "db-*"),
		allowRule("r2", "api-*"),
	})

	br := EvaluateBinding(a, p)

	if len(br.CoveredTools) != 4 {
		t.Errorf("CoveredTools = %d, want 4 (glob should match all)", len(br.CoveredTools))
	}
	if len(br.UncoveredTools) != 0 {
		t.Errorf("UncoveredTools = %d, want 0", len(br.UncoveredTools))
	}
}

// ---------------------------------------------------------------------------
// 18: Score calculation with known inputs
// ---------------------------------------------------------------------------

func TestEvaluateBinding_ScoreCalculation(t *testing.T) {
	// 2 non-elevated uncovered + 1 elevated uncovered (RateLimit=0).
	// UncoveredTools:    3 => -0.30
	// ElevatedUncovered: 1 => -0.15
	// Warnings:
	//   uncovered_tool (medium) x2 => 0
	//   uncovered_tool (critical) x1 => -0.05
	//   elevated_uncovered (high)  x1 => -0.05
	//   rate_limit_missing (medium) x1 => 0
	// Score = 1.0 - 0.30 - 0.15 - 0.05 - 0.05 = 0.45
	a := testAgent("score-agent", []ToolAccess{
		{Name: "tool-a"},
		{Name: "tool-b"},
		{Name: "tool-c", Elevated: true, RateLimit: 0},
	})
	p := testPolicy("no-match", []policy.Rule{
		denyRule("r1", "nonexistent"),
	})

	br := EvaluateBinding(a, p)

	if !approxEqual(br.Score, 0.45, 0.01) {
		t.Errorf("Score = %.4f, want ~0.45", br.Score)
	}
	if br.Grade != "D" {
		t.Errorf("Grade = %q, want %q", br.Grade, "D")
	}
}

// ---------------------------------------------------------------------------
// 19: Grade thresholds
// ---------------------------------------------------------------------------

func TestEvaluateBinding_GradeThresholds(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{1.0, "A"},
		{0.95, "A"},
		{0.9, "A"},
		{0.899, "B"},
		{0.85, "B"},
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
		got := gradeBinding(tt.score)
		if got != tt.want {
			t.Errorf("gradeBinding(%.3f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 20-24: EvaluateAll tests
// ---------------------------------------------------------------------------

func TestEvaluateAll_EmptyInventory(t *testing.T) {
	inv := &Inventory{}
	p := testPolicy("policy", []policy.Rule{
		allowRule("r1", "*"),
	})

	ibr := inv.EvaluateAll(p)

	if ibr.TotalAgents != 0 {
		t.Errorf("TotalAgents = %d, want 0", ibr.TotalAgents)
	}
	if ibr.FullyCovered != 0 {
		t.Errorf("FullyCovered = %d, want 0", ibr.FullyCovered)
	}
	if len(ibr.Results) != 0 {
		t.Errorf("Results = %d, want 0", len(ibr.Results))
	}
	if ibr.Warnings != 0 {
		t.Errorf("Warnings = %d, want 0", ibr.Warnings)
	}
}

func TestEvaluateAll_NilPolicy(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			testAgent("a1", nil),
		},
	}

	ibr := inv.EvaluateAll(nil)

	if ibr == nil {
		t.Fatal("expected non-nil result for nil policy")
	}
	if ibr.PolicyName != "" {
		t.Errorf("PolicyName = %q, want empty", ibr.PolicyName)
	}
}

func TestEvaluateAll_MultipleAgents(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			testAgent("agent-1", []ToolAccess{{Name: "tool-a"}}),
			testAgent("agent-2", []ToolAccess{{Name: "tool-b"}}),
			testAgent("agent-3", []ToolAccess{{Name: "tool-c"}}),
		},
	}
	p := testPolicy("multi-policy", []policy.Rule{
		allowRule("r1", "tool-a"),
		denyRule("r2", "tool-b"),
		// tool-c not covered
	})

	ibr := inv.EvaluateAll(p)

	if ibr.TotalAgents != 3 {
		t.Errorf("TotalAgents = %d, want 3", ibr.TotalAgents)
	}
	if len(ibr.Results) != 3 {
		t.Errorf("Results = %d, want 3", len(ibr.Results))
	}
	// agent-1 and agent-2 fully covered; agent-3 has uncovered tool.
	if ibr.FullyCovered != 2 {
		t.Errorf("FullyCovered = %d, want 2", ibr.FullyCovered)
	}
	if ibr.Warnings == 0 {
		t.Error("expected at least some warnings for uncovered tool-c")
	}
}

func TestEvaluateAll_AllFullyCovered(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			testAgent("a1", []ToolAccess{{Name: "t1"}}),
			testAgent("a2", []ToolAccess{{Name: "t2"}}),
			testAgent("a3", []ToolAccess{{Name: "t3"}}),
		},
	}
	p := testPolicy("full-cov", []policy.Rule{
		denyRule("r1", "*"),
	})

	ibr := inv.EvaluateAll(p)

	if ibr.FullyCovered != 3 {
		t.Errorf("FullyCovered = %d, want 3", ibr.FullyCovered)
	}
	if ibr.TotalAgents != 3 {
		t.Errorf("TotalAgents = %d, want 3", ibr.TotalAgents)
	}
}

func TestEvaluateAll_WarningCount(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			testAgentFull("a1", []ToolAccess{
				{Name: "uncov-1"},
			}, AgentCapabilities{CodeExecution: true}, nil),
			testAgentFull("a2", []ToolAccess{
				{Name: "uncov-2"},
				{Name: "uncov-3"},
			}, AgentCapabilities{}, nil),
		},
	}
	p := testPolicy("partial", []policy.Rule{
		allowRule("r1", "nonexistent"),
	})

	ibr := inv.EvaluateAll(p)

	// Verify the total is the sum of per-agent warnings.
	expectedTotal := 0
	for _, r := range ibr.Results {
		expectedTotal += len(r.Warnings)
	}
	if ibr.Warnings != expectedTotal {
		t.Errorf("Total warnings %d != sum of per-agent warnings %d", ibr.Warnings, expectedTotal)
	}
	if ibr.Warnings == 0 {
		t.Error("expected at least some warnings")
	}
}

// ---------------------------------------------------------------------------
// 25-29: FormatBinding tests
// ---------------------------------------------------------------------------

func TestFormatBinding_Nil(t *testing.T) {
	out := FormatBinding(nil)
	if !strings.Contains(out, "No binding result") {
		t.Errorf("expected 'No binding result', got %q", out)
	}
}

func TestFormatBinding_Output(t *testing.T) {
	br := &BindingResult{
		AgentName:    "test-agent",
		PolicyName:   "test-policy",
		Score:        0.85,
		Grade:        "B",
		CoveredTools: []string{"tool-a"},
	}

	out := FormatBinding(br)

	if !strings.Contains(out, "POLICY BINDING") {
		t.Error("output should contain report header")
	}
	if !strings.Contains(out, "test-agent") {
		t.Error("output should contain agent name")
	}
	if !strings.Contains(out, "test-policy") {
		t.Error("output should contain policy name")
	}
	if !strings.Contains(out, "0.85") {
		t.Error("output should contain score")
	}
	if !strings.Contains(out, "(B)") {
		t.Error("output should contain grade")
	}
	// Box-drawing characters.
	for _, ch := range []string{"┌", "└", "│", "├"} {
		if !strings.Contains(out, ch) {
			t.Errorf("output should contain box-drawing character %q", ch)
		}
	}
}

func TestFormatBinding_CoveredTools(t *testing.T) {
	br := &BindingResult{
		AgentName:    "agent",
		PolicyName:   "policy",
		Score:        1.0,
		Grade:        "A",
		CoveredTools: []string{"my-tool"},
	}

	out := FormatBinding(br)

	if !strings.Contains(out, "Covered Tools") {
		t.Error("output should contain Covered Tools section")
	}
	if !strings.Contains(out, "my-tool") {
		t.Error("output should contain covered tool name")
	}
	if !strings.Contains(out, "[OK]") {
		t.Error("output should contain [OK] marker for covered tools")
	}
}

func TestFormatBinding_UncoveredTools(t *testing.T) {
	br := &BindingResult{
		AgentName:      "agent",
		PolicyName:     "policy",
		Score:          0.5,
		Grade:          "C",
		UncoveredTools: []string{"missing-tool"},
	}

	out := FormatBinding(br)

	if !strings.Contains(out, "Uncovered Tools") {
		t.Error("output should contain Uncovered Tools section")
	}
	if !strings.Contains(out, "missing-tool") {
		t.Error("output should contain uncovered tool name")
	}
	if !strings.Contains(out, "[!!]") {
		t.Error("output should contain [!!] marker for uncovered tools")
	}
}

func TestFormatBinding_Warnings(t *testing.T) {
	br := &BindingResult{
		AgentName:  "agent",
		PolicyName: "policy",
		Score:      0.5,
		Grade:      "C",
		Warnings: []BindingWarning{
			{Tool: "bad-tool", Category: "uncovered_tool", Severity: "high", Description: "uncovered"},
			{Capability: "code_execution", Category: "missing_guardrail", Severity: "high", Description: "no guardrail"},
		},
	}

	out := FormatBinding(br)

	if !strings.Contains(out, "Warnings") {
		t.Error("output should contain Warnings section")
	}
	if !strings.Contains(out, "high") {
		t.Error("output should contain severity label")
	}
	// Capability-based warning should show capability as label.
	if !strings.Contains(out, "code_execution") {
		t.Error("output should show capability name when Tool is empty")
	}
}

// ---------------------------------------------------------------------------
// 30-31: FormatInventoryBinding tests
// ---------------------------------------------------------------------------

func TestFormatInventoryBinding_Nil(t *testing.T) {
	out := FormatInventoryBinding(nil)
	if !strings.Contains(out, "No inventory binding report") {
		t.Errorf("expected 'No inventory binding report', got %q", out)
	}
}

func TestFormatInventoryBinding_Output(t *testing.T) {
	ibr := &InventoryBindingReport{
		PolicyName:   "test-policy",
		TotalAgents:  3,
		FullyCovered: 2,
		Warnings:     5,
		Results: []BindingResult{
			{AgentName: "a1", Score: 1.0, Grade: "A"},
			{AgentName: "a2", Score: 0.5, Grade: "C", UncoveredTools: []string{"x"}},
			{AgentName: "a3", Score: 0.8, Grade: "B"},
		},
	}

	out := FormatInventoryBinding(ibr)

	if !strings.Contains(out, "INVENTORY BINDING REPORT") {
		t.Error("output should contain report header")
	}
	if !strings.Contains(out, "test-policy") {
		t.Error("output should contain policy name")
	}
	if !strings.Contains(out, "a1") {
		t.Error("output should list agent a1")
	}
	if !strings.Contains(out, "a2") {
		t.Error("output should list agent a2")
	}
	if !strings.Contains(out, "Coverage") {
		t.Error("output should contain coverage summary")
	}

	// Worst score first: a2 (0.5) should appear before a3 (0.8) and a1 (1.0).
	a2Idx := strings.Index(out, "a2")
	a1Idx := strings.Index(out, "a1")
	if a2Idx > a1Idx {
		t.Error("worst agent should appear before better agent in sorted output")
	}
}

// ---------------------------------------------------------------------------
// 32: Grade boundary values directly
// ---------------------------------------------------------------------------

func TestGradeBinding(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{1.0, "A"},
		{0.9, "A"},
		{0.8999, "B"},
		{0.7, "B"},
		{0.6999, "C"},
		{0.5, "C"},
		{0.4999, "D"},
		{0.3, "D"},
		{0.2999, "F"},
		{0.0, "F"},
		{-0.5, "F"},
	}
	for _, tt := range tests {
		got := gradeBinding(tt.score)
		if got != tt.want {
			t.Errorf("gradeBinding(%.4f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Additional coverage: edge cases and integration
// ---------------------------------------------------------------------------

func TestEvaluateBinding_NoTools(t *testing.T) {
	// Agent with no tools at all — perfect score.
	a := testAgent("no-tools-agent", nil)
	p := testPolicy("some-policy", []policy.Rule{
		allowRule("r1", "*"),
	})

	br := EvaluateBinding(a, p)

	if len(br.CoveredTools) != 0 {
		t.Errorf("CoveredTools = %d, want 0", len(br.CoveredTools))
	}
	if len(br.UncoveredTools) != 0 {
		t.Errorf("UncoveredTools = %d, want 0", len(br.UncoveredTools))
	}
	if br.Score != 1.0 {
		t.Errorf("Score = %.2f, want 1.0 for agent with no tools", br.Score)
	}
	if br.Grade != "A" {
		t.Errorf("Grade = %q, want %q", br.Grade, "A")
	}
}

func TestEvaluateBinding_ElevatedToolWithAlert(t *testing.T) {
	// Alert rule matches but is NOT a deny rule.
	a := testAgent("elev-alert-agent", []ToolAccess{
		{Name: "admin-tool", Elevated: true, RateLimit: 100},
	})
	p := testPolicy("alert-policy", []policy.Rule{
		alertRule("r1", "admin-tool"),
	})

	br := EvaluateBinding(a, p)

	// Tool is covered by the alert rule.
	if len(br.CoveredTools) != 1 {
		t.Errorf("CoveredTools = %d, want 1", len(br.CoveredTools))
	}
	// Alert is NOT a deny rule — elevated_uncovered should fire.
	if len(br.ElevatedUncovered) != 1 {
		t.Errorf("ElevatedUncovered = %d, want 1 (alert is not deny)", len(br.ElevatedUncovered))
	}
	// But alert IS in deny-or-alert — so overpermissive should NOT fire.
	if hasWarning(br, "overpermissive", "admin-tool") {
		t.Error("should not have overpermissive warning when alert rule covers the tool")
	}
}

func TestEvaluateBinding_MessagePassingWithGlob(t *testing.T) {
	// Glob pattern agent_* should match agent_message.
	a := testAgentFull("msg-glob-agent", nil,
		AgentCapabilities{MessagePassing: true},
		nil,
	)
	p := testPolicy("msg-glob-policy", []policy.Rule{
		denyRule("r1", "agent_*"),
	})

	br := EvaluateBinding(a, p)

	if hasWarning(br, "missing_guardrail", "message_passing") {
		t.Error("should not have message_passing warning when glob pattern matches agent_message")
	}
}

func TestEvaluateBinding_MultipleElevatedMixed(t *testing.T) {
	a := testAgent("mixed-agent", []ToolAccess{
		{Name: "tool-a", Elevated: true, RateLimit: 100},
		{Name: "tool-b", Elevated: true, RateLimit: 100},
		{Name: "tool-c", Elevated: false},
	})
	p := testPolicy("mixed-policy", []policy.Rule{
		denyRule("r1", "tool-a"),
		allowRule("r2", "tool-b"),
		allowRule("r3", "tool-c"),
	})

	br := EvaluateBinding(a, p)

	if len(br.CoveredTools) != 3 {
		t.Errorf("CoveredTools = %d, want 3", len(br.CoveredTools))
	}
	// tool-b is elevated with only allow (no deny) — ElevatedUncovered.
	if len(br.ElevatedUncovered) != 1 {
		t.Errorf("ElevatedUncovered = %d, want 1", len(br.ElevatedUncovered))
	}
	if len(br.ElevatedUncovered) > 0 && br.ElevatedUncovered[0] != "tool-b" {
		t.Errorf("ElevatedUncovered[0] = %q, want %q", br.ElevatedUncovered[0], "tool-b")
	}
}

func TestEvaluateBinding_CriticalSeverityForUncoveredElevated(t *testing.T) {
	a := testAgent("crit-agent", []ToolAccess{
		{Name: "admin-tool", Elevated: true},
	})
	p := testPolicy("no-match", []policy.Rule{
		allowRule("r1", "other"),
	})

	br := EvaluateBinding(a, p)

	for _, w := range br.Warnings {
		if w.Category == "uncovered_tool" && w.Tool == "admin-tool" {
			if w.Severity != "critical" {
				t.Errorf("uncovered elevated tool severity = %q, want %q", w.Severity, "critical")
			}
			return
		}
	}
	t.Error("expected uncovered_tool warning for admin-tool")
}

func TestEvaluateBinding_MediumSeverityForUncoveredNonElevated(t *testing.T) {
	a := testAgent("med-agent", []ToolAccess{
		{Name: "basic-tool", Elevated: false},
	})
	p := testPolicy("no-match", []policy.Rule{
		allowRule("r1", "other"),
	})

	br := EvaluateBinding(a, p)

	for _, w := range br.Warnings {
		if w.Category == "uncovered_tool" && w.Tool == "basic-tool" {
			if w.Severity != "medium" {
				t.Errorf("uncovered non-elevated tool severity = %q, want %q", w.Severity, "medium")
			}
			return
		}
	}
	t.Error("expected uncovered_tool warning for basic-tool")
}

func TestEvaluateBinding_AllCapabilityWarnings(t *testing.T) {
	a := testAgentFull("all-caps-agent", nil,
		AgentCapabilities{
			CodeExecution:  true,
			RAG:            true,
			MessagePassing: true,
		},
		nil, // no guardrails
	)
	p := testPolicy("no-msg-policy", []policy.Rule{
		allowRule("r1", "some-tool"),
	})

	br := EvaluateBinding(a, p)

	caps := map[string]bool{}
	for _, w := range br.Warnings {
		if w.Category == "missing_guardrail" {
			caps[w.Capability] = true
		}
	}
	for _, want := range []string{"code_execution", "rag", "message_passing"} {
		if !caps[want] {
			t.Errorf("missing warning for capability %q", want)
		}
	}
}

func TestEvaluateBinding_RateLimitMixedElevated(t *testing.T) {
	// Two elevated tools: one with rate limit, one without.
	a := testAgent("rl-mixed-agent", []ToolAccess{
		{Name: "fast-tool", Elevated: true, RateLimit: 0},
		{Name: "safe-tool", Elevated: true, RateLimit: 100},
	})
	p := testPolicy("deny-all", []policy.Rule{
		denyRule("r1", "*"),
	})

	br := EvaluateBinding(a, p)

	n := countWarnings(br, "rate_limit_missing")
	if n != 1 {
		t.Errorf("rate_limit_missing warnings = %d, want 1 (only fast-tool)", n)
	}
}

func TestEvaluateBinding_WildcardCoverageAll(t *testing.T) {
	a := testAgent("wildcard-agent", []ToolAccess{
		{Name: "anything"},
		{Name: "other-tool"},
		{Name: "third"},
	})
	p := testPolicy("wildcard-policy", []policy.Rule{
		allowRule("r1", "*"),
	})

	br := EvaluateBinding(a, p)

	if len(br.CoveredTools) != 3 {
		t.Errorf("CoveredTools = %d, want 3", len(br.CoveredTools))
	}
	if len(br.UncoveredTools) != 0 {
		t.Errorf("UncoveredTools = %d, want 0", len(br.UncoveredTools))
	}
}

// --- Score computation unit tests (unexported function) ---

func TestComputeScore_Perfect(t *testing.T) {
	br := &BindingResult{}
	s := computeScore(br)
	if s != 1.0 {
		t.Errorf("computeScore with no issues = %.2f, want 1.0", s)
	}
}

func TestComputeScore_UncoveredPenalty(t *testing.T) {
	br := &BindingResult{
		UncoveredTools: []string{"a", "b"},
	}
	s := computeScore(br)
	// 1.0 - 2*0.1 = 0.8
	if !approxEqual(s, 0.8, 0.001) {
		t.Errorf("computeScore = %.4f, want 0.8", s)
	}
}

func TestComputeScore_ElevatedPenalty(t *testing.T) {
	br := &BindingResult{
		ElevatedUncovered: []string{"x"},
	}
	s := computeScore(br)
	// 1.0 - 0.15 = 0.85
	if !approxEqual(s, 0.85, 0.001) {
		t.Errorf("computeScore = %.4f, want 0.85", s)
	}
}

func TestComputeScore_HighWarningPenalty(t *testing.T) {
	br := &BindingResult{
		Warnings: []BindingWarning{
			{Severity: "high"},
			{Severity: "critical"},
			{Severity: "low"},    // should NOT deduct
			{Severity: "medium"}, // should NOT deduct
		},
	}
	s := computeScore(br)
	// 1.0 - 2*0.05 = 0.9
	if !approxEqual(s, 0.9, 0.001) {
		t.Errorf("computeScore = %.4f, want 0.9", s)
	}
}

func TestComputeScore_Floor(t *testing.T) {
	br := &BindingResult{
		UncoveredTools:    []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"},
		ElevatedUncovered: []string{"x", "y", "z"},
	}
	s := computeScore(br)
	if s != 0.0 {
		t.Errorf("computeScore = %.2f, want 0.0 (should floor at zero)", s)
	}
}

func TestComputeScore_CombinedPenalties(t *testing.T) {
	br := &BindingResult{
		UncoveredTools:    []string{"a"}, // -0.1
		ElevatedUncovered: []string{"b"}, // -0.15
		Warnings: []BindingWarning{
			{Severity: "high"},     // -0.05
			{Severity: "critical"}, // -0.05
			{Severity: "medium"},   // 0
		},
	}
	s := computeScore(br)
	// 1.0 - 0.1 - 0.15 - 0.05 - 0.05 = 0.65
	if !approxEqual(s, 0.65, 0.001) {
		t.Errorf("computeScore = %.4f, want 0.65", s)
	}
}

// --- EvaluateAll edge cases ---

func TestEvaluateAll_NilInventory(t *testing.T) {
	var inv *Inventory
	p := testPolicy("policy", []policy.Rule{
		allowRule("r1", "*"),
	})

	ibr := inv.EvaluateAll(p)

	if ibr == nil {
		t.Fatal("expected non-nil result for nil inventory")
	}
	if ibr.TotalAgents != 0 {
		t.Errorf("TotalAgents = %d, want 0", ibr.TotalAgents)
	}
}

// --- FormatInventoryBinding edge cases ---

func TestFormatInventoryBinding_EmptyResults(t *testing.T) {
	ibr := &InventoryBindingReport{
		PolicyName:  "policy",
		TotalAgents: 0,
	}

	out := FormatInventoryBinding(ibr)

	if !strings.Contains(out, "INVENTORY BINDING REPORT") {
		t.Error("output should still contain header for empty report")
	}
	if !strings.Contains(out, "Coverage: 0%") {
		t.Error("expected 0%% coverage for empty report")
	}
}

func TestFormatInventoryBinding_SortedWorstFirst(t *testing.T) {
	ibr := &InventoryBindingReport{
		PolicyName:  "policy",
		TotalAgents: 2,
		Results: []BindingResult{
			{AgentName: "good-agent", Score: 1.0, Grade: "A"},
			{AgentName: "bad-agent", Score: 0.2, Grade: "F"},
		},
	}

	out := FormatInventoryBinding(ibr)

	badIdx := strings.Index(out, "bad-agent")
	goodIdx := strings.Index(out, "good-agent")
	if badIdx < 0 || goodIdx < 0 {
		t.Fatal("both agent names should appear in output")
	}
	if badIdx > goodIdx {
		t.Error("worst agent should appear before better agent (sorted worst-first)")
	}
}

// --- Integration test: complex multi-concern scenario ---

func TestEvaluateBinding_ComplexScenario(t *testing.T) {
	a := testAgentFull("complex-agent", []ToolAccess{
		{Name: "web-search", Elevated: false, RateLimit: 100},
		{Name: "database-write", Elevated: true, RateLimit: 0},
		{Name: "email-send", Elevated: true, RateLimit: 50},
		{Name: "file-upload", Elevated: false},
		{Name: "admin-console", Elevated: true, RateLimit: 0},
	}, AgentCapabilities{
		CodeExecution:  true,
		RAG:            true,
		MessagePassing: true,
	}, []Guardrail{
		{Name: "tc-guard", Type: "tool-call", Enforced: true},
	})

	p := testPolicy("complex-policy", []policy.Rule{
		allowRule("r1", "web-search"),
		denyRule("r2", "database-*"),
		alertRule("r3", "email-*"),
		// file-upload and admin-console are uncovered.
		// agent_message is not mentioned.
	})

	br := EvaluateBinding(a, p)

	// 3 tools covered (web-search, database-write, email-send), 2 uncovered.
	if len(br.CoveredTools) != 3 {
		t.Errorf("CoveredTools = %d, want 3", len(br.CoveredTools))
	}
	if len(br.UncoveredTools) != 2 {
		t.Errorf("UncoveredTools = %d, want 2", len(br.UncoveredTools))
	}

	// email-send: elevated, alert covers it but hasMatchingDenyRule is false => ElevatedUncovered.
	// admin-console: elevated, no rule at all => ElevatedUncovered.
	// database-write: elevated, deny covers it => NOT ElevatedUncovered.
	if len(br.ElevatedUncovered) != 2 {
		t.Errorf("ElevatedUncovered = %d, want 2 (email-send, admin-console)", len(br.ElevatedUncovered))
	}

	// RAG has no input guardrail.
	if !hasWarning(br, "missing_guardrail", "rag") {
		t.Error("expected missing_guardrail for rag capability")
	}

	// Code execution has tool-call guardrail — no warning.
	if hasWarning(br, "missing_guardrail", "code_execution") {
		t.Error("should not have code_execution warning since tool-call guardrail exists")
	}

	// Message passing — no agent_message rule.
	if !hasWarning(br, "missing_guardrail", "message_passing") {
		t.Error("expected missing_guardrail for message_passing")
	}

	// Rate limit: database-write and admin-console are elevated with RateLimit=0.
	n := countWarnings(br, "rate_limit_missing")
	if n != 2 {
		t.Errorf("rate_limit_missing = %d, want 2", n)
	}

	// Score should be well below 0.5 given the many issues.
	if br.Score >= 0.5 {
		t.Errorf("Score = %.2f, expected < 0.5 for complex scenario with many issues", br.Score)
	}
}

func TestEvaluateBinding_ScoreAndGradeConsistency(t *testing.T) {
	// Verify that computed grade always matches the score.
	for _, nUncovered := range []int{0, 1, 2, 5, 10} {
		tools := make([]ToolAccess, nUncovered)
		for i := range tools {
			tools[i] = ToolAccess{Name: fmt.Sprintf("uncov-%d", i)}
		}
		a := testAgent("score-agent", tools)
		p := testPolicy("empty", []policy.Rule{
			allowRule("r1", "nonexistent"),
		})

		br := EvaluateBinding(a, p)

		expected := gradeBinding(br.Score)
		if br.Grade != expected {
			t.Errorf("uncovered=%d: gradeBinding(%.2f)=%q, br.Grade=%q",
				nUncovered, br.Score, expected, br.Grade)
		}
	}
}
