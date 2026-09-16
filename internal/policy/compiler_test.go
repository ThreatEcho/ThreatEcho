// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"strings"
	"testing"
)

func compilerTestPolicy(rules ...Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta: PolicyMeta{
			Name:        "test-policy",
			Description: "test",
		},
		Agent: AgentScope{Name: "*"},
		Rules: rules,
	}
}

func TestCompile_Basic(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"file_read"}}},
		Rule{ID: "r3", Effect: "alert", Priority: 50,
			Match: RuleMatch{Tactics: []string{"exfiltration"}}},
	)

	cp := Compile(p)

	if cp.Stats.TotalRules != 3 {
		t.Errorf("TotalRules = %d, want 3", cp.Stats.TotalRules)
	}
	if cp.Stats.DenyRules != 1 {
		t.Errorf("DenyRules = %d, want 1", cp.Stats.DenyRules)
	}
	if cp.Stats.AllowRules != 1 {
		t.Errorf("AllowRules = %d, want 1", cp.Stats.AllowRules)
	}
	if cp.Stats.AlertRules != 1 {
		t.Errorf("AlertRules = %d, want 1", cp.Stats.AlertRules)
	}
	if cp.Stats.UniqueTools != 2 {
		t.Errorf("UniqueTools = %d, want 2", cp.Stats.UniqueTools)
	}
	if cp.Stats.UniqueTactics != 1 {
		t.Errorf("UniqueTactics = %d, want 1", cp.Stats.UniqueTactics)
	}

	// Verify tool index.
	if len(cp.RulesByTool["shell_exec"]) != 1 {
		t.Errorf("RulesByTool[shell_exec] = %d, want 1", len(cp.RulesByTool["shell_exec"]))
	}
	if len(cp.RulesByTool["file_read"]) != 1 {
		t.Errorf("RulesByTool[file_read] = %d, want 1", len(cp.RulesByTool["file_read"]))
	}

	// Verify tactic index.
	if len(cp.RulesByTactic["exfiltration"]) != 1 {
		t.Errorf("RulesByTactic[exfiltration] = %d, want 1", len(cp.RulesByTactic["exfiltration"]))
	}
}

func TestCompile_Nil(t *testing.T) {
	cp := Compile(nil)
	if cp == nil {
		t.Fatal("Compile(nil) returned nil")
	}
	if cp.Stats.TotalRules != 0 {
		t.Errorf("TotalRules = %d, want 0", cp.Stats.TotalRules)
	}
	if len(cp.SortedRules) != 0 {
		t.Errorf("SortedRules = %d, want 0", len(cp.SortedRules))
	}
}

func TestCompile_EmptyPolicy(t *testing.T) {
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "empty"},
		Agent:      AgentScope{Name: "*"},
	}
	cp := Compile(p)
	if cp.Stats.TotalRules != 0 {
		t.Errorf("TotalRules = %d, want 0", cp.Stats.TotalRules)
	}
}

func TestCompile_SortedByPriority(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "low", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"a"}}},
		Rule{ID: "high", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"b"}}},
		Rule{ID: "mid", Effect: "alert", Priority: 50,
			Match: RuleMatch{Tools: []string{"c"}}},
	)

	cp := Compile(p)

	if len(cp.SortedRules) != 3 {
		t.Fatalf("SortedRules = %d, want 3", len(cp.SortedRules))
	}
	if cp.SortedRules[0].ID != "high" {
		t.Errorf("SortedRules[0] = %q, want high", cp.SortedRules[0].ID)
	}
	if cp.SortedRules[1].ID != "mid" {
		t.Errorf("SortedRules[1] = %q, want mid", cp.SortedRules[1].ID)
	}
	if cp.SortedRules[2].ID != "low" {
		t.Errorf("SortedRules[2] = %q, want low", cp.SortedRules[2].ID)
	}

	if cp.Stats.MaxPriority != 100 {
		t.Errorf("MaxPriority = %d, want 100", cp.Stats.MaxPriority)
	}
	if cp.Stats.MinPriority != 10 {
		t.Errorf("MinPriority = %d, want 10", cp.Stats.MinPriority)
	}
}

func TestCheckConflicts_NoConflicts(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "deny", Priority: 90,
			Match: RuleMatch{Tools: []string{"file_write"}}},
	)

	conflicts := CheckConflicts(p)
	if len(conflicts) != 0 {
		t.Errorf("got %d conflicts, want 0", len(conflicts))
	}
}

func TestCheckConflicts_DenyAllowSameTool(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "deny-http", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"http_request"}}},
		Rule{ID: "allow-http", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"http_request"}}},
	)

	conflicts := CheckConflicts(p)
	if len(conflicts) != 1 {
		t.Fatalf("got %d conflicts, want 1", len(conflicts))
	}
	if conflicts[0].Dimension != "tool" {
		t.Errorf("dimension = %q, want tool", conflicts[0].Dimension)
	}
	if conflicts[0].Overlap != "http_request" {
		t.Errorf("overlap = %q, want http_request", conflicts[0].Overlap)
	}
}

func TestCheckConflicts_DenyAlertSameTactic(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "deny-exfil", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tactics: []string{"exfiltration"}}},
		Rule{ID: "alert-exfil", Effect: "alert", Priority: 50,
			Match: RuleMatch{Tactics: []string{"exfiltration"}}},
	)

	conflicts := CheckConflicts(p)
	if len(conflicts) != 1 {
		t.Fatalf("got %d conflicts, want 1", len(conflicts))
	}
	if conflicts[0].Dimension != "tactic" {
		t.Errorf("dimension = %q, want tactic", conflicts[0].Dimension)
	}
}

func TestCheckConflicts_GlobOverlap(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "deny-http-glob", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"http_*"}}},
		Rule{ID: "allow-http-req", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"http_request"}}},
	)

	conflicts := CheckConflicts(p)
	if len(conflicts) != 1 {
		t.Fatalf("got %d conflicts, want 1", len(conflicts))
	}
	if conflicts[0].Dimension != "tool" {
		t.Errorf("dimension = %q, want tool", conflicts[0].Dimension)
	}
}

func TestCheckConflicts_NoOverlapDifferentDimensions(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "deny-tool", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "allow-tactic", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tactics: []string{"reconnaissance"}}},
	)

	conflicts := CheckConflicts(p)
	if len(conflicts) != 0 {
		t.Errorf("got %d conflicts, want 0 (different dimensions)", len(conflicts))
	}
}

func TestCheckConflicts_NilPolicy(t *testing.T) {
	conflicts := CheckConflicts(nil)
	if len(conflicts) != 0 {
		t.Errorf("got %d conflicts for nil, want 0", len(conflicts))
	}
}

func TestPatternsOverlap_ExactMatch(t *testing.T) {
	if !patternsOverlap("shell_exec", "shell_exec") {
		t.Error("exact match should overlap")
	}
}

func TestPatternsOverlap_WildcardMatch(t *testing.T) {
	if !patternsOverlap("http_*", "http_request") {
		t.Error("http_* should overlap with http_request")
	}
	if !patternsOverlap("*", "anything") {
		t.Error("* should overlap with anything")
	}
	if !patternsOverlap("file_*", "*_write") {
		t.Error("file_* and *_write should overlap (conservative)")
	}
}

func TestPatternsOverlap_NoOverlap(t *testing.T) {
	if patternsOverlap("shell_exec", "http_request") {
		t.Error("different names should not overlap")
	}
	if patternsOverlap("shell_*", "http_*") {
		t.Error("shell_* and http_* should not overlap (disjoint prefixes)")
	}
}

func TestMergePolicies_TwoPolicies(t *testing.T) {
	p1 := compilerTestPolicy(
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	p2 := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "policy-b"},
		Agent:      AgentScope{Name: "*"},
		Rules: []Rule{
			{ID: "r2", Effect: "allow", Priority: 10,
				Match: RuleMatch{Tools: []string{"file_read"}}},
		},
	}

	merged := MergePolicies(p1, p2)

	if merged == nil {
		t.Fatal("MergePolicies returned nil")
	}
	if len(merged.Rules) != 2 {
		t.Fatalf("merged rules = %d, want 2", len(merged.Rules))
	}
	// Should be sorted by priority.
	if merged.Rules[0].Priority != 100 {
		t.Errorf("first rule priority = %d, want 100", merged.Rules[0].Priority)
	}
}

func TestMergePolicies_IDConflictResolution(t *testing.T) {
	p1 := compilerTestPolicy(
		Rule{ID: "shared-id", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"a"}}},
	)
	p2 := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "policy-b"},
		Agent:      AgentScope{Name: "*"},
		Rules: []Rule{
			{ID: "shared-id", Effect: "allow", Priority: 10,
				Match: RuleMatch{Tools: []string{"b"}}},
		},
	}

	merged := MergePolicies(p1, p2)

	if len(merged.Rules) != 2 {
		t.Fatalf("merged rules = %d, want 2", len(merged.Rules))
	}
	// Both should be prefixed.
	for _, r := range merged.Rules {
		if r.ID == "shared-id" {
			t.Errorf("rule ID %q was not prefixed", r.ID)
		}
	}
	// Check prefixes exist.
	found := map[string]bool{}
	for _, r := range merged.Rules {
		found[r.ID] = true
	}
	if !found["test-policy:shared-id"] {
		t.Error("missing test-policy:shared-id")
	}
	if !found["policy-b:shared-id"] {
		t.Error("missing policy-b:shared-id")
	}
}

func TestMergePolicies_Single(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"a"}}},
	)
	merged := MergePolicies(p)
	if merged != p {
		t.Error("single policy should be passed through as-is")
	}
}

func TestMergePolicies_Empty(t *testing.T) {
	merged := MergePolicies()
	if merged != nil {
		t.Error("empty merge should return nil")
	}
}

func TestAnalyzeCoverage_FullCoverage(t *testing.T) {
	// Build a policy that covers all reference actions and a few tools.
	rules := []Rule{}
	for i, a := range referenceActions {
		rules = append(rules, Rule{
			ID: a, Effect: "deny", Priority: 100 - i,
			Match: RuleMatch{Actions: []string{a}},
		})
	}
	p := compilerTestPolicy(rules...)

	refTools := []string{"shell_exec"}
	// Add a tool rule so at least one tool is covered.
	p.Rules = append(p.Rules, Rule{
		ID: "t1", Effect: "deny", Priority: 50,
		Match: RuleMatch{Tools: []string{"shell_exec"}},
	})

	cr := AnalyzeCoverage(p, refTools)
	if cr.ActionsCoveragePct != 100 {
		t.Errorf("ActionsCoveragePct = %.1f, want 100", cr.ActionsCoveragePct)
	}
	if cr.ToolsCoveragePct != 100 {
		t.Errorf("ToolsCoveragePct = %.1f, want 100", cr.ToolsCoveragePct)
	}
}

func TestAnalyzeCoverage_PartialCoverage(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{
				Tools:   []string{"shell_exec"},
				Tactics: []string{"execution", "impact"},
				Actions: []string{"execute"},
			}},
	)

	refTools := []string{"shell_exec", "http_request", "file_write", "send_email"}
	cr := AnalyzeCoverage(p, refTools)

	if cr.ToolsCoveragePct != 25 {
		t.Errorf("ToolsCoveragePct = %.1f, want 25", cr.ToolsCoveragePct)
	}
	if len(cr.ToolsUncovered) != 3 {
		t.Errorf("ToolsUncovered = %d, want 3", len(cr.ToolsUncovered))
	}
	if len(cr.TacticsCovered) != 2 {
		t.Errorf("TacticsCovered = %d, want 2", len(cr.TacticsCovered))
	}
	if len(cr.Gaps) == 0 {
		t.Error("expected gaps")
	}
}

func TestAnalyzeCoverage_EmptyPolicy(t *testing.T) {
	cr := AnalyzeCoverage(nil, []string{"tool_a", "tool_b"})
	if cr.ToolsCoveragePct != 0 {
		t.Errorf("ToolsCoveragePct = %.1f, want 0", cr.ToolsCoveragePct)
	}
	if len(cr.ToolsUncovered) != 2 {
		t.Errorf("ToolsUncovered = %d, want 2", len(cr.ToolsUncovered))
	}
	// All 14 tactics should be uncovered.
	if len(cr.TacticsUncovered) != 14 {
		t.Errorf("TacticsUncovered = %d, want 14", len(cr.TacticsUncovered))
	}
}

func TestCoverageGap_RiskAssignment(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"safe_tool"}}},
	)

	refTools := []string{"safe_tool", "shell_exec", "file_read", "data_write"}
	cr := AnalyzeCoverage(p, refTools)

	riskByTool := make(map[string]string)
	for _, g := range cr.Gaps {
		if g.Dimension == "tool" {
			riskByTool[g.Value] = g.Risk
		}
	}

	if riskByTool["shell_exec"] != "high" {
		t.Errorf("shell_exec risk = %q, want high", riskByTool["shell_exec"])
	}
	if riskByTool["file_read"] != "low" {
		t.Errorf("file_read risk = %q, want low", riskByTool["file_read"])
	}
	if riskByTool["data_write"] != "high" {
		t.Errorf("data_write risk = %q, want high", riskByTool["data_write"])
	}
}

func TestFormatCompileResult(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	cp := Compile(p)
	out := FormatCompileResult(cp)

	if !strings.Contains(out, "Compilation Report") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "Total:") {
		t.Error("missing total line")
	}
	if !strings.Contains(out, "Deny:") {
		t.Error("missing deny line")
	}
	if !strings.Contains(out, "Conflicts:") {
		t.Error("missing conflicts section")
	}
}

func TestFormatCompileResult_Nil(t *testing.T) {
	out := FormatCompileResult(nil)
	if !strings.Contains(out, "No compilation result") {
		t.Error("nil should produce no-result message")
	}
}

func TestFormatCompileResult_NoConflicts(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	cp := Compile(p)
	out := FormatCompileResult(cp)

	if !strings.Contains(out, "No conflicts detected") {
		t.Error("should show no conflicts")
	}
}

func TestFormatCoverage(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{
				Tools:   []string{"shell_exec"},
				Tactics: []string{"execution"},
				Actions: []string{"execute"},
			}},
	)

	cr := AnalyzeCoverage(p, []string{"shell_exec", "http_request"})
	out := FormatCoverage(cr)

	if !strings.Contains(out, "Coverage Report") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "Tools:") {
		t.Error("missing tools line")
	}
	if !strings.Contains(out, "Tactics:") {
		t.Error("missing tactics line")
	}
	if !strings.Contains(out, "Actions:") {
		t.Error("missing actions line")
	}
	if !strings.Contains(out, "█") {
		t.Error("missing coverage bar")
	}
}

func TestFormatCoverage_Nil(t *testing.T) {
	out := FormatCoverage(nil)
	if !strings.Contains(out, "No coverage data") {
		t.Error("nil should produce no-data message")
	}
}

func TestAnalyzeCoverage_GlobToolCoverage(t *testing.T) {
	p := compilerTestPolicy(
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"http_*"}}},
	)

	refTools := []string{"http_request", "http_upload", "shell_exec"}
	cr := AnalyzeCoverage(p, refTools)

	if len(cr.ToolsCovered) != 2 {
		t.Errorf("ToolsCovered = %d, want 2 (http_request + http_upload)", len(cr.ToolsCovered))
	}
	if len(cr.ToolsUncovered) != 1 {
		t.Errorf("ToolsUncovered = %d, want 1 (shell_exec)", len(cr.ToolsUncovered))
	}
}
