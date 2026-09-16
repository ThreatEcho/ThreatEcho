// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"strings"
	"testing"
)

// riskTestPolicy builds a minimal valid policy from the given rules.
func riskTestPolicy(name string, rules ...Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: name},
		Agent:      AgentScope{Name: "*"},
		Rules:      rules,
	}
}

// ---------------------------------------------------------------------------
// Nil / empty
// ---------------------------------------------------------------------------

func TestAssessRisk_NilPolicy(t *testing.T) {
	ra := AssessRisk(nil)
	if ra == nil {
		t.Fatal("AssessRisk(nil) returned nil")
	}
	if ra.OverallScore != 1.0 {
		t.Errorf("nil policy score = %.2f, want 1.0", ra.OverallScore)
	}
	if ra.OverallGrade != "F" {
		t.Errorf("nil policy grade = %q, want F", ra.OverallGrade)
	}
	if len(ra.Findings) == 0 {
		t.Error("nil policy should produce findings")
	}
	if len(ra.Recommendations) == 0 {
		t.Error("nil policy should produce recommendations")
	}
	if len(ra.Dimensions) != 5 {
		t.Errorf("nil policy dimensions = %d, want 5", len(ra.Dimensions))
	}
	for _, d := range ra.Dimensions {
		if d.Score != 1.0 {
			t.Errorf("nil policy dimension %q score = %.2f, want 1.0", d.Name, d.Score)
		}
	}
}

func TestAssessRisk_EmptyRules(t *testing.T) {
	p := riskTestPolicy("empty")
	ra := AssessRisk(p)
	if ra.OverallScore != 1.0 {
		t.Errorf("empty policy score = %.2f, want 1.0", ra.OverallScore)
	}
	if ra.OverallGrade != "F" {
		t.Errorf("empty policy grade = %q, want F", ra.OverallGrade)
	}
	if ra.PolicyName != "empty" {
		t.Errorf("policy name = %q, want %q", ra.PolicyName, "empty")
	}
	if len(ra.Findings) == 0 {
		t.Error("empty policy should produce at least one finding")
	}
	if ra.Findings[0].Severity != "critical" {
		t.Errorf("empty policy finding severity = %q, want critical", ra.Findings[0].Severity)
	}
}

// ---------------------------------------------------------------------------
// Allow-only policy (high risk)
// ---------------------------------------------------------------------------

func TestAssessRisk_OnlyAllowRules(t *testing.T) {
	p := riskTestPolicy("allow-only",
		Rule{ID: "a1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
		Rule{ID: "a2", Effect: "allow", Priority: 20,
			Match: RuleMatch{Tools: []string{"http_request"}}},
		Rule{ID: "a3", Effect: "allow", Priority: 30,
			Match: RuleMatch{Actions: []string{"read"}}},
	)
	ra := AssessRisk(p)

	// No deny rules means high risk.
	if ra.OverallScore < 0.6 {
		t.Errorf("allow-only score = %.2f, want >= 0.6", ra.OverallScore)
	}

	// Should have a finding for missing deny rules.
	found := false
	for _, f := range ra.Findings {
		if f.Category == "missing-deny" {
			found = true
			break
		}
	}
	if !found {
		t.Error("allow-only policy should produce a missing-deny finding")
	}

	// Should have a structural finding for no deny rules.
	foundStruct := false
	for _, f := range ra.Findings {
		if f.Category == "structural" && strings.Contains(f.Title, "deny") {
			foundStruct = true
			break
		}
	}
	if !foundStruct {
		t.Error("allow-only policy should produce a structural finding about missing deny rules")
	}
}

// ---------------------------------------------------------------------------
// Good deny coverage (low risk)
// ---------------------------------------------------------------------------

func TestAssessRisk_GoodDenyCoverage(t *testing.T) {
	p := riskTestPolicy("hardened",
		// Deny rules for high-risk tools.
		Rule{ID: "d1", Effect: "deny", Priority: 100,
			Match:      RuleMatch{Tools: []string{"shell_exec"}},
			Conditions: []Condition{{Field: "elevated", Operator: "eq", Value: "true"}}},
		Rule{ID: "d2", Effect: "deny", Priority: 95,
			Match: RuleMatch{Tools: []string{"file_access"}}},
		Rule{ID: "d3", Effect: "deny", Priority: 90,
			Match: RuleMatch{Tools: []string{"process_exec"}}},
		Rule{ID: "d4", Effect: "deny", Priority: 85,
			Match: RuleMatch{Tools: []string{"service_control"}}},
		Rule{ID: "d5", Effect: "deny", Priority: 80,
			Match: RuleMatch{Tools: []string{"registry_access"}}},
		Rule{ID: "d6", Effect: "deny", Priority: 75,
			Match: RuleMatch{Tools: []string{"send_email"}}},
		Rule{ID: "d7", Effect: "deny", Priority: 70,
			Match: RuleMatch{Tools: []string{"agent_message"}}},
		Rule{ID: "d8", Effect: "deny", Priority: 65,
			Match: RuleMatch{Tactics: []string{"exfiltration"}}},
		Rule{ID: "d9", Effect: "deny", Priority: 60,
			Match: RuleMatch{Tactics: []string{"execution"}}},
		Rule{ID: "d10", Effect: "deny", Priority: 55,
			Match: RuleMatch{Actions: []string{"execute"}}},
		// Allow rules for safe tools.
		Rule{ID: "a1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
		Rule{ID: "a2", Effect: "allow", Priority: 5,
			Match: RuleMatch{Actions: []string{"read", "query"}}},
	)
	ra := AssessRisk(p)

	// Well-structured policy with strong deny coverage.
	if ra.OverallScore > 0.5 {
		t.Errorf("hardened policy score = %.2f, want <= 0.5", ra.OverallScore)
	}
	if ra.OverallGrade == "F" || ra.OverallGrade == "D" {
		t.Errorf("hardened policy grade = %q, want A/B/C", ra.OverallGrade)
	}
}

// ---------------------------------------------------------------------------
// Grade boundaries
// ---------------------------------------------------------------------------

func TestScoreToGrade_Boundaries(t *testing.T) {
	tests := []struct {
		score float64
		grade string
	}{
		{0.0, "A"},
		{0.1, "A"},
		{0.19, "A"},
		{0.2, "B"},
		{0.3, "B"},
		{0.39, "B"},
		{0.4, "C"},
		{0.5, "C"},
		{0.59, "C"},
		{0.6, "D"},
		{0.7, "D"},
		{0.79, "D"},
		{0.8, "F"},
		{0.9, "F"},
		{1.0, "F"},
	}
	for _, tt := range tests {
		got := scoreToGrade(tt.score)
		if got != tt.grade {
			t.Errorf("scoreToGrade(%.2f) = %q, want %q", tt.score, got, tt.grade)
		}
	}
}

func TestAssessRisk_GradeA(t *testing.T) {
	// A comprehensive policy covering many tools, tactics, actions with
	// high deny ratio, conditions, and distinct priorities.
	p := riskTestPolicy("grade-a",
		Rule{ID: "d1", Effect: "deny", Priority: 100,
			Match:      RuleMatch{Tools: []string{"shell_exec"}},
			Conditions: []Condition{{Field: "elevated", Operator: "eq", Value: "true"}}},
		Rule{ID: "d2", Effect: "deny", Priority: 95,
			Match: RuleMatch{Tools: []string{"file_access", "process_exec", "service_control", "registry_access"}}},
		Rule{ID: "d3", Effect: "deny", Priority: 90,
			Match: RuleMatch{Tools: []string{"send_email", "write_knowledge_base", "agent_message"}}},
		Rule{ID: "d4", Effect: "deny", Priority: 85,
			Match: RuleMatch{Tools: []string{"http_request"},
				Targets: []string{"*.evil.com"}}},
		Rule{ID: "d5", Effect: "deny", Priority: 80,
			Match: RuleMatch{Tactics: []string{"exfiltration", "execution", "initial-access",
				"credential-access", "lateral-movement", "privilege-escalation", "impact"}}},
		Rule{ID: "d6", Effect: "deny", Priority: 75,
			Match: RuleMatch{Actions: []string{"execute", "delete", "send", "write"}}},
		Rule{ID: "d7", Effect: "deny", Priority: 70,
			Match: RuleMatch{Tools: []string{"dns_query", "tool_call"}}},
		Rule{ID: "a1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"search_knowledge_base"},
				Actions: []string{"read", "query"}},
			Conditions: []Condition{{Field: "elevated", Operator: "eq", Value: "false"}}},
		Rule{ID: "a2", Effect: "allow", Priority: 5,
			Match: RuleMatch{Tactics: []string{"reconnaissance", "discovery", "collection",
				"resource-development", "persistence", "defense-evasion", "command-and-control"},
				Actions: []string{"create", "modify"}}},
	)
	ra := AssessRisk(p)

	if ra.OverallGrade != "A" {
		t.Errorf("comprehensive policy grade = %q (score %.3f), want A", ra.OverallGrade, ra.OverallScore)
	}
}

func TestAssessRisk_GradeF(t *testing.T) {
	// A single allow rule with no ID and no conditions.
	p := riskTestPolicy("terrible",
		Rule{Effect: "allow", Match: RuleMatch{Tools: []string{"http_request"}}},
	)
	ra := AssessRisk(p)

	// A single allow rule with no ID scores poorly — expect at least D or F.
	if ra.OverallGrade != "D" && ra.OverallGrade != "F" {
		t.Errorf("terrible policy grade = %q (score %.3f), want D or F", ra.OverallGrade, ra.OverallScore)
	}
}

// ---------------------------------------------------------------------------
// Findings generation
// ---------------------------------------------------------------------------

func TestAssessRisk_FindingsForConflict(t *testing.T) {
	p := riskTestPolicy("conflict",
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 50,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	ra := AssessRisk(p)

	found := false
	for _, f := range ra.Findings {
		if f.Category == "conflict" {
			found = true
			break
		}
	}
	if !found {
		t.Error("conflicting rules should produce a conflict finding")
	}
}

func TestAssessRisk_FindingsForMissingIDs(t *testing.T) {
	p := riskTestPolicy("no-ids",
		Rule{Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"file_read"}}},
	)
	ra := AssessRisk(p)

	found := false
	for _, f := range ra.Findings {
		if f.Category == "structural" && strings.Contains(f.Title, "missing IDs") {
			found = true
			break
		}
	}
	if !found {
		t.Error("rules without IDs should produce a structural finding")
	}
}

func TestAssessRisk_FindingsForSamePriority(t *testing.T) {
	p := riskTestPolicy("same-prio",
		Rule{ID: "r1", Effect: "deny", Priority: 50,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 50,
			Match: RuleMatch{Tools: []string{"file_read"}}},
	)
	ra := AssessRisk(p)

	found := false
	for _, f := range ra.Findings {
		if f.Category == "structural" && strings.Contains(f.Title, "same priority") {
			found = true
			break
		}
	}
	if !found {
		t.Error("rules with same priority should produce a structural finding")
	}
}

func TestAssessRisk_FindingsForNoConditions(t *testing.T) {
	p := riskTestPolicy("no-cond",
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"file_read"}}},
	)
	ra := AssessRisk(p)

	found := false
	for _, f := range ra.Findings {
		if f.Category == "structural" && strings.Contains(f.Title, "conditions") {
			found = true
			break
		}
	}
	if !found {
		t.Error("rules without conditions should produce a structural finding")
	}
}

func TestAssessRisk_FindingsForElevatedAllow(t *testing.T) {
	p := riskTestPolicy("elevated-allow",
		Rule{ID: "r1", Effect: "allow", Priority: 100,
			Match:      RuleMatch{Tools: []string{"shell_exec"}},
			Conditions: []Condition{{Field: "elevated", Operator: "eq", Value: "true"}}},
		Rule{ID: "r2", Effect: "deny", Priority: 50,
			Match: RuleMatch{Tools: []string{"file_access"}}},
	)
	ra := AssessRisk(p)

	found := false
	for _, f := range ra.Findings {
		if f.Category == "excessive-allow" {
			found = true
			break
		}
	}
	if !found {
		t.Error("allow rule with elevated=true should produce an excessive-allow finding")
	}
}

func TestAssessRisk_FindingsSorted(t *testing.T) {
	p := riskTestPolicy("sorted-findings",
		Rule{ID: "r1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"http_request"}}},
	)
	ra := AssessRisk(p)

	if len(ra.Findings) < 2 {
		t.Skip("not enough findings to check sort order")
	}

	for i := 1; i < len(ra.Findings); i++ {
		prev := severityRank[ra.Findings[i-1].Severity]
		curr := severityRank[ra.Findings[i].Severity]
		if prev > curr {
			t.Errorf("findings not sorted by severity: %q (rank %d) before %q (rank %d)",
				ra.Findings[i-1].Severity, prev, ra.Findings[i].Severity, curr)
		}
	}
}

func TestAssessRisk_CoverageGapFinding(t *testing.T) {
	p := riskTestPolicy("gaps",
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"http_request"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
	)
	ra := AssessRisk(p)

	found := false
	for _, f := range ra.Findings {
		if f.Category == "coverage-gap" {
			found = true
			break
		}
	}
	if !found {
		t.Error("policy with gaps should produce coverage-gap findings")
	}
}

// ---------------------------------------------------------------------------
// Recommendations
// ---------------------------------------------------------------------------

func TestAssessRisk_RecommendationsGenerated(t *testing.T) {
	p := riskTestPolicy("sparse",
		Rule{ID: "r1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"http_request"}}},
	)
	ra := AssessRisk(p)

	if len(ra.Recommendations) == 0 {
		t.Error("sparse policy should produce recommendations")
	}
}

func TestAssessRisk_RecommendationNoDuplicates(t *testing.T) {
	p := riskTestPolicy("dedup",
		Rule{ID: "r1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"http_request"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 20,
			Match: RuleMatch{Tools: []string{"dns_query"}}},
	)
	ra := AssessRisk(p)

	seen := make(map[string]bool)
	for _, r := range ra.Recommendations {
		if seen[r] {
			t.Errorf("duplicate recommendation: %q", r)
		}
		seen[r] = true
	}
}

// ---------------------------------------------------------------------------
// AssessRiskWithCoverage
// ---------------------------------------------------------------------------

func TestAssessRiskWithCoverage_CustomTools(t *testing.T) {
	refTools := []string{"tool_a", "tool_b", "tool_c"}
	p := riskTestPolicy("custom",
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"tool_a", "tool_b", "tool_c"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"tool_a"}}},
	)
	ra := AssessRiskWithCoverage(p, refTools)

	// All custom tools are covered.
	var coverageDim *RiskDimension
	for i := range ra.Dimensions {
		if ra.Dimensions[i].Name == "Coverage" {
			coverageDim = &ra.Dimensions[i]
			break
		}
	}
	if coverageDim == nil {
		t.Fatal("Coverage dimension not found")
	}
	// Tools fully covered, but tactics/actions won't be.
	// Tool coverage is 100%, so overall coverage dimension should be improved
	// vs using default tools with only partial coverage.
	if coverageDim.Score > 0.9 {
		t.Errorf("full tool coverage should lower coverage score, got %.2f", coverageDim.Score)
	}
}

func TestAssessRiskWithCoverage_AllToolsCovered(t *testing.T) {
	refTools := []string{"shell_exec"}
	p := riskTestPolicy("covered",
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	ra := AssessRiskWithCoverage(p, refTools)

	// Tools fully covered — check the assessment succeeded.
	if ra == nil {
		t.Fatal("assessment returned nil")
	}
	if ra.OverallScore < 0 || ra.OverallScore > 1 {
		t.Errorf("score out of range: %.2f", ra.OverallScore)
	}
}

// ---------------------------------------------------------------------------
// Single rule edge case
// ---------------------------------------------------------------------------

func TestAssessRisk_SingleDenyRule(t *testing.T) {
	p := riskTestPolicy("single-deny",
		Rule{ID: "d1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	ra := AssessRisk(p)

	if ra.OverallScore < 0.3 {
		t.Errorf("single deny rule should still have moderate risk, got %.2f", ra.OverallScore)
	}
	// Should flag missing allow rules.
	foundAllow := false
	for _, f := range ra.Findings {
		if f.Category == "structural" && strings.Contains(f.Title, "allow") {
			foundAllow = true
			break
		}
	}
	if !foundAllow {
		t.Error("single deny policy should flag missing allow rules")
	}
}

func TestAssessRisk_SingleAllowRule(t *testing.T) {
	p := riskTestPolicy("single-allow",
		Rule{ID: "a1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
	)
	ra := AssessRisk(p)

	// Single allow rule is risky — score should be elevated.
	if ra.OverallScore < 0.5 {
		t.Errorf("single allow rule should be risky, got %.2f", ra.OverallScore)
	}
}

// ---------------------------------------------------------------------------
// Dimension weights
// ---------------------------------------------------------------------------

func TestAssessRisk_DimensionWeights(t *testing.T) {
	p := riskTestPolicy("weights",
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"http_request"}}},
	)
	ra := AssessRisk(p)

	expectedWeights := map[string]float64{
		"Coverage":           0.3,
		"Conflict Density":   0.2,
		"Deny Coverage":      0.2,
		"Structural Quality": 0.15,
		"Elevated Access":    0.15,
	}
	if len(ra.Dimensions) != 5 {
		t.Fatalf("got %d dimensions, want 5", len(ra.Dimensions))
	}
	totalWeight := 0.0
	for _, d := range ra.Dimensions {
		want, ok := expectedWeights[d.Name]
		if !ok {
			t.Errorf("unexpected dimension %q", d.Name)
			continue
		}
		if d.Weight != want {
			t.Errorf("dimension %q weight = %.2f, want %.2f", d.Name, d.Weight, want)
		}
		totalWeight += d.Weight
	}
	if totalWeight < 0.99 || totalWeight > 1.01 {
		t.Errorf("total weight = %.2f, want 1.0", totalWeight)
	}
}

func TestAssessRisk_DimensionScoresInRange(t *testing.T) {
	policies := []*Policy{
		nil,
		riskTestPolicy("empty"),
		riskTestPolicy("one-rule",
			Rule{ID: "r1", Effect: "deny", Priority: 100,
				Match: RuleMatch{Tools: []string{"shell_exec"}}}),
	}
	for _, p := range policies {
		name := "(nil)"
		if p != nil {
			name = p.Meta.Name
		}
		ra := AssessRisk(p)
		for _, d := range ra.Dimensions {
			if d.Score < 0 || d.Score > 1 {
				t.Errorf("policy %q dim %q score %.2f out of [0,1]", name, d.Name, d.Score)
			}
		}
		if ra.OverallScore < 0 || ra.OverallScore > 1 {
			t.Errorf("policy %q overall score %.2f out of [0,1]", name, ra.OverallScore)
		}
	}
}

// ---------------------------------------------------------------------------
// Deny rule for shell_exec
// ---------------------------------------------------------------------------

func TestAssessRisk_ShellExecDenied(t *testing.T) {
	withDeny := riskTestPolicy("with-deny",
		Rule{ID: "d1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "a1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
	)
	withoutDeny := riskTestPolicy("without-deny",
		Rule{ID: "a1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
	)

	raWith := AssessRisk(withDeny)
	raWithout := AssessRisk(withoutDeny)

	if raWith.OverallScore >= raWithout.OverallScore {
		t.Errorf("policy with shell_exec deny (%.2f) should score better than without (%.2f)",
			raWith.OverallScore, raWithout.OverallScore)
	}
}

func TestAssessRisk_WildcardDenyCoversHighRisk(t *testing.T) {
	p := riskTestPolicy("wildcard-deny",
		Rule{ID: "d1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"*"}}},
		Rule{ID: "a1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
	)
	ra := AssessRisk(p)

	// Wildcard deny should cover all high-risk tools.
	for _, f := range ra.Findings {
		if f.Category == "missing-deny" && strings.Contains(f.Title, "No deny rule for") {
			t.Errorf("wildcard deny should cover all tools, but got finding: %s", f.Title)
		}
	}
}

// ---------------------------------------------------------------------------
// Format
// ---------------------------------------------------------------------------

func TestFormatRiskAssessment_Nil(t *testing.T) {
	out := FormatRiskAssessment(nil)
	if out != "No risk assessment.\n" {
		t.Errorf("FormatRiskAssessment(nil) = %q", out)
	}
}

func TestFormatRiskAssessment_ContainsGrade(t *testing.T) {
	ra := AssessRisk(nil)
	out := FormatRiskAssessment(ra)
	if !strings.Contains(out, "Grade:") {
		t.Error("formatted output should contain Grade")
	}
	if !strings.Contains(out, "F") {
		t.Error("formatted output should contain grade F for nil policy")
	}
}

func TestFormatRiskAssessment_ContainsScore(t *testing.T) {
	ra := AssessRisk(nil)
	out := FormatRiskAssessment(ra)
	if !strings.Contains(out, "Score:") {
		t.Error("formatted output should contain Score")
	}
	if !strings.Contains(out, "1.00") {
		t.Error("formatted output should show 1.00 score for nil policy")
	}
}

func TestFormatRiskAssessment_ContainsDimensions(t *testing.T) {
	p := riskTestPolicy("dims",
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	ra := AssessRisk(p)
	out := FormatRiskAssessment(ra)

	dims := []string{"Coverage", "Conflict Density", "Deny Coverage",
		"Structural Quality", "Elevated Access"}
	for _, d := range dims {
		if !strings.Contains(out, d) {
			t.Errorf("formatted output should contain dimension %q", d)
		}
	}
}

func TestFormatRiskAssessment_ContainsFindings(t *testing.T) {
	p := riskTestPolicy("findings",
		Rule{ID: "r1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"http_request"}}},
	)
	ra := AssessRisk(p)
	out := FormatRiskAssessment(ra)

	if !strings.Contains(out, "Findings") {
		t.Error("formatted output should contain Findings section")
	}
}

func TestFormatRiskAssessment_ContainsRecommendations(t *testing.T) {
	p := riskTestPolicy("recs",
		Rule{ID: "r1", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"http_request"}}},
	)
	ra := AssessRisk(p)
	out := FormatRiskAssessment(ra)

	if !strings.Contains(out, "Recommendations") {
		t.Error("formatted output should contain Recommendations section")
	}
}

func TestFormatRiskAssessment_BoxDrawing(t *testing.T) {
	p := riskTestPolicy("box",
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "allow", Priority: 10,
			Match: RuleMatch{Tools: []string{"http_request"}}},
	)
	ra := AssessRisk(p)
	out := FormatRiskAssessment(ra)

	for _, ch := range []string{"─", "│", "┌", "┐", "└", "┘", "├", "┤"} {
		if !strings.Contains(out, ch) {
			t.Errorf("formatted output should contain box-drawing character %q", ch)
		}
	}
}

func TestFormatRiskAssessment_BarCharts(t *testing.T) {
	p := riskTestPolicy("bars",
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	ra := AssessRisk(p)
	out := FormatRiskAssessment(ra)

	if !strings.Contains(out, "█") && !strings.Contains(out, "░") {
		t.Error("formatted output should contain bar chart characters")
	}
}

func TestFormatRiskAssessment_PolicyName(t *testing.T) {
	p := riskTestPolicy("my-test-policy",
		Rule{ID: "r1", Effect: "deny", Priority: 100,
			Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	ra := AssessRisk(p)
	out := FormatRiskAssessment(ra)

	if !strings.Contains(out, "my-test-policy") {
		t.Error("formatted output should contain the policy name")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestRiskBar(t *testing.T) {
	tests := []struct {
		score    float64
		wantLen  int // rune count of the bar including brackets
		hasFill  bool
		hasEmpty bool
	}{
		{0.0, 22, false, true},
		{0.5, 22, true, true},
		{1.0, 22, true, false},
	}
	for _, tt := range tests {
		bar := riskBar(tt.score)
		runes := []rune(bar)
		if len(runes) != tt.wantLen {
			t.Errorf("riskBar(%.1f) rune count = %d, want %d", tt.score, len(runes), tt.wantLen)
		}
		if tt.hasFill && !strings.Contains(bar, "█") {
			t.Errorf("riskBar(%.1f) should contain filled chars", tt.score)
		}
		if tt.hasEmpty && !strings.Contains(bar, "░") {
			t.Errorf("riskBar(%.1f) should contain empty chars", tt.score)
		}
	}
}

func TestClamp01(t *testing.T) {
	tests := []struct {
		in, want float64
	}{
		{-0.5, 0.0},
		{0.0, 0.0},
		{0.5, 0.5},
		{1.0, 1.0},
		{1.5, 1.0},
	}
	for _, tt := range tests {
		got := clamp01(tt.in)
		if got != tt.want {
			t.Errorf("clamp01(%.1f) = %.1f, want %.1f", tt.in, got, tt.want)
		}
	}
}

func TestDedupStrings(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "d"}
	got := dedupStrings(input)
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("dedupStrings length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dedupStrings[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
