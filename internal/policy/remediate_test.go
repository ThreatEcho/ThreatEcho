// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers — prefixed "remTest" to avoid collision with lintTestPolicy
// and testPolicy declared in other test files.
// ---------------------------------------------------------------------------

func remTestPolicy(name string, rules ...Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta: PolicyMeta{
			Name:        name,
			Description: "test policy for remediation",
			Authors:     []string{"tester"},
			Created:     "2025-01-01",
			Modified:    "2025-06-01",
		},
		Agent: AgentScope{Name: "test-agent"},
		Rules: rules,
	}
}

func remTestRule(id, effect string, tools []string) Rule {
	return Rule{
		ID:          id,
		Description: "test rule " + id,
		Effect:      effect,
		Priority:    10,
		Match:       RuleMatch{Tools: tools},
	}
}

func remTestRuleWithTactics(id, effect string, tactics []string) Rule {
	return Rule{
		ID:          id,
		Description: "test rule " + id,
		Effect:      effect,
		Priority:    10,
		Match:       RuleMatch{Tactics: tactics},
	}
}

func remFindAction(plan *RemediationPlan, source string) *RemediationAction {
	if plan == nil {
		return nil
	}
	for i, a := range plan.Actions {
		if a.Source == source {
			return &plan.Actions[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// RemediateFromLint tests
// ---------------------------------------------------------------------------

func TestRemediateFromLint_Nil(t *testing.T) {
	plan := RemediateFromLint(nil, nil)
	if plan.TotalActions != 0 {
		t.Errorf("expected 0 actions, got %d", plan.TotalActions)
	}
	if plan.EstimatedEffort != "minimal" {
		t.Errorf("expected minimal effort, got %q", plan.EstimatedEffort)
	}
}

func TestRemediateFromLint_EmptyReport(t *testing.T) {
	p := remTestPolicy("empty")
	plan := RemediateFromLint(p, &LintReport{})
	if plan.TotalActions != 0 {
		t.Errorf("expected 0 actions, got %d", plan.TotalActions)
	}
	if plan.PolicyName != "empty" {
		t.Errorf("expected policy name %q, got %q", "empty", plan.PolicyName)
	}
}

func TestRemediateFromLint_SEC001(t *testing.T) {
	p := remTestPolicy("sec-test")
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "SEC-001", Severity: LintError, Category: LintCatSecurity, Message: "no deny rules"},
		},
	}
	plan := RemediateFromLint(p, report)
	if plan.TotalActions != 1 {
		t.Fatalf("expected 1 action, got %d", plan.TotalActions)
	}
	a := plan.Actions[0]
	if a.Type != RemAddRule {
		t.Errorf("expected add_rule, got %s", a.Type)
	}
	if a.Priority != RemPriorityCritical {
		t.Errorf("expected critical, got %s", a.Priority)
	}
	if a.Source != "lint:SEC-001" {
		t.Errorf("expected source lint:SEC-001, got %s", a.Source)
	}
	if !a.AutoApplicable {
		t.Error("expected auto-applicable")
	}
	if !strings.Contains(a.RuleAfter, "default-deny") {
		t.Error("expected default-deny rule in RuleAfter")
	}
}

func TestRemediateFromLint_SEC002(t *testing.T) {
	p := remTestPolicy("sec-test", remTestRule("r1", "allow", []string{"*"}))
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "SEC-002", Severity: LintError, Category: LintCatSecurity, RuleID: "r1"},
		},
	}
	plan := RemediateFromLint(p, report)
	a := remFindAction(plan, "lint:SEC-002")
	if a == nil {
		t.Fatal("expected action for SEC-002")
	}
	if a.Type != RemModifyRule {
		t.Errorf("expected modify_rule, got %s", a.Type)
	}
	if a.AutoApplicable {
		t.Error("SEC-002 should not be auto-applicable")
	}
}

func TestRemediateFromLint_SEC003(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "SEC-003", Severity: LintWarning, RuleID: "r2"},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:SEC-003")
	if a == nil {
		t.Fatal("expected action for SEC-003")
	}
	if a.Priority != RemPriorityHigh {
		t.Errorf("expected high priority, got %s", a.Priority)
	}
}

func TestRemediateFromLint_SEC004(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "SEC-004", Severity: LintWarning, RuleID: "r3"},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:SEC-004")
	if a == nil {
		t.Fatal("expected action for SEC-004")
	}
	if a.Type != RemModifyRule {
		t.Errorf("expected modify_rule, got %s", a.Type)
	}
}

func TestRemediateFromLint_SEC005(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "SEC-005", Severity: LintWarning},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:SEC-005")
	if a == nil {
		t.Fatal("expected action for SEC-005")
	}
	if a.Type != RemAddRule {
		t.Errorf("expected add_rule, got %s", a.Type)
	}
}

func TestRemediateFromLint_COV001(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "COV-001", Severity: LintWarning},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:COV-001")
	if a == nil {
		t.Fatal("expected action for COV-001")
	}
	if a.Type != RemAddRule {
		t.Errorf("expected add_rule, got %s", a.Type)
	}
	if a.Priority != RemPriorityMedium {
		t.Errorf("expected medium priority, got %s", a.Priority)
	}
}

func TestRemediateFromLint_COV002(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "COV-002", Severity: LintWarning},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:COV-002")
	if a == nil {
		t.Fatal("expected action for COV-002")
	}
	if !strings.Contains(a.RuleAfter, "tactics:") {
		t.Error("expected tactics in RuleAfter")
	}
}

func TestRemediateFromLint_COV003(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "COV-003", Severity: LintInfo},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:COV-003")
	if a == nil {
		t.Fatal("expected action for COV-003")
	}
	if a.Priority != RemPriorityLow {
		t.Errorf("expected low priority, got %s", a.Priority)
	}
}

func TestRemediateFromLint_COV004(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "COV-004", Severity: LintInfo},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:COV-004")
	if a == nil {
		t.Fatal("expected action for COV-004")
	}
}

func TestRemediateFromLint_RED001(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "RED-001", Severity: LintWarning, RuleID: "dup-rule"},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:RED-001")
	if a == nil {
		t.Fatal("expected action for RED-001")
	}
	if a.Type != RemRemoveRule {
		t.Errorf("expected remove_rule, got %s", a.Type)
	}
}

func TestRemediateFromLint_RED002(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "RED-002", Severity: LintWarning, RuleID: "shadowed"},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:RED-002")
	if a == nil {
		t.Fatal("expected action for RED-002")
	}
	if a.Type != RemRemoveRule {
		t.Errorf("expected remove_rule, got %s", a.Type)
	}
}

func TestRemediateFromLint_RED003(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "RED-003", Severity: LintInfo, RuleID: "unreachable"},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:RED-003")
	if a == nil {
		t.Fatal("expected action for RED-003")
	}
}

func TestRemediateFromLint_NAM001(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "NAM-001", Severity: LintStyle, RuleID: "dup-name"},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:NAM-001")
	if a == nil {
		t.Fatal("expected action for NAM-001")
	}
	if a.Type != RemModifyRule {
		t.Errorf("expected modify_rule, got %s", a.Type)
	}
}

func TestRemediateFromLint_NAM002(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "NAM-002", Severity: LintStyle, RuleID: "r1", Message: "short id"},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:NAM-002")
	if a == nil {
		t.Fatal("expected action for NAM-002")
	}
}

func TestRemediateFromLint_CPX001(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "CPX-001", Severity: LintWarning},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:CPX-001")
	if a == nil {
		t.Fatal("expected action for CPX-001")
	}
	if a.Type != RemRestructure {
		t.Errorf("expected restructure, got %s", a.Type)
	}
}

func TestRemediateFromLint_CPX002(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "CPX-002", Severity: LintInfo, RuleID: "r1", Message: "many conditions"},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:CPX-002")
	if a == nil {
		t.Fatal("expected action for CPX-002")
	}
}

func TestRemediateFromLint_BP001(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "BP-001", Severity: LintStyle},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:BP-001")
	if a == nil {
		t.Fatal("expected action for BP-001")
	}
	if a.Type != RemAddMetadata {
		t.Errorf("expected add_metadata, got %s", a.Type)
	}
	if !a.AutoApplicable {
		t.Error("expected auto-applicable")
	}
}

func TestRemediateFromLint_BP002(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "BP-002", Severity: LintStyle},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:BP-002")
	if a == nil {
		t.Fatal("expected action for BP-002")
	}
}

func TestRemediateFromLint_BP003(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "BP-003", Severity: LintStyle, RuleID: "no-desc"},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:BP-003")
	if a == nil {
		t.Fatal("expected action for BP-003")
	}
}

func TestRemediateFromLint_BP005(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "BP-005", Severity: LintStyle},
		},
	}
	plan := RemediateFromLint(nil, report)
	a := remFindAction(plan, "lint:BP-005")
	if a == nil {
		t.Fatal("expected action for BP-005")
	}
	if a.Type != RemAddMetadata {
		t.Errorf("expected add_metadata, got %s", a.Type)
	}
}

func TestRemediateFromLint_MultipleFindings(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "SEC-001", Severity: LintError},
			{Rule: "COV-001", Severity: LintWarning},
			{Rule: "BP-001", Severity: LintStyle},
		},
	}
	plan := RemediateFromLint(nil, report)
	if plan.TotalActions != 3 {
		t.Fatalf("expected 3 actions, got %d", plan.TotalActions)
	}
	if plan.CriticalCount != 1 {
		t.Errorf("expected 1 critical, got %d", plan.CriticalCount)
	}
	// Check priority ordering: critical first.
	if plan.Actions[0].Priority != RemPriorityCritical {
		t.Errorf("expected first action to be critical, got %s", plan.Actions[0].Priority)
	}
}

func TestRemediateFromLint_UnknownRule(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "UNKNOWN-999", Severity: LintInfo},
		},
	}
	plan := RemediateFromLint(nil, report)
	if plan.TotalActions != 0 {
		t.Errorf("expected 0 actions for unknown rule, got %d", plan.TotalActions)
	}
}

// ---------------------------------------------------------------------------
// RemediateFromDrift tests
// ---------------------------------------------------------------------------

func TestRemediateFromDrift_Nil(t *testing.T) {
	plan := RemediateFromDrift(nil, nil)
	if plan.TotalActions != 0 {
		t.Errorf("expected 0 actions, got %d", plan.TotalActions)
	}
}

func TestRemediateFromDrift_EmptyReport(t *testing.T) {
	plan := RemediateFromDrift(nil, &DriftReport{})
	if plan.TotalActions != 0 {
		t.Errorf("expected 0 actions, got %d", plan.TotalActions)
	}
}

func TestRemediateFromDrift_EffectChanged(t *testing.T) {
	report := &DriftReport{
		Findings: []DriftFinding{
			{
				Type:     DriftEffectChanged,
				Severity: DriftCritical,
				RuleID:   "r1",
				Before:   "effect: deny",
				After:    "effect: allow",
				Impact:   "security posture weakened",
			},
		},
	}
	plan := RemediateFromDrift(nil, report)
	if plan.TotalActions != 1 {
		t.Fatalf("expected 1 action, got %d", plan.TotalActions)
	}
	a := plan.Actions[0]
	if a.Type != RemModifyRule {
		t.Errorf("expected modify_rule, got %s", a.Type)
	}
	if a.Priority != RemPriorityCritical {
		t.Errorf("expected critical, got %s", a.Priority)
	}
	if a.RuleAfter != "effect: deny" {
		t.Errorf("expected restore to deny, got %q", a.RuleAfter)
	}
}

func TestRemediateFromDrift_RuleRemoved(t *testing.T) {
	report := &DriftReport{
		Findings: []DriftFinding{
			{
				Type:        DriftRuleRemoved,
				Severity:    DriftHigh,
				RuleID:      "removed-rule",
				Before:      "id: removed-rule\neffect: deny",
				Description: "rule removed from policy",
				Impact:      "coverage gap",
			},
		},
	}
	plan := RemediateFromDrift(nil, report)
	a := plan.Actions[0]
	if a.Type != RemAddRule {
		t.Errorf("expected add_rule, got %s", a.Type)
	}
	if a.Priority != RemPriorityHigh {
		t.Errorf("expected high, got %s", a.Priority)
	}
}

func TestRemediateFromDrift_RuleAdded(t *testing.T) {
	report := &DriftReport{
		Findings: []DriftFinding{
			{Type: DriftRuleAdded, Severity: DriftMedium, RuleID: "new-rule", After: "new rule content"},
		},
	}
	plan := RemediateFromDrift(nil, report)
	a := plan.Actions[0]
	if a.Type != RemRemoveRule {
		t.Errorf("expected remove_rule for added drift, got %s", a.Type)
	}
}

func TestRemediateFromDrift_ScopeWidened(t *testing.T) {
	report := &DriftReport{
		Findings: []DriftFinding{
			{Type: DriftScopeWidened, Severity: DriftHigh, RuleID: "r1", Before: "tools: [http]", After: "tools: [*]"},
		},
	}
	plan := RemediateFromDrift(nil, report)
	a := plan.Actions[0]
	if a.Type != RemModifyRule {
		t.Errorf("expected modify_rule, got %s", a.Type)
	}
	if a.RuleAfter != "tools: [http]" {
		t.Errorf("expected restore to narrower scope")
	}
}

func TestRemediateFromDrift_ScopeNarrowed(t *testing.T) {
	report := &DriftReport{
		Findings: []DriftFinding{
			{Type: DriftScopeNarrowed, Severity: DriftLow, RuleID: "r1", Before: "tools: [*]", After: "tools: [http]"},
		},
	}
	plan := RemediateFromDrift(nil, report)
	a := plan.Actions[0]
	if a.Priority != RemPriorityLow {
		t.Errorf("expected low priority, got %s", a.Priority)
	}
}

func TestRemediateFromDrift_PriorityShift(t *testing.T) {
	report := &DriftReport{
		Findings: []DriftFinding{
			{Type: DriftPriorityShift, Severity: DriftMedium, RuleID: "r1", Before: "priority: 100", After: "priority: 1"},
		},
	}
	plan := RemediateFromDrift(nil, report)
	if plan.TotalActions != 1 {
		t.Fatalf("expected 1 action, got %d", plan.TotalActions)
	}
}

func TestRemediateFromDrift_ConditionChanged(t *testing.T) {
	report := &DriftReport{
		Findings: []DriftFinding{
			{Type: DriftConditionChanged, Severity: DriftMedium, RuleID: "r1", Before: "conditions: [...]", After: "conditions: []"},
		},
	}
	plan := RemediateFromDrift(nil, report)
	if plan.TotalActions != 1 {
		t.Fatalf("expected 1 action, got %d", plan.TotalActions)
	}
}

func TestRemediateFromDrift_MetaChanged(t *testing.T) {
	report := &DriftReport{
		Findings: []DriftFinding{
			{Type: DriftMetaChanged, Severity: DriftInfo, Description: "name changed"},
		},
	}
	plan := RemediateFromDrift(nil, report)
	a := plan.Actions[0]
	if a.Type != RemAddMetadata {
		t.Errorf("expected add_metadata, got %s", a.Type)
	}
	if a.Priority != RemPriorityLow {
		t.Errorf("expected low for meta drift, got %s", a.Priority)
	}
}

func TestRemediateFromDrift_MultipleDrifts(t *testing.T) {
	report := &DriftReport{
		Findings: []DriftFinding{
			{Type: DriftEffectChanged, Severity: DriftCritical, RuleID: "r1"},
			{Type: DriftRuleRemoved, Severity: DriftHigh, RuleID: "r2"},
			{Type: DriftMetaChanged, Severity: DriftInfo},
		},
	}
	plan := RemediateFromDrift(nil, report)
	if plan.TotalActions != 3 {
		t.Fatalf("expected 3 actions, got %d", plan.TotalActions)
	}
	if plan.CriticalCount != 1 {
		t.Errorf("expected 1 critical, got %d", plan.CriticalCount)
	}
	if plan.HighCount != 1 {
		t.Errorf("expected 1 high, got %d", plan.HighCount)
	}
}

// ---------------------------------------------------------------------------
// RemediateFromCoverage tests
// ---------------------------------------------------------------------------

func TestRemediateFromCoverage_Nil(t *testing.T) {
	plan := RemediateFromCoverage(nil, nil)
	if plan.TotalActions != 0 {
		t.Errorf("expected 0 actions, got %d", plan.TotalActions)
	}
}

func TestRemediateFromCoverage_NoGaps(t *testing.T) {
	report := &CoverageMapReport{Gaps: nil}
	plan := RemediateFromCoverage(nil, report)
	if plan.TotalActions != 0 {
		t.Errorf("expected 0 actions, got %d", plan.TotalActions)
	}
}

func TestRemediateFromCoverage_SingleGap(t *testing.T) {
	p := remTestPolicy("cov-test")
	report := &CoverageMapReport{
		Gaps: []TechniqueGap{
			{
				TechniqueID:     "T1059",
				TechniqueName:   "Command and Scripting Interpreter",
				Tactic:          "execution",
				Severity:        "high",
				Recommendations: []string{"Add a deny rule for shell execution"},
			},
		},
	}
	plan := RemediateFromCoverage(p, report)
	if plan.TotalActions != 1 {
		t.Fatalf("expected 1 action, got %d", plan.TotalActions)
	}
	a := plan.Actions[0]
	if a.Type != RemAddRule {
		t.Errorf("expected add_rule, got %s", a.Type)
	}
	if a.Source != "coverage:T1059" {
		t.Errorf("expected source coverage:T1059, got %s", a.Source)
	}
	if a.Priority != RemPriorityHigh {
		t.Errorf("expected high priority, got %s", a.Priority)
	}
	if !strings.Contains(a.RuleAfter, "cover-t1059") {
		t.Error("expected generated rule ID in RuleAfter")
	}
	if !a.AutoApplicable {
		t.Error("expected auto-applicable")
	}
}

func TestRemediateFromCoverage_MultipleGaps(t *testing.T) {
	report := &CoverageMapReport{
		Gaps: []TechniqueGap{
			{TechniqueID: "T1059", TechniqueName: "Command Execution", Tactic: "execution", Severity: "critical"},
			{TechniqueID: "T1190", TechniqueName: "Exploit Public App", Tactic: "initial-access", Severity: "high"},
			{TechniqueID: "T1071", TechniqueName: "App Layer Protocol", Tactic: "command-and-control", Severity: "medium"},
		},
	}
	plan := RemediateFromCoverage(nil, report)
	if plan.TotalActions != 3 {
		t.Fatalf("expected 3 actions, got %d", plan.TotalActions)
	}
	if plan.CriticalCount != 1 {
		t.Errorf("expected 1 critical, got %d", plan.CriticalCount)
	}
	// Verify priority ordering.
	if plan.Actions[0].Priority != RemPriorityCritical {
		t.Errorf("first action should be critical, got %s", plan.Actions[0].Priority)
	}
}

func TestRemediateFromCoverage_LowSeverityGap(t *testing.T) {
	report := &CoverageMapReport{
		Gaps: []TechniqueGap{
			{TechniqueID: "T1557", TechniqueName: "AITM", Tactic: "credential-access", Severity: "low"},
		},
	}
	plan := RemediateFromCoverage(nil, report)
	if plan.Actions[0].Priority != RemPriorityLow {
		t.Errorf("expected low priority, got %s", plan.Actions[0].Priority)
	}
}

// ---------------------------------------------------------------------------
// MergeRemediations tests
// ---------------------------------------------------------------------------

func TestMergeRemediations_Empty(t *testing.T) {
	plan := MergeRemediations()
	if plan.TotalActions != 0 {
		t.Errorf("expected 0 actions, got %d", plan.TotalActions)
	}
	if plan.EstimatedEffort != "minimal" {
		t.Errorf("expected minimal effort, got %q", plan.EstimatedEffort)
	}
}

func TestMergeRemediations_NilPlans(t *testing.T) {
	plan := MergeRemediations(nil, nil)
	if plan.TotalActions != 0 {
		t.Errorf("expected 0 actions, got %d", plan.TotalActions)
	}
}

func TestMergeRemediations_SinglePlan(t *testing.T) {
	p1 := &RemediationPlan{
		PolicyName: "test",
		Actions: []RemediationAction{
			{Source: "lint:SEC-001", Priority: RemPriorityCritical, Type: RemAddRule},
		},
	}
	merged := MergeRemediations(p1)
	if merged.TotalActions != 1 {
		t.Errorf("expected 1 action, got %d", merged.TotalActions)
	}
	if merged.PolicyName != "test" {
		t.Errorf("expected policy name test, got %q", merged.PolicyName)
	}
}

func TestMergeRemediations_Deduplicate(t *testing.T) {
	p1 := &RemediationPlan{
		PolicyName: "test",
		Actions: []RemediationAction{
			{Source: "lint:SEC-001", Priority: RemPriorityHigh, Type: RemAddRule, Description: "from lint"},
		},
	}
	p2 := &RemediationPlan{
		PolicyName: "test",
		Actions: []RemediationAction{
			{Source: "lint:SEC-001", Priority: RemPriorityCritical, Type: RemAddRule, Description: "from coverage"},
		},
	}
	merged := MergeRemediations(p1, p2)
	if merged.TotalActions != 1 {
		t.Fatalf("expected 1 action after dedup, got %d", merged.TotalActions)
	}
	// Should keep the higher-priority version.
	if merged.Actions[0].Priority != RemPriorityCritical {
		t.Errorf("expected critical (higher priority) to win, got %s", merged.Actions[0].Priority)
	}
}

func TestMergeRemediations_CombineDistinct(t *testing.T) {
	p1 := &RemediationPlan{
		Actions: []RemediationAction{
			{Source: "lint:SEC-001", Priority: RemPriorityCritical},
		},
	}
	p2 := &RemediationPlan{
		PolicyName: "test",
		Actions: []RemediationAction{
			{Source: "coverage:T1059", Priority: RemPriorityHigh},
		},
	}
	merged := MergeRemediations(p1, p2)
	if merged.TotalActions != 2 {
		t.Errorf("expected 2 actions, got %d", merged.TotalActions)
	}
}

func TestMergeRemediations_ReNumbering(t *testing.T) {
	p1 := &RemediationPlan{
		Actions: []RemediationAction{
			{ID: "old-1", Source: "lint:SEC-001", Priority: RemPriorityLow},
			{ID: "old-2", Source: "lint:COV-001", Priority: RemPriorityCritical},
		},
	}
	merged := MergeRemediations(p1)
	// After merge, actions are re-sorted by priority and re-numbered.
	if merged.Actions[0].ID != "REM-001" {
		t.Errorf("expected REM-001, got %s", merged.Actions[0].ID)
	}
	if merged.Actions[0].Priority != RemPriorityCritical {
		t.Errorf("expected critical first after sort, got %s", merged.Actions[0].Priority)
	}
}

// ---------------------------------------------------------------------------
// ApplyRemediation tests
// ---------------------------------------------------------------------------

func TestApplyRemediation_NilPolicy(t *testing.T) {
	_, err := ApplyRemediation(nil, RemediationAction{Type: RemAddRule})
	if err == nil {
		t.Fatal("expected error for nil policy")
	}
}

func TestApplyRemediation_AddRule(t *testing.T) {
	p := remTestPolicy("apply-test", remTestRule("r1", "deny", []string{"shell_exec"}))
	action := RemediationAction{
		Type:   RemAddRule,
		Source: "lint:SEC-001",
		RuleAfter: `- id: default-deny
  description: "Deny all"
  effect: deny
  match:
    tools: ["*"]`,
	}
	result, err := ApplyRemediation(p, action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(result.Rules))
	}
	// Original policy should be unchanged.
	if len(p.Rules) != 1 {
		t.Errorf("original policy should have 1 rule, got %d", len(p.Rules))
	}
	// Verify the new rule.
	found := false
	for _, r := range result.Rules {
		if r.ID == "default-deny" {
			found = true
			if r.Effect != "deny" {
				t.Errorf("expected deny effect, got %s", r.Effect)
			}
		}
	}
	if !found {
		t.Error("expected default-deny rule to be added")
	}
}

func TestApplyRemediation_AddRule_NoDuplicate(t *testing.T) {
	p := remTestPolicy("apply-test", remTestRule("default-deny", "deny", []string{"*"}))
	action := RemediationAction{
		Type:      RemAddRule,
		RuleAfter: "- id: default-deny\n  effect: deny",
	}
	result, err := ApplyRemediation(p, action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not duplicate.
	if len(result.Rules) != 1 {
		t.Errorf("expected 1 rule (no duplicate), got %d", len(result.Rules))
	}
}

func TestApplyRemediation_RemoveRule(t *testing.T) {
	p := remTestPolicy("apply-test",
		remTestRule("r1", "deny", []string{"shell_exec"}),
		remTestRule("dup-rule", "allow", []string{"http"}),
	)
	action := RemediationAction{
		Type:        RemRemoveRule,
		Source:      "lint:RED-001",
		Description: "Remove duplicate rule dup-rule",
	}
	result, err := ApplyRemediation(p, action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Rules) != 1 {
		t.Errorf("expected 1 rule after removal, got %d", len(result.Rules))
	}
	if result.Rules[0].ID != "r1" {
		t.Errorf("expected r1 to remain, got %s", result.Rules[0].ID)
	}
	// Original unchanged.
	if len(p.Rules) != 2 {
		t.Errorf("original should have 2 rules, got %d", len(p.Rules))
	}
}

func TestApplyRemediation_AddMetadata_Description(t *testing.T) {
	p := remTestPolicy("apply-test")
	p.Meta.Description = "" // clear it
	action := RemediationAction{
		Type:   RemAddMetadata,
		Source: "lint:BP-001",
	}
	result, err := ApplyRemediation(p, action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Meta.Description == "" {
		t.Error("expected description to be filled")
	}
}

func TestApplyRemediation_AddMetadata_Authors(t *testing.T) {
	p := remTestPolicy("apply-test")
	p.Meta.Authors = nil // clear
	action := RemediationAction{
		Type:   RemAddMetadata,
		Source: "lint:BP-002",
	}
	result, err := ApplyRemediation(p, action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Meta.Authors) == 0 {
		t.Error("expected authors to be filled")
	}
}

func TestApplyRemediation_AddMetadata_Timestamps(t *testing.T) {
	p := remTestPolicy("apply-test")
	p.Meta.Created = ""
	p.Meta.Modified = ""
	action := RemediationAction{
		Type:   RemAddMetadata,
		Source: "lint:BP-005",
	}
	result, err := ApplyRemediation(p, action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Meta.Created == "" {
		t.Error("expected created to be filled")
	}
	if result.Meta.Modified == "" {
		t.Error("expected modified to be filled")
	}
}

func TestApplyRemediation_ModifyRule_ReturnsError(t *testing.T) {
	p := remTestPolicy("apply-test")
	action := RemediationAction{
		Type:        RemModifyRule,
		Description: "needs manual review",
	}
	_, err := ApplyRemediation(p, action)
	if err == nil {
		t.Fatal("expected error for modify_rule")
	}
	if !strings.Contains(err.Error(), "manual review") {
		t.Errorf("expected manual review message, got %v", err)
	}
}

func TestApplyRemediation_Restructure_ReturnsError(t *testing.T) {
	p := remTestPolicy("apply-test")
	action := RemediationAction{
		Type:        RemRestructure,
		Description: "split policy",
	}
	_, err := ApplyRemediation(p, action)
	if err == nil {
		t.Fatal("expected error for restructure")
	}
}

func TestApplyRemediation_DeepCopy(t *testing.T) {
	p := remTestPolicy("copy-test",
		remTestRule("r1", "deny", []string{"shell_exec", "http_request"}),
	)
	action := RemediationAction{
		Type:      RemAddRule,
		RuleAfter: "- id: new-rule\n  effect: alert\n  match:\n    tools: [dns_query]",
	}
	result, err := ApplyRemediation(p, action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Mutate the result — original must be unchanged.
	result.Rules[0].Match.Tools = append(result.Rules[0].Match.Tools, "mutated")
	if len(p.Rules[0].Match.Tools) != 2 {
		t.Errorf("original tools mutated: got %d", len(p.Rules[0].Match.Tools))
	}
}

// ---------------------------------------------------------------------------
// FormatRemediationPlan tests
// ---------------------------------------------------------------------------

func TestFormatRemediationPlan_Nil(t *testing.T) {
	out := FormatRemediationPlan(nil)
	if out != "No remediation plan." {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestFormatRemediationPlan_Empty(t *testing.T) {
	plan := &RemediationPlan{PolicyName: "empty", EstimatedEffort: "minimal"}
	out := FormatRemediationPlan(plan)
	if !strings.Contains(out, "No remediation actions needed") {
		t.Error("expected 'no actions needed' in output")
	}
	if !strings.Contains(out, "empty") {
		t.Error("expected policy name in output")
	}
}

func TestFormatRemediationPlan_WithActions(t *testing.T) {
	plan := &RemediationPlan{
		PolicyName:          "test-policy",
		TotalActions:        2,
		CriticalCount:       1,
		HighCount:           1,
		AutoApplicableCount: 1,
		EstimatedEffort:     "moderate",
		Actions: []RemediationAction{
			{
				ID:             "REM-001",
				Type:           RemAddRule,
				Priority:       RemPriorityCritical,
				Source:         "lint:SEC-001",
				Description:    "Add default deny rule",
				AutoApplicable: true,
			},
			{
				ID:          "REM-002",
				Type:        RemModifyRule,
				Priority:    RemPriorityHigh,
				Source:      "drift:effect_changed",
				Description: "Restore deny effect for rule r1",
			},
		},
	}
	out := FormatRemediationPlan(plan)
	if !strings.Contains(out, "test-policy") {
		t.Error("expected policy name in output")
	}
	if !strings.Contains(out, "REM-001") {
		t.Error("expected REM-001 in output")
	}
	if !strings.Contains(out, "REM-002") {
		t.Error("expected REM-002 in output")
	}
	if !strings.Contains(out, "moderate") {
		t.Error("expected effort level in output")
	}
}

// ---------------------------------------------------------------------------
// Effort estimation tests
// ---------------------------------------------------------------------------

func TestEstimatedEffort_Minimal(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "BP-001", Severity: LintStyle},
		},
	}
	plan := RemediateFromLint(nil, report)
	if plan.EstimatedEffort != "minimal" {
		t.Errorf("expected minimal, got %q", plan.EstimatedEffort)
	}
}

func TestEstimatedEffort_Moderate(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "SEC-005", Severity: LintWarning},
			{Rule: "COV-001", Severity: LintWarning},
			{Rule: "COV-002", Severity: LintWarning},
			{Rule: "COV-003", Severity: LintInfo},
			{Rule: "COV-004", Severity: LintInfo},
			{Rule: "BP-001", Severity: LintStyle},
		},
	}
	plan := RemediateFromLint(nil, report)
	if plan.EstimatedEffort != "moderate" {
		t.Errorf("expected moderate, got %q", plan.EstimatedEffort)
	}
}

func TestEstimatedEffort_Significant(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "SEC-001", Severity: LintError},
		},
	}
	plan := RemediateFromLint(nil, report)
	if plan.EstimatedEffort != "significant" {
		t.Errorf("expected significant for critical action, got %q", plan.EstimatedEffort)
	}
}

// ---------------------------------------------------------------------------
// Priority ordering tests
// ---------------------------------------------------------------------------

func TestPriorityOrdering(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "BP-001", Severity: LintStyle},    // low
			{Rule: "SEC-001", Severity: LintError},   // critical
			{Rule: "COV-001", Severity: LintWarning}, // medium
			{Rule: "SEC-005", Severity: LintWarning}, // high
		},
	}
	plan := RemediateFromLint(nil, report)
	if len(plan.Actions) < 4 {
		t.Fatalf("expected at least 4 actions, got %d", len(plan.Actions))
	}
	// Verify strict priority ordering.
	for i := 1; i < len(plan.Actions); i++ {
		if priorityRank(plan.Actions[i].Priority) > priorityRank(plan.Actions[i-1].Priority) {
			t.Errorf("actions not sorted: %s (%s) before %s (%s)",
				plan.Actions[i-1].ID, plan.Actions[i-1].Priority,
				plan.Actions[i].ID, plan.Actions[i].Priority)
		}
	}
}

// ---------------------------------------------------------------------------
// ID numbering tests
// ---------------------------------------------------------------------------

func TestActionIDNumbering(t *testing.T) {
	report := &LintReport{
		Findings: []LintFinding{
			{Rule: "SEC-001", Severity: LintError},
			{Rule: "COV-001", Severity: LintWarning},
			{Rule: "BP-001", Severity: LintStyle},
		},
	}
	plan := RemediateFromLint(nil, report)
	for i, a := range plan.Actions {
		expected := fmt.Sprintf("REM-%03d", i+1)
		if a.ID != expected {
			t.Errorf("action %d: expected ID %s, got %s", i, expected, a.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration: full pipeline lint → remediate → apply
// ---------------------------------------------------------------------------

func TestIntegration_LintRemediateApply(t *testing.T) {
	// Policy with no deny rules and no description — triggers SEC-002 (no deny
	// rules) and SEC-004 (no alert rules), both warnings/info in the actual lint.
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "vulnerable", Authors: []string{"tester"}, Created: "2025-01-01", Modified: "2025-01-01"},
		Agent:      AgentScope{Name: "test-agent"},
		Rules: []Rule{
			{ID: "r1", Description: "allow all", Effect: "allow", Priority: 10, Match: RuleMatch{Tools: []string{"*"}}},
		},
	}

	// Lint it.
	lintReport := LintPolicy(p)
	if lintReport.FindingCount == 0 {
		t.Fatal("expected lint findings for policy with no deny rules")
	}

	// Generate remediation.
	plan := RemediateFromLint(p, lintReport)
	if plan.TotalActions == 0 {
		t.Fatal("expected remediation actions")
	}

	// Apply the auto-applicable ones.
	current := p
	applied := 0
	for _, a := range plan.Actions {
		if !a.AutoApplicable {
			continue
		}
		result, err := ApplyRemediation(current, a)
		if err != nil {
			continue // skip non-auto ones
		}
		current = result
		applied++
	}

	if applied == 0 {
		t.Fatal("expected at least one action to be applied")
	}

	// Verify the remediated policy has more rules.
	if len(current.Rules) <= len(p.Rules) {
		t.Errorf("expected more rules after remediation, got %d vs %d", len(current.Rules), len(p.Rules))
	}
}
