// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers — all prefixed with mkImpact to avoid clashes with the many
// existing test files in this package.
// ---------------------------------------------------------------------------

func mkImpactPolicy(name string, rules []Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta: PolicyMeta{
			Name:        name,
			Description: "test policy",
			Authors:     []string{"test"},
			Created:     "2026-01-01",
			Modified:    "2026-01-01",
		},
		Agent: AgentScope{Name: "test-agent"},
		Rules: rules,
	}
}

func mkImpactRule(id, effect string, tools ...string) Rule {
	return Rule{
		ID:          id,
		Description: "rule " + id,
		Effect:      effect,
		Priority:    10,
		Match:       RuleMatch{Tools: tools},
	}
}

func mkImpactRuleWithPriority(id, effect string, priority int, tools ...string) Rule {
	r := mkImpactRule(id, effect, tools...)
	r.Priority = priority
	return r
}

func mkImpactRuleWithConditions(id, effect string, tools []string, conds []Condition) Rule {
	return Rule{
		ID:          id,
		Description: "rule " + id,
		Effect:      effect,
		Priority:    10,
		Match:       RuleMatch{Tools: tools},
		Conditions:  conds,
	}
}

func mkImpactRuleWithTactics(id, effect string, tactics ...string) Rule {
	return Rule{
		ID:          id,
		Description: "rule " + id,
		Effect:      effect,
		Priority:    10,
		Match:       RuleMatch{Tactics: tactics},
	}
}

func mkImpactAgent(name string, tools ...string) ImpactAgent {
	return ImpactAgent{
		Name:  name,
		Tools: tools,
	}
}

func mkImpactTrace(id, agentName string, events []TraceEvent) *Trace {
	return &Trace{
		ID:        id,
		AgentName: agentName,
		Events:    events,
	}
}

func mkImpactToolCallEvent(id, tool string) TraceEvent {
	return TraceEvent{
		ID:   id,
		Type: "tool_call",
		ToolCall: &ToolCallEvent{
			Tool:    tool,
			Action:  "execute",
			Success: true,
		},
	}
}

// ===========================================================================
// DiffPolicyChanges tests
// ===========================================================================

func TestDiffPolicyChanges_AddedRules(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec"), mkImpactRule("r2", "allow", "file_read")})
	changes := DiffPolicyChanges(before, after)
	found := false
	for _, c := range changes {
		if c.Type == "add_rule" && c.RuleAfter != nil && c.RuleAfter.ID == "r2" {
			found = true
		}
	}
	if !found {
		t.Error("expected add_rule change for r2")
	}
}

func TestDiffPolicyChanges_RemovedRules(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec"), mkImpactRule("r2", "allow", "file_read")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	changes := DiffPolicyChanges(before, after)
	found := false
	for _, c := range changes {
		if c.Type == "remove_rule" && c.RuleBefore != nil && c.RuleBefore.ID == "r2" {
			found = true
		}
	}
	if !found {
		t.Error("expected remove_rule change for r2")
	}
}

func TestDiffPolicyChanges_EffectChange(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "allow", "shell_exec")})
	changes := DiffPolicyChanges(before, after)
	found := false
	for _, c := range changes {
		if c.Type == "change_effect" {
			found = true
			if c.RuleBefore.Effect != "deny" || c.RuleAfter.Effect != "allow" {
				t.Errorf("expected deny->allow, got %s->%s", c.RuleBefore.Effect, c.RuleAfter.Effect)
			}
		}
	}
	if !found {
		t.Error("expected change_effect change")
	}
}

func TestDiffPolicyChanges_ModifiedTools(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec", "file_delete")})
	changes := DiffPolicyChanges(before, after)
	found := false
	for _, c := range changes {
		if c.Type == "modify_rule" {
			found = true
		}
	}
	if !found {
		t.Error("expected modify_rule change")
	}
}

func TestDiffPolicyChanges_NoChanges(t *testing.T) {
	t.Parallel()
	p := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	changes := DiffPolicyChanges(p, p)
	if len(changes) != 0 {
		t.Errorf("expected 0 changes, got %d", len(changes))
	}
}

func TestDiffPolicyChanges_NilBefore(t *testing.T) {
	t.Parallel()
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	changes := DiffPolicyChanges(nil, after)
	if len(changes) != 1 || changes[0].Type != "add_rule" {
		t.Error("expected 1 add_rule from nil before")
	}
}

func TestDiffPolicyChanges_NilAfter(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	changes := DiffPolicyChanges(before, nil)
	if len(changes) != 1 || changes[0].Type != "remove_rule" {
		t.Error("expected 1 remove_rule from nil after")
	}
}

func TestDiffPolicyChanges_PriorityChange(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRuleWithPriority("r1", "deny", 10, "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRuleWithPriority("r1", "deny", 90, "shell_exec")})
	changes := DiffPolicyChanges(before, after)
	found := false
	for _, c := range changes {
		if c.Type == "modify_rule" {
			found = true
		}
	}
	if !found {
		t.Error("expected modify_rule for priority change")
	}
}

func TestDiffPolicyChanges_ConditionChange(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRuleWithConditions("r1", "deny", []string{"shell_exec"}, []Condition{{Field: "elevated", Operator: "eq", Value: "true"}})})
	changes := DiffPolicyChanges(before, after)
	found := false
	for _, c := range changes {
		if c.Type == "modify_rule" {
			found = true
		}
	}
	if !found {
		t.Error("expected modify_rule for condition change")
	}
}

func TestDiffPolicyChanges_MultipleChanges(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec"), mkImpactRule("r2", "allow", "file_read"), mkImpactRule("r3", "alert", "http_request")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "allow", "shell_exec"), mkImpactRule("r3", "alert", "http_request"), mkImpactRule("r4", "deny", "database_write")})
	changes := DiffPolicyChanges(before, after)
	types := make(map[string]int)
	for _, c := range changes {
		types[c.Type]++
	}
	if types["remove_rule"] != 1 {
		t.Errorf("expected 1 remove_rule, got %d", types["remove_rule"])
	}
	if types["add_rule"] != 1 {
		t.Errorf("expected 1 add_rule, got %d", types["add_rule"])
	}
	if types["change_effect"] != 1 {
		t.Errorf("expected 1 change_effect, got %d", types["change_effect"])
	}
}

func TestDiffPolicyChanges_TacticsChange(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRuleWithTactics("r1", "deny", "exfiltration")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRuleWithTactics("r1", "deny", "exfiltration", "lateral-movement")})
	changes := DiffPolicyChanges(before, after)
	found := false
	for _, c := range changes {
		if c.Type == "modify_rule" {
			found = true
		}
	}
	if !found {
		t.Error("expected modify_rule for tactics change")
	}
}

func TestDiffPolicyChanges_EffectSubsumesOtherMods(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRuleWithPriority("r1", "deny", 10, "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRuleWithPriority("r1", "allow", 99, "shell_exec", "file_delete")})
	changes := DiffPolicyChanges(before, after)
	if len(changes) != 1 {
		t.Errorf("expected 1 change (effect subsumes others), got %d", len(changes))
	}
	if len(changes) > 0 && changes[0].Type != "change_effect" {
		t.Errorf("expected change_effect, got %s", changes[0].Type)
	}
}

// ===========================================================================
// AssessChange tests
// ===========================================================================

func TestAssessChange_AddDenyRule(t *testing.T) {
	t.Parallel()
	agents := []ImpactAgent{mkImpactAgent("agent-1", "shell_exec"), mkImpactAgent("agent-2", "file_read")}
	change := PolicyChange{Type: "add_rule", RuleAfter: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}}}
	a := AssessChange(change, nil, agents)
	if a.Severity != "high" {
		t.Errorf("expected high severity for critical tool deny, got %s", a.Severity)
	}
	if a.NewDenials == 0 {
		t.Error("expected non-zero new denials")
	}
}

func TestAssessChange_AddDenyMultiAgents(t *testing.T) {
	t.Parallel()
	agents := []ImpactAgent{mkImpactAgent("a1", "file_delete"), mkImpactAgent("a2", "file_delete"), mkImpactAgent("a3", "file_delete")}
	change := PolicyChange{Type: "add_rule", RuleAfter: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"file_delete"}}}}
	a := AssessChange(change, nil, agents)
	if a.Severity != "high" {
		t.Errorf("expected high when >2 agents affected, got %s", a.Severity)
	}
}

func TestAssessChange_RemoveDenyRule(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "remove_rule", RuleBefore: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}}}
	a := AssessChange(change, nil, nil)
	if a.Severity != "critical" {
		t.Errorf("expected critical for removing deny rule, got %s", a.Severity)
	}
	if a.LiftedDenials == 0 {
		t.Error("expected lifted denials > 0")
	}
}

func TestAssessChange_RemoveAlertRule(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "remove_rule", RuleBefore: &Rule{ID: "r1", Effect: "alert", Match: RuleMatch{Tools: []string{"http_request"}}}}
	a := AssessChange(change, nil, nil)
	if a.Severity != "medium" {
		t.Errorf("expected medium for removing alert rule, got %s", a.Severity)
	}
	if len(a.Warnings) == 0 {
		t.Error("expected monitoring warning")
	}
}

func TestAssessChange_RemoveAllowRule(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "remove_rule", RuleBefore: &Rule{ID: "r1", Effect: "allow", Match: RuleMatch{Tools: []string{"file_read"}}}}
	a := AssessChange(change, nil, nil)
	if a.Severity != "medium" {
		t.Errorf("expected medium for removing allow rule, got %s", a.Severity)
	}
}

func TestAssessChange_DenyToAllow(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "change_effect", RuleBefore: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}}, RuleAfter: &Rule{ID: "r1", Effect: "allow", Match: RuleMatch{Tools: []string{"shell_exec"}}}}
	a := AssessChange(change, nil, nil)
	if a.Severity != "critical" {
		t.Errorf("expected critical for deny->allow, got %s", a.Severity)
	}
	if a.LiftedDenials == 0 {
		t.Error("expected lifted denials > 0")
	}
}

func TestAssessChange_AllowToDeny(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "change_effect", RuleBefore: &Rule{ID: "r1", Effect: "allow", Match: RuleMatch{Tools: []string{"file_read"}}}, RuleAfter: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"file_read"}}}}
	a := AssessChange(change, nil, nil)
	if a.Severity != "high" {
		t.Errorf("expected high for allow->deny, got %s", a.Severity)
	}
	if a.NewDenials == 0 {
		t.Error("expected new denials > 0")
	}
}

func TestAssessChange_DenyToAlert(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "change_effect", RuleBefore: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"file_read"}}}, RuleAfter: &Rule{ID: "r1", Effect: "alert", Match: RuleMatch{Tools: []string{"file_read"}}}}
	a := AssessChange(change, nil, nil)
	if a.Severity != "high" {
		t.Errorf("expected high for deny->alert, got %s", a.Severity)
	}
}

func TestAssessChange_AlertToDeny(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "change_effect", RuleBefore: &Rule{ID: "r1", Effect: "alert", Match: RuleMatch{Tools: []string{"file_read"}}}, RuleAfter: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"file_read"}}}}
	a := AssessChange(change, nil, nil)
	if a.NewDenials == 0 {
		t.Error("expected new denials for alert->deny")
	}
}

func TestAssessChange_WidenScope(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "modify_rule", RuleBefore: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}}, RuleAfter: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec", "file_delete"}}}}
	a := AssessChange(change, nil, nil)
	if a.NewDenials == 0 {
		t.Error("expected new denials when deny rule scope widens")
	}
	if a.Severity != "high" {
		t.Errorf("expected high for widened deny scope, got %s", a.Severity)
	}
}

func TestAssessChange_NarrowScope(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "modify_rule", RuleBefore: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec", "file_delete"}}}, RuleAfter: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}}}
	a := AssessChange(change, nil, nil)
	if a.LiftedDenials == 0 {
		t.Error("expected lifted denials when deny rule scope narrows")
	}
}

func TestAssessChange_ModifyAllowRule(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "modify_rule", RuleBefore: &Rule{ID: "r1", Effect: "allow", Match: RuleMatch{Tools: []string{"file_read"}}}, RuleAfter: &Rule{ID: "r1", Effect: "allow", Match: RuleMatch{Tools: []string{"file_read", "file_write"}}}}
	a := AssessChange(change, nil, nil)
	if a.Severity != "medium" {
		t.Errorf("expected medium for modified allow rule, got %s", a.Severity)
	}
}

func TestAssessChange_AddGuardrail(t *testing.T) {
	t.Parallel()
	a := AssessChange(PolicyChange{Type: "add_guardrail", GuardrailID: "inj"}, nil, nil)
	if a.Severity != "low" {
		t.Errorf("expected low for adding guardrail, got %s", a.Severity)
	}
}

func TestAssessChange_RemoveGuardrail(t *testing.T) {
	t.Parallel()
	a := AssessChange(PolicyChange{Type: "remove_guardrail", GuardrailID: "inj"}, nil, nil)
	if a.Severity != "high" {
		t.Errorf("expected high for removing guardrail, got %s", a.Severity)
	}
	if len(a.Warnings) == 0 {
		t.Error("expected warnings when removing guardrail")
	}
}

func TestAssessChange_NoAgents(t *testing.T) {
	t.Parallel()
	a := AssessChange(PolicyChange{Type: "add_rule", RuleAfter: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"some_tool"}}}}, nil, nil)
	if len(a.AffectedAgents) != 0 {
		t.Error("expected no affected agents when nil agents")
	}
}

func TestAssessChange_ChangeTrust(t *testing.T) {
	t.Parallel()
	a := AssessChange(PolicyChange{Type: "change_trust"}, nil, nil)
	if a.Severity != "high" {
		t.Errorf("expected high for trust change, got %s", a.Severity)
	}
}

func TestAssessChange_AddAllowCritical(t *testing.T) {
	t.Parallel()
	a := AssessChange(PolicyChange{Type: "add_rule", RuleAfter: &Rule{ID: "r1", Effect: "allow", Match: RuleMatch{Tools: []string{"shell_exec"}}}}, nil, nil)
	if a.Severity != "medium" {
		t.Errorf("expected medium for allow on critical tool, got %s", a.Severity)
	}
	if len(a.Warnings) == 0 {
		t.Error("expected warning for allow on critical tool")
	}
}

func TestAssessChange_AddAlert(t *testing.T) {
	t.Parallel()
	a := AssessChange(PolicyChange{Type: "add_rule", RuleAfter: &Rule{ID: "r1", Effect: "alert", Match: RuleMatch{Tools: []string{"file_read"}}}}, nil, nil)
	if a.Severity != "low" {
		t.Errorf("expected low for alert rule, got %s", a.Severity)
	}
}

func TestAssessChange_UnknownType(t *testing.T) {
	t.Parallel()
	a := AssessChange(PolicyChange{Type: "unknown"}, nil, nil)
	if a.Severity != "low" {
		t.Errorf("expected low for unknown type, got %s", a.Severity)
	}
}

func TestAssessChange_NilRuleBefore(t *testing.T) {
	t.Parallel()
	a := AssessChange(PolicyChange{Type: "remove_rule", RuleBefore: nil}, nil, nil)
	if a.Severity != "low" {
		t.Errorf("expected low for nil RuleBefore, got %s", a.Severity)
	}
}

func TestAssessChange_NilRuleAfter(t *testing.T) {
	t.Parallel()
	a := AssessChange(PolicyChange{Type: "add_rule", RuleAfter: nil}, nil, nil)
	if a.Severity != "low" {
		t.Errorf("expected low for nil RuleAfter, got %s", a.Severity)
	}
}

func TestAssessChange_DenyToAllowCriticalWarning(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "change_effect", RuleBefore: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}}, RuleAfter: &Rule{ID: "r1", Effect: "allow", Match: RuleMatch{Tools: []string{"shell_exec"}}}}
	a := AssessChange(change, nil, nil)
	found := false
	for _, w := range a.Warnings {
		if strings.Contains(w, "ecurity-critical") {
			found = true
		}
	}
	if !found {
		t.Error("expected security-critical warning for deny->allow on shell_exec")
	}
}

func TestAssessChange_RemoveDenyCriticalWarning(t *testing.T) {
	t.Parallel()
	change := PolicyChange{Type: "remove_rule", RuleBefore: &Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}}}
	a := AssessChange(change, nil, nil)
	found := false
	for _, w := range a.Warnings {
		if strings.Contains(w, "ecurity-critical") || strings.Contains(w, "unrestricted") {
			found = true
		}
	}
	if !found {
		t.Error("expected security-critical warning for removing deny on shell_exec")
	}
}

// ===========================================================================
// AnalyzeImpact tests (integration)
// ===========================================================================

func TestAnalyzeImpact_BasicReport(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "allow", "shell_exec")})
	agents := []ImpactAgent{mkImpactAgent("a1", "shell_exec")}
	report := AnalyzeImpact(before, after, agents)
	if report.PolicyName != "p1" {
		t.Errorf("expected policy name p1, got %s", report.PolicyName)
	}
	if report.ChangeCount != 1 {
		t.Errorf("expected 1 change, got %d", report.ChangeCount)
	}
	if report.OverallRisk != "increased" {
		t.Errorf("expected increased risk, got %s", report.OverallRisk)
	}
}

func TestAnalyzeImpact_NoChanges(t *testing.T) {
	t.Parallel()
	p := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	report := AnalyzeImpact(p, p, nil)
	if report.ChangeCount != 0 {
		t.Errorf("expected 0 changes, got %d", report.ChangeCount)
	}
	if report.OverallRisk != "neutral" {
		t.Errorf("expected neutral risk, got %s", report.OverallRisk)
	}
}

func TestAnalyzeImpact_BreakingCount(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "allow", "shell_exec"), mkImpactRule("r2", "allow", "file_read")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec"), mkImpactRule("r2", "deny", "file_read")})
	report := AnalyzeImpact(before, after, nil)
	if report.BreakingChanges != 2 {
		t.Errorf("expected 2 breaking changes, got %d", report.BreakingChanges)
	}
}

func TestAnalyzeImpact_LintScores(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec"), mkImpactRule("r2", "allow", "file_read"), mkImpactRule("r3", "alert", "http_request")})
	report := AnalyzeImpact(before, after, nil)
	if report.LintBefore < 0 || report.LintBefore > 100 {
		t.Errorf("lint before out of range: %d", report.LintBefore)
	}
	if report.LintAfter < 0 || report.LintAfter > 100 {
		t.Errorf("lint after out of range: %d", report.LintAfter)
	}
}

func TestAnalyzeImpact_Summary(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "allow", "shell_exec")})
	report := AnalyzeImpact(before, after, nil)
	if len(report.Summary) == 0 {
		t.Error("expected non-empty summary")
	}
}

func TestAnalyzeImpact_PolicyNameFallback(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("before-policy", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	report := AnalyzeImpact(before, nil, nil)
	if report.PolicyName == "" {
		t.Error("expected policy name from before when after is nil")
	}
}

// ===========================================================================
// AnalyzeTraceImpact tests
// ===========================================================================

func TestAnalyzeTraceImpact_NewViolations(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "allow", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	traces := []*Trace{mkImpactTrace("t1", "agent-1", []TraceEvent{mkImpactToolCallEvent("ev1", "shell_exec")})}
	impacts := AnalyzeTraceImpact(before, after, traces)
	if len(impacts) != 1 {
		t.Fatalf("expected 1, got %d", len(impacts))
	}
	if impacts[0].NewViolations == 0 {
		t.Error("expected new violations")
	}
	if impacts[0].Verdict != "breaking" {
		t.Errorf("expected breaking, got %s", impacts[0].Verdict)
	}
}

func TestAnalyzeTraceImpact_ResolvedViolations(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "allow", "shell_exec")})
	traces := []*Trace{mkImpactTrace("t1", "agent-1", []TraceEvent{mkImpactToolCallEvent("ev1", "shell_exec")})}
	impacts := AnalyzeTraceImpact(before, after, traces)
	if len(impacts) != 1 {
		t.Fatalf("expected 1, got %d", len(impacts))
	}
	if impacts[0].ResolvedViolations == 0 {
		t.Error("expected resolved violations")
	}
	if impacts[0].Verdict != "improved" {
		t.Errorf("expected improved, got %s", impacts[0].Verdict)
	}
}

func TestAnalyzeTraceImpact_Safe(t *testing.T) {
	t.Parallel()
	p := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	traces := []*Trace{mkImpactTrace("t1", "agent-1", []TraceEvent{mkImpactToolCallEvent("ev1", "file_read")})}
	impacts := AnalyzeTraceImpact(p, p, traces)
	if len(impacts) != 1 {
		t.Fatalf("expected 1, got %d", len(impacts))
	}
	if impacts[0].Verdict != "safe" {
		t.Errorf("expected safe, got %s", impacts[0].Verdict)
	}
}

func TestAnalyzeTraceImpact_Multiple(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "allow", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	traces := []*Trace{mkImpactTrace("t1", "a1", []TraceEvent{mkImpactToolCallEvent("ev1", "shell_exec")}), mkImpactTrace("t2", "a2", []TraceEvent{mkImpactToolCallEvent("ev2", "file_read")})}
	impacts := AnalyzeTraceImpact(before, after, traces)
	if len(impacts) != 2 {
		t.Fatalf("expected 2, got %d", len(impacts))
	}
}

func TestAnalyzeTraceImpact_NilTrace(t *testing.T) {
	t.Parallel()
	impacts := AnalyzeTraceImpact(mkImpactPolicy("p1", nil), mkImpactPolicy("p1", nil), []*Trace{nil})
	if len(impacts) != 0 {
		t.Errorf("expected 0 for nil trace, got %d", len(impacts))
	}
}

func TestAnalyzeTraceImpact_Empty(t *testing.T) {
	t.Parallel()
	impacts := AnalyzeTraceImpact(mkImpactPolicy("p1", nil), mkImpactPolicy("p1", nil), nil)
	if len(impacts) != 0 {
		t.Errorf("expected 0, got %d", len(impacts))
	}
}

func TestAnalyzeTraceImpact_AgentName(t *testing.T) {
	t.Parallel()
	impacts := AnalyzeTraceImpact(mkImpactPolicy("p1", nil), mkImpactPolicy("p1", nil), []*Trace{mkImpactTrace("t1", "my-agent", nil)})
	if len(impacts) != 1 {
		t.Fatalf("expected 1, got %d", len(impacts))
	}
	if impacts[0].AgentName != "my-agent" {
		t.Errorf("expected my-agent, got %s", impacts[0].AgentName)
	}
}

// ===========================================================================
// ComputeRiskDelta tests
// ===========================================================================

func TestComputeRiskDelta_RemoveDeny(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec"), mkImpactRule("r2", "deny", "file_delete")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	delta := ComputeRiskDelta(before, after)
	if delta <= 0 {
		t.Errorf("expected positive delta when deny removed, got %.3f", delta)
	}
}

func TestComputeRiskDelta_AddDeny(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec"), mkImpactRule("r2", "deny", "file_delete")})
	delta := ComputeRiskDelta(before, after)
	if delta >= 0 {
		t.Errorf("expected negative delta when deny added, got %.3f", delta)
	}
}

func TestComputeRiskDelta_Identical(t *testing.T) {
	t.Parallel()
	p := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	if delta := ComputeRiskDelta(p, p); delta != 0 {
		t.Errorf("expected 0 for identical, got %.3f", delta)
	}
}

func TestComputeRiskDelta_Nil(t *testing.T) {
	t.Parallel()
	if delta := ComputeRiskDelta(nil, nil); delta != 0 {
		t.Errorf("expected 0 for nil, got %.3f", delta)
	}
}

func TestComputeRiskDelta_Clamped(t *testing.T) {
	t.Parallel()
	delta := ComputeRiskDelta(mkImpactPolicy("p1", nil), mkImpactPolicy("p1", nil))
	if delta < -1.0 || delta > 1.0 {
		t.Errorf("out of range: %.3f", delta)
	}
}

func TestComputeRiskDelta_AddAllow(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec")})
	after := mkImpactPolicy("p1", []Rule{mkImpactRule("r1", "deny", "shell_exec"), mkImpactRule("r2", "allow", "file_read")})
	delta := ComputeRiskDelta(before, after)
	if delta < -0.5 {
		t.Errorf("adding allow should not significantly decrease risk, got %.3f", delta)
	}
}

// ===========================================================================
// FindAffectedAgents tests
// ===========================================================================

func TestFindAffectedAgents_ByTool(t *testing.T) {
	t.Parallel()
	agents := []ImpactAgent{mkImpactAgent("a1", "shell_exec", "file_read"), mkImpactAgent("a2", "http_request"), mkImpactAgent("a3", "shell_exec")}
	affected := FindAffectedAgents(PolicyChange{RuleBefore: &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}}, agents)
	if len(affected) != 2 {
		t.Errorf("expected 2, got %d: %v", len(affected), affected)
	}
}

func TestFindAffectedAgents_NoMatch(t *testing.T) {
	t.Parallel()
	affected := FindAffectedAgents(PolicyChange{RuleAfter: &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}}, []ImpactAgent{mkImpactAgent("a1", "file_read")})
	if len(affected) != 0 {
		t.Errorf("expected 0, got %d", len(affected))
	}
}

func TestFindAffectedAgents_Glob(t *testing.T) {
	t.Parallel()
	agents := []ImpactAgent{mkImpactAgent("a1", "file_read"), mkImpactAgent("a2", "file_write")}
	affected := FindAffectedAgents(PolicyChange{RuleAfter: &Rule{Match: RuleMatch{Tools: []string{"file_*"}}}}, agents)
	if len(affected) != 2 {
		t.Errorf("expected 2 by glob, got %d", len(affected))
	}
}

func TestFindAffectedAgents_Empty(t *testing.T) {
	t.Parallel()
	affected := FindAffectedAgents(PolicyChange{RuleAfter: &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}}, nil)
	if len(affected) != 0 {
		t.Errorf("expected 0, got %d", len(affected))
	}
}

func TestFindAffectedAgents_EmptyAgent(t *testing.T) {
	t.Parallel()
	affected := FindAffectedAgents(PolicyChange{RuleAfter: &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}}, []ImpactAgent{{}, mkImpactAgent("a1", "shell_exec")})
	if len(affected) != 1 {
		t.Errorf("expected 1, got %d", len(affected))
	}
}

func TestFindAffectedAgents_Sorted(t *testing.T) {
	t.Parallel()
	agents := []ImpactAgent{mkImpactAgent("z", "shell_exec"), mkImpactAgent("a", "shell_exec"), mkImpactAgent("m", "shell_exec")}
	affected := FindAffectedAgents(PolicyChange{RuleAfter: &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}}, agents)
	if len(affected) != 3 {
		t.Fatalf("expected 3, got %d", len(affected))
	}
	if affected[0] != "a" || affected[1] != "m" || affected[2] != "z" {
		t.Errorf("expected sorted, got %v", affected)
	}
}

func TestFindAffectedAgents_GuardrailChangeNoToolMatch(t *testing.T) {
	t.Parallel()
	agents := []ImpactAgent{mkImpactAgent("a1", "shell_exec")}
	// Guardrail changes don't reference tools, so no agents are affected via tool matching.
	affected := FindAffectedAgents(PolicyChange{Type: "remove_guardrail", GuardrailID: "inj"}, agents)
	if len(affected) != 0 {
		t.Errorf("expected 0 affected for guardrail change with no tool refs, got %v", affected)
	}
}

// ===========================================================================
// FindAffectedTools tests
// ===========================================================================

func TestFindAffectedTools_Both(t *testing.T) {
	t.Parallel()
	tools := FindAffectedTools(PolicyChange{RuleBefore: &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}, RuleAfter: &Rule{Match: RuleMatch{Tools: []string{"shell_exec", "file_delete"}}}})
	if len(tools) != 2 {
		t.Errorf("expected 2, got %d: %v", len(tools), tools)
	}
}

func TestFindAffectedTools_Nil(t *testing.T) {
	t.Parallel()
	if len(FindAffectedTools(PolicyChange{})) != 0 {
		t.Error("expected 0 tools for empty change")
	}
}

func TestFindAffectedTools_Dedup(t *testing.T) {
	t.Parallel()
	tools := FindAffectedTools(PolicyChange{RuleBefore: &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}, RuleAfter: &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}})
	if len(tools) != 1 {
		t.Errorf("expected 1 dedup, got %d", len(tools))
	}
}

func TestFindAffectedTools_Sorted(t *testing.T) {
	t.Parallel()
	tools := FindAffectedTools(PolicyChange{RuleAfter: &Rule{Match: RuleMatch{Tools: []string{"z_tool", "a_tool", "m_tool"}}}})
	if len(tools) != 3 {
		t.Fatalf("expected 3, got %d", len(tools))
	}
	if tools[0] != "a_tool" || tools[1] != "m_tool" || tools[2] != "z_tool" {
		t.Errorf("expected sorted, got %v", tools)
	}
}

// ===========================================================================
// IsBreakingChange tests
// ===========================================================================

func TestIsBreakingChange_True(t *testing.T) {
	t.Parallel()
	if !IsBreakingChange(&ImpactAssessment{NewDenials: 3}) {
		t.Error("expected breaking")
	}
}

func TestIsBreakingChange_False(t *testing.T) {
	t.Parallel()
	if IsBreakingChange(&ImpactAssessment{NewDenials: 0}) {
		t.Error("expected non-breaking")
	}
}

func TestIsBreakingChange_Nil(t *testing.T) {
	t.Parallel()
	if IsBreakingChange(nil) {
		t.Error("expected false for nil")
	}
}

func TestIsBreakingChange_LiftedOnly(t *testing.T) {
	t.Parallel()
	if IsBreakingChange(&ImpactAssessment{LiftedDenials: 5}) {
		t.Error("expected non-breaking with only lifted")
	}
}

// ===========================================================================
// FormatImpactReport tests
// ===========================================================================

func TestFormatImpactReport_Nil(t *testing.T) {
	t.Parallel()
	if FormatImpactReport(nil) != "No impact report.\n" {
		t.Error("unexpected nil output")
	}
}

func TestFormatImpactReport_BoxDrawing(t *testing.T) {
	t.Parallel()
	out := FormatImpactReport(&ImpactReport{PolicyName: "test", ChangeCount: 1, OverallRisk: "increased", Assessments: []ImpactAssessment{{Change: PolicyChange{Type: "add_rule", Description: "added"}, Severity: "high"}}})
	if !strings.Contains(out, "POLICY IMPACT REPORT") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "test") {
		t.Error("missing policy name")
	}
}

func TestFormatImpactReport_Agents(t *testing.T) {
	t.Parallel()
	out := FormatImpactReport(&ImpactReport{PolicyName: "test", ChangeCount: 1, Assessments: []ImpactAssessment{{Change: PolicyChange{Type: "x", Description: "t"}, Severity: "high", AffectedAgents: []string{"agent-1"}}}})
	if !strings.Contains(out, "agent-1") {
		t.Error("missing agent")
	}
}

func TestFormatImpactReport_NoChanges(t *testing.T) {
	t.Parallel()
	out := FormatImpactReport(&ImpactReport{PolicyName: "test"})
	if !strings.Contains(out, "No changes") {
		t.Error("missing 'No changes'")
	}
}

func TestFormatImpactReport_Warnings(t *testing.T) {
	t.Parallel()
	out := FormatImpactReport(&ImpactReport{PolicyName: "t", ChangeCount: 1, Assessments: []ImpactAssessment{{Change: PolicyChange{Type: "x", Description: "d"}, Severity: "high", Warnings: []string{"test warning"}}}})
	if !strings.Contains(out, "test warning") {
		t.Error("missing warning")
	}
}

func TestFormatImpactReport_Denials(t *testing.T) {
	t.Parallel()
	out := FormatImpactReport(&ImpactReport{PolicyName: "t", ChangeCount: 1, Assessments: []ImpactAssessment{{Change: PolicyChange{Type: "x", Description: "d"}, Severity: "high", NewDenials: 5}}})
	if !strings.Contains(out, "New denials") {
		t.Error("missing denials")
	}
}

// ===========================================================================
// SummarizeImpact tests
// ===========================================================================

func TestSummarizeImpact_Nil(t *testing.T) {
	t.Parallel()
	if SummarizeImpact(nil) != "No impact data" {
		t.Error("unexpected nil result")
	}
}

func TestSummarizeImpact_NoChanges(t *testing.T) {
	t.Parallel()
	if SummarizeImpact(&ImpactReport{}) != "No changes detected" {
		t.Error("unexpected empty result")
	}
}

func TestSummarizeImpact_WithChanges(t *testing.T) {
	t.Parallel()
	s := SummarizeImpact(&ImpactReport{ChangeCount: 3, BreakingChanges: 1, OverallRisk: "increased", RiskDelta: 0.15, LintBefore: 90, LintAfter: 80})
	if !strings.Contains(s, "3 changes") {
		t.Error("missing count")
	}
	if !strings.Contains(s, "1 breaking") {
		t.Error("missing breaking")
	}
	if !strings.Contains(s, "increased") {
		t.Error("missing risk")
	}
}

// ===========================================================================
// Integration: end-to-end scenarios
// ===========================================================================

func TestImpact_EndToEnd(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("prod", []Rule{mkImpactRule("deny-shell", "deny", "shell_exec"), mkImpactRule("allow-read", "allow", "file_read"), mkImpactRule("alert-http", "alert", "http_request")})
	after := mkImpactPolicy("prod", []Rule{mkImpactRule("deny-shell", "allow", "shell_exec"), mkImpactRule("allow-read", "allow", "file_read"), mkImpactRule("deny-write", "deny", "database_write")})
	agents := []ImpactAgent{mkImpactAgent("data-agent", "shell_exec", "file_read", "database_write"), mkImpactAgent("web-agent", "http_request")}
	traces := []*Trace{mkImpactTrace("trace-1", "data-agent", []TraceEvent{mkImpactToolCallEvent("ev1", "shell_exec"), mkImpactToolCallEvent("ev2", "database_write")})}

	report := AnalyzeImpact(before, after, agents)
	if report.ChangeCount < 3 {
		t.Errorf("expected >= 3 changes, got %d", report.ChangeCount)
	}
	if report.BreakingChanges < 1 {
		t.Error("expected >= 1 breaking change")
	}

	traceImpacts := AnalyzeTraceImpact(before, after, traces)
	if len(traceImpacts) == 0 {
		t.Fatal("expected trace impacts")
	}

	formatted := FormatImpactReport(report)
	if formatted == "" {
		t.Error("empty formatted report")
	}
	summary := SummarizeImpact(report)
	if summary == "" {
		t.Error("empty summary")
	}
}

func TestImpact_EndToEndDecreased(t *testing.T) {
	t.Parallel()
	before := mkImpactPolicy("lax", []Rule{mkImpactRule("r1", "allow", "shell_exec", "file_delete")})
	after := mkImpactPolicy("strict", []Rule{mkImpactRule("r1", "deny", "shell_exec", "file_delete")})
	report := AnalyzeImpact(before, after, nil)
	if report.OverallRisk == "increased" {
		t.Error("expected non-increased risk for allow->deny")
	}
}
