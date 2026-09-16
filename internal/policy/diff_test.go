// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"strings"
	"testing"
)

// diffTestPolicy builds a minimal valid policy for diff testing.
func diffTestPolicy(name string, agent AgentScope, rules ...Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta: PolicyMeta{
			Name:        name,
			Description: "test policy for diff",
		},
		Agent: agent,
		Rules: rules,
	}
}

// denyRule, allowRule, alertRule helpers are in trace_test.go
// (same package — shared across test files).

// --- Identical policies ---

func TestDiffPolicies_Identical(t *testing.T) {
	scope := AgentScope{Name: "test-agent"}
	p := diffTestPolicy("my-policy", scope,
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
	)
	d := DiffPolicies(p, p)

	if !d.Summary.IsIdentical {
		t.Error("identical policies should produce IsIdentical=true")
	}
	if d.Summary.TotalChanges != 0 {
		t.Errorf("TotalChanges = %d, want 0", d.Summary.TotalChanges)
	}
	if len(d.AddedRules) != 0 {
		t.Errorf("AddedRules = %d, want 0", len(d.AddedRules))
	}
	if len(d.RemovedRules) != 0 {
		t.Errorf("RemovedRules = %d, want 0", len(d.RemovedRules))
	}
	if len(d.ModifiedRules) != 0 {
		t.Errorf("ModifiedRules = %d, want 0", len(d.ModifiedRules))
	}
}

func TestDiffPolicies_IdenticalSameContent(t *testing.T) {
	scope := AgentScope{Name: "agent-a", Type: "llm"}
	old := diffTestPolicy("pol", scope,
		denyRule("r1", "", 50, []string{"http_request"}),
	)
	new := diffTestPolicy("pol", scope,
		denyRule("r1", "", 50, []string{"http_request"}),
	)
	d := DiffPolicies(old, new)
	if !d.Summary.IsIdentical {
		t.Error("structurally identical policies should be IsIdentical")
	}
}

// --- Added rules ---

func TestDiffPolicies_AddedRulesOnly(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope,
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	new := diffTestPolicy("p", scope,
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
		alertRule("r3", "", 50, []string{"dns_query"}),
	)

	d := DiffPolicies(old, new)

	if d.Summary.RulesAdded != 2 {
		t.Errorf("RulesAdded = %d, want 2", d.Summary.RulesAdded)
	}
	if d.Summary.RulesRemoved != 0 {
		t.Errorf("RulesRemoved = %d, want 0", d.Summary.RulesRemoved)
	}
	if d.Summary.RulesModified != 0 {
		t.Errorf("RulesModified = %d, want 0", d.Summary.RulesModified)
	}
	if d.Summary.IsIdentical {
		t.Error("should not be identical")
	}

	ids := make(map[string]bool)
	for _, r := range d.AddedRules {
		ids[r.ID] = true
	}
	if !ids["r2"] || !ids["r3"] {
		t.Errorf("expected r2 and r3 in AddedRules, got %v", ids)
	}
}

func TestDiffPolicies_AddDenyRuleNotBreaking(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, allowRule("r1", "", 10, []string{"file_read"}))
	new := diffTestPolicy("p", scope,
		allowRule("r1", "", 10, []string{"file_read"}),
		denyRule("r2", "", 100, []string{"shell_exec"}),
	)
	d := DiffPolicies(old, new)
	if d.Summary.BreakingChanges != 0 {
		t.Errorf("adding a deny rule should not be breaking, got %d", d.Summary.BreakingChanges)
	}
}

// --- Removed rules ---

func TestDiffPolicies_RemovedRulesOnly(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope,
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
		alertRule("r3", "", 50, []string{"dns_query"}),
	)
	new := diffTestPolicy("p", scope,
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)

	d := DiffPolicies(old, new)

	if d.Summary.RulesRemoved != 2 {
		t.Errorf("RulesRemoved = %d, want 2", d.Summary.RulesRemoved)
	}
	if d.Summary.RulesAdded != 0 {
		t.Errorf("RulesAdded = %d, want 0", d.Summary.RulesAdded)
	}

	ids := make(map[string]bool)
	for _, r := range d.RemovedRules {
		ids[r.ID] = true
	}
	if !ids["r2"] || !ids["r3"] {
		t.Errorf("expected r2 and r3 in RemovedRules, got %v", ids)
	}
}

func TestDiffPolicies_RemoveDenyRuleBreaking(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope,
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
	)
	new := diffTestPolicy("p", scope,
		allowRule("r2", "", 10, []string{"file_read"}),
	)

	d := DiffPolicies(old, new)

	if d.Summary.BreakingChanges != 1 {
		t.Errorf("removing a deny rule should be 1 breaking change, got %d", d.Summary.BreakingChanges)
	}
}

func TestDiffPolicies_RemoveAllowRuleNotBreaking(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope,
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
	)
	new := diffTestPolicy("p", scope,
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)

	d := DiffPolicies(old, new)

	if d.Summary.BreakingChanges != 0 {
		t.Errorf("removing an allow rule should not be breaking, got %d", d.Summary.BreakingChanges)
	}
}

// --- Modified rules: effect ---

func TestDiffPolicies_EffectChange(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))
	new := diffTestPolicy("p", scope, allowRule("r1", "", 100, []string{"shell_exec"}))

	d := DiffPolicies(old, new)

	if d.Summary.RulesModified != 1 {
		t.Fatalf("RulesModified = %d, want 1", d.Summary.RulesModified)
	}
	if d.Summary.EffectChanges != 1 {
		t.Errorf("EffectChanges = %d, want 1", d.Summary.EffectChanges)
	}

	found := false
	for _, fc := range d.ModifiedRules[0].Changes {
		if fc.Field == "effect" {
			found = true
			if fc.OldValue != "deny" || fc.NewValue != "allow" {
				t.Errorf("effect change: %q -> %q, want deny -> allow", fc.OldValue, fc.NewValue)
			}
		}
	}
	if !found {
		t.Error("expected an effect field diff")
	}
}

func TestDiffPolicies_DenyToAllowBreaking(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))
	new := diffTestPolicy("p", scope, allowRule("r1", "", 100, []string{"shell_exec"}))

	d := DiffPolicies(old, new)

	if d.Summary.BreakingChanges != 1 {
		t.Errorf("deny->allow should be 1 breaking change, got %d", d.Summary.BreakingChanges)
	}
}

func TestDiffPolicies_AllowToDenyNotBreaking(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, allowRule("r1", "", 10, []string{"file_read"}))
	new := diffTestPolicy("p", scope, denyRule("r1", "", 10, []string{"file_read"}))

	d := DiffPolicies(old, new)

	if d.Summary.BreakingChanges != 0 {
		t.Errorf("allow->deny should not be breaking, got %d", d.Summary.BreakingChanges)
	}
}

func TestDiffPolicies_DenyToAlertNotBreaking(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))
	new := diffTestPolicy("p", scope, alertRule("r1", "", 100, []string{"shell_exec"}))

	d := DiffPolicies(old, new)

	// deny -> alert is not "deny -> allow", so it does not count as breaking
	// under the stated rules.
	if d.Summary.BreakingChanges != 0 {
		t.Errorf("deny->alert should not be breaking per the rules, got %d", d.Summary.BreakingChanges)
	}
}

// --- Modified rules: priority ---

func TestDiffPolicies_PriorityChange(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))
	new := diffTestPolicy("p", scope, denyRule("r1", "", 50, []string{"shell_exec"}))

	d := DiffPolicies(old, new)

	if d.Summary.RulesModified != 1 {
		t.Fatalf("RulesModified = %d, want 1", d.Summary.RulesModified)
	}
	if d.Summary.PriorityChanges != 1 {
		t.Errorf("PriorityChanges = %d, want 1", d.Summary.PriorityChanges)
	}
}

func TestDiffPolicies_LowerDenyPriorityBreaking(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))
	new := diffTestPolicy("p", scope, denyRule("r1", "", 50, []string{"shell_exec"}))

	d := DiffPolicies(old, new)

	if d.Summary.BreakingChanges != 1 {
		t.Errorf("lowering deny priority should be 1 breaking change, got %d", d.Summary.BreakingChanges)
	}
}

func TestDiffPolicies_RaiseDenyPriorityNotBreaking(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 50, []string{"shell_exec"}))
	new := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))

	d := DiffPolicies(old, new)

	if d.Summary.BreakingChanges != 0 {
		t.Errorf("raising deny priority should not be breaking, got %d", d.Summary.BreakingChanges)
	}
}

// --- Modified rules: match.tools ---

func TestDiffPolicies_ToolListChange(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec", "http_request"}))
	new := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec", "dns_query"}))

	d := DiffPolicies(old, new)

	if d.Summary.RulesModified != 1 {
		t.Fatalf("RulesModified = %d, want 1", d.Summary.RulesModified)
	}

	found := false
	for _, fc := range d.ModifiedRules[0].Changes {
		if fc.Field == "match.tools" {
			found = true
		}
	}
	if !found {
		t.Error("expected match.tools in changes")
	}
}

func TestDiffPolicies_RemoveToolFromDenyBreaking(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec", "http_request"}))
	new := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))

	d := DiffPolicies(old, new)

	if d.Summary.BreakingChanges != 1 {
		t.Errorf("removing tool from deny match should be 1 breaking change, got %d", d.Summary.BreakingChanges)
	}
}

func TestDiffPolicies_AddToolToDenyNotBreaking(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))
	new := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec", "http_request"}))

	d := DiffPolicies(old, new)

	if d.Summary.BreakingChanges != 0 {
		t.Errorf("adding tool to deny match should not be breaking, got %d", d.Summary.BreakingChanges)
	}
}

// --- Scope change detection ---

func TestDiffPolicies_ScopeNameChange(t *testing.T) {
	old := diffTestPolicy("p", AgentScope{Name: "agent-a"},
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	new := diffTestPolicy("p", AgentScope{Name: "agent-b"},
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)

	d := DiffPolicies(old, new)

	if !d.ScopeChanged {
		t.Error("scope should be marked as changed")
	}
	if d.OldScope == nil || d.NewScope == nil {
		t.Fatal("OldScope and NewScope should be set")
	}
	if d.OldScope.Name != "agent-a" {
		t.Errorf("OldScope.Name = %q, want agent-a", d.OldScope.Name)
	}
	if d.NewScope.Name != "agent-b" {
		t.Errorf("NewScope.Name = %q, want agent-b", d.NewScope.Name)
	}
}

func TestDiffPolicies_ScopeTypeChange(t *testing.T) {
	old := diffTestPolicy("p", AgentScope{Name: "a", Type: "llm"},
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	new := diffTestPolicy("p", AgentScope{Name: "a", Type: "orchestrator"},
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)

	d := DiffPolicies(old, new)
	if !d.ScopeChanged {
		t.Error("scope type change should be detected")
	}
}

func TestDiffPolicies_ScopeToolsChange(t *testing.T) {
	old := diffTestPolicy("p", AgentScope{Name: "a", Tools: []string{"t1"}},
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	new := diffTestPolicy("p", AgentScope{Name: "a", Tools: []string{"t1", "t2"}},
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)

	d := DiffPolicies(old, new)
	if !d.ScopeChanged {
		t.Error("scope tools change should be detected")
	}
}

func TestDiffPolicies_ScopeUnchanged(t *testing.T) {
	scope := AgentScope{Name: "agent-a", Type: "llm"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))
	new := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))

	d := DiffPolicies(old, new)

	if d.ScopeChanged {
		t.Error("scope should not be marked as changed")
	}
	if d.OldScope != nil || d.NewScope != nil {
		t.Error("OldScope and NewScope should be nil when unchanged")
	}
}

// --- Empty policies ---

func TestDiffPolicies_BothNil(t *testing.T) {
	d := DiffPolicies(nil, nil)
	if !d.Summary.IsIdentical {
		t.Error("two nil policies should be identical")
	}
}

func TestDiffPolicies_OldNil(t *testing.T) {
	scope := AgentScope{Name: "*"}
	new := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))

	d := DiffPolicies(nil, new)

	if d.Summary.RulesAdded != 1 {
		t.Errorf("RulesAdded = %d, want 1", d.Summary.RulesAdded)
	}
}

func TestDiffPolicies_NewNil(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("p", scope, denyRule("r1", "", 100, []string{"shell_exec"}))

	d := DiffPolicies(old, nil)

	if d.Summary.RulesRemoved != 1 {
		t.Errorf("RulesRemoved = %d, want 1", d.Summary.RulesRemoved)
	}
	if d.Summary.BreakingChanges != 1 {
		t.Errorf("removing a deny rule by nil new = breaking, got %d", d.Summary.BreakingChanges)
	}
}

func TestDiffPolicies_BothEmpty(t *testing.T) {
	old := diffTestPolicy("p", AgentScope{Name: "*"})
	new := diffTestPolicy("p", AgentScope{Name: "*"})

	d := DiffPolicies(old, new)

	if !d.Summary.IsIdentical {
		t.Error("two empty policies should be identical")
	}
}

// --- Modified rules: description ---

func TestDiffPolicies_DescriptionChange(t *testing.T) {
	scope := AgentScope{Name: "*"}
	r1old := denyRule("r1", "Block shell", 100, []string{"shell_exec"})
	r1new := denyRule("r1", "Block all shells", 100, []string{"shell_exec"})

	old := diffTestPolicy("p", scope, r1old)
	new := diffTestPolicy("p", scope, r1new)

	d := DiffPolicies(old, new)

	if d.Summary.RulesModified != 1 {
		t.Fatalf("RulesModified = %d, want 1", d.Summary.RulesModified)
	}
	found := false
	for _, fc := range d.ModifiedRules[0].Changes {
		if fc.Field == "description" {
			found = true
		}
	}
	if !found {
		t.Error("expected description in changes")
	}
}

// --- Modified rules: conditions ---

func TestDiffPolicies_ConditionsChange(t *testing.T) {
	scope := AgentScope{Name: "*"}
	r1old := denyRule("r1", "", 100, []string{"shell_exec"})
	r1old.Conditions = []Condition{{Field: "elevated", Operator: "eq", Value: "true"}}
	r1new := denyRule("r1", "", 100, []string{"shell_exec"})
	r1new.Conditions = []Condition{{Field: "platform", Operator: "eq", Value: "linux"}}

	old := diffTestPolicy("p", scope, r1old)
	new := diffTestPolicy("p", scope, r1new)

	d := DiffPolicies(old, new)

	if d.Summary.RulesModified != 1 {
		t.Fatalf("RulesModified = %d, want 1", d.Summary.RulesModified)
	}
	found := false
	for _, fc := range d.ModifiedRules[0].Changes {
		if fc.Field == "conditions" {
			found = true
		}
	}
	if !found {
		t.Error("expected conditions in changes")
	}
}

// --- Modified rules: match.tactics, match.actions, match.targets ---

func TestDiffPolicies_TacticsChange(t *testing.T) {
	scope := AgentScope{Name: "*"}
	r1old := Rule{ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Tactics: []string{"exfiltration"}}}
	r1new := Rule{ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Tactics: []string{"exfiltration", "lateral-movement"}}}

	d := DiffPolicies(
		diffTestPolicy("p", scope, r1old),
		diffTestPolicy("p", scope, r1new),
	)

	if d.Summary.RulesModified != 1 {
		t.Fatalf("RulesModified = %d, want 1", d.Summary.RulesModified)
	}
	found := false
	for _, fc := range d.ModifiedRules[0].Changes {
		if fc.Field == "match.tactics" {
			found = true
		}
	}
	if !found {
		t.Error("expected match.tactics in changes")
	}
}

func TestDiffPolicies_ActionsChange(t *testing.T) {
	scope := AgentScope{Name: "*"}
	r1old := Rule{ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Actions: []string{"execute"}}}
	r1new := Rule{ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Actions: []string{"execute", "send"}}}

	d := DiffPolicies(
		diffTestPolicy("p", scope, r1old),
		diffTestPolicy("p", scope, r1new),
	)

	if d.Summary.RulesModified != 1 {
		t.Fatalf("RulesModified = %d, want 1", d.Summary.RulesModified)
	}
	found := false
	for _, fc := range d.ModifiedRules[0].Changes {
		if fc.Field == "match.actions" {
			found = true
		}
	}
	if !found {
		t.Error("expected match.actions in changes")
	}
}

func TestDiffPolicies_TargetsChange(t *testing.T) {
	scope := AgentScope{Name: "*"}
	r1old := Rule{ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Targets: []string{"http://evil.com/*"}}}
	r1new := Rule{ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Targets: []string{"http://evil.com/*", "http://bad.org/*"}}}

	d := DiffPolicies(
		diffTestPolicy("p", scope, r1old),
		diffTestPolicy("p", scope, r1new),
	)

	if d.Summary.RulesModified != 1 {
		t.Fatalf("RulesModified = %d, want 1", d.Summary.RulesModified)
	}
	found := false
	for _, fc := range d.ModifiedRules[0].Changes {
		if fc.Field == "match.targets" {
			found = true
		}
	}
	if !found {
		t.Error("expected match.targets in changes")
	}
}

// --- Complex multi-change diff ---

func TestDiffPolicies_ComplexMultiChange(t *testing.T) {
	scope := AgentScope{Name: "agent-a", Type: "llm"}
	newScope := AgentScope{Name: "agent-b", Type: "orchestrator"}

	old := diffTestPolicy("policy-v1", scope,
		denyRule("deny-shell", "", 100, []string{"shell_exec"}),
		denyRule("deny-http", "", 90, []string{"http_request"}),
		allowRule("allow-read", "", 10, []string{"file_read"}),
		alertRule("alert-dns", "", 50, []string{"dns_query"}),
	)

	new := diffTestPolicy("policy-v2", newScope,
		// deny-shell: effect changed to allow (breaking)
		allowRule("deny-shell", "", 100, []string{"shell_exec"}),
		// deny-http: removed (breaking)
		// allow-read: priority raised (not breaking)
		allowRule("allow-read", "", 20, []string{"file_read"}),
		// alert-dns: unchanged
		alertRule("alert-dns", "", 50, []string{"dns_query"}),
		// new rule added
		denyRule("deny-exfil", "", 80, []string{"send_email"}),
	)

	d := DiffPolicies(old, new)

	if d.OldName != "policy-v1" {
		t.Errorf("OldName = %q, want policy-v1", d.OldName)
	}
	if d.NewName != "policy-v2" {
		t.Errorf("NewName = %q, want policy-v2", d.NewName)
	}
	if !d.ScopeChanged {
		t.Error("scope should be changed")
	}
	if d.Summary.RulesAdded != 1 {
		t.Errorf("RulesAdded = %d, want 1", d.Summary.RulesAdded)
	}
	if d.Summary.RulesRemoved != 1 {
		t.Errorf("RulesRemoved = %d, want 1", d.Summary.RulesRemoved)
	}
	if d.Summary.RulesModified != 2 {
		t.Errorf("RulesModified = %d, want 2", d.Summary.RulesModified)
	}
	if d.Summary.EffectChanges != 1 {
		t.Errorf("EffectChanges = %d, want 1", d.Summary.EffectChanges)
	}
	if d.Summary.PriorityChanges != 1 {
		t.Errorf("PriorityChanges = %d, want 1", d.Summary.PriorityChanges)
	}
	// Breaking: deny-shell deny->allow, deny-http removed
	if d.Summary.BreakingChanges != 2 {
		t.Errorf("BreakingChanges = %d, want 2", d.Summary.BreakingChanges)
	}
	if d.Summary.TotalChanges != 4 {
		t.Errorf("TotalChanges = %d, want 4", d.Summary.TotalChanges)
	}
	if d.Summary.IsIdentical {
		t.Error("should not be identical")
	}
}

// --- Policy name change ---

func TestDiffPolicies_NameChange(t *testing.T) {
	scope := AgentScope{Name: "*"}
	old := diffTestPolicy("old-name", scope, denyRule("r1", "", 100, []string{"shell_exec"}))
	new := diffTestPolicy("new-name", scope, denyRule("r1", "", 100, []string{"shell_exec"}))

	d := DiffPolicies(old, new)

	if d.OldName != "old-name" {
		t.Errorf("OldName = %q, want old-name", d.OldName)
	}
	if d.NewName != "new-name" {
		t.Errorf("NewName = %q, want new-name", d.NewName)
	}
}

// --- FormatPolicyDiff ---

func TestFormatPolicyDiff_Identical(t *testing.T) {
	d := &PolicyDiff{
		OldName: "test",
		NewName: "test",
		Summary: DiffSummary{IsIdentical: true},
	}

	out := FormatPolicyDiff(d)

	if !strings.Contains(out, "Policy Diff") {
		t.Error("output should contain header")
	}
	if !strings.Contains(out, "identical") {
		t.Error("output should mention identical")
	}
}

func TestFormatPolicyDiff_WithChanges(t *testing.T) {
	d := &PolicyDiff{
		OldName: "v1",
		NewName: "v2",
		AddedRules: []Rule{
			{ID: "r-new", Effect: "deny", Priority: 80, Match: RuleMatch{Tools: []string{"shell_exec"}}},
		},
		RemovedRules: []Rule{
			{ID: "r-old", Effect: "deny", Priority: 100},
		},
		ModifiedRules: []RuleChange{
			{
				RuleID:  "r-mod",
				OldRule: Rule{ID: "r-mod", Effect: "deny", Priority: 100},
				NewRule: Rule{ID: "r-mod", Effect: "allow", Priority: 100},
				Changes: []FieldDiff{
					{Field: "effect", OldValue: "deny", NewValue: "allow"},
				},
			},
		},
		Summary: DiffSummary{
			TotalChanges:    3,
			RulesAdded:      1,
			RulesRemoved:    1,
			RulesModified:   1,
			BreakingChanges: 2,
		},
	}

	out := FormatPolicyDiff(d)

	if !strings.Contains(out, "v1") || !strings.Contains(out, "v2") {
		t.Error("output should contain old and new names")
	}
	if !strings.Contains(out, "1 added") {
		t.Error("output should show added count")
	}
	if !strings.Contains(out, "1 removed") {
		t.Error("output should show removed count")
	}
	if !strings.Contains(out, "1 modified") {
		t.Error("output should show modified count")
	}
	if !strings.Contains(out, "2 breaking") {
		t.Error("output should show breaking count")
	}
	if !strings.Contains(out, "+ r-new") {
		t.Error("output should show added rule with + prefix")
	}
	if !strings.Contains(out, "r-old") {
		t.Error("output should show removed rule")
	}
	if !strings.Contains(out, "⚠") {
		t.Error("output should contain warning icon for breaking changes")
	}
}

func TestFormatPolicyDiff_ScopeChange(t *testing.T) {
	d := &PolicyDiff{
		OldName:      "p",
		NewName:      "p",
		ScopeChanged: true,
		OldScope:     &AgentScope{Name: "agent-a", Type: "llm"},
		NewScope:     &AgentScope{Name: "agent-b", Type: "orchestrator"},
		Summary: DiffSummary{
			TotalChanges: 0,
		},
	}

	out := FormatPolicyDiff(d)

	if !strings.Contains(out, "Scope Changed") {
		t.Error("output should show scope changes")
	}
	if !strings.Contains(out, "agent-a") || !strings.Contains(out, "agent-b") {
		t.Error("output should show old and new scope names")
	}
}

func TestFormatPolicyDiff_ModifiedRuleFields(t *testing.T) {
	d := &PolicyDiff{
		OldName: "p",
		NewName: "p",
		ModifiedRules: []RuleChange{
			{
				RuleID:  "r1",
				OldRule: Rule{ID: "r1", Effect: "deny", Priority: 100},
				NewRule: Rule{ID: "r1", Effect: "deny", Priority: 50},
				Changes: []FieldDiff{
					{Field: "priority", OldValue: "100", NewValue: "50"},
				},
			},
		},
		Summary: DiffSummary{
			TotalChanges:    1,
			RulesModified:   1,
			PriorityChanges: 1,
			BreakingChanges: 1,
		},
	}

	out := FormatPolicyDiff(d)

	if !strings.Contains(out, "priority") {
		t.Error("output should show changed field name")
	}
	if !strings.Contains(out, "100") || !strings.Contains(out, "50") {
		t.Error("output should show old and new priority values")
	}
}

// --- Helper function tests ---

func TestDiff_StringSliceEqual(t *testing.T) {
	tests := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{}, []string{}, true},
		{nil, []string{}, true},
		{[]string{"a"}, []string{"a"}, true},
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a"}, []string{"b"}, false},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{"a", "b"}, []string{"b", "a"}, false}, // order matters
	}

	for _, tt := range tests {
		got := stringSliceEqual(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("stringSliceEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestDiff_ConditionsEqual(t *testing.T) {
	c1 := []Condition{{Field: "elevated", Operator: "eq", Value: "true"}}
	c2 := []Condition{{Field: "elevated", Operator: "eq", Value: "true"}}
	c3 := []Condition{{Field: "platform", Operator: "eq", Value: "linux"}}

	if !conditionsEqual(c1, c2) {
		t.Error("identical conditions should be equal")
	}
	if conditionsEqual(c1, c3) {
		t.Error("different conditions should not be equal")
	}
	if conditionsEqual(c1, nil) {
		t.Error("non-empty vs nil should not be equal")
	}
	if !conditionsEqual(nil, nil) {
		t.Error("both nil should be equal")
	}
}

func TestDiff_FormatConditions(t *testing.T) {
	if formatConditions(nil) != "(none)" {
		t.Error("nil conditions should format as (none)")
	}
	conds := []Condition{
		{Field: "elevated", Operator: "eq", Value: "true"},
		{Field: "platform", Operator: "in", Value: "linux,windows"},
	}
	out := formatConditions(conds)
	if !strings.Contains(out, "elevated eq true") {
		t.Errorf("formatConditions missing first condition in %q", out)
	}
	if !strings.Contains(out, "platform in linux,windows") {
		t.Errorf("formatConditions missing second condition in %q", out)
	}
}

func TestDiff_IsSubsetRemoved(t *testing.T) {
	if isSubsetRemoved([]string{"a", "b"}, []string{"a", "b"}) {
		t.Error("same set should not be subset-removed")
	}
	if !isSubsetRemoved([]string{"a", "b"}, []string{"a"}) {
		t.Error("removing b should be detected")
	}
	if isSubsetRemoved([]string{"a"}, []string{"a", "b"}) {
		t.Error("adding items should not be subset-removed")
	}
	if isSubsetRemoved(nil, nil) {
		t.Error("both nil should not be subset-removed")
	}
}
