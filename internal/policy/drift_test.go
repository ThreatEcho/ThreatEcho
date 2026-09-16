// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"math"
	"strings"
	"testing"
)

// driftTestPolicy builds a minimal valid policy for drift testing.
func driftTestPolicy(name string, rules ...Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta: PolicyMeta{
			Name:        name,
			Description: "test policy for drift",
		},
		Agent: AgentScope{Name: "*"},
		Rules: rules,
	}
}

// ---------------------------------------------------------------------------
// Identical policies — no drift
// ---------------------------------------------------------------------------

func TestDetectDrift_IdenticalPolicies(t *testing.T) {
	p := driftTestPolicy("baseline",
		denyRule("r1", "Block shell", 100, []string{"shell_exec"}),
		allowRule("r2", "Allow reads", 10, []string{"file_read"}),
	)

	r := DetectDrift(p, p)

	if len(r.Findings) != 0 {
		t.Errorf("identical policies should produce 0 findings, got %d", len(r.Findings))
	}
	if r.DriftScore != 0.0 {
		t.Errorf("drift score should be 0.0, got %.2f", r.DriftScore)
	}
	if r.BaselineRules != 2 || r.CurrentRules != 2 {
		t.Errorf("rule counts: baseline=%d current=%d, want 2/2", r.BaselineRules, r.CurrentRules)
	}
	if r.Summary != "No drift detected" {
		t.Errorf("summary = %q, want 'No drift detected'", r.Summary)
	}
}

func TestDetectDrift_IdenticalStructurallySeparate(t *testing.T) {
	baseline := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	current := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)

	r := DetectDrift(baseline, current)

	if len(r.Findings) != 0 {
		t.Errorf("structurally identical separate policies should have 0 findings, got %d", len(r.Findings))
	}
}

// ---------------------------------------------------------------------------
// Added rules
// ---------------------------------------------------------------------------

func TestDetectDrift_RuleAdded(t *testing.T) {
	baseline := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	current := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
		alertRule("r2", "New alert", 50, []string{"dns_query"}),
	)

	r := DetectDrift(baseline, current)

	addedCount := 0
	for _, f := range r.Findings {
		if f.Type == DriftRuleAdded {
			addedCount++
			if f.RuleID != "r2" {
				t.Errorf("added rule ID = %q, want r2", f.RuleID)
			}
		}
	}
	if addedCount != 1 {
		t.Errorf("expected 1 added finding, got %d", addedCount)
	}
	if r.BaselineRules != 1 || r.CurrentRules != 2 {
		t.Errorf("rule counts: baseline=%d current=%d, want 1/2", r.BaselineRules, r.CurrentRules)
	}
}

func TestDetectDrift_DenyRuleAdded_MediumSeverity(t *testing.T) {
	baseline := driftTestPolicy("pol",
		allowRule("r1", "", 10, []string{"file_read"}),
	)
	current := driftTestPolicy("pol",
		allowRule("r1", "", 10, []string{"file_read"}),
		denyRule("r2", "", 100, []string{"shell_exec"}),
	)

	r := DetectDrift(baseline, current)

	for _, f := range r.Findings {
		if f.Type == DriftRuleAdded && f.RuleID == "r2" {
			if f.Severity != DriftMedium {
				t.Errorf("added deny rule severity = %q, want medium", f.Severity)
			}
			return
		}
	}
	t.Error("expected an added rule finding for r2")
}

func TestDetectDrift_AllowRuleAdded_LowSeverity(t *testing.T) {
	baseline := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	current := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
	)

	r := DetectDrift(baseline, current)

	for _, f := range r.Findings {
		if f.Type == DriftRuleAdded && f.RuleID == "r2" {
			if f.Severity != DriftLow {
				t.Errorf("added allow rule severity = %q, want low", f.Severity)
			}
			return
		}
	}
	t.Error("expected an added rule finding for r2")
}

// ---------------------------------------------------------------------------
// Removed rules
// ---------------------------------------------------------------------------

func TestDetectDrift_DenyRuleRemoved_Critical(t *testing.T) {
	baseline := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
	)
	current := driftTestPolicy("pol",
		allowRule("r2", "", 10, []string{"file_read"}),
	)

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.Type == DriftRuleRemoved && f.RuleID == "r1" {
			found = true
			if f.Severity != DriftCritical {
				t.Errorf("removed deny rule severity = %q, want critical", f.Severity)
			}
			if !strings.Contains(f.Impact, "unprotected") {
				t.Errorf("impact should mention unprotected, got %q", f.Impact)
			}
		}
	}
	if !found {
		t.Error("expected a removed rule finding for r1")
	}
	if r.CriticalCount < 1 {
		t.Errorf("CriticalCount = %d, want >= 1", r.CriticalCount)
	}
}

func TestDetectDrift_AllowRuleRemoved_Medium(t *testing.T) {
	baseline := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
	)
	current := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)

	r := DetectDrift(baseline, current)

	for _, f := range r.Findings {
		if f.Type == DriftRuleRemoved && f.RuleID == "r2" {
			if f.Severity != DriftMedium {
				t.Errorf("removed allow rule severity = %q, want medium", f.Severity)
			}
			return
		}
	}
	t.Error("expected a removed rule finding for r2")
}

// ---------------------------------------------------------------------------
// Effect changes
// ---------------------------------------------------------------------------

func TestDetectDrift_EffectDenyToAllow_Critical(t *testing.T) {
	baseline := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	current := driftTestPolicy("pol",
		allowRule("r1", "", 100, []string{"shell_exec"}),
	)

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.Type == DriftEffectChanged && f.RuleID == "r1" {
			found = true
			if f.Severity != DriftCritical {
				t.Errorf("deny→allow severity = %q, want critical", f.Severity)
			}
			if f.Before != "deny" || f.After != "allow" {
				t.Errorf("before=%q after=%q, want deny/allow", f.Before, f.After)
			}
		}
	}
	if !found {
		t.Error("expected an effect_changed finding for r1")
	}
}

func TestDetectDrift_EffectAllowToDeny_High(t *testing.T) {
	baseline := driftTestPolicy("pol",
		allowRule("r1", "", 10, []string{"file_read"}),
	)
	current := driftTestPolicy("pol",
		denyRule("r1", "", 10, []string{"file_read"}),
	)

	r := DetectDrift(baseline, current)

	for _, f := range r.Findings {
		if f.Type == DriftEffectChanged && f.RuleID == "r1" {
			if f.Severity != DriftHigh {
				t.Errorf("allow→deny severity = %q, want high", f.Severity)
			}
			return
		}
	}
	t.Error("expected an effect_changed finding for r1")
}

func TestDetectDrift_EffectDenyToAlert_High(t *testing.T) {
	baseline := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	current := driftTestPolicy("pol",
		alertRule("r1", "", 100, []string{"shell_exec"}),
	)

	r := DetectDrift(baseline, current)

	for _, f := range r.Findings {
		if f.Type == DriftEffectChanged && f.RuleID == "r1" {
			if f.Severity != DriftHigh {
				t.Errorf("deny→alert severity = %q, want high", f.Severity)
			}
			return
		}
	}
	t.Error("expected an effect_changed finding for r1")
}

// ---------------------------------------------------------------------------
// Scope widened / narrowed
// ---------------------------------------------------------------------------

func TestDetectDrift_ScopeWidened(t *testing.T) {
	baseline := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Tools: []string{"file_read"}},
	})
	current := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Tools: []string{"file_*"}},
	})

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.RuleID == "r1" && f.Type == DriftScopeWidened {
			found = true
			if f.Severity != DriftHigh {
				t.Errorf("widened deny scope severity = %q, want high", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected a scope_widened finding for r1")
	}
}

func TestDetectDrift_ScopeNarrowed(t *testing.T) {
	baseline := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Tools: []string{"file_*"}},
	})
	current := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Tools: []string{"file_read"}},
	})

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.RuleID == "r1" && f.Type == DriftScopeNarrowed {
			found = true
			if f.Severity != DriftMedium {
				t.Errorf("narrowed deny scope severity = %q, want medium", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected a scope_narrowed finding for r1")
	}
}

func TestDetectDrift_ScopeWidenedWildcard(t *testing.T) {
	baseline := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Tools: []string{"shell_exec"}},
	})
	current := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Tools: []string{"*"}},
	})

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.RuleID == "r1" && f.Type == DriftScopeWidened {
			found = true
		}
	}
	if !found {
		t.Error("specific→wildcard should be scope_widened")
	}
}

func TestDetectDrift_ScopeOnAllowRule_Low(t *testing.T) {
	baseline := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "allow", Priority: 10,
		Match: RuleMatch{Tools: []string{"file_read"}},
	})
	current := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "allow", Priority: 10,
		Match: RuleMatch{Tools: []string{"file_*"}},
	})

	r := DetectDrift(baseline, current)

	for _, f := range r.Findings {
		if f.RuleID == "r1" && (f.Type == DriftScopeWidened || f.Type == DriftScopeNarrowed || f.Type == DriftRuleModified) {
			if f.Severity != DriftLow {
				t.Errorf("allow rule scope change severity = %q, want low", f.Severity)
			}
			return
		}
	}
	t.Error("expected a scope change finding for r1")
}

// ---------------------------------------------------------------------------
// Priority shifts
// ---------------------------------------------------------------------------

func TestDetectDrift_PriorityShift(t *testing.T) {
	baseline := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	current := driftTestPolicy("pol",
		denyRule("r1", "", 50, []string{"shell_exec"}),
	)

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.Type == DriftPriorityShift && f.RuleID == "r1" {
			found = true
			if f.Severity != DriftMedium {
				t.Errorf("priority shift severity = %q, want medium", f.Severity)
			}
			if f.Before != "100" || f.After != "50" {
				t.Errorf("before=%q after=%q, want 100/50", f.Before, f.After)
			}
		}
	}
	if !found {
		t.Error("expected a priority_shift finding for r1")
	}
}

// ---------------------------------------------------------------------------
// Condition changes
// ---------------------------------------------------------------------------

func TestDetectDrift_ConditionChanged(t *testing.T) {
	r1base := denyRule("r1", "", 100, []string{"shell_exec"})
	r1base.Conditions = []Condition{{Field: "elevated", Operator: "eq", Value: "true"}}

	r1curr := denyRule("r1", "", 100, []string{"shell_exec"})
	r1curr.Conditions = []Condition{{Field: "platform", Operator: "eq", Value: "linux"}}

	baseline := driftTestPolicy("pol", r1base)
	current := driftTestPolicy("pol", r1curr)

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.Type == DriftConditionChanged && f.RuleID == "r1" {
			found = true
			if f.Severity != DriftMedium {
				t.Errorf("condition_changed severity = %q, want medium", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected a condition_changed finding for r1")
	}
}

func TestDetectDrift_ConditionsRemoved(t *testing.T) {
	r1base := denyRule("r1", "", 100, []string{"shell_exec"})
	r1base.Conditions = []Condition{{Field: "elevated", Operator: "eq", Value: "true"}}

	r1curr := denyRule("r1", "", 100, []string{"shell_exec"})
	// No conditions.

	baseline := driftTestPolicy("pol", r1base)
	current := driftTestPolicy("pol", r1curr)

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.Type == DriftConditionChanged && f.RuleID == "r1" {
			found = true
			if !strings.Contains(f.Impact, "unconditionally") {
				t.Errorf("impact should mention unconditionally, got %q", f.Impact)
			}
		}
	}
	if !found {
		t.Error("expected a condition_changed finding for r1")
	}
}

// ---------------------------------------------------------------------------
// Meta changes
// ---------------------------------------------------------------------------

func TestDetectDrift_MetaNameChanged(t *testing.T) {
	baseline := driftTestPolicy("baseline-v1",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)
	current := driftTestPolicy("baseline-v2",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.Type == DriftMetaChanged && strings.Contains(f.Description, "name") {
			found = true
			if f.Severity != DriftInfo {
				t.Errorf("meta_changed severity = %q, want info", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected a meta_changed finding for name")
	}
}

func TestDetectDrift_MetaDescriptionChanged(t *testing.T) {
	baseline := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "pol", Description: "old desc"},
		Agent:      AgentScope{Name: "*"},
		Rules:      []Rule{denyRule("r1", "", 100, []string{"shell_exec"})},
	}
	current := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "pol", Description: "new desc"},
		Agent:      AgentScope{Name: "*"},
		Rules:      []Rule{denyRule("r1", "", 100, []string{"shell_exec"})},
	}

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.Type == DriftMetaChanged && strings.Contains(f.Description, "description") {
			found = true
		}
	}
	if !found {
		t.Error("expected a meta_changed finding for description")
	}
}

// ---------------------------------------------------------------------------
// Multiple simultaneous drifts
// ---------------------------------------------------------------------------

func TestDetectDrift_MultipleDrifts(t *testing.T) {
	baseline := driftTestPolicy("pol-v1",
		denyRule("deny-shell", "", 100, []string{"shell_exec"}),
		denyRule("deny-http", "", 90, []string{"http_request"}),
		allowRule("allow-read", "", 10, []string{"file_read"}),
	)
	current := driftTestPolicy("pol-v2",
		// deny-shell changed to allow (critical)
		allowRule("deny-shell", "", 100, []string{"shell_exec"}),
		// deny-http removed (critical)
		// allow-read priority changed (medium)
		allowRule("allow-read", "", 20, []string{"file_read"}),
		// new deny rule (medium)
		denyRule("deny-exfil", "", 80, []string{"send_email"}),
	)

	r := DetectDrift(baseline, current)

	if r.BaselinePolicy != "pol-v1" || r.CurrentPolicy != "pol-v2" {
		t.Errorf("policy names: baseline=%q current=%q", r.BaselinePolicy, r.CurrentPolicy)
	}

	// Expected findings:
	// - meta name changed (info)
	// - deny-http removed (critical)
	// - deny-exfil added (medium)
	// - deny-shell effect changed deny→allow (critical)
	// - allow-read priority shift (medium)
	if len(r.Findings) < 4 {
		t.Errorf("expected at least 4 findings, got %d", len(r.Findings))
	}

	if r.CriticalCount < 2 {
		t.Errorf("CriticalCount = %d, want >= 2", r.CriticalCount)
	}

	// Drift score should be non-trivial with 2 criticals.
	if r.DriftScore < 0.40 {
		t.Errorf("DriftScore = %.2f, expected >= 0.40 with 2 criticals", r.DriftScore)
	}

	if !strings.Contains(r.Summary, "critical") {
		t.Errorf("summary should mention critical, got %q", r.Summary)
	}
}

// ---------------------------------------------------------------------------
// Nil / empty policy handling
// ---------------------------------------------------------------------------

func TestDetectDrift_BothNil(t *testing.T) {
	r := DetectDrift(nil, nil)

	if len(r.Findings) != 0 {
		t.Errorf("both nil should produce 0 findings, got %d", len(r.Findings))
	}
	if r.DriftScore != 0.0 {
		t.Errorf("drift score should be 0.0, got %.2f", r.DriftScore)
	}
}

func TestDetectDrift_BaselineNil(t *testing.T) {
	current := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)

	r := DetectDrift(nil, current)

	addedCount := 0
	for _, f := range r.Findings {
		if f.Type == DriftRuleAdded {
			addedCount++
		}
	}
	if addedCount != 1 {
		t.Errorf("expected 1 added finding when baseline is nil, got %d", addedCount)
	}
}

func TestDetectDrift_CurrentNil(t *testing.T) {
	baseline := driftTestPolicy("pol",
		denyRule("r1", "", 100, []string{"shell_exec"}),
	)

	r := DetectDrift(baseline, nil)

	removedCount := 0
	for _, f := range r.Findings {
		if f.Type == DriftRuleRemoved {
			removedCount++
		}
	}
	if removedCount != 1 {
		t.Errorf("expected 1 removed finding when current is nil, got %d", removedCount)
	}
	if r.CriticalCount < 1 {
		t.Errorf("removing a deny rule should be critical, CriticalCount = %d", r.CriticalCount)
	}
}

func TestDetectDrift_BothEmpty(t *testing.T) {
	baseline := driftTestPolicy("pol")
	current := driftTestPolicy("pol")

	r := DetectDrift(baseline, current)

	if len(r.Findings) != 0 {
		t.Errorf("both empty should produce 0 findings, got %d", len(r.Findings))
	}
}

// ---------------------------------------------------------------------------
// Drift score calculation
// ---------------------------------------------------------------------------

func TestScoreDrift_Empty(t *testing.T) {
	score := scoreDrift(nil)
	if score != 0.0 {
		t.Errorf("empty findings score = %.2f, want 0.0", score)
	}
}

func TestScoreDrift_SingleCritical(t *testing.T) {
	findings := []DriftFinding{
		{Severity: DriftCritical},
	}
	score := scoreDrift(findings)
	if math.Abs(score-0.25) > 0.001 {
		t.Errorf("1 critical score = %.4f, want 0.25", score)
	}
}

func TestScoreDrift_CapAtOne(t *testing.T) {
	// 5 criticals = 5 * 0.25 = 1.25 → capped at 1.0.
	findings := make([]DriftFinding, 5)
	for i := range findings {
		findings[i].Severity = DriftCritical
	}
	score := scoreDrift(findings)
	if score != 1.0 {
		t.Errorf("5 criticals score = %.2f, want 1.0", score)
	}
}

func TestScoreDrift_MixedSeverities(t *testing.T) {
	findings := []DriftFinding{
		{Severity: DriftCritical}, // 0.25
		{Severity: DriftHigh},     // 0.15
		{Severity: DriftMedium},   // 0.08
		{Severity: DriftLow},      // 0.03
		{Severity: DriftInfo},     // 0.01
	}
	score := scoreDrift(findings)
	expected := 0.25 + 0.15 + 0.08 + 0.03 + 0.01
	if math.Abs(score-expected) > 0.001 {
		t.Errorf("mixed score = %.4f, want %.4f", score, expected)
	}
}

func TestScoreDrift_InfoOnly(t *testing.T) {
	findings := []DriftFinding{
		{Severity: DriftInfo},
		{Severity: DriftInfo},
	}
	score := scoreDrift(findings)
	expected := 0.02
	if math.Abs(score-expected) > 0.001 {
		t.Errorf("2 info score = %.4f, want %.4f", score, expected)
	}
}

// ---------------------------------------------------------------------------
// Severity classification
// ---------------------------------------------------------------------------

func TestClassifyDrift_EffectDenyToAllow(t *testing.T) {
	f := DriftFinding{Type: DriftEffectChanged, Before: "deny", After: "allow"}
	if classifyDrift(f) != DriftCritical {
		t.Errorf("deny→allow = %s, want critical", classifyDrift(f))
	}
}

func TestClassifyDrift_EffectAllowToDeny(t *testing.T) {
	f := DriftFinding{Type: DriftEffectChanged, Before: "allow", After: "deny"}
	if classifyDrift(f) != DriftHigh {
		t.Errorf("allow→deny = %s, want high", classifyDrift(f))
	}
}

func TestClassifyDrift_RuleRemovedDeny(t *testing.T) {
	f := DriftFinding{Type: DriftRuleRemoved, Before: "r1 (effect=deny, priority=100)"}
	if classifyDrift(f) != DriftCritical {
		t.Errorf("removed deny rule = %s, want critical", classifyDrift(f))
	}
}

func TestClassifyDrift_RuleRemovedAllow(t *testing.T) {
	f := DriftFinding{Type: DriftRuleRemoved, Before: "r1 (effect=allow, priority=10)"}
	if classifyDrift(f) != DriftMedium {
		t.Errorf("removed allow rule = %s, want medium", classifyDrift(f))
	}
}

func TestClassifyDrift_MetaChanged(t *testing.T) {
	f := DriftFinding{Type: DriftMetaChanged}
	if classifyDrift(f) != DriftInfo {
		t.Errorf("meta_changed = %s, want info", classifyDrift(f))
	}
}

func TestClassifyDrift_PriorityShift(t *testing.T) {
	f := DriftFinding{Type: DriftPriorityShift}
	if classifyDrift(f) != DriftMedium {
		t.Errorf("priority_shift = %s, want medium", classifyDrift(f))
	}
}

func TestClassifyDrift_ConditionChanged(t *testing.T) {
	f := DriftFinding{Type: DriftConditionChanged}
	if classifyDrift(f) != DriftMedium {
		t.Errorf("condition_changed = %s, want medium", classifyDrift(f))
	}
}

// ---------------------------------------------------------------------------
// compareRuleScope
// ---------------------------------------------------------------------------

func TestCompareRuleScope_Widened(t *testing.T) {
	baseline := Rule{Match: RuleMatch{Tools: []string{"file_read"}}}
	current := Rule{Match: RuleMatch{Tools: []string{"file_*"}}}

	dt := compareRuleScope(baseline, current)
	if dt != DriftScopeWidened {
		t.Errorf("file_read → file_* = %s, want scope_widened", dt)
	}
}

func TestCompareRuleScope_Narrowed(t *testing.T) {
	baseline := Rule{Match: RuleMatch{Tools: []string{"file_*"}}}
	current := Rule{Match: RuleMatch{Tools: []string{"file_read"}}}

	dt := compareRuleScope(baseline, current)
	if dt != DriftScopeNarrowed {
		t.Errorf("file_* → file_read = %s, want scope_narrowed", dt)
	}
}

func TestCompareRuleScope_WildcardToSpecific(t *testing.T) {
	baseline := Rule{Match: RuleMatch{Tools: []string{"*"}}}
	current := Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}

	dt := compareRuleScope(baseline, current)
	if dt != DriftScopeNarrowed {
		t.Errorf("* → shell_exec = %s, want scope_narrowed", dt)
	}
}

func TestCompareRuleScope_SpecificToWildcard(t *testing.T) {
	baseline := Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}
	current := Rule{Match: RuleMatch{Tools: []string{"*"}}}

	dt := compareRuleScope(baseline, current)
	if dt != DriftScopeWidened {
		t.Errorf("shell_exec → * = %s, want scope_widened", dt)
	}
}

func TestCompareRuleScope_DisjointPatterns(t *testing.T) {
	baseline := Rule{Match: RuleMatch{Tools: []string{"file_read"}}}
	current := Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}

	dt := compareRuleScope(baseline, current)
	if dt != DriftRuleModified {
		t.Errorf("disjoint patterns = %s, want rule_modified", dt)
	}
}

// ---------------------------------------------------------------------------
// FormatDriftReport
// ---------------------------------------------------------------------------

func TestFormatDriftReport_NoDrift(t *testing.T) {
	r := &DriftReport{
		BaselinePolicy: "pol-v1",
		CurrentPolicy:  "pol-v1",
		BaselineRules:  3,
		CurrentRules:   3,
		DriftScore:     0.0,
		Summary:        "No drift detected",
	}

	out := FormatDriftReport(r)

	if !strings.Contains(out, "POLICY DRIFT REPORT") {
		t.Error("output should contain header")
	}
	if !strings.Contains(out, "No drift detected") {
		t.Error("output should say no drift detected")
	}
	if !strings.Contains(out, "pol-v1") {
		t.Error("output should contain policy name")
	}
}

func TestFormatDriftReport_WithFindings(t *testing.T) {
	r := &DriftReport{
		BaselinePolicy: "pol-v1",
		CurrentPolicy:  "pol-v2",
		BaselineRules:  3,
		CurrentRules:   2,
		Findings: []DriftFinding{
			{Type: DriftRuleRemoved, Severity: DriftCritical, RuleID: "r1",
				Description: "Rule r1 removed", Impact: "Deny rule removed"},
			{Type: DriftEffectChanged, Severity: DriftCritical, RuleID: "r2",
				Description: "Effect changed deny to allow", Impact: "Security weakened"},
		},
		CriticalCount: 2,
		DriftScore:    0.50,
		Summary:       "2 drifts detected (2 critical): critical rules r1, r2",
	}

	out := FormatDriftReport(r)

	if !strings.Contains(out, "SEVERITY COUNTS") {
		t.Error("output should contain severity counts section")
	}
	if !strings.Contains(out, "FINDINGS") {
		t.Error("output should contain findings section")
	}
	if !strings.Contains(out, "critical") {
		t.Error("output should mention critical severity")
	}
	if !strings.Contains(out, "r1") {
		t.Error("output should contain rule ID r1")
	}
	if !strings.Contains(out, "0.50") {
		t.Error("output should contain drift score")
	}
}

func TestFormatDriftReport_ContainsBoxDrawing(t *testing.T) {
	r := &DriftReport{
		BaselinePolicy: "test",
		CurrentPolicy:  "test",
	}
	out := FormatDriftReport(r)

	for _, ch := range []string{"┌", "┐", "├", "┤", "└", "┘", "│"} {
		if !strings.Contains(out, ch) {
			t.Errorf("output missing box-drawing character %q", ch)
		}
	}
}

// ---------------------------------------------------------------------------
// SummarizeDrift
// ---------------------------------------------------------------------------

func TestSummarizeDrift_NoDrift(t *testing.T) {
	r := &DriftReport{}
	s := SummarizeDrift(r)
	if s != "No drift detected" {
		t.Errorf("summary = %q, want 'No drift detected'", s)
	}
}

func TestSummarizeDrift_WithCritical(t *testing.T) {
	r := &DriftReport{
		Findings: []DriftFinding{
			{Severity: DriftCritical, RuleID: "deny-shell"},
			{Severity: DriftCritical, RuleID: "deny-http"},
		},
		CriticalCount: 2,
	}
	s := SummarizeDrift(r)
	if !strings.Contains(s, "2 critical") {
		t.Errorf("summary should mention 2 critical, got %q", s)
	}
	if !strings.Contains(s, "deny-shell") {
		t.Errorf("summary should mention deny-shell, got %q", s)
	}
	if !strings.Contains(s, "deny-http") {
		t.Errorf("summary should mention deny-http, got %q", s)
	}
}

// ---------------------------------------------------------------------------
// Tactics/targets/actions changes detected
// ---------------------------------------------------------------------------

func TestDetectDrift_TacticsChanged(t *testing.T) {
	baseline := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Tactics: []string{"exfiltration"}},
	})
	current := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Tactics: []string{"exfiltration", "lateral-movement"}},
	})

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.RuleID == "r1" && f.Type == DriftRuleModified {
			found = true
		}
	}
	if !found {
		t.Error("expected a rule_modified finding for tactics change")
	}
}

func TestDetectDrift_TargetsChanged(t *testing.T) {
	baseline := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Targets: []string{"http://evil.com/*"}},
	})
	current := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Targets: []string{"http://evil.com/*", "http://bad.org/*"}},
	})

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.RuleID == "r1" && f.Type == DriftRuleModified {
			found = true
		}
	}
	if !found {
		t.Error("expected a rule_modified finding for targets change")
	}
}

func TestDetectDrift_ActionsChanged(t *testing.T) {
	baseline := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Actions: []string{"execute"}},
	})
	current := driftTestPolicy("pol", Rule{
		ID: "r1", Effect: "deny", Priority: 100,
		Match: RuleMatch{Actions: []string{"execute", "send"}},
	})

	r := DetectDrift(baseline, current)

	found := false
	for _, f := range r.Findings {
		if f.RuleID == "r1" && f.Type == DriftRuleModified {
			found = true
		}
	}
	if !found {
		t.Error("expected a rule_modified finding for actions change")
	}
}
