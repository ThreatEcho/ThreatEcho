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
// Helpers — prefixed with "inh" to avoid collisions with trace_test.go
// helpers (denyRule, allowRule, alertRule) which have different signatures.
// ---------------------------------------------------------------------------

// inhPolicy creates a minimal policy with the given name and rules.
func inhPolicy(name string, rules ...Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta: PolicyMeta{
			Name:        name,
			Description: "Test policy: " + name,
		},
		Agent: AgentScope{
			Name: "test-agent",
			Type: "llm",
		},
		Rules: rules,
	}
}

// inhLoader returns a loader function that resolves policies from a map.
func inhLoader(policies map[string]*Policy) func(string) (*Policy, error) {
	return func(name string) (*Policy, error) {
		p, ok := policies[name]
		if !ok {
			return nil, fmt.Errorf("policy %q not found", name)
		}
		return p, nil
	}
}

// inhDeny creates a deny rule with the given ID matching the given tools.
func inhDeny(id string, tools ...string) Rule {
	return Rule{
		ID:          id,
		Description: "Deny " + id,
		Effect:      "deny",
		Priority:    100,
		Match:       RuleMatch{Tools: tools},
	}
}

// inhAllow creates an allow rule with the given ID matching the given tools.
func inhAllow(id string, tools ...string) Rule {
	return Rule{
		ID:          id,
		Description: "Allow " + id,
		Effect:      "allow",
		Priority:    100,
		Match:       RuleMatch{Tools: tools},
	}
}

// inhAlert creates an alert rule with the given ID matching the given tools.
func inhAlert(id string, tools ...string) Rule {
	return Rule{
		ID:          id,
		Description: "Alert " + id,
		Effect:      "alert",
		Priority:    50,
		Match:       RuleMatch{Tools: tools},
	}
}

// inhTactic creates a deny rule matching the given tactics.
func inhTactic(id string, tactics ...string) Rule {
	return Rule{
		ID:          id,
		Description: "Tactic rule " + id,
		Effect:      "deny",
		Priority:    100,
		Match:       RuleMatch{Tactics: tactics},
	}
}

// inhAction creates a deny rule matching the given actions.
func inhAction(id string, actions ...string) Rule {
	return Rule{
		ID:          id,
		Description: "Action rule " + id,
		Effect:      "deny",
		Priority:    100,
		Match:       RuleMatch{Actions: actions},
	}
}

// inhTarget creates a deny rule matching the given targets.
func inhTarget(id string, targets ...string) Rule {
	return Rule{
		ID:          id,
		Description: "Target rule " + id,
		Effect:      "deny",
		Priority:    100,
		Match:       RuleMatch{Targets: targets},
	}
}

// inhHasRule checks whether a policy contains a rule with the given ID.
func inhHasRule(p *Policy, id string) bool {
	for _, r := range p.Rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

// inhFindRule returns the rule with the given ID, or nil if not found.
func inhFindRule(p *Policy, id string) *Rule {
	for i := range p.Rules {
		if p.Rules[i].ID == id {
			return &p.Rules[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Extends registry tests
// ---------------------------------------------------------------------------

func TestExtendsRegistry(t *testing.T) {
	defer ClearExtends()

	// Initially empty.
	if got := GetExtends("child"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}

	// Register and retrieve.
	RegisterExtends("child", "parent")
	if got := GetExtends("child"); got != "parent" {
		t.Errorf("expected %q, got %q", "parent", got)
	}

	// Overwrite.
	RegisterExtends("child", "grandparent")
	if got := GetExtends("child"); got != "grandparent" {
		t.Errorf("expected %q after overwrite, got %q", "grandparent", got)
	}

	// Clear.
	ClearExtends()
	if got := GetExtends("child"); got != "" {
		t.Errorf("expected empty after clear, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// BuildChain tests
// ---------------------------------------------------------------------------

func TestBuildChain_NilLeaf(t *testing.T) {
	_, err := BuildChain(nil, func(string) (*Policy, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected error for nil leaf")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected nil-related error, got: %v", err)
	}
}

func TestBuildChain_SinglePolicy(t *testing.T) {
	defer ClearExtends()

	leaf := inhPolicy("standalone",
		inhDeny("deny-shell", "shell_exec"),
	)

	chain, err := BuildChain(leaf, func(string) (*Policy, error) {
		return nil, fmt.Errorf("should not be called")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chain.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(chain.Policies))
	}
	if len(chain.Lineage) != 1 {
		t.Fatalf("expected 1 lineage entry, got %d", len(chain.Lineage))
	}
	if chain.Lineage[0] != "standalone" {
		t.Errorf("expected lineage[0]=%q, got %q", "standalone", chain.Lineage[0])
	}
	if len(chain.Overrides) != 0 {
		t.Errorf("expected 0 overrides, got %d", len(chain.Overrides))
	}
	if chain.Resolved == nil {
		t.Fatal("expected resolved policy")
	}
	if len(chain.Resolved.Rules) != 1 {
		t.Errorf("expected 1 resolved rule, got %d", len(chain.Resolved.Rules))
	}
}

func TestBuildChain_TwoLevelChain(t *testing.T) {
	defer ClearExtends()

	base := inhPolicy("base-policy",
		inhDeny("deny-shell", "shell_exec"),
		inhDeny("deny-http", "http_request"),
	)
	child := inhPolicy("child-policy",
		inhAllow("allow-http", "http_request"),
	)

	RegisterExtends("child-policy", "base-policy")

	chain, err := BuildChain(child, inhLoader(map[string]*Policy{
		"base-policy": base,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chain.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(chain.Policies))
	}
	if chain.Lineage[0] != "base-policy" {
		t.Errorf("expected lineage[0]=%q (base), got %q", "base-policy", chain.Lineage[0])
	}
	if chain.Lineage[1] != "child-policy" {
		t.Errorf("expected lineage[1]=%q (leaf), got %q", "child-policy", chain.Lineage[1])
	}
	if chain.Resolved == nil {
		t.Fatal("expected resolved policy")
	}
}

func TestBuildChain_ThreeLevelChain(t *testing.T) {
	defer ClearExtends()

	grandparent := inhPolicy("org-base",
		inhDeny("deny-all-exec", "shell_exec", "process_exec"),
	)
	parent := inhPolicy("team-policy",
		inhAllow("allow-shell", "shell_exec"),
	)
	child := inhPolicy("agent-policy",
		inhDeny("deny-elevated", "shell_exec"),
	)

	RegisterExtends("agent-policy", "team-policy")
	RegisterExtends("team-policy", "org-base")

	chain, err := BuildChain(child, inhLoader(map[string]*Policy{
		"team-policy": parent,
		"org-base":    grandparent,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(chain.Policies) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(chain.Policies))
	}
	if chain.Lineage[0] != "org-base" {
		t.Errorf("expected base first, got %q", chain.Lineage[0])
	}
	if chain.Lineage[2] != "agent-policy" {
		t.Errorf("expected leaf last, got %q", chain.Lineage[2])
	}
}

func TestBuildChain_CircularDetection(t *testing.T) {
	defer ClearExtends()

	policyA := inhPolicy("policy-a", inhDeny("r1", "shell_exec"))
	policyB := inhPolicy("policy-b", inhDeny("r2", "http_request"))

	RegisterExtends("policy-a", "policy-b")
	RegisterExtends("policy-b", "policy-a")

	_, err := BuildChain(policyA, inhLoader(map[string]*Policy{
		"policy-a": policyA,
		"policy-b": policyB,
	}))
	if err == nil {
		t.Fatal("expected circular inheritance error")
	}
	if !strings.Contains(err.Error(), "circular") {
		t.Errorf("expected circular error, got: %v", err)
	}
}

func TestBuildChain_SelfExtends(t *testing.T) {
	defer ClearExtends()

	p := inhPolicy("self-ref", inhDeny("r1", "shell_exec"))
	RegisterExtends("self-ref", "self-ref")

	_, err := BuildChain(p, inhLoader(map[string]*Policy{
		"self-ref": p,
	}))
	if err == nil {
		t.Fatal("expected circular inheritance error for self-extends")
	}
	if !strings.Contains(err.Error(), "circular") {
		t.Errorf("expected circular error, got: %v", err)
	}
}

func TestBuildChain_MissingParent(t *testing.T) {
	defer ClearExtends()

	child := inhPolicy("orphan", inhDeny("r1", "shell_exec"))
	RegisterExtends("orphan", "nonexistent")

	_, err := BuildChain(child, inhLoader(map[string]*Policy{}))
	if err == nil {
		t.Fatal("expected error for missing parent")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("expected error mentioning parent name, got: %v", err)
	}
}

func TestBuildChain_LoaderError(t *testing.T) {
	defer ClearExtends()

	child := inhPolicy("child", inhDeny("r1", "shell_exec"))
	RegisterExtends("child", "parent")

	_, err := BuildChain(child, func(name string) (*Policy, error) {
		return nil, fmt.Errorf("disk on fire")
	})
	if err == nil {
		t.Fatal("expected error from loader failure")
	}
	if !strings.Contains(err.Error(), "disk on fire") {
		t.Errorf("expected loader error propagated, got: %v", err)
	}
}

func TestBuildChain_LoaderReturnsNil(t *testing.T) {
	defer ClearExtends()

	child := inhPolicy("child", inhDeny("r1", "shell_exec"))
	RegisterExtends("child", "parent")

	_, err := BuildChain(child, func(name string) (*Policy, error) {
		return nil, nil // no error but nil policy
	})
	if err == nil {
		t.Fatal("expected error for nil parent")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ResolveChain tests
// ---------------------------------------------------------------------------

func TestResolveChain_Empty(t *testing.T) {
	resolved := ResolveChain(nil)
	if resolved == nil {
		t.Fatal("expected non-nil resolved policy")
	}
	if len(resolved.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(resolved.Rules))
	}
	if resolved.APIVersion != "v1" {
		t.Errorf("expected api_version %q, got %q", "v1", resolved.APIVersion)
	}
}

func TestResolveChain_SinglePolicy(t *testing.T) {
	p := inhPolicy("solo",
		inhDeny("deny-shell", "shell_exec"),
		inhAlert("alert-http", "http_request"),
	)

	resolved := ResolveChain([]*Policy{p})

	if resolved.Meta.Name != "solo" {
		t.Errorf("expected name %q, got %q", "solo", resolved.Meta.Name)
	}
	if len(resolved.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(resolved.Rules))
	}
	// Modifying resolved should not affect original.
	resolved.Rules[0].ID = "changed"
	if p.Rules[0].ID == "changed" {
		t.Error("resolved is not a copy -- modification leaked to original")
	}
}

func TestResolveChain_TwoPolicies_NoOverlap(t *testing.T) {
	base := inhPolicy("base",
		inhDeny("deny-shell", "shell_exec"),
	)
	child := inhPolicy("child",
		inhDeny("deny-dns", "dns_query"),
	)

	resolved := ResolveChain([]*Policy{base, child})

	if len(resolved.Rules) != 2 {
		t.Fatalf("expected 2 rules (no overlap), got %d", len(resolved.Rules))
	}
	if !inhHasRule(resolved, "deny-shell") {
		t.Error("expected inherited parent rule deny-shell")
	}
	if !inhHasRule(resolved, "deny-dns") {
		t.Error("expected child rule deny-dns")
	}
}

func TestResolveChain_OverrideByID(t *testing.T) {
	base := inhPolicy("base",
		inhDeny("deny-shell", "shell_exec"),
		inhDeny("deny-http", "http_request"),
	)
	child := inhPolicy("child",
		inhAllow("deny-shell", "shell_exec"), // same ID, different effect
	)

	resolved := ResolveChain([]*Policy{base, child})

	// deny-shell should be overridden to allow.
	r := inhFindRule(resolved, "deny-shell")
	if r == nil {
		t.Fatal("expected rule deny-shell in resolved")
	}
	if r.Effect != "allow" {
		t.Errorf("expected effect 'allow' (child wins), got %q", r.Effect)
	}
	// deny-http should be inherited from parent.
	if !inhHasRule(resolved, "deny-http") {
		t.Error("expected inherited rule deny-http")
	}
}

func TestResolveChain_OverrideByScopeOverlap(t *testing.T) {
	base := inhPolicy("base",
		inhDeny("deny-shell", "shell_exec"),
	)
	child := inhPolicy("child",
		// Different ID but overlaps on tool pattern.
		inhAllow("shell-ok", "shell_*"),
	)

	resolved := ResolveChain([]*Policy{base, child})

	// Parent rule deny-shell should be overridden by child's shell-ok.
	if inhHasRule(resolved, "deny-shell") {
		t.Error("parent rule deny-shell should be overridden by scope overlap")
	}
	if !inhHasRule(resolved, "shell-ok") {
		t.Error("expected child rule shell-ok")
	}
}

func TestResolveChain_ChildAddsNewRules(t *testing.T) {
	base := inhPolicy("base",
		inhDeny("deny-shell", "shell_exec"),
	)
	child := inhPolicy("child",
		inhDeny("deny-dns", "dns_query"),
		inhAlert("alert-email", "send_email"),
	)

	resolved := ResolveChain([]*Policy{base, child})

	if len(resolved.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(resolved.Rules))
	}
	for _, id := range []string{"deny-shell", "deny-dns", "alert-email"} {
		if !inhHasRule(resolved, id) {
			t.Errorf("expected rule %q in resolved", id)
		}
	}
}

func TestResolveChain_ParentOnlyRulesPreserved(t *testing.T) {
	base := inhPolicy("base",
		inhDeny("deny-shell", "shell_exec"),
		inhDeny("deny-dns", "dns_query"),
		inhTactic("deny-exfil", "exfiltration"),
	)
	child := inhPolicy("child",
		// Only overrides shell, not dns or exfil.
		inhAllow("deny-shell", "shell_exec"),
	)

	resolved := ResolveChain([]*Policy{base, child})

	// dns and exfil should be preserved from parent.
	if !inhHasRule(resolved, "deny-dns") {
		t.Error("expected inherited deny-dns from parent")
	}
	if !inhHasRule(resolved, "deny-exfil") {
		t.Error("expected inherited deny-exfil from parent")
	}
}

func TestResolveChain_MetaInheritance(t *testing.T) {
	base := inhPolicy("base-name")
	base.Meta.Description = "Base description"
	base.Meta.Authors = []string{"author-a"}
	base.Agent = AgentScope{Name: "base-agent", Type: "llm"}

	child := inhPolicy("child-name")
	child.Meta.Description = "Child description"
	child.Rules = []Rule{inhDeny("r1", "shell_exec")}

	resolved := ResolveChain([]*Policy{base, child})

	// Child meta should win.
	if resolved.Meta.Name != "child-name" {
		t.Errorf("expected name %q, got %q", "child-name", resolved.Meta.Name)
	}
	if resolved.Meta.Description != "Child description" {
		t.Errorf("expected child description, got %q", resolved.Meta.Description)
	}
}

func TestResolveChain_AgentInheritance(t *testing.T) {
	base := inhPolicy("base")
	base.Agent = AgentScope{Name: "base-agent", Type: "orchestrator"}

	child := inhPolicy("child")
	child.Agent = AgentScope{Name: "child-agent", Type: "llm"}
	child.Rules = []Rule{inhDeny("r1", "shell_exec")}

	resolved := ResolveChain([]*Policy{base, child})

	if resolved.Agent.Name != "child-agent" {
		t.Errorf("expected child agent name, got %q", resolved.Agent.Name)
	}
	if resolved.Agent.Type != "llm" {
		t.Errorf("expected child agent type %q, got %q", "llm", resolved.Agent.Type)
	}
}

func TestResolveChain_AgentInheritance_ChildEmpty(t *testing.T) {
	base := inhPolicy("base")
	base.Agent = AgentScope{Name: "base-agent", Type: "orchestrator"}

	child := inhPolicy("child")
	child.Agent = AgentScope{} // empty agent
	child.Rules = []Rule{inhDeny("r1", "shell_exec")}

	resolved := ResolveChain([]*Policy{base, child})

	// Parent agent should be preserved when child's is empty.
	if resolved.Agent.Name != "base-agent" {
		t.Errorf("expected parent agent name when child is empty, got %q",
			resolved.Agent.Name)
	}
}

func TestResolveChain_ThreeLevels(t *testing.T) {
	grandparent := inhPolicy("org",
		inhDeny("deny-shell", "shell_exec"),
		inhDeny("deny-http", "http_request"),
		inhDeny("deny-dns", "dns_query"),
	)
	parent := inhPolicy("team",
		inhAllow("deny-shell", "shell_exec"), // override by ID
	)
	child := inhPolicy("agent",
		inhAlert("deny-http", "http_request"), // override by ID
	)

	resolved := ResolveChain([]*Policy{grandparent, parent, child})

	// deny-shell should be allow (from parent).
	r := inhFindRule(resolved, "deny-shell")
	if r == nil {
		t.Fatal("expected deny-shell in resolved")
	}
	if r.Effect != "allow" {
		t.Errorf("expected deny-shell effect 'allow', got %q", r.Effect)
	}

	// deny-http should be alert (from child).
	r = inhFindRule(resolved, "deny-http")
	if r == nil {
		t.Fatal("expected deny-http in resolved")
	}
	if r.Effect != "alert" {
		t.Errorf("expected deny-http effect 'alert', got %q", r.Effect)
	}

	// deny-dns should be inherited unchanged.
	r = inhFindRule(resolved, "deny-dns")
	if r == nil {
		t.Fatal("expected deny-dns in resolved")
	}
	if r.Effect != "deny" {
		t.Errorf("expected deny-dns effect 'deny', got %q", r.Effect)
	}
}

// ---------------------------------------------------------------------------
// DetectOverrides tests
// ---------------------------------------------------------------------------

func TestDetectOverrides_NoOverrides(t *testing.T) {
	parent := inhPolicy("parent",
		inhDeny("deny-shell", "shell_exec"),
	)
	child := inhPolicy("child",
		inhDeny("deny-dns", "dns_query"),
	)

	overrides := DetectOverrides(parent, child)
	if len(overrides) != 0 {
		t.Errorf("expected 0 overrides, got %d", len(overrides))
	}
}

func TestDetectOverrides_IDMatch(t *testing.T) {
	parent := inhPolicy("parent",
		inhDeny("deny-shell", "shell_exec"),
	)
	child := inhPolicy("child",
		inhAllow("deny-shell", "shell_exec"),
	)

	overrides := DetectOverrides(parent, child)
	if len(overrides) != 1 {
		t.Fatalf("expected 1 override, got %d", len(overrides))
	}

	o := overrides[0]
	if o.Dimension != "id" {
		t.Errorf("expected dimension 'id', got %q", o.Dimension)
	}
	if o.ParentRule != "deny-shell" {
		t.Errorf("expected parent rule 'deny-shell', got %q", o.ParentRule)
	}
	if o.ChildRule != "deny-shell" {
		t.Errorf("expected child rule 'deny-shell', got %q", o.ChildRule)
	}
	if !strings.Contains(o.Effect, "deny") || !strings.Contains(o.Effect, "allow") {
		t.Errorf("expected effect containing deny and allow, got %q", o.Effect)
	}
}

func TestDetectOverrides_ScopeOverlap(t *testing.T) {
	parent := inhPolicy("parent",
		inhDeny("deny-shell", "shell_exec"),
	)
	child := inhPolicy("child",
		inhAllow("shell-whitelist", "shell_*"),
	)

	overrides := DetectOverrides(parent, child)
	if len(overrides) != 1 {
		t.Fatalf("expected 1 override (scope overlap), got %d", len(overrides))
	}

	o := overrides[0]
	if o.Dimension != "tool" {
		t.Errorf("expected dimension 'tool', got %q", o.Dimension)
	}
	if o.ParentRule != "deny-shell" {
		t.Errorf("expected parent rule 'deny-shell', got %q", o.ParentRule)
	}
	if o.ChildRule != "shell-whitelist" {
		t.Errorf("expected child rule 'shell-whitelist', got %q", o.ChildRule)
	}
}

func TestDetectOverrides_EffectUnchanged(t *testing.T) {
	parent := inhPolicy("parent",
		inhDeny("deny-shell", "shell_exec"),
	)
	child := inhPolicy("child",
		inhDeny("deny-shell", "shell_exec"), // same ID, same effect
	)

	overrides := DetectOverrides(parent, child)
	if len(overrides) != 1 {
		t.Fatalf("expected 1 override, got %d", len(overrides))
	}
	if overrides[0].Effect != "deny (unchanged)" {
		t.Errorf("expected 'deny (unchanged)', got %q", overrides[0].Effect)
	}
}

func TestDetectOverrides_NilPolicies(t *testing.T) {
	overrides := DetectOverrides(nil, nil)
	if len(overrides) != 0 {
		t.Errorf("expected 0 overrides for nil, got %d", len(overrides))
	}

	p := inhPolicy("p", inhDeny("r1", "shell_exec"))
	overrides = DetectOverrides(p, nil)
	if len(overrides) != 0 {
		t.Errorf("expected 0 overrides for nil child, got %d", len(overrides))
	}
	overrides = DetectOverrides(nil, p)
	if len(overrides) != 0 {
		t.Errorf("expected 0 overrides for nil parent, got %d", len(overrides))
	}
}

func TestDetectOverrides_MultipleOverrides(t *testing.T) {
	parent := inhPolicy("parent",
		inhDeny("deny-shell", "shell_exec"),
		inhDeny("deny-http", "http_request"),
	)
	child := inhPolicy("child",
		inhAllow("deny-shell", "shell_exec"),       // override by ID
		inhAllow("http-whitelist", "http_request"), // override by scope
	)

	overrides := DetectOverrides(parent, child)
	if len(overrides) < 2 {
		t.Fatalf("expected at least 2 overrides, got %d", len(overrides))
	}
}

// ---------------------------------------------------------------------------
// rulesOverlap tests
// ---------------------------------------------------------------------------

func TestRulesOverlap_ExactToolMatch(t *testing.T) {
	a := &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}
	b := &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}
	if !rulesOverlap(a, b) {
		t.Error("expected overlap for exact tool match")
	}
}

func TestRulesOverlap_GlobOverlap(t *testing.T) {
	a := &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}
	b := &Rule{Match: RuleMatch{Tools: []string{"shell_*"}}}
	if !rulesOverlap(a, b) {
		t.Error("expected overlap for glob tool match")
	}
}

func TestRulesOverlap_NoOverlap(t *testing.T) {
	a := &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}
	b := &Rule{Match: RuleMatch{Tools: []string{"http_request"}}}
	if rulesOverlap(a, b) {
		t.Error("expected no overlap for different tools")
	}
}

func TestRulesOverlap_WildcardStar(t *testing.T) {
	a := &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}
	b := &Rule{Match: RuleMatch{Tools: []string{"*"}}}
	if !rulesOverlap(a, b) {
		t.Error("expected overlap with universal wildcard")
	}
}

func TestRulesOverlap_TacticMatch(t *testing.T) {
	a := &Rule{Match: RuleMatch{Tactics: []string{"execution"}}}
	b := &Rule{Match: RuleMatch{Tactics: []string{"execution"}}}
	if !rulesOverlap(a, b) {
		t.Error("expected overlap for same tactic")
	}
}

func TestRulesOverlap_TacticNoMatch(t *testing.T) {
	a := &Rule{Match: RuleMatch{Tactics: []string{"execution"}}}
	b := &Rule{Match: RuleMatch{Tactics: []string{"exfiltration"}}}
	if rulesOverlap(a, b) {
		t.Error("expected no overlap for different tactics")
	}
}

func TestRulesOverlap_ActionMatch(t *testing.T) {
	a := &Rule{Match: RuleMatch{Actions: []string{"execute"}}}
	b := &Rule{Match: RuleMatch{Actions: []string{"execute"}}}
	if !rulesOverlap(a, b) {
		t.Error("expected overlap for same action")
	}
}

func TestRulesOverlap_ActionNoMatch(t *testing.T) {
	a := &Rule{Match: RuleMatch{Actions: []string{"execute"}}}
	b := &Rule{Match: RuleMatch{Actions: []string{"read"}}}
	if rulesOverlap(a, b) {
		t.Error("expected no overlap for different actions")
	}
}

func TestRulesOverlap_TargetGlob(t *testing.T) {
	a := &Rule{Match: RuleMatch{Targets: []string{"https://*.evil.com/*"}}}
	b := &Rule{Match: RuleMatch{Targets: []string{"https://*.evil.com/beacon"}}}
	if !rulesOverlap(a, b) {
		t.Error("expected overlap for matching target globs")
	}
}

func TestRulesOverlap_TargetNoMatch(t *testing.T) {
	a := &Rule{Match: RuleMatch{Targets: []string{"https://good.com/*"}}}
	b := &Rule{Match: RuleMatch{Targets: []string{"https://evil.com/*"}}}
	if rulesOverlap(a, b) {
		t.Error("expected no overlap for different target domains")
	}
}

func TestRulesOverlap_DifferentDimensions(t *testing.T) {
	// Rules with content in different dimensions don't overlap.
	a := &Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}}
	b := &Rule{Match: RuleMatch{Tactics: []string{"execution"}}}
	if rulesOverlap(a, b) {
		t.Error("expected no overlap across different dimensions")
	}
}

func TestRulesOverlap_EmptyRules(t *testing.T) {
	a := &Rule{Match: RuleMatch{}}
	b := &Rule{Match: RuleMatch{}}
	if rulesOverlap(a, b) {
		t.Error("expected no overlap for empty match specs")
	}
}

func TestRulesOverlap_MultipleTools(t *testing.T) {
	a := &Rule{Match: RuleMatch{Tools: []string{"shell_exec", "http_request"}}}
	b := &Rule{Match: RuleMatch{Tools: []string{"dns_query", "http_request"}}}
	if !rulesOverlap(a, b) {
		t.Error("expected overlap when one tool matches")
	}
}

// ---------------------------------------------------------------------------
// FormatChain tests
// ---------------------------------------------------------------------------

func TestFormatChain_Nil(t *testing.T) {
	out := FormatChain(nil)
	if out != "No inheritance chain.\n" {
		t.Errorf("expected nil message, got %q", out)
	}
}

func TestFormatChain_Output(t *testing.T) {
	base := inhPolicy("base-policy",
		inhDeny("deny-shell", "shell_exec"),
	)
	child := inhPolicy("child-policy",
		inhAllow("deny-shell", "shell_exec"),
		inhDeny("deny-dns", "dns_query"),
	)

	chain := &PolicyChain{
		Policies: []*Policy{base, child},
		Lineage:  []string{"base-policy", "child-policy"},
		Overrides: []Override{
			{
				ParentPolicy: "base-policy",
				ParentRule:   "deny-shell",
				ChildPolicy:  "child-policy",
				ChildRule:    "deny-shell",
				Dimension:    "id",
				Effect:       "deny->allow",
			},
		},
		Resolved: inhPolicy("child-policy",
			inhDeny("deny-dns", "dns_query"),
			inhAllow("deny-shell", "shell_exec"),
		),
	}

	out := FormatChain(chain)

	// Check key sections are present.
	for _, want := range []string{
		"Policy Inheritance Chain",
		"Lineage:",
		"base-policy",
		"child-policy",
		"(base)",
		"(leaf)",
		"Layers:",
		"Overrides:",
		"deny-shell",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}

	// Check box drawing characters are present.
	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Error("expected box drawing characters")
	}
}

func TestFormatChain_SinglePolicy(t *testing.T) {
	p := inhPolicy("solo", inhDeny("r1", "shell_exec"))
	chain := &PolicyChain{
		Policies:  []*Policy{p},
		Lineage:   []string{"solo"},
		Overrides: nil,
		Resolved:  p,
	}

	out := FormatChain(chain)
	if !strings.Contains(out, "No overrides") {
		t.Error("expected 'No overrides' for single-policy chain")
	}
	if !strings.Contains(out, "solo") {
		t.Error("expected policy name in output")
	}
}

// ---------------------------------------------------------------------------
// ValidateChain tests
// ---------------------------------------------------------------------------

func TestValidateChain_NilChain(t *testing.T) {
	errs := ValidateChain(nil)
	if len(errs) == 0 {
		t.Fatal("expected errors for nil chain")
	}
	if errs[0].Message != "chain is nil" {
		t.Errorf("expected 'chain is nil', got %q", errs[0].Message)
	}
}

func TestValidateChain_EmptyChain(t *testing.T) {
	chain := &PolicyChain{}
	errs := ValidateChain(chain)
	if len(errs) == 0 {
		t.Fatal("expected errors for empty chain")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "no policies") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'no policies' error")
	}
}

func TestValidateChain_Valid(t *testing.T) {
	base := inhPolicy("base", inhDeny("deny-shell", "shell_exec"))
	child := inhPolicy("child", inhDeny("deny-dns", "dns_query"))

	chain := &PolicyChain{
		Policies:  []*Policy{base, child},
		Lineage:   []string{"base", "child"},
		Overrides: nil,
		Resolved: inhPolicy("child",
			inhDeny("deny-shell", "shell_exec"),
			inhDeny("deny-dns", "dns_query"),
		),
	}

	errs := ValidateChain(chain)
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid chain, got: %v", errs)
	}
}

func TestValidateChain_ConflictingOverrides(t *testing.T) {
	chain := &PolicyChain{
		Policies: []*Policy{
			inhPolicy("base", inhDeny("deny-shell", "shell_exec")),
			inhPolicy("child"),
		},
		Lineage: []string{"base", "child"},
		Overrides: []Override{
			{
				ParentPolicy: "base",
				ParentRule:   "deny-shell",
				ChildPolicy:  "child",
				ChildRule:    "shell-allow",
				Effect:       "deny->allow",
			},
			{
				ParentPolicy: "base",
				ParentRule:   "deny-shell",
				ChildPolicy:  "child",
				ChildRule:    "shell-alert",
				Effect:       "deny->alert",
			},
		},
		Resolved: inhPolicy("child"),
	}

	errs := ValidateChain(chain)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "conflicting overrides") {
			found = true
		}
	}
	if !found {
		t.Error("expected conflicting overrides error")
	}
}

func TestValidateChain_DuplicateResolvedIDs(t *testing.T) {
	resolved := inhPolicy("resolved",
		inhDeny("dup-id", "shell_exec"),
		inhDeny("dup-id", "http_request"), // duplicate
	)

	chain := &PolicyChain{
		Policies: []*Policy{inhPolicy("base")},
		Lineage:  []string{"base"},
		Resolved: resolved,
	}

	errs := ValidateChain(chain)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "duplicate rule ID") {
			found = true
		}
	}
	if !found {
		t.Error("expected duplicate rule ID error")
	}
}

func TestValidateChain_LineageMismatch(t *testing.T) {
	chain := &PolicyChain{
		Policies: []*Policy{
			inhPolicy("base"),
			inhPolicy("child"),
		},
		Lineage:  []string{"base"}, // wrong length
		Resolved: inhPolicy("child"),
	}

	errs := ValidateChain(chain)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "lineage length") {
			found = true
		}
	}
	if !found {
		t.Error("expected lineage mismatch error")
	}
}

func TestValidateChain_UnnamedPolicy(t *testing.T) {
	unnamed := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Rules:      []Rule{inhDeny("r1", "shell_exec")},
	}

	chain := &PolicyChain{
		Policies: []*Policy{unnamed},
		Lineage:  []string{""},
		Resolved: unnamed,
	}

	errs := ValidateChain(chain)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "no name") {
			found = true
		}
	}
	if !found {
		t.Error("expected unnamed policy error")
	}
}

// ---------------------------------------------------------------------------
// InheritanceError tests
// ---------------------------------------------------------------------------

func TestInheritanceError_Error(t *testing.T) {
	e := &InheritanceError{Policy: "my-policy", Message: "something broke"}
	expected := `policy "my-policy": something broke`
	if e.Error() != expected {
		t.Errorf("expected %q, got %q", expected, e.Error())
	}

	e2 := &InheritanceError{Policy: "", Message: "generic error"}
	if e2.Error() != "generic error" {
		t.Errorf("expected %q, got %q", "generic error", e2.Error())
	}
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

func TestInheritance_Integration_FullRoundTrip(t *testing.T) {
	defer ClearExtends()

	// Build a three-level chain: org -> team -> agent.
	org := inhPolicy("org-baseline",
		inhDeny("deny-shell", "shell_exec"),
		inhDeny("deny-http-evil", "http_request"),
		inhTactic("deny-exfil", "exfiltration"),
		inhAlert("alert-email", "send_email"),
	)
	org.Agent = AgentScope{Name: "*", Type: "llm"}

	team := inhPolicy("team-dev",
		inhAllow("deny-shell", "shell_exec"), // override: deny->allow
	)

	agent := inhPolicy("agent-deploy",
		inhDeny("deny-elevated-shell", "shell_exec"), // overrides team's allow by scope
		inhAlert("alert-dns", "dns_query"),           // new rule
	)
	agent.Agent = AgentScope{Name: "deploy-bot", Type: "orchestrator"}

	RegisterExtends("agent-deploy", "team-dev")
	RegisterExtends("team-dev", "org-baseline")

	// Build chain.
	chain, err := BuildChain(agent, inhLoader(map[string]*Policy{
		"team-dev":     team,
		"org-baseline": org,
	}))
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	// Verify chain structure.
	if len(chain.Policies) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(chain.Policies))
	}
	if chain.Lineage[0] != "org-baseline" {
		t.Errorf("expected base = org-baseline, got %q", chain.Lineage[0])
	}
	if chain.Lineage[2] != "agent-deploy" {
		t.Errorf("expected leaf = agent-deploy, got %q", chain.Lineage[2])
	}

	// Verify overrides were detected.
	if len(chain.Overrides) == 0 {
		t.Error("expected at least one override")
	}

	// Verify resolved policy.
	resolved := chain.Resolved
	if resolved == nil {
		t.Fatal("expected resolved policy")
	}
	if resolved.Meta.Name != "agent-deploy" {
		t.Errorf("expected resolved name 'agent-deploy', got %q", resolved.Meta.Name)
	}
	if resolved.Agent.Name != "deploy-bot" {
		t.Errorf("expected agent name 'deploy-bot', got %q", resolved.Agent.Name)
	}

	// Org's deny-exfil should be inherited (no overlap).
	if !inhHasRule(resolved, "deny-exfil") {
		t.Error("expected inherited deny-exfil from org")
	}

	// Agent's new alert-dns should be present.
	if !inhHasRule(resolved, "alert-dns") {
		t.Error("expected agent rule alert-dns")
	}

	// Validate chain.
	errs := ValidateChain(chain)
	// May have some validation notes but no structural errors.
	for _, e := range errs {
		if strings.Contains(e.Message, "circular") || strings.Contains(e.Message, "no policies") {
			t.Errorf("unexpected structural error: %v", e)
		}
	}

	// Format chain -- should not panic and should contain key info.
	out := FormatChain(chain)
	if !strings.Contains(out, "org-baseline") {
		t.Error("formatted output missing org-baseline")
	}
	if !strings.Contains(out, "agent-deploy") {
		t.Error("formatted output missing agent-deploy")
	}
	if !strings.Contains(out, "Overrides:") {
		t.Error("formatted output missing Overrides section")
	}
}

func TestInheritance_Integration_NoOverrides(t *testing.T) {
	defer ClearExtends()

	base := inhPolicy("base",
		inhDeny("deny-shell", "shell_exec"),
	)
	child := inhPolicy("child",
		inhDeny("deny-dns", "dns_query"),
	)

	RegisterExtends("child", "base")

	chain, err := BuildChain(child, inhLoader(map[string]*Policy{
		"base": base,
	}))
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	if len(chain.Overrides) != 0 {
		t.Errorf("expected 0 overrides, got %d", len(chain.Overrides))
	}

	resolved := chain.Resolved
	if len(resolved.Rules) != 2 {
		t.Errorf("expected 2 resolved rules, got %d", len(resolved.Rules))
	}

	errs := ValidateChain(chain)
	if len(errs) != 0 {
		t.Errorf("expected valid chain, got errors: %v", errs)
	}
}
