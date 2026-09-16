// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"math"
	"strings"
	"testing"
	"time"
)

// --- Helpers for chain tests (prefixed to avoid collision with binding_test.go) ---

func mkChainAgent(name, agentType, trustLevel string) *Agent {
	return &Agent{
		Meta:  AgentMeta{Name: name, Type: agentType, Version: "1.0"},
		Trust: TrustConfig{Level: trustLevel},
	}
}

func mkChainAgentTools(name, agentType, trustLevel string, tools []ToolAccess) *Agent {
	a := mkChainAgent(name, agentType, trustLevel)
	a.Tools = tools
	return a
}

func mkChainAgentGuardrails(name, agentType, trustLevel string, guardrails []Guardrail) *Agent {
	a := mkChainAgent(name, agentType, trustLevel)
	a.Guardrails = guardrails
	return a
}

// --- AnalyzeChains: nil/empty inventory ---

func TestAnalyzeChains_NilInventory(t *testing.T) {
	result := AnalyzeChains(nil)
	if result == nil {
		t.Fatal("expected non-nil result for nil inventory")
	}
	if result.TotalAgents != 0 {
		t.Errorf("TotalAgents = %d, want 0", result.TotalAgents)
	}
	if result.TotalChains != 0 {
		t.Errorf("TotalChains = %d, want 0", result.TotalChains)
	}
	if result.RiskScore != 0 {
		t.Errorf("RiskScore = %f, want 0", result.RiskScore)
	}
	if result.Summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestAnalyzeChains_EmptyInventory(t *testing.T) {
	inv := &Inventory{}
	result := AnalyzeChains(inv)
	if result == nil {
		t.Fatal("expected non-nil result for empty inventory")
	}
	if result.TotalAgents != 0 {
		t.Errorf("TotalAgents = %d, want 0", result.TotalAgents)
	}
	if result.TotalChains != 0 {
		t.Errorf("TotalChains = %d, want 0", result.TotalChains)
	}
}

// --- Single agent (no chains) ---

func TestAnalyzeChains_SingleAgent(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			mkChainAgent("solo", TypeRetrieval, TrustStandard),
		},
	}
	result := AnalyzeChains(inv)
	if result.TotalAgents != 1 {
		t.Errorf("TotalAgents = %d, want 1", result.TotalAgents)
	}
	// A single agent with no trust relationships produces a single-link chain.
	for _, c := range result.Chains {
		if c.Length > 1 {
			t.Errorf("single agent should not produce multi-link chains, got length %d", c.Length)
		}
	}
	if result.RiskScore != 0 {
		t.Errorf("RiskScore = %f, want 0 for single agent", result.RiskScore)
	}
}

// --- Linear chain A→B→C ---

func TestAnalyzeChains_LinearChain(t *testing.T) {
	a := mkChainAgent("agent-a", TypeOrchestrator, TrustAdmin)
	b := mkChainAgent("agent-b", TypeToolCalling, TrustStandard)
	b.Trust.TrustedBy = []string{"agent-a"}
	c := mkChainAgent("agent-c", TypeRetrieval, TrustStandard)
	c.Trust.TrustedBy = []string{"agent-b"}

	inv := &Inventory{Agents: []*Agent{a, b, c}}
	result := AnalyzeChains(inv)

	if result.TotalAgents != 3 {
		t.Errorf("TotalAgents = %d, want 3", result.TotalAgents)
	}

	// There should be a 3-link chain a->b->c.
	found := false
	for _, chain := range result.Chains {
		if chain.Length == 3 {
			names := chainNames(chain)
			if names[0] == "agent-a" && names[1] == "agent-b" && names[2] == "agent-c" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected to find linear chain agent-a -> agent-b -> agent-c")
		for _, c := range result.Chains {
			t.Logf("  chain: %v (length %d)", chainNames(c), c.Length)
		}
	}

	if result.MaxChainLength < 3 {
		t.Errorf("MaxChainLength = %d, want >= 3", result.MaxChainLength)
	}
}

// --- Trust escalation detection (low→admin) ---

func TestAnalyzeChains_TrustEscalation(t *testing.T) {
	low := mkChainAgent("low-agent", TypeToolCalling, TrustLow)
	admin := mkChainAgent("admin-agent", TypeOrchestrator, TrustAdmin)
	admin.Trust.TrustedBy = []string{"low-agent"}

	inv := &Inventory{Agents: []*Agent{low, admin}}
	result := AnalyzeChains(inv)

	foundEscalation := false
	for _, v := range result.Violations {
		if v.Type == "escalation" {
			foundEscalation = true
			if v.Severity != "critical" {
				t.Errorf("low->admin escalation severity = %q, want critical", v.Severity)
			}
			break
		}
	}
	if !foundEscalation {
		t.Error("expected escalation violation for low -> admin delegation")
		for _, v := range result.Violations {
			t.Logf("  violation: type=%s severity=%s chain=%v", v.Type, v.Severity, v.Chain)
		}
	}
}

func TestAnalyzeChains_StandardToElevatedEscalation(t *testing.T) {
	std := mkChainAgent("std-agent", TypeToolCalling, TrustStandard)
	elev := mkChainAgent("elev-agent", TypeToolCalling, TrustElevated)
	elev.Trust.TrustedBy = []string{"std-agent"}

	inv := &Inventory{Agents: []*Agent{std, elev}}
	result := AnalyzeChains(inv)

	foundEscalation := false
	for _, v := range result.Violations {
		if v.Type == "escalation" {
			foundEscalation = true
			// standard(2) -> elevated(3): not low/untrusted to elevated/admin, so "high"
			if v.Severity != "high" {
				t.Errorf("standard->elevated escalation severity = %q, want high", v.Severity)
			}
		}
	}
	if !foundEscalation {
		t.Error("expected escalation violation for standard -> elevated")
	}
}

// --- Boundary crossing ---

func TestAnalyzeChains_BoundaryCrossing(t *testing.T) {
	internal := mkChainAgent("internal-agent", TypeToolCalling, TrustStandard)
	internal.Trust.Boundaries = []string{"internal"}

	external := mkChainAgent("external-agent", TypeRetrieval, TrustStandard)
	external.Trust.Boundaries = []string{"external"}
	external.Trust.TrustedBy = []string{"internal-agent"}

	inv := &Inventory{Agents: []*Agent{internal, external}}
	result := AnalyzeChains(inv)

	foundBoundary := false
	for _, v := range result.Violations {
		if v.Type == "boundary_cross" {
			foundBoundary = true
			if v.Severity != "medium" {
				t.Errorf("boundary_cross severity = %q, want medium", v.Severity)
			}
		}
	}
	if !foundBoundary {
		t.Error("expected boundary_cross violation")
		for _, v := range result.Violations {
			t.Logf("  violation: type=%s severity=%s", v.Type, v.Severity)
		}
	}
}

func TestAnalyzeChains_BoundedToUnbounded(t *testing.T) {
	bounded := mkChainAgent("bounded", TypeToolCalling, TrustStandard)
	bounded.Trust.Boundaries = []string{"secure"}

	unbounded := mkChainAgent("unbounded", TypeRetrieval, TrustStandard)
	// No boundaries set.
	unbounded.Trust.TrustedBy = []string{"bounded"}

	inv := &Inventory{Agents: []*Agent{bounded, unbounded}}
	result := AnalyzeChains(inv)

	foundBoundary := false
	for _, v := range result.Violations {
		if v.Type == "boundary_cross" {
			foundBoundary = true
		}
	}
	if !foundBoundary {
		t.Error("expected boundary_cross when delegating from bounded to unbounded agent")
	}
}

// --- Confused deputy pattern ---

func TestAnalyzeChains_ConfusedDeputy(t *testing.T) {
	untrusted := mkChainAgent("public-input", TypeConversational, TrustUntrusted)

	middle := mkChainAgent("middleware", TypeToolCalling, TrustStandard)
	middle.Trust.TrustedBy = []string{"public-input"}

	elevated := mkChainAgentTools("db-admin", TypeToolCalling, TrustElevated,
		[]ToolAccess{{Name: "database", Elevated: true}})
	elevated.Trust.TrustedBy = []string{"middleware"}

	inv := &Inventory{Agents: []*Agent{untrusted, middle, elevated}}
	result := AnalyzeChains(inv)

	foundDeputy := false
	for _, v := range result.Violations {
		if v.Type == "confused_deputy" {
			foundDeputy = true
			if v.Severity != "critical" {
				t.Errorf("confused_deputy severity = %q, want critical", v.Severity)
			}
			// The chain should include the untrusted agent and the elevated agent.
			hasUntrusted := false
			hasElevated := false
			for _, name := range v.Chain {
				if name == "public-input" {
					hasUntrusted = true
				}
				if name == "db-admin" {
					hasElevated = true
				}
			}
			if !hasUntrusted || !hasElevated {
				t.Errorf("confused_deputy chain should include both ends, got %v", v.Chain)
			}
		}
	}
	if !foundDeputy {
		t.Error("expected confused_deputy violation")
		for _, v := range result.Violations {
			t.Logf("  violation: type=%s severity=%s chain=%v", v.Type, v.Severity, v.Chain)
		}
	}
}

// --- Over-delegation (long chain) ---

func TestAnalyzeChains_OverDelegation(t *testing.T) {
	a := mkChainAgent("agent-1", TypeOrchestrator, TrustAdmin)
	b := mkChainAgent("agent-2", TypeToolCalling, TrustStandard)
	b.Trust.TrustedBy = []string{"agent-1"}
	c := mkChainAgent("agent-3", TypeToolCalling, TrustStandard)
	c.Trust.TrustedBy = []string{"agent-2"}
	d := mkChainAgent("agent-4", TypeRetrieval, TrustStandard)
	d.Trust.TrustedBy = []string{"agent-3"}

	inv := &Inventory{Agents: []*Agent{a, b, c, d}}
	result := AnalyzeChains(inv)

	foundOverDelegation := false
	for _, v := range result.Violations {
		if v.Type == "over_delegation" {
			foundOverDelegation = true
			if v.Severity != "medium" {
				t.Errorf("over_delegation severity = %q, want medium", v.Severity)
			}
		}
	}
	if !foundOverDelegation {
		t.Error("expected over_delegation violation for 4-link chain")
		for _, c := range result.Chains {
			t.Logf("  chain length=%d: %v", c.Length, chainNames(c))
		}
	}
}

func TestAnalyzeChains_NoOverDelegation_ShortChain(t *testing.T) {
	a := mkChainAgent("a", TypeOrchestrator, TrustAdmin)
	b := mkChainAgent("b", TypeToolCalling, TrustAdmin)
	b.Trust.TrustedBy = []string{"a"}
	c := mkChainAgent("c", TypeRetrieval, TrustAdmin)
	c.Trust.TrustedBy = []string{"b"}

	inv := &Inventory{Agents: []*Agent{a, b, c}}
	result := AnalyzeChains(inv)

	for _, v := range result.Violations {
		if v.Type == "over_delegation" {
			t.Error("3-link chain should not trigger over_delegation")
		}
	}
}

// --- Unguarded chain link ---

func TestAnalyzeChains_UnguardedChainLink(t *testing.T) {
	a := mkChainAgentGuardrails("guarded", TypeOrchestrator, TrustAdmin,
		[]Guardrail{{Name: "input-filter", Type: "input", Enforced: true}})
	b := mkChainAgent("unguarded", TypeToolCalling, TrustStandard)
	b.Trust.TrustedBy = []string{"guarded"}

	inv := &Inventory{Agents: []*Agent{a, b}}
	result := AnalyzeChains(inv)

	foundUnguarded := false
	for _, v := range result.Violations {
		if v.Type == "unguarded_chain" {
			foundUnguarded = true
			if len(v.Chain) != 1 || v.Chain[0] != "unguarded" {
				t.Errorf("unguarded_chain should reference 'unguarded', got %v", v.Chain)
			}
		}
	}
	if !foundUnguarded {
		t.Error("expected unguarded_chain violation for agent without guardrails in chain")
	}
}

func TestAnalyzeChains_UnguardedElevatedHighSeverity(t *testing.T) {
	a := mkChainAgentGuardrails("root", TypeOrchestrator, TrustAdmin,
		[]Guardrail{{Name: "g", Type: "input", Enforced: true}})
	b := mkChainAgentTools("elevated-no-guard", TypeToolCalling, TrustStandard,
		[]ToolAccess{{Name: "exec", Elevated: true}})
	b.Trust.TrustedBy = []string{"root"}

	inv := &Inventory{Agents: []*Agent{a, b}}
	result := AnalyzeChains(inv)

	for _, v := range result.Violations {
		if v.Type == "unguarded_chain" && v.Chain[0] == "elevated-no-guard" {
			if v.Severity != "high" {
				t.Errorf("unguarded elevated agent severity = %q, want high", v.Severity)
			}
			return
		}
	}
	t.Error("expected unguarded_chain violation with high severity for elevated-tool agent")
}

// --- Cycle handling ---

func TestAnalyzeChains_CycleHandling(t *testing.T) {
	a := mkChainAgent("cycle-a", TypeToolCalling, TrustStandard)
	b := mkChainAgent("cycle-b", TypeToolCalling, TrustStandard)
	a.Trust.TrustedBy = []string{"cycle-b"}
	b.Trust.TrustedBy = []string{"cycle-a"}

	inv := &Inventory{Agents: []*Agent{a, b}}

	// This must not hang or panic.
	done := make(chan *ChainAnalysis, 1)
	go func() {
		done <- AnalyzeChains(inv)
	}()

	select {
	case result := <-done:
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		// Cycles should still produce chains (just not infinite ones).
		if result.TotalAgents != 2 {
			t.Errorf("TotalAgents = %d, want 2", result.TotalAgents)
		}
		// Verify no chain has a repeated agent name.
		for _, c := range result.Chains {
			names := chainNames(c)
			seen := make(map[string]bool)
			for _, n := range names {
				if seen[n] {
					t.Errorf("chain contains cycle (repeated %q): %v", n, names)
				}
				seen[n] = true
			}
		}
	case <-waitTimeout(t, 5):
		t.Fatal("AnalyzeChains hung on cyclic inventory — likely infinite loop")
	}
}

func TestAnalyzeChains_SelfReferentialTrust(t *testing.T) {
	a := mkChainAgent("self-ref", TypeToolCalling, TrustStandard)
	a.Trust.TrustedBy = []string{"self-ref"}

	inv := &Inventory{Agents: []*Agent{a}}
	result := AnalyzeChains(inv)

	// Self-reference should not create multi-link chains.
	for _, c := range result.Chains {
		if c.Length > 1 {
			t.Errorf("self-referential agent produced chain of length %d", c.Length)
		}
	}
}

// --- All-admin chain (no escalation) ---

func TestAnalyzeChains_AllAdminNoEscalation(t *testing.T) {
	a := mkChainAgentGuardrails("admin-a", TypeOrchestrator, TrustAdmin,
		[]Guardrail{{Name: "g", Type: "input", Enforced: true}})
	b := mkChainAgentGuardrails("admin-b", TypeToolCalling, TrustAdmin,
		[]Guardrail{{Name: "g", Type: "input", Enforced: true}})
	b.Trust.TrustedBy = []string{"admin-a"}
	c := mkChainAgentGuardrails("admin-c", TypeRetrieval, TrustAdmin,
		[]Guardrail{{Name: "g", Type: "input", Enforced: true}})
	c.Trust.TrustedBy = []string{"admin-b"}

	inv := &Inventory{Agents: []*Agent{a, b, c}}
	result := AnalyzeChains(inv)

	for _, v := range result.Violations {
		if v.Type == "escalation" {
			t.Error("all-admin chain should not have escalation violations")
		}
	}
}

// --- Mixed violations ---

func TestAnalyzeChains_MixedViolations(t *testing.T) {
	// Build a scenario with multiple violation types.
	untrusted := mkChainAgent("untrusted-entry", TypeConversational, TrustUntrusted)
	untrusted.Trust.Boundaries = []string{"external"}

	middle1 := mkChainAgent("middle-1", TypeToolCalling, TrustStandard)
	middle1.Trust.TrustedBy = []string{"untrusted-entry"}
	middle1.Trust.Boundaries = []string{"internal"} // boundary cross

	middle2 := mkChainAgent("middle-2", TypeToolCalling, TrustStandard)
	middle2.Trust.TrustedBy = []string{"middle-1"}

	elevated := mkChainAgentTools("elevated-target", TypeToolCalling, TrustAdmin,
		[]ToolAccess{{Name: "admin-exec", Elevated: true}})
	elevated.Trust.TrustedBy = []string{"middle-2"}

	inv := &Inventory{Agents: []*Agent{untrusted, middle1, middle2, elevated}}
	result := AnalyzeChains(inv)

	// Should have: escalation (untrusted -> admin path), boundary_cross,
	// confused_deputy, over_delegation (4 agents).
	types := make(map[string]bool)
	for _, v := range result.Violations {
		types[v.Type] = true
	}

	for _, expected := range []string{"escalation", "boundary_cross", "confused_deputy", "over_delegation"} {
		if !types[expected] {
			t.Errorf("expected violation type %q not found", expected)
		}
	}

	if result.CriticalCount == 0 {
		t.Error("expected at least one critical violation")
	}
	if result.RiskScore <= 0 {
		t.Error("expected positive risk score")
	}
}

// --- Risk score calculation ---

func TestScoreChainRisk_Empty(t *testing.T) {
	score := scoreChainRisk(nil)
	if score != 0 {
		t.Errorf("score for nil violations = %f, want 0", score)
	}
}

func TestScoreChainRisk_SingleCritical(t *testing.T) {
	violations := []ChainViolation{
		{Type: "escalation", Severity: "critical"},
	}
	score := scoreChainRisk(violations)
	if math.Abs(score-0.30) > 0.001 {
		t.Errorf("score = %f, want 0.30", score)
	}
}

func TestScoreChainRisk_CappedAtOne(t *testing.T) {
	// 5 critical violations = 5 * 0.30 = 1.50, capped at 1.0
	var violations []ChainViolation
	for i := 0; i < 5; i++ {
		violations = append(violations, ChainViolation{Severity: "critical"})
	}
	score := scoreChainRisk(violations)
	if score != 1.0 {
		t.Errorf("score = %f, want 1.0 (capped)", score)
	}
}

func TestScoreChainRisk_MixedSeverities(t *testing.T) {
	violations := []ChainViolation{
		{Severity: "critical"}, // 0.30
		{Severity: "high"},     // 0.18
		{Severity: "medium"},   // 0.08
		{Severity: "low"},      // 0.03
	}
	expected := 0.30 + 0.18 + 0.08 + 0.03
	score := scoreChainRisk(violations)
	if math.Abs(score-expected) > 0.001 {
		t.Errorf("score = %f, want %f", score, expected)
	}
}

// --- trustLevelRank ---

func TestTrustLevelRank(t *testing.T) {
	tests := []struct {
		level string
		want  int
	}{
		{TrustUntrusted, 0},
		{TrustLow, 1},
		{TrustStandard, 2},
		{TrustElevated, 3},
		{TrustAdmin, 4},
		{"unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := trustLevelRank(tt.level)
		if got != tt.want {
			t.Errorf("trustLevelRank(%q) = %d, want %d", tt.level, got, tt.want)
		}
	}
}

// --- Chain enumeration accuracy ---

func TestEnumerateChains_DiamondShape(t *testing.T) {
	// A delegates to both B and C, both delegate to D.
	a := mkChainAgent("A", TypeOrchestrator, TrustAdmin)
	b := mkChainAgent("B", TypeToolCalling, TrustAdmin)
	b.Trust.TrustedBy = []string{"A"}
	c := mkChainAgent("C", TypeToolCalling, TrustAdmin)
	c.Trust.TrustedBy = []string{"A"}
	d := mkChainAgent("D", TypeRetrieval, TrustAdmin)
	d.Trust.TrustedBy = []string{"B", "C"}

	inv := &Inventory{Agents: []*Agent{a, b, c, d}}
	result := AnalyzeChains(inv)

	// Should have at least two 3-link chains: A->B->D and A->C->D.
	foundABD := false
	foundACD := false
	for _, chain := range result.Chains {
		names := chainNames(chain)
		if len(names) == 3 {
			path := strings.Join(names, "->")
			if path == "A->B->D" {
				foundABD = true
			}
			if path == "A->C->D" {
				foundACD = true
			}
		}
	}
	if !foundABD {
		t.Error("expected chain A->B->D in diamond graph")
	}
	if !foundACD {
		t.Error("expected chain A->C->D in diamond graph")
	}
}

func TestEnumerateChains_OrchestratorImplicitDelegation(t *testing.T) {
	orch := mkChainAgent("orchestrator", TypeOrchestrator, TrustAdmin)
	worker := mkChainAgent("worker", TypeToolCalling, TrustStandard)
	worker.Trust.TrustsFrom = []string{"orchestrator"}

	inv := &Inventory{Agents: []*Agent{orch, worker}}
	result := AnalyzeChains(inv)

	// Orchestrator should implicitly delegate to worker.
	found := false
	for _, chain := range result.Chains {
		names := chainNames(chain)
		if len(names) == 2 && names[0] == "orchestrator" && names[1] == "worker" {
			found = true
		}
	}
	if !found {
		t.Error("expected implicit delegation chain orchestrator -> worker")
		for _, c := range result.Chains {
			t.Logf("  chain: %v", chainNames(c))
		}
	}
}

// --- Format output ---

func TestFormatChainAnalysis_Nil(t *testing.T) {
	out := FormatChainAnalysis(nil)
	if out != "No chain analysis.\n" {
		t.Errorf("unexpected nil output: %q", out)
	}
}

func TestFormatChainAnalysis_ContainsBoxDrawing(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			mkChainAgent("a", TypeOrchestrator, TrustAdmin),
			mkChainAgent("b", TypeToolCalling, TrustStandard),
		},
	}
	inv.Agents[1].Trust.TrustedBy = []string{"a"}

	result := AnalyzeChains(inv)
	out := FormatChainAnalysis(result)

	if !strings.Contains(out, "DELEGATION CHAIN ANALYSIS") {
		t.Error("format output missing header")
	}
	if !strings.Contains(out, "Total Agents") {
		t.Error("format output missing total agents")
	}
	if !strings.Contains(out, "Risk Score") {
		t.Error("format output missing risk score")
	}
	if !strings.Contains(out, "Violations") {
		t.Error("format output missing violations section")
	}
}

func TestFormatChainAnalysis_ShowsViolationDetails(t *testing.T) {
	low := mkChainAgent("low", TypeToolCalling, TrustLow)
	admin := mkChainAgent("admin", TypeOrchestrator, TrustAdmin)
	admin.Trust.TrustedBy = []string{"low"}

	inv := &Inventory{Agents: []*Agent{low, admin}}
	result := AnalyzeChains(inv)
	out := FormatChainAnalysis(result)

	if !strings.Contains(out, "escalation") {
		t.Error("format output should show escalation violation type")
	}
}

// --- SummarizeChains ---

func TestSummarizeChains_Nil(t *testing.T) {
	s := SummarizeChains(nil)
	if s == "" {
		t.Error("expected non-empty summary for nil")
	}
}

func TestSummarizeChains_NoChains(t *testing.T) {
	a := &ChainAnalysis{TotalAgents: 1}
	s := SummarizeChains(a)
	if !strings.Contains(s, "no delegation chains") {
		t.Errorf("summary should mention no chains, got %q", s)
	}
}

func TestSummarizeChains_WithViolations(t *testing.T) {
	a := &ChainAnalysis{
		TotalAgents:   5,
		TotalChains:   3,
		CriticalCount: 1,
		HighCount:     2,
		RiskScore:     0.66,
	}
	s := SummarizeChains(a)
	if !strings.Contains(s, "3 chains") {
		t.Errorf("summary should mention chain count, got %q", s)
	}
	if !strings.Contains(s, "1 critical") {
		t.Errorf("summary should mention critical count, got %q", s)
	}
}

// --- buildDelegationMap ---

func TestBuildDelegationMap_Empty(t *testing.T) {
	inv := &Inventory{}
	m := buildDelegationMap(inv)
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}

func TestBuildDelegationMap_TrustedByEdge(t *testing.T) {
	a := mkChainAgent("a", TypeOrchestrator, TrustAdmin)
	b := mkChainAgent("b", TypeToolCalling, TrustStandard)
	b.Trust.TrustedBy = []string{"a"}

	inv := &Inventory{Agents: []*Agent{a, b}}
	m := buildDelegationMap(inv)

	targets, ok := m["a"]
	if !ok {
		t.Fatal("expected delegation entry for 'a'")
	}
	if len(targets) != 1 || targets[0] != "b" {
		t.Errorf("a's delegation targets = %v, want [b]", targets)
	}
}

// --- boundariesDiffer ---

func TestBoundariesDiffer(t *testing.T) {
	tests := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, false},
		{[]string{}, []string{}, false},
		{[]string{"internal"}, []string{"internal"}, false},
		{[]string{"internal"}, []string{"external"}, true},
		{[]string{"internal"}, nil, true},
		{nil, []string{"external"}, true},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
		{[]string{"a", "b"}, []string{"a", "c"}, true},
	}
	for _, tt := range tests {
		got := boundariesDiffer(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("boundariesDiffer(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// --- wrapText ---

func TestWrapText(t *testing.T) {
	short := "hello"
	lines := wrapText(short, 40)
	if len(lines) != 1 || lines[0] != "hello" {
		t.Errorf("wrapText short = %v, want [hello]", lines)
	}

	long := "this is a rather long line that should be wrapped across multiple lines"
	lines = wrapText(long, 30)
	if len(lines) < 2 {
		t.Errorf("wrapText should wrap long text, got %d lines", len(lines))
	}
	for _, l := range lines {
		if len(l) > 30 {
			t.Errorf("wrapped line exceeds max width: %q (%d chars)", l, len(l))
		}
	}
}

// --- Chain max/min trust tracking ---

func TestChainTrustExtremes(t *testing.T) {
	low := mkChainAgent("low-agent", TypeToolCalling, TrustLow)
	elevated := mkChainAgent("elev-agent", TypeToolCalling, TrustElevated)
	elevated.Trust.TrustedBy = []string{"low-agent"}

	inv := &Inventory{Agents: []*Agent{low, elevated}}
	result := AnalyzeChains(inv)

	for _, c := range result.Chains {
		if c.Length == 2 {
			if c.MinTrust != TrustLow {
				t.Errorf("MinTrust = %q, want %q", c.MinTrust, TrustLow)
			}
			if c.MaxTrust != TrustElevated {
				t.Errorf("MaxTrust = %q, want %q", c.MaxTrust, TrustElevated)
			}
			return
		}
	}
	t.Error("expected a 2-link chain")
}

// --- Disconnected agents ---

func TestAnalyzeChains_DisconnectedAgents(t *testing.T) {
	a := mkChainAgent("island-a", TypeRetrieval, TrustStandard)
	b := mkChainAgent("island-b", TypeRetrieval, TrustStandard)

	inv := &Inventory{Agents: []*Agent{a, b}}
	result := AnalyzeChains(inv)

	if result.TotalAgents != 2 {
		t.Errorf("TotalAgents = %d, want 2", result.TotalAgents)
	}
	// Disconnected agents should not form multi-link chains.
	for _, c := range result.Chains {
		if c.Length > 1 {
			t.Errorf("disconnected agents should not form multi-link chains, got length %d: %v",
				c.Length, chainNames(c))
		}
	}
	if result.RiskScore != 0 {
		t.Errorf("RiskScore = %f, want 0", result.RiskScore)
	}
}

// --- Helpers ---

func chainNames(c DelegationChain) []string {
	names := make([]string, len(c.Links))
	for i, l := range c.Links {
		names[i] = l.AgentName
	}
	return names
}

// waitTimeout returns a channel that closes after the given number of seconds.
func waitTimeout(t *testing.T, seconds int) <-chan struct{} {
	t.Helper()
	ch := make(chan struct{})
	go func() {
		time.Sleep(time.Duration(seconds) * time.Second)
		close(ch)
	}()
	return ch
}
