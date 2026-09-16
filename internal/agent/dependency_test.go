// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers — all prefixed with mkDep to avoid clashes.
// ---------------------------------------------------------------------------

func mkDepAgent(name, agentType, trustLevel string) *Agent {
	return &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       AgentMeta{Name: name, Type: agentType},
		Trust:      TrustConfig{Level: trustLevel},
	}
}

func mkDepAgentWithTools(name, agentType, trustLevel string, tools []ToolAccess) *Agent {
	a := mkDepAgent(name, agentType, trustLevel)
	a.Tools = tools
	return a
}

func mkDepAgentFull(name, agentType, trustLevel string, tools []ToolAccess, trustedBy, trustsFrom []string) *Agent {
	a := mkDepAgentWithTools(name, agentType, trustLevel, tools)
	a.Trust.TrustedBy = trustedBy
	a.Trust.TrustsFrom = trustsFrom
	return a
}

func mkDepInventory(agents ...*Agent) *Inventory {
	return &Inventory{Agents: agents}
}

func mkDepTool(name string) ToolAccess {
	return ToolAccess{Name: name}
}

func mkDepToolTargets(name string, targets ...string) ToolAccess {
	return ToolAccess{Name: name, Targets: targets}
}

func mkDepToolElevated(name string) ToolAccess {
	return ToolAccess{Name: name, Elevated: true}
}

func mkDepHasDep(g *DependencyGraph, from, to, depType string) bool {
	for _, d := range g.Dependencies {
		if d.From == from && d.To == to && d.Type == depType {
			return true
		}
	}
	return false
}

func mkDepCountType(g *DependencyGraph, depType string) int {
	count := 0
	for _, d := range g.Dependencies {
		if d.Type == depType {
			count++
		}
	}
	return count
}

func mkDepContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BuildDependencyGraph tests
// ---------------------------------------------------------------------------

func TestBuildDependencyGraphEmpty(t *testing.T) {
	t.Parallel()
	g := BuildDependencyGraph(mkDepInventory())
	if len(g.Agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(g.Agents))
	}
	if len(g.Dependencies) != 0 {
		t.Errorf("expected 0 dependencies, got %d", len(g.Dependencies))
	}
}

func TestBuildDependencyGraphNil(t *testing.T) {
	t.Parallel()
	g := BuildDependencyGraph(nil)
	if g == nil {
		t.Fatal("expected non-nil graph")
	}
	if len(g.Agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(g.Agents))
	}
}

func TestBuildDependencyGraphSingleAgent(t *testing.T) {
	t.Parallel()
	a := mkDepAgent("solo", TypeToolCalling, TrustStandard)
	g := BuildDependencyGraph(mkDepInventory(a))
	if len(g.Agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(g.Agents))
	}
	if len(g.Dependencies) != 0 {
		t.Errorf("expected 0 dependencies, got %d", len(g.Dependencies))
	}
	if len(g.Isolates) != 1 || g.Isolates[0] != "solo" {
		t.Errorf("expected solo as isolate, got %v", g.Isolates)
	}
}

func TestBuildDependencyGraphSharedTool(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("alpha", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("web-search")})
	b := mkDepAgentWithTools("beta", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("web-search")})
	g := BuildDependencyGraph(mkDepInventory(a, b))

	if !mkDepHasDep(g, "alpha", "beta", "shares_tool") {
		t.Error("expected shares_tool dependency between alpha and beta")
	}
	found := false
	for _, d := range g.Dependencies {
		if d.Type == "shares_tool" && d.Tool == "web-search" {
			found = true
		}
	}
	if !found {
		t.Error("expected shares_tool dependency to reference web-search")
	}
}

func TestBuildDependencyGraphSharedToolThreeAgents(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("db-query")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("db-query")})
	c := mkDepAgentWithTools("c", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("db-query")})
	g := BuildDependencyGraph(mkDepInventory(a, b, c))

	// Three agents sharing one tool = C(3,2) = 3 pairs.
	stCount := mkDepCountType(g, "shares_tool")
	if stCount != 3 {
		t.Errorf("expected 3 shares_tool deps for 3-agent triangle, got %d", stCount)
	}
}

func TestBuildDependencyGraphSharedToolElevated(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepToolElevated("secret-api")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("secret-api")})
	g := BuildDependencyGraph(mkDepInventory(a, b))

	for _, d := range g.Dependencies {
		if d.Type == "shares_tool" && d.Tool == "secret-api" {
			if d.Strength != "moderate" {
				t.Errorf("expected moderate strength for elevated shared tool, got %s", d.Strength)
			}
			return
		}
	}
	t.Error("expected shares_tool dependency for secret-api")
}

func TestBuildDependencyGraphNoSharedTools(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("tool-a")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("tool-b")})
	g := BuildDependencyGraph(mkDepInventory(a, b))

	if mkDepCountType(g, "shares_tool") != 0 {
		t.Error("expected no shares_tool dependencies when tools differ")
	}
}

func TestBuildDependencyGraphDelegatesTo(t *testing.T) {
	t.Parallel()
	// worker is trusted by delegator → delegator delegates_to worker.
	worker := mkDepAgent("worker", TypeToolCalling, TrustStandard)
	worker.Trust.TrustedBy = []string{"delegator"}
	delegator := mkDepAgent("delegator", TypeToolCalling, TrustElevated)

	g := BuildDependencyGraph(mkDepInventory(worker, delegator))

	if !mkDepHasDep(g, "delegator", "worker", "delegates_to") {
		t.Error("expected delegates_to from delegator to worker")
	}
}

func TestBuildDependencyGraphDelegatesToTrustsFrom(t *testing.T) {
	t.Parallel()
	// For non-orchestrators, TrustsFrom alone does not create delegates_to.
	a := mkDepAgent("agent-a", TypeToolCalling, TrustStandard)
	a.Trust.TrustsFrom = []string{"agent-b"}
	b := mkDepAgent("agent-b", TypeToolCalling, TrustStandard)

	g := BuildDependencyGraph(mkDepInventory(a, b))

	if mkDepCountType(g, "delegates_to") != 0 {
		t.Error("non-orchestrator TrustsFrom should not create delegates_to")
	}
}

func TestBuildDependencyGraphOrchestrates(t *testing.T) {
	t.Parallel()
	orch := mkDepAgent("orch", TypeOrchestrator, TrustElevated)
	worker := mkDepAgent("worker", TypeToolCalling, TrustStandard)
	worker.Trust.TrustedBy = []string{"orch"}

	g := BuildDependencyGraph(mkDepInventory(orch, worker))

	if !mkDepHasDep(g, "orch", "worker", "orchestrates") {
		t.Error("expected orchestrates dependency from orch to worker")
	}
	if mkDepCountType(g, "delegates_to") != 0 {
		t.Error("orchestrator edges should be typed orchestrates, not delegates_to")
	}
}

func TestBuildDependencyGraphOrchestratesViaOwnTrustedBy(t *testing.T) {
	t.Parallel()
	// Orchestrator's own TrustedBy list also creates orchestrates edges.
	orch := mkDepAgent("orch", TypeOrchestrator, TrustElevated)
	orch.Trust.TrustedBy = []string{"worker"}
	worker := mkDepAgent("worker", TypeToolCalling, TrustStandard)

	g := BuildDependencyGraph(mkDepInventory(orch, worker))

	if !mkDepHasDep(g, "orch", "worker", "orchestrates") {
		t.Error("expected orchestrates from orch to worker via orch.TrustedBy")
	}
}

func TestBuildDependencyGraphTrustChain(t *testing.T) {
	t.Parallel()
	admin := mkDepAgentWithTools("admin-bot", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("db-write")})
	low := mkDepAgentWithTools("low-bot", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("db-write")})

	g := BuildDependencyGraph(mkDepInventory(admin, low))

	if !mkDepHasDep(g, "admin-bot", "low-bot", "trust_chain") {
		t.Error("expected trust_chain from higher to lower trust agent")
	}
	for _, d := range g.Dependencies {
		if d.Type == "trust_chain" {
			if d.Strength != "strong" {
				t.Errorf("expected strong strength for admin trust chain, got %s", d.Strength)
			}
			if d.Tool != "db-write" {
				t.Errorf("expected trust_chain to reference db-write, got %s", d.Tool)
			}
		}
	}
}

func TestBuildDependencyGraphDataFlow(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("reader", TypeRetrieval, TrustStandard,
		[]ToolAccess{mkDepToolTargets("api", "customer-db", "logs")})
	b := mkDepAgentWithTools("writer", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepToolTargets("api", "customer-db")})

	g := BuildDependencyGraph(mkDepInventory(a, b))

	if !mkDepHasDep(g, "reader", "writer", "data_flow") {
		t.Error("expected data_flow dependency for shared targets")
	}
	for _, d := range g.Dependencies {
		if d.Type == "data_flow" {
			if !strings.Contains(d.Description, "customer-db") {
				t.Error("data_flow description should mention shared target customer-db")
			}
		}
	}
}

func TestBuildDependencyGraphMixed(t *testing.T) {
	t.Parallel()
	orch := mkDepAgentWithTools("orch", TypeOrchestrator, TrustElevated,
		[]ToolAccess{mkDepTool("api")})
	orch.Trust.TrustedBy = []string{"worker-a"}
	workerA := mkDepAgentWithTools("worker-a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("api")})
	workerB := mkDepAgentWithTools("worker-b", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("api")})

	g := BuildDependencyGraph(mkDepInventory(orch, workerA, workerB))

	// Should have shares_tool (api shared by all 3 = 3 pairs).
	if mkDepCountType(g, "shares_tool") != 3 {
		t.Errorf("expected 3 shares_tool deps, got %d", mkDepCountType(g, "shares_tool"))
	}
	// Should have orchestrates.
	if mkDepCountType(g, "orchestrates") == 0 {
		t.Error("expected at least one orchestrates dependency")
	}
	// Should have trust_chain (different trust levels sharing tools).
	if mkDepCountType(g, "trust_chain") == 0 {
		t.Error("expected at least one trust_chain dependency")
	}
}

func TestBuildDependencyGraphIsolates(t *testing.T) {
	t.Parallel()
	connected := mkDepAgentWithTools("conn-a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("shared")})
	connected2 := mkDepAgentWithTools("conn-b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("shared")})
	isolated := mkDepAgent("alone", TypeRetrieval, TrustLow)

	g := BuildDependencyGraph(mkDepInventory(connected, connected2, isolated))

	if len(g.Isolates) != 1 || g.Isolates[0] != "alone" {
		t.Errorf("expected alone as isolate, got %v", g.Isolates)
	}
}

func TestBuildDependencyGraphClusters(t *testing.T) {
	t.Parallel()
	// Two disconnected clusters.
	a1 := mkDepAgentWithTools("c1-a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("tool-1")})
	a2 := mkDepAgentWithTools("c1-b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("tool-1")})
	b1 := mkDepAgentWithTools("c2-a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("tool-2")})
	b2 := mkDepAgentWithTools("c2-b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("tool-2")})

	g := BuildDependencyGraph(mkDepInventory(a1, a2, b1, b2))

	if len(g.Clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(g.Clusters))
	}
}

func TestBuildDependencyGraphSelfReference(t *testing.T) {
	t.Parallel()
	a := mkDepAgent("self", TypeToolCalling, TrustStandard)
	a.Trust.TrustedBy = []string{"self"}

	g := BuildDependencyGraph(mkDepInventory(a))

	// Self-referencing should not create a dependency.
	if len(g.Dependencies) != 0 {
		t.Errorf("expected 0 deps for self-reference, got %d", len(g.Dependencies))
	}
}

// ---------------------------------------------------------------------------
// BlastRadius tests
// ---------------------------------------------------------------------------

func TestBlastRadiusEmpty(t *testing.T) {
	t.Parallel()
	br := AnalyzeBlastRadius(mkDepInventory(), "nobody")
	if br.TotalAffected != 0 {
		t.Errorf("expected 0 affected, got %d", br.TotalAffected)
	}
}

func TestBlastRadiusNil(t *testing.T) {
	t.Parallel()
	br := AnalyzeBlastRadius(nil, "nobody")
	if br == nil {
		t.Fatal("expected non-nil blast radius")
	}
	if br.CompromisedAgent != "nobody" {
		t.Errorf("expected compromised agent nobody, got %s", br.CompromisedAgent)
	}
}

func TestBlastRadiusAgentNotFound(t *testing.T) {
	t.Parallel()
	a := mkDepAgent("exists", TypeToolCalling, TrustStandard)
	br := AnalyzeBlastRadius(mkDepInventory(a), "ghost")
	if br.TotalAffected != 0 {
		t.Errorf("expected 0 affected for nonexistent agent, got %d", br.TotalAffected)
	}
}

func TestBlastRadiusSingleAgent(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("solo", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("api")})
	br := AnalyzeBlastRadius(mkDepInventory(a), "solo")
	if br.TotalAffected != 0 {
		t.Errorf("expected 0 affected for single agent, got %d", br.TotalAffected)
	}
	if br.RiskScore != 0.0 {
		t.Errorf("expected 0 risk for single agent, got %.2f", br.RiskScore)
	}
}

func TestBlastRadiusTwoConnected(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("shared")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("shared")})
	br := AnalyzeBlastRadius(mkDepInventory(a, b), "a")

	if br.TotalAffected != 1 {
		t.Errorf("expected 1 affected, got %d", br.TotalAffected)
	}
	if len(br.DirectImpact) != 1 || br.DirectImpact[0] != "b" {
		t.Errorf("expected direct impact [b], got %v", br.DirectImpact)
	}
	if len(br.IndirectImpact) != 0 {
		t.Errorf("expected no indirect impact, got %v", br.IndirectImpact)
	}
}

func TestBlastRadiusLinearChain(t *testing.T) {
	t.Parallel()
	// A shares tool with B, B shares tool with C. A-B-C chain.
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1"), mkDepTool("t2")})
	c := mkDepAgentWithTools("c", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t2")})

	br := AnalyzeBlastRadius(mkDepInventory(a, b, c), "a")

	if br.TotalAffected != 2 {
		t.Errorf("expected 2 affected in linear chain, got %d", br.TotalAffected)
	}
	if len(br.DirectImpact) != 1 || br.DirectImpact[0] != "b" {
		t.Errorf("expected direct impact [b], got %v", br.DirectImpact)
	}
	if len(br.IndirectImpact) != 1 || br.IndirectImpact[0] != "c" {
		t.Errorf("expected indirect impact [c], got %v", br.IndirectImpact)
	}
}

func TestBlastRadiusStarTopology(t *testing.T) {
	t.Parallel()
	hub := mkDepAgentWithTools("hub", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1"), mkDepTool("t2"), mkDepTool("t3")})
	s1 := mkDepAgentWithTools("spoke-1", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	s2 := mkDepAgentWithTools("spoke-2", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t2")})
	s3 := mkDepAgentWithTools("spoke-3", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t3")})

	br := AnalyzeBlastRadius(mkDepInventory(hub, s1, s2, s3), "hub")

	if br.TotalAffected != 3 {
		t.Errorf("expected 3 affected in star topology, got %d", br.TotalAffected)
	}
	if len(br.DirectImpact) != 3 {
		t.Errorf("expected 3 direct impacts in star, got %d", len(br.DirectImpact))
	}
}

func TestBlastRadiusIsolated(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("connected", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	b := mkDepAgentWithTools("also-connected", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	isolated := mkDepAgent("isolated", TypeRetrieval, TrustLow)

	br := AnalyzeBlastRadius(mkDepInventory(a, b, isolated), "isolated")

	if br.TotalAffected != 0 {
		t.Errorf("expected 0 affected for isolated agent, got %d", br.TotalAffected)
	}
}

func TestBlastRadiusWithEscalation(t *testing.T) {
	t.Parallel()
	low := mkDepAgentWithTools("low-bot", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("shared")})
	admin := mkDepAgentWithTools("admin-bot", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("shared")})

	br := AnalyzeBlastRadius(mkDepInventory(low, admin), "low-bot")

	if len(br.EscalationPaths) == 0 {
		t.Error("expected escalation paths from low to admin")
	}
	found := false
	for _, ep := range br.EscalationPaths {
		if ep.FinalTrust == TrustAdmin {
			found = true
		}
	}
	if !found {
		t.Error("expected escalation path reaching admin trust")
	}
}

func TestBlastRadiusSeverityLow(t *testing.T) {
	t.Parallel()
	// Large inventory, small blast radius, low trust affected.
	target := mkDepAgentWithTools("target", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	affected := mkDepAgentWithTools("affected", TypeToolCalling, TrustUntrusted,
		[]ToolAccess{mkDepTool("t1")})
	unrelated1 := mkDepAgent("unrelated-1", TypeRetrieval, TrustStandard)
	unrelated2 := mkDepAgent("unrelated-2", TypeRetrieval, TrustStandard)
	unrelated3 := mkDepAgent("unrelated-3", TypeRetrieval, TrustStandard)

	br := AnalyzeBlastRadius(mkDepInventory(target, affected, unrelated1, unrelated2, unrelated3), "target")

	if br.Severity != "low" {
		t.Errorf("expected low severity, got %s (score %.2f)", br.Severity, br.RiskScore)
	}
}

func TestBlastRadiusSeverityCritical(t *testing.T) {
	t.Parallel()
	hub := mkDepAgentWithTools("hub", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t1"), mkDepTool("t2"), mkDepTool("t3"), mkDepTool("t4")})
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t1")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t2")})
	c := mkDepAgentWithTools("c", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t3")})
	d := mkDepAgentWithTools("d", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t4")})

	br := AnalyzeBlastRadius(mkDepInventory(hub, a, b, c, d), "hub")

	if br.Severity != "critical" {
		t.Errorf("expected critical severity, got %s (score %.2f)", br.Severity, br.RiskScore)
	}
}

func TestBlastRadiusAffectedTools(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("tool-alpha"), mkDepTool("shared")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("tool-beta"), mkDepTool("shared")})

	br := AnalyzeBlastRadius(mkDepInventory(a, b), "a")

	if !mkDepContains(br.AffectedTools, "tool-alpha") {
		t.Error("expected tool-alpha in affected tools")
	}
	if !mkDepContains(br.AffectedTools, "tool-beta") {
		t.Error("expected tool-beta in affected tools")
	}
	if !mkDepContains(br.AffectedTools, "shared") {
		t.Error("expected shared in affected tools")
	}
}

func TestBlastRadiusAll(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	c := mkDepAgent("c", TypeRetrieval, TrustLow)

	radii := AnalyzeAllBlastRadii(mkDepInventory(a, b, c))

	if len(radii) != 3 {
		t.Fatalf("expected 3 blast radii, got %d", len(radii))
	}
	// a and b should affect each other; c is isolated.
	for _, br := range radii {
		if br.CompromisedAgent == "c" && br.TotalAffected != 0 {
			t.Errorf("expected 0 affected for isolated agent c, got %d", br.TotalAffected)
		}
		if br.CompromisedAgent == "a" && br.TotalAffected != 1 {
			t.Errorf("expected 1 affected when a is compromised, got %d", br.TotalAffected)
		}
	}
}

func TestBlastRadiusAllNil(t *testing.T) {
	t.Parallel()
	radii := AnalyzeAllBlastRadii(nil)
	if radii != nil {
		t.Errorf("expected nil for nil inventory, got %v", radii)
	}
}

// ---------------------------------------------------------------------------
// SinglePointOfFailure tests
// ---------------------------------------------------------------------------

func TestSPOFEmpty(t *testing.T) {
	t.Parallel()
	spofs := FindSinglePointsOfFailure(mkDepInventory())
	if spofs != nil {
		t.Errorf("expected nil for empty inventory, got %v", spofs)
	}
}

func TestSPOFNil(t *testing.T) {
	t.Parallel()
	spofs := FindSinglePointsOfFailure(nil)
	if spofs != nil {
		t.Errorf("expected nil for nil inventory, got %v", spofs)
	}
}

func TestSPOFNoSPOF(t *testing.T) {
	t.Parallel()
	// Two agents, each with 1 neighbor — below threshold.
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})

	spofs := FindSinglePointsOfFailure(mkDepInventory(a, b))

	if len(spofs) != 0 {
		t.Errorf("expected no SPOFs for pair, got %d", len(spofs))
	}
}

func TestSPOFHubAgent(t *testing.T) {
	t.Parallel()
	hub := mkDepAgentWithTools("hub", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1"), mkDepTool("t2"), mkDepTool("t3")})
	s1 := mkDepAgentWithTools("s1", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	s2 := mkDepAgentWithTools("s2", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t2")})
	s3 := mkDepAgentWithTools("s3", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t3")})

	spofs := FindSinglePointsOfFailure(mkDepInventory(hub, s1, s2, s3))

	found := false
	for _, spof := range spofs {
		if spof.Agent == "hub" {
			found = true
			if spof.DependentOn < 3 {
				t.Errorf("expected hub to have >= 3 connections, got %d", spof.DependentOn)
			}
		}
	}
	if !found {
		t.Error("expected hub to be identified as SPOF")
	}
}

func TestSPOFAdminHub(t *testing.T) {
	t.Parallel()
	hub := mkDepAgentWithTools("admin-hub", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t1"), mkDepTool("t2"), mkDepTool("t3")})
	s1 := mkDepAgentWithTools("s1", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	s2 := mkDepAgentWithTools("s2", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t2")})
	s3 := mkDepAgentWithTools("s3", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t3")})

	spofs := FindSinglePointsOfFailure(mkDepInventory(hub, s1, s2, s3))

	for _, spof := range spofs {
		if spof.Agent == "admin-hub" {
			if spof.Risk != "critical" {
				t.Errorf("expected critical risk for admin hub, got %s", spof.Risk)
			}
			return
		}
	}
	t.Error("expected admin-hub as critical SPOF")
}

func TestSPOFOrchestratorHub(t *testing.T) {
	t.Parallel()
	orch := mkDepAgent("orch", TypeOrchestrator, TrustElevated)
	orch.Trust.TrustedBy = []string{"w1", "w2"}
	w1 := mkDepAgent("w1", TypeToolCalling, TrustStandard)
	w2 := mkDepAgent("w2", TypeToolCalling, TrustStandard)

	spofs := FindSinglePointsOfFailure(mkDepInventory(orch, w1, w2))

	for _, spof := range spofs {
		if spof.Agent == "orch" {
			if spof.Risk != "high" {
				t.Errorf("expected high risk for orchestrator SPOF, got %s", spof.Risk)
			}
			return
		}
	}
	t.Error("expected orch as SPOF")
}

func TestSPOFMultiple(t *testing.T) {
	t.Parallel()
	hub1 := mkDepAgentWithTools("hub1", TypeToolCalling, TrustElevated,
		[]ToolAccess{mkDepTool("t1"), mkDepTool("t2"), mkDepTool("t3")})
	hub2 := mkDepAgentWithTools("hub2", TypeToolCalling, TrustElevated,
		[]ToolAccess{mkDepTool("t4"), mkDepTool("t5"), mkDepTool("t6")})
	s1 := mkDepAgentWithTools("s1", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	s2 := mkDepAgentWithTools("s2", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t2")})
	s3 := mkDepAgentWithTools("s3", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t3")})
	s4 := mkDepAgentWithTools("s4", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t4")})
	s5 := mkDepAgentWithTools("s5", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t5")})
	s6 := mkDepAgentWithTools("s6", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t6")})

	spofs := FindSinglePointsOfFailure(mkDepInventory(hub1, hub2, s1, s2, s3, s4, s5, s6))

	hubCount := 0
	for _, spof := range spofs {
		if spof.Agent == "hub1" || spof.Agent == "hub2" {
			hubCount++
		}
	}
	if hubCount != 2 {
		t.Errorf("expected 2 hub SPOFs, got %d", hubCount)
	}
}

func TestSPOFMinimumConnections(t *testing.T) {
	t.Parallel()
	// Agent with only 1 neighbor should not be SPOF.
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t1")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t1")})

	spofs := FindSinglePointsOfFailure(mkDepInventory(a, b))

	if len(spofs) != 0 {
		t.Errorf("expected no SPOFs when max 1 neighbor, got %d", len(spofs))
	}
}

// ---------------------------------------------------------------------------
// EscalationPath tests
// ---------------------------------------------------------------------------

func TestEscalationPathsEmpty(t *testing.T) {
	t.Parallel()
	paths := FindEscalationPaths(mkDepInventory())
	if paths != nil {
		t.Errorf("expected nil for empty inventory, got %v", paths)
	}
}

func TestEscalationPathsNil(t *testing.T) {
	t.Parallel()
	paths := FindEscalationPaths(nil)
	if paths != nil {
		t.Errorf("expected nil for nil inventory, got %v", paths)
	}
}

func TestEscalationPathsNoEscalation(t *testing.T) {
	t.Parallel()
	// All agents at same trust level — no escalation possible.
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})

	paths := FindEscalationPaths(mkDepInventory(a, b))

	if len(paths) != 0 {
		t.Errorf("expected no escalation paths when all same trust, got %d", len(paths))
	}
}

func TestEscalationPathsSimple(t *testing.T) {
	t.Parallel()
	low := mkDepAgentWithTools("low", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("shared")})
	admin := mkDepAgentWithTools("admin", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("shared")})

	paths := FindEscalationPaths(mkDepInventory(low, admin))

	found := false
	for _, p := range paths {
		if len(p.Path) >= 2 && p.Path[0] == "low" && p.FinalTrust == TrustAdmin {
			found = true
		}
	}
	if !found {
		t.Error("expected escalation path from low to admin")
	}
}

func TestEscalationPathsMultiHop(t *testing.T) {
	t.Parallel()
	low := mkDepAgentWithTools("low", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("t1")})
	std := mkDepAgentWithTools("std", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1"), mkDepTool("t2")})
	elev := mkDepAgentWithTools("elev", TypeToolCalling, TrustElevated,
		[]ToolAccess{mkDepTool("t2"), mkDepTool("t3")})
	admin := mkDepAgentWithTools("admin", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t3")})

	paths := FindEscalationPaths(mkDepInventory(low, std, elev, admin))

	// Should find paths from low reaching standard, elevated, and admin.
	foundAdmin := false
	for _, p := range paths {
		if p.Path[0] == "low" && p.FinalTrust == TrustAdmin {
			foundAdmin = true
		}
	}
	if !foundAdmin {
		t.Error("expected multi-hop escalation path from low to admin")
	}
}

func TestEscalationPathsThroughSharedTools(t *testing.T) {
	t.Parallel()
	low := mkDepAgentWithTools("low-agent", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("shared-api")})
	elevated := mkDepAgentWithTools("elevated-agent", TypeToolCalling, TrustElevated,
		[]ToolAccess{mkDepTool("shared-api")})

	paths := FindEscalationPaths(mkDepInventory(low, elevated))

	found := false
	for _, p := range paths {
		if len(p.Path) >= 2 && p.Path[0] == "low-agent" && p.FinalTrust == TrustElevated {
			found = true
		}
	}
	if !found {
		t.Error("expected escalation path from low-agent to elevated-agent via shared tool")
	}
}

func TestEscalationPathsCircular(t *testing.T) {
	t.Parallel()
	// Circular dependency graph should not cause infinite loop.
	a := mkDepAgentWithTools("agent-a", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("t1")})
	a.Trust.TrustedBy = []string{"agent-c"}
	b := mkDepAgentWithTools("agent-b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1"), mkDepTool("t2")})
	c := mkDepAgentWithTools("agent-c", TypeToolCalling, TrustElevated,
		[]ToolAccess{mkDepTool("t2")})

	paths := FindEscalationPaths(mkDepInventory(a, b, c))

	// Should complete without hanging and find at least one path.
	if len(paths) == 0 {
		t.Error("expected escalation paths in circular graph")
	}
}

func TestEscalationPathsMultiplePaths(t *testing.T) {
	t.Parallel()
	// Multiple starting points should each discover their own paths.
	low1 := mkDepAgentWithTools("low1", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("t1")})
	low2 := mkDepAgentWithTools("low2", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("t2")})
	admin := mkDepAgentWithTools("admin", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t1"), mkDepTool("t2")})

	paths := FindEscalationPaths(mkDepInventory(low1, low2, admin))

	// Both low1 and low2 should have escalation paths to admin.
	fromLow1 := false
	fromLow2 := false
	for _, p := range paths {
		if p.Path[0] == "low1" && p.FinalTrust == TrustAdmin {
			fromLow1 = true
		}
		if p.Path[0] == "low2" && p.FinalTrust == TrustAdmin {
			fromLow2 = true
		}
	}
	if !fromLow1 {
		t.Error("expected escalation from low1 to admin")
	}
	if !fromLow2 {
		t.Error("expected escalation from low2 to admin")
	}
}

// ---------------------------------------------------------------------------
// DependencyReport tests
// ---------------------------------------------------------------------------

func TestDependencyReportFull(t *testing.T) {
	t.Parallel()
	hub := mkDepAgentWithTools("hub", TypeOrchestrator, TrustElevated,
		[]ToolAccess{mkDepTool("api"), mkDepTool("db")})
	hub.Trust.TrustedBy = []string{"worker-a", "worker-b"}
	wa := mkDepAgentWithTools("worker-a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("api")})
	wb := mkDepAgentWithTools("worker-b", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("db")})
	isolated := mkDepAgent("isolated", TypeRetrieval, TrustUntrusted)

	r := GenerateDependencyReport(mkDepInventory(hub, wa, wb, isolated))

	if len(r.Graph.Agents) != 4 {
		t.Errorf("expected 4 agents in report, got %d", len(r.Graph.Agents))
	}
	if len(r.Graph.Dependencies) == 0 {
		t.Error("expected dependencies in report")
	}
	if len(r.BlastRadii) != 4 {
		t.Errorf("expected 4 blast radii, got %d", len(r.BlastRadii))
	}
	if r.MostConnected == "" {
		t.Error("expected most connected agent to be set")
	}
	if len(r.Graph.Isolates) != 1 {
		t.Errorf("expected 1 isolate, got %d", len(r.Graph.Isolates))
	}
}

func TestDependencyReportEmpty(t *testing.T) {
	t.Parallel()
	r := GenerateDependencyReport(mkDepInventory())
	if len(r.Graph.Agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(r.Graph.Agents))
	}
	if len(r.BlastRadii) != 0 {
		t.Errorf("expected 0 blast radii, got %d", len(r.BlastRadii))
	}
}

func TestDependencyReportNil(t *testing.T) {
	t.Parallel()
	r := GenerateDependencyReport(nil)
	if r == nil {
		t.Fatal("expected non-nil report for nil inventory")
	}
}

func TestDependencyReportRecommendations(t *testing.T) {
	t.Parallel()
	// Large blast radius should trigger recommendation.
	hub := mkDepAgentWithTools("hub", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("t1"), mkDepTool("t2"), mkDepTool("t3")})
	s1 := mkDepAgentWithTools("s1", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	s2 := mkDepAgentWithTools("s2", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t2")})
	s3 := mkDepAgentWithTools("s3", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("t3")})

	r := GenerateDependencyReport(mkDepInventory(hub, s1, s2, s3))

	if len(r.Recommendations) == 0 {
		t.Error("expected recommendations for topology with SPOFs and escalation")
	}
}

// ---------------------------------------------------------------------------
// Format function tests
// ---------------------------------------------------------------------------

func TestFormatDependencyReport(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("shared")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustLow,
		[]ToolAccess{mkDepTool("shared")})
	r := GenerateDependencyReport(mkDepInventory(a, b))
	output := FormatDependencyReport(r)

	if !strings.Contains(output, "DEPENDENCY ANALYSIS REPORT") {
		t.Error("format should contain report title")
	}
	if !strings.Contains(output, "Agents:") {
		t.Error("format should contain agents count")
	}
	if !strings.Contains(output, "Dependencies:") {
		t.Error("format should contain dependencies count")
	}
	if !strings.Contains(output, "┌") || !strings.Contains(output, "└") {
		t.Error("format should use box-drawing characters")
	}
}

func TestFormatDependencyReportNil(t *testing.T) {
	t.Parallel()
	output := FormatDependencyReport(nil)
	if !strings.Contains(output, "No dependency report") {
		t.Errorf("expected nil message, got %s", output)
	}
}

func TestFormatBlastRadius(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("target", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("api")})
	b := mkDepAgentWithTools("affected", TypeToolCalling, TrustAdmin,
		[]ToolAccess{mkDepTool("api")})
	br := AnalyzeBlastRadius(mkDepInventory(a, b), "target")
	output := FormatBlastRadius(br)

	if !strings.Contains(output, "BLAST RADIUS: target") {
		t.Error("format should contain agent name")
	}
	if !strings.Contains(output, "Risk Score:") {
		t.Error("format should contain risk score")
	}
	if !strings.Contains(output, "affected") {
		t.Error("format should list affected agents")
	}
}

func TestFormatBlastRadiusNil(t *testing.T) {
	t.Parallel()
	output := FormatBlastRadius(nil)
	if !strings.Contains(output, "No blast radius data") {
		t.Errorf("expected nil message, got %s", output)
	}
}

func TestFormatBlastRadiusNoImpact(t *testing.T) {
	t.Parallel()
	a := mkDepAgent("solo", TypeToolCalling, TrustStandard)
	br := AnalyzeBlastRadius(mkDepInventory(a), "solo")
	output := FormatBlastRadius(br)

	if !strings.Contains(output, "BLAST RADIUS: solo") {
		t.Error("should show agent name even with no impact")
	}
	if !strings.Contains(output, "Total Affected:") {
		t.Error("should show total affected line")
	}
}

func TestSummarizeDependencies(t *testing.T) {
	t.Parallel()
	a := mkDepAgentWithTools("a", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	b := mkDepAgentWithTools("b", TypeToolCalling, TrustStandard,
		[]ToolAccess{mkDepTool("t1")})
	r := GenerateDependencyReport(mkDepInventory(a, b))
	summary := SummarizeDependencies(r)

	if !strings.Contains(summary, "2 agents") {
		t.Errorf("summary should mention agent count, got: %s", summary)
	}
	if !strings.Contains(summary, "dependencies") {
		t.Errorf("summary should mention dependencies, got: %s", summary)
	}
}

func TestSummarizeDependenciesNoDeps(t *testing.T) {
	t.Parallel()
	a := mkDepAgent("a", TypeToolCalling, TrustStandard)
	b := mkDepAgent("b", TypeRetrieval, TrustLow)
	r := GenerateDependencyReport(mkDepInventory(a, b))
	summary := SummarizeDependencies(r)

	if !strings.Contains(summary, "no dependencies") {
		t.Errorf("expected 'no dependencies' in summary, got: %s", summary)
	}
}

func TestSummarizeDependenciesNil(t *testing.T) {
	t.Parallel()
	summary := SummarizeDependencies(nil)
	if !strings.Contains(summary, "No dependency data") {
		t.Errorf("expected nil message, got: %s", summary)
	}
}

func TestSummarizeDependenciesEmpty(t *testing.T) {
	t.Parallel()
	r := GenerateDependencyReport(mkDepInventory())
	summary := SummarizeDependencies(r)

	if !strings.Contains(summary, "Empty inventory") {
		t.Errorf("expected empty inventory message, got: %s", summary)
	}
}
