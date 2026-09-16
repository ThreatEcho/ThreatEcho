// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"strings"
	"testing"
)

// --- trust test helpers ---

func mkAgent(name, typ, priv string, tools, policies []string) AgentNode {
	return AgentNode{
		Name:      name,
		Type:      typ,
		Privilege: priv,
		Tools:     tools,
		Policies:  policies,
	}
}

func mkEdge(from, to, dir, channel string, verified bool) TrustEdge {
	return TrustEdge{
		From:      from,
		To:        to,
		Direction: dir,
		Channel:   channel,
		Verified:  verified,
	}
}

// --- NewTrustGraph ---

func TestNewTrustGraph_Empty(t *testing.T) {
	g := NewTrustGraph(nil, nil)
	if g == nil {
		t.Fatal("expected non-nil graph")
	}
	if len(g.Agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(g.Agents))
	}
	if len(g.Edges) != 0 {
		t.Errorf("expected 0 edges, got %d", len(g.Edges))
	}
}

func TestNewTrustGraph_CopiesSlices(t *testing.T) {
	agents := []AgentNode{mkAgent("a", "llm", "standard", nil, nil)}
	edges := []TrustEdge{mkEdge("a", "b", "unidirectional", "api", true)}
	g := NewTrustGraph(agents, edges)

	// Mutate originals.
	agents[0].Name = "mutated"
	edges[0].From = "mutated"

	if g.Agents[0].Name == "mutated" {
		t.Error("agents slice was not copied")
	}
	if g.Edges[0].From == "mutated" {
		t.Error("edges slice was not copied")
	}
}

// --- AnalyzeTrust ---

func TestAnalyzeTrust_EmptyGraph(t *testing.T) {
	g := NewTrustGraph(nil, nil)
	ta := AnalyzeTrust(g)

	if ta.Graph != g {
		t.Error("expected graph reference preserved")
	}
	if len(ta.EscalationPaths) != 0 {
		t.Errorf("expected 0 escalation paths, got %d", len(ta.EscalationPaths))
	}
	if len(ta.UnverifiedEdges) != 0 {
		t.Errorf("expected 0 unverified edges, got %d", len(ta.UnverifiedEdges))
	}
	if len(ta.OverprivilegedAgents) != 0 {
		t.Errorf("expected 0 overprivileged agents, got %d", len(ta.OverprivilegedAgents))
	}
	if len(ta.IsolatedAgents) != 0 {
		t.Errorf("expected 0 isolated agents, got %d", len(ta.IsolatedAgents))
	}
	if ta.Stats.TotalAgents != 0 {
		t.Errorf("expected 0 total agents, got %d", ta.Stats.TotalAgents)
	}
	if ta.Stats.EscalationRisk != "none" {
		t.Errorf("expected escalation risk 'none', got %q", ta.Stats.EscalationRisk)
	}
}

func TestAnalyzeTrust_NilGraph(t *testing.T) {
	ta := AnalyzeTrust(nil)
	if ta.Stats.TotalAgents != 0 {
		t.Errorf("expected 0 total agents for nil graph, got %d", ta.Stats.TotalAgents)
	}
}

func TestAnalyzeTrust_SingleAgent_NoEdges(t *testing.T) {
	agents := []AgentNode{mkAgent("solo", "llm", "standard", nil, nil)}
	g := NewTrustGraph(agents, nil)
	ta := AnalyzeTrust(g)

	if ta.Stats.TotalAgents != 1 {
		t.Errorf("expected 1 agent, got %d", ta.Stats.TotalAgents)
	}
	if len(ta.IsolatedAgents) != 1 {
		t.Errorf("expected 1 isolated agent, got %d", len(ta.IsolatedAgents))
	}
	if ta.IsolatedAgents[0].Name != "solo" {
		t.Errorf("expected isolated agent 'solo', got %q", ta.IsolatedAgents[0].Name)
	}
}

func TestAnalyzeTrust_SimpleTwoAgent(t *testing.T) {
	agents := []AgentNode{
		mkAgent("worker", "llm", "standard", nil, []string{"policy-1"}),
		mkAgent("boss", "orchestrator", "admin", nil, []string{"policy-2"}),
	}
	edges := []TrustEdge{
		mkEdge("worker", "boss", "unidirectional", "api", true),
	}
	g := NewTrustGraph(agents, edges)
	ta := AnalyzeTrust(g)

	if ta.Stats.TotalAgents != 2 {
		t.Errorf("expected 2 agents, got %d", ta.Stats.TotalAgents)
	}
	if ta.Stats.TotalEdges != 1 {
		t.Errorf("expected 1 edge, got %d", ta.Stats.TotalEdges)
	}
	if len(ta.EscalationPaths) != 1 {
		t.Fatalf("expected 1 escalation path, got %d", len(ta.EscalationPaths))
	}
	ep := ta.EscalationPaths[0]
	if ep.From != "worker" || ep.To != "boss" {
		t.Errorf("expected worker→boss, got %s→%s", ep.From, ep.To)
	}
}

// --- FindEscalationPaths ---

func TestTrustFindEscalationPaths_NilGraph(t *testing.T) {
	paths := FindEscalationPaths(nil)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for nil graph, got %d", len(paths))
	}
}

func TestTrustFindEscalationPaths_NoEdges(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("low", "llm", "restricted", nil, nil),
			mkAgent("high", "orchestrator", "admin", nil, nil),
		},
		nil,
	)
	paths := FindEscalationPaths(g)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths with no edges, got %d", len(paths))
	}
}

func TestTrustFindEscalationPaths_OneHop_RestrictedToAdmin(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("attacker", "llm", "restricted", nil, nil),
			mkAgent("root", "orchestrator", "admin", nil, nil),
		},
		[]TrustEdge{mkEdge("attacker", "root", "unidirectional", "api", true)},
	)
	paths := FindEscalationPaths(g)

	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	ep := paths[0]
	if ep.Hops != 1 {
		t.Errorf("expected 1 hop, got %d", ep.Hops)
	}
	if ep.Risk != "critical" {
		t.Errorf("expected critical risk for 1-hop restricted→admin, got %q", ep.Risk)
	}
	if len(ep.Path) != 2 || ep.Path[0] != "attacker" || ep.Path[1] != "root" {
		t.Errorf("unexpected path: %v", ep.Path)
	}
}

func TestTrustFindEscalationPaths_TwoHops(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("attacker", "llm", "restricted", nil, nil),
			mkAgent("relay", "worker", "standard", nil, nil),
			mkAgent("root", "orchestrator", "admin", nil, nil),
		},
		[]TrustEdge{
			mkEdge("attacker", "relay", "unidirectional", "api", true),
			mkEdge("relay", "root", "unidirectional", "api", true),
		},
	)
	paths := FindEscalationPaths(g)

	// attacker(restricted)→root(admin) via relay (2 hops)
	// attacker(restricted)→relay(standard) - no escalation (standard is not >= elevated)
	// relay(standard)→root(admin) via relay→root (1 hop)
	found := false
	for _, ep := range paths {
		if ep.From == "attacker" && ep.To == "root" {
			found = true
			if ep.Hops != 2 {
				t.Errorf("expected 2 hops, got %d", ep.Hops)
			}
			if ep.Risk != "high" {
				t.Errorf("expected high risk for 2-hop restricted→admin, got %q", ep.Risk)
			}
		}
	}
	if !found {
		t.Error("did not find attacker→root escalation path")
	}
}

func TestTrustFindEscalationPaths_ThreePlusHops(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("a", "llm", "restricted", nil, nil),
			mkAgent("b", "worker", "restricted", nil, nil),
			mkAgent("c", "worker", "standard", nil, nil),
			mkAgent("d", "orchestrator", "admin", nil, nil),
		},
		[]TrustEdge{
			mkEdge("a", "b", "unidirectional", "api", true),
			mkEdge("b", "c", "unidirectional", "api", true),
			mkEdge("c", "d", "unidirectional", "api", true),
		},
	)
	paths := FindEscalationPaths(g)

	for _, ep := range paths {
		if ep.From == "a" && ep.To == "d" {
			if ep.Hops != 3 {
				t.Errorf("expected 3 hops, got %d", ep.Hops)
			}
			if ep.Risk != "medium" {
				t.Errorf("expected medium risk for 3-hop restricted→admin, got %q", ep.Risk)
			}
			return
		}
	}
	t.Error("did not find a→d escalation path")
}

func TestTrustFindEscalationPaths_StandardToAdmin_OneHop(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("worker", "llm", "standard", nil, nil),
			mkAgent("root", "orchestrator", "admin", nil, nil),
		},
		[]TrustEdge{mkEdge("worker", "root", "unidirectional", "api", true)},
	)
	paths := FindEscalationPaths(g)

	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if paths[0].Risk != "high" {
		t.Errorf("expected high risk for 1-hop standard→admin, got %q", paths[0].Risk)
	}
}

func TestTrustFindEscalationPaths_StandardToElevated_OneHop(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("worker", "llm", "standard", nil, nil),
			mkAgent("lead", "orchestrator", "elevated", nil, nil),
		},
		[]TrustEdge{mkEdge("worker", "lead", "unidirectional", "api", true)},
	)
	paths := FindEscalationPaths(g)

	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if paths[0].Risk != "medium" {
		t.Errorf("expected medium risk for 1-hop standard→elevated, got %q", paths[0].Risk)
	}
}

func TestTrustFindEscalationPaths_FlatPrivilege_NoPaths(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("a", "llm", "standard", nil, nil),
			mkAgent("b", "worker", "standard", nil, nil),
			mkAgent("c", "retrieval", "standard", nil, nil),
		},
		[]TrustEdge{
			mkEdge("a", "b", "unidirectional", "api", true),
			mkEdge("b", "c", "unidirectional", "api", true),
		},
	)
	paths := FindEscalationPaths(g)

	if len(paths) != 0 {
		t.Errorf("expected 0 escalation paths in flat-priv graph, got %d", len(paths))
	}
}

func TestTrustFindEscalationPaths_HighToLow_NoPaths(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("boss", "orchestrator", "admin", nil, nil),
			mkAgent("worker", "llm", "restricted", nil, nil),
		},
		[]TrustEdge{mkEdge("boss", "worker", "unidirectional", "api", true)},
	)
	paths := FindEscalationPaths(g)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for high→low direction, got %d", len(paths))
	}
}

func TestTrustFindEscalationPaths_BidirectionalEdge(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("low", "llm", "restricted", nil, nil),
			mkAgent("high", "orchestrator", "admin", nil, nil),
		},
		[]TrustEdge{mkEdge("high", "low", "bidirectional", "api", true)},
	)
	paths := FindEscalationPaths(g)

	// low can reach high through the bidirectional edge.
	if len(paths) != 1 {
		t.Fatalf("expected 1 escalation path via bidirectional edge, got %d", len(paths))
	}
	if paths[0].From != "low" || paths[0].To != "high" {
		t.Errorf("expected low→high, got %s→%s", paths[0].From, paths[0].To)
	}
}

// --- Unverified edges ---

func TestTrustUnverifiedEdgeDetection(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("a", "llm", "standard", nil, nil),
			mkAgent("b", "worker", "standard", nil, nil),
		},
		[]TrustEdge{
			mkEdge("a", "b", "unidirectional", "api", false),
		},
	)
	ta := AnalyzeTrust(g)

	if len(ta.UnverifiedEdges) != 1 {
		t.Fatalf("expected 1 unverified edge, got %d", len(ta.UnverifiedEdges))
	}
	if ta.UnverifiedEdges[0].From != "a" {
		t.Errorf("expected unverified from 'a', got %q", ta.UnverifiedEdges[0].From)
	}
	if ta.Stats.UnverifiedEdges != 1 {
		t.Errorf("expected stats.UnverifiedEdges=1, got %d", ta.Stats.UnverifiedEdges)
	}
}

func TestTrustVerifiedEdges_NoFindings(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("a", "llm", "standard", nil, []string{"p1"}),
			mkAgent("b", "worker", "standard", nil, []string{"p2"}),
		},
		[]TrustEdge{
			mkEdge("a", "b", "unidirectional", "api", true),
		},
	)
	ta := AnalyzeTrust(g)

	if len(ta.UnverifiedEdges) != 0 {
		t.Errorf("expected 0 unverified edges, got %d", len(ta.UnverifiedEdges))
	}
}

// --- Overprivileged agents ---

func TestTrustOverprivilegedAgentDetection(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("unconstrained", "orchestrator", "admin", nil, nil),
			mkAgent("constrained", "orchestrator", "admin", nil, []string{"strict-policy"}),
		},
		nil,
	)
	ta := AnalyzeTrust(g)

	if len(ta.OverprivilegedAgents) != 1 {
		t.Fatalf("expected 1 overprivileged agent, got %d", len(ta.OverprivilegedAgents))
	}
	if ta.OverprivilegedAgents[0].Name != "unconstrained" {
		t.Errorf("expected 'unconstrained', got %q", ta.OverprivilegedAgents[0].Name)
	}
}

func TestTrustOverprivileged_NonAdmin_Ignored(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("elevated-no-policy", "llm", "elevated", nil, nil),
		},
		nil,
	)
	ta := AnalyzeTrust(g)

	if len(ta.OverprivilegedAgents) != 0 {
		t.Errorf("elevated agents without policy should not be flagged, got %d", len(ta.OverprivilegedAgents))
	}
}

func TestTrustOverprivileged_AdminWithEmptyPolicies(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("admin-empty", "orchestrator", "admin", nil, []string{}),
		},
		nil,
	)
	ta := AnalyzeTrust(g)

	if len(ta.OverprivilegedAgents) != 1 {
		t.Errorf("admin with empty policies slice should be flagged, got %d", len(ta.OverprivilegedAgents))
	}
}

// --- Isolated agents ---

func TestTrustIsolatedAgentDetection(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("connected", "llm", "standard", nil, nil),
			mkAgent("lonely", "retrieval", "standard", nil, nil),
			mkAgent("peer", "worker", "standard", nil, nil),
		},
		[]TrustEdge{
			mkEdge("connected", "peer", "unidirectional", "api", true),
		},
	)
	ta := AnalyzeTrust(g)

	if len(ta.IsolatedAgents) != 1 {
		t.Fatalf("expected 1 isolated agent, got %d", len(ta.IsolatedAgents))
	}
	if ta.IsolatedAgents[0].Name != "lonely" {
		t.Errorf("expected 'lonely', got %q", ta.IsolatedAgents[0].Name)
	}
}

func TestTrustIsolatedAgent_TargetOfEdge_NotIsolated(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("sender", "llm", "standard", nil, nil),
			mkAgent("receiver", "worker", "standard", nil, nil),
		},
		[]TrustEdge{
			mkEdge("sender", "receiver", "unidirectional", "api", true),
		},
	)
	ta := AnalyzeTrust(g)

	if len(ta.IsolatedAgents) != 0 {
		t.Errorf("receiver of an edge should not be isolated, got %d", len(ta.IsolatedAgents))
	}
}

// --- Stats ---

func TestTrustStats_Counts(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("admin1", "orchestrator", "admin", nil, nil),
			mkAgent("admin2", "orchestrator", "admin", nil, nil),
			mkAgent("worker", "llm", "standard", nil, nil),
		},
		[]TrustEdge{
			mkEdge("worker", "admin1", "unidirectional", "api", false),
			mkEdge("worker", "admin2", "unidirectional", "api", true),
		},
	)
	ta := AnalyzeTrust(g)

	if ta.Stats.TotalAgents != 3 {
		t.Errorf("expected 3 agents, got %d", ta.Stats.TotalAgents)
	}
	if ta.Stats.TotalEdges != 2 {
		t.Errorf("expected 2 edges, got %d", ta.Stats.TotalEdges)
	}
	if ta.Stats.AdminAgents != 2 {
		t.Errorf("expected 2 admin agents, got %d", ta.Stats.AdminAgents)
	}
	if ta.Stats.UnverifiedEdges != 1 {
		t.Errorf("expected 1 unverified edge, got %d", ta.Stats.UnverifiedEdges)
	}
}

func TestTrustStats_AvgConnections(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("a", "llm", "standard", nil, nil),
			mkAgent("b", "worker", "standard", nil, nil),
		},
		[]TrustEdge{
			mkEdge("a", "b", "unidirectional", "api", true),
		},
	)
	ta := AnalyzeTrust(g)

	// a has 1 connection, b has 1 connection => avg = 2/2 = 1.0
	if ta.Stats.AvgConnections != 1.0 {
		t.Errorf("expected avg connections 1.0, got %.1f", ta.Stats.AvgConnections)
	}
}

func TestTrustStats_MaxDepth(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("a", "llm", "standard", nil, nil),
			mkAgent("b", "worker", "standard", nil, nil),
			mkAgent("c", "worker", "standard", nil, nil),
			mkAgent("d", "orchestrator", "standard", nil, nil),
		},
		[]TrustEdge{
			mkEdge("a", "b", "unidirectional", "api", true),
			mkEdge("b", "c", "unidirectional", "api", true),
			mkEdge("c", "d", "unidirectional", "api", true),
		},
	)
	ta := AnalyzeTrust(g)

	if ta.Stats.MaxDepth != 3 {
		t.Errorf("expected max depth 3, got %d", ta.Stats.MaxDepth)
	}
}

func TestTrustStats_EscalationRisk_Critical(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("low", "llm", "restricted", nil, nil),
			mkAgent("high", "orchestrator", "admin", nil, nil),
		},
		[]TrustEdge{mkEdge("low", "high", "unidirectional", "api", true)},
	)
	ta := AnalyzeTrust(g)

	if ta.Stats.EscalationRisk != "critical" {
		t.Errorf("expected escalation risk 'critical', got %q", ta.Stats.EscalationRisk)
	}
}

func TestTrustStats_EscalationRisk_None(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("a", "llm", "standard", nil, nil),
			mkAgent("b", "worker", "standard", nil, nil),
		},
		[]TrustEdge{mkEdge("a", "b", "unidirectional", "api", true)},
	)
	ta := AnalyzeTrust(g)

	if ta.Stats.EscalationRisk != "none" {
		t.Errorf("expected escalation risk 'none', got %q", ta.Stats.EscalationRisk)
	}
}

// --- Findings ---

func TestTrustFindingGeneration_EscalationFinding(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("low", "llm", "restricted", nil, nil),
			mkAgent("high", "orchestrator", "admin", nil, nil),
		},
		[]TrustEdge{mkEdge("low", "high", "unidirectional", "api", true)},
	)
	ta := AnalyzeTrust(g)

	found := false
	for _, f := range ta.Findings {
		if f.Category == "escalation" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("expected critical severity, got %q", f.Severity)
			}
			if !strings.Contains(f.Title, "low") || !strings.Contains(f.Title, "high") {
				t.Errorf("finding title should mention agents: %q", f.Title)
			}
		}
	}
	if !found {
		t.Error("expected an escalation finding")
	}
}

func TestTrustFindingGeneration_UnverifiedFinding(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("a", "llm", "standard", nil, []string{"p"}),
			mkAgent("b", "worker", "standard", nil, []string{"p"}),
		},
		[]TrustEdge{mkEdge("a", "b", "unidirectional", "api", false)},
	)
	ta := AnalyzeTrust(g)

	found := false
	for _, f := range ta.Findings {
		if f.Category == "unverified" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected high severity for unverified, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected an unverified finding")
	}
}

func TestTrustFindingGeneration_OverprivilegedFinding(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("boss", "orchestrator", "admin", nil, nil),
		},
		nil,
	)
	ta := AnalyzeTrust(g)

	found := false
	for _, f := range ta.Findings {
		if f.Category == "overprivileged" {
			found = true
			if !strings.Contains(f.Description, "no policy") {
				t.Errorf("expected mention of 'no policy' in description: %q", f.Description)
			}
		}
	}
	if !found {
		t.Error("expected an overprivileged finding")
	}
}

func TestTrustFindingGeneration_IsolationFinding(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("ghost", "retrieval", "standard", nil, nil),
		},
		nil,
	)
	ta := AnalyzeTrust(g)

	found := false
	for _, f := range ta.Findings {
		if f.Category == "isolation" {
			found = true
			if f.Severity != "medium" {
				t.Errorf("expected medium severity for isolation, got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected an isolation finding")
	}
}

// --- BuildTrustFromTraces ---

func TestBuildTrustFromTraces_Empty(t *testing.T) {
	g := BuildTrustFromTraces(nil)
	if g == nil {
		t.Fatal("expected non-nil graph")
	}
	if len(g.Agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(g.Agents))
	}
}

func TestBuildTrustFromTraces_SingleTrace_NoMessages(t *testing.T) {
	tr := makeTrace("t1", "agent-a",
		toolCallEvent("e1", "http_request", "send", "https://api.example.com"),
	)
	g := BuildTrustFromTraces([]*Trace{tr})

	if len(g.Agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(g.Agents))
	}
	if g.Agents[0].Name != "agent-a" {
		t.Errorf("expected agent 'agent-a', got %q", g.Agents[0].Name)
	}
	if len(g.Edges) != 0 {
		t.Errorf("expected 0 edges with no agent messages, got %d", len(g.Edges))
	}
}

func TestBuildTrustFromTraces_AgentMessages_CreateEdges(t *testing.T) {
	tr := makeTrace("t1", "orchestrator",
		agentMsgEvent("e1", "orchestrator", "worker-1", "do task"),
		agentMsgEvent("e2", "orchestrator", "worker-2", "do other task"),
	)
	g := BuildTrustFromTraces([]*Trace{tr})

	if len(g.Agents) < 3 {
		t.Fatalf("expected at least 3 agents, got %d", len(g.Agents))
	}
	if len(g.Edges) != 2 {
		t.Errorf("expected 2 edges, got %d", len(g.Edges))
	}
}

func TestBuildTrustFromTraces_BidirectionalDetection(t *testing.T) {
	t1 := makeTrace("t1", "agent-a",
		agentMsgEvent("e1", "agent-a", "agent-b", "request"),
	)
	t2 := makeTrace("t2", "agent-b",
		agentMsgEvent("e2", "agent-b", "agent-a", "response"),
	)
	g := BuildTrustFromTraces([]*Trace{t1, t2})

	// Should have exactly 1 bidirectional edge.
	if len(g.Edges) != 1 {
		t.Fatalf("expected 1 bidirectional edge, got %d edges", len(g.Edges))
	}
	if g.Edges[0].Direction != "bidirectional" {
		t.Errorf("expected bidirectional, got %q", g.Edges[0].Direction)
	}
}

func TestBuildTrustFromTraces_ElevatedToolCall_InfersPrivilege(t *testing.T) {
	tr := &Trace{
		ID:        "t1",
		AgentName: "priv-agent",
		AgentType: "llm",
		StartTime: "2026-09-14T10:00:00Z",
		EndTime:   "2026-09-14T10:05:00Z",
		Events: []TraceEvent{
			{
				ID:        "e1",
				Timestamp: "2026-09-14T10:01:00Z",
				Type:      "tool_call",
				ToolCall: &ToolCallEvent{
					Tool:     "shell_exec",
					Action:   "execute",
					Elevated: true,
					Success:  true,
				},
			},
		},
	}
	g := BuildTrustFromTraces([]*Trace{tr})

	if len(g.Agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(g.Agents))
	}
	if g.Agents[0].Privilege != "elevated" {
		t.Errorf("expected elevated privilege from elevated tool call, got %q", g.Agents[0].Privilege)
	}
}

func TestBuildTrustFromTraces_TracksTools(t *testing.T) {
	tr := makeTrace("t1", "multi-tool",
		toolCallEvent("e1", "http_request", "send", "https://example.com"),
		toolCallEvent("e2", "shell_exec", "execute", ""),
		toolCallEvent("e3", "http_request", "send", "https://other.com"), // duplicate tool
	)
	g := BuildTrustFromTraces([]*Trace{tr})

	if len(g.Agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(g.Agents))
	}
	tools := g.Agents[0].Tools
	if len(tools) != 2 {
		t.Errorf("expected 2 unique tools, got %d: %v", len(tools), tools)
	}
}

func TestBuildTrustFromTraces_NilTrace_Skipped(t *testing.T) {
	tr := makeTrace("t1", "agent-a")
	g := BuildTrustFromTraces([]*Trace{nil, tr, nil})

	if len(g.Agents) != 1 {
		t.Errorf("expected 1 agent (nil traces skipped), got %d", len(g.Agents))
	}
}

// --- Complex multi-agent graph ---

func TestTrustComplexMultiAgentGraph(t *testing.T) {
	agents := []AgentNode{
		mkAgent("orchestrator", "orchestrator", "admin", []string{"shell_exec"}, []string{"root-policy"}),
		mkAgent("analyzer", "llm", "elevated", []string{"http_request"}, []string{"sec-policy"}),
		mkAgent("retriever", "retrieval", "standard", []string{"search_knowledge_base"}, nil),
		mkAgent("writer", "worker", "standard", []string{"write_knowledge_base"}, []string{"write-policy"}),
		mkAgent("monitor", "worker", "restricted", nil, nil),
		mkAgent("shadow", "llm", "standard", nil, nil), // isolated
	}
	edges := []TrustEdge{
		mkEdge("monitor", "retriever", "unidirectional", "inter-agent-bus", false),
		mkEdge("retriever", "analyzer", "unidirectional", "api", true),
		mkEdge("analyzer", "orchestrator", "unidirectional", "direct", true),
		mkEdge("writer", "retriever", "bidirectional", "shared-memory", false),
		mkEdge("orchestrator", "writer", "unidirectional", "api", true),
	}
	g := NewTrustGraph(agents, edges)
	ta := AnalyzeTrust(g)

	// Check escalation paths exist.
	if len(ta.EscalationPaths) == 0 {
		t.Error("expected escalation paths in complex graph")
	}
	// monitor(restricted) -> retriever -> analyzer(elevated) should exist.
	foundMonitorToAnalyzer := false
	for _, ep := range ta.EscalationPaths {
		if ep.From == "monitor" && ep.To == "analyzer" {
			foundMonitorToAnalyzer = true
		}
	}
	if !foundMonitorToAnalyzer {
		t.Error("expected monitor→analyzer escalation path")
	}

	// shadow should be isolated.
	if len(ta.IsolatedAgents) != 1 || ta.IsolatedAgents[0].Name != "shadow" {
		t.Errorf("expected shadow to be isolated, got %v", ta.IsolatedAgents)
	}

	// Unverified edges should exist.
	if len(ta.UnverifiedEdges) < 2 {
		t.Errorf("expected at least 2 unverified edges, got %d", len(ta.UnverifiedEdges))
	}

	// Should have findings.
	if len(ta.Findings) == 0 {
		t.Error("expected findings in complex graph")
	}

	// Stats should be filled.
	if ta.Stats.TotalAgents != 6 {
		t.Errorf("expected 6 agents in stats, got %d", ta.Stats.TotalAgents)
	}
	if ta.Stats.TotalEdges != 5 {
		t.Errorf("expected 5 edges in stats, got %d", ta.Stats.TotalEdges)
	}
}

// --- FormatTrustAnalysis ---

func TestFormatTrustAnalysis_Nil(t *testing.T) {
	out := FormatTrustAnalysis(nil)
	if !strings.Contains(out, "No trust analysis") {
		t.Error("expected nil message")
	}
}

func TestFormatTrustAnalysis_EmptyGraph(t *testing.T) {
	ta := AnalyzeTrust(NewTrustGraph(nil, nil))
	out := FormatTrustAnalysis(ta)

	if !strings.Contains(out, "Trust Graph Analysis") {
		t.Error("expected header")
	}
	if !strings.Contains(out, "No escalation paths") {
		t.Error("expected no escalation paths message")
	}
	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Error("expected box drawing characters")
	}
}

func TestFormatTrustAnalysis_WithEscalation(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("attacker", "llm", "restricted", nil, nil),
			mkAgent("root", "orchestrator", "admin", nil, nil),
		},
		[]TrustEdge{mkEdge("attacker", "root", "unidirectional", "api", false)},
	)
	ta := AnalyzeTrust(g)
	out := FormatTrustAnalysis(ta)

	if !strings.Contains(out, "Escalation") {
		t.Error("expected escalation section")
	}
	if !strings.Contains(out, "attacker") {
		t.Error("expected attacker agent name in output")
	}
	if !strings.Contains(out, "Unverified") {
		t.Error("expected unverified edges section")
	}
}

func TestFormatTrustAnalysis_ContainsStats(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("a", "llm", "standard", nil, nil),
			mkAgent("b", "worker", "standard", nil, nil),
		},
		[]TrustEdge{mkEdge("a", "b", "unidirectional", "api", true)},
	)
	ta := AnalyzeTrust(g)
	out := FormatTrustAnalysis(ta)

	if !strings.Contains(out, "Total agents") {
		t.Error("expected total agents in stats")
	}
	if !strings.Contains(out, "Total edges") {
		t.Error("expected total edges in stats")
	}
}

func TestFormatTrustAnalysis_OverprivilegedShown(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("danger", "orchestrator", "admin", nil, nil),
		},
		nil,
	)
	ta := AnalyzeTrust(g)
	out := FormatTrustAnalysis(ta)

	if !strings.Contains(out, "Overprivileged") {
		t.Error("expected overprivileged section")
	}
	if !strings.Contains(out, "danger") {
		t.Error("expected agent name in overprivileged section")
	}
}

// --- Risk classification edge cases ---

func TestTrustRiskClassification_RestrictedToElevated_OneHop(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("low", "llm", "restricted", nil, nil),
			mkAgent("mid", "orchestrator", "elevated", nil, nil),
		},
		[]TrustEdge{mkEdge("low", "mid", "unidirectional", "api", true)},
	)
	paths := FindEscalationPaths(g)

	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if paths[0].Risk != "high" {
		t.Errorf("expected high risk for 1-hop restricted→elevated, got %q", paths[0].Risk)
	}
}

func TestTrustRiskClassification_RestrictedToElevated_TwoHops(t *testing.T) {
	g := NewTrustGraph(
		[]AgentNode{
			mkAgent("low", "llm", "restricted", nil, nil),
			mkAgent("relay", "worker", "restricted", nil, nil),
			mkAgent("mid", "orchestrator", "elevated", nil, nil),
		},
		[]TrustEdge{
			mkEdge("low", "relay", "unidirectional", "api", true),
			mkEdge("relay", "mid", "unidirectional", "api", true),
		},
	)
	paths := FindEscalationPaths(g)

	for _, ep := range paths {
		if ep.From == "low" && ep.To == "mid" {
			if ep.Risk != "medium" {
				t.Errorf("expected medium risk for 2-hop restricted→elevated, got %q", ep.Risk)
			}
			return
		}
	}
	t.Error("did not find low→mid escalation path")
}
