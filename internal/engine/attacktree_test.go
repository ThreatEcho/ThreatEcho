// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func atkAgent(name, typ, trust string, tools []agent.ToolAccess, guardrails []agent.Guardrail) *agent.Agent {
	a := &agent.Agent{
		Meta: agent.AgentMeta{Name: name, Type: typ},
		Trust: agent.TrustConfig{
			Level: trust,
		},
		Tools:      tools,
		Guardrails: guardrails,
	}
	return a
}

func atkTool(name string, elevated bool) agent.ToolAccess {
	return agent.ToolAccess{Name: name, Elevated: elevated}
}

func atkInventory(agents ...*agent.Agent) *agent.Inventory {
	inv := &agent.Inventory{}
	for _, a := range agents {
		inv.Agents = append(inv.Agents, a)
	}
	return inv
}

func atkDenyPolicy(tools ...string) *policy.Policy {
	return &policy.Policy{
		Rules: []policy.Rule{
			{
				ID:     "deny-1",
				Effect: "deny",
				Match: policy.RuleMatch{
					Tools: tools,
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// BuildAttackTree tests
// ---------------------------------------------------------------------------

func TestBuildAttackTree_NilInventory(t *testing.T) {
	tree := BuildAttackTree(nil, nil)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	if tree.Root.Type != NodeLeaf {
		t.Errorf("expected LEAF root for nil inventory, got %s", tree.Root.Type)
	}
}

func TestBuildAttackTree_EmptyInventory(t *testing.T) {
	inv := &agent.Inventory{}
	tree := BuildAttackTree(inv, nil)
	if tree.Root.Type != NodeLeaf {
		t.Errorf("expected LEAF root for empty inventory, got %s", tree.Root.Type)
	}
}

func TestBuildAttackTree_SingleAgent(t *testing.T) {
	inv := atkInventory(
		atkAgent("worker-1", agent.TypeToolCalling, agent.TrustStandard,
			[]agent.ToolAccess{atkTool("code-exec", true)}, nil),
	)
	tree := BuildAttackTree(inv, nil)

	if tree.Root.Type != NodeOR {
		t.Fatalf("expected OR root, got %s", tree.Root.Type)
	}
	if len(tree.Root.Children) != 1 {
		t.Fatalf("expected 1 agent child, got %d", len(tree.Root.Children))
	}
	if tree.NodeCount < 4 {
		t.Errorf("expected at least 4 nodes, got %d", tree.NodeCount)
	}
	if tree.LeafCount == 0 {
		t.Error("expected at least 1 leaf")
	}
	if tree.MaxDepth < 3 {
		t.Errorf("expected depth >= 3, got %d", tree.MaxDepth)
	}
	if tree.RiskScore <= 0 {
		t.Error("expected positive risk score")
	}
}

func TestBuildAttackTree_MultipleAgents(t *testing.T) {
	inv := atkInventory(
		atkAgent("admin-agent", agent.TypeOrchestrator, agent.TrustAdmin,
			[]agent.ToolAccess{atkTool("deploy", true), atkTool("ssh", true)}, nil),
		atkAgent("data-agent", agent.TypeRetrieval, agent.TrustLow,
			[]agent.ToolAccess{atkTool("db-query", false)}, nil),
	)
	tree := BuildAttackTree(inv, nil)

	if len(tree.Root.Children) != 2 {
		t.Fatalf("expected 2 agent children, got %d", len(tree.Root.Children))
	}

	adminNode := tree.Root.Children[0]
	if !strings.Contains(adminNode.Title, "admin-agent") {
		t.Errorf("expected admin-agent in first child title, got %s", adminNode.Title)
	}

	if tree.NodeCount < 8 {
		t.Errorf("expected at least 8 nodes for 2 agents, got %d", tree.NodeCount)
	}
}

func TestBuildAttackTree_AdminHigherRisk(t *testing.T) {
	admin := atkAgent("admin", agent.TypeOrchestrator, agent.TrustAdmin,
		[]agent.ToolAccess{atkTool("deploy", true)}, nil)
	low := atkAgent("low", agent.TypeRetrieval, agent.TrustLow,
		[]agent.ToolAccess{atkTool("read-db", false)}, nil)

	adminTree := BuildAttackTree(atkInventory(admin), nil)
	lowTree := BuildAttackTree(atkInventory(low), nil)

	if adminTree.RiskScore <= lowTree.RiskScore {
		t.Errorf("admin risk %.2f should exceed low risk %.2f",
			adminTree.RiskScore, lowTree.RiskScore)
	}
}

func TestBuildAttackTree_PolicyMitigation(t *testing.T) {
	inv := atkInventory(
		atkAgent("worker", agent.TypeToolCalling, agent.TrustStandard,
			[]agent.ToolAccess{atkTool("code-exec", true)}, nil),
	)

	without := BuildAttackTree(inv, nil)
	with := BuildAttackTree(inv, []*policy.Policy{atkDenyPolicy("code-exec")})

	if with.Mitigated <= without.Mitigated {
		t.Errorf("policy should increase mitigated count: without=%d, with=%d",
			without.Mitigated, with.Mitigated)
	}
}

func TestBuildAttackTree_WildcardDenyMitigatesAll(t *testing.T) {
	inv := atkInventory(
		atkAgent("worker", agent.TypeToolCalling, agent.TrustStandard,
			[]agent.ToolAccess{
				atkTool("exec", true),
				atkTool("read", false),
			}, nil),
	)
	tree := BuildAttackTree(inv, []*policy.Policy{atkDenyPolicy("*")})

	if tree.Mitigated < 2 {
		t.Errorf("wildcard deny should mitigate all tool leaves, mitigated=%d", tree.Mitigated)
	}
}

func TestBuildAttackTree_GuardrailsReduceBypassProb(t *testing.T) {
	withGuardrails := atkAgent("guarded", agent.TypeToolCalling, agent.TrustStandard,
		[]agent.ToolAccess{atkTool("exec", false)},
		[]agent.Guardrail{{Type: "input_filter"}, {Type: "output_filter"}, {Type: "rate_limit"}})
	withoutGuardrails := atkAgent("open", agent.TypeToolCalling, agent.TrustStandard,
		[]agent.ToolAccess{atkTool("exec", false)}, nil)

	p1 := guardrailBypassProb(withGuardrails)
	p2 := guardrailBypassProb(withoutGuardrails)

	if p1 >= p2 {
		t.Errorf("guarded bypass prob %.2f should be less than open %.2f", p1, p2)
	}
}

func TestBuildAttackTree_TrustExploitSubtree(t *testing.T) {
	a := atkAgent("trusted", agent.TypeToolCalling, agent.TrustElevated,
		[]agent.ToolAccess{atkTool("exec", false)}, nil)
	a.Trust.TrustsFrom = []string{"low-agent"}
	a.Trust.CanEscalate = true

	inv := atkInventory(a)
	tree := BuildAttackTree(inv, nil)

	found := false
	var walk func(n *AttackNode)
	walk = func(n *AttackNode) {
		if strings.Contains(n.Title, "Exploit Trust") {
			found = true
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tree.Root)

	if !found {
		t.Error("expected trust exploitation subtree for agent with delegations")
	}
}

func TestBuildAttackTree_PromptInjectionForToolCalling(t *testing.T) {
	inv := atkInventory(
		atkAgent("tool-agent", agent.TypeToolCalling, agent.TrustStandard,
			[]agent.ToolAccess{atkTool("api", false)}, nil),
	)
	tree := BuildAttackTree(inv, nil)

	found := false
	var walk func(n *AttackNode)
	walk = func(n *AttackNode) {
		if strings.Contains(n.Title, "Prompt Injection") {
			found = true
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tree.Root)

	if !found {
		t.Error("expected prompt injection subtree for tool-calling agent")
	}
}

func TestBuildAttackTree_NoPromptInjectionForRetrieval(t *testing.T) {
	inv := atkInventory(
		atkAgent("data", agent.TypeRetrieval, agent.TrustLow,
			[]agent.ToolAccess{atkTool("query", false)}, nil),
	)
	tree := BuildAttackTree(inv, nil)

	found := false
	var walk func(n *AttackNode)
	walk = func(n *AttackNode) {
		if strings.Contains(n.Title, "Prompt Injection") {
			found = true
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tree.Root)

	if found {
		t.Error("retrieval agent should not have prompt injection subtree")
	}
}

func TestBuildAttackTree_EvasionSubtreeOnlyWithGuardrails(t *testing.T) {
	withGR := atkAgent("guarded", agent.TypeRetrieval, agent.TrustStandard,
		nil, []agent.Guardrail{{Type: "content_filter"}})
	withoutGR := atkAgent("open", agent.TypeRetrieval, agent.TrustStandard, nil, nil)

	check := func(root *AttackNode) bool {
		found := false
		var walk func(n *AttackNode)
		walk = func(n *AttackNode) {
			if strings.Contains(n.Title, "Evade Guardrails") {
				found = true
			}
			for _, c := range n.Children {
				walk(c)
			}
		}
		walk(root)
		return found
	}

	t1 := BuildAttackTree(atkInventory(withGR), nil)
	t2 := BuildAttackTree(atkInventory(withoutGR), nil)

	if !check(t1.Root) {
		t.Error("expected evasion subtree for guarded agent")
	}
	if check(t2.Root) {
		t.Error("expected no evasion subtree for unguarded agent")
	}
}

// ---------------------------------------------------------------------------
// Probability propagation
// ---------------------------------------------------------------------------

func TestPropagateProbabilities_ANDNode(t *testing.T) {
	n := &AttackNode{
		Type: NodeAND,
		Children: []*AttackNode{
			{Type: NodeLeaf, Probability: 0.5, Impact: 4.0},
			{Type: NodeLeaf, Probability: 0.8, Impact: 6.0},
		},
	}
	propagateProbabilities(n)

	wantProb := 0.4 // 0.5 * 0.8
	if diff := n.Probability - wantProb; diff > 0.001 || diff < -0.001 {
		t.Errorf("AND probability = %.4f, want %.4f", n.Probability, wantProb)
	}
	wantImpact := 10.0 // 4 + 6 = 10, capped
	if n.Impact != wantImpact {
		t.Errorf("AND impact = %.2f, want %.2f", n.Impact, wantImpact)
	}
}

func TestPropagateProbabilities_ORNode(t *testing.T) {
	n := &AttackNode{
		Type: NodeOR,
		Children: []*AttackNode{
			{Type: NodeLeaf, Probability: 0.3, Impact: 5.0},
			{Type: NodeLeaf, Probability: 0.4, Impact: 8.0},
		},
	}
	propagateProbabilities(n)

	wantProb := 1.0 - (0.7 * 0.6) // 1 - (1-0.3)*(1-0.4) = 0.58
	if diff := n.Probability - wantProb; diff > 0.001 || diff < -0.001 {
		t.Errorf("OR probability = %.4f, want %.4f", n.Probability, wantProb)
	}
	if n.Impact != 8.0 {
		t.Errorf("OR impact = %.2f, want 8.0 (max of children)", n.Impact)
	}
}

func TestPropagateProbabilities_DeepTree(t *testing.T) {
	root := &AttackNode{
		Type: NodeOR,
		Children: []*AttackNode{
			{
				Type: NodeAND,
				Children: []*AttackNode{
					{Type: NodeLeaf, Probability: 1.0, Impact: 5.0},
					{Type: NodeLeaf, Probability: 1.0, Impact: 5.0},
				},
			},
		},
	}
	propagateProbabilities(root)

	if root.Probability != 1.0 {
		t.Errorf("root prob = %.4f, want 1.0 (all certain)", root.Probability)
	}
}

// ---------------------------------------------------------------------------
// Path extraction
// ---------------------------------------------------------------------------

func TestExtractTopPaths_Limit(t *testing.T) {
	inv := atkInventory(
		atkAgent("a1", agent.TypeOrchestrator, agent.TrustAdmin,
			[]agent.ToolAccess{
				atkTool("t1", true), atkTool("t2", true),
				atkTool("t3", true), atkTool("t4", true),
				atkTool("t5", true), atkTool("t6", true),
			}, nil),
	)
	tree := BuildAttackTree(inv, nil)

	if len(tree.TopPaths) > 5 {
		t.Errorf("expected at most 5 top paths, got %d", len(tree.TopPaths))
	}

	for i := 1; i < len(tree.TopPaths); i++ {
		if tree.TopPaths[i].RiskScore > tree.TopPaths[i-1].RiskScore {
			t.Errorf("paths not sorted by risk: [%d]=%.2f > [%d]=%.2f",
				i, tree.TopPaths[i].RiskScore, i-1, tree.TopPaths[i-1].RiskScore)
		}
	}
}

func TestExtractTopPaths_MitigatedPaths(t *testing.T) {
	inv := atkInventory(
		atkAgent("w", agent.TypeToolCalling, agent.TrustStandard,
			[]agent.ToolAccess{atkTool("blocked", false)}, nil),
	)
	tree := BuildAttackTree(inv, []*policy.Policy{atkDenyPolicy("blocked")})

	mitigatedPaths := 0
	for _, p := range tree.TopPaths {
		if p.Mitigated {
			mitigatedPaths++
		}
	}
	if mitigatedPaths == 0 && tree.Mitigated > 0 {
		t.Error("expected at least one mitigated path")
	}
}

// ---------------------------------------------------------------------------
// Tree statistics
// ---------------------------------------------------------------------------

func TestCountNodes(t *testing.T) {
	root := &AttackNode{
		Type: NodeOR,
		Children: []*AttackNode{
			{Type: NodeLeaf},
			{Type: NodeAND, Children: []*AttackNode{
				{Type: NodeLeaf},
				{Type: NodeLeaf},
			}},
		},
	}
	if got := countNodes(root); got != 5 {
		t.Errorf("countNodes = %d, want 5", got)
	}
}

func TestCountLeaves(t *testing.T) {
	root := &AttackNode{
		Type: NodeOR,
		Children: []*AttackNode{
			{Type: NodeLeaf},
			{Type: NodeAND, Children: []*AttackNode{
				{Type: NodeLeaf},
				{Type: NodeLeaf},
			}},
		},
	}
	if got := countLeaves(root); got != 3 {
		t.Errorf("countLeaves = %d, want 3", got)
	}
}

func TestMaxDepth(t *testing.T) {
	root := &AttackNode{
		Type: NodeOR,
		Children: []*AttackNode{
			{Type: NodeLeaf},
			{Type: NodeAND, Children: []*AttackNode{
				{Type: NodeOR, Children: []*AttackNode{
					{Type: NodeLeaf},
				}},
			}},
		},
	}
	if got := maxDepth(root); got != 4 {
		t.Errorf("maxDepth = %d, want 4", got)
	}
}

func TestClamp01(t *testing.T) {
	tests := []struct {
		in, want float64
	}{
		{-0.5, 0},
		{0, 0},
		{0.5, 0.5},
		{1.0, 1.0},
		{1.5, 1.0},
	}
	for _, tt := range tests {
		if got := clamp01(tt.in); got != tt.want {
			t.Errorf("clamp01(%f) = %f, want %f", tt.in, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

func TestFormatAttackTree_Nil(t *testing.T) {
	out := FormatAttackTree(nil)
	if !strings.Contains(out, "No attack tree") {
		t.Error("expected 'No attack tree' for nil")
	}
}

func TestFormatAttackTree_ContainsStructure(t *testing.T) {
	inv := atkInventory(
		atkAgent("w", agent.TypeToolCalling, agent.TrustStandard,
			[]agent.ToolAccess{atkTool("exec", true)}, nil),
	)
	tree := BuildAttackTree(inv, nil)
	out := FormatAttackTree(tree)

	if !strings.Contains(out, "ATTACK TREE ANALYSIS") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "Nodes:") {
		t.Error("missing node count")
	}
	if !strings.Contains(out, "Top Attack Paths") {
		t.Error("missing top paths section")
	}
}

func TestFormatAttackTreeJSON_ValidJSON(t *testing.T) {
	inv := atkInventory(
		atkAgent("a", agent.TypeToolCalling, agent.TrustStandard,
			[]agent.ToolAccess{atkTool("t", false)}, nil),
	)
	tree := BuildAttackTree(inv, nil)
	out, err := FormatAttackTreeJSON(tree)
	if err != nil {
		t.Fatalf("JSON format error: %v", err)
	}

	var parsed AttackTree
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.NodeCount != tree.NodeCount {
		t.Errorf("JSON node_count = %d, want %d", parsed.NodeCount, tree.NodeCount)
	}
}

func TestSummarizeAttackTree(t *testing.T) {
	inv := atkInventory(
		atkAgent("a", agent.TypeToolCalling, agent.TrustStandard,
			[]agent.ToolAccess{atkTool("t", false)}, nil),
	)
	tree := BuildAttackTree(inv, nil)
	summary := SummarizeAttackTree(tree)

	if !strings.Contains(summary, "nodes") {
		t.Error("summary should mention nodes")
	}
	if !strings.Contains(summary, "mitigated") {
		t.Error("summary should mention mitigated")
	}
}

func TestSummarizeAttackTree_Nil(t *testing.T) {
	s := SummarizeAttackTree(nil)
	if s != "No attack tree." {
		t.Errorf("unexpected summary for nil: %q", s)
	}
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

func TestImpactByTrust(t *testing.T) {
	tests := []struct {
		rank int
		want float64
	}{
		{0, 2.0},
		{1, 4.0},
		{2, 6.0},
		{3, 8.0},
		{4, 10.0},
	}
	for _, tt := range tests {
		if got := impactByTrust(tt.rank); got != tt.want {
			t.Errorf("impactByTrust(%d) = %.1f, want %.1f", tt.rank, got, tt.want)
		}
	}
}

func TestToolExploitProbability_ElevatedHigher(t *testing.T) {
	elevated := toolExploitProbability(agent.ToolAccess{Name: "x", Elevated: true}, 2)
	normal := toolExploitProbability(agent.ToolAccess{Name: "x", Elevated: false}, 2)

	if elevated <= normal {
		t.Errorf("elevated prob %.2f should exceed normal %.2f", elevated, normal)
	}
}

func TestAtkSanitizeID(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"my-agent", "MY-AGENT"},
		{"foo bar", "FOO-BAR"},
		{"a.b/c_d", "A-B-C-D"},
	}
	for _, tt := range tests {
		if got := atkSanitizeID(tt.in); got != tt.want {
			t.Errorf("atkSanitizeID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Mitigation checking
// ---------------------------------------------------------------------------

func TestAllChildrenMitigated_AND(t *testing.T) {
	n := &AttackNode{
		Type: NodeAND,
		Children: []*AttackNode{
			{Type: NodeLeaf, Mitigated: true},
			{Type: NodeLeaf, Mitigated: false},
		},
	}
	if !allChildrenMitigated(n) {
		t.Error("AND node: one mitigated child should be enough")
	}
}

func TestAllChildrenMitigated_OR(t *testing.T) {
	n := &AttackNode{
		Type: NodeOR,
		Children: []*AttackNode{
			{Type: NodeLeaf, Mitigated: true},
			{Type: NodeLeaf, Mitigated: false},
		},
	}
	if allChildrenMitigated(n) {
		t.Error("OR node: all children must be mitigated")
	}
}

func TestAllChildrenMitigated_OR_AllMitigated(t *testing.T) {
	n := &AttackNode{
		Type: NodeOR,
		Children: []*AttackNode{
			{Type: NodeLeaf, Mitigated: true},
			{Type: NodeLeaf, Mitigated: true},
		},
	}
	if !allChildrenMitigated(n) {
		t.Error("OR node with all mitigated should be mitigated")
	}
}
