// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// NodeType distinguishes AND vs OR decomposition in the tree.
type NodeType string

const (
	// NodeAND means all children must succeed for the parent to succeed.
	NodeAND NodeType = "AND"
	// NodeOR means any one child succeeding is enough.
	NodeOR NodeType = "OR"
	// NodeLeaf is a terminal node with no children.
	NodeLeaf NodeType = "LEAF"
)

// AttackNode is one node in the attack tree.
type AttackNode struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description,omitempty"`
	Type        NodeType      `json:"type"`
	Probability float64       `json:"probability"` // 0.0-1.0
	Impact      float64       `json:"impact"`      // 0.0-10.0
	RiskScore   float64       `json:"risk_score"`  // probability * impact
	Mitigated   bool          `json:"mitigated"`
	Mitigation  string        `json:"mitigation,omitempty"`
	Agent       string        `json:"agent,omitempty"`
	Tool        string        `json:"tool,omitempty"`
	Category    string        `json:"category,omitempty"` // STRIDE category or custom
	Children    []*AttackNode `json:"children,omitempty"`
}

// AttackTree is a rooted attack tree with summary statistics.
type AttackTree struct {
	Root        *AttackNode  `json:"root"`
	NodeCount   int          `json:"node_count"`
	LeafCount   int          `json:"leaf_count"`
	MaxDepth    int          `json:"max_depth"`
	RiskScore   float64      `json:"risk_score"`
	TopPaths    []AttackPath `json:"top_paths"`
	Mitigated   int          `json:"mitigated"`
	Unmitigated int          `json:"unmitigated"`
}

// AttackPath is a single root-to-leaf path through the tree, representing
// one concrete attack scenario.
type AttackPath struct {
	Steps       []string `json:"steps"`
	Probability float64  `json:"probability"`
	Impact      float64  `json:"impact"`
	RiskScore   float64  `json:"risk_score"`
	Mitigated   bool     `json:"mitigated"`
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// BuildAttackTree generates an attack tree from an agent inventory and
// policy set. The tree decomposes "compromise the agent deployment" into
// per-agent sub-goals, per-tool attack vectors, and leaf preconditions.
// Policies are used to mark mitigated leaves.
func BuildAttackTree(inv *agent.Inventory, policies []*policy.Policy) *AttackTree {
	if inv == nil || len(inv.Agents) == 0 {
		return &AttackTree{Root: &AttackNode{
			ID:    "ROOT",
			Title: "Compromise Agent Deployment",
			Type:  NodeLeaf,
		}}
	}

	root := &AttackNode{
		ID:    "ROOT",
		Title: "Compromise Agent Deployment",
		Type:  NodeOR,
	}

	for _, a := range inv.Agents {
		agentNode := buildAgentSubtree(a, policies)
		root.Children = append(root.Children, agentNode)
	}

	propagateProbabilities(root)

	tree := &AttackTree{Root: root}
	tree.NodeCount = countNodes(root)
	tree.LeafCount = countLeaves(root)
	tree.MaxDepth = maxDepth(root)
	tree.RiskScore = root.RiskScore

	countMitigations(root, &tree.Mitigated, &tree.Unmitigated)
	tree.TopPaths = extractTopPaths(root, 5)

	return tree
}

// buildAgentSubtree decomposes one agent into attack vectors.
func buildAgentSubtree(a *agent.Agent, policies []*policy.Policy) *AttackNode {
	trustRank := agentTrustRank(a)
	agentNode := &AttackNode{
		ID:    fmt.Sprintf("AGENT-%s", atkSanitizeID(a.Meta.Name)),
		Title: fmt.Sprintf("Compromise %s", a.Meta.Name),
		Type:  NodeOR,
		Agent: a.Meta.Name,
	}

	// 1. Direct tool exploitation (OR — any tool is a vector)
	if len(a.Tools) > 0 {
		toolNode := &AttackNode{
			ID:    fmt.Sprintf("TOOLS-%s", atkSanitizeID(a.Meta.Name)),
			Title: fmt.Sprintf("Exploit %s Tools", a.Meta.Name),
			Type:  NodeOR,
			Agent: a.Meta.Name,
		}
		for _, tool := range a.Tools {
			leaf := buildToolLeaf(a, tool, policies, trustRank)
			toolNode.Children = append(toolNode.Children, leaf)
		}
		agentNode.Children = append(agentNode.Children, toolNode)
	}

	// 2. Trust exploitation (AND — requires both impersonation + delegation abuse)
	if len(a.Trust.TrustsFrom) > 0 || a.Trust.CanEscalate {
		trustNode := buildTrustSubtree(a, trustRank)
		agentNode.Children = append(agentNode.Children, trustNode)
	}

	// 3. Prompt injection / input manipulation
	if a.Meta.Type == agent.TypeToolCalling || a.Meta.Type == agent.TypeOrchestrator || a.Meta.Type == agent.TypeAutonomous {
		injNode := &AttackNode{
			ID:          fmt.Sprintf("INJ-%s", atkSanitizeID(a.Meta.Name)),
			Title:       fmt.Sprintf("Prompt Injection on %s", a.Meta.Name),
			Type:        NodeAND,
			Agent:       a.Meta.Name,
			Category:    "spoofing",
			Description: "Inject malicious instructions via crafted input to hijack agent behavior",
		}
		injNode.Children = append(injNode.Children,
			&AttackNode{
				ID:          fmt.Sprintf("INJ-%s-CRAFT", atkSanitizeID(a.Meta.Name)),
				Title:       "Craft adversarial input",
				Type:        NodeLeaf,
				Agent:       a.Meta.Name,
				Probability: 0.7,
				Impact:      impactByTrust(trustRank),
				Category:    "spoofing",
			},
			&AttackNode{
				ID:          fmt.Sprintf("INJ-%s-BYPASS", atkSanitizeID(a.Meta.Name)),
				Title:       "Bypass input guardrails",
				Type:        NodeLeaf,
				Agent:       a.Meta.Name,
				Probability: guardrailBypassProb(a),
				Impact:      impactByTrust(trustRank),
				Mitigated:   len(a.Guardrails) > 0,
				Mitigation:  guardrailMitigation(a),
				Category:    "spoofing",
			},
		)
		agentNode.Children = append(agentNode.Children, injNode)
	}

	// 4. Guardrail evasion (if agent has guardrails, there's an evasion vector)
	if len(a.Guardrails) > 0 {
		evasionNode := &AttackNode{
			ID:          fmt.Sprintf("EVASION-%s", atkSanitizeID(a.Meta.Name)),
			Title:       fmt.Sprintf("Evade Guardrails on %s", a.Meta.Name),
			Type:        NodeAND,
			Agent:       a.Meta.Name,
			Category:    "tampering",
			Description: "Circumvent declared guardrails to perform unauthorized actions",
		}
		evasionNode.Children = append(evasionNode.Children,
			&AttackNode{
				ID:          fmt.Sprintf("EVASION-%s-RECON", atkSanitizeID(a.Meta.Name)),
				Title:       "Enumerate guardrail boundaries",
				Type:        NodeLeaf,
				Agent:       a.Meta.Name,
				Probability: 0.6,
				Impact:      3.0,
				Category:    "tampering",
			},
			&AttackNode{
				ID:          fmt.Sprintf("EVASION-%s-BYPASS", atkSanitizeID(a.Meta.Name)),
				Title:       "Craft guardrail bypass",
				Type:        NodeLeaf,
				Agent:       a.Meta.Name,
				Probability: guardrailBypassProb(a),
				Impact:      impactByTrust(trustRank),
				Category:    "tampering",
			},
		)
		agentNode.Children = append(agentNode.Children, evasionNode)
	}

	return agentNode
}

// buildToolLeaf creates leaf nodes for exploiting a single tool.
func buildToolLeaf(a *agent.Agent, tool agent.ToolAccess, policies []*policy.Policy, trustRank int) *AttackNode {
	prob := toolExploitProbability(tool, trustRank)
	impact := toolExploitImpact(tool, trustRank)

	leaf := &AttackNode{
		ID:       fmt.Sprintf("TOOL-%s-%s", atkSanitizeID(a.Meta.Name), atkSanitizeID(tool.Name)),
		Title:    fmt.Sprintf("Exploit tool: %s", tool.Name),
		Type:     NodeLeaf,
		Agent:    a.Meta.Name,
		Tool:     tool.Name,
		Category: "elevation_of_privilege",

		Probability: prob,
		Impact:      impact,
	}

	leaf.Mitigated = isToolMitigated(tool, a.Meta.Name, policies)
	if leaf.Mitigated {
		leaf.Mitigation = fmt.Sprintf("Policy blocks %s for %s", tool.Name, a.Meta.Name)
	}

	return leaf
}

// buildTrustSubtree decomposes trust exploitation for an agent.
func buildTrustSubtree(a *agent.Agent, trustRank int) *AttackNode {
	node := &AttackNode{
		ID:       fmt.Sprintf("TRUST-%s", atkSanitizeID(a.Meta.Name)),
		Title:    fmt.Sprintf("Exploit Trust of %s", a.Meta.Name),
		Type:     NodeAND,
		Agent:    a.Meta.Name,
		Category: "elevation_of_privilege",
	}

	node.Children = append(node.Children, &AttackNode{
		ID:          fmt.Sprintf("TRUST-%s-IMPERSONATE", atkSanitizeID(a.Meta.Name)),
		Title:       "Impersonate trusted delegator",
		Type:        NodeLeaf,
		Agent:       a.Meta.Name,
		Probability: impersonationProbability(a),
		Impact:      impactByTrust(trustRank),
		Category:    "spoofing",
	})

	if a.Trust.CanEscalate {
		node.Children = append(node.Children, &AttackNode{
			ID:          fmt.Sprintf("TRUST-%s-ESCALATE", atkSanitizeID(a.Meta.Name)),
			Title:       "Leverage escalation capability",
			Type:        NodeLeaf,
			Agent:       a.Meta.Name,
			Probability: 0.8,
			Impact:      10.0,
			Category:    "elevation_of_privilege",
		})
	} else {
		node.Children = append(node.Children, &AttackNode{
			ID:          fmt.Sprintf("TRUST-%s-ABUSE", atkSanitizeID(a.Meta.Name)),
			Title:       "Abuse delegation chain",
			Type:        NodeLeaf,
			Agent:       a.Meta.Name,
			Probability: 0.4,
			Impact:      impactByTrust(trustRank),
			Category:    "elevation_of_privilege",
		})
	}

	return node
}

// ---------------------------------------------------------------------------
// Probability propagation
// ---------------------------------------------------------------------------

// propagateProbabilities walks the tree bottom-up, computing composite
// probabilities: AND nodes multiply children, OR nodes use 1 - product(1-p).
// Impact propagates as the max of children for OR, sum for AND (capped at 10).
func propagateProbabilities(n *AttackNode) {
	if n == nil || n.Type == NodeLeaf {
		n.RiskScore = n.Probability * n.Impact
		return
	}

	for _, c := range n.Children {
		propagateProbabilities(c)
	}

	switch n.Type {
	case NodeAND:
		prob := 1.0
		impactSum := 0.0
		for _, c := range n.Children {
			prob *= c.Probability
			impactSum += c.Impact
		}
		n.Probability = prob
		n.Impact = math.Min(impactSum, 10.0)

	case NodeOR:
		complement := 1.0
		maxImpact := 0.0
		for _, c := range n.Children {
			complement *= (1.0 - c.Probability)
			if c.Impact > maxImpact {
				maxImpact = c.Impact
			}
		}
		n.Probability = 1.0 - complement
		n.Impact = maxImpact
	}

	n.Probability = clamp01(n.Probability)
	n.RiskScore = n.Probability * n.Impact

	n.Mitigated = allChildrenMitigated(n)
}

// ---------------------------------------------------------------------------
// Path extraction
// ---------------------------------------------------------------------------

// extractTopPaths finds up to limit root-to-leaf paths sorted by risk.
func extractTopPaths(root *AttackNode, limit int) []AttackPath {
	var paths []AttackPath
	var walk func(n *AttackNode, steps []string, probAcc float64)
	walk = func(n *AttackNode, steps []string, probAcc float64) {
		steps = append(steps, n.Title)

		if n.Type == NodeLeaf || len(n.Children) == 0 {
			pathSteps := make([]string, len(steps))
			copy(pathSteps, steps)
			prob := probAcc * n.Probability
			if n.Type != NodeLeaf {
				prob = probAcc
			}
			paths = append(paths, AttackPath{
				Steps:       pathSteps,
				Probability: clamp01(prob),
				Impact:      n.Impact,
				RiskScore:   clamp01(prob) * n.Impact,
				Mitigated:   n.Mitigated,
			})
			return
		}

		for _, c := range n.Children {
			childProb := probAcc
			if n.Type == NodeAND {
				childProb = probAcc * n.Probability
			}
			walk(c, steps, childProb)
		}
	}

	walk(root, nil, 1.0)

	sort.SliceStable(paths, func(i, j int) bool {
		return paths[i].RiskScore > paths[j].RiskScore
	})

	if len(paths) > limit {
		paths = paths[:limit]
	}
	return paths
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

func agentTrustRank(a *agent.Agent) int {
	ranks := map[string]int{
		agent.TrustUntrusted: 0,
		agent.TrustLow:       1,
		agent.TrustStandard:  2,
		agent.TrustElevated:  3,
		agent.TrustAdmin:     4,
	}
	if r, ok := ranks[a.Trust.Level]; ok {
		return r
	}
	return 2
}

func impactByTrust(rank int) float64 {
	switch {
	case rank >= 4:
		return 10.0
	case rank == 3:
		return 8.0
	case rank == 2:
		return 6.0
	case rank == 1:
		return 4.0
	default:
		return 2.0
	}
}

func toolExploitProbability(tool agent.ToolAccess, trustRank int) float64 {
	base := 0.3
	if tool.Elevated {
		base = 0.5
	}
	if trustRank >= 3 {
		base += 0.1
	}
	return clamp01(base)
}

func toolExploitImpact(tool agent.ToolAccess, trustRank int) float64 {
	base := impactByTrust(trustRank)
	if tool.Elevated {
		base = math.Min(base+2.0, 10.0)
	}
	return base
}

func impersonationProbability(a *agent.Agent) float64 {
	base := 0.3
	if len(a.Trust.TrustsFrom) > 3 {
		base += 0.2
	}
	if len(a.Guardrails) == 0 {
		base += 0.15
	}
	return clamp01(base)
}

func guardrailBypassProb(a *agent.Agent) float64 {
	if len(a.Guardrails) == 0 {
		return 0.9
	}
	base := 0.4
	if len(a.Guardrails) >= 3 {
		base = 0.2
	}
	return base
}

func guardrailMitigation(a *agent.Agent) string {
	if len(a.Guardrails) == 0 {
		return ""
	}
	names := make([]string, 0, len(a.Guardrails))
	for _, g := range a.Guardrails {
		if g.Type != "" {
			names = append(names, g.Type)
		}
	}
	if len(names) == 0 {
		return "guardrails active"
	}
	return fmt.Sprintf("guardrails: %s", strings.Join(names, ", "))
}

func isToolMitigated(tool agent.ToolAccess, agentName string, policies []*policy.Policy) bool {
	for _, p := range policies {
		for _, r := range p.Rules {
			if r.Effect == "deny" && ruleMatchesToolOrAgent(r, tool.Name, agentName) {
				return true
			}
		}
	}
	return false
}

func ruleMatchesToolOrAgent(r policy.Rule, toolName, agentName string) bool {
	toolMatch := false
	for _, t := range r.Match.Tools {
		if t == toolName || t == "*" {
			toolMatch = true
			break
		}
	}
	if len(r.Match.Tools) == 0 {
		toolMatch = true
	}
	return toolMatch
}

// ---------------------------------------------------------------------------
// Tree statistics
// ---------------------------------------------------------------------------

func countNodes(n *AttackNode) int {
	if n == nil {
		return 0
	}
	c := 1
	for _, child := range n.Children {
		c += countNodes(child)
	}
	return c
}

func countLeaves(n *AttackNode) int {
	if n == nil {
		return 0
	}
	if n.Type == NodeLeaf || len(n.Children) == 0 {
		return 1
	}
	c := 0
	for _, child := range n.Children {
		c += countLeaves(child)
	}
	return c
}

func maxDepth(n *AttackNode) int {
	if n == nil {
		return 0
	}
	if len(n.Children) == 0 {
		return 1
	}
	max := 0
	for _, c := range n.Children {
		d := maxDepth(c)
		if d > max {
			max = d
		}
	}
	return max + 1
}

func countMitigations(n *AttackNode, mitigated, unmitigated *int) {
	if n == nil {
		return
	}
	if n.Type == NodeLeaf || len(n.Children) == 0 {
		if n.Mitigated {
			*mitigated++
		} else {
			*unmitigated++
		}
		return
	}
	for _, c := range n.Children {
		countMitigations(c, mitigated, unmitigated)
	}
}

func allChildrenMitigated(n *AttackNode) bool {
	if len(n.Children) == 0 {
		return n.Mitigated
	}
	switch n.Type {
	case NodeAND:
		for _, c := range n.Children {
			if c.Mitigated {
				return true
			}
		}
		return false
	case NodeOR:
		for _, c := range n.Children {
			if !c.Mitigated {
				return false
			}
		}
		return true
	}
	return false
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func atkSanitizeID(s string) string {
	r := strings.NewReplacer(
		" ", "-",
		"/", "-",
		".", "-",
		"_", "-",
	)
	return strings.ToUpper(r.Replace(s))
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatAttackTree renders the tree as a human-readable text report.
func FormatAttackTree(tree *AttackTree) string {
	if tree == nil || tree.Root == nil {
		return "No attack tree.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│                    ATTACK TREE ANALYSIS                 │\n")
	sb.WriteString("├─────────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Nodes: %-10d  Leaves: %-10d  Depth: %-10d │\n",
		tree.NodeCount, tree.LeafCount, tree.MaxDepth)
	fmt.Fprintf(&sb, "│ Risk Score: %-6.2f  Mitigated: %d/%d                     │\n",
		tree.RiskScore, tree.Mitigated, tree.Mitigated+tree.Unmitigated)
	sb.WriteString("├─────────────────────────────────────────────────────────┤\n")

	sb.WriteString("│ Tree Structure                                          │\n")
	sb.WriteString("├─────────────────────────────────────────────────────────┤\n")
	formatNode(&sb, tree.Root, "", true)

	if len(tree.TopPaths) > 0 {
		sb.WriteString("├─────────────────────────────────────────────────────────┤\n")
		sb.WriteString("│ Top Attack Paths (by risk)                              │\n")
		sb.WriteString("├─────────────────────────────────────────────────────────┤\n")
		for i, p := range tree.TopPaths {
			status := "OPEN"
			if p.Mitigated {
				status = "MITIGATED"
			}
			fmt.Fprintf(&sb, "│ %d. [%.2f] %s                                       │\n",
				i+1, p.RiskScore, status)
			for j, step := range p.Steps {
				prefix := "   "
				if j == len(p.Steps)-1 {
					prefix = " → "
				}
				line := atkTruncStr(step, 50)
				fmt.Fprintf(&sb, "│%s  %s\n", prefix, line)
			}
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────────────┘\n")

	return sb.String()
}

func formatNode(sb *strings.Builder, n *AttackNode, prefix string, isLast bool) {
	if n == nil {
		return
	}

	connector := "├── "
	if isLast {
		connector = "└── "
	}

	icon := nodeIcon(n)
	prob := fmt.Sprintf("p=%.2f", n.Probability)
	mitIcon := " "
	if n.Mitigated {
		mitIcon = "M"
	}

	line := fmt.Sprintf("%s%s[%s] %s {%s %s i=%.1f r=%.2f}",
		prefix, connector, icon, atkTruncStr(n.Title, 30),
		mitIcon, prob, n.Impact, n.RiskScore)
	fmt.Fprintf(sb, "│ %s\n", line)

	childPrefix := prefix + "│   "
	if isLast {
		childPrefix = prefix + "    "
	}

	for i, c := range n.Children {
		formatNode(sb, c, childPrefix, i == len(n.Children)-1)
	}
}

func nodeIcon(n *AttackNode) string {
	switch n.Type {
	case NodeAND:
		return "&"
	case NodeOR:
		return "|"
	default:
		return "*"
	}
}

func atkTruncStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// FormatAttackTreeJSON returns the tree as indented JSON.
func FormatAttackTreeJSON(tree *AttackTree) (string, error) {
	data, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling attack tree: %w", err)
	}
	return string(data), nil
}

// SummarizeAttackTree returns a one-line summary.
func SummarizeAttackTree(tree *AttackTree) string {
	if tree == nil || tree.Root == nil {
		return "No attack tree."
	}
	return fmt.Sprintf(
		"%d nodes (%d leaves, depth %d) — risk %.2f — %d/%d mitigated — top path risk %.2f",
		tree.NodeCount, tree.LeafCount, tree.MaxDepth,
		tree.RiskScore, tree.Mitigated, tree.Mitigated+tree.Unmitigated,
		topPathRisk(tree))
}

func topPathRisk(tree *AttackTree) float64 {
	if len(tree.TopPaths) == 0 {
		return 0
	}
	return tree.TopPaths[0].RiskScore
}
