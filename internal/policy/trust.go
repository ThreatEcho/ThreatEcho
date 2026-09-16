// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"strings"
)

// privilegeLevel maps privilege names to numeric levels for comparison.
// Higher value = higher privilege.
var privilegeLevel = map[string]int{
	"restricted": 0,
	"standard":   1,
	"elevated":   2,
	"admin":      3,
}

// TrustGraph models trust relationships between agents.
type TrustGraph struct {
	Agents []AgentNode `json:"agents"`
	Edges  []TrustEdge `json:"edges"`
}

// AgentNode is one agent in the trust graph.
type AgentNode struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`      // orchestrator, worker, retrieval, llm
	Privilege string   `json:"privilege"` // admin, elevated, standard, restricted
	Tools     []string `json:"tools"`     // tools this agent can invoke
	Policies  []string `json:"policies"`  // policy names applied to this agent
}

// TrustEdge is a directed trust relationship.
type TrustEdge struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Direction string `json:"direction"` // unidirectional, bidirectional
	Channel   string `json:"channel"`   // inter-agent-bus, api, shared-memory, direct
	Verified  bool   `json:"verified"`  // is the identity verified?
}

// TrustAnalysis is the result of analyzing a trust graph.
type TrustAnalysis struct {
	Graph                *TrustGraph      `json:"graph"`
	EscalationPaths      []EscalationPath `json:"escalation_paths"`
	UnverifiedEdges      []TrustEdge      `json:"unverified_edges"`
	OverprivilegedAgents []AgentNode      `json:"overprivileged_agents"`
	IsolatedAgents       []AgentNode      `json:"isolated_agents"`
	Stats                TrustStats       `json:"stats"`
	Findings             []TrustFinding   `json:"findings"`
}

// EscalationPath is a sequence of agents that leads from a low-priv to high-priv agent.
type EscalationPath struct {
	From   string   `json:"from"`
	To     string   `json:"to"`
	Path   []string `json:"path"`
	Hops   int      `json:"hops"`
	Risk   string   `json:"risk"` // critical/high/medium/low
	Reason string   `json:"reason"`
}

// TrustStats summarizes the trust graph.
type TrustStats struct {
	TotalAgents     int     `json:"total_agents"`
	TotalEdges      int     `json:"total_edges"`
	AdminAgents     int     `json:"admin_agents"`
	UnverifiedEdges int     `json:"unverified_edges"`
	AvgConnections  float64 `json:"avg_connections"`
	MaxDepth        int     `json:"max_depth"`
	EscalationRisk  string  `json:"escalation_risk"` // none/low/medium/high/critical
}

// TrustFinding is a specific weakness in the trust model.
type TrustFinding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"` // escalation, unverified, overprivileged, isolation, channel
	Title       string `json:"title"`
	Description string `json:"description"`
}

// NewTrustGraph creates a trust graph from agent definitions.
func NewTrustGraph(agents []AgentNode, edges []TrustEdge) *TrustGraph {
	g := &TrustGraph{}
	if agents != nil {
		g.Agents = make([]AgentNode, len(agents))
		copy(g.Agents, agents)
	}
	if edges != nil {
		g.Edges = make([]TrustEdge, len(edges))
		copy(g.Edges, edges)
	}
	return g
}

// AnalyzeTrust performs a comprehensive trust analysis.
func AnalyzeTrust(g *TrustGraph) *TrustAnalysis {
	if g == nil {
		g = &TrustGraph{}
	}

	ta := &TrustAnalysis{
		Graph: g,
	}

	ta.EscalationPaths = FindEscalationPaths(g)
	ta.UnverifiedEdges = findUnverifiedEdges(g)
	ta.OverprivilegedAgents = findOverprivilegedAgents(g)
	ta.IsolatedAgents = findIsolatedAgents(g)
	ta.Stats = computeStats(g, ta)
	ta.Findings = generateFindings(ta)

	return ta
}

// FindEscalationPaths finds all paths from low-priv to high-priv agents using BFS.
// A path is an escalation when a restricted or standard agent can reach an
// elevated or admin agent through a chain of trust edges.
func FindEscalationPaths(g *TrustGraph) []EscalationPath {
	if g == nil || len(g.Agents) == 0 || len(g.Edges) == 0 {
		return nil
	}

	// Build adjacency list from edges.
	adj := buildAdjacency(g)

	// Index agents by name.
	agentMap := make(map[string]AgentNode, len(g.Agents))
	for _, a := range g.Agents {
		agentMap[a.Name] = a
	}

	// Find low-privilege sources and high-privilege targets.
	var sources []AgentNode
	var targets []AgentNode
	for _, a := range g.Agents {
		lvl := privilegeLevel[a.Privilege]
		if lvl <= 1 { // restricted or standard
			sources = append(sources, a)
		}
		if lvl >= 2 { // elevated or admin
			targets = append(targets, a)
		}
	}

	var paths []EscalationPath
	for _, src := range sources {
		for _, tgt := range targets {
			if src.Name == tgt.Name {
				continue
			}
			path := bfsPath(adj, src.Name, tgt.Name)
			if path == nil {
				continue
			}
			hops := len(path) - 1
			risk := classifyEscalationRisk(src.Privilege, tgt.Privilege, hops)
			reason := fmt.Sprintf("%s (%s) can reach %s (%s) in %d hop(s)",
				src.Name, src.Privilege, tgt.Name, tgt.Privilege, hops)
			paths = append(paths, EscalationPath{
				From:   src.Name,
				To:     tgt.Name,
				Path:   path,
				Hops:   hops,
				Risk:   risk,
				Reason: reason,
			})
		}
	}

	return paths
}

// BuildTrustFromTraces infers a trust graph from a set of agent traces.
// It examines agent_message events to infer edges and tool calls to infer
// privilege levels.
func BuildTrustFromTraces(traces []*Trace) *TrustGraph {
	if len(traces) == 0 {
		return &TrustGraph{}
	}

	agentMap := make(map[string]*AgentNode)
	edgeSet := make(map[string]*TrustEdge) // "from->to" -> edge

	// Register each trace as an agent.
	for _, t := range traces {
		if t == nil {
			continue
		}
		if _, exists := agentMap[t.AgentName]; !exists {
			agentMap[t.AgentName] = &AgentNode{
				Name:      t.AgentName,
				Type:      t.AgentType,
				Privilege: "standard", // default
			}
		}
	}

	// Walk events to infer edges and tools.
	for _, t := range traces {
		if t == nil {
			continue
		}
		agent := agentMap[t.AgentName]

		for _, ev := range t.Events {
			switch ev.Type {
			case "agent_message":
				if ev.AgentMessage == nil {
					continue
				}
				am := ev.AgentMessage

				// Ensure both agents exist in the map.
				if _, ok := agentMap[am.FromAgent]; !ok {
					agentMap[am.FromAgent] = &AgentNode{
						Name:      am.FromAgent,
						Type:      "unknown",
						Privilege: "standard",
					}
				}
				if _, ok := agentMap[am.ToAgent]; !ok {
					agentMap[am.ToAgent] = &AgentNode{
						Name:      am.ToAgent,
						Type:      "unknown",
						Privilege: "standard",
					}
				}

				// Create or update edge.
				key := am.FromAgent + "->" + am.ToAgent
				if _, exists := edgeSet[key]; !exists {
					channel := am.Channel
					if channel == "" {
						channel = "inter-agent-bus"
					}
					edgeSet[key] = &TrustEdge{
						From:      am.FromAgent,
						To:        am.ToAgent,
						Direction: "unidirectional",
						Channel:   channel,
						Verified:  false, // inferred edges are unverified by default
					}
				}

			case "tool_call":
				if ev.ToolCall == nil {
					continue
				}
				tc := ev.ToolCall

				// Track tools.
				toolSeen := false
				for _, existing := range agent.Tools {
					if existing == tc.Tool {
						toolSeen = true
						break
					}
				}
				if !toolSeen {
					agent.Tools = append(agent.Tools, tc.Tool)
				}

				// Infer privilege from elevated tool calls.
				if tc.Elevated && privilegeLevel[agent.Privilege] < privilegeLevel["elevated"] {
					agent.Privilege = "elevated"
				}
			}
		}
	}

	// Check for bidirectional edges.
	for key, edge := range edgeSet {
		reverseKey := edge.To + "->" + edge.From
		if _, exists := edgeSet[reverseKey]; exists {
			edge.Direction = "bidirectional"
			edgeSet[reverseKey].Direction = "bidirectional"
			_ = key // used as map key
		}
	}

	// Collect agents and edges.
	var agents []AgentNode
	for _, a := range agentMap {
		agents = append(agents, *a)
	}
	var edges []TrustEdge
	seen := make(map[string]bool)
	for _, e := range edgeSet {
		// For bidirectional edges, only emit one.
		if e.Direction == "bidirectional" {
			canonical := e.From + "<->" + e.To
			reverse := e.To + "<->" + e.From
			if seen[canonical] || seen[reverse] {
				continue
			}
			seen[canonical] = true
		}
		edges = append(edges, *e)
	}

	return NewTrustGraph(agents, edges)
}

// FormatTrustAnalysis returns a box-drawing formatted trust report.
func FormatTrustAnalysis(ta *TrustAnalysis) string {
	if ta == nil {
		return "No trust analysis result.\n"
	}

	var b strings.Builder

	// Header.
	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│              Trust Graph Analysis                   │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Stats.
	b.WriteString(fmt.Sprintf("│ Total agents:     %-33d │\n", ta.Stats.TotalAgents))
	b.WriteString(fmt.Sprintf("│ Total edges:      %-33d │\n", ta.Stats.TotalEdges))
	b.WriteString(fmt.Sprintf("│ Admin agents:     %-33d │\n", ta.Stats.AdminAgents))
	b.WriteString(fmt.Sprintf("│ Unverified edges: %-33d │\n", ta.Stats.UnverifiedEdges))
	b.WriteString(fmt.Sprintf("│ Avg connections:  %-33s │\n", fmt.Sprintf("%.1f", ta.Stats.AvgConnections)))
	b.WriteString(fmt.Sprintf("│ Max depth:        %-33d │\n", ta.Stats.MaxDepth))
	b.WriteString(fmt.Sprintf("│ Escalation risk:  %-33s │\n", ta.Stats.EscalationRisk))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Agent list.
	b.WriteString("│ Agents:                                             │\n")
	if len(ta.Graph.Agents) == 0 {
		b.WriteString("│   (none)                                            │\n")
	} else {
		for _, a := range ta.Graph.Agents {
			privIcon := privilegeIcon(a.Privilege)
			b.WriteString(fmt.Sprintf("│   %s %-20s %-10s %-10s │\n",
				privIcon,
				truncStr(a.Name, 20),
				truncStr(a.Type, 10),
				truncStr(a.Privilege, 10)))
		}
	}
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Escalation paths.
	if len(ta.EscalationPaths) == 0 {
		b.WriteString("│ ✓ No escalation paths found                         │\n")
	} else {
		b.WriteString("│ ⚠ Escalation Paths:                                │\n")
		for i, ep := range ta.EscalationPaths {
			riskIcon := "⚠"
			if ep.Risk == "critical" {
				riskIcon = "✗"
			}
			b.WriteString(fmt.Sprintf("│   %s %d. [%s] %s\n",
				riskIcon, i+1, ep.Risk, truncStr(ep.Reason, 40)))
			b.WriteString(fmt.Sprintf("│      Path: %s\n",
				truncStr(strings.Join(ep.Path, " → "), 42)))
		}
	}
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Unverified edges.
	if len(ta.UnverifiedEdges) > 0 {
		b.WriteString("│ ⚠ Unverified Edges:                                │\n")
		for _, e := range ta.UnverifiedEdges {
			b.WriteString(fmt.Sprintf("│   ⚠ %s → %s (%s)\n",
				truncStr(e.From, 16), truncStr(e.To, 16), e.Channel))
		}
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
	}

	// Overprivileged agents.
	if len(ta.OverprivilegedAgents) > 0 {
		b.WriteString("│ ⚠ Overprivileged Agents:                           │\n")
		for _, a := range ta.OverprivilegedAgents {
			b.WriteString(fmt.Sprintf("│   ✗ %-20s %s (no policies)\n",
				truncStr(a.Name, 20), a.Privilege))
		}
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
	}

	// Findings.
	if len(ta.Findings) > 0 {
		b.WriteString("│ Findings:                                           │\n")
		for i, f := range ta.Findings {
			b.WriteString(fmt.Sprintf("│   %d. [%s] %s\n",
				i+1, f.Severity, truncStr(f.Title, 38)))
			b.WriteString(fmt.Sprintf("│      %s\n",
				truncStr(f.Description, 46)))
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}

// --- internal helpers ---

// buildAdjacency creates an adjacency list from graph edges.
// Bidirectional edges produce connections in both directions.
func buildAdjacency(g *TrustGraph) map[string][]string {
	adj := make(map[string][]string)
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
		if e.Direction == "bidirectional" {
			adj[e.To] = append(adj[e.To], e.From)
		}
	}
	return adj
}

// bfsPath finds the shortest path from src to dst using BFS.
// Returns nil if no path exists.
func bfsPath(adj map[string][]string, src, dst string) []string {
	if src == dst {
		return []string{src}
	}

	visited := map[string]bool{src: true}
	parent := map[string]string{}

	queue := []string{src}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, neighbor := range adj[current] {
			if visited[neighbor] {
				continue
			}
			visited[neighbor] = true
			parent[neighbor] = current

			if neighbor == dst {
				// Reconstruct path.
				var path []string
				for n := dst; n != ""; n = parent[n] {
					path = append([]string{n}, path...)
					if n == src {
						break
					}
				}
				return path
			}

			queue = append(queue, neighbor)
		}
	}

	return nil
}

// classifyEscalationRisk determines the risk level for an escalation path.
// restricted -> admin: 1 hop = critical, 2 hops = high, 3+ = medium
// standard -> admin:   1 hop = high,     2 hops = medium, 3+ = low
// restricted -> elevated: 1 hop = high, 2 hops = medium, 3+ = low
// standard -> elevated:  1 hop = medium, 2 hops = low, 3+ = low
func classifyEscalationRisk(srcPriv, dstPriv string, hops int) string {
	srcLvl := privilegeLevel[srcPriv]
	dstLvl := privilegeLevel[dstPriv]
	gap := dstLvl - srcLvl

	if gap <= 0 {
		return "low"
	}

	// Base risk from restricted -> admin (gap=3).
	// gap=3: 1 hop = critical, 2 = high, 3+ = medium
	// gap=2: 1 hop = high, 2 = medium, 3+ = low
	// gap=1: 1 hop = medium, 2 = low, 3+ = low
	baseRisks := map[int][]string{
		3: {"critical", "high", "medium"},
		2: {"high", "medium", "low"},
		1: {"medium", "low", "low"},
	}

	risks, ok := baseRisks[gap]
	if !ok {
		return "low"
	}

	idx := hops - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(risks) {
		idx = len(risks) - 1
	}
	return risks[idx]
}

// findUnverifiedEdges returns all edges where Verified is false.
func findUnverifiedEdges(g *TrustGraph) []TrustEdge {
	var result []TrustEdge
	for _, e := range g.Edges {
		if !e.Verified {
			result = append(result, e)
		}
	}
	return result
}

// findOverprivilegedAgents returns agents with admin privilege but no policies applied.
func findOverprivilegedAgents(g *TrustGraph) []AgentNode {
	var result []AgentNode
	for _, a := range g.Agents {
		if a.Privilege == "admin" && len(a.Policies) == 0 {
			result = append(result, a)
		}
	}
	return result
}

// findIsolatedAgents returns agents with no edges (no connections).
func findIsolatedAgents(g *TrustGraph) []AgentNode {
	connected := make(map[string]bool)
	for _, e := range g.Edges {
		connected[e.From] = true
		connected[e.To] = true
	}

	var result []AgentNode
	for _, a := range g.Agents {
		if !connected[a.Name] {
			result = append(result, a)
		}
	}
	return result
}

// computeStats calculates summary statistics for a trust graph.
func computeStats(g *TrustGraph, ta *TrustAnalysis) TrustStats {
	stats := TrustStats{
		TotalAgents: len(g.Agents),
		TotalEdges:  len(g.Edges),
	}

	for _, a := range g.Agents {
		if a.Privilege == "admin" {
			stats.AdminAgents++
		}
	}

	for _, e := range g.Edges {
		if !e.Verified {
			stats.UnverifiedEdges++
		}
	}

	if stats.TotalAgents > 0 {
		// Count connections per agent.
		connections := make(map[string]int)
		for _, e := range g.Edges {
			connections[e.From]++
			connections[e.To]++
		}
		total := 0
		for _, a := range g.Agents {
			total += connections[a.Name]
		}
		stats.AvgConnections = float64(total) / float64(stats.TotalAgents)
	}

	// MaxDepth: longest shortest path from any agent to any other.
	adj := buildAdjacency(g)
	for _, a := range g.Agents {
		depth := bfsMaxDepth(adj, a.Name)
		if depth > stats.MaxDepth {
			stats.MaxDepth = depth
		}
	}

	// Escalation risk: highest risk among escalation paths.
	stats.EscalationRisk = "none"
	riskOrder := map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	for _, ep := range ta.EscalationPaths {
		if riskOrder[ep.Risk] > riskOrder[stats.EscalationRisk] {
			stats.EscalationRisk = ep.Risk
		}
	}

	return stats
}

// bfsMaxDepth returns the longest shortest path from src to any reachable node.
func bfsMaxDepth(adj map[string][]string, src string) int {
	visited := map[string]bool{src: true}
	type entry struct {
		node  string
		depth int
	}
	queue := []entry{{src, 0}}
	maxDepth := 0

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.depth > maxDepth {
			maxDepth = current.depth
		}

		for _, neighbor := range adj[current.node] {
			if visited[neighbor] {
				continue
			}
			visited[neighbor] = true
			queue = append(queue, entry{neighbor, current.depth + 1})
		}
	}

	return maxDepth
}

// generateFindings produces findings from the analysis results.
func generateFindings(ta *TrustAnalysis) []TrustFinding {
	var findings []TrustFinding

	// Escalation path findings.
	for _, ep := range ta.EscalationPaths {
		findings = append(findings, TrustFinding{
			Severity: ep.Risk,
			Category: "escalation",
			Title:    fmt.Sprintf("Privilege escalation: %s → %s", ep.From, ep.To),
			Description: fmt.Sprintf(
				"Agent %q (%s) can reach %q (%s) in %d hop(s) via %s",
				ep.From,
				agentPrivilege(ta.Graph, ep.From),
				ep.To,
				agentPrivilege(ta.Graph, ep.To),
				ep.Hops,
				strings.Join(ep.Path, " → ")),
		})
	}

	// Unverified edge findings.
	for _, e := range ta.UnverifiedEdges {
		findings = append(findings, TrustFinding{
			Severity:    "high",
			Category:    "unverified",
			Title:       fmt.Sprintf("Unverified trust: %s → %s", e.From, e.To),
			Description: fmt.Sprintf("Channel %q between %s and %s lacks identity verification — spoofing risk", e.Channel, e.From, e.To),
		})
	}

	// Overprivileged agent findings.
	for _, a := range ta.OverprivilegedAgents {
		findings = append(findings, TrustFinding{
			Severity:    "high",
			Category:    "overprivileged",
			Title:       fmt.Sprintf("Overprivileged: %s", a.Name),
			Description: fmt.Sprintf("Agent %q has %s privilege with no policy constraints", a.Name, a.Privilege),
		})
	}

	// Isolated agent findings.
	for _, a := range ta.IsolatedAgents {
		findings = append(findings, TrustFinding{
			Severity:    "medium",
			Category:    "isolation",
			Title:       fmt.Sprintf("Isolated agent: %s", a.Name),
			Description: fmt.Sprintf("Agent %q has no trust edges — potential monitoring blind spot", a.Name),
		})
	}

	return findings
}

// agentPrivilege looks up an agent's privilege level by name.
func agentPrivilege(g *TrustGraph, name string) string {
	for _, a := range g.Agents {
		if a.Name == name {
			return a.Privilege
		}
	}
	return "unknown"
}

// privilegeIcon returns a visual icon for a privilege level.
func privilegeIcon(priv string) string {
	switch priv {
	case "admin":
		return "★"
	case "elevated":
		return "▲"
	case "standard":
		return "●"
	case "restricted":
		return "○"
	default:
		return "?"
	}
}
