// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"fmt"
	"strings"
)

// TrustGraph is a directed graph of trust relationships between agents.
type TrustGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// GraphNode represents an agent in the trust graph.
type GraphNode struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Trust      string `json:"trust"`
	ToolCount  int    `json:"tool_count"`
	Guardrails int    `json:"guardrails"`
	HasRisks   bool   `json:"has_risks"`
}

// GraphEdge represents a trust relationship between agents.
type GraphEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label"` // "trusts", "trusted_by", "escalates"
	Risk  bool   `json:"risk"`  // true if this edge represents a risk
}

// BuildTrustGraph builds a trust graph from an inventory.
func BuildTrustGraph(inv *Inventory) *TrustGraph {
	if inv == nil || len(inv.Agents) == 0 {
		return &TrustGraph{}
	}

	g := &TrustGraph{}

	// Build a lookup for quick agent retrieval.
	agentMap := make(map[string]*Agent)
	for _, a := range inv.Agents {
		agentMap[a.Meta.Name] = a
	}

	// Run trust analysis to detect risks.
	analysis := inv.AnalyzeTrust()
	riskAgents := make(map[string]bool)
	for _, r := range analysis.Risks {
		riskAgents[r.AgentName] = true
	}

	// Build nodes.
	for _, a := range inv.Agents {
		g.Nodes = append(g.Nodes, GraphNode{
			Name:       a.Meta.Name,
			Type:       a.Meta.Type,
			Trust:      a.Trust.Level,
			ToolCount:  len(a.Tools),
			Guardrails: len(a.Guardrails),
			HasRisks:   riskAgents[a.Meta.Name],
		})
	}

	// Build edges from trust relationships.
	for _, a := range inv.Agents {
		for _, trustedByName := range a.Trust.TrustedBy {
			isRisk := false
			// Risk: if a lower-trust agent trusts a higher-trust agent.
			if other, ok := agentMap[trustedByName]; ok {
				if trustLevelOrder[a.Trust.Level] > trustLevelOrder[other.Trust.Level] {
					isRisk = true
				}
			}
			g.Edges = append(g.Edges, GraphEdge{
				From:  trustedByName,
				To:    a.Meta.Name,
				Label: "trusts",
				Risk:  isRisk,
			})
		}

		for _, trustsFromName := range a.Trust.TrustsFrom {
			g.Edges = append(g.Edges, GraphEdge{
				From:  a.Meta.Name,
				To:    trustsFromName,
				Label: "trusts",
			})
		}

		// Escalation edges.
		if a.Trust.CanEscalate {
			for _, trustsFromName := range a.Trust.TrustsFrom {
				if other, ok := agentMap[trustsFromName]; ok {
					if trustLevelOrder[other.Trust.Level] > trustLevelOrder[a.Trust.Level] {
						g.Edges = append(g.Edges, GraphEdge{
							From:  a.Meta.Name,
							To:    trustsFromName,
							Label: "escalates",
							Risk:  true,
						})
					}
				}
			}
		}
	}

	return g
}

// FormatDOT renders the trust graph as a Graphviz DOT string.
func (g *TrustGraph) FormatDOT() string {
	var sb strings.Builder

	sb.WriteString("digraph TrustGraph {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=rounded, fontname=\"Helvetica\"];\n")
	sb.WriteString("  edge [fontname=\"Helvetica\", fontsize=10];\n")
	sb.WriteString("\n")

	// Style nodes by trust level.
	for _, n := range g.Nodes {
		color := trustColor(n.Trust)
		border := ""
		if n.HasRisks {
			border = ", penwidth=2, color=red"
		}
		label := fmt.Sprintf("%s\\n[%s] %s\\n%d tools, %d guardrails",
			n.Name, n.Trust, n.Type, n.ToolCount, n.Guardrails)
		fmt.Fprintf(&sb, "  %q [label=%q, fillcolor=%q, style=\"rounded,filled\"%s];\n",
			n.Name, label, color, border)
	}

	sb.WriteString("\n")

	// Draw edges.
	for _, e := range g.Edges {
		style := ""
		edgeColor := "black"
		if e.Risk {
			style = ", style=dashed"
			edgeColor = "red"
		}
		if e.Label == "escalates" {
			style = ", style=bold"
			edgeColor = "red"
		}
		fmt.Fprintf(&sb, "  %q -> %q [label=%q, color=%q%s];\n",
			e.From, e.To, e.Label, edgeColor, style)
	}

	sb.WriteString("}\n")

	return sb.String()
}

// FormatMermaid renders the trust graph as a Mermaid diagram.
func (g *TrustGraph) FormatMermaid() string {
	var sb strings.Builder

	sb.WriteString("graph LR\n")

	// Render nodes.
	for _, n := range g.Nodes {
		label := fmt.Sprintf("%s<br/>%s / %s<br/>%d tools",
			n.Name, n.Trust, n.Type, n.ToolCount)
		if n.HasRisks {
			// Use a different shape for risky agents.
			fmt.Fprintf(&sb, "  %s{{%q}}\n", sanitizeMermaidID(n.Name), label)
		} else {
			fmt.Fprintf(&sb, "  %s[%q]\n", sanitizeMermaidID(n.Name), label)
		}
	}

	sb.WriteString("\n")

	// Render edges.
	for _, e := range g.Edges {
		fromID := sanitizeMermaidID(e.From)
		toID := sanitizeMermaidID(e.To)
		if e.Risk || e.Label == "escalates" {
			fmt.Fprintf(&sb, "  %s --%q-.-> %s\n", fromID, e.Label, toID)
		} else {
			fmt.Fprintf(&sb, "  %s --%q--> %s\n", fromID, e.Label, toID)
		}
	}

	// Style risky nodes.
	for _, n := range g.Nodes {
		if n.HasRisks {
			fmt.Fprintf(&sb, "  style %s fill:#ff6b6b,stroke:#c0392b\n",
				sanitizeMermaidID(n.Name))
		} else {
			color := trustMermaidColor(n.Trust)
			fmt.Fprintf(&sb, "  style %s fill:%s\n",
				sanitizeMermaidID(n.Name), color)
		}
	}

	return sb.String()
}

// FormatText renders the trust graph as plain text for terminal display.
func (g *TrustGraph) FormatText() string {
	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│              AGENT TRUST GRAPH                  │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Agents: %-40d │\n", len(g.Nodes))
	fmt.Fprintf(&sb, "│ Trust Edges: %-35d │\n", len(g.Edges))

	riskEdges := 0
	for _, e := range g.Edges {
		if e.Risk {
			riskEdges++
		}
	}
	fmt.Fprintf(&sb, "│ Risk Edges: %-36d │\n", riskEdges)
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Nodes grouped by trust level.
	levels := []string{TrustAdmin, TrustElevated, TrustStandard, TrustLow, TrustUntrusted}
	for _, level := range levels {
		var agents []string
		for _, n := range g.Nodes {
			if n.Trust == level {
				agents = append(agents, n.Name)
			}
		}
		if len(agents) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "│ [%-10s]                                    │\n", level)
		for _, name := range agents {
			icon := "  "
			for _, n := range g.Nodes {
				if n.Name == name && n.HasRisks {
					icon = "⚠ "
					break
				}
			}
			fmt.Fprintf(&sb, "│   %s%-44s │\n", icon, truncate(name, 44))
		}
	}

	// Edge list.
	if len(g.Edges) > 0 {
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
		sb.WriteString("│ Relationships                                   │\n")
		for _, e := range g.Edges {
			arrow := "→"
			if e.Risk {
				arrow = "⚠→"
			}
			if e.Label == "escalates" {
				arrow = "⇑"
			}
			line := fmt.Sprintf("%s %s %s (%s)", e.From, arrow, e.To, e.Label)
			fmt.Fprintf(&sb, "│   %-46s │\n", truncate(line, 46))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// trustColor returns a DOT fill color for the trust level.
func trustColor(level string) string {
	switch level {
	case TrustAdmin:
		return "#ffcccb"
	case TrustElevated:
		return "#ffd699"
	case TrustStandard:
		return "#ffffcc"
	case TrustLow:
		return "#ccffcc"
	case TrustUntrusted:
		return "#e0e0e0"
	default:
		return "#ffffff"
	}
}

// trustMermaidColor returns a CSS color for Mermaid diagrams.
func trustMermaidColor(level string) string {
	switch level {
	case TrustAdmin:
		return "#ffcccb"
	case TrustElevated:
		return "#ffd699"
	case TrustStandard:
		return "#ffffcc"
	case TrustLow:
		return "#ccffcc"
	case TrustUntrusted:
		return "#e0e0e0"
	default:
		return "#ffffff"
	}
}

// sanitizeMermaidID converts a name to a valid Mermaid node ID.
func sanitizeMermaidID(name string) string {
	r := strings.NewReplacer(
		"-", "_",
		" ", "_",
		".", "_",
		"/", "_",
	)
	return r.Replace(name)
}
