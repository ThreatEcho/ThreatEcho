// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"fmt"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Dependency represents a directed relationship between two agents.
type Dependency struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Type        string `json:"type"` // delegates_to, shares_tool, trust_chain, data_flow, orchestrates
	Tool        string `json:"tool,omitempty"`
	Strength    string `json:"strength"` // strong, moderate, weak
	Description string `json:"description"`
}

// DependencyGraph holds all inter-agent dependencies discovered in an inventory.
type DependencyGraph struct {
	Agents       []string       `json:"agents"`
	Dependencies []Dependency   `json:"dependencies"`
	Clusters     []AgentCluster `json:"clusters"`
	Isolates     []string       `json:"isolates"`
}

// AgentCluster is a group of tightly connected agents.
type AgentCluster struct {
	ID     string   `json:"id"`
	Agents []string `json:"agents"`
	Reason string   `json:"reason"`
}

// BlastRadius describes the impact of compromising a single agent.
type BlastRadius struct {
	CompromisedAgent string           `json:"compromised_agent"`
	DirectImpact     []string         `json:"direct_impact"`
	IndirectImpact   []string         `json:"indirect_impact"`
	TotalAffected    int              `json:"total_affected"`
	RiskScore        float64          `json:"risk_score"`
	Severity         string           `json:"severity"`
	AffectedTools    []string         `json:"affected_tools"`
	EscalationPaths  []EscalationPath `json:"escalation_paths"`
}

// EscalationPath records a trust-escalation chain through the dependency graph.
type EscalationPath struct {
	Path        []string `json:"path"`
	FinalTrust  string   `json:"final_trust"`
	Description string   `json:"description"`
}

// SinglePointOfFailure identifies an agent whose compromise or failure would
// disproportionately affect the system.
type SinglePointOfFailure struct {
	Agent       string   `json:"agent"`
	DependentOn int      `json:"dependent_on"`
	TrustLevel  string   `json:"trust_level"`
	Tools       []string `json:"tools"`
	Risk        string   `json:"risk"`
	Reason      string   `json:"reason"`
}

// DependencyReport is the full dependency analysis for an inventory.
type DependencyReport struct {
	Graph               DependencyGraph        `json:"graph"`
	BlastRadii          []BlastRadius          `json:"blast_radii"`
	SinglePointFailures []SinglePointOfFailure `json:"single_point_failures"`
	MaxBlastRadius      int                    `json:"max_blast_radius"`
	AvgConnections      float64                `json:"avg_connections"`
	MostConnected       string                 `json:"most_connected"`
	Recommendations     []string               `json:"recommendations"`
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// BuildDependencyGraph analyzes an inventory and discovers all inter-agent
// dependencies: tool sharing, delegation, trust chains, data flows, and
// orchestration relationships.
func BuildDependencyGraph(inv *Inventory) *DependencyGraph {
	if inv == nil || len(inv.Agents) == 0 {
		return &DependencyGraph{}
	}

	g := &DependencyGraph{}

	agentMap := make(map[string]*Agent)
	for _, a := range inv.Agents {
		agentMap[a.Meta.Name] = a
		g.Agents = append(g.Agents, a.Meta.Name)
	}
	sort.Strings(g.Agents)

	// Deduplication set keyed on From|To|Type|Tool.
	depSet := make(map[string]bool)
	addDep := func(d Dependency) {
		if d.From == d.To {
			return
		}
		key := d.From + "\x00" + d.To + "\x00" + d.Type + "\x00" + d.Tool
		if !depSet[key] {
			depSet[key] = true
			g.Dependencies = append(g.Dependencies, d)
		}
	}

	// --- 1. shares_tool --------------------------------------------------
	toolUsers := inv.ToolMatrix()
	for toolName, users := range toolUsers {
		if len(users) < 2 {
			continue
		}
		sort.Strings(users)
		for i := 0; i < len(users); i++ {
			for j := i + 1; j < len(users); j++ {
				strength := "weak"
				if hasElevatedTool(agentMap[users[i]], toolName) ||
					hasElevatedTool(agentMap[users[j]], toolName) {
					strength = "moderate"
				}
				addDep(Dependency{
					From:        users[i],
					To:          users[j],
					Type:        "shares_tool",
					Tool:        toolName,
					Strength:    strength,
					Description: fmt.Sprintf("%s and %s both use tool %s", users[i], users[j], toolName),
				})
			}
		}
	}

	// --- 2. delegates_to / orchestrates ----------------------------------
	for _, a := range inv.Agents {
		// TrustedBy: if a is trusted by delegator, delegator delegates to a.
		for _, delegator := range a.Trust.TrustedBy {
			src, ok := agentMap[delegator]
			if !ok {
				continue
			}
			if src.Meta.Type == TypeOrchestrator {
				addDep(Dependency{
					From:        delegator,
					To:          a.Meta.Name,
					Type:        "orchestrates",
					Strength:    "strong",
					Description: fmt.Sprintf("orchestrator %s manages %s", delegator, a.Meta.Name),
				})
			} else {
				addDep(Dependency{
					From:        delegator,
					To:          a.Meta.Name,
					Type:        "delegates_to",
					Strength:    "moderate",
					Description: fmt.Sprintf("%s delegates to %s", delegator, a.Meta.Name),
				})
			}
		}
		// TrustsFrom: if a trusts from an orchestrator, orchestrator delegates to a.
		for _, trustedSource := range a.Trust.TrustsFrom {
			src, ok := agentMap[trustedSource]
			if !ok {
				continue
			}
			if src.Meta.Type == TypeOrchestrator {
				addDep(Dependency{
					From:        trustedSource,
					To:          a.Meta.Name,
					Type:        "orchestrates",
					Strength:    "strong",
					Description: fmt.Sprintf("orchestrator %s manages %s", trustedSource, a.Meta.Name),
				})
			}
		}
	}
	// Orchestrators also delegate to agents in their own TrustedBy list.
	for _, a := range inv.Agents {
		if a.Meta.Type == TypeOrchestrator {
			for _, target := range a.Trust.TrustedBy {
				if _, ok := agentMap[target]; ok {
					addDep(Dependency{
						From:        a.Meta.Name,
						To:          target,
						Type:        "orchestrates",
						Strength:    "strong",
						Description: fmt.Sprintf("orchestrator %s manages %s", a.Meta.Name, target),
					})
				}
			}
		}
	}

	// --- 3. trust_chain --------------------------------------------------
	for i := 0; i < len(inv.Agents); i++ {
		for j := i + 1; j < len(inv.Agents); j++ {
			a, b := inv.Agents[i], inv.Agents[j]
			shared := findSharedToolNames(a, b)
			if len(shared) == 0 {
				continue
			}
			aRank := trustLevelOrder[a.Trust.Level]
			bRank := trustLevelOrder[b.Trust.Level]
			if aRank == bRank {
				continue
			}
			var higher, lower *Agent
			if aRank > bRank {
				higher, lower = a, b
			} else {
				higher, lower = b, a
			}
			strength := "moderate"
			if trustLevelOrder[higher.Trust.Level] >= trustLevelOrder[TrustAdmin] {
				strength = "strong"
			}
			addDep(Dependency{
				From:        higher.Meta.Name,
				To:          lower.Meta.Name,
				Type:        "trust_chain",
				Tool:        strings.Join(shared, ","),
				Strength:    strength,
				Description: fmt.Sprintf("%s (%s) and %s (%s) share tools across trust levels", higher.Meta.Name, higher.Trust.Level, lower.Meta.Name, lower.Trust.Level),
			})
		}
	}

	// --- 4. data_flow ----------------------------------------------------
	type agentTargetSet struct {
		name    string
		targets map[string]bool
	}
	var targetSets []agentTargetSet
	for _, a := range inv.Agents {
		ts := make(map[string]bool)
		for _, t := range a.Tools {
			for _, tgt := range t.Targets {
				ts[tgt] = true
			}
		}
		if len(ts) > 0 {
			targetSets = append(targetSets, agentTargetSet{name: a.Meta.Name, targets: ts})
		}
	}
	for i := 0; i < len(targetSets); i++ {
		for j := i + 1; j < len(targetSets); j++ {
			var shared []string
			for t := range targetSets[i].targets {
				if targetSets[j].targets[t] {
					shared = append(shared, t)
				}
			}
			if len(shared) > 0 {
				sort.Strings(shared)
				addDep(Dependency{
					From:        targetSets[i].name,
					To:          targetSets[j].name,
					Type:        "data_flow",
					Strength:    "weak",
					Description: fmt.Sprintf("%s and %s share data targets: %s", targetSets[i].name, targetSets[j].name, strings.Join(shared, ", ")),
				})
			}
		}
	}

	// Sort dependencies for deterministic output: by type, then from, then to.
	sort.Slice(g.Dependencies, func(i, j int) bool {
		di, dj := g.Dependencies[i], g.Dependencies[j]
		if di.Type != dj.Type {
			return di.Type < dj.Type
		}
		if di.From != dj.From {
			return di.From < dj.From
		}
		return di.To < dj.To
	})

	// Discover clusters (connected components).
	g.Clusters = findDepClusters(g)

	// Discover isolates (agents with no dependency edges).
	connected := make(map[string]bool)
	for _, d := range g.Dependencies {
		connected[d.From] = true
		connected[d.To] = true
	}
	for _, name := range g.Agents {
		if !connected[name] {
			g.Isolates = append(g.Isolates, name)
		}
	}

	return g
}

// AnalyzeBlastRadius computes the blast radius for compromising a single agent.
func AnalyzeBlastRadius(inv *Inventory, agentName string) *BlastRadius {
	g := BuildDependencyGraph(inv)
	return analyzeBlastRadiusFromGraph(g, inv, agentName)
}

// AnalyzeAllBlastRadii computes blast radii for every agent in the inventory.
func AnalyzeAllBlastRadii(inv *Inventory) []BlastRadius {
	if inv == nil || len(inv.Agents) == 0 {
		return nil
	}
	g := BuildDependencyGraph(inv)
	radii := make([]BlastRadius, 0, len(inv.Agents))
	for _, a := range inv.Agents {
		br := analyzeBlastRadiusFromGraph(g, inv, a.Meta.Name)
		radii = append(radii, *br)
	}
	return radii
}

// FindSinglePointsOfFailure identifies agents whose compromise would
// disproportionately affect the system.
func FindSinglePointsOfFailure(inv *Inventory) []SinglePointOfFailure {
	if inv == nil || len(inv.Agents) == 0 {
		return nil
	}

	g := BuildDependencyGraph(inv)

	// Count unique bidirectional neighbors for each agent.
	neighborSet := make(map[string]map[string]bool)
	for _, d := range g.Dependencies {
		if neighborSet[d.From] == nil {
			neighborSet[d.From] = make(map[string]bool)
		}
		if neighborSet[d.To] == nil {
			neighborSet[d.To] = make(map[string]bool)
		}
		neighborSet[d.From][d.To] = true
		neighborSet[d.To][d.From] = true
	}

	agentMap := make(map[string]*Agent)
	for _, a := range inv.Agents {
		agentMap[a.Meta.Name] = a
	}

	var spofs []SinglePointOfFailure
	for _, a := range inv.Agents {
		name := a.Meta.Name
		neighbors := len(neighborSet[name])
		if neighbors < 2 {
			continue
		}

		var tools []string
		for _, t := range a.Tools {
			tools = append(tools, t.Name)
		}

		risk, reason := classifySPOFRisk(a, neighbors)

		spofs = append(spofs, SinglePointOfFailure{
			Agent:       name,
			DependentOn: neighbors,
			TrustLevel:  a.Trust.Level,
			Tools:       tools,
			Risk:        risk,
			Reason:      reason,
		})
	}

	sort.SliceStable(spofs, func(i, j int) bool {
		return severityRank(spofs[i].Risk) > severityRank(spofs[j].Risk)
	})

	return spofs
}

// FindEscalationPaths discovers all trust-escalation paths in the inventory.
// An escalation path is a chain through the dependency graph where trust
// increases from start to end.
func FindEscalationPaths(inv *Inventory) []EscalationPath {
	if inv == nil || len(inv.Agents) == 0 {
		return nil
	}

	g := BuildDependencyGraph(inv)
	agentMap := make(map[string]*Agent)
	for _, a := range inv.Agents {
		agentMap[a.Meta.Name] = a
	}

	var allPaths []EscalationPath
	seen := make(map[string]bool)

	for _, a := range inv.Agents {
		paths := findDepEscalationPaths(g, agentMap, a.Meta.Name)
		for _, p := range paths {
			key := strings.Join(p.Path, "|")
			if !seen[key] {
				seen[key] = true
				allPaths = append(allPaths, p)
			}
		}
	}

	return allPaths
}

// GenerateDependencyReport produces a full dependency analysis for an inventory.
func GenerateDependencyReport(inv *Inventory) *DependencyReport {
	r := &DependencyReport{}

	if inv == nil || len(inv.Agents) == 0 {
		return r
	}

	g := BuildDependencyGraph(inv)
	r.Graph = *g

	// Blast radii for every agent.
	for _, a := range inv.Agents {
		br := analyzeBlastRadiusFromGraph(g, inv, a.Meta.Name)
		r.BlastRadii = append(r.BlastRadii, *br)
	}

	// Single points of failure.
	r.SinglePointFailures = FindSinglePointsOfFailure(inv)

	// Summary statistics.
	maxBR := 0
	for _, br := range r.BlastRadii {
		if br.TotalAffected > maxBR {
			maxBR = br.TotalAffected
		}
	}
	r.MaxBlastRadius = maxBR

	neighborSet := make(map[string]map[string]bool)
	for _, d := range g.Dependencies {
		if neighborSet[d.From] == nil {
			neighborSet[d.From] = make(map[string]bool)
		}
		if neighborSet[d.To] == nil {
			neighborSet[d.To] = make(map[string]bool)
		}
		neighborSet[d.From][d.To] = true
		neighborSet[d.To][d.From] = true
	}
	totalConnections := 0
	mostConnName := ""
	mostConnCount := 0
	for name, ns := range neighborSet {
		count := len(ns)
		totalConnections += count
		if count > mostConnCount {
			mostConnCount = count
			mostConnName = name
		}
	}
	if len(inv.Agents) > 0 {
		r.AvgConnections = float64(totalConnections) / float64(len(inv.Agents))
	}
	r.MostConnected = mostConnName

	// Recommendations.
	r.Recommendations = generateDepRecommendations(r, g, inv)

	return r
}

// FormatDependencyReport renders a dependency report as a box-drawing string.
func FormatDependencyReport(r *DependencyReport) string {
	if r == nil {
		return "No dependency report.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│         DEPENDENCY ANALYSIS REPORT              │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Agents:           %-30d │\n", len(r.Graph.Agents))
	fmt.Fprintf(&sb, "│ Dependencies:     %-30d │\n", len(r.Graph.Dependencies))
	fmt.Fprintf(&sb, "│ Clusters:         %-30d │\n", len(r.Graph.Clusters))
	fmt.Fprintf(&sb, "│ Isolates:         %-30d │\n", len(r.Graph.Isolates))
	fmt.Fprintf(&sb, "│ Max Blast Radius: %-30d │\n", r.MaxBlastRadius)
	fmt.Fprintf(&sb, "│ Avg Connections:  %-30s │\n", fmt.Sprintf("%.2f", r.AvgConnections))
	fmt.Fprintf(&sb, "│ Most Connected:   %-30s │\n", truncate(r.MostConnected, 30))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Dependency type breakdown.
	typeCounts := make(map[string]int)
	for _, d := range r.Graph.Dependencies {
		typeCounts[d.Type]++
	}
	if len(typeCounts) > 0 {
		sb.WriteString("│ Dependency Types                                │\n")
		for _, t := range sortedMapKeys(typeCounts) {
			fmt.Fprintf(&sb, "│   %-16s %-30d │\n", t, typeCounts[t])
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Single points of failure.
	if len(r.SinglePointFailures) > 0 {
		sb.WriteString("│ Single Points of Failure                        │\n")
		for _, spof := range r.SinglePointFailures {
			line := fmt.Sprintf("%s (%d deps)", spof.Agent, spof.DependentOn)
			fmt.Fprintf(&sb, "│  %s [%-8s] %-33s │\n",
				gapIcon(spof.Risk),
				truncate(spof.Risk, 8),
				truncate(line, 33))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Top blast radii (up to 5).
	nonZero := make([]BlastRadius, 0)
	for _, br := range r.BlastRadii {
		if br.TotalAffected > 0 {
			nonZero = append(nonZero, br)
		}
	}
	if len(nonZero) > 0 {
		sort.SliceStable(nonZero, func(i, j int) bool {
			return nonZero[i].TotalAffected > nonZero[j].TotalAffected
		})
		sb.WriteString("│ Blast Radii                                     │\n")
		limit := 5
		if len(nonZero) < limit {
			limit = len(nonZero)
		}
		for _, br := range nonZero[:limit] {
			line := fmt.Sprintf("%s: %d affected (%.2f %s)",
				br.CompromisedAgent, br.TotalAffected, br.RiskScore, br.Severity)
			fmt.Fprintf(&sb, "│   %-46s │\n", truncate(line, 46))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Recommendations.
	if len(r.Recommendations) > 0 {
		sb.WriteString("│ Recommendations                                 │\n")
		for _, rec := range r.Recommendations {
			lines := wrapText(rec, 46)
			for _, line := range lines {
				fmt.Fprintf(&sb, "│   %-46s │\n", line)
			}
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// FormatBlastRadius renders a single agent's blast radius as a box-drawing
// string.
func FormatBlastRadius(b *BlastRadius) string {
	if b == nil {
		return "No blast radius data.\n"
	}

	var sb strings.Builder

	title := fmt.Sprintf("BLAST RADIUS: %s", b.CompromisedAgent)
	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	fmt.Fprintf(&sb, "│ %-48s │\n", truncate(title, 48))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Risk Score:      %-31s │\n",
		fmt.Sprintf("%.2f (%s)", b.RiskScore, b.Severity))
	fmt.Fprintf(&sb, "│ Total Affected:  %-31d │\n", b.TotalAffected)
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	if len(b.DirectImpact) > 0 {
		sb.WriteString("│ Direct Impact                                   │\n")
		for _, name := range b.DirectImpact {
			fmt.Fprintf(&sb, "│   %-46s │\n", truncate(name, 46))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	if len(b.IndirectImpact) > 0 {
		sb.WriteString("│ Indirect Impact                                 │\n")
		for _, name := range b.IndirectImpact {
			fmt.Fprintf(&sb, "│   %-46s │\n", truncate(name, 46))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	if len(b.AffectedTools) > 0 {
		sb.WriteString("│ Affected Tools                                  │\n")
		toolStr := strings.Join(b.AffectedTools, ", ")
		lines := wrapText(toolStr, 46)
		for _, line := range lines {
			fmt.Fprintf(&sb, "│   %-46s │\n", line)
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	if len(b.EscalationPaths) > 0 {
		sb.WriteString("│ Escalation Paths                                │\n")
		for _, ep := range b.EscalationPaths {
			chain := strings.Join(ep.Path, " -> ")
			fmt.Fprintf(&sb, "│   %-34s (%-8s) │\n",
				truncate(chain, 34),
				truncate(ep.FinalTrust, 8))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// SummarizeDependencies returns a one-line summary of the dependency report.
func SummarizeDependencies(r *DependencyReport) string {
	if r == nil {
		return "No dependency data."
	}
	if len(r.Graph.Agents) == 0 {
		return "Empty inventory — no dependencies to analyze."
	}
	if len(r.Graph.Dependencies) == 0 {
		return fmt.Sprintf("%d agents, no dependencies found.", len(r.Graph.Agents))
	}
	return fmt.Sprintf(
		"%d agents, %d dependencies, %d clusters, %d SPOFs — max blast radius %d, most connected: %s.",
		len(r.Graph.Agents),
		len(r.Graph.Dependencies),
		len(r.Graph.Clusters),
		len(r.SinglePointFailures),
		r.MaxBlastRadius,
		r.MostConnected,
	)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// analyzeBlastRadiusFromGraph computes the blast radius using a pre-built graph.
func analyzeBlastRadiusFromGraph(g *DependencyGraph, inv *Inventory, agentName string) *BlastRadius {
	br := &BlastRadius{CompromisedAgent: agentName}

	if inv == nil || len(inv.Agents) == 0 {
		return br
	}

	agent := inv.FindAgent(agentName)
	if agent == nil {
		return br
	}

	// Build bidirectional adjacency from dependency edges.
	adj := make(map[string]map[string]bool)
	for _, d := range g.Dependencies {
		if adj[d.From] == nil {
			adj[d.From] = make(map[string]bool)
		}
		adj[d.From][d.To] = true
		if adj[d.To] == nil {
			adj[d.To] = make(map[string]bool)
		}
		adj[d.To][d.From] = true
	}

	// BFS from the compromised agent.
	dist := map[string]int{agentName: 0}
	queue := []string{agentName}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for neighbor := range adj[cur] {
			if _, visited := dist[neighbor]; !visited {
				dist[neighbor] = dist[cur] + 1
				queue = append(queue, neighbor)
			}
		}
	}

	// Separate direct (distance 1) from indirect (distance 2+).
	for name, d := range dist {
		if name == agentName {
			continue
		}
		if d == 1 {
			br.DirectImpact = append(br.DirectImpact, name)
		} else {
			br.IndirectImpact = append(br.IndirectImpact, name)
		}
	}
	sort.Strings(br.DirectImpact)
	sort.Strings(br.IndirectImpact)
	br.TotalAffected = len(br.DirectImpact) + len(br.IndirectImpact)

	// Collect affected tools from all impacted agents.
	agentMap := make(map[string]*Agent)
	for _, a := range inv.Agents {
		agentMap[a.Meta.Name] = a
	}
	toolSet := make(map[string]bool)
	for _, t := range agent.Tools {
		toolSet[t.Name] = true
	}
	allAffected := append(append([]string{}, br.DirectImpact...), br.IndirectImpact...)
	for _, name := range allAffected {
		if a, ok := agentMap[name]; ok {
			for _, t := range a.Tools {
				toolSet[t.Name] = true
			}
		}
	}
	for tool := range toolSet {
		br.AffectedTools = append(br.AffectedTools, tool)
	}
	sort.Strings(br.AffectedTools)

	// Discover escalation paths originating from the compromised agent.
	br.EscalationPaths = findDepEscalationPaths(g, agentMap, agentName)

	// Compute risk score and severity.
	br.RiskScore = calcBlastRiskScore(br, inv, agentMap)
	br.Severity = blastSeverity(br.RiskScore)

	return br
}

// findDepEscalationPaths discovers trust-escalation paths starting from a
// specific agent through the dependency graph.
func findDepEscalationPaths(g *DependencyGraph, agentMap map[string]*Agent, startName string) []EscalationPath {
	startAgent := agentMap[startName]
	if startAgent == nil {
		return nil
	}
	startRank := trustLevelOrder[startAgent.Trust.Level]

	// Build bidirectional sorted adjacency for deterministic traversal.
	adj := make(map[string][]string)
	edgeSet := make(map[string]bool)
	for _, d := range g.Dependencies {
		fwd := d.From + "\x00" + d.To
		rev := d.To + "\x00" + d.From
		if !edgeSet[fwd] {
			edgeSet[fwd] = true
			adj[d.From] = append(adj[d.From], d.To)
		}
		if !edgeSet[rev] {
			edgeSet[rev] = true
			adj[d.To] = append(adj[d.To], d.From)
		}
	}
	for k := range adj {
		sort.Strings(adj[k])
	}

	var paths []EscalationPath
	visited := make(map[string]bool)

	var dfs func(current string, path []string)
	dfs = func(current string, path []string) {
		visited[current] = true
		path = append(path, current)

		if cur, ok := agentMap[current]; ok {
			curRank := trustLevelOrder[cur.Trust.Level]
			if curRank > startRank && len(path) > 1 {
				p := make([]string, len(path))
				copy(p, path)
				paths = append(paths, EscalationPath{
					Path:       p,
					FinalTrust: cur.Trust.Level,
					Description: fmt.Sprintf(
						"escalation from %s (%s) to %s (%s) via %d hops",
						startName, startAgent.Trust.Level,
						current, cur.Trust.Level,
						len(path)-1),
				})
			}
		}

		for _, next := range adj[current] {
			if !visited[next] {
				dfs(next, path)
			}
		}

		visited[current] = false
	}

	dfs(startName, nil)
	return paths
}

// findDepClusters discovers connected components using union-find.
func findDepClusters(g *DependencyGraph) []AgentCluster {
	if len(g.Dependencies) == 0 {
		return nil
	}

	parent := make(map[string]string)
	ufRank := make(map[string]int)
	for _, a := range g.Agents {
		parent[a] = a
	}

	var find func(string) string
	find = func(x string) string {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(x, y string) {
		rx, ry := find(x), find(y)
		if rx == ry {
			return
		}
		if ufRank[rx] < ufRank[ry] {
			rx, ry = ry, rx
		}
		parent[ry] = rx
		if ufRank[rx] == ufRank[ry] {
			ufRank[rx]++
		}
	}

	for _, d := range g.Dependencies {
		union(d.From, d.To)
	}

	// Group agents by root.
	groups := make(map[string][]string)
	for _, a := range g.Agents {
		root := find(a)
		groups[root] = append(groups[root], a)
	}

	// Collect dependency types per cluster.
	clusterTypeCounts := make(map[string]map[string]int)
	for _, d := range g.Dependencies {
		root := find(d.From)
		if clusterTypeCounts[root] == nil {
			clusterTypeCounts[root] = make(map[string]int)
		}
		clusterTypeCounts[root][d.Type]++
	}

	// Build cluster list for groups with 2+ agents.
	var roots []string
	for r := range groups {
		roots = append(roots, r)
	}
	sort.Strings(roots)

	var clusters []AgentCluster
	id := 0
	for _, root := range roots {
		members := groups[root]
		if len(members) < 2 {
			continue
		}
		sort.Strings(members)
		id++
		clusters = append(clusters, AgentCluster{
			ID:     fmt.Sprintf("cluster-%d", id),
			Agents: members,
			Reason: depClusterReason(clusterTypeCounts[root]),
		})
	}

	return clusters
}

// depClusterReason generates a human-readable reason for a cluster based on
// the dominant dependency type.
func depClusterReason(typeCounts map[string]int) string {
	if len(typeCounts) == 0 {
		return "connected agents"
	}
	maxType := ""
	maxCount := 0
	total := 0
	for t, c := range typeCounts {
		total += c
		if c > maxCount {
			maxCount = c
			maxType = t
		}
	}
	if maxCount*2 > total {
		switch maxType {
		case "shares_tool":
			return "shared tooling"
		case "delegates_to":
			return "delegation chain"
		case "orchestrates":
			return "orchestration group"
		case "trust_chain":
			return "trust relationship"
		case "data_flow":
			return "shared data targets"
		}
	}
	return "multiple dependency types"
}

// classifySPOFRisk determines the risk level and reason for a potential SPOF.
func classifySPOFRisk(a *Agent, neighborCount int) (string, string) {
	name := a.Meta.Name
	if a.Trust.Level == TrustAdmin && neighborCount >= 3 {
		return "critical", fmt.Sprintf(
			"admin agent %s with %d connections is a critical single point of failure",
			name, neighborCount)
	}
	if a.Trust.Level == TrustElevated && neighborCount >= 3 {
		return "high", fmt.Sprintf(
			"elevated-trust agent %s with %d connections", name, neighborCount)
	}
	if a.Meta.Type == TypeOrchestrator {
		return "high", fmt.Sprintf(
			"orchestrator %s managing %d connected agents", name, neighborCount)
	}
	if neighborCount >= 4 {
		return "high", fmt.Sprintf(
			"highly connected agent %s (%d dependencies)", name, neighborCount)
	}
	return "medium", fmt.Sprintf(
		"agent %s connected to %d other agents", name, neighborCount)
}

// hasElevatedTool checks whether an agent has elevated access to a named tool.
func hasElevatedTool(a *Agent, toolName string) bool {
	if a == nil {
		return false
	}
	for _, t := range a.Tools {
		if t.Name == toolName && t.Elevated {
			return true
		}
	}
	return false
}

// findSharedToolNames returns the sorted tool names shared between two agents.
func findSharedToolNames(a, b *Agent) []string {
	aTools := make(map[string]bool)
	for _, t := range a.Tools {
		aTools[t.Name] = true
	}
	var shared []string
	for _, t := range b.Tools {
		if aTools[t.Name] {
			shared = append(shared, t.Name)
		}
	}
	sort.Strings(shared)
	return shared
}

// calcBlastRiskScore computes a risk score (0.0-1.0) for a blast radius.
// The score is based on the fraction of agents affected weighted by the
// maximum trust level among them, with a bonus for escalation paths.
func calcBlastRiskScore(br *BlastRadius, inv *Inventory, agentMap map[string]*Agent) float64 {
	if len(inv.Agents) <= 1 || br.TotalAffected == 0 {
		return 0.0
	}

	base := float64(br.TotalAffected) / float64(len(inv.Agents)-1)

	maxRank := 0
	allAffected := append(append([]string{}, br.DirectImpact...), br.IndirectImpact...)
	for _, name := range allAffected {
		if a, ok := agentMap[name]; ok {
			rank := trustLevelOrder[a.Trust.Level]
			if rank > maxRank {
				maxRank = rank
			}
		}
	}

	trustMul := 0.2
	switch maxRank {
	case 4:
		trustMul = 1.0
	case 3:
		trustMul = 0.8
	case 2:
		trustMul = 0.6
	case 1:
		trustMul = 0.4
	}

	score := base * (0.5 + 0.5*trustMul)
	score += float64(len(br.EscalationPaths)) * 0.1

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// blastSeverity maps a risk score to a severity label.
func blastSeverity(score float64) string {
	switch {
	case score >= 0.7:
		return "critical"
	case score >= 0.4:
		return "high"
	case score >= 0.2:
		return "medium"
	default:
		return "low"
	}
}

// generateDepRecommendations produces actionable recommendations based on the
// dependency analysis.
func generateDepRecommendations(r *DependencyReport, g *DependencyGraph, inv *Inventory) []string {
	var recs []string

	for _, spof := range r.SinglePointFailures {
		if spof.Risk == "critical" {
			recs = append(recs, fmt.Sprintf(
				"Critical SPOF: distribute responsibilities away from %s (%d connections)",
				spof.Agent, spof.DependentOn))
		}
	}
	if len(r.SinglePointFailures) > 0 && len(recs) == 0 {
		recs = append(recs, "Reduce single points of failure by distributing agent responsibilities")
	}

	if len(g.Agents) > 2 && r.MaxBlastRadius > len(g.Agents)/2 {
		recs = append(recs, "Large blast radius detected — isolate high-impact agents with trust boundaries")
	}

	hasEscalation := false
	for _, br := range r.BlastRadii {
		if len(br.EscalationPaths) > 0 {
			hasEscalation = true
			break
		}
	}
	if hasEscalation {
		recs = append(recs, "Trust escalation paths found — add authorization gates between trust levels")
	}

	if len(g.Isolates) > 0 && len(g.Isolates) < len(g.Agents) {
		recs = append(recs, fmt.Sprintf(
			"%d isolated agents — verify intentional isolation or add to dependency graph",
			len(g.Isolates)))
	}

	if r.AvgConnections > 3.0 {
		recs = append(recs, "Dense dependency graph — consider segmenting agents into isolated trust domains")
	}

	return recs
}
