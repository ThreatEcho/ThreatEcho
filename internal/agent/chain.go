// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"fmt"
	"sort"
	"strings"
)

// ChainLink represents one agent in a delegation chain.
type ChainLink struct {
	AgentName   string   `json:"agent_name"`
	AgentType   string   `json:"agent_type"`
	TrustLevel  string   `json:"trust_level"`
	Delegations []string `json:"delegations"` // agents this link delegates to
	Tools       []string `json:"tools"`       // tools available at this link
	Elevated    bool     `json:"elevated"`    // has any elevated tool access
	Boundaries  []string `json:"boundaries"`  // trust boundaries
}

// DelegationChain represents a path through the agent graph.
type DelegationChain struct {
	Links           []ChainLink `json:"links"`
	Length          int         `json:"length"`
	MaxTrust        string      `json:"max_trust"`        // highest trust in chain
	MinTrust        string      `json:"min_trust"`        // lowest trust in chain
	CrossesBoundary bool        `json:"crosses_boundary"` // enters different trust boundaries
}

// ChainViolation records a trust/security issue in a delegation chain.
type ChainViolation struct {
	Type           string   `json:"type"`     // escalation, boundary_cross, confused_deputy, over_delegation, unguarded_chain
	Severity       string   `json:"severity"` // critical, high, medium, low
	Chain          []string `json:"chain"`    // agent names in the problematic chain
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation"`
}

// ChainAnalysis holds the full analysis result.
type ChainAnalysis struct {
	TotalAgents    int               `json:"total_agents"`
	TotalChains    int               `json:"total_chains"`
	MaxChainLength int               `json:"max_chain_length"`
	Chains         []DelegationChain `json:"chains"`
	Violations     []ChainViolation  `json:"violations"`
	CriticalCount  int               `json:"critical_count"`
	HighCount      int               `json:"high_count"`
	MediumCount    int               `json:"medium_count"`
	LowCount       int               `json:"low_count"`
	RiskScore      float64           `json:"risk_score"` // 0-1
	Summary        string            `json:"summary"`
}

// AnalyzeChains is the main entry point for multi-agent delegation chain analysis.
// It builds a delegation map from trust relationships, enumerates all delegation
// chains, detects violations, and calculates a risk score.
func AnalyzeChains(inv *Inventory) *ChainAnalysis {
	if inv == nil || len(inv.Agents) == 0 {
		return &ChainAnalysis{
			Summary: "No agents to analyze.",
		}
	}

	// Index agents by name for quick lookup.
	agentMap := make(map[string]*Agent)
	for _, a := range inv.Agents {
		agentMap[a.Meta.Name] = a
	}

	// Build the delegation adjacency list.
	delegations := buildDelegationMap(inv)

	// Enumerate all delegation chains.
	chains := enumerateChains(delegations, agentMap)

	// Detect violations across all chains.
	violations := detectViolations(chains, agentMap)

	// Calculate risk score from violations.
	riskScore := scoreChainRisk(violations)

	// Count violations by severity.
	var critCount, highCount, medCount, lowCount int
	for _, v := range violations {
		switch v.Severity {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		case "low":
			lowCount++
		}
	}

	// Find max chain length.
	maxLen := 0
	for _, c := range chains {
		if c.Length > maxLen {
			maxLen = c.Length
		}
	}

	analysis := &ChainAnalysis{
		TotalAgents:    len(inv.Agents),
		TotalChains:    len(chains),
		MaxChainLength: maxLen,
		Chains:         chains,
		Violations:     violations,
		CriticalCount:  critCount,
		HighCount:      highCount,
		MediumCount:    medCount,
		LowCount:       lowCount,
		RiskScore:      riskScore,
	}
	analysis.Summary = SummarizeChains(analysis)
	return analysis
}

// buildDelegationMap constructs the delegation adjacency list from trust
// relationships. If agent B lists A in its TrustedBy field, then A can
// delegate to B (A → B). Orchestrators also implicitly delegate to agents
// that trust them (via TrustsFrom).
func buildDelegationMap(inv *Inventory) map[string][]string {
	delegations := make(map[string][]string)

	// Set to deduplicate edges.
	edgeSet := make(map[string]bool)
	addEdge := func(from, to string) {
		key := from + "\x00" + to
		if !edgeSet[key] && from != to {
			edgeSet[key] = true
			delegations[from] = append(delegations[from], to)
		}
	}

	// Index agents by name for type lookups.
	agentMap := make(map[string]*Agent)
	for _, a := range inv.Agents {
		agentMap[a.Meta.Name] = a
	}

	// Primary: TrustedBy relationships define delegation edges.
	// If agent B is trusted by A, then A delegates to B.
	for _, a := range inv.Agents {
		for _, trustedByName := range a.Trust.TrustedBy {
			// trustedByName delegates to a.
			addEdge(trustedByName, a.Meta.Name)
		}
	}

	// Secondary: Orchestrators delegate to agents that trust them (TrustsFrom).
	// If agent B lists orchestrator O in TrustsFrom, O delegates to B.
	for _, a := range inv.Agents {
		for _, trustsFromName := range a.Trust.TrustsFrom {
			if source, ok := agentMap[trustsFromName]; ok {
				if source.Meta.Type == TypeOrchestrator {
					addEdge(trustsFromName, a.Meta.Name)
				}
			}
		}
	}

	// Tertiary: Orchestrators delegate to any agent in their TrustedBy list
	// (those they explicitly trust).
	for _, a := range inv.Agents {
		if a.Meta.Type == TypeOrchestrator {
			for _, trustedByName := range a.Trust.TrustedBy {
				addEdge(a.Meta.Name, trustedByName)
			}
		}
	}

	// Sort targets for deterministic output.
	for k := range delegations {
		sort.Strings(delegations[k])
	}

	return delegations
}

// enumerateChains walks all paths from each agent through the delegation graph,
// building a DelegationChain for each maximal path. Tracks visited nodes to
// avoid cycles.
func enumerateChains(delegations map[string][]string, agents map[string]*Agent) []DelegationChain {
	// Find all agent names that appear in the graph.
	allNames := make(map[string]bool)
	for from, tos := range delegations {
		allNames[from] = true
		for _, to := range tos {
			allNames[to] = true
		}
	}
	// Also include agents that have no delegation edges at all.
	for name := range agents {
		allNames[name] = true
	}

	// Identify root agents: those with no incoming delegation edges.
	hasIncoming := make(map[string]bool)
	for _, tos := range delegations {
		for _, to := range tos {
			hasIncoming[to] = true
		}
	}
	var roots []string
	for name := range allNames {
		if !hasIncoming[name] {
			roots = append(roots, name)
		}
	}
	sort.Strings(roots)

	// If all agents have incoming edges (fully connected cycle), use all as roots.
	if len(roots) == 0 {
		for name := range allNames {
			roots = append(roots, name)
		}
		sort.Strings(roots)
	}

	var chains []DelegationChain

	// DFS from each root to enumerate maximal chains.
	for _, root := range roots {
		visited := make(map[string]bool)
		var path []string
		var dfs func(current string)
		dfs = func(current string) {
			visited[current] = true
			path = append(path, current)

			targets := delegations[current]
			expanded := false
			for _, next := range targets {
				if !visited[next] {
					expanded = true
					dfs(next)
				}
			}

			// If we could not expand further, this is a maximal path — record it.
			if !expanded && len(path) > 0 {
				chain := buildChainFromPath(path, delegations, agents)
				chains = append(chains, chain)
			}

			path = path[:len(path)-1]
			visited[current] = false
		}
		dfs(root)
	}

	// Deduplicate chains that have identical link sequences.
	chains = deduplicateChains(chains)

	return chains
}

// buildChainFromPath constructs a DelegationChain from a sequence of agent names.
func buildChainFromPath(path []string, delegations map[string][]string, agents map[string]*Agent) DelegationChain {
	chain := DelegationChain{
		Length: len(path),
	}

	maxRank := -1
	minRank := 5
	allBoundaries := make(map[string]bool)

	for i, name := range path {
		link := ChainLink{
			AgentName: name,
		}

		if a, ok := agents[name]; ok {
			link.AgentType = a.Meta.Type
			link.TrustLevel = a.Trust.Level
			link.Boundaries = a.Trust.Boundaries

			// Collect tools and check for elevated access.
			for _, t := range a.Tools {
				link.Tools = append(link.Tools, t.Name)
				if t.Elevated {
					link.Elevated = true
				}
			}

			// Track trust extremes.
			rank := trustLevelRank(a.Trust.Level)
			if rank > maxRank {
				maxRank = rank
				chain.MaxTrust = a.Trust.Level
			}
			if rank < minRank {
				minRank = rank
				chain.MinTrust = a.Trust.Level
			}

			// Track boundaries.
			for _, b := range a.Trust.Boundaries {
				allBoundaries[b] = true
			}
		}

		// Determine what this link delegates to (within the chain path).
		if i < len(path)-1 {
			link.Delegations = []string{path[i+1]}
		}

		chain.Links = append(chain.Links, link)
	}

	// A chain crosses boundaries if more than one distinct boundary appears,
	// or if some links have boundaries and others don't.
	hasBounded := false
	hasUnbounded := false
	for _, link := range chain.Links {
		if len(link.Boundaries) > 0 {
			hasBounded = true
		} else {
			hasUnbounded = true
		}
	}
	if len(allBoundaries) > 1 || (hasBounded && hasUnbounded) {
		chain.CrossesBoundary = true
	}

	// Handle case where no agents were found in the agents map.
	if maxRank == -1 {
		chain.MaxTrust = ""
		chain.MinTrust = ""
	}

	return chain
}

// detectViolations analyzes delegation chains for trust and security issues.
func detectViolations(chains []DelegationChain, agents map[string]*Agent) []ChainViolation {
	var violations []ChainViolation

	// Track unique violations to avoid duplicates.
	seen := make(map[string]bool)
	addViolation := func(v ChainViolation) {
		key := v.Type + "|" + strings.Join(v.Chain, ",")
		if !seen[key] {
			seen[key] = true
			violations = append(violations, v)
		}
	}

	for _, chain := range chains {
		chainNames := make([]string, len(chain.Links))
		for i, l := range chain.Links {
			chainNames[i] = l.AgentName
		}

		// Check for trust escalation: a lower-trust link delegates to a higher-trust link.
		for i := 0; i < len(chain.Links)-1; i++ {
			fromLink := chain.Links[i]
			toLink := chain.Links[i+1]

			fromRank := trustLevelRank(fromLink.TrustLevel)
			toRank := trustLevelRank(toLink.TrustLevel)

			if fromRank < toRank {
				severity := "high"
				if fromRank <= 1 && toRank >= 3 {
					// Low/untrusted delegating to elevated/admin is critical.
					severity = "critical"
				}
				addViolation(ChainViolation{
					Type:     "escalation",
					Severity: severity,
					Chain:    []string{fromLink.AgentName, toLink.AgentName},
					Description: fmt.Sprintf(
						"Trust escalation: %s (%s) delegates to %s (%s)",
						fromLink.AgentName, fromLink.TrustLevel,
						toLink.AgentName, toLink.TrustLevel,
					),
					Recommendation: fmt.Sprintf(
						"Add explicit escalation authorization between %s and %s, or lower %s trust level",
						fromLink.AgentName, toLink.AgentName, toLink.AgentName,
					),
				})
			}
		}

		// Check for boundary crossing.
		if chain.CrossesBoundary {
			// Find the specific crossing points.
			for i := 0; i < len(chain.Links)-1; i++ {
				fromBounds := chain.Links[i].Boundaries
				toBounds := chain.Links[i+1].Boundaries
				if boundariesDiffer(fromBounds, toBounds) {
					addViolation(ChainViolation{
						Type:     "boundary_cross",
						Severity: "medium",
						Chain:    []string{chain.Links[i].AgentName, chain.Links[i+1].AgentName},
						Description: fmt.Sprintf(
							"Delegation crosses trust boundary: %s [%s] -> %s [%s]",
							chain.Links[i].AgentName, strings.Join(fromBounds, ","),
							chain.Links[i+1].AgentName, strings.Join(toBounds, ","),
						),
						Recommendation: fmt.Sprintf(
							"Add a boundary gateway between %s and %s, or unify their trust boundaries",
							chain.Links[i].AgentName, chain.Links[i+1].AgentName,
						),
					})
				}
			}
		}

		// Check for confused deputy: an agent with elevated tool access is
		// reachable from an untrusted or low-trust agent through the chain.
		detectConfusedDeputy(chain, agents, addViolation)

		// Check for over-delegation: chain length > 3.
		if chain.Length > 3 {
			addViolation(ChainViolation{
				Type:     "over_delegation",
				Severity: "medium",
				Chain:    chainNames,
				Description: fmt.Sprintf(
					"Deep delegation chain (%d links): %s — increased attack surface",
					chain.Length, strings.Join(chainNames, " -> "),
				),
				Recommendation: "Reduce chain depth by consolidating agent responsibilities or introducing direct delegation",
			})
		}

		// Check for unguarded chain links: agents with no guardrails in the chain.
		for _, link := range chain.Links {
			if a, ok := agents[link.AgentName]; ok {
				if len(a.Guardrails) == 0 && chain.Length > 1 {
					severity := "low"
					if link.Elevated {
						severity = "high"
					} else if trustLevelRank(link.TrustLevel) >= trustLevelRank(TrustElevated) {
						severity = "medium"
					}
					addViolation(ChainViolation{
						Type:     "unguarded_chain",
						Severity: severity,
						Chain:    []string{link.AgentName},
						Description: fmt.Sprintf(
							"Agent %s in delegation chain has no guardrails",
							link.AgentName,
						),
						Recommendation: fmt.Sprintf(
							"Add input/output/tool-call guardrails to %s",
							link.AgentName,
						),
					})
				}
			}
		}
	}

	// Sort violations: critical first, then high, medium, low.
	sort.SliceStable(violations, func(i, j int) bool {
		return severityRank(violations[i].Severity) > severityRank(violations[j].Severity)
	})

	return violations
}

// detectConfusedDeputy checks whether an elevated-tool agent is reachable from
// an untrusted or low-trust agent through the chain.
func detectConfusedDeputy(chain DelegationChain, agents map[string]*Agent, addViolation func(ChainViolation)) {
	// Find all low/untrusted entry points.
	for i, link := range chain.Links {
		entryRank := trustLevelRank(link.TrustLevel)
		if entryRank > trustLevelRank(TrustLow) {
			continue // not an untrusted/low entry point
		}

		// Scan forward for elevated-tool agents.
		for j := i + 1; j < len(chain.Links); j++ {
			target := chain.Links[j]
			if target.Elevated {
				// Build the sub-chain from entry to target.
				subChain := make([]string, j-i+1)
				for k := i; k <= j; k++ {
					subChain[k-i] = chain.Links[k].AgentName
				}
				addViolation(ChainViolation{
					Type:     "confused_deputy",
					Severity: "critical",
					Chain:    subChain,
					Description: fmt.Sprintf(
						"Confused deputy: %s (%s trust) can reach elevated-tool agent %s through chain %s",
						link.AgentName, link.TrustLevel,
						target.AgentName, strings.Join(subChain, " -> "),
					),
					Recommendation: fmt.Sprintf(
						"Break the delegation path between %s and %s, or remove elevated tool access from %s",
						link.AgentName, target.AgentName, target.AgentName,
					),
				})
			}
		}
	}
}

// boundariesDiffer returns true if two boundary sets are not equal.
// An empty set and a non-empty set are considered different.
func boundariesDiffer(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return false
	}
	if len(a) != len(b) {
		return true
	}
	setA := make(map[string]bool, len(a))
	for _, v := range a {
		setA[v] = true
	}
	for _, v := range b {
		if !setA[v] {
			return true
		}
	}
	return false
}

// deduplicateChains removes chains with identical agent name sequences.
func deduplicateChains(chains []DelegationChain) []DelegationChain {
	seen := make(map[string]bool)
	var result []DelegationChain
	for _, c := range chains {
		names := make([]string, len(c.Links))
		for i, l := range c.Links {
			names[i] = l.AgentName
		}
		key := strings.Join(names, "|")
		if !seen[key] {
			seen[key] = true
			result = append(result, c)
		}
	}
	return result
}

// trustLevelRank returns a numeric rank for a trust level string.
// Unknown levels return 0.
func trustLevelRank(level string) int {
	if rank, ok := trustLevelOrder[level]; ok {
		return rank
	}
	return 0
}

// scoreChainRisk computes a risk score from 0.0 to 1.0 based on violations.
// Each violation adds to the score: critical=0.30, high=0.18, medium=0.08,
// low=0.03. The result is capped at 1.0.
func scoreChainRisk(violations []ChainViolation) float64 {
	score := 0.0
	for _, v := range violations {
		switch v.Severity {
		case "critical":
			score += 0.30
		case "high":
			score += 0.18
		case "medium":
			score += 0.08
		case "low":
			score += 0.03
		}
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// FormatChainAnalysis renders the chain analysis as a box-drawing report.
func FormatChainAnalysis(a *ChainAnalysis) string {
	if a == nil {
		return "No chain analysis.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│          DELEGATION CHAIN ANALYSIS              │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Total Agents:     %-30d │\n", a.TotalAgents)
	fmt.Fprintf(&sb, "│ Total Chains:     %-30d │\n", a.TotalChains)
	fmt.Fprintf(&sb, "│ Max Chain Length:  %-30d │\n", a.MaxChainLength)
	fmt.Fprintf(&sb, "│ Risk Score:       %-30s │\n", fmt.Sprintf("%.2f", a.RiskScore))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Violation summary.
	sb.WriteString("│ Violations                                      │\n")
	fmt.Fprintf(&sb, "│   Critical: %-36d │\n", a.CriticalCount)
	fmt.Fprintf(&sb, "│   High:     %-36d │\n", a.HighCount)
	fmt.Fprintf(&sb, "│   Medium:   %-36d │\n", a.MediumCount)
	fmt.Fprintf(&sb, "│   Low:      %-36d │\n", a.LowCount)
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// List each chain.
	if len(a.Chains) > 0 {
		sb.WriteString("│ Chains                                          │\n")
		for i, c := range a.Chains {
			names := make([]string, len(c.Links))
			for j, l := range c.Links {
				names[j] = l.AgentName
			}
			chainStr := strings.Join(names, " -> ")
			marker := " "
			if c.CrossesBoundary {
				marker = "!"
			}
			fmt.Fprintf(&sb, "│ %s %d. %-44s │\n",
				marker, i+1, truncate(chainStr, 44))
			fmt.Fprintf(&sb, "│     trust: %-14s -> %-22s │\n",
				truncate(c.MinTrust, 14),
				truncate(c.MaxTrust, 22))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// List violations with details.
	if len(a.Violations) > 0 {
		sb.WriteString("│ Violation Details                               │\n")
		for _, v := range a.Violations {
			icon := gapIcon(v.Severity)
			fmt.Fprintf(&sb, "│ %s [%-8s] %-35s │\n",
				icon,
				truncate(v.Severity, 8),
				truncate(v.Type, 35))
			// Wrap description across lines if needed.
			descLines := wrapText(v.Description, 45)
			for _, line := range descLines {
				fmt.Fprintf(&sb, "│     %-44s │\n", line)
			}
		}
	}

	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ %-48s │\n", truncate(a.Summary, 48))
	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// SummarizeChains returns a one-line summary of the chain analysis.
func SummarizeChains(a *ChainAnalysis) string {
	if a == nil {
		return "No analysis available."
	}
	if a.TotalChains == 0 {
		return fmt.Sprintf("%d agents, no delegation chains found.", a.TotalAgents)
	}

	totalViolations := a.CriticalCount + a.HighCount + a.MediumCount + a.LowCount
	if totalViolations == 0 {
		return fmt.Sprintf("%d chains across %d agents — no violations detected (risk: %.2f).",
			a.TotalChains, a.TotalAgents, a.RiskScore)
	}

	return fmt.Sprintf(
		"%d chains, %d violations (%d critical, %d high) across %d agents — risk score %.2f.",
		a.TotalChains, totalViolations,
		a.CriticalCount, a.HighCount,
		a.TotalAgents, a.RiskScore,
	)
}

// wrapText splits a string into lines of at most maxWidth characters,
// breaking at word boundaries.
func wrapText(s string, maxWidth int) []string {
	if len(s) <= maxWidth {
		return []string{s}
	}

	words := strings.Fields(s)
	var lines []string
	var current strings.Builder

	for _, w := range words {
		if current.Len() == 0 {
			current.WriteString(w)
		} else if current.Len()+1+len(w) <= maxWidth {
			current.WriteByte(' ')
			current.WriteString(w)
		} else {
			lines = append(lines, current.String())
			current.Reset()
			current.WriteString(w)
		}
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}

	return lines
}
