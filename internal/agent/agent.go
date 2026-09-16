// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Trust level constants define the privilege tiers for agents.
const (
	// TrustUntrusted indicates an agent with no established trust.
	TrustUntrusted = "untrusted"
	// TrustLow indicates an agent with minimal, restricted trust.
	TrustLow = "low"
	// TrustStandard indicates an agent with normal operational trust.
	TrustStandard = "standard"
	// TrustElevated indicates an agent with heightened privileges.
	TrustElevated = "elevated"
	// TrustAdmin indicates an agent with full administrative privileges.
	TrustAdmin = "admin"
)

// Agent type constants define the operational categories.
const (
	// TypeRetrieval identifies agents focused on data retrieval and RAG operations.
	TypeRetrieval = "retrieval"
	// TypeConversational identifies agents that conduct natural language conversations.
	TypeConversational = "conversational"
	// TypeToolCalling identifies agents that invoke external tools and APIs.
	TypeToolCalling = "tool-calling"
	// TypeOrchestrator identifies agents that coordinate and delegate to other agents.
	TypeOrchestrator = "orchestrator"
	// TypeAutonomous identifies agents that operate independently without human oversight.
	TypeAutonomous = "autonomous"
)

// validTrustLevels enumerates all recognized trust levels.
var validTrustLevels = map[string]bool{
	TrustUntrusted: true,
	TrustLow:       true,
	TrustStandard:  true,
	TrustElevated:  true,
	TrustAdmin:     true,
}

// trustLevelOrder maps trust levels to a numeric rank for comparisons.
var trustLevelOrder = map[string]int{
	TrustUntrusted: 0,
	TrustLow:       1,
	TrustStandard:  2,
	TrustElevated:  3,
	TrustAdmin:     4,
}

// validAgentTypes enumerates all recognized agent types.
var validAgentTypes = map[string]bool{
	TypeRetrieval:      true,
	TypeConversational: true,
	TypeToolCalling:    true,
	TypeOrchestrator:   true,
	TypeAutonomous:     true,
}

// Agent is the top-level declaration for an AI agent in the inventory.
type Agent struct {
	APIVersion   string            `yaml:"api_version" json:"api_version"`
	Kind         string            `yaml:"kind"        json:"kind"`
	Meta         AgentMeta         `yaml:"meta"        json:"meta"`
	Capabilities AgentCapabilities `yaml:"capabilities" json:"capabilities"`
	Tools        []ToolAccess      `yaml:"tools,omitempty" json:"tools,omitempty"`
	Trust        TrustConfig       `yaml:"trust"       json:"trust"`
	Guardrails   []Guardrail       `yaml:"guardrails,omitempty" json:"guardrails,omitempty"`
}

// AgentMeta holds agent metadata and classification.
type AgentMeta struct {
	Name        string   `yaml:"name"        json:"name"`
	Type        string   `yaml:"type"        json:"type"`
	Description string   `yaml:"description" json:"description"`
	Model       string   `yaml:"model"       json:"model"`
	Version     string   `yaml:"version"     json:"version"`
	Owner       string   `yaml:"owner"       json:"owner"`
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// AgentCapabilities declares what an agent can do.
type AgentCapabilities struct {
	ToolCalling    bool `yaml:"tool_calling"    json:"tool_calling"`
	RAG            bool `yaml:"rag"             json:"rag"`
	CodeExecution  bool `yaml:"code_execution"  json:"code_execution"`
	WebAccess      bool `yaml:"web_access"      json:"web_access"`
	FileAccess     bool `yaml:"file_access"     json:"file_access"`
	MessagePassing bool `yaml:"message_passing" json:"message_passing"`
	Memory         bool `yaml:"memory"          json:"memory"`
	Autonomous     bool `yaml:"autonomous"      json:"autonomous"`
}

// ToolAccess declares an agent's access to a specific tool.
type ToolAccess struct {
	Name      string   `yaml:"name"                json:"name"`
	Actions   []string `yaml:"actions,omitempty"    json:"actions,omitempty"`
	Targets   []string `yaml:"targets,omitempty"    json:"targets,omitempty"`
	Elevated  bool     `yaml:"elevated,omitempty"   json:"elevated,omitempty"`
	RateLimit int      `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
}

// TrustConfig defines the trust posture for an agent.
type TrustConfig struct {
	Level       string   `yaml:"level"                  json:"level"`
	TrustsFrom  []string `yaml:"trusts_from,omitempty"  json:"trusts_from,omitempty"`
	TrustedBy   []string `yaml:"trusted_by,omitempty"   json:"trusted_by,omitempty"`
	Boundaries  []string `yaml:"boundaries,omitempty"   json:"boundaries,omitempty"`
	CanEscalate bool     `yaml:"can_escalate,omitempty" json:"can_escalate,omitempty"`
}

// Guardrail defines a safety guardrail applied to an agent.
type Guardrail struct {
	Name     string `yaml:"name"     json:"name"`
	Type     string `yaml:"type"     json:"type"`
	Enforced bool   `yaml:"enforced" json:"enforced"`
}

// Inventory is a collection of agents loaded from disk.
type Inventory struct {
	Agents []*Agent
}

// TrustEdge represents a directed trust relationship between two agents.
type TrustEdge struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Direction string `json:"direction"`
}

// TrustAnalysis is the result of analyzing trust relationships across an inventory.
type TrustAnalysis struct {
	TotalAgents       int                 `json:"total_agents"`
	TrustEdges        []TrustEdge         `json:"trust_edges"`
	AdminAgents       []string            `json:"admin_agents"`
	UntrustedAgents   []string            `json:"untrusted_agents"`
	EscalationPaths   [][]string          `json:"escalation_paths"`
	TrustBoundaries   map[string][]string `json:"trust_boundaries"`
	OverTrustedAgents []string            `json:"over_trusted_agents"`
	Risks             []TrustRisk         `json:"risks"`
}

// TrustRisk represents a security risk identified in the trust graph.
type TrustRisk struct {
	AgentName   string `json:"agent_name"`
	Risk        string `json:"risk"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// validGuardrailTypes enumerates recognized guardrail types.
var validGuardrailTypes = map[string]bool{
	"input":          true,
	"output":         true,
	"tool-call":      true,
	"content-filter": true,
}

// LoadAgent reads and parses an agent definition from a YAML file or directory.
// If path is a directory, it looks for agent.yaml inside it.
func LoadAgent(path string) (*Agent, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("agent path %q: %w", path, err)
	}
	if info.IsDir() {
		path = filepath.Join(path, "agent.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading agent: %w", err)
	}

	var a Agent
	if err := yaml.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parsing agent YAML: %w", err)
	}

	return &a, nil
}

// LoadInventory scans a directory tree for agent.yaml files and loads all agents
// into an Inventory.
func LoadInventory(dir string) (*Inventory, error) {
	inv := &Inventory{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if info.Name() == "agent.yaml" {
			a, loadErr := LoadAgent(path)
			if loadErr != nil {
				return fmt.Errorf("loading %s: %w", path, loadErr)
			}
			inv.Agents = append(inv.Agents, a)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanning inventory directory: %w", err)
	}

	return inv, nil
}

// ValidateAgent checks an agent definition for correctness and returns a list
// of validation errors. An empty slice means the agent is valid.
func ValidateAgent(a *Agent) []string {
	var errs []string

	if a.Meta.Name == "" {
		errs = append(errs, "meta.name is required")
	}
	if a.Kind == "" {
		errs = append(errs, "kind is required")
	} else if a.Kind != "Agent" {
		errs = append(errs, fmt.Sprintf("kind must be \"Agent\", got %q", a.Kind))
	}
	if a.APIVersion == "" {
		errs = append(errs, "api_version is required")
	}
	if a.Meta.Type == "" {
		errs = append(errs, "meta.type is required")
	} else if !validAgentTypes[a.Meta.Type] {
		errs = append(errs, fmt.Sprintf("invalid agent type %q", a.Meta.Type))
	}
	if a.Trust.Level == "" {
		errs = append(errs, "trust.level is required")
	} else if !validTrustLevels[a.Trust.Level] {
		errs = append(errs, fmt.Sprintf("invalid trust level %q", a.Trust.Level))
	}

	// Validate guardrails.
	for i, g := range a.Guardrails {
		if g.Name == "" {
			errs = append(errs, fmt.Sprintf("guardrails[%d].name is required", i))
		}
		if g.Type == "" {
			errs = append(errs, fmt.Sprintf("guardrails[%d].type is required", i))
		} else if !validGuardrailTypes[g.Type] {
			errs = append(errs, fmt.Sprintf("guardrails[%d]: invalid type %q", i, g.Type))
		}
	}

	// Validate tools.
	for i, t := range a.Tools {
		if t.Name == "" {
			errs = append(errs, fmt.Sprintf("tools[%d].name is required", i))
		}
		if t.RateLimit < 0 {
			errs = append(errs, fmt.Sprintf("tools[%d].rate_limit must be non-negative", i))
		}
	}

	// Warn about capability/guardrail mismatch.
	if a.Capabilities.ToolCalling && len(a.Guardrails) == 0 {
		errs = append(errs, "agent has tool_calling capability but no guardrails defined")
	}

	// Autonomous agents should have elevated or admin trust to be valid.
	if a.Meta.Type == TypeAutonomous && a.Trust.Level != TrustElevated && a.Trust.Level != TrustAdmin {
		errs = append(errs, "autonomous agents should have elevated or admin trust level")
	}

	return errs
}

// FindAgent returns the first agent with the given name, or nil if not found.
func (inv *Inventory) FindAgent(name string) *Agent {
	for _, a := range inv.Agents {
		if a.Meta.Name == name {
			return a
		}
	}
	return nil
}

// AgentsByType returns all agents matching the given type.
func (inv *Inventory) AgentsByType(agentType string) []*Agent {
	var result []*Agent
	for _, a := range inv.Agents {
		if a.Meta.Type == agentType {
			result = append(result, a)
		}
	}
	return result
}

// AgentsByTrust returns all agents at the given trust level.
func (inv *Inventory) AgentsByTrust(level string) []*Agent {
	var result []*Agent
	for _, a := range inv.Agents {
		if a.Trust.Level == level {
			result = append(result, a)
		}
	}
	return result
}

// ToolMatrix returns a map from tool name to the list of agent names that use it.
func (inv *Inventory) ToolMatrix() map[string][]string {
	matrix := make(map[string][]string)
	for _, a := range inv.Agents {
		for _, t := range a.Tools {
			matrix[t.Name] = append(matrix[t.Name], a.Meta.Name)
		}
	}
	return matrix
}

// AnalyzeTrust performs a comprehensive trust graph analysis across the inventory.
// It identifies trust edges, escalation paths, over-trusted agents, boundary gaps,
// and missing guardrails.
func (inv *Inventory) AnalyzeTrust() *TrustAnalysis {
	ta := &TrustAnalysis{
		TotalAgents:     len(inv.Agents),
		TrustBoundaries: make(map[string][]string),
	}

	// Index agents by name.
	agentMap := make(map[string]*Agent)
	for _, a := range inv.Agents {
		agentMap[a.Meta.Name] = a
	}

	// Collect admin and untrusted agents.
	for _, a := range inv.Agents {
		switch a.Trust.Level {
		case TrustAdmin:
			ta.AdminAgents = append(ta.AdminAgents, a.Meta.Name)
		case TrustUntrusted:
			ta.UntrustedAgents = append(ta.UntrustedAgents, a.Meta.Name)
		}
	}

	// Build trust edges from TrustsFrom and TrustedBy.
	edgeSet := make(map[string]bool)
	for _, a := range inv.Agents {
		for _, from := range a.Trust.TrustsFrom {
			key := from + "->" + a.Meta.Name
			if !edgeSet[key] {
				ta.TrustEdges = append(ta.TrustEdges, TrustEdge{
					From:      from,
					To:        a.Meta.Name,
					Direction: "trusts_from",
				})
				edgeSet[key] = true
			}
		}
		for _, by := range a.Trust.TrustedBy {
			key := a.Meta.Name + "->" + by
			if !edgeSet[key] {
				ta.TrustEdges = append(ta.TrustEdges, TrustEdge{
					From:      a.Meta.Name,
					To:        by,
					Direction: "trusted_by",
				})
				edgeSet[key] = true
			}
		}
	}

	// Build trust boundaries.
	for _, a := range inv.Agents {
		for _, b := range a.Trust.Boundaries {
			ta.TrustBoundaries[b] = append(ta.TrustBoundaries[b], a.Meta.Name)
		}
	}

	// Count how many agents trust each agent (inbound trust count).
	trustedByCount := make(map[string]int)
	for _, edge := range ta.TrustEdges {
		trustedByCount[edge.To]++
	}

	// Detect over-trusted agents: trusted by 3+ others AND having
	// code_execution or file_access capabilities.
	for _, a := range inv.Agents {
		if trustedByCount[a.Meta.Name] >= 3 {
			if a.Capabilities.CodeExecution || a.Capabilities.FileAccess {
				ta.OverTrustedAgents = append(ta.OverTrustedAgents, a.Meta.Name)
			}
		}
	}

	// Detect escalation paths: chains where trust flows from a lower
	// trust level to a higher trust level.
	ta.EscalationPaths = findEscalationPaths(inv.Agents, ta.TrustEdges, agentMap)

	// Identify risks.
	ta.Risks = identifyRisks(inv.Agents, ta, agentMap)

	return ta
}

// findEscalationPaths returns all chains from lower-trust agents to higher-trust agents.
func findEscalationPaths(agents []*Agent, edges []TrustEdge, agentMap map[string]*Agent) [][]string {
	// Build adjacency list: from -> []to (trust flows).
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}

	var paths [][]string

	// For each agent, try to find paths to agents with higher trust.
	for _, a := range agents {
		startLevel := trustLevelOrder[a.Trust.Level]
		visited := make(map[string]bool)
		var dfs func(current string, path []string)
		dfs = func(current string, path []string) {
			if visited[current] {
				return
			}
			visited[current] = true
			path = append(path, current)

			if target, ok := agentMap[current]; ok {
				targetLevel := trustLevelOrder[target.Trust.Level]
				if targetLevel > startLevel && len(path) > 1 {
					// Found an escalation path.
					esc := make([]string, len(path))
					copy(esc, path)
					paths = append(paths, esc)
				}
			}

			for _, next := range adj[current] {
				dfs(next, path)
			}
			visited[current] = false
		}
		dfs(a.Meta.Name, nil)
	}

	return paths
}

// identifyRisks examines agents for common security risks.
func identifyRisks(agents []*Agent, ta *TrustAnalysis, agentMap map[string]*Agent) []TrustRisk {
	var risks []TrustRisk

	for _, a := range agents {
		// Missing guardrails on tool-calling agents.
		if a.Capabilities.ToolCalling && len(a.Guardrails) == 0 {
			risks = append(risks, TrustRisk{
				AgentName:   a.Meta.Name,
				Risk:        "missing_guardrails",
				Severity:    "high",
				Description: fmt.Sprintf("Agent %q has tool_calling capability but no guardrails", a.Meta.Name),
			})
		}

		// Autonomous agent without elevated trust.
		if a.Meta.Type == TypeAutonomous && trustLevelOrder[a.Trust.Level] < trustLevelOrder[TrustElevated] {
			risks = append(risks, TrustRisk{
				AgentName:   a.Meta.Name,
				Risk:        "low_trust_autonomous",
				Severity:    "critical",
				Description: fmt.Sprintf("Autonomous agent %q has trust level %q (should be elevated or admin)", a.Meta.Name, a.Trust.Level),
			})
		}

		// Admin agent with code execution and no guardrails.
		if a.Trust.Level == TrustAdmin && a.Capabilities.CodeExecution && len(a.Guardrails) == 0 {
			risks = append(risks, TrustRisk{
				AgentName:   a.Meta.Name,
				Risk:        "unguarded_admin",
				Severity:    "critical",
				Description: fmt.Sprintf("Admin agent %q has code_execution but no guardrails", a.Meta.Name),
			})
		}

		// Boundary gap: agent trusts another agent outside its boundary.
		if len(a.Trust.Boundaries) > 0 {
			boundarySet := make(map[string]bool)
			for _, b := range a.Trust.Boundaries {
				boundarySet[b] = true
			}
			for _, from := range a.Trust.TrustsFrom {
				if target, ok := agentMap[from]; ok {
					inBoundary := false
					for _, tb := range target.Trust.Boundaries {
						if boundarySet[tb] {
							inBoundary = true
							break
						}
					}
					if !inBoundary {
						risks = append(risks, TrustRisk{
							AgentName:   a.Meta.Name,
							Risk:        "boundary_gap",
							Severity:    "medium",
							Description: fmt.Sprintf("Agent %q trusts %q which is outside its trust boundary", a.Meta.Name, from),
						})
					}
				}
			}
		}

		// Elevated tool access without elevated trust.
		for _, t := range a.Tools {
			if t.Elevated && trustLevelOrder[a.Trust.Level] < trustLevelOrder[TrustElevated] {
				risks = append(risks, TrustRisk{
					AgentName:   a.Meta.Name,
					Risk:        "elevated_tool_low_trust",
					Severity:    "high",
					Description: fmt.Sprintf("Agent %q uses elevated tool %q but has trust level %q", a.Meta.Name, t.Name, a.Trust.Level),
				})
			}
		}
	}

	return risks
}

// FormatInventory renders an inventory as a box-drawing report.
func FormatInventory(inv *Inventory) string {
	if len(inv.Agents) == 0 {
		return "No agents in inventory.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│              AGENT INVENTORY                    │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Total Agents: %-34d │\n", len(inv.Agents))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Count by type.
	typeCounts := make(map[string]int)
	for _, a := range inv.Agents {
		typeCounts[a.Meta.Type]++
	}
	sb.WriteString("│ By Type                                         │\n")
	for _, t := range sortedMapKeys(typeCounts) {
		fmt.Fprintf(&sb, "│   %-16s %30d │\n", t, typeCounts[t])
	}
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Count by trust level.
	trustCounts := make(map[string]int)
	for _, a := range inv.Agents {
		trustCounts[a.Trust.Level]++
	}
	sb.WriteString("│ By Trust Level                                  │\n")
	for _, lvl := range []string{TrustAdmin, TrustElevated, TrustStandard, TrustLow, TrustUntrusted} {
		if c, ok := trustCounts[lvl]; ok {
			fmt.Fprintf(&sb, "│   %-16s %30d │\n", lvl, c)
		}
	}
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// List agents.
	sb.WriteString("│ Agents                                          │\n")
	for _, a := range inv.Agents {
		fmt.Fprintf(&sb, "│  %-20s %-12s %-13s │\n",
			truncate(a.Meta.Name, 20),
			truncate(a.Meta.Type, 12),
			truncate(a.Trust.Level, 13))
	}
	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// FormatTrustAnalysis renders a trust analysis as a box-drawing report.
func FormatTrustAnalysis(ta *TrustAnalysis) string {
	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│             TRUST ANALYSIS                      │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Total Agents: %-34d │\n", ta.TotalAgents)
	fmt.Fprintf(&sb, "│ Trust Edges:  %-34d │\n", len(ta.TrustEdges))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Admin agents.
	if len(ta.AdminAgents) > 0 {
		sb.WriteString("│ Admin Agents                                    │\n")
		for _, name := range ta.AdminAgents {
			fmt.Fprintf(&sb, "│   %-46s │\n", truncate(name, 46))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Untrusted agents.
	if len(ta.UntrustedAgents) > 0 {
		sb.WriteString("│ Untrusted Agents                                │\n")
		for _, name := range ta.UntrustedAgents {
			fmt.Fprintf(&sb, "│   %-46s │\n", truncate(name, 46))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Over-trusted agents.
	if len(ta.OverTrustedAgents) > 0 {
		sb.WriteString("│ Over-Trusted Agents                             │\n")
		for _, name := range ta.OverTrustedAgents {
			fmt.Fprintf(&sb, "│   %-46s │\n", truncate(name, 46))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Escalation paths.
	if len(ta.EscalationPaths) > 0 {
		sb.WriteString("│ Escalation Paths                                │\n")
		for _, path := range ta.EscalationPaths {
			chain := strings.Join(path, " -> ")
			fmt.Fprintf(&sb, "│   %-46s │\n", truncate(chain, 46))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Trust boundaries.
	if len(ta.TrustBoundaries) > 0 {
		sb.WriteString("│ Trust Boundaries                                │\n")
		for _, bName := range sortedMapKeysStr(ta.TrustBoundaries) {
			agents := ta.TrustBoundaries[bName]
			fmt.Fprintf(&sb, "│   %-20s %26s │\n",
				truncate(bName, 20),
				truncate(strings.Join(agents, ", "), 26))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Risks.
	if len(ta.Risks) > 0 {
		sb.WriteString("│ Risks                                           │\n")
		for _, r := range ta.Risks {
			fmt.Fprintf(&sb, "│  [%-8s] %-36s │\n",
				truncate(r.Severity, 8),
				truncate(r.Risk+": "+r.AgentName, 36))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// FormatAgent renders a detailed view of a single agent.
func FormatAgent(a *Agent) string {
	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│                AGENT DETAIL                     │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Name:        %-35s │\n", truncate(a.Meta.Name, 35))
	fmt.Fprintf(&sb, "│ Type:        %-35s │\n", truncate(a.Meta.Type, 35))
	fmt.Fprintf(&sb, "│ Model:       %-35s │\n", truncate(a.Meta.Model, 35))
	fmt.Fprintf(&sb, "│ Version:     %-35s │\n", truncate(a.Meta.Version, 35))
	fmt.Fprintf(&sb, "│ Owner:       %-35s │\n", truncate(a.Meta.Owner, 35))
	fmt.Fprintf(&sb, "│ Trust Level: %-35s │\n", truncate(a.Trust.Level, 35))
	if a.Meta.Description != "" {
		fmt.Fprintf(&sb, "│ Description: %-35s │\n", truncate(a.Meta.Description, 35))
	}
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Capabilities.
	sb.WriteString("│ Capabilities                                    │\n")
	caps := []struct {
		name    string
		enabled bool
	}{
		{"tool_calling", a.Capabilities.ToolCalling},
		{"rag", a.Capabilities.RAG},
		{"code_execution", a.Capabilities.CodeExecution},
		{"web_access", a.Capabilities.WebAccess},
		{"file_access", a.Capabilities.FileAccess},
		{"message_passing", a.Capabilities.MessagePassing},
		{"memory", a.Capabilities.Memory},
		{"autonomous", a.Capabilities.Autonomous},
	}
	for _, c := range caps {
		marker := "  "
		if c.enabled {
			marker = "* "
		}
		fmt.Fprintf(&sb, "│   %s%-45s │\n", marker, c.name)
	}
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Tools.
	if len(a.Tools) > 0 {
		sb.WriteString("│ Tools                                           │\n")
		for _, t := range a.Tools {
			elev := ""
			if t.Elevated {
				elev = " [ELEVATED]"
			}
			fmt.Fprintf(&sb, "│   %-46s │\n", truncate(t.Name+elev, 46))
			if len(t.Actions) > 0 {
				fmt.Fprintf(&sb, "│     actions: %-34s │\n", truncate(strings.Join(t.Actions, ", "), 34))
			}
			if len(t.Targets) > 0 {
				fmt.Fprintf(&sb, "│     targets: %-34s │\n", truncate(strings.Join(t.Targets, ", "), 34))
			}
			if t.RateLimit > 0 {
				fmt.Fprintf(&sb, "│     rate_limit: %-31d │\n", t.RateLimit)
			}
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Trust.
	sb.WriteString("│ Trust                                           │\n")
	if len(a.Trust.TrustsFrom) > 0 {
		fmt.Fprintf(&sb, "│   trusts_from: %-33s │\n",
			truncate(strings.Join(a.Trust.TrustsFrom, ", "), 33))
	}
	if len(a.Trust.TrustedBy) > 0 {
		fmt.Fprintf(&sb, "│   trusted_by:  %-33s │\n",
			truncate(strings.Join(a.Trust.TrustedBy, ", "), 33))
	}
	if len(a.Trust.Boundaries) > 0 {
		fmt.Fprintf(&sb, "│   boundaries:  %-33s │\n",
			truncate(strings.Join(a.Trust.Boundaries, ", "), 33))
	}
	escalate := "no"
	if a.Trust.CanEscalate {
		escalate = "yes"
	}
	fmt.Fprintf(&sb, "│   can_escalate: %-32s │\n", escalate)
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Guardrails.
	if len(a.Guardrails) > 0 {
		sb.WriteString("│ Guardrails                                      │\n")
		for _, g := range a.Guardrails {
			enforced := "unenforced"
			if g.Enforced {
				enforced = "enforced"
			}
			fmt.Fprintf(&sb, "│   %-20s %-12s %-12s │\n",
				truncate(g.Name, 20),
				truncate(g.Type, 12),
				enforced)
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// truncate shortens a string to maxLen characters, appending ".." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 2 {
		return s[:maxLen]
	}
	return s[:maxLen-2] + ".."
}

// sortedMapKeys returns sorted keys from a map[string]int.
func sortedMapKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedMapKeysStr returns sorted keys from a map[string][]string.
func sortedMapKeysStr(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
