// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"strings"
)

// GraphAnalysis holds comprehensive analysis of a campaign's dependency graph.
type GraphAnalysis struct {
	StageCount      int
	EdgeCount       int
	EntryPoints     []string         // stages with no depends_on (roots)
	TerminalStages  []string         // stages that nothing depends on (leaves)
	Unreachable     []string         // stages not reachable from any entry point via on_success/on_failure transitions
	OrphanDeps      []string         // stages referenced in depends_on but not defined
	DeadTransitions []DeadTransition // on_success/on_failure targets that don't exist
	MaxDepth        int              // longest path from any entry to any terminal
	CriticalPath    []string         // the longest dependency chain (stage IDs in order)
	Parallel        [][]string       // stages that could execute in parallel (same depth level)
	HasCycles       bool             // redundant with Validate but useful in analysis
}

// DeadTransition records an on_success or on_failure reference to a non-existent stage.
type DeadTransition struct {
	StageID string
	Field   string // "on_success" or "on_failure"
	Target  string // the missing target
}

// AnalyzeGraph returns comprehensive graph analysis for a campaign.
func AnalyzeGraph(c *Campaign) *GraphAnalysis {
	a := &GraphAnalysis{}

	if c == nil || len(c.Stages) == 0 {
		return a
	}

	a.StageCount = len(c.Stages)

	// Build lookup structures.
	stageSet := make(map[string]bool, len(c.Stages))
	for _, s := range c.Stages {
		stageSet[s.ID] = true
	}

	// Count edges and find entry/terminal stages.
	dependedOn := make(map[string]bool) // stages that appear as a dependency target
	hasDeps := make(map[string]bool)    // stages that depend on something
	children := make(map[string][]string)

	for _, s := range c.Stages {
		for _, dep := range s.DependsOn {
			a.EdgeCount++
			dependedOn[dep] = true
			hasDeps[s.ID] = true
			children[dep] = append(children[dep], s.ID)
		}
	}

	// Entry points: stages with no depends_on.
	for _, s := range c.Stages {
		if !hasDeps[s.ID] {
			a.EntryPoints = append(a.EntryPoints, s.ID)
		}
	}

	// Terminal stages: stages that no other stage depends on.
	for _, s := range c.Stages {
		if !dependedOn[s.ID] {
			a.TerminalStages = append(a.TerminalStages, s.ID)
		}
	}

	// Orphan dependencies: referenced in depends_on but not defined.
	orphanSeen := make(map[string]bool)
	for _, s := range c.Stages {
		for _, dep := range s.DependsOn {
			if !stageSet[dep] && !orphanSeen[dep] {
				orphanSeen[dep] = true
				a.OrphanDeps = append(a.OrphanDeps, dep)
			}
		}
	}

	// Dead transitions: on_success/on_failure targets that reference non-existent stages.
	for _, s := range c.Stages {
		if s.OnSuccess != "" && !stageSet[s.OnSuccess] {
			a.DeadTransitions = append(a.DeadTransitions, DeadTransition{
				StageID: s.ID,
				Field:   "on_success",
				Target:  s.OnSuccess,
			})
		}
		// on_failure can be a mode (abort/skip/continue) or a stage reference.
		// Only flag as dead transition if it's not a known mode string.
		if s.OnFailure != "" && !validFailureModes[s.OnFailure] && !stageSet[s.OnFailure] {
			a.DeadTransitions = append(a.DeadTransitions, DeadTransition{
				StageID: s.ID,
				Field:   "on_failure",
				Target:  s.OnFailure,
			})
		}
	}

	// Unreachable: stages not reachable from any entry point via transition edges.
	// We traverse from entry points following on_success and on_failure (when they
	// are stage references), as well as depends_on children.
	reachable := make(map[string]bool)
	var walk func(id string)
	walk = func(id string) {
		if reachable[id] || !stageSet[id] {
			return
		}
		reachable[id] = true
		// Follow children (stages that depend on this one).
		for _, child := range children[id] {
			walk(child)
		}
		// Follow on_success transition.
		for _, s := range c.Stages {
			if s.ID == id {
				if s.OnSuccess != "" && stageSet[s.OnSuccess] {
					walk(s.OnSuccess)
				}
				if s.OnFailure != "" && !validFailureModes[s.OnFailure] && stageSet[s.OnFailure] {
					walk(s.OnFailure)
				}
				break
			}
		}
	}
	for _, ep := range a.EntryPoints {
		walk(ep)
	}
	for _, s := range c.Stages {
		if !reachable[s.ID] {
			a.Unreachable = append(a.Unreachable, s.ID)
		}
	}

	// Cycle detection.
	a.HasCycles = detectCycle(c.Stages) != ""

	// Depth computation and critical path using BFS-based topological depth.
	// Depth of a node = max(depth of dependencies) + 1.
	depth := computeDepths(c.Stages, stageSet)

	maxDepth := 0
	for _, d := range depth {
		if d > maxDepth {
			maxDepth = d
		}
	}
	a.MaxDepth = maxDepth

	// Parallel groups: stages at the same depth level.
	if maxDepth > 0 {
		levelMap := make(map[int][]string)
		for _, s := range c.Stages {
			d := depth[s.ID]
			levelMap[d] = append(levelMap[d], s.ID)
		}
		for d := 1; d <= maxDepth; d++ {
			if group, ok := levelMap[d]; ok {
				a.Parallel = append(a.Parallel, group)
			}
		}
	}

	// Critical path: the longest chain from an entry point to a terminal.
	a.CriticalPath = findCriticalPath(c.Stages, depth, a.EntryPoints, a.TerminalStages, children)

	return a
}

// computeDepths assigns each stage a depth (1-based) where depth = max(deps' depths) + 1.
// Stages with no dependencies get depth 1. Handles orphan deps gracefully.
func computeDepths(stages []Stage, stageSet map[string]bool) map[string]int {
	depth := make(map[string]int)

	var resolve func(id string) int
	resolve = func(id string) int {
		if d, ok := depth[id]; ok {
			return d
		}
		// Sentinel to detect cycles during resolution; avoids infinite recursion.
		depth[id] = -1

		maxDep := 0
		for _, s := range stages {
			if s.ID == id {
				for _, dep := range s.DependsOn {
					if !stageSet[dep] {
						continue // orphan dependency
					}
					d := resolve(dep)
					if d < 0 {
						continue // cycle
					}
					if d > maxDep {
						maxDep = d
					}
				}
				break
			}
		}
		depth[id] = maxDep + 1
		return depth[id]
	}

	for _, s := range stages {
		resolve(s.ID)
	}
	return depth
}

// findCriticalPath returns the longest chain from any entry to any terminal.
func findCriticalPath(stages []Stage, depth map[string]int, entries, terminals []string, children map[string][]string) []string {
	if len(stages) == 0 {
		return nil
	}

	// Build index for fast lookup.
	stageIndex := make(map[string]*Stage, len(stages))
	for i := range stages {
		stageIndex[stages[i].ID] = &stages[i]
	}

	// Find the terminal with maximum depth -- that's the end of the critical path.
	termSet := make(map[string]bool, len(terminals))
	for _, t := range terminals {
		termSet[t] = true
	}

	bestTerminal := ""
	bestDepth := 0
	for _, t := range terminals {
		if depth[t] > bestDepth {
			bestDepth = depth[t]
			bestTerminal = t
		}
	}
	if bestTerminal == "" {
		// No terminals (should not happen for a valid graph).
		// Fall back to any stage with maximum depth.
		for _, s := range stages {
			if depth[s.ID] > bestDepth {
				bestDepth = depth[s.ID]
				bestTerminal = s.ID
			}
		}
	}
	if bestTerminal == "" {
		return nil
	}

	// Trace back from the terminal, always picking the dependency with maximum depth.
	// Track visited nodes to avoid infinite loops in cyclic graphs.
	var path []string
	visited := make(map[string]bool)
	current := bestTerminal
	for current != "" && !visited[current] {
		visited[current] = true
		path = append([]string{current}, path...)
		s := stageIndex[current]
		if s == nil || len(s.DependsOn) == 0 {
			break
		}
		bestPred := ""
		bestPredDepth := 0
		for _, dep := range s.DependsOn {
			if !visited[dep] && depth[dep] > bestPredDepth {
				bestPredDepth = depth[dep]
				bestPred = dep
			}
		}
		current = bestPred
	}

	return path
}

// GraphDOT returns a Graphviz DOT representation of the campaign's dependency graph.
func GraphDOT(c *Campaign) string {
	if c == nil || len(c.Stages) == 0 {
		return "digraph campaign {\n}\n"
	}

	a := AnalyzeGraph(c)
	entrySet := make(map[string]bool, len(a.EntryPoints))
	for _, e := range a.EntryPoints {
		entrySet[e] = true
	}
	termSet := make(map[string]bool, len(a.TerminalStages))
	for _, t := range a.TerminalStages {
		termSet[t] = true
	}

	var b strings.Builder
	b.WriteString("digraph campaign {\n")
	b.WriteString("    rankdir=TB;\n")
	b.WriteString("    node [shape=box];\n\n")

	// Nodes.
	for _, s := range c.Stages {
		label := fmt.Sprintf("%s\n%s", s.ID, s.Technique)
		attrs := fmt.Sprintf("label=%q", label)
		if entrySet[s.ID] {
			attrs += ", style=filled, fillcolor=\"#90EE90\""
		} else if termSet[s.ID] {
			attrs += ", style=filled, fillcolor=\"#FFB6C1\""
		}
		fmt.Fprintf(&b, "    %q [%s];\n", s.ID, attrs)
	}
	b.WriteString("\n")

	// Edges.
	for _, s := range c.Stages {
		// depends_on: solid edges.
		for _, dep := range s.DependsOn {
			fmt.Fprintf(&b, "    %q -> %q;\n", dep, s.ID)
		}
		// on_success: dashed green.
		if s.OnSuccess != "" {
			fmt.Fprintf(&b, "    %q -> %q [style=dashed, color=\"green\", label=\"success\"];\n", s.ID, s.OnSuccess)
		}
		// on_failure: dashed red (only if it references a stage, not a mode).
		if s.OnFailure != "" && !validFailureModes[s.OnFailure] {
			fmt.Fprintf(&b, "    %q -> %q [style=dashed, color=\"red\", label=\"failure\"];\n", s.ID, s.OnFailure)
		}
	}

	b.WriteString("}\n")
	return b.String()
}

// GraphMermaid returns a Mermaid diagram of the campaign's dependency graph.
func GraphMermaid(c *Campaign) string {
	if c == nil || len(c.Stages) == 0 {
		return "graph TD\n"
	}

	a := AnalyzeGraph(c)
	entrySet := make(map[string]bool, len(a.EntryPoints))
	for _, e := range a.EntryPoints {
		entrySet[e] = true
	}
	termSet := make(map[string]bool, len(a.TerminalStages))
	for _, t := range a.TerminalStages {
		termSet[t] = true
	}

	// Mermaid IDs cannot contain hyphens in some renderers, so sanitize.
	sanitize := func(id string) string {
		return strings.ReplaceAll(id, "-", "_")
	}

	var b strings.Builder
	b.WriteString("graph TD\n")

	// Node definitions with labels.
	for _, s := range c.Stages {
		sid := sanitize(s.ID)
		label := fmt.Sprintf("%s<br/>%s", s.ID, s.Technique)
		fmt.Fprintf(&b, "    %s[\"%s\"]\n", sid, label)
	}

	// Edges.
	for _, s := range c.Stages {
		sid := sanitize(s.ID)
		for _, dep := range s.DependsOn {
			fmt.Fprintf(&b, "    %s --> %s\n", sanitize(dep), sid)
		}
		if s.OnSuccess != "" {
			fmt.Fprintf(&b, "    %s -.->|success| %s\n", sid, sanitize(s.OnSuccess))
		}
		if s.OnFailure != "" && !validFailureModes[s.OnFailure] {
			fmt.Fprintf(&b, "    %s -.->|failure| %s\n", sid, sanitize(s.OnFailure))
		}
	}

	// Styling.
	for _, e := range a.EntryPoints {
		fmt.Fprintf(&b, "    style %s fill:#90EE90,stroke:#333\n", sanitize(e))
	}
	for _, t := range a.TerminalStages {
		fmt.Fprintf(&b, "    style %s fill:#FFB6C1,stroke:#333\n", sanitize(t))
	}

	return b.String()
}
