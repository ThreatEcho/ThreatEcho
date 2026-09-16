// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import "fmt"

// ResolveOrder returns stages in topological order (dependencies first).
// Returns an error if the graph contains a cycle.
func ResolveOrder(stages []Stage) ([]Stage, error) {
	index := make(map[string]int)
	for i, s := range stages {
		index[s.ID] = i
	}

	// Kahn's algorithm.
	inDegree := make(map[string]int)
	children := make(map[string][]string)
	for _, s := range stages {
		if _, ok := inDegree[s.ID]; !ok {
			inDegree[s.ID] = 0
		}
		for _, dep := range s.DependsOn {
			children[dep] = append(children[dep], s.ID)
			inDegree[s.ID]++
		}
	}

	var queue []string
	for _, s := range stages {
		if inDegree[s.ID] == 0 {
			queue = append(queue, s.ID)
		}
	}

	var ordered []Stage
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		ordered = append(ordered, stages[index[id]])
		for _, child := range children[id] {
			inDegree[child]--
			if inDegree[child] == 0 {
				queue = append(queue, child)
			}
		}
	}

	if len(ordered) != len(stages) {
		return nil, fmt.Errorf("dependency cycle: resolved %d of %d stages", len(ordered), len(stages))
	}
	return ordered, nil
}

// detectCycle returns a description of the first cycle found, or "" if acyclic.
func detectCycle(stages []Stage) string {
	index := make(map[string]*Stage)
	for i := range stages {
		index[stages[i].ID] = &stages[i]
	}

	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := make(map[string]int)

	var dfs func(id string, path []string) string
	dfs = func(id string, path []string) string {
		color[id] = grey
		path = append(path, id)

		s := index[id]
		if s == nil {
			return ""
		}
		for _, dep := range s.DependsOn {
			switch color[dep] {
			case grey:
				return fmt.Sprintf("%s → %s", dep, id)
			case white:
				if cycle := dfs(dep, path); cycle != "" {
					return cycle
				}
			}
		}
		color[id] = black
		return ""
	}

	for _, s := range stages {
		if color[s.ID] == white {
			if cycle := dfs(s.ID, nil); cycle != "" {
				return cycle
			}
		}
	}
	return ""
}
