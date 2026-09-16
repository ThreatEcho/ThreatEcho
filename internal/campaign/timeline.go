// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"strings"
	"time"
)

// TimelineEstimate holds the estimated execution timeline for a campaign.
type TimelineEstimate struct {
	// TotalSequential is the time if every stage ran one after another.
	TotalSequential time.Duration
	// TotalParallel is the time if stages at the same depth level run concurrently.
	// This is the critical-path duration.
	TotalParallel time.Duration
	// Speedup is TotalSequential / TotalParallel (>1.0 means parallelism helps).
	Speedup float64
	// Stages holds per-stage timing details, in execution order.
	Stages []StageTimeline
	// CriticalPath lists stage IDs on the longest-duration path.
	CriticalPath []string
	// ParallelLevels shows which stages run at each depth level with that level's duration.
	ParallelLevels []ParallelLevel
}

// StageTimeline holds timing info for one stage.
type StageTimeline struct {
	ID            string
	Depth         int           // DAG depth level (1-based)
	Duration      time.Duration // estimated execution time
	Delay         time.Duration // pre-execution delay
	EarliestStart time.Duration // earliest possible start time (sum of critical path to this point)
	EarliestEnd   time.Duration // EarliestStart + Delay + Duration
}

// ParallelLevel represents stages at one depth level.
type ParallelLevel struct {
	Level    int
	StageIDs []string
	Duration time.Duration // max(stage delay+duration) at this level — the level takes this long
	Delay    time.Duration // max(stage delays) at this level
}

// DefaultStageDuration is used when a stage has no timeout set.
const DefaultStageDuration = 30 * time.Second

// EstimateTimeline calculates execution time estimates for a campaign.
// It uses stage Timeout as duration estimate (falling back to DefaultStageDuration),
// respects Delay fields, and accounts for DAG parallelism.
func EstimateTimeline(c *Campaign) *TimelineEstimate {
	est := &TimelineEstimate{}

	if c == nil || len(c.Stages) == 0 {
		return est
	}

	ga := AnalyzeGraph(c)

	// Build stage lookup.
	stageMap := make(map[string]*Stage, len(c.Stages))
	for i := range c.Stages {
		stageMap[c.Stages[i].ID] = &c.Stages[i]
	}

	// Derive depth per stage from ga.Parallel (each element is a depth level, 0-indexed).
	depthMap := make(map[string]int, len(c.Stages))
	for lvl, group := range ga.Parallel {
		for _, id := range group {
			depthMap[id] = lvl + 1 // 1-based
		}
	}

	// Compute per-stage execution duration and delay.
	dur := make(map[string]time.Duration, len(c.Stages))
	del := make(map[string]time.Duration, len(c.Stages))
	for _, s := range c.Stages {
		if s.Timeout.Duration > 0 {
			dur[s.ID] = s.Timeout.Duration
		} else {
			dur[s.ID] = DefaultStageDuration
		}
		del[s.ID] = s.Delay.Duration
	}

	// TotalSequential: sum of all (delay + duration).
	for _, s := range c.Stages {
		est.TotalSequential += dur[s.ID] + del[s.ID]
	}

	// Compute EarliestStart and EarliestEnd per stage via topological order.
	// ga.Parallel provides stages grouped by depth, so processing level-by-level
	// guarantees all dependencies are resolved before their dependents.
	earliestStart := make(map[string]time.Duration, len(c.Stages))
	earliestEnd := make(map[string]time.Duration, len(c.Stages))

	for _, group := range ga.Parallel {
		for _, id := range group {
			s := stageMap[id]
			if s == nil {
				continue
			}
			var maxDepEnd time.Duration
			for _, dep := range s.DependsOn {
				if ee, ok := earliestEnd[dep]; ok && ee > maxDepEnd {
					maxDepEnd = ee
				}
			}
			earliestStart[id] = maxDepEnd
			earliestEnd[id] = maxDepEnd + del[id] + dur[id]
		}
	}

	// TotalParallel = max(EarliestEnd) across all stages.
	for _, s := range c.Stages {
		if earliestEnd[s.ID] > est.TotalParallel {
			est.TotalParallel = earliestEnd[s.ID]
		}
	}

	// Speedup ratio (guard against zero).
	if est.TotalParallel > 0 {
		est.Speedup = float64(est.TotalSequential) / float64(est.TotalParallel)
	}

	// Build ParallelLevels.
	for lvl, group := range ga.Parallel {
		pl := ParallelLevel{
			Level:    lvl + 1,
			StageIDs: group,
		}
		for _, id := range group {
			total := del[id] + dur[id]
			if total > pl.Duration {
				pl.Duration = total
			}
			if del[id] > pl.Delay {
				pl.Delay = del[id]
			}
		}
		est.ParallelLevels = append(est.ParallelLevels, pl)
	}

	// CriticalPath: duration-weighted longest path through the DAG.
	est.CriticalPath = findDurationCriticalPath(c.Stages, stageMap, earliestEnd)

	// Build per-stage timeline entries in execution order (depth first, then campaign order).
	for _, group := range ga.Parallel {
		for _, id := range group {
			est.Stages = append(est.Stages, StageTimeline{
				ID:            id,
				Depth:         depthMap[id],
				Duration:      dur[id],
				Delay:         del[id],
				EarliestStart: earliestStart[id],
				EarliestEnd:   earliestEnd[id],
			})
		}
	}

	return est
}

// findDurationCriticalPath traces the longest-duration path through the DAG.
// It finds the stage with the maximum EarliestEnd and traces backward through
// dependencies, always choosing the predecessor with the highest EarliestEnd.
func findDurationCriticalPath(stages []Stage, stageMap map[string]*Stage, earliestEnd map[string]time.Duration) []string {
	if len(stages) == 0 {
		return nil
	}

	// Find the stage with maximum EarliestEnd.
	var maxEnd time.Duration
	var endStage string
	for _, s := range stages {
		if ee := earliestEnd[s.ID]; ee > maxEnd || (ee == maxEnd && endStage == "") {
			maxEnd = ee
			endStage = s.ID
		}
	}
	if endStage == "" {
		return nil
	}

	// Trace backward from the end stage.
	var path []string
	visited := make(map[string]bool)
	current := endStage

	for current != "" && !visited[current] {
		visited[current] = true
		path = append([]string{current}, path...)

		s := stageMap[current]
		if s == nil || len(s.DependsOn) == 0 {
			break
		}

		// Pick the dependency with the highest EarliestEnd.
		bestPred := ""
		var bestPredEnd time.Duration
		for _, dep := range s.DependsOn {
			if visited[dep] {
				continue
			}
			if ee := earliestEnd[dep]; ee > bestPredEnd || bestPred == "" {
				bestPredEnd = ee
				bestPred = dep
			}
		}
		current = bestPred
	}

	return path
}

// FormatTimeline returns a human-readable timeline report.
func FormatTimeline(est *TimelineEstimate) string {
	if est == nil {
		return "No timeline estimate available.\n"
	}

	var b strings.Builder

	b.WriteString("Campaign Timeline Estimate\n")
	b.WriteString("===========================\n\n")

	// Summary.
	fmt.Fprintf(&b, "Sequential: %s (all stages in series)\n", formatDur(est.TotalSequential))
	fmt.Fprintf(&b, "Parallel:   %s (with DAG concurrency)\n", formatDur(est.TotalParallel))
	fmt.Fprintf(&b, "Speedup:    %.1fx\n", est.Speedup)

	// Critical path.
	if len(est.CriticalPath) > 0 {
		b.WriteString("\nCritical Path: ")
		b.WriteString(strings.Join(est.CriticalPath, " → "))
		b.WriteString("\n")
	}

	// Execution levels.
	if len(est.ParallelLevels) > 0 {
		b.WriteString("\nExecution Levels:\n")
		var cumulative time.Duration
		for _, pl := range est.ParallelLevels {
			start := cumulative
			end := cumulative + pl.Duration
			fmt.Fprintf(&b, "  Level %d (%s-%s): %s\n",
				pl.Level,
				formatDur(start),
				formatDur(end),
				strings.Join(pl.StageIDs, ", "),
			)
			cumulative = end
		}
	}

	// Stage details.
	if len(est.Stages) > 0 {
		b.WriteString("\nStage Details:\n")
		for _, st := range est.Stages {
			durStr := formatDur(st.Duration)
			if st.Delay > 0 {
				durStr += fmt.Sprintf(" + %s delay", formatDur(st.Delay))
			}
			fmt.Fprintf(&b, "  %s: %s (depth %d, starts at %s)\n",
				st.ID,
				durStr,
				st.Depth,
				formatDur(st.EarliestStart),
			)
		}
	}

	return b.String()
}

// formatDur formats a duration for display. Zero durations show as "0s".
func formatDur(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	return d.String()
}
