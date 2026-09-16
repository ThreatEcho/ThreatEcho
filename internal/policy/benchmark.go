// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// DefaultBenchmarkIterations is the number of evaluation cycles when
// the caller does not specify a count.
const DefaultBenchmarkIterations = 1000

// BenchmarkResult holds timing metrics for a single benchmark run
// (one tool name evaluated against all rules).
type BenchmarkResult struct {
	ToolName       string        `json:"tool_name"`
	Matched        bool          `json:"matched"`
	EvalTimeAvg    time.Duration `json:"eval_time_avg"`
	EvalTimeP99    time.Duration `json:"eval_time_p99"`
	EvalTimeMax    time.Duration `json:"eval_time_max"`
	TotalEvals     int           `json:"total_evals"`
	RulesEvaluated int           `json:"rules_evaluated"`
	ToolsPerSec    float64       `json:"tools_per_sec"`
}

// BenchmarkReport aggregates benchmark results across all synthetic
// tool calls and provides an overall summary.
type BenchmarkReport struct {
	PolicyName     string            `json:"policy_name"`
	RuleCount      int               `json:"rule_count"`
	Iterations     int               `json:"iterations"`
	Results        []BenchmarkResult `json:"results"`
	OverallStats   OverallStats      `json:"overall_stats"`
	Recommendation string            `json:"recommendation"`
}

// OverallStats summarises timing across every tool evaluated.
type OverallStats struct {
	TotalTools  int           `json:"total_tools"`
	TotalEvals  int           `json:"total_evals"`
	AvgEvalTime time.Duration `json:"avg_eval_time"`
	P99EvalTime time.Duration `json:"p99_eval_time"`
	MaxEvalTime time.Duration `json:"max_eval_time"`
	MinEvalTime time.Duration `json:"min_eval_time"`
	TotalTime   time.Duration `json:"total_time"`
	ToolsPerSec float64       `json:"tools_per_sec"`
}

// BenchmarkPolicy evaluates all synthetic tool names against every rule in p
// for iterations cycles, collecting per-evaluation timing. It returns a
// BenchmarkReport with per-tool and aggregate statistics.
func BenchmarkPolicy(p *Policy, iterations int) *BenchmarkReport {
	if iterations <= 0 {
		iterations = DefaultBenchmarkIterations
	}

	tools := generateSyntheticTools(p)
	report := &BenchmarkReport{
		PolicyName: p.Meta.Name,
		RuleCount:  len(p.Rules),
		Iterations: iterations,
	}

	// Sort rules once (same order as Evaluate).
	sorted := make([]Rule, len(p.Rules))
	copy(sorted, p.Rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})

	var allDurations []time.Duration

	for _, toolName := range tools {
		durations := make([]time.Duration, 0, iterations)

		for i := 0; i < iterations; i++ {
			start := time.Now()
			_ = evalToolAgainstRules(sorted, toolName)
			elapsed := time.Since(start)
			durations = append(durations, elapsed)
		}

		matched := evalToolAgainstRules(sorted, toolName)

		avg, p99, maxD := computeBenchmarkStats(durations)
		tps := 0.0
		if avg > 0 {
			tps = float64(time.Second) / float64(avg)
		}

		report.Results = append(report.Results, BenchmarkResult{
			ToolName:       toolName,
			Matched:        matched,
			EvalTimeAvg:    avg,
			EvalTimeP99:    p99,
			EvalTimeMax:    maxD,
			TotalEvals:     iterations,
			RulesEvaluated: len(sorted),
			ToolsPerSec:    tps,
		})

		allDurations = append(allDurations, durations...)
	}

	// Compute overall stats.
	if len(allDurations) > 0 {
		avg, p99, maxD := computeBenchmarkStats(allDurations)
		minD := allDurations[0]
		for _, d := range allDurations {
			if d < minD {
				minD = d
			}
		}
		var total time.Duration
		for _, d := range allDurations {
			total += d
		}
		tps := 0.0
		if avg > 0 {
			tps = float64(time.Second) / float64(avg)
		}

		report.OverallStats = OverallStats{
			TotalTools:  len(tools),
			TotalEvals:  len(allDurations),
			AvgEvalTime: avg,
			P99EvalTime: p99,
			MaxEvalTime: maxD,
			MinEvalTime: minD,
			TotalTime:   total,
			ToolsPerSec: tps,
		}
	}

	report.Recommendation = generateRecommendation(report)

	return report
}

// evalToolAgainstRules checks whether a tool name matches any rule pattern.
// Returns true if a match is found.
func evalToolAgainstRules(rules []Rule, toolName string) bool {
	for _, rule := range rules {
		for _, pattern := range rule.Match.Tools {
			if GlobMatch(pattern, toolName) {
				return true
			}
		}
	}
	return false
}

// generateSyntheticTools builds a mix of tool names: some that match
// policy rules and some that do not, for realistic benchmark coverage.
func generateSyntheticTools(p *Policy) []string {
	seen := make(map[string]bool)
	var tools []string

	// Extract concrete tool names from rules (ones without wildcards).
	for _, r := range p.Rules {
		for _, t := range r.Match.Tools {
			if !strings.Contains(t, "*") && !seen[t] {
				seen[t] = true
				tools = append(tools, t)
			}
		}
	}

	// Generate tools that should match wildcard rules.
	matchingTools := []string{
		"shell_exec",
		"http_request",
		"file_access",
		"dns_query",
		"send_email",
		"agent_message",
		"search_knowledge_base",
		"write_knowledge_base",
		"process_exec",
		"registry_access",
	}
	for _, t := range matchingTools {
		if !seen[t] {
			seen[t] = true
			tools = append(tools, t)
		}
	}

	// Add non-matching tools for realistic miss testing.
	nonMatching := []string{
		"custom_tool_alpha",
		"internal_metric_push",
		"noop_health_check",
		"ui_render_widget",
		"cache_invalidate",
	}
	for _, t := range nonMatching {
		if !seen[t] {
			seen[t] = true
			tools = append(tools, t)
		}
	}

	sort.Strings(tools)
	return tools
}

// computeBenchmarkStats returns avg, p99 and max from a slice of durations.
func computeBenchmarkStats(durations []time.Duration) (avg, p99, max time.Duration) {
	if len(durations) == 0 {
		return 0, 0, 0
	}

	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	avg = total / time.Duration(len(sorted))

	p99Idx := int(math.Ceil(float64(len(sorted))*0.99)) - 1
	if p99Idx < 0 {
		p99Idx = 0
	}
	if p99Idx >= len(sorted) {
		p99Idx = len(sorted) - 1
	}
	p99 = sorted[p99Idx]

	max = sorted[len(sorted)-1]
	return avg, p99, max
}

// generateRecommendation produces a short guidance string based on timing.
func generateRecommendation(r *BenchmarkReport) string {
	if r.OverallStats.P99EvalTime < 10*time.Microsecond {
		return "Excellent — policy evaluates well within microsecond budget. Safe for inline agent gating."
	}
	if r.OverallStats.P99EvalTime < 100*time.Microsecond {
		return "Good — p99 under 100us. Suitable for production inline evaluation."
	}
	if r.OverallStats.P99EvalTime < time.Millisecond {
		return "Acceptable — p99 under 1ms. Consider caching for high-throughput agents."
	}
	if r.OverallStats.P99EvalTime < 10*time.Millisecond {
		return "Warning — p99 over 1ms. May add noticeable latency to agent tool calls. Reduce rule count or simplify patterns."
	}
	return "Critical — p99 over 10ms. Policy is too complex for inline evaluation. Refactor rules or implement async evaluation."
}

// FormatBenchmarkReport produces a human-readable box-drawing report.
func FormatBenchmarkReport(r *BenchmarkReport) string {
	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────────────┐\n")
	b.WriteString("│              POLICY BENCHMARK REPORT                        │\n")
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│  Policy:      %-44s│\n", r.PolicyName))
	b.WriteString(fmt.Sprintf("│  Rules:       %-44d│\n", r.RuleCount))
	b.WriteString(fmt.Sprintf("│  Iterations:  %-44d│\n", r.Iterations))
	b.WriteString(fmt.Sprintf("│  Tools:       %-44d│\n", r.OverallStats.TotalTools))
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")

	// Per-tool results table.
	b.WriteString("│  TOOL                          AVG       P99       MATCH    │\n")
	b.WriteString("│  ────────────────────────────── ───────── ───────── ──────── │\n")
	for _, res := range r.Results {
		name := res.ToolName
		if len(name) > 30 {
			name = name[:27] + "..."
		}
		matchStr := "miss"
		if res.Matched {
			matchStr = "hit"
		}
		b.WriteString(fmt.Sprintf("│  %-30s %-9s %-9s %-8s│\n",
			name,
			formatDuration(res.EvalTimeAvg),
			formatDuration(res.EvalTimeP99),
			matchStr,
		))
	}

	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	b.WriteString("│  OVERALL                                                    │\n")
	b.WriteString(fmt.Sprintf("│  Avg eval:    %-44s│\n", formatDuration(r.OverallStats.AvgEvalTime)))
	b.WriteString(fmt.Sprintf("│  P99 eval:    %-44s│\n", formatDuration(r.OverallStats.P99EvalTime)))
	b.WriteString(fmt.Sprintf("│  Max eval:    %-44s│\n", formatDuration(r.OverallStats.MaxEvalTime)))
	b.WriteString(fmt.Sprintf("│  Min eval:    %-44s│\n", formatDuration(r.OverallStats.MinEvalTime)))
	b.WriteString(fmt.Sprintf("│  Total time:  %-44s│\n", r.OverallStats.TotalTime.String()))
	b.WriteString(fmt.Sprintf("│  Throughput:  %-44s│\n", fmt.Sprintf("%.0f evals/sec", r.OverallStats.ToolsPerSec)))
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│  %s\n", r.Recommendation))
	b.WriteString("└─────────────────────────────────────────────────────────────┘\n")

	return b.String()
}

// benchmarkComputeStats calculates avg, p99, and max from a slice of durations.
func benchmarkComputeStats(durations []time.Duration) (avg, p99, maxD time.Duration) {
	if len(durations) == 0 {
		return 0, 0, 0
	}

	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	avg = total / time.Duration(len(sorted))

	p99Idx := int(math.Ceil(float64(len(sorted))*0.99)) - 1
	if p99Idx < 0 {
		p99Idx = 0
	}
	if p99Idx >= len(sorted) {
		p99Idx = len(sorted) - 1
	}
	p99 = sorted[p99Idx]
	maxD = sorted[len(sorted)-1]

	return avg, p99, maxD
}

// formatDuration renders a duration in a human-friendly unit.
func formatDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.1fµs", float64(d.Nanoseconds())/1000)
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
	}
	return d.Round(time.Millisecond).String()
}
