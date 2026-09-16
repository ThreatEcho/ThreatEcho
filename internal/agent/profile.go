// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// BehaviorProfile is a behavioral baseline built from an agent's historical
// execution traces. It captures typical tool usage, action sequences, timing,
// and boundary (target) behavior so that new traces can be compared against
// what "normal" looks like for this agent.
type BehaviorProfile struct {
	AgentName       string               `json:"agent_name"`
	AgentType       string               `json:"agent_type"`
	ToolUsage       map[string]ToolStats `json:"tool_usage"`
	ActionPatterns  []ActionPattern      `json:"action_patterns"`
	TimeProfile     TimeStats            `json:"time_profile"`
	BoundaryProfile BoundaryStats        `json:"boundary_profile"`
	RiskBaseline    float64              `json:"risk_baseline"` // 0.0-1.0, normal risk level
	SampleSize      int                  `json:"sample_size"`   // number of traces used to build the profile
}

// ToolStats holds baseline usage statistics for a single tool.
type ToolStats struct {
	CallCount        int      `json:"call_count"`
	AvgCallsPerTrace float64  `json:"avg_calls_per_trace"`
	SuccessRate      float64  `json:"success_rate"` // 0.0-1.0
	CommonActions    []string `json:"common_actions"`
	CommonTargets    []string `json:"common_targets"`
}

// ActionPattern is a recurring sequence of tool calls observed across traces.
type ActionPattern struct {
	Sequence   []string `json:"sequence"` // tool names in order
	Frequency  int      `json:"frequency"`
	Confidence float64  `json:"confidence"` // 0.0-1.0
}

// TimeStats holds baseline timing characteristics for an agent.
type TimeStats struct {
	AvgEventsPerTrace float64 `json:"avg_events_per_trace"`
	AvgDuration       string  `json:"avg_duration"` // Go duration string, e.g. "5s"
	PeakHour          int     `json:"peak_hour"`    // 0-23, UTC hour with the most activity
}

// BoundaryStats holds baseline information about what targets an agent
// typically reaches.
type BoundaryStats struct {
	UniqueTargets int      `json:"unique_targets"`
	CommonDomains []string `json:"common_domains"`
}

// Deviation type constants identify categories of behavioral anomaly.
const (
	// DeviationNewTool indicates the agent invoked a tool not seen in its baseline.
	DeviationNewTool = "new_tool"
	// DeviationFrequencySpike indicates an abnormal increase in tool call volume.
	DeviationFrequencySpike = "frequency_spike"
	// DeviationUnusualTarget indicates the agent contacted a target outside its normal set.
	DeviationUnusualTarget = "unusual_target"
	// DeviationTimingAnomaly indicates tool calls occurring outside the agent's normal schedule.
	DeviationTimingAnomaly = "timing_anomaly"
	// DeviationPatternBreak indicates a break in the agent's typical action sequence.
	DeviationPatternBreak = "pattern_break"
	// DeviationBoundaryExpand indicates the agent reached targets beyond its established boundary.
	DeviationBoundaryExpand = "boundary_expansion"
	// DeviationRiskElevation indicates the agent's computed risk score increased above baseline.
	DeviationRiskElevation = "risk_elevation"
)

// ProfileDeviation is a single detected deviation from an agent's baseline.
type ProfileDeviation struct {
	Type        string  `json:"type"`     // new_tool, frequency_spike, unusual_target, timing_anomaly, pattern_break, boundary_expansion, risk_elevation
	Severity    string  `json:"severity"` // critical, high, medium, low, info
	Description string  `json:"description"`
	Score       float64 `json:"score"` // 0.0-1.0
	Tool        string  `json:"tool,omitempty"`
	Expected    string  `json:"expected,omitempty"`
	Observed    string  `json:"observed,omitempty"`
}

// DeviationReport is the result of comparing a trace against a baseline profile.
type DeviationReport struct {
	AgentName  string             `json:"agent_name"`
	Profile    *BehaviorProfile   `json:"profile"`
	Deviations []ProfileDeviation `json:"deviations"`
	RiskScore  float64            `json:"risk_score"` // 0.0-1.0
	IsAnomaly  bool               `json:"is_anomaly"` // true if RiskScore >= DefaultDeviationThreshold()
}

// DefaultDeviationThreshold returns the default risk score above which a
// DeviationReport is considered anomalous.
func DefaultDeviationThreshold() float64 {
	return 0.6
}

// ---------------------------------------------------------------------------
// Profile building
// ---------------------------------------------------------------------------

// BuildProfile builds a behavioral baseline for agentName from a set of
// execution traces. Traces whose AgentName does not match agentName are
// ignored (unless agentName is empty, in which case all non-nil traces are
// used). Returns an empty, zero-sample profile if no traces match.
func BuildProfile(agentName string, traces []*policy.Trace) *BehaviorProfile {
	profile := &BehaviorProfile{
		AgentName: agentName,
		ToolUsage: make(map[string]ToolStats),
	}

	relevant := filterTracesByAgent(agentName, traces)
	profile.SampleSize = len(relevant)
	if profile.SampleSize == 0 {
		return profile
	}

	for _, t := range relevant {
		if t.AgentType != "" {
			profile.AgentType = t.AgentType
			break
		}
	}

	profile.ToolUsage = buildToolStats(relevant)
	profile.ActionPatterns = buildActionPatterns(relevant)
	profile.TimeProfile = buildTimeStats(relevant)
	profile.BoundaryProfile = buildBoundaryStats(relevant)
	profile.RiskBaseline = computeRiskBaseline(relevant)

	return profile
}

// filterTracesByAgent returns the non-nil traces belonging to agentName.
// If agentName is empty, all non-nil traces are returned.
func filterTracesByAgent(agentName string, traces []*policy.Trace) []*policy.Trace {
	var out []*policy.Trace
	for _, t := range traces {
		if t == nil {
			continue
		}
		if agentName == "" || t.AgentName == agentName {
			out = append(out, t)
		}
	}
	return out
}

// toolAgg accumulates per-tool statistics while scanning traces.
type toolAgg struct {
	callCount   int
	successCnt  int
	actionCount map[string]int
	targetCount map[string]int
}

// buildToolStats aggregates per-tool usage statistics across traces.
func buildToolStats(traces []*policy.Trace) map[string]ToolStats {
	agg := make(map[string]*toolAgg)

	for _, t := range traces {
		for _, ev := range t.Events {
			if ev.Type != "tool_call" || ev.ToolCall == nil || ev.ToolCall.Tool == "" {
				continue
			}
			tc := ev.ToolCall
			a, ok := agg[tc.Tool]
			if !ok {
				a = &toolAgg{
					actionCount: make(map[string]int),
					targetCount: make(map[string]int),
				}
				agg[tc.Tool] = a
			}
			a.callCount++
			if tc.Success {
				a.successCnt++
			}
			if tc.Action != "" {
				a.actionCount[tc.Action]++
			}
			if tc.Target != "" {
				a.targetCount[tc.Target]++
			}
		}
	}

	sampleSize := len(traces)
	stats := make(map[string]ToolStats, len(agg))
	for tool, a := range agg {
		s := ToolStats{
			CallCount:     a.callCount,
			CommonActions: topByFrequency(a.actionCount, 5),
			CommonTargets: topByFrequency(a.targetCount, 5),
		}
		if sampleSize > 0 {
			s.AvgCallsPerTrace = round2(float64(a.callCount) / float64(sampleSize))
		}
		if a.callCount > 0 {
			s.SuccessRate = round2(float64(a.successCnt) / float64(a.callCount))
		}
		stats[tool] = s
	}
	return stats
}

// topByFrequency returns up to limit keys of m, ordered by descending count
// with ties broken alphabetically.
func topByFrequency(m map[string]int, limit int) []string {
	if len(m) == 0 {
		return nil
	}
	keys := sortedMapKeys(m)
	sort.SliceStable(keys, func(i, j int) bool {
		return m[keys[i]] > m[keys[j]]
	})
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	return keys
}

// ngramAgg accumulates occurrences of a specific tool-call sequence.
type ngramAgg struct {
	seq   []string
	count int
}

// buildActionPatterns detects recurring 2- and 3-length tool-call sequences
// across traces. A sequence must recur (occur 2+ times) to be considered a
// pattern.
func buildActionPatterns(traces []*policy.Trace) []ActionPattern {
	ngrams := make(map[string]*ngramAgg)
	totalByLen := map[int]int{2: 0, 3: 0}

	for _, t := range traces {
		seq := toolSequence(t)
		for n := 2; n <= 3; n++ {
			if len(seq) < n {
				continue
			}
			for i := 0; i+n <= len(seq); i++ {
				sub := seq[i : i+n]
				key := strings.Join(sub, "\x00")
				a, ok := ngrams[key]
				if !ok {
					a = &ngramAgg{seq: append([]string(nil), sub...)}
					ngrams[key] = a
				}
				a.count++
				totalByLen[n]++
			}
		}
	}

	var patterns []ActionPattern
	for _, a := range ngrams {
		if a.count < 2 {
			continue
		}
		total := totalByLen[len(a.seq)]
		conf := 0.0
		if total > 0 {
			conf = round2(float64(a.count) / float64(total))
		}
		patterns = append(patterns, ActionPattern{
			Sequence:   a.seq,
			Frequency:  a.count,
			Confidence: conf,
		})
	}

	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].Frequency != patterns[j].Frequency {
			return patterns[i].Frequency > patterns[j].Frequency
		}
		return strings.Join(patterns[i].Sequence, ",") < strings.Join(patterns[j].Sequence, ",")
	})

	const maxPatterns = 10
	if len(patterns) > maxPatterns {
		patterns = patterns[:maxPatterns]
	}

	return patterns
}

// toolSequence extracts the ordered sequence of tool names from a trace's
// tool_call events.
func toolSequence(t *policy.Trace) []string {
	var seq []string
	for _, ev := range t.Events {
		if ev.Type == "tool_call" && ev.ToolCall != nil && ev.ToolCall.Tool != "" {
			seq = append(seq, ev.ToolCall.Tool)
		}
	}
	return seq
}

// buildTimeStats computes baseline timing characteristics across traces.
func buildTimeStats(traces []*policy.Trace) TimeStats {
	ts := TimeStats{}
	if len(traces) == 0 {
		return ts
	}

	totalEvents := 0
	var totalDuration time.Duration
	durCount := 0
	hourCount := make(map[int]int)

	for _, t := range traces {
		totalEvents += len(t.Events)

		if d, ok := traceDuration(t); ok {
			totalDuration += d
			durCount++
		}

		for _, ev := range t.Events {
			if hh, ok := eventHour(ev.Timestamp); ok {
				hourCount[hh]++
			}
		}
	}

	ts.AvgEventsPerTrace = round2(float64(totalEvents) / float64(len(traces)))

	if durCount > 0 {
		avg := totalDuration / time.Duration(durCount)
		ts.AvgDuration = avg.Round(time.Second).String()
	} else {
		ts.AvgDuration = "0s"
	}

	ts.PeakHour = peakHour(hourCount)

	return ts
}

// traceDuration returns the wall-clock duration between a trace's start and
// end times, if both parse as RFC3339 timestamps.
func traceDuration(t *policy.Trace) (time.Duration, bool) {
	start, err1 := time.Parse(time.RFC3339, t.StartTime)
	end, err2 := time.Parse(time.RFC3339, t.EndTime)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	d := end.Sub(start)
	if d < 0 {
		d = 0
	}
	return d, true
}

// eventHour returns the UTC hour-of-day for an RFC3339 timestamp.
func eventHour(ts string) (int, bool) {
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0, false
	}
	return parsed.UTC().Hour(), true
}

// peakHour returns the hour (0-23) with the highest count. Ties favor the
// earliest hour.
func peakHour(hourCount map[int]int) int {
	best, bestCount := 0, -1
	for h := 0; h < 24; h++ {
		if hourCount[h] > bestCount {
			best = h
			bestCount = hourCount[h]
		}
	}
	return best
}

// buildBoundaryStats aggregates the distinct targets and domains an agent
// reaches across traces.
func buildBoundaryStats(traces []*policy.Trace) BoundaryStats {
	targets := make(map[string]bool)
	domainCount := make(map[string]int)

	for _, t := range traces {
		for _, ev := range t.Events {
			if ev.Type != "tool_call" || ev.ToolCall == nil || ev.ToolCall.Target == "" {
				continue
			}
			target := ev.ToolCall.Target
			targets[target] = true
			domainCount[extractDomain(target)]++
		}
	}

	return BoundaryStats{
		UniqueTargets: len(targets),
		CommonDomains: topByFrequency(domainCount, 5),
	}
}

// extractDomain pulls a host-like component out of a target string. For
// URL-like targets ("scheme://host/path") it returns the host. For anything
// else (file paths, opaque identifiers) it returns the target unchanged.
func extractDomain(target string) string {
	rest := target
	if idx := strings.Index(target, "://"); idx >= 0 {
		rest = target[idx+3:]
	}
	if idx := strings.IndexAny(rest, "/?#"); idx >= 0 {
		rest = rest[:idx]
	}
	if rest == "" {
		return target
	}
	return rest
}

// computeRiskBaseline derives a 0.0-1.0 risk level from the proportion of
// elevated and failed tool calls across traces.
func computeRiskBaseline(traces []*policy.Trace) float64 {
	var total, elevated, failed int
	for _, t := range traces {
		for _, ev := range t.Events {
			if ev.Type != "tool_call" || ev.ToolCall == nil {
				continue
			}
			total++
			if ev.ToolCall.Elevated {
				elevated++
			}
			if !ev.ToolCall.Success {
				failed++
			}
		}
	}
	if total == 0 {
		return 0
	}
	elevatedRatio := float64(elevated) / float64(total)
	failedRatio := float64(failed) / float64(total)
	return clampScore(round2(elevatedRatio*0.7 + failedRatio*0.3))
}

// ---------------------------------------------------------------------------
// Deviation detection
// ---------------------------------------------------------------------------

// DetectDeviations compares a new trace against a baseline profile and
// returns a DeviationReport. A nil profile or nil trace yields a report with
// no deviations.
func DetectDeviations(profile *BehaviorProfile, trace *policy.Trace) *DeviationReport {
	report := &DeviationReport{Profile: profile}

	switch {
	case trace != nil:
		report.AgentName = trace.AgentName
	case profile != nil:
		report.AgentName = profile.AgentName
	}

	if profile == nil || trace == nil {
		return report
	}

	var deviations []ProfileDeviation
	deviations = append(deviations, detectNewTools(profile, trace)...)
	deviations = append(deviations, detectFrequencySpikes(profile, trace)...)
	deviations = append(deviations, detectUnusualTargets(profile, trace)...)
	deviations = append(deviations, detectTimingAnomalies(profile, trace)...)
	deviations = append(deviations, detectPatternBreaks(profile, trace)...)
	deviations = append(deviations, detectBoundaryExpansion(profile, trace)...)
	deviations = append(deviations, detectRiskElevation(profile, trace)...)

	sort.SliceStable(deviations, func(i, j int) bool {
		if deviations[i].Score != deviations[j].Score {
			return deviations[i].Score > deviations[j].Score
		}
		return deviations[i].Type < deviations[j].Type
	})

	report.Deviations = deviations
	report.RiskScore = scoreDeviationRisk(deviations)
	report.IsAnomaly = report.RiskScore >= DefaultDeviationThreshold()

	return report
}

// detectNewTools flags tools used in the trace that never appeared in the
// baseline.
func detectNewTools(profile *BehaviorProfile, trace *policy.Trace) []ProfileDeviation {
	if profile.SampleSize == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var out []ProfileDeviation
	for _, ev := range trace.Events {
		if ev.Type != "tool_call" || ev.ToolCall == nil || ev.ToolCall.Tool == "" {
			continue
		}
		tool := ev.ToolCall.Tool
		if seen[tool] {
			continue
		}
		seen[tool] = true
		if _, known := profile.ToolUsage[tool]; known {
			continue
		}

		score := 0.45
		if toolElevated(trace, tool) {
			score = 0.8
		}
		out = append(out, ProfileDeviation{
			Type:        DeviationNewTool,
			Severity:    deviationSeverity(score),
			Description: fmt.Sprintf("Agent used tool %q which does not appear in its baseline", tool),
			Score:       score,
			Tool:        tool,
			Expected:    "not used",
			Observed:    "used in this trace",
		})
	}
	return out
}

// detectFrequencySpikes flags tools called far more often in this trace than
// the baseline average per trace.
func detectFrequencySpikes(profile *BehaviorProfile, trace *policy.Trace) []ProfileDeviation {
	if profile.SampleSize == 0 {
		return nil
	}

	counts := toolCallCounts(trace)
	var out []ProfileDeviation
	for _, tool := range sortedMapKeys(counts) {
		observed := counts[tool]
		stats, known := profile.ToolUsage[tool]
		if !known {
			continue // new tools are handled separately
		}

		baseline := stats.AvgCallsPerTrace
		threshold := baseline*3 + 2
		if float64(observed) <= threshold {
			continue
		}

		ratio := float64(observed)
		if baseline > 0 {
			ratio = float64(observed) / baseline
		}

		score := clampScore(round2(0.3 + ratio*0.05))
		out = append(out, ProfileDeviation{
			Type:        DeviationFrequencySpike,
			Severity:    deviationSeverity(score),
			Description: fmt.Sprintf("Tool %q called %d times, well above baseline average of %.2f/trace", tool, observed, baseline),
			Score:       score,
			Tool:        tool,
			Expected:    fmt.Sprintf("~%.2f calls/trace", baseline),
			Observed:    fmt.Sprintf("%d calls", observed),
		})
	}
	return out
}

// detectUnusualTargets flags (tool, target) pairs not present in the
// baseline's common targets for that tool.
func detectUnusualTargets(profile *BehaviorProfile, trace *policy.Trace) []ProfileDeviation {
	if profile.SampleSize == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var out []ProfileDeviation
	for _, ev := range trace.Events {
		if ev.Type != "tool_call" || ev.ToolCall == nil || ev.ToolCall.Target == "" {
			continue
		}
		tc := ev.ToolCall
		key := tc.Tool + "\x00" + tc.Target
		if seen[key] {
			continue
		}
		seen[key] = true

		stats, known := profile.ToolUsage[tc.Tool]
		if !known || len(stats.CommonTargets) == 0 {
			continue // no target baseline to compare against
		}
		if containsStr(stats.CommonTargets, tc.Target) {
			continue
		}

		out = append(out, ProfileDeviation{
			Type:        DeviationUnusualTarget,
			Severity:    deviationSeverity(0.45),
			Description: fmt.Sprintf("Tool %q accessed target %q not seen in baseline", tc.Tool, tc.Target),
			Score:       0.45,
			Tool:        tc.Tool,
			Expected:    strings.Join(stats.CommonTargets, ", "),
			Observed:    tc.Target,
		})
	}
	return out
}

// detectTimingAnomalies flags traces whose duration or activity-hour profile
// deviates sharply from the baseline.
func detectTimingAnomalies(profile *BehaviorProfile, trace *policy.Trace) []ProfileDeviation {
	if profile.SampleSize == 0 {
		return nil
	}

	var out []ProfileDeviation

	if d, ok := traceDuration(trace); ok {
		if baseline, err := time.ParseDuration(profile.TimeProfile.AvgDuration); err == nil && baseline > 0 {
			ratio := float64(d) / float64(baseline)
			if ratio >= 3 || ratio <= 1.0/3.0 {
				score := clampScore(round2(0.3 + absF(ratio-1)*0.1))
				out = append(out, ProfileDeviation{
					Type:        DeviationTimingAnomaly,
					Severity:    deviationSeverity(score),
					Description: fmt.Sprintf("Trace duration %s deviates sharply from baseline average %s", d.Round(time.Second), baseline.Round(time.Second)),
					Score:       score,
					Expected:    baseline.Round(time.Second).String(),
					Observed:    d.Round(time.Second).String(),
				})
			}
		}
	}

	hourCount := make(map[int]int)
	for _, ev := range trace.Events {
		if hh, ok := eventHour(ev.Timestamp); ok {
			hourCount[hh]++
		}
	}
	if len(hourCount) > 0 {
		observedPeak := peakHour(hourCount)
		diff := hourDistance(observedPeak, profile.TimeProfile.PeakHour)
		if diff >= 6 {
			score := clampScore(round2(0.25 + float64(diff)*0.03))
			out = append(out, ProfileDeviation{
				Type:        DeviationTimingAnomaly,
				Severity:    deviationSeverity(score),
				Description: fmt.Sprintf("Activity peaked at %02d:00, far from baseline peak hour %02d:00", observedPeak, profile.TimeProfile.PeakHour),
				Score:       score,
				Expected:    fmt.Sprintf("%02d:00", profile.TimeProfile.PeakHour),
				Observed:    fmt.Sprintf("%02d:00", observedPeak),
			})
		}
	}

	return out
}

// detectPatternBreaks flags traces whose tool-call sequence contains no
// subsequence matching any known baseline action pattern.
func detectPatternBreaks(profile *BehaviorProfile, trace *policy.Trace) []ProfileDeviation {
	if len(profile.ActionPatterns) == 0 {
		return nil
	}

	seq := toolSequence(trace)
	if len(seq) < 2 {
		return nil
	}

	known := make(map[string]bool, len(profile.ActionPatterns))
	for _, p := range profile.ActionPatterns {
		known[strings.Join(p.Sequence, "\x00")] = true
	}

	for n := 2; n <= 3 && n <= len(seq); n++ {
		for i := 0; i+n <= len(seq); i++ {
			if known[strings.Join(seq[i:i+n], "\x00")] {
				return nil // at least one known pattern present — no break
			}
		}
	}

	return []ProfileDeviation{{
		Type:        DeviationPatternBreak,
		Severity:    deviationSeverity(0.4),
		Description: fmt.Sprintf("Tool call sequence %s does not match any known baseline pattern", strings.Join(seq, " -> ")),
		Score:       0.4,
		Expected:    formatPatternList(profile.ActionPatterns),
		Observed:    strings.Join(seq, " -> "),
	}}
}

// detectBoundaryExpansion flags traces that reach as many or more new target
// domains than the entire set of domains known to the baseline.
func detectBoundaryExpansion(profile *BehaviorProfile, trace *policy.Trace) []ProfileDeviation {
	if profile.SampleSize == 0 || len(profile.BoundaryProfile.CommonDomains) == 0 {
		return nil
	}

	known := make(map[string]bool, len(profile.BoundaryProfile.CommonDomains))
	for _, d := range profile.BoundaryProfile.CommonDomains {
		known[d] = true
	}

	newDomains := make(map[string]bool)
	for _, ev := range trace.Events {
		if ev.Type != "tool_call" || ev.ToolCall == nil || ev.ToolCall.Target == "" {
			continue
		}
		domain := extractDomain(ev.ToolCall.Target)
		if !known[domain] {
			newDomains[domain] = true
		}
	}

	if len(newDomains) == 0 || len(newDomains) < len(profile.BoundaryProfile.CommonDomains) {
		return nil
	}

	domainList := make([]string, 0, len(newDomains))
	for d := range newDomains {
		domainList = append(domainList, d)
	}
	sort.Strings(domainList)

	score := clampScore(round2(0.4 + float64(len(newDomains))*0.1))
	return []ProfileDeviation{{
		Type:        DeviationBoundaryExpand,
		Severity:    deviationSeverity(score),
		Description: fmt.Sprintf("Agent reached %d new target domain(s) outside its established boundary", len(newDomains)),
		Score:       score,
		Expected:    strings.Join(profile.BoundaryProfile.CommonDomains, ", "),
		Observed:    strings.Join(domainList, ", "),
	}}
}

// detectRiskElevation flags traces whose own risk level is significantly
// above the baseline risk level.
func detectRiskElevation(profile *BehaviorProfile, trace *policy.Trace) []ProfileDeviation {
	if profile.SampleSize == 0 {
		return nil
	}

	observed := computeRiskBaseline([]*policy.Trace{trace})
	delta := observed - profile.RiskBaseline
	if delta < 0.3 {
		return nil
	}

	score := clampScore(round2(delta))
	return []ProfileDeviation{{
		Type:        DeviationRiskElevation,
		Severity:    deviationSeverity(score),
		Description: fmt.Sprintf("Observed risk %.2f is significantly above baseline %.2f", observed, profile.RiskBaseline),
		Score:       score,
		Expected:    fmt.Sprintf("%.2f", profile.RiskBaseline),
		Observed:    fmt.Sprintf("%.2f", observed),
	}}
}

// deviationSeverity classifies a 0.0-1.0 deviation score into a severity band.
func deviationSeverity(score float64) string {
	switch {
	case score >= 0.8:
		return "critical"
	case score >= 0.6:
		return "high"
	case score >= 0.35:
		return "medium"
	case score >= 0.15:
		return "low"
	default:
		return "info"
	}
}

// scoreDeviationRisk aggregates deviations into an overall 0.0-1.0 risk score.
func scoreDeviationRisk(deviations []ProfileDeviation) float64 {
	score := 0.0
	for _, d := range deviations {
		switch d.Severity {
		case "critical":
			score += 0.35
		case "high":
			score += 0.22
		case "medium":
			score += 0.12
		case "low":
			score += 0.05
		default:
			score += 0.02
		}
	}
	return clampScore(round2(score))
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// round2 rounds a float to 2 decimal places.
func round2(f float64) float64 {
	return math.Round(f*100) / 100
}

// clampScore clamps a float to the [0, 1] range.
func clampScore(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

// absF returns the absolute value of a float64.
func absF(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// toolCallCounts counts tool_call events per tool within a single trace.
func toolCallCounts(t *policy.Trace) map[string]int {
	counts := make(map[string]int)
	for _, ev := range t.Events {
		if ev.Type == "tool_call" && ev.ToolCall != nil && ev.ToolCall.Tool != "" {
			counts[ev.ToolCall.Tool]++
		}
	}
	return counts
}

// toolElevated reports whether any call to tool within the trace was marked elevated.
func toolElevated(t *policy.Trace, tool string) bool {
	for _, ev := range t.Events {
		if ev.Type == "tool_call" && ev.ToolCall != nil && ev.ToolCall.Tool == tool && ev.ToolCall.Elevated {
			return true
		}
	}
	return false
}

// containsStr reports whether s is present in list.
func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// hourDistance returns the circular distance in hours between two hours of
// day on a 24-hour clock.
func hourDistance(a, b int) int {
	d := a - b
	if d < 0 {
		d = -d
	}
	if d > 12 {
		d = 24 - d
	}
	return d
}

// formatPatternList renders up to the first 3 action patterns as a
// human-readable, comma-separated list of sequences.
func formatPatternList(patterns []ActionPattern) string {
	if len(patterns) == 0 {
		return ""
	}
	limit := len(patterns)
	if limit > 3 {
		limit = 3
	}
	parts := make([]string, 0, limit)
	for _, p := range patterns[:limit] {
		parts = append(parts, strings.Join(p.Sequence, "->"))
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatProfile renders a BehaviorProfile as a box-drawing report.
func FormatProfile(p *BehaviorProfile) string {
	if p == nil {
		return "No behavior profile.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│            AGENT BEHAVIOR PROFILE                │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Agent:         %-34s │\n", truncate(p.AgentName, 34))
	fmt.Fprintf(&sb, "│ Type:          %-34s │\n", truncate(p.AgentType, 34))
	fmt.Fprintf(&sb, "│ Sample size:   %-34d │\n", p.SampleSize)
	fmt.Fprintf(&sb, "│ Risk baseline: %-34s │\n", fmt.Sprintf("%.2f", p.RiskBaseline))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	sb.WriteString("│ Tool Usage                                       │\n")
	if len(p.ToolUsage) == 0 {
		sb.WriteString("│   (no tool calls observed)                       │\n")
	} else {
		names := make([]string, 0, len(p.ToolUsage))
		for name := range p.ToolUsage {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			s := p.ToolUsage[name]
			fmt.Fprintf(&sb, "│   • %-20s calls:%-5d avg:%-6.2f  │\n",
				truncate(name, 20), s.CallCount, s.AvgCallsPerTrace)
			fmt.Fprintf(&sb, "│       success: %-33s │\n",
				fmt.Sprintf("%.0f%%", s.SuccessRate*100))
		}
	}
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	sb.WriteString("│ Action Patterns                                  │\n")
	if len(p.ActionPatterns) == 0 {
		sb.WriteString("│   (none detected)                                │\n")
	} else {
		for _, pat := range p.ActionPatterns {
			seqStr := strings.Join(pat.Sequence, " -> ")
			fmt.Fprintf(&sb, "│   • %-35s x%-3d %3.0f%% │\n",
				truncate(seqStr, 35), pat.Frequency, pat.Confidence*100)
		}
	}
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	sb.WriteString("│ Time Profile                                     │\n")
	fmt.Fprintf(&sb, "│   Avg events/trace: %-29.2f │\n", p.TimeProfile.AvgEventsPerTrace)
	fmt.Fprintf(&sb, "│   Avg duration:     %-29s │\n", truncate(p.TimeProfile.AvgDuration, 29))
	fmt.Fprintf(&sb, "│   Peak hour:        %02d:00%-24s │\n", p.TimeProfile.PeakHour, "")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	sb.WriteString("│ Boundary Profile                                 │\n")
	fmt.Fprintf(&sb, "│   Unique targets: %-31d │\n", p.BoundaryProfile.UniqueTargets)
	if len(p.BoundaryProfile.CommonDomains) == 0 {
		sb.WriteString("│   (no domains observed)                          │\n")
	} else {
		for _, d := range p.BoundaryProfile.CommonDomains {
			fmt.Fprintf(&sb, "│     • %-43s │\n", truncate(d, 43))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// FormatDeviationReport renders a DeviationReport as a box-drawing report.
func FormatDeviationReport(r *DeviationReport) string {
	if r == nil {
		return "No deviation report.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│           BEHAVIOR DEVIATION REPORT              │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Agent:      %-37s │\n", truncate(r.AgentName, 37))
	fmt.Fprintf(&sb, "│ Risk score: %-37s │\n", fmt.Sprintf("%.2f", r.RiskScore))
	anomalyStr := "no"
	if r.IsAnomaly {
		anomalyStr = "YES"
	}
	fmt.Fprintf(&sb, "│ Anomaly:    %-37s │\n", anomalyStr)
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	if len(r.Deviations) == 0 {
		sb.WriteString("│ ✓ No deviations detected                         │\n")
	} else {
		sb.WriteString("│ Deviations                                       │\n")
		for _, d := range r.Deviations {
			icon := gapIcon(d.Severity)
			fmt.Fprintf(&sb, "│ %s [%-8s] %-28s │\n", icon, truncate(d.Severity, 8), truncate(d.Type, 28))
			for _, line := range wrapText(d.Description, 45) {
				fmt.Fprintf(&sb, "│     %-44s │\n", line)
			}
			if d.Expected != "" || d.Observed != "" {
				fmt.Fprintf(&sb, "│     expected: %-34s │\n", truncate(d.Expected, 34))
				fmt.Fprintf(&sb, "│     observed: %-34s │\n", truncate(d.Observed, 34))
			}
		}
	}

	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ %-49s │\n", truncate(SummarizeDeviations(r), 49))
	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// SummarizeDeviations returns a one-line summary of a DeviationReport.
func SummarizeDeviations(r *DeviationReport) string {
	if r == nil {
		return "No deviation report available."
	}
	if len(r.Deviations) == 0 {
		return fmt.Sprintf("%s: no deviations detected (risk: %.2f).", r.AgentName, r.RiskScore)
	}

	var crit, high int
	for _, d := range r.Deviations {
		switch d.Severity {
		case "critical":
			crit++
		case "high":
			high++
		}
	}

	status := "within normal bounds"
	if r.IsAnomaly {
		status = "ANOMALY"
	}

	return fmt.Sprintf("%s: %d deviations (%d critical, %d high) — risk %.2f — %s.",
		r.AgentName, len(r.Deviations), crit, high, r.RiskScore, status)
}
