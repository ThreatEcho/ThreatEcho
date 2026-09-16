// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package trace provides a trace replay and analysis engine for AI agent
// execution traces. It replays recorded agent actions chronologically,
// detects anomalies (elevated access, rapid calls, prompt injection,
// data exfiltration, privilege escalation), and produces risk-scored
// security analysis suitable for the closed-loop detection pipeline.
package trace

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Anomaly types
// ---------------------------------------------------------------------------

// AnomalyType classifies detected anomalies.
type AnomalyType string

const (
	// AnomalyElevatedTool — elevated tool call without proper context.
	AnomalyElevatedTool AnomalyType = "elevated_tool"
	// AnomalyRapidCalls — too many calls in a short window.
	AnomalyRapidCalls AnomalyType = "rapid_calls"
	// AnomalyUnusualTarget — target not seen in baseline set.
	AnomalyUnusualTarget AnomalyType = "unusual_target"
	// AnomalyTimestampGap — large gap or out-of-order timestamps.
	AnomalyTimestampGap AnomalyType = "timestamp_gap"
	// AnomalyDeniedAction — action that would be denied by policy.
	AnomalyDeniedAction AnomalyType = "denied_action"
	// AnomalyPromptInjection — suspicious prompt content patterns.
	AnomalyPromptInjection AnomalyType = "prompt_injection"
	// AnomalyPrivilegeEscalation — agent acting outside trust level.
	AnomalyPrivilegeEscalation AnomalyType = "privilege_escalation"
	// AnomalyDataExfiltration — patterns suggesting data theft.
	AnomalyDataExfiltration AnomalyType = "data_exfiltration"
)

// Severity constants.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

// Anomaly records a detected issue in the trace.
type Anomaly struct {
	Type        AnomalyType `json:"type"`
	Severity    string      `json:"severity"` // critical, high, medium, low, info
	EventID     string      `json:"event_id"`
	Timestamp   string      `json:"timestamp"`
	Description string      `json:"description"`
	Evidence    string      `json:"evidence,omitempty"`
}

// TimelineEntry is a chronological event in the replay.
type TimelineEntry struct {
	Timestamp string `json:"timestamp"`
	EventID   string `json:"event_id"`
	Type      string `json:"type"`
	Tool      string `json:"tool,omitempty"`
	Action    string `json:"action,omitempty"`
	Target    string `json:"target,omitempty"`
	Elevated  bool   `json:"elevated,omitempty"`
	Summary   string `json:"summary"`
}

// ReplayResult holds the full replay analysis.
type ReplayResult struct {
	TraceID       string          `json:"trace_id"`
	AgentName     string          `json:"agent_name"`
	AgentType     string          `json:"agent_type"`
	Duration      string          `json:"duration"`
	EventCount    int             `json:"event_count"`
	Timeline      []TimelineEntry `json:"timeline"`
	Anomalies     []Anomaly       `json:"anomalies"`
	CriticalCount int             `json:"critical_count"`
	HighCount     int             `json:"high_count"`
	MediumCount   int             `json:"medium_count"`
	LowCount      int             `json:"low_count"`
	RiskScore     float64         `json:"risk_score"` // 0–1
	Summary       string          `json:"summary"`
}

// ReplayConfig controls the replay behaviour.
type ReplayConfig struct {
	MaxRapidCallsWindow   int      // events in a window to trigger rapid_calls (default: 10)
	RapidCallsWindowSec   float64  // window duration in seconds (default: 5)
	CheckPromptInjection  bool     // scan prompt content for injection patterns (default: true)
	CheckDataExfiltration bool     // scan for data exfiltration patterns (default: true)
	BaselineTargets       []string // known-good targets; unlisted ones trigger unusual_target
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// DefaultReplayConfig returns a ReplayConfig with sensible defaults.
func DefaultReplayConfig() *ReplayConfig {
	return &ReplayConfig{
		MaxRapidCallsWindow:   10,
		RapidCallsWindowSec:   5.0,
		CheckPromptInjection:  true,
		CheckDataExfiltration: true,
		BaselineTargets:       nil,
	}
}

// ReplayTrace replays a recorded agent trace and produces a security analysis.
// If cfg is nil, DefaultReplayConfig() is used.
func ReplayTrace(trace *policy.Trace, cfg *ReplayConfig) *ReplayResult {
	if cfg == nil {
		cfg = DefaultReplayConfig()
	}

	result := &ReplayResult{}

	if trace == nil {
		result.Summary = "no trace provided"
		return result
	}

	result.TraceID = trace.ID
	result.AgentName = trace.AgentName
	result.AgentType = trace.AgentType
	result.EventCount = len(trace.Events)
	result.Duration = computeDuration(trace.StartTime, trace.EndTime)

	// Build chronological timeline.
	result.Timeline = buildTimeline(trace)

	// Detect anomalies.
	result.Anomalies = detectAnomalies(trace, result.Timeline, cfg)

	// Score and count.
	result.RiskScore = scoreReplayRisk(result.Anomalies)
	countSeverities(result)

	// Summary.
	result.Summary = SummarizeReplay(result)

	return result
}

// ReplayTraceWithPolicy replays a trace and additionally checks each tool call
// against the supplied policy, generating denied_action anomalies.
func ReplayTraceWithPolicy(trace *policy.Trace, p *policy.Policy, cfg *ReplayConfig) *ReplayResult {
	if cfg == nil {
		cfg = DefaultReplayConfig()
	}

	// Start with the base replay.
	result := ReplayTrace(trace, cfg)

	if trace == nil || p == nil {
		return result
	}

	// Use EvaluateTrace from the policy package and convert violations.
	evalResult := policy.EvaluateTrace(p, trace)
	for _, v := range evalResult.Violations {
		eventID := ""
		ts := ""
		evidence := ""
		if v.Event != nil {
			eventID = v.Event.ID
			ts = v.Event.Timestamp
			evidence = fmt.Sprintf("rule=%s effect=%s tool=%s", v.Rule.ID, v.Effect, v.Tool)
		}

		severity := SeverityMedium
		if v.Effect == "deny" {
			severity = SeverityHigh
		}

		result.Anomalies = append(result.Anomalies, Anomaly{
			Type:        AnomalyDeniedAction,
			Severity:    severity,
			EventID:     eventID,
			Timestamp:   ts,
			Description: v.Reason,
			Evidence:    evidence,
		})
	}

	// Recalculate scores after adding policy anomalies.
	result.RiskScore = scoreReplayRisk(result.Anomalies)
	countSeverities(result)
	result.Summary = SummarizeReplay(result)

	return result
}

// ---------------------------------------------------------------------------
// Timeline construction
// ---------------------------------------------------------------------------

// buildTimeline converts trace events into a chronologically sorted
// slice of TimelineEntry values.
func buildTimeline(trace *policy.Trace) []TimelineEntry {
	if trace == nil || len(trace.Events) == 0 {
		return nil
	}

	entries := make([]TimelineEntry, 0, len(trace.Events))

	for i := range trace.Events {
		ev := &trace.Events[i]
		entry := TimelineEntry{
			Timestamp: ev.Timestamp,
			EventID:   ev.ID,
			Type:      ev.Type,
		}

		switch ev.Type {
		case "tool_call":
			if ev.ToolCall != nil {
				entry.Tool = ev.ToolCall.Tool
				entry.Action = ev.ToolCall.Action
				entry.Target = ev.ToolCall.Target
				entry.Elevated = ev.ToolCall.Elevated
				entry.Summary = fmt.Sprintf("tool_call: %s %s %s",
					ev.ToolCall.Tool, ev.ToolCall.Action, ev.ToolCall.Target)
			} else {
				entry.Summary = "tool_call: (no details)"
			}
		case "prompt":
			if ev.Prompt != nil {
				snippet := truncate(ev.Prompt.Content, 60)
				entry.Summary = fmt.Sprintf("prompt [%s]: %s", ev.Prompt.Role, snippet)
			} else {
				entry.Summary = "prompt: (no details)"
			}
		case "response":
			if ev.Response != nil {
				snippet := truncate(ev.Response.Content, 60)
				entry.Summary = fmt.Sprintf("response: %s", snippet)
			} else {
				entry.Summary = "response: (no details)"
			}
		case "guardrail":
			if ev.Guardrail != nil {
				entry.Summary = fmt.Sprintf("guardrail %s: triggered=%v score=%.2f",
					ev.Guardrail.GuardrailID, ev.Guardrail.Triggered, ev.Guardrail.Score)
			} else {
				entry.Summary = "guardrail: (no details)"
			}
		case "agent_message":
			if ev.AgentMessage != nil {
				snippet := truncate(ev.AgentMessage.Content, 40)
				entry.Summary = fmt.Sprintf("message %s→%s: %s",
					ev.AgentMessage.FromAgent, ev.AgentMessage.ToAgent, snippet)
			} else {
				entry.Summary = "agent_message: (no details)"
			}
		default:
			entry.Summary = fmt.Sprintf("event: %s", ev.Type)
		}

		entries = append(entries, entry)
	}

	// Sort by timestamp (stable to preserve insertion order for identical ts).
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Timestamp < entries[j].Timestamp
	})

	return entries
}

// ---------------------------------------------------------------------------
// Anomaly detection
// ---------------------------------------------------------------------------

// promptInjectionPatterns are substrings whose presence in prompt content is
// suspicious. All comparisons are lower-cased.
var promptInjectionPatterns = []string{
	"ignore previous instructions",
	"ignore all instructions",
	"system prompt",
	"bypass",
	"jailbreak",
	"disregard",
	"override safety",
	"you are now",
	"pretend you are",
	"act as if",
	"forget your instructions",
	"new instructions",
	"reveal your prompt",
}

// dataExfilToolPatterns are tool-name substrings that suggest exfiltration.
var dataExfilToolPatterns = []string{
	"upload",
	"export",
	"send_email",
	"http_request",
	"webhook",
	"ftp",
}

// dataExfilTargetPatterns are target substrings that suggest exfiltration.
var dataExfilTargetPatterns = []string{
	"external",
	"public",
	"pastebin",
	"ngrok",
	"webhook.site",
	"requestbin",
	"burpcollaborator",
}

// detectAnomalies runs all anomaly detection passes over the trace.
func detectAnomalies(trace *policy.Trace, timeline []TimelineEntry, cfg *ReplayConfig) []Anomaly {
	if trace == nil || len(trace.Events) == 0 {
		return nil
	}

	var anomalies []Anomaly

	anomalies = append(anomalies, detectElevatedTools(trace)...)
	anomalies = append(anomalies, detectRapidCalls(trace, cfg)...)
	anomalies = append(anomalies, detectTimestampAnomalies(trace)...)
	anomalies = append(anomalies, detectUnusualTargets(trace, cfg)...)
	anomalies = append(anomalies, detectPrivilegeEscalation(trace)...)

	if cfg.CheckPromptInjection {
		anomalies = append(anomalies, detectPromptInjection(trace)...)
	}
	if cfg.CheckDataExfiltration {
		anomalies = append(anomalies, detectDataExfiltration(trace)...)
	}

	return anomalies
}

// detectElevatedTools flags tool calls with the Elevated flag set.
func detectElevatedTools(trace *policy.Trace) []Anomaly {
	var out []Anomaly
	for i := range trace.Events {
		ev := &trace.Events[i]
		if ev.Type == "tool_call" && ev.ToolCall != nil && ev.ToolCall.Elevated {
			out = append(out, Anomaly{
				Type:      AnomalyElevatedTool,
				Severity:  SeverityHigh,
				EventID:   ev.ID,
				Timestamp: ev.Timestamp,
				Description: fmt.Sprintf("elevated tool call: %s %s on %s",
					ev.ToolCall.Tool, ev.ToolCall.Action, ev.ToolCall.Target),
				Evidence: fmt.Sprintf("tool=%s elevated=true", ev.ToolCall.Tool),
			})
		}
	}
	return out
}

// detectRapidCalls flags bursts of events within a short time window.
func detectRapidCalls(trace *policy.Trace, cfg *ReplayConfig) []Anomaly {
	if len(trace.Events) < cfg.MaxRapidCallsWindow {
		return nil
	}

	// Parse timestamps.
	type tsEntry struct {
		t  time.Time
		ev *policy.TraceEvent
	}
	parsed := make([]tsEntry, 0, len(trace.Events))
	for i := range trace.Events {
		ev := &trace.Events[i]
		t, err := time.Parse(time.RFC3339, ev.Timestamp)
		if err != nil {
			continue
		}
		parsed = append(parsed, tsEntry{t: t, ev: ev})
	}

	sort.Slice(parsed, func(i, j int) bool {
		return parsed[i].t.Before(parsed[j].t)
	})

	windowDur := time.Duration(cfg.RapidCallsWindowSec * float64(time.Second))
	var out []Anomaly

	// Sliding window.
	for i := 0; i <= len(parsed)-cfg.MaxRapidCallsWindow; i++ {
		windowEnd := parsed[i].t.Add(windowDur)
		count := 0
		for j := i; j < len(parsed) && !parsed[j].t.After(windowEnd); j++ {
			count++
		}
		if count >= cfg.MaxRapidCallsWindow {
			out = append(out, Anomaly{
				Type:      AnomalyRapidCalls,
				Severity:  SeverityMedium,
				EventID:   parsed[i].ev.ID,
				Timestamp: parsed[i].ev.Timestamp,
				Description: fmt.Sprintf("%d events in %.1fs window starting at %s",
					count, cfg.RapidCallsWindowSec, parsed[i].ev.Timestamp),
				Evidence: fmt.Sprintf("count=%d window=%.1fs threshold=%d",
					count, cfg.RapidCallsWindowSec, cfg.MaxRapidCallsWindow),
			})
			// Skip ahead to avoid duplicate alerts for overlapping windows.
			i += cfg.MaxRapidCallsWindow - 1
		}
	}

	return out
}

// detectTimestampAnomalies flags gaps >60s or out-of-order timestamps.
func detectTimestampAnomalies(trace *policy.Trace) []Anomaly {
	if len(trace.Events) < 2 {
		return nil
	}

	var out []Anomaly
	var prevTime time.Time
	prevValid := false

	for i := range trace.Events {
		ev := &trace.Events[i]
		t, err := time.Parse(time.RFC3339, ev.Timestamp)
		if err != nil {
			continue
		}
		if prevValid {
			gap := t.Sub(prevTime)

			// Out-of-order.
			if gap < 0 {
				out = append(out, Anomaly{
					Type:        AnomalyTimestampGap,
					Severity:    SeverityMedium,
					EventID:     ev.ID,
					Timestamp:   ev.Timestamp,
					Description: fmt.Sprintf("out-of-order timestamp: jumped back %s", -gap),
					Evidence:    fmt.Sprintf("previous=%s current=%s", prevTime.Format(time.RFC3339), ev.Timestamp),
				})
			}

			// Large gap.
			if gap > 60*time.Second {
				out = append(out, Anomaly{
					Type:        AnomalyTimestampGap,
					Severity:    SeverityLow,
					EventID:     ev.ID,
					Timestamp:   ev.Timestamp,
					Description: fmt.Sprintf("large timestamp gap: %s", gap),
					Evidence:    fmt.Sprintf("previous=%s current=%s gap=%s", prevTime.Format(time.RFC3339), ev.Timestamp, gap),
				})
			}
		}
		prevTime = t
		prevValid = true
	}

	return out
}

// detectUnusualTargets flags tool-call targets not present in the baseline set.
func detectUnusualTargets(trace *policy.Trace, cfg *ReplayConfig) []Anomaly {
	if len(cfg.BaselineTargets) == 0 {
		return nil
	}

	baselineSet := make(map[string]bool, len(cfg.BaselineTargets))
	for _, t := range cfg.BaselineTargets {
		baselineSet[t] = true
	}

	var out []Anomaly
	for i := range trace.Events {
		ev := &trace.Events[i]
		if ev.Type != "tool_call" || ev.ToolCall == nil || ev.ToolCall.Target == "" {
			continue
		}
		if !baselineSet[ev.ToolCall.Target] {
			out = append(out, Anomaly{
				Type:        AnomalyUnusualTarget,
				Severity:    SeverityMedium,
				EventID:     ev.ID,
				Timestamp:   ev.Timestamp,
				Description: fmt.Sprintf("target %q not in baseline", ev.ToolCall.Target),
				Evidence:    fmt.Sprintf("tool=%s target=%s", ev.ToolCall.Tool, ev.ToolCall.Target),
			})
		}
	}

	return out
}

// detectPromptInjection scans prompt events for injection-like content.
func detectPromptInjection(trace *policy.Trace) []Anomaly {
	var out []Anomaly
	for i := range trace.Events {
		ev := &trace.Events[i]
		if ev.Type != "prompt" || ev.Prompt == nil {
			continue
		}
		lower := strings.ToLower(ev.Prompt.Content)
		for _, pattern := range promptInjectionPatterns {
			if strings.Contains(lower, pattern) {
				out = append(out, Anomaly{
					Type:        AnomalyPromptInjection,
					Severity:    SeverityCritical,
					EventID:     ev.ID,
					Timestamp:   ev.Timestamp,
					Description: fmt.Sprintf("prompt injection pattern detected: %q", pattern),
					Evidence:    fmt.Sprintf("role=%s pattern=%q", ev.Prompt.Role, pattern),
				})
				break // one anomaly per event
			}
		}
	}
	return out
}

// detectDataExfiltration scans tool calls for exfiltration indicators.
func detectDataExfiltration(trace *policy.Trace) []Anomaly {
	var out []Anomaly
	for i := range trace.Events {
		ev := &trace.Events[i]
		if ev.Type != "tool_call" || ev.ToolCall == nil {
			continue
		}
		tc := ev.ToolCall
		toolLower := strings.ToLower(tc.Tool)
		targetLower := strings.ToLower(tc.Target)

		// Check tool name patterns.
		toolMatch := ""
		for _, p := range dataExfilToolPatterns {
			if strings.Contains(toolLower, p) {
				toolMatch = p
				break
			}
		}

		// Check target patterns.
		targetMatch := ""
		for _, p := range dataExfilTargetPatterns {
			if strings.Contains(targetLower, p) {
				targetMatch = p
				break
			}
		}

		// Flag if both tool and target match, or if the target alone is strongly suspicious.
		if toolMatch != "" && targetMatch != "" {
			out = append(out, Anomaly{
				Type:      AnomalyDataExfiltration,
				Severity:  SeverityCritical,
				EventID:   ev.ID,
				Timestamp: ev.Timestamp,
				Description: fmt.Sprintf("potential data exfiltration: %s to %s",
					tc.Tool, tc.Target),
				Evidence: fmt.Sprintf("tool_pattern=%q target_pattern=%q", toolMatch, targetMatch),
			})
		} else if targetMatch != "" {
			out = append(out, Anomaly{
				Type:      AnomalyDataExfiltration,
				Severity:  SeverityHigh,
				EventID:   ev.ID,
				Timestamp: ev.Timestamp,
				Description: fmt.Sprintf("suspicious target for tool %s: %s",
					tc.Tool, tc.Target),
				Evidence: fmt.Sprintf("target_pattern=%q", targetMatch),
			})
		}
	}
	return out
}

// detectPrivilegeEscalation looks for agents acting outside their trust level.
// Heuristic: orchestrator agents calling elevated tools or non-orchestrator
// agents sending inter-agent messages both raise flags.
func detectPrivilegeEscalation(trace *policy.Trace) []Anomaly {
	var out []Anomaly

	for i := range trace.Events {
		ev := &trace.Events[i]

		// A tool-type agent issuing elevated calls is suspicious.
		if trace.AgentType == "tool" && ev.Type == "tool_call" && ev.ToolCall != nil && ev.ToolCall.Elevated {
			out = append(out, Anomaly{
				Type:      AnomalyPrivilegeEscalation,
				Severity:  SeverityCritical,
				EventID:   ev.ID,
				Timestamp: ev.Timestamp,
				Description: fmt.Sprintf("tool-type agent %q made elevated call to %s",
					trace.AgentName, ev.ToolCall.Tool),
				Evidence: fmt.Sprintf("agent_type=%s tool=%s elevated=true", trace.AgentType, ev.ToolCall.Tool),
			})
		}

		// A retrieval-type agent sending inter-agent messages is unusual.
		if trace.AgentType == "retrieval" && ev.Type == "agent_message" && ev.AgentMessage != nil {
			out = append(out, Anomaly{
				Type:      AnomalyPrivilegeEscalation,
				Severity:  SeverityHigh,
				EventID:   ev.ID,
				Timestamp: ev.Timestamp,
				Description: fmt.Sprintf("retrieval agent %q sent message to %s",
					trace.AgentName, ev.AgentMessage.ToAgent),
				Evidence: fmt.Sprintf("agent_type=%s from=%s to=%s",
					trace.AgentType, ev.AgentMessage.FromAgent, ev.AgentMessage.ToAgent),
			})
		}
	}

	return out
}

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

// Risk weight per severity level.
const (
	weightCritical = 0.25
	weightHigh     = 0.15
	weightMedium   = 0.08
	weightLow      = 0.03
)

// scoreReplayRisk computes a 0–1 risk score from the anomaly list.
// The score is capped at 1.0.
func scoreReplayRisk(anomalies []Anomaly) float64 {
	if len(anomalies) == 0 {
		return 0
	}

	var score float64
	for _, a := range anomalies {
		switch a.Severity {
		case SeverityCritical:
			score += weightCritical
		case SeverityHigh:
			score += weightHigh
		case SeverityMedium:
			score += weightMedium
		case SeverityLow:
			score += weightLow
		}
	}

	return math.Min(score, 1.0)
}

// countSeverities populates the severity counters on a ReplayResult.
func countSeverities(r *ReplayResult) {
	r.CriticalCount = 0
	r.HighCount = 0
	r.MediumCount = 0
	r.LowCount = 0
	for _, a := range r.Anomalies {
		switch a.Severity {
		case SeverityCritical:
			r.CriticalCount++
		case SeverityHigh:
			r.HighCount++
		case SeverityMedium:
			r.MediumCount++
		case SeverityLow:
			r.LowCount++
		}
	}
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatReplayResult returns a box-drawing formatted report of the replay.
func FormatReplayResult(r *ReplayResult) string {
	if r == nil {
		return "No replay result.\n"
	}

	var b strings.Builder

	b.WriteString("┌───────────────────────────────────────────────────────┐\n")
	b.WriteString("│              Trace Replay Analysis                    │\n")
	b.WriteString("├───────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Trace:     %-43s │\n", trunc(r.TraceID, 43)))
	b.WriteString(fmt.Sprintf("│ Agent:     %-43s │\n", trunc(r.AgentName, 43)))
	b.WriteString(fmt.Sprintf("│ Type:      %-43s │\n", trunc(r.AgentType, 43)))
	b.WriteString(fmt.Sprintf("│ Duration:  %-43s │\n", trunc(r.Duration, 43)))
	b.WriteString(fmt.Sprintf("│ Events:    %-43d │\n", r.EventCount))
	b.WriteString("├───────────────────────────────────────────────────────┤\n")

	// Risk score.
	riskLabel := "LOW"
	if r.RiskScore >= 0.7 {
		riskLabel = "CRITICAL"
	} else if r.RiskScore >= 0.4 {
		riskLabel = "HIGH"
	} else if r.RiskScore >= 0.2 {
		riskLabel = "MEDIUM"
	}
	b.WriteString(fmt.Sprintf("│ Risk:      %-6s (%.2f)                              │\n", riskLabel, r.RiskScore))
	b.WriteString(fmt.Sprintf("│ Critical:  %-3d  High: %-3d  Medium: %-3d  Low: %-3d      │\n",
		r.CriticalCount, r.HighCount, r.MediumCount, r.LowCount))
	b.WriteString("├───────────────────────────────────────────────────────┤\n")

	// Anomalies.
	if len(r.Anomalies) == 0 {
		b.WriteString("│ No anomalies detected                                 │\n")
	} else {
		b.WriteString("│ Anomalies:                                            │\n")
		b.WriteString("├───────────────────────────────────────────────────────┤\n")
		for i, a := range r.Anomalies {
			sev := strings.ToUpper(a.Severity)
			b.WriteString(fmt.Sprintf("│ %2d. [%-8s] %-8s %s\n",
				i+1, sev, a.Type, trunc(a.Description, 30)))
			if a.Evidence != "" {
				b.WriteString(fmt.Sprintf("│     evidence: %s\n", trunc(a.Evidence, 40)))
			}
		}
	}

	b.WriteString("├───────────────────────────────────────────────────────┤\n")

	// Timeline (first 20 entries).
	maxTimeline := 20
	if len(r.Timeline) > 0 {
		b.WriteString("│ Timeline:                                             │\n")
		b.WriteString("├───────────────────────────────────────────────────────┤\n")
		shown := len(r.Timeline)
		if shown > maxTimeline {
			shown = maxTimeline
		}
		for i := 0; i < shown; i++ {
			te := r.Timeline[i]
			ts := trunc(te.Timestamp, 19)
			b.WriteString(fmt.Sprintf("│  %s  %-45s\n", ts, trunc(te.Summary, 45)))
		}
		if len(r.Timeline) > maxTimeline {
			b.WriteString(fmt.Sprintf("│  ... and %d more events\n", len(r.Timeline)-maxTimeline))
		}
	}

	b.WriteString("└───────────────────────────────────────────────────────┘\n")
	return b.String()
}

// SummarizeReplay returns a one-line summary of the replay result.
func SummarizeReplay(r *ReplayResult) string {
	if r == nil {
		return "no result"
	}

	total := len(r.Anomalies)
	if total == 0 {
		return fmt.Sprintf("trace %s: %d events, no anomalies, risk=0.00",
			r.TraceID, r.EventCount)
	}

	return fmt.Sprintf("trace %s: %d events, %d anomalies (%d critical, %d high), risk=%.2f",
		r.TraceID, r.EventCount, total, r.CriticalCount, r.HighCount, r.RiskScore)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// computeDuration returns the elapsed time between two ISO 8601 timestamps
// as a human-readable string. Returns "unknown" on parse errors.
func computeDuration(start, end string) string {
	s, err1 := time.Parse(time.RFC3339, start)
	e, err2 := time.Parse(time.RFC3339, end)
	if err1 != nil || err2 != nil {
		return "unknown"
	}
	d := e.Sub(s)
	if d < 0 {
		return "unknown"
	}
	return d.String()
}

// trunc truncates a string to maxLen, adding "..." if truncated.
func trunc(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// truncate is an alias for trunc used in timeline summaries.
func truncate(s string, maxLen int) string {
	return trunc(s, maxLen)
}
