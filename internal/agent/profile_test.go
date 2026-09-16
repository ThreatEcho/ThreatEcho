// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// helpers — prefixed mkProfile to avoid clashing with other test files
// ---------------------------------------------------------------------------

func mkProfileTrace(agent, agentType string, events []policy.TraceEvent) *policy.Trace {
	return &policy.Trace{
		ID:        "tr-" + agent,
		AgentName: agent,
		AgentType: agentType,
		StartTime: "2026-01-15T10:00:00Z",
		EndTime:   "2026-01-15T10:05:00Z",
		Events:    events,
	}
}

func mkProfileEvent(tool, action, target string, success bool) policy.TraceEvent {
	return policy.TraceEvent{
		ID:        "ev-" + tool,
		Timestamp: "2026-01-15T10:01:00Z",
		Type:      "tool_call",
		ToolCall: &policy.ToolCallEvent{
			Tool:    tool,
			Action:  action,
			Target:  target,
			Success: success,
		},
	}
}

func mkProfileEventTimed(tool, action, target, ts string, success bool) policy.TraceEvent {
	return policy.TraceEvent{
		ID:        "ev-" + tool + "-" + ts,
		Timestamp: ts,
		Type:      "tool_call",
		ToolCall: &policy.ToolCallEvent{
			Tool:    tool,
			Action:  action,
			Target:  target,
			Success: success,
		},
	}
}

// ---------------------------------------------------------------------------
// DefaultDeviationThreshold
// ---------------------------------------------------------------------------

func TestDefaultDeviationThreshold(t *testing.T) {
	t.Parallel()
	th := DefaultDeviationThreshold()
	if th < 0 || th > 1 {
		t.Errorf("threshold should be in [0,1], got %f", th)
	}
	if th != 0.6 {
		t.Errorf("expected 0.6, got %f", th)
	}
}

// ---------------------------------------------------------------------------
// BuildProfile
// ---------------------------------------------------------------------------

func TestBuildProfile_NilTraces(t *testing.T) {
	t.Parallel()
	p := BuildProfile("agent-a", nil)
	if p == nil {
		t.Fatal("profile should not be nil")
	}
	if p.SampleSize != 0 {
		t.Errorf("expected 0 samples, got %d", p.SampleSize)
	}
	if p.AgentName != "agent-a" {
		t.Errorf("expected agent-a, got %s", p.AgentName)
	}
}

func TestBuildProfile_EmptyTraces(t *testing.T) {
	t.Parallel()
	p := BuildProfile("agent-b", []*policy.Trace{})
	if p == nil {
		t.Fatal("profile should not be nil")
	}
	if p.SampleSize != 0 {
		t.Errorf("expected 0 samples, got %d", p.SampleSize)
	}
}

func TestBuildProfile_SingleTrace(t *testing.T) {
	t.Parallel()
	tr := mkProfileTrace("agent-c", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "https://api.example.com/data", true),
		mkProfileEvent("database_query", "read", "db://users", true),
	})
	p := BuildProfile("agent-c", []*policy.Trace{tr})
	if p.SampleSize != 1 {
		t.Errorf("expected 1 sample, got %d", p.SampleSize)
	}
	if len(p.ToolUsage) != 2 {
		t.Errorf("expected 2 tools, got %d", len(p.ToolUsage))
	}
	if _, ok := p.ToolUsage["http_request"]; !ok {
		t.Error("expected http_request in tool usage")
	}
}

func TestBuildProfile_MultipleTraces(t *testing.T) {
	t.Parallel()
	tr1 := mkProfileTrace("agent-d", "retrieval", []policy.TraceEvent{
		mkProfileEvent("document_search", "search", "docs://wiki", true),
	})
	tr2 := mkProfileTrace("agent-d", "retrieval", []policy.TraceEvent{
		mkProfileEvent("document_search", "search", "docs://kb", true),
		mkProfileEvent("http_request", "send", "https://api.example.com", true),
	})
	p := BuildProfile("agent-d", []*policy.Trace{tr1, tr2})
	if p.SampleSize != 2 {
		t.Errorf("expected 2 samples, got %d", p.SampleSize)
	}
	if stats, ok := p.ToolUsage["document_search"]; ok {
		if stats.CallCount != 2 {
			t.Errorf("expected 2 calls for document_search, got %d", stats.CallCount)
		}
	} else {
		t.Error("expected document_search in tool usage")
	}
}

func TestBuildProfile_FiltersOtherAgents(t *testing.T) {
	t.Parallel()
	tr1 := mkProfileTrace("agent-e", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("shell_exec", "execute", "", true),
	})
	tr2 := mkProfileTrace("other-agent", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "https://evil.com", true),
	})
	p := BuildProfile("agent-e", []*policy.Trace{tr1, tr2})
	if p.SampleSize != 1 {
		t.Errorf("expected 1 sample (filtered other-agent), got %d", p.SampleSize)
	}
	if _, ok := p.ToolUsage["http_request"]; ok {
		t.Error("http_request from other agent should not be in profile")
	}
}

func TestBuildProfile_ToolStats(t *testing.T) {
	t.Parallel()
	tr := mkProfileTrace("agent-f", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "https://api.example.com", true),
		mkProfileEvent("http_request", "send", "https://api.example.com", true),
		mkProfileEvent("http_request", "send", "https://api.example.com", false),
	})
	p := BuildProfile("agent-f", []*policy.Trace{tr})
	stats := p.ToolUsage["http_request"]
	if stats.CallCount != 3 {
		t.Errorf("expected 3 calls, got %d", stats.CallCount)
	}
	// Success rate: 2/3
	if stats.SuccessRate < 0.6 || stats.SuccessRate > 0.7 {
		t.Errorf("expected ~0.667 success rate, got %f", stats.SuccessRate)
	}
}

func TestBuildProfile_NoToolCalls(t *testing.T) {
	t.Parallel()
	tr := mkProfileTrace("agent-g", "conversational", []policy.TraceEvent{
		{ID: "ev-1", Timestamp: "2026-01-15T10:01:00Z", Type: "message"},
	})
	p := BuildProfile("agent-g", []*policy.Trace{tr})
	if p.SampleSize != 1 {
		t.Errorf("expected 1 sample, got %d", p.SampleSize)
	}
	if len(p.ToolUsage) != 0 {
		t.Errorf("expected 0 tools, got %d", len(p.ToolUsage))
	}
}

func TestBuildProfile_ActionPatterns(t *testing.T) {
	t.Parallel()
	events := []policy.TraceEvent{
		mkProfileEventTimed("http_request", "send", "https://api.example.com", "2026-01-15T10:01:00Z", true),
		mkProfileEventTimed("database_query", "write", "db://logs", "2026-01-15T10:02:00Z", true),
	}
	tr1 := mkProfileTrace("agent-h", "tool-calling", events)
	tr2 := mkProfileTrace("agent-h", "tool-calling", events)
	p := BuildProfile("agent-h", []*policy.Trace{tr1, tr2})
	if len(p.ActionPatterns) == 0 {
		t.Error("expected at least one action pattern from repeated sequences")
	}
}

func TestBuildProfile_TimeStats(t *testing.T) {
	t.Parallel()
	tr := mkProfileTrace("agent-i", "tool-calling", []policy.TraceEvent{
		mkProfileEventTimed("http_request", "send", "", "2026-01-15T10:01:00Z", true),
		mkProfileEventTimed("http_request", "send", "", "2026-01-15T10:02:00Z", true),
		mkProfileEventTimed("http_request", "send", "", "2026-01-15T10:03:00Z", true),
	})
	p := BuildProfile("agent-i", []*policy.Trace{tr})
	if p.TimeProfile.AvgEventsPerTrace != 3 {
		t.Errorf("expected 3 avg events, got %f", p.TimeProfile.AvgEventsPerTrace)
	}
}

func TestBuildProfile_BoundaryStats(t *testing.T) {
	t.Parallel()
	tr := mkProfileTrace("agent-j", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "https://api.example.com/v1", true),
		mkProfileEvent("http_request", "send", "https://api.example.com/v2", true),
		mkProfileEvent("http_request", "send", "https://other.example.com/data", true),
	})
	p := BuildProfile("agent-j", []*policy.Trace{tr})
	if p.BoundaryProfile.UniqueTargets < 2 {
		t.Errorf("expected at least 2 unique targets, got %d", p.BoundaryProfile.UniqueTargets)
	}
}

func TestBuildProfile_RiskBaseline(t *testing.T) {
	t.Parallel()
	tr := mkProfileTrace("agent-k", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "", true),
	})
	p := BuildProfile("agent-k", []*policy.Trace{tr})
	if p.RiskBaseline < 0 || p.RiskBaseline > 1 {
		t.Errorf("risk baseline should be in [0,1], got %f", p.RiskBaseline)
	}
}

// ---------------------------------------------------------------------------
// DetectDeviations
// ---------------------------------------------------------------------------

func TestDetectDeviations_NilProfile(t *testing.T) {
	t.Parallel()
	tr := mkProfileTrace("agent-l", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "", true),
	})
	r := DetectDeviations(nil, tr)
	if r == nil {
		t.Fatal("report should not be nil for nil profile")
	}
}

func TestDetectDeviations_NilTrace(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName: "agent-m",
		ToolUsage: map[string]ToolStats{},
	}
	r := DetectDeviations(profile, nil)
	if r == nil {
		t.Fatal("report should not be nil for nil trace")
	}
}

func TestDetectDeviations_CleanTrace(t *testing.T) {
	t.Parallel()
	events := []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "https://api.example.com", true),
	}
	tr := mkProfileTrace("agent-n", "tool-calling", events)
	profile := BuildProfile("agent-n", []*policy.Trace{tr})
	r := DetectDeviations(profile, tr)
	if r.IsAnomaly {
		t.Errorf("same trace should not be anomalous, risk=%f", r.RiskScore)
	}
}

func TestDetectDeviations_NewTool(t *testing.T) {
	t.Parallel()
	tr1 := mkProfileTrace("agent-o", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "", true),
	})
	profile := BuildProfile("agent-o", []*policy.Trace{tr1})

	tr2 := mkProfileTrace("agent-o", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("shell_exec", "execute", "", true),
	})
	r := DetectDeviations(profile, tr2)
	found := false
	for _, d := range r.Deviations {
		if d.Type == DeviationNewTool {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected new_tool deviation for shell_exec")
	}
}

func TestDetectDeviations_FrequencySpike(t *testing.T) {
	t.Parallel()
	tr1 := mkProfileTrace("agent-p", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "", true),
	})
	profile := BuildProfile("agent-p", []*policy.Trace{tr1})

	many := make([]policy.TraceEvent, 10)
	for i := range many {
		many[i] = mkProfileEvent("http_request", "send", "", true)
	}
	tr2 := mkProfileTrace("agent-p", "tool-calling", many)
	r := DetectDeviations(profile, tr2)
	found := false
	for _, d := range r.Deviations {
		if d.Type == DeviationFrequencySpike {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected frequency_spike deviation for 10x burst")
	}
}

func TestDetectDeviations_UnusualTarget(t *testing.T) {
	t.Parallel()
	tr1 := mkProfileTrace("agent-q", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "https://api.example.com", true),
	})
	profile := BuildProfile("agent-q", []*policy.Trace{tr1})

	tr2 := mkProfileTrace("agent-q", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "https://evil.attacker.com", true),
	})
	r := DetectDeviations(profile, tr2)
	found := false
	for _, d := range r.Deviations {
		if d.Type == DeviationUnusualTarget {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected unusual_target deviation for new domain")
	}
}

func TestDetectDeviations_RiskScore(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName: "agent-r",
		ToolUsage: map[string]ToolStats{},
	}
	tr := mkProfileTrace("agent-r", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("shell_exec", "execute", "", true),
		mkProfileEvent("code_exec", "run", "", true),
	})
	r := DetectDeviations(profile, tr)
	if r.RiskScore < 0 || r.RiskScore > 1 {
		t.Errorf("risk score should be in [0,1], got %f", r.RiskScore)
	}
}

func TestDetectDeviations_SeverityLevels(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName: "agent-t",
		ToolUsage: map[string]ToolStats{},
	}
	tr := mkProfileTrace("agent-t", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("shell_exec", "execute", "", true),
	})
	r := DetectDeviations(profile, tr)
	for _, d := range r.Deviations {
		switch d.Severity {
		case "critical", "high", "medium", "low", "info":
			// Valid.
		default:
			t.Errorf("unexpected severity %q", d.Severity)
		}
	}
}

// ---------------------------------------------------------------------------
// Format functions
// ---------------------------------------------------------------------------

func TestFormatProfile_NonNil(t *testing.T) {
	t.Parallel()
	tr := mkProfileTrace("format-agent", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "https://api.example.com", true),
	})
	p := BuildProfile("format-agent", []*policy.Trace{tr})
	out := FormatProfile(p)
	if out == "" {
		t.Error("format output should not be empty")
	}
	if !strings.Contains(out, "format-agent") {
		t.Errorf("output should contain agent name")
	}
}

func TestFormatProfile_NilProfile(t *testing.T) {
	t.Parallel()
	out := FormatProfile(nil)
	if out == "" {
		t.Error("should return non-empty string for nil profile")
	}
}

func TestFormatDeviationReport_NonNil(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName: "dev-agent",
		ToolUsage: map[string]ToolStats{},
	}
	tr := mkProfileTrace("dev-agent", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("shell_exec", "execute", "", true),
	})
	r := DetectDeviations(profile, tr)
	out := FormatDeviationReport(r)
	if out == "" {
		t.Error("format output should not be empty")
	}
}

func TestFormatDeviationReport_Nil(t *testing.T) {
	t.Parallel()
	out := FormatDeviationReport(nil)
	if out == "" {
		t.Error("should return non-empty string for nil report")
	}
}

func TestSummarizeDeviations_Basic(t *testing.T) {
	t.Parallel()
	r := &DeviationReport{
		AgentName:  "sum-agent",
		Deviations: []ProfileDeviation{{Type: "new_tool", Severity: "high"}},
		RiskScore:  0.5,
	}
	s := SummarizeDeviations(r)
	if s == "" {
		t.Error("summary should not be empty")
	}
}

func TestSummarizeDeviations_Nil(t *testing.T) {
	t.Parallel()
	s := SummarizeDeviations(nil)
	if s == "" {
		t.Error("should return non-empty string for nil report")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestBuildProfile_EmptyAgentName(t *testing.T) {
	t.Parallel()
	tr := mkProfileTrace("", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("http_request", "send", "", true),
	})
	p := BuildProfile("", []*policy.Trace{tr})
	if p.SampleSize < 1 {
		t.Errorf("expected at least 1 sample, got %d", p.SampleSize)
	}
}

func TestBuildProfile_NilTraceInSlice(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		nil,
		mkProfileTrace("agent-u", "tool-calling", []policy.TraceEvent{
			mkProfileEvent("http_request", "send", "", true),
		}),
		nil,
	}
	p := BuildProfile("agent-u", traces)
	if p.SampleSize != 1 {
		t.Errorf("expected 1 sample (skipping nils), got %d", p.SampleSize)
	}
}

func TestBuildProfile_TracesWithNoEvents(t *testing.T) {
	t.Parallel()
	tr := mkProfileTrace("agent-v", "tool-calling", nil)
	p := BuildProfile("agent-v", []*policy.Trace{tr})
	if p.SampleSize != 1 {
		t.Errorf("expected 1 sample, got %d", p.SampleSize)
	}
	if len(p.ToolUsage) != 0 {
		t.Errorf("expected 0 tools, got %d", len(p.ToolUsage))
	}
}

// ---------------------------------------------------------------------------
// Additional deviation-type tests
// ---------------------------------------------------------------------------

func TestDetectDeviations_TimingAnomalyDuration(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName:   "agent-timing",
		SampleSize:  5,
		ToolUsage:   map[string]ToolStats{},
		TimeProfile: TimeStats{AvgEventsPerTrace: 2, AvgDuration: "5m0s", PeakHour: 10},
	}
	// Trace lasts 1h vs baseline 5m → ratio = 12 → deviation.
	tr := &policy.Trace{
		ID:        "tr-timing",
		AgentName: "agent-timing",
		StartTime: "2026-01-15T10:00:00Z",
		EndTime:   "2026-01-15T11:00:00Z",
		Events: []policy.TraceEvent{
			mkProfileEventTimed("tool-a", "exec", "", "2026-01-15T10:00:00Z", true),
		},
	}
	r := DetectDeviations(profile, tr)
	found := false
	for _, d := range r.Deviations {
		if d.Type == DeviationTimingAnomaly && strings.Contains(d.Description, "duration") {
			found = true
		}
	}
	if !found {
		t.Error("expected timing_anomaly deviation for extreme duration")
	}
}

func TestDetectDeviations_TimingAnomalyPeakHour(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName:   "agent-peak",
		SampleSize:  5,
		ToolUsage:   map[string]ToolStats{},
		TimeProfile: TimeStats{AvgEventsPerTrace: 2, AvgDuration: "5m0s", PeakHour: 10},
	}
	// Events at 22:00 vs baseline peak 10:00 → distance = 12 → deviation.
	tr := &policy.Trace{
		ID:        "tr-peak",
		AgentName: "agent-peak",
		StartTime: "2026-01-15T22:00:00Z",
		EndTime:   "2026-01-15T22:05:00Z",
		Events: []policy.TraceEvent{
			mkProfileEventTimed("tool-a", "exec", "", "2026-01-15T22:00:00Z", true),
			mkProfileEventTimed("tool-b", "exec", "", "2026-01-15T22:02:00Z", true),
		},
	}
	r := DetectDeviations(profile, tr)
	found := false
	for _, d := range r.Deviations {
		if d.Type == DeviationTimingAnomaly && strings.Contains(d.Description, "peaked") {
			found = true
		}
	}
	if !found {
		t.Error("expected timing_anomaly deviation for peak-hour shift")
	}
}

func TestDetectDeviations_PatternBreak(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName:  "agent-pat",
		SampleSize: 5,
		ToolUsage:  map[string]ToolStats{},
		ActionPatterns: []ActionPattern{
			{Sequence: []string{"auth", "query"}, Frequency: 8, Confidence: 0.5},
			{Sequence: []string{"query", "report"}, Frequency: 6, Confidence: 0.3},
		},
	}
	// Trace with completely different sequence → pattern break.
	tr := mkProfileTrace("agent-pat", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("delete", "execute", "", true),
		mkProfileEvent("purge", "execute", "", true),
	})
	r := DetectDeviations(profile, tr)
	found := false
	for _, d := range r.Deviations {
		if d.Type == DeviationPatternBreak {
			found = true
		}
	}
	if !found {
		t.Error("expected pattern_break deviation")
	}
}

func TestDetectDeviations_PatternMatchNoBreak(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName:  "agent-pat2",
		SampleSize: 5,
		ToolUsage: map[string]ToolStats{
			"auth":  {CallCount: 10, AvgCallsPerTrace: 2},
			"query": {CallCount: 10, AvgCallsPerTrace: 2},
		},
		ActionPatterns: []ActionPattern{
			{Sequence: []string{"auth", "query"}, Frequency: 8, Confidence: 0.5},
		},
	}
	tr := mkProfileTrace("agent-pat2", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("auth", "execute", "", true),
		mkProfileEvent("query", "execute", "", true),
	})
	r := DetectDeviations(profile, tr)
	for _, d := range r.Deviations {
		if d.Type == DeviationPatternBreak {
			t.Error("should not report pattern_break when known pattern is present")
		}
	}
}

func TestDetectDeviations_BoundaryExpansion(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName:       "agent-bound",
		SampleSize:      5,
		ToolUsage:       map[string]ToolStats{},
		BoundaryProfile: BoundaryStats{UniqueTargets: 1, CommonDomains: []string{"api.example.com"}},
	}
	tr := mkProfileTrace("agent-bound", "tool-calling", []policy.TraceEvent{
		mkProfileEvent("web_fetch", "query", "https://evil.com/data", true),
	})
	r := DetectDeviations(profile, tr)
	found := false
	for _, d := range r.Deviations {
		if d.Type == DeviationBoundaryExpand {
			found = true
		}
	}
	if !found {
		t.Error("expected boundary_expansion deviation")
	}
}

func TestDetectDeviations_RiskElevation(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName:    "agent-risk",
		SampleSize:   10,
		ToolUsage:    map[string]ToolStats{},
		RiskBaseline: 0.0,
	}
	// All elevated + all failed → risk ≈ 1.0 → delta from 0 triggers.
	tr := mkProfileTrace("agent-risk", "tool-calling", []policy.TraceEvent{
		{ID: "ev-1", Timestamp: "2026-01-15T10:01:00Z", Type: "tool_call",
			ToolCall: &policy.ToolCallEvent{Tool: "shell", Action: "exec", Success: false, Elevated: true}},
		{ID: "ev-2", Timestamp: "2026-01-15T10:02:00Z", Type: "tool_call",
			ToolCall: &policy.ToolCallEvent{Tool: "admin", Action: "exec", Success: false, Elevated: true}},
	})
	r := DetectDeviations(profile, tr)
	found := false
	for _, d := range r.Deviations {
		if d.Type == DeviationRiskElevation {
			found = true
		}
	}
	if !found {
		t.Error("expected risk_elevation deviation")
	}
}

func TestDetectDeviations_SortedDescendingScore(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName:  "agent-sort",
		SampleSize: 5,
		ToolUsage: map[string]ToolStats{
			"file_read": {CallCount: 10, AvgCallsPerTrace: 2, CommonTargets: []string{"known"}},
		},
		RiskBaseline: 0.0,
	}
	tr := mkProfileTrace("agent-sort", "tool-calling", []policy.TraceEvent{
		{ID: "ev-1", Timestamp: "2026-01-15T10:01:00Z", Type: "tool_call",
			ToolCall: &policy.ToolCallEvent{Tool: "new_dangerous", Action: "exec", Success: false, Elevated: true}},
		mkProfileEvent("file_read", "read", "unusual-target", false),
	})
	r := DetectDeviations(profile, tr)
	if len(r.Deviations) < 2 {
		t.Skipf("need at least 2 deviations, got %d", len(r.Deviations))
	}
	for i := 1; i < len(r.Deviations); i++ {
		if r.Deviations[i].Score > r.Deviations[i-1].Score {
			t.Errorf("deviations not sorted by score desc: [%d]=%.2f > [%d]=%.2f",
				i, r.Deviations[i].Score, i-1, r.Deviations[i-1].Score)
		}
	}
}

func TestDetectDeviations_AnomalyFlagTrue(t *testing.T) {
	t.Parallel()
	profile := &BehaviorProfile{
		AgentName:    "agent-anom",
		SampleSize:   10,
		ToolUsage:    map[string]ToolStats{},
		RiskBaseline: 0.0,
	}
	tr := mkProfileTrace("agent-anom", "tool-calling", []policy.TraceEvent{
		{ID: "ev-1", Timestamp: "2026-01-15T10:01:00Z", Type: "tool_call",
			ToolCall: &policy.ToolCallEvent{Tool: "bad-1", Action: "exec", Success: false, Elevated: true}},
		{ID: "ev-2", Timestamp: "2026-01-15T10:02:00Z", Type: "tool_call",
			ToolCall: &policy.ToolCallEvent{Tool: "bad-2", Action: "exec", Success: false, Elevated: true}},
	})
	r := DetectDeviations(profile, tr)
	if !r.IsAnomaly {
		t.Errorf("expected IsAnomaly=true, risk=%.2f (threshold %.2f)",
			r.RiskScore, DefaultDeviationThreshold())
	}
}

func TestFormatProfile_ContainsSections(t *testing.T) {
	t.Parallel()
	p := &BehaviorProfile{
		AgentName:  "section-agent",
		AgentType:  "llm",
		SampleSize: 3,
		ToolUsage: map[string]ToolStats{
			"web_fetch": {CallCount: 6, AvgCallsPerTrace: 2.0, SuccessRate: 0.9},
		},
		ActionPatterns: []ActionPattern{
			{Sequence: []string{"auth", "query"}, Frequency: 3, Confidence: 0.5},
		},
		TimeProfile:     TimeStats{AvgEventsPerTrace: 4, AvgDuration: "5m0s", PeakHour: 14},
		BoundaryProfile: BoundaryStats{UniqueTargets: 2, CommonDomains: []string{"api.example.com"}},
		RiskBaseline:    0.1,
	}
	out := FormatProfile(p)
	for _, want := range []string{
		"AGENT BEHAVIOR PROFILE", "section-agent", "llm", "Tool Usage",
		"web_fetch", "Action Patterns", "Time Profile", "Boundary Profile",
		"api.example.com",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatProfile missing %q", want)
		}
	}
}

func TestFormatDeviationReport_WithDeviations(t *testing.T) {
	t.Parallel()
	r := &DeviationReport{
		AgentName: "dev-report-agent",
		Deviations: []ProfileDeviation{
			{Type: DeviationNewTool, Severity: "high", Description: "used shell_exec", Score: 0.8, Tool: "shell_exec"},
		},
		RiskScore: 0.65,
		IsAnomaly: true,
	}
	out := FormatDeviationReport(r)
	if !strings.Contains(out, "BEHAVIOR DEVIATION REPORT") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "YES") {
		t.Error("expected Anomaly YES")
	}
}

func TestSummarizeDeviations_WithCounts(t *testing.T) {
	t.Parallel()
	r := &DeviationReport{
		AgentName: "sum-count-agent",
		Deviations: []ProfileDeviation{
			{Type: DeviationNewTool, Severity: "critical", Score: 0.9},
			{Type: DeviationFrequencySpike, Severity: "high", Score: 0.7},
			{Type: DeviationUnusualTarget, Severity: "medium", Score: 0.4},
		},
		RiskScore: 0.85,
		IsAnomaly: true,
	}
	s := SummarizeDeviations(r)
	if !strings.Contains(s, "3 deviations") {
		t.Errorf("expected '3 deviations', got %q", s)
	}
	if !strings.Contains(s, "1 critical") {
		t.Errorf("expected '1 critical', got %q", s)
	}
	if !strings.Contains(s, "ANOMALY") {
		t.Errorf("expected ANOMALY, got %q", s)
	}
}
