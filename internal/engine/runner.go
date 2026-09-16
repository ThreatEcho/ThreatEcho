// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// RunConfig controls how the scenario runner generates traces.
type RunConfig struct {
	AgentName       string        // name of the simulated agent
	AgentType       string        // type: "llm", "retrieval", "orchestrator", "tool"
	TimestampBase   string        // ISO 8601 start time (default: now)
	EventGap        time.Duration // gap between events (default: 1s)
	IncludeMetadata bool          // include stage metadata in trace events
}

// DefaultRunConfig returns sensible defaults for RunConfig.
func DefaultRunConfig() *RunConfig {
	return &RunConfig{
		AgentName: "simulated-agent",
		AgentType: "llm",
		EventGap:  time.Second,
	}
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

// ScenarioResult holds the output of a scenario run. Named ScenarioResult
// (not RunResult) to avoid conflict with the existing RunResult type in
// engine.go which serves simulation and live run results.
type ScenarioResult struct {
	CampaignName string                `json:"campaign_name"`
	Traces       []*policy.Trace       `json:"traces"`
	StageResults []ScenarioStageResult `json:"stage_results,omitempty"`
	StageCount   int                   `json:"stage_count"`
	EventCount   int                   `json:"event_count"`
}

// ScenarioStageResult holds per-stage trace generation results.
type ScenarioStageResult struct {
	StageName  string `json:"stage_name"`
	EventCount int    `json:"event_count"`
}

// ---------------------------------------------------------------------------
// Execute-type → tool/action mapping (local to runner; mirrors the unexported
// maps in policy.go so the engine package stays self-contained)
// ---------------------------------------------------------------------------

// execToTool maps execute types to tool names for trace generation.
var execToTool = map[string]string{
	"http":       "http_request",
	"shell":      "shell_exec",
	"powershell": "shell_exec",
	"dns":        "dns_query",
	"file":       "file_access",
	"registry":   "registry_access",
	"service":    "service_control",
	"process":    "process_exec",
}

// execToAction maps execute types to action categories.
var execToAction = map[string]string{
	"http":       "send",
	"shell":      "execute",
	"powershell": "execute",
	"dns":        "query",
	"file":       "write",
	"registry":   "write",
	"service":    "execute",
	"process":    "execute",
}

// ---------------------------------------------------------------------------
// Telemetry → event-type / tool-name mapping
// ---------------------------------------------------------------------------

// telemetryEventType maps campaign telemetry names to TraceEvent types.
var telemetryEventType = map[string]string{
	"tool_call":           "tool_call",
	"email_sent":          "tool_call",
	"embedding_query":     "tool_call",
	"vector_store_write":  "tool_call",
	"inter_agent_message": "agent_message",
	"prompt_log":          "prompt",
	"guardrail_trigger":   "guardrail",
	"process_create":      "tool_call",
	"network_connection":  "tool_call",
	"api_call":            "tool_call",
	"file_create":         "tool_call",
	"file_upload":         "tool_call",
}

// telemetryToolName maps campaign telemetry names to tool names for
// tool_call events generated from telemetry entries.
var telemetryToolName = map[string]string{
	"tool_call":          "tool_call",
	"email_sent":         "send_email",
	"embedding_query":    "search_knowledge_base",
	"vector_store_write": "write_knowledge_base",
	"process_create":     "process_exec",
	"network_connection": "network_connect",
	"api_call":           "http_request",
	"file_create":        "file_access",
	"file_upload":        "file_upload",
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

// RunScenario generates synthetic Trace objects from a campaign's stage
// definitions, simulating the agent behavior described in the campaign
// without actually executing anything. This completes the closed loop:
//
//	campaign → trace → policy eval
//
// For each stage a separate Trace is created. Events are generated from
// the stage's Execute.Commands (each becomes a tool_call event) and
// Expect.Telemetry entries (each becomes an event of the mapped type).
// When a stage has no commands but has an execute type (e.g. HTTP), a
// single tool_call event is synthesised from the execute configuration.
func RunScenario(c *campaign.Campaign, cfg *RunConfig) (*ScenarioResult, error) {
	if c == nil {
		return nil, fmt.Errorf("campaign is nil")
	}
	if cfg == nil {
		cfg = DefaultRunConfig()
	}

	baseTime := parseBaseTime(cfg.TimestampBase)
	gap := cfg.EventGap
	if gap <= 0 {
		gap = time.Second
	}

	result := &ScenarioResult{
		CampaignName: c.Meta.Name,
		StageCount:   len(c.Stages),
	}

	// Global event counter keeps timestamps monotonically increasing
	// across all stages in the scenario.
	cursor := 0
	for _, stage := range c.Stages {
		trace, count := generateStageTrace(c, stage, cfg, baseTime, gap, cursor)
		result.Traces = append(result.Traces, trace)
		result.StageResults = append(result.StageResults, ScenarioStageResult{
			StageName:  stage.Name,
			EventCount: count,
		})
		result.EventCount += count
		cursor += count
	}

	return result, nil
}

// RunScenarioFromDir loads a campaign from disk then calls RunScenario.
// The path may be a directory containing campaign.yaml or a direct YAML path.
func RunScenarioFromDir(campaignPath string, cfg *RunConfig) (*ScenarioResult, error) {
	c, err := campaign.Load(campaignPath)
	if err != nil {
		return nil, fmt.Errorf("loading campaign from %q: %w", campaignPath, err)
	}
	return RunScenario(c, cfg)
}

// ---------------------------------------------------------------------------
// Trace generation (per stage)
// ---------------------------------------------------------------------------

// generateStageTrace creates a policy.Trace from a single campaign stage.
// It returns the trace and the number of events generated.
func generateStageTrace(
	c *campaign.Campaign,
	stage campaign.Stage,
	cfg *RunConfig,
	baseTime time.Time,
	gap time.Duration,
	offset int,
) (*policy.Trace, int) {
	traceID := fmt.Sprintf("%s-%s-trace", sanitizeID(c.Meta.Name), sanitizeID(stage.ID))

	var events []policy.TraceEvent
	n := 0

	// 1. Tool-call events from Execute.Commands.
	//    Each command becomes a separate tool_call event with the execute type
	//    mapped to its corresponding tool name.
	for _, cmd := range stage.Execute.Commands {
		ts := baseTime.Add(time.Duration(offset+n) * gap)
		ev := policy.TraceEvent{
			ID:        fmt.Sprintf("%s-evt-%d", traceID, n),
			Timestamp: ts.Format(time.RFC3339),
			Type:      "tool_call",
			ToolCall: &policy.ToolCallEvent{
				Tool:      mapExecToTool(stage.Execute.Type),
				Action:    mapExecToAction(stage.Execute.Type),
				Target:    stage.Execute.Target,
				Arguments: map[string]string{"command": cmd},
				Elevated:  stage.Execute.Elevated,
				Success:   true,
			},
		}
		if cfg.IncludeMetadata {
			ev.Labels = stageLabels(stage)
		}
		events = append(events, ev)
		n++
	}

	// 2. If no commands but the stage has an execute type (e.g. HTTP stages
	//    have target + args instead of shell commands), create one tool_call
	//    event from the execute configuration.
	if len(stage.Execute.Commands) == 0 && stage.Execute.Type != "" {
		ts := baseTime.Add(time.Duration(offset+n) * gap)
		args := copyStringMap(stage.Execute.Args)
		if stage.Execute.Payload != "" {
			args["payload"] = stage.Execute.Payload
		}
		ev := policy.TraceEvent{
			ID:        fmt.Sprintf("%s-evt-%d", traceID, n),
			Timestamp: ts.Format(time.RFC3339),
			Type:      "tool_call",
			ToolCall: &policy.ToolCallEvent{
				Tool:      mapExecToTool(stage.Execute.Type),
				Action:    mapExecToAction(stage.Execute.Type),
				Target:    stage.Execute.Target,
				Arguments: args,
				Elevated:  stage.Execute.Elevated,
				Success:   true,
			},
		}
		if cfg.IncludeMetadata {
			ev.Labels = stageLabels(stage)
		}
		events = append(events, ev)
		n++
	}

	// 3. Events from Expect.Telemetry entries. Each telemetry type is mapped
	//    to a TraceEvent type (tool_call, prompt, guardrail, agent_message).
	for _, tel := range stage.Expect.Telemetry {
		ts := baseTime.Add(time.Duration(offset+n) * gap)
		ev := buildTelemetryEvent(traceID, n, ts, tel, stage, cfg)
		events = append(events, ev)
		n++
	}

	// Build the trace envelope.
	startTime := baseTime.Add(time.Duration(offset) * gap)
	endTime := startTime
	if n > 0 {
		endTime = baseTime.Add(time.Duration(offset+n-1) * gap)
	}

	trace := &policy.Trace{
		ID:        traceID,
		AgentName: cfg.AgentName,
		AgentType: cfg.AgentType,
		StartTime: startTime.Format(time.RFC3339),
		EndTime:   endTime.Format(time.RFC3339),
		Events:    events,
	}

	if cfg.IncludeMetadata {
		trace.Metadata = map[string]string{
			"campaign":  c.Meta.Name,
			"stage":     stage.Name,
			"stage_id":  stage.ID,
			"technique": stage.Technique,
			"tactic":    stage.Tactic,
		}
		if stage.Execute.Elevated {
			trace.Metadata["elevated"] = "true"
		}
	}

	return trace, n
}

// buildTelemetryEvent creates a TraceEvent from a campaign telemetry type.
// The telemetry name is mapped to the appropriate TraceEvent type, and the
// corresponding sub-event struct is populated with simulated data.
func buildTelemetryEvent(
	traceID string,
	eventNum int,
	ts time.Time,
	telType string,
	stage campaign.Stage,
	cfg *RunConfig,
) policy.TraceEvent {
	evType := mapTelemetryToEventType(telType)

	ev := policy.TraceEvent{
		ID:        fmt.Sprintf("%s-evt-%d", traceID, eventNum),
		Timestamp: ts.Format(time.RFC3339),
		Type:      evType,
	}

	switch evType {
	case "tool_call":
		ev.ToolCall = &policy.ToolCallEvent{
			Tool:     mapTelemetryToToolName(telType),
			Action:   inferTelemetryAction(telType),
			Target:   stage.Execute.Target,
			Elevated: stage.Execute.Elevated,
			Success:  true,
		}

	case "prompt":
		ev.Prompt = &policy.PromptEvent{
			Role:    "user",
			Content: fmt.Sprintf("[simulated] %s for stage %q", telType, stage.Name),
		}

	case "guardrail":
		ev.Guardrail = &policy.GuardrailEvent{
			GuardrailID: fmt.Sprintf("gr-%s", sanitizeID(stage.ID)),
			Triggered:   true,
			Category:    "policy",
			Score:       0.95,
			Action:      "log",
		}

	case "agent_message":
		ev.AgentMessage = &policy.AgentMessageEvent{
			FromAgent: cfg.AgentName,
			ToAgent:   "target-agent",
			Content:   fmt.Sprintf("[simulated] inter-agent message for stage %q", stage.Name),
		}
	}

	if cfg.IncludeMetadata {
		ev.Labels = stageLabels(stage)
	}

	return ev
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatScenarioResult returns a box-drawing formatted summary of a scenario
// run result, suitable for terminal display.
func FormatScenarioResult(r *ScenarioResult) string {
	if r == nil {
		return "No scenario result.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│              Scenario Run Result                    │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Campaign:   %-39s │\n", scenarioTrunc(r.CampaignName, 39)))
	b.WriteString(fmt.Sprintf("│ Stages:     %-39d │\n", r.StageCount))
	b.WriteString(fmt.Sprintf("│ Traces:     %-39d │\n", len(r.Traces)))
	b.WriteString(fmt.Sprintf("│ Events:     %-39d │\n", r.EventCount))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	if len(r.StageResults) == 0 {
		b.WriteString("│ (no stages)                                         │\n")
	} else {
		b.WriteString("│ Per-stage breakdown:                                │\n")
		for i, sr := range r.StageResults {
			b.WriteString(fmt.Sprintf("│  %2d. %-35s %4d evts │\n",
				i+1, scenarioTrunc(sr.StageName, 35), sr.EventCount))
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}

// scenarioTrunc truncates s to maxLen, appending "…" when truncated.
func scenarioTrunc(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return "…"
	}
	return s[:maxLen-1] + "…"
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// parseBaseTime parses an ISO 8601 timestamp string. Returns time.Now().UTC()
// when the string is empty or unparseable.
func parseBaseTime(s string) time.Time {
	if s == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now().UTC()
	}
	return t
}

// sanitizeID replaces spaces and slashes with hyphens and lowercases the
// result, producing a safe identifier fragment.
func sanitizeID(s string) string {
	r := strings.NewReplacer(" ", "-", "/", "-", "\\", "-")
	return strings.ToLower(r.Replace(s))
}

// copyStringMap returns a shallow copy of a string→string map. If the input
// is nil an empty (non-nil) map is returned so callers can add entries.
func copyStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// stageLabels returns metadata labels derived from a campaign stage.
func stageLabels(s campaign.Stage) map[string]string {
	return map[string]string{
		"stage_id":  s.ID,
		"stage":     s.Name,
		"technique": s.Technique,
		"tactic":    s.Tactic,
	}
}

// mapExecToTool maps an execute type to a tool name. Falls back to the raw
// type string (or "unknown" if empty).
func mapExecToTool(execType string) string {
	if t, ok := execToTool[execType]; ok {
		return t
	}
	if execType == "" {
		return "unknown"
	}
	return execType
}

// mapExecToAction maps an execute type to an action category. Falls back to
// "execute" when no mapping exists.
func mapExecToAction(execType string) string {
	if a, ok := execToAction[execType]; ok {
		return a
	}
	return "execute"
}

// mapTelemetryToEventType maps a campaign telemetry type name to a TraceEvent
// type string. Defaults to "tool_call" for unrecognised telemetry.
func mapTelemetryToEventType(telType string) string {
	if t, ok := telemetryEventType[telType]; ok {
		return t
	}
	return "tool_call"
}

// mapTelemetryToToolName maps a campaign telemetry type name to a tool name.
// Falls back to the raw telemetry name.
func mapTelemetryToToolName(telType string) string {
	if t, ok := telemetryToolName[telType]; ok {
		return t
	}
	return telType
}

// inferTelemetryAction infers the action category from a telemetry type name.
func inferTelemetryAction(telType string) string {
	switch telType {
	case "embedding_query", "api_call":
		return "query"
	case "vector_store_write", "file_create", "file_upload":
		return "write"
	case "email_sent", "network_connection":
		return "send"
	case "process_create":
		return "execute"
	default:
		return "execute"
	}
}
