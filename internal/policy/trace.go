// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Trace represents an AI agent's execution trace — the sequence of actions
// an agent actually performed during a session. Used for post-hoc policy
// evaluation in the closed-loop detection pipeline.
type Trace struct {
	ID        string            `json:"id"`
	AgentName string            `json:"agent_name"`
	AgentType string            `json:"agent_type"` // "llm", "retrieval", "orchestrator", "tool"
	StartTime string            `json:"start_time"` // ISO 8601
	EndTime   string            `json:"end_time"`   // ISO 8601
	Events    []TraceEvent      `json:"events"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// TraceEvent is a single event in an agent execution trace.
type TraceEvent struct {
	ID           string             `json:"id"`
	Timestamp    string             `json:"timestamp"` // ISO 8601
	Type         string             `json:"type"`      // "tool_call", "prompt", "response", "error", "guardrail", "agent_message"
	ToolCall     *ToolCallEvent     `json:"tool_call,omitempty"`
	Prompt       *PromptEvent       `json:"prompt,omitempty"`
	Response     *ResponseEvent     `json:"response,omitempty"`
	Guardrail    *GuardrailEvent    `json:"guardrail,omitempty"`
	AgentMessage *AgentMessageEvent `json:"agent_message,omitempty"`
	ParentID     string             `json:"parent_id,omitempty"`
	Labels       map[string]string  `json:"labels,omitempty"`
}

// ToolCallEvent records a tool invocation by an agent.
type ToolCallEvent struct {
	Tool      string            `json:"tool"`
	Action    string            `json:"action"`              // "read", "write", "execute", "send", "query"
	Target    string            `json:"target,omitempty"`    // URL, file path, or service endpoint
	Arguments map[string]string `json:"arguments,omitempty"` // tool arguments
	Result    string            `json:"result,omitempty"`    // tool call result
	Elevated  bool              `json:"elevated,omitempty"`
	Duration  string            `json:"duration,omitempty"` // e.g. "150ms"
	Success   bool              `json:"success"`
}

// PromptEvent records a prompt sent to/from an LLM.
type PromptEvent struct {
	Role       string `json:"role"` // "user", "system", "assistant"
	Content    string `json:"content"`
	TokenCount int    `json:"token_count,omitempty"`
}

// ResponseEvent records an LLM response.
type ResponseEvent struct {
	Content      string `json:"content"`
	TokenCount   int    `json:"token_count,omitempty"`
	FinishReason string `json:"finish_reason,omitempty"` // "stop", "tool_call", "length", "content_filter"
	Model        string `json:"model,omitempty"`
}

// GuardrailEvent records a safety guardrail evaluation.
type GuardrailEvent struct {
	GuardrailID string  `json:"guardrail_id"`
	Triggered   bool    `json:"triggered"`
	Category    string  `json:"category"` // "injection", "jailbreak", "pii", "toxicity", "policy"
	Score       float64 `json:"score"`
	Action      string  `json:"action"` // "block", "warn", "log"
}

// AgentMessageEvent records inter-agent communication.
type AgentMessageEvent struct {
	FromAgent string `json:"from_agent"`
	ToAgent   string `json:"to_agent"`
	Content   string `json:"content"`
	Channel   string `json:"channel,omitempty"`
}

// TraceViolation is a policy violation found in a trace event.
type TraceViolation struct {
	Event    *TraceEvent `json:"event"`
	Rule     *Rule       `json:"rule"`
	Effect   string      `json:"effect"`   // "deny", "alert"
	Tool     string      `json:"tool"`     // the tool that triggered
	Reason   string      `json:"reason"`   // human-readable reason
	Severity string      `json:"severity"` // "critical", "high", "medium", "low"
}

// TraceEvalResult is the outcome of evaluating a trace against a policy.
type TraceEvalResult struct {
	Trace          *Trace           `json:"trace"`
	Policy         string           `json:"policy"`
	Violations     []TraceViolation `json:"violations"`
	ToolCallCount  int              `json:"tool_call_count"`
	DeniedCount    int              `json:"denied_count"`
	AlertedCount   int              `json:"alerted_count"`
	AllowedCount   int              `json:"allowed_count"`
	EventsAnalyzed int              `json:"events_analyzed"`
	Coverage       float64          `json:"coverage"` // percentage of events matched by at least one rule
}

// TraceStats holds aggregate statistics about a trace.
type TraceStats struct {
	TotalEvents         int      `json:"total_events"`
	ToolCalls           int      `json:"tool_calls"`
	Prompts             int      `json:"prompts"`
	Responses           int      `json:"responses"`
	Errors              int      `json:"errors"`
	UniqueTools         []string `json:"unique_tools"`
	AvgToolCallsPerTurn float64  `json:"avg_tool_calls_per_turn"`
	GuardrailTriggers   int      `json:"guardrail_triggers"`
	AgentMessages       int      `json:"agent_messages"`
}

// validEventTypes lists recognized event types.
var validEventTypes = map[string]bool{
	"tool_call":     true,
	"prompt":        true,
	"response":      true,
	"error":         true,
	"guardrail":     true,
	"agent_message": true,
}

// ParseTrace parses JSON data into a Trace. Returns an error if the JSON
// is malformed or required fields are missing.
func ParseTrace(data []byte) (*Trace, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty trace data")
	}

	var t Trace
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing trace JSON: %w", err)
	}

	if t.ID == "" {
		return nil, fmt.Errorf("trace missing required field: id")
	}
	if t.AgentName == "" {
		return nil, fmt.Errorf("trace missing required field: agent_name")
	}

	return &t, nil
}

// ParseTraceFile reads a trace from a JSON file.
func ParseTraceFile(path string) (*Trace, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading trace file %q: %w", path, err)
	}
	return ParseTrace(data)
}

// EvaluateTrace evaluates an agent execution trace against a policy.
// For each tool_call and agent_message event, rules are matched in priority
// order (highest first); the first matching rule wins. Violations are recorded
// for deny and alert effects.
func EvaluateTrace(p *Policy, t *Trace) *TraceEvalResult {
	result := &TraceEvalResult{
		Trace:  t,
		Policy: p.Meta.Name,
	}

	// Sort rules by priority descending.
	sorted := make([]Rule, len(p.Rules))
	copy(sorted, p.Rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})

	matchedEvents := 0

	for i := range t.Events {
		ev := &t.Events[i]
		result.EventsAnalyzed++

		switch ev.Type {
		case "tool_call":
			if ev.ToolCall == nil {
				continue
			}
			result.ToolCallCount++
			evalToolCallEvent(ev, sorted, result, &matchedEvents)

		case "agent_message":
			if ev.AgentMessage == nil {
				continue
			}
			evalAgentMessageEvent(ev, sorted, result, &matchedEvents)

		case "guardrail":
			// Guardrail events are informational — record triggered ones.
			if ev.Guardrail != nil && ev.Guardrail.Triggered {
				matchedEvents++
			}

		default:
			// prompt, response, error — no policy evaluation needed.
		}
	}

	if result.EventsAnalyzed > 0 {
		result.Coverage = float64(matchedEvents) / float64(result.EventsAnalyzed) * 100
	}

	return result
}

// evalToolCallEvent evaluates a single tool_call event against sorted rules.
func evalToolCallEvent(ev *TraceEvent, rules []Rule, result *TraceEvalResult, matched *int) {
	tc := ev.ToolCall
	tools := []string{tc.Tool}
	actions := []string{}
	if tc.Action != "" {
		actions = []string{tc.Action}
	}
	target := tc.Target

	for _, rule := range rules {
		matchedTool := matchTools(rule.Match.Tools, tools)
		matchedAction := matchActions(rule.Match.Actions, actions)
		matchedTarget := matchTarget(rule.Match.Targets, target)
		// Tactic is not present on traces — skip tactic matching dimension.
		matchedTactic := false

		if !traceRuleMatchesEvent(rule.Match, matchedTool, matchedTactic, matchedAction, matchedTarget) {
			continue
		}

		// Check conditions against the tool call.
		if !traceConditionsPass(rule.Conditions, tc) {
			continue
		}

		*matched++

		switch rule.Effect {
		case "deny":
			result.DeniedCount++
			result.Violations = append(result.Violations, TraceViolation{
				Event:    ev,
				Rule:     &rule,
				Effect:   "deny",
				Tool:     tc.Tool,
				Reason:   fmt.Sprintf("denied by rule %q: %s", rule.ID, rule.Description),
				Severity: effectToSeverity(rule.Effect, rule.Priority),
			})
		case "alert":
			result.AlertedCount++
			result.Violations = append(result.Violations, TraceViolation{
				Event:    ev,
				Rule:     &rule,
				Effect:   "alert",
				Tool:     tc.Tool,
				Reason:   fmt.Sprintf("alert from rule %q: %s", rule.ID, rule.Description),
				Severity: effectToSeverity(rule.Effect, rule.Priority),
			})
		case "allow":
			result.AllowedCount++
		}

		return // first matching rule wins
	}

	// No matching rule — implicit allow.
	result.AllowedCount++
}

// evalAgentMessageEvent evaluates an agent_message event against rules.
// Agent messages are matched as if the tool is "agent_message".
func evalAgentMessageEvent(ev *TraceEvent, rules []Rule, result *TraceEvalResult, matched *int) {
	tools := []string{"agent_message"}
	actions := []string{"send"}

	for _, rule := range rules {
		matchedTool := matchTools(rule.Match.Tools, tools)
		matchedAction := matchActions(rule.Match.Actions, actions)
		matchedTactic := false
		matchedTarget := false

		if !traceRuleMatchesEvent(rule.Match, matchedTool, matchedTactic, matchedAction, matchedTarget) {
			continue
		}

		*matched++

		switch rule.Effect {
		case "deny":
			result.DeniedCount++
			result.Violations = append(result.Violations, TraceViolation{
				Event:    ev,
				Rule:     &rule,
				Effect:   "deny",
				Tool:     "agent_message",
				Reason:   fmt.Sprintf("denied by rule %q: %s", rule.ID, rule.Description),
				Severity: effectToSeverity(rule.Effect, rule.Priority),
			})
		case "alert":
			result.AlertedCount++
			result.Violations = append(result.Violations, TraceViolation{
				Event:    ev,
				Rule:     &rule,
				Effect:   "alert",
				Tool:     "agent_message",
				Reason:   fmt.Sprintf("alert from rule %q: %s", rule.ID, rule.Description),
				Severity: effectToSeverity(rule.Effect, rule.Priority),
			})
		case "allow":
			result.AllowedCount++
		}

		return
	}

	result.AllowedCount++
}

// traceRuleMatchesEvent checks whether a rule's match dimensions align with a trace event.
// Similar to ruleMatchesStage but for trace events (no tactic dimension typically).
func traceRuleMatchesEvent(m RuleMatch, tool, tactic, action, target bool) bool {
	if len(m.Tools) > 0 && !tool {
		return false
	}
	if len(m.Tactics) > 0 && !tactic {
		return false
	}
	if len(m.Actions) > 0 && !action {
		return false
	}
	if len(m.Targets) > 0 && !target {
		return false
	}
	return (len(m.Tools) > 0 && tool) ||
		(len(m.Tactics) > 0 && tactic) ||
		(len(m.Actions) > 0 && action) ||
		(len(m.Targets) > 0 && target)
}

// traceConditionsPass checks whether all conditions on a rule are satisfied
// by a tool call event.
func traceConditionsPass(conds []Condition, tc *ToolCallEvent) bool {
	for _, c := range conds {
		if !traceConditionPasses(c, tc) {
			return false
		}
	}
	return true
}

// traceConditionPasses evaluates a single condition against a tool call event.
func traceConditionPasses(c Condition, tc *ToolCallEvent) bool {
	val := traceFieldValue(c.Field, tc)

	switch c.Operator {
	case "eq":
		return val == c.Value
	case "ne":
		return val != c.Value
	case "in":
		for _, v := range strings.Split(c.Value, ",") {
			if strings.TrimSpace(v) == val {
				return true
			}
		}
		return false
	case "not_in":
		for _, v := range strings.Split(c.Value, ",") {
			if strings.TrimSpace(v) == val {
				return false
			}
		}
		return true
	case "matches":
		return GlobMatch(c.Value, val)
	}
	return false
}

// traceFieldValue extracts a field value from a tool call for condition evaluation.
func traceFieldValue(field string, tc *ToolCallEvent) string {
	switch field {
	case "elevated":
		if tc.Elevated {
			return "true"
		}
		return "false"
	case "exec_type":
		return tc.Action
	case "tool":
		return tc.Tool
	case "target":
		return tc.Target
	}
	return ""
}

// effectToSeverity maps a rule effect and priority to a severity level.
func effectToSeverity(effect string, priority int) string {
	if effect == "deny" {
		if priority >= 95 {
			return "critical"
		}
		if priority >= 85 {
			return "high"
		}
		return "medium"
	}
	// alert
	if priority >= 80 {
		return "high"
	}
	if priority >= 50 {
		return "medium"
	}
	return "low"
}

// AnalyzeTrace computes statistics about a trace without policy evaluation.
func AnalyzeTrace(t *Trace) *TraceStats {
	stats := &TraceStats{}
	if t == nil {
		return stats
	}

	stats.TotalEvents = len(t.Events)
	toolSet := make(map[string]bool)
	turns := 0

	for _, ev := range t.Events {
		switch ev.Type {
		case "tool_call":
			stats.ToolCalls++
			if ev.ToolCall != nil {
				toolSet[ev.ToolCall.Tool] = true
			}
		case "prompt":
			stats.Prompts++
			if ev.Prompt != nil && ev.Prompt.Role == "user" {
				turns++
			}
		case "response":
			stats.Responses++
		case "error":
			stats.Errors++
		case "guardrail":
			if ev.Guardrail != nil && ev.Guardrail.Triggered {
				stats.GuardrailTriggers++
			}
		case "agent_message":
			stats.AgentMessages++
		}
	}

	for tool := range toolSet {
		stats.UniqueTools = append(stats.UniqueTools, tool)
	}
	sort.Strings(stats.UniqueTools)

	if turns > 0 {
		stats.AvgToolCallsPerTurn = float64(stats.ToolCalls) / float64(turns)
	}

	return stats
}

// FormatTraceEval formats a trace evaluation result using box-drawing characters.
func FormatTraceEval(r *TraceEvalResult) string {
	if r == nil {
		return "No trace evaluation result.\n"
	}

	var b strings.Builder

	// Header.
	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│             Trace Policy Evaluation                 │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	if r.Trace != nil {
		b.WriteString(fmt.Sprintf("│ Trace:    %-41s │\n", truncStr(r.Trace.ID, 41)))
		b.WriteString(fmt.Sprintf("│ Agent:    %-41s │\n", truncStr(r.Trace.AgentName, 41)))
	}
	b.WriteString(fmt.Sprintf("│ Policy:   %-41s │\n", truncStr(r.Policy, 41)))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Summary.
	b.WriteString(fmt.Sprintf("│ Events analyzed: %-34d │\n", r.EventsAnalyzed))
	b.WriteString(fmt.Sprintf("│ Tool calls:      %-34d │\n", r.ToolCallCount))
	b.WriteString(fmt.Sprintf("│ Denied:          %-34d │\n", r.DeniedCount))
	b.WriteString(fmt.Sprintf("│ Alerted:         %-34d │\n", r.AlertedCount))
	b.WriteString(fmt.Sprintf("│ Allowed:         %-34d │\n", r.AllowedCount))
	b.WriteString(fmt.Sprintf("│ Coverage:        %-34s │\n", fmt.Sprintf("%.1f%%", r.Coverage)))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Violations.
	if len(r.Violations) == 0 {
		b.WriteString("│ ✓ No violations found                               │\n")
	} else {
		b.WriteString("│ Violations:                                         │\n")
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for i, v := range r.Violations {
			ts := ""
			if v.Event != nil {
				ts = truncStr(v.Event.Timestamp, 19)
			}
			effect := strings.ToUpper(v.Effect)
			b.WriteString(fmt.Sprintf("│ %d. [%s] %-6s %-13s %s\n",
				i+1, ts, effect, truncStr(v.Tool, 13),
				truncStr(v.Rule.ID, 20)))
			b.WriteString(fmt.Sprintf("│    %s\n", truncStr(v.Reason, 48)))
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}

// FormatTraceStats formats trace statistics using box-drawing characters.
func FormatTraceStats(s *TraceStats) string {
	if s == nil {
		return "No trace statistics.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│              Trace Analysis                         │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Total events:       %-31d │\n", s.TotalEvents))
	b.WriteString(fmt.Sprintf("│ Tool calls:         %-31d │\n", s.ToolCalls))
	b.WriteString(fmt.Sprintf("│ Prompts:            %-31d │\n", s.Prompts))
	b.WriteString(fmt.Sprintf("│ Responses:          %-31d │\n", s.Responses))
	b.WriteString(fmt.Sprintf("│ Errors:             %-31d │\n", s.Errors))
	b.WriteString(fmt.Sprintf("│ Guardrail triggers: %-31d │\n", s.GuardrailTriggers))
	b.WriteString(fmt.Sprintf("│ Agent messages:     %-31d │\n", s.AgentMessages))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Unique tools:       %-31d │\n", len(s.UniqueTools)))
	for _, tool := range s.UniqueTools {
		b.WriteString(fmt.Sprintf("│   • %-47s │\n", truncStr(tool, 47)))
	}
	b.WriteString(fmt.Sprintf("│ Avg calls/turn:     %-31s │\n", fmt.Sprintf("%.1f", s.AvgToolCallsPerTurn)))
	b.WriteString("└─────────────────────────────────────────────────────┘\n")

	return b.String()
}

// truncStr truncates a string to maxLen, adding "…" if truncated.
func truncStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return "…"
	}
	return s[:maxLen-1] + "…"
}
