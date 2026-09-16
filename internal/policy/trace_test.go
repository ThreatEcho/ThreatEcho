// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- helpers ---

func makeTrace(id, agent string, events ...TraceEvent) *Trace {
	return &Trace{
		ID:        id,
		AgentName: agent,
		AgentType: "llm",
		StartTime: "2026-09-14T10:00:00Z",
		EndTime:   "2026-09-14T10:05:00Z",
		Events:    events,
	}
}

func toolCallEvent(id, tool, action, target string) TraceEvent {
	return TraceEvent{
		ID:        id,
		Timestamp: "2026-09-14T10:01:00Z",
		Type:      "tool_call",
		ToolCall: &ToolCallEvent{
			Tool:    tool,
			Action:  action,
			Target:  target,
			Success: true,
		},
	}
}

func promptEvent(id, role, content string) TraceEvent {
	return TraceEvent{
		ID:        id,
		Timestamp: "2026-09-14T10:00:30Z",
		Type:      "prompt",
		Prompt: &PromptEvent{
			Role:       role,
			Content:    content,
			TokenCount: 100,
		},
	}
}

func responseEvent(id, content string) TraceEvent {
	return TraceEvent{
		ID:        id,
		Timestamp: "2026-09-14T10:00:45Z",
		Type:      "response",
		Response: &ResponseEvent{
			Content:      content,
			TokenCount:   50,
			FinishReason: "stop",
			Model:        "gpt-4",
		},
	}
}

func guardrailEvent(id, category string, triggered bool) TraceEvent {
	return TraceEvent{
		ID:        id,
		Timestamp: "2026-09-14T10:01:05Z",
		Type:      "guardrail",
		Guardrail: &GuardrailEvent{
			GuardrailID: "gr-" + id,
			Triggered:   triggered,
			Category:    category,
			Score:       0.95,
			Action:      "block",
		},
	}
}

func agentMsgEvent(id, from, to, content string) TraceEvent {
	return TraceEvent{
		ID:        id,
		Timestamp: "2026-09-14T10:02:00Z",
		Type:      "agent_message",
		AgentMessage: &AgentMessageEvent{
			FromAgent: from,
			ToAgent:   to,
			Content:   content,
			Channel:   "internal",
		},
	}
}

func denyRule(id, desc string, priority int, tools []string) Rule {
	return Rule{
		ID:          id,
		Description: desc,
		Effect:      "deny",
		Priority:    priority,
		Match:       RuleMatch{Tools: tools},
	}
}

func alertRule(id, desc string, priority int, tools []string) Rule {
	return Rule{
		ID:          id,
		Description: desc,
		Effect:      "alert",
		Priority:    priority,
		Match:       RuleMatch{Tools: tools},
	}
}

func allowRule(id, desc string, priority int, tools []string) Rule {
	return Rule{
		ID:          id,
		Description: desc,
		Effect:      "allow",
		Priority:    priority,
		Match:       RuleMatch{Tools: tools},
	}
}

func traceTestPolicy(name string, rules ...Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: name},
		Agent:      AgentScope{Name: "*"},
		Rules:      rules,
	}
}

// --- ParseTrace tests ---

func TestParseTrace_Valid(t *testing.T) {
	tr := makeTrace("trace-1", "support-agent",
		toolCallEvent("e1", "http_request", "send", "https://api.example.com/data"),
		promptEvent("e2", "user", "hello"),
		responseEvent("e3", "Hi there!"),
	)
	data, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseTrace(data)
	if err != nil {
		t.Fatalf("ParseTrace failed: %v", err)
	}
	if parsed.ID != "trace-1" {
		t.Errorf("got ID %q, want %q", parsed.ID, "trace-1")
	}
	if parsed.AgentName != "support-agent" {
		t.Errorf("got AgentName %q, want %q", parsed.AgentName, "support-agent")
	}
	if len(parsed.Events) != 3 {
		t.Errorf("got %d events, want 3", len(parsed.Events))
	}
}

func TestParseTrace_Empty(t *testing.T) {
	_, err := ParseTrace(nil)
	if err == nil {
		t.Fatal("expected error for empty data")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got %q", err.Error())
	}
}

func TestParseTrace_InvalidJSON(t *testing.T) {
	_, err := ParseTrace([]byte("{invalid json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing trace JSON") {
		t.Errorf("expected 'parsing trace JSON' in error, got %q", err.Error())
	}
}

func TestParseTrace_MissingID(t *testing.T) {
	data := []byte(`{"agent_name": "test"}`)
	_, err := ParseTrace(data)
	if err == nil {
		t.Fatal("expected error for missing id")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("expected 'id' in error, got %q", err.Error())
	}
}

func TestParseTrace_MissingAgentName(t *testing.T) {
	data := []byte(`{"id": "t1"}`)
	_, err := ParseTrace(data)
	if err == nil {
		t.Fatal("expected error for missing agent_name")
	}
	if !strings.Contains(err.Error(), "agent_name") {
		t.Errorf("expected 'agent_name' in error, got %q", err.Error())
	}
}

func TestParseTrace_MinimalFields(t *testing.T) {
	data := []byte(`{"id": "t1", "agent_name": "a1"}`)
	tr, err := ParseTrace(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.ID != "t1" || tr.AgentName != "a1" {
		t.Errorf("unexpected fields: %+v", tr)
	}
	if len(tr.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(tr.Events))
	}
}

func TestParseTraceFile(t *testing.T) {
	tr := makeTrace("file-trace", "file-agent")
	data, _ := json.Marshal(tr)

	dir := t.TempDir()
	path := filepath.Join(dir, "trace.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseTraceFile(path)
	if err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}
	if parsed.ID != "file-trace" {
		t.Errorf("got ID %q, want %q", parsed.ID, "file-trace")
	}
}

func TestParseTraceFile_NotFound(t *testing.T) {
	_, err := ParseTraceFile("/nonexistent/path/trace.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// --- EvaluateTrace tests ---

func TestEvaluateTrace_NoViolations(t *testing.T) {
	pol := traceTestPolicy("permissive",
		allowRule("allow-all", "Allow everything", 10, []string{"*"}),
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "search_knowledge_base", "query", ""),
	)

	result := EvaluateTrace(pol, tr)
	if len(result.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(result.Violations))
	}
	if result.AllowedCount != 1 {
		t.Errorf("expected 1 allowed, got %d", result.AllowedCount)
	}
}

func TestEvaluateTrace_DenyToolCall(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
	)

	result := EvaluateTrace(pol, tr)
	if result.DeniedCount != 1 {
		t.Errorf("expected 1 denied, got %d", result.DeniedCount)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	v := result.Violations[0]
	if v.Effect != "deny" {
		t.Errorf("expected deny effect, got %q", v.Effect)
	}
	if v.Tool != "shell_exec" {
		t.Errorf("expected tool shell_exec, got %q", v.Tool)
	}
	if v.Rule.ID != "deny-shell" {
		t.Errorf("expected rule deny-shell, got %q", v.Rule.ID)
	}
}

func TestEvaluateTrace_AlertOnHTTP(t *testing.T) {
	pol := traceTestPolicy("monitoring",
		alertRule("alert-http", "Alert on HTTP", 50, []string{"http_request"}),
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "http_request", "send", "https://api.example.com"),
	)

	result := EvaluateTrace(pol, tr)
	if result.AlertedCount != 1 {
		t.Errorf("expected 1 alerted, got %d", result.AlertedCount)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Effect != "alert" {
		t.Errorf("expected alert, got %q", result.Violations[0].Effect)
	}
}

func TestEvaluateTrace_MultipleViolations(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
		denyRule("deny-email", "Block email", 95, []string{"send_email"}),
		alertRule("alert-http", "Alert HTTP", 50, []string{"http_request"}),
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
		toolCallEvent("e2", "send_email", "send", ""),
		toolCallEvent("e3", "http_request", "send", "https://api.example.com"),
	)

	result := EvaluateTrace(pol, tr)
	if result.DeniedCount != 2 {
		t.Errorf("expected 2 denied, got %d", result.DeniedCount)
	}
	if result.AlertedCount != 1 {
		t.Errorf("expected 1 alerted, got %d", result.AlertedCount)
	}
	if len(result.Violations) != 3 {
		t.Errorf("expected 3 violations, got %d", len(result.Violations))
	}
}

func TestEvaluateTrace_PriorityOrder(t *testing.T) {
	// Higher priority deny should win over lower priority allow.
	pol := traceTestPolicy("priority-test",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
		allowRule("allow-shell", "Allow shell", 10, []string{"shell_exec"}),
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
	)

	result := EvaluateTrace(pol, tr)
	if result.DeniedCount != 1 {
		t.Errorf("expected 1 denied, got %d", result.DeniedCount)
	}
	if result.AllowedCount != 0 {
		t.Errorf("expected 0 allowed, got %d", result.AllowedCount)
	}
}

func TestEvaluateTrace_TargetGlobMatch(t *testing.T) {
	pol := traceTestPolicy("target-test",
		Rule{
			ID:          "deny-evil",
			Description: "Block evil domains",
			Effect:      "deny",
			Priority:    100,
			Match:       RuleMatch{Targets: []string{"https://*.evil.com/*"}},
		},
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "http_request", "send", "https://c2.evil.com/callback"),
	)

	result := EvaluateTrace(pol, tr)
	if result.DeniedCount != 1 {
		t.Errorf("expected 1 denied, got %d", result.DeniedCount)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Tool != "http_request" {
		t.Errorf("expected tool http_request, got %q", result.Violations[0].Tool)
	}
}

func TestEvaluateTrace_AgentMessage(t *testing.T) {
	pol := traceTestPolicy("no-messaging",
		denyRule("deny-messaging", "Block agent messages", 95, []string{"agent_message"}),
	)
	tr := makeTrace("t1", "support-agent",
		agentMsgEvent("e1", "support-agent", "billing-agent", "Process refund"),
	)

	result := EvaluateTrace(pol, tr)
	if result.DeniedCount != 1 {
		t.Errorf("expected 1 denied, got %d", result.DeniedCount)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Tool != "agent_message" {
		t.Errorf("expected tool agent_message, got %q", result.Violations[0].Tool)
	}
}

func TestEvaluateTrace_ElevatedCondition(t *testing.T) {
	pol := traceTestPolicy("no-elevated",
		Rule{
			ID:          "deny-elevated",
			Description: "Block elevated actions",
			Effect:      "deny",
			Priority:    100,
			Match:       RuleMatch{Actions: []string{"execute"}},
			Conditions: []Condition{
				{Field: "elevated", Operator: "eq", Value: "true"},
			},
		},
	)

	elevated := toolCallEvent("e1", "shell_exec", "execute", "")
	elevated.ToolCall.Elevated = true

	normal := toolCallEvent("e2", "shell_exec", "execute", "")
	normal.ToolCall.Elevated = false

	tr := makeTrace("t1", "agent", elevated, normal)

	result := EvaluateTrace(pol, tr)
	if result.DeniedCount != 1 {
		t.Errorf("expected 1 denied (elevated only), got %d", result.DeniedCount)
	}
	// The non-elevated one gets implicit allow.
	if result.AllowedCount != 1 {
		t.Errorf("expected 1 allowed, got %d", result.AllowedCount)
	}
}

func TestEvaluateTrace_EmptyTrace(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
	)
	tr := makeTrace("t1", "agent")

	result := EvaluateTrace(pol, tr)
	if result.EventsAnalyzed != 0 {
		t.Errorf("expected 0 events, got %d", result.EventsAnalyzed)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(result.Violations))
	}
	if result.Coverage != 0 {
		t.Errorf("expected 0 coverage, got %.1f", result.Coverage)
	}
}

func TestEvaluateTrace_NonToolEvents(t *testing.T) {
	pol := traceTestPolicy("strict",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
	)
	tr := makeTrace("t1", "agent",
		promptEvent("e1", "user", "hello"),
		responseEvent("e2", "Hi there!"),
		promptEvent("e3", "user", "what tools do you have?"),
		responseEvent("e4", "I have shell and HTTP."),
	)

	result := EvaluateTrace(pol, tr)
	if result.EventsAnalyzed != 4 {
		t.Errorf("expected 4 events analyzed, got %d", result.EventsAnalyzed)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(result.Violations))
	}
	if result.ToolCallCount != 0 {
		t.Errorf("expected 0 tool calls, got %d", result.ToolCallCount)
	}
}

func TestEvaluateTrace_GlobWildcard(t *testing.T) {
	pol := traceTestPolicy("glob-test",
		denyRule("deny-any-exec", "Block all exec tools", 100, []string{"*_exec"}),
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
		toolCallEvent("e2", "process_exec", "execute", ""),
		toolCallEvent("e3", "http_request", "send", ""),
	)

	result := EvaluateTrace(pol, tr)
	if result.DeniedCount != 2 {
		t.Errorf("expected 2 denied (shell_exec, process_exec), got %d", result.DeniedCount)
	}
	if result.AllowedCount != 1 {
		t.Errorf("expected 1 allowed (http_request), got %d", result.AllowedCount)
	}
}

func TestEvaluateTrace_ActionMatch(t *testing.T) {
	pol := traceTestPolicy("action-test",
		Rule{
			ID:          "deny-send",
			Description: "Block send actions",
			Effect:      "deny",
			Priority:    80,
			Match:       RuleMatch{Actions: []string{"send"}},
		},
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "send_email", "send", ""),
		toolCallEvent("e2", "search_knowledge_base", "query", ""),
	)

	result := EvaluateTrace(pol, tr)
	if result.DeniedCount != 1 {
		t.Errorf("expected 1 denied, got %d", result.DeniedCount)
	}
}

func TestEvaluateTrace_Coverage(t *testing.T) {
	pol := traceTestPolicy("coverage-test",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
		allowRule("allow-http", "Allow HTTP", 10, []string{"http_request"}),
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
		toolCallEvent("e2", "http_request", "send", ""),
		promptEvent("e3", "user", "hello"),
		responseEvent("e4", "Hi"),
	)

	result := EvaluateTrace(pol, tr)
	// 2 of 4 events matched rules
	if result.Coverage < 49 || result.Coverage > 51 {
		t.Errorf("expected ~50%% coverage, got %.1f%%", result.Coverage)
	}
}

func TestEvaluateTrace_NilToolCall(t *testing.T) {
	pol := traceTestPolicy("test",
		denyRule("deny-shell", "Block shell", 100, []string{"shell_exec"}),
	)
	// Event claims to be tool_call but has nil ToolCall pointer.
	tr := makeTrace("t1", "agent",
		TraceEvent{ID: "e1", Timestamp: "2026-09-14T10:01:00Z", Type: "tool_call"},
	)

	result := EvaluateTrace(pol, tr)
	if result.EventsAnalyzed != 1 {
		t.Errorf("expected 1 event analyzed, got %d", result.EventsAnalyzed)
	}
	// Should not panic and should not count as a tool call.
	if result.ToolCallCount != 0 {
		t.Errorf("expected 0 tool calls (nil ToolCall), got %d", result.ToolCallCount)
	}
}

func TestEvaluateTrace_Severity(t *testing.T) {
	pol := traceTestPolicy("severity-test",
		denyRule("deny-critical", "Critical block", 100, []string{"shell_exec"}),
		denyRule("deny-high", "High block", 90, []string{"send_email"}),
		alertRule("alert-medium", "Medium alert", 50, []string{"http_request"}),
		alertRule("alert-low", "Low alert", 30, []string{"file_read"}),
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
		toolCallEvent("e2", "send_email", "send", ""),
		toolCallEvent("e3", "http_request", "send", ""),
		toolCallEvent("e4", "file_read", "read", ""),
	)

	result := EvaluateTrace(pol, tr)
	if len(result.Violations) != 4 {
		t.Fatalf("expected 4 violations, got %d", len(result.Violations))
	}
	expected := []string{"critical", "high", "medium", "low"}
	for i, v := range result.Violations {
		if v.Severity != expected[i] {
			t.Errorf("violation %d: expected severity %q, got %q", i, expected[i], v.Severity)
		}
	}
}

// --- AnalyzeTrace tests ---

func TestAnalyzeTrace_Stats(t *testing.T) {
	tr := makeTrace("t1", "agent",
		promptEvent("e1", "user", "hello"),
		toolCallEvent("e2", "shell_exec", "execute", ""),
		responseEvent("e3", "done"),
		toolCallEvent("e4", "http_request", "send", ""),
		guardrailEvent("e5", "injection", true),
		agentMsgEvent("e6", "a1", "a2", "msg"),
		TraceEvent{ID: "e7", Type: "error"},
	)

	stats := AnalyzeTrace(tr)
	if stats.TotalEvents != 7 {
		t.Errorf("expected 7 events, got %d", stats.TotalEvents)
	}
	if stats.ToolCalls != 2 {
		t.Errorf("expected 2 tool calls, got %d", stats.ToolCalls)
	}
	if stats.Prompts != 1 {
		t.Errorf("expected 1 prompt, got %d", stats.Prompts)
	}
	if stats.Responses != 1 {
		t.Errorf("expected 1 response, got %d", stats.Responses)
	}
	if stats.Errors != 1 {
		t.Errorf("expected 1 error, got %d", stats.Errors)
	}
	if stats.GuardrailTriggers != 1 {
		t.Errorf("expected 1 guardrail trigger, got %d", stats.GuardrailTriggers)
	}
	if stats.AgentMessages != 1 {
		t.Errorf("expected 1 agent message, got %d", stats.AgentMessages)
	}
}

func TestAnalyzeTrace_UniqueTools(t *testing.T) {
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
		toolCallEvent("e2", "http_request", "send", ""),
		toolCallEvent("e3", "shell_exec", "execute", ""), // duplicate
		toolCallEvent("e4", "file_read", "read", ""),
	)

	stats := AnalyzeTrace(tr)
	if len(stats.UniqueTools) != 3 {
		t.Errorf("expected 3 unique tools, got %d: %v", len(stats.UniqueTools), stats.UniqueTools)
	}
	// Should be sorted.
	expected := []string{"file_read", "http_request", "shell_exec"}
	for i, tool := range stats.UniqueTools {
		if tool != expected[i] {
			t.Errorf("position %d: expected %q, got %q", i, expected[i], tool)
		}
	}
}

func TestAnalyzeTrace_AvgToolCallsPerTurn(t *testing.T) {
	tr := makeTrace("t1", "agent",
		promptEvent("e1", "user", "do something"),
		toolCallEvent("e2", "shell_exec", "execute", ""),
		toolCallEvent("e3", "http_request", "send", ""),
		responseEvent("e4", "done"),
		promptEvent("e5", "user", "do more"),
		toolCallEvent("e6", "file_read", "read", ""),
		responseEvent("e7", "done again"),
	)

	stats := AnalyzeTrace(tr)
	// 3 tool calls / 2 user turns = 1.5
	if stats.AvgToolCallsPerTurn < 1.4 || stats.AvgToolCallsPerTurn > 1.6 {
		t.Errorf("expected ~1.5 avg calls/turn, got %.1f", stats.AvgToolCallsPerTurn)
	}
}

func TestAnalyzeTrace_Empty(t *testing.T) {
	tr := makeTrace("t1", "agent")

	stats := AnalyzeTrace(tr)
	if stats.TotalEvents != 0 {
		t.Errorf("expected 0 events, got %d", stats.TotalEvents)
	}
	if stats.AvgToolCallsPerTurn != 0 {
		t.Errorf("expected 0 avg, got %.1f", stats.AvgToolCallsPerTurn)
	}
}

func TestAnalyzeTrace_Nil(t *testing.T) {
	stats := AnalyzeTrace(nil)
	if stats.TotalEvents != 0 {
		t.Errorf("expected 0 events for nil trace, got %d", stats.TotalEvents)
	}
}

func TestAnalyzeTrace_GuardrailNotTriggered(t *testing.T) {
	tr := makeTrace("t1", "agent",
		guardrailEvent("e1", "injection", false),
		guardrailEvent("e2", "pii", true),
	)

	stats := AnalyzeTrace(tr)
	if stats.GuardrailTriggers != 1 {
		t.Errorf("expected 1 trigger (only the true one), got %d", stats.GuardrailTriggers)
	}
}

// --- Format tests ---

func TestFormatTraceEval_ContainsSections(t *testing.T) {
	pol := traceTestPolicy("test-policy",
		denyRule("deny-shell", "Block shell execution", 100, []string{"shell_exec"}),
	)
	tr := makeTrace("trace-abc", "support-agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
	)

	result := EvaluateTrace(pol, tr)
	output := FormatTraceEval(result)

	checks := []string{
		"Trace Policy Evaluation",
		"trace-abc",
		"support-agent",
		"test-policy",
		"Events analyzed",
		"Tool calls",
		"Denied",
		"Violations",
		"deny-shell",
		"DENY",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q", check)
		}
	}

	// Box-drawing characters.
	if !strings.Contains(output, "┌") || !strings.Contains(output, "└") {
		t.Error("output missing box-drawing characters")
	}
}

func TestFormatTraceEval_NoViolations(t *testing.T) {
	pol := traceTestPolicy("permissive",
		allowRule("allow-all", "Allow everything", 10, []string{"*"}),
	)
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "search_knowledge_base", "query", ""),
	)

	result := EvaluateTrace(pol, tr)
	output := FormatTraceEval(result)

	if !strings.Contains(output, "No violations") {
		t.Error("expected 'No violations' in output")
	}
}

func TestFormatTraceEval_Nil(t *testing.T) {
	output := FormatTraceEval(nil)
	if !strings.Contains(output, "No trace evaluation") {
		t.Error("expected 'No trace evaluation' for nil result")
	}
}

func TestFormatTraceStats_ContainsSections(t *testing.T) {
	tr := makeTrace("t1", "agent",
		promptEvent("e1", "user", "hello"),
		toolCallEvent("e2", "shell_exec", "execute", ""),
		toolCallEvent("e3", "http_request", "send", ""),
		responseEvent("e4", "done"),
	)

	stats := AnalyzeTrace(tr)
	output := FormatTraceStats(stats)

	checks := []string{
		"Trace Analysis",
		"Total events",
		"Tool calls",
		"Prompts",
		"Responses",
		"Unique tools",
		"shell_exec",
		"http_request",
		"Avg calls/turn",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestFormatTraceStats_Nil(t *testing.T) {
	output := FormatTraceStats(nil)
	if !strings.Contains(output, "No trace statistics") {
		t.Error("expected 'No trace statistics' for nil")
	}
}

// --- Edge cases ---

func TestEffectToSeverity(t *testing.T) {
	tests := []struct {
		effect   string
		priority int
		want     string
	}{
		{"deny", 100, "critical"},
		{"deny", 95, "critical"},
		{"deny", 90, "high"},
		{"deny", 85, "high"},
		{"deny", 50, "medium"},
		{"alert", 80, "high"},
		{"alert", 50, "medium"},
		{"alert", 30, "low"},
	}
	for _, tt := range tests {
		got := effectToSeverity(tt.effect, tt.priority)
		if got != tt.want {
			t.Errorf("effectToSeverity(%q, %d) = %q, want %q", tt.effect, tt.priority, got, tt.want)
		}
	}
}

func TestTruncStr(t *testing.T) {
	tests := []struct {
		s      string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hell…"},
		{"ab", 1, "…"},
		{"", 5, ""},
	}
	for _, tt := range tests {
		got := truncStr(tt.s, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncStr(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
		}
	}
}
