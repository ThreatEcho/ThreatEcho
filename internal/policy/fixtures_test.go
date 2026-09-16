// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"strings"
	"testing"
)

func TestExampleScenarios_Count(t *testing.T) {
	scenarios := ExampleScenarios()
	if len(scenarios) != 11 {
		t.Errorf("expected 11 scenarios, got %d", len(scenarios))
	}
}

func TestExampleScenarios_Fields(t *testing.T) {
	for _, s := range ExampleScenarios() {
		if s.Name == "" {
			t.Error("scenario has empty name")
		}
		if s.Description == "" {
			t.Errorf("scenario %q has empty description", s.Name)
		}
		if s.Risk == "" {
			t.Errorf("scenario %q has empty risk", s.Name)
		}
	}
}

func TestExampleTrace_AllScenariosExist(t *testing.T) {
	for _, s := range ExampleScenarios() {
		trace := ExampleTrace(s.Name)
		if trace == nil {
			t.Errorf("ExampleTrace(%q) returned nil", s.Name)
			continue
		}
		if trace.ID == "" {
			t.Errorf("trace for %q has empty ID", s.Name)
		}
		if len(trace.Events) == 0 {
			t.Errorf("trace for %q has no events", s.Name)
		}
	}
}

func TestExampleTrace_Unknown(t *testing.T) {
	if ExampleTrace("nonexistent") != nil {
		t.Error("expected nil for unknown scenario")
	}
}

func TestExampleTrace_BenignRAG(t *testing.T) {
	trace := ExampleTrace("benign-rag")
	if trace == nil {
		t.Fatal("benign-rag trace is nil")
	}
	if trace.AgentType != "retrieval" {
		t.Errorf("expected agent type 'retrieval', got %q", trace.AgentType)
	}
	// Should have a KB search tool call.
	hasKBSearch := false
	for _, ev := range trace.Events {
		if ev.Type == "tool_call" && ev.ToolCall != nil && ev.ToolCall.Tool == "search_knowledge_base" {
			hasKBSearch = true
		}
	}
	if !hasKBSearch {
		t.Error("benign-rag should include search_knowledge_base tool call")
	}
}

func TestExampleTrace_PromptInjection(t *testing.T) {
	trace := ExampleTrace("prompt-injection")
	if trace == nil {
		t.Fatal("prompt-injection trace is nil")
	}
	// Should have a guardrail trigger.
	hasGuardrail := false
	for _, ev := range trace.Events {
		if ev.Type == "guardrail" && ev.Guardrail != nil && ev.Guardrail.Triggered {
			hasGuardrail = true
		}
	}
	if !hasGuardrail {
		t.Error("prompt-injection should include a triggered guardrail")
	}
}

func TestExampleTrace_ToolAbuse(t *testing.T) {
	trace := ExampleTrace("tool-abuse")
	if trace == nil {
		t.Fatal("tool-abuse trace is nil")
	}
	// Should have elevated shell_exec.
	hasElevated := false
	for _, ev := range trace.Events {
		if ev.Type == "tool_call" && ev.ToolCall != nil && ev.ToolCall.Elevated {
			hasElevated = true
		}
	}
	if !hasElevated {
		t.Error("tool-abuse should include elevated tool calls")
	}
}

func TestExampleTrace_DataExfiltration(t *testing.T) {
	trace := ExampleTrace("data-exfiltration")
	if trace == nil {
		t.Fatal("data-exfiltration trace is nil")
	}
	// Should have send_email tool call.
	hasEmail := false
	for _, ev := range trace.Events {
		if ev.Type == "tool_call" && ev.ToolCall != nil && ev.ToolCall.Tool == "send_email" {
			hasEmail = true
		}
	}
	if !hasEmail {
		t.Error("data-exfiltration should include send_email tool call")
	}
}

func TestExampleTrace_AgentPropagation(t *testing.T) {
	trace := ExampleTrace("agent-propagation")
	if trace == nil {
		t.Fatal("agent-propagation trace is nil")
	}
	// Should have agent_message events.
	hasAgentMsg := false
	for _, ev := range trace.Events {
		if ev.Type == "agent_message" && ev.AgentMessage != nil {
			hasAgentMsg = true
		}
	}
	if !hasAgentMsg {
		t.Error("agent-propagation should include agent_message events")
	}
}

func TestExampleTrace_ElevatedExecution(t *testing.T) {
	trace := ExampleTrace("elevated-execution")
	if trace == nil {
		t.Fatal("elevated-execution trace is nil")
	}
	// All tool calls should be elevated.
	for _, ev := range trace.Events {
		if ev.Type == "tool_call" && ev.ToolCall != nil {
			if !ev.ToolCall.Elevated {
				t.Errorf("event %s should be elevated", ev.ID)
			}
		}
	}
}

func TestExampleTrace_EvalAgainstStrictPolicy(t *testing.T) {
	// Load agent-strict policy and evaluate each attack scenario.
	strictPolicy := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "test-strict"},
		Agent:      AgentScope{Name: "*", Type: "llm"},
		Rules: []Rule{
			{ID: "deny-shell", Effect: "deny", Priority: 100, Match: RuleMatch{Tools: []string{"shell_exec"}}},
			{ID: "deny-email", Effect: "deny", Priority: 95, Match: RuleMatch{Tools: []string{"send_email"}}},
			{ID: "deny-agent-msg", Effect: "deny", Priority: 95, Match: RuleMatch{Tools: []string{"agent_message"}}},
			{ID: "deny-file-write", Effect: "deny", Priority: 90, Match: RuleMatch{Tools: []string{"file_access"}}},
			{ID: "allow-kb-search", Effect: "allow", Priority: 10, Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
		},
	}

	attackScenarios := []string{"tool-abuse", "data-exfiltration", "agent-propagation", "elevated-execution"}
	for _, scenario := range attackScenarios {
		t.Run(scenario, func(t *testing.T) {
			trace := ExampleTrace(scenario)
			result := EvaluateTrace(strictPolicy, trace)
			if result.DeniedCount == 0 {
				t.Errorf("strict policy should deny at least one tool call in %q scenario", scenario)
			}
		})
	}
}

func TestExampleTrace_BenignPassesPermissivePolicy(t *testing.T) {
	permissivePolicy := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "test-permissive"},
		Agent:      AgentScope{Name: "*"},
		Rules: []Rule{
			{ID: "allow-all-search", Effect: "allow", Priority: 10, Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
		},
	}

	trace := ExampleTrace("benign-rag")
	result := EvaluateTrace(permissivePolicy, trace)
	if result.DeniedCount > 0 {
		t.Errorf("benign trace should not trigger denials, got %d", result.DeniedCount)
	}
}

func TestExampleTrace_FormatScenarioList(t *testing.T) {
	scenarios := ExampleScenarios()
	var sb strings.Builder
	for _, s := range scenarios {
		sb.WriteString(s.Name)
		sb.WriteString(" ")
	}
	output := sb.String()
	expected := []string{
		"benign-rag", "benign-tool-use", "prompt-injection", "tool-abuse",
		"data-exfiltration", "agent-propagation", "elevated-execution",
		"rag-poisoning", "mcp-tool-hijack", "memory-poisoning", "model-extraction",
	}
	for _, e := range expected {
		if !strings.Contains(output, e) {
			t.Errorf("missing scenario %q in list", e)
		}
	}
}

func TestExampleTrace_BenignToolUse(t *testing.T) {
	trace := ExampleTrace("benign-tool-use")
	if trace == nil {
		t.Fatal("benign-tool-use trace is nil")
	}
	if trace.AgentType != "tool-calling" {
		t.Errorf("expected agent type 'tool-calling', got %q", trace.AgentType)
	}
	// Should have calendar, document_store, and send_email tool calls.
	tools := make(map[string]bool)
	for _, ev := range trace.Events {
		if ev.Type == "tool_call" && ev.ToolCall != nil {
			tools[ev.ToolCall.Tool] = true
		}
	}
	for _, expected := range []string{"calendar", "document_store", "send_email"} {
		if !tools[expected] {
			t.Errorf("benign-tool-use should include %s tool call", expected)
		}
	}
}

func TestExampleTrace_RAGPoisoning(t *testing.T) {
	trace := ExampleTrace("rag-poisoning")
	if trace == nil {
		t.Fatal("rag-poisoning trace is nil")
	}
	// Should have poisoned KB search result and guardrail trigger.
	hasGuardrail := false
	hasVectorWrite := false
	hasExternalRequest := false
	for _, ev := range trace.Events {
		if ev.Type == "guardrail" && ev.Guardrail != nil && ev.Guardrail.Category == "poisoned_content" {
			hasGuardrail = true
		}
		if ev.Type == "tool_call" && ev.ToolCall != nil {
			if ev.ToolCall.Tool == "vector_store" && ev.ToolCall.Action == "write" {
				hasVectorWrite = true
			}
			if ev.ToolCall.Tool == "http_request" && strings.Contains(ev.ToolCall.Target, "evil.com") {
				hasExternalRequest = true
			}
		}
	}
	if !hasGuardrail {
		t.Error("rag-poisoning should trigger a poisoned_content guardrail")
	}
	if !hasVectorWrite {
		t.Error("rag-poisoning should include a vector_store write")
	}
	if !hasExternalRequest {
		t.Error("rag-poisoning should include an http_request to external target")
	}
}

func TestExampleTrace_MCPToolHijack(t *testing.T) {
	trace := ExampleTrace("mcp-tool-hijack")
	if trace == nil {
		t.Fatal("mcp-tool-hijack trace is nil")
	}
	// Should have MCP tool call to attacker-controlled endpoint.
	hasMCPCall := false
	hasExfil := false
	hasGuardrail := false
	for _, ev := range trace.Events {
		if ev.Type == "tool_call" && ev.ToolCall != nil {
			if ev.ToolCall.Tool == "mcp_payment_gateway" {
				hasMCPCall = true
			}
			if strings.Contains(ev.ToolCall.Target, "attacker") && ev.ToolCall.Tool == "http_request" {
				hasExfil = true
			}
		}
		if ev.Type == "guardrail" && ev.Guardrail != nil && ev.Guardrail.Category == "tool_hijack" {
			hasGuardrail = true
		}
	}
	if !hasMCPCall {
		t.Error("mcp-tool-hijack should include mcp_payment_gateway tool call")
	}
	if !hasExfil {
		t.Error("mcp-tool-hijack should include exfiltration http_request")
	}
	if !hasGuardrail {
		t.Error("mcp-tool-hijack should trigger tool_hijack guardrail")
	}
}

func TestExampleTrace_MemoryPoisoning(t *testing.T) {
	trace := ExampleTrace("memory-poisoning")
	if trace == nil {
		t.Fatal("memory-poisoning trace is nil")
	}
	// Should have multiple agent_memory writes including privilege escalation.
	memWrites := 0
	hasPrivEsc := false
	for _, ev := range trace.Events {
		if ev.Type == "tool_call" && ev.ToolCall != nil && ev.ToolCall.Tool == "agent_memory" && ev.ToolCall.Action == "write" {
			memWrites++
			if val, ok := ev.ToolCall.Arguments["key"]; ok && val == "system_override_instructions" {
				hasPrivEsc = true
			}
		}
	}
	if memWrites < 2 {
		t.Errorf("memory-poisoning should have multiple memory writes, got %d", memWrites)
	}
	if !hasPrivEsc {
		t.Error("memory-poisoning should include a system_override_instructions write")
	}
}

func TestExampleTrace_ModelExtraction(t *testing.T) {
	trace := ExampleTrace("model-extraction")
	if trace == nil {
		t.Fatal("model-extraction trace is nil")
	}
	// Should have system prompt extraction guardrail, logprob harvesting, and data exfil.
	hasGuardrail := false
	hasExfil := false
	hasLogprobs := false
	for _, ev := range trace.Events {
		if ev.Type == "guardrail" && ev.Guardrail != nil && ev.Guardrail.Category == "system_prompt_extraction" {
			hasGuardrail = true
		}
		if ev.Type == "tool_call" && ev.ToolCall != nil {
			if args := ev.ToolCall.Arguments; args != nil {
				if _, ok := args["logprobs"]; ok {
					hasLogprobs = true
				}
			}
			if strings.Contains(ev.ToolCall.Target, "training-data") {
				hasExfil = true
			}
		}
	}
	if !hasGuardrail {
		t.Error("model-extraction should trigger system_prompt_extraction guardrail")
	}
	if !hasLogprobs {
		t.Error("model-extraction should include logprob extraction request")
	}
	if !hasExfil {
		t.Error("model-extraction should include training data exfiltration")
	}
}

func TestExampleTrace_NewAttackScenariosVsStrictPolicy(t *testing.T) {
	strictPolicy := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "test-strict-extended"},
		Agent:      AgentScope{Name: "*", Type: "*"},
		Rules: []Rule{
			{ID: "deny-shell", Effect: "deny", Priority: 100, Match: RuleMatch{Tools: []string{"shell_exec"}}},
			{ID: "deny-http-external", Effect: "deny", Priority: 95, Match: RuleMatch{Tools: []string{"http_request"}}},
			{ID: "deny-email", Effect: "deny", Priority: 95, Match: RuleMatch{Tools: []string{"send_email"}}},
			{ID: "deny-agent-msg", Effect: "deny", Priority: 95, Match: RuleMatch{Tools: []string{"agent_message"}}},
			{ID: "deny-file-write", Effect: "deny", Priority: 90, Match: RuleMatch{Tools: []string{"file_access"}}},
			{ID: "deny-vector-write", Effect: "deny", Priority: 90, Match: RuleMatch{Tools: []string{"vector_store"}}},
			{ID: "deny-memory-write", Effect: "deny", Priority: 90, Match: RuleMatch{Tools: []string{"agent_memory"}}},
			{ID: "deny-mcp-unknown", Effect: "deny", Priority: 85, Match: RuleMatch{Tools: []string{"mcp_*"}}},
			{ID: "allow-kb-search", Effect: "allow", Priority: 10, Match: RuleMatch{Tools: []string{"search_knowledge_base"}}},
		},
	}

	attackScenarios := []string{"rag-poisoning", "mcp-tool-hijack", "memory-poisoning", "model-extraction"}
	for _, scenario := range attackScenarios {
		t.Run(scenario, func(t *testing.T) {
			trace := ExampleTrace(scenario)
			result := EvaluateTrace(strictPolicy, trace)
			if result.DeniedCount == 0 {
				t.Errorf("strict policy should deny at least one tool call in %q scenario", scenario)
			}
		})
	}
}

func TestExampleTrace_BenignToolUsePassesReasonablePolicy(t *testing.T) {
	reasonablePolicy := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "test-reasonable"},
		Agent:      AgentScope{Name: "*"},
		Rules: []Rule{
			{ID: "allow-calendar", Effect: "allow", Priority: 10, Match: RuleMatch{Tools: []string{"calendar"}}},
			{ID: "allow-docs", Effect: "allow", Priority: 10, Match: RuleMatch{Tools: []string{"document_store"}}},
			{ID: "allow-email-internal", Effect: "allow", Priority: 10, Match: RuleMatch{Tools: []string{"send_email"}}},
		},
	}

	trace := ExampleTrace("benign-tool-use")
	result := EvaluateTrace(reasonablePolicy, trace)
	if result.DeniedCount > 0 {
		t.Errorf("benign-tool-use should not trigger denials with reasonable policy, got %d", result.DeniedCount)
	}
}
