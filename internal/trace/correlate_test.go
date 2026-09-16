// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package trace

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Test helpers (mkCorr-prefixed to avoid clashing with replay_test.go)
// ---------------------------------------------------------------------------

// mkCorrTrace builds a policy.Trace with an explicit start/end time.
func mkCorrTrace(id, agent, agentType, start, end string, events ...policy.TraceEvent) *policy.Trace {
	return &policy.Trace{
		ID:        id,
		AgentName: agent,
		AgentType: agentType,
		StartTime: start,
		EndTime:   end,
		Events:    events,
	}
}

// mkCorrTool builds a tool_call TraceEvent with full control over success/elevated.
func mkCorrTool(id, ts, tool, action, target string, elevated, success bool) policy.TraceEvent {
	return policy.TraceEvent{
		ID:        id,
		Timestamp: ts,
		Type:      "tool_call",
		ToolCall: &policy.ToolCallEvent{
			Tool:     tool,
			Action:   action,
			Target:   target,
			Elevated: elevated,
			Success:  success,
		},
	}
}

// mkCorrMsg builds an agent_message TraceEvent.
func mkCorrMsg(id, ts, from, to, content string) policy.TraceEvent {
	return policy.TraceEvent{
		ID:        id,
		Timestamp: ts,
		Type:      "agent_message",
		AgentMessage: &policy.AgentMessageEvent{
			FromAgent: from,
			ToAgent:   to,
			Content:   content,
		},
	}
}

// mkCorrPrompt builds a prompt TraceEvent (used for no-tool-calls fixtures).
func mkCorrPrompt(id, ts, role, content string) policy.TraceEvent {
	return policy.TraceEvent{
		ID:        id,
		Timestamp: ts,
		Type:      "prompt",
		Prompt: &policy.PromptEvent{
			Role:    role,
			Content: content,
		},
	}
}

// findCorrelationsByRule returns correlations from a report matching a rule name.
func findCorrelationsByRule(r *CorrelationReport, name string) []Correlation {
	var out []Correlation
	for _, c := range r.Correlations {
		if c.Rule.Name == name {
			out = append(out, c)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// CorrelateTraces / basic report shape
// ---------------------------------------------------------------------------

func TestCorrelateTraces_NilSlice(t *testing.T) {
	t.Parallel()
	r := CorrelateTraces(nil)
	if r == nil {
		t.Fatal("expected non-nil report")
	}
	if r.TraceCount != 0 || r.CorrelationCount != 0 || len(r.Correlations) != 0 {
		t.Fatalf("expected empty report, got %+v", r)
	}
	if r.RiskScore != 0 {
		t.Fatalf("expected risk score 0, got %v", r.RiskScore)
	}
}

func TestCorrelateTraces_EmptySliceNotNil(t *testing.T) {
	t.Parallel()
	r := CorrelateTraces([]*policy.Trace{})
	if r.TraceCount != 0 || r.CorrelationCount != 0 {
		t.Fatalf("expected empty report, got %+v", r)
	}
}

func TestCorrelateTraces_SingleTrace_NoCorrelations(t *testing.T) {
	t.Parallel()
	tr := mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
		mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "https://internal/api", false, true),
	)
	r := CorrelateTraces([]*policy.Trace{tr})
	if r.TraceCount != 1 {
		t.Fatalf("expected trace count 1, got %d", r.TraceCount)
	}
	if r.CorrelationCount != 0 {
		t.Fatalf("expected no correlations for a single benign trace, got %d: %+v", r.CorrelationCount, r.Correlations)
	}
}

func TestCorrelateTraces_NilTraceInSlice(t *testing.T) {
	t.Parallel()
	tr := mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
		mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "https://internal/api", false, true),
	)
	r := CorrelateTraces([]*policy.Trace{nil, tr, nil})
	if r.TraceCount != 3 {
		t.Fatalf("expected trace count 3 (raw slice length), got %d", r.TraceCount)
	}
	// Must not panic; no assertions on correlation content required.
}

func TestCorrelateTraces_TraceWithNoEvents(t *testing.T) {
	t.Parallel()
	tr := mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z")
	r := CorrelateTraces([]*policy.Trace{tr})
	if r.TraceCount != 1 {
		t.Fatalf("expected trace count 1, got %d", r.TraceCount)
	}
	if r.CorrelationCount != 0 {
		t.Fatalf("expected no correlations for an eventless trace, got %d", r.CorrelationCount)
	}
}

func TestCorrelateTraces_TraceWithNoToolCalls(t *testing.T) {
	t.Parallel()
	tr := mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
		mkCorrPrompt("e1", "2026-09-14T09:00:00Z", "user", "hello there"),
	)
	r := CorrelateTraces([]*policy.Trace{tr})
	if r.CorrelationCount != 0 {
		t.Fatalf("expected no correlations for a trace with only prompt events, got %d", r.CorrelationCount)
	}
}

func TestCorrelateTraces_MultipleTraces_TraceCount(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z"),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:01:00Z", "2026-09-14T09:06:00Z"),
		mkCorrTrace("t3", "agent-c", "llm", "2026-09-14T09:02:00Z", "2026-09-14T09:07:00Z"),
		mkCorrTrace("t4", "agent-d", "llm", "2026-09-14T09:03:00Z", "2026-09-14T09:08:00Z"),
	}
	r := CorrelateTraces(traces)
	if r.TraceCount != 4 {
		t.Fatalf("expected trace count 4, got %d", r.TraceCount)
	}
}

// ---------------------------------------------------------------------------
// DefaultCorrelationRules
// ---------------------------------------------------------------------------

func TestDefaultCorrelationRules_MinimumCount(t *testing.T) {
	t.Parallel()
	rules := DefaultCorrelationRules()
	if len(rules) < 8 {
		t.Fatalf("expected at least 8 default rules, got %d", len(rules))
	}
}

func TestDefaultCorrelationRules_UniqueNames(t *testing.T) {
	t.Parallel()
	rules := DefaultCorrelationRules()
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Name] {
			t.Fatalf("duplicate rule name: %s", r.Name)
		}
		seen[r.Name] = true
	}
}

func TestDefaultCorrelationRules_ValidTypes(t *testing.T) {
	t.Parallel()
	valid := map[string]bool{
		"temporal": true, "target": true, "tool_sequence": true,
		"agent_cluster": true, "escalation_path": true,
	}
	for _, r := range DefaultCorrelationRules() {
		if !valid[r.Type] {
			t.Errorf("rule %s has invalid type %q", r.Name, r.Type)
		}
	}
}

func TestDefaultCorrelationRules_ValidSeverities(t *testing.T) {
	t.Parallel()
	valid := map[string]bool{
		SeverityCritical: true, SeverityHigh: true, SeverityMedium: true, SeverityLow: true,
	}
	for _, r := range DefaultCorrelationRules() {
		if !valid[r.Severity] {
			t.Errorf("rule %s has invalid severity %q", r.Name, r.Severity)
		}
	}
}

func TestDefaultCorrelationRules_AllHaveDescriptions(t *testing.T) {
	t.Parallel()
	for _, r := range DefaultCorrelationRules() {
		if r.Description == "" {
			t.Errorf("rule %s has empty description", r.Name)
		}
	}
}

func TestDefaultCorrelationRules_ExpectedNamesPresent(t *testing.T) {
	t.Parallel()
	expected := []string{
		"temporal-burst", "tool-sequence-attack", "privilege-chain",
		"data-convergence", "target-sweep", "coordinated-access",
		"relay-attack", "boundary-probe",
	}
	rules := DefaultCorrelationRules()
	names := map[string]bool{}
	for _, r := range rules {
		names[r.Name] = true
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("expected built-in rule %q not found", name)
		}
	}
}

// ---------------------------------------------------------------------------
// temporal-burst
// ---------------------------------------------------------------------------

func TestDetectTemporalBurst_Detected(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "shared-target", false, true),
		),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e2", "2026-09-14T09:00:10Z", "http_get", "read", "shared-target", false, true),
		),
	}
	r := CorrelateTraces(traces)
	found := findCorrelationsByRule(r, "temporal-burst")
	if len(found) == 0 {
		t.Fatalf("expected temporal-burst correlation, got none: %+v", r.Correlations)
	}
	if len(found[0].AgentNames) != 2 {
		t.Errorf("expected 2 distinct agents, got %v", found[0].AgentNames)
	}
}

func TestDetectTemporalBurst_NotDetected_SingleAgent(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "shared-target", false, true),
			mkCorrTool("e2", "2026-09-14T09:00:05Z", "http_get", "read", "shared-target", false, true),
		),
	}
	r := CorrelateTraces(traces)
	if len(findCorrelationsByRule(r, "temporal-burst")) != 0 {
		t.Fatalf("did not expect temporal-burst for a single agent")
	}
}

func TestDetectTemporalBurst_NotDetected_FarApart(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "shared-target", false, true),
		),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:10:00Z", "2026-09-14T09:15:00Z",
			mkCorrTool("e2", "2026-09-14T09:10:00Z", "http_get", "read", "shared-target", false, true),
		),
	}
	r := CorrelateTraces(traces)
	if len(findCorrelationsByRule(r, "temporal-burst")) != 0 {
		t.Fatalf("did not expect temporal-burst for events 10 minutes apart")
	}
}

// ---------------------------------------------------------------------------
// tool-sequence-attack
// ---------------------------------------------------------------------------

func TestDetectToolSequenceAttack_Detected(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("recon-trace", "scout", "llm", "2026-09-14T10:00:00Z", "2026-09-14T10:05:00Z",
			mkCorrTool("e1", "2026-09-14T10:00:00Z", "port_scanner", "query", "host1", false, true),
		),
		mkCorrTrace("exploit-trace", "breaker", "llm", "2026-09-14T10:05:00Z", "2026-09-14T10:10:00Z",
			mkCorrTool("e2", "2026-09-14T10:01:00Z", "exploit_runner", "execute", "host1", true, true),
		),
		mkCorrTrace("exfil-trace", "shipper", "llm", "2026-09-14T10:10:00Z", "2026-09-14T10:15:00Z",
			mkCorrTool("e3", "2026-09-14T10:02:00Z", "http_request", "send", "https://webhook.site/abc", false, true),
		),
	}
	r := CorrelateTraces(traces)
	found := findCorrelationsByRule(r, "tool-sequence-attack")
	if len(found) == 0 {
		t.Fatalf("expected tool-sequence-attack correlation, got none: %+v", r.Correlations)
	}
	if len(found[0].TraceIDs) < 2 {
		t.Errorf("expected the sequence to span >=2 traces, got %v", found[0].TraceIDs)
	}
	if len(found[0].Events) != 3 {
		t.Errorf("expected 3 events in the sequence correlation, got %d", len(found[0].Events))
	}
}

func TestDetectToolSequenceAttack_NotDetected_SingleTrace(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "solo-agent", "llm", "2026-09-14T10:00:00Z", "2026-09-14T10:05:00Z",
			mkCorrTool("e1", "2026-09-14T10:00:00Z", "port_scanner", "query", "host1", false, true),
			mkCorrTool("e2", "2026-09-14T10:01:00Z", "exploit_runner", "execute", "host1", true, true),
			mkCorrTool("e3", "2026-09-14T10:02:00Z", "http_request", "send", "https://webhook.site/abc", false, true),
		),
	}
	r := CorrelateTraces(traces)
	if len(findCorrelationsByRule(r, "tool-sequence-attack")) != 0 {
		t.Fatalf("did not expect tool-sequence-attack when the whole chain is a single trace")
	}
}

func TestDetectToolSequenceAttack_NotDetected_NoExfil(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("recon-trace", "scout", "llm", "2026-09-14T10:00:00Z", "2026-09-14T10:05:00Z",
			mkCorrTool("e1", "2026-09-14T10:00:00Z", "port_scanner", "query", "host1", false, true),
		),
		mkCorrTrace("exploit-trace", "breaker", "llm", "2026-09-14T10:05:00Z", "2026-09-14T10:10:00Z",
			mkCorrTool("e2", "2026-09-14T10:01:00Z", "exploit_runner", "execute", "host1", true, true),
		),
	}
	r := CorrelateTraces(traces)
	if len(findCorrelationsByRule(r, "tool-sequence-attack")) != 0 {
		t.Fatalf("did not expect tool-sequence-attack without an exfil stage")
	}
}

// ---------------------------------------------------------------------------
// privilege-chain
// ---------------------------------------------------------------------------

func TestDetectPrivilegeChain_Detected(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-low", "retrieval", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "search", "query", "docs", false, true),
		),
		mkCorrTrace("t2", "agent-mid", "llm", "2026-09-14T09:05:00Z", "2026-09-14T09:10:00Z",
			mkCorrTool("e2", "2026-09-14T09:05:00Z", "summarize", "read", "docs", false, true),
		),
		mkCorrTrace("t3", "agent-high", "orchestrator", "2026-09-14T09:10:00Z", "2026-09-14T09:15:00Z",
			mkCorrTool("e3", "2026-09-14T09:10:00Z", "deploy", "execute", "prod", true, true),
		),
	}
	r := CorrelateTraces(traces)
	found := findCorrelationsByRule(r, "privilege-chain")
	if len(found) == 0 {
		t.Fatalf("expected privilege-chain correlation, got none: %+v", r.Correlations)
	}
	if len(found[0].TraceIDs) < 3 {
		t.Errorf("expected chain of >=3 traces, got %v", found[0].TraceIDs)
	}
}

func TestDetectPrivilegeChain_NotDetected_SameLevel(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z"),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:05:00Z", "2026-09-14T09:10:00Z"),
		mkCorrTrace("t3", "agent-c", "llm", "2026-09-14T09:10:00Z", "2026-09-14T09:15:00Z"),
	}
	r := CorrelateTraces(traces)
	if len(findCorrelationsByRule(r, "privilege-chain")) != 0 {
		t.Fatalf("did not expect privilege-chain when there is no net privilege increase")
	}
}

func TestDetectPrivilegeChain_NotDetected_TooFewTraces(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-low", "retrieval", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z"),
		mkCorrTrace("t2", "agent-high", "orchestrator", "2026-09-14T09:05:00Z", "2026-09-14T09:10:00Z"),
	}
	r := CorrelateTraces(traces)
	if len(findCorrelationsByRule(r, "privilege-chain")) != 0 {
		t.Fatalf("did not expect privilege-chain with only 2 traces (need >=3)")
	}
}

// ---------------------------------------------------------------------------
// data-convergence
// ---------------------------------------------------------------------------

func TestDetectDataConvergence_Detected(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "export_data", "send", "https://pastebin.com/abc", false, true),
		),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:30:00Z", "2026-09-14T09:35:00Z",
			mkCorrTool("e2", "2026-09-14T09:30:00Z", "upload_file", "send", "https://pastebin.com/abc", false, true),
		),
	}
	r := CorrelateTraces(traces)
	found := findCorrelationsByRule(r, "data-convergence")
	if len(found) == 0 {
		t.Fatalf("expected data-convergence correlation, got none: %+v", r.Correlations)
	}
}

func TestDetectDataConvergence_NotDetected_SingleAgent(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "export_data", "send", "https://pastebin.com/abc", false, true),
			mkCorrTool("e2", "2026-09-14T09:01:00Z", "export_data", "send", "https://pastebin.com/abc", false, true),
		),
	}
	r := CorrelateTraces(traces)
	if len(findCorrelationsByRule(r, "data-convergence")) != 0 {
		t.Fatalf("did not expect data-convergence for a single agent")
	}
}

// ---------------------------------------------------------------------------
// target-sweep
// ---------------------------------------------------------------------------

func TestDetectTargetSweep_Detected(t *testing.T) {
	t.Parallel()
	tr := mkCorrTrace("t1", "sweeper", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
		mkCorrTool("e1", "2026-09-14T09:00:00Z", "probe", "read", "host-1", false, true),
		mkCorrTool("e2", "2026-09-14T09:00:01Z", "probe", "read", "host-2", false, true),
		mkCorrTool("e3", "2026-09-14T09:00:02Z", "probe", "read", "host-3", false, true),
		mkCorrTool("e4", "2026-09-14T09:00:03Z", "probe", "read", "host-4", false, true),
		mkCorrTool("e5", "2026-09-14T09:00:04Z", "probe", "read", "host-5", false, true),
	)
	r := CorrelateTraces([]*policy.Trace{tr})
	found := findCorrelationsByRule(r, "target-sweep")
	if len(found) == 0 {
		t.Fatalf("expected target-sweep correlation, got none: %+v", r.Correlations)
	}
}

func TestDetectTargetSweep_NotDetected_FewTargets(t *testing.T) {
	t.Parallel()
	tr := mkCorrTrace("t1", "sweeper", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
		mkCorrTool("e1", "2026-09-14T09:00:00Z", "probe", "read", "host-1", false, true),
		mkCorrTool("e2", "2026-09-14T09:00:01Z", "probe", "read", "host-2", false, true),
	)
	r := CorrelateTraces([]*policy.Trace{tr})
	if len(findCorrelationsByRule(r, "target-sweep")) != 0 {
		t.Fatalf("did not expect target-sweep for only 2 distinct targets")
	}
}

// ---------------------------------------------------------------------------
// coordinated-access
// ---------------------------------------------------------------------------

func TestDetectCoordinatedAccess_Detected(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "db_client", "read", "prod-database-01", false, true),
		),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e2", "2026-09-14T09:00:20Z", "db_client", "read", "prod-database-01", false, true),
		),
	}
	r := CorrelateTraces(traces)
	found := findCorrelationsByRule(r, "coordinated-access")
	if len(found) == 0 {
		t.Fatalf("expected coordinated-access correlation, got none: %+v", r.Correlations)
	}
}

func TestDetectCoordinatedAccess_NotDetected_NonSensitive(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "public-blog", false, true),
		),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e2", "2026-09-14T09:00:20Z", "http_get", "read", "public-blog", false, true),
		),
	}
	r := CorrelateTraces(traces)
	if len(findCorrelationsByRule(r, "coordinated-access")) != 0 {
		t.Fatalf("did not expect coordinated-access for a non-sensitive target")
	}
}

// ---------------------------------------------------------------------------
// relay-attack
// ---------------------------------------------------------------------------

func TestDetectRelayAttack_Detected(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "orchestrator-1", "orchestrator", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrMsg("m1", "2026-09-14T09:00:00Z", "orchestrator-1", "worker-1", "please fetch the admin credentials"),
		),
		mkCorrTrace("t2", "worker-1", "tool", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:30Z", "vault_read", "execute", "vault/admin", true, true),
		),
	}
	r := CorrelateTraces(traces)
	found := findCorrelationsByRule(r, "relay-attack")
	if len(found) == 0 {
		t.Fatalf("expected relay-attack correlation, got none: %+v", r.Correlations)
	}
	if len(found[0].Events) != 2 {
		t.Errorf("expected 2 events (message + action), got %d", len(found[0].Events))
	}
}

func TestDetectRelayAttack_NotDetected_TooLate(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "orchestrator-1", "orchestrator", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrMsg("m1", "2026-09-14T09:00:00Z", "orchestrator-1", "worker-1", "please fetch the admin credentials"),
		),
		mkCorrTrace("t2", "worker-1", "tool", "2026-09-14T09:10:00Z", "2026-09-14T09:15:00Z",
			mkCorrTool("e1", "2026-09-14T09:10:00Z", "vault_read", "execute", "vault/admin", true, true),
		),
	}
	r := CorrelateTraces(traces)
	if len(findCorrelationsByRule(r, "relay-attack")) != 0 {
		t.Fatalf("did not expect relay-attack when the action is outside the relay window")
	}
}

func TestDetectRelayAttack_NotDetected_Benign(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "orchestrator-1", "orchestrator", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrMsg("m1", "2026-09-14T09:00:00Z", "orchestrator-1", "worker-1", "please summarize the report"),
		),
		mkCorrTrace("t2", "worker-1", "tool", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:30Z", "summarize", "read", "report.txt", false, true),
		),
	}
	r := CorrelateTraces(traces)
	if len(findCorrelationsByRule(r, "relay-attack")) != 0 {
		t.Fatalf("did not expect relay-attack for a benign non-elevated, non-exfil action")
	}
}

// ---------------------------------------------------------------------------
// boundary-probe
// ---------------------------------------------------------------------------

func TestDetectBoundaryProbe_Detected_SingleAgentManyFailures(t *testing.T) {
	t.Parallel()
	tr := mkCorrTrace("t1", "prober", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
		mkCorrTool("e1", "2026-09-14T09:00:00Z", "admin_tool", "execute", "zone-a", true, false),
		mkCorrTool("e2", "2026-09-14T09:00:01Z", "admin_tool", "execute", "zone-b", true, false),
		mkCorrTool("e3", "2026-09-14T09:00:02Z", "admin_tool", "execute", "zone-a", true, false),
	)
	r := CorrelateTraces([]*policy.Trace{tr})
	found := findCorrelationsByRule(r, "boundary-probe")
	if len(found) == 0 {
		t.Fatalf("expected boundary-probe correlation, got none: %+v", r.Correlations)
	}
}

func TestDetectBoundaryProbe_Detected_MultiAgentSameTarget(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "admin_tool", "execute", "restricted-zone", true, false),
		),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:01:00Z", "2026-09-14T09:06:00Z",
			mkCorrTool("e2", "2026-09-14T09:01:00Z", "admin_tool", "execute", "restricted-zone", true, false),
		),
	}
	r := CorrelateTraces(traces)
	found := findCorrelationsByRule(r, "boundary-probe")
	if len(found) == 0 {
		t.Fatalf("expected boundary-probe correlation for multiple agents on the same target, got none: %+v", r.Correlations)
	}
	hasMultiAgentDesc := false
	for _, c := range found {
		if strings.Contains(c.Description, "agents made failed") {
			hasMultiAgentDesc = true
		}
	}
	if !hasMultiAgentDesc {
		t.Errorf("expected a multi-agent boundary-probe description, got %+v", found)
	}
}

func TestDetectBoundaryProbe_NotDetected_AllSuccess(t *testing.T) {
	t.Parallel()
	tr := mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
		mkCorrTool("e1", "2026-09-14T09:00:00Z", "admin_tool", "execute", "zone-a", true, true),
		mkCorrTool("e2", "2026-09-14T09:00:01Z", "admin_tool", "execute", "zone-b", true, true),
		mkCorrTool("e3", "2026-09-14T09:00:02Z", "admin_tool", "execute", "zone-c", true, true),
	)
	r := CorrelateTraces([]*policy.Trace{tr})
	if len(findCorrelationsByRule(r, "boundary-probe")) != 0 {
		t.Fatalf("did not expect boundary-probe when all calls succeeded")
	}
}

// ---------------------------------------------------------------------------
// CorrelateWithRules
// ---------------------------------------------------------------------------

func TestCorrelateWithRules_UnknownRuleName_NoOp(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "shared-target", false, true),
		),
	}
	rules := []CorrelationRule{
		{Name: "made-up-rule", Description: "not a real detector", Type: "temporal", Severity: SeverityLow},
	}
	r := CorrelateWithRules(traces, rules)
	if r.CorrelationCount != 0 {
		t.Fatalf("expected 0 correlations for an unrecognized rule name, got %d", r.CorrelationCount)
	}
}

func TestCorrelateWithRules_SubsetOfRules(t *testing.T) {
	t.Parallel()
	// This fixture would trigger both temporal-burst and data-convergence,
	// but we only pass temporal-burst.
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "export_data", "send", "https://pastebin.com/abc", false, true),
		),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e2", "2026-09-14T09:00:10Z", "export_data", "send", "https://pastebin.com/abc", false, true),
		),
	}
	rules := []CorrelationRule{
		{Name: "temporal-burst", Description: "d", Type: CorrelationTypeTemporal, Severity: SeverityMedium},
	}
	r := CorrelateWithRules(traces, rules)
	for _, c := range r.Correlations {
		if c.Rule.Name != "temporal-burst" {
			t.Errorf("expected only temporal-burst correlations, got rule %s", c.Rule.Name)
		}
	}
}

func TestCorrelateWithRules_EmptyRules(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "x", false, true),
		),
	}
	r := CorrelateWithRules(traces, nil)
	if r.CorrelationCount != 0 {
		t.Fatalf("expected 0 correlations with no rules, got %d", r.CorrelationCount)
	}
}

func TestCorrelation_IDsSequential(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "shared-target", false, true),
			mkCorrTool("e2", "2026-09-14T09:00:00Z", "export_data", "send", "https://pastebin.com/abc", false, true),
		),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e3", "2026-09-14T09:00:10Z", "http_get", "read", "shared-target", false, true),
			mkCorrTool("e4", "2026-09-14T09:00:10Z", "export_data", "send", "https://pastebin.com/abc", false, true),
		),
	}
	r := CorrelateTraces(traces)
	if len(r.Correlations) < 2 {
		t.Fatalf("expected at least 2 correlations to check ID sequencing, got %d", len(r.Correlations))
	}
	for i, c := range r.Correlations {
		want := fmt.Sprintf("COR-%03d", i+1)
		if c.ID != want {
			t.Errorf("correlation %d: expected ID %s, got %s", i, want, c.ID)
		}
	}
}

func TestCorrelationReport_HighestSeverity_PicksCritical(t *testing.T) {
	t.Parallel()
	// tool-sequence-attack (critical) + temporal-burst (medium) both triggered.
	traces := []*policy.Trace{
		mkCorrTrace("recon-trace", "scout", "llm", "2026-09-14T10:00:00Z", "2026-09-14T10:05:00Z",
			mkCorrTool("e1", "2026-09-14T10:00:00Z", "port_scanner", "query", "host1", false, true),
		),
		mkCorrTrace("exploit-trace", "breaker", "llm", "2026-09-14T10:05:00Z", "2026-09-14T10:10:00Z",
			mkCorrTool("e2", "2026-09-14T10:01:00Z", "exploit_runner", "execute", "host1", true, true),
		),
		mkCorrTrace("exfil-trace", "shipper", "llm", "2026-09-14T10:10:00Z", "2026-09-14T10:15:00Z",
			mkCorrTool("e3", "2026-09-14T10:02:00Z", "http_request", "send", "https://webhook.site/abc", false, true),
		),
		mkCorrTrace("burst-a", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e4", "2026-09-14T09:00:00Z", "http_get", "read", "shared-target", false, true),
		),
		mkCorrTrace("burst-b", "agent-b", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e5", "2026-09-14T09:00:05Z", "http_get", "read", "shared-target", false, true),
		),
	}
	r := CorrelateTraces(traces)
	if r.HighestSeverity != SeverityCritical {
		t.Fatalf("expected highest severity critical, got %q (correlations: %+v)", r.HighestSeverity, r.Correlations)
	}
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

func TestScoreCorrelationRisk_Empty(t *testing.T) {
	t.Parallel()
	if got := scoreCorrelationRisk(nil); got != 0 {
		t.Fatalf("expected 0, got %v", got)
	}
}

func TestScoreCorrelationRisk_SeverityOrdering(t *testing.T) {
	t.Parallel()
	mk := func(sev string) []Correlation {
		return []Correlation{{Rule: CorrelationRule{Severity: sev}}}
	}
	critical := scoreCorrelationRisk(mk(SeverityCritical))
	high := scoreCorrelationRisk(mk(SeverityHigh))
	medium := scoreCorrelationRisk(mk(SeverityMedium))
	low := scoreCorrelationRisk(mk(SeverityLow))

	if !(critical > high && high > medium && medium > low) {
		t.Fatalf("expected strictly descending risk by severity, got critical=%v high=%v medium=%v low=%v",
			critical, high, medium, low)
	}
}

func TestScoreCorrelationRisk_CapsAtOne(t *testing.T) {
	t.Parallel()
	var many []Correlation
	for i := 0; i < 10; i++ {
		many = append(many, Correlation{Rule: CorrelationRule{Severity: SeverityCritical}})
	}
	got := scoreCorrelationRisk(many)
	if got != 1.0 {
		t.Fatalf("expected risk score capped at 1.0, got %v", got)
	}
}

func TestComputeCorrelationScore_Bounds(t *testing.T) {
	t.Parallel()
	rule := CorrelationRule{Severity: SeverityCritical}
	got := computeCorrelationScore(rule, 10, 10, 10)
	if got < 0 || got > 1 {
		t.Fatalf("expected score within [0,1], got %v", got)
	}
	low := computeCorrelationScore(CorrelationRule{Severity: SeverityLow}, 1, 1, 1)
	if low < 0 || low > 1 {
		t.Fatalf("expected score within [0,1], got %v", low)
	}
	if got <= low {
		t.Errorf("expected a critical, well-corroborated correlation to score higher than a minimal low one: %v vs %v", got, low)
	}
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

func TestFormatCorrelationReport_Nil(t *testing.T) {
	t.Parallel()
	got := FormatCorrelationReport(nil)
	if got != "No correlation report.\n" {
		t.Fatalf("unexpected output for nil report: %q", got)
	}
}

func TestFormatCorrelationReport_NoCorrelations(t *testing.T) {
	t.Parallel()
	r := CorrelateTraces([]*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z"),
	})
	out := FormatCorrelationReport(r)
	if !strings.Contains(out, "No cross-trace correlations detected") {
		t.Errorf("expected 'no correlations' message, got:\n%s", out)
	}
	if !strings.Contains(out, "Multi-Trace Correlation Report") {
		t.Errorf("expected report title, got:\n%s", out)
	}
}

func TestFormatCorrelationReport_WithCorrelations(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "shared-target", false, true),
		),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e2", "2026-09-14T09:00:05Z", "http_get", "read", "shared-target", false, true),
		),
	}
	r := CorrelateTraces(traces)
	out := FormatCorrelationReport(r)

	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Errorf("expected box-drawing borders, got:\n%s", out)
	}
	if !strings.Contains(out, "COR-001") {
		t.Errorf("expected correlation ID in output, got:\n%s", out)
	}
	if !strings.Contains(out, "TEMPORAL-BURST") && !strings.Contains(out, "temporal-burst") {
		t.Errorf("expected rule name in output, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// SummarizeCorrelations
// ---------------------------------------------------------------------------

func TestSummarizeCorrelations_Nil(t *testing.T) {
	t.Parallel()
	if got := SummarizeCorrelations(nil); got != "no correlation report" {
		t.Fatalf("unexpected summary for nil report: %q", got)
	}
}

func TestSummarizeCorrelations_NoCorrelations(t *testing.T) {
	t.Parallel()
	r := CorrelateTraces([]*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z"),
	})
	got := SummarizeCorrelations(r)
	if !strings.Contains(got, "no correlations found") {
		t.Fatalf("expected 'no correlations found' in summary, got %q", got)
	}
}

func TestSummarizeCorrelations_WithCorrelations(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e1", "2026-09-14T09:00:00Z", "http_get", "read", "shared-target", false, true),
		),
		mkCorrTrace("t2", "agent-b", "llm", "2026-09-14T09:00:00Z", "2026-09-14T09:05:00Z",
			mkCorrTool("e2", "2026-09-14T09:00:05Z", "http_get", "read", "shared-target", false, true),
		),
	}
	r := CorrelateTraces(traces)
	got := SummarizeCorrelations(r)
	if !strings.Contains(got, "correlations found") {
		t.Fatalf("expected 'correlations found' in summary, got %q", got)
	}
	if !strings.Contains(got, "traces analyzed") {
		t.Fatalf("expected trace count phrase in summary, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Misc / cross-cutting
// ---------------------------------------------------------------------------

func TestCorrelationStage_Classification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rec  toolCallRec
		want string
	}{
		{toolCallRec{Tool: "port_scanner", Action: "query"}, "recon"},
		{toolCallRec{Tool: "exploit_runner", Action: "execute"}, "exploit"},
		{toolCallRec{Tool: "http_request", Action: "send", Target: "https://webhook.site/x"}, "exfil"},
		{toolCallRec{Tool: "generic_tool", Action: "noop"}, ""},
	}
	for _, c := range cases {
		if got := correlationStage(c.rec); got != c.want {
			t.Errorf("correlationStage(%+v) = %q, want %q", c.rec, got, c.want)
		}
	}
}

func TestHighestCorrelationSeverity_Empty(t *testing.T) {
	t.Parallel()
	if got := highestCorrelationSeverity(nil); got != "" {
		t.Fatalf("expected empty string for no correlations, got %q", got)
	}
}

func TestSortedKeys_Deterministic(t *testing.T) {
	t.Parallel()
	m := map[string]bool{"zeta": true, "alpha": true, "mid": true}
	got := sortedKeys(m)
	want := []string{"alpha", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("expected %d keys, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected sorted keys %v, got %v", want, got)
		}
	}
}

func TestCorrelateTraces_AllRulesDoNotPanicOnSparseData(t *testing.T) {
	t.Parallel()
	traces := []*policy.Trace{
		mkCorrTrace("t1", "agent-a", "", "not-a-valid-timestamp", "not-a-valid-timestamp",
			mkCorrTool("e1", "not-a-valid-timestamp", "", "", "", false, false),
		),
	}
	r := CorrelateTraces(traces)
	if r == nil {
		t.Fatal("expected non-nil report even with malformed timestamps")
	}
}
