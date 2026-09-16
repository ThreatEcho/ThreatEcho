// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

// --- SimulatePolicy tests ---

func TestSimulatePolicy_NoStages(t *testing.T) {
	t.Parallel()

	p := testPolicy()
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "empty-campaign"},
		Stages:     nil,
	}

	r := SimulatePolicy(p, c)
	if r.Policy != "test-policy" {
		t.Errorf("expected policy name %q, got %q", "test-policy", r.Policy)
	}
	if r.Campaign != "empty-campaign" {
		t.Errorf("expected campaign name %q, got %q", "empty-campaign", r.Campaign)
	}
	if len(r.Stages) != 0 {
		t.Errorf("expected 0 stages, got %d", len(r.Stages))
	}
	if r.TotalTools != 0 {
		t.Errorf("expected 0 total tools, got %d", r.TotalTools)
	}
	if r.TotalAllowed != 0 || r.TotalDenied != 0 || r.TotalAlerted != 0 {
		t.Errorf("expected all counters 0, got allowed=%d denied=%d alerted=%d",
			r.TotalAllowed, r.TotalDenied, r.TotalAlerted)
	}
}

func TestSimulatePolicy_AllDenied(t *testing.T) {
	t.Parallel()

	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "deny-all"},
		Agent:      AgentScope{Name: "test-agent"},
		Rules: []Rule{
			{
				ID:          "deny-shell",
				Description: "Deny shell execution",
				Effect:      "deny",
				Priority:    100,
				Match:       RuleMatch{Tools: []string{"shell_exec"}},
			},
			{
				ID:          "deny-http",
				Description: "Deny HTTP requests",
				Effect:      "deny",
				Priority:    90,
				Match:       RuleMatch{Tools: []string{"http_request"}},
			},
		},
	}

	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "attack-campaign"},
		Stages: []campaign.Stage{
			{
				ID: "s1", Name: "Shell Stage",
				Technique: "T1059", Tactic: "execution",
				Execute: campaign.Execute{Type: "shell"},
			},
			{
				ID: "s2", Name: "HTTP Stage",
				Technique: "T1071", Tactic: "c2",
				Execute: campaign.Execute{Type: "http"},
			},
		},
	}

	r := SimulatePolicy(p, c)
	if r.TotalDenied != 2 {
		t.Errorf("expected 2 denied, got %d", r.TotalDenied)
	}
	if r.TotalAllowed != 0 {
		t.Errorf("expected 0 allowed, got %d", r.TotalAllowed)
	}
	if r.CoveragePct != 100.0 {
		t.Errorf("expected 100%% coverage, got %.1f%%", r.CoveragePct)
	}

	// Both stages should have denied decisions.
	for _, stage := range r.Stages {
		if stage.Denied != 1 {
			t.Errorf("stage %s: expected 1 denied, got %d", stage.StageID, stage.Denied)
		}
		if len(stage.Decisions) != 1 {
			t.Errorf("stage %s: expected 1 decision, got %d", stage.StageID, len(stage.Decisions))
			continue
		}
		if stage.Decisions[0].Effect != "deny" {
			t.Errorf("stage %s: expected deny effect, got %q", stage.StageID, stage.Decisions[0].Effect)
		}
	}
}

func TestSimulatePolicy_AllAllowed(t *testing.T) {
	t.Parallel()

	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "allow-all"},
		Agent:      AgentScope{Name: "test-agent"},
		Rules: []Rule{
			{
				ID:          "allow-shell",
				Description: "Allow shell execution",
				Effect:      "allow",
				Priority:    100,
				Match:       RuleMatch{Tools: []string{"shell_exec"}},
			},
			{
				ID:          "allow-http",
				Description: "Allow HTTP requests",
				Effect:      "allow",
				Priority:    90,
				Match:       RuleMatch{Tools: []string{"http_request"}},
			},
		},
	}

	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "benign-campaign"},
		Stages: []campaign.Stage{
			{
				ID: "s1", Name: "Shell Stage",
				Technique: "T1059", Tactic: "execution",
				Execute: campaign.Execute{Type: "shell"},
			},
			{
				ID: "s2", Name: "HTTP Stage",
				Technique: "T1071", Tactic: "c2",
				Execute: campaign.Execute{Type: "http"},
			},
		},
	}

	r := SimulatePolicy(p, c)
	if r.TotalAllowed != 2 {
		t.Errorf("expected 2 allowed, got %d", r.TotalAllowed)
	}
	if r.TotalDenied != 0 {
		t.Errorf("expected 0 denied, got %d", r.TotalDenied)
	}
	if r.CoveragePct != 100.0 {
		t.Errorf("expected 100%% coverage, got %.1f%%", r.CoveragePct)
	}
}

func TestSimulatePolicy_MixedResults(t *testing.T) {
	t.Parallel()

	p := testPolicy()   // denies shell_exec only
	c := testCampaign() // 3 stages: shell, http, http+tool_call

	r := SimulatePolicy(p, c)

	if r.TotalDenied != 1 {
		t.Errorf("expected 1 denied (shell stage), got %d", r.TotalDenied)
	}
	if r.TotalDenied+r.TotalAllowed+r.TotalAlerted != r.TotalTools {
		t.Errorf("decision counts don't add up: %d+%d+%d != %d",
			r.TotalAllowed, r.TotalDenied, r.TotalAlerted, r.TotalTools)
	}
	if len(r.Stages) != 3 {
		t.Errorf("expected 3 stages, got %d", len(r.Stages))
	}

	// Stage 1 (shell) should be denied.
	if len(r.Stages) > 0 && r.Stages[0].Denied != 1 {
		t.Errorf("stage-1: expected 1 denied, got %d", r.Stages[0].Denied)
	}
}

func TestSimulatePolicy_AlertEffect(t *testing.T) {
	t.Parallel()

	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "alert-policy"},
		Agent:      AgentScope{Name: "test-agent"},
		Rules: []Rule{
			{
				ID:          "alert-http",
				Description: "Alert on HTTP requests",
				Effect:      "alert",
				Priority:    100,
				Match:       RuleMatch{Tools: []string{"http_request"}},
			},
		},
	}

	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "http-campaign"},
		Stages: []campaign.Stage{
			{
				ID: "s1", Name: "HTTP Call",
				Technique: "T1071", Tactic: "c2",
				Execute: campaign.Execute{Type: "http"},
			},
		},
	}

	r := SimulatePolicy(p, c)
	if r.TotalAlerted != 1 {
		t.Errorf("expected 1 alerted, got %d", r.TotalAlerted)
	}
	if r.Stages[0].Decisions[0].Effect != "alert" {
		t.Errorf("expected alert effect, got %q", r.Stages[0].Decisions[0].Effect)
	}
	if r.Stages[0].Decisions[0].RuleID != "alert-http" {
		t.Errorf("expected rule ID %q, got %q", "alert-http", r.Stages[0].Decisions[0].RuleID)
	}
}

func TestSimulatePolicy_EmptyPolicy(t *testing.T) {
	t.Parallel()

	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "empty-policy"},
		Agent:      AgentScope{Name: "test-agent"},
		Rules:      nil,
	}

	c := testCampaign()
	r := SimulatePolicy(p, c)

	// All tool calls should be implicitly allowed.
	if r.TotalDenied != 0 {
		t.Errorf("expected 0 denied with empty policy, got %d", r.TotalDenied)
	}
	if r.TotalAlerted != 0 {
		t.Errorf("expected 0 alerted with empty policy, got %d", r.TotalAlerted)
	}
	if r.TotalAllowed != r.TotalTools {
		t.Errorf("expected all tools allowed: got %d allowed out of %d", r.TotalAllowed, r.TotalTools)
	}
	if r.CoveragePct != 0 {
		t.Errorf("expected 0%% coverage with empty policy, got %.1f%%", r.CoveragePct)
	}
}

func TestSimulatePolicy_NoToolsInferred(t *testing.T) {
	t.Parallel()

	p := testPolicy()
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "no-tools-campaign"},
		Stages: []campaign.Stage{
			{
				ID: "s1", Name: "Unknown Type Stage",
				Technique: "T9999", Tactic: "unknown",
				Execute: campaign.Execute{Type: "unknown_type"},
			},
		},
	}

	r := SimulatePolicy(p, c)
	if len(r.Stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(r.Stages))
	}
	// Stage with no inferred tools gets a "(none)" decision.
	if len(r.Stages[0].Decisions) != 1 {
		t.Errorf("expected 1 decision for no-tools stage, got %d", len(r.Stages[0].Decisions))
	}
	if r.Stages[0].Decisions[0].Tool != "(none)" {
		t.Errorf("expected tool %q, got %q", "(none)", r.Stages[0].Decisions[0].Tool)
	}
}

func TestSimulatePolicy_TelemetryInferredTools(t *testing.T) {
	t.Parallel()

	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "email-deny"},
		Agent:      AgentScope{Name: "test-agent"},
		Rules: []Rule{
			{
				ID:          "deny-email",
				Description: "Deny email sending",
				Effect:      "deny",
				Priority:    100,
				Match:       RuleMatch{Tools: []string{"send_email"}},
			},
		},
	}

	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "email-exfil"},
		Stages: []campaign.Stage{
			{
				ID: "s1", Name: "Exfiltrate via Email",
				Technique: "T1048", Tactic: "exfiltration",
				Execute: campaign.Execute{Type: "http"},
				Expect: campaign.Expect{
					Telemetry: []string{"email_sent"},
				},
			},
		},
	}

	r := SimulatePolicy(p, c)
	// Should find send_email from telemetry and deny it.
	foundDeny := false
	for _, stage := range r.Stages {
		for _, d := range stage.Decisions {
			if d.Tool == "send_email" && d.Effect == "deny" {
				foundDeny = true
			}
		}
	}
	if !foundDeny {
		t.Error("expected send_email to be denied via telemetry inference")
	}
}

func TestSimulatePolicy_PriorityOrder(t *testing.T) {
	t.Parallel()

	// High-priority allow should override low-priority deny.
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "priority-test"},
		Agent:      AgentScope{Name: "test-agent"},
		Rules: []Rule{
			{
				ID:          "low-deny",
				Description: "Low priority deny",
				Effect:      "deny",
				Priority:    10,
				Match:       RuleMatch{Tools: []string{"shell_exec"}},
			},
			{
				ID:          "high-allow",
				Description: "High priority allow",
				Effect:      "allow",
				Priority:    100,
				Match:       RuleMatch{Tools: []string{"shell_exec"}},
			},
		},
	}

	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "priority-campaign"},
		Stages: []campaign.Stage{
			{
				ID: "s1", Name: "Shell Command",
				Technique: "T1059", Tactic: "execution",
				Execute: campaign.Execute{Type: "shell"},
			},
		},
	}

	r := SimulatePolicy(p, c)
	if r.TotalAllowed != 1 {
		t.Errorf("expected 1 allowed (high-priority allow wins), got %d", r.TotalAllowed)
	}
	if r.TotalDenied != 0 {
		t.Errorf("expected 0 denied, got %d", r.TotalDenied)
	}
	if r.Stages[0].Decisions[0].RuleID != "high-allow" {
		t.Errorf("expected rule %q to win, got %q", "high-allow", r.Stages[0].Decisions[0].RuleID)
	}
}

// --- FormatSimulationReport tests ---

func TestFormatSimulationReport_BoxDrawing(t *testing.T) {
	t.Parallel()

	r := &SimulationReport{
		Policy:       "test-policy",
		Campaign:     "test-campaign",
		TotalAllowed: 2,
		TotalDenied:  1,
		TotalAlerted: 0,
		TotalTools:   3,
		CoveragePct:  33.3,
		Stages: []StageSimResult{
			{
				StageID: "s1", StageName: "Shell Command",
				Tactic: "execution", Technique: "T1059",
				Tools:   []string{"shell_exec"},
				Allowed: 0, Denied: 1,
				Decisions: []ToolDecision{
					{Tool: "shell_exec", Effect: "deny", RuleID: "deny-shell", Reason: "denied"},
				},
			},
		},
	}

	out := FormatSimulationReport(r)

	// Check box characters.
	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Error("expected box-drawing characters in output")
	}
	if !strings.Contains(out, "Policy Simulation Report") {
		t.Error("expected 'Policy Simulation Report' header")
	}
	if !strings.Contains(out, "test-policy") {
		t.Error("expected policy name in output")
	}
	if !strings.Contains(out, "test-campaign") {
		t.Error("expected campaign name in output")
	}
	if !strings.Contains(out, "shell_exec") {
		t.Error("expected tool name in output")
	}
	if !strings.Contains(out, "deny") {
		t.Error("expected 'deny' effect in output")
	}
	if !strings.Contains(out, "Summary") {
		t.Error("expected 'Summary' line in output")
	}
	if !strings.Contains(out, "Coverage") {
		t.Error("expected 'Coverage' line in output")
	}
}

func TestFormatSimulationReport_EmptyStages(t *testing.T) {
	t.Parallel()

	r := &SimulationReport{
		Policy:   "empty-pol",
		Campaign: "empty-camp",
	}

	out := FormatSimulationReport(r)
	if !strings.Contains(out, "0 allowed") {
		t.Error("expected '0 allowed' in empty report")
	}
}

// --- JSON round-trip test ---

func TestSimulationReport_JSON(t *testing.T) {
	t.Parallel()

	p := testPolicy()
	c := testCampaign()
	r := SimulatePolicy(p, c)

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("failed to marshal report to JSON: %v", err)
	}

	var decoded SimulationReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal report from JSON: %v", err)
	}

	if decoded.Policy != r.Policy {
		t.Errorf("JSON round-trip: policy %q != %q", decoded.Policy, r.Policy)
	}
	if decoded.Campaign != r.Campaign {
		t.Errorf("JSON round-trip: campaign %q != %q", decoded.Campaign, r.Campaign)
	}
	if decoded.TotalTools != r.TotalTools {
		t.Errorf("JSON round-trip: total tools %d != %d", decoded.TotalTools, r.TotalTools)
	}
	if decoded.TotalDenied != r.TotalDenied {
		t.Errorf("JSON round-trip: denied %d != %d", decoded.TotalDenied, r.TotalDenied)
	}
	if len(decoded.Stages) != len(r.Stages) {
		t.Errorf("JSON round-trip: stages %d != %d", len(decoded.Stages), len(r.Stages))
	}
}
