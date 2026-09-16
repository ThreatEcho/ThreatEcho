// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

// --- Helpers ---

// testPolicy returns a minimal valid policy for testing.
func testPolicy() *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta: PolicyMeta{
			Name:        "test-policy",
			Description: "Test policy for unit tests",
		},
		Agent: AgentScope{
			Name: "test-agent",
			Type: "llm",
		},
		Rules: []Rule{
			{
				ID:          "deny-shell",
				Description: "Deny shell execution",
				Effect:      "deny",
				Priority:    100,
				Match: RuleMatch{
					Tools: []string{"shell_exec"},
				},
			},
		},
	}
}

// testCampaign returns an inline campaign fixture for evaluation tests.
func testCampaign() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "test-campaign",
			Adversary: "test-actor",
			Severity:  "high",
		},
		Stages: []campaign.Stage{
			{
				ID:        "stage-1",
				Name:      "Shell Command Execution",
				Technique: "T1059",
				Tactic:    "execution",
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"whoami"},
				},
				Expect: campaign.Expect{
					Telemetry:  []string{"process_create"},
					Detections: []string{"shell_detected"},
				},
			},
			{
				ID:        "stage-2",
				Name:      "HTTP C2 Beacon",
				Technique: "T1071.001",
				Tactic:    "command-and-control",
				Execute: campaign.Execute{
					Type:   "http",
					Target: "https://c2.evil.com/beacon",
				},
				Expect: campaign.Expect{
					Telemetry:  []string{"network_connection"},
					Detections: []string{"c2_beacon_detected"},
				},
			},
			{
				ID:        "stage-3",
				Name:      "Tool Abuse via Agent",
				Technique: "LLM06",
				Tactic:    "ml-model-access",
				Execute: campaign.Execute{
					Type:   "http",
					Target: "https://agent.target.com/api/v1/chat",
				},
				Expect: campaign.Expect{
					Telemetry:  []string{"tool_call", "guardrail_trigger"},
					Detections: []string{"unauthorized_tool_invocation"},
				},
			},
		},
	}
}

// agentCampaign returns a campaign with agent-specific telemetry for tool inference tests.
func agentCampaign() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "agent-hijack",
			Adversary: "AI Threat Actor",
			Severity:  "critical",
		},
		Stages: []campaign.Stage{
			{
				ID:        "email-exfil",
				Name:      "Data Exfiltration via Email",
				Technique: "AML.T0042",
				Tactic:    "exfiltration",
				Execute: campaign.Execute{
					Type:   "http",
					Target: "https://agent.target.com/api/v1/chat",
				},
				Expect: campaign.Expect{
					Telemetry: []string{"email_sent", "tool_call"},
				},
			},
			{
				ID:        "rag-poison",
				Name:      "RAG Knowledge Base Poisoning",
				Technique: "AML.T0050",
				Tactic:    "persistence",
				Execute: campaign.Execute{
					Type:   "http",
					Target: "https://agent.target.com/api/v1/chat",
				},
				Expect: campaign.Expect{
					Telemetry: []string{"embedding_query", "vector_store_write"},
				},
			},
			{
				ID:        "agent-lateral",
				Name:      "Agent-to-Agent Propagation",
				Technique: "AML.T0015",
				Tactic:    "lateral-movement",
				Execute: campaign.Execute{
					Type:   "http",
					Target: "https://agent.target.com/api/v1/chat",
				},
				Expect: campaign.Expect{
					Telemetry: []string{"inter_agent_message", "tool_call"},
				},
			},
		},
	}
}

// --- Tests ---

func TestLoadPolicy(t *testing.T) {
	// Write a temp policy YAML.
	dir := t.TempDir()
	content := `api_version: v1
kind: Policy
meta:
  name: test-load
  description: Load test policy
  created: "2026-09-14"
  modified: "2026-09-14"
agent:
  name: test-agent
  type: llm
rules:
  - id: deny-shell
    description: Block shell execution
    effect: deny
    priority: 100
    match:
      tools: ["shell_exec"]
`

	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	// Load from file path.
	p, err := LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy file: %v", err)
	}
	if p.Meta.Name != "test-load" {
		t.Errorf("expected name 'test-load', got %q", p.Meta.Name)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Rules))
	}
	if p.Rules[0].Effect != "deny" {
		t.Errorf("expected effect 'deny', got %q", p.Rules[0].Effect)
	}

	// Load from directory.
	p2, err := LoadPolicy(dir)
	if err != nil {
		t.Fatalf("LoadPolicy dir: %v", err)
	}
	if p2.Meta.Name != "test-load" {
		t.Errorf("dir load: expected name 'test-load', got %q", p2.Meta.Name)
	}

	// Load from non-existent path.
	_, err = LoadPolicy("/nonexistent/policy.yaml")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestValidatePolicy_Valid(t *testing.T) {
	p := testPolicy()
	errs := ValidatePolicy(p)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidatePolicy_MissingFields(t *testing.T) {
	p := &Policy{} // Empty policy.
	errs := ValidatePolicy(p)

	// Should flag: api_version, kind, meta.name, agent.name, no rules.
	if len(errs) < 4 {
		t.Errorf("expected at least 4 errors for empty policy, got %d: %v", len(errs), errs)
	}

	// Check specific messages.
	found := map[string]bool{}
	for _, e := range errs {
		found[e] = true
	}
	for _, expected := range []string{
		"missing api_version",
		"missing kind",
		"meta.name is required",
		"agent.name is required",
		"policy must have at least one rule",
	} {
		if !found[expected] {
			t.Errorf("missing expected error: %q", expected)
		}
	}
}

func TestValidatePolicy_InvalidEffect(t *testing.T) {
	p := testPolicy()
	p.Rules[0].Effect = "block" // Not a valid effect.

	errs := ValidatePolicy(p)
	if len(errs) == 0 {
		t.Fatal("expected error for invalid effect")
	}

	found := false
	for _, e := range errs {
		if e == `rules[0] (deny-shell): effect "block" is not valid (use deny/allow/alert)` {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected invalid effect error, got: %v", errs)
	}
}

func TestEvaluate_DenyRule_MatchesTactic(t *testing.T) {
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "tactic-deny"},
		Agent:      AgentScope{Name: "*"},
		Rules: []Rule{
			{
				ID:          "deny-c2",
				Description: "Deny command-and-control tactic",
				Effect:      "deny",
				Priority:    100,
				Match: RuleMatch{
					Tactics: []string{"command-and-control"},
				},
			},
		},
	}

	c := testCampaign()
	result := Evaluate(p, c)

	if result.Denied != 1 {
		t.Errorf("expected 1 denied, got %d", result.Denied)
	}
	if result.Allowed != 2 {
		t.Errorf("expected 2 allowed, got %d", result.Allowed)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	v := result.Violations[0]
	if v.StageID != "stage-2" {
		t.Errorf("expected violation on stage-2, got %q", v.StageID)
	}
	if v.Effect != "deny" {
		t.Errorf("expected deny effect, got %q", v.Effect)
	}
}

func TestEvaluate_DenyRule_MatchesTool(t *testing.T) {
	p := testPolicy() // Denies shell_exec.
	c := testCampaign()

	result := Evaluate(p, c)

	if result.Denied != 1 {
		t.Errorf("expected 1 denied (shell), got %d", result.Denied)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].StageID != "stage-1" {
		t.Errorf("expected violation on stage-1, got %q", result.Violations[0].StageID)
	}
	if result.Violations[0].Tool != "shell_exec" {
		t.Errorf("expected tool 'shell_exec', got %q", result.Violations[0].Tool)
	}
}

func TestEvaluate_AllowRule_Override(t *testing.T) {
	// Higher-priority allow rule overrides a lower-priority deny.
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "allow-override"},
		Agent:      AgentScope{Name: "*"},
		Rules: []Rule{
			{
				ID:          "allow-shell",
				Description: "Allow shell for this agent",
				Effect:      "allow",
				Priority:    200, // Higher priority.
				Match: RuleMatch{
					Tools: []string{"shell_exec"},
				},
			},
			{
				ID:          "deny-all-exec",
				Description: "Deny all execution",
				Effect:      "deny",
				Priority:    100,
				Match: RuleMatch{
					Actions: []string{"execute"},
				},
			},
		},
	}

	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "override-test"},
		Stages: []campaign.Stage{
			{
				ID:      "s1",
				Name:    "Shell Stage",
				Tactic:  "execution",
				Execute: campaign.Execute{Type: "shell"},
			},
		},
	}

	result := Evaluate(p, c)

	// The allow rule (priority 200) should win over deny (priority 100).
	if result.Allowed != 1 {
		t.Errorf("expected 1 allowed, got %d", result.Allowed)
	}
	if result.Denied != 0 {
		t.Errorf("expected 0 denied, got %d", result.Denied)
	}
}

func TestEvaluate_AlertRule(t *testing.T) {
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "alert-test"},
		Agent:      AgentScope{Name: "*"},
		Rules: []Rule{
			{
				ID:          "alert-email",
				Description: "Alert on email sends",
				Effect:      "alert",
				Priority:    100,
				Match: RuleMatch{
					Tools: []string{"send_email"},
				},
			},
		},
	}

	c := agentCampaign()
	result := Evaluate(p, c)

	if result.Alerted != 1 {
		t.Errorf("expected 1 alerted, got %d", result.Alerted)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	v := result.Violations[0]
	if v.Effect != "alert" {
		t.Errorf("expected alert effect, got %q", v.Effect)
	}
	if v.StageID != "email-exfil" {
		t.Errorf("expected email-exfil stage, got %q", v.StageID)
	}
}

func TestEvaluate_ConditionField(t *testing.T) {
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "cond-test"},
		Agent:      AgentScope{Name: "*"},
		Rules: []Rule{
			{
				ID:          "deny-elevated-shell",
				Description: "Deny elevated shell only",
				Effect:      "deny",
				Priority:    100,
				Match: RuleMatch{
					Tools: []string{"shell_exec"},
				},
				Conditions: []Condition{
					{Field: "elevated", Operator: "eq", Value: "true"},
				},
			},
		},
	}

	// Campaign with one elevated and one non-elevated shell stage.
	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "cond-campaign"},
		Stages: []campaign.Stage{
			{
				ID:      "elevated-shell",
				Name:    "Elevated Shell",
				Tactic:  "execution",
				Execute: campaign.Execute{Type: "shell", Elevated: true},
			},
			{
				ID:      "normal-shell",
				Name:    "Normal Shell",
				Tactic:  "execution",
				Execute: campaign.Execute{Type: "shell", Elevated: false},
			},
		},
	}

	result := Evaluate(p, c)

	if result.Denied != 1 {
		t.Errorf("expected 1 denied (elevated only), got %d", result.Denied)
	}
	if result.Allowed != 1 {
		t.Errorf("expected 1 allowed (non-elevated), got %d", result.Allowed)
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].StageID != "elevated-shell" {
		t.Errorf("expected violation on elevated-shell, got %q", result.Violations[0].StageID)
	}
}

func TestEvaluate_PriorityOrdering(t *testing.T) {
	// Two rules that both match, different priorities.
	// Higher priority deny should win over lower priority allow.
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "priority-test"},
		Agent:      AgentScope{Name: "*"},
		Rules: []Rule{
			{
				ID:       "low-allow",
				Effect:   "allow",
				Priority: 10,
				Match:    RuleMatch{Tactics: []string{"execution"}},
			},
			{
				ID:       "high-deny",
				Effect:   "deny",
				Priority: 50,
				Match:    RuleMatch{Tactics: []string{"execution"}},
			},
		},
	}

	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "p-test"},
		Stages: []campaign.Stage{
			{
				ID:      "s1",
				Name:    "Exec",
				Tactic:  "execution",
				Execute: campaign.Execute{Type: "shell"},
			},
		},
	}

	result := Evaluate(p, c)

	// high-deny (50) should win over low-allow (10).
	if result.Denied != 1 {
		t.Errorf("expected 1 denied (high priority), got %d", result.Denied)
	}
	if result.Allowed != 0 {
		t.Errorf("expected 0 allowed, got %d", result.Allowed)
	}
}

func TestEvaluate_NoMatchImplicitAllow(t *testing.T) {
	// Rules that don't match any stage → implicit allow.
	p := &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "nomatch-test"},
		Agent:      AgentScope{Name: "*"},
		Rules: []Rule{
			{
				ID:       "deny-dns",
				Effect:   "deny",
				Priority: 100,
				Match:    RuleMatch{Tools: []string{"dns_query"}},
			},
		},
	}

	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "nm-test"},
		Stages: []campaign.Stage{
			{
				ID:      "s1",
				Name:    "Shell Only",
				Tactic:  "execution",
				Execute: campaign.Execute{Type: "shell"},
			},
		},
	}

	result := Evaluate(p, c)

	if result.Allowed != 1 {
		t.Errorf("expected 1 allowed (implicit), got %d", result.Allowed)
	}
	if result.Denied != 0 {
		t.Errorf("expected 0 denied, got %d", result.Denied)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(result.Violations))
	}
}

func TestToolInference(t *testing.T) {
	tests := []struct {
		name     string
		stage    campaign.Stage
		expected []string
	}{
		{
			name: "shell exec type",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "shell"},
			},
			expected: []string{"shell_exec"},
		},
		{
			name: "http exec type",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "http"},
			},
			expected: []string{"http_request"},
		},
		{
			name: "dns exec type",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "dns"},
			},
			expected: []string{"dns_query"},
		},
		{
			name: "file exec type",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "file"},
			},
			expected: []string{"file_access"},
		},
		{
			name: "email_sent telemetry",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "http"},
				Expect: campaign.Expect{
					Telemetry: []string{"email_sent"},
				},
			},
			expected: []string{"http_request", "send_email"},
		},
		{
			name: "embedding_query telemetry",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "http"},
				Expect: campaign.Expect{
					Telemetry: []string{"embedding_query"},
				},
			},
			expected: []string{"http_request", "search_knowledge_base"},
		},
		{
			name: "vector_store_write telemetry",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "http"},
				Expect: campaign.Expect{
					Telemetry: []string{"vector_store_write"},
				},
			},
			expected: []string{"http_request", "write_knowledge_base"},
		},
		{
			name: "inter_agent_message telemetry",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "http"},
				Expect: campaign.Expect{
					Telemetry: []string{"inter_agent_message"},
				},
			},
			expected: []string{"http_request", "agent_message"},
		},
		{
			name: "tool_call telemetry",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "http"},
				Expect: campaign.Expect{
					Telemetry: []string{"tool_call"},
				},
			},
			expected: []string{"http_request", "tool_call"},
		},
		{
			name: "combined exec + multiple telemetry",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "http"},
				Expect: campaign.Expect{
					Telemetry: []string{"tool_call", "email_sent", "embedding_query"},
				},
			},
			expected: []string{"http_request", "tool_call", "send_email", "search_knowledge_base"},
		},
		{
			name: "no known telemetry",
			stage: campaign.Stage{
				Execute: campaign.Execute{Type: "http"},
				Expect: campaign.Expect{
					Telemetry: []string{"network_connection", "dns_query_log"},
				},
			},
			expected: []string{"http_request"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InferTools(tt.stage)
			if len(got) != len(tt.expected) {
				t.Fatalf("expected %d tools %v, got %d tools %v", len(tt.expected), tt.expected, len(got), got)
			}
			for i, tool := range tt.expected {
				if got[i] != tool {
					t.Errorf("tool[%d]: expected %q, got %q", i, tool, got[i])
				}
			}
		})
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		// Exact match.
		{"shell_exec", "shell_exec", true},
		{"shell_exec", "http_request", false},

		// Simple glob.
		{"shell_*", "shell_exec", true},
		{"shell_*", "shell_remote", true},
		{"shell_*", "http_request", false},

		// Wildcard prefix.
		{"*_exec", "shell_exec", true},
		{"*_exec", "process_exec", true},
		{"*_exec", "http_request", false},

		// Middle wildcard.
		{"*knowledge*", "search_knowledge_base", true},
		{"*knowledge*", "write_knowledge_base", true},
		{"*knowledge*", "shell_exec", false},

		// URL-like patterns.
		{"https://*.evil.com/*", "https://c2.evil.com/beacon", true},
		{"https://*.evil.com/*", "https://legit.example.com/api", false},

		// Single char glob (path.Match).
		{"shell_e?ec", "shell_exec", true},
		{"shell_e?ec", "shell_exxxxxec", false},

		// No match.
		{"dns_query", "shell_exec", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.name, func(t *testing.T) {
			got := GlobMatch(tt.pattern, tt.name)
			if got != tt.want {
				t.Errorf("GlobMatch(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
			}
		})
	}
}
