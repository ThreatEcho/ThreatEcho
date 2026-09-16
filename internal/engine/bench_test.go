// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"context"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

func benchInventory() *agent.Inventory {
	return &agent.Inventory{
		Agents: []*agent.Agent{
			{Meta: agent.AgentMeta{Name: "admin", Type: agent.TypeOrchestrator},
				Trust:      agent.TrustConfig{Level: agent.TrustAdmin, TrustedBy: []string{"worker-1", "worker-2"}},
				Tools:      []agent.ToolAccess{{Name: "deploy", Elevated: true}, {Name: "ssh", Elevated: true}},
				Guardrails: []agent.Guardrail{{Type: "rate_limit"}}},
			{Meta: agent.AgentMeta{Name: "worker-1", Type: agent.TypeToolCalling},
				Trust: agent.TrustConfig{Level: agent.TrustStandard, TrustsFrom: []string{"admin"}},
				Tools: []agent.ToolAccess{{Name: "exec", Elevated: false}, {Name: "read", Elevated: false}}},
			{Meta: agent.AgentMeta{Name: "worker-2", Type: agent.TypeToolCalling},
				Trust: agent.TrustConfig{Level: agent.TrustStandard, TrustsFrom: []string{"admin"}},
				Tools: []agent.ToolAccess{{Name: "exec", Elevated: false}, {Name: "write", Elevated: false}}},
			{Meta: agent.AgentMeta{Name: "retrieval", Type: agent.TypeRetrieval},
				Trust: agent.TrustConfig{Level: agent.TrustLow},
				Tools: []agent.ToolAccess{{Name: "read", Elevated: false}}},
		},
	}
}

func benchPolicies() []*policy.Policy {
	return []*policy.Policy{
		{Meta: policy.PolicyMeta{Name: "default"},
			Rules: []policy.Rule{
				{ID: "deny-exec", Effect: "deny", Priority: 100,
					Match: policy.RuleMatch{Tools: []string{"exec"}, Tactics: []string{"execution"}}},
				{ID: "alert-exfil", Effect: "alert", Priority: 90,
					Match: policy.RuleMatch{Tactics: []string{"exfiltration"}}},
				{ID: "allow-read", Effect: "allow", Priority: 50,
					Match: policy.RuleMatch{Tools: []string{"read"}, Actions: []string{"read"}}},
			},
		},
	}
}

func BenchmarkBuildAttackTree(b *testing.B) {
	inv := benchInventory()
	policies := benchPolicies()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildAttackTree(inv, policies)
	}
}

func BenchmarkGenerateThreatModel(b *testing.B) {
	inv := benchInventory()
	policies := benchPolicies()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GenerateThreatModel(inv, policies)
	}
}

func BenchmarkAssessRisk(b *testing.B) {
	inv := benchInventory()
	policies := benchPolicies()
	tm := GenerateThreatModel(inv, policies)
	inputs := &RiskInputs{ThreatModel: tm}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AssessRisk(nil, inputs)
	}
}

func BenchmarkSimulate(b *testing.B) {
	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "bench"},
		Stages: []campaign.Stage{
			{ID: "s1", Name: "Recon", Tactic: "discovery", Execute: campaign.Execute{Type: "shell", Commands: []string{"echo 1"}}},
			{ID: "s2", Name: "Exploit", Tactic: "execution", DependsOn: []string{"s1"}, Execute: campaign.Execute{Type: "shell", Commands: []string{"echo 2"}}},
			{ID: "s3", Name: "Persist", Tactic: "persistence", DependsOn: []string{"s2"}, Execute: campaign.Execute{Type: "shell", Commands: []string{"echo 3"}}},
			{ID: "s4", Name: "Exfil", Tactic: "exfiltration", DependsOn: []string{"s3"}, Execute: campaign.Execute{Type: "http", Target: "https://example.com"}},
		},
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Simulate(ctx, c, Options{})
	}
}

func BenchmarkCaptureBaseline(b *testing.B) {
	inv := benchInventory()
	policies := benchPolicies()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CaptureBaseline(policies, inv, "bench")
	}
}
