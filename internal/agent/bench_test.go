// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"testing"

	"gopkg.in/yaml.v3"
)

var benchAgentYAML = []byte(`api_version: v1
kind: Agent
meta:
  name: bench-agent
  type: orchestrator
  description: Benchmark agent with realistic structure
  version: "2.0"
trust:
  level: elevated
  trusts_from: [worker-1, worker-2, retrieval-agent]
  trusted_by: [admin-controller]
  boundaries: [internal-api, database]
  can_escalate: false
tools:
  - name: code-exec
    elevated: true
    actions: [execute]
    targets: [sandbox.internal]
  - name: db-query
    elevated: false
    actions: [read, query]
    targets: [postgres.internal]
  - name: http-client
    elevated: false
    actions: [read, send]
    targets: ["*.api.internal"]
  - name: file-write
    elevated: true
    actions: [write]
    targets: ["/data/*"]
guardrails:
  - type: input_filter
  - type: output_filter
  - type: rate_limit
capabilities:
  tools: true
  memory: true
  rag: true
  web_browse: false
  code_exec: true
`)

func BenchmarkAgentYAMLParse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var a Agent
		if err := yaml.Unmarshal(benchAgentYAML, &a); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAgentValidate(b *testing.B) {
	var a Agent
	if err := yaml.Unmarshal(benchAgentYAML, &a); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateAgent(&a)
	}
}

func BenchmarkTrustAnalysis(b *testing.B) {
	agents := []*Agent{
		{Meta: AgentMeta{Name: "admin", Type: TypeOrchestrator},
			Trust: TrustConfig{Level: TrustAdmin, TrustsFrom: []string{"elevated-1"}, TrustedBy: []string{}},
			Tools: []ToolAccess{{Name: "deploy", Elevated: true}}},
		{Meta: AgentMeta{Name: "elevated-1", Type: TypeToolCalling},
			Trust: TrustConfig{Level: TrustElevated, TrustsFrom: []string{"worker-1", "worker-2"}, TrustedBy: []string{"admin"}},
			Tools: []ToolAccess{{Name: "exec", Elevated: true}, {Name: "read", Elevated: false}}},
		{Meta: AgentMeta{Name: "worker-1", Type: TypeToolCalling},
			Trust: TrustConfig{Level: TrustStandard, TrustsFrom: []string{}, TrustedBy: []string{"elevated-1"}},
			Tools: []ToolAccess{{Name: "read", Elevated: false}}},
		{Meta: AgentMeta{Name: "worker-2", Type: TypeToolCalling},
			Trust: TrustConfig{Level: TrustStandard, TrustsFrom: []string{}, TrustedBy: []string{"elevated-1"}},
			Tools: []ToolAccess{{Name: "read", Elevated: false}, {Name: "exec", Elevated: false}}},
		{Meta: AgentMeta{Name: "untrusted", Type: TypeRetrieval},
			Trust: TrustConfig{Level: TrustLow},
			Tools: []ToolAccess{{Name: "query", Elevated: false}}},
	}
	inv := &Inventory{Agents: agents}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = inv.AnalyzeTrust()
	}
}

func BenchmarkBuildTrustGraph(b *testing.B) {
	agents := []*Agent{
		{Meta: AgentMeta{Name: "admin", Type: TypeOrchestrator},
			Trust: TrustConfig{Level: TrustAdmin, TrustedBy: []string{"elevated-1"}},
			Tools: []ToolAccess{{Name: "deploy", Elevated: true}}},
		{Meta: AgentMeta{Name: "elevated-1", Type: TypeToolCalling},
			Trust: TrustConfig{Level: TrustElevated, TrustsFrom: []string{"admin"}, TrustedBy: []string{"worker-1"}},
			Tools: []ToolAccess{{Name: "exec", Elevated: true}}},
		{Meta: AgentMeta{Name: "worker-1", Type: TypeToolCalling},
			Trust: TrustConfig{Level: TrustStandard, TrustsFrom: []string{"elevated-1"}},
			Tools: []ToolAccess{{Name: "read", Elevated: false}}},
	}
	inv := &Inventory{Agents: agents}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildTrustGraph(inv)
	}
}

func BenchmarkDependencyGraph(b *testing.B) {
	agents := []*Agent{
		{Meta: AgentMeta{Name: "orch", Type: TypeOrchestrator},
			Trust: TrustConfig{Level: TrustAdmin, TrustedBy: []string{"w1", "w2", "w3"}},
			Tools: []ToolAccess{{Name: "deploy", Elevated: true}, {Name: "exec", Elevated: true}}},
		{Meta: AgentMeta{Name: "w1", Type: TypeToolCalling},
			Trust: TrustConfig{Level: TrustStandard, TrustsFrom: []string{"orch"}},
			Tools: []ToolAccess{{Name: "exec", Elevated: false}, {Name: "read", Elevated: false}}},
		{Meta: AgentMeta{Name: "w2", Type: TypeToolCalling},
			Trust: TrustConfig{Level: TrustStandard, TrustsFrom: []string{"orch"}},
			Tools: []ToolAccess{{Name: "exec", Elevated: false}, {Name: "write", Elevated: false}}},
		{Meta: AgentMeta{Name: "w3", Type: TypeRetrieval},
			Trust: TrustConfig{Level: TrustLow},
			Tools: []ToolAccess{{Name: "read", Elevated: false}}},
	}
	inv := &Inventory{Agents: agents}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildDependencyGraph(inv)
	}
}
