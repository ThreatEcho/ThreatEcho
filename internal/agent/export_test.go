// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestExportInventory_NilInventory(t *testing.T) {
	snap := ExportInventory(nil)
	if snap.GeneratedBy != "threatecho" {
		t.Errorf("expected generated_by threatecho, got %q", snap.GeneratedBy)
	}
	if snap.AgentCount != 0 {
		t.Errorf("expected 0 agents, got %d", snap.AgentCount)
	}
}

func TestExportInventory_EmptyInventory(t *testing.T) {
	inv := &Inventory{}
	snap := ExportInventory(inv)
	if snap.AgentCount != 0 {
		t.Errorf("expected 0 agents, got %d", snap.AgentCount)
	}
}

func TestExportInventory_WithAgents(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:         AgentMeta{Name: "test-agent", Type: TypeToolCalling, Version: "1.0", Model: "gpt-4"},
				Trust:        TrustConfig{Level: TrustStandard, Boundaries: []string{"internal"}},
				Tools:        []ToolAccess{{Name: "db.read"}, {Name: "db.write", Elevated: true}},
				Capabilities: AgentCapabilities{ToolCalling: true, RAG: true},
				Guardrails:   []Guardrail{{Name: "input-filter", Type: "input", Enforced: true}},
			},
		},
	}
	snap := ExportInventory(inv)

	if snap.AgentCount != 1 {
		t.Fatalf("expected 1 agent, got %d", snap.AgentCount)
	}

	as := snap.Agents[0]
	if as.Name != "test-agent" {
		t.Errorf("expected agent name test-agent, got %q", as.Name)
	}
	if as.Type != TypeToolCalling {
		t.Errorf("expected type tool-calling, got %q", as.Type)
	}
	if as.Trust != TrustStandard {
		t.Errorf("expected trust standard, got %q", as.Trust)
	}
	if as.Model != "gpt-4" {
		t.Errorf("expected model gpt-4, got %q", as.Model)
	}
	if as.ToolCount != 2 {
		t.Errorf("expected 2 tools, got %d", as.ToolCount)
	}
	if as.Guardrails != 1 {
		t.Errorf("expected 1 guardrail, got %d", as.Guardrails)
	}

	// Check tool labels.
	found := false
	for _, tool := range as.Tools {
		if tool == "db.write (elevated)" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'db.write (elevated)' in tools")
	}

	// Check capabilities.
	if len(as.Capabilities) == 0 {
		t.Error("expected capabilities to be populated")
	}
}

func TestExportInventory_TrustGraphSummary(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:  AgentMeta{Name: "admin", Type: TypeOrchestrator, Version: "1.0"},
				Trust: TrustConfig{Level: TrustAdmin},
			},
			{
				Meta:  AgentMeta{Name: "worker", Type: TypeToolCalling, Version: "1.0"},
				Trust: TrustConfig{Level: TrustLow, TrustedBy: []string{"admin"}},
			},
		},
	}
	snap := ExportInventory(inv)
	if snap.TrustGraph == nil {
		t.Fatal("expected trust graph summary")
	}
	if len(snap.TrustGraph.AdminAgents) == 0 {
		t.Error("expected admin agents in trust graph")
	}
}

func TestExportInventory_GuardrailSummary(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:         AgentMeta{Name: "worker", Type: TypeToolCalling, Version: "1.0"},
				Trust:        TrustConfig{Level: TrustStandard},
				Capabilities: AgentCapabilities{ToolCalling: true},
				// Missing tool-call guardrail → gap
			},
		},
	}
	snap := ExportInventory(inv)
	if snap.GuardrailSummary == nil {
		t.Fatal("expected guardrail summary")
	}
	if snap.GuardrailSummary.TotalGaps == 0 {
		t.Error("expected at least one guardrail gap")
	}
}

func TestExportJSON(t *testing.T) {
	snap := &InventorySnapshot{
		GeneratedBy: "threatecho",
		AgentCount:  1,
		Agents: []AgentSnapshot{
			{Name: "test", Type: "tool-calling", Trust: "standard"},
		},
	}
	data, err := ExportJSON(snap)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	// Verify valid JSON.
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["agent_count"].(float64) != 1 {
		t.Error("expected agent_count 1")
	}
}

func TestExportYAML(t *testing.T) {
	snap := &InventorySnapshot{
		GeneratedBy: "threatecho",
		AgentCount:  2,
		Agents: []AgentSnapshot{
			{Name: "a1", Type: "retrieval", Trust: "low"},
			{Name: "a2", Type: "orchestrator", Trust: "admin"},
		},
	}
	data, err := ExportYAML(snap)
	if err != nil {
		t.Fatalf("ExportYAML failed: %v", err)
	}

	// Verify valid YAML.
	var result map[string]interface{}
	if err := yaml.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}
	if result["agent_count"].(int) != 2 {
		t.Error("expected agent_count 2")
	}
}

func TestExportMarkdown(t *testing.T) {
	snap := &InventorySnapshot{
		GeneratedBy: "threatecho",
		AgentCount:  1,
		Agents: []AgentSnapshot{
			{
				Name:         "billing-bot",
				Type:         "tool-calling",
				Trust:        "elevated",
				Model:        "claude-3",
				ToolCount:    3,
				Guardrails:   2,
				Tools:        []string{"db.read", "payment.charge (elevated)"},
				Capabilities: []string{"tool_calling", "rag"},
				Boundaries:   []string{"financial"},
				Risks:        []string{"elevated tool without deny rule"},
			},
		},
		TrustGraph: &TrustAnalysisSummary{
			TotalEdges:      2,
			EscalationPaths: 1,
			RiskCount:       1,
			AdminAgents:     []string{"orchestrator"},
		},
		GuardrailSummary: &GuardrailSummary{
			TotalGaps:         3,
			CriticalGaps:      1,
			FullyCoveredCount: 0,
		},
	}

	md := ExportMarkdown(snap)

	checks := []string{
		"# Agent Inventory Report",
		"billing-bot",
		"tool-calling",
		"elevated",
		"claude-3",
		"payment.charge (elevated)",
		"tool_calling",
		"financial",
		"Trust Graph",
		"Guardrail Status",
		"⚠ Risks",
	}
	for _, check := range checks {
		if !strings.Contains(md, check) {
			t.Errorf("markdown should contain %q", check)
		}
	}
}

func TestExportMarkdown_NoTrustGraph(t *testing.T) {
	snap := &InventorySnapshot{
		GeneratedBy: "threatecho",
		AgentCount:  0,
	}
	md := ExportMarkdown(snap)
	if !strings.Contains(md, "# Agent Inventory Report") {
		t.Error("markdown should contain header")
	}
}

func TestExportMarkdown_NoRisks(t *testing.T) {
	snap := &InventorySnapshot{
		GeneratedBy: "threatecho",
		AgentCount:  1,
		Agents: []AgentSnapshot{
			{Name: "safe-bot", Type: "retrieval", Trust: "standard"},
		},
	}
	md := ExportMarkdown(snap)
	if strings.Contains(md, "⚠ Risks") {
		t.Error("markdown should not contain risks section for agent with no risks")
	}
}
