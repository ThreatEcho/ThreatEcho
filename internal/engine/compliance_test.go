// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Test helpers — all prefixed with mkComp
// ---------------------------------------------------------------------------

// mkCompAgent returns a minimal agent with standard trust, no guardrails,
// no description, no capabilities — the baseline non-compliant agent.
func mkCompAgent(name string) *agent.Agent {
	return &agent.Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta: agent.AgentMeta{
			Name:  name,
			Type:  agent.TypeConversational,
			Model: "test-model",
		},
		Trust: agent.TrustConfig{
			Level: agent.TrustStandard,
		},
	}
}

// mkCompAgentWithDesc returns an agent with a description set.
func mkCompAgentWithDesc(name, desc string) *agent.Agent {
	a := mkCompAgent(name)
	a.Meta.Description = desc
	return a
}

// mkCompAgentFull returns a fully compliant agent: description, all
// guardrail types, trust level, rate-limited tools.
func mkCompAgentFull(name string) *agent.Agent {
	return &agent.Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta: agent.AgentMeta{
			Name:        name,
			Type:        agent.TypeToolCalling,
			Description: "A fully configured test agent for compliance",
			Model:       "test-model",
			Version:     "1.0.0",
			Owner:       "test-owner",
		},
		Capabilities: agent.AgentCapabilities{
			ToolCalling:    true,
			RAG:            true,
			WebAccess:      true,
			FileAccess:     true,
			MessagePassing: true,
			Memory:         true,
		},
		Tools: []agent.ToolAccess{
			{Name: "search", Actions: []string{"read", "query"}, RateLimit: 100},
			{Name: "writer", Actions: []string{"write"}, RateLimit: 50},
		},
		Trust: agent.TrustConfig{
			Level:      agent.TrustElevated,
			Boundaries: []string{"internal", "external"},
		},
		Guardrails: []agent.Guardrail{
			{Name: "input-filter", Type: "input", Enforced: true},
			{Name: "output-filter", Type: "output", Enforced: true},
			{Name: "tool-guard", Type: "tool-call", Enforced: true},
			{Name: "content-guard", Type: "content-filter", Enforced: true},
		},
	}
}

// mkCompAgentAutonomous returns an autonomous agent with guardrails.
func mkCompAgentAutonomous(name string) *agent.Agent {
	a := mkCompAgentFull(name)
	a.Meta.Type = agent.TypeAutonomous
	a.Capabilities.Autonomous = true
	a.Trust.Level = agent.TrustElevated
	return a
}

// mkCompAgentUntrusted returns an agent with untrusted level and no
// guardrails.
func mkCompAgentUntrusted(name string) *agent.Agent {
	a := mkCompAgent(name)
	a.Trust.Level = agent.TrustUntrusted
	return a
}

// mkCompPolicy returns a basic policy with one wildcard deny rule.
func mkCompPolicy(agentName string) *policy.Policy {
	return &policy.Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       policy.PolicyMeta{Name: "test-policy"},
		Agent:      policy.AgentScope{Name: agentName},
		Rules: []policy.Rule{
			{ID: "r1", Effect: "deny", Match: policy.RuleMatch{Tools: []string{"*"}}},
		},
	}
}

// mkCompPolicyFull returns a policy with deny, alert, action, target, and
// tool rules — maximally covering every compliance check.
func mkCompPolicyFull(agentName string) *policy.Policy {
	return &policy.Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       policy.PolicyMeta{Name: "full-policy"},
		Agent:      policy.AgentScope{Name: agentName},
		Rules: []policy.Rule{
			{ID: "deny-exfil", Effect: "deny", Match: policy.RuleMatch{
				Actions: []string{"send", "write"},
				Targets: []string{"*.external.com"},
			}},
			{ID: "deny-exec", Effect: "deny", Match: policy.RuleMatch{
				Actions: []string{"execute"},
			}},
			{ID: "alert-read", Effect: "alert", Match: policy.RuleMatch{
				Actions: []string{"read", "query"},
			}},
			{ID: "deny-tools", Effect: "deny", Match: policy.RuleMatch{
				Tools: []string{"shell_exec", "dangerous_*"},
			}},
			{ID: "alert-all", Effect: "alert", Match: policy.RuleMatch{
				Tools: []string{"*"},
			}},
		},
	}
}

// mkCompPolicyAlert returns a policy with one alert rule.
func mkCompPolicyAlert(agentName string) *policy.Policy {
	return &policy.Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       policy.PolicyMeta{Name: "alert-policy"},
		Agent:      policy.AgentScope{Name: agentName},
		Rules: []policy.Rule{
			{ID: "alert-1", Effect: "alert", Match: policy.RuleMatch{Tools: []string{"*"}}},
		},
	}
}

// mkCompInventory wraps agents in an Inventory.
func mkCompInventory(agents ...*agent.Agent) *agent.Inventory {
	return &agent.Inventory{Agents: agents}
}

// mkCompFindMapping finds a mapping by control ID in a report.
func mkCompFindMapping(r *ComplianceReport, controlID string) *ControlMapping {
	for i, m := range r.Mappings {
		if m.Control.ID == controlID {
			return &r.Mappings[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Framework listing and retrieval tests
// ---------------------------------------------------------------------------

func TestListFrameworks(t *testing.T) {
	t.Parallel()
	fws := ListFrameworks()
	if len(fws) != 3 {
		t.Fatalf("expected 3 frameworks, got %d", len(fws))
	}
}

func TestListFrameworksIDs(t *testing.T) {
	t.Parallel()
	fws := ListFrameworks()
	ids := make(map[string]bool)
	for _, fw := range fws {
		ids[fw.ID] = true
	}
	for _, want := range []string{"nist-ai-rmf", "owasp-llm-top10", "mitre-atlas"} {
		if !ids[want] {
			t.Errorf("missing framework ID %q", want)
		}
	}
}

func TestListFrameworksNonEmpty(t *testing.T) {
	t.Parallel()
	for _, fw := range ListFrameworks() {
		if fw.Name == "" {
			t.Errorf("framework %q has empty name", fw.ID)
		}
		if fw.Version == "" {
			t.Errorf("framework %q has empty version", fw.ID)
		}
		if len(fw.Controls) == 0 {
			t.Errorf("framework %q has no controls", fw.ID)
		}
	}
}

func TestGetFramework_NIST(t *testing.T) {
	t.Parallel()
	fw, ok := GetFramework("nist-ai-rmf")
	if !ok {
		t.Fatal("expected to find nist-ai-rmf")
	}
	if fw.Name != "NIST AI Risk Management Framework" {
		t.Errorf("unexpected name: %q", fw.Name)
	}
}

func TestGetFramework_OWASP(t *testing.T) {
	t.Parallel()
	fw, ok := GetFramework("owasp-llm-top10")
	if !ok {
		t.Fatal("expected to find owasp-llm-top10")
	}
	if fw.Name != "OWASP LLM Top 10" {
		t.Errorf("unexpected name: %q", fw.Name)
	}
}

func TestGetFramework_ATLAS(t *testing.T) {
	t.Parallel()
	fw, ok := GetFramework("mitre-atlas")
	if !ok {
		t.Fatal("expected to find mitre-atlas")
	}
	if fw.Name != "MITRE ATLAS" {
		t.Errorf("unexpected name: %q", fw.Name)
	}
}

func TestGetFramework_NotFound(t *testing.T) {
	t.Parallel()
	_, ok := GetFramework("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent ID")
	}
}

func TestGetFramework_EmptyID(t *testing.T) {
	t.Parallel()
	_, ok := GetFramework("")
	if ok {
		t.Error("expected not found for empty ID")
	}
}

// ---------------------------------------------------------------------------
// Framework control count tests
// ---------------------------------------------------------------------------

func TestNISTControlCount(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	if len(fw.Controls) != 10 {
		t.Errorf("expected 10 NIST controls, got %d", len(fw.Controls))
	}
}

func TestOWASPControlCount(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	if len(fw.Controls) != 10 {
		t.Errorf("expected 10 OWASP controls, got %d", len(fw.Controls))
	}
}

func TestATLASControlCount(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("mitre-atlas")
	if len(fw.Controls) != 8 {
		t.Errorf("expected 8 ATLAS controls, got %d", len(fw.Controls))
	}
}

func TestControlSeveritiesValid(t *testing.T) {
	t.Parallel()
	valid := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	for _, fw := range ListFrameworks() {
		for _, ctrl := range fw.Controls {
			if !valid[ctrl.Severity] {
				t.Errorf("framework %q control %q has invalid severity %q", fw.ID, ctrl.ID, ctrl.Severity)
			}
		}
	}
}

func TestControlIDsUnique(t *testing.T) {
	t.Parallel()
	for _, fw := range ListFrameworks() {
		seen := make(map[string]bool)
		for _, ctrl := range fw.Controls {
			if seen[ctrl.ID] {
				t.Errorf("framework %q has duplicate control ID %q", fw.ID, ctrl.ID)
			}
			seen[ctrl.ID] = true
		}
	}
}

// ---------------------------------------------------------------------------
// Edge case tests — nil / empty inputs
// ---------------------------------------------------------------------------

func TestMapCompliance_NilFramework(t *testing.T) {
	t.Parallel()
	r := MapCompliance(nil, nil, nil)
	if r == nil {
		t.Fatal("expected non-nil report")
	}
	if len(r.Mappings) != 0 {
		t.Errorf("expected 0 mappings for nil framework, got %d", len(r.Mappings))
	}
}

func TestMapCompliance_NilPolicies(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	r := MapCompliance(fw, nil, nil)
	if r == nil {
		t.Fatal("expected non-nil report")
	}
	if len(r.Mappings) != 10 {
		t.Errorf("expected 10 mappings, got %d", len(r.Mappings))
	}
}

func TestMapCompliance_NilInventory(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	r := MapCompliance(fw, []*policy.Policy{mkCompPolicyFull("*")}, nil)
	if r == nil {
		t.Fatal("expected non-nil report")
	}
	// Should still produce mappings; some controls may be partial.
	if len(r.Mappings) != 10 {
		t.Errorf("expected 10 mappings, got %d", len(r.Mappings))
	}
}

func TestMapCompliance_EmptyPolicies(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	inv := mkCompInventory(mkCompAgent("a1"))
	r := MapCompliance(fw, []*policy.Policy{}, inv)
	if r.CompliantCount+r.PartialCount > 10 {
		t.Error("empty policies should not produce more than 10 mappings")
	}
}

func TestMapCompliance_EmptyInventory(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	r := MapCompliance(fw, []*policy.Policy{mkCompPolicyFull("*")}, mkCompInventory())
	if r == nil {
		t.Fatal("expected non-nil report")
	}
}

func TestMapCompliance_NilPolicyEntry(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	policies := []*policy.Policy{nil, mkCompPolicy("*")}
	r := MapCompliance(fw, policies, mkCompInventory(mkCompAgent("a1")))
	if r == nil {
		t.Fatal("nil policy entry should not crash")
	}
}

// ---------------------------------------------------------------------------
// NIST AI RMF — full and no coverage
// ---------------------------------------------------------------------------

func TestMapCompliance_NIST_NoCoverage(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	inv := mkCompInventory(mkCompAgentUntrusted("bare"))
	r := MapCompliance(fw, nil, inv)
	if r.OverallScore > 50 {
		t.Errorf("bare agent + no policies should score below 50, got %.1f", r.OverallScore)
	}
	if r.Grade == "A" || r.Grade == "B" {
		t.Errorf("expected low grade, got %s", r.Grade)
	}
}

func TestMapCompliance_NIST_FullCoverage(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	a := mkCompAgentFull("compliant-agent")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	if r.OverallScore < 80 {
		t.Errorf("fully equipped agent should score >= 80, got %.1f", r.OverallScore)
	}
}

// ---------------------------------------------------------------------------
// OWASP — full and no coverage
// ---------------------------------------------------------------------------

func TestMapCompliance_OWASP_NoCoverage(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	inv := mkCompInventory(mkCompAgentUntrusted("bare"))
	r := MapCompliance(fw, nil, inv)
	if r.OverallScore > 50 {
		t.Errorf("expected low score, got %.1f", r.OverallScore)
	}
}

func TestMapCompliance_OWASP_FullCoverage(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	a := mkCompAgentFull("compliant-agent")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	if r.OverallScore < 70 {
		t.Errorf("fully equipped agent should score >= 70, got %.1f", r.OverallScore)
	}
}

// ---------------------------------------------------------------------------
// ATLAS — full and no coverage
// ---------------------------------------------------------------------------

func TestMapCompliance_ATLAS_NoCoverage(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("mitre-atlas")
	inv := mkCompInventory(mkCompAgentUntrusted("bare"))
	r := MapCompliance(fw, nil, inv)
	if r.OverallScore > 50 {
		t.Errorf("expected low score, got %.1f", r.OverallScore)
	}
}

func TestMapCompliance_ATLAS_FullCoverage(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("mitre-atlas")
	a := mkCompAgentFull("compliant-agent")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	if r.OverallScore < 70 {
		t.Errorf("fully equipped agent should score >= 70, got %.1f", r.OverallScore)
	}
}

// ---------------------------------------------------------------------------
// Individual control mapping tests — NIST
// ---------------------------------------------------------------------------

func TestMapCompliance_AgentDocumentation(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	inv := mkCompInventory(mkCompAgentWithDesc("a1", "documented agent"))
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "MAP-1.1")
	if m == nil {
		t.Fatal("MAP-1.1 mapping not found")
	}
	if m.Status != compCompliant {
		t.Errorf("expected compliant for documented agent, got %s", m.Status)
	}
	if m.Score != 1.0 {
		t.Errorf("expected score 1.0, got %.2f", m.Score)
	}
}

func TestMapCompliance_AgentDocumentation_Missing(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	inv := mkCompInventory(mkCompAgent("a1"))
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "MAP-1.1")
	if m.Status != compNonCompliant {
		t.Errorf("expected non_compliant for undocumented agent, got %s", m.Status)
	}
}

func TestMapCompliance_AgentDocumentation_Partial(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	inv := mkCompInventory(mkCompAgentWithDesc("a1", "has desc"), mkCompAgent("a2"))
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "MAP-1.1")
	if m.Status != compPartial {
		t.Errorf("expected partial for mixed agents, got %s", m.Status)
	}
	if m.Score != 0.5 {
		t.Errorf("expected score 0.5, got %.2f", m.Score)
	}
}

func TestMapCompliance_RiskIdentification(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	a := mkCompAgent("a1")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicy("a1")}
	r := MapCompliance(fw, policies, inv)
	m := mkCompFindMapping(r, "MAP-1.5")
	if m.Status != compCompliant {
		t.Errorf("expected compliant when agent is covered by policy, got %s", m.Status)
	}
}

func TestMapCompliance_SystemMonitoring(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	a := mkCompAgentFull("monitored")
	inv := mkCompInventory(a)
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "MEASURE-2.3")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for agent with guardrails, got %s", m.Status)
	}
}

func TestMapCompliance_HumanOversight(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	a := mkCompAgentFull("overseen")
	inv := mkCompInventory(a)
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "MANAGE-2.1")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for enforced guardrails, got %s", m.Status)
	}
}

func TestMapCompliance_HumanOversight_None(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	inv := mkCompInventory(mkCompAgent("bare"))
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "MANAGE-2.1")
	if m.Status != compNonCompliant {
		t.Errorf("expected non_compliant without enforced guardrails, got %s", m.Status)
	}
}

func TestMapCompliance_AccessControls(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	a := mkCompAgent("a1") // standard trust — should pass
	inv := mkCompInventory(a)
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "MANAGE-2.2")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for standard trust, got %s", m.Status)
	}
}

func TestMapCompliance_AccessControls_Untrusted(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	inv := mkCompInventory(mkCompAgentUntrusted("bare"))
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "MANAGE-2.2")
	if m.Status != compNonCompliant {
		t.Errorf("expected non_compliant for untrusted agent, got %s", m.Status)
	}
}

func TestMapCompliance_GovernancePolicies(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	policies := []*policy.Policy{mkCompPolicy("*")}
	r := MapCompliance(fw, policies, mkCompInventory(mkCompAgent("a1")))
	m := mkCompFindMapping(r, "GOVERN-1.1")
	if m.Status != compCompliant {
		t.Errorf("expected compliant when policies exist, got %s", m.Status)
	}
}

func TestMapCompliance_GovernancePolicies_None(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	r := MapCompliance(fw, nil, mkCompInventory(mkCompAgent("a1")))
	m := mkCompFindMapping(r, "GOVERN-1.1")
	if m.Status != compNonCompliant {
		t.Errorf("expected non_compliant without policies, got %s", m.Status)
	}
}

// ---------------------------------------------------------------------------
// Individual control mapping tests — OWASP
// ---------------------------------------------------------------------------

func TestMapCompliance_PromptInjection(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	a := mkCompAgentFull("guarded")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	m := mkCompFindMapping(r, "LLM01")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for input guardrails + deny rules, got %s", m.Status)
	}
}

func TestMapCompliance_PromptInjection_NoGuardrails(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	inv := mkCompInventory(mkCompAgent("bare"))
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	m := mkCompFindMapping(r, "LLM01")
	if m.Status != compPartial {
		t.Errorf("expected partial (policy but no guardrails), got %s", m.Status)
	}
}

func TestMapCompliance_OutputHandling(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	a := mkCompAgentFull("guarded")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	m := mkCompFindMapping(r, "LLM02")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for output guardrails, got %s", m.Status)
	}
}

func TestMapCompliance_DataPoisoning_NotApplicable(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	a := mkCompAgent("no-rag")
	inv := mkCompInventory(a)
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "LLM03")
	if m.Status != compNotApplicable {
		t.Errorf("expected not_applicable for non-RAG agent, got %s", m.Status)
	}
}

func TestMapCompliance_DataPoisoning_RAGAgent(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	a := mkCompAgentFull("rag-agent") // has RAG and content-filter
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	m := mkCompFindMapping(r, "LLM03")
	if m.Status == compNonCompliant {
		t.Error("RAG agent with guardrails and policies should not be non_compliant")
	}
}

func TestMapCompliance_ModelDoS(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	a := mkCompAgentFull("rate-limited")
	inv := mkCompInventory(a)
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "LLM04")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for rate-limited tools, got %s", m.Status)
	}
}

func TestMapCompliance_ModelDoS_NoRateLimit(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	a := mkCompAgent("bare")
	a.Tools = []agent.ToolAccess{{Name: "tool1", Actions: []string{"execute"}}}
	inv := mkCompInventory(a)
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "LLM04")
	if m.Status != compNonCompliant {
		t.Errorf("expected non_compliant for tool without rate limit, got %s", m.Status)
	}
}

func TestMapCompliance_SupplyChain(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, mkCompInventory(mkCompAgent("a1")))
	m := mkCompFindMapping(r, "LLM05")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for tool-pattern policies, got %s", m.Status)
	}
}

func TestMapCompliance_ExcessiveAgency(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	a := mkCompAgentFull("constrained")
	inv := mkCompInventory(a)
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "LLM08")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for agent with trust and guardrails, got %s", m.Status)
	}
}

func TestMapCompliance_ExcessiveAgency_NoneSet(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	inv := mkCompInventory(mkCompAgentUntrusted("bare"))
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "LLM08")
	if m.Status != compNonCompliant {
		t.Errorf("expected non_compliant for untrusted agent without guardrails, got %s", m.Status)
	}
}

func TestMapCompliance_Overreliance_NotApplicable(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	inv := mkCompInventory(mkCompAgent("non-auto"))
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "LLM09")
	if m.Status != compNotApplicable {
		t.Errorf("expected not_applicable for non-autonomous agent, got %s", m.Status)
	}
}

func TestMapCompliance_Overreliance_Autonomous(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("owasp-llm-top10")
	a := mkCompAgentAutonomous("auto")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyAlert("*")}
	r := MapCompliance(fw, policies, inv)
	m := mkCompFindMapping(r, "LLM09")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for autonomous agent with alert rules, got %s", m.Status)
	}
}

// ---------------------------------------------------------------------------
// Individual control mapping tests — ATLAS
// ---------------------------------------------------------------------------

func TestMapCompliance_AdversarialData(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("mitre-atlas")
	a := mkCompAgentFull("guarded")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	m := mkCompFindMapping(r, "AML.T0043")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for input guardrails + deny rules, got %s", m.Status)
	}
}

func TestMapCompliance_LLMPromptInjection(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("mitre-atlas")
	a := mkCompAgentFull("guarded")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	m := mkCompFindMapping(r, "AML.T0054")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for input guardrails, got %s", m.Status)
	}
}

func TestMapCompliance_PublicFacingApp_NotApplicable(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("mitre-atlas")
	a := mkCompAgent("no-web")
	inv := mkCompInventory(a)
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "AML.T0051")
	if m.Status != compNotApplicable {
		t.Errorf("expected not_applicable for non-web agent, got %s", m.Status)
	}
}

func TestMapCompliance_PublicFacingApp_WebAgent(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("mitre-atlas")
	a := mkCompAgentFull("web-agent")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	m := mkCompFindMapping(r, "AML.T0051")
	if m.Status == compNonCompliant {
		t.Error("web agent with guardrails and policies should not be non_compliant")
	}
}

func TestMapCompliance_VerifyAttack(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("mitre-atlas")
	a := mkCompAgentFull("monitored")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyAlert("*")}
	r := MapCompliance(fw, policies, inv)
	m := mkCompFindMapping(r, "AML.T0042")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for alert rules + guardrails, got %s", m.Status)
	}
}

func TestMapCompliance_MLAPIAccess(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("mitre-atlas")
	a := mkCompAgentFull("authed")
	inv := mkCompInventory(a)
	r := MapCompliance(fw, nil, inv)
	m := mkCompFindMapping(r, "AML.T0040")
	if m.Status != compCompliant {
		t.Errorf("expected compliant for agent with trust level, got %s", m.Status)
	}
}

// ---------------------------------------------------------------------------
// Grade boundary tests
// ---------------------------------------------------------------------------

func TestGrade_A(t *testing.T) {
	t.Parallel()
	if g := compGrade(95); g != "A" {
		t.Errorf("expected A for 95, got %s", g)
	}
}

func TestGrade_BoundaryA90(t *testing.T) {
	t.Parallel()
	if g := compGrade(90); g != "A" {
		t.Errorf("expected A for 90, got %s", g)
	}
}

func TestGrade_B(t *testing.T) {
	t.Parallel()
	if g := compGrade(85); g != "B" {
		t.Errorf("expected B for 85, got %s", g)
	}
}

func TestGrade_BoundaryB80(t *testing.T) {
	t.Parallel()
	if g := compGrade(80); g != "B" {
		t.Errorf("expected B for 80, got %s", g)
	}
}

func TestGrade_C(t *testing.T) {
	t.Parallel()
	if g := compGrade(75); g != "C" {
		t.Errorf("expected C for 75, got %s", g)
	}
}

func TestGrade_D(t *testing.T) {
	t.Parallel()
	if g := compGrade(65); g != "D" {
		t.Errorf("expected D for 65, got %s", g)
	}
}

func TestGrade_F(t *testing.T) {
	t.Parallel()
	if g := compGrade(50); g != "F" {
		t.Errorf("expected F for 50, got %s", g)
	}
}

func TestGrade_BoundaryF59(t *testing.T) {
	t.Parallel()
	if g := compGrade(59.9); g != "F" {
		t.Errorf("expected F for 59.9, got %s", g)
	}
}

func TestGrade_Zero(t *testing.T) {
	t.Parallel()
	if g := compGrade(0); g != "F" {
		t.Errorf("expected F for 0, got %s", g)
	}
}

func TestGrade_Hundred(t *testing.T) {
	t.Parallel()
	if g := compGrade(100); g != "A" {
		t.Errorf("expected A for 100, got %s", g)
	}
}

// ---------------------------------------------------------------------------
// Score weighting tests
// ---------------------------------------------------------------------------

func TestComplianceScore_AllCompliant(t *testing.T) {
	t.Parallel()
	mappings := []ControlMapping{
		{Control: Control{Severity: "critical"}, Status: compCompliant, Score: 1.0},
		{Control: Control{Severity: "high"}, Status: compCompliant, Score: 1.0},
		{Control: Control{Severity: "medium"}, Status: compCompliant, Score: 1.0},
	}
	score := compOverallScore(mappings)
	if score != 100.0 {
		t.Errorf("expected 100.0 for all compliant, got %.1f", score)
	}
}

func TestComplianceScore_AllNonCompliant(t *testing.T) {
	t.Parallel()
	mappings := []ControlMapping{
		{Control: Control{Severity: "critical"}, Status: compNonCompliant, Score: 0.0},
		{Control: Control{Severity: "high"}, Status: compNonCompliant, Score: 0.0},
	}
	score := compOverallScore(mappings)
	if score != 0.0 {
		t.Errorf("expected 0.0 for all non-compliant, got %.1f", score)
	}
}

func TestComplianceScore_WeightedAverage(t *testing.T) {
	t.Parallel()
	// critical (weight 3) compliant (1.0): 3 * 1.0 = 3.0
	// high (weight 2) non_compliant (0.0): 2 * 0.0 = 0.0
	// total weight = 5, weighted sum = 3.0
	// score = (3.0 / 5.0) * 100 = 60.0
	mappings := []ControlMapping{
		{Control: Control{Severity: "critical"}, Status: compCompliant, Score: 1.0},
		{Control: Control{Severity: "high"}, Status: compNonCompliant, Score: 0.0},
	}
	score := compOverallScore(mappings)
	if score != 60.0 {
		t.Errorf("expected 60.0, got %.1f", score)
	}
}

func TestComplianceScore_NotApplicableExcluded(t *testing.T) {
	t.Parallel()
	mappings := []ControlMapping{
		{Control: Control{Severity: "critical"}, Status: compCompliant, Score: 1.0},
		{Control: Control{Severity: "high"}, Status: compNotApplicable, Score: 0.0},
	}
	// Only the critical control counts: 1.0 * 3 / 3 * 100 = 100
	score := compOverallScore(mappings)
	if score != 100.0 {
		t.Errorf("expected 100.0 with N/A excluded, got %.1f", score)
	}
}

func TestComplianceScore_Empty(t *testing.T) {
	t.Parallel()
	score := compOverallScore(nil)
	if score != 0.0 {
		t.Errorf("expected 0.0 for empty mappings, got %.1f", score)
	}
}

func TestComplianceScore_PartialControls(t *testing.T) {
	t.Parallel()
	// critical (3) partial (0.5): 1.5
	// medium (1) compliant (1.0): 1.0
	// total weight = 4, sum = 2.5
	// score = 2.5/4 * 100 = 62.5
	mappings := []ControlMapping{
		{Control: Control{Severity: "critical"}, Status: compPartial, Score: 0.5},
		{Control: Control{Severity: "medium"}, Status: compCompliant, Score: 1.0},
	}
	score := compOverallScore(mappings)
	if score != 62.5 {
		t.Errorf("expected 62.5, got %.1f", score)
	}
}

// ---------------------------------------------------------------------------
// MapAllFrameworks tests
// ---------------------------------------------------------------------------

func TestMapAllFrameworks(t *testing.T) {
	t.Parallel()
	a := mkCompAgentFull("all-fw")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	s := MapAllFrameworks(policies, inv)
	if s == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(s.Frameworks) != 3 {
		t.Errorf("expected 3 framework scores, got %d", len(s.Frameworks))
	}
}

func TestMapAllFrameworks_Empty(t *testing.T) {
	t.Parallel()
	s := MapAllFrameworks(nil, nil)
	if s == nil {
		t.Fatal("expected non-nil summary")
	}
	if len(s.Frameworks) != 3 {
		t.Errorf("expected 3 framework scores even with nil inputs, got %d", len(s.Frameworks))
	}
}

func TestMapAllFrameworks_BestWorstAvg(t *testing.T) {
	t.Parallel()
	a := mkCompAgentFull("full")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	s := MapAllFrameworks(policies, inv)
	if s.BestScore < s.WorstScore {
		t.Error("best score should be >= worst score")
	}
	if s.AvgScore < s.WorstScore || s.AvgScore > s.BestScore {
		t.Errorf("avg (%.1f) should be between worst (%.1f) and best (%.1f)",
			s.AvgScore, s.WorstScore, s.BestScore)
	}
}

// ---------------------------------------------------------------------------
// Format tests
// ---------------------------------------------------------------------------

func TestFormatComplianceReport(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	a := mkCompAgentFull("fmt-test")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	out := FormatComplianceReport(r)
	if !strings.Contains(out, "COMPLIANCE REPORT") {
		t.Error("expected COMPLIANCE REPORT header")
	}
	if !strings.Contains(out, "NIST AI Risk Management Framework") {
		t.Error("expected framework name in output")
	}
	if !strings.Contains(out, "MAP-1.1") {
		t.Error("expected control ID in output")
	}
	// Verify box-drawing characters.
	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Error("expected box-drawing characters")
	}
}

func TestFormatComplianceReport_Nil(t *testing.T) {
	t.Parallel()
	out := FormatComplianceReport(nil)
	if !strings.Contains(out, "No compliance data") {
		t.Error("expected 'No compliance data' for nil report")
	}
}

func TestFormatComplianceReport_Empty(t *testing.T) {
	t.Parallel()
	r := &ComplianceReport{}
	out := FormatComplianceReport(r)
	if !strings.Contains(out, "No compliance data") {
		t.Error("expected 'No compliance data' for empty report")
	}
}

func TestFormatComplianceSummary(t *testing.T) {
	t.Parallel()
	a := mkCompAgentFull("fmt-test")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	s := MapAllFrameworks(policies, inv)
	out := FormatComplianceSummary(s)
	if !strings.Contains(out, "COMPLIANCE SUMMARY") {
		t.Error("expected COMPLIANCE SUMMARY header")
	}
	if !strings.Contains(out, "Best:") {
		t.Error("expected Best score in summary")
	}
}

func TestFormatComplianceSummary_Nil(t *testing.T) {
	t.Parallel()
	out := FormatComplianceSummary(nil)
	if !strings.Contains(out, "No compliance data") {
		t.Error("expected 'No compliance data' for nil summary")
	}
}

// ---------------------------------------------------------------------------
// SummarizeCompliance tests
// ---------------------------------------------------------------------------

func TestSummarizeCompliance(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	a := mkCompAgentFull("summary-test")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	out := SummarizeCompliance(r)
	if !strings.Contains(out, "NIST AI Risk Management Framework") {
		t.Error("expected framework name in summary")
	}
	if !strings.Contains(out, "grade") {
		t.Error("expected 'grade' in summary")
	}
}

func TestSummarizeCompliance_Nil(t *testing.T) {
	t.Parallel()
	out := SummarizeCompliance(nil)
	if !strings.Contains(out, "No compliance data") {
		t.Error("expected 'No compliance data' for nil report")
	}
}

func TestSummarizeCompliance_Empty(t *testing.T) {
	t.Parallel()
	r := &ComplianceReport{}
	out := SummarizeCompliance(r)
	if !strings.Contains(out, "No compliance data") {
		t.Error("expected 'No compliance data' for empty report")
	}
}

// ---------------------------------------------------------------------------
// Recommendations tests
// ---------------------------------------------------------------------------

func TestRecommendations_NonCompliant(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	inv := mkCompInventory(mkCompAgentUntrusted("bare"))
	r := MapCompliance(fw, nil, inv)
	if len(r.Recommendations) == 0 {
		t.Error("expected recommendations for non-compliant report")
	}
	for _, rec := range r.Recommendations {
		if !strings.HasPrefix(rec, "Address ") && !strings.HasPrefix(rec, "Improve ") {
			t.Errorf("unexpected recommendation format: %q", rec)
		}
	}
}

func TestCriticalGaps_NonCompliant(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	inv := mkCompInventory(mkCompAgentUntrusted("bare"))
	r := MapCompliance(fw, nil, inv)
	if len(r.CriticalGaps) == 0 {
		t.Error("expected critical gaps for non-compliant report against NIST")
	}
}

// ---------------------------------------------------------------------------
// Status score mapping tests
// ---------------------------------------------------------------------------

func TestCompStatusScore_Compliant(t *testing.T) {
	t.Parallel()
	if s := compStatusScore(compCompliant); s != 1.0 {
		t.Errorf("expected 1.0, got %.2f", s)
	}
}

func TestCompStatusScore_Partial(t *testing.T) {
	t.Parallel()
	if s := compStatusScore(compPartial); s != 0.5 {
		t.Errorf("expected 0.5, got %.2f", s)
	}
}

func TestCompStatusScore_NonCompliant(t *testing.T) {
	t.Parallel()
	if s := compStatusScore(compNonCompliant); s != 0.0 {
		t.Errorf("expected 0.0, got %.2f", s)
	}
}

func TestCompStatusScore_NotApplicable(t *testing.T) {
	t.Parallel()
	if s := compStatusScore(compNotApplicable); s != 0.0 {
		t.Errorf("expected 0.0, got %.2f", s)
	}
}

// ---------------------------------------------------------------------------
// Counts validation tests
// ---------------------------------------------------------------------------

func TestReportCounts_Consistent(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")
	a := mkCompAgentFull("counts")
	inv := mkCompInventory(a)
	policies := []*policy.Policy{mkCompPolicyFull("*")}
	r := MapCompliance(fw, policies, inv)
	total := r.CompliantCount + r.PartialCount + r.NonCompliant
	naCount := 0
	for _, m := range r.Mappings {
		if m.Status == compNotApplicable {
			naCount++
		}
	}
	if total+naCount != len(r.Mappings) {
		t.Errorf("counts inconsistent: compliant(%d) + partial(%d) + non_compliant(%d) + na(%d) = %d, but %d mappings",
			r.CompliantCount, r.PartialCount, r.NonCompliant, naCount, total+naCount, len(r.Mappings))
	}
}

func TestReportGradeMatchesScore(t *testing.T) {
	t.Parallel()
	fw, _ := GetFramework("nist-ai-rmf")

	tests := []struct {
		name string
		inv  *agent.Inventory
		pols []*policy.Policy
	}{
		{"bare", mkCompInventory(mkCompAgent("a")), nil},
		{"full", mkCompInventory(mkCompAgentFull("a")), []*policy.Policy{mkCompPolicyFull("*")}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := MapCompliance(fw, tc.pols, tc.inv)
			expected := compGrade(r.OverallScore)
			if r.Grade != expected {
				t.Errorf("grade %q does not match score %.1f (expected %q)", r.Grade, r.OverallScore, expected)
			}
		})
	}
}
