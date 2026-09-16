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
// Test helpers — agent / policy builders
// ---------------------------------------------------------------------------

// tmAgentBasic returns a minimal, low-risk agent: standard trust, no
// capabilities enabled, no guardrails, one trust boundary. With no
// guardrails it still trips the baseline Repudiation "no audit trail"
// threat, so it is never a zero-threat agent.
func tmAgentBasic(name string) *agent.Agent {
	return &agent.Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta: agent.AgentMeta{
			Name:    name,
			Type:    agent.TypeConversational,
			Model:   "test-model",
			Version: "1.0.0",
			Owner:   "test-owner",
		},
		Capabilities: agent.AgentCapabilities{},
		Trust: agent.TrustConfig{
			Level:      agent.TrustStandard,
			Boundaries: []string{"internal"},
		},
	}
}

// tmAgentUnattested returns an agent whose attestation fails verification:
// it claims an external-facing capability (web_access) but defines no
// trust boundary, so AttestAgent's default config marks that capability
// claim unverified.
func tmAgentUnattested(name string) *agent.Agent {
	return &agent.Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta: agent.AgentMeta{
			Name: name,
			Type: agent.TypeConversational,
		},
		Capabilities: agent.AgentCapabilities{
			WebAccess: true,
		},
		Trust: agent.TrustConfig{
			Level: agent.TrustStandard,
		},
	}
}

// tmAgentToolCalling returns a tool-calling agent with one write tool and
// no rate limit set, and no guardrails (worst-case repudiation/tampering).
func tmAgentToolCalling(name string) *agent.Agent {
	return &agent.Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta: agent.AgentMeta{
			Name: name,
			Type: agent.TypeToolCalling,
		},
		Capabilities: agent.AgentCapabilities{
			ToolCalling: true,
		},
		Tools: []agent.ToolAccess{
			{Name: "file_writer", Actions: []string{"write"}, Targets: []string{"/data"}},
		},
		Trust: agent.TrustConfig{
			Level: agent.TrustStandard,
		},
	}
}

// tmAgentAllCapabilities returns an agent with every capability flag set,
// an elevated tool, escalation enabled, and no guardrails: a worst case
// across every STRIDE category.
func tmAgentAllCapabilities(name string) *agent.Agent {
	return &agent.Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta: agent.AgentMeta{
			Name: name,
			Type: agent.TypeOrchestrator,
		},
		Capabilities: agent.AgentCapabilities{
			ToolCalling:    true,
			RAG:            true,
			CodeExecution:  true,
			WebAccess:      true,
			FileAccess:     true,
			MessagePassing: true,
			Memory:         true,
			Autonomous:     true,
		},
		Tools: []agent.ToolAccess{
			{Name: "admin_console", Actions: []string{"execute"}, Elevated: true},
			{Name: "config_writer", Actions: []string{"write"}, Targets: []string{"config-store"}},
		},
		Trust: agent.TrustConfig{
			Level:       agent.TrustLow,
			Boundaries:  []string{"internal", "external", "partner"},
			TrustedBy:   []string{"peer-agent"},
			CanEscalate: true,
		},
	}
}

// tmAgentMitigated returns an agent that mirrors tmAgentToolCalling but with
// an enforced guardrail, used to test the "existing mitigation" path.
func tmAgentMitigated(name string) *agent.Agent {
	a := tmAgentToolCalling(name)
	a.Guardrails = []agent.Guardrail{
		{Name: "write-guard", Type: "tool-call", Enforced: true},
	}
	return a
}

// tmPolicyDenyTool returns a policy that denies write access to a named
// tool for a named agent.
func tmPolicyDenyTool(agentName, toolName string) *policy.Policy {
	return &policy.Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       policy.PolicyMeta{Name: "deny-" + toolName},
		Agent:      policy.AgentScope{Name: agentName},
		Rules: []policy.Rule{
			{
				ID:     "deny-write",
				Effect: "deny",
				Match: policy.RuleMatch{
					Tools:   []string{toolName},
					Actions: []string{"write"},
				},
			},
		},
	}
}

// tmPolicyAlertAgent returns a policy with an alert rule scoped to a named
// agent, used to test Repudiation mitigation via audit/alert rules.
func tmPolicyAlertAgent(agentName string) *policy.Policy {
	return &policy.Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       policy.PolicyMeta{Name: "audit-" + agentName},
		Agent:      policy.AgentScope{Name: agentName},
		Rules: []policy.Rule{
			{
				ID:     "audit-all",
				Effect: "alert",
				Match: policy.RuleMatch{
					Actions: []string{"execute", "write", "read", "query", "send"},
				},
			},
		},
	}
}

// tmPolicyWildcard returns a policy scoped to every agent ("*") with a deny
// rule on the given tool.
func tmPolicyWildcard(toolName string) *policy.Policy {
	return &policy.Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       policy.PolicyMeta{Name: "wildcard-deny"},
		Agent:      policy.AgentScope{Name: "*"},
		Rules: []policy.Rule{
			{
				ID:     "deny-all-write",
				Effect: "deny",
				Match: policy.RuleMatch{
					Tools: []string{toolName},
				},
			},
		},
	}
}

// tmInventory wraps a list of agents into an Inventory.
func tmInventory(agents ...*agent.Agent) *agent.Inventory {
	return &agent.Inventory{Agents: agents}
}

// ---------------------------------------------------------------------------
// Empty / nil inputs
// ---------------------------------------------------------------------------

func TestThreatModel_NilInventory(t *testing.T) {
	t.Parallel()
	m := GenerateThreatModel(nil, nil)
	if m == nil {
		t.Fatal("expected non-nil threat model")
	}
	if m.ThreatCount != 0 {
		t.Errorf("expected 0 threats, got %d", m.ThreatCount)
	}
	if len(m.Threats) != 0 {
		t.Errorf("expected empty Threats slice, got %d", len(m.Threats))
	}
}

func TestThreatModel_EmptyInventory(t *testing.T) {
	t.Parallel()
	inv := &agent.Inventory{}
	m := GenerateThreatModel(inv, nil)
	if m.ThreatCount != 0 {
		t.Errorf("expected 0 threats, got %d", m.ThreatCount)
	}
	if m.OverallRisk != 0 {
		t.Errorf("expected overall risk 0, got %v", m.OverallRisk)
	}
}

func TestThreatModel_EmptyInventoryNoPolicies(t *testing.T) {
	t.Parallel()
	m := GenerateThreatModel(tmInventory(), []*policy.Policy{})
	if m.ThreatCount != 0 {
		t.Errorf("expected 0 threats, got %d", m.ThreatCount)
	}
}

func TestThreatModel_NilAgentInList(t *testing.T) {
	t.Parallel()
	inv := &agent.Inventory{Agents: []*agent.Agent{nil, tmAgentBasic("a1")}}
	m := GenerateThreatModel(inv, nil)
	if m.ThreatCount == 0 {
		t.Error("expected threats generated for the non-nil agent")
	}
}

// ---------------------------------------------------------------------------
// Single-agent / multi-agent model generation
// ---------------------------------------------------------------------------

func TestThreatModel_SingleAgent(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentBasic("solo"))
	m := GenerateThreatModel(inv, nil)
	if m.ThreatCount == 0 {
		t.Fatal("expected at least one threat for a basic agent")
	}
	for _, th := range m.Threats {
		if th.AffectedAgent != "solo" {
			t.Errorf("expected AffectedAgent 'solo', got %q", th.AffectedAgent)
		}
	}
}

func TestThreatModel_MultiAgent(t *testing.T) {
	t.Parallel()
	inv := tmInventory(
		tmAgentBasic("agent-one"),
		tmAgentToolCalling("agent-two"),
		tmAgentAllCapabilities("agent-three"),
	)
	m := GenerateThreatModel(inv, nil)

	agentsSeen := make(map[string]bool)
	for _, th := range m.Threats {
		agentsSeen[th.AffectedAgent] = true
	}
	if len(agentsSeen) != 3 {
		t.Errorf("expected threats across 3 agents, saw %d", len(agentsSeen))
	}
	if !agentsSeen["agent-one"] || !agentsSeen["agent-two"] || !agentsSeen["agent-three"] {
		t.Errorf("expected all three agent names present, got %v", agentsSeen)
	}
}

func TestThreatModel_ThreatIDsSequential(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentBasic("a1"), tmAgentToolCalling("a2"))
	m := GenerateThreatModel(inv, nil)
	if len(m.Threats) < 2 {
		t.Fatal("expected at least 2 threats")
	}
	for i, th := range m.Threats {
		want := "THR-" + padThree(i+1)
		if th.ID != want {
			t.Errorf("threat[%d].ID = %q, want %q", i, th.ID, want)
		}
	}
}

func padThree(n int) string {
	s := ""
	if n < 10 {
		s = "00"
	} else if n < 100 {
		s = "0"
	}
	return s + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func TestThreatModel_ThreatCountMatchesLen(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("big"))
	m := GenerateThreatModel(inv, nil)
	if m.ThreatCount != len(m.Threats) {
		t.Errorf("ThreatCount %d != len(Threats) %d", m.ThreatCount, len(m.Threats))
	}
}

// ---------------------------------------------------------------------------
// STRIDE category generation
// ---------------------------------------------------------------------------

func threatsInCategory(m *ThreatModel, cat ThreatCategory) []Threat {
	var out []Threat
	for _, th := range m.Threats {
		if th.Category == cat {
			out = append(out, th)
		}
	}
	return out
}

func TestThreatModel_SpoofingUnattestedAgent(t *testing.T) {
	t.Parallel()
	// An external-facing agent with no trust boundary fails attestation
	// verification under the default attestation config.
	inv := tmInventory(tmAgentUnattested("unattested"))
	m := GenerateThreatModel(inv, nil)
	threats := threatsInCategory(m, Spoofing)
	if len(threats) == 0 {
		t.Error("expected at least one spoofing threat")
	}
}

func TestThreatModel_SpoofingOrchestrator(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("orch"))
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, Spoofing) {
		if strings.Contains(th.Title, "Delegating") {
			found = true
		}
	}
	if !found {
		t.Error("expected a delegating-agent spoofing threat for an orchestrator")
	}
}

func TestThreatModel_SpoofingMessagePassing(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("msg-agent")
	a.Capabilities.MessagePassing = true
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, Spoofing) {
		if strings.Contains(th.Title, "Inter-agent") {
			found = true
		}
	}
	if !found {
		t.Error("expected an inter-agent identity claim spoofing threat")
	}
}

func TestThreatModel_TamperingWriteTool(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentToolCalling("writer"))
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, Tampering) {
		if th.AffectedTool == "file_writer" {
			found = true
		}
	}
	if !found {
		t.Error("expected a tampering threat on the write-capable tool")
	}
}

func TestThreatModel_TamperingConfigTool(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("configurer"))
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, Tampering) {
		if strings.Contains(th.Title, "Configuration") {
			found = true
		}
	}
	if !found {
		t.Error("expected a configuration tampering threat")
	}
}

func TestThreatModel_TamperingCodeExecution(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("coder")
	a.Capabilities.CodeExecution = true
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, Tampering) {
		if strings.Contains(th.Title, "code execution") || strings.Contains(th.Description, "execute code") {
			found = true
		}
	}
	if !found {
		t.Error("expected an arbitrary code execution tampering threat")
	}
}

func TestThreatModel_RepudiationNoGuardrails(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentToolCalling("no-guardrails"))
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, Repudiation) {
		if strings.Contains(th.Title, "No audit trail") {
			found = true
		}
	}
	if !found {
		t.Error("expected a no-audit-trail repudiation threat")
	}
}

func TestThreatModel_RepudiationUnenforcedGuardrails(t *testing.T) {
	t.Parallel()
	a := tmAgentToolCalling("unenforced")
	a.Guardrails = []agent.Guardrail{
		{Name: "present-not-enforced", Type: "output", Enforced: false},
	}
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, Repudiation) {
		if strings.Contains(th.Title, "unenforced") {
			found = true
		}
	}
	if !found {
		t.Error("expected an unenforced-guardrails repudiation threat")
	}
}

func TestThreatModel_RepudiationEnforcedGuardrailsNoThreat(t *testing.T) {
	t.Parallel()
	a := tmAgentToolCalling("enforced")
	a.Guardrails = []agent.Guardrail{
		{Name: "logger", Type: "output", Enforced: true},
	}
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	for _, th := range threatsInCategory(m, Repudiation) {
		t.Errorf("expected no repudiation threat for a fully-enforced agent, got %q", th.Title)
	}
}

func TestThreatModel_InfoDisclosureFileAccess(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("file-agent")
	a.Capabilities.FileAccess = true
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, InformationDisclosure) {
		if strings.Contains(th.Title, "file data") {
			found = true
		}
	}
	if !found {
		t.Error("expected a file-access information disclosure threat")
	}
}

func TestThreatModel_InfoDisclosureCrossBoundary(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("cross-boundary")
	a.Trust.Boundaries = []string{"internal", "external"}
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, InformationDisclosure) {
		if strings.Contains(th.Title, "Cross-boundary") {
			found = true
		}
	}
	if !found {
		t.Error("expected a cross-boundary information disclosure threat")
	}
}

func TestThreatModel_InfoDisclosureSingleBoundaryNoThreat(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("single-boundary")
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	for _, th := range threatsInCategory(m, InformationDisclosure) {
		if strings.Contains(th.Title, "Cross-boundary") {
			t.Error("did not expect a cross-boundary threat with only one boundary")
		}
	}
}

func TestThreatModel_InfoDisclosureRAG(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("rag-agent")
	a.Capabilities.RAG = true
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, InformationDisclosure) {
		if strings.Contains(th.Title, "RAG") {
			found = true
		}
	}
	if !found {
		t.Error("expected a RAG index content disclosure threat")
	}
}

func TestThreatModel_DoSUnboundedRateLimit(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentToolCalling("unbounded")) // file_writer has RateLimit 0
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, DenialOfService) {
		if th.AffectedTool == "file_writer" {
			found = true
		}
	}
	if !found {
		t.Error("expected a DoS threat for the unbounded-rate-limit tool")
	}
}

func TestThreatModel_DoSHighRateLimit(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("high-rate")
	a.Tools = []agent.ToolAccess{
		{Name: "bulk_reader", Actions: []string{"read"}, RateLimit: 5000},
	}
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, DenialOfService) {
		if th.AffectedTool == "bulk_reader" {
			found = true
		}
	}
	if !found {
		t.Error("expected a DoS threat for the high-rate-limit tool")
	}
}

func TestThreatModel_DoSReasonableRateLimitNoThreat(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("reasonable-rate")
	a.Tools = []agent.ToolAccess{
		{Name: "modest_tool", Actions: []string{"read"}, RateLimit: 10},
	}
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	for _, th := range threatsInCategory(m, DenialOfService) {
		if th.AffectedTool == "modest_tool" {
			t.Error("did not expect a DoS threat for a modestly-rate-limited tool")
		}
	}
}

func TestThreatModel_DoSAutonomous(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("auto-agent")
	a.Capabilities.Autonomous = true
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, DenialOfService) {
		if strings.Contains(th.Title, "Autonomous") {
			found = true
		}
	}
	if !found {
		t.Error("expected an autonomous-execution DoS threat")
	}
}

func TestThreatModel_DoSRecursiveDelegation(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("recursive-orch"))
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, DenialOfService) {
		if strings.Contains(th.Title, "Recursive delegation") {
			found = true
		}
	}
	if !found {
		t.Error("expected a recursive delegation DoS threat")
	}
}

func TestThreatModel_ElevationCanEscalate(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("escalator")
	a.Trust.CanEscalate = true
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, ElevationOfPrivilege) {
		if strings.Contains(th.Title, "escalation") {
			found = true
		}
	}
	if !found {
		t.Error("expected a trust escalation elevation-of-privilege threat")
	}
}

func TestThreatModel_ElevationAdminTool(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("admin-tool-agent"))
	m := GenerateThreatModel(inv, nil)
	found := false
	for _, th := range threatsInCategory(m, ElevationOfPrivilege) {
		if th.AffectedTool == "admin_console" {
			found = true
		}
	}
	if !found {
		t.Error("expected an elevated-tool-access threat")
	}
}

func TestThreatModel_ElevationSeverityCriticalWhenTrustLow(t *testing.T) {
	t.Parallel()
	// tmAgentAllCapabilities has TrustLow with an elevated admin_console tool.
	inv := tmInventory(tmAgentAllCapabilities("low-trust-elevated"))
	m := GenerateThreatModel(inv, nil)
	for _, th := range threatsInCategory(m, ElevationOfPrivilege) {
		if th.AffectedTool == "admin_console" && th.Severity != "critical" {
			t.Errorf("expected critical severity for elevated tool on low-trust agent, got %q", th.Severity)
		}
	}
}

func TestThreatModel_ElevationNoElevatedToolsNoThreat(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentToolCalling("no-elevated"))
	m := GenerateThreatModel(inv, nil)
	for _, th := range threatsInCategory(m, ElevationOfPrivilege) {
		if th.Title == "Elevated tool access" {
			t.Error("did not expect elevated tool access threat when no tool is elevated")
		}
	}
}

func TestThreatModel_AllCapabilitiesCoversAllCategories(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("kitchen-sink"))
	m := GenerateThreatModel(inv, nil)
	for _, cat := range strideOrder {
		if len(threatsInCategory(m, cat)) == 0 {
			t.Errorf("expected at least one threat in category %q for an all-capabilities agent", cat)
		}
	}
}

// ---------------------------------------------------------------------------
// Mitigation detection from policies
// ---------------------------------------------------------------------------

func TestThreatModel_UnmitigatedByDefault(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentToolCalling("plain"))
	m := GenerateThreatModel(inv, nil)
	for _, th := range m.Threats {
		if th.MitigationStatus != "unmitigated" {
			t.Errorf("expected threat %q unmitigated with no guardrails/policies, got %q", th.Title, th.MitigationStatus)
		}
	}
}

func TestThreatModel_MitigatedByGuardrailAndPolicy(t *testing.T) {
	t.Parallel()
	a := tmAgentMitigated("guarded-writer")
	inv := tmInventory(a)
	policies := []*policy.Policy{tmPolicyDenyTool("guarded-writer", "file_writer")}
	m := GenerateThreatModel(inv, policies)

	found := false
	for _, th := range threatsInCategory(m, Tampering) {
		if th.AffectedTool == "file_writer" {
			found = true
			if th.MitigationStatus != "mitigated" {
				t.Errorf("expected mitigated, got %q", th.MitigationStatus)
			}
		}
	}
	if !found {
		t.Fatal("expected a tampering threat on file_writer")
	}
}

func TestThreatModel_PartialWhenOnlyGuardrail(t *testing.T) {
	t.Parallel()
	a := tmAgentMitigated("guardrail-only")
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil) // no policies at all

	for _, th := range threatsInCategory(m, Tampering) {
		if th.AffectedTool == "file_writer" && th.MitigationStatus != "partial" {
			t.Errorf("expected partial mitigation with guardrail but no policy, got %q", th.MitigationStatus)
		}
	}
}

func TestThreatModel_PartialWhenOnlyPolicy(t *testing.T) {
	t.Parallel()
	a := tmAgentToolCalling("policy-only") // no guardrails
	inv := tmInventory(a)
	policies := []*policy.Policy{tmPolicyDenyTool("policy-only", "file_writer")}
	m := GenerateThreatModel(inv, policies)

	for _, th := range threatsInCategory(m, Tampering) {
		if th.AffectedTool == "file_writer" && th.MitigationStatus != "partial" {
			t.Errorf("expected partial mitigation with policy but no guardrail, got %q", th.MitigationStatus)
		}
	}
}

func TestThreatModel_PolicyScopedToDifferentAgentDoesNotMitigate(t *testing.T) {
	t.Parallel()
	a := tmAgentToolCalling("target-agent")
	inv := tmInventory(a)
	policies := []*policy.Policy{tmPolicyDenyTool("other-agent", "file_writer")}
	m := GenerateThreatModel(inv, policies)

	for _, th := range threatsInCategory(m, Tampering) {
		if th.AffectedTool == "file_writer" && th.MitigationStatus == "mitigated" {
			t.Error("policy scoped to a different agent should not mitigate this threat")
		}
	}
}

func TestThreatModel_WildcardPolicyAppliesToAllAgents(t *testing.T) {
	t.Parallel()
	a := tmAgentMitigated("wildcard-target")
	inv := tmInventory(a)
	policies := []*policy.Policy{tmPolicyWildcard("file_writer")}
	m := GenerateThreatModel(inv, policies)

	found := false
	for _, th := range threatsInCategory(m, Tampering) {
		if th.AffectedTool == "file_writer" {
			found = true
			if th.MitigationStatus != "mitigated" {
				t.Errorf("expected mitigated via wildcard policy, got %q", th.MitigationStatus)
			}
		}
	}
	if !found {
		t.Fatal("expected a tampering threat on file_writer")
	}
}

func TestThreatModel_RepudiationMitigatedByAlertPolicy(t *testing.T) {
	t.Parallel()
	a := tmAgentToolCalling("audited")
	a.Guardrails = []agent.Guardrail{{Name: "log", Type: "output", Enforced: true}}
	inv := tmInventory(a)
	policies := []*policy.Policy{tmPolicyAlertAgent("audited")}
	m := GenerateThreatModel(inv, policies)

	// tmAgentToolCalling + guardrails means no repudiation threat is
	// generated at all (guardrails present and enforced), so instead verify
	// on a variant that still trips repudiation: unenforced guardrail.
	a2 := tmAgentToolCalling("audited-unenforced")
	a2.Guardrails = []agent.Guardrail{{Name: "log", Type: "output", Enforced: false}}
	inv2 := tmInventory(a2)
	policies2 := []*policy.Policy{tmPolicyAlertAgent("audited-unenforced")}
	m2 := GenerateThreatModel(inv2, policies2)

	found := false
	for _, th := range threatsInCategory(m2, Repudiation) {
		found = true
		if th.MitigationStatus != "partial" {
			t.Errorf("expected partial mitigation (alert rule, no enforced guardrail), got %q", th.MitigationStatus)
		}
	}
	if !found {
		t.Fatal("expected a repudiation threat for the unenforced-guardrail agent")
	}

	_ = m // m from the fully-guarded agent should have no repudiation threats
	for _, th := range threatsInCategory(m, Repudiation) {
		t.Errorf("did not expect a repudiation threat on a fully-guarded agent, got %q", th.Title)
	}
}

func TestThreatModel_RepudiationUnmitigatedWithoutAlertPolicy(t *testing.T) {
	t.Parallel()
	a := tmAgentToolCalling("no-audit-policy") // no guardrails at all
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)

	found := false
	for _, th := range threatsInCategory(m, Repudiation) {
		found = true
		if th.MitigationStatus != "unmitigated" {
			t.Errorf("expected unmitigated repudiation threat, got %q", th.MitigationStatus)
		}
	}
	if !found {
		t.Fatal("expected a repudiation threat")
	}
}

// ---------------------------------------------------------------------------
// Risk score computation
// ---------------------------------------------------------------------------

func TestComputeThreatRisk_CriticalVeryLikely(t *testing.T) {
	t.Parallel()
	got := computeThreatRisk("critical", "very_likely")
	if got != 10 {
		t.Errorf("computeThreatRisk(critical, very_likely) = %v, want 10", got)
	}
}

func TestComputeThreatRisk_LowUnlikely(t *testing.T) {
	t.Parallel()
	got := computeThreatRisk("low", "unlikely")
	if got != 0.5 {
		t.Errorf("computeThreatRisk(low, unlikely) = %v, want 0.5", got)
	}
}

func TestComputeThreatRisk_Ordering(t *testing.T) {
	t.Parallel()
	high := computeThreatRisk("high", "likely")
	medium := computeThreatRisk("medium", "likely")
	if high <= medium {
		t.Errorf("expected high risk (%v) > medium risk (%v) at same likelihood", high, medium)
	}
}

func TestComputeThreatRisk_LikelihoodOrdering(t *testing.T) {
	t.Parallel()
	likely := computeThreatRisk("high", "likely")
	possible := computeThreatRisk("high", "possible")
	if likely <= possible {
		t.Errorf("expected likely risk (%v) > possible risk (%v) at same severity", likely, possible)
	}
}

func TestComputeThreatRisk_UnknownLabelsFallBack(t *testing.T) {
	t.Parallel()
	got := computeThreatRisk("nonsense", "nonsense")
	if got <= 0 || got > 10 {
		t.Errorf("expected a fallback score in (0,10], got %v", got)
	}
}

func TestComputeThreatRisk_CappedAtTen(t *testing.T) {
	t.Parallel()
	got := computeThreatRisk("critical", "very_likely")
	if got > 10 {
		t.Errorf("expected risk score capped at 10, got %v", got)
	}
}

func TestThreatModel_RiskScoreWithinRange(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("risk-check"))
	m := GenerateThreatModel(inv, nil)
	for _, th := range m.Threats {
		if th.RiskScore < 0 || th.RiskScore > 10 {
			t.Errorf("threat %q risk score %v out of range [0,10]", th.ID, th.RiskScore)
		}
	}
}

func TestThreatModel_OverallRiskWithinRange(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("overall-risk-check"))
	m := GenerateThreatModel(inv, nil)
	if m.OverallRisk < 0 || m.OverallRisk > 10 {
		t.Errorf("overall risk %v out of range [0,10]", m.OverallRisk)
	}
}

func TestThreatModel_OverallRiskIsAverage(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentBasic("avg-check"))
	m := GenerateThreatModel(inv, nil)
	if len(m.Threats) == 0 {
		t.Fatal("expected at least one threat")
	}
	var sum float64
	for _, th := range m.Threats {
		sum += th.RiskScore
	}
	want := roundTo1(sum / float64(len(m.Threats)))
	if m.OverallRisk != want {
		t.Errorf("OverallRisk = %v, want %v", m.OverallRisk, want)
	}
}

// ---------------------------------------------------------------------------
// Category breakdown / severity / mitigation counts
// ---------------------------------------------------------------------------

func TestThreatModel_CategoryBreakdownSumsToTotal(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("breakdown"))
	m := GenerateThreatModel(inv, nil)
	sum := 0
	for _, c := range m.CategoryBreakdown {
		sum += c
	}
	if sum != m.ThreatCount {
		t.Errorf("category breakdown sums to %d, want %d", sum, m.ThreatCount)
	}
}

func TestThreatModel_SeverityCountsSumToTotal(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("severity-sum"))
	m := GenerateThreatModel(inv, nil)
	sum := m.CriticalCount + m.HighCount + m.MediumCount + m.LowCount
	if sum != m.ThreatCount {
		t.Errorf("severity counts sum to %d, want %d", sum, m.ThreatCount)
	}
}

func TestThreatModel_MitigationCountsSumToTotal(t *testing.T) {
	t.Parallel()
	a := tmAgentMitigated("mitigation-sum")
	inv := tmInventory(a)
	policies := []*policy.Policy{tmPolicyDenyTool("mitigation-sum", "file_writer")}
	m := GenerateThreatModel(inv, policies)
	sum := m.MitigatedCount + m.PartialCount + m.UnmitigatedCount
	if sum != m.ThreatCount {
		t.Errorf("mitigation counts sum to %d, want %d", sum, m.ThreatCount)
	}
}

func TestThreatModel_CategoryBreakdownKeysAreStrideCategories(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("category-keys"))
	m := GenerateThreatModel(inv, nil)
	valid := map[ThreatCategory]bool{}
	for _, c := range strideOrder {
		valid[c] = true
	}
	for cat := range m.CategoryBreakdown {
		if !valid[cat] {
			t.Errorf("unexpected category key %q in breakdown", cat)
		}
	}
}

// ---------------------------------------------------------------------------
// assessMitigationStatus direct tests
// ---------------------------------------------------------------------------

func TestAssessMitigationStatus_NoMitigationsUnmitigated(t *testing.T) {
	t.Parallel()
	th := &Threat{Category: Tampering, AffectedAgent: "a1", AffectedTool: "t1"}
	got := assessMitigationStatus(th, nil)
	if got != "unmitigated" {
		t.Errorf("got %q, want unmitigated", got)
	}
}

func TestAssessMitigationStatus_GuardrailOnlyPartial(t *testing.T) {
	t.Parallel()
	th := &Threat{Category: Tampering, AffectedAgent: "a1", AffectedTool: "t1", Mitigations: []string{"g1"}}
	got := assessMitigationStatus(th, nil)
	if got != "partial" {
		t.Errorf("got %q, want partial", got)
	}
}

func TestAssessMitigationStatus_PolicyAndGuardrailMitigated(t *testing.T) {
	t.Parallel()
	th := &Threat{Category: Tampering, AffectedAgent: "a1", AffectedTool: "t1", Mitigations: []string{"g1"}}
	policies := []*policy.Policy{tmPolicyDenyTool("a1", "t1")}
	got := assessMitigationStatus(th, policies)
	if got != "mitigated" {
		t.Errorf("got %q, want mitigated", got)
	}
}

// ---------------------------------------------------------------------------
// Format output structure
// ---------------------------------------------------------------------------

func TestFormatThreatModel_Empty(t *testing.T) {
	t.Parallel()
	out := FormatThreatModel(&ThreatModel{})
	if !strings.Contains(out, "No threats") {
		t.Errorf("expected 'No threats' message, got %q", out)
	}
}

func TestFormatThreatModel_Nil(t *testing.T) {
	t.Parallel()
	out := FormatThreatModel(nil)
	if !strings.Contains(out, "No threats") {
		t.Errorf("expected 'No threats' message for nil model, got %q", out)
	}
}

func TestFormatThreatModel_ContainsHeader(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentBasic("fmt-agent"))
	m := GenerateThreatModel(inv, nil)
	out := FormatThreatModel(m)
	if !strings.Contains(out, "STRIDE Threat Model") {
		t.Error("expected header 'STRIDE Threat Model' in output")
	}
}

func TestFormatThreatModel_ContainsThreatIDs(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentToolCalling("fmt-tool-agent"))
	m := GenerateThreatModel(inv, nil)
	out := FormatThreatModel(m)
	for _, th := range m.Threats {
		if !strings.Contains(out, th.ID) {
			t.Errorf("expected output to contain threat ID %q", th.ID)
		}
	}
}

func TestFormatThreatModel_ContainsBoxDrawing(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentBasic("box-agent"))
	m := GenerateThreatModel(inv, nil)
	out := FormatThreatModel(m)
	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Error("expected box-drawing characters in formatted output")
	}
}

func TestFormatThreatModel_ContainsCategoryBreakdown(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("fmt-category"))
	m := GenerateThreatModel(inv, nil)
	out := FormatThreatModel(m)
	if !strings.Contains(out, "STRIDE Category Breakdown") {
		t.Error("expected category breakdown section in output")
	}
}

// ---------------------------------------------------------------------------
// SummarizeThreatModel
// ---------------------------------------------------------------------------

func TestSummarizeThreatModel_Empty(t *testing.T) {
	t.Parallel()
	out := SummarizeThreatModel(&ThreatModel{})
	if !strings.Contains(out, "No threats") {
		t.Errorf("expected 'No threats' summary, got %q", out)
	}
}

func TestSummarizeThreatModel_Nil(t *testing.T) {
	t.Parallel()
	out := SummarizeThreatModel(nil)
	if !strings.Contains(out, "No threats") {
		t.Errorf("expected 'No threats' summary for nil model, got %q", out)
	}
}

func TestSummarizeThreatModel_ContainsCount(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentToolCalling("summary-agent"))
	m := GenerateThreatModel(inv, nil)
	out := SummarizeThreatModel(m)
	if !strings.Contains(out, "threats identified") {
		t.Errorf("expected summary to mention threat count, got %q", out)
	}
}

func TestSummarizeThreatModel_IsSingleLine(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("single-line"))
	m := GenerateThreatModel(inv, nil)
	out := SummarizeThreatModel(m)
	if strings.Contains(out, "\n") {
		t.Error("expected a single-line summary")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestThreatModel_AgentWithNoToolsNoCrashInTampering(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("no-tools")
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	// Should not panic and should still produce a valid model.
	if m == nil {
		t.Fatal("expected non-nil model")
	}
}

func TestThreatModel_AgentWithEmptyToolNamesHandled(t *testing.T) {
	t.Parallel()
	a := tmAgentBasic("empty-tool-name")
	a.Tools = []agent.ToolAccess{{Name: "", Actions: []string{"write"}}}
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	if m == nil {
		t.Fatal("expected non-nil model")
	}
}

func TestThreatModel_DeterministicThreatCountAcrossRuns(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("deterministic"))
	m1 := GenerateThreatModel(inv, nil)
	m2 := GenerateThreatModel(inv, nil)
	if m1.ThreatCount != m2.ThreatCount {
		t.Errorf("expected deterministic threat count, got %d vs %d", m1.ThreatCount, m2.ThreatCount)
	}
}

func TestThreatModel_EveryThreatHasRequiredFields(t *testing.T) {
	t.Parallel()
	inv := tmInventory(tmAgentAllCapabilities("required-fields"))
	m := GenerateThreatModel(inv, nil)
	for _, th := range m.Threats {
		if th.ID == "" {
			t.Error("threat missing ID")
		}
		if th.Category == "" {
			t.Error("threat missing Category")
		}
		if th.Title == "" {
			t.Error("threat missing Title")
		}
		if th.AffectedAgent == "" {
			t.Error("threat missing AffectedAgent")
		}
		if th.Severity == "" {
			t.Error("threat missing Severity")
		}
		if th.Likelihood == "" {
			t.Error("threat missing Likelihood")
		}
		if th.MitigationStatus == "" {
			t.Error("threat missing MitigationStatus")
		}
		if len(th.Recommendations) == 0 {
			t.Errorf("threat %q missing recommendations", th.ID)
		}
	}
}

func TestThreatModel_GeneratedAtIsSet(t *testing.T) {
	t.Parallel()
	m := GenerateThreatModel(tmInventory(), nil)
	if m.GeneratedAt == "" {
		t.Error("expected GeneratedAt to be set even for an empty model")
	}
}

func TestThreatModel_NilPoliciesTreatedAsNone(t *testing.T) {
	t.Parallel()
	a := tmAgentMitigated("nil-policies")
	inv := tmInventory(a)
	m := GenerateThreatModel(inv, nil)
	for _, th := range threatsInCategory(m, Tampering) {
		if th.AffectedTool == "file_writer" && th.MitigationStatus == "mitigated" {
			t.Error("did not expect full mitigation without any policy")
		}
	}
}

func TestThreatModel_PolicyWithNilEntrySkipped(t *testing.T) {
	t.Parallel()
	a := tmAgentToolCalling("nil-entry")
	inv := tmInventory(a)
	policies := []*policy.Policy{nil, tmPolicyDenyTool("nil-entry", "file_writer")}
	m := GenerateThreatModel(inv, policies)
	found := false
	for _, th := range threatsInCategory(m, Tampering) {
		if th.AffectedTool == "file_writer" {
			found = true
			if th.MitigationStatus != "partial" {
				t.Errorf("expected partial (policy only, no guardrail), got %q", th.MitigationStatus)
			}
		}
	}
	if !found {
		t.Fatal("expected a tampering threat")
	}
}
