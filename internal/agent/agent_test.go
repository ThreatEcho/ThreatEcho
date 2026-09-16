// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper to write a YAML file and return its path.
func writeYAML(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const validAgentYAML = `
api_version: v1
kind: Agent
meta:
  name: test-agent
  type: tool-calling
  description: A test agent
  model: gpt-4
  version: "1.0"
  owner: test-owner
  tags:
    - test
    - demo
capabilities:
  tool_calling: true
  rag: false
  code_execution: false
  web_access: true
  file_access: false
  message_passing: true
  memory: false
  autonomous: false
tools:
  - name: web-search
    actions: [search, fetch]
    targets: ["*.example.com"]
    elevated: false
    rate_limit: 100
  - name: database
    actions: [read, write]
    targets: [internal-db]
    elevated: true
    rate_limit: 50
trust:
  level: standard
  trusts_from:
    - orchestrator-agent
  trusted_by:
    - retrieval-agent
  boundaries:
    - internal
  can_escalate: false
guardrails:
  - name: input-sanitizer
    type: input
    enforced: true
  - name: output-filter
    type: output
    enforced: true
`

// --- LoadAgent tests ---

func TestLoadAgentFromFile(t *testing.T) {
	dir := t.TempDir()
	p := writeYAML(t, dir, "agent.yaml", validAgentYAML)

	a, err := LoadAgent(p)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if a.Meta.Name != "test-agent" {
		t.Errorf("name = %q, want %q", a.Meta.Name, "test-agent")
	}
	if a.Kind != "Agent" {
		t.Errorf("kind = %q, want %q", a.Kind, "Agent")
	}
	if a.APIVersion != "v1" {
		t.Errorf("api_version = %q, want %q", a.APIVersion, "v1")
	}
	if a.Meta.Type != TypeToolCalling {
		t.Errorf("type = %q, want %q", a.Meta.Type, TypeToolCalling)
	}
	if a.Meta.Model != "gpt-4" {
		t.Errorf("model = %q, want %q", a.Meta.Model, "gpt-4")
	}
	if a.Meta.Version != "1.0" {
		t.Errorf("version = %q, want %q", a.Meta.Version, "1.0")
	}
	if a.Meta.Owner != "test-owner" {
		t.Errorf("owner = %q, want %q", a.Meta.Owner, "test-owner")
	}
	if len(a.Meta.Tags) != 2 {
		t.Errorf("tags len = %d, want 2", len(a.Meta.Tags))
	}
}

func TestLoadAgentFromDirectory(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "agent.yaml", validAgentYAML)

	a, err := LoadAgent(dir)
	if err != nil {
		t.Fatalf("LoadAgent from dir: %v", err)
	}
	if a.Meta.Name != "test-agent" {
		t.Errorf("name = %q, want %q", a.Meta.Name, "test-agent")
	}
}

func TestLoadAgentCapabilities(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "agent.yaml", validAgentYAML)

	a, err := LoadAgent(dir)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if !a.Capabilities.ToolCalling {
		t.Error("expected ToolCalling = true")
	}
	if a.Capabilities.RAG {
		t.Error("expected RAG = false")
	}
	if a.Capabilities.CodeExecution {
		t.Error("expected CodeExecution = false")
	}
	if !a.Capabilities.WebAccess {
		t.Error("expected WebAccess = true")
	}
	if a.Capabilities.FileAccess {
		t.Error("expected FileAccess = false")
	}
	if !a.Capabilities.MessagePassing {
		t.Error("expected MessagePassing = true")
	}
	if a.Capabilities.Memory {
		t.Error("expected Memory = false")
	}
	if a.Capabilities.Autonomous {
		t.Error("expected Autonomous = false")
	}
}

func TestLoadAgentTools(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "agent.yaml", validAgentYAML)

	a, err := LoadAgent(dir)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if len(a.Tools) != 2 {
		t.Fatalf("tools len = %d, want 2", len(a.Tools))
	}
	if a.Tools[0].Name != "web-search" {
		t.Errorf("tool[0].name = %q, want %q", a.Tools[0].Name, "web-search")
	}
	if a.Tools[0].RateLimit != 100 {
		t.Errorf("tool[0].rate_limit = %d, want 100", a.Tools[0].RateLimit)
	}
	if !a.Tools[1].Elevated {
		t.Error("tool[1] should be elevated")
	}
}

func TestLoadAgentTrust(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "agent.yaml", validAgentYAML)

	a, err := LoadAgent(dir)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if a.Trust.Level != TrustStandard {
		t.Errorf("trust.level = %q, want %q", a.Trust.Level, TrustStandard)
	}
	if len(a.Trust.TrustsFrom) != 1 || a.Trust.TrustsFrom[0] != "orchestrator-agent" {
		t.Errorf("trust.trusts_from = %v, want [orchestrator-agent]", a.Trust.TrustsFrom)
	}
	if len(a.Trust.TrustedBy) != 1 || a.Trust.TrustedBy[0] != "retrieval-agent" {
		t.Errorf("trust.trusted_by = %v, want [retrieval-agent]", a.Trust.TrustedBy)
	}
	if a.Trust.CanEscalate {
		t.Error("expected can_escalate = false")
	}
}

func TestLoadAgentGuardrails(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "agent.yaml", validAgentYAML)

	a, err := LoadAgent(dir)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if len(a.Guardrails) != 2 {
		t.Fatalf("guardrails len = %d, want 2", len(a.Guardrails))
	}
	if a.Guardrails[0].Name != "input-sanitizer" {
		t.Errorf("guardrail[0].name = %q, want %q", a.Guardrails[0].Name, "input-sanitizer")
	}
	if a.Guardrails[0].Type != "input" {
		t.Errorf("guardrail[0].type = %q, want %q", a.Guardrails[0].Type, "input")
	}
	if !a.Guardrails[0].Enforced {
		t.Error("guardrail[0] should be enforced")
	}
}

func TestLoadAgentMissingFile(t *testing.T) {
	_, err := LoadAgent("/nonexistent/path/agent.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadAgentBadYAML(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "agent.yaml", "{{invalid yaml")

	_, err := LoadAgent(dir)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadAgentMissingFileInDir(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadAgent(dir)
	if err == nil {
		t.Fatal("expected error for missing agent.yaml in dir")
	}
}

// --- LoadInventory tests ---

func makeInventoryDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeYAML(t, filepath.Join(dir, "agent-a"), "agent.yaml", `
api_version: v1
kind: Agent
meta:
  name: agent-a
  type: retrieval
  description: Agent A
  model: gpt-4
  version: "1.0"
  owner: team-a
capabilities:
  tool_calling: false
  rag: true
trust:
  level: low
`)

	writeYAML(t, filepath.Join(dir, "agent-b"), "agent.yaml", `
api_version: v1
kind: Agent
meta:
  name: agent-b
  type: orchestrator
  description: Agent B
  model: claude-3
  version: "2.0"
  owner: team-b
capabilities:
  tool_calling: true
  code_execution: true
  file_access: true
tools:
  - name: shell
    actions: [execute]
    elevated: true
trust:
  level: admin
  trusted_by:
    - agent-a
    - agent-c
    - agent-d
guardrails:
  - name: command-filter
    type: tool-call
    enforced: true
`)

	writeYAML(t, filepath.Join(dir, "agent-c"), "agent.yaml", `
api_version: v1
kind: Agent
meta:
  name: agent-c
  type: tool-calling
  description: Agent C
  model: gpt-4
  version: "1.0"
  owner: team-a
capabilities:
  tool_calling: true
  web_access: true
tools:
  - name: web-fetch
    actions: [get]
trust:
  level: standard
  trusts_from:
    - agent-a
  boundaries:
    - internal
guardrails:
  - name: url-filter
    type: input
    enforced: true
`)

	writeYAML(t, filepath.Join(dir, "agent-d"), "agent.yaml", `
api_version: v1
kind: Agent
meta:
  name: agent-d
  type: conversational
  description: Agent D
  model: gpt-4
  version: "1.0"
  owner: team-c
capabilities:
  tool_calling: false
trust:
  level: untrusted
`)

	return dir
}

func TestLoadInventory(t *testing.T) {
	dir := makeInventoryDir(t)

	inv, err := LoadInventory(dir)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if len(inv.Agents) != 4 {
		t.Fatalf("agents = %d, want 4", len(inv.Agents))
	}
}

func TestLoadInventoryEmptyDir(t *testing.T) {
	dir := t.TempDir()

	inv, err := LoadInventory(dir)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if len(inv.Agents) != 0 {
		t.Errorf("agents = %d, want 0", len(inv.Agents))
	}
}

func TestLoadInventoryBadDir(t *testing.T) {
	_, err := LoadInventory("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestLoadInventoryBadAgentSkipsNone(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "bad"), "agent.yaml", "{{bad yaml")

	_, err := LoadInventory(dir)
	if err == nil {
		t.Fatal("expected error for bad agent YAML")
	}
}

// --- ValidateAgent tests ---

func TestValidateAgentValid(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta: AgentMeta{
			Name: "valid-agent",
			Type: TypeToolCalling,
		},
		Capabilities: AgentCapabilities{ToolCalling: true},
		Trust:        TrustConfig{Level: TrustStandard},
		Guardrails: []Guardrail{
			{Name: "test", Type: "input", Enforced: true},
		},
	}
	errs := ValidateAgent(a)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidateAgentMissingName(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       AgentMeta{Type: TypeRetrieval},
		Trust:      TrustConfig{Level: TrustLow},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "meta.name") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected meta.name error, got %v", errs)
	}
}

func TestValidateAgentMissingKind(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Meta:       AgentMeta{Name: "x", Type: TypeRetrieval},
		Trust:      TrustConfig{Level: TrustLow},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "kind is required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected kind error, got %v", errs)
	}
}

func TestValidateAgentWrongKind(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       AgentMeta{Name: "x", Type: TypeRetrieval},
		Trust:      TrustConfig{Level: TrustLow},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "kind must be") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected kind mismatch error, got %v", errs)
	}
}

func TestValidateAgentInvalidType(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       AgentMeta{Name: "x", Type: "invalid-type"},
		Trust:      TrustConfig{Level: TrustStandard},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "invalid agent type") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid type error, got %v", errs)
	}
}

func TestValidateAgentInvalidTrustLevel(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       AgentMeta{Name: "x", Type: TypeRetrieval},
		Trust:      TrustConfig{Level: "super-admin"},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "invalid trust level") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid trust level error, got %v", errs)
	}
}

func TestValidateAgentMissingAPIVersion(t *testing.T) {
	a := &Agent{
		Kind:  "Agent",
		Meta:  AgentMeta{Name: "x", Type: TypeRetrieval},
		Trust: TrustConfig{Level: TrustLow},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "api_version") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected api_version error, got %v", errs)
	}
}

func TestValidateAgentMissingType(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       AgentMeta{Name: "x"},
		Trust:      TrustConfig{Level: TrustStandard},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "meta.type is required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected meta.type error, got %v", errs)
	}
}

func TestValidateAgentMissingTrustLevel(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       AgentMeta{Name: "x", Type: TypeRetrieval},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "trust.level is required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected trust.level error, got %v", errs)
	}
}

func TestValidateAgentToolCallingNoGuardrails(t *testing.T) {
	a := &Agent{
		APIVersion:   "v1",
		Kind:         "Agent",
		Meta:         AgentMeta{Name: "x", Type: TypeToolCalling},
		Capabilities: AgentCapabilities{ToolCalling: true},
		Trust:        TrustConfig{Level: TrustStandard},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "no guardrails") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected guardrail warning, got %v", errs)
	}
}

func TestValidateAgentAutonomousLowTrust(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       AgentMeta{Name: "x", Type: TypeAutonomous},
		Trust:      TrustConfig{Level: TrustLow},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "autonomous agents") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected autonomous trust error, got %v", errs)
	}
}

func TestValidateAgentInvalidGuardrailType(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       AgentMeta{Name: "x", Type: TypeRetrieval},
		Trust:      TrustConfig{Level: TrustLow},
		Guardrails: []Guardrail{{Name: "g1", Type: "invalid-type"}},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "invalid type") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected guardrail type error, got %v", errs)
	}
}

func TestValidateAgentGuardrailMissingName(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       AgentMeta{Name: "x", Type: TypeRetrieval},
		Trust:      TrustConfig{Level: TrustLow},
		Guardrails: []Guardrail{{Type: "input"}},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "name is required") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected guardrail name error, got %v", errs)
	}
}

func TestValidateAgentToolMissingName(t *testing.T) {
	a := &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       AgentMeta{Name: "x", Type: TypeRetrieval},
		Trust:      TrustConfig{Level: TrustLow},
		Tools:      []ToolAccess{{Actions: []string{"read"}}},
	}
	errs := ValidateAgent(a)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "tools[0].name") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected tool name error, got %v", errs)
	}
}

// --- FindAgent tests ---

func TestFindAgentFound(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{Meta: AgentMeta{Name: "alpha"}},
			{Meta: AgentMeta{Name: "beta"}},
		},
	}
	a := inv.FindAgent("beta")
	if a == nil {
		t.Fatal("expected to find beta")
	}
	if a.Meta.Name != "beta" {
		t.Errorf("name = %q, want %q", a.Meta.Name, "beta")
	}
}

func TestFindAgentNotFound(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{Meta: AgentMeta{Name: "alpha"}},
		},
	}
	a := inv.FindAgent("gamma")
	if a != nil {
		t.Error("expected nil for missing agent")
	}
}

// --- AgentsByType tests ---

func TestAgentsByType(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{Meta: AgentMeta{Name: "a", Type: TypeRetrieval}},
			{Meta: AgentMeta{Name: "b", Type: TypeOrchestrator}},
			{Meta: AgentMeta{Name: "c", Type: TypeRetrieval}},
		},
	}
	result := inv.AgentsByType(TypeRetrieval)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
}

func TestAgentsByTypeNone(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{Meta: AgentMeta{Name: "a", Type: TypeRetrieval}},
		},
	}
	result := inv.AgentsByType(TypeAutonomous)
	if len(result) != 0 {
		t.Errorf("len = %d, want 0", len(result))
	}
}

// --- AgentsByTrust tests ---

func TestAgentsByTrust(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{Meta: AgentMeta{Name: "a"}, Trust: TrustConfig{Level: TrustAdmin}},
			{Meta: AgentMeta{Name: "b"}, Trust: TrustConfig{Level: TrustLow}},
			{Meta: AgentMeta{Name: "c"}, Trust: TrustConfig{Level: TrustAdmin}},
		},
	}
	result := inv.AgentsByTrust(TrustAdmin)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
}

func TestAgentsByTrustNone(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{Meta: AgentMeta{Name: "a"}, Trust: TrustConfig{Level: TrustLow}},
		},
	}
	result := inv.AgentsByTrust(TrustAdmin)
	if len(result) != 0 {
		t.Errorf("len = %d, want 0", len(result))
	}
}

// --- ToolMatrix tests ---

func TestToolMatrix(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:  AgentMeta{Name: "a"},
				Tools: []ToolAccess{{Name: "web-search"}, {Name: "db"}},
			},
			{
				Meta:  AgentMeta{Name: "b"},
				Tools: []ToolAccess{{Name: "web-search"}},
			},
			{
				Meta:  AgentMeta{Name: "c"},
				Tools: []ToolAccess{{Name: "db"}, {Name: "shell"}},
			},
		},
	}
	matrix := inv.ToolMatrix()
	if len(matrix["web-search"]) != 2 {
		t.Errorf("web-search agents = %d, want 2", len(matrix["web-search"]))
	}
	if len(matrix["db"]) != 2 {
		t.Errorf("db agents = %d, want 2", len(matrix["db"]))
	}
	if len(matrix["shell"]) != 1 {
		t.Errorf("shell agents = %d, want 1", len(matrix["shell"]))
	}
}

func TestToolMatrixEmpty(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{Meta: AgentMeta{Name: "a"}},
		},
	}
	matrix := inv.ToolMatrix()
	if len(matrix) != 0 {
		t.Errorf("expected empty matrix, got %d entries", len(matrix))
	}
}

// --- AnalyzeTrust tests ---

func TestAnalyzeTrustEmpty(t *testing.T) {
	inv := &Inventory{}
	ta := inv.AnalyzeTrust()
	if ta.TotalAgents != 0 {
		t.Errorf("total = %d, want 0", ta.TotalAgents)
	}
	if len(ta.TrustEdges) != 0 {
		t.Errorf("edges = %d, want 0", len(ta.TrustEdges))
	}
}

func TestAnalyzeTrustSingleAgent(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:  AgentMeta{Name: "solo", Type: TypeRetrieval},
				Trust: TrustConfig{Level: TrustStandard},
			},
		},
	}
	ta := inv.AnalyzeTrust()
	if ta.TotalAgents != 1 {
		t.Errorf("total = %d, want 1", ta.TotalAgents)
	}
	if len(ta.AdminAgents) != 0 {
		t.Errorf("admin agents = %d, want 0", len(ta.AdminAgents))
	}
}

func TestAnalyzeTrustAdminAndUntrusted(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{Meta: AgentMeta{Name: "admin-bot"}, Trust: TrustConfig{Level: TrustAdmin}},
			{Meta: AgentMeta{Name: "sketch-bot"}, Trust: TrustConfig{Level: TrustUntrusted}},
			{Meta: AgentMeta{Name: "normal-bot"}, Trust: TrustConfig{Level: TrustStandard}},
		},
	}
	ta := inv.AnalyzeTrust()
	if len(ta.AdminAgents) != 1 || ta.AdminAgents[0] != "admin-bot" {
		t.Errorf("admin agents = %v, want [admin-bot]", ta.AdminAgents)
	}
	if len(ta.UntrustedAgents) != 1 || ta.UntrustedAgents[0] != "sketch-bot" {
		t.Errorf("untrusted agents = %v, want [sketch-bot]", ta.UntrustedAgents)
	}
}

func TestAnalyzeTrustEdges(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta: AgentMeta{Name: "a"},
				Trust: TrustConfig{
					Level:      TrustStandard,
					TrustsFrom: []string{"b"},
				},
			},
			{
				Meta: AgentMeta{Name: "b"},
				Trust: TrustConfig{
					Level:     TrustLow,
					TrustedBy: []string{"c"},
				},
			},
			{
				Meta:  AgentMeta{Name: "c"},
				Trust: TrustConfig{Level: TrustStandard},
			},
		},
	}
	ta := inv.AnalyzeTrust()
	if len(ta.TrustEdges) != 2 {
		t.Errorf("edges = %d, want 2", len(ta.TrustEdges))
	}
}

func TestAnalyzeTrustMutualTrust(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta: AgentMeta{Name: "a"},
				Trust: TrustConfig{
					Level:      TrustStandard,
					TrustsFrom: []string{"b"},
					TrustedBy:  []string{"b"},
				},
			},
			{
				Meta: AgentMeta{Name: "b"},
				Trust: TrustConfig{
					Level:      TrustStandard,
					TrustsFrom: []string{"a"},
					TrustedBy:  []string{"a"},
				},
			},
		},
	}
	ta := inv.AnalyzeTrust()
	// Should have edges in both directions: a->b and b->a.
	if len(ta.TrustEdges) < 2 {
		t.Errorf("edges = %d, want >= 2", len(ta.TrustEdges))
	}
}

func TestAnalyzeTrustEscalationPath(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta: AgentMeta{Name: "low-agent"},
				Trust: TrustConfig{
					Level:     TrustLow,
					TrustedBy: []string{"admin-agent"},
				},
			},
			{
				Meta: AgentMeta{Name: "admin-agent"},
				Trust: TrustConfig{
					Level:      TrustAdmin,
					TrustsFrom: []string{"low-agent"},
				},
			},
		},
	}
	ta := inv.AnalyzeTrust()
	if len(ta.EscalationPaths) == 0 {
		t.Error("expected at least one escalation path")
	}
	// Check that a path goes from low-agent to admin-agent.
	found := false
	for _, path := range ta.EscalationPaths {
		if len(path) >= 2 && path[0] == "low-agent" && path[len(path)-1] == "admin-agent" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected escalation path from low-agent to admin-agent, got %v", ta.EscalationPaths)
	}
}

func TestAnalyzeTrustOverTrusted(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:         AgentMeta{Name: "popular"},
				Capabilities: AgentCapabilities{CodeExecution: true},
				Trust:        TrustConfig{Level: TrustStandard},
			},
			{
				Meta: AgentMeta{Name: "a"},
				Trust: TrustConfig{
					Level:     TrustLow,
					TrustedBy: []string{"popular"},
				},
			},
			{
				Meta: AgentMeta{Name: "b"},
				Trust: TrustConfig{
					Level:     TrustLow,
					TrustedBy: []string{"popular"},
				},
			},
			{
				Meta: AgentMeta{Name: "c"},
				Trust: TrustConfig{
					Level:     TrustLow,
					TrustedBy: []string{"popular"},
				},
			},
		},
	}
	ta := inv.AnalyzeTrust()
	found := false
	for _, name := range ta.OverTrustedAgents {
		if name == "popular" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected popular to be over-trusted, got %v", ta.OverTrustedAgents)
	}
}

func TestAnalyzeTrustBoundaryGap(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta: AgentMeta{Name: "internal-agent"},
				Trust: TrustConfig{
					Level:      TrustStandard,
					Boundaries: []string{"internal"},
					TrustsFrom: []string{"external-agent"},
				},
			},
			{
				Meta: AgentMeta{Name: "external-agent"},
				Trust: TrustConfig{
					Level:      TrustLow,
					Boundaries: []string{"external"},
				},
			},
		},
	}
	ta := inv.AnalyzeTrust()
	found := false
	for _, r := range ta.Risks {
		if r.Risk == "boundary_gap" && r.AgentName == "internal-agent" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected boundary_gap risk for internal-agent, got risks: %v", ta.Risks)
	}
}

func TestAnalyzeTrustMissingGuardrailsRisk(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:         AgentMeta{Name: "risky"},
				Capabilities: AgentCapabilities{ToolCalling: true},
				Trust:        TrustConfig{Level: TrustStandard},
			},
		},
	}
	ta := inv.AnalyzeTrust()
	found := false
	for _, r := range ta.Risks {
		if r.Risk == "missing_guardrails" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected missing_guardrails risk, got %v", ta.Risks)
	}
}

func TestAnalyzeTrustElevatedToolLowTrustRisk(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:  AgentMeta{Name: "lowbie", Type: TypeToolCalling},
				Tools: []ToolAccess{{Name: "shell", Elevated: true}},
				Trust: TrustConfig{Level: TrustLow},
			},
		},
	}
	ta := inv.AnalyzeTrust()
	found := false
	for _, r := range ta.Risks {
		if r.Risk == "elevated_tool_low_trust" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected elevated_tool_low_trust risk, got %v", ta.Risks)
	}
}

func TestAnalyzeTrustBoundaries(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:  AgentMeta{Name: "a"},
				Trust: TrustConfig{Level: TrustStandard, Boundaries: []string{"zone-1"}},
			},
			{
				Meta:  AgentMeta{Name: "b"},
				Trust: TrustConfig{Level: TrustStandard, Boundaries: []string{"zone-1", "zone-2"}},
			},
			{
				Meta:  AgentMeta{Name: "c"},
				Trust: TrustConfig{Level: TrustLow, Boundaries: []string{"zone-2"}},
			},
		},
	}
	ta := inv.AnalyzeTrust()
	if agents, ok := ta.TrustBoundaries["zone-1"]; !ok || len(agents) != 2 {
		t.Errorf("zone-1 agents = %v, want 2 agents", agents)
	}
	if agents, ok := ta.TrustBoundaries["zone-2"]; !ok || len(agents) != 2 {
		t.Errorf("zone-2 agents = %v, want 2 agents", agents)
	}
}

// --- FormatInventory tests ---

func TestFormatInventoryEmpty(t *testing.T) {
	inv := &Inventory{}
	out := FormatInventory(inv)
	if !strings.Contains(out, "No agents") {
		t.Error("expected 'No agents' message for empty inventory")
	}
}

func TestFormatInventoryContainsHeader(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:  AgentMeta{Name: "alpha", Type: TypeRetrieval},
				Trust: TrustConfig{Level: TrustStandard},
			},
		},
	}
	out := FormatInventory(inv)
	if !strings.Contains(out, "AGENT INVENTORY") {
		t.Error("expected AGENT INVENTORY header")
	}
	if !strings.Contains(out, "alpha") {
		t.Error("expected agent name in output")
	}
	if !strings.Contains(out, "Total Agents") {
		t.Error("expected Total Agents in output")
	}
}

func TestFormatInventoryBoxDrawing(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{
				Meta:  AgentMeta{Name: "a", Type: TypeRetrieval},
				Trust: TrustConfig{Level: TrustLow},
			},
		},
	}
	out := FormatInventory(inv)
	if !strings.Contains(out, "┌") {
		t.Error("expected box drawing top-left corner")
	}
	if !strings.Contains(out, "└") {
		t.Error("expected box drawing bottom-left corner")
	}
	if !strings.Contains(out, "├") {
		t.Error("expected box drawing T-junction")
	}
}

func TestFormatInventoryMultipleAgents(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			{Meta: AgentMeta{Name: "agent-1", Type: TypeRetrieval}, Trust: TrustConfig{Level: TrustLow}},
			{Meta: AgentMeta{Name: "agent-2", Type: TypeOrchestrator}, Trust: TrustConfig{Level: TrustAdmin}},
			{Meta: AgentMeta{Name: "agent-3", Type: TypeRetrieval}, Trust: TrustConfig{Level: TrustStandard}},
		},
	}
	out := FormatInventory(inv)
	if !strings.Contains(out, "agent-1") {
		t.Error("missing agent-1")
	}
	if !strings.Contains(out, "agent-2") {
		t.Error("missing agent-2")
	}
	if !strings.Contains(out, "agent-3") {
		t.Error("missing agent-3")
	}
	if !strings.Contains(out, "By Type") {
		t.Error("missing By Type section")
	}
	if !strings.Contains(out, "By Trust Level") {
		t.Error("missing By Trust Level section")
	}
}

// --- FormatTrustAnalysis tests ---

func TestFormatTrustAnalysisContainsHeader(t *testing.T) {
	ta := &TrustAnalysis{
		TotalAgents:     3,
		TrustBoundaries: make(map[string][]string),
	}
	out := FormatTrustAnalysis(ta)
	if !strings.Contains(out, "TRUST ANALYSIS") {
		t.Error("expected TRUST ANALYSIS header")
	}
	if !strings.Contains(out, "Total Agents") {
		t.Error("expected Total Agents line")
	}
}

func TestFormatTrustAnalysisWithRisks(t *testing.T) {
	ta := &TrustAnalysis{
		TotalAgents:     2,
		TrustBoundaries: make(map[string][]string),
		Risks: []TrustRisk{
			{AgentName: "bad-bot", Risk: "missing_guardrails", Severity: "high", Description: "no guardrails"},
		},
	}
	out := FormatTrustAnalysis(ta)
	if !strings.Contains(out, "Risks") {
		t.Error("expected Risks section")
	}
	if !strings.Contains(out, "high") {
		t.Error("expected severity in output")
	}
}

func TestFormatTrustAnalysisWithAdminAndUntrusted(t *testing.T) {
	ta := &TrustAnalysis{
		TotalAgents:     3,
		AdminAgents:     []string{"boss"},
		UntrustedAgents: []string{"rogue"},
		TrustBoundaries: make(map[string][]string),
	}
	out := FormatTrustAnalysis(ta)
	if !strings.Contains(out, "Admin Agents") {
		t.Error("expected Admin Agents section")
	}
	if !strings.Contains(out, "boss") {
		t.Error("expected boss in output")
	}
	if !strings.Contains(out, "Untrusted Agents") {
		t.Error("expected Untrusted Agents section")
	}
	if !strings.Contains(out, "rogue") {
		t.Error("expected rogue in output")
	}
}

func TestFormatTrustAnalysisWithEscalation(t *testing.T) {
	ta := &TrustAnalysis{
		TotalAgents:     2,
		TrustBoundaries: make(map[string][]string),
		EscalationPaths: [][]string{{"low-bot", "admin-bot"}},
	}
	out := FormatTrustAnalysis(ta)
	if !strings.Contains(out, "Escalation Paths") {
		t.Error("expected Escalation Paths section")
	}
	if !strings.Contains(out, "low-bot -> admin-bot") {
		t.Error("expected escalation path in output")
	}
}

func TestFormatTrustAnalysisWithBoundaries(t *testing.T) {
	ta := &TrustAnalysis{
		TotalAgents: 2,
		TrustBoundaries: map[string][]string{
			"zone-a": {"agent-1", "agent-2"},
		},
	}
	out := FormatTrustAnalysis(ta)
	if !strings.Contains(out, "Trust Boundaries") {
		t.Error("expected Trust Boundaries section")
	}
	if !strings.Contains(out, "zone-a") {
		t.Error("expected zone-a in output")
	}
}

// --- FormatAgent tests ---

func TestFormatAgentContainsName(t *testing.T) {
	a := &Agent{
		Meta: AgentMeta{
			Name:        "test-agent",
			Type:        TypeToolCalling,
			Model:       "gpt-4",
			Version:     "1.0",
			Owner:       "team-x",
			Description: "A test agent for formatting",
		},
		Capabilities: AgentCapabilities{ToolCalling: true, WebAccess: true},
		Trust: TrustConfig{
			Level:       TrustStandard,
			TrustsFrom:  []string{"other-agent"},
			TrustedBy:   []string{"another-agent"},
			Boundaries:  []string{"internal"},
			CanEscalate: true,
		},
		Tools: []ToolAccess{
			{Name: "web-search", Actions: []string{"search"}, RateLimit: 100},
			{Name: "shell", Elevated: true},
		},
		Guardrails: []Guardrail{
			{Name: "sanitizer", Type: "input", Enforced: true},
		},
	}
	out := FormatAgent(a)
	if !strings.Contains(out, "AGENT DETAIL") {
		t.Error("expected AGENT DETAIL header")
	}
	if !strings.Contains(out, "test-agent") {
		t.Error("expected agent name")
	}
	if !strings.Contains(out, "tool-calling") {
		t.Error("expected agent type")
	}
	if !strings.Contains(out, "gpt-4") {
		t.Error("expected model")
	}
	if !strings.Contains(out, "Capabilities") {
		t.Error("expected Capabilities section")
	}
	if !strings.Contains(out, "* tool_calling") {
		t.Error("expected tool_calling marked with *")
	}
	if !strings.Contains(out, "Tools") {
		t.Error("expected Tools section")
	}
	if !strings.Contains(out, "web-search") {
		t.Error("expected web-search tool")
	}
	if !strings.Contains(out, "ELEVATED") {
		t.Error("expected ELEVATED marker")
	}
	if !strings.Contains(out, "Trust") {
		t.Error("expected Trust section")
	}
	if !strings.Contains(out, "can_escalate") {
		t.Error("expected can_escalate")
	}
	if !strings.Contains(out, "yes") {
		t.Error("expected escalate=yes")
	}
	if !strings.Contains(out, "Guardrails") {
		t.Error("expected Guardrails section")
	}
	if !strings.Contains(out, "sanitizer") {
		t.Error("expected guardrail name")
	}
}

func TestFormatAgentNoToolsOrGuardrails(t *testing.T) {
	a := &Agent{
		Meta:  AgentMeta{Name: "minimal", Type: TypeConversational, Model: "gpt-4", Version: "1.0", Owner: "me"},
		Trust: TrustConfig{Level: TrustLow},
	}
	out := FormatAgent(a)
	if !strings.Contains(out, "minimal") {
		t.Error("expected agent name")
	}
	// Should still have box drawing.
	if !strings.Contains(out, "┌") {
		t.Error("expected box drawing")
	}
}

// --- Integration: LoadInventory + AnalyzeTrust ---

func TestLoadInventoryAndAnalyze(t *testing.T) {
	dir := makeInventoryDir(t)

	inv, err := LoadInventory(dir)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}

	ta := inv.AnalyzeTrust()

	if ta.TotalAgents != 4 {
		t.Errorf("total agents = %d, want 4", ta.TotalAgents)
	}

	// agent-b is admin.
	foundAdmin := false
	for _, name := range ta.AdminAgents {
		if name == "agent-b" {
			foundAdmin = true
		}
	}
	if !foundAdmin {
		t.Errorf("expected agent-b in admin agents, got %v", ta.AdminAgents)
	}

	// agent-d is untrusted.
	foundUntrusted := false
	for _, name := range ta.UntrustedAgents {
		if name == "agent-d" {
			foundUntrusted = true
		}
	}
	if !foundUntrusted {
		t.Errorf("expected agent-d in untrusted agents, got %v", ta.UntrustedAgents)
	}

	// FormatInventory should not crash.
	out := FormatInventory(inv)
	if out == "" {
		t.Error("FormatInventory returned empty")
	}

	// FormatTrustAnalysis should not crash.
	taOut := FormatTrustAnalysis(ta)
	if taOut == "" {
		t.Error("FormatTrustAnalysis returned empty")
	}
}

// --- truncate tests ---

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is .."},
		{"ab", 2, "ab"},
		{"abc", 2, "ab"},
		{"", 5, ""},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}
