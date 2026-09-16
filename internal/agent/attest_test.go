// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"strings"
	"testing"
)

// --- helper builders ---

func makeMinimalAgent(name string) *Agent {
	return &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta: AgentMeta{
			Name:    name,
			Type:    TypeToolCalling,
			Version: "1.0",
			Model:   "gpt-4",
		},
		Trust: TrustConfig{
			Level: TrustStandard,
		},
	}
}

func makeFullAgent() *Agent {
	return &Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta: AgentMeta{
			Name:    "full-agent",
			Type:    TypeOrchestrator,
			Version: "2.0",
			Model:   "gpt-4",
			Owner:   "security-team",
		},
		Capabilities: AgentCapabilities{
			ToolCalling:    true,
			RAG:            true,
			CodeExecution:  false,
			WebAccess:      true,
			FileAccess:     false,
			MessagePassing: true,
			Memory:         true,
			Autonomous:     false,
		},
		Tools: []ToolAccess{
			{Name: "web-search", Actions: []string{"search", "fetch"}, Elevated: false},
			{Name: "database", Actions: []string{"read", "write"}, Elevated: true},
			{Name: "api-call", Elevated: false},
		},
		Trust: TrustConfig{
			Level:      TrustElevated,
			TrustsFrom: []string{"coordinator"},
			TrustedBy:  []string{"retrieval-bot"},
			Boundaries: []string{"internal", "partner-api"},
		},
		Guardrails: []Guardrail{
			{Name: "input-sanitizer", Type: "input", Enforced: true},
			{Name: "output-filter", Type: "output", Enforced: true},
			{Name: "tool-gate", Type: "tool-call", Enforced: true},
		},
	}
}

// --- AttestAgent tests ---

func TestAttestAgent_Nil(t *testing.T) {
	att := AttestAgent(nil, nil)
	if att == nil {
		t.Fatal("expected non-nil attestation for nil agent")
	}
	if att.Valid {
		t.Error("nil agent should produce invalid attestation")
	}
	if att.CreatedAt == "" {
		t.Error("created_at should be set even for nil agent")
	}
}

func TestAttestAgent_EmptyAgent(t *testing.T) {
	a := &Agent{
		Meta:  AgentMeta{Name: "empty"},
		Trust: TrustConfig{Level: TrustLow},
	}
	att := AttestAgent(a, DefaultAttestConfig())
	if att == nil {
		t.Fatal("expected non-nil attestation")
	}
	if att.AgentName != "empty" {
		t.Errorf("expected agent_name 'empty', got %q", att.AgentName)
	}
	// No tools, caps, guardrails, boundaries = no claims = valid.
	if !att.Valid {
		t.Error("empty agent with no claims should be valid")
	}
	if len(att.Claims) != 0 {
		t.Errorf("expected 0 claims, got %d", len(att.Claims))
	}
	if att.Fingerprint == "" {
		t.Error("fingerprint should never be empty")
	}
}

func TestAttestAgent_SimpleWithTools(t *testing.T) {
	a := makeMinimalAgent("tool-user")
	a.Tools = []ToolAccess{
		{Name: "read-file", Elevated: false},
		{Name: "write-file", Elevated: false},
	}
	att := AttestAgent(a, DefaultAttestConfig())
	if att.AgentName != "tool-user" {
		t.Errorf("agent_name = %q, want tool-user", att.AgentName)
	}
	if len(att.Claims) != 2 {
		t.Fatalf("expected 2 tool claims, got %d", len(att.Claims))
	}
	for _, c := range att.Claims {
		if c.Type != "tool_access" {
			t.Errorf("expected claim type tool_access, got %q", c.Type)
		}
		if !c.Verified {
			t.Errorf("non-elevated tool claim should be verified: %s", c.Description)
		}
	}
	if !att.Valid {
		t.Error("agent with only non-elevated tools should be valid")
	}
}

func TestAttestAgent_ElevatedToolsCorrectTrust(t *testing.T) {
	a := makeMinimalAgent("elevated-ok")
	a.Trust.Level = TrustElevated
	a.Tools = []ToolAccess{
		{Name: "admin-panel", Elevated: true},
	}
	a.Guardrails = []Guardrail{
		{Name: "gate", Type: "tool-call", Enforced: true},
	}
	att := AttestAgent(a, DefaultAttestConfig())
	// Elevated tool with elevated trust = verified.
	toolClaim := findClaim(att.Claims, "tool_access")
	if toolClaim == nil {
		t.Fatal("missing tool_access claim")
	}
	if !toolClaim.Verified {
		t.Error("elevated tool with elevated trust should be verified")
	}
}

func TestAttestAgent_ElevatedToolsWrongTrust(t *testing.T) {
	a := makeMinimalAgent("elevated-bad")
	a.Trust.Level = TrustLow
	a.Tools = []ToolAccess{
		{Name: "admin-panel", Elevated: true},
	}
	att := AttestAgent(a, DefaultAttestConfig())
	toolClaim := findClaim(att.Claims, "tool_access")
	if toolClaim == nil {
		t.Fatal("missing tool_access claim")
	}
	if toolClaim.Verified {
		t.Error("elevated tool with low trust should NOT be verified")
	}
	if att.Valid {
		t.Error("attestation should be invalid when elevated tool trust is insufficient")
	}
}

func TestAttestAgent_WithGuardrails(t *testing.T) {
	a := makeMinimalAgent("guarded")
	a.Guardrails = []Guardrail{
		{Name: "input-guard", Type: "input", Enforced: true},
		{Name: "output-guard", Type: "output", Enforced: true},
	}
	att := AttestAgent(a, DefaultAttestConfig())
	gClaims := filterClaims(att.Claims, "guardrail")
	if len(gClaims) != 2 {
		t.Fatalf("expected 2 guardrail claims, got %d", len(gClaims))
	}
	for _, c := range gClaims {
		if !c.Verified {
			t.Errorf("enforced guardrail claim should be verified: %s", c.Description)
		}
	}
}

func TestAttestAgent_UnenforcedGuardrailNotVerified(t *testing.T) {
	a := makeMinimalAgent("unenforced")
	a.Guardrails = []Guardrail{
		{Name: "lax-guard", Type: "output", Enforced: false},
	}
	att := AttestAgent(a, DefaultAttestConfig())
	gClaims := filterClaims(att.Claims, "guardrail")
	if len(gClaims) != 1 {
		t.Fatalf("expected 1 guardrail claim, got %d", len(gClaims))
	}
	if gClaims[0].Verified {
		t.Error("unenforced guardrail claim should NOT be verified")
	}
}

func TestAttestAgent_WithBoundaries(t *testing.T) {
	a := makeMinimalAgent("bounded")
	a.Trust.Boundaries = []string{"internal", "dmz"}
	att := AttestAgent(a, DefaultAttestConfig())
	bClaims := filterClaims(att.Claims, "trust_boundary")
	if len(bClaims) != 2 {
		t.Fatalf("expected 2 boundary claims, got %d", len(bClaims))
	}
	for _, c := range bClaims {
		if !c.Verified {
			t.Errorf("boundary claim should be verified: %s", c.Description)
		}
	}
}

func TestAttestAgent_CapabilityClaims(t *testing.T) {
	a := makeMinimalAgent("capable")
	a.Capabilities = AgentCapabilities{
		ToolCalling: true,
		RAG:         true,
		WebAccess:   true,
	}
	a.Trust.Boundaries = []string{"internal"} // satisfy RequireBoundaries for external caps
	att := AttestAgent(a, DefaultAttestConfig())
	capClaims := filterClaims(att.Claims, "capability")
	if len(capClaims) != 3 {
		t.Fatalf("expected 3 capability claims, got %d", len(capClaims))
	}
}

func TestAttestAgent_ExternalCapNoBoundary(t *testing.T) {
	a := makeMinimalAgent("external-no-boundary")
	a.Capabilities = AgentCapabilities{
		WebAccess: true,
	}
	// No boundaries, RequireBoundaries=true.
	cfg := DefaultAttestConfig()
	att := AttestAgent(a, cfg)
	capClaims := filterClaims(att.Claims, "capability")
	if len(capClaims) != 1 {
		t.Fatalf("expected 1 capability claim, got %d", len(capClaims))
	}
	if capClaims[0].Verified {
		t.Error("external capability without boundaries should NOT be verified when RequireBoundaries is set")
	}
}

func TestAttestAgent_FullAgent(t *testing.T) {
	a := makeFullAgent()
	att := AttestAgent(a, DefaultAttestConfig())
	if att.AgentName != "full-agent" {
		t.Errorf("expected full-agent, got %q", att.AgentName)
	}
	if att.Fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
	if att.ToolHash == "" || att.CapHash == "" || att.GuardrailHash == "" || att.BoundaryHash == "" {
		t.Error("no component hash should be empty for a full agent")
	}
	// Full agent: 3 tools + 2 boundaries + 5 caps + 3 guardrails = 13 claims.
	if len(att.Claims) != 13 {
		t.Errorf("expected 13 claims, got %d", len(att.Claims))
	}
}

func TestAttestAgent_NilConfig(t *testing.T) {
	a := makeMinimalAgent("nil-cfg")
	att := AttestAgent(a, nil)
	if att == nil {
		t.Fatal("should handle nil config gracefully")
	}
	if att.AgentName != "nil-cfg" {
		t.Errorf("agent_name = %q, want nil-cfg", att.AgentName)
	}
}

// --- AttestInventory tests ---

func TestAttestInventory_NilInventory(t *testing.T) {
	r := AttestInventory(nil, nil)
	if r == nil {
		t.Fatal("nil inventory should produce non-nil report")
	}
	if r.AgentCount != 0 {
		t.Errorf("expected 0 agents, got %d", r.AgentCount)
	}
}

func TestAttestInventory_EmptyInventory(t *testing.T) {
	inv := &Inventory{}
	r := AttestInventory(inv, DefaultAttestConfig())
	if r.AgentCount != 0 {
		t.Errorf("expected 0 agents, got %d", r.AgentCount)
	}
	if r.IntegrityScore != 1.0 {
		t.Errorf("empty inventory integrity = %.2f, want 1.00", r.IntegrityScore)
	}
}

func TestAttestInventory_MultipleAgents(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			makeFullAgent(),
			makeMinimalAgent("simple"),
		},
	}
	r := AttestInventory(inv, DefaultAttestConfig())
	if r.AgentCount != 2 {
		t.Errorf("expected 2 agents, got %d", r.AgentCount)
	}
	if len(r.Attestations) != 2 {
		t.Errorf("expected 2 attestations, got %d", len(r.Attestations))
	}
	if r.IntegrityScore < 0 || r.IntegrityScore > 1 {
		t.Errorf("integrity score out of range: %.2f", r.IntegrityScore)
	}
}

func TestAttestInventory_Warnings(t *testing.T) {
	a := makeMinimalAgent("no-guardrails")
	// No guardrails, no boundaries.
	inv := &Inventory{Agents: []*Agent{a}}
	r := AttestInventory(inv, DefaultAttestConfig())
	if len(r.Warnings) == 0 {
		t.Error("expected warnings for agent without guardrails and boundaries")
	}
	foundGuardrail := false
	foundBoundary := false
	for _, w := range r.Warnings {
		if strings.Contains(w, "no guardrails") {
			foundGuardrail = true
		}
		if strings.Contains(w, "no trust boundaries") {
			foundBoundary = true
		}
	}
	if !foundGuardrail {
		t.Error("expected warning about missing guardrails")
	}
	if !foundBoundary {
		t.Error("expected warning about missing boundaries")
	}
}

func TestAttestInventory_IntegrityScorePerfect(t *testing.T) {
	a := makeMinimalAgent("perfect")
	// No tools, caps, guardrails = no claims = perfect integrity trivially.
	inv := &Inventory{Agents: []*Agent{a}}
	cfg := &AttestConfig{
		RequireGuardrails:   false,
		RequireBoundaries:   false,
		MinTrustForElevated: TrustElevated,
	}
	r := AttestInventory(inv, cfg)
	if r.IntegrityScore != 1.0 {
		t.Errorf("integrity = %.2f, want 1.00", r.IntegrityScore)
	}
	if r.FullyAttested != 1 {
		t.Errorf("fully_attested = %d, want 1", r.FullyAttested)
	}
}

func TestAttestInventory_IntegrityScorePartial(t *testing.T) {
	a := makeMinimalAgent("partial")
	a.Trust.Level = TrustLow
	a.Tools = []ToolAccess{
		{Name: "safe-tool", Elevated: false},
		{Name: "risky-tool", Elevated: true}, // will fail: low trust
	}
	inv := &Inventory{Agents: []*Agent{a}}
	r := AttestInventory(inv, DefaultAttestConfig())
	if r.IntegrityScore >= 1.0 {
		t.Error("partial attestation should have score < 1.0")
	}
	if r.IntegrityScore <= 0 {
		t.Error("partial attestation should have score > 0")
	}
	if r.PartiallyAttested != 1 {
		t.Errorf("partially_attested = %d, want 1", r.PartiallyAttested)
	}
}

// --- VerifyAttestation tests ---

func TestVerifyAttestation_Success(t *testing.T) {
	a := makeFullAgent()
	att := AttestAgent(a, DefaultAttestConfig())
	if !VerifyAttestation(a, att) {
		t.Error("verification should pass for an unmodified agent")
	}
}

func TestVerifyAttestation_FailAfterModification(t *testing.T) {
	a := makeFullAgent()
	att := AttestAgent(a, DefaultAttestConfig())
	// Mutate the agent.
	a.Tools = append(a.Tools, ToolAccess{Name: "new-tool", Elevated: true})
	if VerifyAttestation(a, att) {
		t.Error("verification should fail after adding a tool")
	}
}

func TestVerifyAttestation_FailOnCapChange(t *testing.T) {
	a := makeFullAgent()
	att := AttestAgent(a, DefaultAttestConfig())
	a.Capabilities.Autonomous = true
	if VerifyAttestation(a, att) {
		t.Error("verification should fail after changing capability")
	}
}

func TestVerifyAttestation_FailOnGuardrailChange(t *testing.T) {
	a := makeFullAgent()
	att := AttestAgent(a, DefaultAttestConfig())
	a.Guardrails = a.Guardrails[:1] // remove guardrails
	if VerifyAttestation(a, att) {
		t.Error("verification should fail after removing guardrails")
	}
}

func TestVerifyAttestation_FailOnBoundaryChange(t *testing.T) {
	a := makeFullAgent()
	att := AttestAgent(a, DefaultAttestConfig())
	a.Trust.Boundaries = []string{"external"} // change boundaries
	if VerifyAttestation(a, att) {
		t.Error("verification should fail after changing boundaries")
	}
}

func TestVerifyAttestation_NilAgent(t *testing.T) {
	att := &Attestation{Fingerprint: "abc"}
	if VerifyAttestation(nil, att) {
		t.Error("nil agent should fail verification")
	}
}

func TestVerifyAttestation_NilAttestation(t *testing.T) {
	a := makeMinimalAgent("a")
	if VerifyAttestation(a, nil) {
		t.Error("nil attestation should fail verification")
	}
}

// --- Hash consistency and determinism ---

func TestHashConsistency_SameInput(t *testing.T) {
	a := makeFullAgent()
	h1 := computeFingerprint(a)
	h2 := computeFingerprint(a)
	if h1 != h2 {
		t.Errorf("same agent should produce same fingerprint: %s != %s", h1, h2)
	}
}

func TestHashConsistency_DifferentInput(t *testing.T) {
	a1 := makeMinimalAgent("agent-a")
	a2 := makeMinimalAgent("agent-b")
	h1 := computeFingerprint(a1)
	h2 := computeFingerprint(a2)
	if h1 == h2 {
		t.Error("different agents should produce different fingerprints")
	}
}

func TestToolHashDeterministic(t *testing.T) {
	tools := []ToolAccess{
		{Name: "z-tool", Elevated: true},
		{Name: "a-tool", Elevated: false},
	}
	reversed := []ToolAccess{
		{Name: "a-tool", Elevated: false},
		{Name: "z-tool", Elevated: true},
	}
	h1 := computeToolHash(tools)
	h2 := computeToolHash(reversed)
	if h1 != h2 {
		t.Error("tool hash should be order-independent")
	}
}

func TestToolHashEmpty(t *testing.T) {
	h := computeToolHash(nil)
	if h == "" {
		t.Error("hash of empty tools should still be a valid SHA-256 hex string")
	}
	if len(h) != 64 {
		t.Errorf("expected 64-char hex string, got %d chars", len(h))
	}
}

func TestCapHashDifferentValues(t *testing.T) {
	c1 := AgentCapabilities{ToolCalling: true}
	c2 := AgentCapabilities{ToolCalling: false}
	if computeCapHash(c1) == computeCapHash(c2) {
		t.Error("different capabilities should produce different hashes")
	}
}

func TestGuardrailHashDeterministic(t *testing.T) {
	gs := []Guardrail{
		{Name: "beta", Type: "output", Enforced: true},
		{Name: "alpha", Type: "input", Enforced: true},
	}
	reversed := []Guardrail{
		{Name: "alpha", Type: "input", Enforced: true},
		{Name: "beta", Type: "output", Enforced: true},
	}
	if computeGuardrailHash(gs) != computeGuardrailHash(reversed) {
		t.Error("guardrail hash should be order-independent")
	}
}

func TestBoundaryHashDeterministic(t *testing.T) {
	b1 := []string{"z", "a", "m"}
	b2 := []string{"a", "m", "z"}
	if computeBoundaryHash(b1) != computeBoundaryHash(b2) {
		t.Error("boundary hash should be order-independent")
	}
}

func TestFingerprintIncludesAllComponents(t *testing.T) {
	a := makeFullAgent()
	base := computeFingerprint(a)

	// Change each component and verify fingerprint changes.
	a2 := makeFullAgent()
	a2.Meta.Name = "different-name"
	if computeFingerprint(a2) == base {
		t.Error("fingerprint should change when name changes")
	}

	a3 := makeFullAgent()
	a3.Tools = append(a3.Tools, ToolAccess{Name: "extra"})
	if computeFingerprint(a3) == base {
		t.Error("fingerprint should change when tools change")
	}

	a4 := makeFullAgent()
	a4.Capabilities.Autonomous = true
	if computeFingerprint(a4) == base {
		t.Error("fingerprint should change when capabilities change")
	}

	a5 := makeFullAgent()
	a5.Guardrails = nil
	if computeFingerprint(a5) == base {
		t.Error("fingerprint should change when guardrails change")
	}

	a6 := makeFullAgent()
	a6.Trust.Boundaries = []string{"different"}
	if computeFingerprint(a6) == base {
		t.Error("fingerprint should change when boundaries change")
	}

	a7 := makeFullAgent()
	a7.Trust.Level = TrustAdmin
	if computeFingerprint(a7) == base {
		t.Error("fingerprint should change when trust level changes")
	}
}

// --- Claims tests ---

func TestBuildClaims_ToolClaims(t *testing.T) {
	a := makeMinimalAgent("tc")
	a.Tools = []ToolAccess{
		{Name: "alpha", Elevated: false},
		{Name: "beta", Elevated: true},
	}
	claims := buildClaims(a, DefaultAttestConfig())
	if len(claims) != 2 {
		t.Fatalf("expected 2 claims, got %d", len(claims))
	}
	if !strings.Contains(claims[0].Description, "alpha") {
		t.Error("first claim should mention alpha")
	}
	if !strings.Contains(claims[1].Description, "elevated") {
		t.Error("elevated tool claim should say 'elevated'")
	}
}

func TestBuildClaims_AllTypes(t *testing.T) {
	a := makeFullAgent()
	claims := buildClaims(a, DefaultAttestConfig())
	types := make(map[string]int)
	for _, c := range claims {
		types[c.Type]++
	}
	if types["tool_access"] != 3 {
		t.Errorf("tool_access claims = %d, want 3", types["tool_access"])
	}
	if types["trust_boundary"] != 2 {
		t.Errorf("trust_boundary claims = %d, want 2", types["trust_boundary"])
	}
	if types["guardrail"] != 3 {
		t.Errorf("guardrail claims = %d, want 3", types["guardrail"])
	}
	if types["capability"] < 1 {
		t.Error("expected at least 1 capability claim")
	}
}

func TestBuildClaims_NilAgent(t *testing.T) {
	claims := buildClaims(nil, DefaultAttestConfig())
	if claims != nil {
		t.Errorf("nil agent should produce nil claims, got %d", len(claims))
	}
}

// --- Format tests ---

func TestFormatAttestation_NilAttestation(t *testing.T) {
	out := FormatAttestation(nil)
	if out != "No attestation.\n" {
		t.Errorf("unexpected output for nil: %q", out)
	}
}

func TestFormatAttestation_ContainsAgentName(t *testing.T) {
	a := makeFullAgent()
	att := AttestAgent(a, DefaultAttestConfig())
	out := FormatAttestation(att)
	if !strings.Contains(out, "full-agent") {
		t.Error("formatted output should contain agent name")
	}
	if !strings.Contains(out, "AGENT ATTESTATION") {
		t.Error("formatted output should contain header")
	}
	if !strings.Contains(out, att.Fingerprint[:10]) {
		t.Error("formatted output should contain fingerprint prefix")
	}
}

func TestFormatAttestationReport_Nil(t *testing.T) {
	out := FormatAttestationReport(nil)
	if out != "No attestation report.\n" {
		t.Errorf("unexpected output for nil: %q", out)
	}
}

func TestFormatAttestationReport_ContainsSummary(t *testing.T) {
	inv := &Inventory{Agents: []*Agent{makeFullAgent()}}
	r := AttestInventory(inv, DefaultAttestConfig())
	out := FormatAttestationReport(r)
	if !strings.Contains(out, "ATTESTATION REPORT") {
		t.Error("report should contain header")
	}
	if !strings.Contains(out, "Agent Count") {
		t.Error("report should contain agent count label")
	}
	if !strings.Contains(out, "Integrity Score") {
		t.Error("report should contain integrity score")
	}
}

// --- DefaultAttestConfig test ---

func TestDefaultAttestConfig(t *testing.T) {
	cfg := DefaultAttestConfig()
	if cfg == nil {
		t.Fatal("default config should not be nil")
	}
	if !cfg.RequireGuardrails {
		t.Error("default should require guardrails")
	}
	if !cfg.RequireBoundaries {
		t.Error("default should require boundaries")
	}
	if cfg.MinTrustForElevated != TrustElevated {
		t.Errorf("min trust = %q, want %q", cfg.MinTrustForElevated, TrustElevated)
	}
}

// --- extractQuoted helper test ---

func TestExtractQuoted(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`can access tool "web-search"`, "web-search"},
		{`has capability "rag"`, "rag"},
		{`no quotes here`, ""},
		{`"only-open`, ""},
		{`""`, ""},
	}
	for _, tt := range tests {
		got := extractQuoted(tt.input)
		if got != tt.want {
			t.Errorf("extractQuoted(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- helpers for test assertions ---

func findClaim(claims []AttestClaim, claimType string) *AttestClaim {
	for i := range claims {
		if claims[i].Type == claimType {
			return &claims[i]
		}
	}
	return nil
}

func filterClaims(claims []AttestClaim, claimType string) []AttestClaim {
	var out []AttestClaim
	for _, c := range claims {
		if c.Type == claimType {
			out = append(out, c)
		}
	}
	return out
}
