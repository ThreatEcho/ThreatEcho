// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"strings"
	"testing"
)

// guardrailAgent builds a minimal Agent for guardrail testing.
func guardrailAgent(name string, caps AgentCapabilities, guardrails []Guardrail, trust TrustConfig) *Agent {
	return &Agent{
		Meta:         AgentMeta{Name: name, Version: "1.0", Type: "tool-calling"},
		Capabilities: caps,
		Guardrails:   guardrails,
		Trust:        trust,
	}
}

// --- 1. Nil agent --------------------------------------------------------

func TestAnalyzeGuardrails_NilAgent(t *testing.T) {
	r := AnalyzeGuardrails(nil)
	if r == nil {
		t.Fatal("expected non-nil report for nil agent")
	}
	if r.Score != 0.0 {
		t.Errorf("expected score 0.0, got %f", r.Score)
	}
	if r.Grade != "F" {
		t.Errorf("expected grade F, got %s", r.Grade)
	}
}

// --- 2. No capabilities, no guardrails -----------------------------------

func TestAnalyzeGuardrails_NoCapabilities(t *testing.T) {
	a := guardrailAgent("clean-agent", AgentCapabilities{}, nil,
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	// No capability-driven gaps, but trust-level minimum may trigger.
	// standard needs 2 enforced; agent has 0 → trust gap expected.
	foundTrustGap := false
	for _, g := range r.Gaps {
		if g.GapType == "insufficient" {
			foundTrustGap = true
		}
	}
	if !foundTrustGap {
		t.Error("expected trust-level insufficient gap for standard trust with 0 enforced guardrails")
	}
}

// --- 3. tool_calling missing guardrail -----------------------------------

func TestAnalyzeGuardrails_ToolCallingMissingGuardrail(t *testing.T) {
	a := guardrailAgent("tc-missing",
		AgentCapabilities{ToolCalling: true}, nil,
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	found := false
	for _, g := range r.Gaps {
		if g.GapType == "missing" && g.Guardrail == "tool-call" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing tool-call gap for tool_calling capability")
	}
}

// --- 4. tool_calling with guardrail --------------------------------------

func TestAnalyzeGuardrails_ToolCallingWithGuardrail(t *testing.T) {
	a := guardrailAgent("tc-ok",
		AgentCapabilities{ToolCalling: true},
		[]Guardrail{
			{Name: "tool-call-policy", Type: "tool-call", Enforced: true},
			{Name: "output-filter", Type: "output", Enforced: true},
		},
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	for _, g := range r.Gaps {
		if g.GapType == "missing" && g.Guardrail == "tool-call" {
			t.Error("should not have missing tool-call gap when guardrail present")
		}
	}
}

// --- 5. rag missing guardrails -------------------------------------------

func TestAnalyzeGuardrails_RAGMissingGuardrails(t *testing.T) {
	a := guardrailAgent("rag-missing",
		AgentCapabilities{RAG: true}, nil,
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	needs := map[string]bool{"input": false, "output": false}
	for _, g := range r.Gaps {
		if g.GapType == "missing" {
			if _, ok := needs[g.Guardrail]; ok {
				needs[g.Guardrail] = true
			}
		}
	}
	for gtype, found := range needs {
		if !found {
			t.Errorf("expected missing %q gap for rag capability", gtype)
		}
	}
}

// --- 6. rag with guardrails ----------------------------------------------

func TestAnalyzeGuardrails_RAGWithGuardrails(t *testing.T) {
	a := guardrailAgent("rag-ok",
		AgentCapabilities{RAG: true},
		[]Guardrail{
			{Name: "input-sanitizer", Type: "input", Enforced: true},
			{Name: "output-filter", Type: "output", Enforced: true},
		},
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	for _, g := range r.Gaps {
		if g.GapType == "missing" && (g.Guardrail == "input" || g.Guardrail == "output") {
			t.Errorf("should not have missing %q gap when guardrail present", g.Guardrail)
		}
	}
}

// --- 7. code_execution missing -------------------------------------------

func TestAnalyzeGuardrails_CodeExecutionMissing(t *testing.T) {
	a := guardrailAgent("code-missing",
		AgentCapabilities{CodeExecution: true}, nil,
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	needs := map[string]bool{"tool-call": false, "output": false}
	for _, g := range r.Gaps {
		if g.GapType == "missing" {
			if _, ok := needs[g.Guardrail]; ok {
				needs[g.Guardrail] = true
			}
		}
	}
	for gtype, found := range needs {
		if !found {
			t.Errorf("expected missing %q gap for code_execution", gtype)
		}
	}
}

// --- 8. code_execution complete ------------------------------------------

func TestAnalyzeGuardrails_CodeExecutionComplete(t *testing.T) {
	a := guardrailAgent("code-ok",
		AgentCapabilities{CodeExecution: true},
		[]Guardrail{
			{Name: "tc-guard", Type: "tool-call", Enforced: true},
			{Name: "out-guard", Type: "output", Enforced: true},
		},
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	for _, g := range r.Gaps {
		if g.GapType == "missing" && (g.Guardrail == "tool-call" || g.Guardrail == "output") {
			t.Errorf("should not have missing %q gap", g.Guardrail)
		}
	}
}

// --- 9. web_access missing -----------------------------------------------

func TestAnalyzeGuardrails_WebAccessMissing(t *testing.T) {
	a := guardrailAgent("web-missing",
		AgentCapabilities{WebAccess: true}, nil,
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	needs := map[string]bool{"input": false, "output": false, "content-filter": false}
	for _, g := range r.Gaps {
		if g.GapType == "missing" {
			if _, ok := needs[g.Guardrail]; ok {
				needs[g.Guardrail] = true
			}
		}
	}
	for gtype, found := range needs {
		if !found {
			t.Errorf("expected missing %q gap for web_access", gtype)
		}
	}
}

// --- 10. web_access complete ---------------------------------------------

func TestAnalyzeGuardrails_WebAccessComplete(t *testing.T) {
	a := guardrailAgent("web-ok",
		AgentCapabilities{WebAccess: true},
		[]Guardrail{
			{Name: "in", Type: "input", Enforced: true},
			{Name: "out", Type: "output", Enforced: true},
			{Name: "cf", Type: "content-filter", Enforced: true},
		},
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	for _, g := range r.Gaps {
		if g.GapType == "missing" {
			t.Errorf("should not have missing %q gap", g.Guardrail)
		}
	}
}

// --- 11. autonomous missing ----------------------------------------------

func TestAnalyzeGuardrails_AutonomousMissing(t *testing.T) {
	a := guardrailAgent("auto-missing",
		AgentCapabilities{Autonomous: true}, nil,
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	needs := map[string]bool{
		"tool-call":      false,
		"input":          false,
		"output":         false,
		"content-filter": false,
	}
	for _, g := range r.Gaps {
		if g.GapType == "missing" {
			if _, ok := needs[g.Guardrail]; ok {
				needs[g.Guardrail] = true
			}
		}
	}
	for gtype, found := range needs {
		if !found {
			t.Errorf("expected missing %q gap for autonomous capability", gtype)
		}
	}
}

// --- 12. autonomous complete ---------------------------------------------

func TestAnalyzeGuardrails_AutonomousComplete(t *testing.T) {
	a := guardrailAgent("auto-ok",
		AgentCapabilities{Autonomous: true},
		[]Guardrail{
			{Name: "tc", Type: "tool-call", Enforced: true},
			{Name: "in", Type: "input", Enforced: true},
			{Name: "out", Type: "output", Enforced: true},
			{Name: "cf", Type: "content-filter", Enforced: true},
		},
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	for _, g := range r.Gaps {
		if g.GapType == "missing" {
			t.Errorf("should not have missing %q gap for fully covered autonomous", g.Guardrail)
		}
	}
}

// --- 13. file_access missing ---------------------------------------------

func TestAnalyzeGuardrails_FileAccessMissing(t *testing.T) {
	a := guardrailAgent("file-missing",
		AgentCapabilities{FileAccess: true}, nil,
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	found := false
	for _, g := range r.Gaps {
		if g.GapType == "missing" && g.Guardrail == "tool-call" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing tool-call gap for file_access capability")
	}
}

// --- 14. memory missing --------------------------------------------------

func TestAnalyzeGuardrails_MemoryMissing(t *testing.T) {
	a := guardrailAgent("mem-missing",
		AgentCapabilities{Memory: true}, nil,
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	needs := map[string]bool{"input": false, "output": false}
	for _, g := range r.Gaps {
		if g.GapType == "missing" {
			if _, ok := needs[g.Guardrail]; ok {
				needs[g.Guardrail] = true
			}
		}
	}
	for gtype, found := range needs {
		if !found {
			t.Errorf("expected missing %q gap for memory capability", gtype)
		}
	}
}

// --- 15. message_passing missing -----------------------------------------

func TestAnalyzeGuardrails_MessagePassingMissing(t *testing.T) {
	a := guardrailAgent("msg-missing",
		AgentCapabilities{MessagePassing: true}, nil,
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	needs := map[string]bool{"input": false, "output": false}
	for _, g := range r.Gaps {
		if g.GapType == "missing" {
			if _, ok := needs[g.Guardrail]; ok {
				needs[g.Guardrail] = true
			}
		}
	}
	for gtype, found := range needs {
		if !found {
			t.Errorf("expected missing %q gap for message_passing capability", gtype)
		}
	}
}

// --- 16. admin trust minimum ---------------------------------------------

func TestAnalyzeGuardrails_AdminTrustMinimum(t *testing.T) {
	// admin needs 4 enforced; give it 3.
	a := guardrailAgent("admin-short",
		AgentCapabilities{},
		[]Guardrail{
			{Name: "g1", Type: "input", Enforced: true},
			{Name: "g2", Type: "output", Enforced: true},
			{Name: "g3", Type: "tool-call", Enforced: true},
		},
		TrustConfig{Level: TrustAdmin})
	r := AnalyzeGuardrails(a)

	found := false
	for _, g := range r.Gaps {
		if g.GapType == "insufficient" {
			found = true
			if g.Severity != "high" {
				t.Errorf("admin insufficient gap should be high severity, got %q", g.Severity)
			}
		}
	}
	if !found {
		t.Error("expected insufficient gap for admin with only 3 enforced guardrails")
	}
}

// --- 17. elevated trust minimum ------------------------------------------

func TestAnalyzeGuardrails_ElevatedTrustMinimum(t *testing.T) {
	// elevated needs 3 enforced; give it 2.
	a := guardrailAgent("elev-short",
		AgentCapabilities{},
		[]Guardrail{
			{Name: "g1", Type: "input", Enforced: true},
			{Name: "g2", Type: "output", Enforced: true},
		},
		TrustConfig{Level: TrustElevated})
	r := AnalyzeGuardrails(a)

	found := false
	for _, g := range r.Gaps {
		if g.GapType == "insufficient" {
			found = true
			if g.Severity != "high" {
				t.Errorf("elevated insufficient gap should be high severity, got %q", g.Severity)
			}
		}
	}
	if !found {
		t.Error("expected insufficient gap for elevated trust with only 2 enforced guardrails")
	}
}

// --- 18. standard trust minimum ------------------------------------------

func TestAnalyzeGuardrails_StandardTrustMinimum(t *testing.T) {
	// standard needs 2 enforced; give it 1.
	a := guardrailAgent("std-short",
		AgentCapabilities{},
		[]Guardrail{
			{Name: "g1", Type: "input", Enforced: true},
		},
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	found := false
	for _, g := range r.Gaps {
		if g.GapType == "insufficient" {
			found = true
			if g.Severity != "medium" {
				t.Errorf("standard insufficient gap should be medium severity, got %q", g.Severity)
			}
		}
	}
	if !found {
		t.Error("expected insufficient gap for standard trust with only 1 enforced guardrail")
	}
}

// --- 19. low trust minimum -----------------------------------------------

func TestAnalyzeGuardrails_LowTrustMinimum(t *testing.T) {
	// low needs 3 enforced; give it 2.
	a := guardrailAgent("low-short",
		AgentCapabilities{},
		[]Guardrail{
			{Name: "g1", Type: "input", Enforced: true},
			{Name: "g2", Type: "output", Enforced: true},
		},
		TrustConfig{Level: TrustLow})
	r := AnalyzeGuardrails(a)

	found := false
	for _, g := range r.Gaps {
		if g.GapType == "insufficient" {
			found = true
		}
	}
	if !found {
		t.Error("expected insufficient gap for low trust with only 2 enforced guardrails")
	}
}

// --- 20. untrusted minimum -----------------------------------------------

func TestAnalyzeGuardrails_UntrustedMinimum(t *testing.T) {
	// untrusted needs 4 enforced; give it 3.
	a := guardrailAgent("untrust-short",
		AgentCapabilities{},
		[]Guardrail{
			{Name: "g1", Type: "input", Enforced: true},
			{Name: "g2", Type: "output", Enforced: true},
			{Name: "g3", Type: "tool-call", Enforced: true},
		},
		TrustConfig{Level: TrustUntrusted})
	r := AnalyzeGuardrails(a)

	found := false
	for _, g := range r.Gaps {
		if g.GapType == "insufficient" {
			found = true
		}
	}
	if !found {
		t.Error("expected insufficient gap for untrusted trust with only 3 enforced guardrails")
	}
}

// --- 21. elevated tool without tool-call guardrail -----------------------

func TestAnalyzeGuardrails_ElevatedToolNoGuardrail(t *testing.T) {
	a := &Agent{
		Meta: AgentMeta{Name: "elev-tool-ng", Version: "1.0", Type: "tool-calling"},
		Tools: []ToolAccess{
			{Name: "admin-api", Elevated: true},
		},
		Trust: TrustConfig{Level: TrustStandard},
	}
	r := AnalyzeGuardrails(a)

	found := false
	for _, g := range r.Gaps {
		if g.GapType == "missing" && g.Guardrail == "tool-call" && g.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Error("expected critical missing tool-call gap for elevated tool without guardrail")
	}
}

// --- 22. elevated tool with tool-call guardrail --------------------------

func TestAnalyzeGuardrails_ElevatedToolWithGuardrail(t *testing.T) {
	a := &Agent{
		Meta: AgentMeta{Name: "elev-tool-ok", Version: "1.0", Type: "tool-calling"},
		Tools: []ToolAccess{
			{Name: "admin-api", Elevated: true},
		},
		Guardrails: []Guardrail{
			{Name: "tc-policy", Type: "tool-call", Enforced: true},
			{Name: "in-guard", Type: "input", Enforced: true},
		},
		Trust: TrustConfig{Level: TrustStandard},
	}
	r := AnalyzeGuardrails(a)

	for _, g := range r.Gaps {
		if g.GapType == "missing" && g.Guardrail == "tool-call" && g.Severity == "critical" {
			t.Error("should not have critical missing tool-call gap when guardrail present")
		}
	}
}

// --- 23. unenforced guardrail --------------------------------------------

func TestAnalyzeGuardrails_UnenforcedGuardrail(t *testing.T) {
	a := guardrailAgent("unenforced-agent",
		AgentCapabilities{},
		[]Guardrail{
			{Name: "soft-guard", Type: "input", Enforced: false},
			{Name: "hard-guard", Type: "output", Enforced: true},
			{Name: "another-hard", Type: "tool-call", Enforced: true},
		},
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	found := false
	for _, g := range r.Gaps {
		if g.GapType == "unenforced" && g.Guardrail == "input" && g.Severity == "low" {
			found = true
		}
	}
	if !found {
		t.Error("expected low-severity unenforced gap for non-enforced guardrail")
	}
}

// --- 24. redundant guardrails --------------------------------------------

func TestAnalyzeGuardrails_RedundantGuardrails(t *testing.T) {
	a := guardrailAgent("redundant-agent",
		AgentCapabilities{},
		[]Guardrail{
			{Name: "input-1", Type: "input", Enforced: true},
			{Name: "input-2", Type: "input", Enforced: true},
			{Name: "output-1", Type: "output", Enforced: true},
		},
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	found := false
	for _, g := range r.Gaps {
		if g.GapType == "redundant" && g.Guardrail == "input" {
			found = true
		}
	}
	if !found {
		t.Error("expected redundant gap when same guardrail type declared twice")
	}
}

// --- 25. score: critical gap deducts 0.20 --------------------------------

func TestAnalyzeGuardrails_ScoreCritical(t *testing.T) {
	// Agent with elevated trust and tool_calling but no guardrails.
	// Elevated + missing tool-call = critical gap.
	a := guardrailAgent("score-crit",
		AgentCapabilities{ToolCalling: true}, nil,
		TrustConfig{Level: TrustElevated})
	r := AnalyzeGuardrails(a)

	hasCritical := false
	for _, g := range r.Gaps {
		if g.Severity == "critical" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Fatal("expected at least one critical gap")
	}
	if r.Score >= 1.0 {
		t.Error("score should be reduced by critical gap")
	}
}

// --- 26. score: high gap deducts 0.12 ------------------------------------

func TestAnalyzeGuardrails_ScoreHigh(t *testing.T) {
	// Standard trust + tool_calling no guardrails = high gap for missing
	// (standard trust gives severity "high" for capability gap).
	a := guardrailAgent("score-high",
		AgentCapabilities{ToolCalling: true}, nil,
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	hasHigh := false
	for _, g := range r.Gaps {
		if g.Severity == "high" {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Fatal("expected at least one high-severity gap")
	}
	if r.Score >= 1.0 {
		t.Error("score should be reduced by high gap")
	}
}

// --- 27. score: medium gap deducts 0.06 ----------------------------------

func TestAnalyzeGuardrails_ScoreMedium(t *testing.T) {
	// Standard trust with 1 enforced (needs 2) = medium insufficient gap.
	a := guardrailAgent("score-med",
		AgentCapabilities{},
		[]Guardrail{
			{Name: "g1", Type: "input", Enforced: true},
		},
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	hasMedium := false
	for _, g := range r.Gaps {
		if g.Severity == "medium" {
			hasMedium = true
		}
	}
	if !hasMedium {
		t.Fatal("expected at least one medium-severity gap")
	}
	if r.Score >= 1.0 {
		t.Error("score should be reduced by medium gap")
	}
}

// --- 28. score: low gap deducts 0.03 -------------------------------------

func TestAnalyzeGuardrails_ScoreLow(t *testing.T) {
	// Agent with an unenforced guardrail = low gap.
	a := guardrailAgent("score-low",
		AgentCapabilities{},
		[]Guardrail{
			{Name: "soft", Type: "input", Enforced: false},
			{Name: "h1", Type: "output", Enforced: true},
			{Name: "h2", Type: "tool-call", Enforced: true},
		},
		TrustConfig{Level: TrustStandard})
	r := AnalyzeGuardrails(a)

	hasLow := false
	for _, g := range r.Gaps {
		if g.Severity == "low" {
			hasLow = true
		}
	}
	if !hasLow {
		t.Fatal("expected at least one low-severity gap")
	}
	if r.Score >= 1.0 {
		t.Error("score should be reduced by low gap")
	}
}

// --- 29. score floor at 0.0 ----------------------------------------------

func TestAnalyzeGuardrails_ScoreFloor(t *testing.T) {
	// Create enough gaps to push score well below zero.
	// autonomous + admin + no guardrails = many critical/high gaps.
	a := guardrailAgent("score-floor",
		AgentCapabilities{
			ToolCalling:    true,
			RAG:            true,
			CodeExecution:  true,
			WebAccess:      true,
			FileAccess:     true,
			MessagePassing: true,
			Memory:         true,
			Autonomous:     true,
		},
		nil,
		TrustConfig{Level: TrustAdmin})
	r := AnalyzeGuardrails(a)

	if r.Score < 0.0 {
		t.Errorf("score should never go below 0.0, got %f", r.Score)
	}
	if r.Score != 0.0 {
		t.Logf("score: %f (expected 0.0 from massive deductions)", r.Score)
	}
}

// --- 30. gradeGuardrail thresholds ----------------------------------------

func TestGradeGuardrail(t *testing.T) {
	tests := []struct {
		score float64
		grade string
	}{
		{1.0, "A"},
		{0.95, "A"},
		{0.9, "A"},
		{0.89, "B"},
		{0.7, "B"},
		{0.69, "C"},
		{0.5, "C"},
		{0.49, "D"},
		{0.3, "D"},
		{0.29, "F"},
		{0.1, "F"},
		{0.0, "F"},
	}
	for _, tt := range tests {
		got := gradeGuardrail(tt.score)
		if got != tt.grade {
			t.Errorf("gradeGuardrail(%f) = %q, want %q", tt.score, got, tt.grade)
		}
	}
}

// --- 31. AnalyzeAllGuardrails nil inventory ------------------------------

func TestAnalyzeAllGuardrails_Empty(t *testing.T) {
	var inv *Inventory
	r := inv.AnalyzeAllGuardrails()
	if r == nil {
		t.Fatal("expected non-nil report for nil inventory")
	}
	if r.TotalAgents != 0 {
		t.Errorf("expected 0 total agents, got %d", r.TotalAgents)
	}
}

// --- 32. AnalyzeAllGuardrails multiple agents ----------------------------

func TestAnalyzeAllGuardrails_MultipleAgents(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			guardrailAgent("agent-a",
				AgentCapabilities{ToolCalling: true},
				[]Guardrail{
					{Name: "tc", Type: "tool-call", Enforced: true},
					{Name: "in", Type: "input", Enforced: true},
				},
				TrustConfig{Level: TrustStandard}),
			guardrailAgent("agent-b",
				AgentCapabilities{RAG: true}, nil,
				TrustConfig{Level: TrustStandard}),
			guardrailAgent("agent-c",
				AgentCapabilities{},
				[]Guardrail{
					{Name: "in", Type: "input", Enforced: true},
					{Name: "out", Type: "output", Enforced: true},
				},
				TrustConfig{Level: TrustStandard}),
		},
	}
	r := inv.AnalyzeAllGuardrails()

	if r.TotalAgents != 3 {
		t.Errorf("expected 3 total agents, got %d", r.TotalAgents)
	}
	if len(r.Reports) != 3 {
		t.Errorf("expected 3 reports, got %d", len(r.Reports))
	}
	if r.TotalGaps == 0 {
		t.Error("expected at least some gaps across 3 agents")
	}
}

// --- 33. AnalyzeAllGuardrails critical gap counting ----------------------

func TestAnalyzeAllGuardrails_CriticalCount(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			// elevated + tool_calling + no guardrails = critical gap.
			guardrailAgent("crit-1",
				AgentCapabilities{ToolCalling: true}, nil,
				TrustConfig{Level: TrustElevated}),
			// admin + rag + no guardrails = critical gaps.
			guardrailAgent("crit-2",
				AgentCapabilities{RAG: true}, nil,
				TrustConfig{Level: TrustAdmin}),
		},
	}
	r := inv.AnalyzeAllGuardrails()

	if r.CriticalGaps == 0 {
		t.Error("expected at least one critical gap")
	}
}

// --- 34. AnalyzeAllGuardrails worst agents (grade D/F) -------------------

func TestAnalyzeAllGuardrails_WorstAgents(t *testing.T) {
	inv := &Inventory{
		Agents: []*Agent{
			// This should score poorly (many gaps = D or F).
			guardrailAgent("bad-agent",
				AgentCapabilities{
					ToolCalling:   true,
					RAG:           true,
					CodeExecution: true,
					WebAccess:     true,
					Autonomous:    true,
				}, nil,
				TrustConfig{Level: TrustAdmin}),
			// This one should be fully covered.
			guardrailAgent("good-agent",
				AgentCapabilities{},
				[]Guardrail{
					{Name: "in", Type: "input", Enforced: true},
					{Name: "out", Type: "output", Enforced: true},
					{Name: "tc", Type: "tool-call", Enforced: true},
					{Name: "cf", Type: "content-filter", Enforced: true},
				},
				TrustConfig{Level: TrustAdmin}),
		},
	}
	r := inv.AnalyzeAllGuardrails()

	foundBad := false
	for _, name := range r.WorstAgents {
		if name == "bad-agent" {
			foundBad = true
		}
		if name == "good-agent" {
			t.Error("good-agent should not be in worst agents")
		}
	}
	if !foundBad {
		t.Error("bad-agent should be in worst agents (grade D or F)")
	}
}

// --- 35. FormatGuardrailReport nil ---------------------------------------

func TestFormatGuardrailReport_Nil(t *testing.T) {
	out := FormatGuardrailReport(nil)
	if !strings.Contains(out, "No guardrail report") {
		t.Error("nil report should produce 'No guardrail report' message")
	}
}

// --- 36. FormatGuardrailReport non-nil output ----------------------------

func TestFormatGuardrailReport_Output(t *testing.T) {
	r := &GuardrailReport{
		AgentName:       "test-agent",
		AgentType:       "tool-calling",
		TrustLevel:      "standard",
		TotalGuardrails: 2,
		EnforcedCount:   1,
		Score:           0.75,
		Grade:           "B",
		Gaps: []GuardrailGap{
			{AgentName: "test-agent", GapType: "missing", Guardrail: "tool-call", Severity: "high"},
		},
	}
	out := FormatGuardrailReport(r)

	checks := []string{
		"GUARDRAIL ANALYSIS",
		"test-agent",
		"tool-calling",
		"standard",
		"0.75",
		"B",
		"missing",
		"tool-call",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("formatted report should contain %q", c)
		}
	}
}

// --- 37. FormatGuardrailReport with no gaps ------------------------------

func TestFormatGuardrailReport_NoGaps(t *testing.T) {
	r := &GuardrailReport{
		AgentName:       "clean-agent",
		AgentType:       "retrieval",
		TrustLevel:      "standard",
		TotalGuardrails: 3,
		EnforcedCount:   3,
		Score:           1.0,
		Grade:           "A",
	}
	out := FormatGuardrailReport(r)

	if !strings.Contains(out, "No guardrail gaps found") {
		t.Error("report with no gaps should contain 'No guardrail gaps found'")
	}
}

// --- 38. FormatInventoryGuardrailReport nil -------------------------------

func TestFormatInventoryGuardrailReport_Nil(t *testing.T) {
	out := FormatInventoryGuardrailReport(nil)
	if !strings.Contains(out, "No inventory guardrail report") {
		t.Error("nil inventory report should produce 'No inventory guardrail report' message")
	}
}

// --- 39. FormatInventoryGuardrailReport non-nil output -------------------

func TestFormatInventoryGuardrailReport_Output(t *testing.T) {
	igr := &InventoryGuardrailReport{
		TotalAgents:       2,
		TotalGaps:         3,
		CriticalGaps:      1,
		FullyCoveredCount: 1,
		Reports: []GuardrailReport{
			{AgentName: "agent-alpha", Score: 0.8, Grade: "B", Gaps: []GuardrailGap{
				{Severity: "high"},
			}},
			{AgentName: "agent-beta", Score: 1.0, Grade: "A"},
		},
		WorstAgents: []string{"agent-gamma"},
	}
	out := FormatInventoryGuardrailReport(igr)

	checks := []string{
		"INVENTORY GUARDRAIL REPORT",
		"agent-alpha",
		"agent-beta",
		"agent-gamma",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("formatted inventory report should contain %q", c)
		}
	}
}

// --- 40. activeCapabilities function ------------------------------------

func TestActiveCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		caps     AgentCapabilities
		expected []string
	}{
		{
			name:     "all off",
			caps:     AgentCapabilities{},
			expected: nil,
		},
		{
			name:     "tool_calling only",
			caps:     AgentCapabilities{ToolCalling: true},
			expected: []string{"tool_calling"},
		},
		{
			name:     "rag only",
			caps:     AgentCapabilities{RAG: true},
			expected: []string{"rag"},
		},
		{
			name:     "code_execution only",
			caps:     AgentCapabilities{CodeExecution: true},
			expected: []string{"code_execution"},
		},
		{
			name:     "web_access only",
			caps:     AgentCapabilities{WebAccess: true},
			expected: []string{"web_access"},
		},
		{
			name:     "file_access only",
			caps:     AgentCapabilities{FileAccess: true},
			expected: []string{"file_access"},
		},
		{
			name:     "message_passing only",
			caps:     AgentCapabilities{MessagePassing: true},
			expected: []string{"message_passing"},
		},
		{
			name:     "memory only",
			caps:     AgentCapabilities{Memory: true},
			expected: []string{"memory"},
		},
		{
			name:     "autonomous only",
			caps:     AgentCapabilities{Autonomous: true},
			expected: []string{"autonomous"},
		},
		{
			name: "all on",
			caps: AgentCapabilities{
				ToolCalling:    true,
				RAG:            true,
				CodeExecution:  true,
				WebAccess:      true,
				FileAccess:     true,
				MessagePassing: true,
				Memory:         true,
				Autonomous:     true,
			},
			expected: []string{
				"tool_calling", "rag", "code_execution", "web_access",
				"file_access", "message_passing", "memory", "autonomous",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{Capabilities: tt.caps}
			got := activeCapabilities(a)

			if len(got) != len(tt.expected) {
				t.Fatalf("activeCapabilities returned %d items, want %d: got=%v", len(got), len(tt.expected), got)
			}
			for i, want := range tt.expected {
				if got[i] != want {
					t.Errorf("activeCapabilities[%d] = %q, want %q", i, got[i], want)
				}
			}
		})
	}
}

// --- 41. severityRank function -------------------------------------------

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity string
		rank     int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := severityRank(tt.severity)
		if got != tt.rank {
			t.Errorf("severityRank(%q) = %d, want %d", tt.severity, got, tt.rank)
		}
	}
}

// --- 42. gapIcon function ------------------------------------------------

func TestGapIcon(t *testing.T) {
	tests := []struct {
		severity string
		icon     string
	}{
		{"critical", "\xf0\x9f\x94\xb4"}, // red circle
		{"high", "\xf0\x9f\x9f\xa0"},     // orange circle
		{"medium", "\xf0\x9f\x9f\xa1"},   // yellow circle
		{"low", "\xf0\x9f\x94\xb5"},      // blue circle
		{"unknown", "\xe2\x9a\xaa"},      // white circle
		{"", "\xe2\x9a\xaa"},             // white circle
	}
	for _, tt := range tests {
		got := gapIcon(tt.severity)
		if got != tt.icon {
			t.Errorf("gapIcon(%q) = %q, want %q", tt.severity, got, tt.icon)
		}
	}
}
