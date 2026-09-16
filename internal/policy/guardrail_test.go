// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"strings"
	"testing"
)

// --- guardrail test helpers (no denyRule/allowRule/alertRule — those live in trace_test.go) ---

func grConfig(id, category, position, action string, threshold float64, required bool) GuardrailConfig {
	return GuardrailConfig{
		ID:        id,
		Name:      id,
		Category:  category,
		Position:  position,
		Action:    action,
		Threshold: threshold,
		Required:  required,
	}
}

func guardrailEventFull(id, gid, category, action string, triggered bool, score float64) TraceEvent {
	return TraceEvent{
		ID:        id,
		Timestamp: "2026-09-14T10:01:05Z",
		Type:      "guardrail",
		Guardrail: &GuardrailEvent{
			GuardrailID: gid,
			Triggered:   triggered,
			Category:    category,
			Score:       score,
			Action:      action,
		},
	}
}

// --- DefaultGuardrails tests ---

func TestGuardrailDefaultGuardrails_Count(t *testing.T) {
	dg := DefaultGuardrails()
	if len(dg) != 8 {
		t.Errorf("expected 8 default guardrails, got %d", len(dg))
	}
}

func TestGuardrailDefaultGuardrails_IDs(t *testing.T) {
	dg := DefaultGuardrails()
	expected := []string{
		"prompt-injection-detector",
		"output-toxicity-filter",
		"pii-detector",
		"content-safety-filter",
		"jailbreak-detector",
		"data-leakage-monitor",
		"credential-filter",
		"instruction-hierarchy-enforcer",
	}
	for i, id := range expected {
		if dg[i].ID != id {
			t.Errorf("default[%d]: expected ID %q, got %q", i, id, dg[i].ID)
		}
	}
}

func TestGuardrailDefaultGuardrails_Categories(t *testing.T) {
	dg := DefaultGuardrails()
	cats := make(map[string]int)
	for _, gr := range dg {
		cats[gr.Category]++
	}
	// injection: 3, pii: 3, toxicity: 1, content: 1
	if cats["injection"] != 3 {
		t.Errorf("expected 3 injection guardrails, got %d", cats["injection"])
	}
	if cats["pii"] != 3 {
		t.Errorf("expected 3 pii guardrails, got %d", cats["pii"])
	}
	if cats["toxicity"] != 1 {
		t.Errorf("expected 1 toxicity guardrail, got %d", cats["toxicity"])
	}
	if cats["content"] != 1 {
		t.Errorf("expected 1 content guardrail, got %d", cats["content"])
	}
}

func TestGuardrailDefaultGuardrails_Positions(t *testing.T) {
	dg := DefaultGuardrails()
	positions := make(map[string]int)
	for _, gr := range dg {
		positions[gr.Position]++
	}
	if positions["input"] < 1 {
		t.Error("expected at least 1 input guardrail")
	}
	if positions["output"] < 1 {
		t.Error("expected at least 1 output guardrail")
	}
	if positions["both"] < 1 {
		t.Error("expected at least 1 both-position guardrail")
	}
}

func TestGuardrailDefaultGuardrails_RequiredCount(t *testing.T) {
	dg := DefaultGuardrails()
	required := 0
	for _, gr := range dg {
		if gr.Required {
			required++
		}
	}
	if required < 5 {
		t.Errorf("expected at least 5 required guardrails, got %d", required)
	}
}

func TestGuardrailDefaultGuardrails_Thresholds(t *testing.T) {
	dg := DefaultGuardrails()
	for _, gr := range dg {
		if gr.Threshold < 0.0 || gr.Threshold > 1.0 {
			t.Errorf("guardrail %q: threshold %.2f out of range [0,1]", gr.ID, gr.Threshold)
		}
	}
}

// --- AnalyzeGuardrails tests ---

func TestGuardrailAnalyze_EmptyInputs(t *testing.T) {
	ga := AnalyzeGuardrails(nil, nil, nil)
	if ga == nil {
		t.Fatal("expected non-nil analysis")
	}
	if len(ga.TraceResults) != 0 {
		t.Errorf("expected 0 trace results, got %d", len(ga.TraceResults))
	}
	if ga.Stats.TotalGuardrails != 0 {
		t.Errorf("expected 0 total guardrails, got %d", ga.Stats.TotalGuardrails)
	}
}

func TestGuardrailAnalyze_NoTraces(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	if len(ga.TraceResults) != 1 {
		t.Fatalf("expected 1 trace result, got %d", len(ga.TraceResults))
	}
	if ga.TraceResults[0].TriggerCount != 0 {
		t.Errorf("expected 0 triggers, got %d", ga.TraceResults[0].TriggerCount)
	}
}

func TestGuardrailAnalyze_TraceMatchByID(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("injection-1", "injection", "input", "block", 0.9, true),
	}
	tr := makeTrace("t1", "agent",
		guardrailEventFull("e1", "injection-1", "injection", "block", true, 0.92),
		guardrailEventFull("e2", "injection-1", "injection", "block", true, 0.88),
	)
	ga := AnalyzeGuardrails(grs, []*Trace{tr}, nil)
	if len(ga.TraceResults) != 1 {
		t.Fatalf("expected 1 result, got %d", len(ga.TraceResults))
	}
	r := ga.TraceResults[0]
	if r.TriggerCount != 2 {
		t.Errorf("expected 2 triggers, got %d", r.TriggerCount)
	}
	if r.BlockCount != 2 {
		t.Errorf("expected 2 blocks, got %d", r.BlockCount)
	}
}

func TestGuardrailAnalyze_TraceMatchByCategory(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("pii-guard", "pii", "output", "redact", 0.8, true),
	}
	tr := makeTrace("t1", "agent",
		guardrailEventFull("e1", "other-id", "pii", "warn", true, 0.75),
	)
	ga := AnalyzeGuardrails(grs, []*Trace{tr}, nil)
	r := ga.TraceResults[0]
	if r.TriggerCount != 1 {
		t.Errorf("expected 1 trigger by category match, got %d", r.TriggerCount)
	}
	if r.WarnCount != 1 {
		t.Errorf("expected 1 warn, got %d", r.WarnCount)
	}
}

func TestGuardrailAnalyze_ScoreTracking(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	tr := makeTrace("t1", "agent",
		guardrailEventFull("e1", "gr-1", "injection", "block", true, 0.80),
		guardrailEventFull("e2", "gr-1", "injection", "block", true, 0.90),
		guardrailEventFull("e3", "gr-1", "injection", "block", true, 1.00),
	)
	ga := AnalyzeGuardrails(grs, []*Trace{tr}, nil)
	r := ga.TraceResults[0]
	if r.MaxScore != 1.0 {
		t.Errorf("expected max score 1.0, got %.2f", r.MaxScore)
	}
	// avg = (0.80 + 0.90 + 1.00) / 3 = 0.90
	if r.AvgScore < 0.89 || r.AvgScore > 0.91 {
		t.Errorf("expected avg score ~0.90, got %.4f", r.AvgScore)
	}
}

func TestGuardrailAnalyze_FalsePositives(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "warn", 0.9, true),
	}
	// Benign trace (no blocking guardrail triggers) but the warn guardrail fires.
	benign := makeTrace("t1", "agent",
		guardrailEventFull("e1", "gr-1", "injection", "warn", true, 0.75),
	)
	ga := AnalyzeGuardrails(grs, []*Trace{benign}, nil)
	r := ga.TraceResults[0]
	if r.FalsePositives != 1 {
		t.Errorf("expected 1 false positive, got %d", r.FalsePositives)
	}
}

func TestGuardrailAnalyze_NotTriggeredIgnored(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	tr := makeTrace("t1", "agent",
		guardrailEventFull("e1", "gr-1", "injection", "block", false, 0.3),
	)
	ga := AnalyzeGuardrails(grs, []*Trace{tr}, nil)
	r := ga.TraceResults[0]
	if r.TriggerCount != 0 {
		t.Errorf("expected 0 triggers for non-triggered event, got %d", r.TriggerCount)
	}
}

func TestGuardrailAnalyze_MultipleTraces(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	t1 := makeTrace("t1", "agent1",
		guardrailEventFull("e1", "gr-1", "injection", "block", true, 0.92),
	)
	t2 := makeTrace("t2", "agent2",
		guardrailEventFull("e2", "gr-1", "injection", "block", true, 0.88),
	)
	ga := AnalyzeGuardrails(grs, []*Trace{t1, t2}, nil)
	r := ga.TraceResults[0]
	if r.TriggerCount != 2 {
		t.Errorf("expected 2 triggers across traces, got %d", r.TriggerCount)
	}
}

// --- Policy alignment tests ---

func TestGuardrailAlignment_MatchingDenyRule(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	pol := traceTestPolicy("strict",
		denyRule("deny-injection", "Block injection attacks", 100, []string{"inject*"}),
	)
	ga := AnalyzeGuardrails(grs, nil, pol)
	if len(ga.PolicyAlignment) != 1 {
		t.Fatalf("expected 1 alignment result, got %d", len(ga.PolicyAlignment))
	}
	ar := ga.PolicyAlignment[0]
	if !ar.HasMatchingRule {
		t.Error("expected matching rule for injection guardrail")
	}
	if !ar.Aligned {
		t.Error("expected aligned (both block/deny)")
	}
	if ar.RuleID != "deny-injection" {
		t.Errorf("expected rule ID deny-injection, got %q", ar.RuleID)
	}
}

func TestGuardrailAlignment_ConflictBlockVsAllow(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	pol := traceTestPolicy("permissive",
		allowRule("allow-injection", "Allow injection tools", 10, []string{"inject*"}),
	)
	ga := AnalyzeGuardrails(grs, nil, pol)
	ar := ga.PolicyAlignment[0]
	if ar.Aligned {
		t.Error("expected conflict (guardrail blocks, policy allows)")
	}
	if ar.Conflict == "" {
		t.Error("expected non-empty conflict description")
	}
	if !strings.Contains(ar.Conflict, "blocks") || !strings.Contains(ar.Conflict, "allows") {
		t.Errorf("conflict description should mention blocks/allows: %q", ar.Conflict)
	}
}

func TestGuardrailAlignment_ConflictWarnVsDeny(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "warn", 0.9, true),
	}
	pol := traceTestPolicy("strict",
		denyRule("deny-injection", "Block injection", 100, []string{"injection_tool"}),
	)
	ga := AnalyzeGuardrails(grs, nil, pol)
	ar := ga.PolicyAlignment[0]
	if ar.Aligned {
		t.Error("expected conflict (guardrail warns, policy denies)")
	}
	if !strings.Contains(ar.Conflict, "warns") || !strings.Contains(ar.Conflict, "denies") {
		t.Errorf("expected conflict about warn vs deny, got %q", ar.Conflict)
	}
}

func TestGuardrailAlignment_NoMatchingRule(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	pol := traceTestPolicy("unrelated",
		denyRule("deny-http", "Block HTTP", 100, []string{"http_request"}),
	)
	ga := AnalyzeGuardrails(grs, nil, pol)
	ar := ga.PolicyAlignment[0]
	if ar.HasMatchingRule {
		t.Error("expected no matching rule for injection guardrail against HTTP policy")
	}
	if ar.Aligned {
		t.Error("expected not aligned when no matching rule")
	}
}

func TestGuardrailAlignment_NilPolicy(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	if len(ga.PolicyAlignment) != 0 {
		t.Errorf("expected 0 alignment results with nil policy, got %d", len(ga.PolicyAlignment))
	}
}

// --- Gap analysis tests ---

func TestGuardrailGaps_AllMandatoryCovered(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
		grConfig("gr-2", "pii", "both", "redact", 0.8, true),
		grConfig("gr-3", "toxicity", "output", "block", 0.85, true),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	if len(ga.GapAnalysis) != 0 {
		t.Errorf("expected 0 gaps when all mandatory categories covered, got %d", len(ga.GapAnalysis))
	}
}

func TestGuardrailGaps_MissingInjection(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "pii", "both", "redact", 0.8, true),
		grConfig("gr-2", "toxicity", "output", "block", 0.85, true),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	if len(ga.GapAnalysis) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(ga.GapAnalysis))
	}
	if ga.GapAnalysis[0].Category != "injection" {
		t.Errorf("expected injection gap, got %q", ga.GapAnalysis[0].Category)
	}
	if ga.GapAnalysis[0].Risk != "critical" {
		t.Errorf("expected critical risk for injection gap, got %q", ga.GapAnalysis[0].Risk)
	}
}

func TestGuardrailGaps_AllMissing(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "content", "output", "block", 0.9, false),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	if len(ga.GapAnalysis) != 3 {
		t.Errorf("expected 3 gaps (injection, pii, toxicity), got %d", len(ga.GapAnalysis))
	}
}

func TestGuardrailGaps_EmptyGuardrails(t *testing.T) {
	ga := AnalyzeGuardrails(nil, nil, nil)
	if len(ga.GapAnalysis) != 3 {
		t.Errorf("expected 3 gaps for empty guardrails, got %d", len(ga.GapAnalysis))
	}
}

// --- Stats tests ---

func TestGuardrailStats_Counts(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
		grConfig("gr-2", "toxicity", "output", "block", 0.85, true),
		grConfig("gr-3", "pii", "both", "redact", 0.8, true),
		grConfig("gr-4", "content", "output", "block", 0.9, false),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	s := ga.Stats

	if s.TotalGuardrails != 4 {
		t.Errorf("expected 4 total, got %d", s.TotalGuardrails)
	}
	// input: gr-1 + gr-3(both) = 2
	if s.InputGuardrails != 2 {
		t.Errorf("expected 2 input guardrails, got %d", s.InputGuardrails)
	}
	// output: gr-2 + gr-3(both) + gr-4 = 3
	if s.OutputGuardrails != 3 {
		t.Errorf("expected 3 output guardrails, got %d", s.OutputGuardrails)
	}
	if s.RequiredCount != 3 {
		t.Errorf("expected 3 required, got %d", s.RequiredCount)
	}
}

func TestGuardrailStats_CoverageScore(t *testing.T) {
	// All mandatory covered.
	grs := DefaultGuardrails()
	ga := AnalyzeGuardrails(grs, nil, nil)
	if ga.Stats.CoverageScore != 1.0 {
		t.Errorf("expected coverage 1.0 for default guardrails, got %.2f", ga.Stats.CoverageScore)
	}
}

func TestGuardrailStats_PartialCoverage(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	// 1 of 3 mandatory categories.
	expected := 1.0 / 3.0
	if ga.Stats.CoverageScore < expected-0.01 || ga.Stats.CoverageScore > expected+0.01 {
		t.Errorf("expected coverage ~%.2f, got %.2f", expected, ga.Stats.CoverageScore)
	}
}

func TestGuardrailStats_AlignmentScore(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
		grConfig("gr-2", "pii", "output", "block", 0.8, true),
	}
	pol := traceTestPolicy("mixed",
		denyRule("deny-injection", "Block injection", 100, []string{"injection_tool"}),
		// No PII rule.
	)
	ga := AnalyzeGuardrails(grs, nil, pol)
	// 1 of 2 aligned.
	if ga.Stats.AlignmentScore < 0.49 || ga.Stats.AlignmentScore > 0.51 {
		t.Errorf("expected alignment ~0.5, got %.2f", ga.Stats.AlignmentScore)
	}
}

// --- Recommendations tests ---

func TestGuardrailRecommendations_GapFilling(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "content", "output", "block", 0.9, false),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	found := false
	for _, rec := range ga.Recommendations {
		if strings.Contains(rec, "injection") && strings.Contains(rec, "guardrail") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected recommendation to add injection guardrail")
	}
}

func TestGuardrailRecommendations_ConflictResolution(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	pol := traceTestPolicy("permissive",
		allowRule("allow-injection", "Allow injection tools", 10, []string{"inject*"}),
	)
	ga := AnalyzeGuardrails(grs, nil, pol)
	found := false
	for _, rec := range ga.Recommendations {
		if strings.Contains(rec, "conflict") || strings.Contains(rec, "Resolve") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected recommendation to resolve conflict")
	}
}

func TestGuardrailRecommendations_NoInputGuardrails(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "output", "block", 0.9, true),
		grConfig("gr-2", "pii", "output", "redact", 0.8, true),
		grConfig("gr-3", "toxicity", "output", "block", 0.85, true),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	found := false
	for _, rec := range ga.Recommendations {
		if strings.Contains(rec, "input") && strings.Contains(rec, "guardrail") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected recommendation to add input guardrails")
	}
}

// --- FormatGuardrailAnalysis tests ---

func TestGuardrailFormat_Nil(t *testing.T) {
	out := FormatGuardrailAnalysis(nil)
	if !strings.Contains(out, "No guardrail analysis") {
		t.Error("expected 'No guardrail analysis' for nil")
	}
}

func TestGuardrailFormat_ContainsSections(t *testing.T) {
	grs := DefaultGuardrails()
	pol := traceTestPolicy("test-policy",
		denyRule("deny-injection", "Block injection", 100, []string{"injection*"}),
	)
	tr := makeTrace("t1", "agent",
		guardrailEventFull("e1", "prompt-injection-detector", "injection", "block", true, 0.95),
	)
	ga := AnalyzeGuardrails(grs, []*Trace{tr}, pol)
	out := FormatGuardrailAnalysis(ga)

	checks := []string{
		"Guardrail Analysis",
		"Total guardrails",
		"Input guardrails",
		"Output guardrails",
		"Required",
		"Coverage",
		"Alignment",
		"Guardrails:",
		"Trace Results:",
		"Policy Alignment:",
		"prompt-injection-det",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestGuardrailFormat_BoxDrawing(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	out := FormatGuardrailAnalysis(ga)
	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Error("output missing box-drawing characters")
	}
	if !strings.Contains(out, "├") {
		t.Error("output missing section separator")
	}
}

func TestGuardrailFormat_ShowsGaps(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "content", "output", "block", 0.9, false),
	}
	ga := AnalyzeGuardrails(grs, nil, nil)
	out := FormatGuardrailAnalysis(ga)
	if !strings.Contains(out, "Coverage Gaps") {
		t.Error("output missing Coverage Gaps section")
	}
	if !strings.Contains(out, "injection") {
		t.Error("output should list injection as a gap")
	}
}

func TestGuardrailFormat_ShowsRecommendations(t *testing.T) {
	ga := AnalyzeGuardrails(nil, nil, nil)
	out := FormatGuardrailAnalysis(ga)
	if !strings.Contains(out, "Coverage Gaps") {
		t.Error("output should show gaps for empty guardrails")
	}
}

// --- Integration / edge case tests ---

func TestGuardrailAnalyze_NilTrace(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	ga := AnalyzeGuardrails(grs, []*Trace{nil}, nil)
	if ga.TraceResults[0].TriggerCount != 0 {
		t.Errorf("expected 0 triggers for nil trace, got %d", ga.TraceResults[0].TriggerCount)
	}
}

func TestGuardrailAnalyze_NonGuardrailEventsIgnored(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	tr := makeTrace("t1", "agent",
		toolCallEvent("e1", "shell_exec", "execute", ""),
		promptEvent("e2", "user", "hello"),
		responseEvent("e3", "done"),
	)
	ga := AnalyzeGuardrails(grs, []*Trace{tr}, nil)
	if ga.TraceResults[0].TriggerCount != 0 {
		t.Errorf("expected 0 triggers for non-guardrail events, got %d", ga.TraceResults[0].TriggerCount)
	}
}

func TestGuardrailAnalyze_FullDefaultWithTraces(t *testing.T) {
	grs := DefaultGuardrails()
	tr := makeTrace("t1", "agent",
		guardrailEventFull("e1", "prompt-injection-detector", "injection", "block", true, 0.95),
		guardrailEventFull("e2", "pii-detector", "pii", "warn", true, 0.82),
		guardrailEventFull("e3", "output-toxicity-filter", "toxicity", "block", true, 0.91),
		guardrailEventFull("e4", "content-safety-filter", "content", "block", false, 0.40),
	)
	pol := traceTestPolicy("complete",
		denyRule("deny-injection", "Block injection", 100, []string{"injection*"}),
		denyRule("deny-pii", "Block PII leaks", 95, []string{"pii_extractor"}),
	)
	ga := AnalyzeGuardrails(grs, []*Trace{tr}, pol)

	if ga.Stats.TotalGuardrails != 8 {
		t.Errorf("expected 8 guardrails, got %d", ga.Stats.TotalGuardrails)
	}
	if ga.Stats.CoverageScore != 1.0 {
		t.Errorf("expected full coverage, got %.2f", ga.Stats.CoverageScore)
	}
	if len(ga.TraceResults) != 8 {
		t.Errorf("expected 8 trace results, got %d", len(ga.TraceResults))
	}

	// prompt-injection-detector should have 1 trigger.
	for _, r := range ga.TraceResults {
		if r.GuardrailID == "prompt-injection-detector" {
			if r.TriggerCount != 1 {
				t.Errorf("prompt-injection-detector: expected 1 trigger, got %d", r.TriggerCount)
			}
			if r.BlockCount != 1 {
				t.Errorf("prompt-injection-detector: expected 1 block, got %d", r.BlockCount)
			}
		}
	}
}

func TestGuardrailIsTraceBenign_Benign(t *testing.T) {
	tr := makeTrace("t1", "agent",
		guardrailEventFull("e1", "gr-1", "injection", "warn", true, 0.5),
		toolCallEvent("e2", "search", "query", ""),
	)
	if !isTraceBenign(tr) {
		t.Error("expected trace to be benign (no blocking triggers)")
	}
}

func TestGuardrailIsTraceBenign_NotBenign(t *testing.T) {
	tr := makeTrace("t1", "agent",
		guardrailEventFull("e1", "gr-1", "injection", "block", true, 0.95),
	)
	if isTraceBenign(tr) {
		t.Error("expected trace to not be benign (has blocking trigger)")
	}
}

func TestGuardrailDetectConflict_RedactVsAllow(t *testing.T) {
	gr := grConfig("gr-1", "pii", "output", "redact", 0.8, true)
	r := allowRule("allow-pii", "Allow PII tools", 10, []string{"pii*"})
	conflict := detectConflict(gr, &r)
	if conflict == "" {
		t.Error("expected conflict for redact vs allow")
	}
	if !strings.Contains(conflict, "redacts") || !strings.Contains(conflict, "allows") {
		t.Errorf("expected redacts/allows in conflict, got %q", conflict)
	}
}

func TestGuardrailDetectConflict_NoConflict(t *testing.T) {
	gr := grConfig("gr-1", "injection", "input", "block", 0.9, true)
	r := denyRule("deny-injection", "Block injection", 100, []string{"inject*"})
	conflict := detectConflict(gr, &r)
	if conflict != "" {
		t.Errorf("expected no conflict for block+deny, got %q", conflict)
	}
}

func TestGuardrailPadRight(t *testing.T) {
	tests := []struct {
		s     string
		width int
		want  string
	}{
		{"hi", 5, "hi   "},
		{"hello", 5, "hello"},
		{"toolong", 3, "toolong"},
		{"", 3, "   "},
	}
	for _, tt := range tests {
		got := padRight(tt.s, tt.width)
		if got != tt.want {
			t.Errorf("padRight(%q, %d) = %q, want %q", tt.s, tt.width, got, tt.want)
		}
	}
}

func TestGuardrailCategories_Collected(t *testing.T) {
	grs := []GuardrailConfig{
		grConfig("gr-1", "injection", "input", "block", 0.9, true),
	}
	tr := makeTrace("t1", "agent",
		guardrailEventFull("e1", "gr-1", "injection", "block", true, 0.9),
		guardrailEventFull("e2", "gr-1", "jailbreak", "block", true, 0.88),
	)
	ga := AnalyzeGuardrails(grs, []*Trace{tr}, nil)
	r := ga.TraceResults[0]
	// Should collect both injection (by ID) and jailbreak (by... actually jailbreak doesn't match injection category).
	// gr-1 has category "injection", event e2 has category "jailbreak" and ID "gr-1" — matched by ID.
	if r.TriggerCount != 2 {
		t.Errorf("expected 2 triggers (both match by ID), got %d", r.TriggerCount)
	}
}
