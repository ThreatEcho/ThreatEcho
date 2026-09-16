// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// --- test helpers ---

func intPtr(n int) *int { return &n }

func decision(tool, effect string) policy.ToolDecision {
	return policy.ToolDecision{Tool: tool, Effect: effect, RuleID: "r-" + tool, Reason: "test"}
}

// stage builds a StageSimResult from a stage ID and a list of tool effects,
// e.g. stage("s1", "allow", "deny") produces one allowed and one denied decision.
func stage(id string, effects ...string) policy.StageSimResult {
	sr := policy.StageSimResult{StageID: id, StageName: id, Tactic: "execution", Technique: "T1059"}
	for i, eff := range effects {
		tool := "tool" + string(rune('a'+i))
		sr.Decisions = append(sr.Decisions, decision(tool, eff))
		switch eff {
		case "allow":
			sr.Allowed++
		case "deny":
			sr.Denied++
		case "alert":
			sr.Alerted++
		}
	}
	return sr
}

func validScenario() *Scenario {
	return &Scenario{
		APIVersion: "v1",
		Kind:       "Scenario",
		Meta: ScenarioMeta{
			Name:     "test-scenario",
			Severity: "high",
		},
		Campaign: "prompt-leaking",
		Policy:   "ai-agent-policy",
	}
}

func anyContains(errs []string, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

// --- Constant tests ---

func TestOutcomeConstants(t *testing.T) {
	t.Parallel()
	if OutcomeBlocked != "blocked" {
		t.Error("OutcomeBlocked mismatch")
	}
	if OutcomeAllowed != "allowed" {
		t.Error("OutcomeAllowed mismatch")
	}
	if OutcomeAlerted != "alerted" {
		t.Error("OutcomeAlerted mismatch")
	}
	if OutcomeAny != "any" {
		t.Error("OutcomeAny mismatch")
	}
}

func TestPreconditionConstants(t *testing.T) {
	t.Parallel()
	if PreconditionPolicyExists != "policy_exists" {
		t.Error("PreconditionPolicyExists mismatch")
	}
	if PreconditionCampaignExists != "campaign_exists" {
		t.Error("PreconditionCampaignExists mismatch")
	}
}

// --- Load tests ---

func TestLoad_ValidFile(t *testing.T) {
	t.Parallel()
	s, err := Load("testdata/valid-scenario/scenario.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Meta.Name != "prompt-injection-blocked" {
		t.Errorf("meta.name = %q, want %q", s.Meta.Name, "prompt-injection-blocked")
	}
	if s.APIVersion != "v1" {
		t.Errorf("api_version = %q, want %q", s.APIVersion, "v1")
	}
	if s.Campaign != "prompt-leaking" {
		t.Errorf("campaign = %q, want %q", s.Campaign, "prompt-leaking")
	}
	if s.Policy != "ai-agent-policy" {
		t.Errorf("policy = %q, want %q", s.Policy, "ai-agent-policy")
	}
	if len(s.Expectations) != 3 {
		t.Fatalf("got %d expectations, want 3", len(s.Expectations))
	}
	if s.Expectations[0].Stage != "direct-extraction" || s.Expectations[0].Outcome != "blocked" {
		t.Errorf("unexpected first expectation: %+v", s.Expectations[0])
	}
	if len(s.Expectations[0].ToolsDenied) != 1 || s.Expectations[0].ToolsDenied[0] != "llm_chat" {
		t.Errorf("unexpected tools_denied: %+v", s.Expectations[0].ToolsDenied)
	}
	if len(s.Preconditions) != 2 {
		t.Fatalf("got %d preconditions, want 2", len(s.Preconditions))
	}
	if s.PassCriteria.MinBlockedRatio != 0.8 {
		t.Errorf("min_blocked_ratio = %v, want 0.8", s.PassCriteria.MinBlockedRatio)
	}
	if s.PassCriteria.MaxAllowed == nil || *s.PassCriteria.MaxAllowed != 0 {
		t.Errorf("max_allowed = %v, want pointer to 0", s.PassCriteria.MaxAllowed)
	}
	if !s.PassCriteria.RequireAllExpectations {
		t.Errorf("require_all_expectations = false, want true")
	}
}

func TestLoad_Directory(t *testing.T) {
	t.Parallel()
	s, err := Load("testdata/valid-scenario")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Meta.Name != "prompt-injection-blocked" {
		t.Errorf("meta.name = %q, want %q", s.Meta.Name, "prompt-injection-blocked")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := Load("testdata/nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "scenario path") {
		t.Errorf("error = %q, want it to mention \"scenario path\"", err.Error())
	}
}

func TestLoad_InvalidScenario(t *testing.T) {
	t.Parallel()
	_, err := Load("testdata/invalid-scenario.yaml")
	if err == nil {
		t.Fatal("expected error for invalid scenario, got nil")
	}
	if !strings.Contains(err.Error(), "invalid scenario") {
		t.Errorf("error = %q, want it to mention \"invalid scenario\"", err.Error())
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "scenario.yaml")
	if err := os.WriteFile(path, []byte("{{{{not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
	if !strings.Contains(err.Error(), "parsing scenario YAML") {
		t.Errorf("error = %q, want it to mention \"parsing scenario YAML\"", err.Error())
	}
}

// --- Validate tests ---

func TestValidate_Valid(t *testing.T) {
	t.Parallel()
	s := validScenario()
	if errs := Validate(s); len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidate_Nil(t *testing.T) {
	t.Parallel()
	errs := Validate(nil)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error for nil scenario, got %v", errs)
	}
	if errs[0] != "scenario is nil" {
		t.Errorf("error = %q, want %q", errs[0], "scenario is nil")
	}
}

func TestValidate_EmptyScenarioStruct(t *testing.T) {
	t.Parallel()
	errs := Validate(&Scenario{})
	if len(errs) == 0 {
		t.Error("expected validation errors for a completely empty scenario")
	}
}

func TestValidate_MissingTopLevelFields(t *testing.T) {
	t.Parallel()
	s := &Scenario{}
	errs := Validate(s)

	wantSubstrings := []string{
		"missing api_version",
		"missing kind",
		"meta.name is required",
		"campaign is required",
		"policy is required",
	}
	for _, want := range wantSubstrings {
		if !anyContains(errs, want) {
			t.Errorf("expected an error containing %q, got %v", want, errs)
		}
	}
}

func TestValidate_InvalidKind(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Kind = "Policy"
	errs := Validate(s)
	if !anyContains(errs, `kind must be "Scenario"`) {
		t.Errorf("expected kind error, got %v", errs)
	}
}

func TestValidate_EmptyKind(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Kind = ""
	errs := Validate(s)
	if !anyContains(errs, "missing kind") {
		t.Errorf("expected 'missing kind' error, got %v", errs)
	}
}

func TestValidate_InvalidSeverity(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Meta.Severity = "urgent"
	errs := Validate(s)
	if !anyContains(errs, "meta.severity") {
		t.Errorf("expected severity error, got %v", errs)
	}
}

func TestValidate_AllSeveritiesAccepted(t *testing.T) {
	t.Parallel()
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		s := validScenario()
		s.Meta.Severity = sev
		if errs := Validate(s); len(errs) != 0 {
			t.Errorf("severity %q should be valid, got %v", sev, errs)
		}
	}
}

func TestValidate_EmptySeverityAccepted(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Meta.Severity = ""
	if errs := Validate(s); len(errs) != 0 {
		t.Errorf("empty severity should be valid, got %v", errs)
	}
}

func TestValidate_AllOutcomesAccepted(t *testing.T) {
	t.Parallel()
	for _, outcome := range []string{"blocked", "allowed", "alerted", "any"} {
		s := validScenario()
		s.Expectations = []StageExpectation{{Stage: "s1", Outcome: outcome}}
		if errs := Validate(s); len(errs) != 0 {
			t.Errorf("outcome %q should be valid, got %v", outcome, errs)
		}
	}
}

func TestValidate_ExpectationMissingStage(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{{Outcome: "blocked"}}
	errs := Validate(s)
	if !anyContains(errs, "expectations[0]: stage is required") {
		t.Errorf("expected missing stage error, got %v", errs)
	}
}

func TestValidate_ExpectationMissingOutcome(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{{Stage: "s1"}}
	errs := Validate(s)
	if !anyContains(errs, "expectations[0]: outcome is required") {
		t.Errorf("expected missing outcome error, got %v", errs)
	}
}

func TestValidate_ExpectationInvalidOutcome(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{{Stage: "s1", Outcome: "maybe"}}
	errs := Validate(s)
	if !anyContains(errs, `outcome "maybe" is not valid`) {
		t.Errorf("expected invalid outcome error, got %v", errs)
	}
}

func TestValidate_ExpectationDuplicateStage(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{
		{Stage: "s1", Outcome: "blocked"},
		{Stage: "s1", Outcome: "allowed"},
	}
	errs := Validate(s)
	if !anyContains(errs, "duplicate expectation for stage") {
		t.Errorf("expected duplicate stage error, got %v", errs)
	}
}

func TestValidate_MultipleDistinctExpectationsOK(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{
		{Stage: "s1", Outcome: "blocked"},
		{Stage: "s2", Outcome: "allowed"},
		{Stage: "s3", Outcome: "alerted"},
	}
	if errs := Validate(s); len(errs) != 0 {
		t.Errorf("expected no errors for distinct stages, got %v", errs)
	}
}

func TestValidate_PreconditionMissingType(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Preconditions = []Precondition{{Value: "x"}}
	errs := Validate(s)
	if !anyContains(errs, "preconditions[0]: type is required") {
		t.Errorf("expected missing precondition type error, got %v", errs)
	}
}

func TestValidate_PreconditionInvalidType(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Preconditions = []Precondition{{Type: "file_exists", Value: "x"}}
	errs := Validate(s)
	if !anyContains(errs, `type "file_exists" is not valid`) {
		t.Errorf("expected invalid precondition type error, got %v", errs)
	}
}

func TestValidate_PreconditionMissingValue(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Preconditions = []Precondition{{Type: PreconditionPolicyExists}}
	errs := Validate(s)
	if !anyContains(errs, "preconditions[0]: value is required") {
		t.Errorf("expected missing precondition value error, got %v", errs)
	}
}

func TestValidate_ValidPreconditionTypes(t *testing.T) {
	t.Parallel()
	for _, pt := range []string{PreconditionPolicyExists, PreconditionCampaignExists} {
		s := validScenario()
		s.Preconditions = []Precondition{{Type: pt, Value: "some-value"}}
		if errs := Validate(s); len(errs) != 0 {
			t.Errorf("precondition type %q should be valid, got %v", pt, errs)
		}
	}
}

func TestValidate_PassCriteriaMinBlockedRatioOutOfRange(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.PassCriteria.MinBlockedRatio = 1.5
	errs := Validate(s)
	if !anyContains(errs, "min_blocked_ratio") {
		t.Errorf("expected min_blocked_ratio error, got %v", errs)
	}

	s2 := validScenario()
	s2.PassCriteria.MinBlockedRatio = -0.1
	errs2 := Validate(s2)
	if !anyContains(errs2, "min_blocked_ratio") {
		t.Errorf("expected min_blocked_ratio error for negative value, got %v", errs2)
	}
}

func TestValidate_PassCriteriaBoundaryRatios(t *testing.T) {
	t.Parallel()
	// 0.0 and 1.0 are valid boundaries
	for _, ratio := range []float64{0.0, 0.5, 1.0} {
		s := validScenario()
		s.PassCriteria.MinBlockedRatio = ratio
		if errs := Validate(s); len(errs) != 0 {
			t.Errorf("min_blocked_ratio %.1f should be valid, got %v", ratio, errs)
		}
	}
}

func TestValidate_PassCriteriaMaxAllowedNegative(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.PassCriteria.MaxAllowed = intPtr(-1)
	errs := Validate(s)
	if !anyContains(errs, "max_allowed") {
		t.Errorf("expected max_allowed error, got %v", errs)
	}
}

func TestValidate_PassCriteriaMaxAllowedZeroIsValid(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.PassCriteria.MaxAllowed = intPtr(0)
	if errs := Validate(s); len(errs) != 0 {
		t.Errorf("max_allowed=0 should be valid, got %v", errs)
	}
}

func TestValidate_PassCriteriaMaxAllowedNilIsValid(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.PassCriteria.MaxAllowed = nil
	if errs := Validate(s); len(errs) != 0 {
		t.Errorf("max_allowed=nil should be valid, got %v", errs)
	}
}

// --- LoadDir tests ---

func TestLoadDir(t *testing.T) {
	t.Parallel()
	summaries, err := LoadDir("testdata/scenario-list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("got %d summaries, want 2", len(summaries))
	}
	// LoadDir sorts by name.
	if summaries[0].Name != "scenario-one" || summaries[1].Name != "scenario-two" {
		t.Errorf("unexpected summary order/names: %+v", summaries)
	}
	if summaries[0].Campaign != "prompt-leaking" {
		t.Errorf("summary campaign = %q, want %q", summaries[0].Campaign, "prompt-leaking")
	}
	if summaries[0].Severity != "high" {
		t.Errorf("summary severity = %q, want %q", summaries[0].Severity, "high")
	}
	if summaries[1].Campaign != "agent-jailbreak" {
		t.Errorf("summary[1].campaign = %q, want %q", summaries[1].Campaign, "agent-jailbreak")
	}
}

func TestLoadDir_MissingDir(t *testing.T) {
	t.Parallel()
	_, err := LoadDir("testdata/does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing directory, got nil")
	}
}

func TestLoadDir_EmptyDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	summaries, err := LoadDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries for empty dir, got %d", len(summaries))
	}
}

func TestLoadDir_NoSubdirectoriesWithScenario(t *testing.T) {
	t.Parallel()
	// valid-scenario is a scenario dir itself, not a container of scenario dirs,
	// so no subdirectories with scenario.yaml should be found.
	summaries, err := LoadDir("testdata/valid-scenario")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries, got %d: %+v", len(summaries), summaries)
	}
}

func TestLoadDir_SkipsInvalidScenarios(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	// Create one valid subdirectory.
	validDir := filepath.Join(tmp, "good")
	if err := os.MkdirAll(validDir, 0o755); err != nil {
		t.Fatal(err)
	}
	validYAML := `api_version: v1
kind: Scenario
meta:
  name: good-scenario
campaign: c1
policy: p1
`
	if err := os.WriteFile(filepath.Join(validDir, "scenario.yaml"), []byte(validYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create one invalid subdirectory (missing required fields).
	badDir := filepath.Join(tmp, "bad")
	if err := os.MkdirAll(badDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDir, "scenario.yaml"), []byte("api_version: v1\nkind: Scenario\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	summaries, err := LoadDir(tmp)
	if err != nil {
		t.Fatalf("LoadDir returned error: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 valid summary (bad skipped), got %d", len(summaries))
	}
	if summaries[0].Name != "good-scenario" {
		t.Errorf("expected 'good-scenario', got %q", summaries[0].Name)
	}
}

func TestLoadDir_SkipsNonDirectoryEntries(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	// A regular file at the top level should be ignored.
	if err := os.WriteFile(filepath.Join(tmp, "not-a-dir.yaml"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	summaries, err := LoadDir(tmp)
	if err != nil {
		t.Fatalf("LoadDir returned error: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries (no subdirectories), got %d", len(summaries))
	}
}

func TestLoadDir_SortedByName(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	// Create three scenarios in reverse-alpha directory order.
	for _, name := range []string{"zeta", "alpha", "mu"} {
		dir := filepath.Join(tmp, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		yaml := "api_version: v1\nkind: Scenario\nmeta:\n  name: " + name + "\ncampaign: c\npolicy: p\n"
		if err := os.WriteFile(filepath.Join(dir, "scenario.yaml"), []byte(yaml), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	summaries, err := LoadDir(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summaries) != 3 {
		t.Fatalf("got %d summaries, want 3", len(summaries))
	}
	if summaries[0].Name != "alpha" || summaries[1].Name != "mu" || summaries[2].Name != "zeta" {
		t.Errorf("expected sorted order [alpha, mu, zeta], got [%s, %s, %s]",
			summaries[0].Name, summaries[1].Name, summaries[2].Name)
	}
}

// --- Evaluate tests ---

func TestEvaluate_NilScenario(t *testing.T) {
	t.Parallel()
	r := Evaluate(nil, &policy.SimulationReport{})
	if r.Passed {
		t.Error("expected Passed = false for nil scenario")
	}
	if len(r.Reasons) == 0 || r.Reasons[0] != "no scenario provided" {
		t.Errorf("expected 'no scenario provided' reason, got %v", r.Reasons)
	}
}

func TestEvaluate_NilSimReport(t *testing.T) {
	t.Parallel()
	s := validScenario()
	r := Evaluate(s, nil)
	if r.Passed {
		t.Error("expected Passed = false for nil simulation report")
	}
	if r.Scenario != "test-scenario" {
		t.Errorf("scenario name = %q, want %q", r.Scenario, "test-scenario")
	}
	if len(r.Reasons) == 0 || r.Reasons[0] != "no simulation report provided" {
		t.Errorf("expected 'no simulation report provided' reason, got %v", r.Reasons)
	}
}

func TestEvaluate_EmptyScenario_NoStages(t *testing.T) {
	t.Parallel()
	s := validScenario()
	report := &policy.SimulationReport{Policy: "ai-agent-policy", Campaign: "prompt-leaking"}
	r := Evaluate(s, report)
	if !r.Passed {
		t.Errorf("expected Passed = true for empty simulation report with no criteria, got reasons: %v", r.Reasons)
	}
	if r.TotalStages != 0 {
		t.Errorf("expected 0 total stages, got %d", r.TotalStages)
	}
	if r.BlockedRatio != 0 {
		t.Errorf("expected blocked ratio 0 for no stages, got %f", r.BlockedRatio)
	}
}

func TestEvaluate_AllStagesBlocked_Pass(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.PassCriteria = PassCriteria{MinBlockedRatio: 0.8, MaxAllowed: intPtr(0)}
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{
			stage("s1", "deny"),
			stage("s2", "deny"),
			stage("s3", "deny"),
		},
	}
	r := Evaluate(s, report)
	if !r.Passed {
		t.Fatalf("expected Passed = true, got reasons: %v", r.Reasons)
	}
	if r.BlockedCount != 3 || r.AllowedCount != 0 {
		t.Errorf("blocked=%d allowed=%d, want blocked=3 allowed=0", r.BlockedCount, r.AllowedCount)
	}
	if r.BlockedRatio != 1.0 {
		t.Errorf("blocked ratio = %v, want 1.0", r.BlockedRatio)
	}
	for _, sr := range r.Stages {
		if sr.ActualOutcome != OutcomeBlocked {
			t.Errorf("stage %s actual outcome = %q, want blocked", sr.StageID, sr.ActualOutcome)
		}
	}
}

func TestEvaluate_SomeAllowed_ConditionalPassFail(t *testing.T) {
	t.Parallel()
	s := validScenario()
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{
			stage("s1", "deny"),
			stage("s2", "allow"),
		},
	}

	// No pass criteria set -> passes trivially.
	r := Evaluate(s, report)
	if !r.Passed {
		t.Errorf("expected Passed = true with no pass criteria, got reasons: %v", r.Reasons)
	}

	// With max_allowed: 0, should now fail.
	s2 := validScenario()
	s2.PassCriteria = PassCriteria{MaxAllowed: intPtr(0)}
	r2 := Evaluate(s2, report)
	if r2.Passed {
		t.Error("expected Passed = false when an allowed stage exceeds max_allowed")
	}
}

func TestEvaluate_ExplicitExpectationsMatch(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{
		{Stage: "s1", Outcome: "blocked"},
		{Stage: "s2", Outcome: "allowed"},
	}
	s.PassCriteria = PassCriteria{RequireAllExpectations: true}

	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{
			stage("s1", "deny"),
			stage("s2", "allow"),
		},
	}
	r := Evaluate(s, report)
	if !r.Passed {
		t.Fatalf("expected Passed = true, got reasons: %v", r.Reasons)
	}
	if r.ExpectationsMatched != 2 || r.ExpectationsTotal != 2 {
		t.Errorf("expectations matched=%d total=%d, want 2/2", r.ExpectationsMatched, r.ExpectationsTotal)
	}
	for _, sr := range r.Stages {
		if !sr.Matched {
			t.Errorf("stage %s expected Matched = true, got false (%s)", sr.StageID, sr.Details)
		}
		if sr.Details != "expectation matched" {
			t.Errorf("stage %s details = %q, want %q", sr.StageID, sr.Details, "expectation matched")
		}
	}
}

func TestEvaluate_ExplicitExpectationsNotMatch(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{
		{Stage: "s1", Outcome: "blocked"},
	}
	s.PassCriteria = PassCriteria{RequireAllExpectations: true}

	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{
			stage("s1", "allow"), // actual outcome is allowed, not blocked
		},
	}
	r := Evaluate(s, report)
	if r.Passed {
		t.Fatal("expected Passed = false when explicit expectation doesn't match")
	}
	if r.ExpectationsMatched != 0 || r.ExpectationsTotal != 1 {
		t.Errorf("expectations matched=%d total=%d, want 0/1", r.ExpectationsMatched, r.ExpectationsTotal)
	}
	if r.Stages[0].Matched {
		t.Error("expected stage Matched = false")
	}
	if !strings.Contains(r.Stages[0].Details, "expected blocked, got allowed") {
		t.Errorf("unexpected details: %q", r.Stages[0].Details)
	}
}

func TestEvaluate_RequireAllExpectations_FalseDoesNotFailOnMismatch(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{{Stage: "s1", Outcome: "blocked"}}
	// RequireAllExpectations left false, and no other criteria set.
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "allow")},
	}
	r := Evaluate(s, report)
	if !r.Passed {
		t.Errorf("expected Passed = true when require_all_expectations is false and no other criteria fail, got reasons: %v", r.Reasons)
	}
	if r.ExpectationsMatched != 0 {
		t.Errorf("expected 0 expectations matched (still tracked), got %d", r.ExpectationsMatched)
	}
}

func TestEvaluate_OutcomeAny(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{{Stage: "s1", Outcome: OutcomeAny}}
	s.PassCriteria = PassCriteria{RequireAllExpectations: true}

	// OutcomeAny should match any actual outcome.
	for _, eff := range []string{"deny", "allow", "alert"} {
		report := &policy.SimulationReport{
			Stages: []policy.StageSimResult{stage("s1", eff)},
		}
		r := Evaluate(s, report)
		if !r.Passed {
			t.Errorf("OutcomeAny should match effect %q, got reasons: %v", eff, r.Reasons)
		}
		if r.ExpectationsMatched != 1 {
			t.Errorf("expected 1 expectation matched for effect %q, got %d", eff, r.ExpectationsMatched)
		}
	}
}

func TestEvaluate_ToolsDeniedExpectation(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{
		{Stage: "s1", Outcome: "blocked", ToolsDenied: []string{"toola"}},
	}
	s.PassCriteria = PassCriteria{RequireAllExpectations: true}

	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "deny")}, // decision tool is "toola"
	}
	r := Evaluate(s, report)
	if !r.Passed {
		t.Fatalf("expected Passed = true, got reasons: %v", r.Reasons)
	}

	// Now require a tool that was never denied.
	s2 := validScenario()
	s2.Expectations = []StageExpectation{
		{Stage: "s1", Outcome: "blocked", ToolsDenied: []string{"toolz"}},
	}
	s2.PassCriteria = PassCriteria{RequireAllExpectations: true}
	r2 := Evaluate(s2, report)
	if r2.Passed {
		t.Error("expected Passed = false when required denied tool is missing")
	}
}

func TestEvaluate_ToolsAllowedExpectation(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{
		{Stage: "s1", Outcome: "allowed", ToolsAllowed: []string{"toola"}},
	}
	s.PassCriteria = PassCriteria{RequireAllExpectations: true}

	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "allow")}, // decision tool is "toola"
	}
	r := Evaluate(s, report)
	if !r.Passed {
		t.Fatalf("expected Passed = true when required allowed tool is present, reasons: %v", r.Reasons)
	}

	// Require a tool that was not allowed.
	s2 := validScenario()
	s2.Expectations = []StageExpectation{
		{Stage: "s1", Outcome: "allowed", ToolsAllowed: []string{"toolz"}},
	}
	s2.PassCriteria = PassCriteria{RequireAllExpectations: true}
	r2 := Evaluate(s2, report)
	if r2.Passed {
		t.Error("expected Passed = false when required allowed tool is missing")
	}
}

func TestEvaluate_NoExpectations_TrivialMatch(t *testing.T) {
	t.Parallel()
	s := validScenario()
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "allow"), stage("s2", "deny")},
	}
	r := Evaluate(s, report)
	for _, sr := range r.Stages {
		if !sr.Matched {
			t.Errorf("stage %s: expected Matched = true when no explicit expectation exists", sr.StageID)
		}
		if sr.ExpectedOutcome != "" {
			t.Errorf("stage %s: expected empty ExpectedOutcome, got %q", sr.StageID, sr.ExpectedOutcome)
		}
		if sr.Details != "no explicit expectation" {
			t.Errorf("stage %s: details = %q, want %q", sr.StageID, sr.Details, "no explicit expectation")
		}
	}
	if r.ExpectationsTotal != 0 {
		t.Errorf("expected 0 expectations total, got %d", r.ExpectationsTotal)
	}
}

func TestEvaluate_MinBlockedRatio(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.PassCriteria = PassCriteria{MinBlockedRatio: 0.75}
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{
			stage("s1", "deny"),
			stage("s2", "deny"),
			stage("s3", "deny"),
			stage("s4", "allow"),
		},
	}
	r := Evaluate(s, report)
	if !r.Passed {
		t.Fatalf("expected Passed = true at exactly the threshold, got reasons: %v", r.Reasons)
	}

	s2 := validScenario()
	s2.PassCriteria = PassCriteria{MinBlockedRatio: 0.9}
	r2 := Evaluate(s2, report)
	if r2.Passed {
		t.Error("expected Passed = false when blocked ratio is below threshold")
	}
	if !anyContains(r2.Reasons, "below min_blocked_ratio") {
		t.Errorf("expected a min_blocked_ratio reason, got %v", r2.Reasons)
	}
}

func TestEvaluate_MaxAllowed(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.PassCriteria = PassCriteria{MaxAllowed: intPtr(1)}
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{
			stage("s1", "allow"),
			stage("s2", "deny"),
		},
	}
	r := Evaluate(s, report)
	if !r.Passed {
		t.Fatalf("expected Passed = true (1 allowed <= max_allowed 1), got reasons: %v", r.Reasons)
	}

	report2 := &policy.SimulationReport{
		Stages: []policy.StageSimResult{
			stage("s1", "allow"),
			stage("s2", "allow"),
		},
	}
	r2 := Evaluate(s, report2)
	if r2.Passed {
		t.Error("expected Passed = false (2 allowed > max_allowed 1)")
	}
	if !anyContains(r2.Reasons, "exceeds max_allowed") {
		t.Errorf("expected a max_allowed reason, got %v", r2.Reasons)
	}
}

func TestEvaluate_MaxAllowedZero(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.PassCriteria = PassCriteria{MaxAllowed: intPtr(0)}

	// All blocked should pass.
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "deny")},
	}
	r := Evaluate(s, report)
	if !r.Passed {
		t.Errorf("expected Passed = true when all blocked with max_allowed=0, reasons: %v", r.Reasons)
	}

	// One allowed should fail.
	report2 := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "allow")},
	}
	r2 := Evaluate(s, report2)
	if r2.Passed {
		t.Error("expected Passed = false when 1 allowed with max_allowed=0")
	}
}

func TestEvaluate_AlertedStagesCounted(t *testing.T) {
	t.Parallel()
	s := validScenario()
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "alert")},
	}
	r := Evaluate(s, report)
	if r.AlertedCount != 1 {
		t.Errorf("alerted count = %d, want 1", r.AlertedCount)
	}
	if r.Stages[0].ActualOutcome != OutcomeAlerted {
		t.Errorf("actual outcome = %q, want alerted", r.Stages[0].ActualOutcome)
	}
}

func TestEvaluate_DenyTakesPrecedenceOverAlert(t *testing.T) {
	t.Parallel()
	// A stage with both an alert and a deny decision should report as blocked.
	s := validScenario()
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "alert", "deny")},
	}
	r := Evaluate(s, report)
	if r.Stages[0].ActualOutcome != OutcomeBlocked {
		t.Errorf("actual outcome = %q, want blocked", r.Stages[0].ActualOutcome)
	}
	if r.BlockedCount != 1 {
		t.Errorf("blocked count = %d, want 1", r.BlockedCount)
	}
}

func TestEvaluate_BlockedRatioCalculation(t *testing.T) {
	t.Parallel()
	s := validScenario()
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{
			stage("s1", "deny"),
			stage("s2", "allow"),
			stage("s3", "deny"),
			stage("s4", "allow"),
		},
	}
	r := Evaluate(s, report)
	if r.BlockedRatio != 0.5 {
		t.Errorf("expected blocked ratio 0.5, got %f", r.BlockedRatio)
	}
	if r.BlockedCount != 2 {
		t.Errorf("expected blocked count 2, got %d", r.BlockedCount)
	}
	if r.AllowedCount != 2 {
		t.Errorf("expected allowed count 2, got %d", r.AllowedCount)
	}
}

func TestEvaluate_ExpectationForUnknownStageIsIgnored(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{{Stage: "does-not-exist", Outcome: "blocked"}}
	s.PassCriteria = PassCriteria{RequireAllExpectations: true}
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "deny")},
	}
	r := Evaluate(s, report)
	// The expectation never matches any real stage, so it's never counted.
	if r.ExpectationsTotal != 0 {
		t.Errorf("expected 0 expectations total (unknown stage not in report), got %d", r.ExpectationsTotal)
	}
	if !r.Passed {
		t.Errorf("expected Passed = true, got reasons: %v", r.Reasons)
	}
}

func TestEvaluate_MultipleFailureReasons(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.Expectations = []StageExpectation{{Stage: "s1", Outcome: "blocked"}}
	s.PassCriteria = PassCriteria{
		MinBlockedRatio:        1.0,
		MaxAllowed:             intPtr(0),
		RequireAllExpectations: true,
	}
	// Stage is allowed: violates all three criteria.
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "allow")},
	}
	r := Evaluate(s, report)
	if r.Passed {
		t.Error("expected Passed = false")
	}
	if len(r.Reasons) < 3 {
		t.Errorf("expected at least 3 failure reasons, got %d: %v", len(r.Reasons), r.Reasons)
	}
}

func TestEvaluate_PassReasonWhenAllCriteriaSatisfied(t *testing.T) {
	t.Parallel()
	s := validScenario()
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{stage("s1", "deny")},
	}
	r := Evaluate(s, report)
	if !r.Passed {
		t.Fatalf("expected Passed = true, reasons: %v", r.Reasons)
	}
	if len(r.Reasons) != 1 || r.Reasons[0] != "all configured pass criteria satisfied" {
		t.Errorf("expected success reason, got %v", r.Reasons)
	}
}

func TestEvaluate_ToolDecisionsCategorized(t *testing.T) {
	t.Parallel()
	s := validScenario()
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{
			{
				StageID: "s1",
				Denied:  1,
				Alerted: 1,
				Allowed: 1,
				Decisions: []policy.ToolDecision{
					{Tool: "llm_chat", Effect: "deny"},
					{Tool: "web_search", Effect: "alert"},
					{Tool: "file_read", Effect: "allow"},
				},
			},
		},
	}
	r := Evaluate(s, report)
	sr := r.Stages[0]
	if len(sr.ToolsDenied) != 1 || sr.ToolsDenied[0] != "llm_chat" {
		t.Errorf("tools_denied = %v, want [llm_chat]", sr.ToolsDenied)
	}
	if len(sr.ToolsAlerted) != 1 || sr.ToolsAlerted[0] != "web_search" {
		t.Errorf("tools_alerted = %v, want [web_search]", sr.ToolsAlerted)
	}
	if len(sr.ToolsAllowed) != 1 || sr.ToolsAllowed[0] != "file_read" {
		t.Errorf("tools_allowed = %v, want [file_read]", sr.ToolsAllowed)
	}
}

// --- stageOutcome / matchesExpectation / containsAll unit tests ---

func TestStageOutcome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		sr   policy.StageSimResult
		want string
	}{
		{"denied wins", policy.StageSimResult{Denied: 1, Alerted: 1, Allowed: 1}, OutcomeBlocked},
		{"alerted wins over allowed", policy.StageSimResult{Alerted: 1, Allowed: 1}, OutcomeAlerted},
		{"allowed only", policy.StageSimResult{Allowed: 1}, OutcomeAllowed},
		{"no decisions defaults allowed", policy.StageSimResult{}, OutcomeAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := stageOutcome(c.sr); got != c.want {
				t.Errorf("stageOutcome() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestContainsAll(t *testing.T) {
	t.Parallel()
	if !containsAll([]string{"a", "b"}, nil) {
		t.Error("empty want should always match")
	}
	if !containsAll([]string{"a", "b"}, []string{}) {
		t.Error("empty want slice should always match")
	}
	if !containsAll([]string{"a", "b"}, []string{"a"}) {
		t.Error("subset should match")
	}
	if !containsAll([]string{"a", "b"}, []string{"a", "b"}) {
		t.Error("exact match should return true")
	}
	if containsAll([]string{"a"}, []string{"a", "b"}) {
		t.Error("missing element should not match")
	}
	if containsAll(nil, []string{"a"}) {
		t.Error("nil have with non-empty want should return false")
	}
	if !containsAll(nil, nil) {
		t.Error("both nil should return true")
	}
}

func TestMatchesExpectation_OutcomeAny(t *testing.T) {
	t.Parallel()
	exp := StageExpectation{Outcome: OutcomeAny}
	sr := StageResult{ActualOutcome: OutcomeBlocked}
	if !matchesExpectation(exp, sr) {
		t.Error("outcome 'any' should match any actual outcome")
	}
}

func TestMatchesExpectation_OutcomeMismatch(t *testing.T) {
	t.Parallel()
	exp := StageExpectation{Outcome: OutcomeBlocked}
	sr := StageResult{ActualOutcome: OutcomeAllowed}
	if matchesExpectation(exp, sr) {
		t.Error("blocked should not match allowed")
	}
}

func TestMatchesExpectation_ToolsSubsetRequired(t *testing.T) {
	t.Parallel()
	exp := StageExpectation{
		Outcome:      OutcomeBlocked,
		ToolsDenied:  []string{"a", "b"},
		ToolsAllowed: []string{"c"},
	}
	sr := StageResult{
		ActualOutcome: OutcomeBlocked,
		ToolsDenied:   []string{"a", "b", "d"},
		ToolsAllowed:  []string{"c", "e"},
	}
	if !matchesExpectation(exp, sr) {
		t.Error("expected match when all required tools are present as superset")
	}
}

// --- describeExpectation tests ---

func TestDescribeExpectation_OutcomeOnly(t *testing.T) {
	t.Parallel()
	exp := StageExpectation{Outcome: "blocked"}
	got := describeExpectation(exp)
	if got != "blocked" {
		t.Errorf("expected 'blocked', got %q", got)
	}
}

func TestDescribeExpectation_WithToolsDenied(t *testing.T) {
	t.Parallel()
	exp := StageExpectation{Outcome: "blocked", ToolsDenied: []string{"a", "b"}}
	got := describeExpectation(exp)
	if !strings.Contains(got, "tools_denied=a,b") {
		t.Errorf("expected tools_denied in output, got %q", got)
	}
}

func TestDescribeExpectation_WithToolsAllowed(t *testing.T) {
	t.Parallel()
	exp := StageExpectation{Outcome: "allowed", ToolsAllowed: []string{"x"}}
	got := describeExpectation(exp)
	if !strings.Contains(got, "tools_allowed=x") {
		t.Errorf("expected tools_allowed in output, got %q", got)
	}
}

func TestDescribeExpectation_WithBothToolLists(t *testing.T) {
	t.Parallel()
	exp := StageExpectation{
		Outcome:      "blocked",
		ToolsDenied:  []string{"a"},
		ToolsAllowed: []string{"b"},
	}
	got := describeExpectation(exp)
	if !strings.Contains(got, "tools_denied=a") || !strings.Contains(got, "tools_allowed=b") {
		t.Errorf("expected both tool lists in output, got %q", got)
	}
}

// --- FormatResult / FormatSummaryTable tests ---

func TestFormatResult(t *testing.T) {
	t.Parallel()
	s := validScenario()
	s.PassCriteria = PassCriteria{MinBlockedRatio: 0.5}
	report := &policy.SimulationReport{
		Stages: []policy.StageSimResult{
			stage("s1", "deny"),
			stage("s2", "allow"),
		},
	}
	r := Evaluate(s, report)
	out := FormatResult(r)

	for _, want := range []string{"Scenario Result", "test-scenario", "prompt-leaking", "ai-agent-policy", "s1", "s2"} {
		if !strings.Contains(out, want) {
			t.Errorf("formatted output missing %q", want)
		}
	}
	if !strings.Contains(out, "PASS") && !strings.Contains(out, "FAIL") {
		t.Error("formatted output missing pass/fail status")
	}
}

func TestFormatResult_Nil(t *testing.T) {
	t.Parallel()
	out := FormatResult(nil)
	if out != "(no scenario result)\n" {
		t.Errorf("expected nil result message, got %q", out)
	}
}

func TestFormatResult_PassingShowsCheckIcon(t *testing.T) {
	t.Parallel()
	r := &ScenarioResult{
		Scenario: "test",
		Passed:   true,
		Stages: []StageResult{
			{StageID: "s1", ActualOutcome: OutcomeBlocked, Matched: true, Details: "ok"},
		},
		Reasons: []string{"all configured pass criteria satisfied"},
	}
	out := FormatResult(r)
	if !strings.Contains(out, "PASS") {
		t.Error("should contain PASS")
	}
	if !strings.Contains(out, "✓") { // check mark
		t.Error("matched stage should show check icon")
	}
}

func TestFormatResult_FailingShowsCrossIcon(t *testing.T) {
	t.Parallel()
	r := &ScenarioResult{
		Scenario: "test",
		Passed:   false,
		Stages: []StageResult{
			{StageID: "s1", ActualOutcome: OutcomeAllowed, ExpectedOutcome: OutcomeBlocked, Matched: false},
		},
		Reasons: []string{"failed"},
	}
	out := FormatResult(r)
	if !strings.Contains(out, "FAIL") {
		t.Error("should contain FAIL")
	}
	if !strings.Contains(out, "✗") { // cross mark
		t.Error("unmatched stage should show cross icon")
	}
}

func TestFormatResult_BoxDrawingStructure(t *testing.T) {
	t.Parallel()
	r := &ScenarioResult{
		Scenario: "box-test",
		Passed:   true,
		Reasons:  []string{"ok"},
	}
	out := FormatResult(r)
	if !strings.HasPrefix(out, "┌") { // top-left corner
		t.Error("output should start with top-left box corner")
	}
	if !strings.Contains(out, "└") { // bottom-left corner
		t.Error("output should contain bottom-left box corner")
	}
}

func TestFormatSummaryTable(t *testing.T) {
	t.Parallel()
	summaries := []ScenarioSummary{
		{Name: "scenario-one", Description: "first", Campaign: "c1", Policy: "p1", Severity: "high", Tags: []string{"a"}},
		{Name: "scenario-two", Description: "second", Campaign: "c2", Policy: "p2", Severity: "low", Tags: []string{"b"}},
	}
	out := FormatSummaryTable(summaries)
	for _, want := range []string{"scenario-one", "scenario-two", "c1", "p2", "Total: 2", "severity: high", "tags: a", "tags: b"} {
		if !strings.Contains(out, want) {
			t.Errorf("formatted table missing %q", want)
		}
	}
}

func TestFormatSummaryTable_EmptyNil(t *testing.T) {
	t.Parallel()
	out := FormatSummaryTable(nil)
	if !strings.Contains(out, "No scenarios found") {
		t.Errorf("expected empty-state message, got:\n%s", out)
	}
}

func TestFormatSummaryTable_EmptySlice(t *testing.T) {
	t.Parallel()
	out := FormatSummaryTable([]ScenarioSummary{})
	if !strings.Contains(out, "No scenarios found") {
		t.Errorf("expected empty-state message for empty slice, got:\n%s", out)
	}
}

func TestFormatSummaryTable_OmitsEmptySeverityAndTags(t *testing.T) {
	t.Parallel()
	summaries := []ScenarioSummary{
		{Name: "minimal", Campaign: "c", Policy: "p"},
	}
	out := FormatSummaryTable(summaries)
	if strings.Contains(out, "severity:") {
		t.Error("should not show severity line when empty")
	}
	if strings.Contains(out, "tags:") {
		t.Error("should not show tags line when empty")
	}
}
