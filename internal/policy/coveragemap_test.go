// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"sort"
	"strings"
	"testing"
)

// coverageTestPolicy builds a minimal valid policy from the given rules.
func coverageTestPolicy(name string, rules ...Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: name},
		Agent:      AgentScope{Name: "*"},
		Rules:      rules,
	}
}

// contains reports whether ss contains s.
func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// MapCoverage — nil / empty
// ---------------------------------------------------------------------------

func TestMapCoverage_NilPolicy(t *testing.T) {
	t.Parallel()
	r := MapCoverage(nil)
	if r == nil {
		t.Fatal("MapCoverage(nil) returned nil")
	}
	if r.PolicyName != "(nil)" {
		t.Errorf("PolicyName = %q, want %q", r.PolicyName, "(nil)")
	}
	if r.CoveredTechniques != 0 {
		t.Errorf("CoveredTechniques = %d, want 0", r.CoveredTechniques)
	}
	if r.CoveragePercent != 0 {
		t.Errorf("CoveragePercent = %.2f, want 0", r.CoveragePercent)
	}
	if len(r.Mappings) != 0 {
		t.Errorf("Mappings length = %d, want 0", len(r.Mappings))
	}
	if len(r.Gaps) != r.TotalTechniques {
		t.Errorf("Gaps length = %d, want %d", len(r.Gaps), r.TotalTechniques)
	}
	if r.RiskScore != 1.0 {
		t.Errorf("RiskScore = %.2f, want 1.0", r.RiskScore)
	}
}

func TestMapCoverage_EmptyRules(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("empty-policy")
	r := MapCoverage(p)
	if r.PolicyName != "empty-policy" {
		t.Errorf("PolicyName = %q, want empty-policy", r.PolicyName)
	}
	if r.TotalRules != 0 {
		t.Errorf("TotalRules = %d, want 0", r.TotalRules)
	}
	if r.CoveredTechniques != 0 {
		t.Errorf("CoveredTechniques = %d, want 0", r.CoveredTechniques)
	}
	if len(r.Gaps) != r.TotalTechniques {
		t.Errorf("Gaps length = %d, want %d", len(r.Gaps), r.TotalTechniques)
	}
}

func TestMapCoverage_TotalTechniquesIsCatalogSize(t *testing.T) {
	t.Parallel()
	r := MapCoverage(nil)
	want := len(sortedTechniqueIDs())
	if r.TotalTechniques != want {
		t.Errorf("TotalTechniques = %d, want %d", r.TotalTechniques, want)
	}
}

// ---------------------------------------------------------------------------
// MapCoverage — single rule
// ---------------------------------------------------------------------------

func TestMapCoverage_SingleDenyRuleShellExec(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("shell-policy",
		Rule{ID: "deny-shell", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)

	if len(r.Mappings) != 1 {
		t.Fatalf("Mappings length = %d, want 1", len(r.Mappings))
	}
	m := r.Mappings[0]
	if !containsStr(m.Techniques, "T1059") {
		t.Errorf("Techniques = %v, want to contain T1059", m.Techniques)
	}
	if r.CoveredTechniques == 0 {
		t.Error("expected at least one covered technique for a deny rule on shell_exec")
	}
}

func TestMapCoverage_SingleAllowRuleDoesNotCloseGap(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("allow-only",
		Rule{ID: "allow-shell", Effect: "allow", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)

	if len(r.Mappings) != 1 {
		t.Fatalf("Mappings length = %d, want 1", len(r.Mappings))
	}
	if r.CoveredTechniques != 0 {
		t.Errorf("CoveredTechniques = %d, want 0 (allow rules must not close gaps)", r.CoveredTechniques)
	}
	if len(r.Gaps) != r.TotalTechniques {
		t.Errorf("Gaps length = %d, want %d (nothing should be covered)", len(r.Gaps), r.TotalTechniques)
	}
}

func TestMapCoverage_AlertRuleCovers(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("alert-policy",
		Rule{ID: "alert-shell", Effect: "alert", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)

	if r.CoveredTechniques == 0 {
		t.Error("expected alert rule to cover at least one technique")
	}
}

func TestMapCoverage_RuleWithNoSignalsExcludedFromMappings(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("unmapped",
		Rule{ID: "no-signal", Effect: "deny", Match: RuleMatch{Tools: []string{"unknown_widget_xyz"}}},
	)
	r := MapCoverage(p)

	if len(r.Mappings) != 0 {
		t.Errorf("Mappings length = %d, want 0 for a rule with no inferable techniques", len(r.Mappings))
	}
	if r.CoveredTechniques != 0 {
		t.Errorf("CoveredTechniques = %d, want 0", r.CoveredTechniques)
	}
}

// ---------------------------------------------------------------------------
// MapCoverage — multi-rule policies
// ---------------------------------------------------------------------------

func TestMapCoverage_MultipleRules(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("multi",
		Rule{ID: "deny-shell", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "deny-http", Effect: "deny", Match: RuleMatch{Tools: []string{"http_request"}}},
		Rule{ID: "alert-db", Effect: "alert", Match: RuleMatch{Tools: []string{"db_query"}}},
	)
	r := MapCoverage(p)

	if r.TotalRules != 3 {
		t.Errorf("TotalRules = %d, want 3", r.TotalRules)
	}
	if len(r.Mappings) != 3 {
		t.Errorf("Mappings length = %d, want 3", len(r.Mappings))
	}
	if r.CoveredTechniques < 3 {
		t.Errorf("CoveredTechniques = %d, want at least 3", r.CoveredTechniques)
	}
}

func TestMapCoverage_TotalRulesCount(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("count-test",
		Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "allow", Match: RuleMatch{Tools: []string{"unknown_xyz"}}},
		Rule{ID: "r3", Effect: "deny", Match: RuleMatch{Tools: []string{"http_request"}}},
		Rule{ID: "r4", Effect: "alert", Match: RuleMatch{Tools: []string{"db_query"}}},
		Rule{ID: "r5", Effect: "deny", Match: RuleMatch{Tools: []string{"file_write"}}},
	)
	r := MapCoverage(p)
	if r.TotalRules != 5 {
		t.Errorf("TotalRules = %d, want 5", r.TotalRules)
	}
}

func TestMapCoverage_OverlappingRulesSameTechnique(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("overlap",
		Rule{ID: "deny-shell-a", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "deny-shell-b", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_run"}}},
	)
	r := MapCoverage(p)

	if len(r.Mappings) != 2 {
		t.Fatalf("Mappings length = %d, want 2", len(r.Mappings))
	}
	// Both rules cover T1059; it should only be counted once toward
	// CoveredTechniques.
	count := 0
	for _, id := range sortedTechniqueIDs() {
		if id == "T1059" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("sanity: T1059 appears %d times in catalog, want 1", count)
	}
}

func TestMapCoverage_MappingsSortedByName(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("sort-test",
		Rule{ID: "zzz-last", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "aaa-first", Effect: "deny", Match: RuleMatch{Tools: []string{"http_request"}}},
	)
	r := MapCoverage(p)

	if len(r.Mappings) != 2 {
		t.Fatalf("Mappings length = %d, want 2", len(r.Mappings))
	}
	if r.Mappings[0].RuleName != "aaa-first" || r.Mappings[1].RuleName != "zzz-last" {
		t.Errorf("Mappings not sorted by name: got [%s, %s]", r.Mappings[0].RuleName, r.Mappings[1].RuleName)
	}
}

func TestMapCoverage_PolicyNamePropagated(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("my-special-policy",
		Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)
	if r.PolicyName != "my-special-policy" {
		t.Errorf("PolicyName = %q, want my-special-policy", r.PolicyName)
	}
}

// ---------------------------------------------------------------------------
// MapCoverage — full coverage / risk boundaries
// ---------------------------------------------------------------------------

func allTechniqueCoveringRules() []Rule {
	ids := sortedTechniqueIDs()
	rules := make([]Rule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, Rule{
			ID:     "deny-" + id,
			Effect: "deny",
			Match:  RuleMatch{Tools: []string{"placeholder_tool"}},
			Conditions: []Condition{
				{Field: "technique", Operator: "eq", Value: id},
			},
		})
	}
	return rules
}

func TestMapCoverage_FullCoverageZeroGaps(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("full-coverage", allTechniqueCoveringRules()...)
	r := MapCoverage(p)

	if r.CoveredTechniques != r.TotalTechniques {
		t.Errorf("CoveredTechniques = %d, want %d", r.CoveredTechniques, r.TotalTechniques)
	}
	if r.UncoveredTechniques != 0 {
		t.Errorf("UncoveredTechniques = %d, want 0", r.UncoveredTechniques)
	}
	if len(r.Gaps) != 0 {
		t.Errorf("Gaps length = %d, want 0", len(r.Gaps))
	}
	if r.CoveragePercent != 100 {
		t.Errorf("CoveragePercent = %.2f, want 100", r.CoveragePercent)
	}
}

func TestMapCoverage_NoRulesAllGapsRiskOne(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("no-rules")
	r := MapCoverage(p)

	if r.RiskScore != 1.0 {
		t.Errorf("RiskScore = %.4f, want 1.0", r.RiskScore)
	}
}

func TestMapCoverage_GapsSortedBySeverity(t *testing.T) {
	t.Parallel()
	r := MapCoverage(nil)
	if len(r.Gaps) < 2 {
		t.Fatal("expected multiple gaps for nil policy")
	}
	for i := 1; i < len(r.Gaps); i++ {
		prev := severityRank[r.Gaps[i-1].Severity]
		cur := severityRank[r.Gaps[i].Severity]
		if cur < prev {
			t.Errorf("gaps not sorted by severity at index %d: %s (%s) before %s (%s)",
				i, r.Gaps[i-1].TechniqueID, r.Gaps[i-1].Severity, r.Gaps[i].TechniqueID, r.Gaps[i].Severity)
		}
	}
}

func TestMapCoverage_GapRecommendationsPresent(t *testing.T) {
	t.Parallel()
	r := MapCoverage(nil)
	for _, g := range r.Gaps {
		if len(g.Recommendations) == 0 {
			t.Errorf("gap %s has no recommendations", g.TechniqueID)
		}
		if g.TechniqueName == "" {
			t.Errorf("gap %s has no technique name", g.TechniqueID)
		}
		if g.Tactic == "" {
			t.Errorf("gap %s has no tactic", g.TechniqueID)
		}
	}
}

// ---------------------------------------------------------------------------
// inferTechniques — tool pattern inference
// ---------------------------------------------------------------------------

func TestInferTechniques_ShellPattern(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{Match: RuleMatch{Tools: []string{"shell_exec"}}})
	if !containsStr(techs, "T1059") {
		t.Errorf("techniques = %v, want to contain T1059", techs)
	}
	if !containsStr(techs, "TE002") {
		t.Errorf("techniques = %v, want to contain TE002", techs)
	}
}

func TestInferTechniques_HTTPPattern(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{Match: RuleMatch{Tools: []string{"http_request"}}})
	if !containsStr(techs, "T1071") {
		t.Errorf("techniques = %v, want to contain T1071", techs)
	}
}

func TestInferTechniques_DBPattern(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{Match: RuleMatch{Tools: []string{"db_query"}}})
	if !containsStr(techs, "T1003") {
		t.Errorf("techniques = %v, want to contain T1003", techs)
	}
}

func TestInferTechniques_FilePattern(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{Match: RuleMatch{Tools: []string{"file_write"}}})
	if !containsStr(techs, "TE003") {
		t.Errorf("techniques = %v, want to contain TE003", techs)
	}
}

func TestInferTechniques_WildcardTool(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{Match: RuleMatch{Tools: []string{"*"}}})
	if len(techs) != 2 {
		t.Fatalf("techniques = %v, want exactly 2 entries", techs)
	}
	if !containsStr(techs, "TE002") || !containsStr(techs, "TE008") {
		t.Errorf("techniques = %v, want [TE002 TE008]", techs)
	}
}

func TestInferTechniques_EmptyRule(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{})
	if len(techs) != 0 {
		t.Errorf("techniques = %v, want empty", techs)
	}
}

func TestInferTechniques_SortedOutput(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{Match: RuleMatch{Tools: []string{"shell_exec", "http_request"}}})
	if !sort.StringsAreSorted(techs) {
		t.Errorf("techniques = %v, want sorted", techs)
	}
}

func TestInferTechniques_Deduplication(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{
		Match: RuleMatch{Tools: []string{"shell_exec"}, Actions: []string{"execute"}},
	})
	seen := make(map[string]bool)
	for _, id := range techs {
		if seen[id] {
			t.Errorf("technique %s appeared more than once in %v", id, techs)
		}
		seen[id] = true
	}
}

// ---------------------------------------------------------------------------
// inferTechniques — action inference
// ---------------------------------------------------------------------------

func TestInferTechniques_ActionExecute(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{Match: RuleMatch{Actions: []string{"execute"}}})
	if !containsStr(techs, "T1059") || !containsStr(techs, "TE002") {
		t.Errorf("techniques = %v, want T1059 and TE002", techs)
	}
}

func TestInferTechniques_ActionSend(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{Match: RuleMatch{Actions: []string{"send"}}})
	if !containsStr(techs, "T1071") || !containsStr(techs, "TE003") {
		t.Errorf("techniques = %v, want T1071 and TE003", techs)
	}
}

func TestInferTechniques_ActionUnknownIgnored(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{Match: RuleMatch{Actions: []string{"teleport"}}})
	if len(techs) != 0 {
		t.Errorf("techniques = %v, want empty for unknown action", techs)
	}
}

// ---------------------------------------------------------------------------
// inferTechniques — target inference
// ---------------------------------------------------------------------------

func TestInferTechniques_TargetAttacker(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{Match: RuleMatch{Targets: []string{"https://attacker.evil.com/collect"}}})
	if !containsStr(techs, "T1071") || !containsStr(techs, "TE003") {
		t.Errorf("techniques = %v, want T1071 and TE003", techs)
	}
}

// ---------------------------------------------------------------------------
// inferTechniques — condition inference
// ---------------------------------------------------------------------------

func TestInferTechniques_ElevatedConditionTrue(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{
		Conditions: []Condition{{Field: "elevated", Operator: "eq", Value: "true"}},
	})
	for _, want := range []string{"T1548", "T1134", "TE004"} {
		if !containsStr(techs, want) {
			t.Errorf("techniques = %v, want to contain %s", techs, want)
		}
	}
}

func TestInferTechniques_ElevatedConditionFalseNoMatch(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{
		Conditions: []Condition{{Field: "elevated", Operator: "eq", Value: "false"}},
	})
	if len(techs) != 0 {
		t.Errorf("techniques = %v, want empty", techs)
	}
}

func TestInferTechniques_TechniqueConditionKnown(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{
		Conditions: []Condition{{Field: "technique", Operator: "eq", Value: "T1557"}},
	})
	if len(techs) != 1 || techs[0] != "T1557" {
		t.Errorf("techniques = %v, want [T1557]", techs)
	}
}

func TestInferTechniques_TechniqueConditionUnknownIgnored(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{
		Conditions: []Condition{{Field: "technique", Operator: "eq", Value: "T9999"}},
	})
	if len(techs) != 0 {
		t.Errorf("techniques = %v, want empty for unrecognized technique ID", techs)
	}
}

func TestInferTechniques_TacticConditionExfiltration(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{
		Conditions: []Condition{{Field: "tactic", Operator: "eq", Value: "exfiltration"}},
	})
	if len(techs) != 1 || techs[0] != "TE003" {
		t.Errorf("techniques = %v, want [TE003]", techs)
	}
}

func TestInferTechniques_TacticConditionUnknownTactic(t *testing.T) {
	t.Parallel()
	techs := inferTechniques(Rule{
		Conditions: []Condition{{Field: "tactic", Operator: "eq", Value: "not-a-real-tactic"}},
	})
	if len(techs) != 0 {
		t.Errorf("techniques = %v, want empty", techs)
	}
}

// ---------------------------------------------------------------------------
// CoverageMapping naming and confidence
// ---------------------------------------------------------------------------

func TestCoverageMapping_RuleNameFromID(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("p",
		Rule{ID: "deny-shell", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)
	if r.Mappings[0].RuleName != "deny-shell" {
		t.Errorf("RuleName = %q, want deny-shell", r.Mappings[0].RuleName)
	}
}

func TestCoverageMapping_RuleNameFromDescriptionWhenNoID(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("p",
		Rule{Description: "blocks shell", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)
	if r.Mappings[0].RuleName != "blocks shell" {
		t.Errorf("RuleName = %q, want %q", r.Mappings[0].RuleName, "blocks shell")
	}
}

func TestCoverageMapping_UnnamedRuleFallback(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("p",
		Rule{Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)
	if r.Mappings[0].RuleName != "(unnamed rule)" {
		t.Errorf("RuleName = %q, want %q", r.Mappings[0].RuleName, "(unnamed rule)")
	}
}

func TestCoverageMapping_RuleActionReflectsEffect(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("p",
		Rule{ID: "r1", Effect: "audit-not-a-real-effect", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)
	if r.Mappings[0].RuleAction != "audit-not-a-real-effect" {
		t.Errorf("RuleAction = %q, want passthrough of Effect", r.Mappings[0].RuleAction)
	}
}

func TestCoverageMapping_ConfidenceInRange(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("p",
		Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
		Rule{ID: "r2", Effect: "allow", Match: RuleMatch{Tools: []string{"http_request"}}},
		Rule{ID: "r3", Effect: "alert", Match: RuleMatch{Actions: []string{"read"}}},
	)
	r := MapCoverage(p)
	for _, m := range r.Mappings {
		if m.Confidence < 0 || m.Confidence > 1 {
			t.Errorf("rule %s confidence = %.4f, want within [0,1]", m.RuleName, m.Confidence)
		}
	}
}

func TestCoverageMapping_AllowConfidenceHalvedVsDeny(t *testing.T) {
	t.Parallel()
	denyPolicy := coverageTestPolicy("deny-p",
		Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	allowPolicy := coverageTestPolicy("allow-p",
		Rule{ID: "r1", Effect: "allow", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)

	denyReport := MapCoverage(denyPolicy)
	allowReport := MapCoverage(allowPolicy)

	denyConf := denyReport.Mappings[0].Confidence
	allowConf := allowReport.Mappings[0].Confidence

	const epsilon = 1e-9
	if diff := denyConf/2 - allowConf; diff > epsilon || diff < -epsilon {
		t.Errorf("allow confidence = %.4f, want half of deny confidence %.4f", allowConf, denyConf)
	}
}

// ---------------------------------------------------------------------------
// computeTacticCoverage
// ---------------------------------------------------------------------------

func TestComputeTacticCoverage_EmptyMappings(t *testing.T) {
	t.Parallel()
	allTactics := map[string][]string{"execution": {"T1059"}}
	got := computeTacticCoverage(nil, allTactics)
	if got["execution"] != 0 {
		t.Errorf("execution coverage = %.2f, want 0", got["execution"])
	}
}

func TestComputeTacticCoverage_FullyCovered(t *testing.T) {
	t.Parallel()
	mappings := []CoverageMapping{
		{RuleName: "r1", RuleAction: "deny", Techniques: []string{"T1059"}},
	}
	allTactics := map[string][]string{"execution": {"T1059"}}
	got := computeTacticCoverage(mappings, allTactics)
	if got["execution"] != 100 {
		t.Errorf("execution coverage = %.2f, want 100", got["execution"])
	}
}

func TestComputeTacticCoverage_PartialCovered(t *testing.T) {
	t.Parallel()
	mappings := []CoverageMapping{
		{RuleName: "r1", RuleAction: "deny", Techniques: []string{"T1059"}},
	}
	allTactics := map[string][]string{"execution": {"T1059", "TE002"}}
	got := computeTacticCoverage(mappings, allTactics)
	if got["execution"] != 50 {
		t.Errorf("execution coverage = %.2f, want 50", got["execution"])
	}
}

func TestComputeTacticCoverage_AllowMappingsIgnored(t *testing.T) {
	t.Parallel()
	mappings := []CoverageMapping{
		{RuleName: "r1", RuleAction: "allow", Techniques: []string{"T1059"}},
	}
	allTactics := map[string][]string{"execution": {"T1059"}}
	got := computeTacticCoverage(mappings, allTactics)
	if got["execution"] != 0 {
		t.Errorf("execution coverage = %.2f, want 0 (allow should not count)", got["execution"])
	}
}

func TestComputeTacticCoverage_AlertMappingsCount(t *testing.T) {
	t.Parallel()
	mappings := []CoverageMapping{
		{RuleName: "r1", RuleAction: "alert", Techniques: []string{"T1059"}},
	}
	allTactics := map[string][]string{"execution": {"T1059"}}
	got := computeTacticCoverage(mappings, allTactics)
	if got["execution"] != 100 {
		t.Errorf("execution coverage = %.2f, want 100 (alert should count)", got["execution"])
	}
}

func TestComputeTacticCoverage_TacticWithNoTechniques(t *testing.T) {
	t.Parallel()
	allTactics := map[string][]string{"reconnaissance": {}}
	got := computeTacticCoverage(nil, allTactics)
	if got["reconnaissance"] != 0 {
		t.Errorf("reconnaissance coverage = %.2f, want 0", got["reconnaissance"])
	}
}

func TestMapCoverage_TacticCoverageAllTacticsPresent(t *testing.T) {
	t.Parallel()
	r := MapCoverage(nil)
	idx := catalogTacticIndex()
	for tactic := range idx {
		if _, ok := r.TacticCoverage[tactic]; !ok {
			t.Errorf("TacticCoverage missing tactic %q", tactic)
		}
	}
}

// ---------------------------------------------------------------------------
// scoreCoverageRisk
// ---------------------------------------------------------------------------

func TestScoreCoverageRisk_NilReport(t *testing.T) {
	t.Parallel()
	if got := scoreCoverageRisk(nil); got != 0 {
		t.Errorf("scoreCoverageRisk(nil) = %.2f, want 0", got)
	}
}

func TestScoreCoverageRisk_FullCoverageIsZero(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("full", allTechniqueCoveringRules()...)
	r := MapCoverage(p)
	if r.RiskScore != 0 {
		t.Errorf("RiskScore = %.4f, want 0 for full coverage", r.RiskScore)
	}
}

func TestScoreCoverageRisk_NoCoverageIsOne(t *testing.T) {
	t.Parallel()
	r := MapCoverage(nil)
	if r.RiskScore != 1 {
		t.Errorf("RiskScore = %.4f, want 1 for no coverage", r.RiskScore)
	}
}

func TestScoreCoverageRisk_PartialWithinBounds(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("partial",
		Rule{ID: "deny-shell", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)
	if r.RiskScore <= 0 || r.RiskScore >= 1 {
		t.Errorf("RiskScore = %.4f, want strictly between 0 and 1 for partial coverage", r.RiskScore)
	}
}

func TestScoreCoverageRisk_MoreCoverageLowersRisk(t *testing.T) {
	t.Parallel()
	light := coverageTestPolicy("light",
		Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	heavy := coverageTestPolicy("heavy", allTechniqueCoveringRules()...)

	lightReport := MapCoverage(light)
	heavyReport := MapCoverage(heavy)

	if heavyReport.RiskScore >= lightReport.RiskScore {
		t.Errorf("heavy coverage risk (%.4f) should be lower than light coverage risk (%.4f)",
			heavyReport.RiskScore, lightReport.RiskScore)
	}
}

// ---------------------------------------------------------------------------
// FormatCoverageReport / SummarizeCoverage
// ---------------------------------------------------------------------------

func TestFormatCoverageReport_NilReport(t *testing.T) {
	t.Parallel()
	out := FormatCoverageReport(nil)
	if !strings.Contains(out, "No coverage report") {
		t.Errorf("output = %q, want to contain 'No coverage report'", out)
	}
}

func TestFormatCoverageReport_ContainsSections(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("format-test",
		Rule{ID: "deny-shell", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)
	out := FormatCoverageReport(r)

	for _, want := range []string{
		"Technique Coverage Report",
		"Policy:",
		"Rules:",
		"Techniques:",
		"Gaps:",
		"Risk Score:",
		"Tactic Coverage",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

func TestFormatCoverageReport_NoGapsMessage(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("full", allTechniqueCoveringRules()...)
	r := MapCoverage(p)
	out := FormatCoverageReport(r)
	if !strings.Contains(out, "No coverage gaps") {
		t.Errorf("output missing 'No coverage gaps'; got:\n%s", out)
	}
}

func TestFormatCoverageReport_ListsGapSeverity(t *testing.T) {
	t.Parallel()
	r := MapCoverage(nil)
	out := FormatCoverageReport(r)
	if !strings.Contains(out, "[CRITICAL]") {
		t.Errorf("output missing a [CRITICAL] gap marker; got:\n%s", out)
	}
}

func TestSummarizeCoverage_NilReport(t *testing.T) {
	t.Parallel()
	out := SummarizeCoverage(nil)
	if !strings.Contains(out, "No coverage report") {
		t.Errorf("output = %q, want to contain 'No coverage report'", out)
	}
}

func TestSummarizeCoverage_ContainsPolicyName(t *testing.T) {
	t.Parallel()
	p := coverageTestPolicy("summary-policy",
		Rule{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_exec"}}},
	)
	r := MapCoverage(p)
	out := SummarizeCoverage(r)
	if !strings.Contains(out, "summary-policy") {
		t.Errorf("summary = %q, want to contain policy name", out)
	}
}

func TestSummarizeCoverage_IsSingleLine(t *testing.T) {
	t.Parallel()
	r := MapCoverage(nil)
	// nil report short-circuits before reaching the policy summary path;
	// exercise the non-nil path here.
	p := coverageTestPolicy("one-liner")
	r = MapCoverage(p)
	out := SummarizeCoverage(r)
	if strings.Contains(out, "\n") {
		t.Errorf("summary should be a single line, got %q", out)
	}
}
