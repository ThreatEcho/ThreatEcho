// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"strings"
	"testing"
	"time"
)

// helper to build a minimal campaign with the given name, severity, and stages.
func testCampaign(name, severity string, stages []Stage) *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:         name,
			Adversary:    name + "-adversary",
			Description:  name + " description",
			Severity:     severity,
			MitreVersion: "14.1",
			Tags:         []string{name + "-tag"},
			Authors:      []string{name + "-author"},
			References:   []string{"https://" + name + ".example.com"},
		},
		Stages: stages,
	}
}

func TestMerge_SingleCampaign(t *testing.T) {
	c := testCampaign("alpha", "high", []Stage{
		{ID: "s1", Name: "Stage 1", Technique: "T1059", Tactic: "execution"},
	})
	result, err := Merge([]*Campaign{c}, MergeOptions{Name: "solo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Campaign.Meta.Name != "solo" {
		t.Errorf("name = %q, want %q", result.Campaign.Meta.Name, "solo")
	}
	if len(result.Campaign.Stages) != 1 {
		t.Errorf("stages = %d, want 1", len(result.Campaign.Stages))
	}
	if result.Campaign.Stages[0].ID != "s1" {
		t.Errorf("stage ID = %q, want %q", result.Campaign.Stages[0].ID, "s1")
	}
	if result.Campaign.APIVersion != "v1" {
		t.Errorf("api_version = %q, want %q", result.Campaign.APIVersion, "v1")
	}
}

func TestMerge_TwoCampaigns_NoCollisions(t *testing.T) {
	c1 := testCampaign("alpha", "medium", []Stage{
		{ID: "a1", Name: "Alpha 1", Technique: "T1059", Tactic: "execution"},
	})
	c2 := testCampaign("bravo", "high", []Stage{
		{ID: "b1", Name: "Bravo 1", Technique: "T1078", Tactic: "persistence"},
	})
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{Name: "combined"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Campaign.Stages) != 2 {
		t.Fatalf("stages = %d, want 2", len(result.Campaign.Stages))
	}
	if result.Campaign.Stages[0].ID != "a1" {
		t.Errorf("first stage ID = %q, want %q", result.Campaign.Stages[0].ID, "a1")
	}
	if result.Campaign.Stages[1].ID != "b1" {
		t.Errorf("second stage ID = %q, want %q", result.Campaign.Stages[1].ID, "b1")
	}
	if len(result.Conflicts) != 0 {
		t.Errorf("unexpected conflicts: %v", result.Conflicts)
	}
}

func TestMerge_StageIDCollision_ErrorStrategy(t *testing.T) {
	c1 := testCampaign("alpha", "high", []Stage{
		{ID: "recon", Name: "Alpha recon", Technique: "T1595", Tactic: "reconnaissance"},
	})
	c2 := testCampaign("bravo", "high", []Stage{
		{ID: "recon", Name: "Bravo recon", Technique: "T1595", Tactic: "reconnaissance"},
	})
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{Strategy: "error"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With "error" strategy, collisions go to Conflicts, not error return.
	if len(result.Conflicts) == 0 {
		t.Fatal("expected conflicts for duplicate stage ID")
	}
	found := false
	for _, c := range result.Conflicts {
		if c.Type == "stage_id" && c.Key == "recon" {
			found = true
			if len(c.Sources) < 2 {
				t.Errorf("conflict sources = %v, want at least 2", c.Sources)
			}
		}
	}
	if !found {
		t.Error("expected a stage_id conflict for 'recon'")
	}
	// Only the first campaign's stage should be in the merged result
	// (second was skipped due to collision in error mode).
	if len(result.Campaign.Stages) != 1 {
		t.Errorf("stages = %d, want 1 (first kept, second conflicted)", len(result.Campaign.Stages))
	}
}

func TestMerge_StageIDCollision_FirstStrategy(t *testing.T) {
	c1 := testCampaign("alpha", "high", []Stage{
		{ID: "recon", Name: "Alpha recon", Technique: "T1595", Tactic: "reconnaissance"},
	})
	c2 := testCampaign("bravo", "high", []Stage{
		{ID: "recon", Name: "Bravo recon", Technique: "T1595", Tactic: "reconnaissance"},
	})
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{Strategy: "first"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Conflicts) != 0 {
		t.Errorf("first strategy should produce no conflicts, got %v", result.Conflicts)
	}
	if len(result.Campaign.Stages) != 1 {
		t.Fatalf("stages = %d, want 1", len(result.Campaign.Stages))
	}
	if result.Campaign.Stages[0].Name != "Alpha recon" {
		t.Errorf("kept stage name = %q, want %q (first wins)", result.Campaign.Stages[0].Name, "Alpha recon")
	}
}

func TestMerge_StageIDCollision_Prefix(t *testing.T) {
	c1 := testCampaign("Alpha", "high", []Stage{
		{ID: "recon", Name: "Alpha recon", Technique: "T1595", Tactic: "reconnaissance"},
	})
	c2 := testCampaign("Bravo", "high", []Stage{
		{ID: "recon", Name: "Bravo recon", Technique: "T1595", Tactic: "reconnaissance"},
	})
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{Prefix: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Conflicts) != 0 {
		t.Errorf("prefix mode should avoid conflicts, got %v", result.Conflicts)
	}
	if len(result.Campaign.Stages) != 2 {
		t.Fatalf("stages = %d, want 2", len(result.Campaign.Stages))
	}
	if result.Campaign.Stages[0].ID != "alpha/recon" {
		t.Errorf("stage 0 ID = %q, want %q", result.Campaign.Stages[0].ID, "alpha/recon")
	}
	if result.Campaign.Stages[1].ID != "bravo/recon" {
		t.Errorf("stage 1 ID = %q, want %q", result.Campaign.Stages[1].ID, "bravo/recon")
	}
}

func TestMerge_PrefixUpdatesDepends(t *testing.T) {
	c := testCampaign("Alpha", "high", []Stage{
		{ID: "s1", Name: "First", Technique: "T1059", Tactic: "execution"},
		{ID: "s2", Name: "Second", Technique: "T1078", Tactic: "persistence", DependsOn: []string{"s1"}},
	})
	result, err := Merge([]*Campaign{c}, MergeOptions{Prefix: true, Name: "prefixed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s2 := result.Campaign.Stages[1]
	if len(s2.DependsOn) != 1 || s2.DependsOn[0] != "alpha/s1" {
		t.Errorf("depends_on = %v, want [alpha/s1]", s2.DependsOn)
	}
}

func TestMerge_PrefixUpdatesOnSuccess(t *testing.T) {
	c := testCampaign("Alpha", "high", []Stage{
		{ID: "s1", Name: "First", Technique: "T1059", Tactic: "execution", OnSuccess: "s2"},
		{ID: "s2", Name: "Second", Technique: "T1078", Tactic: "persistence"},
	})
	result, err := Merge([]*Campaign{c}, MergeOptions{Prefix: true, Name: "prefixed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s1 := result.Campaign.Stages[0]
	if s1.OnSuccess != "alpha/s2" {
		t.Errorf("on_success = %q, want %q", s1.OnSuccess, "alpha/s2")
	}
}

func TestMerge_PrefixUpdatesOnFailure(t *testing.T) {
	c := testCampaign("Alpha", "high", []Stage{
		{ID: "s1", Name: "First", Technique: "T1059", Tactic: "execution", OnFailure: "s2"},
		{ID: "s2", Name: "Fallback", Technique: "T1078", Tactic: "persistence"},
	})
	result, err := Merge([]*Campaign{c}, MergeOptions{Prefix: true, Name: "prefixed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s1 := result.Campaign.Stages[0]
	if s1.OnFailure != "alpha/s2" {
		t.Errorf("on_failure = %q, want %q", s1.OnFailure, "alpha/s2")
	}
}

func TestMerge_PrefixOnFailure_NonStageID(t *testing.T) {
	// "abort" is a control keyword, not a stage ID — it should NOT be prefixed.
	c := testCampaign("Alpha", "high", []Stage{
		{ID: "s1", Name: "First", Technique: "T1059", Tactic: "execution", OnFailure: "abort"},
	})
	result, err := Merge([]*Campaign{c}, MergeOptions{Prefix: true, Name: "prefixed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s1 := result.Campaign.Stages[0]
	if s1.OnFailure != "abort" {
		t.Errorf("on_failure = %q, want %q (should not prefix control keywords)", s1.OnFailure, "abort")
	}
}

func TestMerge_VariableMerge_NoCollision(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c1.Variables = map[string]string{"target_ip": "10.0.0.1"}
	c2 := testCampaign("bravo", "high", nil)
	c2.Variables = map[string]string{"payload_url": "http://evil.com"}
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Campaign.Variables["target_ip"] != "10.0.0.1" {
		t.Error("missing target_ip variable")
	}
	if result.Campaign.Variables["payload_url"] != "http://evil.com" {
		t.Error("missing payload_url variable")
	}
	if len(result.Conflicts) != 0 {
		t.Errorf("unexpected conflicts: %v", result.Conflicts)
	}
}

func TestMerge_VariableMerge_SameValue(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c1.Variables = map[string]string{"target_ip": "10.0.0.1"}
	c2 := testCampaign("bravo", "high", nil)
	c2.Variables = map[string]string{"target_ip": "10.0.0.1"}
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Campaign.Variables["target_ip"] != "10.0.0.1" {
		t.Error("variable not merged correctly")
	}
	// Same value should produce a warning, not a conflict.
	if len(result.Warnings) == 0 {
		t.Error("expected warning for duplicate variable with same value")
	}
	foundWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "target_ip") && strings.Contains(w, "same value") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("warning does not mention target_ip: %v", result.Warnings)
	}
	if len(result.Conflicts) != 0 {
		t.Errorf("same-value variables should not conflict, got %v", result.Conflicts)
	}
}

func TestMerge_VariableMerge_DifferentValue(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c1.Variables = map[string]string{"target_ip": "10.0.0.1"}
	c2 := testCampaign("bravo", "high", nil)
	c2.Variables = map[string]string{"target_ip": "192.168.1.1"}
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, c := range result.Conflicts {
		if c.Type == "variable" && c.Key == "target_ip" {
			found = true
			if len(c.Sources) < 2 {
				t.Errorf("conflict sources = %v, want at least 2", c.Sources)
			}
		}
	}
	if !found {
		t.Error("expected variable conflict for 'target_ip'")
	}
}

func TestMerge_MetaSeverityHighestWins(t *testing.T) {
	tests := []struct {
		severities []string
		want       string
	}{
		{[]string{"low", "medium"}, "medium"},
		{[]string{"high", "low"}, "high"},
		{[]string{"medium", "critical"}, "critical"},
		{[]string{"low", "low"}, "low"},
		{[]string{"critical", "high", "medium"}, "critical"},
	}
	for _, tt := range tests {
		var campaigns []*Campaign
		for i, sev := range tt.severities {
			c := testCampaign("c"+string(rune('0'+i)), sev, nil)
			campaigns = append(campaigns, c)
		}
		result, err := Merge(campaigns, MergeOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Campaign.Meta.Severity != tt.want {
			t.Errorf("severities %v: got %q, want %q", tt.severities, result.Campaign.Meta.Severity, tt.want)
		}
	}
}

func TestMerge_MetaTagsDeduped(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c1.Meta.Tags = []string{"apt", "windows", "lateral-movement"}
	c2 := testCampaign("bravo", "high", nil)
	c2.Meta.Tags = []string{"apt", "linux", "lateral-movement"}
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tags := result.Campaign.Meta.Tags
	expected := []string{"apt", "lateral-movement", "linux", "windows"} // sorted
	if len(tags) != len(expected) {
		t.Fatalf("tags = %v, want %v", tags, expected)
	}
	for i, tag := range tags {
		if tag != expected[i] {
			t.Errorf("tag[%d] = %q, want %q", i, tag, expected[i])
		}
	}
}

func TestMerge_MetaAuthorsDeduped(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c1.Meta.Authors = []string{"alice", "bob"}
	c2 := testCampaign("bravo", "high", nil)
	c2.Meta.Authors = []string{"bob", "charlie"}
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	authors := result.Campaign.Meta.Authors
	expected := []string{"alice", "bob", "charlie"}
	if len(authors) != len(expected) {
		t.Fatalf("authors = %v, want %v", authors, expected)
	}
	for i, a := range authors {
		if a != expected[i] {
			t.Errorf("author[%d] = %q, want %q", i, a, expected[i])
		}
	}
}

func TestMerge_MetaReferencesDeduped(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c1.Meta.References = []string{"https://example.com/a", "https://example.com/shared"}
	c2 := testCampaign("bravo", "high", nil)
	c2.Meta.References = []string{"https://example.com/shared", "https://example.com/b"}
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	refs := result.Campaign.Meta.References
	expected := []string{"https://example.com/a", "https://example.com/b", "https://example.com/shared"}
	if len(refs) != len(expected) {
		t.Fatalf("references = %v, want %v", refs, expected)
	}
	for i, r := range refs {
		if r != expected[i] {
			t.Errorf("ref[%d] = %q, want %q", i, r, expected[i])
		}
	}
}

func TestMerge_MetaAdversaryJoined(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c1.Meta.Adversary = "APT29"
	c2 := testCampaign("bravo", "high", nil)
	c2.Meta.Adversary = "FIN6"
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Campaign.Meta.Adversary != "APT29 + FIN6" {
		t.Errorf("adversary = %q, want %q", result.Campaign.Meta.Adversary, "APT29 + FIN6")
	}
}

func TestMerge_MetaAdversaryDeduplicated(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c1.Meta.Adversary = "APT29"
	c2 := testCampaign("bravo", "high", nil)
	c2.Meta.Adversary = "APT29"
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Campaign.Meta.Adversary != "APT29" {
		t.Errorf("adversary = %q, want %q (should dedupe)", result.Campaign.Meta.Adversary, "APT29")
	}
}

func TestMerge_MetaMitreVersionHighest(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c1.Meta.MitreVersion = "13.1"
	c2 := testCampaign("bravo", "high", nil)
	c2.Meta.MitreVersion = "14.1"
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Campaign.Meta.MitreVersion != "14.1" {
		t.Errorf("mitre_version = %q, want %q", result.Campaign.Meta.MitreVersion, "14.1")
	}
}

func TestMerge_EmptyInput(t *testing.T) {
	_, err := Merge(nil, MergeOptions{})
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	_, err = Merge([]*Campaign{}, MergeOptions{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestMerge_NilCampaign(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	_, err := Merge([]*Campaign{c1, nil}, MergeOptions{})
	if err == nil {
		t.Fatal("expected error for nil campaign in slice")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error = %q, want mention of nil", err.Error())
	}
}

func TestMerge_DefaultName(t *testing.T) {
	c := testCampaign("alpha", "high", nil)
	result, err := Merge([]*Campaign{c}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Campaign.Meta.Name != "merged-campaign" {
		t.Errorf("default name = %q, want %q", result.Campaign.Meta.Name, "merged-campaign")
	}
}

func TestMerge_StageDeepCopy(t *testing.T) {
	// Verify that the merge deep-copies stages so mutations don't leak.
	c := testCampaign("alpha", "high", []Stage{
		{
			ID:        "s1",
			Name:      "Stage 1",
			Technique: "T1059",
			Tactic:    "execution",
			DependsOn: []string{"s0"},
			Execute: Execute{
				Type:     "shell",
				Commands: []string{"whoami"},
				Args:     map[string]string{"key": "val"},
			},
			Timeout: Duration{30 * time.Second},
		},
	})
	result, err := Merge([]*Campaign{c}, MergeOptions{Name: "copy-test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Mutate the merged stage and verify the original is untouched.
	result.Campaign.Stages[0].DependsOn[0] = "MUTATED"
	result.Campaign.Stages[0].Execute.Commands[0] = "MUTATED"
	result.Campaign.Stages[0].Execute.Args["key"] = "MUTATED"

	if c.Stages[0].DependsOn[0] == "MUTATED" {
		t.Error("DependsOn leaked mutation to original")
	}
	if c.Stages[0].Execute.Commands[0] == "MUTATED" {
		t.Error("Commands leaked mutation to original")
	}
	if c.Stages[0].Execute.Args["key"] == "MUTATED" {
		t.Error("Args leaked mutation to original")
	}
}

func TestMerge_Description(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c2 := testCampaign("bravo", "medium", nil)
	result, err := Merge([]*Campaign{c1, c2}, MergeOptions{Name: "combo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Merged campaign: alpha, bravo"
	if result.Campaign.Meta.Description != want {
		t.Errorf("description = %q, want %q", result.Campaign.Meta.Description, want)
	}
}

func TestMerge_PrefixCrossCampaignDeps(t *testing.T) {
	// When a stage references a dep that does NOT exist in its own campaign,
	// the dep should remain as-is (it might reference another campaign's stage).
	c1 := testCampaign("Alpha", "high", []Stage{
		{ID: "s1", Name: "A1", Technique: "T1059", Tactic: "execution", DependsOn: []string{"external-stage"}},
	})
	result, err := Merge([]*Campaign{c1}, MergeOptions{Prefix: true, Name: "cross-test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	deps := result.Campaign.Stages[0].DependsOn
	if len(deps) != 1 || deps[0] != "external-stage" {
		t.Errorf("cross-campaign dep = %v, want [external-stage] (unchanged)", deps)
	}
}

func TestMerge_KindAndAPIVersion(t *testing.T) {
	c1 := testCampaign("alpha", "high", nil)
	c1.APIVersion = "v0"
	c1.Kind = "OldCampaign"
	result, err := Merge([]*Campaign{c1}, MergeOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Campaign.APIVersion != "v1" {
		t.Errorf("api_version = %q, want %q", result.Campaign.APIVersion, "v1")
	}
	if result.Campaign.Kind != "Campaign" {
		t.Errorf("kind = %q, want %q", result.Campaign.Kind, "Campaign")
	}
}
