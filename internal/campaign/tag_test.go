// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- helper campaigns for tag tests ---

func taggedCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "apt29-cozy-bear",
			Adversary: "APT29 Cozy Bear",
			Severity:  "critical",
			Tags:      []string{"espionage", "supply-chain", "Russia"},
		},
		Stages: []Stage{
			{ID: "s1", Technique: "T1566.001", Tactic: "initial-access", Execute: Execute{Type: "shell"}},
			{ID: "s2", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
			{ID: "s3", Technique: "T1041", Tactic: "exfiltration", Execute: Execute{Type: "http"}},
		},
	}
}

func taggedCampaign2() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "fin7-carbanak",
			Adversary: "FIN7",
			Severity:  "high",
			Tags:      []string{"financial", "espionage"},
		},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059.003", Tactic: "execution", Execute: Execute{Type: "shell"}},
			{ID: "s2", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
		},
	}
}

func untaggedCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "ransomware-op",
			Adversary: "Unknown",
			Severity:  "critical",
		},
		Stages: []Stage{
			{ID: "s1", Technique: "T1486", Tactic: "impact", Execute: Execute{Type: "shell"}},
			{ID: "s2", Technique: "T1490", Tactic: "impact", Execute: Execute{Type: "shell"}},
		},
	}
}

func aiCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "ai-agent-attack",
			Adversary: "Red Team",
			Severity:  "high",
		},
		Stages: []Stage{
			{ID: "s1", Technique: "AML.T0043", Tactic: "ml-attack-staging", Execute: Execute{Type: "shell"}},
			{ID: "s2", Technique: "LLM01", Tactic: "prompt-injection", Execute: Execute{Type: "http"}},
		},
	}
}

func cloudCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "cloud-exfil",
			Adversary: "APT41",
			Severity:  "high",
		},
		Stages: []Stage{
			{ID: "s1", Technique: "T1530", Tactic: "collection", Execute: Execute{Type: "http"}},
			{ID: "s2", Technique: "T1537", Tactic: "exfiltration", Execute: Execute{Type: "http"}},
		},
	}
}

func lateralMovementCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "lateral-spread",
			Adversary: "APT28",
			Severity:  "high",
		},
		Stages: []Stage{
			{ID: "s1", Technique: "T1021.002", Tactic: "lateral-movement", Execute: Execute{Type: "shell"}},
			{ID: "s2", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
		},
	}
}

// --- ListTags tests ---

func TestListTags_Basic(t *testing.T) {
	campaigns := []*Campaign{taggedCampaign(), taggedCampaign2()}
	ts := ListTags(campaigns)

	if ts.TotalCampaigns != 2 {
		t.Errorf("TotalCampaigns = %d, want 2", ts.TotalCampaigns)
	}
	if ts.TaggedCount != 2 {
		t.Errorf("TaggedCount = %d, want 2", ts.TaggedCount)
	}
	if ts.UntaggedCount != 0 {
		t.Errorf("UntaggedCount = %d, want 0", ts.UntaggedCount)
	}
}

func TestListTags_TagCounts(t *testing.T) {
	campaigns := []*Campaign{taggedCampaign(), taggedCampaign2()}
	ts := ListTags(campaigns)

	// "espionage" appears in both campaigns.
	found := false
	for _, ti := range ts.Tags {
		if ti.Tag == "espionage" {
			found = true
			if ti.Count != 2 {
				t.Errorf("espionage count = %d, want 2", ti.Count)
			}
			if len(ti.Campaigns) != 2 {
				t.Errorf("espionage campaigns = %d, want 2", len(ti.Campaigns))
			}
			break
		}
	}
	if !found {
		t.Error("expected to find 'espionage' tag")
	}
}

func TestListTags_SortOrder(t *testing.T) {
	campaigns := []*Campaign{taggedCampaign(), taggedCampaign2()}
	ts := ListTags(campaigns)

	if len(ts.Tags) == 0 {
		t.Fatal("expected tags, got none")
	}

	// First tag should be "espionage" (count=2, the only one with count>1).
	if ts.Tags[0].Tag != "espionage" {
		t.Errorf("first tag = %q, want %q (highest count)", ts.Tags[0].Tag, "espionage")
	}

	// Remaining tags all have count=1, should be sorted alphabetically.
	for i := 1; i < len(ts.Tags)-1; i++ {
		if ts.Tags[i].Count == ts.Tags[i+1].Count {
			if ts.Tags[i].Tag > ts.Tags[i+1].Tag {
				t.Errorf("tags not alphabetical: %q before %q", ts.Tags[i].Tag, ts.Tags[i+1].Tag)
			}
		}
	}
}

func TestListTags_WithUntagged(t *testing.T) {
	campaigns := []*Campaign{taggedCampaign(), untaggedCampaign()}
	ts := ListTags(campaigns)

	if ts.TotalCampaigns != 2 {
		t.Errorf("TotalCampaigns = %d, want 2", ts.TotalCampaigns)
	}
	if ts.TaggedCount != 1 {
		t.Errorf("TaggedCount = %d, want 1", ts.TaggedCount)
	}
	if ts.UntaggedCount != 1 {
		t.Errorf("UntaggedCount = %d, want 1", ts.UntaggedCount)
	}
	if len(ts.Suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(ts.Suggestions))
	}
	if ts.Suggestions[0].CampaignName != "ransomware-op" {
		t.Errorf("suggestion campaign = %q, want %q", ts.Suggestions[0].CampaignName, "ransomware-op")
	}
}

func TestListTags_Empty(t *testing.T) {
	ts := ListTags(nil)
	if ts.TotalCampaigns != 0 {
		t.Errorf("TotalCampaigns = %d, want 0", ts.TotalCampaigns)
	}
	if len(ts.Tags) != 0 {
		t.Errorf("expected no tags, got %d", len(ts.Tags))
	}
}

func TestListTags_EmptySlice(t *testing.T) {
	ts := ListTags([]*Campaign{})
	if ts.TotalCampaigns != 0 {
		t.Errorf("TotalCampaigns = %d, want 0", ts.TotalCampaigns)
	}
}

func TestListTags_NilCampaignInSlice(t *testing.T) {
	campaigns := []*Campaign{taggedCampaign(), nil, taggedCampaign2()}
	ts := ListTags(campaigns)
	if ts.TotalCampaigns != 2 {
		t.Errorf("TotalCampaigns = %d, want 2 (nil skipped)", ts.TotalCampaigns)
	}
}

func TestListTags_AllUntagged(t *testing.T) {
	campaigns := []*Campaign{untaggedCampaign(), aiCampaign()}
	ts := ListTags(campaigns)

	if ts.TaggedCount != 0 {
		t.Errorf("TaggedCount = %d, want 0", ts.TaggedCount)
	}
	if ts.UntaggedCount != 2 {
		t.Errorf("UntaggedCount = %d, want 2", ts.UntaggedCount)
	}
	if len(ts.Tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(ts.Tags))
	}
	if len(ts.Suggestions) != 2 {
		t.Errorf("expected 2 suggestions, got %d", len(ts.Suggestions))
	}
}

// --- FindByTag tests ---

func TestFindByTag_ExactMatch(t *testing.T) {
	campaigns := []*Campaign{taggedCampaign(), taggedCampaign2()}
	found := FindByTag(campaigns, "espionage")
	if len(found) != 2 {
		t.Fatalf("expected 2 campaigns with 'espionage', got %d", len(found))
	}
}

func TestFindByTag_CaseInsensitive(t *testing.T) {
	campaigns := []*Campaign{taggedCampaign()}
	found := FindByTag(campaigns, "RUSSIA")
	if len(found) != 1 {
		t.Fatalf("expected 1 campaign with 'RUSSIA' (case-insensitive), got %d", len(found))
	}
	if found[0].Meta.Name != "apt29-cozy-bear" {
		t.Errorf("name = %q, want %q", found[0].Meta.Name, "apt29-cozy-bear")
	}
}

func TestFindByTag_NoMatch(t *testing.T) {
	campaigns := []*Campaign{taggedCampaign(), taggedCampaign2()}
	found := FindByTag(campaigns, "nonexistent-tag")
	if len(found) != 0 {
		t.Errorf("expected 0 results for nonexistent tag, got %d", len(found))
	}
}

func TestFindByTag_EmptyInput(t *testing.T) {
	found := FindByTag(nil, "espionage")
	if len(found) != 0 {
		t.Errorf("expected 0 results for nil campaigns, got %d", len(found))
	}
}

func TestFindByTag_EmptyTag(t *testing.T) {
	campaigns := []*Campaign{taggedCampaign()}
	found := FindByTag(campaigns, "")
	if len(found) != 0 {
		t.Errorf("expected 0 results for empty tag, got %d", len(found))
	}
}

func TestFindByTag_NilCampaignSkipped(t *testing.T) {
	campaigns := []*Campaign{nil, taggedCampaign()}
	found := FindByTag(campaigns, "espionage")
	if len(found) != 1 {
		t.Errorf("expected 1 result (nil skipped), got %d", len(found))
	}
}

// --- SuggestTags tests ---

func TestSuggestTags_Ransomware(t *testing.T) {
	c := untaggedCampaign() // has T1486, T1490
	s := SuggestTags(c)

	assertHasSuggestion(t, s, "ransomware")
	assertHasSuggestion(t, s, "critical") // severity = critical
}

func TestSuggestTags_CredentialAccess(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "cred-test", Adversary: "Test", Severity: "medium"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1003.001", Tactic: "credential-access", Execute: Execute{Type: "shell"}},
		},
	}
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "credential-theft")
}

func TestSuggestTags_LateralMovement(t *testing.T) {
	c := lateralMovementCampaign()
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "lateral-movement")
}

func TestSuggestTags_APT(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "apt-test", Adversary: "APT28 Fancy Bear", Severity: "high"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		},
	}
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "apt")
}

func TestSuggestTags_ATLAS(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "atlas-test", Adversary: "Test", Severity: "medium"},
		Stages: []Stage{
			{ID: "s1", Technique: "AML.T0043", Tactic: "ml-attack-staging", Execute: Execute{Type: "shell"}},
		},
	}
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "ai-security")
}

func TestSuggestTags_OWASP(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "owasp-test", Adversary: "Test", Severity: "medium"},
		Stages: []Stage{
			{ID: "s1", Technique: "LLM01", Tactic: "prompt-injection", Execute: Execute{Type: "http"}},
		},
	}
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "llm-security")
}

func TestSuggestTags_Critical(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "critical-test", Adversary: "Test", Severity: "critical"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		},
	}
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "critical")
}

func TestSuggestTags_Exfiltration(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "exfil-test", Adversary: "Test", Severity: "medium"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1041", Tactic: "exfiltration", Execute: Execute{Type: "http"}},
		},
	}
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "data-theft")
}

func TestSuggestTags_Phishing(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "phish-test", Adversary: "Test", Severity: "medium"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1566.001", Tactic: "initial-access", Execute: Execute{Type: "shell"}},
		},
	}
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "phishing")
}

func TestSuggestTags_PhishingBase(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "phish-base-test", Adversary: "Test", Severity: "medium"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1566", Tactic: "initial-access", Execute: Execute{Type: "shell"}},
		},
	}
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "phishing")
}

func TestSuggestTags_Cloud(t *testing.T) {
	c := cloudCampaign()
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "cloud")
}

func TestSuggestTags_Multiple(t *testing.T) {
	// AI campaign has ATLAS + OWASP techniques but no tags.
	c := aiCampaign()
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "ai-security")
	assertHasSuggestion(t, s, "llm-security")
}

func TestSuggestTags_NoSuggestions(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "boring", Adversary: "Unknown", Severity: "low"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
		},
	}
	s := SuggestTags(c)
	if len(s.Suggested) != 0 {
		t.Errorf("expected 0 suggestions, got %v", s.Suggested)
	}
}

func TestSuggestTags_ReasonsMatchSuggested(t *testing.T) {
	c := untaggedCampaign()
	s := SuggestTags(c)
	if len(s.Suggested) != len(s.Reasons) {
		t.Errorf("len(Suggested)=%d != len(Reasons)=%d", len(s.Suggested), len(s.Reasons))
	}
	for _, reason := range s.Reasons {
		if reason == "" {
			t.Error("reason should not be empty")
		}
	}
}

func TestSuggestTags_CampaignNameSet(t *testing.T) {
	c := untaggedCampaign()
	s := SuggestTags(c)
	if s.CampaignName != "ransomware-op" {
		t.Errorf("CampaignName = %q, want %q", s.CampaignName, "ransomware-op")
	}
}

func TestSuggestTags_RansomwareSubTechnique(t *testing.T) {
	// T1486.001 is a sub-technique of a ransomware technique — base should match.
	c := &Campaign{
		Meta: Meta{Name: "ransom-sub", Adversary: "Test", Severity: "medium"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1486.001", Tactic: "impact", Execute: Execute{Type: "shell"}},
		},
	}
	s := SuggestTags(c)
	assertHasSuggestion(t, s, "ransomware")
}

// --- FormatTagSummary tests ---

func TestFormatTagSummary_Basic(t *testing.T) {
	ts := ListTags([]*Campaign{taggedCampaign(), taggedCampaign2()})
	out := FormatTagSummary(ts)

	if len(out) == 0 {
		t.Fatal("FormatTagSummary returned empty string")
	}
	if !strings.Contains(out, "Tag Taxonomy Report") {
		t.Error("output should contain report title")
	}
	if !strings.Contains(out, "espionage") {
		t.Error("output should contain tag 'espionage'")
	}
	if !strings.Contains(out, "Campaigns") {
		t.Error("output should contain 'Campaigns'")
	}
	if !strings.Contains(out, "Coverage") {
		t.Error("output should contain 'Coverage'")
	}
}

func TestFormatTagSummary_WithSuggestions(t *testing.T) {
	ts := ListTags([]*Campaign{taggedCampaign(), untaggedCampaign()})
	out := FormatTagSummary(ts)

	if !strings.Contains(out, "Suggestions") {
		t.Error("output should contain 'Suggestions' section")
	}
	if !strings.Contains(out, "ransomware-op") {
		t.Error("output should mention untagged campaign name")
	}
	if !strings.Contains(out, "ransomware") {
		t.Error("output should suggest 'ransomware' tag")
	}
}

func TestFormatTagSummary_Nil(t *testing.T) {
	out := FormatTagSummary(nil)
	if out != "" {
		t.Errorf("expected empty string for nil, got %q", out)
	}
}

func TestFormatTagSummary_Empty(t *testing.T) {
	ts := ListTags([]*Campaign{})
	out := FormatTagSummary(ts)
	if !strings.Contains(out, "Campaigns: 0") {
		t.Error("output should indicate 0 campaigns")
	}
}

func TestFormatTagSummary_ContainsBoxChars(t *testing.T) {
	ts := ListTags([]*Campaign{taggedCampaign()})
	out := FormatTagSummary(ts)
	if !strings.Contains(out, "╔") || !strings.Contains(out, "╚") {
		t.Error("output should contain box drawing characters")
	}
}

// --- ListTagsDir tests ---

func TestListTagsDir_Basic(t *testing.T) {
	dir := t.TempDir()

	writeTestCampaignYAML(t, dir, "apt29", `
api_version: v1
kind: Campaign
meta:
  name: apt29-cozy-bear
  adversary: APT29
  severity: critical
  tags: [espionage, supply-chain]
  created: "2026-01-01"
  modified: "2026-01-01"
stages:
  - id: phish
    name: Spearphishing
    technique: T1566.001
    tactic: initial-access
    execute:
      type: shell
`)

	writeTestCampaignYAML(t, dir, "untagged", `
api_version: v1
kind: Campaign
meta:
  name: untagged-campaign
  adversary: Unknown
  severity: high
  created: "2026-01-01"
  modified: "2026-01-01"
stages:
  - id: exec
    name: Execution
    technique: T1059.001
    tactic: execution
    execute:
      type: shell
`)

	ts, err := ListTagsDir(dir)
	if err != nil {
		t.Fatalf("ListTagsDir error: %v", err)
	}
	if ts.TotalCampaigns != 2 {
		t.Errorf("TotalCampaigns = %d, want 2", ts.TotalCampaigns)
	}
	if ts.TaggedCount != 1 {
		t.Errorf("TaggedCount = %d, want 1", ts.TaggedCount)
	}
	if ts.UntaggedCount != 1 {
		t.Errorf("UntaggedCount = %d, want 1", ts.UntaggedCount)
	}
}

func TestListTagsDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	ts, err := ListTagsDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts.TotalCampaigns != 0 {
		t.Errorf("TotalCampaigns = %d, want 0", ts.TotalCampaigns)
	}
}

func TestListTagsDir_NonexistentDir(t *testing.T) {
	_, err := ListTagsDir("/nonexistent/path/for/tag/test")
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

func TestListTagsDir_SkipsInvalidYAML(t *testing.T) {
	dir := t.TempDir()

	// Valid campaign.
	writeTestCampaignYAML(t, dir, "valid", `
api_version: v1
kind: Campaign
meta:
  name: valid-campaign
  adversary: Test
  severity: low
  tags: [test]
  created: "2026-01-01"
  modified: "2026-01-01"
stages:
  - id: s1
    name: Stage
    technique: T1059.001
    tactic: execution
    execute:
      type: shell
`)

	// Invalid YAML.
	invalidDir := filepath.Join(dir, "broken")
	if err := os.MkdirAll(invalidDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(invalidDir, "campaign.yaml"), []byte("{{invalid yaml"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	ts, err := ListTagsDir(dir)
	if err != nil {
		t.Fatalf("ListTagsDir error: %v", err)
	}
	if ts.TotalCampaigns != 1 {
		t.Errorf("TotalCampaigns = %d, want 1 (invalid skipped)", ts.TotalCampaigns)
	}
}

// --- techBase tests ---

func TestTechBase_WithSub(t *testing.T) {
	if got := techBase("T1059.001"); got != "T1059" {
		t.Errorf("techBase(T1059.001) = %q, want T1059", got)
	}
}

func TestTechBase_NoSub(t *testing.T) {
	if got := techBase("T1486"); got != "T1486" {
		t.Errorf("techBase(T1486) = %q, want T1486", got)
	}
}

func TestTechBase_ATLAS(t *testing.T) {
	if got := techBase("AML.T0043"); got != "AML" {
		t.Errorf("techBase(AML.T0043) = %q, want AML", got)
	}
}

// --- Combined scenario tests ---

func TestFullScenario_MixedCampaigns(t *testing.T) {
	campaigns := []*Campaign{
		taggedCampaign(),
		taggedCampaign2(),
		untaggedCampaign(),
		aiCampaign(),
		cloudCampaign(),
	}

	ts := ListTags(campaigns)

	if ts.TotalCampaigns != 5 {
		t.Errorf("TotalCampaigns = %d, want 5", ts.TotalCampaigns)
	}
	if ts.TaggedCount != 2 {
		t.Errorf("TaggedCount = %d, want 2", ts.TaggedCount)
	}
	if ts.UntaggedCount != 3 {
		t.Errorf("UntaggedCount = %d, want 3", ts.UntaggedCount)
	}

	// Should have suggestions for the 3 untagged campaigns.
	if len(ts.Suggestions) != 3 {
		t.Errorf("Suggestions = %d, want 3", len(ts.Suggestions))
	}

	// Verify the format doesn't panic.
	out := FormatTagSummary(ts)
	if len(out) == 0 {
		t.Error("FormatTagSummary should produce non-empty output")
	}
}

func TestFindByTag_AcrossMixed(t *testing.T) {
	campaigns := []*Campaign{
		taggedCampaign(),  // has "espionage"
		taggedCampaign2(), // has "espionage"
		untaggedCampaign(),
	}

	found := FindByTag(campaigns, "espionage")
	if len(found) != 2 {
		t.Errorf("expected 2 campaigns with 'espionage', got %d", len(found))
	}

	found = FindByTag(campaigns, "financial")
	if len(found) != 1 {
		t.Errorf("expected 1 campaign with 'financial', got %d", len(found))
	}
}

// --- helpers ---

func assertHasSuggestion(t *testing.T, s *TagSuggestion, tag string) {
	t.Helper()
	for _, suggested := range s.Suggested {
		if suggested == tag {
			return
		}
	}
	t.Errorf("expected suggestion %q in %v for campaign %q", tag, s.Suggested, s.CampaignName)
}
