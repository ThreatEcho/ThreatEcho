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

// searchTestCampaign builds a rich campaign for search tests.
func searchTestCampaign() *Campaign {
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
			{
				ID:          "initial-access",
				Name:        "Spearphishing Attachment",
				Description: "Deliver weaponized document via email",
				Technique:   "T1566.001",
				Tactic:      "initial-access",
				Platform:    []string{"windows", "linux"},
				Execute:     Execute{Type: "shell"},
			},
			{
				ID:          "execution",
				Name:        "PowerShell Execution",
				Description: "Execute encoded PowerShell command",
				Technique:   "T1059.001",
				Tactic:      "execution",
				Platform:    []string{"windows"},
				Execute:     Execute{Type: "shell"},
			},
			{
				ID:          "persistence",
				Name:        "Registry Run Key",
				Description: "Establish persistence via registry modification",
				Technique:   "T1547.001",
				Tactic:      "persistence",
				Platform:    []string{"windows"},
				Execute:     Execute{Type: "registry"},
			},
			{
				ID:          "lateral-movement",
				Name:        "WMI Remote Execution",
				Description: "Move laterally using WMI",
				Technique:   "T1047",
				Tactic:      "execution",
				Platform:    []string{"windows"},
				Execute:     Execute{Type: "shell"},
			},
			{
				ID:          "exfiltration",
				Name:        "HTTP Exfiltration",
				Description: "Exfiltrate data over HTTPS to C2 server",
				Technique:   "T1041",
				Tactic:      "exfiltration",
				Platform:    []string{"windows", "linux", "macos"},
				Execute:     Execute{Type: "http"},
			},
		},
	}
}

// secondCampaign builds a different campaign for multi-campaign tests.
func secondCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "lazarus-group",
			Adversary: "Lazarus Group",
			Severity:  "high",
			Tags:      []string{"financial", "destructive"},
		},
		Stages: []Stage{
			{
				ID:          "supply-chain",
				Name:        "Supply Chain Compromise",
				Description: "Compromise software distribution channel",
				Technique:   "T1195.002",
				Tactic:      "initial-access",
				Platform:    []string{"windows", "linux"},
				Execute:     Execute{Type: "shell"},
			},
			{
				ID:          "scripting",
				Name:        "Python Script Execution",
				Description: "Execute malicious Python script",
				Technique:   "T1059.006",
				Tactic:      "execution",
				Platform:    []string{"linux"},
				Execute:     Execute{Type: "shell"},
			},
		},
	}
}

func TestSearch_TechniqueExact(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Technique: "T1566.001"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Stage.ID != "initial-access" {
		t.Errorf("stage ID = %q, want %q", results[0].Stage.ID, "initial-access")
	}
	assertHasReason(t, results[0], "technique:")
}

func TestSearch_TechniquePrefix(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Technique: "T1059"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result for T1059 prefix, got %d", len(results))
	}
	if results[0].Stage.Technique != "T1059.001" {
		t.Errorf("technique = %q, want %q", results[0].Stage.Technique, "T1059.001")
	}
}

func TestSearch_TechniquePrefixMultiple(t *testing.T) {
	// Build a campaign where T1059 prefix matches multiple sub-techniques.
	c := &Campaign{
		Meta: Meta{Name: "multi-t1059"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059.001", Tactic: "execution", Execute: Execute{Type: "shell"}},
			{ID: "s2", Technique: "T1059.003", Tactic: "execution", Execute: Execute{Type: "shell"}},
			{ID: "s3", Technique: "T1059.006", Tactic: "execution", Execute: Execute{Type: "shell"}},
			{ID: "s4", Technique: "T1047", Tactic: "execution", Execute: Execute{Type: "shell"}},
		},
	}
	results := Search(c, SearchQuery{Technique: "T1059"})
	if len(results) != 3 {
		t.Fatalf("expected 3 results for T1059 prefix, got %d", len(results))
	}
}

func TestSearch_TechniquePrefixNoFalsePositive(t *testing.T) {
	// T105 should NOT match T1059.001 as a prefix (no dot boundary).
	// Actually T105 + "." = "T105." and "T1059.001" starts with "T105" but not "T105."
	// Wait — "T1059.001" does start with "T105." — hmm no, "T1059" starts with "T105"
	// but "T1059.001" starts with "T105" and the 4th char is "9" not ".".
	// Let me re-check: prefix = "T105.", stage = "T1059.001" → HasPrefix("T1059.001", "T105.") = false. Good.
	c := &Campaign{
		Meta: Meta{Name: "test"},
		Stages: []Stage{
			{ID: "s1", Technique: "T1059.001", Execute: Execute{Type: "shell"}},
		},
	}
	results := Search(c, SearchQuery{Technique: "T105"})
	if len(results) != 0 {
		t.Errorf("expected 0 results for T105 (no exact/prefix match), got %d", len(results))
	}
}

func TestSearch_Tactic(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Tactic: "execution"})
	if len(results) != 2 {
		t.Fatalf("expected 2 execution stages, got %d", len(results))
	}
	for _, r := range results {
		assertHasReason(t, r, "tactic:")
	}
}

func TestSearch_TacticCaseInsensitive(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Tactic: "EXECUTION"})
	if len(results) != 2 {
		t.Errorf("expected 2 results for case-insensitive tactic, got %d", len(results))
	}
}

func TestSearch_Adversary(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Adversary: "cozy"})
	if len(results) != len(c.Stages) {
		t.Fatalf("expected all %d stages (adversary is campaign-level), got %d", len(c.Stages), len(results))
	}
	assertHasReason(t, results[0], "adversary:")
}

func TestSearch_AdversaryNoMatch(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Adversary: "fin7"})
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSearch_Tag(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Tag: "espionage"})
	if len(results) != len(c.Stages) {
		t.Fatalf("expected all %d stages (tag is campaign-level), got %d", len(c.Stages), len(results))
	}
	assertHasReason(t, results[0], "tag:")
}

func TestSearch_TagCaseInsensitive(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Tag: "RUSSIA"})
	if len(results) != len(c.Stages) {
		t.Errorf("expected all stages for case-insensitive tag, got %d", len(results))
	}
}

func TestSearch_TagSubstring(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Tag: "supply"})
	if len(results) != len(c.Stages) {
		t.Errorf("expected all stages for tag substring, got %d", len(results))
	}
}

func TestSearch_KeywordCampaignName(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Keyword: "apt29"})
	if len(results) != len(c.Stages) {
		t.Fatalf("expected all stages (keyword in campaign name), got %d", len(results))
	}
	assertHasReason(t, results[0], "keyword:campaign-name")
}

func TestSearch_KeywordStageName(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Keyword: "PowerShell"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Stage.ID != "execution" {
		t.Errorf("stage ID = %q, want %q", results[0].Stage.ID, "execution")
	}
	assertHasReason(t, results[0], "keyword:stage-name")
}

func TestSearch_KeywordDescription(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Keyword: "weaponized"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	assertHasReason(t, results[0], "keyword:description")
}

func TestSearch_KeywordStageID(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Keyword: "exfiltration"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Stage.ID != "exfiltration" {
		t.Errorf("stage ID = %q, want %q", results[0].Stage.ID, "exfiltration")
	}
}

func TestSearch_Severity(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Severity: "critical"})
	if len(results) != len(c.Stages) {
		t.Fatalf("expected all %d stages (severity is campaign-level), got %d", len(c.Stages), len(results))
	}
	assertHasReason(t, results[0], "severity:")
}

func TestSearch_SeverityNoMatch(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Severity: "low"})
	if len(results) != 0 {
		t.Errorf("expected 0 results for severity=low, got %d", len(results))
	}
}

func TestSearch_StageIDExact(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{StageID: "persistence"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Stage.ID != "persistence" {
		t.Errorf("stage ID = %q, want %q", results[0].Stage.ID, "persistence")
	}
	assertHasReason(t, results[0], "stage-id:")
}

func TestSearch_StageIDContains(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{StageID: "lateral"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Stage.ID != "lateral-movement" {
		t.Errorf("stage ID = %q, want %q", results[0].Stage.ID, "lateral-movement")
	}
}

func TestSearch_Platform(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Platform: "macos"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result for macos, got %d", len(results))
	}
	if results[0].Stage.ID != "exfiltration" {
		t.Errorf("stage ID = %q, want %q", results[0].Stage.ID, "exfiltration")
	}
	assertHasReason(t, results[0], "platform:")
}

func TestSearch_PlatformWindows(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Platform: "windows"})
	if len(results) != 5 {
		t.Errorf("expected 5 windows stages, got %d", len(results))
	}
}

func TestSearch_ExecType(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{ExecType: "http"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result for http, got %d", len(results))
	}
	if results[0].Stage.ID != "exfiltration" {
		t.Errorf("stage ID = %q, want %q", results[0].Stage.ID, "exfiltration")
	}
	assertHasReason(t, results[0], "exec-type:")
}

func TestSearch_ExecTypeRegistry(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{ExecType: "registry"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result for registry, got %d", len(results))
	}
	if results[0].Stage.ID != "persistence" {
		t.Errorf("stage ID = %q, want %q", results[0].Stage.ID, "persistence")
	}
}

func TestSearch_MultiFieldAND(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Technique: "T1059", Tactic: "execution"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result for T1059+execution, got %d", len(results))
	}
	if results[0].Stage.Technique != "T1059.001" {
		t.Errorf("technique = %q, want %q", results[0].Stage.Technique, "T1059.001")
	}
	assertHasReason(t, results[0], "technique:")
	assertHasReason(t, results[0], "tactic:")
}

func TestSearch_MultiFieldAND_TechniqueAndPlatform(t *testing.T) {
	c := searchTestCampaign()
	// T1041 is on exfiltration stage which has linux.
	results := Search(c, SearchQuery{Technique: "T1041", Platform: "linux"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	assertHasReason(t, results[0], "technique:")
	assertHasReason(t, results[0], "platform:")
}

func TestSearch_MultiFieldAND_NoOverlap(t *testing.T) {
	c := searchTestCampaign()
	// T1041 is exfiltration tactic, not execution — should return 0.
	results := Search(c, SearchQuery{Technique: "T1041", Tactic: "execution"})
	if len(results) != 0 {
		t.Errorf("expected 0 results for non-overlapping AND, got %d", len(results))
	}
}

func TestSearch_EmptyQuery(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{})
	if len(results) != len(c.Stages) {
		t.Errorf("expected all %d stages for empty query, got %d", len(c.Stages), len(results))
	}
}

func TestSearch_NoMatches(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{Technique: "T9999"})
	if len(results) != 0 {
		t.Errorf("expected 0 results for nonexistent technique, got %d", len(results))
	}
}

func TestSearch_CampaignNameSet(t *testing.T) {
	c := searchTestCampaign()
	results := Search(c, SearchQuery{})
	for _, r := range results {
		if r.CampaignName != "apt29-cozy-bear" {
			t.Errorf("CampaignName = %q, want %q", r.CampaignName, "apt29-cozy-bear")
		}
	}
}

func TestSearchDir(t *testing.T) {
	dir := t.TempDir()

	// Create two campaign subdirectories.
	writeTestCampaignYAML(t, dir, "apt29", `
api_version: v1
kind: Campaign
meta:
  name: apt29-cozy-bear
  adversary: APT29
  severity: critical
  tags: [espionage]
  created: "2026-01-01"
  modified: "2026-01-01"
stages:
  - id: phish
    name: Spearphishing
    technique: T1566.001
    tactic: initial-access
    platform: [windows]
    execute:
      type: shell
  - id: exec
    name: PowerShell
    technique: T1059.001
    tactic: execution
    platform: [windows]
    execute:
      type: shell
`)

	writeTestCampaignYAML(t, dir, "lazarus", `
api_version: v1
kind: Campaign
meta:
  name: lazarus-group
  adversary: Lazarus Group
  severity: high
  tags: [financial]
  created: "2026-01-01"
  modified: "2026-01-01"
stages:
  - id: supply-chain
    name: Supply Chain
    technique: T1195.002
    tactic: initial-access
    platform: [linux]
    execute:
      type: shell
`)

	// Search across both campaigns.
	results, err := SearchDir(dir, SearchQuery{Tactic: "initial-access"})
	if err != nil {
		t.Fatalf("SearchDir error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 initial-access results across campaigns, got %d", len(results))
	}

	// Verify campaign files are set.
	for _, r := range results {
		if r.CampaignFile == "" {
			t.Error("CampaignFile should be set by SearchDir")
		}
	}
}

func TestSearchDir_TechniquePrefix(t *testing.T) {
	dir := t.TempDir()
	writeTestCampaignYAML(t, dir, "multi", `
api_version: v1
kind: Campaign
meta:
  name: multi-technique
  adversary: TestActor
  severity: medium
  created: "2026-01-01"
  modified: "2026-01-01"
stages:
  - id: s1
    name: Stage One
    technique: T1059.001
    tactic: execution
    execute:
      type: shell
  - id: s2
    name: Stage Two
    technique: T1059.003
    tactic: execution
    execute:
      type: shell
  - id: s3
    name: Stage Three
    technique: T1190
    tactic: initial-access
    execute:
      type: shell
`)

	results, err := SearchDir(dir, SearchQuery{Technique: "T1059"})
	if err != nil {
		t.Fatalf("SearchDir error: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results for T1059 prefix, got %d", len(results))
	}
}

func TestSearchDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	results, err := SearchDir(dir, SearchQuery{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty dir, got %d", len(results))
	}
}

func TestSearchDir_NonexistentDir(t *testing.T) {
	_, err := SearchDir("/nonexistent/path/for/test", SearchQuery{})
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

func TestFormatSearchResults_NonEmpty(t *testing.T) {
	results := []SearchResult{
		{
			CampaignName: "apt29-cozy-bear",
			Stage:        Stage{ID: "initial-access", Technique: "T1566.001", Tactic: "initial-access"},
			MatchReasons: []string{"technique:T1566.001"},
		},
		{
			CampaignName: "lazarus-group",
			Stage:        Stage{ID: "supply-chain", Technique: "T1195.002", Tactic: "initial-access"},
			MatchReasons: []string{"tactic:initial-access"},
		},
	}

	out := FormatSearchResults(results)
	if len(out) == 0 {
		t.Fatal("FormatSearchResults returned empty string")
	}
	if !strings.Contains(out, "apt29-cozy-bear") {
		t.Error("output should contain campaign name apt29-cozy-bear")
	}
	if !strings.Contains(out, "lazarus-group") {
		t.Error("output should contain campaign name lazarus-group")
	}
	if !strings.Contains(out, "T1566.001") {
		t.Error("output should contain technique T1566.001")
	}
	if !strings.Contains(out, "technique:T1566.001") {
		t.Error("output should contain match reason")
	}
	if !strings.Contains(out, "Campaign") {
		t.Error("output should contain header")
	}
	if !strings.Contains(out, "─") {
		t.Error("output should contain separator line")
	}
}

func TestFormatSearchResults_Empty(t *testing.T) {
	out := FormatSearchResults(nil)
	if !strings.Contains(out, "No results") {
		t.Error("empty results should say 'No results'")
	}
}

// --- helpers ---

func writeTestCampaignYAML(t *testing.T, baseDir, name, content string) {
	t.Helper()
	dir := filepath.Join(baseDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "campaign.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write campaign.yaml: %v", err)
	}
}

func assertHasReason(t *testing.T, r SearchResult, prefix string) {
	t.Helper()
	for _, reason := range r.MatchReasons {
		if strings.HasPrefix(reason, prefix) {
			return
		}
	}
	t.Errorf("expected a match reason starting with %q in %v", prefix, r.MatchReasons)
}
