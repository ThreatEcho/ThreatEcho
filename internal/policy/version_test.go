// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// testVersionPolicy builds a minimal valid policy for version testing.
// denyRule, allowRule, alertRule helpers are defined in trace_test.go.
func testVersionPolicy(name string, rules []Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: name, Description: "test policy"},
		Agent:      AgentScope{Name: "test-agent"},
		Rules:      rules,
	}
}

// ---------------------------------------------------------------------------
// NewHistory
// ---------------------------------------------------------------------------

func TestNewHistory(t *testing.T) {
	p := testVersionPolicy("my-policy", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p, "alice", "initial version")

	if h == nil {
		t.Fatal("NewHistory returned nil")
	}
	if len(h.Versions) != 1 {
		t.Fatalf("Versions count = %d, want 1", len(h.Versions))
	}
	if h.PolicyName != "my-policy" {
		t.Errorf("PolicyName = %q, want %q", h.PolicyName, "my-policy")
	}
	if h.Current != 0 {
		t.Errorf("Current = %d, want 0", h.Current)
	}

	v := h.Versions[0]
	if v.Author != "alice" {
		t.Errorf("Author = %q, want %q", v.Author, "alice")
	}
	if v.Comment != "initial version" {
		t.Errorf("Comment = %q, want %q", v.Comment, "initial version")
	}
	if v.Policy != p {
		t.Error("Policy pointer mismatch")
	}
	if v.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestNewHistory_VersionOne(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 10, []string{"*"}),
	})
	h := NewHistory(p, "bob", "init")

	if h.Versions[0].Version != 1 {
		t.Errorf("first version number = %d, want 1", h.Versions[0].Version)
	}
}

func TestNewHistory_Fingerprint(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 10, []string{"*"}),
	})
	h := NewHistory(p, "alice", "init")

	fp := h.Versions[0].Fingerprint
	if fp == "" {
		t.Fatal("Fingerprint should not be empty")
	}
	// SHA256 hex should be 64 characters.
	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64 (SHA256 hex)", len(fp))
	}
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Fingerprint contains non-hex char %q", string(c))
			break
		}
	}
}

// ---------------------------------------------------------------------------
// AddVersion
// ---------------------------------------------------------------------------

func TestAddVersion_IncreasesVersion(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p1, "alice", "v1")

	p2 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
	})
	ver := h.AddVersion(p2, "bob", "add allow rule")

	if ver != 2 {
		t.Errorf("AddVersion returned %d, want 2", ver)
	}
	if h.Versions[1].Version != 2 {
		t.Errorf("second version number = %d, want 2", h.Versions[1].Version)
	}
}

func TestAddVersion_UpdatesCurrent(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"*"}),
	})
	h := NewHistory(p, "alice", "init")
	if h.Current != 0 {
		t.Fatalf("Current after NewHistory = %d, want 0", h.Current)
	}

	h.AddVersion(p, "bob", "v2")
	if h.Current != 1 {
		t.Errorf("Current after first AddVersion = %d, want 1", h.Current)
	}

	h.AddVersion(p, "charlie", "v3")
	if h.Current != 2 {
		t.Errorf("Current after second AddVersion = %d, want 2", h.Current)
	}
}

func TestAddVersion_MultipleVersions(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p, "alice", "v1")

	h.AddVersion(p, "bob", "v2")
	h.AddVersion(p, "charlie", "v3")

	if len(h.Versions) != 3 {
		t.Fatalf("Versions count = %d, want 3", len(h.Versions))
	}
	for i, v := range h.Versions {
		expected := i + 1
		if v.Version != expected {
			t.Errorf("Versions[%d].Version = %d, want %d", i, v.Version, expected)
		}
	}
	if h.Versions[0].Author != "alice" {
		t.Errorf("v1 author = %q, want alice", h.Versions[0].Author)
	}
	if h.Versions[1].Author != "bob" {
		t.Errorf("v2 author = %q, want bob", h.Versions[1].Author)
	}
	if h.Versions[2].Author != "charlie" {
		t.Errorf("v3 author = %q, want charlie", h.Versions[2].Author)
	}
}

// ---------------------------------------------------------------------------
// GetVersion
// ---------------------------------------------------------------------------

func TestGetVersion_Found(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "first", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p1, "alice", "v1")

	p2 := testVersionPolicy("p", []Rule{
		denyRule("r1", "second", 100, []string{"shell_exec"}),
	})
	h.AddVersion(p2, "bob", "v2")

	v, ok := h.GetVersion(2)
	if !ok {
		t.Fatal("GetVersion(2) should return true")
	}
	if v.Version != 2 {
		t.Errorf("Version = %d, want 2", v.Version)
	}
	if v.Author != "bob" {
		t.Errorf("Author = %q, want bob", v.Author)
	}
}

func TestGetVersion_NotFound(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"*"}),
	})
	h := NewHistory(p, "alice", "init")

	_, ok := h.GetVersion(99)
	if ok {
		t.Error("GetVersion(99) should return false for non-existent version")
	}

	_, ok = h.GetVersion(0)
	if ok {
		t.Error("GetVersion(0) should return false")
	}

	_, ok = h.GetVersion(-1)
	if ok {
		t.Error("GetVersion(-1) should return false")
	}
}

func TestGetVersion_FirstVersion(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "the first", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p, "alice", "init")
	h.AddVersion(p, "bob", "v2")
	h.AddVersion(p, "charlie", "v3")

	v, ok := h.GetVersion(1)
	if !ok {
		t.Fatal("GetVersion(1) should return true")
	}
	if v.Version != 1 {
		t.Errorf("Version = %d, want 1", v.Version)
	}
	if v.Author != "alice" {
		t.Errorf("Author = %q, want alice", v.Author)
	}
	if v.Comment != "init" {
		t.Errorf("Comment = %q, want init", v.Comment)
	}
}

// ---------------------------------------------------------------------------
// DiffVersions
// ---------------------------------------------------------------------------

func TestDiffVersions_ValidDiff(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p1, "alice", "v1")

	p2 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
		alertRule("r2", "new alert", 50, []string{"dns_query"}),
	})
	h.AddVersion(p2, "bob", "add alert")

	vd, err := h.DiffVersions(1, 2)
	if err != nil {
		t.Fatalf("DiffVersions: %v", err)
	}
	if vd.OldVersion != 1 {
		t.Errorf("OldVersion = %d, want 1", vd.OldVersion)
	}
	if vd.NewVersion != 2 {
		t.Errorf("NewVersion = %d, want 2", vd.NewVersion)
	}
	if vd.Diff == nil {
		t.Fatal("Diff should not be nil")
	}
	if vd.Diff.Summary.RulesAdded != 1 {
		t.Errorf("RulesAdded = %d, want 1", vd.Diff.Summary.RulesAdded)
	}
	if vd.Author != "bob" {
		t.Errorf("Author = %q, want bob", vd.Author)
	}
}

func TestDiffVersions_OldNotFound(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"*"}),
	})
	h := NewHistory(p, "alice", "init")

	_, err := h.DiffVersions(99, 1)
	if err == nil {
		t.Fatal("DiffVersions with invalid old version should error")
	}
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("error should mention version 99, got: %v", err)
	}
}

func TestDiffVersions_NewNotFound(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"*"}),
	})
	h := NewHistory(p, "alice", "init")

	_, err := h.DiffVersions(1, 42)
	if err == nil {
		t.Fatal("DiffVersions with invalid new version should error")
	}
	if !strings.Contains(err.Error(), "42") {
		t.Errorf("error should mention version 42, got: %v", err)
	}
}

func TestDiffVersions_SameVersion(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p, "alice", "v1")
	// Add a second version with the same policy to test diffing version 1 against itself.
	h.AddVersion(p, "alice", "same policy")

	vd, err := h.DiffVersions(1, 2)
	if err != nil {
		t.Fatalf("DiffVersions: %v", err)
	}
	if !vd.Diff.Summary.IsIdentical {
		t.Error("diff of same policy across versions should be marked identical")
	}
	if vd.Diff.Summary.TotalChanges != 0 {
		t.Errorf("TotalChanges = %d, want 0", vd.Diff.Summary.TotalChanges)
	}
}

func TestDiffVersions_RuleAdded(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p1, "alice", "v1")

	p2 := testVersionPolicy("p", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
		alertRule("r2", "monitor dns", 50, []string{"dns_query"}),
		allowRule("r3", "allow reads", 10, []string{"file_read"}),
	})
	h.AddVersion(p2, "bob", "add two rules")

	vd, err := h.DiffVersions(1, 2)
	if err != nil {
		t.Fatalf("DiffVersions: %v", err)
	}
	if len(vd.Diff.AddedRules) != 2 {
		t.Errorf("AddedRules count = %d, want 2", len(vd.Diff.AddedRules))
	}
	if vd.Diff.Summary.RulesAdded != 2 {
		t.Errorf("RulesAdded = %d, want 2", vd.Diff.Summary.RulesAdded)
	}
	if len(vd.Diff.RemovedRules) != 0 {
		t.Errorf("RemovedRules count = %d, want 0", len(vd.Diff.RemovedRules))
	}
}

func TestDiffVersions_RuleRemoved(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
		alertRule("r2", "monitor dns", 50, []string{"dns_query"}),
		allowRule("r3", "allow reads", 10, []string{"file_read"}),
	})
	h := NewHistory(p1, "alice", "v1")

	p2 := testVersionPolicy("p", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
	})
	h.AddVersion(p2, "bob", "strip rules")

	vd, err := h.DiffVersions(1, 2)
	if err != nil {
		t.Fatalf("DiffVersions: %v", err)
	}
	if len(vd.Diff.RemovedRules) != 2 {
		t.Errorf("RemovedRules count = %d, want 2", len(vd.Diff.RemovedRules))
	}
	if vd.Diff.Summary.RulesRemoved != 2 {
		t.Errorf("RulesRemoved = %d, want 2", vd.Diff.Summary.RulesRemoved)
	}
	if len(vd.Diff.AddedRules) != 0 {
		t.Errorf("AddedRules count = %d, want 0", len(vd.Diff.AddedRules))
	}
}

// ---------------------------------------------------------------------------
// GetStats
// ---------------------------------------------------------------------------

func TestGetStats_EmptyHistory(t *testing.T) {
	h := &PolicyHistory{
		PolicyName: "empty",
		Versions:   nil,
	}
	stats := h.GetStats()

	if stats.TotalVersions != 0 {
		t.Errorf("TotalVersions = %d, want 0", stats.TotalVersions)
	}
	if stats.UniqueAuthors != 0 {
		t.Errorf("UniqueAuthors = %d, want 0", stats.UniqueAuthors)
	}
	if stats.BreakingChanges != 0 {
		t.Errorf("BreakingChanges = %d, want 0", stats.BreakingChanges)
	}
	if stats.FirstVersion != "" {
		t.Errorf("FirstVersion = %q, want empty", stats.FirstVersion)
	}
	if stats.LatestVersion != "" {
		t.Errorf("LatestVersion = %q, want empty", stats.LatestVersion)
	}
}

func TestGetStats_SingleVersion(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
	})
	h := NewHistory(p, "alice", "init")

	stats := h.GetStats()

	if stats.TotalVersions != 1 {
		t.Errorf("TotalVersions = %d, want 1", stats.TotalVersions)
	}
	if stats.UniqueAuthors != 1 {
		t.Errorf("UniqueAuthors = %d, want 1", stats.UniqueAuthors)
	}
	if stats.AvgRulesPerVersion != 2.0 {
		t.Errorf("AvgRulesPerVersion = %f, want 2.0", stats.AvgRulesPerVersion)
	}
	if stats.TotalRuleChanges != 0 {
		t.Errorf("TotalRuleChanges = %d, want 0 (single version)", stats.TotalRuleChanges)
	}
	if stats.BreakingChanges != 0 {
		t.Errorf("BreakingChanges = %d, want 0", stats.BreakingChanges)
	}
	if stats.FirstVersion == "" {
		t.Error("FirstVersion should not be empty")
	}
	if stats.LatestVersion == "" {
		t.Error("LatestVersion should not be empty")
	}
}

func TestGetStats_MultipleVersions(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p1, "alice", "v1")

	p2 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
		alertRule("r2", "", 50, []string{"dns_query"}),
	})
	h.AddVersion(p2, "bob", "v2")

	p3 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
		alertRule("r2", "", 50, []string{"dns_query"}),
		allowRule("r3", "", 10, []string{"file_read"}),
	})
	h.AddVersion(p3, "charlie", "v3")

	stats := h.GetStats()

	if stats.TotalVersions != 3 {
		t.Errorf("TotalVersions = %d, want 3", stats.TotalVersions)
	}
	if stats.UniqueAuthors != 3 {
		t.Errorf("UniqueAuthors = %d, want 3", stats.UniqueAuthors)
	}
	// v1=1 rule, v2=2 rules, v3=3 rules -> avg = 6/3 = 2.0
	if stats.AvgRulesPerVersion != 2.0 {
		t.Errorf("AvgRulesPerVersion = %f, want 2.0", stats.AvgRulesPerVersion)
	}
	// v1->v2: 1 added, v2->v3: 1 added = 2 total changes
	if stats.TotalRuleChanges != 2 {
		t.Errorf("TotalRuleChanges = %d, want 2", stats.TotalRuleChanges)
	}
	if stats.FirstVersion == "" {
		t.Error("FirstVersion should not be empty")
	}
	if stats.LatestVersion == "" {
		t.Error("LatestVersion should not be empty")
	}
}

func TestGetStats_UniqueAuthors(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"*"}),
	})
	h := NewHistory(p, "alice", "v1")
	h.AddVersion(p, "bob", "v2")
	// alice again -- should not increase unique count.
	h.AddVersion(p, "alice", "v3")

	stats := h.GetStats()
	if stats.UniqueAuthors != 2 {
		t.Errorf("UniqueAuthors = %d, want 2 (alice, bob)", stats.UniqueAuthors)
	}
}

func TestGetStats_BreakingChanges(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
		denyRule("r2", "", 90, []string{"http_request"}),
	})
	h := NewHistory(p1, "alice", "strict")

	// v2: remove r2 (breaking -- removing a deny rule).
	p2 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
	})
	h.AddVersion(p2, "bob", "remove http deny")

	// v3: change r1 deny->allow (breaking).
	p3 := testVersionPolicy("p", []Rule{
		allowRule("r1", "", 100, []string{"shell_exec"}),
	})
	h.AddVersion(p3, "charlie", "relax shell")

	stats := h.GetStats()

	if stats.BreakingChanges != 2 {
		t.Errorf("BreakingChanges = %d, want 2", stats.BreakingChanges)
	}
}

// ---------------------------------------------------------------------------
// JSON round-trip
// ---------------------------------------------------------------------------

func TestHistoryJSON_RoundTrip(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p1, "alice", "initial")

	p2 := testVersionPolicy("p", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
		alertRule("r2", "alert dns", 50, []string{"dns_query"}),
	})
	h.AddVersion(p2, "bob", "add dns alert")

	data, err := HistoryToJSON(h)
	if err != nil {
		t.Fatalf("HistoryToJSON: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("JSON output should not be empty")
	}

	h2, err := HistoryFromJSON(data)
	if err != nil {
		t.Fatalf("HistoryFromJSON: %v", err)
	}

	if h2.PolicyName != h.PolicyName {
		t.Errorf("PolicyName = %q, want %q", h2.PolicyName, h.PolicyName)
	}
	if len(h2.Versions) != len(h.Versions) {
		t.Fatalf("Versions count = %d, want %d", len(h2.Versions), len(h.Versions))
	}
	if h2.Current != h.Current {
		t.Errorf("Current = %d, want %d", h2.Current, h.Current)
	}

	for i := range h.Versions {
		if h2.Versions[i].Version != h.Versions[i].Version {
			t.Errorf("Version[%d] = %d, want %d", i, h2.Versions[i].Version, h.Versions[i].Version)
		}
		if h2.Versions[i].Author != h.Versions[i].Author {
			t.Errorf("Author[%d] = %q, want %q", i, h2.Versions[i].Author, h.Versions[i].Author)
		}
		if h2.Versions[i].Comment != h.Versions[i].Comment {
			t.Errorf("Comment[%d] = %q, want %q", i, h2.Versions[i].Comment, h.Versions[i].Comment)
		}
		if h2.Versions[i].Fingerprint != h.Versions[i].Fingerprint {
			t.Errorf("Fingerprint[%d] = %q, want %q", i, h2.Versions[i].Fingerprint, h.Versions[i].Fingerprint)
		}
	}

	// Verify rules survived the round-trip.
	if h2.Versions[0].Policy == nil {
		t.Fatal("Deserialized v1 policy should not be nil")
	}
	if len(h2.Versions[0].Policy.Rules) != 1 {
		t.Errorf("Deserialized v1 rules count = %d, want 1", len(h2.Versions[0].Policy.Rules))
	}
	if h2.Versions[1].Policy == nil {
		t.Fatal("Deserialized v2 policy should not be nil")
	}
	if len(h2.Versions[1].Policy.Rules) != 2 {
		t.Errorf("Deserialized v2 rules count = %d, want 2", len(h2.Versions[1].Policy.Rules))
	}
}

func TestHistoryJSON_InvalidJSON(t *testing.T) {
	_, err := HistoryFromJSON([]byte("not json"))
	if err == nil {
		t.Error("HistoryFromJSON should error on invalid JSON")
	}

	_, err = HistoryFromJSON([]byte("{truncated"))
	if err == nil {
		t.Error("HistoryFromJSON should error on truncated JSON")
	}

	_, err = HistoryFromJSON([]byte(""))
	if err == nil {
		t.Error("HistoryFromJSON should error on empty input")
	}
}

// ---------------------------------------------------------------------------
// FormatHistory
// ---------------------------------------------------------------------------

func TestFormatHistory(t *testing.T) {
	p := testVersionPolicy("agent-firewall", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p, "alice", "initial")
	h.AddVersion(p, "bob", "reviewed")

	out := FormatHistory(h)

	if !strings.Contains(out, "Policy History") {
		t.Error("output should contain 'Policy History' header")
	}
	if !strings.Contains(out, "agent-firewall") {
		t.Error("output should contain the policy name")
	}
	if !strings.Contains(out, "v1") {
		t.Error("output should contain version marker v1")
	}
	if !strings.Contains(out, "v2") {
		t.Error("output should contain version marker v2")
	}
	if !strings.Contains(out, "2 version(s)") {
		t.Error("output should show version count")
	}
}

func TestFormatHistory_CurrentMarker(t *testing.T) {
	p := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"*"}),
	})
	h := NewHistory(p, "alice", "init")
	h.AddVersion(p, "bob", "v2")
	h.AddVersion(p, "charlie", "v3")

	out := FormatHistory(h)

	if !strings.Contains(out, "►") {
		t.Error("output should contain current version marker (unicode right pointer)")
	}

	// The current marker should appear on the last (current) version line.
	lines := strings.Split(out, "\n")
	foundMarkerOnCurrent := false
	for _, line := range lines {
		if strings.Contains(line, "►") && strings.Contains(line, "v3") {
			foundMarkerOnCurrent = true
			break
		}
	}
	if !foundMarkerOnCurrent {
		t.Error("current marker should appear on v3 (the latest version)")
	}
}

func TestFormatHistory_BreakingMarker(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p1, "alice", "strict")

	p2 := testVersionPolicy("p", []Rule{
		allowRule("r1", "", 100, []string{"shell_exec"}),
	})
	h.AddVersion(p2, "bob", "relax")

	out := FormatHistory(h)

	if !strings.Contains(out, "BREAKING") {
		t.Error("output should show BREAKING marker for deny->allow change")
	}
	if !strings.Contains(out, "⚠") {
		t.Error("output should contain warning sign for breaking change")
	}
}

// ---------------------------------------------------------------------------
// FormatVersionDiff
// ---------------------------------------------------------------------------

func TestFormatVersionDiff(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p1, "alice", "v1")

	p2 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
		allowRule("r2", "", 10, []string{"file_read"}),
	})
	h.AddVersion(p2, "bob", "add allow")

	vd, err := h.DiffVersions(1, 2)
	if err != nil {
		t.Fatalf("DiffVersions: %v", err)
	}

	out := FormatVersionDiff(vd)

	if !strings.Contains(out, "Version Diff") {
		t.Error("output should contain 'Version Diff' header")
	}
	if !strings.Contains(out, "v1") {
		t.Error("output should reference v1")
	}
	if !strings.Contains(out, "v2") {
		t.Error("output should reference v2")
	}
	if !strings.Contains(out, "bob") {
		t.Error("output should show author")
	}
}

func TestFormatVersionDiff_WithComment(t *testing.T) {
	p1 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
	})
	h := NewHistory(p1, "alice", "v1")

	p2 := testVersionPolicy("p", []Rule{
		denyRule("r1", "", 100, []string{"shell_exec"}),
		alertRule("r2", "new monitor", 50, []string{"dns_query"}),
	})
	h.AddVersion(p2, "bob", "added DNS monitoring rule per SOC request")

	vd, err := h.DiffVersions(1, 2)
	if err != nil {
		t.Fatalf("DiffVersions: %v", err)
	}

	out := FormatVersionDiff(vd)

	if !strings.Contains(out, "added DNS monitoring rule per SOC request") {
		t.Error("output should include the version comment")
	}
	if !strings.Contains(out, "Note:") {
		t.Error("output should contain 'Note:' label for the comment")
	}
}

// ---------------------------------------------------------------------------
// policyFingerprint
// ---------------------------------------------------------------------------

func TestPolicyFingerprint_Deterministic(t *testing.T) {
	p := testVersionPolicy("deterministic-test", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
		allowRule("r2", "allow reads", 10, []string{"file_read"}),
	})

	fp1 := policyFingerprint(p)
	fp2 := policyFingerprint(p)
	fp3 := policyFingerprint(p)

	if fp1 != fp2 {
		t.Errorf("Fingerprint not deterministic: %q vs %q", fp1, fp2)
	}
	if fp2 != fp3 {
		t.Errorf("Fingerprint not deterministic: %q vs %q", fp2, fp3)
	}
}

func TestPolicyFingerprint_DifferentPolicies(t *testing.T) {
	p1 := testVersionPolicy("policy-a", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
	})
	p2 := testVersionPolicy("policy-b", []Rule{
		allowRule("r1", "allow shell", 100, []string{"shell_exec"}),
	})

	fp1 := policyFingerprint(p1)
	fp2 := policyFingerprint(p2)

	if fp1 == fp2 {
		t.Errorf("Different policies should produce different fingerprints: both = %q", fp1)
	}

	// Also test that adding a rule changes the fingerprint.
	p3 := testVersionPolicy("policy-a", []Rule{
		denyRule("r1", "block shell", 100, []string{"shell_exec"}),
		alertRule("r2", "monitor dns", 50, []string{"dns_query"}),
	})
	fp3 := policyFingerprint(p3)
	if fp1 == fp3 {
		t.Error("Adding a rule should change the fingerprint")
	}
}

// ---------------------------------------------------------------------------
// Verify encoding/json import is exercised beyond HistoryToJSON/FromJSON.
// ---------------------------------------------------------------------------

func TestHistoryJSON_StructTags(t *testing.T) {
	// Verify that the JSON struct tags produce the expected field names.
	p := testVersionPolicy("tag-test", []Rule{
		denyRule("r1", "", 100, []string{"*"}),
	})
	h := NewHistory(p, "alice", "init")

	data, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	s := string(data)

	expectedFields := []string{
		`"policy_name"`,
		`"versions"`,
		`"current"`,
		`"version"`,
		`"timestamp"`,
		`"author"`,
		`"comment"`,
		`"fingerprint"`,
	}
	for _, f := range expectedFields {
		if !strings.Contains(s, f) {
			t.Errorf("JSON output missing expected field %s", f)
		}
	}
}
