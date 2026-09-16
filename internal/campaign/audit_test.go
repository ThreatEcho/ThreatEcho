// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// --- helpers ---

func auditTestCampaign(name, severity string, stages []Stage) *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:         name,
			Adversary:    "TestActor",
			Severity:     severity,
			MitreVersion: "15.1",
		},
		Stages: stages,
	}
}

func testStages() []Stage {
	return []Stage{
		{
			ID:        "recon",
			Name:      "Network Scan",
			Technique: "T1016",
			Tactic:    "discovery",
			Execute:   Execute{Type: "shell"},
		},
		{
			ID:        "access",
			Name:      "Initial Access",
			Technique: "T1190",
			Tactic:    "initial-access",
			DependsOn: []string{"recon"},
			Execute:   Execute{Type: "shell"},
		},
	}
}

func twoCampaigns() []*Campaign {
	return []*Campaign{
		auditTestCampaign("alpha", "high", testStages()),
		auditTestCampaign("bravo", "medium", []Stage{
			{
				ID:        "exfil",
				Name:      "Data Exfil",
				Technique: "T1041",
				Tactic:    "exfiltration",
				Execute:   Execute{Type: "http"},
			},
		}),
	}
}

// --- TakeSnapshot tests ---

func TestTakeSnapshot_Basic(t *testing.T) {
	camps := twoCampaigns()
	snap := TakeSnapshot(camps)

	if snap.CampaignCount != 2 {
		t.Errorf("CampaignCount = %d, want 2", snap.CampaignCount)
	}
	if snap.TotalStages != 3 {
		t.Errorf("TotalStages = %d, want 3", snap.TotalStages)
	}
	if snap.Timestamp == "" {
		t.Error("Timestamp is empty")
	}
}

func TestTakeSnapshot_CampaignsSortedByName(t *testing.T) {
	// Pass in reverse order to verify sorting.
	camps := []*Campaign{
		auditTestCampaign("zulu", "low", nil),
		auditTestCampaign("alpha", "low", nil),
		auditTestCampaign("mike", "low", nil),
	}
	snap := TakeSnapshot(camps)

	names := make([]string, len(snap.Campaigns))
	for i, cs := range snap.Campaigns {
		names[i] = cs.Name
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("campaigns not sorted by name: %v", names)
	}
}

func TestTakeSnapshot_HashIsFingerprint(t *testing.T) {
	c := testCampaign("hashtest", "high", testStages())
	snap := TakeSnapshot([]*Campaign{c})

	expected := Fingerprint(c)
	if snap.Campaigns[0].Hash != expected {
		t.Errorf("Hash = %q, want Fingerprint %q", snap.Campaigns[0].Hash, expected)
	}
}

func TestTakeSnapshot_TechniquesSorted(t *testing.T) {
	c := testCampaign("techsort", "low", []Stage{
		{ID: "s1", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1016", Tactic: "discovery", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
	})
	snap := TakeSnapshot([]*Campaign{c})

	techs := snap.Campaigns[0].Techniques
	if !sort.StringsAreSorted(techs) {
		t.Errorf("techniques not sorted: %v", techs)
	}
}

func TestTakeSnapshot_TacticsSortedAndUnique(t *testing.T) {
	c := testCampaign("tacsort", "low", []Stage{
		{ID: "s1", Technique: "T1016", Tactic: "discovery", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1018", Tactic: "discovery", Execute: Execute{Type: "shell"}},
		{ID: "s3", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
	})
	snap := TakeSnapshot([]*Campaign{c})

	tactics := snap.Campaigns[0].Tactics
	if !sort.StringsAreSorted(tactics) {
		t.Errorf("tactics not sorted: %v", tactics)
	}
	// Should be deduplicated.
	seen := make(map[string]bool)
	for _, tac := range tactics {
		if seen[tac] {
			t.Errorf("duplicate tactic: %s", tac)
		}
		seen[tac] = true
	}
}

func TestTakeSnapshot_EmptyInput(t *testing.T) {
	snap := TakeSnapshot(nil)
	if snap.CampaignCount != 0 {
		t.Errorf("CampaignCount = %d, want 0", snap.CampaignCount)
	}
	if snap.TotalStages != 0 {
		t.Errorf("TotalStages = %d, want 0", snap.TotalStages)
	}
	if len(snap.Campaigns) != 0 {
		t.Errorf("Campaigns = %d, want 0", len(snap.Campaigns))
	}
}

func TestTakeSnapshot_SeverityPreserved(t *testing.T) {
	c := testCampaign("severity-test", "critical", testStages())
	snap := TakeSnapshot([]*Campaign{c})

	if snap.Campaigns[0].Severity != "critical" {
		t.Errorf("Severity = %q, want %q", snap.Campaigns[0].Severity, "critical")
	}
}

// --- TakeSnapshotDir tests ---

func TestTakeSnapshotDir_ValidDir(t *testing.T) {
	snap, err := TakeSnapshotDir("testdata")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snap.CampaignCount == 0 {
		t.Fatal("expected at least one campaign from testdata")
	}
	found := false
	for _, cs := range snap.Campaigns {
		if cs.Name == "test-campaign" {
			found = true
			break
		}
	}
	if !found {
		t.Error("test-campaign not found in snapshot")
	}
}

func TestTakeSnapshotDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	snap, err := TakeSnapshotDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snap.CampaignCount != 0 {
		t.Errorf("CampaignCount = %d, want 0", snap.CampaignCount)
	}
}

func TestTakeSnapshotDir_NonexistentDir(t *testing.T) {
	_, err := TakeSnapshotDir(filepath.Join(os.TempDir(), "nonexistent-audit-dir"))
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

// --- DiffSnapshots tests ---

func TestDiffSnapshots_NoDifference(t *testing.T) {
	camps := twoCampaigns()
	snap := TakeSnapshot(camps)
	diff := DiffSnapshots(snap, snap)

	if len(diff.Added) != 0 {
		t.Errorf("Added = %d, want 0", len(diff.Added))
	}
	if len(diff.Removed) != 0 {
		t.Errorf("Removed = %d, want 0", len(diff.Removed))
	}
	if len(diff.Modified) != 0 {
		t.Errorf("Modified = %d, want 0", len(diff.Modified))
	}
	if diff.Unchanged != 2 {
		t.Errorf("Unchanged = %d, want 2", diff.Unchanged)
	}
}

func TestDiffSnapshots_CampaignAdded(t *testing.T) {
	before := TakeSnapshot([]*Campaign{
		auditTestCampaign("alpha", "high", testStages()),
	})
	after := TakeSnapshot([]*Campaign{
		auditTestCampaign("alpha", "high", testStages()),
		auditTestCampaign("bravo", "medium", testStages()),
	})

	diff := DiffSnapshots(before, after)
	if len(diff.Added) != 1 {
		t.Fatalf("Added = %d, want 1", len(diff.Added))
	}
	if diff.Added[0].Name != "bravo" {
		t.Errorf("Added[0].Name = %q, want %q", diff.Added[0].Name, "bravo")
	}
	if diff.Unchanged != 1 {
		t.Errorf("Unchanged = %d, want 1", diff.Unchanged)
	}
}

func TestDiffSnapshots_CampaignRemoved(t *testing.T) {
	before := TakeSnapshot([]*Campaign{
		auditTestCampaign("alpha", "high", testStages()),
		auditTestCampaign("bravo", "medium", testStages()),
	})
	after := TakeSnapshot([]*Campaign{
		auditTestCampaign("alpha", "high", testStages()),
	})

	diff := DiffSnapshots(before, after)
	if len(diff.Removed) != 1 {
		t.Fatalf("Removed = %d, want 1", len(diff.Removed))
	}
	if diff.Removed[0].Name != "bravo" {
		t.Errorf("Removed[0].Name = %q, want %q", diff.Removed[0].Name, "bravo")
	}
}

func TestDiffSnapshots_CampaignModified_Severity(t *testing.T) {
	before := TakeSnapshot([]*Campaign{
		auditTestCampaign("alpha", "low", testStages()),
	})
	after := TakeSnapshot([]*Campaign{
		auditTestCampaign("alpha", "critical", testStages()),
	})

	diff := DiffSnapshots(before, after)
	if len(diff.Modified) != 1 {
		t.Fatalf("Modified = %d, want 1", len(diff.Modified))
	}
	ch := diff.Modified[0]
	if ch.OldSeverity != "low" || ch.NewSeverity != "critical" {
		t.Errorf("Severity change = %q→%q, want low→critical", ch.OldSeverity, ch.NewSeverity)
	}
	if ch.OldHash == ch.NewHash {
		t.Error("hashes should differ for modified campaign")
	}
}

func TestDiffSnapshots_CampaignModified_StagesAdded(t *testing.T) {
	before := TakeSnapshot([]*Campaign{
		auditTestCampaign("alpha", "high", testStages()[:1]),
	})
	after := TakeSnapshot([]*Campaign{
		auditTestCampaign("alpha", "high", testStages()),
	})

	diff := DiffSnapshots(before, after)
	if len(diff.Modified) != 1 {
		t.Fatalf("Modified = %d, want 1", len(diff.Modified))
	}
	if diff.Modified[0].StagesAdded != 1 {
		t.Errorf("StagesAdded = %d, want 1", diff.Modified[0].StagesAdded)
	}
}

func TestDiffSnapshots_CampaignModified_StagesRemoved(t *testing.T) {
	before := TakeSnapshot([]*Campaign{
		auditTestCampaign("alpha", "high", testStages()),
	})
	after := TakeSnapshot([]*Campaign{
		auditTestCampaign("alpha", "high", testStages()[:1]),
	})

	diff := DiffSnapshots(before, after)
	if len(diff.Modified) != 1 {
		t.Fatalf("Modified = %d, want 1", len(diff.Modified))
	}
	if diff.Modified[0].StagesRemoved != 1 {
		t.Errorf("StagesRemoved = %d, want 1", diff.Modified[0].StagesRemoved)
	}
}

func TestDiffSnapshots_CampaignModified_TechniquesChanged(t *testing.T) {
	stagesBefore := []Stage{
		{ID: "s1", Technique: "T1016", Tactic: "discovery", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1190", Tactic: "initial-access", Execute: Execute{Type: "shell"}},
	}
	stagesAfter := []Stage{
		{ID: "s1", Technique: "T1016", Tactic: "discovery", Execute: Execute{Type: "shell"}},
		{ID: "s2", Technique: "T1059", Tactic: "execution", Execute: Execute{Type: "shell"}},
	}

	before := TakeSnapshot([]*Campaign{testCampaign("alpha", "high", stagesBefore)})
	after := TakeSnapshot([]*Campaign{testCampaign("alpha", "high", stagesAfter)})

	diff := DiffSnapshots(before, after)
	if len(diff.Modified) != 1 {
		t.Fatalf("Modified = %d, want 1", len(diff.Modified))
	}
	ch := diff.Modified[0]
	if len(ch.TechniquesAdded) != 1 || ch.TechniquesAdded[0] != "T1059" {
		t.Errorf("TechniquesAdded = %v, want [T1059]", ch.TechniquesAdded)
	}
	if len(ch.TechniquesRemoved) != 1 || ch.TechniquesRemoved[0] != "T1190" {
		t.Errorf("TechniquesRemoved = %v, want [T1190]", ch.TechniquesRemoved)
	}
}

func TestDiffSnapshots_BothEmpty(t *testing.T) {
	before := TakeSnapshot(nil)
	after := TakeSnapshot(nil)
	diff := DiffSnapshots(before, after)

	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Modified) != 0 {
		t.Error("empty→empty diff should have no changes")
	}
	if diff.Unchanged != 0 {
		t.Errorf("Unchanged = %d, want 0", diff.Unchanged)
	}
}

func TestDiffSnapshots_FromEmptyToSome(t *testing.T) {
	before := TakeSnapshot(nil)
	after := TakeSnapshot(twoCampaigns())
	diff := DiffSnapshots(before, after)

	if len(diff.Added) != 2 {
		t.Errorf("Added = %d, want 2", len(diff.Added))
	}
	if len(diff.Removed) != 0 {
		t.Errorf("Removed = %d, want 0", len(diff.Removed))
	}
}

func TestDiffSnapshots_FromSomeToEmpty(t *testing.T) {
	before := TakeSnapshot(twoCampaigns())
	after := TakeSnapshot(nil)
	diff := DiffSnapshots(before, after)

	if len(diff.Removed) != 2 {
		t.Errorf("Removed = %d, want 2", len(diff.Removed))
	}
	if len(diff.Added) != 0 {
		t.Errorf("Added = %d, want 0", len(diff.Added))
	}
}

// --- JSON round-trip tests ---

func TestSnapshotJSON_RoundTrip(t *testing.T) {
	original := TakeSnapshot(twoCampaigns())
	data, err := SnapshotToJSON(original)
	if err != nil {
		t.Fatalf("SnapshotToJSON error: %v", err)
	}

	restored, err := SnapshotFromJSON(data)
	if err != nil {
		t.Fatalf("SnapshotFromJSON error: %v", err)
	}

	if restored.Timestamp != original.Timestamp {
		t.Errorf("Timestamp = %q, want %q", restored.Timestamp, original.Timestamp)
	}
	if restored.CampaignCount != original.CampaignCount {
		t.Errorf("CampaignCount = %d, want %d", restored.CampaignCount, original.CampaignCount)
	}
	if restored.TotalStages != original.TotalStages {
		t.Errorf("TotalStages = %d, want %d", restored.TotalStages, original.TotalStages)
	}
	if len(restored.Campaigns) != len(original.Campaigns) {
		t.Fatalf("len(Campaigns) = %d, want %d", len(restored.Campaigns), len(original.Campaigns))
	}
	for i, cs := range restored.Campaigns {
		if cs.Name != original.Campaigns[i].Name {
			t.Errorf("Campaign[%d].Name = %q, want %q", i, cs.Name, original.Campaigns[i].Name)
		}
		if cs.Hash != original.Campaigns[i].Hash {
			t.Errorf("Campaign[%d].Hash differs", i)
		}
	}
}

func TestSnapshotJSON_EmptySnapshot(t *testing.T) {
	original := TakeSnapshot(nil)
	data, err := SnapshotToJSON(original)
	if err != nil {
		t.Fatalf("SnapshotToJSON error: %v", err)
	}
	restored, err := SnapshotFromJSON(data)
	if err != nil {
		t.Fatalf("SnapshotFromJSON error: %v", err)
	}
	if restored.CampaignCount != 0 {
		t.Errorf("CampaignCount = %d, want 0", restored.CampaignCount)
	}
}

func TestSnapshotFromJSON_InvalidJSON(t *testing.T) {
	_, err := SnapshotFromJSON([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// --- Format output tests ---

func TestFormatSnapshot_ContainsCampaignInfo(t *testing.T) {
	snap := TakeSnapshot(twoCampaigns())
	out := FormatSnapshot(snap)

	if !strings.Contains(out, "alpha") {
		t.Error("formatted output missing campaign name 'alpha'")
	}
	if !strings.Contains(out, "bravo") {
		t.Error("formatted output missing campaign name 'bravo'")
	}
	if !strings.Contains(out, "Campaigns: 2") {
		t.Error("formatted output missing campaign count")
	}
	if !strings.Contains(out, "Stages: 3") {
		t.Error("formatted output missing total stages")
	}
}

func TestFormatSnapshot_EmptySnapshot(t *testing.T) {
	snap := TakeSnapshot(nil)
	out := FormatSnapshot(snap)

	if !strings.Contains(out, "Campaigns: 0") {
		t.Error("formatted output missing zero campaign count")
	}
}

func TestFormatDiff_ShowsAllSections(t *testing.T) {
	before := TakeSnapshot([]*Campaign{
		auditTestCampaign("kept", "low", testStages()),
		auditTestCampaign("removed", "medium", testStages()),
		auditTestCampaign("changed", "low", testStages()),
	})
	after := TakeSnapshot([]*Campaign{
		auditTestCampaign("kept", "low", testStages()),
		auditTestCampaign("added", "high", testStages()),
		auditTestCampaign("changed", "critical", testStages()),
	})

	diff := DiffSnapshots(before, after)
	out := FormatSnapshotDiff(diff)

	if !strings.Contains(out, "Added:") {
		t.Error("formatted diff missing Added section")
	}
	if !strings.Contains(out, "Removed:") {
		t.Error("formatted diff missing Removed section")
	}
	if !strings.Contains(out, "Modified:") {
		t.Error("formatted diff missing Modified section")
	}
	if !strings.Contains(out, "+ added") {
		t.Error("formatted diff missing added campaign")
	}
	if !strings.Contains(out, "- removed") {
		t.Error("formatted diff missing removed campaign")
	}
	if !strings.Contains(out, "~ changed") {
		t.Error("formatted diff missing modified campaign")
	}
}

func TestFormatDiff_NoDifference(t *testing.T) {
	snap := TakeSnapshot(twoCampaigns())
	diff := DiffSnapshots(snap, snap)
	out := FormatSnapshotDiff(diff)

	if !strings.Contains(out, "0 added") {
		t.Error("no-change diff should show 0 added")
	}
	if !strings.Contains(out, "2 unchanged") {
		t.Error("no-change diff should show 2 unchanged")
	}
}

func TestFormatDiff_SeverityChange(t *testing.T) {
	before := TakeSnapshot([]*Campaign{
		auditTestCampaign("test", "low", testStages()),
	})
	after := TakeSnapshot([]*Campaign{
		auditTestCampaign("test", "critical", testStages()),
	})
	diff := DiffSnapshots(before, after)
	out := FormatSnapshotDiff(diff)

	if !strings.Contains(out, "low") || !strings.Contains(out, "critical") {
		t.Error("severity change not shown in formatted diff")
	}
}

// --- TakeSnapshotDir with created files ---

func TestTakeSnapshotDir_MultiCampaign(t *testing.T) {
	dir := t.TempDir()

	mkCampaign := func(subdir, name, severity string) {
		d := filepath.Join(dir, subdir)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		yaml := "api_version: v1\nkind: Campaign\nmeta:\n  name: " + name +
			"\n  adversary: A\n  severity: " + severity +
			"\n  mitre_version: \"15\"\nstages:\n" +
			"  - id: s1\n    name: Step\n    technique: T1001\n    tactic: exfil\n" +
			"    execute:\n      type: shell\n"
		if err := os.WriteFile(filepath.Join(d, "campaign.yaml"), []byte(yaml), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mkCampaign("camp-a", "alpha", "high")
	mkCampaign("camp-b", "bravo", "low")

	snap, err := TakeSnapshotDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snap.CampaignCount != 2 {
		t.Errorf("CampaignCount = %d, want 2", snap.CampaignCount)
	}
}
