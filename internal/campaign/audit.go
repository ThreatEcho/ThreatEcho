// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Snapshot captures the state of campaigns at a point in time.
type Snapshot struct {
	Timestamp     string             `json:"timestamp"` // ISO-8601
	CampaignCount int                `json:"campaign_count"`
	TotalStages   int                `json:"total_stages"`
	Campaigns     []CampaignSnapshot `json:"campaigns"`
}

// CampaignSnapshot captures one campaign's state.
type CampaignSnapshot struct {
	Name       string   `json:"name"`
	Hash       string   `json:"hash"` // SHA256 content hash
	StageCount int      `json:"stage_count"`
	Severity   string   `json:"severity"`
	Techniques []string `json:"techniques"` // sorted technique IDs
	Tactics    []string `json:"tactics"`    // sorted unique tactics
}

// SnapshotDiff shows what changed between two snapshots.
type SnapshotDiff struct {
	Added     []CampaignSnapshot `json:"added"`     // new campaigns
	Removed   []CampaignSnapshot `json:"removed"`   // deleted campaigns
	Modified  []CampaignChange   `json:"modified"`  // content changed
	Unchanged int                `json:"unchanged"` // count of unchanged
}

// CampaignChange shows what changed in one campaign.
type CampaignChange struct {
	Name              string   `json:"name"`
	OldHash           string   `json:"old_hash"`
	NewHash           string   `json:"new_hash"`
	StagesAdded       int      `json:"stages_added"`
	StagesRemoved     int      `json:"stages_removed"`
	OldSeverity       string   `json:"old_severity"`
	NewSeverity       string   `json:"new_severity"`
	TechniquesAdded   []string `json:"techniques_added"`
	TechniquesRemoved []string `json:"techniques_removed"`
}

// TakeSnapshot computes a snapshot from loaded campaigns.
func TakeSnapshot(campaigns []*Campaign) *Snapshot {
	snap := &Snapshot{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	for _, c := range campaigns {
		cs := buildCampaignSnapshot(c)
		snap.Campaigns = append(snap.Campaigns, cs)
		snap.TotalStages += cs.StageCount
	}

	// Sort campaigns by name for deterministic output.
	sort.Slice(snap.Campaigns, func(i, j int) bool {
		return snap.Campaigns[i].Name < snap.Campaigns[j].Name
	})

	snap.CampaignCount = len(snap.Campaigns)
	return snap
}

// TakeSnapshotDir computes a snapshot from all campaigns in a directory.
// It follows the same convention as LoadDir: each subdirectory containing
// a campaign.yaml is treated as a campaign.
func TakeSnapshotDir(dir string) (*Snapshot, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("snapshot dir %q: %w", dir, err)
	}

	var campaigns []*Campaign
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cpath := filepath.Join(dir, e.Name(), "campaign.yaml")
		if _, err := os.Stat(cpath); err != nil {
			continue
		}
		c, err := Load(cpath)
		if err != nil {
			continue
		}
		campaigns = append(campaigns, c)
	}

	return TakeSnapshot(campaigns), nil
}

// DiffSnapshots computes the changes between two snapshots, matching
// campaigns by name.
func DiffSnapshots(before, after *Snapshot) *SnapshotDiff {
	diff := &SnapshotDiff{}

	beforeMap := make(map[string]CampaignSnapshot)
	for _, cs := range before.Campaigns {
		beforeMap[cs.Name] = cs
	}

	afterMap := make(map[string]CampaignSnapshot)
	for _, cs := range after.Campaigns {
		afterMap[cs.Name] = cs
	}

	// Detect removed campaigns (in before but not in after).
	for _, cs := range before.Campaigns {
		if _, ok := afterMap[cs.Name]; !ok {
			diff.Removed = append(diff.Removed, cs)
		}
	}

	// Detect added and modified/unchanged campaigns.
	for _, cs := range after.Campaigns {
		old, existed := beforeMap[cs.Name]
		if !existed {
			diff.Added = append(diff.Added, cs)
			continue
		}
		if old.Hash == cs.Hash {
			diff.Unchanged++
			continue
		}
		change := buildCampaignChange(old, cs)
		diff.Modified = append(diff.Modified, change)
	}

	return diff
}

// FormatSnapshot formats a snapshot as human-readable text.
func FormatSnapshot(s *Snapshot) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Snapshot: %s\n", s.Timestamp))
	b.WriteString(fmt.Sprintf("Campaigns: %d | Stages: %d\n", s.CampaignCount, s.TotalStages))
	b.WriteString(strings.Repeat("─", 60))
	b.WriteByte('\n')

	for _, cs := range s.Campaigns {
		b.WriteString(fmt.Sprintf("  %-30s [%s] %d stages\n", cs.Name, cs.Severity, cs.StageCount))
		b.WriteString(fmt.Sprintf("    Hash:       %s\n", cs.Hash))
		b.WriteString(fmt.Sprintf("    Techniques: %s\n", strings.Join(cs.Techniques, ", ")))
		b.WriteString(fmt.Sprintf("    Tactics:    %s\n", strings.Join(cs.Tactics, ", ")))
	}
	return b.String()
}

// FormatSnapshotDiff formats a snapshot diff as human-readable text.
func FormatSnapshotDiff(d *SnapshotDiff) string {
	var b strings.Builder

	total := len(d.Added) + len(d.Removed) + len(d.Modified) + d.Unchanged
	b.WriteString(fmt.Sprintf("Diff: %d added, %d removed, %d modified, %d unchanged\n",
		len(d.Added), len(d.Removed), len(d.Modified), d.Unchanged))
	b.WriteString(fmt.Sprintf("Total: %d campaigns\n", total))
	b.WriteString(strings.Repeat("─", 60))
	b.WriteByte('\n')

	if len(d.Added) > 0 {
		b.WriteString("\nAdded:\n")
		for _, cs := range d.Added {
			b.WriteString(fmt.Sprintf("  + %s [%s] %d stages\n", cs.Name, cs.Severity, cs.StageCount))
		}
	}

	if len(d.Removed) > 0 {
		b.WriteString("\nRemoved:\n")
		for _, cs := range d.Removed {
			b.WriteString(fmt.Sprintf("  - %s [%s] %d stages\n", cs.Name, cs.Severity, cs.StageCount))
		}
	}

	if len(d.Modified) > 0 {
		b.WriteString("\nModified:\n")
		for _, ch := range d.Modified {
			b.WriteString(fmt.Sprintf("  ~ %s\n", ch.Name))
			if ch.OldSeverity != ch.NewSeverity {
				b.WriteString(fmt.Sprintf("      Severity: %s → %s\n", ch.OldSeverity, ch.NewSeverity))
			}
			if ch.StagesAdded > 0 {
				b.WriteString(fmt.Sprintf("      Stages added: %d\n", ch.StagesAdded))
			}
			if ch.StagesRemoved > 0 {
				b.WriteString(fmt.Sprintf("      Stages removed: %d\n", ch.StagesRemoved))
			}
			if len(ch.TechniquesAdded) > 0 {
				b.WriteString(fmt.Sprintf("      Techniques added: %s\n", strings.Join(ch.TechniquesAdded, ", ")))
			}
			if len(ch.TechniquesRemoved) > 0 {
				b.WriteString(fmt.Sprintf("      Techniques removed: %s\n", strings.Join(ch.TechniquesRemoved, ", ")))
			}
		}
	}

	return b.String()
}

// SnapshotToJSON serializes a snapshot to JSON.
func SnapshotToJSON(s *Snapshot) ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serializing snapshot: %w", err)
	}
	return data, nil
}

// SnapshotFromJSON deserializes a snapshot from JSON.
func SnapshotFromJSON(data []byte) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("deserializing snapshot: %w", err)
	}
	return &s, nil
}

// buildCampaignSnapshot creates a CampaignSnapshot from a Campaign.
func buildCampaignSnapshot(c *Campaign) CampaignSnapshot {
	techniques := sortedCopy(c.UniqueTechniques())
	tactics := sortedCopy(c.UniqueTactics())

	return CampaignSnapshot{
		Name:       c.Meta.Name,
		Hash:       Fingerprint(c),
		StageCount: len(c.Stages),
		Severity:   c.Meta.Severity,
		Techniques: techniques,
		Tactics:    tactics,
	}
}

// buildCampaignChange computes the diff between two snapshots of the same
// campaign (matched by name).
func buildCampaignChange(old, new CampaignSnapshot) CampaignChange {
	change := CampaignChange{
		Name:        old.Name,
		OldHash:     old.Hash,
		NewHash:     new.Hash,
		OldSeverity: old.Severity,
		NewSeverity: new.Severity,
	}

	// Stage count changes.
	if new.StageCount > old.StageCount {
		change.StagesAdded = new.StageCount - old.StageCount
	} else if old.StageCount > new.StageCount {
		change.StagesRemoved = old.StageCount - new.StageCount
	}

	// Technique set differences.
	oldTech := toSet(old.Techniques)
	newTech := toSet(new.Techniques)
	for _, t := range new.Techniques {
		if !oldTech[t] {
			change.TechniquesAdded = append(change.TechniquesAdded, t)
		}
	}
	for _, t := range old.Techniques {
		if !newTech[t] {
			change.TechniquesRemoved = append(change.TechniquesRemoved, t)
		}
	}

	return change
}

// toSet converts a string slice to a lookup map.
func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}
