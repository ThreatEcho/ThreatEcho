// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// PolicyVersion represents one version of a policy.
type PolicyVersion struct {
	Version     int     `json:"version"`
	Timestamp   string  `json:"timestamp"`
	Author      string  `json:"author"`
	Comment     string  `json:"comment"`
	Policy      *Policy `json:"policy"`
	Fingerprint string  `json:"fingerprint"` // SHA256 of policy YAML
}

// PolicyHistory tracks all versions of a policy.
type PolicyHistory struct {
	PolicyName string          `json:"policy_name"`
	Versions   []PolicyVersion `json:"versions"`
	Current    int             `json:"current"` // index of current version
}

// VersionDiff describes changes between two specific versions.
type VersionDiff struct {
	OldVersion int         `json:"old_version"`
	NewVersion int         `json:"new_version"`
	Diff       *PolicyDiff `json:"diff"`
	Author     string      `json:"author"`
	Comment    string      `json:"comment"`
	Timestamp  string      `json:"timestamp"`
}

// HistoryStats summarizes the version history.
type HistoryStats struct {
	TotalVersions      int     `json:"total_versions"`
	FirstVersion       string  `json:"first_version"`  // timestamp
	LatestVersion      string  `json:"latest_version"` // timestamp
	TotalRuleChanges   int     `json:"total_rule_changes"`
	BreakingChanges    int     `json:"breaking_changes"`
	UniqueAuthors      int     `json:"unique_authors"`
	AvgRulesPerVersion float64 `json:"avg_rules_per_version"`
}

// policyFingerprint computes the SHA256 hash of a policy's YAML representation.
func policyFingerprint(p *Policy) string {
	data, err := yaml.Marshal(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// nowTimestamp returns the current time in RFC3339 format.
func nowTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// NewHistory creates a new policy history starting with the given policy.
func NewHistory(p *Policy, author, comment string) *PolicyHistory {
	v := PolicyVersion{
		Version:     1,
		Timestamp:   nowTimestamp(),
		Author:      author,
		Comment:     comment,
		Policy:      p,
		Fingerprint: policyFingerprint(p),
	}
	return &PolicyHistory{
		PolicyName: p.Meta.Name,
		Versions:   []PolicyVersion{v},
		Current:    0,
	}
}

// AddVersion appends a new version to the history. Returns the new version number.
func (h *PolicyHistory) AddVersion(p *Policy, author, comment string) int {
	nextVersion := h.Versions[len(h.Versions)-1].Version + 1
	v := PolicyVersion{
		Version:     nextVersion,
		Timestamp:   nowTimestamp(),
		Author:      author,
		Comment:     comment,
		Policy:      p,
		Fingerprint: policyFingerprint(p),
	}
	h.Versions = append(h.Versions, v)
	h.Current = len(h.Versions) - 1
	return nextVersion
}

// GetVersion returns a specific version by number.
func (h *PolicyHistory) GetVersion(version int) (*PolicyVersion, bool) {
	for i := range h.Versions {
		if h.Versions[i].Version == version {
			return &h.Versions[i], true
		}
	}
	return nil, false
}

// DiffVersions computes the diff between two version numbers.
func (h *PolicyHistory) DiffVersions(oldV, newV int) (*VersionDiff, error) {
	oldVer, ok := h.GetVersion(oldV)
	if !ok {
		return nil, fmt.Errorf("version %d not found", oldV)
	}
	newVer, ok := h.GetVersion(newV)
	if !ok {
		return nil, fmt.Errorf("version %d not found", newV)
	}

	d := DiffPolicies(oldVer.Policy, newVer.Policy)

	return &VersionDiff{
		OldVersion: oldV,
		NewVersion: newV,
		Diff:       d,
		Author:     newVer.Author,
		Comment:    newVer.Comment,
		Timestamp:  newVer.Timestamp,
	}, nil
}

// GetStats returns statistics about the version history.
func (h *PolicyHistory) GetStats() *HistoryStats {
	stats := &HistoryStats{}

	n := len(h.Versions)
	if n == 0 {
		return stats
	}

	stats.TotalVersions = n
	stats.FirstVersion = h.Versions[0].Timestamp
	stats.LatestVersion = h.Versions[n-1].Timestamp

	// Unique authors.
	authors := make(map[string]bool)
	// Sum of rules across versions for averaging.
	totalRules := 0

	for i := range h.Versions {
		authors[h.Versions[i].Author] = true
		if h.Versions[i].Policy != nil {
			totalRules += len(h.Versions[i].Policy.Rules)
		}
	}
	stats.UniqueAuthors = len(authors)
	stats.AvgRulesPerVersion = float64(totalRules) / float64(n)

	// Compute diffs between consecutive versions.
	for i := 1; i < n; i++ {
		d := DiffPolicies(h.Versions[i-1].Policy, h.Versions[i].Policy)
		stats.TotalRuleChanges += d.Summary.TotalChanges
		stats.BreakingChanges += d.Summary.BreakingChanges
	}

	return stats
}

// HistoryToJSON serializes history to JSON bytes.
func HistoryToJSON(h *PolicyHistory) ([]byte, error) {
	return json.MarshalIndent(h, "", "  ")
}

// HistoryFromJSON deserializes history from JSON bytes.
func HistoryFromJSON(data []byte) (*PolicyHistory, error) {
	var h PolicyHistory
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("parsing policy history JSON: %w", err)
	}
	return &h, nil
}

// FormatHistory returns a box-drawing formatted history report.
func FormatHistory(h *PolicyHistory) string {
	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│ Policy History                                      │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ %-51s │\n", h.PolicyName))
	b.WriteString(fmt.Sprintf("│ %-51s │\n",
		fmt.Sprintf("%d version(s)", len(h.Versions))))
	b.WriteString("└─────────────────────────────────────────────────────┘\n")

	if len(h.Versions) == 0 {
		b.WriteString("\n  No versions recorded.\n")
		return b.String()
	}

	b.WriteString("\n")

	for i, v := range h.Versions {
		// Current version marker.
		marker := "  "
		if i == h.Current {
			marker = "► "
		}

		ruleCount := 0
		if v.Policy != nil {
			ruleCount = len(v.Policy.Rules)
		}

		// Show rule count change vs previous version.
		ruleInfo := fmt.Sprintf("%d rules", ruleCount)
		if i > 0 {
			prevCount := 0
			if h.Versions[i-1].Policy != nil {
				prevCount = len(h.Versions[i-1].Policy.Rules)
			}
			delta := ruleCount - prevCount
			if delta > 0 {
				ruleInfo = fmt.Sprintf("%d rules (+%d)", ruleCount, delta)
			} else if delta < 0 {
				ruleInfo = fmt.Sprintf("%d rules (%d)", ruleCount, delta)
			}
		}

		// Check for breaking changes vs previous.
		breakingMarker := ""
		if i > 0 {
			d := DiffPolicies(h.Versions[i-1].Policy, h.Versions[i].Policy)
			if d.Summary.BreakingChanges > 0 {
				breakingMarker = " ⚠ BREAKING"
			}
		}

		b.WriteString(fmt.Sprintf("%sv%d  %s  %s%s\n", marker, v.Version, v.Timestamp, v.Author, breakingMarker))
		b.WriteString(fmt.Sprintf("    %s | %s\n", ruleInfo, v.Comment))

		// Timeline connector between versions.
		if i < len(h.Versions)-1 {
			b.WriteString("    │\n")
		}
	}

	return b.String()
}

// FormatVersionDiff returns a formatted diff between versions.
func FormatVersionDiff(vd *VersionDiff) string {
	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│ Version Diff                                        │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ %-51s │\n",
		fmt.Sprintf("v%d → v%d", vd.OldVersion, vd.NewVersion)))
	b.WriteString(fmt.Sprintf("│ %-51s │\n",
		fmt.Sprintf("Author: %s", vd.Author)))
	b.WriteString(fmt.Sprintf("│ %-51s │\n",
		fmt.Sprintf("Date:   %s", vd.Timestamp)))
	if vd.Comment != "" {
		b.WriteString(fmt.Sprintf("│ %-51s │\n",
			fmt.Sprintf("Note:   %s", vd.Comment)))
	}
	b.WriteString("└─────────────────────────────────────────────────────┘\n")

	if vd.Diff != nil {
		b.WriteString(FormatPolicyDiff(vd.Diff))
	}

	return b.String()
}
