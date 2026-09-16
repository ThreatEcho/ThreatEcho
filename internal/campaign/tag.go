// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TagSummary holds aggregate tag data across all campaigns.
type TagSummary struct {
	TotalCampaigns int
	TaggedCount    int
	UntaggedCount  int
	Tags           []TagInfo       // sorted by count desc, then alpha
	Suggestions    []TagSuggestion // for untagged campaigns
}

// TagInfo holds one tag and which campaigns use it.
type TagInfo struct {
	Tag       string
	Count     int
	Campaigns []string // campaign names
}

// TagSuggestion suggests tags for a campaign based on its content.
type TagSuggestion struct {
	CampaignName string
	Suggested    []string
	Reasons      []string // why each tag was suggested
}

// ransomware-related technique IDs.
var ransomwareTechniques = map[string]bool{
	"T1486": true, // Data Encrypted for Impact
	"T1490": true, // Inhibit System Recovery
	"T1489": true, // Service Stop
	"T1529": true, // System Shutdown/Reboot
}

// cloudTechniques are technique IDs associated with cloud operations.
var cloudTechniques = map[string]bool{
	"T1078.004": true, // Valid Accounts: Cloud Accounts
	"T1530":     true, // Data from Cloud Storage
	"T1537":     true, // Transfer Data to Cloud Account
	"T1538":     true, // Cloud Service Dashboard
	"T1578":     true, // Modify Cloud Compute Infrastructure
	"T1578.001": true, // Create Snapshot
	"T1578.002": true, // Create Cloud Instance
	"T1578.003": true, // Delete Cloud Instance
	"T1578.004": true, // Revert Cloud Instance
	"T1580":     true, // Cloud Infrastructure Discovery
	"T1619":     true, // Cloud Storage Object Discovery
	"T1550.001": true, // Application Access Token
}

// ListTags analyzes all tags across the provided campaigns.
func ListTags(campaigns []*Campaign) *TagSummary {
	ts := &TagSummary{}

	if len(campaigns) == 0 {
		return ts
	}

	tagMap := make(map[string]*TagInfo)

	for _, c := range campaigns {
		if c == nil {
			continue
		}
		ts.TotalCampaigns++

		if len(c.Meta.Tags) == 0 {
			ts.UntaggedCount++
			suggestion := SuggestTags(c)
			if len(suggestion.Suggested) > 0 {
				ts.Suggestions = append(ts.Suggestions, *suggestion)
			}
			continue
		}

		ts.TaggedCount++
		for _, tag := range c.Meta.Tags {
			ti, ok := tagMap[tag]
			if !ok {
				ti = &TagInfo{Tag: tag}
				tagMap[tag] = ti
			}
			ti.Count++
			if !containsString(ti.Campaigns, c.Meta.Name) {
				ti.Campaigns = append(ti.Campaigns, c.Meta.Name)
			}
		}
	}

	// Collect and sort tags: count desc, then alphabetical.
	for _, ti := range tagMap {
		ts.Tags = append(ts.Tags, *ti)
	}
	sort.Slice(ts.Tags, func(i, j int) bool {
		if ts.Tags[i].Count != ts.Tags[j].Count {
			return ts.Tags[i].Count > ts.Tags[j].Count
		}
		return ts.Tags[i].Tag < ts.Tags[j].Tag
	})

	return ts
}

// ListTagsDir loads all campaigns from a directory and analyzes their tags.
func ListTagsDir(dir string) (*TagSummary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %q: %w", dir, err)
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

	return ListTags(campaigns), nil
}

// FindByTag returns campaigns that have the specified tag (case-insensitive).
func FindByTag(campaigns []*Campaign, tag string) []*Campaign {
	var matched []*Campaign
	lower := strings.ToLower(tag)

	for _, c := range campaigns {
		if c == nil {
			continue
		}
		for _, t := range c.Meta.Tags {
			if strings.ToLower(t) == lower {
				matched = append(matched, c)
				break
			}
		}
	}

	return matched
}

// SuggestTags suggests tags for a campaign based on its techniques, tactics,
// adversary, severity, and other content indicators.
func SuggestTags(c *Campaign) *TagSuggestion {
	suggestion := &TagSuggestion{CampaignName: c.Meta.Name}

	if c == nil {
		return suggestion
	}

	// Collect all techniques and tactics for analysis.
	techniques := c.UniqueTechniques()
	tactics := c.UniqueTactics()

	tacticSet := make(map[string]bool)
	for _, tac := range tactics {
		tacticSet[strings.ToLower(tac)] = true
	}

	// Ransomware techniques.
	for _, tech := range techniques {
		base := techBase(tech)
		if ransomwareTechniques[base] || ransomwareTechniques[tech] {
			suggestion.Suggested = append(suggestion.Suggested, "ransomware")
			suggestion.Reasons = append(suggestion.Reasons, fmt.Sprintf("technique %s is ransomware-related", tech))
			break
		}
	}

	// Credential-access tactic.
	if tacticSet["credential-access"] {
		suggestion.Suggested = append(suggestion.Suggested, "credential-theft")
		suggestion.Reasons = append(suggestion.Reasons, "campaign uses credential-access tactic")
	}

	// Lateral-movement tactic.
	if tacticSet["lateral-movement"] {
		suggestion.Suggested = append(suggestion.Suggested, "lateral-movement")
		suggestion.Reasons = append(suggestion.Reasons, "campaign uses lateral-movement tactic")
	}

	// APT adversary.
	if strings.Contains(strings.ToUpper(c.Meta.Adversary), "APT") {
		suggestion.Suggested = append(suggestion.Suggested, "apt")
		suggestion.Reasons = append(suggestion.Reasons, fmt.Sprintf("adversary %q contains APT designation", c.Meta.Adversary))
	}

	// ATLAS techniques (AML.*).
	for _, tech := range techniques {
		if strings.HasPrefix(tech, "AML.") {
			suggestion.Suggested = append(suggestion.Suggested, "ai-security")
			suggestion.Reasons = append(suggestion.Reasons, fmt.Sprintf("technique %s is an ATLAS (AI) technique", tech))
			break
		}
	}

	// OWASP techniques (LLM*).
	for _, tech := range techniques {
		if strings.HasPrefix(tech, "LLM") {
			suggestion.Suggested = append(suggestion.Suggested, "llm-security")
			suggestion.Reasons = append(suggestion.Reasons, fmt.Sprintf("technique %s is an OWASP LLM technique", tech))
			break
		}
	}

	// Critical severity.
	if strings.EqualFold(c.Meta.Severity, "critical") {
		suggestion.Suggested = append(suggestion.Suggested, "critical")
		suggestion.Reasons = append(suggestion.Reasons, "campaign severity is critical")
	}

	// Exfiltration tactic.
	if tacticSet["exfiltration"] {
		suggestion.Suggested = append(suggestion.Suggested, "data-theft")
		suggestion.Reasons = append(suggestion.Reasons, "campaign uses exfiltration tactic")
	}

	// Phishing techniques (T1566.*).
	for _, tech := range techniques {
		if tech == "T1566" || strings.HasPrefix(tech, "T1566.") {
			suggestion.Suggested = append(suggestion.Suggested, "phishing")
			suggestion.Reasons = append(suggestion.Reasons, fmt.Sprintf("technique %s is a phishing technique", tech))
			break
		}
	}

	// Cloud-related techniques.
	for _, tech := range techniques {
		if cloudTechniques[tech] || cloudTechniques[techBase(tech)] {
			suggestion.Suggested = append(suggestion.Suggested, "cloud")
			suggestion.Reasons = append(suggestion.Reasons, fmt.Sprintf("technique %s is cloud-related", tech))
			break
		}
	}

	return suggestion
}

// FormatTagSummary formats a tag summary as a human-readable report.
func FormatTagSummary(ts *TagSummary) string {
	if ts == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(boxLine("top"))
	b.WriteString(boxCenter("Tag Taxonomy Report"))
	b.WriteString(boxLine("mid"))
	b.WriteString("\n")

	// Overview.
	fmt.Fprintf(&b, "  Campaigns: %-8d Tagged: %-8d Untagged: %d\n",
		ts.TotalCampaigns, ts.TaggedCount, ts.UntaggedCount)

	if ts.TotalCampaigns > 0 {
		coverage := float64(ts.TaggedCount) / float64(ts.TotalCampaigns) * 100
		fmt.Fprintf(&b, "  Coverage:  %.1f%%\n", coverage)
	}

	// Tag list.
	if len(ts.Tags) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionHeader("Tags"))
		maxCount := ts.Tags[0].Count
		for _, ti := range ts.Tags {
			bar := renderBar(ti.Count, maxCount, 10)
			campaigns := strings.Join(ti.Campaigns, ", ")
			if len(campaigns) > 40 {
				campaigns = campaigns[:37] + "..."
			}
			fmt.Fprintf(&b, "    %-20s %s  %d  [%s]\n", ti.Tag, bar, ti.Count, campaigns)
		}
	}

	// Suggestions for untagged campaigns.
	if len(ts.Suggestions) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionHeader("Suggestions"))
		for _, s := range ts.Suggestions {
			fmt.Fprintf(&b, "    %s:\n", s.CampaignName)
			for i, tag := range s.Suggested {
				reason := ""
				if i < len(s.Reasons) {
					reason = s.Reasons[i]
				}
				fmt.Fprintf(&b, "      + %-20s  (%s)\n", tag, reason)
			}
		}
	}

	b.WriteString("\n")
	b.WriteString(boxLine("bottom"))

	return b.String()
}

// techBase extracts the base technique ID (e.g. "T1059" from "T1059.001").
func techBase(id string) string {
	if idx := strings.Index(id, "."); idx != -1 {
		return id[:idx]
	}
	return id
}
