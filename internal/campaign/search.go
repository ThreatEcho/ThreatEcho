// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SearchQuery defines multi-field search criteria. All non-empty fields are ANDed.
type SearchQuery struct {
	Technique string // match technique ID (exact or prefix, e.g. "T1059" matches T1059.001)
	Tactic    string // match tactic name (exact, case-insensitive)
	Adversary string // match campaign adversary (case-insensitive contains)
	Tag       string // match any campaign tag (case-insensitive contains)
	Keyword   string // free-text search across names, descriptions, stage IDs
	Severity  string // match campaign severity (exact)
	StageID   string // match specific stage ID (exact or contains)
	Platform  string // match stage platform
	ExecType  string // match execute type (shell, http, etc.)
}

// SearchResult represents a matched campaign stage.
type SearchResult struct {
	CampaignName string
	CampaignFile string
	Stage        Stage
	MatchReasons []string // e.g. ["technique:T1059.001", "tactic:execution"]
}

// Search searches a campaign against a query, returning matching stages.
func Search(c *Campaign, query SearchQuery) []SearchResult {
	var results []SearchResult
	for _, stage := range c.Stages {
		reasons := matchStage(c, stage, query)
		if reasons != nil {
			results = append(results, SearchResult{
				CampaignName: c.Meta.Name,
				Stage:        stage,
				MatchReasons: reasons,
			})
		}
	}
	return results
}

// SearchDir searches all campaigns in a directory.
// It walks subdirectories looking for campaign.yaml files (same convention as LoadDir).
func SearchDir(dir string, query SearchQuery) ([]SearchResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %q: %w", dir, err)
	}

	var results []SearchResult
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
		for _, r := range Search(c, query) {
			r.CampaignFile = cpath
			results = append(results, r)
		}
	}
	return results, nil
}

// FormatSearchResults formats results as a human-readable table.
func FormatSearchResults(results []SearchResult) string {
	if len(results) == 0 {
		return "No results found.\n"
	}

	// Compute column widths.
	cw := 18 // Campaign
	sw := 18 // Stage ID
	tw := 12 // Technique
	aw := 19 // Tactic
	for _, r := range results {
		if n := len(r.CampaignName); n+2 > cw {
			cw = n + 2
		}
		if n := len(r.Stage.ID); n+2 > sw {
			sw = n + 2
		}
		if n := len(r.Stage.Technique); n+2 > tw {
			tw = n + 2
		}
		if n := len(r.Stage.Tactic); n+2 > aw {
			aw = n + 2
		}
	}

	var b strings.Builder
	header := fmt.Sprintf("%-*s%-*s%-*s%-*sMatch\n", cw, "Campaign", sw, "Stage ID", tw, "Technique", aw, "Tactic")
	b.WriteString(header)
	b.WriteString(strings.Repeat("─", len(header)+10))
	b.WriteByte('\n')

	for _, r := range results {
		matchStr := strings.Join(r.MatchReasons, ", ")
		b.WriteString(fmt.Sprintf("%-*s%-*s%-*s%-*s%s\n",
			cw, r.CampaignName,
			sw, r.Stage.ID,
			tw, r.Stage.Technique,
			aw, r.Stage.Tactic,
			matchStr))
	}
	return b.String()
}

// matchStage checks whether a stage matches the query. It returns the list of
// match reasons, or nil if the stage does not match.
func matchStage(c *Campaign, stage Stage, query SearchQuery) []string {
	empty := isEmptyQuery(query)
	if empty {
		// Empty query matches everything — no specific reasons.
		return []string{"all"}
	}

	var reasons []string

	if query.Technique != "" {
		if matchTechnique(stage.Technique, query.Technique) {
			reasons = append(reasons, "technique:"+stage.Technique)
		} else {
			return nil
		}
	}

	if query.Tactic != "" {
		if strings.EqualFold(stage.Tactic, query.Tactic) {
			reasons = append(reasons, "tactic:"+stage.Tactic)
		} else {
			return nil
		}
	}

	if query.Adversary != "" {
		if containsFold(c.Meta.Adversary, query.Adversary) {
			reasons = append(reasons, "adversary:"+c.Meta.Adversary)
		} else {
			return nil
		}
	}

	if query.Tag != "" {
		matched := false
		for _, tag := range c.Meta.Tags {
			if containsFold(tag, query.Tag) {
				matched = true
				reasons = append(reasons, "tag:"+tag)
				break
			}
		}
		if !matched {
			return nil
		}
	}

	if query.Keyword != "" {
		kw := strings.ToLower(query.Keyword)
		matched := false
		if strings.Contains(strings.ToLower(c.Meta.Name), kw) {
			matched = true
			reasons = append(reasons, "keyword:campaign-name")
		}
		if strings.Contains(strings.ToLower(stage.Name), kw) {
			matched = true
			reasons = append(reasons, "keyword:stage-name")
		}
		if strings.Contains(strings.ToLower(stage.Description), kw) {
			matched = true
			reasons = append(reasons, "keyword:description")
		}
		if strings.Contains(strings.ToLower(stage.ID), kw) {
			matched = true
			reasons = append(reasons, "keyword:stage-id")
		}
		if !matched {
			return nil
		}
	}

	if query.Severity != "" {
		if strings.EqualFold(c.Meta.Severity, query.Severity) {
			reasons = append(reasons, "severity:"+c.Meta.Severity)
		} else {
			return nil
		}
	}

	if query.StageID != "" {
		if stage.ID == query.StageID || strings.Contains(stage.ID, query.StageID) {
			reasons = append(reasons, "stage-id:"+stage.ID)
		} else {
			return nil
		}
	}

	if query.Platform != "" {
		matched := false
		for _, p := range stage.Platform {
			if strings.EqualFold(p, query.Platform) {
				matched = true
				reasons = append(reasons, "platform:"+p)
				break
			}
		}
		if !matched {
			return nil
		}
	}

	if query.ExecType != "" {
		if strings.EqualFold(stage.Execute.Type, query.ExecType) {
			reasons = append(reasons, "exec-type:"+stage.Execute.Type)
		} else {
			return nil
		}
	}

	return reasons
}

// matchTechnique checks if a stage technique matches the query technique.
// It supports exact match and prefix match (T1059 matches T1059, T1059.001, T1059.003).
func matchTechnique(stageTechnique, queryTechnique string) bool {
	if strings.EqualFold(stageTechnique, queryTechnique) {
		return true
	}
	// Prefix match: queryTechnique "T1059" should match "T1059.001".
	// We check that the stage technique starts with the query technique
	// followed by a dot, so "T1059" matches "T1059.001" but not "T10590".
	prefix := strings.ToUpper(queryTechnique) + "."
	return strings.HasPrefix(strings.ToUpper(stageTechnique), prefix)
}

// containsFold reports whether substr is within s, case-insensitive.
func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// isEmptyQuery returns true if all query fields are empty strings.
func isEmptyQuery(q SearchQuery) bool {
	return q.Technique == "" && q.Tactic == "" && q.Adversary == "" &&
		q.Tag == "" && q.Keyword == "" && q.Severity == "" &&
		q.StageID == "" && q.Platform == "" && q.ExecType == ""
}
