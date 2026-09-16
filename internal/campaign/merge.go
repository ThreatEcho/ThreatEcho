// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// MergeOptions controls how multiple campaigns are combined.
type MergeOptions struct {
	// Name for the merged campaign. Default: "merged-campaign".
	Name string
	// Prefix stage IDs with campaign name to avoid collisions (e.g. "apt29/initial-access").
	Prefix bool
	// Strategy for handling stage ID collisions: "first" (keep first) or "error" (report conflict).
	// Default: "error".
	Strategy string
}

// MergeResult holds the output of a campaign merge.
type MergeResult struct {
	Campaign  *Campaign
	Warnings  []string
	Conflicts []MergeConflict
}

// MergeConflict describes a collision that could not be auto-resolved.
type MergeConflict struct {
	Type    string   // "stage_id" or "variable"
	Key     string   // the conflicting ID or variable name
	Sources []string // campaign names that contribute this key
}

// severityRank maps severity labels to numeric rank (higher = more severe).
var severityRank = map[string]int{
	"low":      0,
	"medium":   1,
	"high":     2,
	"critical": 3,
}

// Merge combines multiple campaigns into one composite campaign.
// It returns an error only for truly unrecoverable issues (nil campaigns, empty list).
// Collisions are reported via MergeResult.Conflicts when Strategy="error".
func Merge(campaigns []*Campaign, opts MergeOptions) (*MergeResult, error) {
	if len(campaigns) == 0 {
		return nil, errors.New("merge: no campaigns provided")
	}
	for i, c := range campaigns {
		if c == nil {
			return nil, fmt.Errorf("merge: campaign at index %d is nil", i)
		}
	}

	// Apply defaults.
	if opts.Name == "" {
		opts.Name = "merged-campaign"
	}
	if opts.Strategy == "" {
		opts.Strategy = "error"
	}

	result := &MergeResult{}

	// Pass-through for a single campaign when prefix is off: clone with overridden meta.
	if len(campaigns) == 1 && !opts.Prefix {
		merged := cloneCampaign(campaigns[0])
		merged.APIVersion = "v1"
		merged.Kind = "Campaign"
		merged.Meta.Name = opts.Name
		merged.Meta.Description = "Merged campaign: " + campaigns[0].Meta.Name
		merged.Meta.Created = time.Now().UTC().Format("2006-01-02")
		merged.Meta.Modified = merged.Meta.Created
		result.Campaign = merged
		return result, nil
	}

	merged := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Variables:  make(map[string]string),
	}

	// Build merged meta.
	merged.Meta = mergeMeta(campaigns, opts.Name)

	// Build a set of all stage IDs per source campaign (needed for prefix cross-ref logic).
	campaignStageIDs := make([]map[string]bool, len(campaigns))
	for i, c := range campaigns {
		ids := make(map[string]bool, len(c.Stages))
		for _, s := range c.Stages {
			ids[s.ID] = true
		}
		campaignStageIDs[i] = ids
	}

	// Track which stage IDs have been seen and from which campaign.
	stageIDSources := make(map[string][]string) // stageID -> list of campaign names

	// Merge stages.
	for i, c := range campaigns {
		prefix := sanitizeName(c.Meta.Name)
		for _, stage := range c.Stages {
			s := cloneStage(stage)

			if opts.Prefix {
				origID := s.ID
				s.ID = prefix + "/" + s.ID

				// Update depends_on: prefix references that belong to this campaign.
				for j, dep := range s.DependsOn {
					if campaignStageIDs[i][dep] {
						s.DependsOn[j] = prefix + "/" + dep
					}
				}
				// Update on_success reference.
				if s.OnSuccess != "" && campaignStageIDs[i][s.OnSuccess] {
					s.OnSuccess = prefix + "/" + s.OnSuccess
				}
				// Update on_failure reference (only if it looks like a stage ID, not "abort"/"skip"/"continue").
				if s.OnFailure != "" && campaignStageIDs[i][s.OnFailure] {
					s.OnFailure = prefix + "/" + s.OnFailure
				}

				_ = origID // suppress unused warning
			}

			// Check for ID collision.
			if sources, exists := stageIDSources[s.ID]; exists {
				switch opts.Strategy {
				case "first":
					// Skip this duplicate stage.
					continue
				case "error":
					// Record the conflict — append to existing sources.
					// We'll deduplicate later.
					stageIDSources[s.ID] = append(sources, c.Meta.Name)
					continue
				}
			}

			stageIDSources[s.ID] = []string{c.Meta.Name}
			merged.Stages = append(merged.Stages, s)
		}
	}

	// Build conflicts for any stage IDs that had more than one source.
	for id, sources := range stageIDSources {
		if len(sources) > 1 {
			result.Conflicts = append(result.Conflicts, MergeConflict{
				Type:    "stage_id",
				Key:     id,
				Sources: sources,
			})
		}
	}
	// Sort conflicts for deterministic output.
	sort.Slice(result.Conflicts, func(i, j int) bool {
		return result.Conflicts[i].Key < result.Conflicts[j].Key
	})

	// Merge variables.
	mergeVariables(campaigns, merged, result, opts.Strategy)

	merged.Meta.Created = time.Now().UTC().Format("2006-01-02")
	merged.Meta.Modified = merged.Meta.Created

	result.Campaign = merged
	return result, nil
}

// MergeFiles loads campaigns from file paths and merges them.
func MergeFiles(paths []string, opts MergeOptions) (*MergeResult, error) {
	if len(paths) == 0 {
		return nil, errors.New("merge: no file paths provided")
	}
	campaigns := make([]*Campaign, 0, len(paths))
	for _, p := range paths {
		c, err := Load(p)
		if err != nil {
			return nil, fmt.Errorf("merge: loading %q: %w", p, err)
		}
		campaigns = append(campaigns, c)
	}
	return Merge(campaigns, opts)
}

// mergeMeta composes metadata from all source campaigns.
func mergeMeta(campaigns []*Campaign, name string) Meta {
	m := Meta{
		Name: name,
	}

	// Collect campaign names for description.
	names := make([]string, 0, len(campaigns))
	for _, c := range campaigns {
		names = append(names, c.Meta.Name)
	}
	m.Description = "Merged campaign: " + strings.Join(names, ", ")

	// Adversary: joined unique adversaries.
	m.Adversary = mergeUniqueJoined(campaigns, func(c *Campaign) string { return c.Meta.Adversary }, " + ")

	// Severity: highest wins.
	m.Severity = highestSeverity(campaigns)

	// MitreVersion: highest version string.
	m.MitreVersion = highestVersion(campaigns)

	// Tags: union, sorted, deduped.
	m.Tags = mergeStringSlices(campaigns, func(c *Campaign) []string { return c.Meta.Tags })

	// Authors: union, sorted, deduped.
	m.Authors = mergeStringSlices(campaigns, func(c *Campaign) []string { return c.Meta.Authors })

	// References: union, sorted, deduped.
	m.References = mergeStringSlices(campaigns, func(c *Campaign) []string { return c.Meta.References })

	return m
}

// mergeUniqueJoined collects unique non-empty string values from campaigns and joins them.
func mergeUniqueJoined(campaigns []*Campaign, extract func(*Campaign) string, sep string) string {
	seen := make(map[string]bool)
	var vals []string
	for _, c := range campaigns {
		v := extract(c)
		if v != "" && !seen[v] {
			seen[v] = true
			vals = append(vals, v)
		}
	}
	return strings.Join(vals, sep)
}

// highestSeverity returns the most severe severity across all campaigns.
func highestSeverity(campaigns []*Campaign) string {
	best := -1
	bestLabel := "low"
	for _, c := range campaigns {
		rank, ok := severityRank[strings.ToLower(c.Meta.Severity)]
		if ok && rank > best {
			best = rank
			bestLabel = strings.ToLower(c.Meta.Severity)
		}
	}
	return bestLabel
}

// highestVersion returns the lexicographically highest MITRE version.
func highestVersion(campaigns []*Campaign) string {
	best := ""
	for _, c := range campaigns {
		if c.Meta.MitreVersion > best {
			best = c.Meta.MitreVersion
		}
	}
	return best
}

// mergeStringSlices collects, deduplicates, and sorts strings from all campaigns.
func mergeStringSlices(campaigns []*Campaign, extract func(*Campaign) []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, c := range campaigns {
		for _, v := range extract(c) {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// mergeVariables merges variables from all campaigns into the merged campaign.
// Same key with same value produces a warning. Same key with different value
// is a conflict under "error" strategy, or a warning under "first" strategy.
func mergeVariables(campaigns []*Campaign, merged *Campaign, result *MergeResult, strategy string) {
	// Track variable sources: key -> map[value] -> list of campaign names.
	varSources := make(map[string]map[string][]string)

	for _, c := range campaigns {
		for k, v := range c.Variables {
			if varSources[k] == nil {
				varSources[k] = make(map[string][]string)
			}
			varSources[k][v] = append(varSources[k][v], c.Meta.Name)
		}
	}

	for k, valMap := range varSources {
		if len(valMap) == 1 {
			// All campaigns that define this variable agree on the value.
			for v, sources := range valMap {
				merged.Variables[k] = v
				if len(sources) > 1 {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("variable %q defined in multiple campaigns with same value %q", k, v))
				}
			}
		} else {
			// Different values for the same key.
			var sources []string
			for _, ss := range valMap {
				sources = append(sources, ss...)
			}
			sort.Strings(sources)

			// Pick the first value: iterate campaigns in order to find
			// the first definition, ensuring deterministic choice.
			for _, c := range campaigns {
				if v, ok := c.Variables[k]; ok {
					merged.Variables[k] = v
					break
				}
			}

			if strategy == "first" {
				// Under "first" strategy, variable collisions become warnings.
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("variable %q has conflicting values across campaigns; using first value", k))
			} else {
				// Under "error" strategy, variable collisions are conflicts.
				result.Conflicts = append(result.Conflicts, MergeConflict{
					Type:    "variable",
					Key:     k,
					Sources: sources,
				})
			}
		}
	}

	// Clean up empty variables map.
	if len(merged.Variables) == 0 {
		merged.Variables = nil
	}

	// Sort warnings for deterministic output.
	sort.Strings(result.Warnings)
}

// sanitizeName returns a filesystem/ID-safe version of a campaign name.
func sanitizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "-")
	return name
}

// cloneCampaign returns a deep copy of a campaign.
func cloneCampaign(c *Campaign) *Campaign {
	out := *c
	out.Meta.Tags = cloneStrings(c.Meta.Tags)
	out.Meta.Authors = cloneStrings(c.Meta.Authors)
	out.Meta.References = cloneStrings(c.Meta.References)
	if c.Variables != nil {
		out.Variables = make(map[string]string, len(c.Variables))
		for k, v := range c.Variables {
			out.Variables[k] = v
		}
	}
	out.Stages = make([]Stage, len(c.Stages))
	for i, s := range c.Stages {
		out.Stages[i] = cloneStage(s)
	}
	return &out
}

// cloneStage returns a deep copy of a stage.
func cloneStage(s Stage) Stage {
	out := s
	out.Platform = cloneStrings(s.Platform)
	out.DependsOn = cloneStrings(s.DependsOn)
	out.Execute.Commands = cloneStrings(s.Execute.Commands)
	out.Execute.Cleanup = cloneStrings(s.Execute.Cleanup)
	if s.Execute.Args != nil {
		out.Execute.Args = make(map[string]string, len(s.Execute.Args))
		for k, v := range s.Execute.Args {
			out.Execute.Args[k] = v
		}
	}
	out.Expect.Telemetry = cloneStrings(s.Expect.Telemetry)
	out.Expect.Detections = cloneStrings(s.Expect.Detections)
	out.Expect.Artifacts = cloneStrings(s.Expect.Artifacts)
	out.Expect.IOCs = cloneStrings(s.Expect.IOCs)
	return out
}

// cloneStrings returns a copy of a string slice. Nil in, nil out.
func cloneStrings(ss []string) []string {
	if ss == nil {
		return nil
	}
	out := make([]string, len(ss))
	copy(out, ss)
	return out
}
