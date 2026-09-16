// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// ProjectStats holds aggregate statistics across all campaigns in a project.
type ProjectStats struct {
	// Campaign-level
	TotalCampaigns int
	TotalStages    int
	SeverityCounts map[string]int // critical:3, high:2, etc.
	AdversaryList  []string       // unique adversaries sorted

	// Technique analysis
	TotalUniqueTechniques int
	TechniqueFrequency    []TechniqueFreq // sorted by count desc
	TacticDistribution    []TacticDist    // sorted by count desc
	FrameworkBreakdown    FrameworkStats

	// Execution analysis
	ExecTypeCounts map[string]int // shell:45, http:12, etc.
	ElevatedCount  int
	TotalCommands  int

	// Detection readiness
	StagesWithDetections int
	StagesWithTelemetry  int
	StagesWithoutEither  int
	DetectionCoverage    float64 // percentage
	TelemetryCoverage    float64

	// Dependency complexity
	TotalDependencies int
	MaxGraphDepth     int
	AvgGraphDepth     float64

	// Content metrics
	TotalVariables     int
	UniqueVariableKeys []string
	TotalCleanupCmds   int
	StagesWithTimeout  int
	StagesWithDelay    int
}

// TechniqueFreq holds a technique ID and how many stages use it.
type TechniqueFreq struct {
	TechniqueID string
	Name        string // resolved name from mitre registry
	Count       int
	Campaigns   []string // which campaigns use it
}

// TacticDist holds a tactic and its stage count.
type TacticDist struct {
	Tactic    string
	Count     int
	Campaigns []string
}

// FrameworkStats breaks down technique usage by framework.
type FrameworkStats struct {
	ATTACKCount  int
	ATLASCount   int
	OWASPCount   int
	UnknownCount int
}

// ComputeStats computes aggregate statistics from multiple campaigns.
func ComputeStats(campaigns []*Campaign) *ProjectStats {
	ps := &ProjectStats{
		SeverityCounts: make(map[string]int),
		ExecTypeCounts: make(map[string]int),
	}

	if len(campaigns) == 0 {
		return ps
	}

	ps.TotalCampaigns = len(campaigns)

	// Track unique values across all campaigns.
	adversarySet := make(map[string]bool)
	techniqueMap := make(map[string]*TechniqueFreq) // technique ID -> freq entry
	tacticMap := make(map[string]*TacticDist)       // tactic -> dist entry
	variableKeySet := make(map[string]bool)

	var depthSum float64
	var depthCount int

	for _, c := range campaigns {
		if c == nil {
			continue
		}

		campaignName := c.Meta.Name

		// Severity.
		if c.Meta.Severity != "" {
			ps.SeverityCounts[c.Meta.Severity]++
		}

		// Adversary.
		if c.Meta.Adversary != "" {
			adversarySet[c.Meta.Adversary] = true
		}

		// Variables.
		for k := range c.Variables {
			variableKeySet[k] = true
		}
		ps.TotalVariables += len(c.Variables)

		// Stage-level metrics.
		ps.TotalStages += len(c.Stages)

		for _, s := range c.Stages {
			// Technique frequency.
			if s.Technique != "" {
				tf, ok := techniqueMap[s.Technique]
				if !ok {
					name := mitre.ResolveName(s.Technique)
					tf = &TechniqueFreq{
						TechniqueID: s.Technique,
						Name:        name,
					}
					techniqueMap[s.Technique] = tf
				}
				tf.Count++
				if !containsString(tf.Campaigns, campaignName) {
					tf.Campaigns = append(tf.Campaigns, campaignName)
				}

				// Framework breakdown.
				switch mitre.ClassifyFramework(s.Technique) {
				case "attack":
					ps.FrameworkBreakdown.ATTACKCount++
				case "atlas":
					ps.FrameworkBreakdown.ATLASCount++
				case "owasp":
					ps.FrameworkBreakdown.OWASPCount++
				default:
					ps.FrameworkBreakdown.UnknownCount++
				}
			}

			// Tactic distribution.
			if s.Tactic != "" {
				td, ok := tacticMap[s.Tactic]
				if !ok {
					td = &TacticDist{Tactic: s.Tactic}
					tacticMap[s.Tactic] = td
				}
				td.Count++
				if !containsString(td.Campaigns, campaignName) {
					td.Campaigns = append(td.Campaigns, campaignName)
				}
			}

			// Execution type.
			if s.Execute.Type != "" {
				ps.ExecTypeCounts[s.Execute.Type]++
			}

			// Commands count.
			ps.TotalCommands += len(s.Execute.Commands)

			// Elevated.
			if s.Execute.Elevated {
				ps.ElevatedCount++
			}

			// Cleanup commands.
			ps.TotalCleanupCmds += len(s.Execute.Cleanup)

			// Detection readiness.
			hasDetections := len(s.Expect.Detections) > 0
			hasTelemetry := len(s.Expect.Telemetry) > 0
			if hasDetections {
				ps.StagesWithDetections++
			}
			if hasTelemetry {
				ps.StagesWithTelemetry++
			}
			if !hasDetections && !hasTelemetry {
				ps.StagesWithoutEither++
			}

			// Dependencies count.
			ps.TotalDependencies += len(s.DependsOn)

			// Timeout/delay.
			if s.Timeout.Duration > 0 {
				ps.StagesWithTimeout++
			}
			if s.Delay.Duration > 0 {
				ps.StagesWithDelay++
			}
		}

		// Graph depth per campaign.
		ga := AnalyzeGraph(c)
		if ga.MaxDepth > ps.MaxGraphDepth {
			ps.MaxGraphDepth = ga.MaxDepth
		}
		if ga.MaxDepth > 0 {
			depthSum += float64(ga.MaxDepth)
			depthCount++
		}
	}

	// Finalize adversary list.
	for adv := range adversarySet {
		ps.AdversaryList = append(ps.AdversaryList, adv)
	}
	sort.Strings(ps.AdversaryList)

	// Finalize technique frequency.
	ps.TotalUniqueTechniques = len(techniqueMap)
	for _, tf := range techniqueMap {
		ps.TechniqueFrequency = append(ps.TechniqueFrequency, *tf)
	}
	sort.Slice(ps.TechniqueFrequency, func(i, j int) bool {
		if ps.TechniqueFrequency[i].Count != ps.TechniqueFrequency[j].Count {
			return ps.TechniqueFrequency[i].Count > ps.TechniqueFrequency[j].Count
		}
		return ps.TechniqueFrequency[i].TechniqueID < ps.TechniqueFrequency[j].TechniqueID
	})

	// Finalize tactic distribution.
	for _, td := range tacticMap {
		ps.TacticDistribution = append(ps.TacticDistribution, *td)
	}
	sort.Slice(ps.TacticDistribution, func(i, j int) bool {
		if ps.TacticDistribution[i].Count != ps.TacticDistribution[j].Count {
			return ps.TacticDistribution[i].Count > ps.TacticDistribution[j].Count
		}
		return ps.TacticDistribution[i].Tactic < ps.TacticDistribution[j].Tactic
	})

	// Finalize variable keys.
	for k := range variableKeySet {
		ps.UniqueVariableKeys = append(ps.UniqueVariableKeys, k)
	}
	sort.Strings(ps.UniqueVariableKeys)

	// Coverage percentages.
	if ps.TotalStages > 0 {
		ps.DetectionCoverage = float64(ps.StagesWithDetections) / float64(ps.TotalStages) * 100
		ps.TelemetryCoverage = float64(ps.StagesWithTelemetry) / float64(ps.TotalStages) * 100
	}

	// Average graph depth.
	if depthCount > 0 {
		ps.AvgGraphDepth = depthSum / float64(depthCount)
	}

	return ps
}

// ComputeStatsDir loads all campaigns from a directory and computes stats.
func ComputeStatsDir(dir string) (*ProjectStats, error) {
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

	return ComputeStats(campaigns), nil
}

// FormatStats formats statistics as a human-readable dashboard.
func FormatStats(stats *ProjectStats) string {
	if stats == nil {
		return ""
	}

	var b strings.Builder

	// Header.
	b.WriteString("\n")
	b.WriteString(boxLine("top"))
	b.WriteString(boxCenter("ThreatEcho Project Statistics"))
	b.WriteString(boxLine("mid"))
	b.WriteString("\n")

	// Campaign summary.
	fmt.Fprintf(&b, "  Campaigns: %-8d Stages: %-8d Adversaries: %d\n",
		stats.TotalCampaigns, stats.TotalStages, len(stats.AdversaryList))

	if len(stats.SeverityCounts) > 0 {
		b.WriteString("  Severity:  ")
		severities := sortedMapKeys(stats.SeverityCounts)
		parts := make([]string, 0, len(severities))
		for _, sev := range severities {
			parts = append(parts, fmt.Sprintf("%s(%d)", sev, stats.SeverityCounts[sev]))
		}
		b.WriteString(strings.Join(parts, " "))
		b.WriteString("\n")
	}

	if len(stats.AdversaryList) > 0 {
		b.WriteString("  Actors:    ")
		b.WriteString(strings.Join(stats.AdversaryList, ", "))
		b.WriteString("\n")
	}

	// Technique Analysis.
	b.WriteString("\n")
	b.WriteString(sectionHeader("Technique Analysis"))
	fmt.Fprintf(&b, "  Unique techniques: %d\n", stats.TotalUniqueTechniques)
	fmt.Fprintf(&b, "  Frameworks: ATT&CK(%d) ATLAS(%d) OWASP(%d)",
		stats.FrameworkBreakdown.ATTACKCount,
		stats.FrameworkBreakdown.ATLASCount,
		stats.FrameworkBreakdown.OWASPCount)
	if stats.FrameworkBreakdown.UnknownCount > 0 {
		fmt.Fprintf(&b, " Unknown(%d)", stats.FrameworkBreakdown.UnknownCount)
	}
	b.WriteString("\n")

	if len(stats.TechniqueFrequency) > 0 {
		b.WriteString("\n  Top techniques:\n")
		limit := len(stats.TechniqueFrequency)
		if limit > 10 {
			limit = 10
		}
		maxCount := stats.TechniqueFrequency[0].Count
		for i := 0; i < limit; i++ {
			tf := stats.TechniqueFrequency[i]
			name := tf.Name
			if name == "" {
				name = "(unknown)"
			}
			if len(name) > 30 {
				name = name[:27] + "..."
			}
			bar := renderBar(tf.Count, maxCount, 10)
			fmt.Fprintf(&b, "    %-12s %-30s %s  %d campaigns\n",
				tf.TechniqueID, name, bar, len(tf.Campaigns))
		}
	}

	// Tactic Distribution.
	b.WriteString("\n")
	b.WriteString(sectionHeader("Tactic Distribution"))
	if len(stats.TacticDistribution) > 0 {
		maxCount := stats.TacticDistribution[0].Count
		for _, td := range stats.TacticDistribution {
			bar := renderBar(td.Count, maxCount, 16)
			fmt.Fprintf(&b, "    %-22s %s  %d stages\n", td.Tactic, bar, td.Count)
		}
	}

	// Execution Profile.
	b.WriteString("\n")
	b.WriteString(sectionHeader("Execution Profile"))
	if len(stats.ExecTypeCounts) > 0 {
		b.WriteString("    ")
		execTypes := sortedMapKeys(stats.ExecTypeCounts)
		parts := make([]string, 0, len(execTypes))
		for _, et := range execTypes {
			parts = append(parts, fmt.Sprintf("%s: %d", et, stats.ExecTypeCounts[et]))
		}
		b.WriteString(strings.Join(parts, "   "))
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "    Elevated: %d stages   Cleanup: %d commands\n",
		stats.ElevatedCount, stats.TotalCleanupCmds)

	// Detection Readiness.
	b.WriteString("\n")
	b.WriteString(sectionHeader("Detection Readiness"))
	detBar := renderBar(stats.StagesWithDetections, stats.TotalStages, 10)
	telBar := renderBar(stats.StagesWithTelemetry, stats.TotalStages, 10)
	fmt.Fprintf(&b, "    With detections:  %d/%d (%.1f%%)  %s\n",
		stats.StagesWithDetections, stats.TotalStages, stats.DetectionCoverage, detBar)
	fmt.Fprintf(&b, "    With telemetry:   %d/%d (%.1f%%)  %s\n",
		stats.StagesWithTelemetry, stats.TotalStages, stats.TelemetryCoverage, telBar)
	fmt.Fprintf(&b, "    Neither:          %d stages\n", stats.StagesWithoutEither)

	// Dependency Graph.
	b.WriteString("\n")
	b.WriteString(sectionHeader("Dependency Graph"))
	fmt.Fprintf(&b, "    Total dependencies: %d\n", stats.TotalDependencies)
	fmt.Fprintf(&b, "    Max depth: %d\n", stats.MaxGraphDepth)
	fmt.Fprintf(&b, "    Avg depth: %.1f\n", stats.AvgGraphDepth)

	// Content Metrics.
	b.WriteString("\n")
	b.WriteString(sectionHeader("Content Metrics"))
	fmt.Fprintf(&b, "    Variables: %d (%d unique keys)\n", stats.TotalVariables, len(stats.UniqueVariableKeys))
	fmt.Fprintf(&b, "    Commands:  %d total\n", stats.TotalCommands)
	fmt.Fprintf(&b, "    Timeouts:  %d stages   Delays: %d stages\n",
		stats.StagesWithTimeout, stats.StagesWithDelay)

	b.WriteString("\n")
	b.WriteString(boxLine("bottom"))

	return b.String()
}

// containsString returns true if the slice contains the given string.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// sortedMapKeys returns the keys of a map[string]int sorted alphabetically.
func sortedMapKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// renderBar renders a proportional bar chart using block characters.
func renderBar(value, max, width int) string {
	if max <= 0 || width <= 0 {
		return strings.Repeat("░", width) // light shade for zero
	}
	filled := int(math.Round(float64(value) / float64(max) * float64(width)))
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

const boxWidth = 54

func boxLine(pos string) string {
	switch pos {
	case "top":
		return "╔" + strings.Repeat("═", boxWidth) + "╗\n"
	case "mid":
		return "╠" + strings.Repeat("═", boxWidth) + "╣\n"
	case "bottom":
		return "╚" + strings.Repeat("═", boxWidth) + "╝\n"
	}
	return ""
}

func boxCenter(text string) string {
	pad := boxWidth - len(text)
	left := pad / 2
	right := pad - left
	return "║" + strings.Repeat(" ", left) + text + strings.Repeat(" ", right) + "║\n"
}

func sectionHeader(title string) string {
	dashes := boxWidth - len(title) - 5
	if dashes < 2 {
		dashes = 2
	}
	return "── " + title + " " + strings.Repeat("─", dashes) + "\n"
}
