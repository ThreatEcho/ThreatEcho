// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"sort"
	"strings"
)

// Profile holds detailed complexity and coverage metrics for a campaign.
type Profile struct {
	// Identity
	Name      string
	Adversary string
	Severity  string

	// Size metrics
	StageCount      int
	TechniqueCount  int
	TacticCount     int
	TelemetryTypes  int
	DetectionRules  int
	VariableCount   int
	DependencyEdges int

	// Execution profile
	ShellStages    int
	HTTPStages     int
	FileStages     int
	RegistryStages int
	ServiceStages  int
	ElevatedStages int

	// Coverage
	AttackTechniques []string // T-prefixed technique IDs
	AtlasTechniques  []string // AML-prefixed technique IDs
	OwaspTechniques  []string // LLM-prefixed technique IDs
	TacticsUsed      []string

	// Telemetry breakdown
	TelemetryByCategory map[string][]string // category → type list
	MostUsedTelemetry   []TelemetryUsage

	// Graph metrics
	MaxDepth      int
	EntryPoints   int
	TerminalNodes int
	ParallelWidth int // widest parallel level
	HasCycles     bool

	// Complexity score (0-100, higher = more complex)
	ComplexityScore int
	ComplexityGrade string // A (simple), B, C, D, E (very complex)

	// Quality indicators
	DetectionCoverage float64 // percentage of stages with detections
	TelemetryCoverage float64 // percentage of stages with telemetry
}

// TelemetryUsage tracks how many stages use a given telemetry type.
type TelemetryUsage struct {
	Type  string
	Count int
}

// ProfileCampaign analyzes a campaign and returns detailed metrics.
func ProfileCampaign(c *Campaign) *Profile {
	p := &Profile{
		Name:      c.Meta.Name,
		Adversary: c.Meta.Adversary,
		Severity:  c.Meta.Severity,

		StageCount:          len(c.Stages),
		VariableCount:       len(c.Variables),
		TelemetryByCategory: make(map[string][]string),
	}

	// Technique classification
	techSet := make(map[string]bool)
	tacticSet := make(map[string]bool)
	telSet := make(map[string]bool)
	detSet := make(map[string]bool)
	telCount := make(map[string]int) // telemetry type → stage count

	stagesWithDetections := 0
	stagesWithTelemetry := 0

	for _, s := range c.Stages {
		// Technique classification
		if s.Technique != "" && !techSet[s.Technique] {
			techSet[s.Technique] = true
			if strings.HasPrefix(s.Technique, "T") {
				p.AttackTechniques = append(p.AttackTechniques, s.Technique)
			} else if strings.HasPrefix(s.Technique, "AML.") {
				p.AtlasTechniques = append(p.AtlasTechniques, s.Technique)
			} else if strings.HasPrefix(s.Technique, "LLM") {
				p.OwaspTechniques = append(p.OwaspTechniques, s.Technique)
			}
		}

		// Tactics
		if s.Tactic != "" && !tacticSet[s.Tactic] {
			tacticSet[s.Tactic] = true
			p.TacticsUsed = append(p.TacticsUsed, s.Tactic)
		}

		// Execute type breakdown
		switch s.Execute.Type {
		case "shell":
			p.ShellStages++
		case "http":
			p.HTTPStages++
		case "file":
			p.FileStages++
		case "registry":
			p.RegistryStages++
		case "service":
			p.ServiceStages++
		}
		if s.Execute.Elevated {
			p.ElevatedStages++
		}

		// Telemetry
		if len(s.Expect.Telemetry) > 0 {
			stagesWithTelemetry++
		}
		for _, t := range s.Expect.Telemetry {
			if !telSet[t] {
				telSet[t] = true
			}
			telCount[t]++
		}

		// Detections
		if len(s.Expect.Detections) > 0 {
			stagesWithDetections++
		}
		for _, d := range s.Expect.Detections {
			if !detSet[d] {
				detSet[d] = true
			}
		}

		// Dependencies
		p.DependencyEdges += len(s.DependsOn)
	}

	p.TechniqueCount = len(techSet)
	p.TacticCount = len(tacticSet)
	p.TelemetryTypes = len(telSet)
	p.DetectionRules = len(detSet)

	// Sort technique lists
	sort.Strings(p.AttackTechniques)
	sort.Strings(p.AtlasTechniques)
	sort.Strings(p.OwaspTechniques)
	sort.Strings(p.TacticsUsed)

	// Telemetry usage ranking
	for t, count := range telCount {
		p.MostUsedTelemetry = append(p.MostUsedTelemetry, TelemetryUsage{Type: t, Count: count})
	}
	sort.Slice(p.MostUsedTelemetry, func(i, j int) bool {
		if p.MostUsedTelemetry[i].Count != p.MostUsedTelemetry[j].Count {
			return p.MostUsedTelemetry[i].Count > p.MostUsedTelemetry[j].Count
		}
		return p.MostUsedTelemetry[i].Type < p.MostUsedTelemetry[j].Type
	})

	// Coverage percentages
	if p.StageCount > 0 {
		p.DetectionCoverage = float64(stagesWithDetections) / float64(p.StageCount) * 100
		p.TelemetryCoverage = float64(stagesWithTelemetry) / float64(p.StageCount) * 100
	}

	// Graph metrics via AnalyzeGraph
	ga := AnalyzeGraph(c)
	p.MaxDepth = ga.MaxDepth
	p.EntryPoints = len(ga.EntryPoints)
	p.TerminalNodes = len(ga.TerminalStages)
	p.HasCycles = ga.HasCycles

	// Parallel width: widest level
	for _, level := range ga.Parallel {
		if len(level) > p.ParallelWidth {
			p.ParallelWidth = len(level)
		}
	}

	// Complexity score calculation
	p.ComplexityScore = computeComplexity(p)
	p.ComplexityGrade = complexityGrade(p.ComplexityScore)

	return p
}

// computeComplexity produces a 0-100 score from profile metrics.
// Factors: stage count, dependency density, technique diversity,
// execution diversity, depth, parallelism.
func computeComplexity(p *Profile) int {
	score := 0

	// Stage count contribution (0-25)
	switch {
	case p.StageCount >= 15:
		score += 25
	case p.StageCount >= 10:
		score += 20
	case p.StageCount >= 7:
		score += 15
	case p.StageCount >= 4:
		score += 10
	case p.StageCount >= 2:
		score += 5
	}

	// Technique diversity (0-15)
	switch {
	case p.TechniqueCount >= 12:
		score += 15
	case p.TechniqueCount >= 8:
		score += 12
	case p.TechniqueCount >= 5:
		score += 8
	case p.TechniqueCount >= 3:
		score += 4
	}

	// Tactic breadth (0-15)
	switch {
	case p.TacticCount >= 10:
		score += 15
	case p.TacticCount >= 7:
		score += 12
	case p.TacticCount >= 5:
		score += 8
	case p.TacticCount >= 3:
		score += 4
	}

	// Dependency density (0-15)
	if p.StageCount > 1 {
		density := float64(p.DependencyEdges) / float64(p.StageCount-1)
		switch {
		case density >= 2.0:
			score += 15
		case density >= 1.5:
			score += 12
		case density >= 1.0:
			score += 8
		case density >= 0.5:
			score += 4
		}
	}

	// Graph depth (0-10)
	switch {
	case p.MaxDepth >= 8:
		score += 10
	case p.MaxDepth >= 5:
		score += 7
	case p.MaxDepth >= 3:
		score += 4
	case p.MaxDepth >= 2:
		score += 2
	}

	// Execution type diversity (0-10)
	execTypes := 0
	if p.ShellStages > 0 {
		execTypes++
	}
	if p.HTTPStages > 0 {
		execTypes++
	}
	if p.FileStages > 0 {
		execTypes++
	}
	if p.RegistryStages > 0 {
		execTypes++
	}
	if p.ServiceStages > 0 {
		execTypes++
	}
	score += execTypes * 2

	// Multi-framework bonus (0-10)
	frameworks := 0
	if len(p.AttackTechniques) > 0 {
		frameworks++
	}
	if len(p.AtlasTechniques) > 0 {
		frameworks++
	}
	if len(p.OwaspTechniques) > 0 {
		frameworks++
	}
	switch frameworks {
	case 3:
		score += 10
	case 2:
		score += 5
	}

	if score > 100 {
		score = 100
	}
	return score
}

func complexityGrade(score int) string {
	switch {
	case score >= 80:
		return "E" // very complex
	case score >= 60:
		return "D"
	case score >= 40:
		return "C"
	case score >= 20:
		return "B"
	default:
		return "A" // simple
	}
}

// FormatProfile returns a human-readable profile report.
func FormatProfile(p *Profile) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Campaign Profile: %s\n", p.Name))
	sb.WriteString(strings.Repeat("═", 60) + "\n\n")

	// Identity
	sb.WriteString(fmt.Sprintf("  Adversary:   %s\n", p.Adversary))
	sb.WriteString(fmt.Sprintf("  Severity:    %s\n", p.Severity))
	sb.WriteString(fmt.Sprintf("  Complexity:  %d/100 (Grade %s)\n", p.ComplexityScore, p.ComplexityGrade))
	sb.WriteString("\n")

	// Size
	sb.WriteString("Size\n")
	sb.WriteString(strings.Repeat("─", 40) + "\n")
	sb.WriteString(fmt.Sprintf("  Stages:         %d\n", p.StageCount))
	sb.WriteString(fmt.Sprintf("  Techniques:     %d\n", p.TechniqueCount))
	sb.WriteString(fmt.Sprintf("  Tactics:        %d\n", p.TacticCount))
	sb.WriteString(fmt.Sprintf("  Telemetry types:%d\n", p.TelemetryTypes))
	sb.WriteString(fmt.Sprintf("  Detection rules:%d\n", p.DetectionRules))
	sb.WriteString(fmt.Sprintf("  Variables:      %d\n", p.VariableCount))
	sb.WriteString("\n")

	// Framework breakdown
	sb.WriteString("Framework Coverage\n")
	sb.WriteString(strings.Repeat("─", 40) + "\n")
	if len(p.AttackTechniques) > 0 {
		sb.WriteString(fmt.Sprintf("  MITRE ATT&CK:   %d techniques (%s)\n",
			len(p.AttackTechniques), strings.Join(p.AttackTechniques, ", ")))
	}
	if len(p.AtlasTechniques) > 0 {
		sb.WriteString(fmt.Sprintf("  MITRE ATLAS:     %d techniques (%s)\n",
			len(p.AtlasTechniques), strings.Join(p.AtlasTechniques, ", ")))
	}
	if len(p.OwaspTechniques) > 0 {
		sb.WriteString(fmt.Sprintf("  OWASP LLM Top10: %d techniques (%s)\n",
			len(p.OwaspTechniques), strings.Join(p.OwaspTechniques, ", ")))
	}
	sb.WriteString("\n")

	// Tactics
	sb.WriteString("Tactics Used\n")
	sb.WriteString(strings.Repeat("─", 40) + "\n")
	for _, t := range p.TacticsUsed {
		sb.WriteString(fmt.Sprintf("  • %s\n", t))
	}
	sb.WriteString("\n")

	// Execution profile
	sb.WriteString("Execution Profile\n")
	sb.WriteString(strings.Repeat("─", 40) + "\n")
	if p.ShellStages > 0 {
		sb.WriteString(fmt.Sprintf("  Shell stages:    %d\n", p.ShellStages))
	}
	if p.HTTPStages > 0 {
		sb.WriteString(fmt.Sprintf("  HTTP stages:     %d\n", p.HTTPStages))
	}
	if p.FileStages > 0 {
		sb.WriteString(fmt.Sprintf("  File stages:     %d\n", p.FileStages))
	}
	if p.RegistryStages > 0 {
		sb.WriteString(fmt.Sprintf("  Registry stages: %d\n", p.RegistryStages))
	}
	if p.ServiceStages > 0 {
		sb.WriteString(fmt.Sprintf("  Service stages:  %d\n", p.ServiceStages))
	}
	if p.ElevatedStages > 0 {
		sb.WriteString(fmt.Sprintf("  Elevated stages: %d ⚠\n", p.ElevatedStages))
	}
	sb.WriteString("\n")

	// Graph metrics
	sb.WriteString("Dependency Graph\n")
	sb.WriteString(strings.Repeat("─", 40) + "\n")
	sb.WriteString(fmt.Sprintf("  Max depth:       %d\n", p.MaxDepth))
	sb.WriteString(fmt.Sprintf("  Entry points:    %d\n", p.EntryPoints))
	sb.WriteString(fmt.Sprintf("  Terminal nodes:  %d\n", p.TerminalNodes))
	sb.WriteString(fmt.Sprintf("  Dependency edges:%d\n", p.DependencyEdges))
	sb.WriteString(fmt.Sprintf("  Parallel width:  %d\n", p.ParallelWidth))
	if p.HasCycles {
		sb.WriteString("  ⚠ Dependency cycle detected\n")
	}
	sb.WriteString("\n")

	// Quality
	sb.WriteString("Quality Indicators\n")
	sb.WriteString(strings.Repeat("─", 40) + "\n")
	sb.WriteString(fmt.Sprintf("  Detection coverage: %.0f%%\n", p.DetectionCoverage))
	sb.WriteString(fmt.Sprintf("  Telemetry coverage: %.0f%%\n", p.TelemetryCoverage))
	sb.WriteString("\n")

	// Top telemetry
	if len(p.MostUsedTelemetry) > 0 {
		sb.WriteString("Top Telemetry Types\n")
		sb.WriteString(strings.Repeat("─", 40) + "\n")
		limit := len(p.MostUsedTelemetry)
		if limit > 10 {
			limit = 10
		}
		for _, tu := range p.MostUsedTelemetry[:limit] {
			bar := strings.Repeat("█", tu.Count)
			sb.WriteString(fmt.Sprintf("  %-25s %s (%d)\n", tu.Type, bar, tu.Count))
		}
	}

	return sb.String()
}

// ProfileDir profiles all campaigns in a directory and returns
// a sorted slice (by complexity score descending).
func ProfileDir(dir string) ([]*Profile, error) {
	summaries, err := LoadDir(dir)
	if err != nil {
		return nil, err
	}

	var profiles []*Profile
	for _, s := range summaries {
		c, err := Load(s.Path)
		if err != nil {
			continue
		}
		profiles = append(profiles, ProfileCampaign(c))
	}

	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].ComplexityScore > profiles[j].ComplexityScore
	})

	return profiles, nil
}

// FormatProfileSummary returns a compact table of multiple profiles.
func FormatProfileSummary(profiles []*Profile) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%-28s %-5s %-8s %-6s %-6s %-6s %-7s %-6s %s\n",
		"CAMPAIGN", "GRADE", "COMPLEX", "STAGES", "TECHS", "TACTS", "DET%", "TEL%", "FRAMEWORKS"))
	sb.WriteString(strings.Repeat("─", 100) + "\n")

	for _, p := range profiles {
		frameworks := []string{}
		if len(p.AttackTechniques) > 0 {
			frameworks = append(frameworks, fmt.Sprintf("ATT&CK(%d)", len(p.AttackTechniques)))
		}
		if len(p.AtlasTechniques) > 0 {
			frameworks = append(frameworks, fmt.Sprintf("ATLAS(%d)", len(p.AtlasTechniques)))
		}
		if len(p.OwaspTechniques) > 0 {
			frameworks = append(frameworks, fmt.Sprintf("OWASP(%d)", len(p.OwaspTechniques)))
		}

		sb.WriteString(fmt.Sprintf("%-28s %-5s %-8d %-6d %-6d %-6d %-7.0f %-6.0f %s\n",
			p.Name, p.ComplexityGrade, p.ComplexityScore, p.StageCount,
			p.TechniqueCount, p.TacticCount,
			p.DetectionCoverage, p.TelemetryCoverage,
			strings.Join(frameworks, " ")))
	}

	return sb.String()
}
