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
	"time"

	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// ExecutiveReport holds all sections of the combined report.
type ExecutiveReport struct {
	Title         string
	GeneratedAt   string // ISO timestamp
	ProjectStats  *ProjectStats
	Scores        []*ScoredCampaign
	CampaignCount int

	// Computed summaries.
	TopRisks        []RiskItem
	CoverageGaps    []CoverageGapItem
	Recommendations []string
}

// RiskItem is one high-risk finding for the executive summary.
type RiskItem struct {
	Campaign string
	Grade    string
	Score    float64
	Reason   string
}

// CoverageGapItem is one detection gap.
type CoverageGapItem struct {
	Tactic   string
	Coverage string // e.g. "3/14 tactics covered"
	Risk     string // critical/high/medium/low
}

// GenerateReport computes the full executive report from campaigns.
func GenerateReport(campaigns []*Campaign) *ExecutiveReport {
	now := time.Now().UTC().Format(time.RFC3339)

	r := &ExecutiveReport{
		Title:         "ThreatEcho Executive Report",
		GeneratedAt:   now,
		CampaignCount: len(campaigns),
	}

	// Compute project stats.
	r.ProjectStats = ComputeStats(campaigns)

	// Score each campaign.
	for _, c := range campaigns {
		if c == nil {
			continue
		}
		sc := ScoreCampaign(c)
		if sc != nil {
			r.Scores = append(r.Scores, sc)
		}
	}

	// Sort scores descending (highest risk first).
	sort.Slice(r.Scores, func(i, j int) bool {
		return r.Scores[i].Score.OverallScore > r.Scores[j].Score.OverallScore
	})

	// Build computed summaries.
	r.TopRisks = buildTopRisks(r.Scores)
	r.CoverageGaps = buildCoverageGaps(r.ProjectStats)
	r.Recommendations = buildRecommendations(r.ProjectStats, r.Scores, r.CoverageGaps)

	return r
}

// GenerateReportDir loads all campaigns from a directory and generates a report.
func GenerateReportDir(dir string) (*ExecutiveReport, error) {
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

	return GenerateReport(campaigns), nil
}

// FormatReportText renders an executive report as rich terminal text.
func FormatReportText(r *ExecutiveReport) string {
	if r == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(boxLine("top"))
	b.WriteString(boxCenter(r.Title))
	b.WriteString(boxLine("mid"))
	b.WriteString("\n")

	// Generation timestamp.
	fmt.Fprintf(&b, "  Generated: %s\n\n", r.GeneratedAt)

	// Executive Summary section.
	b.WriteString(sectionHeader("Executive Summary"))
	fmt.Fprintf(&b, "  Campaigns:          %d\n", r.CampaignCount)
	if r.ProjectStats != nil {
		fmt.Fprintf(&b, "  Total stages:       %d\n", r.ProjectStats.TotalStages)
		fmt.Fprintf(&b, "  Unique techniques:  %d\n", r.ProjectStats.TotalUniqueTechniques)
		fmt.Fprintf(&b, "  Detection coverage: %.1f%%\n", r.ProjectStats.DetectionCoverage)
	}

	overallGrade := computeOverallGrade(r.Scores)
	fmt.Fprintf(&b, "  Overall risk grade: %s\n", overallGrade)

	// Risk Assessment section.
	b.WriteString("\n")
	b.WriteString(sectionHeader("Risk Assessment"))
	if len(r.TopRisks) == 0 {
		b.WriteString("  No campaigns scored.\n")
	}
	for _, ri := range r.TopRisks {
		gradeInd := gradeIndicator(ri.Grade)
		fmt.Fprintf(&b, "  [%s] %-30s  Score: %5.1f  Grade: %s\n",
			gradeInd, truncate(ri.Campaign, 30), ri.Score, ri.Grade)
		fmt.Fprintf(&b, "         %s\n", ri.Reason)
	}

	// Coverage Overview section.
	b.WriteString("\n")
	b.WriteString(sectionHeader("Coverage Overview"))

	if r.ProjectStats != nil {
		coveredTactics := buildCoveredTacticSet(r.ProjectStats)
		allTactics := mitre.TacticShorts()
		fmt.Fprintf(&b, "  Tactic coverage: %d/%d\n\n", len(coveredTactics), len(allTactics))

		for _, tac := range allTactics {
			marker := "  "
			if coveredTactics[tac] {
				marker = "[x]"
			} else {
				marker = "[ ]"
			}
			tacInfo := mitre.TacticByShort(tac)
			name := tac
			if tacInfo != nil {
				name = tacInfo.Name
			}
			fmt.Fprintf(&b, "    %s %s\n", marker, name)
		}

		// Top techniques.
		if len(r.ProjectStats.TechniqueFrequency) > 0 {
			b.WriteString("\n  Top techniques:\n")
			limit := len(r.ProjectStats.TechniqueFrequency)
			if limit > 10 {
				limit = 10
			}
			for i := 0; i < limit; i++ {
				tf := r.ProjectStats.TechniqueFrequency[i]
				name := tf.Name
				if name == "" {
					name = "(unknown)"
				}
				if len(name) > 30 {
					name = name[:27] + "..."
				}
				fmt.Fprintf(&b, "    %-12s %-30s  %d uses\n", tf.TechniqueID, name, tf.Count)
			}
		}
	}

	// Detection Readiness section.
	b.WriteString("\n")
	b.WriteString(sectionHeader("Detection Readiness"))
	if r.ProjectStats != nil && r.ProjectStats.TotalStages > 0 {
		total := r.ProjectStats.TotalStages
		detBar := renderBar(r.ProjectStats.StagesWithDetections, total, 10)
		telBar := renderBar(r.ProjectStats.StagesWithTelemetry, total, 10)
		neiBar := renderBar(r.ProjectStats.StagesWithoutEither, total, 10)
		fmt.Fprintf(&b, "  With detections:  %d/%d (%.1f%%)  %s\n",
			r.ProjectStats.StagesWithDetections, total, r.ProjectStats.DetectionCoverage, detBar)
		fmt.Fprintf(&b, "  With telemetry:   %d/%d (%.1f%%)  %s\n",
			r.ProjectStats.StagesWithTelemetry, total, r.ProjectStats.TelemetryCoverage, telBar)
		neiPct := float64(r.ProjectStats.StagesWithoutEither) / float64(total) * 100
		fmt.Fprintf(&b, "  Neither:          %d/%d (%.1f%%)  %s\n",
			r.ProjectStats.StagesWithoutEither, total, neiPct, neiBar)
	} else {
		b.WriteString("  No stages to analyze.\n")
	}

	// Recommendations section.
	b.WriteString("\n")
	b.WriteString(sectionHeader("Recommendations"))
	if len(r.Recommendations) == 0 {
		b.WriteString("  No recommendations at this time.\n")
	}
	for i, rec := range r.Recommendations {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, rec)
	}

	b.WriteString("\n")
	b.WriteString(boxLine("bottom"))

	return b.String()
}

// FormatReportMarkdown renders an executive report as Markdown.
func FormatReportMarkdown(r *ExecutiveReport) string {
	if r == nil {
		return ""
	}

	var b strings.Builder

	fmt.Fprintf(&b, "# %s\n\n", r.Title)
	fmt.Fprintf(&b, "_Generated: %s_\n\n", r.GeneratedAt)

	// Executive Summary.
	b.WriteString("## Executive Summary\n\n")
	fmt.Fprintf(&b, "| Metric | Value |\n")
	fmt.Fprintf(&b, "|--------|-------|\n")
	fmt.Fprintf(&b, "| Campaigns | %d |\n", r.CampaignCount)
	if r.ProjectStats != nil {
		fmt.Fprintf(&b, "| Total Stages | %d |\n", r.ProjectStats.TotalStages)
		fmt.Fprintf(&b, "| Unique Techniques | %d |\n", r.ProjectStats.TotalUniqueTechniques)
		fmt.Fprintf(&b, "| Detection Coverage | %.1f%% |\n", r.ProjectStats.DetectionCoverage)
	}
	overallGrade := computeOverallGrade(r.Scores)
	fmt.Fprintf(&b, "| Overall Risk Grade | %s |\n", overallGrade)
	b.WriteString("\n")

	// Risk Assessment.
	b.WriteString("## Risk Assessment\n\n")
	if len(r.TopRisks) == 0 {
		b.WriteString("No campaigns scored.\n\n")
	} else {
		fmt.Fprintf(&b, "| Campaign | Score | Grade | Finding |\n")
		fmt.Fprintf(&b, "|----------|-------|-------|----------|\n")
		for _, ri := range r.TopRisks {
			fmt.Fprintf(&b, "| %s | %.1f | %s | %s |\n",
				ri.Campaign, ri.Score, ri.Grade, ri.Reason)
		}
		b.WriteString("\n")
	}

	// Coverage Overview.
	b.WriteString("## Coverage Overview\n\n")
	if r.ProjectStats != nil {
		coveredTactics := buildCoveredTacticSet(r.ProjectStats)
		allTactics := mitre.TacticShorts()
		fmt.Fprintf(&b, "**Tactic coverage: %d/%d**\n\n", len(coveredTactics), len(allTactics))

		for _, tac := range allTactics {
			tacInfo := mitre.TacticByShort(tac)
			name := tac
			if tacInfo != nil {
				name = tacInfo.Name
			}
			if coveredTactics[tac] {
				fmt.Fprintf(&b, "- [x] %s\n", name)
			} else {
				fmt.Fprintf(&b, "- [ ] %s\n", name)
			}
		}
		b.WriteString("\n")

		// Top techniques.
		if len(r.ProjectStats.TechniqueFrequency) > 0 {
			b.WriteString("### Top Techniques\n\n")
			fmt.Fprintf(&b, "| Technique | Name | Uses |\n")
			fmt.Fprintf(&b, "|-----------|------|------|\n")
			limit := len(r.ProjectStats.TechniqueFrequency)
			if limit > 10 {
				limit = 10
			}
			for i := 0; i < limit; i++ {
				tf := r.ProjectStats.TechniqueFrequency[i]
				name := tf.Name
				if name == "" {
					name = "(unknown)"
				}
				fmt.Fprintf(&b, "| %s | %s | %d |\n", tf.TechniqueID, name, tf.Count)
			}
			b.WriteString("\n")
		}
	}

	// Detection Readiness.
	b.WriteString("## Detection Readiness\n\n")
	if r.ProjectStats != nil && r.ProjectStats.TotalStages > 0 {
		total := r.ProjectStats.TotalStages
		neiPct := float64(r.ProjectStats.StagesWithoutEither) / float64(total) * 100
		fmt.Fprintf(&b, "| Category | Count | Percentage |\n")
		fmt.Fprintf(&b, "|----------|-------|------------|\n")
		fmt.Fprintf(&b, "| With Detections | %d/%d | %.1f%% |\n",
			r.ProjectStats.StagesWithDetections, total, r.ProjectStats.DetectionCoverage)
		fmt.Fprintf(&b, "| With Telemetry | %d/%d | %.1f%% |\n",
			r.ProjectStats.StagesWithTelemetry, total, r.ProjectStats.TelemetryCoverage)
		fmt.Fprintf(&b, "| Neither | %d/%d | %.1f%% |\n",
			r.ProjectStats.StagesWithoutEither, total, neiPct)
		b.WriteString("\n")
	} else {
		b.WriteString("No stages to analyze.\n\n")
	}

	// Recommendations.
	b.WriteString("## Recommendations\n\n")
	if len(r.Recommendations) == 0 {
		b.WriteString("No recommendations at this time.\n")
	}
	for i, rec := range r.Recommendations {
		fmt.Fprintf(&b, "%d. %s\n", i+1, rec)
	}

	return b.String()
}

// buildTopRisks extracts risk items from scored campaigns.
func buildTopRisks(scores []*ScoredCampaign) []RiskItem {
	var items []RiskItem
	for _, sc := range scores {
		reason := buildRiskReason(sc)
		items = append(items, RiskItem{
			Campaign: sc.CampaignName,
			Grade:    sc.Score.Grade,
			Score:    sc.Score.OverallScore,
			Reason:   reason,
		})
	}
	return items
}

// buildRiskReason produces a brief explanation for a scored campaign.
func buildRiskReason(sc *ScoredCampaign) string {
	var parts []string

	if sc.Score.DetectionDifficulty >= 80 {
		parts = append(parts, "very hard to detect")
	} else if sc.Score.DetectionDifficulty >= 60 {
		parts = append(parts, "hard to detect")
	}

	if sc.Score.EvasionSophistication >= 60 {
		parts = append(parts, "sophisticated evasion")
	}

	if sc.Score.TechniqueComplexity >= 60 {
		parts = append(parts, "high technique complexity")
	}

	if sc.Score.TacticBreadth >= 60 {
		parts = append(parts, "broad tactic coverage")
	}

	if sc.Severity == "critical" {
		parts = append(parts, "critical severity")
	} else if sc.Severity == "high" {
		parts = append(parts, "high severity")
	}

	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d stages, %s severity", sc.StageCount, sc.Severity))
	}

	return strings.Join(parts, "; ")
}

// buildCoverageGaps identifies which ATT&CK tactics are not covered.
func buildCoverageGaps(stats *ProjectStats) []CoverageGapItem {
	if stats == nil {
		return nil
	}

	coveredTactics := buildCoveredTacticSet(stats)
	allTactics := mitre.TacticShorts()

	var gaps []CoverageGapItem
	for _, tac := range allTactics {
		if coveredTactics[tac] {
			continue
		}
		tacInfo := mitre.TacticByShort(tac)
		name := tac
		if tacInfo != nil {
			name = tacInfo.Name
		}
		risk := tacticGapRisk(tac)
		gaps = append(gaps, CoverageGapItem{
			Tactic:   name,
			Coverage: fmt.Sprintf("%d/%d tactics covered", len(coveredTactics), len(allTactics)),
			Risk:     risk,
		})
	}

	return gaps
}

// buildCoveredTacticSet returns a set of tactics that appear in the stats distribution.
func buildCoveredTacticSet(stats *ProjectStats) map[string]bool {
	covered := make(map[string]bool)
	for _, td := range stats.TacticDistribution {
		covered[td.Tactic] = true
	}
	return covered
}

// tacticGapRisk assigns a risk level to a missing tactic based on how critical it is.
func tacticGapRisk(tactic string) string {
	switch tactic {
	case "initial-access", "execution", "defense-evasion":
		return "critical"
	case "credential-access", "privilege-escalation", "lateral-movement":
		return "high"
	case "persistence", "exfiltration", "command-and-control":
		return "high"
	case "discovery", "collection":
		return "medium"
	default:
		return "low"
	}
}

// buildRecommendations produces auto-generated recommendations from report data.
func buildRecommendations(stats *ProjectStats, scores []*ScoredCampaign, gaps []CoverageGapItem) []string {
	var recs []string

	if stats == nil {
		return recs
	}

	// Recommend adding detection rules for uncovered stages.
	if stats.StagesWithoutEither > 0 {
		recs = append(recs, fmt.Sprintf(
			"Add detection rules for %d stages that lack coverage",
			stats.StagesWithoutEither))
	}

	// Recommend expanding tactic coverage.
	if len(gaps) > 0 {
		var missing []string
		for _, g := range gaps {
			missing = append(missing, g.Tactic)
		}
		recs = append(recs, fmt.Sprintf(
			"Expand tactic coverage — missing: %s",
			strings.Join(missing, ", ")))
	}

	// Recommend campaigns for under-represented tactics.
	allTactics := mitre.TacticShorts()
	coveredTactics := buildCoveredTacticSet(stats)
	for _, tac := range allTactics {
		if !coveredTactics[tac] {
			continue
		}
		// Find the count for this tactic.
		count := 0
		for _, td := range stats.TacticDistribution {
			if td.Tactic == tac {
				count = td.Count
				break
			}
		}
		if count > 0 && count <= 2 {
			tacInfo := mitre.TacticByShort(tac)
			name := tac
			if tacInfo != nil {
				name = tacInfo.Name
			}
			recs = append(recs, fmt.Sprintf(
				"Consider campaigns for %s — currently %d techniques",
				name, count))
		}
	}

	// Flag high-risk campaigns needing review.
	for _, sc := range scores {
		if sc.Score.Grade == "A" || sc.Score.Grade == "B" {
			recs = append(recs, fmt.Sprintf(
				"High-risk campaign %q (Grade %s) needs review",
				sc.CampaignName, sc.Score.Grade))
		}
	}

	return recs
}

// computeOverallGrade computes the average grade across all scored campaigns.
func computeOverallGrade(scores []*ScoredCampaign) string {
	if len(scores) == 0 {
		return "N/A"
	}
	var sum float64
	for _, sc := range scores {
		sum += sc.Score.OverallScore
	}
	avg := sum / float64(len(scores))
	avg = math.Round(avg*10) / 10
	return gradeFromScore(avg)
}
