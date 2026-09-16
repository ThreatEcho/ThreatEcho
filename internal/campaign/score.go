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
)

// ScoreBreakdown shows the per-dimension scores.
type ScoreBreakdown struct {
	TechniqueComplexity   float64 // 0-100: based on number and severity of techniques
	TacticBreadth         float64 // 0-100: how many ATT&CK tactics are covered
	DetectionDifficulty   float64 // 0-100: how hard to detect (inverse of detection coverage)
	ExecutionComplexity   float64 // 0-100: elevated privs, multi-step, dependencies
	EvasionSophistication float64 // 0-100: defense-evasion techniques, obfuscation
	OverallScore          float64 // 0-100: weighted composite
	Grade                 string  // A-F letter grade
}

// ScoredCampaign holds a campaign with its computed scores.
type ScoredCampaign struct {
	CampaignName string
	CampaignFile string
	StageCount   int
	Severity     string
	Score        ScoreBreakdown
	Factors      []ScoreFactor // individual scoring factors
}

// ScoreFactor is one factor contributing to the score.
type ScoreFactor struct {
	Dimension   string  // which dimension it belongs to
	Description string  // human-readable reason
	Points      float64 // contribution to dimension score
}

// totalATTACKTactics is the number of ATT&CK tactics used for breadth scoring.
const totalATTACKTactics = 14

// Dimension weight constants for the weighted composite.
const (
	weightTechniqueComplexity   = 0.25
	weightTacticBreadth         = 0.20
	weightDetectionDifficulty   = 0.25
	weightExecutionComplexity   = 0.15
	weightEvasionSophistication = 0.15
)

// ScoreCampaign computes risk/complexity scores for a single campaign.
// Returns nil if c is nil.
func ScoreCampaign(c *Campaign) *ScoredCampaign {
	if c == nil {
		return nil
	}

	sc := &ScoredCampaign{
		CampaignName: c.Meta.Name,
		StageCount:   len(c.Stages),
		Severity:     c.Meta.Severity,
	}

	sc.Score.TechniqueComplexity = scoreTechniqueComplexity(c, &sc.Factors)
	sc.Score.TacticBreadth = scoreTacticBreadth(c, &sc.Factors)
	sc.Score.DetectionDifficulty = scoreDetectionDifficulty(c, &sc.Factors)
	sc.Score.ExecutionComplexity = scoreExecutionComplexity(c, &sc.Factors)
	sc.Score.EvasionSophistication = scoreEvasionSophistication(c, &sc.Factors)

	sc.Score.OverallScore = computeOverallScore(sc.Score)
	sc.Score.Grade = gradeFromScore(sc.Score.OverallScore)

	return sc
}

// ScoreDir loads and scores all campaigns in a directory.
// Each subdirectory containing campaign.yaml is scored.
func ScoreDir(dir string) ([]*ScoredCampaign, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %q: %w", dir, err)
	}

	var results []*ScoredCampaign
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
		sc := ScoreCampaign(c)
		if sc != nil {
			sc.CampaignFile = filepath.Join(dir, e.Name())
			results = append(results, sc)
		}
	}

	// Sort by overall score descending.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score.OverallScore > results[j].Score.OverallScore
	})

	return results, nil
}

// FormatScores renders a formatted score report with ASCII bars for multiple campaigns.
func FormatScores(scores []*ScoredCampaign) string {
	if len(scores) == 0 {
		return ""
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(boxLine("top"))
	b.WriteString(boxCenter("ThreatEcho Campaign Risk Scores"))
	b.WriteString(boxLine("mid"))
	b.WriteString("\n")

	for i, sc := range scores {
		if i > 0 {
			b.WriteString("\n")
		}
		gradeColor := gradeIndicator(sc.Score.Grade)
		fmt.Fprintf(&b, "  [%s] %-30s  Score: %5.1f  Grade: %s\n",
			gradeColor, truncate(sc.CampaignName, 30), sc.Score.OverallScore, sc.Score.Grade)
		fmt.Fprintf(&b, "      Stages: %-4d  Severity: %-10s\n",
			sc.StageCount, sc.Severity)

		// Dimension bars.
		fmt.Fprintf(&b, "      Technique   %s  %5.1f\n",
			renderBar(int(math.Round(sc.Score.TechniqueComplexity)), 100, 16), sc.Score.TechniqueComplexity)
		fmt.Fprintf(&b, "      Tactic      %s  %5.1f\n",
			renderBar(int(math.Round(sc.Score.TacticBreadth)), 100, 16), sc.Score.TacticBreadth)
		fmt.Fprintf(&b, "      Detection   %s  %5.1f\n",
			renderBar(int(math.Round(sc.Score.DetectionDifficulty)), 100, 16), sc.Score.DetectionDifficulty)
		fmt.Fprintf(&b, "      Execution   %s  %5.1f\n",
			renderBar(int(math.Round(sc.Score.ExecutionComplexity)), 100, 16), sc.Score.ExecutionComplexity)
		fmt.Fprintf(&b, "      Evasion     %s  %5.1f\n",
			renderBar(int(math.Round(sc.Score.EvasionSophistication)), 100, 16), sc.Score.EvasionSophistication)
	}

	b.WriteString("\n")
	b.WriteString(boxLine("bottom"))

	return b.String()
}

// FormatScoreDetail renders a detailed breakdown for one campaign.
func FormatScoreDetail(sc *ScoredCampaign) string {
	if sc == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(boxLine("top"))
	b.WriteString(boxCenter(fmt.Sprintf("Score Detail: %s", truncate(sc.CampaignName, 30))))
	b.WriteString(boxLine("mid"))
	b.WriteString("\n")

	gradeColor := gradeIndicator(sc.Score.Grade)
	fmt.Fprintf(&b, "  Overall Score: %5.1f / 100    Grade: %s [%s]\n",
		sc.Score.OverallScore, sc.Score.Grade, gradeColor)
	fmt.Fprintf(&b, "  Stages: %d    Severity: %s\n\n", sc.StageCount, sc.Severity)

	// Per-dimension sections.
	dimensions := []struct {
		name   string
		score  float64
		weight float64
	}{
		{"TechniqueComplexity", sc.Score.TechniqueComplexity, weightTechniqueComplexity},
		{"TacticBreadth", sc.Score.TacticBreadth, weightTacticBreadth},
		{"DetectionDifficulty", sc.Score.DetectionDifficulty, weightDetectionDifficulty},
		{"ExecutionComplexity", sc.Score.ExecutionComplexity, weightExecutionComplexity},
		{"EvasionSophistication", sc.Score.EvasionSophistication, weightEvasionSophistication},
	}

	for _, dim := range dimensions {
		bar := renderBar(int(math.Round(dim.score)), 100, 20)
		fmt.Fprintf(&b, "  %s (weight: %.0f%%)\n", dim.name, dim.weight*100)
		fmt.Fprintf(&b, "    Score: %5.1f  %s\n", dim.score, bar)

		// Show contributing factors.
		for _, f := range sc.Factors {
			if f.Dimension == dim.name {
				fmt.Fprintf(&b, "      %+.0f  %s\n", f.Points, f.Description)
			}
		}
		b.WriteString("\n")
	}

	b.WriteString(boxLine("bottom"))

	return b.String()
}

// scoreTechniqueComplexity scores based on technique count and severity.
// Weight: 25%.
func scoreTechniqueComplexity(c *Campaign, factors *[]ScoreFactor) float64 {
	var score float64

	uniqueTechs := c.UniqueTechniques()
	techCount := len(uniqueTechs)

	// Base: 10 pts per unique technique, capped at 50.
	base := float64(techCount) * 10
	if base > 50 {
		base = 50
	}
	if base > 0 {
		*factors = append(*factors, ScoreFactor{
			Dimension:   "TechniqueComplexity",
			Description: fmt.Sprintf("%d unique techniques (10 pts each, cap 50)", techCount),
			Points:      base,
		})
	}
	score += base

	// +15 if uses sub-techniques (contains a dot in any technique ID).
	hasSubTech := false
	for _, t := range uniqueTechs {
		if strings.Contains(t, ".") {
			hasSubTech = true
			break
		}
	}
	if hasSubTech {
		*factors = append(*factors, ScoreFactor{
			Dimension:   "TechniqueComplexity",
			Description: "uses sub-techniques",
			Points:      15,
		})
		score += 15
	}

	// +10 per technique in credential-access tactic.
	credCount := countStagesInTactic(c, "credential-access")
	if credCount > 0 {
		pts := float64(credCount) * 10
		*factors = append(*factors, ScoreFactor{
			Dimension:   "TechniqueComplexity",
			Description: fmt.Sprintf("%d credential-access techniques (+10 each)", credCount),
			Points:      pts,
		})
		score += pts
	}

	// +10 per technique in privilege-escalation tactic.
	privCount := countStagesInTactic(c, "privilege-escalation")
	if privCount > 0 {
		pts := float64(privCount) * 10
		*factors = append(*factors, ScoreFactor{
			Dimension:   "TechniqueComplexity",
			Description: fmt.Sprintf("%d privilege-escalation techniques (+10 each)", privCount),
			Points:      pts,
		})
		score += pts
	}

	// +5 per technique in lateral-movement tactic.
	latCount := countStagesInTactic(c, "lateral-movement")
	if latCount > 0 {
		pts := float64(latCount) * 5
		*factors = append(*factors, ScoreFactor{
			Dimension:   "TechniqueComplexity",
			Description: fmt.Sprintf("%d lateral-movement techniques (+5 each)", latCount),
			Points:      pts,
		})
		score += pts
	}

	return cap100(score)
}

// scoreTacticBreadth scores based on the number of unique tactics covered.
// Weight: 20%.
func scoreTacticBreadth(c *Campaign, factors *[]ScoreFactor) float64 {
	var score float64

	tactics := c.UniqueTactics()
	tacticCount := len(tactics)

	// Score = (unique_tactics / 14) * 100.
	if tacticCount > 0 {
		breadth := (float64(tacticCount) / float64(totalATTACKTactics)) * 100
		*factors = append(*factors, ScoreFactor{
			Dimension:   "TacticBreadth",
			Description: fmt.Sprintf("%d of %d ATT&CK tactics covered", tacticCount, totalATTACKTactics),
			Points:      breadth,
		})
		score += breadth
	}

	// Bonus 10 pts if covers both initial-access AND exfiltration (full kill-chain).
	tacticSet := make(map[string]bool, len(tactics))
	for _, t := range tactics {
		tacticSet[t] = true
	}
	if tacticSet["initial-access"] && tacticSet["exfiltration"] {
		*factors = append(*factors, ScoreFactor{
			Dimension:   "TacticBreadth",
			Description: "full kill-chain: initial-access + exfiltration",
			Points:      10,
		})
		score += 10
	}

	return cap100(score)
}

// scoreDetectionDifficulty scores how hard the campaign is to detect.
// Weight: 25%. Starts at 100 (max difficulty) and subtracts for detection readiness.
func scoreDetectionDifficulty(c *Campaign, factors *[]ScoreFactor) float64 {
	score := 100.0

	// -30 if campaign has detection rules defined (any stage).
	hasDetections := false
	for _, s := range c.Stages {
		if len(s.Expect.Detections) > 0 {
			hasDetections = true
			break
		}
	}
	if hasDetections {
		*factors = append(*factors, ScoreFactor{
			Dimension:   "DetectionDifficulty",
			Description: "has detection rules defined",
			Points:      -30,
		})
		score -= 30
	}

	// -20 if campaign has telemetry sources defined (any stage).
	hasTelemetry := false
	for _, s := range c.Stages {
		if len(s.Expect.Telemetry) > 0 {
			hasTelemetry = true
			break
		}
	}
	if hasTelemetry {
		*factors = append(*factors, ScoreFactor{
			Dimension:   "DetectionDifficulty",
			Description: "has telemetry sources defined",
			Points:      -20,
		})
		score -= 20
	}

	// -10 per stage with cleanup commands (shows awareness of evasion).
	cleanupStages := 0
	for _, s := range c.Stages {
		if len(s.Execute.Cleanup) > 0 {
			cleanupStages++
		}
	}
	if cleanupStages > 0 {
		pts := float64(cleanupStages) * -10
		*factors = append(*factors, ScoreFactor{
			Dimension:   "DetectionDifficulty",
			Description: fmt.Sprintf("%d stages with cleanup commands (-10 each)", cleanupStages),
			Points:      pts,
		})
		score += pts
	}

	// +15 for defense-evasion techniques present.
	hasDefEvasion := false
	for _, s := range c.Stages {
		if s.Tactic == "defense-evasion" {
			hasDefEvasion = true
			break
		}
	}
	if hasDefEvasion {
		*factors = append(*factors, ScoreFactor{
			Dimension:   "DetectionDifficulty",
			Description: "defense-evasion techniques present",
			Points:      15,
		})
		score += 15
	}

	// Clamp to [0, 100].
	if score < 0 {
		score = 0
	}
	return cap100(score)
}

// scoreExecutionComplexity scores based on execution characteristics.
// Weight: 15%.
func scoreExecutionComplexity(c *Campaign, factors *[]ScoreFactor) float64 {
	var score float64

	// +15 per elevated-privilege stage.
	elevatedCount := 0
	for _, s := range c.Stages {
		if s.Execute.Elevated {
			elevatedCount++
		}
	}
	if elevatedCount > 0 {
		pts := float64(elevatedCount) * 15
		*factors = append(*factors, ScoreFactor{
			Dimension:   "ExecutionComplexity",
			Description: fmt.Sprintf("%d elevated-privilege stages (+15 each)", elevatedCount),
			Points:      pts,
		})
		score += pts
	}

	// +20 if has dependencies between stages (any DependsOn).
	hasDeps := false
	for _, s := range c.Stages {
		if len(s.DependsOn) > 0 {
			hasDeps = true
			break
		}
	}
	if hasDeps {
		*factors = append(*factors, ScoreFactor{
			Dimension:   "ExecutionComplexity",
			Description: "has inter-stage dependencies",
			Points:      20,
		})
		score += 20
	}

	// +10 per unique exec type beyond 1.
	execTypes := make(map[string]bool)
	for _, s := range c.Stages {
		if s.Execute.Type != "" {
			execTypes[s.Execute.Type] = true
		}
	}
	extraTypes := len(execTypes) - 1
	if extraTypes > 0 {
		pts := float64(extraTypes) * 10
		*factors = append(*factors, ScoreFactor{
			Dimension:   "ExecutionComplexity",
			Description: fmt.Sprintf("%d extra execution types (+10 each)", extraTypes),
			Points:      pts,
		})
		score += pts
	}

	// +15 if has HTTP-based stages (C2).
	if execTypes["http"] {
		*factors = append(*factors, ScoreFactor{
			Dimension:   "ExecutionComplexity",
			Description: "has HTTP-based stages (C2)",
			Points:      15,
		})
		score += 15
	}

	return cap100(score)
}

// scoreEvasionSophistication scores based on evasion and persistence indicators.
// Weight: 15%.
func scoreEvasionSophistication(c *Campaign, factors *[]ScoreFactor) float64 {
	var score float64

	// +20 per defense-evasion technique (unique).
	defEvasionCount := countUniqueTechniquesInTactic(c, "defense-evasion")
	if defEvasionCount > 0 {
		pts := float64(defEvasionCount) * 20
		*factors = append(*factors, ScoreFactor{
			Dimension:   "EvasionSophistication",
			Description: fmt.Sprintf("%d defense-evasion techniques (+20 each)", defEvasionCount),
			Points:      pts,
		})
		score += pts
	}

	// +15 per privilege-escalation technique (unique).
	privEscCount := countUniqueTechniquesInTactic(c, "privilege-escalation")
	if privEscCount > 0 {
		pts := float64(privEscCount) * 15
		*factors = append(*factors, ScoreFactor{
			Dimension:   "EvasionSophistication",
			Description: fmt.Sprintf("%d privilege-escalation techniques (+15 each)", privEscCount),
			Points:      pts,
		})
		score += pts
	}

	// +10 if has stages with cleanup commands.
	hasCleanup := false
	for _, s := range c.Stages {
		if len(s.Execute.Cleanup) > 0 {
			hasCleanup = true
			break
		}
	}
	if hasCleanup {
		*factors = append(*factors, ScoreFactor{
			Dimension:   "EvasionSophistication",
			Description: "stages with cleanup commands",
			Points:      10,
		})
		score += 10
	}

	// +10 if has "persistence" techniques.
	hasPersistence := false
	for _, s := range c.Stages {
		if s.Tactic == "persistence" {
			hasPersistence = true
			break
		}
	}
	if hasPersistence {
		*factors = append(*factors, ScoreFactor{
			Dimension:   "EvasionSophistication",
			Description: "persistence techniques present",
			Points:      10,
		})
		score += 10
	}

	return cap100(score)
}

// computeOverallScore calculates the weighted composite score.
func computeOverallScore(s ScoreBreakdown) float64 {
	overall := s.TechniqueComplexity*weightTechniqueComplexity +
		s.TacticBreadth*weightTacticBreadth +
		s.DetectionDifficulty*weightDetectionDifficulty +
		s.ExecutionComplexity*weightExecutionComplexity +
		s.EvasionSophistication*weightEvasionSophistication
	return math.Round(overall*10) / 10
}

// gradeFromScore converts a numeric score to a letter grade.
func gradeFromScore(score float64) string {
	switch {
	case score >= 80:
		return "A"
	case score >= 60:
		return "B"
	case score >= 40:
		return "C"
	case score >= 20:
		return "D"
	default:
		return "F"
	}
}

// gradeIndicator returns a visual indicator for the grade.
func gradeIndicator(grade string) string {
	switch grade {
	case "A":
		return "!!!"
	case "B":
		return "!! "
	case "C":
		return "!  "
	case "D":
		return ".  "
	default:
		return "   "
	}
}

// countStagesInTactic counts stages that use the given tactic.
func countStagesInTactic(c *Campaign, tactic string) int {
	count := 0
	for _, s := range c.Stages {
		if s.Tactic == tactic {
			count++
		}
	}
	return count
}

// countUniqueTechniquesInTactic counts unique technique IDs within a given tactic.
func countUniqueTechniquesInTactic(c *Campaign, tactic string) int {
	seen := make(map[string]bool)
	for _, s := range c.Stages {
		if s.Tactic == tactic && !seen[s.Technique] {
			seen[s.Technique] = true
		}
	}
	return len(seen)
}

// cap100 clamps a value to the [0, 100] range.
func cap100(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// truncate shortens a string to maxLen, adding "..." if needed.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
