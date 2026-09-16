// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package gap

import (
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// GapReport is the output of a detection gap analysis across one or more campaigns.
type GapReport struct {
	Campaigns   []CampaignCoverage
	Aggregate   AggregateCoverage
	Gaps        []Gap
	RiskSummary RiskSummary
	GeneratedAt time.Time
}

// CampaignCoverage summarizes one campaign's detection surface.
type CampaignCoverage struct {
	Name           string
	Adversary      string
	Stages         int
	Completed      int
	Skipped        int
	TechniquesUsed int
	AttackTactics  TacticBreakdown
	AtlasTactics   TacticBreakdown
	Framework      FrameworkBreakdown
}

// TacticBreakdown shows how many tactics are covered and which are missing.
type TacticBreakdown struct {
	Total   int
	Covered int
	Missing []string // tactic short names that have zero stage coverage
	Details []TacticDetail
}

// TacticDetail describes a single tactic's coverage.
type TacticDetail struct {
	Short  string
	Name   string
	Stages int // how many stages exercise this tactic
}

// FrameworkBreakdown counts stages by technique framework.
type FrameworkBreakdown struct {
	ATTACKStages int
	ATLASStages  int
	OWASPStages  int
}

// AggregateCoverage merges coverage across all analyzed campaigns.
type AggregateCoverage struct {
	TotalCampaigns   int
	TotalStages      int
	TotalCompleted   int
	TotalSkipped     int
	UniqueTechniques int
	UniqueDetections int
	UniqueTelemetry  int
	AttackTactics    TacticBreakdown
	AtlasTactics     TacticBreakdown
	Framework        FrameworkBreakdown
}

// Gap represents a single detection or coverage gap.
type Gap struct {
	CampaignName  string
	StageID       string
	StageName     string
	Technique     string
	TechniqueName string
	Tactic        string
	Type          GapType
	Risk          string // critical, high, medium, low
	Description   string
}

// GapType classifies what kind of gap was found.
type GapType string

const (
	// GapDetectionMissing indicates a stage with telemetry expectations but no detection rules.
	GapDetectionMissing GapType = "detection_missing"
	// GapTelemetryMissing indicates a stage with no telemetry expectations at all.
	GapTelemetryMissing GapType = "telemetry_missing"
	// GapTacticUncovered indicates an entire tactic with no stage coverage.
	GapTacticUncovered GapType = "tactic_uncovered"
)

// RiskSummary aggregates gap counts by severity.
type RiskSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Total    int
	Score    float64 // 0-100 weighted risk score
}

// All ATT&CK tactic short names in kill-chain order.
var attackTacticOrder = []string{
	"reconnaissance", "resource-development", "initial-access",
	"execution", "persistence", "privilege-escalation",
	"defense-evasion", "credential-access", "discovery",
	"lateral-movement", "collection", "command-and-control",
	"exfiltration", "impact",
}

// All ATLAS tactic short names.
var atlasTacticOrder = []string{
	"reconnaissance", "resource-development", "initial-access",
	"ml-attack-staging", "ml-model-access", "exfiltration", "impact",
}

// Critical tactics — uncovered gaps here score critical.
var criticalTactics = map[string]bool{
	"initial-access": true,
	"execution":      true,
	"exfiltration":   true,
}

// High-risk tactics — uncovered gaps here score high.
var highTactics = map[string]bool{
	"credential-access": true,
	"lateral-movement":  true,
	"impact":            true,
}

// Analyze produces a gap report from one or more simulation results.
func Analyze(results ...*engine.RunResult) *GapReport {
	report := &GapReport{
		GeneratedAt: time.Now(),
	}

	// Aggregate counters.
	allTechniques := make(map[string]bool)
	allDetections := make(map[string]bool)
	allTelemetry := make(map[string]bool)
	aggAttackTacticStages := make(map[string]int) // tactic → stage count
	aggAtlasTacticStages := make(map[string]int)
	var aggFramework FrameworkBreakdown

	for _, r := range results {
		cc := analyzeCampaign(r)
		report.Campaigns = append(report.Campaigns, cc)

		// Merge into aggregate.
		for _, sr := range r.Stages {
			if sr.Skipped {
				continue
			}
			s := sr.Stage
			allTechniques[s.Technique] = true
			for _, d := range s.Expect.Detections {
				allDetections[d] = true
			}
			for _, t := range s.Expect.Telemetry {
				allTelemetry[t] = true
			}

			fw := classifyTechnique(s.Technique)
			switch fw {
			case "attack":
				aggFramework.ATTACKStages++
				if mitre.ValidTactic(s.Tactic) {
					aggAttackTacticStages[s.Tactic]++
				}
			case "atlas":
				aggFramework.ATLASStages++
				if mitre.ValidATLASTactic(s.Tactic) {
					aggAtlasTacticStages[s.Tactic]++
				}
			case "owasp":
				aggFramework.OWASPStages++
				// OWASP LLM stages use ATLAS tactics; count them.
				if mitre.ValidATLASTactic(s.Tactic) {
					aggAtlasTacticStages[s.Tactic]++
				}
			}
		}

		// Collect per-stage gaps.
		gaps := findGaps(r)
		report.Gaps = append(report.Gaps, gaps...)
	}

	// Tactic-uncovered gaps — one per missing tactic across the aggregate.
	attackBreak := buildTacticBreakdown(attackTacticOrder, aggAttackTacticStages, false)
	atlasBreak := buildTacticBreakdown(atlasTacticOrder, aggAtlasTacticStages, true)

	for _, m := range attackBreak.Missing {
		g := Gap{
			Tactic:      m,
			Type:        GapTacticUncovered,
			Description: tacticGapDescription(m, "ATT&CK"),
		}
		g.Risk = riskForGap(g)
		report.Gaps = append(report.Gaps, g)
	}
	for _, m := range atlasBreak.Missing {
		// Skip shared tactic names already emitted from ATT&CK unless it's
		// an ATLAS-only tactic.
		if mitre.ValidTactic(m) {
			continue
		}
		g := Gap{
			Tactic:      m,
			Type:        GapTacticUncovered,
			Description: tacticGapDescription(m, "ATLAS"),
		}
		g.Risk = riskForGap(g)
		report.Gaps = append(report.Gaps, g)
	}

	report.Aggregate = AggregateCoverage{
		TotalCampaigns:   len(results),
		TotalStages:      sumField(report.Campaigns, func(c CampaignCoverage) int { return c.Stages }),
		TotalCompleted:   sumField(report.Campaigns, func(c CampaignCoverage) int { return c.Completed }),
		TotalSkipped:     sumField(report.Campaigns, func(c CampaignCoverage) int { return c.Skipped }),
		UniqueTechniques: len(allTechniques),
		UniqueDetections: len(allDetections),
		UniqueTelemetry:  len(allTelemetry),
		AttackTactics:    attackBreak,
		AtlasTactics:     atlasBreak,
		Framework:        aggFramework,
	}

	report.RiskSummary = computeRisk(report.Gaps)
	return report
}

// analyzeCampaign produces coverage stats for a single campaign result.
func analyzeCampaign(r *engine.RunResult) CampaignCoverage {
	c := r.Campaign
	attackStages := make(map[string]int)
	atlasStages := make(map[string]int)
	var fw FrameworkBreakdown
	techSeen := make(map[string]bool)

	for _, sr := range r.Stages {
		if sr.Skipped {
			continue
		}
		s := sr.Stage
		techSeen[s.Technique] = true

		switch classifyTechnique(s.Technique) {
		case "attack":
			fw.ATTACKStages++
			if mitre.ValidTactic(s.Tactic) {
				attackStages[s.Tactic]++
			}
		case "atlas":
			fw.ATLASStages++
			if mitre.ValidATLASTactic(s.Tactic) {
				atlasStages[s.Tactic]++
			}
		case "owasp":
			fw.OWASPStages++
			// OWASP LLM stages use ATLAS tactics; count them.
			if mitre.ValidATLASTactic(s.Tactic) {
				atlasStages[s.Tactic]++
			}
		}
	}

	return CampaignCoverage{
		Name:           c.Meta.Name,
		Adversary:      c.Meta.Adversary,
		Stages:         len(c.Stages),
		Completed:      r.Completed,
		Skipped:        r.Skipped,
		TechniquesUsed: len(techSeen),
		AttackTactics:  buildTacticBreakdown(attackTacticOrder, attackStages, false),
		AtlasTactics:   buildTacticBreakdown(atlasTacticOrder, atlasStages, true),
		Framework:      fw,
	}
}

// findGaps identifies detection and telemetry gaps in a single campaign result.
func findGaps(r *engine.RunResult) []Gap {
	var gaps []Gap
	for _, sr := range r.Stages {
		if sr.Skipped {
			continue
		}
		s := sr.Stage
		techName := ResolveTechniqueName(s.Technique)

		// Detection gap: stage has telemetry expectations but no detections.
		if len(s.Expect.Telemetry) > 0 && len(s.Expect.Detections) == 0 {
			g := Gap{
				CampaignName:  r.Campaign.Meta.Name,
				StageID:       s.ID,
				StageName:     s.Name,
				Technique:     s.Technique,
				TechniqueName: techName,
				Tactic:        s.Tactic,
				Type:          GapDetectionMissing,
				Description:   "Stage declares expected telemetry but no detection rules — telemetry will fire with nothing to catch it",
			}
			g.Risk = riskForGap(g)
			gaps = append(gaps, g)
		}

		// Telemetry gap: stage has no telemetry expectations at all.
		if len(s.Expect.Telemetry) == 0 {
			g := Gap{
				CampaignName:  r.Campaign.Meta.Name,
				StageID:       s.ID,
				StageName:     s.Name,
				Technique:     s.Technique,
				TechniqueName: techName,
				Tactic:        s.Tactic,
				Type:          GapTelemetryMissing,
				Description:   "Stage declares no expected telemetry — detection engineering cannot begin without observable artifacts",
			}
			g.Risk = riskForGap(g)
			gaps = append(gaps, g)
		}
	}
	return gaps
}

// buildTacticBreakdown computes coverage for a tactic list given stage counts.
func buildTacticBreakdown(order []string, stageCounts map[string]int, isATLAS bool) TacticBreakdown {
	bd := TacticBreakdown{Total: len(order)}
	for _, short := range order {
		count := stageCounts[short]
		name := tacticName(short, isATLAS)
		if count > 0 {
			bd.Covered++
			bd.Details = append(bd.Details, TacticDetail{
				Short:  short,
				Name:   name,
				Stages: count,
			})
		} else {
			bd.Missing = append(bd.Missing, short)
		}
	}
	return bd
}

// tacticName resolves a tactic short name to its display name.
func tacticName(short string, preferATLAS bool) string {
	if preferATLAS {
		if t := mitre.ATLASTacticByShort(short); t != nil {
			return t.Name
		}
	}
	if t := mitre.TacticByShort(short); t != nil {
		return t.Name
	}
	if t := mitre.ATLASTacticByShort(short); t != nil {
		return t.Name
	}
	return short
}

func tacticGapDescription(tactic, framework string) string {
	name := tactic
	if t := mitre.TacticByShort(tactic); t != nil {
		name = t.Name
	} else if t := mitre.ATLASTacticByShort(tactic); t != nil {
		name = t.Name
	}
	return framework + " tactic \"" + name + "\" has no stage coverage across any analyzed campaign"
}

// ClassifyTechnique returns the framework a technique ID belongs to ("attack", "atlas", "owasp", or "unknown").
func ClassifyTechnique(id string) string {
	return classifyTechnique(id)
}

func classifyTechnique(id string) string {
	if strings.HasPrefix(id, "AML.") {
		return "atlas"
	}
	if strings.HasPrefix(id, "LLM") {
		return "owasp"
	}
	if strings.HasPrefix(id, "T") {
		return "attack"
	}
	return "unknown"
}

// ResolveTechniqueName looks up a technique name across all supported frameworks.
func ResolveTechniqueName(id string) string {
	if t := mitre.LookupTechnique(id); t != nil {
		return t.Name
	}
	if t := mitre.LookupATLASTechnique(id); t != nil {
		return t.Name
	}
	if e := mitre.LookupOWASPLLM(id); e != nil {
		return e.Name
	}
	return id
}

// riskForGap assigns a risk level based on gap type and tactic.
func riskForGap(g Gap) string {
	switch g.Type {
	case GapTacticUncovered:
		if criticalTactics[g.Tactic] {
			return "critical"
		}
		if highTactics[g.Tactic] {
			return "high"
		}
		return "medium"

	case GapDetectionMissing:
		if criticalTactics[g.Tactic] {
			return "high"
		}
		return "medium"

	case GapTelemetryMissing:
		return "medium"
	}
	return "low"
}

// computeRisk builds the overall risk summary from the gap list.
func computeRisk(gaps []Gap) RiskSummary {
	rs := RiskSummary{Total: len(gaps)}
	for _, g := range gaps {
		switch g.Risk {
		case "critical":
			rs.Critical++
		case "high":
			rs.High++
		case "medium":
			rs.Medium++
		case "low":
			rs.Low++
		}
	}
	if rs.Total > 0 {
		// Weight: critical=10, high=5, medium=2, low=1.
		weighted := float64(rs.Critical*10 + rs.High*5 + rs.Medium*2 + rs.Low*1)
		maxPossible := float64(rs.Total * 10)
		rs.Score = weighted / maxPossible * 100
	}
	return rs
}

func sumField(cs []CampaignCoverage, f func(CampaignCoverage) int) int {
	total := 0
	for _, c := range cs {
		total += f(c)
	}
	return total
}
