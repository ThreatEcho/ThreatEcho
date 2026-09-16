// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Risk dimension names
// ---------------------------------------------------------------------------

const (
	// DimPolicyLint is the risk dimension for policy syntax and structure violations.
	DimPolicyLint = "policy_lint"
	// DimPolicyDrift is the risk dimension for divergence between live and declared policies.
	DimPolicyDrift = "policy_drift"
	// DimCoverageGaps is the risk dimension for missing detection or telemetry coverage.
	DimCoverageGaps = "coverage_gaps"
	// DimAgentChains is the risk dimension for delegation chain trust violations.
	DimAgentChains = "agent_chains"
	// DimThreatModel is the risk dimension for STRIDE threat model findings.
	DimThreatModel = "threat_model"
	// DimBehaviorProfile is the risk dimension for agent behavioral anomalies.
	DimBehaviorProfile = "behavior_profile"
)

// allDimensions lists every dimension in display order.
var allDimensions = []string{
	DimPolicyLint,
	DimCoverageGaps,
	DimThreatModel,
	DimAgentChains,
	DimPolicyDrift,
	DimBehaviorProfile,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// RiskDimension is one risk signal source contributing to the overall posture.
type RiskDimension struct {
	Name             string  `json:"name"`
	Score            float64 `json:"score"`             // 0.0 (safe) to 1.0 (critical risk)
	Weight           float64 `json:"weight"`            // contribution weight
	Findings         int     `json:"findings"`          // total issues found
	CriticalFindings int     `json:"critical_findings"` // critical-severity issues
	Details          string  `json:"details"`           // one-line summary
	Available        bool    `json:"available"`         // whether data was provided
}

// RiskPosture is the unified risk assessment combining all dimensions.
type RiskPosture struct {
	OverallScore     float64         `json:"overall_score"` // 0.0-1.0 weighted average
	Grade            string          `json:"grade"`         // A-F
	Verdict          string          `json:"verdict"`       // acceptable, needs_attention, at_risk, critical
	Dimensions       []RiskDimension `json:"dimensions"`
	TopRisks         []string        `json:"top_risks"` // up to 5 specific risk descriptions
	Recommendations  []string        `json:"recommendations"`
	TotalFindings    int             `json:"total_findings"`
	CriticalFindings int             `json:"critical_findings"`
}

// RiskConfig controls dimension weights.
type RiskConfig struct {
	Weights map[string]float64 `json:"weights"`
}

// RiskInputs collects the optional outputs of each analysis engine.
// Any field may be nil if that engine was not run.
type RiskInputs struct {
	LintReport      *policy.LintReport
	DriftReport     *policy.DriftReport
	CoverageMap     *policy.CoverageMapReport
	ChainAnalysis   *agent.ChainAnalysis
	ThreatModel     *ThreatModel // same package
	BehaviorReports []*agent.DeviationReport
}

// ---------------------------------------------------------------------------
// Default configuration
// ---------------------------------------------------------------------------

// DefaultRiskConfig returns sensible default weights for each dimension.
// The weights reflect relative importance: coverage gaps and threat-model
// findings carry more weight because they indicate structural exposure,
// while lint and drift are more about hygiene.
func DefaultRiskConfig() *RiskConfig {
	return &RiskConfig{
		Weights: map[string]float64{
			DimPolicyLint:      0.15,
			DimCoverageGaps:    0.25,
			DimThreatModel:     0.25,
			DimAgentChains:     0.20,
			DimPolicyDrift:     0.10,
			DimBehaviorProfile: 0.05,
		},
	}
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

// AssessRisk produces a unified RiskPosture from the supplied analysis
// inputs, weighting each dimension according to cfg.  Nil inputs are
// treated as unavailable; their weight is redistributed proportionally
// to the dimensions that are present.
func AssessRisk(cfg *RiskConfig, inputs *RiskInputs) *RiskPosture {
	if cfg == nil {
		cfg = DefaultRiskConfig()
	}
	if inputs == nil {
		inputs = &RiskInputs{}
	}

	dims := buildDimensions(cfg, inputs)

	// Compute weighted score, redistributing weight from unavailable dims.
	var totalWeight float64
	var weightedSum float64
	var totalFindings, totalCritical int
	for _, d := range dims {
		if d.Available {
			totalWeight += d.Weight
			weightedSum += d.Score * d.Weight
		}
		totalFindings += d.Findings
		totalCritical += d.CriticalFindings
	}

	var overall float64
	if totalWeight > 0 {
		overall = weightedSum / totalWeight
	}
	overall = clampRisk(overall)

	posture := &RiskPosture{
		OverallScore:     roundRisk(overall),
		Grade:            riskGrade(overall),
		Verdict:          riskVerdict(overall),
		Dimensions:       dims,
		TotalFindings:    totalFindings,
		CriticalFindings: totalCritical,
	}

	posture.TopRisks = extractTopRisks(dims)
	posture.Recommendations = generateRecommendations(posture)

	return posture
}

// ---------------------------------------------------------------------------
// Dimension builders
// ---------------------------------------------------------------------------

func buildDimensions(cfg *RiskConfig, inputs *RiskInputs) []RiskDimension {
	dims := make([]RiskDimension, 0, len(allDimensions))
	for _, name := range allDimensions {
		w := cfg.Weights[name]
		switch name {
		case DimPolicyLint:
			dims = append(dims, buildLintDimension(inputs.LintReport, w))
		case DimPolicyDrift:
			dims = append(dims, buildDriftDimension(inputs.DriftReport, w))
		case DimCoverageGaps:
			dims = append(dims, buildCoverageDimension(inputs.CoverageMap, w))
		case DimAgentChains:
			dims = append(dims, buildChainDimension(inputs.ChainAnalysis, w))
		case DimThreatModel:
			dims = append(dims, buildThreatDimension(inputs.ThreatModel, w))
		case DimBehaviorProfile:
			dims = append(dims, buildBehaviorDimension(inputs.BehaviorReports, w))
		}
	}
	return dims
}

func buildLintDimension(r *policy.LintReport, w float64) RiskDimension {
	d := RiskDimension{Name: DimPolicyLint, Weight: w}
	if r == nil {
		d.Details = "not computed"
		return d
	}
	d.Available = true
	// Lint score runs 0 (terrible) to 1 (perfect); invert for risk.
	d.Score = clampRisk(1.0 - r.Score)
	d.Findings = r.FindingCount
	d.CriticalFindings = r.ErrorCount // lint "error" = critical
	d.Details = fmt.Sprintf("lint score %s (%d findings)", r.Grade, r.FindingCount)
	return d
}

func buildDriftDimension(r *policy.DriftReport, w float64) RiskDimension {
	d := RiskDimension{Name: DimPolicyDrift, Weight: w}
	if r == nil {
		d.Details = "not computed"
		return d
	}
	d.Available = true
	// Weight drift findings by severity, cap at 1.0.
	var weighted float64
	for _, f := range r.Findings {
		weighted += driftSeverityWeight(f.Severity)
	}
	d.Score = clampRisk(weighted / 10.0)
	d.Findings = len(r.Findings)
	d.CriticalFindings = r.CriticalCount
	d.Details = fmt.Sprintf("%d changes detected (drift score %.2f)", len(r.Findings), r.DriftScore)
	return d
}

func driftSeverityWeight(sev policy.DriftSeverity) float64 {
	switch sev {
	case policy.DriftCritical:
		return 4.0
	case policy.DriftHigh:
		return 2.5
	case policy.DriftMedium:
		return 1.5
	case policy.DriftLow:
		return 0.5
	default:
		return 0.1
	}
}

func buildCoverageDimension(r *policy.CoverageMapReport, w float64) RiskDimension {
	d := RiskDimension{Name: DimCoverageGaps, Weight: w}
	if r == nil {
		d.Details = "not computed"
		return d
	}
	d.Available = true
	d.Score = clampRisk(r.RiskScore)
	d.Findings = r.UncoveredTechniques
	// Treat gaps in critical tactics as critical findings.
	d.CriticalFindings = countCriticalGaps(r)
	d.Details = fmt.Sprintf("%.0f%% coverage (%d gaps)", r.CoveragePercent, r.UncoveredTechniques)
	return d
}

func countCriticalGaps(r *policy.CoverageMapReport) int {
	var n int
	for _, g := range r.Gaps {
		if g.Severity == "critical" || g.Severity == "high" {
			n++
		}
	}
	return n
}

func buildChainDimension(a *agent.ChainAnalysis, w float64) RiskDimension {
	d := RiskDimension{Name: DimAgentChains, Weight: w}
	if a == nil {
		d.Details = "not computed"
		return d
	}
	d.Available = true
	// Weight violations by severity, cap at 1.0.
	var weighted float64
	for _, v := range a.Violations {
		weighted += chainSeverityWeight(v.Severity)
	}
	d.Score = clampRisk(weighted / 5.0)
	d.Findings = len(a.Violations)
	d.CriticalFindings = a.CriticalCount
	d.Details = fmt.Sprintf("%d violations across %d chains", len(a.Violations), a.TotalChains)
	return d
}

func chainSeverityWeight(sev string) float64 {
	switch sev {
	case "critical":
		return 3.0
	case "high":
		return 2.0
	case "medium":
		return 1.0
	case "low":
		return 0.3
	default:
		return 0.1
	}
}

func buildThreatDimension(m *ThreatModel, w float64) RiskDimension {
	d := RiskDimension{Name: DimThreatModel, Weight: w}
	if m == nil {
		d.Details = "not computed"
		return d
	}
	d.Available = true
	d.Score = clampRisk(m.OverallRisk / 10.0)
	d.Findings = m.ThreatCount
	d.CriticalFindings = m.CriticalCount
	d.Details = fmt.Sprintf("%d threats (overall risk %.1f/10)", m.ThreatCount, m.OverallRisk)
	return d
}

func buildBehaviorDimension(reports []*agent.DeviationReport, w float64) RiskDimension {
	d := RiskDimension{Name: DimBehaviorProfile, Weight: w}
	if len(reports) == 0 {
		d.Details = "not computed"
		return d
	}
	d.Available = true

	var totalDeviations, criticalDeviations, anomalyCount int
	var maxRisk float64
	for _, r := range reports {
		if r == nil {
			continue
		}
		totalDeviations += len(r.Deviations)
		if r.IsAnomaly {
			anomalyCount++
		}
		if r.RiskScore > maxRisk {
			maxRisk = r.RiskScore
		}
		for _, dev := range r.Deviations {
			if dev.Severity == "critical" {
				criticalDeviations++
			}
		}
	}

	d.Findings = totalDeviations
	d.CriticalFindings = criticalDeviations

	// Score: blend the worst-case agent risk with the anomaly ratio.
	anomalyRatio := 0.0
	if len(reports) > 0 {
		anomalyRatio = float64(anomalyCount) / float64(len(reports))
	}
	d.Score = clampRisk(0.6*maxRisk + 0.4*anomalyRatio)
	d.Details = fmt.Sprintf("%d deviations across %d agents (%d anomalous)",
		totalDeviations, len(reports), anomalyCount)
	return d
}

// ---------------------------------------------------------------------------
// Grading, verdict, and scoring helpers
// ---------------------------------------------------------------------------

func riskGrade(score float64) string {
	switch {
	case score < 0.15:
		return "A"
	case score < 0.30:
		return "B"
	case score < 0.50:
		return "C"
	case score < 0.70:
		return "D"
	default:
		return "F"
	}
}

func riskVerdict(score float64) string {
	switch {
	case score < 0.15:
		return "acceptable"
	case score < 0.30:
		return "needs_attention"
	case score < 0.50:
		return "at_risk"
	default:
		return "critical"
	}
}

func clampRisk(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func roundRisk(f float64) float64 {
	return math.Round(f*100) / 100
}

// ---------------------------------------------------------------------------
// Top-risk extraction
// ---------------------------------------------------------------------------

// extractTopRisks finds the most significant risk descriptions across all
// available dimensions, returning up to 5.
func extractTopRisks(dims []RiskDimension) []string {
	type scoredRisk struct {
		score float64
		desc  string
	}
	var risks []scoredRisk

	for _, d := range dims {
		if !d.Available || d.Score == 0 {
			continue
		}
		risks = append(risks, scoredRisk{
			score: d.Score * d.Weight,
			desc:  fmt.Sprintf("[%s] %s (score %.2f)", d.Name, d.Details, d.Score),
		})
	}

	sort.Slice(risks, func(i, j int) bool { return risks[i].score > risks[j].score })

	out := make([]string, 0, 5)
	for i, r := range risks {
		if i >= 5 {
			break
		}
		out = append(out, r.desc)
	}
	return out
}

// ---------------------------------------------------------------------------
// Recommendation generation
// ---------------------------------------------------------------------------

func generateRecommendations(p *RiskPosture) []string {
	var recs []string

	for _, d := range p.Dimensions {
		if !d.Available {
			recs = append(recs, fmt.Sprintf("Run %s analysis to improve visibility", d.Name))
			continue
		}
		switch {
		case d.Score >= 0.70:
			recs = append(recs, fmt.Sprintf("CRITICAL: address %s issues immediately (%d findings)", d.Name, d.Findings))
		case d.Score >= 0.50:
			recs = append(recs, fmt.Sprintf("HIGH: reduce %s risk (%d findings)", d.Name, d.Findings))
		case d.Score >= 0.30:
			recs = append(recs, fmt.Sprintf("Review %s findings (%d issues)", d.Name, d.Findings))
		}
	}

	if p.CriticalFindings > 0 {
		recs = append(recs, fmt.Sprintf("Resolve %d critical findings before deployment", p.CriticalFindings))
	}

	return recs
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatRiskPosture renders the risk posture as a human-readable report
// with box-drawing characters.
func FormatRiskPosture(p *RiskPosture) string {
	if p == nil {
		return "No risk assessment available.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│                  RISK POSTURE                       │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	b.WriteString(fmt.Sprintf("│  Overall Score : %-6.2f  Grade: %-3s               │\n", p.OverallScore, p.Grade))
	b.WriteString(fmt.Sprintf("│  Verdict       : %-36s│\n", p.Verdict))
	b.WriteString(fmt.Sprintf("│  Findings      : %-4d total, %-4d critical          │\n", p.TotalFindings, p.CriticalFindings))

	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	b.WriteString("│  DIMENSIONS                                         │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	for _, d := range p.Dimensions {
		status := "✓"
		if !d.Available {
			status = "○"
		}
		bar := riskBar(d.Score, 20)
		b.WriteString(fmt.Sprintf("│  %s %-18s %s %-6.2f (%d findings) │\n",
			status, d.Name, bar, d.Score, d.Findings))
	}

	if len(p.TopRisks) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│  TOP RISKS                                          │\n")
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for i, r := range p.TopRisks {
			// Wrap long risk descriptions.
			if len(r) > 49 {
				r = r[:46] + "..."
			}
			b.WriteString(fmt.Sprintf("│  %d. %-48s│\n", i+1, r))
		}
	}

	if len(p.Recommendations) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│  RECOMMENDATIONS                                    │\n")
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for _, r := range p.Recommendations {
			if len(r) > 49 {
				r = r[:46] + "..."
			}
			b.WriteString(fmt.Sprintf("│  • %-49s│\n", r))
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}

// riskBar renders a fixed-width bar chart segment showing the risk level.
func riskBar(score float64, width int) string {
	filled := int(math.Round(score * float64(width)))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

// SummarizeRisk returns a one-line summary of the risk posture.
func SummarizeRisk(p *RiskPosture) string {
	if p == nil {
		return "no risk assessment"
	}
	return fmt.Sprintf("Risk: %s (%.2f) — %s — %d findings (%d critical)",
		p.Grade, p.OverallScore, p.Verdict, p.TotalFindings, p.CriticalFindings)
}
