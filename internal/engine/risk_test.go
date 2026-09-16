// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"math"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func riskCfg() *RiskConfig { return DefaultRiskConfig() }

func lintReport(score float64, errorCount, warnCount, infoCount int) *policy.LintReport {
	return &policy.LintReport{
		PolicyName:   "test-policy",
		Score:        score,
		Grade:        "B",
		FindingCount: errorCount + warnCount + infoCount,
		ErrorCount:   errorCount,
		WarningCount: warnCount,
		InfoCount:    infoCount,
	}
}

func driftReport(findings []policy.DriftFinding) *policy.DriftReport {
	r := &policy.DriftReport{
		BaselinePolicy: "baseline",
		CurrentPolicy:  "current",
		Findings:       findings,
	}
	for _, f := range findings {
		switch f.Severity {
		case policy.DriftCritical:
			r.CriticalCount++
		case policy.DriftHigh:
			r.HighCount++
		case policy.DriftMedium:
			r.MediumCount++
		case policy.DriftLow:
			r.LowCount++
		default:
			r.InfoCount++
		}
	}
	r.DriftScore = float64(len(findings)) * 0.5
	return r
}

func coverageReport(riskScore, coveragePct float64, gaps int) *policy.CoverageMapReport {
	r := &policy.CoverageMapReport{
		PolicyName:          "test-policy",
		RiskScore:           riskScore,
		CoveragePercent:     coveragePct,
		UncoveredTechniques: gaps,
		TotalTechniques:     20,
		CoveredTechniques:   20 - gaps,
	}
	for i := 0; i < gaps; i++ {
		sev := "medium"
		if i < 2 {
			sev = "critical"
		}
		r.Gaps = append(r.Gaps, policy.TechniqueGap{
			TechniqueID: "T1234",
			Severity:    sev,
		})
	}
	return r
}

func chainAnalysis(violations []agent.ChainViolation) *agent.ChainAnalysis {
	a := &agent.ChainAnalysis{
		TotalAgents: 5,
		TotalChains: 3,
		Violations:  violations,
	}
	for _, v := range violations {
		switch v.Severity {
		case "critical":
			a.CriticalCount++
		case "high":
			a.HighCount++
		case "medium":
			a.MediumCount++
		case "low":
			a.LowCount++
		}
	}
	a.RiskScore = float64(len(violations)) * 0.2
	if a.RiskScore > 1 {
		a.RiskScore = 1
	}
	return a
}

func threatModel(overallRisk float64, critCount, totalCount int) *ThreatModel {
	return &ThreatModel{
		Name:          "test-deployment",
		OverallRisk:   overallRisk,
		ThreatCount:   totalCount,
		CriticalCount: critCount,
		HighCount:     totalCount - critCount,
	}
}

func chainViolation(sev string) agent.ChainViolation {
	return agent.ChainViolation{
		Type:        "escalation",
		Severity:    sev,
		Chain:       []string{"a", "b"},
		Description: sev + " violation",
	}
}

func driftFinding(sev policy.DriftSeverity) policy.DriftFinding {
	return policy.DriftFinding{
		Type:        policy.DriftEffectChanged,
		Severity:    sev,
		Description: string(sev) + " drift",
	}
}

// ---------------------------------------------------------------------------
// DefaultRiskConfig
// ---------------------------------------------------------------------------

func TestDefaultRiskConfig(t *testing.T) {
	cfg := DefaultRiskConfig()
	if cfg == nil {
		t.Fatal("DefaultRiskConfig returned nil")
	}
	if len(cfg.Weights) != 6 {
		t.Errorf("expected 6 weights, got %d", len(cfg.Weights))
	}
	// Weights should sum to ~1.0.
	var sum float64
	for _, w := range cfg.Weights {
		sum += w
	}
	if math.Abs(sum-1.0) > 0.01 {
		t.Errorf("weights sum to %.3f, want ~1.0", sum)
	}
}

// ---------------------------------------------------------------------------
// Nil / empty inputs
// ---------------------------------------------------------------------------

func TestAssessRisk_NilInputs(t *testing.T) {
	p := AssessRisk(nil, nil)
	if p.Grade != "A" {
		t.Errorf("nil inputs: grade = %s, want A", p.Grade)
	}
	if p.OverallScore != 0 {
		t.Errorf("nil inputs: score = %f, want 0", p.OverallScore)
	}
	if p.TotalFindings != 0 {
		t.Errorf("nil inputs: findings = %d, want 0", p.TotalFindings)
	}
	if p.Verdict != "acceptable" {
		t.Errorf("nil inputs: verdict = %s, want acceptable", p.Verdict)
	}
}

func TestAssessRisk_EmptyInputs(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{})
	if p.Grade != "A" {
		t.Errorf("empty inputs: grade = %s, want A", p.Grade)
	}
	if p.OverallScore != 0 {
		t.Errorf("empty inputs: score = %f, want 0", p.OverallScore)
	}
}

func TestAssessRisk_NilConfig(t *testing.T) {
	p := AssessRisk(nil, &RiskInputs{
		LintReport: lintReport(0.90, 1, 2, 0),
	})
	if p == nil {
		t.Fatal("nil config: returned nil")
	}
	if p.OverallScore == 0 {
		t.Error("nil config with lint input: score should be > 0")
	}
}

// ---------------------------------------------------------------------------
// Single-dimension tests
// ---------------------------------------------------------------------------

func TestAssessRisk_OnlyLint(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport: lintReport(0.80, 2, 3, 1), // score 0.80 → risk 0.20
	})
	// Only lint is available; weight redistributed → score = lint risk = 0.20.
	if p.OverallScore < 0.15 || p.OverallScore > 0.25 {
		t.Errorf("lint-only: score = %.2f, want ~0.20", p.OverallScore)
	}
	if p.TotalFindings != 6 {
		t.Errorf("lint-only: findings = %d, want 6", p.TotalFindings)
	}
	if p.CriticalFindings != 2 {
		t.Errorf("lint-only: critical = %d, want 2", p.CriticalFindings)
	}
}

func TestAssessRisk_OnlyCoverage(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		CoverageMap: coverageReport(0.60, 40.0, 12),
	})
	// Only coverage; redistributed → score = coverage risk = 0.60.
	if p.OverallScore < 0.55 || p.OverallScore > 0.65 {
		t.Errorf("coverage-only: score = %.2f, want ~0.60", p.OverallScore)
	}
}

func TestAssessRisk_OnlyThreatModel(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		ThreatModel: threatModel(7.5, 3, 10),
	})
	// OverallRisk 7.5 / 10 = 0.75.
	if p.OverallScore < 0.70 || p.OverallScore > 0.80 {
		t.Errorf("threat-only: score = %.2f, want ~0.75", p.OverallScore)
	}
	if p.CriticalFindings != 3 {
		t.Errorf("threat-only: critical = %d, want 3", p.CriticalFindings)
	}
}

func TestAssessRisk_OnlyChains(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		ChainAnalysis: chainAnalysis([]agent.ChainViolation{
			chainViolation("critical"),
			chainViolation("high"),
		}),
	})
	// (3.0 + 2.0) / 5.0 = 1.0 → capped at 1.0.
	if p.OverallScore < 0.95 {
		t.Errorf("chains-only: score = %.2f, want ~1.0", p.OverallScore)
	}
}

func TestAssessRisk_OnlyDrift(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		DriftReport: driftReport([]policy.DriftFinding{
			driftFinding(policy.DriftHigh),
			driftFinding(policy.DriftMedium),
		}),
	})
	// (2.5 + 1.5) / 10 = 0.40.
	if p.OverallScore < 0.35 || p.OverallScore > 0.45 {
		t.Errorf("drift-only: score = %.2f, want ~0.40", p.OverallScore)
	}
}

// ---------------------------------------------------------------------------
// Multi-dimension tests
// ---------------------------------------------------------------------------

func TestAssessRisk_AllInputs(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport:    lintReport(0.85, 1, 2, 0),
		DriftReport:   driftReport([]policy.DriftFinding{driftFinding(policy.DriftLow)}),
		CoverageMap:   coverageReport(0.30, 70.0, 6),
		ChainAnalysis: chainAnalysis([]agent.ChainViolation{chainViolation("medium")}),
		ThreatModel:   threatModel(4.0, 1, 8),
		BehaviorReports: []*agent.DeviationReport{
			{AgentName: "test", RiskScore: 0.3, IsAnomaly: false,
				Deviations: []agent.ProfileDeviation{{Severity: "low", Score: 0.2}}},
		},
	})

	if p.OverallScore < 0.10 || p.OverallScore > 0.50 {
		t.Errorf("all-inputs: score = %.2f, want in [0.10, 0.50]", p.OverallScore)
	}
	if p.TotalFindings == 0 {
		t.Error("all-inputs: total findings should be > 0")
	}
	if len(p.Dimensions) != 6 {
		t.Errorf("all-inputs: dimensions = %d, want 6", len(p.Dimensions))
	}

	available := 0
	for _, d := range p.Dimensions {
		if d.Available {
			available++
		}
	}
	if available != 6 {
		t.Errorf("all-inputs: available = %d, want 6", available)
	}
}

func TestAssessRisk_DimensionOrder(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{})
	if len(p.Dimensions) != 6 {
		t.Fatalf("expected 6 dimensions, got %d", len(p.Dimensions))
	}
	expected := []string{DimPolicyLint, DimCoverageGaps, DimThreatModel, DimAgentChains, DimPolicyDrift, DimBehaviorProfile}
	for i, d := range p.Dimensions {
		if d.Name != expected[i] {
			t.Errorf("dimension[%d] = %s, want %s", i, d.Name, expected[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Custom weights
// ---------------------------------------------------------------------------

func TestAssessRisk_CustomWeights(t *testing.T) {
	cfg := &RiskConfig{
		Weights: map[string]float64{
			DimPolicyLint:      1.0,
			DimCoverageGaps:    0.0,
			DimThreatModel:     0.0,
			DimAgentChains:     0.0,
			DimPolicyDrift:     0.0,
			DimBehaviorProfile: 0.0,
		},
	}
	p := AssessRisk(cfg, &RiskInputs{
		LintReport:  lintReport(0.50, 5, 3, 2),
		CoverageMap: coverageReport(0.90, 10.0, 18),
	})
	// Only lint has weight; coverage's weight is 0.
	// Lint risk = 1.0 - 0.50 = 0.50; total weight = 1.0 from lint.
	if math.Abs(p.OverallScore-0.50) > 0.01 {
		t.Errorf("custom weights: score = %.2f, want 0.50", p.OverallScore)
	}
}

func TestAssessRisk_ZeroWeightDimExcluded(t *testing.T) {
	cfg := &RiskConfig{
		Weights: map[string]float64{
			DimPolicyLint:      0.50,
			DimCoverageGaps:    0.50,
			DimThreatModel:     0.0,
			DimAgentChains:     0.0,
			DimPolicyDrift:     0.0,
			DimBehaviorProfile: 0.0,
		},
	}
	p := AssessRisk(cfg, &RiskInputs{
		LintReport:  lintReport(1.0, 0, 0, 0), // risk = 0.0
		CoverageMap: coverageReport(0.40, 60.0, 8),
	})
	// (0.0 * 0.5 + 0.4 * 0.5) / 1.0 = 0.20.
	if math.Abs(p.OverallScore-0.20) > 0.01 {
		t.Errorf("zero-weight: score = %.2f, want 0.20", p.OverallScore)
	}
}

// ---------------------------------------------------------------------------
// Grade boundary tests
// ---------------------------------------------------------------------------

func TestRiskGrade_A(t *testing.T) {
	if g := riskGrade(0.0); g != "A" {
		t.Errorf("grade(0.0) = %s, want A", g)
	}
	if g := riskGrade(0.14); g != "A" {
		t.Errorf("grade(0.14) = %s, want A", g)
	}
}

func TestRiskGrade_B(t *testing.T) {
	if g := riskGrade(0.15); g != "B" {
		t.Errorf("grade(0.15) = %s, want B", g)
	}
	if g := riskGrade(0.29); g != "B" {
		t.Errorf("grade(0.29) = %s, want B", g)
	}
}

func TestRiskGrade_C(t *testing.T) {
	if g := riskGrade(0.30); g != "C" {
		t.Errorf("grade(0.30) = %s, want C", g)
	}
	if g := riskGrade(0.49); g != "C" {
		t.Errorf("grade(0.49) = %s, want C", g)
	}
}

func TestRiskGrade_D(t *testing.T) {
	if g := riskGrade(0.50); g != "D" {
		t.Errorf("grade(0.50) = %s, want D", g)
	}
	if g := riskGrade(0.69); g != "D" {
		t.Errorf("grade(0.69) = %s, want D", g)
	}
}

func TestRiskGrade_F(t *testing.T) {
	if g := riskGrade(0.70); g != "F" {
		t.Errorf("grade(0.70) = %s, want F", g)
	}
	if g := riskGrade(1.0); g != "F" {
		t.Errorf("grade(1.0) = %s, want F", g)
	}
}

// ---------------------------------------------------------------------------
// Verdict tests
// ---------------------------------------------------------------------------

func TestRiskVerdict_Acceptable(t *testing.T) {
	if v := riskVerdict(0.0); v != "acceptable" {
		t.Errorf("verdict(0.0) = %s, want acceptable", v)
	}
}

func TestRiskVerdict_NeedsAttention(t *testing.T) {
	if v := riskVerdict(0.20); v != "needs_attention" {
		t.Errorf("verdict(0.20) = %s, want needs_attention", v)
	}
}

func TestRiskVerdict_AtRisk(t *testing.T) {
	if v := riskVerdict(0.40); v != "at_risk" {
		t.Errorf("verdict(0.40) = %s, want at_risk", v)
	}
}

func TestRiskVerdict_Critical(t *testing.T) {
	if v := riskVerdict(0.80); v != "critical" {
		t.Errorf("verdict(0.80) = %s, want critical", v)
	}
}

// ---------------------------------------------------------------------------
// Score clamping
// ---------------------------------------------------------------------------

func TestClampRisk_NegativeToZero(t *testing.T) {
	if c := clampRisk(-0.5); c != 0 {
		t.Errorf("clamp(-0.5) = %f, want 0", c)
	}
}

func TestClampRisk_AboveOneToOne(t *testing.T) {
	if c := clampRisk(1.5); c != 1.0 {
		t.Errorf("clamp(1.5) = %f, want 1.0", c)
	}
}

func TestClampRisk_InRange(t *testing.T) {
	if c := clampRisk(0.42); math.Abs(c-0.42) > 0.001 {
		t.Errorf("clamp(0.42) = %f, want 0.42", c)
	}
}

// ---------------------------------------------------------------------------
// TopRisks extraction
// ---------------------------------------------------------------------------

func TestExtractTopRisks_Empty(t *testing.T) {
	risks := extractTopRisks(nil)
	if len(risks) != 0 {
		t.Errorf("nil dims: top risks = %d, want 0", len(risks))
	}
}

func TestExtractTopRisks_Capped(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport:    lintReport(0.50, 3, 3, 1),
		DriftReport:   driftReport([]policy.DriftFinding{driftFinding(policy.DriftHigh)}),
		CoverageMap:   coverageReport(0.60, 40.0, 12),
		ChainAnalysis: chainAnalysis([]agent.ChainViolation{chainViolation("high")}),
		ThreatModel:   threatModel(6.0, 2, 8),
	})
	if len(p.TopRisks) > 5 {
		t.Errorf("top risks = %d, want <= 5", len(p.TopRisks))
	}
	if len(p.TopRisks) == 0 {
		t.Error("expected at least one top risk")
	}
}

func TestExtractTopRisks_SortedByWeightedScore(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport:  lintReport(0.30, 5, 5, 2), // risk = 0.70, high
		CoverageMap: coverageReport(0.10, 90.0, 2),
	})
	if len(p.TopRisks) < 2 {
		t.Fatalf("expected >= 2 top risks, got %d", len(p.TopRisks))
	}
	// Lint has higher weighted risk (0.70 * 0.15 = 0.105) but coverage has
	// lower score (0.10 * 0.25 = 0.025), so lint should be first.
	if !strings.Contains(p.TopRisks[0], "policy_lint") {
		t.Errorf("first top risk should contain policy_lint, got: %s", p.TopRisks[0])
	}
}

// ---------------------------------------------------------------------------
// Recommendations
// ---------------------------------------------------------------------------

func TestRecommendations_UnavailableDims(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{})
	// All 6 dimensions unavailable → 6 "run analysis" recommendations.
	foundRun := 0
	for _, r := range p.Recommendations {
		if strings.Contains(r, "Run") && strings.Contains(r, "analysis") {
			foundRun++
		}
	}
	if foundRun != 6 {
		t.Errorf("expected 6 'run analysis' recommendations, got %d", foundRun)
	}
}

func TestRecommendations_CriticalFindings(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		ThreatModel: threatModel(8.0, 5, 12),
	})
	found := false
	for _, r := range p.Recommendations {
		if strings.Contains(r, "critical findings") {
			found = true
		}
	}
	if !found {
		t.Error("expected critical-findings recommendation")
	}
}

func TestRecommendations_HighRiskDim(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		CoverageMap: coverageReport(0.80, 20.0, 16),
	})
	found := false
	for _, r := range p.Recommendations {
		if strings.Contains(r, "CRITICAL") && strings.Contains(r, "coverage_gaps") {
			found = true
		}
	}
	if !found {
		t.Error("expected CRITICAL recommendation for high-risk coverage gaps")
	}
}

// ---------------------------------------------------------------------------
// Format output
// ---------------------------------------------------------------------------

func TestFormatRiskPosture_Nil(t *testing.T) {
	out := FormatRiskPosture(nil)
	if !strings.Contains(out, "No risk assessment") {
		t.Error("nil posture: expected 'No risk assessment'")
	}
}

func TestFormatRiskPosture_ContainsSections(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport:  lintReport(0.70, 2, 3, 1),
		CoverageMap: coverageReport(0.40, 60.0, 8),
	})
	out := FormatRiskPosture(p)
	sections := []string{"RISK POSTURE", "DIMENSIONS", "TOP RISKS", "RECOMMENDATIONS"}
	for _, s := range sections {
		if !strings.Contains(out, s) {
			t.Errorf("format: missing section %q", s)
		}
	}
}

func TestFormatRiskPosture_ShowsGrade(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport: lintReport(0.90, 1, 1, 0),
	})
	out := FormatRiskPosture(p)
	if !strings.Contains(out, p.Grade) {
		t.Error("format: missing grade")
	}
}

func TestFormatRiskPosture_ShowsDimensions(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport: lintReport(0.80, 1, 2, 0),
	})
	out := FormatRiskPosture(p)
	if !strings.Contains(out, "policy_lint") {
		t.Error("format: missing policy_lint dimension")
	}
	if !strings.Contains(out, "coverage_gaps") {
		t.Error("format: missing coverage_gaps dimension")
	}
}

func TestFormatRiskPosture_RiskBar(t *testing.T) {
	bar := riskBar(0.5, 10)
	if !strings.Contains(bar, "█") {
		t.Error("risk bar: missing filled chars")
	}
	if !strings.Contains(bar, "░") {
		t.Error("risk bar: missing empty chars")
	}
}

// ---------------------------------------------------------------------------
// Summarize
// ---------------------------------------------------------------------------

func TestSummarizeRisk_Nil(t *testing.T) {
	s := SummarizeRisk(nil)
	if s != "no risk assessment" {
		t.Errorf("nil: got %q", s)
	}
}

func TestSummarizeRisk_OneLine(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport: lintReport(0.85, 1, 1, 0),
	})
	s := SummarizeRisk(p)
	if !strings.Contains(s, "Risk:") {
		t.Error("summary: missing 'Risk:'")
	}
	if !strings.Contains(s, p.Grade) {
		t.Errorf("summary: missing grade %s", p.Grade)
	}
	if !strings.Contains(s, p.Verdict) {
		t.Errorf("summary: missing verdict %s", p.Verdict)
	}
	if strings.Count(s, "\n") > 0 {
		t.Error("summary: should be one line")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestAssessRisk_PerfectLint(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport: lintReport(1.0, 0, 0, 0),
	})
	// 1.0 - 1.0 = 0 risk.
	if p.OverallScore != 0 {
		t.Errorf("perfect lint: score = %.2f, want 0", p.OverallScore)
	}
	if p.Grade != "A" {
		t.Errorf("perfect lint: grade = %s, want A", p.Grade)
	}
}

func TestAssessRisk_WorstCase(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport: lintReport(0.0, 10, 5, 3),
		DriftReport: driftReport([]policy.DriftFinding{
			driftFinding(policy.DriftCritical),
			driftFinding(policy.DriftCritical),
			driftFinding(policy.DriftCritical),
		}),
		CoverageMap:   coverageReport(1.0, 0.0, 20),
		ChainAnalysis: chainAnalysis([]agent.ChainViolation{chainViolation("critical"), chainViolation("critical")}),
		ThreatModel:   threatModel(10.0, 8, 12),
	})
	if p.OverallScore < 0.90 {
		t.Errorf("worst case: score = %.2f, want >= 0.90", p.OverallScore)
	}
	if p.Grade != "F" {
		t.Errorf("worst case: grade = %s, want F", p.Grade)
	}
	if p.Verdict != "critical" {
		t.Errorf("worst case: verdict = %s, want critical", p.Verdict)
	}
}

func TestAssessRisk_WeightRedistribution(t *testing.T) {
	// If only lint is available (weight 0.15), and lint risk = 0.50,
	// after redistribution the overall score should equal lint's raw score.
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport: lintReport(0.50, 5, 5, 0),
	})
	if math.Abs(p.OverallScore-0.50) > 0.01 {
		t.Errorf("weight redistribution: score = %.2f, want 0.50", p.OverallScore)
	}
}

func TestRoundRisk(t *testing.T) {
	tests := []struct {
		in   float64
		want float64
	}{
		{0.0, 0.0},
		{0.123, 0.12},
		{0.999, 1.0},
		{0.555, 0.56},
	}
	for _, tc := range tests {
		got := roundRisk(tc.in)
		if math.Abs(got-tc.want) > 0.001 {
			t.Errorf("roundRisk(%f) = %f, want %f", tc.in, got, tc.want)
		}
	}
}

func TestRiskBar_Extremes(t *testing.T) {
	zero := riskBar(0.0, 10)
	if strings.Contains(zero, "█") {
		t.Error("0-score bar should have no filled chars")
	}
	full := riskBar(1.0, 10)
	if strings.Contains(full, "░") {
		t.Error("1.0-score bar should have no empty chars")
	}
}

func TestAssessRisk_DimensionAvailability(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport: lintReport(0.80, 1, 1, 0),
	})
	for _, d := range p.Dimensions {
		switch d.Name {
		case DimPolicyLint:
			if !d.Available {
				t.Error("lint should be available")
			}
		default:
			if d.Available {
				t.Errorf("%s should not be available", d.Name)
			}
		}
	}
}

func TestAssessRisk_FindingsSummedCorrectly(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{
		LintReport:    lintReport(0.70, 2, 3, 1), // 6 findings, 2 critical
		CoverageMap:   coverageReport(0.30, 70.0, 6),
		ChainAnalysis: chainAnalysis([]agent.ChainViolation{chainViolation("critical")}),
	})
	expectedTotal := 6 + 6 + 1 // lint + coverage gaps + chain violations
	if p.TotalFindings != expectedTotal {
		t.Errorf("total findings = %d, want %d", p.TotalFindings, expectedTotal)
	}
}

// ---------------------------------------------------------------------------
// Behavior profile dimension
// ---------------------------------------------------------------------------

func TestAssessRisk_BehaviorNilReports(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{BehaviorReports: nil})
	for _, d := range p.Dimensions {
		if d.Name == DimBehaviorProfile && d.Available {
			t.Error("behavior dimension should be unavailable with nil reports")
		}
	}
}

func TestAssessRisk_BehaviorEmptyReports(t *testing.T) {
	p := AssessRisk(riskCfg(), &RiskInputs{BehaviorReports: []*agent.DeviationReport{}})
	for _, d := range p.Dimensions {
		if d.Name == DimBehaviorProfile && d.Available {
			t.Error("behavior dimension should be unavailable with empty reports")
		}
	}
}

func TestAssessRisk_BehaviorNoAnomalies(t *testing.T) {
	reports := []*agent.DeviationReport{
		{AgentName: "normal", RiskScore: 0.1, IsAnomaly: false},
	}
	p := AssessRisk(riskCfg(), &RiskInputs{BehaviorReports: reports})
	for _, d := range p.Dimensions {
		if d.Name == DimBehaviorProfile {
			if !d.Available {
				t.Error("behavior dimension should be available")
			}
			if d.Score > 0.15 {
				t.Errorf("low-risk agent should have low score, got %.2f", d.Score)
			}
		}
	}
}

func TestAssessRisk_BehaviorHighAnomaly(t *testing.T) {
	reports := []*agent.DeviationReport{
		{AgentName: "bad", RiskScore: 0.9, IsAnomaly: true,
			Deviations: []agent.ProfileDeviation{
				{Severity: "critical", Score: 0.9, Type: "new_tool"},
				{Severity: "high", Score: 0.7, Type: "frequency_spike"},
			}},
	}
	p := AssessRisk(riskCfg(), &RiskInputs{BehaviorReports: reports})
	for _, d := range p.Dimensions {
		if d.Name == DimBehaviorProfile {
			if !d.Available {
				t.Error("behavior dimension should be available")
			}
			if d.Score < 0.5 {
				t.Errorf("anomalous agent should have high score, got %.2f", d.Score)
			}
			if d.CriticalFindings != 1 {
				t.Errorf("expected 1 critical finding, got %d", d.CriticalFindings)
			}
			if d.Findings != 2 {
				t.Errorf("expected 2 findings, got %d", d.Findings)
			}
		}
	}
}

func TestAssessRisk_BehaviorMultipleAgents(t *testing.T) {
	reports := []*agent.DeviationReport{
		{AgentName: "normal", RiskScore: 0.1, IsAnomaly: false},
		{AgentName: "suspect", RiskScore: 0.7, IsAnomaly: true,
			Deviations: []agent.ProfileDeviation{
				{Severity: "medium", Score: 0.5},
			}},
		{AgentName: "clean", RiskScore: 0.05, IsAnomaly: false},
	}
	p := AssessRisk(riskCfg(), &RiskInputs{BehaviorReports: reports})
	for _, d := range p.Dimensions {
		if d.Name == DimBehaviorProfile {
			if d.Findings != 1 {
				t.Errorf("expected 1 total deviation, got %d", d.Findings)
			}
			if !strings.Contains(d.Details, "1 anomalous") {
				t.Errorf("details should mention 1 anomalous, got: %s", d.Details)
			}
		}
	}
}

func TestBuildBehaviorDimension_NilEntries(t *testing.T) {
	reports := []*agent.DeviationReport{nil, nil}
	d := buildBehaviorDimension(reports, 0.05)
	if !d.Available {
		t.Error("dimension should be available even with nil entries")
	}
	if d.Findings != 0 {
		t.Errorf("nil reports should yield 0 findings, got %d", d.Findings)
	}
}
