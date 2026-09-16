// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package compliance

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/gap"
	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// Framework identifies a compliance framework.
type Framework string

const (
	NISTCSF   Framework = "nist-csf"
	NIST80053 Framework = "nist-800-53"
	CISv8     Framework = "cis-v8"
)

// ValidFrameworks returns all supported framework identifiers.
func ValidFrameworks() []string {
	return []string{string(NISTCSF), string(NIST80053), string(CISv8)}
}

// ValidFramework reports whether name is a supported framework.
func ValidFramework(name string) bool {
	for _, f := range ValidFrameworks() {
		if f == name {
			return true
		}
	}
	return false
}

// Control represents a single compliance control or category.
type Control struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tactics     []string `json:"tactics"`
}

// FrameworkDef defines a compliance framework and its controls.
type FrameworkDef struct {
	ID          Framework  `json:"id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description"`
	Controls    []*Control `json:"controls"`
}

// Assessment is the result of mapping campaign coverage to a framework.
type Assessment struct {
	Framework       FrameworkDef         `json:"framework"`
	TotalControls   int                  `json:"total_controls"`
	CoveredControls int                  `json:"covered_controls"`
	CoveragePercent float64              `json:"coverage_percent"`
	ControlResults  []ControlResult      `json:"control_results"`
	TacticsCovered  map[string]bool      `json:"-"`
	GapsByControl   map[string][]gap.Gap `json:"-"`
	Summary         AssessmentSummary    `json:"summary"`
}

// ControlResult is the coverage assessment for one control.
type ControlResult struct {
	Control    Control  `json:"control"`
	Covered    bool     `json:"covered"`
	Coverage   float64  `json:"coverage"`
	Techniques []string `json:"techniques,omitempty"`
	Gaps       []string `json:"gaps,omitempty"`
	RiskLevel  string   `json:"risk_level"`
}

// AssessmentSummary provides aggregate metrics.
type AssessmentSummary struct {
	CriticalGaps  int     `json:"critical_gaps"`
	HighGaps      int     `json:"high_gaps"`
	MediumGaps    int     `json:"medium_gaps"`
	LowGaps       int     `json:"low_gaps"`
	PostureScore  float64 `json:"posture_score"`
	PostureRating string  `json:"posture_rating"`
}

// Assess maps a gap report's coverage to a compliance framework.
func Assess(report *gap.GapReport, framework Framework) (*Assessment, error) {
	def := LookupFramework(framework)
	if def == nil {
		return nil, fmt.Errorf("unknown framework: %s", framework)
	}

	tacticsCovered := extractCoveredTactics(report)
	techniquesByTactic := extractTechniquesByTactic(report)
	gapsByTactic := extractGapsByTactic(report)

	a := &Assessment{
		Framework:      *def,
		TotalControls:  len(def.Controls),
		TacticsCovered: tacticsCovered,
		GapsByControl:  make(map[string][]gap.Gap),
	}

	for _, ctrl := range def.Controls {
		cr := assessControl(ctrl, tacticsCovered, techniquesByTactic, gapsByTactic)
		a.ControlResults = append(a.ControlResults, cr)
		if cr.Covered {
			a.CoveredControls++
		}
		if len(cr.Gaps) > 0 {
			var controlGaps []gap.Gap
			for _, t := range ctrl.Tactics {
				controlGaps = append(controlGaps, gapsByTactic[t]...)
			}
			a.GapsByControl[ctrl.ID] = controlGaps
		}
	}

	if a.TotalControls > 0 {
		a.CoveragePercent = float64(a.CoveredControls) / float64(a.TotalControls) * 100
	}

	a.Summary = computeSummary(a)
	return a, nil
}

// AssessAll maps coverage against all supported frameworks.
func AssessAll(report *gap.GapReport) ([]*Assessment, error) {
	var results []*Assessment
	for _, fw := range ValidFrameworks() {
		a, err := Assess(report, Framework(fw))
		if err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	return results, nil
}

// LookupFramework returns the framework definition, or nil if unknown.
func LookupFramework(fw Framework) *FrameworkDef {
	switch fw {
	case NISTCSF:
		return nistCSFDef()
	case NIST80053:
		return nist80053Def()
	case CISv8:
		return cisV8Def()
	}
	return nil
}

func assessControl(ctrl *Control, tacticsCovered map[string]bool, techniquesByTactic map[string][]string, gapsByTactic map[string][]gap.Gap) ControlResult {
	cr := ControlResult{
		Control: *ctrl,
	}

	if len(ctrl.Tactics) == 0 {
		cr.RiskLevel = "low"
		return cr
	}

	coveredCount := 0
	for _, t := range ctrl.Tactics {
		if tacticsCovered[t] {
			coveredCount++
			cr.Techniques = append(cr.Techniques, techniquesByTactic[t]...)
		} else {
			cr.Gaps = append(cr.Gaps, "No campaign coverage for tactic: "+t)
		}
		for _, g := range gapsByTactic[t] {
			if g.Type == gap.GapDetectionMissing {
				cr.Gaps = append(cr.Gaps, fmt.Sprintf("Detection gap: %s (%s)", g.StageName, g.Technique))
			}
		}
	}

	if coveredCount > 0 {
		cr.Covered = true
		cr.Coverage = float64(coveredCount) / float64(len(ctrl.Tactics)) * 100
	}

	cr.Techniques = dedup(cr.Techniques)
	cr.RiskLevel = controlRiskLevel(ctrl, cr.Covered)
	return cr
}

func controlRiskLevel(ctrl *Control, covered bool) string {
	if covered {
		return "low"
	}
	for _, t := range ctrl.Tactics {
		if t == "initial-access" || t == "execution" || t == "exfiltration" || t == "impact" {
			return "critical"
		}
		if t == "credential-access" || t == "lateral-movement" || t == "privilege-escalation" {
			return "high"
		}
	}
	return "medium"
}

func computeSummary(a *Assessment) AssessmentSummary {
	s := AssessmentSummary{}
	for _, cr := range a.ControlResults {
		if cr.Covered {
			continue
		}
		switch cr.RiskLevel {
		case "critical":
			s.CriticalGaps++
		case "high":
			s.HighGaps++
		case "medium":
			s.MediumGaps++
		case "low":
			s.LowGaps++
		}
	}

	totalWeight := float64(a.TotalControls * 10)
	if totalWeight == 0 {
		return s
	}
	coveredWeight := float64(a.CoveredControls * 10)
	gapPenalty := float64(s.CriticalGaps*10 + s.HighGaps*5 + s.MediumGaps*2 + s.LowGaps*1)
	s.PostureScore = (coveredWeight - gapPenalty) / totalWeight * 100
	if s.PostureScore < 0 {
		s.PostureScore = 0
	}

	switch {
	case s.PostureScore >= 90:
		s.PostureRating = "strong"
	case s.PostureScore >= 70:
		s.PostureRating = "moderate"
	case s.PostureScore >= 50:
		s.PostureRating = "developing"
	default:
		s.PostureRating = "weak"
	}
	return s
}

func extractCoveredTactics(report *gap.GapReport) map[string]bool {
	covered := make(map[string]bool)
	if report.Aggregate.AttackTactics.Covered > 0 {
		for _, d := range report.Aggregate.AttackTactics.Details {
			covered[d.Short] = true
		}
	}
	if report.Aggregate.AtlasTactics.Covered > 0 {
		for _, d := range report.Aggregate.AtlasTactics.Details {
			covered[d.Short] = true
		}
	}
	return covered
}

func extractTechniquesByTactic(report *gap.GapReport) map[string][]string {
	byTactic := make(map[string][]string)
	for _, g := range report.Gaps {
		if g.Technique != "" && g.Tactic != "" {
			byTactic[g.Tactic] = append(byTactic[g.Tactic], g.Technique)
		}
	}
	for _, cc := range report.Campaigns {
		for _, d := range cc.AttackTactics.Details {
			if t := mitre.TacticByShort(d.Short); t != nil {
				byTactic[d.Short] = appendIfMissing(byTactic[d.Short], t.ID)
			}
		}
		for _, d := range cc.AtlasTactics.Details {
			if t := mitre.ATLASTacticByShort(d.Short); t != nil {
				byTactic[d.Short] = appendIfMissing(byTactic[d.Short], t.ID)
			}
		}
	}
	return byTactic
}

func extractGapsByTactic(report *gap.GapReport) map[string][]gap.Gap {
	byTactic := make(map[string][]gap.Gap)
	for _, g := range report.Gaps {
		if g.Tactic != "" {
			byTactic[g.Tactic] = append(byTactic[g.Tactic], g)
		}
	}
	return byTactic
}

func dedup(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func appendIfMissing(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}

// FormatAssessment formats a compliance assessment as human-readable text.
func FormatAssessment(a *Assessment) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Compliance Assessment: %s %s\n", a.Framework.Name, a.Framework.Version)
	fmt.Fprintf(&b, "%s\n\n", strings.Repeat("=", 60))
	fmt.Fprintf(&b, "Coverage: %d / %d controls (%.1f%%)\n", a.CoveredControls, a.TotalControls, a.CoveragePercent)
	fmt.Fprintf(&b, "Posture Score: %.1f / 100 (%s)\n\n", a.Summary.PostureScore, a.Summary.PostureRating)

	if a.Summary.CriticalGaps > 0 || a.Summary.HighGaps > 0 {
		fmt.Fprintf(&b, "Risk Summary:\n")
		if a.Summary.CriticalGaps > 0 {
			fmt.Fprintf(&b, "  Critical: %d controls uncovered\n", a.Summary.CriticalGaps)
		}
		if a.Summary.HighGaps > 0 {
			fmt.Fprintf(&b, "  High:     %d controls uncovered\n", a.Summary.HighGaps)
		}
		if a.Summary.MediumGaps > 0 {
			fmt.Fprintf(&b, "  Medium:   %d controls uncovered\n", a.Summary.MediumGaps)
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintf(&b, "%-12s %-40s %s\n", "Control", "Name", "Status")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 70))

	for _, cr := range a.ControlResults {
		status := "COVERED"
		if !cr.Covered {
			status = "GAP [" + cr.RiskLevel + "]"
		}
		fmt.Fprintf(&b, "%-12s %-40s %s\n", cr.Control.ID, truncate(cr.Control.Name, 40), status)
	}
	fmt.Fprintln(&b)

	uncovered := 0
	for _, cr := range a.ControlResults {
		if !cr.Covered {
			uncovered++
		}
	}
	if uncovered > 0 {
		fmt.Fprintf(&b, "Uncovered Controls (%d):\n\n", uncovered)
		for _, cr := range a.ControlResults {
			if cr.Covered {
				continue
			}
			fmt.Fprintf(&b, "  %s — %s\n", cr.Control.ID, cr.Control.Name)
			for _, g := range cr.Gaps {
				fmt.Fprintf(&b, "    • %s\n", g)
			}
			fmt.Fprintln(&b)
		}
	}

	return b.String()
}

// FormatAssessmentJSON formats a compliance assessment as JSON.
func FormatAssessmentJSON(a *Assessment) (string, error) {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FormatMultiAssessment formats multiple framework assessments.
func FormatMultiAssessment(assessments []*Assessment) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Compliance Assessment — All Frameworks\n")
	fmt.Fprintf(&b, "%s\n\n", strings.Repeat("=", 60))

	fmt.Fprintf(&b, "%-15s %-30s %8s %8s %8s\n", "Framework", "Name", "Coverage", "Score", "Rating")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 75))

	for _, a := range assessments {
		fmt.Fprintf(&b, "%-15s %-30s %7.1f%% %7.1f  %s\n",
			a.Framework.ID, truncate(a.Framework.Name, 30),
			a.CoveragePercent, a.Summary.PostureScore, a.Summary.PostureRating)
	}
	fmt.Fprintln(&b)

	for _, a := range assessments {
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "%s", FormatAssessment(a))
	}

	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 4 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
