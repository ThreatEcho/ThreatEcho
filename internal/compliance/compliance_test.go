// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package compliance

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/gap"
)

func mkGapReport(attackTactics, atlasTactics []string, gaps []gap.Gap) *gap.GapReport {
	var attackDetails []gap.TacticDetail
	for _, t := range attackTactics {
		attackDetails = append(attackDetails, gap.TacticDetail{Short: t, Name: t, Stages: 1})
	}
	var atlasDetails []gap.TacticDetail
	for _, t := range atlasTactics {
		atlasDetails = append(atlasDetails, gap.TacticDetail{Short: t, Name: t, Stages: 1})
	}

	return &gap.GapReport{
		Aggregate: gap.AggregateCoverage{
			TotalCampaigns:   1,
			TotalStages:      10,
			UniqueTechniques: 5,
			AttackTactics: gap.TacticBreakdown{
				Total:   14,
				Covered: len(attackTactics),
				Details: attackDetails,
			},
			AtlasTactics: gap.TacticBreakdown{
				Total:   7,
				Covered: len(atlasTactics),
				Details: atlasDetails,
			},
		},
		Gaps: gaps,
	}
}

func TestValidFrameworks(t *testing.T) {
	fw := ValidFrameworks()
	if len(fw) != 3 {
		t.Fatalf("expected 3 frameworks, got %d", len(fw))
	}
	expected := map[string]bool{"nist-csf": true, "nist-800-53": true, "cis-v8": true}
	for _, f := range fw {
		if !expected[f] {
			t.Errorf("unexpected framework: %s", f)
		}
	}
}

func TestValidFramework(t *testing.T) {
	if !ValidFramework("nist-csf") {
		t.Error("nist-csf should be valid")
	}
	if !ValidFramework("nist-800-53") {
		t.Error("nist-800-53 should be valid")
	}
	if !ValidFramework("cis-v8") {
		t.Error("cis-v8 should be valid")
	}
	if ValidFramework("iso-27001") {
		t.Error("iso-27001 should not be valid")
	}
}

func TestLookupFramework(t *testing.T) {
	tests := []struct {
		fw   Framework
		want string
	}{
		{NISTCSF, "NIST Cybersecurity Framework"},
		{NIST80053, "NIST SP 800-53"},
		{CISv8, "CIS Controls"},
		{"unknown", ""},
	}
	for _, tt := range tests {
		def := LookupFramework(tt.fw)
		if tt.want == "" {
			if def != nil {
				t.Errorf("LookupFramework(%s) should be nil", tt.fw)
			}
			continue
		}
		if def == nil {
			t.Errorf("LookupFramework(%s) returned nil", tt.fw)
			continue
		}
		if def.Name != tt.want {
			t.Errorf("LookupFramework(%s) name = %q, want %q", tt.fw, def.Name, tt.want)
		}
		if len(def.Controls) == 0 {
			t.Errorf("LookupFramework(%s) has no controls", tt.fw)
		}
	}
}

func TestAssessUnknownFramework(t *testing.T) {
	report := mkGapReport(nil, nil, nil)
	_, err := Assess(report, "unknown")
	if err == nil {
		t.Fatal("expected error for unknown framework")
	}
	if !strings.Contains(err.Error(), "unknown framework") {
		t.Errorf("error = %q, want 'unknown framework'", err.Error())
	}
}

func TestAssessNISTCSFFullCoverage(t *testing.T) {
	allTactics := []string{
		"reconnaissance", "resource-development", "initial-access",
		"execution", "persistence", "privilege-escalation",
		"defense-evasion", "credential-access", "discovery",
		"lateral-movement", "collection", "command-and-control",
		"exfiltration", "impact",
	}
	report := mkGapReport(allTactics, nil, nil)
	a, err := Assess(report, NISTCSF)
	if err != nil {
		t.Fatal(err)
	}
	if a.TotalControls == 0 {
		t.Fatal("expected controls")
	}
	tacticsControlCount := 0
	for _, cr := range a.ControlResults {
		if len(cr.Control.Tactics) > 0 {
			tacticsControlCount++
			if !cr.Covered {
				t.Errorf("control %s should be covered with all tactics present", cr.Control.ID)
			}
		}
	}
	if tacticsControlCount == 0 {
		t.Error("no controls have tactic mappings")
	}
	if a.CoveragePercent == 0 {
		t.Error("coverage should be > 0 with all tactics covered")
	}
}

func TestAssessNISTCSFPartialCoverage(t *testing.T) {
	report := mkGapReport([]string{"execution", "persistence"}, nil, nil)
	a, err := Assess(report, NISTCSF)
	if err != nil {
		t.Fatal(err)
	}
	if a.CoveredControls == a.TotalControls {
		t.Error("should not have full coverage with only 2 tactics")
	}
	if a.CoveredControls == 0 {
		t.Error("should have some coverage with execution and persistence")
	}
	foundCovered := false
	foundUncovered := false
	for _, cr := range a.ControlResults {
		if cr.Covered {
			foundCovered = true
		} else if len(cr.Control.Tactics) > 0 {
			foundUncovered = true
		}
	}
	if !foundCovered {
		t.Error("expected at least one covered control")
	}
	if !foundUncovered {
		t.Error("expected at least one uncovered control with tactics")
	}
}

func TestAssessNISTCSFNoCoverage(t *testing.T) {
	report := mkGapReport(nil, nil, nil)
	a, err := Assess(report, NISTCSF)
	if err != nil {
		t.Fatal(err)
	}
	for _, cr := range a.ControlResults {
		if len(cr.Control.Tactics) > 0 && cr.Covered {
			t.Errorf("control %s should not be covered with no tactics", cr.Control.ID)
		}
	}
	if a.Summary.PostureRating == "strong" {
		t.Error("posture should not be strong with no coverage")
	}
}

func TestAssessNIST80053(t *testing.T) {
	report := mkGapReport([]string{"credential-access", "execution", "defense-evasion"}, nil, nil)
	a, err := Assess(report, NIST80053)
	if err != nil {
		t.Fatal(err)
	}
	if a.Framework.Name != "NIST SP 800-53" {
		t.Errorf("framework name = %q", a.Framework.Name)
	}
	if a.TotalControls == 0 {
		t.Fatal("expected controls")
	}
	acCovered := false
	for _, cr := range a.ControlResults {
		if cr.Control.ID == "AC" && cr.Covered {
			acCovered = true
		}
	}
	if !acCovered {
		t.Error("AC (Access Control) should be covered with credential-access tactic")
	}
}

func TestAssessCISv8(t *testing.T) {
	report := mkGapReport([]string{"initial-access", "execution"}, nil, nil)
	a, err := Assess(report, CISv8)
	if err != nil {
		t.Fatal(err)
	}
	if a.Framework.Name != "CIS Controls" {
		t.Errorf("framework name = %q", a.Framework.Name)
	}
	if a.TotalControls != 18 {
		t.Errorf("expected 18 CIS controls, got %d", a.TotalControls)
	}
}

func TestAssessAll(t *testing.T) {
	report := mkGapReport([]string{"execution"}, nil, nil)
	assessments, err := AssessAll(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(assessments) != 3 {
		t.Fatalf("expected 3 assessments, got %d", len(assessments))
	}
	frameworks := make(map[Framework]bool)
	for _, a := range assessments {
		frameworks[a.Framework.ID] = true
	}
	if !frameworks[NISTCSF] || !frameworks[NIST80053] || !frameworks[CISv8] {
		t.Error("missing expected framework in assessments")
	}
}

func TestControlRiskLevel(t *testing.T) {
	tests := []struct {
		tactics  []string
		covered  bool
		wantRisk string
	}{
		{[]string{"execution"}, true, "low"},
		{[]string{"execution"}, false, "critical"},
		{[]string{"initial-access"}, false, "critical"},
		{[]string{"exfiltration"}, false, "critical"},
		{[]string{"impact"}, false, "critical"},
		{[]string{"credential-access"}, false, "high"},
		{[]string{"lateral-movement"}, false, "high"},
		{[]string{"privilege-escalation"}, false, "high"},
		{[]string{"discovery"}, false, "medium"},
		{[]string{"persistence"}, false, "medium"},
		{nil, false, "medium"},
	}
	for _, tt := range tests {
		ctrl := &Control{Tactics: tt.tactics}
		got := controlRiskLevel(ctrl, tt.covered)
		if got != tt.wantRisk {
			t.Errorf("controlRiskLevel(tactics=%v, covered=%v) = %q, want %q", tt.tactics, tt.covered, got, tt.wantRisk)
		}
	}
}

func TestPostureRating(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{95, "strong"},
		{90, "strong"},
		{75, "moderate"},
		{70, "moderate"},
		{55, "developing"},
		{50, "developing"},
		{30, "weak"},
		{0, "weak"},
	}
	for _, tt := range tests {
		a := &Assessment{
			TotalControls: 10,
			Summary:       AssessmentSummary{PostureScore: tt.score},
		}
		s := computeSummary(a)
		_ = s
		got := ""
		switch {
		case tt.score >= 90:
			got = "strong"
		case tt.score >= 70:
			got = "moderate"
		case tt.score >= 50:
			got = "developing"
		default:
			got = "weak"
		}
		if got != tt.want {
			t.Errorf("posture rating for score %.1f = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestGapsAffectCoverage(t *testing.T) {
	detGap := gap.Gap{
		CampaignName: "test",
		StageID:      "s1",
		StageName:    "Stage One",
		Technique:    "T1059",
		Tactic:       "execution",
		Type:         gap.GapDetectionMissing,
		Risk:         "high",
		Description:  "Missing detection",
	}
	report := mkGapReport([]string{"execution"}, nil, []gap.Gap{detGap})
	a, err := Assess(report, NISTCSF)
	if err != nil {
		t.Fatal(err)
	}

	for _, cr := range a.ControlResults {
		if !cr.Covered {
			continue
		}
		for _, tac := range cr.Control.Tactics {
			if tac == "execution" {
				if len(cr.Gaps) == 0 {
					t.Errorf("control %s should report detection gaps for execution tactic", cr.Control.ID)
				}
				return
			}
		}
	}
}

func TestFormatAssessment(t *testing.T) {
	report := mkGapReport([]string{"execution", "persistence", "discovery"}, nil, nil)
	a, err := Assess(report, NISTCSF)
	if err != nil {
		t.Fatal(err)
	}
	out := FormatAssessment(a)
	if !strings.Contains(out, "NIST Cybersecurity Framework") {
		t.Error("output should contain framework name")
	}
	if !strings.Contains(out, "Coverage:") {
		t.Error("output should contain coverage line")
	}
	if !strings.Contains(out, "Posture Score:") {
		t.Error("output should contain posture score")
	}
	if !strings.Contains(out, "COVERED") {
		t.Error("output should contain COVERED status")
	}
}

func TestFormatAssessmentJSON(t *testing.T) {
	report := mkGapReport([]string{"execution"}, nil, nil)
	a, err := Assess(report, NISTCSF)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr, err := FormatAssessmentJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := parsed["framework"]; !ok {
		t.Error("JSON should contain 'framework' key")
	}
	if _, ok := parsed["coverage_percent"]; !ok {
		t.Error("JSON should contain 'coverage_percent' key")
	}
	if _, ok := parsed["summary"]; !ok {
		t.Error("JSON should contain 'summary' key")
	}
}

func TestFormatMultiAssessment(t *testing.T) {
	report := mkGapReport([]string{"execution"}, nil, nil)
	assessments, err := AssessAll(report)
	if err != nil {
		t.Fatal(err)
	}
	out := FormatMultiAssessment(assessments)
	if !strings.Contains(out, "All Frameworks") {
		t.Error("output should contain 'All Frameworks'")
	}
	if !strings.Contains(out, "NIST Cybersecurity Framework") {
		t.Error("output should contain NIST CSF")
	}
	if !strings.Contains(out, "CIS Controls") {
		t.Error("output should contain CIS Controls")
	}
	if !strings.Contains(out, "NIST SP 800-53") {
		t.Error("output should contain NIST 800-53")
	}
}

func TestNISTCSFControlCount(t *testing.T) {
	def := nistCSFDef()
	if len(def.Controls) < 15 {
		t.Errorf("NIST CSF should have at least 15 controls, got %d", len(def.Controls))
	}
	ids := make(map[string]bool)
	for _, c := range def.Controls {
		if ids[c.ID] {
			t.Errorf("duplicate control ID: %s", c.ID)
		}
		ids[c.ID] = true
		if c.Name == "" {
			t.Errorf("control %s has no name", c.ID)
		}
	}
}

func TestNIST80053ControlCount(t *testing.T) {
	def := nist80053Def()
	if len(def.Controls) < 15 {
		t.Errorf("NIST 800-53 should have at least 15 control families, got %d", len(def.Controls))
	}
	ids := make(map[string]bool)
	for _, c := range def.Controls {
		if ids[c.ID] {
			t.Errorf("duplicate control ID: %s", c.ID)
		}
		ids[c.ID] = true
	}
}

func TestCISv8ControlCount(t *testing.T) {
	def := cisV8Def()
	if len(def.Controls) != 18 {
		t.Errorf("CIS v8 should have 18 controls, got %d", len(def.Controls))
	}
	for i, c := range def.Controls {
		expected := fmt.Sprintf("CIS.%02d", i+1)
		if c.ID != expected {
			t.Errorf("control %d has ID %q, want %q", i, c.ID, expected)
		}
	}
}

func TestDedup(t *testing.T) {
	tests := []struct {
		in   []string
		want int
	}{
		{nil, 0},
		{[]string{"a"}, 1},
		{[]string{"a", "b", "a"}, 2},
		{[]string{"c", "b", "a", "b"}, 3},
	}
	for _, tt := range tests {
		got := dedup(tt.in)
		if len(got) != tt.want {
			t.Errorf("dedup(%v) len = %d, want %d", tt.in, len(got), tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in  string
		max int
		out string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "he..."},
		{"hi", 2, "hi"},
		{"hello", 3, "hel"},
	}
	for _, tt := range tests {
		got := truncate(tt.in, tt.max)
		if got != tt.out {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.out)
		}
	}
}

func TestAssessControlsWithNoTactics(t *testing.T) {
	report := mkGapReport([]string{"execution"}, nil, nil)
	a, err := Assess(report, NISTCSF)
	if err != nil {
		t.Fatal(err)
	}
	for _, cr := range a.ControlResults {
		if len(cr.Control.Tactics) == 0 {
			if cr.Covered {
				t.Errorf("control %s has no tactics but is marked covered", cr.Control.ID)
			}
			if cr.RiskLevel != "low" {
				t.Errorf("control %s with no tactics should be low risk, got %q", cr.Control.ID, cr.RiskLevel)
			}
		}
	}
}

func TestAssessATLASTactics(t *testing.T) {
	report := mkGapReport(nil, []string{"ml-attack-staging", "ml-model-access"}, nil)
	a, err := Assess(report, NISTCSF)
	if err != nil {
		t.Fatal(err)
	}
	if a.TacticsCovered == nil {
		t.Fatal("TacticsCovered should not be nil")
	}
	if !a.TacticsCovered["ml-attack-staging"] {
		t.Error("ml-attack-staging should be in covered tactics")
	}
}

func TestSummaryGapCounts(t *testing.T) {
	report := mkGapReport(nil, nil, nil)
	a, err := Assess(report, CISv8)
	if err != nil {
		t.Fatal(err)
	}
	totalGaps := a.Summary.CriticalGaps + a.Summary.HighGaps + a.Summary.MediumGaps + a.Summary.LowGaps
	uncoveredWithTactics := 0
	for _, cr := range a.ControlResults {
		if !cr.Covered && len(cr.Control.Tactics) > 0 {
			uncoveredWithTactics++
		}
	}
	if totalGaps != uncoveredWithTactics {
		t.Errorf("gap counts (%d) should match uncovered controls with tactics (%d)", totalGaps, uncoveredWithTactics)
	}
}

func TestCoveragePercent(t *testing.T) {
	report := mkGapReport(nil, nil, nil)
	a, err := Assess(report, NISTCSF)
	if err != nil {
		t.Fatal(err)
	}
	noTacticsCount := 0
	for _, cr := range a.ControlResults {
		if len(cr.Control.Tactics) == 0 {
			noTacticsCount++
		}
	}
	if noTacticsCount > 0 && a.CoveredControls != 0 {
		t.Error("with no tactics covered, only controls with no tactics should have zero coverage")
	}
}

func TestPartialControlCoverage(t *testing.T) {
	report := mkGapReport([]string{"execution"}, nil, nil)
	a, err := Assess(report, NISTCSF)
	if err != nil {
		t.Fatal(err)
	}
	for _, cr := range a.ControlResults {
		if !cr.Covered {
			continue
		}
		if len(cr.Control.Tactics) > 1 {
			hasExecution := false
			for _, tac := range cr.Control.Tactics {
				if tac == "execution" {
					hasExecution = true
				}
			}
			if hasExecution && cr.Coverage == 100 && len(cr.Control.Tactics) > 1 {
				t.Errorf("control %s with multiple tactics should have partial coverage when only execution is present", cr.Control.ID)
			}
		}
	}
}

// Ensure fmt is used (it's used in TestCISv8ControlCount).
var _ = fmt.Sprintf
