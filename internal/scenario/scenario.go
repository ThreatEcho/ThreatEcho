// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package scenario implements scenarios: reusable test cases that bind a
// campaign to a policy and define expected outcomes. A scenario is the
// atomic unit of detection engineering testing — like a unit test for
// security — evaluated against the output of policy.SimulatePolicy.
package scenario

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// Outcome values used in expectations and results.
const (
	OutcomeBlocked = "blocked"
	OutcomeAllowed = "allowed"
	OutcomeAlerted = "alerted"
	OutcomeAny     = "any"
)

// Precondition type values.
const (
	PreconditionPolicyExists   = "policy_exists"
	PreconditionCampaignExists = "campaign_exists"
)

// Scenario is a reusable test case binding a campaign to a policy with
// expected outcomes and pass criteria.
type Scenario struct {
	APIVersion    string             `yaml:"api_version"`
	Kind          string             `yaml:"kind"`
	Meta          ScenarioMeta       `yaml:"meta"`
	Campaign      string             `yaml:"campaign"`
	Policy        string             `yaml:"policy"`
	Expectations  []StageExpectation `yaml:"expectations,omitempty"`
	Preconditions []Precondition     `yaml:"preconditions,omitempty"`
	PassCriteria  PassCriteria       `yaml:"pass_criteria,omitempty"`
}

// ScenarioMeta holds scenario metadata.
type ScenarioMeta struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Author      string   `yaml:"author,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Severity    string   `yaml:"severity,omitempty"` // critical, high, medium, low, info
}

// StageExpectation declares the expected outcome for a single campaign stage.
type StageExpectation struct {
	Stage        string   `yaml:"stage"`
	Outcome      string   `yaml:"outcome"` // blocked, allowed, alerted, any
	ToolsDenied  []string `yaml:"tools_denied,omitempty"`
	ToolsAllowed []string `yaml:"tools_allowed,omitempty"`
}

// Precondition is a fact that must hold for a scenario to be runnable.
type Precondition struct {
	Type  string `yaml:"type"` // policy_exists, campaign_exists
	Value string `yaml:"value"`
}

// PassCriteria defines the thresholds a ScenarioResult must clear to pass.
// Every field is optional; only criteria that are explicitly set are
// enforced. MaxAllowed uses a pointer so an explicit 0 (no stage may be
// allowed) can be distinguished from "not set" (no limit).
type PassCriteria struct {
	MinBlockedRatio        float64 `yaml:"min_blocked_ratio,omitempty"`
	MaxAllowed             *int    `yaml:"max_allowed,omitempty"`
	RequireAllExpectations bool    `yaml:"require_all_expectations,omitempty"`
}

// ScenarioResult is the outcome of evaluating a scenario against a
// simulation report.
type ScenarioResult struct {
	Scenario     string        `json:"scenario"`
	Campaign     string        `json:"campaign"`
	Policy       string        `json:"policy"`
	Passed       bool          `json:"passed"`
	Stages       []StageResult `json:"stages"`
	TotalStages  int           `json:"total_stages"`
	BlockedCount int           `json:"blocked_count"`
	AllowedCount int           `json:"allowed_count"`
	AlertedCount int           `json:"alerted_count"`
	BlockedRatio float64       `json:"blocked_ratio"`

	ExpectationsTotal   int `json:"expectations_total"`
	ExpectationsMatched int `json:"expectations_matched"`

	Reasons []string `json:"reasons,omitempty"` // why the scenario passed/failed
}

// StageResult is the per-stage detail of a scenario evaluation.
type StageResult struct {
	StageID         string   `json:"stage_id"`
	ActualOutcome   string   `json:"actual_outcome"`             // blocked, allowed, alerted
	ExpectedOutcome string   `json:"expected_outcome,omitempty"` // "" if no explicit expectation
	Matched         bool     `json:"matched"`
	ToolsDenied     []string `json:"tools_denied,omitempty"`
	ToolsAllowed    []string `json:"tools_allowed,omitempty"`
	ToolsAlerted    []string `json:"tools_alerted,omitempty"`
	Details         string   `json:"details,omitempty"`
}

// ScenarioSummary is a compact view of a scenario for directory listings.
type ScenarioSummary struct {
	Name        string
	Description string
	Campaign    string
	Policy      string
	Tags        []string
	Severity    string
	Path        string
}

// Load reads and parses a scenario from a YAML file or directory.
// If path is a directory, it looks for scenario.yaml inside it.
func Load(path string) (*Scenario, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("scenario path %q: %w", path, err)
	}
	if info.IsDir() {
		path = filepath.Join(path, "scenario.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scenario: %w", err)
	}

	var s Scenario
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing scenario YAML: %w", err)
	}

	if errs := Validate(&s); len(errs) > 0 {
		return &s, fmt.Errorf("invalid scenario: %s", strings.Join(errs, "; "))
	}

	return &s, nil
}

// LoadDir scans a directory for scenario subdirectories (each containing
// scenario.yaml) and returns metadata for each found scenario. Entries
// that fail to load or validate are skipped.
func LoadDir(dir string) ([]ScenarioSummary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading scenarios directory: %w", err)
	}

	var summaries []ScenarioSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		spath := filepath.Join(dir, e.Name(), "scenario.yaml")
		if _, err := os.Stat(spath); err != nil {
			continue
		}
		s, err := Load(spath)
		if err != nil {
			continue
		}
		summaries = append(summaries, ScenarioSummary{
			Name:        s.Meta.Name,
			Description: s.Meta.Description,
			Campaign:    s.Campaign,
			Policy:      s.Policy,
			Tags:        s.Meta.Tags,
			Severity:    s.Meta.Severity,
			Path:        filepath.Join(dir, e.Name()),
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Name < summaries[j].Name
	})

	return summaries, nil
}

var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
}

var validOutcomes = map[string]bool{
	OutcomeBlocked: true,
	OutcomeAllowed: true,
	OutcomeAlerted: true,
	OutcomeAny:     true,
}

var validPreconditionTypes = map[string]bool{
	PreconditionPolicyExists:   true,
	PreconditionCampaignExists: true,
}

// Validate checks a scenario for structural and semantic errors.
// Returns a slice of issues; empty means valid.
func Validate(s *Scenario) []string {
	var errs []string

	if s == nil {
		return []string{"scenario is nil"}
	}

	if s.APIVersion == "" {
		errs = append(errs, "missing api_version")
	}
	if s.Kind == "" {
		errs = append(errs, "missing kind")
	} else if s.Kind != "Scenario" {
		errs = append(errs, fmt.Sprintf("kind must be \"Scenario\", got %q", s.Kind))
	}

	if s.Meta.Name == "" {
		errs = append(errs, "meta.name is required")
	}
	if s.Meta.Severity != "" && !validSeverities[s.Meta.Severity] {
		errs = append(errs, fmt.Sprintf("meta.severity %q is not valid (use critical/high/medium/low/info)", s.Meta.Severity))
	}

	if s.Campaign == "" {
		errs = append(errs, "campaign is required")
	}
	if s.Policy == "" {
		errs = append(errs, "policy is required")
	}

	seenStages := make(map[string]int)
	for i, exp := range s.Expectations {
		prefix := fmt.Sprintf("expectations[%d]", i)
		if exp.Stage == "" {
			errs = append(errs, fmt.Sprintf("%s: stage is required", prefix))
		} else {
			if prev, dup := seenStages[exp.Stage]; dup {
				errs = append(errs, fmt.Sprintf("%s: duplicate expectation for stage %q (first at expectations[%d])", prefix, exp.Stage, prev))
			}
			seenStages[exp.Stage] = i
		}
		if exp.Outcome == "" {
			errs = append(errs, fmt.Sprintf("%s: outcome is required", prefix))
		} else if !validOutcomes[exp.Outcome] {
			errs = append(errs, fmt.Sprintf("%s: outcome %q is not valid (use blocked/allowed/alerted/any)", prefix, exp.Outcome))
		}
	}

	for i, pc := range s.Preconditions {
		prefix := fmt.Sprintf("preconditions[%d]", i)
		if pc.Type == "" {
			errs = append(errs, fmt.Sprintf("%s: type is required", prefix))
		} else if !validPreconditionTypes[pc.Type] {
			errs = append(errs, fmt.Sprintf("%s: type %q is not valid (use policy_exists/campaign_exists)", prefix, pc.Type))
		}
		if pc.Value == "" {
			errs = append(errs, fmt.Sprintf("%s: value is required", prefix))
		}
	}

	if s.PassCriteria.MinBlockedRatio < 0 || s.PassCriteria.MinBlockedRatio > 1 {
		errs = append(errs, fmt.Sprintf("pass_criteria.min_blocked_ratio %.2f must be between 0 and 1", s.PassCriteria.MinBlockedRatio))
	}
	if s.PassCriteria.MaxAllowed != nil && *s.PassCriteria.MaxAllowed < 0 {
		errs = append(errs, fmt.Sprintf("pass_criteria.max_allowed %d must be >= 0", *s.PassCriteria.MaxAllowed))
	}

	return errs
}

// Evaluate checks a scenario's expectations and pass criteria against a
// policy simulation report. simReport is expected to have been produced by
// running the scenario's campaign against the scenario's policy (via
// policy.SimulatePolicy), though Evaluate does not itself enforce that the
// names match — callers that care should check simReport.Campaign /
// simReport.Policy against s.Campaign / s.Policy first.
func Evaluate(s *Scenario, simReport *policy.SimulationReport) *ScenarioResult {
	result := &ScenarioResult{}

	if s == nil {
		result.Reasons = append(result.Reasons, "no scenario provided")
		return result
	}

	result.Scenario = s.Meta.Name
	result.Campaign = s.Campaign
	result.Policy = s.Policy

	if simReport == nil {
		result.Reasons = append(result.Reasons, "no simulation report provided")
		return result
	}

	expByStage := make(map[string]StageExpectation, len(s.Expectations))
	for _, exp := range s.Expectations {
		expByStage[exp.Stage] = exp
	}

	result.TotalStages = len(simReport.Stages)

	for _, stage := range simReport.Stages {
		sr := StageResult{
			StageID:       stage.StageID,
			ActualOutcome: stageOutcome(stage),
		}

		for _, d := range stage.Decisions {
			switch d.Effect {
			case "deny":
				sr.ToolsDenied = append(sr.ToolsDenied, d.Tool)
			case "allow":
				sr.ToolsAllowed = append(sr.ToolsAllowed, d.Tool)
			case "alert":
				sr.ToolsAlerted = append(sr.ToolsAlerted, d.Tool)
			}
		}

		switch sr.ActualOutcome {
		case OutcomeBlocked:
			result.BlockedCount++
		case OutcomeAllowed:
			result.AllowedCount++
		case OutcomeAlerted:
			result.AlertedCount++
		}

		if exp, ok := expByStage[stage.StageID]; ok {
			sr.ExpectedOutcome = exp.Outcome
			sr.Matched = matchesExpectation(exp, sr)
			if sr.Matched {
				sr.Details = "expectation matched"
			} else {
				sr.Details = fmt.Sprintf("expected %s, got %s", describeExpectation(exp), sr.ActualOutcome)
			}
			result.ExpectationsTotal++
			if sr.Matched {
				result.ExpectationsMatched++
			}
		} else {
			// No explicit expectation for this stage — trivially satisfied.
			sr.Matched = true
			sr.Details = "no explicit expectation"
		}

		result.Stages = append(result.Stages, sr)
	}

	if result.TotalStages > 0 {
		result.BlockedRatio = float64(result.BlockedCount) / float64(result.TotalStages)
	}

	result.Passed = true

	if s.PassCriteria.MinBlockedRatio > 0 && result.BlockedRatio < s.PassCriteria.MinBlockedRatio {
		result.Passed = false
		result.Reasons = append(result.Reasons, fmt.Sprintf(
			"blocked ratio %.2f is below min_blocked_ratio %.2f", result.BlockedRatio, s.PassCriteria.MinBlockedRatio))
	}

	if s.PassCriteria.MaxAllowed != nil && result.AllowedCount > *s.PassCriteria.MaxAllowed {
		result.Passed = false
		result.Reasons = append(result.Reasons, fmt.Sprintf(
			"allowed count %d exceeds max_allowed %d", result.AllowedCount, *s.PassCriteria.MaxAllowed))
	}

	if s.PassCriteria.RequireAllExpectations && result.ExpectationsTotal > 0 && result.ExpectationsMatched < result.ExpectationsTotal {
		result.Passed = false
		result.Reasons = append(result.Reasons, fmt.Sprintf(
			"only %d/%d explicit expectations matched", result.ExpectationsMatched, result.ExpectationsTotal))
	}

	if len(result.Reasons) == 0 {
		result.Reasons = append(result.Reasons, "all configured pass criteria satisfied")
	}

	return result
}

// stageOutcome derives a single outcome label for a stage from its
// aggregated decision counts. deny takes precedence over alert, which
// takes precedence over allow — the most restrictive decision made for
// any tool in the stage determines the stage's outcome.
func stageOutcome(stage policy.StageSimResult) string {
	switch {
	case stage.Denied > 0:
		return OutcomeBlocked
	case stage.Alerted > 0:
		return OutcomeAlerted
	default:
		return OutcomeAllowed
	}
}

// matchesExpectation checks whether a stage result satisfies an explicit
// stage expectation: the outcome (or "any"), plus any required
// tools_denied / tools_allowed subsets.
func matchesExpectation(exp StageExpectation, sr StageResult) bool {
	if exp.Outcome != OutcomeAny && exp.Outcome != sr.ActualOutcome {
		return false
	}
	if !containsAll(sr.ToolsDenied, exp.ToolsDenied) {
		return false
	}
	if !containsAll(sr.ToolsAllowed, exp.ToolsAllowed) {
		return false
	}
	return true
}

// containsAll reports whether every element of want is present in have.
func containsAll(have, want []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func describeExpectation(exp StageExpectation) string {
	parts := []string{exp.Outcome}
	if len(exp.ToolsDenied) > 0 {
		parts = append(parts, fmt.Sprintf("tools_denied=%s", strings.Join(exp.ToolsDenied, ",")))
	}
	if len(exp.ToolsAllowed) > 0 {
		parts = append(parts, fmt.Sprintf("tools_allowed=%s", strings.Join(exp.ToolsAllowed, ",")))
	}
	return strings.Join(parts, " ")
}

// FormatResult renders a box-drawing formatted text report for a scenario result.
func FormatResult(r *ScenarioResult) string {
	var b strings.Builder

	if r == nil {
		return "(no scenario result)\n"
	}

	b.WriteString("┌─────────────────────────────────────────────────────────────┐\n")
	b.WriteString("│ Scenario Result                                              │\n")
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	writePaddedLine(&b, fmt.Sprintf("Scenario: %s", r.Scenario))
	writePaddedLine(&b, fmt.Sprintf("Campaign: %s", r.Campaign))
	writePaddedLine(&b, fmt.Sprintf("Policy:   %s", r.Policy))
	status := "FAIL"
	if r.Passed {
		status = "PASS"
	}
	writePaddedLine(&b, fmt.Sprintf("Result:   %s", status))
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")

	for _, stage := range r.Stages {
		icon := "✓"
		if !stage.Matched {
			icon = "✗"
		}
		writePaddedLine(&b, fmt.Sprintf("%s %s → %s", icon, stage.StageID, stage.ActualOutcome))
		if stage.ExpectedOutcome != "" {
			writePaddedLine(&b, fmt.Sprintf("    expected: %s", stage.ExpectedOutcome))
		}
		if stage.Details != "" {
			writePaddedLine(&b, fmt.Sprintf("    %s", stage.Details))
		}
	}

	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	writePaddedLine(&b, fmt.Sprintf("Stages: %d total, %d blocked, %d allowed, %d alerted",
		r.TotalStages, r.BlockedCount, r.AllowedCount, r.AlertedCount))
	writePaddedLine(&b, fmt.Sprintf("Blocked ratio: %.0f%%", r.BlockedRatio*100))
	writePaddedLine(&b, fmt.Sprintf("Expectations: %d/%d matched", r.ExpectationsMatched, r.ExpectationsTotal))
	for _, reason := range r.Reasons {
		writePaddedLine(&b, fmt.Sprintf("Reason: %s", reason))
	}
	b.WriteString("└─────────────────────────────────────────────────────────────┘\n")

	return b.String()
}

// FormatSummaryTable renders a box-drawing table of scenario summaries,
// suitable for `scenario list`-style output.
func FormatSummaryTable(summaries []ScenarioSummary) string {
	var b strings.Builder

	if len(summaries) == 0 {
		b.WriteString("┌─────────────────────────────────────────────────────────────┐\n")
		b.WriteString("│ No scenarios found                                           │\n")
		b.WriteString("└─────────────────────────────────────────────────────────────┘\n")
		return b.String()
	}

	b.WriteString("┌─────────────────────────────────────────────────────────────┐\n")
	b.WriteString("│ Scenarios                                                    │\n")
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")

	for _, s := range summaries {
		writePaddedLine(&b, fmt.Sprintf("%s", s.Name))
		writePaddedLine(&b, fmt.Sprintf("  campaign: %s  policy: %s", s.Campaign, s.Policy))
		if s.Severity != "" {
			writePaddedLine(&b, fmt.Sprintf("  severity: %s", s.Severity))
		}
		if len(s.Tags) > 0 {
			writePaddedLine(&b, fmt.Sprintf("  tags: %s", strings.Join(s.Tags, ", ")))
		}
		if s.Description != "" {
			writePaddedLine(&b, fmt.Sprintf("  %s", s.Description))
		}
		b.WriteString("│                                                             │\n")
	}

	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	writePaddedLine(&b, fmt.Sprintf("Total: %d scenario(s)", len(summaries)))
	b.WriteString("└─────────────────────────────────────────────────────────────┘\n")

	return b.String()
}

// writePaddedLine writes a box-drawing line padded to fill the box width.
func writePaddedLine(b *strings.Builder, content string) {
	const width = 59
	line := content
	if len(line) > width {
		line = line[:width]
	}
	fmt.Fprintf(b, "│ %-*s │\n", width, line)
}
