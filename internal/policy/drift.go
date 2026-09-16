// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Drift severity and type enums
// ---------------------------------------------------------------------------

// DriftSeverity classifies how impactful a drift is.
type DriftSeverity string

const (
	DriftCritical DriftSeverity = "critical" // security posture weakened significantly
	DriftHigh     DriftSeverity = "high"     // meaningful security change
	DriftMedium   DriftSeverity = "medium"   // notable change, review recommended
	DriftLow      DriftSeverity = "low"      // minor change, low risk
	DriftInfo     DriftSeverity = "info"     // informational, no security impact
)

// DriftType classifies what kind of change occurred.
type DriftType string

const (
	DriftRuleAdded        DriftType = "rule_added"        // new rule introduced
	DriftRuleRemoved      DriftType = "rule_removed"      // existing rule deleted
	DriftRuleModified     DriftType = "rule_modified"     // rule changed in a non-specific way
	DriftEffectChanged    DriftType = "effect_changed"    // allow→deny, deny→allow etc.
	DriftScopeWidened     DriftType = "scope_widened"     // tool pattern became broader
	DriftScopeNarrowed    DriftType = "scope_narrowed"    // tool pattern became tighter
	DriftPriorityShift    DriftType = "priority_shift"    // rule priority changed
	DriftConditionChanged DriftType = "condition_changed" // conditions added/removed
	DriftMetaChanged      DriftType = "meta_changed"      // name, description, authors
)

// ---------------------------------------------------------------------------
// Drift finding and report types
// ---------------------------------------------------------------------------

// DriftFinding records a single detected drift.
type DriftFinding struct {
	Type        DriftType     `json:"type"`
	Severity    DriftSeverity `json:"severity"`
	RuleID      string        `json:"rule_id,omitempty"`
	Description string        `json:"description"`
	Before      string        `json:"before,omitempty"`
	After       string        `json:"after,omitempty"`
	Impact      string        `json:"impact"`
}

// DriftReport aggregates all drift findings between baseline and current.
type DriftReport struct {
	BaselinePolicy string         `json:"baseline_policy"`
	CurrentPolicy  string         `json:"current_policy"`
	BaselineRules  int            `json:"baseline_rules"`
	CurrentRules   int            `json:"current_rules"`
	Findings       []DriftFinding `json:"findings"`
	CriticalCount  int            `json:"critical_count"`
	HighCount      int            `json:"high_count"`
	MediumCount    int            `json:"medium_count"`
	LowCount       int            `json:"low_count"`
	InfoCount      int            `json:"info_count"`
	DriftScore     float64        `json:"drift_score"`
	Summary        string         `json:"summary"`
}

// ---------------------------------------------------------------------------
// Drift score weights per severity
// ---------------------------------------------------------------------------

var driftScoreWeights = map[DriftSeverity]float64{
	DriftCritical: 0.25,
	DriftHigh:     0.15,
	DriftMedium:   0.08,
	DriftLow:      0.03,
	DriftInfo:     0.01,
}

// ---------------------------------------------------------------------------
// DetectDrift — main entry point
// ---------------------------------------------------------------------------

// DetectDrift compares a baseline policy against a current policy and returns
// a report of all semantic differences. It goes beyond textual diff by
// analysing effect changes, scope widening/narrowing, priority shifts, and
// condition mutations.
func DetectDrift(baseline, current *Policy) *DriftReport {
	report := &DriftReport{}

	if baseline == nil {
		baseline = &Policy{}
	}
	if current == nil {
		current = &Policy{}
	}

	report.BaselinePolicy = baseline.Meta.Name
	report.CurrentPolicy = current.Meta.Name
	report.BaselineRules = len(baseline.Rules)
	report.CurrentRules = len(current.Rules)

	// 1. Compare meta fields.
	detectMetaDrift(baseline, current, report)

	// 2. Index rules by ID.
	baseByID := indexRules(baseline.Rules)
	currByID := indexRules(current.Rules)

	// 3. Removed rules (in baseline, not in current).
	for _, r := range baseline.Rules {
		if _, exists := currByID[r.ID]; !exists {
			f := DriftFinding{
				Type:        DriftRuleRemoved,
				RuleID:      r.ID,
				Description: fmt.Sprintf("Rule %q removed", r.ID),
				Before:      fmt.Sprintf("%s (effect=%s, priority=%d)", r.ID, r.Effect, r.Priority),
				After:       "(absent)",
				Impact:      ruleRemovedImpact(r),
			}
			f.Severity = classifyDrift(f)
			report.Findings = append(report.Findings, f)
		}
	}

	// 4. Added rules (in current, not in baseline).
	for _, r := range current.Rules {
		if _, exists := baseByID[r.ID]; !exists {
			f := DriftFinding{
				Type:        DriftRuleAdded,
				RuleID:      r.ID,
				Description: fmt.Sprintf("Rule %q added", r.ID),
				Before:      "(absent)",
				After:       fmt.Sprintf("%s (effect=%s, priority=%d)", r.ID, r.Effect, r.Priority),
				Impact:      ruleAddedImpact(r),
			}
			f.Severity = classifyDrift(f)
			report.Findings = append(report.Findings, f)
		}
	}

	// 5. Matched rules — deep comparison.
	for _, baseRule := range baseline.Rules {
		currRule, exists := currByID[baseRule.ID]
		if !exists {
			continue
		}
		compareMatchedRules(baseRule, currRule, report)
	}

	// 6. Tally severity counts and compute drift score.
	tallySeverities(report)
	report.DriftScore = scoreDrift(report.Findings)
	report.Summary = SummarizeDrift(report)

	return report
}

// ---------------------------------------------------------------------------
// Meta drift detection
// ---------------------------------------------------------------------------

func detectMetaDrift(baseline, current *Policy, report *DriftReport) {
	if baseline.Meta.Name != current.Meta.Name && (baseline.Meta.Name != "" || current.Meta.Name != "") {
		report.Findings = append(report.Findings, DriftFinding{
			Type:        DriftMetaChanged,
			Severity:    DriftInfo,
			Description: "Policy name changed",
			Before:      baseline.Meta.Name,
			After:       current.Meta.Name,
			Impact:      "Policy identity changed; verify references are updated",
		})
	}
	if baseline.Meta.Description != current.Meta.Description &&
		(baseline.Meta.Description != "" || current.Meta.Description != "") {
		report.Findings = append(report.Findings, DriftFinding{
			Type:        DriftMetaChanged,
			Severity:    DriftInfo,
			Description: "Policy description changed",
			Before:      baseline.Meta.Description,
			After:       current.Meta.Description,
			Impact:      "Informational — description updated",
		})
	}
}

// ---------------------------------------------------------------------------
// Matched-rule comparison
// ---------------------------------------------------------------------------

func compareMatchedRules(baseRule, currRule Rule, report *DriftReport) {
	// Effect change.
	if baseRule.Effect != currRule.Effect {
		f := DriftFinding{
			Type:        DriftEffectChanged,
			RuleID:      baseRule.ID,
			Description: fmt.Sprintf("Rule %q effect changed from %s to %s", baseRule.ID, baseRule.Effect, currRule.Effect),
			Before:      baseRule.Effect,
			After:       currRule.Effect,
			Impact:      effectChangeImpact(baseRule.Effect, currRule.Effect),
		}
		f.Severity = classifyDrift(f)
		report.Findings = append(report.Findings, f)
	}

	// Priority shift.
	if baseRule.Priority != currRule.Priority {
		f := DriftFinding{
			Type:        DriftPriorityShift,
			RuleID:      baseRule.ID,
			Description: fmt.Sprintf("Rule %q priority changed from %d to %d", baseRule.ID, baseRule.Priority, currRule.Priority),
			Before:      fmt.Sprintf("%d", baseRule.Priority),
			After:       fmt.Sprintf("%d", currRule.Priority),
			Impact:      priorityChangeImpact(baseRule, currRule),
		}
		f.Severity = classifyDrift(f)
		report.Findings = append(report.Findings, f)
	}

	// Tool scope comparison.
	if !stringSliceEqual(baseRule.Match.Tools, currRule.Match.Tools) {
		scopeType := compareRuleScope(baseRule, currRule)
		f := DriftFinding{
			Type:        scopeType,
			RuleID:      baseRule.ID,
			Description: fmt.Sprintf("Rule %q tool scope %s", baseRule.ID, scopeType),
			Before:      strings.Join(baseRule.Match.Tools, ", "),
			After:       strings.Join(currRule.Match.Tools, ", "),
			Impact:      scopeChangeImpact(scopeType, baseRule.Effect),
		}
		f.Severity = classifyDrift(f)
		report.Findings = append(report.Findings, f)
	}

	// Tactics change.
	if !stringSliceEqual(baseRule.Match.Tactics, currRule.Match.Tactics) {
		f := DriftFinding{
			Type:        DriftRuleModified,
			RuleID:      baseRule.ID,
			Description: fmt.Sprintf("Rule %q tactics changed", baseRule.ID),
			Before:      strings.Join(baseRule.Match.Tactics, ", "),
			After:       strings.Join(currRule.Match.Tactics, ", "),
			Impact:      "Tactics filter changed; rule may match different attack stages",
		}
		f.Severity = classifyDrift(f)
		report.Findings = append(report.Findings, f)
	}

	// Targets change.
	if !stringSliceEqual(baseRule.Match.Targets, currRule.Match.Targets) {
		f := DriftFinding{
			Type:        DriftRuleModified,
			RuleID:      baseRule.ID,
			Description: fmt.Sprintf("Rule %q targets changed", baseRule.ID),
			Before:      strings.Join(baseRule.Match.Targets, ", "),
			After:       strings.Join(currRule.Match.Targets, ", "),
			Impact:      "Target patterns changed; rule may apply to different endpoints",
		}
		f.Severity = classifyDrift(f)
		report.Findings = append(report.Findings, f)
	}

	// Actions change.
	if !stringSliceEqual(baseRule.Match.Actions, currRule.Match.Actions) {
		f := DriftFinding{
			Type:        DriftRuleModified,
			RuleID:      baseRule.ID,
			Description: fmt.Sprintf("Rule %q actions changed", baseRule.ID),
			Before:      strings.Join(baseRule.Match.Actions, ", "),
			After:       strings.Join(currRule.Match.Actions, ", "),
			Impact:      "Action filter changed; rule may match different operation types",
		}
		f.Severity = classifyDrift(f)
		report.Findings = append(report.Findings, f)
	}

	// Conditions change.
	if !conditionsEqual(baseRule.Conditions, currRule.Conditions) {
		f := DriftFinding{
			Type:        DriftConditionChanged,
			RuleID:      baseRule.ID,
			Description: fmt.Sprintf("Rule %q conditions changed", baseRule.ID),
			Before:      formatConditions(baseRule.Conditions),
			After:       formatConditions(currRule.Conditions),
			Impact:      conditionChangeImpact(baseRule, currRule),
		}
		f.Severity = classifyDrift(f)
		report.Findings = append(report.Findings, f)
	}
}

// ---------------------------------------------------------------------------
// classifyDrift — assigns severity based on drift type and context
// ---------------------------------------------------------------------------

func classifyDrift(f DriftFinding) DriftSeverity {
	switch f.Type {
	case DriftEffectChanged:
		// deny→allow is critical; allow→deny is high; others medium.
		if f.Before == "deny" && f.After == "allow" {
			return DriftCritical
		}
		if f.Before == "allow" && f.After == "deny" {
			return DriftHigh
		}
		// deny→alert or alert→allow etc.
		if f.Before == "deny" {
			return DriftHigh
		}
		return DriftMedium

	case DriftRuleRemoved:
		// Removing a deny rule is critical; removing allow/alert is medium.
		if strings.Contains(f.Before, "effect=deny") {
			return DriftCritical
		}
		return DriftMedium

	case DriftRuleAdded:
		// Adding a deny rule is medium (tightens policy); allow is low.
		if strings.Contains(f.After, "effect=deny") {
			return DriftMedium
		}
		return DriftLow

	case DriftScopeWidened:
		// Wider scope on deny = high (more things blocked);
		// wider scope on allow = low (more things permitted).
		if strings.Contains(f.Impact, "deny") {
			return DriftHigh
		}
		return DriftLow

	case DriftScopeNarrowed:
		// Narrower deny = medium (less protection).
		if strings.Contains(f.Impact, "deny") {
			return DriftMedium
		}
		return DriftLow

	case DriftPriorityShift:
		return DriftMedium

	case DriftConditionChanged:
		return DriftMedium

	case DriftRuleModified:
		return DriftMedium

	case DriftMetaChanged:
		return DriftInfo
	}

	return DriftLow
}

// ---------------------------------------------------------------------------
// compareRuleScope — determine whether tool patterns widened or narrowed
// ---------------------------------------------------------------------------

// compareRuleScope examines the tool patterns on two rules with the same ID
// and determines whether the effective scope widened, narrowed, or was simply
// modified. A pattern is "wider" if it matches everything the other matches
// plus more. When the relationship is ambiguous, DriftRuleModified is returned.
func compareRuleScope(baseline, current Rule) DriftType {
	baseTools := baseline.Match.Tools
	currTools := current.Match.Tools

	// Check if every baseline pattern is covered by some current pattern.
	baselineCovered := allPatternsCovered(baseTools, currTools)
	// Check if every current pattern is covered by some baseline pattern.
	currentCovered := allPatternsCovered(currTools, baseTools)

	switch {
	case baselineCovered && !currentCovered:
		// Current covers everything baseline did and more → widened.
		return DriftScopeWidened
	case !baselineCovered && currentCovered:
		// Current covers less than baseline → narrowed.
		return DriftScopeNarrowed
	case baselineCovered && currentCovered:
		// Equivalent scope — unusual but possible with different patterns.
		return DriftRuleModified
	default:
		// Neither fully covers the other — mixed change.
		return DriftRuleModified
	}
}

// allPatternsCovered returns true if every pattern in "a" is matched by at
// least one pattern in "b" (i.e., b is at least as wide as a for every entry).
func allPatternsCovered(a, b []string) bool {
	for _, pa := range a {
		covered := false
		for _, pb := range b {
			if patternCovers(pb, pa) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// patternCovers returns true if the covering pattern matches everything the
// covered pattern would match. This uses a heuristic: if covering is "*" it
// covers anything; if covering == covered they are identical; if covering is
// a prefix-glob like "file_*" and covered is "file_read", covered is narrower.
// We test by checking if covering matches covered (as a concrete string) via
// GlobMatch, and then checking the reverse.
func patternCovers(covering, covered string) bool {
	if covering == covered {
		return true
	}
	// If covering is "*" it matches everything.
	if covering == "*" {
		return true
	}
	// If covering matches covered as a literal name, covering is at least
	// as wide. This works for "file_*" covering "file_read".
	if GlobMatch(covering, covered) {
		// But also check the reverse: if covered also matches covering,
		// they are equivalent. If not, covering is strictly wider.
		if !GlobMatch(covered, covering) {
			return true
		}
		// Both match each other — equivalent patterns.
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// scoreDrift — compute 0-1 drift score from findings
// ---------------------------------------------------------------------------

func scoreDrift(findings []DriftFinding) float64 {
	score := 0.0
	for _, f := range findings {
		w, ok := driftScoreWeights[f.Severity]
		if !ok {
			w = 0.01
		}
		score += w
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// ---------------------------------------------------------------------------
// FormatDriftReport — box-drawing formatted output
// ---------------------------------------------------------------------------

// FormatDriftReport produces a human-readable box-drawing report following the
// style established by FormatBenchmarkReport.
func FormatDriftReport(r *DriftReport) string {
	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────────────┐\n")
	b.WriteString("│              POLICY DRIFT REPORT                            │\n")
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│  Baseline:    %-44s│\n", r.BaselinePolicy))
	b.WriteString(fmt.Sprintf("│  Current:     %-44s│\n", r.CurrentPolicy))
	b.WriteString(fmt.Sprintf("│  Rules:       %-3d → %-40d│\n", r.BaselineRules, r.CurrentRules))
	b.WriteString(fmt.Sprintf("│  Drift Score: %-44s│\n", fmt.Sprintf("%.2f", r.DriftScore)))
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")

	if len(r.Findings) == 0 {
		b.WriteString("│  No drift detected. Policies are semantically identical.   │\n")
		b.WriteString("└─────────────────────────────────────────────────────────────┘\n")
		return b.String()
	}

	// Severity counts.
	b.WriteString("│  SEVERITY COUNTS                                            │\n")
	b.WriteString(fmt.Sprintf("│    Critical: %-46d│\n", r.CriticalCount))
	b.WriteString(fmt.Sprintf("│    High:     %-46d│\n", r.HighCount))
	b.WriteString(fmt.Sprintf("│    Medium:   %-46d│\n", r.MediumCount))
	b.WriteString(fmt.Sprintf("│    Low:      %-46d│\n", r.LowCount))
	b.WriteString(fmt.Sprintf("│    Info:     %-46d│\n", r.InfoCount))
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")

	// Findings.
	b.WriteString("│  FINDINGS                                                   │\n")
	b.WriteString("│  ────────────────────────────────────────────────────────    │\n")

	for _, f := range r.Findings {
		icon := severityIcon(f.Severity)
		ruleLabel := f.RuleID
		if ruleLabel == "" {
			ruleLabel = "(meta)"
		}
		line := fmt.Sprintf("%s [%s] %s: %s", icon, f.Severity, ruleLabel, f.Description)
		if len(line) > 57 {
			line = line[:54] + "..."
		}
		b.WriteString(fmt.Sprintf("│  %-57s│\n", line))
	}

	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	summaryLine := r.Summary
	if len(summaryLine) > 57 {
		summaryLine = summaryLine[:54] + "..."
	}
	b.WriteString(fmt.Sprintf("│  %s\n", summaryLine))
	b.WriteString("└─────────────────────────────────────────────────────────────┘\n")

	return b.String()
}

func severityIcon(s DriftSeverity) string {
	switch s {
	case DriftCritical:
		return "!!"
	case DriftHigh:
		return "! "
	case DriftMedium:
		return "~ "
	case DriftLow:
		return "- "
	case DriftInfo:
		return "i "
	}
	return "  "
}

// ---------------------------------------------------------------------------
// SummarizeDrift — one-line human summary
// ---------------------------------------------------------------------------

// SummarizeDrift returns a concise one-line description of the drift report.
func SummarizeDrift(r *DriftReport) string {
	if len(r.Findings) == 0 {
		return "No drift detected"
	}

	parts := []string{}
	if r.CriticalCount > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", r.CriticalCount))
	}
	if r.HighCount > 0 {
		parts = append(parts, fmt.Sprintf("%d high", r.HighCount))
	}
	if r.MediumCount > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", r.MediumCount))
	}
	if r.LowCount > 0 {
		parts = append(parts, fmt.Sprintf("%d low", r.LowCount))
	}
	if r.InfoCount > 0 {
		parts = append(parts, fmt.Sprintf("%d info", r.InfoCount))
	}

	// Collect critical rule IDs for detail.
	var criticalIDs []string
	for _, f := range r.Findings {
		if f.Severity == DriftCritical && f.RuleID != "" {
			criticalIDs = append(criticalIDs, f.RuleID)
		}
	}

	summary := fmt.Sprintf("%d drifts detected (%s)", len(r.Findings), strings.Join(parts, ", "))

	if len(criticalIDs) > 0 {
		summary += fmt.Sprintf(": critical rules %s", strings.Join(criticalIDs, ", "))
	}

	return summary
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func indexRules(rules []Rule) map[string]Rule {
	m := make(map[string]Rule, len(rules))
	for _, r := range rules {
		m[r.ID] = r
	}
	return m
}

func tallySeverities(report *DriftReport) {
	for _, f := range report.Findings {
		switch f.Severity {
		case DriftCritical:
			report.CriticalCount++
		case DriftHigh:
			report.HighCount++
		case DriftMedium:
			report.MediumCount++
		case DriftLow:
			report.LowCount++
		case DriftInfo:
			report.InfoCount++
		}
	}
}

func ruleRemovedImpact(r Rule) string {
	switch r.Effect {
	case "deny":
		return fmt.Sprintf("Deny rule removed — previously blocked actions matching %s are now unprotected",
			strings.Join(r.Match.Tools, ", "))
	case "alert":
		return fmt.Sprintf("Alert rule removed — monitoring for %s has been dropped",
			strings.Join(r.Match.Tools, ", "))
	default:
		return fmt.Sprintf("Allow rule removed — explicit permission for %s revoked",
			strings.Join(r.Match.Tools, ", "))
	}
}

func ruleAddedImpact(r Rule) string {
	switch r.Effect {
	case "deny":
		return fmt.Sprintf("New deny rule blocks %s", strings.Join(r.Match.Tools, ", "))
	case "alert":
		return fmt.Sprintf("New alert rule monitors %s", strings.Join(r.Match.Tools, ", "))
	default:
		return fmt.Sprintf("New allow rule permits %s", strings.Join(r.Match.Tools, ", "))
	}
}

func effectChangeImpact(before, after string) string {
	return fmt.Sprintf("Effect changed from %s to %s — security posture %s",
		before, after, effectPosture(before, after))
}

func effectPosture(before, after string) string {
	if before == "deny" && after == "allow" {
		return "weakened (previously blocked actions now permitted)"
	}
	if before == "allow" && after == "deny" {
		return "strengthened (previously permitted actions now blocked)"
	}
	if before == "deny" && after == "alert" {
		return "weakened (blocking downgraded to alerting)"
	}
	if before == "alert" && after == "deny" {
		return "strengthened (alerting upgraded to blocking)"
	}
	return "changed"
}

func priorityChangeImpact(baseRule, currRule Rule) string {
	if currRule.Priority > baseRule.Priority {
		return "Priority increased — rule evaluates earlier in the chain"
	}
	return "Priority decreased — rule evaluates later, may be overridden by other rules"
}

func scopeChangeImpact(driftType DriftType, effect string) string {
	verb := "modified"
	switch driftType {
	case DriftScopeWidened:
		verb = "widened"
	case DriftScopeNarrowed:
		verb = "narrowed"
	}
	return fmt.Sprintf("Tool scope %s on %s rule", verb, effect)
}

func conditionChangeImpact(baseRule, currRule Rule) string {
	baseConds := len(baseRule.Conditions)
	currConds := len(currRule.Conditions)
	switch {
	case baseConds == 0 && currConds > 0:
		return "Conditions added — rule now fires only under specific circumstances"
	case baseConds > 0 && currConds == 0:
		return "Conditions removed — rule now fires unconditionally"
	default:
		return "Conditions modified — rule firing criteria changed"
	}
}
