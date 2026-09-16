// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Agent proxy — avoids import cycle (internal/agent already imports policy)
// ---------------------------------------------------------------------------

// ImpactAgent is a lightweight projection of an agent definition used by the
// impact analysis functions. The policy package cannot import internal/agent
// (which already imports policy), so callers convert their *agent.Agent values
// into this type before passing them here. Test code, which is allowed to
// import both packages, typically does the conversion in a helper.
type ImpactAgent struct {
	Name  string   // agent.Meta.Name
	Tools []string // tool names from agent.Tools[].Name
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// PolicyChange describes a single proposed or detected change between two
// policy versions.
type PolicyChange struct {
	Type        string `json:"type"` // add_rule, remove_rule, modify_rule, change_effect, change_trust, add_guardrail, remove_guardrail
	Description string `json:"description"`
	RuleBefore  *Rule  `json:"rule_before,omitempty"`
	RuleAfter   *Rule  `json:"rule_after,omitempty"`
	GuardrailID string `json:"guardrail_id,omitempty"`
}

// ImpactAssessment evaluates the impact of a single policy change.
type ImpactAssessment struct {
	Change         PolicyChange `json:"change"`
	Severity       string       `json:"severity"` // critical, high, medium, low
	AffectedAgents []string     `json:"affected_agents"`
	AffectedTools  []string     `json:"affected_tools"`
	NewDenials     int          `json:"new_denials"`
	LiftedDenials  int          `json:"lifted_denials"`
	RiskDelta      float64      `json:"risk_delta"`
	Warnings       []string     `json:"warnings"`
}

// ImpactReport is the aggregate result of analyzing all changes between two
// policy versions.
type ImpactReport struct {
	PolicyName      string             `json:"policy_name"`
	ChangeCount     int                `json:"change_count"`
	Assessments     []ImpactAssessment `json:"assessments"`
	OverallRisk     string             `json:"overall_risk"` // increased, decreased, neutral
	RiskDelta       float64            `json:"risk_delta"`
	BreakingChanges int                `json:"breaking_changes"`
	Summary         []string           `json:"summary"`
	LintBefore      int                `json:"lint_score_before"`
	LintAfter       int                `json:"lint_score_after"`
}

// TraceImpact records how a policy change affects a single historical trace.
type TraceImpact struct {
	TraceID            string `json:"trace_id"`
	AgentName          string `json:"agent_name"`
	EventsAffected     int    `json:"events_affected"`
	NewViolations      int    `json:"new_violations"`
	ResolvedViolations int    `json:"resolved_violations"`
	Verdict            string `json:"verdict"` // safe, breaking, improved
}

// securityCriticalTools are tools whose unrestricted access warrants elevated
// severity and explicit warnings.
var securityCriticalTools = map[string]bool{
	"shell_exec":      true,
	"file_delete":     true,
	"database_write":  true,
	"admin_panel":     true,
	"process_exec":    true,
	"registry_access": true,
	"credential_read": true,
	"code_execution":  true,
	"service_control": true,
}

// ---------------------------------------------------------------------------
// DiffPolicyChanges — compute structural diff between two policy versions
// ---------------------------------------------------------------------------

// DiffPolicyChanges compares two policy versions and returns the list of
// semantic changes as PolicyChange values. It leverages the existing
// DiffPolicies function (which returns a *PolicyDiff) and converts each
// finding into the impact-oriented PolicyChange representation.
func DiffPolicyChanges(before, after *Policy) []PolicyChange {
	diff := DiffPolicies(before, after)
	if diff == nil || diff.Summary.IsIdentical {
		return nil
	}

	var changes []PolicyChange

	// Removed rules.
	for _, r := range diff.RemovedRules {
		rc := r
		changes = append(changes, PolicyChange{
			Type:        "remove_rule",
			Description: fmt.Sprintf("Rule %q removed (effect=%s)", r.ID, r.Effect),
			RuleBefore:  &rc,
		})
	}

	// Added rules.
	for _, r := range diff.AddedRules {
		rc := r
		changes = append(changes, PolicyChange{
			Type:        "add_rule",
			Description: fmt.Sprintf("Rule %q added (effect=%s)", r.ID, r.Effect),
			RuleAfter:   &rc,
		})
	}

	// Modified rules — split into effect changes vs general modifications.
	for _, mc := range diff.ModifiedRules {
		old := mc.OldRule
		newR := mc.NewRule

		isEffectChange := false
		for _, fc := range mc.Changes {
			if fc.Field == "effect" {
				isEffectChange = true
				break
			}
		}

		if isEffectChange {
			changes = append(changes, PolicyChange{
				Type:        "change_effect",
				Description: fmt.Sprintf("Rule %q effect changed from %s to %s", mc.RuleID, old.Effect, newR.Effect),
				RuleBefore:  &old,
				RuleAfter:   &newR,
			})
		} else {
			changes = append(changes, PolicyChange{
				Type:        "modify_rule",
				Description: fmt.Sprintf("Rule %q modified", mc.RuleID),
				RuleBefore:  &old,
				RuleAfter:   &newR,
			})
		}
	}

	return changes
}

// ---------------------------------------------------------------------------
// AnalyzeImpact — main analysis entry point
// ---------------------------------------------------------------------------

// AnalyzeImpact computes the full impact report for a policy change by
// diffing the two versions, assessing each change, and computing aggregate
// risk and lint scores.
func AnalyzeImpact(before, after *Policy, agents []ImpactAgent) *ImpactReport {
	changes := DiffPolicyChanges(before, after)

	report := &ImpactReport{
		ChangeCount: len(changes),
	}

	if after != nil {
		report.PolicyName = after.Meta.Name
	} else if before != nil {
		report.PolicyName = before.Meta.Name
	}

	// Assess each change.
	for _, ch := range changes {
		assessment := AssessChange(ch, after, agents)
		report.Assessments = append(report.Assessments, *assessment)
		if IsBreakingChange(assessment) {
			report.BreakingChanges++
		}
	}

	// Aggregate risk delta.
	report.RiskDelta = ComputeRiskDelta(before, after)
	switch {
	case report.RiskDelta > 0.01:
		report.OverallRisk = "increased"
	case report.RiskDelta < -0.01:
		report.OverallRisk = "decreased"
	default:
		report.OverallRisk = "neutral"
	}

	// Lint scores.
	lintBefore := LintPolicy(before)
	lintAfter := LintPolicy(after)
	report.LintBefore = int(lintBefore.Score * 100)
	report.LintAfter = int(lintAfter.Score * 100)

	// Build summary lines.
	report.Summary = buildImpactSummary(report)

	return report
}

// ---------------------------------------------------------------------------
// AnalyzeTraceImpact — replay traces against both policy versions
// ---------------------------------------------------------------------------

// AnalyzeTraceImpact replays historical traces against both policy versions
// and reports how each trace is affected.
func AnalyzeTraceImpact(before, after *Policy, traces []*Trace) []TraceImpact {
	if before == nil {
		before = &Policy{}
	}
	if after == nil {
		after = &Policy{}
	}

	var results []TraceImpact

	for _, tr := range traces {
		if tr == nil {
			continue
		}

		evalBefore := EvaluateTrace(before, tr)
		evalAfter := EvaluateTrace(after, tr)

		// Build sets of violated event IDs for each evaluation.
		beforeViolated := make(map[string]bool)
		for _, v := range evalBefore.Violations {
			if v.Event != nil {
				beforeViolated[v.Event.ID] = true
			}
		}
		afterViolated := make(map[string]bool)
		for _, v := range evalAfter.Violations {
			if v.Event != nil {
				afterViolated[v.Event.ID] = true
			}
		}

		// New violations: in after but not in before.
		newViolations := 0
		for id := range afterViolated {
			if !beforeViolated[id] {
				newViolations++
			}
		}

		// Resolved violations: in before but not in after.
		resolvedViolations := 0
		for id := range beforeViolated {
			if !afterViolated[id] {
				resolvedViolations++
			}
		}

		eventsAffected := newViolations + resolvedViolations

		verdict := "safe"
		if newViolations > 0 {
			verdict = "breaking"
		} else if resolvedViolations > 0 {
			verdict = "improved"
		}

		results = append(results, TraceImpact{
			TraceID:            tr.ID,
			AgentName:          tr.AgentName,
			EventsAffected:     eventsAffected,
			NewViolations:      newViolations,
			ResolvedViolations: resolvedViolations,
			Verdict:            verdict,
		})
	}

	return results
}

// ---------------------------------------------------------------------------
// AssessChange — assess a single policy change
// ---------------------------------------------------------------------------

// AssessChange evaluates the impact of a single policy change against the
// current policy and agent inventory.
func AssessChange(change PolicyChange, p *Policy, agents []ImpactAgent) *ImpactAssessment {
	assessment := &ImpactAssessment{
		Change: change,
	}

	assessment.AffectedAgents = FindAffectedAgents(change, agents)
	assessment.AffectedTools = FindAffectedTools(change)

	switch change.Type {
	case "add_rule":
		assessAddRule(change, assessment)
	case "remove_rule":
		assessRemoveRule(change, assessment)
	case "modify_rule":
		assessModifyRule(change, assessment)
	case "change_effect":
		assessChangeEffect(change, assessment)
	case "change_trust":
		assessChangeTrust(assessment)
	case "add_guardrail":
		assessAddGuardrail(change, assessment)
	case "remove_guardrail":
		assessRemoveGuardrail(change, assessment)
	default:
		assessment.Severity = "low"
	}

	// Compute per-change risk delta.
	assessment.RiskDelta = computeAssessmentRiskDelta(assessment)

	return assessment
}

func assessAddRule(change PolicyChange, a *ImpactAssessment) {
	if change.RuleAfter == nil {
		a.Severity = "low"
		return
	}
	r := change.RuleAfter
	agentCount := len(a.AffectedAgents)

	switch r.Effect {
	case "deny":
		a.NewDenials = estimateDenials(r, agentCount)
		if hasCriticalTool(r.Match.Tools) {
			a.Severity = "high"
			a.Warnings = append(a.Warnings, "New deny rule affects security-critical tools")
		} else if agentCount > 2 {
			a.Severity = "high"
		} else if agentCount > 0 {
			a.Severity = "medium"
		} else {
			a.Severity = "low"
		}
	case "allow":
		a.Severity = "low"
		if hasCriticalTool(r.Match.Tools) {
			a.Severity = "medium"
			a.Warnings = append(a.Warnings, "New allow rule covers security-critical tools")
		}
	case "alert":
		a.Severity = "low"
	default:
		a.Severity = "low"
	}
}

func assessRemoveRule(change PolicyChange, a *ImpactAssessment) {
	if change.RuleBefore == nil {
		a.Severity = "low"
		return
	}
	r := change.RuleBefore
	agentCount := len(a.AffectedAgents)

	switch r.Effect {
	case "deny":
		a.LiftedDenials = estimateDenials(r, agentCount)
		a.Severity = "critical"
		a.Warnings = append(a.Warnings, "Removing deny rule lifts previous restrictions")
		if hasCriticalTool(r.Match.Tools) {
			a.Warnings = append(a.Warnings, "Security-critical tools are newly unrestricted")
		}
	case "allow":
		a.Severity = "medium"
	case "alert":
		a.Severity = "medium"
		a.Warnings = append(a.Warnings, "Removing alert rule reduces monitoring visibility")
	default:
		a.Severity = "low"
	}
}

func assessModifyRule(change PolicyChange, a *ImpactAssessment) {
	if change.RuleBefore == nil || change.RuleAfter == nil {
		a.Severity = "medium"
		return
	}

	beforeTools := len(change.RuleBefore.Match.Tools)
	afterTools := len(change.RuleAfter.Match.Tools)
	agentCount := impactMax(1, len(a.AffectedAgents))

	if change.RuleBefore.Effect == "deny" {
		if afterTools > beforeTools {
			a.NewDenials = (afterTools - beforeTools) * agentCount
			a.Severity = "high"
			a.Warnings = append(a.Warnings, "Deny rule scope widened — more tools blocked")
		} else if afterTools < beforeTools {
			a.LiftedDenials = (beforeTools - afterTools) * agentCount
			a.Severity = "high"
			a.Warnings = append(a.Warnings, "Deny rule scope narrowed — some tools unblocked")
		} else {
			a.Severity = "medium"
		}
	} else {
		a.Severity = "medium"
	}
}

func assessChangeEffect(change PolicyChange, a *ImpactAssessment) {
	if change.RuleBefore == nil || change.RuleAfter == nil {
		a.Severity = "high"
		return
	}

	before := change.RuleBefore.Effect
	after := change.RuleAfter.Effect
	agentCount := impactMax(1, len(a.AffectedAgents))
	toolCount := impactMax(1, len(change.RuleBefore.Match.Tools))

	switch {
	case before == "allow" && after == "deny":
		a.Severity = "high"
		a.NewDenials = toolCount * agentCount
		a.Warnings = append(a.Warnings, "Previously allowed actions will now be denied")
	case before == "deny" && after == "allow":
		a.Severity = "critical"
		a.LiftedDenials = toolCount * agentCount
		a.Warnings = append(a.Warnings, "Previously denied actions will now be allowed")
		if hasCriticalTool(change.RuleBefore.Match.Tools) {
			a.Warnings = append(a.Warnings, "Security-critical tools are being unblocked")
		}
	case before == "deny" && after == "alert":
		a.Severity = "high"
		a.LiftedDenials = toolCount * agentCount
		a.Warnings = append(a.Warnings, "Blocking downgraded to alerting")
	case before == "alert" && after == "deny":
		a.Severity = "high"
		a.NewDenials = toolCount * agentCount
	default:
		a.Severity = "medium"
	}
}

func assessChangeTrust(a *ImpactAssessment) {
	a.Severity = "high"
	a.Warnings = append(a.Warnings, "Trust level change affects agent privilege boundaries")
}

func assessAddGuardrail(change PolicyChange, a *ImpactAssessment) {
	a.Severity = "low"
	if change.GuardrailID != "" {
		a.Warnings = append(a.Warnings, fmt.Sprintf("Guardrail %q added", change.GuardrailID))
	}
}

func assessRemoveGuardrail(change PolicyChange, a *ImpactAssessment) {
	a.Severity = "high"
	a.Warnings = append(a.Warnings, fmt.Sprintf("Guardrail %q removed — safety coverage reduced", change.GuardrailID))
}

// ---------------------------------------------------------------------------
// ComputeRiskDelta — overall risk change (-1 to +1)
// ---------------------------------------------------------------------------

// ComputeRiskDelta computes the overall risk change between two policy
// versions. Positive values mean increased risk (weaker policy); negative
// values mean decreased risk (stronger policy). The range is clamped to
// [-1, +1].
func ComputeRiskDelta(before, after *Policy) float64 {
	if before == nil {
		before = &Policy{}
	}
	if after == nil {
		after = &Policy{}
	}

	// Factor 1: deny-rule count ratio.
	beforeDenyCount := countEffect(before.Rules, "deny")
	afterDenyCount := countEffect(after.Rules, "deny")

	denyDelta := 0.0
	if beforeDenyCount > 0 || afterDenyCount > 0 {
		total := float64(impactMax(beforeDenyCount, afterDenyCount))
		denyDelta = float64(beforeDenyCount-afterDenyCount) / total * 0.4
	}

	// Factor 2: allow-rule count ratio (more allows = more risk).
	beforeAllowCount := countEffect(before.Rules, "allow")
	afterAllowCount := countEffect(after.Rules, "allow")

	allowDelta := 0.0
	if beforeAllowCount > 0 || afterAllowCount > 0 {
		total := float64(impactMax(beforeAllowCount, afterAllowCount))
		allowDelta = float64(afterAllowCount-beforeAllowCount) / total * 0.3
	}

	// Factor 3: total rule coverage.
	coverageDelta := 0.0
	if len(before.Rules) > 0 || len(after.Rules) > 0 {
		maxRules := float64(impactMax(len(before.Rules), len(after.Rules)))
		coverageDelta = float64(len(before.Rules)-len(after.Rules)) / maxRules * 0.15
	}

	// Factor 4: lint score improvement.
	lintBefore := LintPolicy(before)
	lintAfter := LintPolicy(after)
	lintDelta := (lintBefore.Score - lintAfter.Score) * 0.15

	delta := denyDelta + allowDelta + coverageDelta + lintDelta

	// Clamp to [-1, 1].
	return math.Max(-1.0, math.Min(1.0, delta))
}

// ---------------------------------------------------------------------------
// FindAffectedAgents — which agents are affected by a change
// ---------------------------------------------------------------------------

// FindAffectedAgents returns the names of agents whose tool access overlaps
// with the tools referenced in the policy change.
func FindAffectedAgents(change PolicyChange, agents []ImpactAgent) []string {
	affectedTools := FindAffectedTools(change)
	if len(affectedTools) == 0 {
		return nil
	}

	var affected []string
	seen := make(map[string]bool)

	for i := range agents {
		a := &agents[i]
		for _, agentTool := range a.Tools {
			if impactToolMatches(affectedTools, agentTool) {
				if !seen[a.Name] {
					seen[a.Name] = true
					affected = append(affected, a.Name)
				}
				break
			}
		}
	}

	sort.Strings(affected)
	return affected
}

// ---------------------------------------------------------------------------
// FindAffectedTools — which tools are referenced in a change
// ---------------------------------------------------------------------------

// FindAffectedTools extracts the union of tools referenced in both the before
// and after rules of a change.
func FindAffectedTools(change PolicyChange) []string {
	seen := make(map[string]bool)
	var tools []string

	addTools := func(r *Rule) {
		if r == nil {
			return
		}
		for _, t := range r.Match.Tools {
			if !seen[t] {
				seen[t] = true
				tools = append(tools, t)
			}
		}
	}

	addTools(change.RuleBefore)
	addTools(change.RuleAfter)

	sort.Strings(tools)
	return tools
}

// ---------------------------------------------------------------------------
// IsBreakingChange
// ---------------------------------------------------------------------------

// IsBreakingChange returns true when a policy change would deny actions that
// were previously allowed. This is the strongest possible impact: existing
// agent workflows may fail.
func IsBreakingChange(assessment *ImpactAssessment) bool {
	if assessment == nil {
		return false
	}
	return assessment.NewDenials > 0
}

// ---------------------------------------------------------------------------
// FormatImpactReport — box-drawing formatted output
// ---------------------------------------------------------------------------

// FormatImpactReport renders a full impact report using box-drawing characters,
// following the style used by FormatDriftReport and FormatLintReport.
func FormatImpactReport(r *ImpactReport) string {
	if r == nil {
		return "No impact report.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────────────┐\n")
	b.WriteString("│              POLICY IMPACT REPORT                           │\n")
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&b, "│  Policy:      %-44s│\n", truncate(r.PolicyName, 44))
	fmt.Fprintf(&b, "│  Changes:     %-44d│\n", r.ChangeCount)
	fmt.Fprintf(&b, "│  Breaking:    %-44d│\n", r.BreakingChanges)
	fmt.Fprintf(&b, "│  Risk:        %-44s│\n", r.OverallRisk)
	fmt.Fprintf(&b, "│  Risk Delta:  %-44s│\n", fmt.Sprintf("%.3f", r.RiskDelta))
	fmt.Fprintf(&b, "│  Lint Score:  %-44s│\n", fmt.Sprintf("%d%% -> %d%%", r.LintBefore, r.LintAfter))
	b.WriteString("├─────────────────────────────────────────────────────────────┤\n")

	if len(r.Assessments) == 0 {
		b.WriteString("│  No changes detected.                                       │\n")
	} else {
		b.WriteString("│  ASSESSMENTS                                                │\n")
		b.WriteString("│  ────────────────────────────────────────────────────────    │\n")
		for i, a := range r.Assessments {
			icon := impactSeverityIcon(a.Severity)
			line := fmt.Sprintf("%d. %s [%s] %s", i+1, icon, a.Severity, a.Change.Type)
			fmt.Fprintf(&b, "│  %-57s│\n", truncate(line, 57))
			desc := a.Change.Description
			fmt.Fprintf(&b, "│    %-55s│\n", truncate(desc, 55))
			if len(a.AffectedAgents) > 0 {
				agentList := strings.Join(a.AffectedAgents, ", ")
				fmt.Fprintf(&b, "│    Agents: %-48s│\n", truncate(agentList, 48))
			}
			if a.NewDenials > 0 {
				fmt.Fprintf(&b, "│    New denials: %-43d│\n", a.NewDenials)
			}
			if a.LiftedDenials > 0 {
				fmt.Fprintf(&b, "│    Lifted denials: %-40d│\n", a.LiftedDenials)
			}
			for _, w := range a.Warnings {
				fmt.Fprintf(&b, "│    ! %-53s│\n", truncate(w, 53))
			}
		}
	}

	if len(r.Summary) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────────────┤\n")
		b.WriteString("│  SUMMARY                                                    │\n")
		for _, line := range r.Summary {
			fmt.Fprintf(&b, "│  %-57s│\n", truncate(line, 57))
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────────────┘\n")

	return b.String()
}

// ---------------------------------------------------------------------------
// SummarizeImpact — one-line summary
// ---------------------------------------------------------------------------

// SummarizeImpact returns a concise one-line description of the impact report.
func SummarizeImpact(r *ImpactReport) string {
	if r == nil {
		return "No impact data"
	}
	if r.ChangeCount == 0 {
		return "No changes detected"
	}
	return fmt.Sprintf("%d changes (%d breaking), risk %s (delta %.3f), lint %d%%->%d%%",
		r.ChangeCount, r.BreakingChanges, r.OverallRisk, r.RiskDelta,
		r.LintBefore, r.LintAfter)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func countEffect(rules []Rule, effect string) int {
	n := 0
	for _, r := range rules {
		if r.Effect == effect {
			n++
		}
	}
	return n
}

func estimateDenials(r *Rule, agentCount int) int {
	toolCount := len(r.Match.Tools)
	if toolCount == 0 {
		toolCount = 1
	}
	agents := agentCount
	if agents == 0 {
		agents = 1
	}
	return toolCount * agents
}

func hasCriticalTool(tools []string) bool {
	for _, t := range tools {
		if securityCriticalTools[t] {
			return true
		}
		// Check glob patterns against known critical tools.
		for ct := range securityCriticalTools {
			if GlobMatch(t, ct) {
				return true
			}
		}
	}
	return false
}

func impactToolMatches(patterns []string, tool string) bool {
	for _, p := range patterns {
		if p == tool || GlobMatch(p, tool) {
			return true
		}
	}
	return false
}

func computeAssessmentRiskDelta(a *ImpactAssessment) float64 {
	delta := 0.0

	// Lifted denials increase risk.
	delta += float64(a.LiftedDenials) * 0.05
	// New denials decrease risk (tighter policy).
	delta -= float64(a.NewDenials) * 0.03

	// Severity multiplier.
	switch a.Severity {
	case "critical":
		delta += 0.2
	case "high":
		delta += 0.1
	case "medium":
		delta += 0.02
	}

	// Change type adjustments.
	switch a.Change.Type {
	case "remove_rule":
		if a.Change.RuleBefore != nil && a.Change.RuleBefore.Effect == "deny" {
			delta += 0.15
		}
	case "change_effect":
		if a.Change.RuleBefore != nil && a.Change.RuleAfter != nil {
			if a.Change.RuleBefore.Effect == "deny" && a.Change.RuleAfter.Effect == "allow" {
				delta += 0.2
			}
		}
	}

	return math.Max(-1.0, math.Min(1.0, delta))
}

func buildImpactSummary(r *ImpactReport) []string {
	var lines []string

	if r.ChangeCount == 0 {
		lines = append(lines, "No policy changes detected")
		return lines
	}

	lines = append(lines, fmt.Sprintf("%d change(s) analyzed", r.ChangeCount))

	if r.BreakingChanges > 0 {
		lines = append(lines, fmt.Sprintf("%d breaking change(s) will deny previously allowed actions", r.BreakingChanges))
	}

	switch r.OverallRisk {
	case "increased":
		lines = append(lines, fmt.Sprintf("Overall risk INCREASED (delta=%.3f)", r.RiskDelta))
	case "decreased":
		lines = append(lines, fmt.Sprintf("Overall risk DECREASED (delta=%.3f)", r.RiskDelta))
	default:
		lines = append(lines, "Overall risk is neutral")
	}

	if r.LintAfter > r.LintBefore {
		lines = append(lines, fmt.Sprintf("Lint score improved: %d%% -> %d%%", r.LintBefore, r.LintAfter))
	} else if r.LintAfter < r.LintBefore {
		lines = append(lines, fmt.Sprintf("Lint score degraded: %d%% -> %d%%", r.LintBefore, r.LintAfter))
	}

	return lines
}

func impactSeverityIcon(s string) string {
	switch s {
	case "critical":
		return "!!"
	case "high":
		return "! "
	case "medium":
		return "~ "
	case "low":
		return "- "
	}
	return "  "
}

// impactMax returns the greater of a and b.
func impactMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}
