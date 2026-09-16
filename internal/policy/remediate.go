// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Remediation action types
// ---------------------------------------------------------------------------

// RemediationType classifies what kind of fix a remediation action performs.
type RemediationType string

const (
	// RemAddRule is a remediation that inserts a new rule into the policy.
	RemAddRule RemediationType = "add_rule"
	// RemModifyRule is a remediation that changes an existing rule's configuration.
	RemModifyRule RemediationType = "modify_rule"
	// RemRemoveRule is a remediation that deletes a redundant or shadowed rule.
	RemRemoveRule RemediationType = "remove_rule"
	// RemAddMetadata is a remediation that fills in missing policy metadata fields.
	RemAddMetadata RemediationType = "add_metadata"
	// RemRestructure is a remediation that reorganizes the policy structure.
	RemRestructure RemediationType = "restructure"
)

// RemediationPriority classifies the urgency of a fix.
type RemediationPriority string

const (
	// RemPriorityCritical indicates a fix that must be applied immediately.
	RemPriorityCritical RemediationPriority = "critical"
	// RemPriorityHigh indicates a fix that should be applied soon.
	RemPriorityHigh RemediationPriority = "high"
	// RemPriorityMedium indicates a fix with moderate urgency.
	RemPriorityMedium RemediationPriority = "medium"
	// RemPriorityLow indicates a fix that can be deferred.
	RemPriorityLow RemediationPriority = "low"
)

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

// RemediationAction is a single concrete fix suggestion.
type RemediationAction struct {
	ID             string              `json:"id"`              // auto: "REM-001"
	Type           RemediationType     `json:"type"`            // add_rule, modify_rule, etc.
	Priority       RemediationPriority `json:"priority"`        // critical, high, medium, low
	Source         string              `json:"source"`          // origin: "lint:SEC-001", "drift:effect_changed", "coverage:T1059"
	Description    string              `json:"description"`     // human-readable explanation
	RuleBefore     string              `json:"rule_before"`     // YAML snippet of current state (empty for add)
	RuleAfter      string              `json:"rule_after"`      // YAML snippet of suggested state (empty for remove)
	Rationale      string              `json:"rationale"`       // why this fix matters
	AutoApplicable bool                `json:"auto_applicable"` // whether it can be applied automatically
}

// RemediationPlan is the full set of remediation actions for a policy.
type RemediationPlan struct {
	PolicyName          string              `json:"policy_name"`
	Actions             []RemediationAction `json:"actions"`
	TotalActions        int                 `json:"total_actions"`
	CriticalCount       int                 `json:"critical_count"`
	HighCount           int                 `json:"high_count"`
	MediumCount         int                 `json:"medium_count"`
	LowCount            int                 `json:"low_count"`
	AutoApplicableCount int                 `json:"auto_applicable_count"`
	EstimatedEffort     string              `json:"estimated_effort"` // "minimal", "moderate", "significant"
}

// ---------------------------------------------------------------------------
// RemediateFromLint — generate fixes from lint findings
// ---------------------------------------------------------------------------

// RemediateFromLint produces a remediation plan from policy lint results.
// Each lint finding is mapped to a concrete fix suggestion with YAML
// before/after snippets where possible.
func RemediateFromLint(p *Policy, report *LintReport) *RemediationPlan {
	plan := &RemediationPlan{}
	if p != nil {
		plan.PolicyName = p.Meta.Name
	}
	if report == nil || len(report.Findings) == 0 {
		plan.EstimatedEffort = "minimal"
		return plan
	}

	for _, f := range report.Findings {
		action := remediateFromLintFinding(p, f)
		if action != nil {
			plan.Actions = append(plan.Actions, *action)
		}
	}

	finalizePlan(plan)
	return plan
}

// remediateFromLintFinding maps a single lint finding to a remediation action.
func remediateFromLintFinding(p *Policy, f LintFinding) *RemediationAction {
	switch f.Rule {
	case "SEC-001":
		return &RemediationAction{
			Type:        RemAddRule,
			Priority:    RemPriorityCritical,
			Source:      "lint:SEC-001",
			Description: "Add a default deny rule to catch unmatched tool calls",
			RuleAfter: `- id: default-deny
  description: "Deny all unmatched tool calls"
  effect: deny
  priority: 0
  match:
    tools: ["*"]`,
			Rationale:      "Without a deny rule, unmatched tool calls are implicitly allowed, which is a security risk",
			AutoApplicable: true,
		}

	case "SEC-002":
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    RemPriorityCritical,
			Source:      "lint:SEC-002",
			Description: fmt.Sprintf("Restrict wildcard allow on rule %s to specific tools", f.RuleID),
			RuleBefore:  fmt.Sprintf("rule %s: effect=allow, tools=[*]", f.RuleID),
			RuleAfter: fmt.Sprintf(`- id: %s
  effect: allow
  match:
    tools: ["specific-tool-1", "specific-tool-2"]`, f.RuleID),
			Rationale:      "Wildcard allow rules bypass all deny rules and should be scoped to specific tools",
			AutoApplicable: false,
		}

	case "SEC-003":
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    RemPriorityHigh,
			Source:      "lint:SEC-003",
			Description: fmt.Sprintf("Add conditions to elevated allow rule %s", f.RuleID),
			RuleBefore:  fmt.Sprintf("rule %s: effect=allow, elevated=true, no conditions", f.RuleID),
			RuleAfter: fmt.Sprintf(`- id: %s
  effect: allow
  conditions:
    - field: elevated
      operator: eq
      value: "true"
    - field: technique
      operator: not_in
      value: "T1548,T1134"`, f.RuleID),
			Rationale:      "Elevated operations need explicit conditions to prevent privilege abuse",
			AutoApplicable: false,
		}

	case "SEC-004":
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    RemPriorityHigh,
			Source:      "lint:SEC-004",
			Description: "Add target restrictions to exfiltration-tactic rules",
			RuleBefore:  fmt.Sprintf("rule %s: tactic=exfiltration, no target restrictions", f.RuleID),
			RuleAfter: fmt.Sprintf(`- id: %s
  effect: deny
  match:
    tactics: [exfiltration]
    targets: ["*external*"]`, f.RuleID),
			Rationale:      "Exfiltration rules without target restrictions may miss data leakage paths",
			AutoApplicable: false,
		}

	case "SEC-005":
		return &RemediationAction{
			Type:        RemAddRule,
			Priority:    RemPriorityHigh,
			Source:      "lint:SEC-005",
			Description: "Add deny rules for high-risk tactics",
			RuleAfter: `- id: deny-impact
  description: "Deny impact-tactic tool calls"
  effect: deny
  match:
    tactics: [impact]`,
			Rationale:      "High-risk tactics should have explicit deny rules",
			AutoApplicable: true,
		}

	case "COV-001":
		return &RemediationAction{
			Type:        RemAddRule,
			Priority:    RemPriorityMedium,
			Source:      "lint:COV-001",
			Description: "Add rules covering common tool patterns",
			RuleAfter: `- id: tool-coverage-http
  description: "Alert on HTTP requests"
  effect: alert
  match:
    tools: [http_request]
- id: tool-coverage-shell
  description: "Deny shell execution by default"
  effect: deny
  match:
    tools: [shell_exec]`,
			Rationale:      "Rules should reference tool patterns to enforce tool-call policies",
			AutoApplicable: true,
		}

	case "COV-002":
		return &RemediationAction{
			Type:        RemAddRule,
			Priority:    RemPriorityMedium,
			Source:      "lint:COV-002",
			Description: "Add rules for uncovered tactics",
			RuleAfter: `- id: tactic-coverage-recon
  description: "Alert on reconnaissance activity"
  effect: alert
  match:
    tactics: [reconnaissance]`,
			Rationale:      "All relevant ATLAS/ATT&CK tactics should have explicit rules",
			AutoApplicable: true,
		}

	case "COV-003":
		return &RemediationAction{
			Type:        RemAddRule,
			Priority:    RemPriorityLow,
			Source:      "lint:COV-003",
			Description: "Add rules covering action types",
			RuleAfter: `- id: action-coverage
  description: "Alert on write actions"
  effect: alert
  match:
    actions: [write]`,
			Rationale:      "Covering action types ensures comprehensive monitoring",
			AutoApplicable: true,
		}

	case "COV-004":
		return &RemediationAction{
			Type:        RemAddRule,
			Priority:    RemPriorityLow,
			Source:      "lint:COV-004",
			Description: "Add target-based rules for network monitoring",
			RuleAfter: `- id: target-coverage
  description: "Alert on external targets"
  effect: alert
  match:
    targets: ["*external*", "*.io"]`,
			Rationale:      "Target-based rules help detect data exfiltration and C2 traffic",
			AutoApplicable: true,
		}

	case "RED-001":
		return &RemediationAction{
			Type:        RemRemoveRule,
			Priority:    RemPriorityLow,
			Source:      "lint:RED-001",
			Description: fmt.Sprintf("Remove duplicate rule %s", f.RuleID),
			RuleBefore:  fmt.Sprintf("rule %s: duplicate match patterns", f.RuleID),
			Rationale:   "Duplicate rules add complexity without changing behavior",
		}

	case "RED-002":
		return &RemediationAction{
			Type:        RemRemoveRule,
			Priority:    RemPriorityLow,
			Source:      "lint:RED-002",
			Description: fmt.Sprintf("Remove shadowed rule %s", f.RuleID),
			RuleBefore:  fmt.Sprintf("rule %s: shadowed by higher-priority rule", f.RuleID),
			Rationale:   "Shadowed rules never fire and add confusion",
		}

	case "RED-003":
		return &RemediationAction{
			Type:        RemRemoveRule,
			Priority:    RemPriorityLow,
			Source:      "lint:RED-003",
			Description: fmt.Sprintf("Remove unreachable rule %s", f.RuleID),
			RuleBefore:  fmt.Sprintf("rule %s: unreachable due to prior rules", f.RuleID),
			Rationale:   "Unreachable rules are dead code in the policy",
		}

	case "NAM-001":
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    RemPriorityLow,
			Source:      "lint:NAM-001",
			Description: fmt.Sprintf("Rename rule %s to avoid duplication", f.RuleID),
			RuleBefore:  fmt.Sprintf("rule %s: duplicate description", f.RuleID),
			RuleAfter:   fmt.Sprintf("rule %s: add unique suffix to description", f.RuleID),
			Rationale:   "Unique descriptions make policies easier to audit",
		}

	case "NAM-002", "NAM-003", "NAM-004":
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    RemPriorityLow,
			Source:      fmt.Sprintf("lint:%s", f.Rule),
			Description: fmt.Sprintf("Improve naming for rule %s: %s", f.RuleID, f.Message),
			Rationale:   "Good naming conventions improve policy readability",
		}

	case "CPX-001":
		return &RemediationAction{
			Type:        RemRestructure,
			Priority:    RemPriorityMedium,
			Source:      "lint:CPX-001",
			Description: "Split policy into smaller, focused sub-policies",
			Rationale:   "Large policies are harder to review, test, and maintain",
		}

	case "CPX-002", "CPX-003", "CPX-004":
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    RemPriorityLow,
			Source:      fmt.Sprintf("lint:%s", f.Rule),
			Description: fmt.Sprintf("Simplify rule %s: %s", f.RuleID, f.Message),
			Rationale:   "Complex rules are harder to reason about and more likely to have unintended behavior",
		}

	case "BP-001":
		return &RemediationAction{
			Type:        RemAddMetadata,
			Priority:    RemPriorityLow,
			Source:      "lint:BP-001",
			Description: "Add a description to the policy metadata",
			RuleAfter: `meta:
  description: "Tool-call policy for agent enforcement"`,
			Rationale:      "Descriptions help humans understand policy intent",
			AutoApplicable: true,
		}

	case "BP-002":
		return &RemediationAction{
			Type:        RemAddMetadata,
			Priority:    RemPriorityLow,
			Source:      "lint:BP-002",
			Description: "Add authors to the policy metadata",
			RuleAfter: `meta:
  authors: ["security-team"]`,
			Rationale:      "Author attribution enables accountability and review tracking",
			AutoApplicable: true,
		}

	case "BP-003":
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    RemPriorityLow,
			Source:      "lint:BP-003",
			Description: fmt.Sprintf("Add a description to rule %s", f.RuleID),
			Rationale:   "Every rule should explain its purpose",
		}

	case "BP-004":
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    RemPriorityLow,
			Source:      "lint:BP-004",
			Description: "Use consistent priority numbering across rules",
			Rationale:   "Consistent priorities prevent rule-ordering surprises",
		}

	case "BP-005":
		return &RemediationAction{
			Type:        RemAddMetadata,
			Priority:    RemPriorityLow,
			Source:      "lint:BP-005",
			Description: "Add created/modified timestamps to the policy metadata",
			RuleAfter: `meta:
  created: "2025-01-01"
  modified: "2025-01-01"`,
			Rationale:      "Timestamps support audit trails and drift detection",
			AutoApplicable: true,
		}
	}

	// Fallback for unmapped rules.
	return nil
}

// ---------------------------------------------------------------------------
// RemediateFromDrift — generate fixes from drift detection
// ---------------------------------------------------------------------------

// RemediateFromDrift produces remediation actions from a drift report,
// suggesting how to bring the current policy back to the baseline or
// explicitly acknowledge the drift.
func RemediateFromDrift(p *Policy, report *DriftReport) *RemediationPlan {
	plan := &RemediationPlan{}
	if p != nil {
		plan.PolicyName = p.Meta.Name
	}
	if report == nil || len(report.Findings) == 0 {
		plan.EstimatedEffort = "minimal"
		return plan
	}

	for _, f := range report.Findings {
		action := remediateFromDriftFinding(f)
		if action != nil {
			plan.Actions = append(plan.Actions, *action)
		}
	}

	finalizePlan(plan)
	return plan
}

// remediateFromDriftFinding maps a single drift finding to a remediation action.
func remediateFromDriftFinding(f DriftFinding) *RemediationAction {
	switch f.Type {
	case DriftEffectChanged:
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    driftSeverityToPriority(f.Severity),
			Source:      fmt.Sprintf("drift:%s", f.Type),
			Description: fmt.Sprintf("Restore original effect for rule %s", f.RuleID),
			RuleBefore:  f.After,
			RuleAfter:   f.Before,
			Rationale:   fmt.Sprintf("Rule effect changed: %s. %s", f.Description, f.Impact),
		}

	case DriftRuleRemoved:
		return &RemediationAction{
			Type:        RemAddRule,
			Priority:    driftSeverityToPriority(f.Severity),
			Source:      fmt.Sprintf("drift:%s", f.Type),
			Description: fmt.Sprintf("Restore removed rule %s", f.RuleID),
			RuleAfter:   f.Before,
			Rationale:   fmt.Sprintf("Rule was removed: %s. %s", f.Description, f.Impact),
		}

	case DriftRuleAdded:
		return &RemediationAction{
			Type:        RemRemoveRule,
			Priority:    driftSeverityToPriority(f.Severity),
			Source:      fmt.Sprintf("drift:%s", f.Type),
			Description: fmt.Sprintf("Review new rule %s for alignment with baseline", f.RuleID),
			RuleBefore:  f.After,
			Rationale:   fmt.Sprintf("New rule added: %s. %s", f.Description, f.Impact),
		}

	case DriftScopeWidened:
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    driftSeverityToPriority(f.Severity),
			Source:      fmt.Sprintf("drift:%s", f.Type),
			Description: fmt.Sprintf("Narrow scope back to baseline for rule %s", f.RuleID),
			RuleBefore:  f.After,
			RuleAfter:   f.Before,
			Rationale:   fmt.Sprintf("Scope was widened: %s. %s", f.Description, f.Impact),
		}

	case DriftScopeNarrowed:
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    driftSeverityToPriority(f.Severity),
			Source:      fmt.Sprintf("drift:%s", f.Type),
			Description: fmt.Sprintf("Restore original scope for rule %s", f.RuleID),
			RuleBefore:  f.After,
			RuleAfter:   f.Before,
			Rationale:   fmt.Sprintf("Scope was narrowed: %s. %s", f.Description, f.Impact),
		}

	case DriftPriorityShift:
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    driftSeverityToPriority(f.Severity),
			Source:      fmt.Sprintf("drift:%s", f.Type),
			Description: fmt.Sprintf("Restore original priority for rule %s", f.RuleID),
			RuleBefore:  f.After,
			RuleAfter:   f.Before,
			Rationale:   fmt.Sprintf("Priority was shifted: %s. %s", f.Description, f.Impact),
		}

	case DriftConditionChanged:
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    driftSeverityToPriority(f.Severity),
			Source:      fmt.Sprintf("drift:%s", f.Type),
			Description: fmt.Sprintf("Restore conditions for rule %s", f.RuleID),
			RuleBefore:  f.After,
			RuleAfter:   f.Before,
			Rationale:   fmt.Sprintf("Conditions changed: %s. %s", f.Description, f.Impact),
		}

	case DriftRuleModified:
		return &RemediationAction{
			Type:        RemModifyRule,
			Priority:    driftSeverityToPriority(f.Severity),
			Source:      fmt.Sprintf("drift:%s", f.Type),
			Description: fmt.Sprintf("Review modifications to rule %s", f.RuleID),
			RuleBefore:  f.After,
			RuleAfter:   f.Before,
			Rationale:   fmt.Sprintf("Rule was modified: %s. %s", f.Description, f.Impact),
		}

	case DriftMetaChanged:
		return &RemediationAction{
			Type:        RemAddMetadata,
			Priority:    RemPriorityLow,
			Source:      fmt.Sprintf("drift:%s", f.Type),
			Description: "Restore baseline metadata",
			RuleBefore:  f.After,
			RuleAfter:   f.Before,
			Rationale:   fmt.Sprintf("Metadata changed: %s", f.Description),
		}
	}

	return nil
}

// driftSeverityToPriority maps drift severity to remediation priority.
func driftSeverityToPriority(s DriftSeverity) RemediationPriority {
	switch s {
	case DriftCritical:
		return RemPriorityCritical
	case DriftHigh:
		return RemPriorityHigh
	case DriftMedium:
		return RemPriorityMedium
	default:
		return RemPriorityLow
	}
}

// ---------------------------------------------------------------------------
// RemediateFromCoverage — generate rules to close coverage gaps
// ---------------------------------------------------------------------------

// RemediateFromCoverage produces remediation actions from a coverage map
// report, generating rule suggestions for each uncovered technique.
func RemediateFromCoverage(p *Policy, report *CoverageMapReport) *RemediationPlan {
	plan := &RemediationPlan{}
	if p != nil {
		plan.PolicyName = p.Meta.Name
	}
	if report == nil || len(report.Gaps) == 0 {
		plan.EstimatedEffort = "minimal"
		return plan
	}

	for _, gap := range report.Gaps {
		action := remediateFromGap(gap)
		plan.Actions = append(plan.Actions, action)
	}

	finalizePlan(plan)
	return plan
}

// remediateFromGap builds a remediation action for a single coverage gap.
func remediateFromGap(gap TechniqueGap) RemediationAction {
	priority := gapSeverityToPriority(gap.Severity)

	// Build a rule suggestion based on the technique.
	slug := strings.ToLower(strings.ReplaceAll(gap.TechniqueID, ".", "-"))
	ruleID := fmt.Sprintf("cover-%s", slug)

	// Determine the best match dimension from recommendations.
	matchYAML := buildGapMatchYAML(gap)

	ruleAfter := fmt.Sprintf(`- id: %s
  description: "Detect %s (%s)"
  effect: alert
  match:
%s`, ruleID, gap.TechniqueName, gap.TechniqueID, matchYAML)

	rationale := fmt.Sprintf("Technique %s (%s) in tactic %q is uncovered",
		gap.TechniqueID, gap.TechniqueName, gap.Tactic)
	if len(gap.Recommendations) > 0 {
		rationale += "; " + gap.Recommendations[0]
	}

	return RemediationAction{
		Type:           RemAddRule,
		Priority:       priority,
		Source:         fmt.Sprintf("coverage:%s", gap.TechniqueID),
		Description:    fmt.Sprintf("Add rule to cover %s (%s)", gap.TechniqueID, gap.TechniqueName),
		RuleAfter:      ruleAfter,
		Rationale:      rationale,
		AutoApplicable: true,
	}
}

// buildGapMatchYAML generates a plausible YAML match stanza for a technique gap.
func buildGapMatchYAML(gap TechniqueGap) string {
	tactic := gap.Tactic
	if tactic == "" {
		tactic = "execution"
	}
	return fmt.Sprintf("    tactics: [%s]", tactic)
}

// gapSeverityToPriority maps gap severity to remediation priority.
func gapSeverityToPriority(sev string) RemediationPriority {
	switch sev {
	case "critical":
		return RemPriorityCritical
	case "high":
		return RemPriorityHigh
	case "medium":
		return RemPriorityMedium
	default:
		return RemPriorityLow
	}
}

// ---------------------------------------------------------------------------
// MergeRemediations — combine multiple plans, dedupe, re-prioritize
// ---------------------------------------------------------------------------

// MergeRemediations merges multiple remediation plans into one. Actions with
// identical Source values are deduplicated — the higher-priority one wins.
// The merged plan is re-sorted by priority and re-numbered.
func MergeRemediations(plans ...*RemediationPlan) *RemediationPlan {
	merged := &RemediationPlan{}

	if len(plans) == 0 {
		merged.EstimatedEffort = "minimal"
		return merged
	}

	// Collect policy name from first non-empty plan.
	for _, plan := range plans {
		if plan != nil && plan.PolicyName != "" {
			merged.PolicyName = plan.PolicyName
			break
		}
	}

	// Deduplicate by Source — keep higher priority.
	seen := make(map[string]int) // source → index in merged.Actions
	for _, plan := range plans {
		if plan == nil {
			continue
		}
		for _, a := range plan.Actions {
			if idx, exists := seen[a.Source]; exists {
				// Keep the higher priority one.
				if priorityRank(a.Priority) > priorityRank(merged.Actions[idx].Priority) {
					merged.Actions[idx] = a
				}
			} else {
				seen[a.Source] = len(merged.Actions)
				merged.Actions = append(merged.Actions, a)
			}
		}
	}

	finalizePlan(merged)
	return merged
}

// priorityRank returns a numeric rank for sorting (higher = more urgent).
func priorityRank(p RemediationPriority) int {
	switch p {
	case RemPriorityCritical:
		return 4
	case RemPriorityHigh:
		return 3
	case RemPriorityMedium:
		return 2
	case RemPriorityLow:
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// ApplyRemediation — apply one fix to a policy (returns modified copy)
// ---------------------------------------------------------------------------

// ApplyRemediation applies a single remediation action to a policy, returning
// a modified copy. Only add_rule, remove_rule, and add_metadata actions are
// automatically applicable; modify_rule and restructure actions require
// manual intervention.
func ApplyRemediation(p *Policy, action RemediationAction) (*Policy, error) {
	if p == nil {
		return nil, fmt.Errorf("nil policy")
	}

	// Deep copy the policy.
	cp := copyPolicyDeep(p)

	switch action.Type {
	case RemAddRule:
		return applyAddRule(cp, action)
	case RemRemoveRule:
		return applyRemoveRule(cp, action)
	case RemAddMetadata:
		return applyAddMetadata(cp, action)
	case RemModifyRule:
		return nil, fmt.Errorf("modify_rule actions require manual review: %s", action.Description)
	case RemRestructure:
		return nil, fmt.Errorf("restructure actions require manual review: %s", action.Description)
	default:
		return nil, fmt.Errorf("unknown action type %q", action.Type)
	}
}

// applyAddRule adds a new deny/alert rule to the policy.
func applyAddRule(p *Policy, action RemediationAction) (*Policy, error) {
	// Parse the rule ID from the RuleAfter snippet.
	ruleID := extractRuleIDFromSnippet(action.RuleAfter)
	if ruleID == "" {
		ruleID = fmt.Sprintf("rem-%03d", len(p.Rules)+1)
	}

	// Check for duplicate rule IDs.
	for _, r := range p.Rules {
		if r.ID == ruleID {
			return p, nil // already present, no-op
		}
	}

	// Build a generic rule from the action context.
	newRule := buildRuleFromAction(action, ruleID)
	p.Rules = append(p.Rules, newRule)
	return p, nil
}

// applyRemoveRule removes a rule referenced in the action's Source.
func applyRemoveRule(p *Policy, action RemediationAction) (*Policy, error) {
	targetID := extractTargetRuleID(action)
	if targetID == "" {
		return p, nil // nothing to remove
	}

	var kept []Rule
	for _, r := range p.Rules {
		if r.ID != targetID {
			kept = append(kept, r)
		}
	}
	p.Rules = kept
	return p, nil
}

// applyAddMetadata fills in missing metadata fields.
func applyAddMetadata(p *Policy, action RemediationAction) (*Policy, error) {
	switch action.Source {
	case "lint:BP-001":
		if p.Meta.Description == "" {
			p.Meta.Description = "Tool-call policy for agent enforcement"
		}
	case "lint:BP-002":
		if len(p.Meta.Authors) == 0 {
			p.Meta.Authors = []string{"security-team"}
		}
	case "lint:BP-005":
		if p.Meta.Created == "" {
			p.Meta.Created = "2025-01-01"
		}
		if p.Meta.Modified == "" {
			p.Meta.Modified = "2025-01-01"
		}
	default:
		// Drift meta restoration — best effort.
		if p.Meta.Description == "" && action.RuleAfter != "" {
			p.Meta.Description = "restored from drift remediation"
		}
	}
	return p, nil
}

// ---------------------------------------------------------------------------
// FormatRemediationPlan — box-drawing formatted output
// ---------------------------------------------------------------------------

// FormatRemediationPlan formats a remediation plan as box-drawing output
// suitable for terminal display.
func FormatRemediationPlan(plan *RemediationPlan) string {
	if plan == nil {
		return "No remediation plan."
	}

	var b strings.Builder
	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString(fmt.Sprintf("│ Remediation Plan: %-33s │\n", remTruncate(plan.PolicyName, 33)))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Actions: %-3d  (C:%-2d H:%-2d M:%-2d L:%-2d)               │\n",
		plan.TotalActions, plan.CriticalCount, plan.HighCount,
		plan.MediumCount, plan.LowCount))
	b.WriteString(fmt.Sprintf("│ Auto-applicable: %-3d  Effort: %-10s            │\n",
		plan.AutoApplicableCount, plan.EstimatedEffort))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	if len(plan.Actions) == 0 {
		b.WriteString("│ ✓ No remediation actions needed                     │\n")
	}

	for _, a := range plan.Actions {
		icon := remPriorityIcon(a.Priority)
		auto := " "
		if a.AutoApplicable {
			auto = "⚡"
		}
		b.WriteString(fmt.Sprintf("│ %s %s %-5s [%-12s] %-21s │\n",
			icon, auto, a.ID, a.Type, remTruncate(a.Source, 21)))
		b.WriteString(fmt.Sprintf("│   %s │\n", remTruncate(a.Description, 49)))
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// finalizePlan numbers actions, computes counts, and estimates effort.
func finalizePlan(plan *RemediationPlan) {
	// Sort by priority (critical first).
	sortActions(plan.Actions)

	// Re-number.
	for i := range plan.Actions {
		plan.Actions[i].ID = fmt.Sprintf("REM-%03d", i+1)
	}

	// Counts.
	plan.TotalActions = len(plan.Actions)
	plan.CriticalCount = 0
	plan.HighCount = 0
	plan.MediumCount = 0
	plan.LowCount = 0
	plan.AutoApplicableCount = 0

	for _, a := range plan.Actions {
		switch a.Priority {
		case RemPriorityCritical:
			plan.CriticalCount++
		case RemPriorityHigh:
			plan.HighCount++
		case RemPriorityMedium:
			plan.MediumCount++
		case RemPriorityLow:
			plan.LowCount++
		}
		if a.AutoApplicable {
			plan.AutoApplicableCount++
		}
	}

	// Estimate effort.
	if plan.TotalActions == 0 {
		plan.EstimatedEffort = "minimal"
	} else if plan.CriticalCount > 0 || plan.TotalActions > 10 {
		plan.EstimatedEffort = "significant"
	} else if plan.HighCount > 0 || plan.TotalActions > 5 {
		plan.EstimatedEffort = "moderate"
	} else {
		plan.EstimatedEffort = "minimal"
	}
}

// sortActions sorts by priority descending (critical first).
func sortActions(actions []RemediationAction) {
	for i := 0; i < len(actions); i++ {
		for j := i + 1; j < len(actions); j++ {
			if priorityRank(actions[j].Priority) > priorityRank(actions[i].Priority) {
				actions[i], actions[j] = actions[j], actions[i]
			}
		}
	}
}

// copyPolicyDeep returns a deep copy of a policy. Used by both remediate and
// inherit to avoid mutating the original.
func copyPolicyDeep(p *Policy) *Policy {
	cp := *p
	cp.Rules = make([]Rule, len(p.Rules))
	for i, r := range p.Rules {
		cp.Rules[i] = r
		cp.Rules[i].Match.Tools = append([]string(nil), r.Match.Tools...)
		cp.Rules[i].Match.Tactics = append([]string(nil), r.Match.Tactics...)
		cp.Rules[i].Match.Actions = append([]string(nil), r.Match.Actions...)
		cp.Rules[i].Match.Targets = append([]string(nil), r.Match.Targets...)
		cp.Rules[i].Conditions = append([]Condition(nil), r.Conditions...)
	}
	cp.Meta.Authors = append([]string(nil), p.Meta.Authors...)
	cp.Agent.Tools = append([]string(nil), p.Agent.Tools...)
	return &cp
}

// extractRuleIDFromSnippet tries to find "id: xxx" in a YAML snippet.
func extractRuleIDFromSnippet(snippet string) string {
	for _, line := range strings.Split(snippet, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id:") || strings.HasPrefix(line, "- id:") {
			val := strings.TrimPrefix(line, "- id:")
			val = strings.TrimPrefix(val, "id:")
			val = strings.TrimSpace(val)
			return val
		}
	}
	return ""
}

// extractTargetRuleID gets the rule ID that a remove/modify action targets.
func extractTargetRuleID(a RemediationAction) string {
	// Try parsing from Source field — e.g. "lint:RED-001" doesn't carry it.
	// Try from RuleBefore.
	if id := extractRuleIDFromSnippet(a.RuleBefore); id != "" {
		return id
	}
	// Try from Description — "Remove duplicate rule xyz".
	desc := a.Description
	for _, prefix := range []string{
		"Remove duplicate rule ",
		"Remove shadowed rule ",
		"Remove unreachable rule ",
	} {
		if strings.HasPrefix(desc, prefix) {
			return strings.TrimPrefix(desc, prefix)
		}
	}
	return ""
}

// buildRuleFromAction creates a Rule struct from an add_rule action.
func buildRuleFromAction(a RemediationAction, ruleID string) Rule {
	effect := "alert"
	if strings.Contains(a.RuleAfter, "effect: deny") {
		effect = "deny"
	} else if strings.Contains(a.RuleAfter, "effect: allow") {
		effect = "allow"
	}

	// Extract tools from snippet if present.
	var tools []string
	for _, line := range strings.Split(a.RuleAfter, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "tools:") {
			inner := strings.TrimPrefix(line, "tools:")
			inner = strings.TrimSpace(inner)
			inner = strings.Trim(inner, "[]")
			for _, t := range strings.Split(inner, ",") {
				t = strings.TrimSpace(t)
				t = strings.Trim(t, "\"'")
				if t != "" {
					tools = append(tools, t)
				}
			}
		}
	}

	// Extract tactics from snippet if present.
	var tactics []string
	for _, line := range strings.Split(a.RuleAfter, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "tactics:") {
			inner := strings.TrimPrefix(line, "tactics:")
			inner = strings.TrimSpace(inner)
			inner = strings.Trim(inner, "[]")
			for _, t := range strings.Split(inner, ",") {
				t = strings.TrimSpace(t)
				t = strings.Trim(t, "\"'")
				if t != "" {
					tactics = append(tactics, t)
				}
			}
		}
	}

	return Rule{
		ID:          ruleID,
		Description: a.Description,
		Effect:      effect,
		Priority:    0,
		Match: RuleMatch{
			Tools:   tools,
			Tactics: tactics,
		},
	}
}

// remTruncate truncates a string to maxLen, appending "…" if needed.
func remTruncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 2 {
		return s[:maxLen]
	}
	return s[:maxLen-1] + "…"
}

// remPriorityIcon returns a severity icon for terminal display.
func remPriorityIcon(p RemediationPriority) string {
	switch p {
	case RemPriorityCritical:
		return "🔴"
	case RemPriorityHigh:
		return "🟠"
	case RemPriorityMedium:
		return "🟡"
	case RemPriorityLow:
		return "🔵"
	}
	return "⚪"
}
