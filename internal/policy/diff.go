// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"sort"
	"strings"
)

// PolicyDiff represents the differences between two policies.
type PolicyDiff struct {
	OldName       string       `json:"old_name"`
	NewName       string       `json:"new_name"`
	AddedRules    []Rule       `json:"added_rules"`
	RemovedRules  []Rule       `json:"removed_rules"`
	ModifiedRules []RuleChange `json:"modified_rules"`
	ScopeChanged  bool         `json:"scope_changed"`
	OldScope      *AgentScope  `json:"old_scope,omitempty"`
	NewScope      *AgentScope  `json:"new_scope,omitempty"`
	Summary       DiffSummary  `json:"summary"`
}

// RuleChange describes how a single rule was modified.
type RuleChange struct {
	RuleID  string      `json:"rule_id"`
	OldRule Rule        `json:"old_rule"`
	NewRule Rule        `json:"new_rule"`
	Changes []FieldDiff `json:"changes"`
}

// FieldDiff describes a change to one field of a rule.
type FieldDiff struct {
	Field    string `json:"field"` // e.g. "effect", "priority", "match.tools"
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
}

// DiffSummary gives aggregate stats about the diff.
type DiffSummary struct {
	TotalChanges    int  `json:"total_changes"`
	RulesAdded      int  `json:"rules_added"`
	RulesRemoved    int  `json:"rules_removed"`
	RulesModified   int  `json:"rules_modified"`
	EffectChanges   int  `json:"effect_changes"` // deny→allow or vice versa
	PriorityChanges int  `json:"priority_changes"`
	BreakingChanges int  `json:"breaking_changes"` // changes that weaken security
	IsIdentical     bool `json:"is_identical"`
}

// DiffPolicies compares two policies and returns their differences.
// Rules are matched by ID.
func DiffPolicies(old, new *Policy) *PolicyDiff {
	d := &PolicyDiff{}

	if old == nil && new == nil {
		d.Summary.IsIdentical = true
		return d
	}
	if old == nil {
		old = &Policy{}
	}
	if new == nil {
		new = &Policy{}
	}

	d.OldName = old.Meta.Name
	d.NewName = new.Meta.Name

	// Check scope changes.
	if old.Agent.Name != new.Agent.Name ||
		old.Agent.Type != new.Agent.Type ||
		!stringSliceEqual(old.Agent.Tools, new.Agent.Tools) {
		d.ScopeChanged = true
		oldScope := old.Agent
		newScope := new.Agent
		d.OldScope = &oldScope
		d.NewScope = &newScope
	}

	// Index old and new rules by ID.
	oldByID := make(map[string]Rule, len(old.Rules))
	for _, r := range old.Rules {
		oldByID[r.ID] = r
	}
	newByID := make(map[string]Rule, len(new.Rules))
	for _, r := range new.Rules {
		newByID[r.ID] = r
	}

	// Added rules: in new but not in old.
	for _, r := range new.Rules {
		if _, exists := oldByID[r.ID]; !exists {
			d.AddedRules = append(d.AddedRules, r)
		}
	}

	// Removed rules: in old but not in new.
	for _, r := range old.Rules {
		if _, exists := newByID[r.ID]; !exists {
			d.RemovedRules = append(d.RemovedRules, r)
		}
	}

	// Modified rules: same ID, different content.
	for _, oldRule := range old.Rules {
		newRule, exists := newByID[oldRule.ID]
		if !exists {
			continue
		}
		changes := diffRule(oldRule, newRule)
		if len(changes) > 0 {
			d.ModifiedRules = append(d.ModifiedRules, RuleChange{
				RuleID:  oldRule.ID,
				OldRule: oldRule,
				NewRule: newRule,
				Changes: changes,
			})
		}
	}

	// Build summary.
	d.Summary = buildSummary(d)

	return d
}

// diffRule compares two rules with the same ID and returns field-level diffs.
func diffRule(old, new Rule) []FieldDiff {
	var diffs []FieldDiff

	if old.Description != new.Description {
		diffs = append(diffs, FieldDiff{
			Field:    "description",
			OldValue: old.Description,
			NewValue: new.Description,
		})
	}

	if old.Effect != new.Effect {
		diffs = append(diffs, FieldDiff{
			Field:    "effect",
			OldValue: old.Effect,
			NewValue: new.Effect,
		})
	}

	if old.Priority != new.Priority {
		diffs = append(diffs, FieldDiff{
			Field:    "priority",
			OldValue: fmt.Sprintf("%d", old.Priority),
			NewValue: fmt.Sprintf("%d", new.Priority),
		})
	}

	if !stringSliceEqual(old.Match.Tools, new.Match.Tools) {
		diffs = append(diffs, FieldDiff{
			Field:    "match.tools",
			OldValue: strings.Join(old.Match.Tools, ", "),
			NewValue: strings.Join(new.Match.Tools, ", "),
		})
	}

	if !stringSliceEqual(old.Match.Tactics, new.Match.Tactics) {
		diffs = append(diffs, FieldDiff{
			Field:    "match.tactics",
			OldValue: strings.Join(old.Match.Tactics, ", "),
			NewValue: strings.Join(new.Match.Tactics, ", "),
		})
	}

	if !stringSliceEqual(old.Match.Actions, new.Match.Actions) {
		diffs = append(diffs, FieldDiff{
			Field:    "match.actions",
			OldValue: strings.Join(old.Match.Actions, ", "),
			NewValue: strings.Join(new.Match.Actions, ", "),
		})
	}

	if !stringSliceEqual(old.Match.Targets, new.Match.Targets) {
		diffs = append(diffs, FieldDiff{
			Field:    "match.targets",
			OldValue: strings.Join(old.Match.Targets, ", "),
			NewValue: strings.Join(new.Match.Targets, ", "),
		})
	}

	if !conditionsEqual(old.Conditions, new.Conditions) {
		diffs = append(diffs, FieldDiff{
			Field:    "conditions",
			OldValue: formatConditions(old.Conditions),
			NewValue: formatConditions(new.Conditions),
		})
	}

	return diffs
}

// buildSummary computes aggregate statistics from a PolicyDiff.
func buildSummary(d *PolicyDiff) DiffSummary {
	s := DiffSummary{
		RulesAdded:    len(d.AddedRules),
		RulesRemoved:  len(d.RemovedRules),
		RulesModified: len(d.ModifiedRules),
	}

	s.TotalChanges = s.RulesAdded + s.RulesRemoved + s.RulesModified

	// Count effect and priority changes within modified rules.
	for _, mc := range d.ModifiedRules {
		for _, fc := range mc.Changes {
			switch fc.Field {
			case "effect":
				s.EffectChanges++
			case "priority":
				s.PriorityChanges++
			}
		}
	}

	// Count breaking changes.
	s.BreakingChanges = countBreakingChanges(d)

	s.IsIdentical = s.TotalChanges == 0 && !d.ScopeChanged

	return s
}

// countBreakingChanges counts changes that weaken security posture.
// A breaking change is:
//   - Removing a deny rule
//   - Changing a rule's effect from deny to allow
//   - Lowering the priority of a deny rule
//   - Removing tools from a deny rule's match
func countBreakingChanges(d *PolicyDiff) int {
	count := 0

	// Removing a deny rule is breaking.
	for _, r := range d.RemovedRules {
		if r.Effect == "deny" {
			count++
		}
	}

	// Modified rules: check for security-weakening changes.
	for _, mc := range d.ModifiedRules {
		if isBreakingModification(mc) {
			count++
		}
	}

	return count
}

// isBreakingModification checks if a rule modification weakens security.
func isBreakingModification(mc RuleChange) bool {
	for _, fc := range mc.Changes {
		switch fc.Field {
		case "effect":
			// deny → allow is breaking.
			if fc.OldValue == "deny" && fc.NewValue == "allow" {
				return true
			}
		case "priority":
			// Lowering priority of a deny rule is breaking.
			if mc.OldRule.Effect == "deny" && mc.NewRule.Effect == "deny" {
				if mc.NewRule.Priority < mc.OldRule.Priority {
					return true
				}
			}
		case "match.tools":
			// Removing tools from a deny rule's match is breaking
			// (narrows what the deny covers).
			if mc.OldRule.Effect == "deny" && mc.NewRule.Effect == "deny" {
				if isSubsetRemoved(mc.OldRule.Match.Tools, mc.NewRule.Match.Tools) {
					return true
				}
			}
		}
	}
	return false
}

// isSubsetRemoved returns true if newItems is missing items that were in oldItems.
func isSubsetRemoved(oldItems, newItems []string) bool {
	newSet := make(map[string]bool, len(newItems))
	for _, item := range newItems {
		newSet[item] = true
	}
	for _, item := range oldItems {
		if !newSet[item] {
			return true
		}
	}
	return false
}

// stringSliceEqual compares two string slices for equality.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// conditionsEqual compares two condition slices for equality.
func conditionsEqual(a, b []Condition) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Field != b[i].Field ||
			a[i].Operator != b[i].Operator ||
			a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}

// formatConditions returns a human-readable representation of conditions.
func formatConditions(conds []Condition) string {
	if len(conds) == 0 {
		return "(none)"
	}
	parts := make([]string, len(conds))
	for i, c := range conds {
		parts[i] = fmt.Sprintf("%s %s %s", c.Field, c.Operator, c.Value)
	}
	return strings.Join(parts, "; ")
}

// FormatPolicyDiff returns a box-drawing formatted diff report.
func FormatPolicyDiff(d *PolicyDiff) string {
	var b strings.Builder

	// Header.
	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│ Policy Diff                                         │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	if d.OldName != d.NewName {
		b.WriteString(fmt.Sprintf("│ %-20s → %-28s │\n", d.OldName, d.NewName))
	} else {
		b.WriteString(fmt.Sprintf("│ %-51s │\n", d.OldName))
	}
	b.WriteString("└─────────────────────────────────────────────────────┘\n")

	// Identical check.
	if d.Summary.IsIdentical {
		b.WriteString("\n  Policies are identical. No changes detected.\n")
		return b.String()
	}

	// Summary line.
	b.WriteString("\n")
	summaryParts := []string{}
	if d.Summary.RulesAdded > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d added", d.Summary.RulesAdded))
	}
	if d.Summary.RulesRemoved > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("%d removed", d.Summary.RulesRemoved))
	}
	if d.Summary.RulesModified > 0 {
		modStr := fmt.Sprintf("%d modified", d.Summary.RulesModified)
		if d.Summary.BreakingChanges > 0 {
			modStr += fmt.Sprintf(" (%d breaking)", d.Summary.BreakingChanges)
		}
		summaryParts = append(summaryParts, modStr)
	}
	b.WriteString("  Summary: " + strings.Join(summaryParts, ", ") + "\n")

	// Scope changes.
	if d.ScopeChanged {
		b.WriteString("\n  Scope Changed:\n")
		if d.OldScope != nil && d.NewScope != nil {
			if d.OldScope.Name != d.NewScope.Name {
				b.WriteString(fmt.Sprintf("    agent.name: %q → %q\n", d.OldScope.Name, d.NewScope.Name))
			}
			if d.OldScope.Type != d.NewScope.Type {
				b.WriteString(fmt.Sprintf("    agent.type: %q → %q\n", d.OldScope.Type, d.NewScope.Type))
			}
			if !stringSliceEqual(d.OldScope.Tools, d.NewScope.Tools) {
				b.WriteString(fmt.Sprintf("    agent.tools: [%s] → [%s]\n",
					strings.Join(d.OldScope.Tools, ", "),
					strings.Join(d.NewScope.Tools, ", ")))
			}
		}
	}

	// Added rules.
	if len(d.AddedRules) > 0 {
		b.WriteString("\n  Added Rules:\n")
		for _, r := range d.AddedRules {
			b.WriteString(fmt.Sprintf("    + %s (%s, priority %d)\n", r.ID, r.Effect, r.Priority))
			if len(r.Match.Tools) > 0 {
				b.WriteString(fmt.Sprintf("      tools: %s\n", strings.Join(r.Match.Tools, ", ")))
			}
		}
	}

	// Removed rules.
	if len(d.RemovedRules) > 0 {
		b.WriteString("\n  Removed Rules:\n")
		for _, r := range d.RemovedRules {
			prefix := "    - "
			if r.Effect == "deny" {
				prefix = "    ⚠ - "
			}
			b.WriteString(fmt.Sprintf("%s%s (%s, priority %d)\n", prefix, r.ID, r.Effect, r.Priority))
		}
	}

	// Modified rules.
	if len(d.ModifiedRules) > 0 {
		b.WriteString("\n  Modified Rules:\n")
		for _, mc := range d.ModifiedRules {
			breaking := isBreakingModification(mc)
			prefix := "    ~ "
			if breaking {
				prefix = "    ⚠ ~ "
			}
			b.WriteString(fmt.Sprintf("%s%s\n", prefix, mc.RuleID))
			// Sort changes by field name for deterministic output.
			sorted := make([]FieldDiff, len(mc.Changes))
			copy(sorted, mc.Changes)
			sort.Slice(sorted, func(i, j int) bool {
				return sorted[i].Field < sorted[j].Field
			})
			for _, fc := range sorted {
				b.WriteString(fmt.Sprintf("        %s: %q → %q\n", fc.Field, fc.OldValue, fc.NewValue))
			}
		}
	}

	return b.String()
}
