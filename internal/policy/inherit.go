// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// PolicyChain is an ordered list of policies from base to most specific.
// Rules are resolved bottom-up: the most specific matching rule wins.
type PolicyChain struct {
	Policies  []*Policy
	Resolved  *Policy    // the flattened result
	Lineage   []string   // policy names from base to leaf
	Overrides []Override // which rules were overridden and by what
}

// Override records when a child rule overrides a parent rule.
type Override struct {
	ParentPolicy string `json:"parent_policy"`
	ParentRule   string `json:"parent_rule"` // rule ID
	ChildPolicy  string `json:"child_policy"`
	ChildRule    string `json:"child_rule"` // rule ID
	Dimension    string `json:"dimension"`  // what matched: "id", "tool", "tactic", "action", "target"
	Effect       string `json:"effect"`     // what changed: "deny→allow", "allow→deny", "alert→deny", etc
}

// InheritanceError represents a problem in the inheritance chain.
type InheritanceError struct {
	Policy  string
	Message string
}

// Error implements the error interface.
func (e *InheritanceError) Error() string {
	if e.Policy == "" {
		return e.Message
	}
	return fmt.Sprintf("policy %q: %s", e.Policy, e.Message)
}

// ---------------------------------------------------------------------------
// Extends registry
// ---------------------------------------------------------------------------
//
// The base Policy struct does not carry an extends field. Rather than modify
// the existing type, inheritance relationships are tracked in a package-level
// registry. In production code the policy loader populates this when it
// encounters an `extends:` key in the YAML. Tests call RegisterExtends
// directly.

// extendsRegistry maps child policy names to their parent policy names.
var extendsRegistry = make(map[string]string)

// RegisterExtends declares that childPolicy extends parentPolicy.
func RegisterExtends(childPolicy, parentPolicy string) {
	extendsRegistry[childPolicy] = parentPolicy
}

// ClearExtends removes all registered extends relationships.
func ClearExtends() {
	extendsRegistry = make(map[string]string)
}

// GetExtends returns the parent policy name for the given policy, or empty
// string if no extends relationship is registered.
func GetExtends(policyName string) string {
	return extendsRegistry[policyName]
}

// ---------------------------------------------------------------------------
// Chain construction
// ---------------------------------------------------------------------------

// BuildChain recursively resolves extends references, building the chain
// from base to leaf. The loader function is called to load parent policies
// by name. Detects circular inheritance and missing parents.
//
// The returned PolicyChain has Policies ordered from base (index 0) to leaf
// (last index), Lineage listing the policy names in the same order,
// Overrides populated from consecutive layer comparisons, and Resolved
// containing the fully flattened policy.
func BuildChain(leaf *Policy, loader func(name string) (*Policy, error)) (*PolicyChain, error) {
	if leaf == nil {
		return nil, fmt.Errorf("leaf policy is nil")
	}

	// Walk from leaf towards base following extends references.
	var stack []*Policy
	seen := make(map[string]bool)
	var visited []string
	current := leaf

	for {
		name := current.Meta.Name
		if seen[name] {
			// We've seen this name already — cycle detected.
			visited = append(visited, name)
			return nil, fmt.Errorf("circular inheritance detected: %s",
				strings.Join(visited, " → "))
		}
		seen[name] = true
		visited = append(visited, name)
		stack = append(stack, current)

		parentName := GetExtends(name)
		if parentName == "" {
			break // no parent — this is the base
		}

		parent, err := loader(parentName)
		if err != nil {
			return nil, fmt.Errorf("loading parent policy %q for %q: %w",
				parentName, name, err)
		}
		if parent == nil {
			return nil, fmt.Errorf("parent policy %q not found (referenced by %q)",
				parentName, name)
		}

		current = parent
	}

	// Reverse stack so the base is first and leaf is last.
	policies := make([]*Policy, len(stack))
	for i, p := range stack {
		policies[len(stack)-1-i] = p
	}

	chain := &PolicyChain{
		Policies: policies,
	}

	// Build lineage from base to leaf.
	for _, p := range policies {
		chain.Lineage = append(chain.Lineage, p.Meta.Name)
	}

	// Detect overrides between consecutive layers.
	for i := 0; i < len(policies)-1; i++ {
		overrides := DetectOverrides(policies[i], policies[i+1])
		chain.Overrides = append(chain.Overrides, overrides...)
	}

	// Resolve the chain into a single flattened policy.
	chain.Resolved = ResolveChain(policies)

	return chain, nil
}

// ---------------------------------------------------------------------------
// Chain resolution
// ---------------------------------------------------------------------------

// ResolveChain flattens a policy chain into a single resolved policy.
// Policies must be ordered from base to leaf (most specific last).
//
// Resolution rules:
//  1. Child rules with the same ID as a parent rule fully replace it.
//  2. Child rules with overlapping scope but different IDs override it.
//  3. Parent rules not matched by any child rule are inherited as-is.
//  4. Meta fields: child name/description/authors/dates win if set.
//  5. Agent scope: child wins if its name field is set.
//  6. Default effect: the parent's implicit default (no matching rule = allow)
//     carries through; the child can override it by adding explicit rules.
func ResolveChain(chain []*Policy) *Policy {
	if len(chain) == 0 {
		return &Policy{
			APIVersion: "v1",
			Kind:       "Policy",
		}
	}

	if len(chain) == 1 {
		return copyPolicyDeep(chain[0])
	}

	// Start with a copy of the base and layer each child on top.
	resolved := copyPolicyDeep(chain[0])
	for i := 1; i < len(chain); i++ {
		resolved = mergeChild(resolved, chain[i])
	}

	return resolved
}

// copyPolicy creates a deep copy of a policy. Delegates to copyPolicyDeep
// in remediate.go.
func copyPolicy(p *Policy) *Policy {
	return copyPolicyDeep(p)
}

// mergeChild applies a child policy on top of a parent policy, returning
// the merged result. The parent's rules that are not overridden (by ID or
// scope overlap) are preserved; all child rules are included.
func mergeChild(parent, child *Policy) *Policy {
	result := &Policy{
		APIVersion: parent.APIVersion,
		Kind:       parent.Kind,
		Meta:       parent.Meta,
		Agent:      parent.Agent,
	}

	// Child meta fields win when set.
	if child.Meta.Name != "" {
		result.Meta.Name = child.Meta.Name
	}
	if child.Meta.Description != "" {
		result.Meta.Description = child.Meta.Description
	}
	if len(child.Meta.Authors) > 0 {
		result.Meta.Authors = child.Meta.Authors
	}
	if child.Meta.Created != "" {
		result.Meta.Created = child.Meta.Created
	}
	if child.Meta.Modified != "" {
		result.Meta.Modified = child.Meta.Modified
	}

	// Child agent wins if its name is set.
	if child.Agent.Name != "" {
		result.Agent = child.Agent
	}

	// Build a set of child rule IDs for fast lookup.
	childRuleIDs := make(map[string]bool)
	for _, r := range child.Rules {
		childRuleIDs[r.ID] = true
	}

	// Collect parent rules that are NOT overridden by any child rule.
	var inherited []Rule
	for _, pr := range parent.Rules {
		// Overridden by same ID?
		if childRuleIDs[pr.ID] {
			continue
		}

		// Overridden by scope overlap?
		overridden := false
		for i := range child.Rules {
			if rulesOverlap(&pr, &child.Rules[i]) {
				overridden = true
				break
			}
		}
		if overridden {
			continue
		}

		inherited = append(inherited, pr)
	}

	// Final rule set: inherited parent rules + all child rules.
	result.Rules = append(inherited, child.Rules...)

	return result
}

// ---------------------------------------------------------------------------
// Override detection
// ---------------------------------------------------------------------------

// DetectOverrides finds which child rules override parent rules.
// Returns one Override entry per parent–child rule pair that represents
// an override, either by matching ID or by overlapping scope.
func DetectOverrides(parent, child *Policy) []Override {
	if parent == nil || child == nil {
		return nil
	}

	var overrides []Override
	seen := make(map[string]bool)

	for i := range child.Rules {
		cr := &child.Rules[i]
		for j := range parent.Rules {
			pr := &parent.Rules[j]

			// Deduplicate: each parent–child pair recorded at most once.
			key := pr.ID + "\x00" + cr.ID
			if seen[key] {
				continue
			}

			// Same ID = explicit override.
			if cr.ID == pr.ID {
				seen[key] = true
				overrides = append(overrides, Override{
					ParentPolicy: parent.Meta.Name,
					ParentRule:   pr.ID,
					ChildPolicy:  child.Meta.Name,
					ChildRule:    cr.ID,
					Dimension:    "id",
					Effect:       formatEffect(pr.Effect, cr.Effect),
				})
				continue
			}

			// Different IDs but overlapping scope.
			if rulesOverlap(pr, cr) {
				seen[key] = true
				dim := overlapDimension(pr, cr)
				overrides = append(overrides, Override{
					ParentPolicy: parent.Meta.Name,
					ParentRule:   pr.ID,
					ChildPolicy:  child.Meta.Name,
					ChildRule:    cr.ID,
					Dimension:    dim,
					Effect:       formatEffect(pr.Effect, cr.Effect),
				})
			}
		}
	}

	return overrides
}

// formatEffect returns a human-readable effect transition string.
// Same effects produce "deny (unchanged)"; different effects produce
// "deny→allow".
func formatEffect(parentEffect, childEffect string) string {
	if parentEffect == childEffect {
		return parentEffect + " (unchanged)"
	}
	return parentEffect + "→" + childEffect
}

// ---------------------------------------------------------------------------
// Rule overlap detection
// ---------------------------------------------------------------------------

// rulesOverlap determines if two rules target the same scope. Two rules
// overlap if they share at least one matching dimension (tools, tactics,
// actions, or targets) where the values intersect. Tool and target
// comparisons use glob matching via patternsOverlap; tactic and action
// comparisons use exact string matching.
func rulesOverlap(a, b *Rule) bool {
	// Tool dimension.
	for _, at := range a.Match.Tools {
		for _, bt := range b.Match.Tools {
			if patternsOverlap(at, bt) {
				return true
			}
		}
	}

	// Tactic dimension.
	for _, at := range a.Match.Tactics {
		for _, bt := range b.Match.Tactics {
			if at == bt {
				return true
			}
		}
	}

	// Action dimension.
	for _, aa := range a.Match.Actions {
		for _, ba := range b.Match.Actions {
			if aa == ba {
				return true
			}
		}
	}

	// Target dimension.
	for _, at := range a.Match.Targets {
		for _, bt := range b.Match.Targets {
			if patternsOverlap(at, bt) {
				return true
			}
		}
	}

	return false
}

// overlapDimension returns the first dimension where two rules overlap.
// Returns "unknown" if no overlap is detected (should not happen when
// called after rulesOverlap returned true).
func overlapDimension(a, b *Rule) string {
	for _, at := range a.Match.Tools {
		for _, bt := range b.Match.Tools {
			if patternsOverlap(at, bt) {
				return "tool"
			}
		}
	}
	for _, at := range a.Match.Tactics {
		for _, bt := range b.Match.Tactics {
			if at == bt {
				return "tactic"
			}
		}
	}
	for _, aa := range a.Match.Actions {
		for _, ba := range b.Match.Actions {
			if aa == ba {
				return "action"
			}
		}
	}
	for _, at := range a.Match.Targets {
		for _, bt := range b.Match.Targets {
			if patternsOverlap(at, bt) {
				return "target"
			}
		}
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatChain renders a box-drawing report showing the inheritance chain,
// overrides, and final resolved rule count. Follows the same visual style
// as FormatCompileResult in compiler.go.
func FormatChain(chain *PolicyChain) string {
	if chain == nil {
		return "No inheritance chain.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────┐\n")
	b.WriteString("│       Policy Inheritance Chain               │\n")
	b.WriteString("├─────────────────────────────────────────────┤\n")

	// Lineage with tree connectors.
	b.WriteString("│ Lineage:                                    │\n")
	for i, name := range chain.Lineage {
		connector := "  ├─"
		if i == len(chain.Lineage)-1 {
			connector = "  └─"
		}
		label := name
		if i == 0 && len(chain.Lineage) > 1 {
			label += " (base)"
		}
		if i == len(chain.Lineage)-1 && len(chain.Lineage) > 1 {
			label += " (leaf)"
		}
		if len(label) > 38 {
			label = label[:35] + "..."
		}
		b.WriteString(fmt.Sprintf("│ %s %-38s│\n", connector, label))
	}

	// Metrics.
	b.WriteString("├─────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Layers:    %-33d│\n", len(chain.Policies)))

	totalRules := 0
	for _, p := range chain.Policies {
		totalRules += len(p.Rules)
	}
	b.WriteString(fmt.Sprintf("│ Total Rules (all layers): %-18d│\n", totalRules))

	if chain.Resolved != nil {
		b.WriteString(fmt.Sprintf("│ Resolved Rules:           %-18d│\n",
			len(chain.Resolved.Rules)))
	}

	// Per-layer breakdown.
	if len(chain.Policies) > 1 {
		b.WriteString("├─────────────────────────────────────────────┤\n")
		b.WriteString("│ Per Layer:                                  │\n")
		for _, p := range chain.Policies {
			name := p.Meta.Name
			if len(name) > 25 {
				name = name[:22] + "..."
			}
			b.WriteString(fmt.Sprintf("│   %-27s %2d rules    │\n",
				name, len(p.Rules)))
		}
	}

	// Overrides.
	if len(chain.Overrides) > 0 {
		b.WriteString("├─────────────────────────────────────────────┤\n")
		b.WriteString(fmt.Sprintf("│ Overrides: %-33d│\n", len(chain.Overrides)))
		for i, o := range chain.Overrides {
			if i >= 8 {
				remaining := len(chain.Overrides) - 8
				msg := fmt.Sprintf("... and %d more", remaining)
				b.WriteString(fmt.Sprintf("│   %-41s│\n", msg))
				break
			}
			desc := fmt.Sprintf("%s → %s [%s]", o.ParentRule, o.ChildRule, o.Effect)
			runeLen := len([]rune(desc))
			if runeLen > 39 {
				runes := []rune(desc)
				desc = string(runes[:36]) + "..."
			}
			b.WriteString(fmt.Sprintf("│   • %-39s│\n", desc))
		}
	} else {
		b.WriteString("├─────────────────────────────────────────────┤\n")
		b.WriteString("│ No overrides                                │\n")
	}

	b.WriteString("└─────────────────────────────────────────────┘\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// ValidateChain validates the chain for issues: conflicting overrides,
// duplicate rule IDs in the resolved output, missing policy names, and
// structural problems. Returns an empty slice when the chain is valid.
func ValidateChain(chain *PolicyChain) []InheritanceError {
	if chain == nil {
		return []InheritanceError{{Policy: "", Message: "chain is nil"}}
	}

	var errs []InheritanceError

	if len(chain.Policies) == 0 {
		errs = append(errs, InheritanceError{
			Policy:  "",
			Message: "chain has no policies",
		})
		return errs
	}

	// Every policy in the chain must have a name.
	for i, p := range chain.Policies {
		if p.Meta.Name == "" {
			errs = append(errs, InheritanceError{
				Policy:  fmt.Sprintf("(unnamed at index %d)", i),
				Message: "policy in chain has no name",
			})
		}
	}

	// Check for conflicting overrides: the same parent rule overridden by
	// multiple child rules with different effect transitions.
	parentRuleOverrides := make(map[string][]Override)
	for _, o := range chain.Overrides {
		key := o.ParentPolicy + "\x00" + o.ParentRule
		parentRuleOverrides[key] = append(parentRuleOverrides[key], o)
	}
	for _, overrides := range parentRuleOverrides {
		if len(overrides) <= 1 {
			continue
		}
		effects := make(map[string]bool)
		for _, o := range overrides {
			effects[o.Effect] = true
		}
		if len(effects) > 1 {
			var effectList []string
			for e := range effects {
				effectList = append(effectList, e)
			}
			errs = append(errs, InheritanceError{
				Policy: overrides[0].ChildPolicy,
				Message: fmt.Sprintf(
					"parent rule %q from %q has conflicting overrides: %s",
					overrides[0].ParentRule,
					overrides[0].ParentPolicy,
					strings.Join(effectList, ", "),
				),
			})
		}
	}

	// Check resolved policy for duplicate rule IDs.
	if chain.Resolved != nil {
		idSeen := make(map[string]bool)
		for _, r := range chain.Resolved.Rules {
			if idSeen[r.ID] {
				errs = append(errs, InheritanceError{
					Policy:  chain.Resolved.Meta.Name,
					Message: fmt.Sprintf("duplicate rule ID %q in resolved policy", r.ID),
				})
			}
			idSeen[r.ID] = true
		}
	}

	// Lineage must match the policy count.
	if len(chain.Lineage) != len(chain.Policies) {
		errs = append(errs, InheritanceError{
			Policy: "",
			Message: fmt.Sprintf("lineage length (%d) does not match policy count (%d)",
				len(chain.Lineage), len(chain.Policies)),
		})
	}

	return errs
}
