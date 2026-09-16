// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Baseline is a point-in-time snapshot of the security posture. It captures
// all policies, agents, their relationships, lint scores, and coverage
// state so that future changes can be detected and assessed.
type Baseline struct {
	ID          string           `json:"id"`
	Label       string           `json:"label,omitempty"`
	CreatedAt   string           `json:"created_at"`
	Fingerprint string           `json:"fingerprint"` // SHA-256 of the canonical snapshot
	Policies    []BaselinePolicy `json:"policies"`
	Agents      []BaselineAgent  `json:"agents"`
	Summary     BaselineSummary  `json:"summary"`
}

// BaselinePolicy captures the state of a single policy at baseline time.
type BaselinePolicy struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	RuleCount  int      `json:"rule_count"`
	LintScore  float64  `json:"lint_score"`
	LintGrade  string   `json:"lint_grade"`
	DenyRules  int      `json:"deny_rules"`
	AlertRules int      `json:"alert_rules"`
	AllowRules int      `json:"allow_rules"`
	Tools      []string `json:"tools,omitempty"`   // unique tool patterns
	Tactics    []string `json:"tactics,omitempty"` // unique tactics covered
	Hash       string   `json:"hash"`              // SHA-256 of serialized policy
}

// BaselineAgent captures the state of a single agent at baseline time.
type BaselineAgent struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	TrustLevel  string   `json:"trust_level"`
	ToolCount   int      `json:"tool_count"`
	Tools       []string `json:"tools"`
	Delegations []string `json:"delegations,omitempty"`
	Hash        string   `json:"hash"`
}

// BaselineSummary provides aggregate metrics for the baseline.
type BaselineSummary struct {
	TotalPolicies  int     `json:"total_policies"`
	TotalAgents    int     `json:"total_agents"`
	TotalRules     int     `json:"total_rules"`
	TotalDenyRules int     `json:"total_deny_rules"`
	AvgLintScore   float64 `json:"avg_lint_score"`
	AvgLintGrade   string  `json:"avg_lint_grade"`
}

// BaselineDiff compares two baselines and identifies changes.
type BaselineDiff struct {
	Before    *Baseline        `json:"before"`
	After     *Baseline        `json:"after"`
	Changes   []BaselineChange `json:"changes"`
	RiskDelta float64          `json:"risk_delta"` // positive = riskier
	Verdict   string           `json:"verdict"`    // improved, degraded, stable, mixed
	Summary   string           `json:"summary"`
}

// BaselineChange records a single change between two baselines.
type BaselineChange struct {
	Category    string `json:"category"` // policy_added, policy_removed, policy_modified, agent_added, agent_removed, agent_modified, score_change
	Severity    string `json:"severity"` // critical, high, medium, low, info
	Entity      string `json:"entity"`   // policy or agent name
	Description string `json:"description"`
	Before      string `json:"before,omitempty"`
	After       string `json:"after,omitempty"`
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

// CaptureBaseline takes a snapshot of the current deployment state.
func CaptureBaseline(policies []*policy.Policy, inv *agent.Inventory, label string) *Baseline {
	b := &Baseline{
		Label:     label,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Snapshot policies.
	for _, p := range policies {
		bp := snapshotPolicy(p)
		b.Policies = append(b.Policies, bp)
	}
	sort.Slice(b.Policies, func(i, j int) bool {
		return b.Policies[i].Name < b.Policies[j].Name
	})

	// Snapshot agents.
	if inv != nil {
		for _, a := range inv.Agents {
			ba := snapshotAgent(a)
			b.Agents = append(b.Agents, ba)
		}
		sort.Slice(b.Agents, func(i, j int) bool {
			return b.Agents[i].Name < b.Agents[j].Name
		})
	}

	// Compute summary.
	b.Summary = computeBaselineSummary(b)

	// Compute fingerprint.
	b.Fingerprint = computeBaselineFingerprint(b)
	b.ID = b.Fingerprint[:12]

	return b
}

func snapshotPolicy(p *policy.Policy) BaselinePolicy {
	bp := BaselinePolicy{
		Name:      p.Meta.Name,
		RuleCount: len(p.Rules),
	}

	// Lint.
	lr := policy.LintPolicy(p)
	bp.LintScore = lr.Score
	bp.LintGrade = lr.Grade

	// Count rule effects and collect tools/tactics.
	toolSet := make(map[string]bool)
	tacticSet := make(map[string]bool)
	for _, r := range p.Rules {
		switch r.Effect {
		case "deny":
			bp.DenyRules++
		case "alert":
			bp.AlertRules++
		case "allow":
			bp.AllowRules++
		}
		for _, t := range r.Match.Tools {
			toolSet[t] = true
		}
		for _, t := range r.Match.Tactics {
			tacticSet[t] = true
		}
	}
	for t := range toolSet {
		bp.Tools = append(bp.Tools, t)
	}
	sort.Strings(bp.Tools)
	for t := range tacticSet {
		bp.Tactics = append(bp.Tactics, t)
	}
	sort.Strings(bp.Tactics)

	// Hash.
	data, _ := json.Marshal(p)
	h := sha256.Sum256(data)
	bp.Hash = fmt.Sprintf("%x", h[:8])

	return bp
}

func snapshotAgent(a *agent.Agent) BaselineAgent {
	ba := BaselineAgent{
		Name:       a.Meta.Name,
		Type:       a.Meta.Type,
		TrustLevel: a.Trust.Level,
		ToolCount:  len(a.Tools),
	}
	for _, t := range a.Tools {
		ba.Tools = append(ba.Tools, t.Name)
	}
	sort.Strings(ba.Tools)

	for _, d := range a.Trust.TrustsFrom {
		ba.Delegations = append(ba.Delegations, d)
	}
	sort.Strings(ba.Delegations)

	data, _ := json.Marshal(a)
	h := sha256.Sum256(data)
	ba.Hash = fmt.Sprintf("%x", h[:8])

	return ba
}

func computeBaselineSummary(b *Baseline) BaselineSummary {
	s := BaselineSummary{
		TotalPolicies: len(b.Policies),
		TotalAgents:   len(b.Agents),
	}

	var totalScore float64
	for _, p := range b.Policies {
		s.TotalRules += p.RuleCount
		s.TotalDenyRules += p.DenyRules
		totalScore += p.LintScore
	}
	if s.TotalPolicies > 0 {
		s.AvgLintScore = totalScore / float64(s.TotalPolicies)
	}
	s.AvgLintGrade = scoreToGrade(s.AvgLintScore * 100)

	return s
}

func scoreToGrade(score float64) string {
	switch {
	case score >= 95:
		return "A"
	case score >= 85:
		return "B"
	case score >= 70:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

func computeBaselineFingerprint(b *Baseline) string {
	// Canonical representation: sorted policies + agents hashes.
	var parts []string
	for _, p := range b.Policies {
		parts = append(parts, fmt.Sprintf("p:%s:%s", p.Name, p.Hash))
	}
	for _, a := range b.Agents {
		parts = append(parts, fmt.Sprintf("a:%s:%s", a.Name, a.Hash))
	}
	sort.Strings(parts)
	data := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h)
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

// DiffBaselines compares two baselines and identifies all changes.
func DiffBaselines(before, after *Baseline) *BaselineDiff {
	diff := &BaselineDiff{
		Before: before,
		After:  after,
	}

	if before.Fingerprint == after.Fingerprint {
		diff.Verdict = "stable"
		diff.Summary = "No changes detected between baselines."
		return diff
	}

	// Index policies.
	beforePolicies := indexPolicies(before.Policies)
	afterPolicies := indexPolicies(after.Policies)

	// Removed policies.
	for name, bp := range beforePolicies {
		if _, ok := afterPolicies[name]; !ok {
			diff.Changes = append(diff.Changes, BaselineChange{
				Category:    "policy_removed",
				Severity:    "high",
				Entity:      name,
				Description: fmt.Sprintf("Policy %q removed (%d rules, %d deny)", name, bp.RuleCount, bp.DenyRules),
				Before:      fmt.Sprintf("score=%.0f grade=%s rules=%d", bp.LintScore, bp.LintGrade, bp.RuleCount),
			})
		}
	}

	// Added policies.
	for name, ap := range afterPolicies {
		if _, ok := beforePolicies[name]; !ok {
			diff.Changes = append(diff.Changes, BaselineChange{
				Category:    "policy_added",
				Severity:    "info",
				Entity:      name,
				Description: fmt.Sprintf("Policy %q added (%d rules, %d deny)", name, ap.RuleCount, ap.DenyRules),
				After:       fmt.Sprintf("score=%.0f grade=%s rules=%d", ap.LintScore, ap.LintGrade, ap.RuleCount),
			})
		}
	}

	// Modified policies.
	for name, bp := range beforePolicies {
		ap, ok := afterPolicies[name]
		if !ok {
			continue
		}
		if bp.Hash != ap.Hash {
			changes := describePolicyChanges(bp, ap)
			sev := "medium"
			if bp.DenyRules > ap.DenyRules {
				sev = "high" // lost deny rules
			}
			diff.Changes = append(diff.Changes, BaselineChange{
				Category:    "policy_modified",
				Severity:    sev,
				Entity:      name,
				Description: strings.Join(changes, "; "),
				Before:      fmt.Sprintf("score=%.0f grade=%s rules=%d deny=%d", bp.LintScore, bp.LintGrade, bp.RuleCount, bp.DenyRules),
				After:       fmt.Sprintf("score=%.0f grade=%s rules=%d deny=%d", ap.LintScore, ap.LintGrade, ap.RuleCount, ap.DenyRules),
			})
		}
	}

	// Index agents.
	beforeAgents := indexAgents(before.Agents)
	afterAgents := indexAgents(after.Agents)

	// Removed agents.
	for name := range beforeAgents {
		if _, ok := afterAgents[name]; !ok {
			diff.Changes = append(diff.Changes, BaselineChange{
				Category:    "agent_removed",
				Severity:    "medium",
				Entity:      name,
				Description: fmt.Sprintf("Agent %q removed from deployment", name),
			})
		}
	}

	// Added agents.
	for name, aa := range afterAgents {
		if _, ok := beforeAgents[name]; !ok {
			sev := "info"
			if aa.TrustLevel == "high" || aa.TrustLevel == "critical" {
				sev = "medium"
			}
			diff.Changes = append(diff.Changes, BaselineChange{
				Category:    "agent_added",
				Severity:    sev,
				Entity:      name,
				Description: fmt.Sprintf("Agent %q added (type=%s trust=%s tools=%d)", name, aa.Type, aa.TrustLevel, aa.ToolCount),
			})
		}
	}

	// Modified agents.
	for name, ba := range beforeAgents {
		aa, ok := afterAgents[name]
		if !ok {
			continue
		}
		if ba.Hash != aa.Hash {
			changes := describeAgentChanges(ba, aa)
			sev := "low"
			if ba.TrustLevel != aa.TrustLevel {
				sev = "high"
			}
			diff.Changes = append(diff.Changes, BaselineChange{
				Category:    "agent_modified",
				Severity:    sev,
				Entity:      name,
				Description: strings.Join(changes, "; "),
			})
		}
	}

	// Score changes.
	if before.Summary.AvgLintScore != after.Summary.AvgLintScore {
		delta := after.Summary.AvgLintScore - before.Summary.AvgLintScore
		sev := "info"
		if delta < -10 {
			sev = "high"
		} else if delta < -5 {
			sev = "medium"
		}
		diff.Changes = append(diff.Changes, BaselineChange{
			Category:    "score_change",
			Severity:    sev,
			Entity:      "deployment",
			Description: fmt.Sprintf("Average lint score: %.0f → %.0f (Δ%.0f)", before.Summary.AvgLintScore, after.Summary.AvgLintScore, delta),
			Before:      fmt.Sprintf("%.0f (%s)", before.Summary.AvgLintScore, before.Summary.AvgLintGrade),
			After:       fmt.Sprintf("%.0f (%s)", after.Summary.AvgLintScore, after.Summary.AvgLintGrade),
		})
	}

	// Sort by severity.
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(diff.Changes, func(i, j int) bool {
		return sevOrder[diff.Changes[i].Severity] < sevOrder[diff.Changes[j].Severity]
	})

	// Compute verdict.
	diff.RiskDelta = computeRiskDelta(diff)
	diff.Verdict = computeVerdict(diff)
	diff.Summary = computeDiffSummary(diff)

	return diff
}

func indexPolicies(policies []BaselinePolicy) map[string]BaselinePolicy {
	m := make(map[string]BaselinePolicy, len(policies))
	for _, p := range policies {
		m[p.Name] = p
	}
	return m
}

func indexAgents(agents []BaselineAgent) map[string]BaselineAgent {
	m := make(map[string]BaselineAgent, len(agents))
	for _, a := range agents {
		m[a.Name] = a
	}
	return m
}

func describePolicyChanges(before, after BaselinePolicy) []string {
	var changes []string
	if before.RuleCount != after.RuleCount {
		changes = append(changes, fmt.Sprintf("rules %d→%d", before.RuleCount, after.RuleCount))
	}
	if before.DenyRules != after.DenyRules {
		changes = append(changes, fmt.Sprintf("deny %d→%d", before.DenyRules, after.DenyRules))
	}
	if before.AlertRules != after.AlertRules {
		changes = append(changes, fmt.Sprintf("alert %d→%d", before.AlertRules, after.AlertRules))
	}
	if before.LintGrade != after.LintGrade {
		changes = append(changes, fmt.Sprintf("grade %s→%s", before.LintGrade, after.LintGrade))
	}
	if before.LintScore != after.LintScore {
		changes = append(changes, fmt.Sprintf("score %.0f→%.0f", before.LintScore, after.LintScore))
	}
	if len(changes) == 0 {
		changes = append(changes, "content changed (hash differs)")
	}
	return changes
}

func describeAgentChanges(before, after BaselineAgent) []string {
	var changes []string
	if before.TrustLevel != after.TrustLevel {
		changes = append(changes, fmt.Sprintf("trust %s→%s", before.TrustLevel, after.TrustLevel))
	}
	if before.ToolCount != after.ToolCount {
		changes = append(changes, fmt.Sprintf("tools %d→%d", before.ToolCount, after.ToolCount))
	}
	if before.Type != after.Type {
		changes = append(changes, fmt.Sprintf("type %s→%s", before.Type, after.Type))
	}
	if len(changes) == 0 {
		changes = append(changes, "configuration changed")
	}
	return changes
}

func computeRiskDelta(diff *BaselineDiff) float64 {
	delta := 0.0
	for _, c := range diff.Changes {
		switch c.Severity {
		case "critical":
			delta += 3.0
		case "high":
			delta += 2.0
		case "medium":
			delta += 1.0
		case "low":
			delta += 0.5
		}
		// Removals are worse than additions.
		if strings.HasSuffix(c.Category, "_removed") {
			delta += 1.0
		}
	}
	// Improvements reduce risk.
	if diff.After != nil && diff.Before != nil {
		if diff.After.Summary.AvgLintScore > diff.Before.Summary.AvgLintScore {
			delta -= 1.0
		}
		if diff.After.Summary.TotalDenyRules > diff.Before.Summary.TotalDenyRules {
			delta -= 0.5
		}
	}
	return delta
}

func computeVerdict(diff *BaselineDiff) string {
	if len(diff.Changes) == 0 {
		return "stable"
	}
	if diff.RiskDelta > 3 {
		return "degraded"
	}
	if diff.RiskDelta < -1 {
		return "improved"
	}
	// Check if all changes are info-level.
	allInfo := true
	for _, c := range diff.Changes {
		if c.Severity != "info" {
			allInfo = false
			break
		}
	}
	if allInfo {
		return "stable"
	}
	return "mixed"
}

func computeDiffSummary(diff *BaselineDiff) string {
	counts := make(map[string]int)
	for _, c := range diff.Changes {
		counts[c.Category]++
	}

	var parts []string
	for cat, n := range counts {
		label := strings.ReplaceAll(cat, "_", " ")
		if n > 1 {
			parts = append(parts, fmt.Sprintf("%d %ss", n, label))
		} else {
			parts = append(parts, fmt.Sprintf("%d %s", n, label))
		}
	}
	sort.Strings(parts)

	if len(parts) == 0 {
		return "No changes."
	}
	return fmt.Sprintf("%d changes: %s. Verdict: %s (risk Δ%.1f).",
		len(diff.Changes), strings.Join(parts, ", "), diff.Verdict, diff.RiskDelta)
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

// SaveBaseline writes a baseline to a JSON file.
func SaveBaseline(b *Baseline, path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadBaseline reads a baseline from a JSON file.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	return &b, nil
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatBaseline renders a baseline as a human-readable summary.
func FormatBaseline(b *Baseline) string {
	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────────┐\n")
	sb.WriteString("│              Deployment Baseline                     │\n")
	sb.WriteString("├─────────────────────────────────────────────────────┤\n")
	if b.Label != "" {
		sb.WriteString(fmt.Sprintf("│ Label:        %-38s │\n", b.Label))
	}
	sb.WriteString(fmt.Sprintf("│ ID:           %-38s │\n", b.ID))
	sb.WriteString(fmt.Sprintf("│ Created:      %-38s │\n", b.CreatedAt))
	sb.WriteString(fmt.Sprintf("│ Fingerprint:  %-38s │\n", b.Fingerprint[:16]+"..."))
	sb.WriteString("├─────────────────────────────────────────────────────┤\n")
	sb.WriteString(fmt.Sprintf("│ Policies: %-3d    Agents: %-3d    Rules: %-4d        │\n",
		b.Summary.TotalPolicies, b.Summary.TotalAgents, b.Summary.TotalRules))
	sb.WriteString(fmt.Sprintf("│ Deny rules: %-3d  Avg score: %-4.0f  Grade: %-2s        │\n",
		b.Summary.TotalDenyRules, b.Summary.AvgLintScore, b.Summary.AvgLintGrade))
	sb.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Policies.
	sb.WriteString("│ Policies                                             │\n")
	for _, p := range b.Policies {
		sb.WriteString(fmt.Sprintf("│  %-20s %2d rules  score=%-3.0f  %s   │\n",
			truncStr(p.Name, 20), p.RuleCount, p.LintScore, p.LintGrade))
	}

	// Agents.
	if len(b.Agents) > 0 {
		sb.WriteString("├─────────────────────────────────────────────────────┤\n")
		sb.WriteString("│ Agents                                               │\n")
		for _, a := range b.Agents {
			sb.WriteString(fmt.Sprintf("│  %-20s %-10s trust=%-6s %2d tools │\n",
				truncStr(a.Name, 20), truncStr(a.Type, 10), a.TrustLevel, a.ToolCount))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────────┘\n")
	return sb.String()
}

// FormatBaselineDiff renders a baseline comparison as human-readable text.
func FormatBaselineDiff(d *BaselineDiff) string {
	if d.Verdict == "stable" {
		return "✓ No changes between baselines.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────────┐\n")
	sb.WriteString("│              Baseline Comparison                     │\n")
	sb.WriteString("├─────────────────────────────────────────────────────┤\n")
	sb.WriteString(fmt.Sprintf("│ Before: %-44s │\n", d.Before.ID))
	sb.WriteString(fmt.Sprintf("│ After:  %-44s │\n", d.After.ID))
	sb.WriteString(fmt.Sprintf("│ Changes: %-3d   Risk Δ: %+.1f   Verdict: %-10s   │\n",
		len(d.Changes), d.RiskDelta, d.Verdict))
	sb.WriteString("├─────────────────────────────────────────────────────┤\n")

	sevIcon := map[string]string{"critical": "✗", "high": "!", "medium": "~", "low": "·", "info": "i"}
	for _, c := range d.Changes {
		icon := sevIcon[c.Severity]
		if icon == "" {
			icon = "·"
		}
		sb.WriteString(fmt.Sprintf("│ [%s] %-47s │\n", icon, truncStr(c.Description, 47)))
		if c.Before != "" {
			sb.WriteString(fmt.Sprintf("│     before: %-40s │\n", truncStr(c.Before, 40)))
		}
		if c.After != "" {
			sb.WriteString(fmt.Sprintf("│     after:  %-40s │\n", truncStr(c.After, 40)))
		}
	}

	sb.WriteString("├─────────────────────────────────────────────────────┤\n")
	sb.WriteString(fmt.Sprintf("│ %s\n", d.Summary))
	sb.WriteString("└─────────────────────────────────────────────────────┘\n")
	return sb.String()
}

// SummarizeBaseline returns a one-line summary of a baseline.
func SummarizeBaseline(b *Baseline) string {
	return fmt.Sprintf("Baseline %s: %d policies, %d agents, %d rules, avg score %.0f (%s)",
		b.ID, b.Summary.TotalPolicies, b.Summary.TotalAgents, b.Summary.TotalRules,
		b.Summary.AvgLintScore, b.Summary.AvgLintGrade)
}

// SummarizeDiff returns a one-line summary of a baseline diff.
func SummarizeDiff(d *BaselineDiff) string {
	return d.Summary
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
