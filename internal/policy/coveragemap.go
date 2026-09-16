// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// ---------------------------------------------------------------------------
// Types
//
// Note on naming: internal/policy/compiler.go already declares
// CoverageReport and CoverageGap types for tool/tactic/action coverage
// (AnalyzeCoverage). This engine maps rules onto MITRE ATT&CK techniques
// instead, which is a different shape of report, so its report and gap
// types are named CoverageMapReport and TechniqueGap to avoid colliding
// with those existing declarations in the same package.
// ---------------------------------------------------------------------------

// CoverageMapping maps a single policy rule to the MITRE ATT&CK techniques
// and agent-specific pseudo-techniques it detects or controls.
type CoverageMapping struct {
	RuleName   string   `json:"rule_name"`
	RuleAction string   `json:"rule_action"` // the rule's effect: "deny", "allow", or "alert"
	Techniques []string `json:"techniques"`
	Confidence float64  `json:"confidence"` // 0.0-1.0
}

// TechniqueGap is a cataloged technique with no covering deny/alert rule
// in the policy.
type TechniqueGap struct {
	TechniqueID     string   `json:"technique_id"`
	TechniqueName   string   `json:"technique_name"`
	Tactic          string   `json:"tactic"`
	Severity        string   `json:"severity"` // "critical", "high", "medium", "low"
	Recommendations []string `json:"recommendations"`
}

// CoverageMapReport is the full result of mapping a policy's rules onto
// the MITRE ATT&CK / agent pseudo-technique catalog.
type CoverageMapReport struct {
	PolicyName          string             `json:"policy_name"`
	TotalRules          int                `json:"total_rules"`
	TotalTechniques     int                `json:"total_techniques"`
	CoveredTechniques   int                `json:"covered_techniques"`
	UncoveredTechniques int                `json:"uncovered_techniques"`
	CoveragePercent     float64            `json:"coverage_percent"`
	Mappings            []CoverageMapping  `json:"mappings"`
	Gaps                []TechniqueGap     `json:"gaps"`
	TacticCoverage      map[string]float64 `json:"tactic_coverage"`
	RiskScore           float64            `json:"risk_score"` // 0.0 (fully covered) to 1.0 (no coverage)
}

// ---------------------------------------------------------------------------
// Technique catalog
// ---------------------------------------------------------------------------

// techniqueInfo describes one cataloged technique for coverage mapping.
type techniqueInfo struct {
	Name   string
	Tactic string // short tactic name, as in internal/mitre.Tactics
}

// techniqueCatalog is the reference set of common agent-relevant MITRE
// ATT&CK techniques plus agent-specific pseudo-techniques (TE00x), used as
// the universe of "things a policy should cover" for MapCoverage. Real
// ATT&CK entries are resolved from internal/mitre where modeled there;
// T1557 (not currently in internal/mitre) and the TE00x pseudo-techniques
// are defined locally.
var techniqueCatalog = buildTechniqueCatalog()

func buildTechniqueCatalog() map[string]techniqueInfo {
	cat := map[string]techniqueInfo{
		// Not modeled in internal/mitre — defined locally.
		"T1557": {Name: "Adversary-in-the-Middle", Tactic: "credential-access"},

		// Agent-specific pseudo-techniques.
		"TE001": {Name: "Prompt Injection", Tactic: "initial-access"},
		"TE002": {Name: "Tool Call Abuse", Tactic: "execution"},
		"TE003": {Name: "Data Exfiltration", Tactic: "exfiltration"},
		"TE004": {Name: "Privilege Escalation", Tactic: "privilege-escalation"},
		"TE005": {Name: "Agent Hijacking", Tactic: "persistence"},
		"TE006": {Name: "RAG Poisoning", Tactic: "collection"},
		"TE007": {Name: "Model Abuse", Tactic: "collection"},
		"TE008": {Name: "Boundary Violation", Tactic: "defense-evasion"},
	}

	// Canonical ATT&CK techniques resolved from internal/mitre.
	for _, id := range []string{"T1059", "T1190", "T1071", "T1548", "T1134", "T1110", "T1003", "T1055"} {
		if t := mitre.LookupTechnique(id); t != nil {
			cat[id] = techniqueInfo{Name: t.Name, Tactic: t.Tactic}
		}
	}

	return cat
}

// techniqueSeverity assigns a severity to each cataloged technique for use
// when it appears as a coverage gap. Techniques with outsized agent-attack
// impact (credential dumping, process injection, elevation, and the
// core agent-hijacking pseudo-techniques) are rated critical.
var techniqueSeverity = map[string]string{
	"T1059": "high",
	"T1190": "high",
	"T1071": "medium",
	"T1548": "critical",
	"T1134": "high",
	"T1557": "high",
	"T1110": "medium",
	"T1003": "critical",
	"T1055": "critical",
	"TE001": "critical",
	"TE002": "critical",
	"TE003": "critical",
	"TE004": "critical",
	"TE005": "high",
	"TE006": "high",
	"TE007": "medium",
	"TE008": "high",
}

// sortedTechniqueIDs returns all cataloged technique IDs in sorted order,
// for deterministic iteration.
func sortedTechniqueIDs() []string {
	ids := make([]string, 0, len(techniqueCatalog))
	for id := range techniqueCatalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// catalogTacticIndex groups cataloged technique IDs by tactic.
func catalogTacticIndex() map[string][]string {
	idx := make(map[string][]string)
	for _, id := range sortedTechniqueIDs() {
		info := techniqueCatalog[id]
		idx[info.Tactic] = append(idx[info.Tactic], id)
	}
	return idx
}

// ---------------------------------------------------------------------------
// Signal tables — how rule tool patterns, actions, and targets map to
// cataloged techniques, with a confidence per signal.
// ---------------------------------------------------------------------------

type techniqueSignalRule struct {
	match      string // substring to match, case-insensitive
	techniques []string
	confidence float64
}

// toolPatternSignals maps substrings commonly found in tool names
// (shell_*, http_*, db_*, file_*, etc.) to the techniques they suggest.
var toolPatternSignals = []techniqueSignalRule{
	{"shell", []string{"T1059", "TE002"}, 0.85},
	{"process", []string{"T1055", "TE002"}, 0.80},
	{"http", []string{"T1071"}, 0.75},
	{"db", []string{"T1003"}, 0.70},
	{"sql", []string{"T1003"}, 0.70},
	{"file", []string{"TE003"}, 0.60},
	{"registry", []string{"T1548"}, 0.75},
	{"service", []string{"T1548"}, 0.65},
	{"auth", []string{"T1110"}, 0.70},
	{"login", []string{"T1110"}, 0.70},
	{"credential", []string{"T1003", "T1110"}, 0.80},
	{"proxy", []string{"T1557"}, 0.70},
	{"mitm", []string{"T1557"}, 0.85},
	{"intercept", []string{"T1557"}, 0.70},
	{"memory", []string{"TE005"}, 0.65},
	{"agent_message", []string{"TE005"}, 0.70},
	{"rag", []string{"TE006"}, 0.75},
	{"vector", []string{"TE006"}, 0.65},
	{"knowledge", []string{"TE006"}, 0.60},
	{"embedding", []string{"TE006"}, 0.60},
	{"prompt", []string{"TE001"}, 0.80},
	{"model", []string{"TE007"}, 0.65},
	{"inference", []string{"TE007"}, 0.60},
	{"token", []string{"T1134"}, 0.70},
	{"elevat", []string{"T1548", "TE004"}, 0.75},
	{"admin", []string{"T1134", "TE004"}, 0.65},
	{"sudo", []string{"T1548", "TE004"}, 0.75},
}

// actionSignals maps rule action categories to the techniques they
// suggest.
var actionSignals = map[string]techniqueSignalRule{
	"execute": {techniques: []string{"T1059", "TE002"}, confidence: 0.60},
	"send":    {techniques: []string{"T1071", "TE003"}, confidence: 0.55},
	"write":   {techniques: []string{"TE003", "TE005"}, confidence: 0.50},
	"query":   {techniques: []string{"T1003"}, confidence: 0.45},
	"read":    {techniques: []string{"TE006", "TE007"}, confidence: 0.40},
	"create":  {techniques: []string{"TE008"}, confidence: 0.35},
	"modify":  {techniques: []string{"TE008"}, confidence: 0.35},
	"delete":  {techniques: []string{"TE008"}, confidence: 0.40},
}

// targetSignals maps substrings in rule target patterns (hosts/URLs) to
// the techniques they suggest.
var targetSignals = []techniqueSignalRule{
	{"admin", []string{"T1134", "TE004"}, 0.60},
	{"root", []string{"T1548", "TE004"}, 0.60},
	{"sudo", []string{"T1548"}, 0.60},
	{"attacker", []string{"T1071", "TE003"}, 0.70},
	{"evil", []string{"T1071", "TE003"}, 0.70},
	{"c2", []string{"T1071", "TE003"}, 0.75},
	{"external", []string{"TE003"}, 0.50},
}

// wildcardToolTechniques are the (low-confidence) techniques attributed to
// a rule that matches every tool via a "*" pattern.
var wildcardToolTechniques = []string{"TE002", "TE008"}

const wildcardToolConfidence = 0.30

// ---------------------------------------------------------------------------
// Inference
// ---------------------------------------------------------------------------

// inferTechniques analyzes a rule's tool patterns, actions, targets, and
// conditions to infer which cataloged techniques it maps to. Returns a
// sorted, de-duplicated list of technique IDs. Only IDs present in
// techniqueCatalog are returned.
func inferTechniques(r Rule) []string {
	signals := techniqueSignals(r)
	ids := make([]string, 0, len(signals))
	for id := range signals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// techniqueSignals computes, for a single rule, every cataloged technique
// it appears to map to and the confidence of the strongest signal for
// that technique.
func techniqueSignals(r Rule) map[string]float64 {
	out := make(map[string]float64)

	add := func(id string, conf float64) {
		if _, ok := techniqueCatalog[id]; !ok {
			return
		}
		if cur, ok := out[id]; !ok || conf > cur {
			out[id] = conf
		}
	}
	addAll := func(ids []string, conf float64) {
		for _, id := range ids {
			add(id, conf)
		}
	}

	// Tool patterns.
	for _, tool := range r.Match.Tools {
		if tool == "*" {
			addAll(wildcardToolTechniques, wildcardToolConfidence)
			continue
		}
		lower := strings.ToLower(tool)
		for _, sig := range toolPatternSignals {
			if strings.Contains(lower, sig.match) {
				addAll(sig.techniques, sig.confidence)
			}
		}
	}

	// Actions.
	for _, action := range r.Match.Actions {
		if sig, ok := actionSignals[strings.ToLower(action)]; ok {
			addAll(sig.techniques, sig.confidence)
		}
	}

	// Targets.
	for _, target := range r.Match.Targets {
		lower := strings.ToLower(target)
		for _, sig := range targetSignals {
			if strings.Contains(lower, sig.match) {
				addAll(sig.techniques, sig.confidence)
			}
		}
	}

	// Conditions.
	for _, c := range r.Conditions {
		switch c.Field {
		case "elevated":
			if c.Operator == "eq" && c.Value == "true" {
				addAll([]string{"T1548", "T1134", "TE004"}, 0.80)
			}
		case "technique":
			if _, ok := techniqueCatalog[c.Value]; ok {
				add(c.Value, 1.0)
			}
		case "tactic":
			for id, info := range techniqueCatalog {
				if info.Tactic == c.Value {
					add(id, 0.50)
				}
			}
		}
	}

	return out
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

// MapCoverage examines each rule in a policy, infers which cataloged
// MITRE ATT&CK / agent pseudo-techniques it maps to, and reports overall
// technique coverage along with gaps.
//
// Coverage semantics: a technique is considered "covered" only when it is
// mapped to by a "deny" or "alert" rule — those are the rules that provide
// active control or detection. "allow" rules are still recorded in
// Mappings for transparency (at half confidence) but do not close a gap,
// since an allow rule explicitly permits the behavior rather than
// controlling it.
func MapCoverage(p *Policy) *CoverageMapReport {
	allIDs := sortedTechniqueIDs()

	report := &CoverageMapReport{
		TotalTechniques: len(allIDs),
	}

	if p == nil {
		report.PolicyName = "(nil)"
		report.UncoveredTechniques = report.TotalTechniques
		report.Gaps = buildGaps(allIDs, nil)
		report.TacticCoverage = computeTacticCoverage(nil, catalogTacticIndex())
		report.RiskScore = scoreCoverageRisk(report)
		return report
	}

	report.PolicyName = p.Meta.Name
	report.TotalRules = len(p.Rules)

	covered := make(map[string]bool)

	for _, r := range p.Rules {
		signals := techniqueSignals(r)
		if len(signals) == 0 {
			continue
		}

		ids := make([]string, 0, len(signals))
		maxConf := 0.0
		for id, conf := range signals {
			ids = append(ids, id)
			if conf > maxConf {
				maxConf = conf
			}
		}
		sort.Strings(ids)

		ruleConf := maxConf
		if r.Effect == "allow" {
			ruleConf *= 0.5
		}

		report.Mappings = append(report.Mappings, CoverageMapping{
			RuleName:   ruleDisplayName(r),
			RuleAction: r.Effect,
			Techniques: ids,
			Confidence: clamp01(ruleConf),
		})

		if r.Effect == "deny" || r.Effect == "alert" {
			for _, id := range ids {
				covered[id] = true
			}
		}
	}

	sort.SliceStable(report.Mappings, func(i, j int) bool {
		return report.Mappings[i].RuleName < report.Mappings[j].RuleName
	})

	for _, id := range allIDs {
		if covered[id] {
			report.CoveredTechniques++
		}
	}
	report.UncoveredTechniques = report.TotalTechniques - report.CoveredTechniques
	if report.TotalTechniques > 0 {
		report.CoveragePercent = float64(report.CoveredTechniques) / float64(report.TotalTechniques) * 100
	}

	report.Gaps = buildGaps(allIDs, covered)
	report.TacticCoverage = computeTacticCoverage(report.Mappings, catalogTacticIndex())
	report.RiskScore = scoreCoverageRisk(report)

	return report
}

// ruleDisplayName picks the best available human-readable name for a rule.
func ruleDisplayName(r Rule) string {
	if r.ID != "" {
		return r.ID
	}
	if r.Description != "" {
		return r.Description
	}
	return "(unnamed rule)"
}

// ---------------------------------------------------------------------------
// Tactic coverage
// ---------------------------------------------------------------------------

// computeTacticCoverage computes the percentage of cataloged techniques
// covered per tactic, given a set of rule mappings and a tactic ->
// technique-ID index (see catalogTacticIndex). Only mappings whose
// RuleAction is "deny" or "alert" count toward coverage; "allow" mappings
// are informational and do not close a gap. Tactics with no cataloged
// techniques report 0.
func computeTacticCoverage(mappings []CoverageMapping, allTactics map[string][]string) map[string]float64 {
	out := make(map[string]float64, len(allTactics))

	coveredIDs := make(map[string]bool)
	for _, m := range mappings {
		if m.RuleAction != "deny" && m.RuleAction != "alert" {
			continue
		}
		for _, id := range m.Techniques {
			coveredIDs[id] = true
		}
	}

	for tactic, ids := range allTactics {
		if len(ids) == 0 {
			out[tactic] = 0
			continue
		}
		n := 0
		for _, id := range ids {
			if coveredIDs[id] {
				n++
			}
		}
		out[tactic] = float64(n) / float64(len(ids)) * 100
	}

	return out
}

// ---------------------------------------------------------------------------
// Gaps
// ---------------------------------------------------------------------------

// buildGaps returns a TechniqueGap for every cataloged technique not
// present (as a true key) in covered, sorted by severity (critical first)
// then technique ID. A nil covered map yields a gap for every technique.
func buildGaps(allIDs []string, covered map[string]bool) []TechniqueGap {
	var gaps []TechniqueGap
	for _, id := range allIDs {
		if covered[id] {
			continue
		}
		gaps = append(gaps, techniqueGap(id))
	}
	sort.SliceStable(gaps, func(i, j int) bool {
		si, sj := severityRank[gaps[i].Severity], severityRank[gaps[j].Severity]
		if si != sj {
			return si < sj
		}
		return gaps[i].TechniqueID < gaps[j].TechniqueID
	})
	return gaps
}

func techniqueGap(id string) TechniqueGap {
	info := techniqueCatalog[id]
	sev := techniqueSeverity[id]
	if sev == "" {
		sev = "medium"
	}
	return TechniqueGap{
		TechniqueID:     id,
		TechniqueName:   info.Name,
		Tactic:          info.Tactic,
		Severity:        sev,
		Recommendations: recommendationsFor(id, info),
	}
}

func recommendationsFor(id string, info techniqueInfo) []string {
	return []string{
		fmt.Sprintf("Add a deny or alert rule covering %s (%s).", id, info.Name),
		fmt.Sprintf("Review tool patterns and conditions for the %q tactic.", info.Tactic),
	}
}

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

// scoreCoverageRisk derives a 0.0-1.0 risk score from a coverage report:
// 0.0 means every cataloged technique is covered, 1.0 means none are.
// The score blends overall gap ratio (60%) with the fraction of
// critical-severity techniques left uncovered (40%), so a handful of
// critical gaps move the score more than the same number of low-severity
// ones.
func scoreCoverageRisk(report *CoverageMapReport) float64 {
	if report == nil || report.TotalTechniques == 0 {
		return 0
	}

	base := 1.0 - report.CoveragePercent/100.0

	totalCritical := 0
	for _, sev := range techniqueSeverity {
		if sev == "critical" {
			totalCritical++
		}
	}

	criticalGaps := 0
	for _, g := range report.Gaps {
		if g.Severity == "critical" {
			criticalGaps++
		}
	}

	criticalRatio := 0.0
	if totalCritical > 0 {
		criticalRatio = float64(criticalGaps) / float64(totalCritical)
	}

	return clamp01(0.6*base + 0.4*criticalRatio)
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// SummarizeCoverage returns a one-line human-readable summary of a
// coverage report.
func SummarizeCoverage(r *CoverageMapReport) string {
	if r == nil {
		return "No coverage report."
	}
	name := r.PolicyName
	if name == "" {
		name = "(unnamed policy)"
	}
	return fmt.Sprintf(
		"Policy %q: %d/%d techniques covered (%.0f%%), %d gap(s), risk %.2f.",
		name, r.CoveredTechniques, r.TotalTechniques, r.CoveragePercent, len(r.Gaps), r.RiskScore,
	)
}

// FormatCoverageReport returns a box-drawing formatted representation of a
// technique coverage report.
func FormatCoverageReport(r *CoverageMapReport) string {
	if r == nil {
		return "No coverage report.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│            Technique Coverage Report                │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Policy:     %-41s │\n", truncStr(r.PolicyName, 41)))
	b.WriteString(fmt.Sprintf("│ Rules:      %-41d │\n", r.TotalRules))
	b.WriteString(fmt.Sprintf("│ Techniques: %-41s │\n",
		fmt.Sprintf("%d covered / %d total (%.0f%%)", r.CoveredTechniques, r.TotalTechniques, r.CoveragePercent)))
	b.WriteString(fmt.Sprintf("│ Gaps:       %-41d │\n", len(r.Gaps)))
	b.WriteString(fmt.Sprintf("│ Risk Score: %-41s │\n", fmt.Sprintf("%.2f / 1.00", r.RiskScore)))

	// Tactic coverage.
	if len(r.TacticCoverage) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│ Tactic Coverage                                     │\n")
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		tactics := make([]string, 0, len(r.TacticCoverage))
		for t := range r.TacticCoverage {
			tactics = append(tactics, t)
		}
		sort.Strings(tactics)
		for _, t := range tactics {
			pct := r.TacticCoverage[t]
			line := fmt.Sprintf(" %-22s %s", truncStr(t, 22), riskBar(1.0-pct/100.0))
			b.WriteString(fmt.Sprintf("│%-53s%.0f%%│\n", line, pct))
		}
	}

	// Gaps.
	if len(r.Gaps) == 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│ No coverage gaps                                    │\n")
	} else {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString(fmt.Sprintf("│ Gaps (%d)%-45s│\n", len(r.Gaps), ""))
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for i, g := range r.Gaps {
			if i >= 20 {
				rem := fmt.Sprintf("   ... and %d more", len(r.Gaps)-20)
				b.WriteString(fmt.Sprintf("│%-53s│\n", rem))
				break
			}
			sev := fmt.Sprintf("[%s]", strings.ToUpper(g.Severity))
			maxName := 51 - len(sev) - len(g.TechniqueID) - 4
			if maxName < 5 {
				maxName = 5
			}
			line := fmt.Sprintf(" %-10s %s %s", sev, g.TechniqueID, truncStr(g.TechniqueName, maxName))
			b.WriteString(fmt.Sprintf("│%-53s│\n", line))
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}
