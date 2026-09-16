// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"fmt"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Compliance status constants
// ---------------------------------------------------------------------------

const (
	compCompliant     = "compliant"
	compPartial       = "partial"
	compNonCompliant  = "non_compliant"
	compNotApplicable = "not_applicable"
)

// compSevWeight maps a control's severity to its weight in the overall score.
// Critical controls count 3x, high 2x, medium 1x, low 0.5x.
var compSevWeight = map[string]float64{
	"critical": 3.0,
	"high":     2.0,
	"medium":   1.0,
	"low":      0.5,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Framework represents a compliance/security framework.
type Framework struct {
	ID       string    `json:"id"` // e.g. "nist-ai-rmf", "owasp-llm-top10", "mitre-atlas"
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Controls []Control `json:"controls"`
}

// Control is a single compliance requirement within a framework.
type Control struct {
	ID          string `json:"id"` // e.g. "MAP-1.1", "LLM01", "AML.T0043"
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Severity    string `json:"severity"` // critical, high, medium, low
}

// ControlMapping records the compliance status for one control.
type ControlMapping struct {
	Control  Control  `json:"control"`
	Status   string   `json:"status"`   // compliant, partial, non_compliant, not_applicable
	Evidence []string `json:"evidence"` // which policies/rules satisfy this
	Gaps     []string `json:"gaps"`     // what's missing
	Score    float64  `json:"score"`    // 0-1 compliance score for this control
}

// ComplianceReport is the output of mapping an agent deployment against a
// single compliance framework.
type ComplianceReport struct {
	Framework       Framework        `json:"framework"`
	Mappings        []ControlMapping `json:"mappings"`
	OverallScore    float64          `json:"overall_score"` // 0-100 percentage
	Grade           string           `json:"grade"`         // A/B/C/D/F
	CompliantCount  int              `json:"compliant_count"`
	PartialCount    int              `json:"partial_count"`
	NonCompliant    int              `json:"non_compliant_count"`
	CriticalGaps    []string         `json:"critical_gaps"`
	Recommendations []string         `json:"recommendations"`
}

// ComplianceSummary aggregates scores across all built-in frameworks.
type ComplianceSummary struct {
	Frameworks []FrameworkScore `json:"frameworks"`
	BestScore  float64          `json:"best_score"`
	WorstScore float64          `json:"worst_score"`
	AvgScore   float64          `json:"avg_score"`
}

// FrameworkScore is one row in a ComplianceSummary.
type FrameworkScore struct {
	FrameworkID string  `json:"framework_id"`
	Name        string  `json:"name"`
	Score       float64 `json:"score"`
	Grade       string  `json:"grade"`
}

// compCheck holds the intermediate result of a single control check.
type compCheck struct {
	status   string
	evidence []string
	gaps     []string
}

// ---------------------------------------------------------------------------
// Built-in framework definitions
// ---------------------------------------------------------------------------

func nistAIRMFFramework() Framework {
	return Framework{
		ID:      "nist-ai-rmf",
		Name:    "NIST AI Risk Management Framework",
		Version: "1.0",
		Controls: []Control{
			{ID: "MAP-1.1", Title: "AI system purpose documented", Description: "The intended purpose, context of use, and benefits of the AI system are documented", Category: "Map", Severity: "medium"},
			{ID: "MAP-1.5", Title: "Risk identification", Description: "AI system risks have been identified and documented", Category: "Map", Severity: "high"},
			{ID: "MEASURE-2.3", Title: "AI system monitoring", Description: "AI system is monitored for performance and behavior", Category: "Measure", Severity: "high"},
			{ID: "MEASURE-2.5", Title: "Testing against known risks", Description: "AI system is tested against identified risks", Category: "Measure", Severity: "high"},
			{ID: "MANAGE-1.1", Title: "Risk response documented", Description: "Risk response and remediation procedures are documented", Category: "Manage", Severity: "medium"},
			{ID: "MANAGE-2.1", Title: "Human oversight mechanisms", Description: "Human oversight and intervention mechanisms are in place", Category: "Manage", Severity: "critical"},
			{ID: "MANAGE-2.2", Title: "Access controls", Description: "Access controls and trust boundaries are defined", Category: "Manage", Severity: "high"},
			{ID: "MANAGE-3.1", Title: "Incident response", Description: "Incident response procedures for AI failures are defined", Category: "Manage", Severity: "critical"},
			{ID: "GOVERN-1.1", Title: "AI governance policies", Description: "Organizational AI governance policies are established", Category: "Govern", Severity: "critical"},
			{ID: "GOVERN-5.1", Title: "Third-party risk", Description: "Third-party AI components and services are assessed for risk", Category: "Govern", Severity: "high"},
		},
	}
}

func owaspLLMTop10Framework() Framework {
	return Framework{
		ID:      "owasp-llm-top10",
		Name:    "OWASP LLM Top 10",
		Version: "2025",
		Controls: []Control{
			{ID: "LLM01", Title: "Prompt Injection", Description: "Guardrails detect and prevent prompt injection attacks", Category: "Injection", Severity: "critical"},
			{ID: "LLM02", Title: "Insecure Output Handling", Description: "Output validation prevents harmful or unintended responses", Category: "Output", Severity: "high"},
			{ID: "LLM03", Title: "Training Data Poisoning", Description: "Data source restrictions prevent training data contamination", Category: "Data", Severity: "medium"},
			{ID: "LLM04", Title: "Model Denial of Service", Description: "Rate limiting prevents resource exhaustion attacks", Category: "Availability", Severity: "medium"},
			{ID: "LLM05", Title: "Supply Chain Vulnerabilities", Description: "Tool and dependency allowlisting prevents supply chain attacks", Category: "Supply Chain", Severity: "high"},
			{ID: "LLM06", Title: "Sensitive Information Disclosure", Description: "Data exfiltration rules prevent sensitive data leaks", Category: "Data", Severity: "critical"},
			{ID: "LLM07", Title: "Insecure Plugin Design", Description: "Tool-call policies enforce secure plugin interactions", Category: "Plugin", Severity: "high"},
			{ID: "LLM08", Title: "Excessive Agency", Description: "Trust levels and guardrails constrain agent autonomy", Category: "Agency", Severity: "critical"},
			{ID: "LLM09", Title: "Overreliance", Description: "Human-in-the-loop rules prevent unsupervised AI decisions", Category: "Oversight", Severity: "medium"},
			{ID: "LLM10", Title: "Model Theft", Description: "Access restrictions prevent unauthorized model access", Category: "Access", Severity: "high"},
		},
	}
}

func mitreATLASFramework() Framework {
	return Framework{
		ID:      "mitre-atlas",
		Name:    "MITRE ATLAS",
		Version: "4.0",
		Controls: []Control{
			{ID: "AML.T0043", Title: "Craft Adversarial Data", Description: "Input validation detects adversarially crafted data", Category: "ML Attack", Severity: "high"},
			{ID: "AML.T0044", Title: "Adversarial ML Attack", Description: "Model integrity controls detect adversarial ML attacks", Category: "ML Attack", Severity: "critical"},
			{ID: "AML.T0047", Title: "ML Supply Chain Compromise", Description: "Dependency controls prevent ML supply chain compromise", Category: "Supply Chain", Severity: "high"},
			{ID: "AML.T0048", Title: "Model API Inference", Description: "API access controls prevent unauthorized model inference", Category: "API Security", Severity: "high"},
			{ID: "AML.T0051", Title: "Exploit Public-Facing ML App", Description: "External access controls protect public-facing ML applications", Category: "Application", Severity: "critical"},
			{ID: "AML.T0040", Title: "ML Model Inference API Access", Description: "Authentication controls restrict model API access", Category: "API Security", Severity: "high"},
			{ID: "AML.T0042", Title: "Verify Attack", Description: "Monitoring and alerting detect ongoing attacks", Category: "Detection", Severity: "medium"},
			{ID: "AML.T0054", Title: "LLM Prompt Injection", Description: "Injection guardrails prevent LLM prompt manipulation", Category: "Injection", Severity: "critical"},
		},
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ListFrameworks returns all built-in compliance frameworks.
func ListFrameworks() []Framework {
	return []Framework{
		nistAIRMFFramework(),
		owaspLLMTop10Framework(),
		mitreATLASFramework(),
	}
}

// GetFramework returns the framework with the given ID, or (nil, false) if
// no built-in framework matches.
func GetFramework(id string) (*Framework, bool) {
	for _, fw := range ListFrameworks() {
		if fw.ID == id {
			return &fw, true
		}
	}
	return nil, false
}

// MapCompliance maps policies and an agent inventory against a single
// compliance framework, returning a detailed compliance report. Nil
// arguments are handled gracefully.
func MapCompliance(fw *Framework, policies []*policy.Policy, inv *agent.Inventory) *ComplianceReport {
	if fw == nil {
		empty := Framework{}
		fw = &empty
	}

	report := &ComplianceReport{
		Framework: *fw,
	}

	for _, ctrl := range fw.Controls {
		chk := runControlCheck(ctrl.ID, policies, inv)

		score := compStatusScore(chk.status)
		mapping := ControlMapping{
			Control:  ctrl,
			Status:   chk.status,
			Evidence: chk.evidence,
			Gaps:     chk.gaps,
			Score:    score,
		}
		report.Mappings = append(report.Mappings, mapping)

		switch chk.status {
		case compCompliant:
			report.CompliantCount++
		case compPartial:
			report.PartialCount++
		case compNonCompliant:
			report.NonCompliant++
		}

		// Collect critical gaps.
		if chk.status == compNonCompliant && (ctrl.Severity == "critical" || ctrl.Severity == "high") {
			report.CriticalGaps = append(report.CriticalGaps,
				fmt.Sprintf("[%s] %s: %s", ctrl.ID, ctrl.Title, ctrl.Severity))
		}
	}

	report.OverallScore = compOverallScore(report.Mappings)
	report.Grade = compGrade(report.OverallScore)
	report.Recommendations = compRecommendations(report.Mappings)

	return report
}

// MapAllFrameworks runs MapCompliance against every built-in framework and
// returns an aggregated summary.
func MapAllFrameworks(policies []*policy.Policy, inv *agent.Inventory) *ComplianceSummary {
	summary := &ComplianceSummary{}

	var total float64
	for _, fw := range ListFrameworks() {
		r := MapCompliance(&fw, policies, inv)
		fs := FrameworkScore{
			FrameworkID: fw.ID,
			Name:        fw.Name,
			Score:       r.OverallScore,
			Grade:       r.Grade,
		}
		summary.Frameworks = append(summary.Frameworks, fs)
		total += r.OverallScore
	}

	n := len(summary.Frameworks)
	if n > 0 {
		summary.BestScore = summary.Frameworks[0].Score
		summary.WorstScore = summary.Frameworks[0].Score
		for _, fs := range summary.Frameworks {
			if fs.Score > summary.BestScore {
				summary.BestScore = fs.Score
			}
			if fs.Score < summary.WorstScore {
				summary.WorstScore = fs.Score
			}
		}
		summary.AvgScore = roundTo1(total / float64(n))
	}

	return summary
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatComplianceReport renders a ComplianceReport as a box-drawing report.
func FormatComplianceReport(r *ComplianceReport) string {
	if r == nil || len(r.Mappings) == 0 {
		return "No compliance data available.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│               COMPLIANCE REPORT                     │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&b, "│ Framework: %-42s │\n", scenarioTrunc(r.Framework.Name+" v"+r.Framework.Version, 42))
	fmt.Fprintf(&b, "│ Score:     %-5.1f%%   Grade: %-22s │\n", r.OverallScore, r.Grade)
	fmt.Fprintf(&b, "│ Controls:  %-4d compliant:%-3d partial:%-3d gap:%-3d │\n",
		len(r.Mappings), r.CompliantCount, r.PartialCount, r.NonCompliant)
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	b.WriteString("│ Controls                                             │\n")
	for _, m := range r.Mappings {
		icon := "✗"
		switch m.Status {
		case compCompliant:
			icon = "✓"
		case compPartial:
			icon = "~"
		case compNotApplicable:
			icon = "-"
		}
		label := fmt.Sprintf("%s %-10s %s", icon, m.Control.ID, m.Control.Title)
		fmt.Fprintf(&b, "│  %-47s %4.2f │\n", scenarioTrunc(label, 47), m.Score)
	}

	if len(r.CriticalGaps) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│ Critical Gaps                                       │\n")
		for _, g := range r.CriticalGaps {
			fmt.Fprintf(&b, "│  • %-49s│\n", scenarioTrunc(g, 49))
		}
	}

	if len(r.Recommendations) > 0 {
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		b.WriteString("│ Recommendations                                     │\n")
		for _, rec := range r.Recommendations {
			fmt.Fprintf(&b, "│  • %-49s│\n", scenarioTrunc(rec, 49))
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}

// FormatComplianceSummary renders a multi-framework compliance summary.
func FormatComplianceSummary(s *ComplianceSummary) string {
	if s == nil || len(s.Frameworks) == 0 {
		return "No compliance data available.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│             COMPLIANCE SUMMARY                      │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	for _, fs := range s.Frameworks {
		fmt.Fprintf(&b, "│  %-35s %5.1f%% [%s] │\n",
			scenarioTrunc(fs.Name, 35), fs.Score, fs.Grade)
	}

	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&b, "│  Best:  %5.1f%%   Worst: %5.1f%%   Avg: %5.1f%%        │\n",
		s.BestScore, s.WorstScore, s.AvgScore)
	b.WriteString("└─────────────────────────────────────────────────────┘\n")

	return b.String()
}

// SummarizeCompliance returns a single-line summary of a compliance report.
func SummarizeCompliance(r *ComplianceReport) string {
	if r == nil || len(r.Mappings) == 0 {
		return "No compliance data available."
	}
	return fmt.Sprintf(
		"%s: %.1f%% (grade %s) — %d compliant, %d partial, %d non-compliant",
		r.Framework.Name, r.OverallScore, r.Grade,
		r.CompliantCount, r.PartialCount, r.NonCompliant,
	)
}

// ---------------------------------------------------------------------------
// Control check dispatcher
// ---------------------------------------------------------------------------

// runControlCheck dispatches a compliance check by control ID.
func runControlCheck(id string, policies []*policy.Policy, inv *agent.Inventory) compCheck {
	switch id {
	// NIST AI RMF
	case "MAP-1.1":
		return checkAgentDocumentation(policies, inv)
	case "MAP-1.5":
		return checkRiskIdentification(policies, inv)
	case "MEASURE-2.3":
		return checkSystemMonitoring(policies, inv)
	case "MEASURE-2.5":
		return checkRiskTesting(policies, inv)
	case "MANAGE-1.1":
		return checkRiskResponse(policies, inv)
	case "MANAGE-2.1":
		return checkHumanOversight(policies, inv)
	case "MANAGE-2.2":
		return checkAccessControls(policies, inv)
	case "MANAGE-3.1":
		return checkIncidentResponse(policies, inv)
	case "GOVERN-1.1":
		return checkGovernancePolicies(policies, inv)
	case "GOVERN-5.1":
		return checkThirdPartyRisk(policies, inv)

	// OWASP LLM Top 10
	case "LLM01":
		return checkPromptInjection(policies, inv)
	case "LLM02":
		return checkOutputHandling(policies, inv)
	case "LLM03":
		return checkDataPoisoning(policies, inv)
	case "LLM04":
		return checkModelDoS(policies, inv)
	case "LLM05":
		return checkSupplyChain(policies, inv)
	case "LLM06":
		return checkDataExfiltration(policies, inv)
	case "LLM07":
		return checkPluginDesign(policies, inv)
	case "LLM08":
		return checkExcessiveAgency(policies, inv)
	case "LLM09":
		return checkOverreliance(policies, inv)
	case "LLM10":
		return checkModelTheft(policies, inv)

	// MITRE ATLAS
	case "AML.T0043":
		return checkAdversarialData(policies, inv)
	case "AML.T0044":
		return checkMLAttack(policies, inv)
	case "AML.T0047":
		return checkMLSupplyChain(policies, inv)
	case "AML.T0048":
		return checkModelAPIInference(policies, inv)
	case "AML.T0051":
		return checkPublicFacingApp(policies, inv)
	case "AML.T0040":
		return checkMLAPIAccess(policies, inv)
	case "AML.T0042":
		return checkVerifyAttack(policies, inv)
	case "AML.T0054":
		return checkLLMPromptInjection(policies, inv)

	default:
		return compCheck{status: compNonCompliant, gaps: []string{"unknown control"}}
	}
}

// ---------------------------------------------------------------------------
// NIST AI RMF check functions
// ---------------------------------------------------------------------------

// checkAgentDocumentation (MAP-1.1): agents have descriptions.
func checkAgentDocumentation(_ []*policy.Policy, inv *agent.Inventory) compCheck {
	ev, gaps := compAgentsWithProp(inv, func(a *agent.Agent) bool {
		return a.Meta.Description != ""
	}, "has description", "has no description")
	return compResult(ev, gaps)
}

// checkRiskIdentification (MAP-1.5): policies exist scoped to agents.
func checkRiskIdentification(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	pev := compPoliciesExist(policies)
	aev, agaps := compAgentsCoveredByPolicy(policies, inv)
	ev := append(pev, aev...)
	return compResult(ev, agaps)
}

// checkSystemMonitoring (MEASURE-2.3): agents have guardrails.
func checkSystemMonitoring(_ []*policy.Policy, inv *agent.Inventory) compCheck {
	ev, gaps := compAgentsWithProp(inv, func(a *agent.Agent) bool {
		return len(a.Guardrails) > 0
	}, "has guardrails", "has no guardrails")
	return compResult(ev, gaps)
}

// checkRiskTesting (MEASURE-2.5): deny rules exist.
func checkRiskTesting(policies []*policy.Policy, _ *agent.Inventory) compCheck {
	ev := compRulesWithEffect(policies, "deny")
	var gaps []string
	if len(ev) == 0 {
		gaps = append(gaps, "no deny rules configured for risk testing")
	}
	return compResult(ev, gaps)
}

// checkRiskResponse (MANAGE-1.1): alert rules exist for documented response.
func checkRiskResponse(policies []*policy.Policy, _ *agent.Inventory) compCheck {
	ev := compRulesWithEffect(policies, "alert")
	var gaps []string
	if len(ev) == 0 {
		gaps = append(gaps, "no alert rules configured for risk response")
	}
	return compResult(ev, gaps)
}

// checkHumanOversight (MANAGE-2.1): agents have enforced guardrails.
func checkHumanOversight(_ []*policy.Policy, inv *agent.Inventory) compCheck {
	ev, gaps := compAgentsWithProp(inv, func(a *agent.Agent) bool {
		for _, g := range a.Guardrails {
			if g.Enforced {
				return true
			}
		}
		return false
	}, "has enforced guardrails", "has no enforced guardrails")
	return compResult(ev, gaps)
}

// checkAccessControls (MANAGE-2.2): agents have explicit trust levels.
func checkAccessControls(_ []*policy.Policy, inv *agent.Inventory) compCheck {
	ev, gaps := compAgentsWithProp(inv, func(a *agent.Agent) bool {
		return a.Trust.Level != "" && a.Trust.Level != agent.TrustUntrusted
	}, "has configured trust level", "has no configured trust level")
	return compResult(ev, gaps)
}

// checkIncidentResponse (MANAGE-3.1): deny or alert rules exist.
func checkIncidentResponse(policies []*policy.Policy, _ *agent.Inventory) compCheck {
	denyEv := compRulesWithEffect(policies, "deny")
	alertEv := compRulesWithEffect(policies, "alert")
	ev := append(denyEv, alertEv...)
	var gaps []string
	if len(ev) == 0 {
		gaps = append(gaps, "no deny or alert rules for incident response")
	}
	return compResult(ev, gaps)
}

// checkGovernancePolicies (GOVERN-1.1): at least one policy exists.
func checkGovernancePolicies(policies []*policy.Policy, _ *agent.Inventory) compCheck {
	ev := compPoliciesExist(policies)
	var gaps []string
	if len(ev) == 0 {
		gaps = append(gaps, "no governance policies defined")
	}
	return compResult(ev, gaps)
}

// checkThirdPartyRisk (GOVERN-5.1): target restrictions on external tools.
func checkThirdPartyRisk(policies []*policy.Policy, _ *agent.Inventory) compCheck {
	ev := compRulesWithTargets(policies)
	toolEv := compRulesWithToolPatterns(policies)
	ev = append(ev, toolEv...)
	var gaps []string
	if len(ev) == 0 {
		gaps = append(gaps, "no target or tool restrictions for third-party risk")
	}
	return compResult(ev, gaps)
}

// ---------------------------------------------------------------------------
// OWASP LLM Top 10 check functions
// ---------------------------------------------------------------------------

// checkPromptInjection (LLM01): input guardrails + deny rules.
func checkPromptInjection(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	gev, ggaps := compGuardrailType(inv, "input")
	pev := compRulesWithActions(policies, "deny", []string{"execute"})
	ev := append(gev, pev...)
	return compResult(ev, ggaps)
}

// checkOutputHandling (LLM02): output guardrails.
func checkOutputHandling(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	gev, ggaps := compGuardrailType(inv, "output")
	pev := compRulesWithActions(policies, "deny", []string{"send", "write"})
	ev := append(gev, pev...)
	return compResult(ev, ggaps)
}

// checkDataPoisoning (LLM03): RAG agents have data source protections.
// Not applicable if no RAG agents exist.
func checkDataPoisoning(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	ragAgents := compAgentsWithCap(inv, func(a *agent.Agent) bool {
		return a.Capabilities.RAG
	})
	if len(ragAgents) == 0 {
		return compCheck{status: compNotApplicable}
	}

	gev, ggaps := compGuardrailType(inv, "content-filter")
	pev := compRulesWithActions(policies, "deny", []string{"query", "read"})
	ev := append(gev, pev...)
	return compResult(ev, ggaps)
}

// checkModelDoS (LLM04): tools have rate limits.
func checkModelDoS(_ []*policy.Policy, inv *agent.Inventory) compCheck {
	ev, gaps := compToolsWithRateLimit(inv)
	return compResult(ev, gaps)
}

// checkSupplyChain (LLM05): tool allowlisting rules.
func checkSupplyChain(policies []*policy.Policy, _ *agent.Inventory) compCheck {
	ev := compRulesWithToolPatterns(policies)
	var gaps []string
	if len(ev) == 0 {
		gaps = append(gaps, "no tool allowlisting rules for supply chain protection")
	}
	return compResult(ev, gaps)
}

// checkDataExfiltration (LLM06): deny rules on send actions.
func checkDataExfiltration(policies []*policy.Policy, _ *agent.Inventory) compCheck {
	ev := compRulesWithActions(policies, "deny", []string{"send", "write"})
	targetEv := compRulesWithTargets(policies)
	ev = append(ev, targetEv...)
	var gaps []string
	if len(ev) == 0 {
		gaps = append(gaps, "no data exfiltration prevention rules")
	}
	return compResult(ev, gaps)
}

// checkPluginDesign (LLM07): tool-call guardrails.
func checkPluginDesign(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	gev, ggaps := compGuardrailType(inv, "tool-call")
	pev := compRulesWithToolPatterns(policies)
	ev := append(gev, pev...)
	return compResult(ev, ggaps)
}

// checkExcessiveAgency (LLM08): trust levels + guardrails constrain agents.
func checkExcessiveAgency(_ []*policy.Policy, inv *agent.Inventory) compCheck {
	ev, gaps := compAgentsWithProp(inv, func(a *agent.Agent) bool {
		hasTrust := a.Trust.Level != "" && a.Trust.Level != agent.TrustUntrusted
		hasGuardrails := len(a.Guardrails) > 0
		return hasTrust && hasGuardrails
	}, "has trust level and guardrails", "missing trust level or guardrails")
	return compResult(ev, gaps)
}

// checkOverreliance (LLM09): non-autonomous agents or alert rules.
// Not applicable if no autonomous agents exist.
func checkOverreliance(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	autoAgents := compAgentsWithCap(inv, func(a *agent.Agent) bool {
		return a.Capabilities.Autonomous
	})
	if len(autoAgents) == 0 {
		return compCheck{status: compNotApplicable}
	}

	alertEv := compRulesWithEffect(policies, "alert")
	var ev []string
	var gaps []string
	ev = append(ev, alertEv...)
	if len(alertEv) == 0 {
		gaps = append(gaps, "autonomous agents present but no alert rules for human oversight")
	}
	return compResult(ev, gaps)
}

// checkModelTheft (LLM10): access restrictions and trust levels.
func checkModelTheft(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	tev, tgaps := compAgentsWithProp(inv, func(a *agent.Agent) bool {
		return a.Trust.Level != "" && a.Trust.Level != agent.TrustUntrusted
	}, "has access controls", "has no access controls")
	pev := compRulesWithTargets(policies)
	ev := append(tev, pev...)
	return compResult(ev, tgaps)
}

// ---------------------------------------------------------------------------
// MITRE ATLAS check functions
// ---------------------------------------------------------------------------

// checkAdversarialData (AML.T0043): input guardrails.
func checkAdversarialData(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	gev, ggaps := compGuardrailType(inv, "input")
	pev := compRulesWithActions(policies, "deny", []string{"execute", "write"})
	ev := append(gev, pev...)
	return compResult(ev, ggaps)
}

// checkMLAttack (AML.T0044): content-filter guardrails.
func checkMLAttack(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	gev, ggaps := compGuardrailType(inv, "content-filter")
	pev := compRulesWithEffect(policies, "deny")
	ev := append(gev, pev...)
	return compResult(ev, ggaps)
}

// checkMLSupplyChain (AML.T0047): dependency and tool restrictions.
func checkMLSupplyChain(policies []*policy.Policy, _ *agent.Inventory) compCheck {
	ev := compRulesWithToolPatterns(policies)
	var gaps []string
	if len(ev) == 0 {
		gaps = append(gaps, "no dependency or tool restriction rules")
	}
	return compResult(ev, gaps)
}

// checkModelAPIInference (AML.T0048): target restrictions.
func checkModelAPIInference(policies []*policy.Policy, _ *agent.Inventory) compCheck {
	ev := compRulesWithTargets(policies)
	var gaps []string
	if len(ev) == 0 {
		gaps = append(gaps, "no API access controls configured")
	}
	return compResult(ev, gaps)
}

// checkPublicFacingApp (AML.T0051): external access restrictions.
// Not applicable if no web-access agents exist.
func checkPublicFacingApp(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	webAgents := compAgentsWithCap(inv, func(a *agent.Agent) bool {
		return a.Capabilities.WebAccess
	})
	if len(webAgents) == 0 {
		return compCheck{status: compNotApplicable}
	}

	gev, ggaps := compGuardrailType(inv, "input")
	pev := compRulesWithTargets(policies)
	ev := append(gev, pev...)
	return compResult(ev, ggaps)
}

// checkMLAPIAccess (AML.T0040): authentication via trust levels.
func checkMLAPIAccess(_ []*policy.Policy, inv *agent.Inventory) compCheck {
	ev, gaps := compAgentsWithProp(inv, func(a *agent.Agent) bool {
		return a.Trust.Level != "" && a.Trust.Level != agent.TrustUntrusted
	}, "has authentication controls", "has no authentication controls")
	return compResult(ev, gaps)
}

// checkVerifyAttack (AML.T0042): alert rules for monitoring.
func checkVerifyAttack(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	aev := compRulesWithEffect(policies, "alert")
	gev, ggaps := compAgentsWithProp(inv, func(a *agent.Agent) bool {
		return len(a.Guardrails) > 0
	}, "has monitoring guardrails", "has no monitoring guardrails")
	ev := append(aev, gev...)
	return compResult(ev, ggaps)
}

// checkLLMPromptInjection (AML.T0054): input guardrails for injection.
func checkLLMPromptInjection(policies []*policy.Policy, inv *agent.Inventory) compCheck {
	gev, ggaps := compGuardrailType(inv, "input")
	pev := compRulesWithActions(policies, "deny", []string{"execute"})
	ev := append(gev, pev...)
	return compResult(ev, ggaps)
}

// ---------------------------------------------------------------------------
// Evidence collection helpers
// ---------------------------------------------------------------------------

// compAgentsWithProp iterates agents and collects evidence for those passing
// fn. Returns evidence descriptions for passing agents and gap descriptions
// for failing agents.
func compAgentsWithProp(inv *agent.Inventory, fn func(*agent.Agent) bool, pass, fail string) (evidence, gaps []string) {
	if inv == nil {
		return nil, []string{"no agent inventory provided"}
	}
	if len(inv.Agents) == 0 {
		return nil, []string{"no agents in inventory"}
	}
	for _, a := range inv.Agents {
		if a == nil {
			continue
		}
		if fn(a) {
			evidence = append(evidence, fmt.Sprintf("agent %q %s", a.Meta.Name, pass))
		} else {
			gaps = append(gaps, fmt.Sprintf("agent %q %s", a.Meta.Name, fail))
		}
	}
	return
}

// compAgentsWithCap returns the names of agents that satisfy a capability
// predicate.
func compAgentsWithCap(inv *agent.Inventory, fn func(*agent.Agent) bool) []string {
	if inv == nil {
		return nil
	}
	var names []string
	for _, a := range inv.Agents {
		if a == nil {
			continue
		}
		if fn(a) {
			names = append(names, a.Meta.Name)
		}
	}
	return names
}

// compAgentsCoveredByPolicy returns evidence for agents covered by at least
// one policy, and gaps for uncovered agents.
func compAgentsCoveredByPolicy(policies []*policy.Policy, inv *agent.Inventory) (evidence, gaps []string) {
	if inv == nil || len(inv.Agents) == 0 {
		return nil, nil
	}
	for _, a := range inv.Agents {
		if a == nil {
			continue
		}
		covered := false
		for _, p := range policies {
			if p == nil {
				continue
			}
			if agentScopeMatches(p.Agent, a.Meta.Name) {
				covered = true
				break
			}
		}
		if covered {
			evidence = append(evidence, fmt.Sprintf("agent %q is covered by policy", a.Meta.Name))
		} else {
			gaps = append(gaps, fmt.Sprintf("agent %q has no covering policy", a.Meta.Name))
		}
	}
	return
}

// compPoliciesExist returns evidence strings for each non-nil policy.
func compPoliciesExist(policies []*policy.Policy) []string {
	var ev []string
	for _, p := range policies {
		if p != nil {
			ev = append(ev, fmt.Sprintf("policy %q", p.Meta.Name))
		}
	}
	return ev
}

// compRulesWithEffect returns evidence for rules matching the given effect.
func compRulesWithEffect(policies []*policy.Policy, effect string) []string {
	var ev []string
	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, r := range p.Rules {
			if r.Effect == effect {
				ev = append(ev, fmt.Sprintf("policy %q rule %q (%s)", p.Meta.Name, r.ID, effect))
			}
		}
	}
	return ev
}

// compRulesWithActions returns evidence for rules matching the given effect
// and at least one of the given actions.
func compRulesWithActions(policies []*policy.Policy, effect string, actions []string) []string {
	want := make(map[string]bool, len(actions))
	for _, a := range actions {
		want[strings.ToLower(a)] = true
	}

	var ev []string
	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, r := range p.Rules {
			if r.Effect != effect {
				continue
			}
			for _, a := range r.Match.Actions {
				if want[strings.ToLower(a)] {
					ev = append(ev, fmt.Sprintf("policy %q rule %q matches action %q", p.Meta.Name, r.ID, a))
					break
				}
			}
		}
	}
	return ev
}

// compRulesWithTargets returns evidence for rules that restrict targets.
func compRulesWithTargets(policies []*policy.Policy) []string {
	var ev []string
	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, r := range p.Rules {
			if len(r.Match.Targets) > 0 {
				ev = append(ev, fmt.Sprintf("policy %q rule %q restricts targets %v", p.Meta.Name, r.ID, r.Match.Targets))
			}
		}
	}
	return ev
}

// compRulesWithToolPatterns returns evidence for rules with tool patterns.
func compRulesWithToolPatterns(policies []*policy.Policy) []string {
	var ev []string
	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, r := range p.Rules {
			if len(r.Match.Tools) > 0 {
				ev = append(ev, fmt.Sprintf("policy %q rule %q covers tools %v", p.Meta.Name, r.ID, r.Match.Tools))
			}
		}
	}
	return ev
}

// compGuardrailType returns evidence/gaps for agents with a specific
// guardrail type.
func compGuardrailType(inv *agent.Inventory, gType string) (evidence, gaps []string) {
	return compAgentsWithProp(inv, func(a *agent.Agent) bool {
		for _, g := range a.Guardrails {
			if g.Type == gType {
				return true
			}
		}
		return false
	}, fmt.Sprintf("has %s guardrail", gType), fmt.Sprintf("has no %s guardrail", gType))
}

// compToolsWithRateLimit checks whether tools across all agents have rate
// limits configured.
func compToolsWithRateLimit(inv *agent.Inventory) (evidence, gaps []string) {
	if inv == nil {
		return nil, []string{"no agent inventory provided"}
	}
	if len(inv.Agents) == 0 {
		return nil, []string{"no agents in inventory"}
	}
	for _, a := range inv.Agents {
		if a == nil {
			continue
		}
		for _, t := range a.Tools {
			if t.RateLimit > 0 {
				evidence = append(evidence, fmt.Sprintf("agent %q tool %q has rate limit %d", a.Meta.Name, t.Name, t.RateLimit))
			} else {
				gaps = append(gaps, fmt.Sprintf("agent %q tool %q has no rate limit", a.Meta.Name, t.Name))
			}
		}
	}
	// Agents with no tools: no evidence or gaps for rate limiting.
	return
}

// ---------------------------------------------------------------------------
// Status / scoring helpers
// ---------------------------------------------------------------------------

// compResult determines the compliance status from evidence and gaps.
func compResult(evidence, gaps []string) compCheck {
	switch {
	case len(evidence) > 0 && len(gaps) == 0:
		return compCheck{status: compCompliant, evidence: evidence, gaps: gaps}
	case len(evidence) > 0:
		return compCheck{status: compPartial, evidence: evidence, gaps: gaps}
	default:
		return compCheck{status: compNonCompliant, evidence: evidence, gaps: gaps}
	}
}

// compStatusScore converts a compliance status to a 0-1 score.
func compStatusScore(status string) float64 {
	switch status {
	case compCompliant:
		return 1.0
	case compPartial:
		return 0.5
	default:
		return 0.0
	}
}

// compOverallScore computes the weighted-average overall score (0-100).
func compOverallScore(mappings []ControlMapping) float64 {
	var weightedSum, totalWeight float64
	for _, m := range mappings {
		if m.Status == compNotApplicable {
			continue
		}
		w := compSevWeight[m.Control.Severity]
		if w == 0 {
			w = 1.0 // default for unrecognized severity
		}
		weightedSum += m.Score * w
		totalWeight += w
	}
	if totalWeight == 0 {
		return 0
	}
	return roundTo1((weightedSum / totalWeight) * 100)
}

// compGrade maps an overall percentage score (0-100) to a letter grade.
func compGrade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// compRecommendations generates recommendations from the control mappings.
func compRecommendations(mappings []ControlMapping) []string {
	var recs []string
	for _, m := range mappings {
		if m.Status == compNonCompliant {
			recs = append(recs, fmt.Sprintf("Address %s: %s", m.Control.ID, m.Control.Title))
		}
	}
	for _, m := range mappings {
		if m.Status == compPartial {
			recs = append(recs, fmt.Sprintf("Improve %s: %s", m.Control.ID, m.Control.Title))
		}
	}
	return recs
}
