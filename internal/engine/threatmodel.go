// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// STRIDE categories
// ---------------------------------------------------------------------------

// ThreatCategory identifies one of the six STRIDE threat categories.
type ThreatCategory string

// STRIDE threat categories.
const (
	// Spoofing represents identity forgery threats such as impersonation or credential theft.
	Spoofing ThreatCategory = "spoofing"
	// Tampering represents unauthorized modification of data or configuration.
	Tampering ThreatCategory = "tampering"
	// Repudiation represents threats where an actor denies performing an action without proof.
	Repudiation ThreatCategory = "repudiation"
	// InformationDisclosure represents unauthorized exposure of sensitive data.
	InformationDisclosure ThreatCategory = "information_disclosure"
	// DenialOfService represents threats that degrade or block availability.
	DenialOfService ThreatCategory = "denial_of_service"
	// ElevationOfPrivilege represents unauthorized escalation of access rights.
	ElevationOfPrivilege ThreatCategory = "elevation_of_privilege"
)

// strideOrder lists the STRIDE categories in canonical order, used when
// walking an agent's threats or rendering a category breakdown.
var strideOrder = []ThreatCategory{
	Spoofing,
	Tampering,
	Repudiation,
	InformationDisclosure,
	DenialOfService,
	ElevationOfPrivilege,
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

// Threat is a single STRIDE-classified threat identified against an agent
// (and optionally one of its tools) in a threat model.
type Threat struct {
	ID               string         `json:"id"`
	Category         ThreatCategory `json:"category"`
	Title            string         `json:"title"`
	Description      string         `json:"description"`
	AffectedAgent    string         `json:"affected_agent"`
	AffectedTool     string         `json:"affected_tool,omitempty"`
	Severity         string         `json:"severity"`   // "critical", "high", "medium", "low"
	Likelihood       string         `json:"likelihood"` // "very_likely", "likely", "possible", "unlikely"
	RiskScore        float64        `json:"risk_score"` // 0-10, severity x likelihood
	Mitigations      []string       `json:"mitigations,omitempty"`
	Recommendations  []string       `json:"recommendations,omitempty"`
	MitigationStatus string         `json:"mitigation_status"` // "mitigated", "partial", "unmitigated"
}

// ThreatModel is the full STRIDE threat model generated for an agent
// deployment: every identified Threat plus rollup statistics.
type ThreatModel struct {
	Name              string                 `json:"name"`
	GeneratedAt       string                 `json:"generated_at"`
	Threats           []Threat               `json:"threats"`
	ThreatCount       int                    `json:"threat_count"`
	CriticalCount     int                    `json:"critical_count"`
	HighCount         int                    `json:"high_count"`
	MediumCount       int                    `json:"medium_count"`
	LowCount          int                    `json:"low_count"`
	MitigatedCount    int                    `json:"mitigated_count"`
	PartialCount      int                    `json:"partial_count"`
	UnmitigatedCount  int                    `json:"unmitigated_count"`
	OverallRisk       float64                `json:"overall_risk"` // 0-10
	CategoryBreakdown map[ThreatCategory]int `json:"category_breakdown"`
}

// ---------------------------------------------------------------------------
// Scoring tables
// ---------------------------------------------------------------------------

// severityWeight maps a severity label to its base risk contribution (0-10).
var severityWeight = map[string]float64{
	"critical": 10,
	"high":     7,
	"medium":   4,
	"low":      2,
}

// likelihoodWeight maps a likelihood label to a multiplier (0-1).
var likelihoodWeight = map[string]float64{
	"very_likely": 1.0,
	"likely":      0.8,
	"possible":    0.5,
	"unlikely":    0.25,
}

// tmTrustOrder mirrors the trust-level ranking used internally by the agent
// package. Kept local (rather than exported from agent) so the engine
// package does not reach into agent's unexported state.
var tmTrustOrder = map[string]int{
	agent.TrustUntrusted: 0,
	agent.TrustLow:       1,
	agent.TrustStandard:  2,
	agent.TrustElevated:  3,
	agent.TrustAdmin:     4,
}

// categoryActions maps a STRIDE category to the tool-call action verbs that
// typically realize that category of threat. It is used to recognize policy
// rules that mitigate a threat by action rather than by naming a specific
// tool.
var categoryActions = map[ThreatCategory][]string{
	Tampering:             {"write", "execute"},
	InformationDisclosure: {"read", "query", "send"},
	DenialOfService:       {"execute", "query"},
	ElevationOfPrivilege:  {"execute", "write"},
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// GenerateThreatModel produces a STRIDE-based threat model for an agent
// inventory, using the supplied policies to assess which threats are
// already mitigated. A nil or empty inventory yields an empty threat model.
func GenerateThreatModel(inv *agent.Inventory, policies []*policy.Policy) *ThreatModel {
	tm := &ThreatModel{
		Name:              "AI Agent Deployment Threat Model",
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		CategoryBreakdown: make(map[ThreatCategory]int),
	}

	if inv == nil || len(inv.Agents) == 0 {
		return tm
	}

	var all []Threat
	for _, a := range inv.Agents {
		if a == nil {
			continue
		}
		all = append(all, spoofingThreats(a)...)
		all = append(all, tamperingThreats(a)...)
		all = append(all, repudiationThreats(a)...)
		all = append(all, infoDisclosureThreats(a)...)
		all = append(all, dosThreats(a)...)
		all = append(all, elevationThreats(a)...)
	}

	var riskSum float64
	for i := range all {
		t := &all[i]
		t.ID = fmt.Sprintf("THR-%03d", i+1)
		t.RiskScore = computeThreatRisk(t.Severity, t.Likelihood)
		t.MitigationStatus = assessMitigationStatus(t, policies)

		switch t.Severity {
		case "critical":
			tm.CriticalCount++
		case "high":
			tm.HighCount++
		case "medium":
			tm.MediumCount++
		case "low":
			tm.LowCount++
		}

		switch t.MitigationStatus {
		case "mitigated":
			tm.MitigatedCount++
		case "partial":
			tm.PartialCount++
		default:
			tm.UnmitigatedCount++
		}

		tm.CategoryBreakdown[t.Category]++
		riskSum += t.RiskScore
	}

	tm.Threats = all
	tm.ThreatCount = len(all)
	if len(all) > 0 {
		tm.OverallRisk = roundTo1(riskSum / float64(len(all)))
	}

	return tm
}

// ---------------------------------------------------------------------------
// STRIDE category generators
// ---------------------------------------------------------------------------

// spoofingThreats identifies Spoofing threats: agents without a verified
// attestation, delegating (orchestrator) agents, and agents that exchange
// identity-bearing messages with other agents.
func spoofingThreats(a *agent.Agent) []Threat {
	var threats []Threat
	mitig := enforcedGuardrailNames(a)

	if att := agent.AttestAgent(a, nil); !att.Valid {
		threats = append(threats, Threat{
			Category:      Spoofing,
			Title:         "Unattested agent identity",
			Description:   fmt.Sprintf("Agent %q does not present a fully verified attestation, allowing an impersonator to masquerade as it.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "high",
			Likelihood:    "likely",
			Mitigations:   mitig,
			Recommendations: []string{
				"Issue and verify a cryptographic attestation for the agent before deployment",
				"Rotate attestation fingerprints on every configuration change",
			},
		})
	}

	if a.Meta.Type == agent.TypeOrchestrator {
		threats = append(threats, Threat{
			Category:      Spoofing,
			Title:         "Delegating agent impersonation",
			Description:   fmt.Sprintf("Orchestrator agent %q delegates work to sub-agents; a spoofed delegate could inject forged results back into the chain.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "high",
			Likelihood:    "possible",
			Mitigations:   mitig,
			Recommendations: []string{
				"Require signed responses from delegated agents",
				"Bind delegate identity to a verified attestation before accepting its output",
			},
		})
	}

	if a.Capabilities.MessagePassing {
		threats = append(threats, Threat{
			Category:      Spoofing,
			Title:         "Inter-agent identity claim spoofing",
			Description:   fmt.Sprintf("Agent %q exchanges messages with other agents; identity claims in those messages can be forged absent mutual authentication.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "medium",
			Likelihood:    "possible",
			Mitigations:   mitig,
			Recommendations: []string{
				"Authenticate inter-agent messages with signed tokens",
				"Validate sender identity against the trust graph before acting on a message",
			},
		})
	}

	return threats
}

// tamperingThreats identifies Tampering threats: tools that permit write
// actions, tools that touch configuration, and agents with code execution.
func tamperingThreats(a *agent.Agent) []Threat {
	var threats []Threat
	mitig := enforcedGuardrailNames(a)

	for _, t := range a.Tools {
		if hasAction(t.Actions, "write") {
			threats = append(threats, Threat{
				Category:      Tampering,
				Title:         "Unauthorized write access",
				Description:   fmt.Sprintf("Tool %q available to agent %q permits write actions, allowing tampering with downstream data or systems.", t.Name, a.Meta.Name),
				AffectedAgent: a.Meta.Name,
				AffectedTool:  t.Name,
				Severity:      "high",
				Likelihood:    "likely",
				Mitigations:   mitig,
				Recommendations: []string{
					fmt.Sprintf("Restrict %q to read-only actions unless write is strictly required", t.Name),
					"Add integrity checks (hash/signature) on writes performed by this tool",
				},
			})
		}

		if strings.Contains(strings.ToLower(t.Name), "config") || containsCI(t.Targets, "config") {
			threats = append(threats, Threat{
				Category:      Tampering,
				Title:         "Configuration tampering",
				Description:   fmt.Sprintf("Tool %q used by agent %q can modify configuration, risking silent policy or behavior changes.", t.Name, a.Meta.Name),
				AffectedAgent: a.Meta.Name,
				AffectedTool:  t.Name,
				Severity:      "critical",
				Likelihood:    "possible",
				Mitigations:   mitig,
				Recommendations: []string{
					"Version and checksum configuration before and after each write",
					"Require a second approval step (human or policy) for configuration changes",
				},
			})
		}
	}

	if a.Capabilities.CodeExecution {
		threats = append(threats, Threat{
			Category:      Tampering,
			Title:         "Arbitrary code execution tampering",
			Description:   fmt.Sprintf("Agent %q can execute code, enabling tampering with its own runtime, memory, or host environment.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "critical",
			Likelihood:    "likely",
			Mitigations:   mitig,
			Recommendations: []string{
				"Sandbox code execution in an isolated, ephemeral environment",
				"Whitelist allowed interpreters/commands rather than allowing arbitrary code",
			},
		})
	}

	return threats
}

// repudiationThreats identifies Repudiation threats: agents with no
// guardrails at all, and agents whose guardrails exist but are unenforced
// (so no verifiable audit trail is actually produced).
func repudiationThreats(a *agent.Agent) []Threat {
	var threats []Threat
	mitig := enforcedGuardrailNames(a)

	switch {
	case len(a.Guardrails) == 0:
		threats = append(threats, Threat{
			Category:      Repudiation,
			Title:         "No audit trail for agent actions",
			Description:   fmt.Sprintf("Agent %q has no guardrails configured, so its tool calls and decisions leave no verifiable audit trail.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "high",
			Likelihood:    "likely",
			Mitigations:   mitig,
			Recommendations: []string{
				"Attach a logging guardrail to record every tool call and decision",
				"Forward agent action logs to a tamper-evident, append-only store",
			},
		})
	case len(mitig) == 0:
		threats = append(threats, Threat{
			Category:      Repudiation,
			Title:         "Guardrails defined but unenforced",
			Description:   fmt.Sprintf("Agent %q has guardrails configured but none are enforced, leaving its actions effectively unlogged.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "medium",
			Likelihood:    "possible",
			Mitigations:   mitig,
			Recommendations: []string{
				"Set enforced: true on the agent's audit/logging guardrails",
				"Alert when a configured guardrail is deployed but not enforced",
			},
		})
	}

	return threats
}

// infoDisclosureThreats identifies Information Disclosure threats: agents
// with file access, agents whose trust configuration spans multiple
// boundaries, and RAG-capable agents.
func infoDisclosureThreats(a *agent.Agent) []Threat {
	var threats []Threat
	mitig := enforcedGuardrailNames(a)

	if a.Capabilities.FileAccess {
		threats = append(threats, Threat{
			Category:      InformationDisclosure,
			Title:         "Sensitive file data disclosure",
			Description:   fmt.Sprintf("Agent %q has file access, risking disclosure of sensitive files to unauthorized parties.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "high",
			Likelihood:    "likely",
			Mitigations:   mitig,
			Recommendations: []string{
				"Scope file access to a minimal, allow-listed directory set",
				"Apply data-loss-prevention scanning to file reads before they reach the model context",
			},
		})
	}

	if len(a.Trust.Boundaries) > 1 {
		threats = append(threats, Threat{
			Category:      InformationDisclosure,
			Title:         "Cross-boundary information disclosure",
			Description:   fmt.Sprintf("Agent %q operates across %d trust boundaries (%s), risking data leaking from one boundary into another.", a.Meta.Name, len(a.Trust.Boundaries), strings.Join(a.Trust.Boundaries, ", ")),
			AffectedAgent: a.Meta.Name,
			Severity:      "high",
			Likelihood:    "possible",
			Mitigations:   mitig,
			Recommendations: []string{
				"Enforce per-boundary data classification and tagging",
				"Require explicit policy allow rules for any cross-boundary data flow",
			},
		})
	}

	if a.Capabilities.RAG {
		threats = append(threats, Threat{
			Category:      InformationDisclosure,
			Title:         "RAG index content disclosure",
			Description:   fmt.Sprintf("Agent %q retrieves from a knowledge base; sensitive indexed content may be surfaced to unauthorized requesters or exfiltrated via prompt injection.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "high",
			Likelihood:    "likely",
			Mitigations:   mitig,
			Recommendations: []string{
				"Apply document-level access control on the retrieval index",
				"Filter retrieved content for sensitive data before it reaches the model context",
			},
		})
	}

	return threats
}

// dosThreats identifies Denial of Service threats: tools with no or very
// high rate limits, autonomous agents, and orchestrators with recursive
// delegation potential.
func dosThreats(a *agent.Agent) []Threat {
	var threats []Threat
	mitig := enforcedGuardrailNames(a)

	const highRateLimit = 1000

	for _, t := range a.Tools {
		if t.RateLimit == 0 || t.RateLimit > highRateLimit {
			desc := fmt.Sprintf("Tool %q used by agent %q has no configured rate limit, allowing resource exhaustion through unbounded calls.", t.Name, a.Meta.Name)
			if t.RateLimit > highRateLimit {
				desc = fmt.Sprintf("Tool %q used by agent %q has a very high rate limit (%d), allowing resource exhaustion through excessive calls.", t.Name, a.Meta.Name, t.RateLimit)
			}
			threats = append(threats, Threat{
				Category:      DenialOfService,
				Title:         "Unbounded tool rate limit",
				Description:   desc,
				AffectedAgent: a.Meta.Name,
				AffectedTool:  t.Name,
				Severity:      "medium",
				Likelihood:    "possible",
				Mitigations:   mitig,
				Recommendations: []string{
					fmt.Sprintf("Set a conservative rate_limit on %q sized to expected legitimate usage", t.Name),
					"Add a circuit breaker that suspends the tool after sustained abnormal call volume",
				},
			})
		}
	}

	if a.Capabilities.Autonomous {
		threats = append(threats, Threat{
			Category:      DenialOfService,
			Title:         "Autonomous execution resource exhaustion",
			Description:   fmt.Sprintf("Agent %q operates autonomously and may loop or over-execute without human checkpoints, exhausting compute or downstream capacity.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "medium",
			Likelihood:    "possible",
			Mitigations:   mitig,
			Recommendations: []string{
				"Cap the number of autonomous steps or wall-clock time per run",
				"Require a human checkpoint after N consecutive autonomous actions",
			},
		})
	}

	if a.Meta.Type == agent.TypeOrchestrator && a.Capabilities.MessagePassing && len(a.Trust.TrustedBy) > 0 {
		threats = append(threats, Threat{
			Category:      DenialOfService,
			Title:         "Recursive delegation loop",
			Description:   fmt.Sprintf("Orchestrator agent %q delegates to agents that are also trusted by it, creating the potential for a recursive delegation loop that exhausts resources.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "high",
			Likelihood:    "possible",
			Mitigations:   mitig,
			Recommendations: []string{
				"Enforce a maximum delegation depth across the agent chain",
				"Detect and break cycles in the delegation/trust graph before execution",
			},
		})
	}

	return threats
}

// elevationThreats identifies Elevation of Privilege threats: agents whose
// trust configuration allows escalation, and tool-calling agents that hold
// elevated tool access.
func elevationThreats(a *agent.Agent) []Threat {
	var threats []Threat
	mitig := enforcedGuardrailNames(a)

	if a.Trust.CanEscalate {
		threats = append(threats, Threat{
			Category:      ElevationOfPrivilege,
			Title:         "Trust escalation path enabled",
			Description:   fmt.Sprintf("Agent %q is configured with can_escalate, allowing it to obtain higher trust than initially granted.", a.Meta.Name),
			AffectedAgent: a.Meta.Name,
			Severity:      "critical",
			Likelihood:    "likely",
			Mitigations:   mitig,
			Recommendations: []string{
				"Disable can_escalate unless there is an explicit, reviewed business need",
				"Gate any escalation behind a human approval or a signed policy exception",
			},
		})
	}

	if a.Capabilities.ToolCalling {
		for _, t := range a.Tools {
			if !t.Elevated {
				continue
			}
			severity := "high"
			if trustBelowElevated(a.Trust.Level) {
				severity = "critical"
			}
			threats = append(threats, Threat{
				Category:      ElevationOfPrivilege,
				Title:         "Elevated tool access",
				Description:   fmt.Sprintf("Tool-calling agent %q (trust level %q) can invoke elevated tool %q, risking privilege escalation if the agent is manipulated.", a.Meta.Name, a.Trust.Level, t.Name),
				AffectedAgent: a.Meta.Name,
				AffectedTool:  t.Name,
				Severity:      severity,
				Likelihood:    "likely",
				Mitigations:   mitig,
				Recommendations: []string{
					fmt.Sprintf("Require elevated trust before granting %q, or remove the elevated flag", t.Name),
					"Add a policy deny rule for this tool outside its intended trust boundary",
				},
			})
		}
	}

	return threats
}

// ---------------------------------------------------------------------------
// Mitigation assessment
// ---------------------------------------------------------------------------

// assessMitigationStatus determines whether a threat is "mitigated",
// "partial", or "unmitigated" by combining the agent-level guardrails
// already recorded on the threat with any covering policy rule.
// Repudiation threats look for an "alert" rule scoped to the agent
// (an audit/logging control); every other category looks for a "deny"
// rule that covers the affected tool or the category's typical actions.
func assessMitigationStatus(t *Threat, policies []*policy.Policy) string {
	guardrailMitigation := len(t.Mitigations) > 0

	requiredEffect := "deny"
	if t.Category == Repudiation {
		requiredEffect = "alert"
	}
	policyMitigation := policyCoversThreat(t, policies, requiredEffect)

	switch {
	case guardrailMitigation && policyMitigation:
		return "mitigated"
	case guardrailMitigation || policyMitigation:
		return "partial"
	default:
		return "unmitigated"
	}
}

// policyCoversThreat reports whether any policy scoped to the threat's
// affected agent has a rule with the given effect that covers the threat.
func policyCoversThreat(t *Threat, policies []*policy.Policy, effect string) bool {
	for _, p := range policies {
		if p == nil {
			continue
		}
		if !agentScopeMatches(p.Agent, t.AffectedAgent) {
			continue
		}
		for _, r := range p.Rules {
			if r.Effect != effect {
				continue
			}
			// Repudiation is about the existence of an audit/alert control
			// for the agent, not about a specific tool or action.
			if t.Category == Repudiation {
				return true
			}
			if ruleCoversThreat(r, t) {
				return true
			}
		}
	}
	return false
}

// agentScopeMatches reports whether a policy's agent scope applies to the
// given agent name. An empty or wildcard scope name matches every agent.
func agentScopeMatches(scope policy.AgentScope, agentName string) bool {
	if scope.Name == "" || scope.Name == "*" {
		return true
	}
	return policy.GlobMatch(scope.Name, agentName)
}

// ruleCoversThreat reports whether a rule's match criteria cover a threat,
// either by naming the affected tool directly or by matching one of the
// action verbs typically associated with the threat's category.
func ruleCoversThreat(r policy.Rule, t *Threat) bool {
	if t.AffectedTool != "" {
		for _, pattern := range r.Match.Tools {
			if policy.GlobMatch(pattern, t.AffectedTool) {
				return true
			}
		}
	}

	wanted := categoryActions[t.Category]
	for _, ra := range r.Match.Actions {
		for _, w := range wanted {
			if strings.EqualFold(ra, w) {
				return true
			}
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

// computeThreatRisk computes a 0-10 risk score from a severity and
// likelihood label, as severity weight x likelihood multiplier. Unknown
// labels fall back to medium/possible.
func computeThreatRisk(severity, likelihood string) float64 {
	sw, ok := severityWeight[severity]
	if !ok {
		sw = severityWeight["medium"]
	}
	lw, ok := likelihoodWeight[likelihood]
	if !ok {
		lw = likelihoodWeight["possible"]
	}

	score := sw * lw
	if score > 10 {
		score = 10
	}
	return roundTo1(score)
}

// roundTo1 rounds f to one decimal place.
func roundTo1(f float64) float64 {
	return math.Round(f*10) / 10
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// enforcedGuardrailNames returns the names of an agent's enforced
// guardrails; these count as existing mitigations for any threat against
// that agent.
func enforcedGuardrailNames(a *agent.Agent) []string {
	var names []string
	for _, g := range a.Guardrails {
		if g.Enforced {
			names = append(names, g.Name)
		}
	}
	return names
}

// hasAction reports whether want appears in actions (case-insensitive).
func hasAction(actions []string, want string) bool {
	for _, act := range actions {
		if strings.EqualFold(act, want) {
			return true
		}
	}
	return false
}

// containsCI reports whether sub appears as a case-insensitive substring of
// any entry in list.
func containsCI(list []string, sub string) bool {
	subLower := strings.ToLower(sub)
	for _, s := range list {
		if strings.Contains(strings.ToLower(s), subLower) {
			return true
		}
	}
	return false
}

// trustBelowElevated reports whether a trust level ranks below "elevated".
func trustBelowElevated(level string) bool {
	return tmTrustOrder[level] < tmTrustOrder[agent.TrustElevated]
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatThreatModel renders a threat model as a box-drawing report.
func FormatThreatModel(m *ThreatModel) string {
	if m == nil || len(m.Threats) == 0 {
		return "No threats identified.\n"
	}

	var b strings.Builder

	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│              STRIDE Threat Model                     │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&b, "│ Deployment: %-42s │\n", scenarioTrunc(m.Name, 42))
	fmt.Fprintf(&b, "│ Generated:  %-42s │\n", scenarioTrunc(m.GeneratedAt, 42))
	fmt.Fprintf(&b, "│ Threats:    %-4d   Overall Risk: %-13s │\n", m.ThreatCount, fmt.Sprintf("%.1f/10", m.OverallRisk))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	b.WriteString("│ Severity                                             │\n")
	fmt.Fprintf(&b, "│   critical:%-4d high:%-4d medium:%-4d low:%-4d     │\n",
		m.CriticalCount, m.HighCount, m.MediumCount, m.LowCount)
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	b.WriteString("│ Mitigation Status                                    │\n")
	fmt.Fprintf(&b, "│   mitigated:%-4d partial:%-4d unmitigated:%-4d     │\n",
		m.MitigatedCount, m.PartialCount, m.UnmitigatedCount)
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	b.WriteString("│ STRIDE Category Breakdown                            │\n")
	for _, cat := range strideOrder {
		if c, ok := m.CategoryBreakdown[cat]; ok && c > 0 {
			fmt.Fprintf(&b, "│   %-30s %19d │\n", string(cat), c)
		}
	}
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	b.WriteString("│ Threats                                              │\n")
	for _, t := range m.Threats {
		label := fmt.Sprintf("%s [%s] %s", t.ID, t.Severity, t.Title)
		fmt.Fprintf(&b, "│  %-53s │\n", scenarioTrunc(label, 53))

		target := t.AffectedAgent
		if t.AffectedTool != "" {
			target += "/" + t.AffectedTool
		}
		fmt.Fprintf(&b, "│    %-32s status: %-11s │\n", scenarioTrunc(target, 32), t.MitigationStatus)
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}

// SummarizeThreatModel returns a single-line summary of a threat model.
func SummarizeThreatModel(m *ThreatModel) string {
	if m == nil || m.ThreatCount == 0 {
		return "No threats identified."
	}
	return fmt.Sprintf(
		"%d threats identified (%d critical, %d high, %d medium, %d low); overall risk %.1f/10; %d mitigated, %d partial, %d unmitigated",
		m.ThreatCount, m.CriticalCount, m.HighCount, m.MediumCount, m.LowCount,
		m.OverallRisk, m.MitigatedCount, m.PartialCount, m.UnmitigatedCount,
	)
}
