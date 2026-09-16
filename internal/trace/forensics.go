// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package trace

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Core forensic types
// ---------------------------------------------------------------------------

// EvidenceItem is a single piece of forensic evidence extracted from a trace.
type EvidenceItem struct {
	ID          string             `json:"id"`
	Type        string             `json:"type"` // tool_call, agent_message, guardrail_trigger, prompt_injection, data_access, auth_event
	Timestamp   string             `json:"timestamp"`
	AgentName   string             `json:"agent_name"`
	Description string             `json:"description"`
	Severity    string             `json:"severity"` // critical, high, medium, low, info
	Tags        []string           `json:"tags"`
	RawEvent    *policy.TraceEvent `json:"raw_event,omitempty"`
}

// EvidenceChain groups related evidence items into a logical attack narrative.
type EvidenceChain struct {
	ID         string         `json:"id"`
	Title      string         `json:"title"`
	Items      []EvidenceItem `json:"items"`
	Confidence float64        `json:"confidence"` // 0-1
	Narrative  string         `json:"narrative"`  // human-readable explanation
}

// ForensicTimeline is a chronological view across all traces under analysis.
type ForensicTimeline struct {
	Events     []ForensicTimelineEntry `json:"events"`
	StartTime  string                  `json:"start_time"`
	EndTime    string                  `json:"end_time"`
	Duration   string                  `json:"duration"`
	AgentCount int                     `json:"agent_count"`
}

// ForensicTimelineEntry is one row in the forensic timeline.
type ForensicTimelineEntry struct {
	Timestamp   string `json:"timestamp"`
	AgentName   string `json:"agent_name"`
	EventType   string `json:"event_type"`
	Summary     string `json:"summary"`
	Severity    string `json:"severity"`
	EvidenceRef string `json:"evidence_ref,omitempty"` // links to EvidenceItem.ID
}

// ForensicReport is the top-level output of a forensic analysis.
type ForensicReport struct {
	CaseID          string            `json:"case_id"`
	GeneratedAt     string            `json:"generated_at"`
	TraceCount      int               `json:"trace_count"`
	EvidenceCount   int               `json:"evidence_count"`
	Timeline        ForensicTimeline  `json:"timeline"`
	EvidenceChains  []EvidenceChain   `json:"evidence_chains"`
	Indicators      []Indicator       `json:"indicators"`
	RiskAssessment  string            `json:"risk_assessment"` // critical/high/medium/low
	Recommendations []string          `json:"recommendations"`
	Checksums       map[string]string `json:"checksums"` // SHA-256 of input traces
}

// Indicator is an indicator of compromise (IOC) extracted from the traces.
type Indicator struct {
	Type        string  `json:"type"` // tool, target, pattern, agent
	Value       string  `json:"value"`
	Context     string  `json:"context"`
	Confidence  float64 `json:"confidence"`
	Occurrences int     `json:"occurrences"`
}

// ---------------------------------------------------------------------------
// High-risk tool / target / pattern definitions
// ---------------------------------------------------------------------------

// highRiskTools are tool names (or substrings) considered inherently dangerous.
var highRiskTools = []string{
	"shell_exec",
	"code_eval",
	"file_write",
	"http_request",
}

// suspiciousTargets are target substrings that suggest access to sensitive
// or external resources.
var suspiciousTargets = []string{
	"external",
	"credential",
	"password",
	"passwd",
	"admin",
	"secret",
	"token",
	"pastebin",
	"ngrok",
	"webhook.site",
	"requestbin",
	"burpcollaborator",
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// AnalyzeForensics is the main entry point. It builds a complete forensic
// report from one or more agent execution traces.
func AnalyzeForensics(traces []*policy.Trace) *ForensicReport {
	now := time.Now().UTC().Format(time.RFC3339)
	report := &ForensicReport{
		CaseID:      fmt.Sprintf("CASE-%s", now[:10]),
		GeneratedAt: now,
		TraceCount:  len(traces),
		Checksums:   ComputeChecksums(traces),
	}

	if len(traces) == 0 {
		report.RiskAssessment = "low"
		report.Timeline = ForensicTimeline{}
		return report
	}

	// Collect all evidence across traces.
	var allEvidence []EvidenceItem
	for _, tr := range traces {
		if tr == nil {
			continue
		}
		allEvidence = append(allEvidence, ExtractEvidence(tr)...)
	}
	report.EvidenceCount = len(allEvidence)

	// Build evidence chains.
	report.EvidenceChains = BuildEvidenceChains(allEvidence)

	// Build timeline.
	report.Timeline = *BuildTimeline(traces)

	// Extract indicators.
	report.Indicators = ExtractIndicators(traces)

	// Assess risk.
	report.RiskAssessment = assessRisk(allEvidence, report.EvidenceChains)

	// Generate recommendations.
	report.Recommendations = generateRecommendations(allEvidence, report.EvidenceChains, report.Indicators)

	return report
}

// ExtractEvidence extracts forensic evidence items from a single trace.
func ExtractEvidence(tr *policy.Trace) []EvidenceItem {
	if tr == nil {
		return nil
	}

	var items []EvidenceItem
	evNum := 0

	for i := range tr.Events {
		ev := &tr.Events[i]
		evNum++

		switch ev.Type {
		case "tool_call":
			if ev.ToolCall == nil {
				continue
			}
			item := extractToolCallEvidence(tr, ev, evNum)
			if item != nil {
				items = append(items, *item)
			}

		case "agent_message":
			if ev.AgentMessage == nil {
				continue
			}
			item := extractAgentMessageEvidence(tr, ev, evNum)
			if item != nil {
				items = append(items, *item)
			}

		case "guardrail":
			if ev.Guardrail == nil || !ev.Guardrail.Triggered {
				continue
			}
			items = append(items, EvidenceItem{
				ID:          fmt.Sprintf("EV-%s-%03d", tr.ID, evNum),
				Type:        "guardrail_trigger",
				Timestamp:   ev.Timestamp,
				AgentName:   tr.AgentName,
				Description: fmt.Sprintf("guardrail %s triggered (category=%s, score=%.2f, action=%s)", ev.Guardrail.GuardrailID, ev.Guardrail.Category, ev.Guardrail.Score, ev.Guardrail.Action),
				Severity:    guardrailSeverity(ev.Guardrail),
				Tags:        []string{"guardrail", ev.Guardrail.Category},
				RawEvent:    ev,
			})

		case "prompt":
			if ev.Prompt == nil {
				continue
			}
			item := extractPromptEvidence(tr, ev, evNum)
			if item != nil {
				items = append(items, *item)
			}
		}
	}

	return items
}

// BuildEvidenceChains groups evidence items into logical attack chains.
func BuildEvidenceChains(items []EvidenceItem) []EvidenceChain {
	if len(items) == 0 {
		return nil
	}

	// Sort items by timestamp for sequential analysis.
	sorted := make([]EvidenceItem, len(items))
	copy(sorted, items)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Timestamp < sorted[j].Timestamp
	})

	var chains []EvidenceChain
	chainNum := 0

	// Detect data exfiltration chain: read/query followed by upload/send.
	if chain := detectExfilChain(sorted, &chainNum); chain != nil {
		chains = append(chains, *chain)
	}

	// Detect privilege escalation chain.
	if chain := detectPrivEscChain(sorted, &chainNum); chain != nil {
		chains = append(chains, *chain)
	}

	// Detect reconnaissance chain.
	if chain := detectReconChain(sorted, &chainNum); chain != nil {
		chains = append(chains, *chain)
	}

	// Detect injection chain: prompt injection followed by unauthorized actions.
	if chain := detectInjectionChain(sorted, &chainNum); chain != nil {
		chains = append(chains, *chain)
	}

	// Detect lateral movement chain.
	if chain := detectLateralMovementChain(sorted, &chainNum); chain != nil {
		chains = append(chains, *chain)
	}

	return chains
}

// BuildTimeline constructs a chronological forensic timeline across all traces.
func BuildTimeline(traces []*policy.Trace) *ForensicTimeline {
	tl := &ForensicTimeline{}

	if len(traces) == 0 {
		return tl
	}

	agents := map[string]bool{}
	var entries []ForensicTimelineEntry
	var earliest, latest time.Time
	firstParsed := false

	for _, tr := range traces {
		if tr == nil {
			continue
		}
		agents[tr.AgentName] = true

		for i := range tr.Events {
			ev := &tr.Events[i]
			entry := ForensicTimelineEntry{
				Timestamp: ev.Timestamp,
				AgentName: tr.AgentName,
				EventType: ev.Type,
				Summary:   forensicEventSummary(ev),
				Severity:  forensicEventSeverity(ev),
			}
			entries = append(entries, entry)

			if t, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
				if !firstParsed || t.Before(earliest) {
					earliest = t
				}
				if !firstParsed || t.After(latest) {
					latest = t
				}
				firstParsed = true
			}
		}
	}

	// Sort entries by timestamp.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Timestamp < entries[j].Timestamp
	})

	tl.Events = entries
	tl.AgentCount = len(agents)

	if firstParsed {
		tl.StartTime = earliest.Format(time.RFC3339)
		tl.EndTime = latest.Format(time.RFC3339)
		d := latest.Sub(earliest)
		if d >= 0 {
			tl.Duration = d.String()
		} else {
			tl.Duration = "unknown"
		}
	}

	return tl
}

// ExtractIndicators extracts IOCs from the traces: suspicious tools, targets,
// patterns, and agents exhibiting risky behaviour.
func ExtractIndicators(traces []*policy.Trace) []Indicator {
	if len(traces) == 0 {
		return nil
	}

	toolCounts := map[string]int{}
	targetCounts := map[string]int{}
	patternCounts := map[string]int{}
	agentRisk := map[string]int{}

	for _, tr := range traces {
		if tr == nil {
			continue
		}
		for i := range tr.Events {
			ev := &tr.Events[i]

			switch ev.Type {
			case "tool_call":
				if ev.ToolCall == nil {
					continue
				}
				tc := ev.ToolCall
				toolLower := strings.ToLower(tc.Tool)

				// Check high-risk tools.
				for _, hrt := range highRiskTools {
					if strings.Contains(toolLower, hrt) {
						toolCounts[tc.Tool]++
						break
					}
				}

				// Check suspicious targets.
				if tc.Target != "" {
					targetLower := strings.ToLower(tc.Target)
					for _, st := range suspiciousTargets {
						if strings.Contains(targetLower, st) {
							targetCounts[tc.Target]++
							break
						}
					}
				}

				// Elevated calls.
				if tc.Elevated {
					agentRisk[tr.AgentName]++
				}

				// Failed-then-succeeded pattern detection is based on
				// the success field.
				if !tc.Success {
					patternCounts["failed_call"]++
				}

			case "prompt":
				if ev.Prompt == nil {
					continue
				}
				lower := strings.ToLower(ev.Prompt.Content)
				for _, p := range promptInjectionPatterns {
					if strings.Contains(lower, p) {
						patternCounts["prompt_injection"]++
						break
					}
				}

			case "guardrail":
				if ev.Guardrail != nil && ev.Guardrail.Triggered {
					patternCounts["guardrail_trigger"]++
				}
			}
		}
	}

	var indicators []Indicator

	// Tool indicators.
	for tool, count := range toolCounts {
		indicators = append(indicators, Indicator{
			Type:        "tool",
			Value:       tool,
			Context:     "high-risk tool invocation",
			Confidence:  toolConfidence(count),
			Occurrences: count,
		})
	}

	// Target indicators.
	for target, count := range targetCounts {
		indicators = append(indicators, Indicator{
			Type:        "target",
			Value:       target,
			Context:     "suspicious target access",
			Confidence:  targetConfidence(count),
			Occurrences: count,
		})
	}

	// Pattern indicators.
	for pattern, count := range patternCounts {
		indicators = append(indicators, Indicator{
			Type:        "pattern",
			Value:       pattern,
			Context:     patternContext(pattern),
			Confidence:  patternConfidence(pattern, count),
			Occurrences: count,
		})
	}

	// Agent indicators.
	for agent, riskCount := range agentRisk {
		indicators = append(indicators, Indicator{
			Type:        "agent",
			Value:       agent,
			Context:     "agent with elevated/risky behaviour",
			Confidence:  math.Min(0.5+float64(riskCount)*0.1, 1.0),
			Occurrences: riskCount,
		})
	}

	// Sort for determinism: by type, then value.
	sort.Slice(indicators, func(i, j int) bool {
		if indicators[i].Type != indicators[j].Type {
			return indicators[i].Type < indicators[j].Type
		}
		return indicators[i].Value < indicators[j].Value
	})

	return indicators
}

// ComputeChecksums returns a SHA-256 checksum for each trace, keyed by trace ID.
// The hash is computed over the canonical JSON representation of the trace.
func ComputeChecksums(traces []*policy.Trace) map[string]string {
	checksums := make(map[string]string, len(traces))
	for _, tr := range traces {
		if tr == nil {
			continue
		}
		data, err := json.Marshal(tr)
		if err != nil {
			checksums[tr.ID] = "error"
			continue
		}
		h := sha256.Sum256(data)
		checksums[tr.ID] = fmt.Sprintf("%x", h)
	}
	return checksums
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatForensicReport returns a box-drawing formatted report matching the
// style used by FormatReplayResult and FormatCorrelationReport.
func FormatForensicReport(r *ForensicReport) string {
	if r == nil {
		return "No forensic report.\n"
	}

	var b strings.Builder

	b.WriteString("┌───────────────────────────────────────────────────────┐\n")
	b.WriteString("│              Forensic Analysis Report                 │\n")
	b.WriteString("├───────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Case:      %-43s │\n", trunc(r.CaseID, 43)))
	b.WriteString(fmt.Sprintf("│ Generated: %-43s │\n", trunc(r.GeneratedAt, 43)))
	b.WriteString(fmt.Sprintf("│ Traces:    %-43d │\n", r.TraceCount))
	b.WriteString(fmt.Sprintf("│ Evidence:  %-43d │\n", r.EvidenceCount))
	b.WriteString(fmt.Sprintf("│ Risk:      %-43s │\n", strings.ToUpper(r.RiskAssessment)))
	b.WriteString("├───────────────────────────────────────────────────────┤\n")

	// Timeline summary.
	b.WriteString(fmt.Sprintf("│ Timeline:  %-43s │\n", trunc(r.Timeline.Duration, 43)))
	b.WriteString(fmt.Sprintf("│ Agents:    %-43d │\n", r.Timeline.AgentCount))
	maxTimelineEntries := 15
	shown := len(r.Timeline.Events)
	if shown > maxTimelineEntries {
		shown = maxTimelineEntries
	}
	for i := 0; i < shown; i++ {
		te := r.Timeline.Events[i]
		ts := trunc(te.Timestamp, 19)
		sev := te.Severity
		if sev == "" {
			sev = "info"
		}
		b.WriteString(fmt.Sprintf("│  %s [%-8s] %-26s\n", ts, sev, trunc(te.Summary, 26)))
	}
	if len(r.Timeline.Events) > maxTimelineEntries {
		b.WriteString(fmt.Sprintf("│  ... and %d more events\n", len(r.Timeline.Events)-maxTimelineEntries))
	}
	b.WriteString("├───────────────────────────────────────────────────────┤\n")

	// Evidence chains.
	if len(r.EvidenceChains) == 0 {
		b.WriteString("│ No evidence chains detected                           │\n")
	} else {
		b.WriteString("│ Evidence Chains:                                      │\n")
		b.WriteString("├───────────────────────────────────────────────────────┤\n")
		for _, chain := range r.EvidenceChains {
			b.WriteString(fmt.Sprintf("│ %s: %-48s\n", chain.ID, trunc(chain.Title, 48)))
			b.WriteString(fmt.Sprintf("│   confidence=%.2f  items=%d\n", chain.Confidence, len(chain.Items)))
			b.WriteString(fmt.Sprintf("│   %s\n", trunc(chain.Narrative, 52)))
		}
	}
	b.WriteString("├───────────────────────────────────────────────────────┤\n")

	// Indicators.
	if len(r.Indicators) == 0 {
		b.WriteString("│ No indicators extracted                               │\n")
	} else {
		b.WriteString("│ Indicators of Compromise:                             │\n")
		b.WriteString("├───────────────────────────────────────────────────────┤\n")
		maxIndicators := 10
		shownInd := len(r.Indicators)
		if shownInd > maxIndicators {
			shownInd = maxIndicators
		}
		for i := 0; i < shownInd; i++ {
			ind := r.Indicators[i]
			b.WriteString(fmt.Sprintf("│  [%-7s] %-20s conf=%.2f n=%d\n",
				ind.Type, trunc(ind.Value, 20), ind.Confidence, ind.Occurrences))
		}
		if len(r.Indicators) > maxIndicators {
			b.WriteString(fmt.Sprintf("│  ... and %d more indicators\n", len(r.Indicators)-maxIndicators))
		}
	}
	b.WriteString("├───────────────────────────────────────────────────────┤\n")

	// Recommendations.
	if len(r.Recommendations) > 0 {
		b.WriteString("│ Recommendations:                                      │\n")
		for i, rec := range r.Recommendations {
			b.WriteString(fmt.Sprintf("│  %d. %-50s\n", i+1, trunc(rec, 50)))
		}
	}

	// Checksums.
	if len(r.Checksums) > 0 {
		b.WriteString("├───────────────────────────────────────────────────────┤\n")
		b.WriteString("│ Chain of Custody (SHA-256):                           │\n")
		for id, hash := range r.Checksums {
			b.WriteString(fmt.Sprintf("│  %-12s %s\n", trunc(id, 12), trunc(hash, 40)))
		}
	}

	b.WriteString("└───────────────────────────────────────────────────────┘\n")
	return b.String()
}

// SummarizeForensics returns a one-line summary of the forensic report.
func SummarizeForensics(r *ForensicReport) string {
	if r == nil {
		return "no forensic report"
	}
	if r.EvidenceCount == 0 {
		return fmt.Sprintf("case %s: %d traces, no evidence found, risk=%s",
			r.CaseID, r.TraceCount, r.RiskAssessment)
	}
	return fmt.Sprintf("case %s: %d traces, %d evidence items, %d chains, %d indicators, risk=%s",
		r.CaseID, r.TraceCount, r.EvidenceCount, len(r.EvidenceChains),
		len(r.Indicators), r.RiskAssessment)
}

// ---------------------------------------------------------------------------
// Evidence extraction helpers
// ---------------------------------------------------------------------------

// extractToolCallEvidence creates an EvidenceItem from a tool_call event if
// it is forensically interesting (elevated, high-risk tool, suspicious target).
func extractToolCallEvidence(tr *policy.Trace, ev *policy.TraceEvent, num int) *EvidenceItem {
	tc := ev.ToolCall
	toolLower := strings.ToLower(tc.Tool)
	targetLower := strings.ToLower(tc.Target)

	isHighRiskTool := false
	for _, hrt := range highRiskTools {
		if strings.Contains(toolLower, hrt) {
			isHighRiskTool = true
			break
		}
	}

	isSuspiciousTarget := false
	for _, st := range suspiciousTargets {
		if strings.Contains(targetLower, st) {
			isSuspiciousTarget = true
			break
		}
	}

	if !tc.Elevated && !isHighRiskTool && !isSuspiciousTarget {
		return nil
	}

	severity := SeverityMedium
	tags := []string{"tool_call"}
	evType := "tool_call"

	if tc.Elevated {
		severity = SeverityHigh
		tags = append(tags, "elevated")
		evType = "auth_event"
	}
	if isHighRiskTool {
		if severity != SeverityCritical {
			severity = SeverityHigh
		}
		tags = append(tags, "high_risk_tool")
	}
	if isSuspiciousTarget {
		severity = SeverityCritical
		tags = append(tags, "suspicious_target")
		evType = "data_access"
	}

	return &EvidenceItem{
		ID:          fmt.Sprintf("EV-%s-%03d", tr.ID, num),
		Type:        evType,
		Timestamp:   ev.Timestamp,
		AgentName:   tr.AgentName,
		Description: fmt.Sprintf("%s %s on %s (elevated=%v, success=%v)", tc.Tool, tc.Action, tc.Target, tc.Elevated, tc.Success),
		Severity:    severity,
		Tags:        tags,
		RawEvent:    ev,
	}
}

// extractAgentMessageEvidence creates an EvidenceItem from agent_message
// events that mention suspicious keywords.
func extractAgentMessageEvidence(tr *policy.Trace, ev *policy.TraceEvent, num int) *EvidenceItem {
	am := ev.AgentMessage
	lower := strings.ToLower(am.Content)

	// Look for suspicious content in agent messages.
	suspicious := false
	for _, kw := range []string{"credential", "password", "secret", "token", "admin", "elevated", "bypass"} {
		if strings.Contains(lower, kw) {
			suspicious = true
			break
		}
	}

	if !suspicious {
		return nil
	}

	return &EvidenceItem{
		ID:          fmt.Sprintf("EV-%s-%03d", tr.ID, num),
		Type:        "agent_message",
		Timestamp:   ev.Timestamp,
		AgentName:   tr.AgentName,
		Description: fmt.Sprintf("suspicious agent message from %s to %s: %s", am.FromAgent, am.ToAgent, trunc(am.Content, 60)),
		Severity:    SeverityHigh,
		Tags:        []string{"agent_message", "suspicious_content"},
		RawEvent:    ev,
	}
}

// extractPromptEvidence creates an EvidenceItem if prompt content matches
// injection patterns.
func extractPromptEvidence(tr *policy.Trace, ev *policy.TraceEvent, num int) *EvidenceItem {
	lower := strings.ToLower(ev.Prompt.Content)

	matched := ""
	for _, p := range promptInjectionPatterns {
		if strings.Contains(lower, p) {
			matched = p
			break
		}
	}

	if matched == "" {
		return nil
	}

	return &EvidenceItem{
		ID:          fmt.Sprintf("EV-%s-%03d", tr.ID, num),
		Type:        "prompt_injection",
		Timestamp:   ev.Timestamp,
		AgentName:   tr.AgentName,
		Description: fmt.Sprintf("prompt injection pattern %q in %s prompt", matched, ev.Prompt.Role),
		Severity:    SeverityCritical,
		Tags:        []string{"prompt_injection", matched},
		RawEvent:    ev,
	}
}

// guardrailSeverity maps a guardrail event to a severity level.
func guardrailSeverity(g *policy.GuardrailEvent) string {
	switch g.Category {
	case "injection", "jailbreak":
		return SeverityCritical
	case "policy":
		return SeverityHigh
	case "pii":
		return SeverityHigh
	case "toxicity":
		return SeverityMedium
	default:
		return SeverityMedium
	}
}

// ---------------------------------------------------------------------------
// Evidence chain detection
// ---------------------------------------------------------------------------

// detectExfilChain looks for a data exfiltration sequence: read/query events
// followed by upload/send/write-external events.
func detectExfilChain(items []EvidenceItem, chainNum *int) *EvidenceChain {
	var readItems, sendItems []EvidenceItem

	for _, item := range items {
		if item.RawEvent == nil || item.RawEvent.ToolCall == nil {
			continue
		}
		tc := item.RawEvent.ToolCall
		actionLower := strings.ToLower(tc.Action)
		toolLower := strings.ToLower(tc.Tool)

		if actionLower == "read" || actionLower == "query" {
			readItems = append(readItems, item)
		}
		if actionLower == "write" || actionLower == "send" || actionLower == "execute" {
			for _, p := range dataExfilToolPatterns {
				if strings.Contains(toolLower, p) {
					sendItems = append(sendItems, item)
					break
				}
			}
		}
	}

	if len(readItems) == 0 || len(sendItems) == 0 {
		return nil
	}

	// Build chain from the first read to the first send.
	*chainNum++
	chainItems := []EvidenceItem{readItems[0], sendItems[0]}
	return &EvidenceChain{
		ID:         fmt.Sprintf("CHAIN-%03d", *chainNum),
		Title:      "Data Exfiltration",
		Items:      chainItems,
		Confidence: exfilConfidence(readItems, sendItems),
		Narrative:  fmt.Sprintf("Data access (%s) followed by external transfer (%s), suggesting exfiltration", readItems[0].Description, sendItems[0].Description),
	}
}

// detectPrivEscChain looks for privilege escalation patterns: elevated calls,
// admin access, auth events.
func detectPrivEscChain(items []EvidenceItem, chainNum *int) *EvidenceChain {
	var escalationItems []EvidenceItem

	for _, item := range items {
		for _, tag := range item.Tags {
			if tag == "elevated" || tag == "auth_event" {
				escalationItems = append(escalationItems, item)
				break
			}
		}
	}

	if len(escalationItems) < 2 {
		return nil
	}

	*chainNum++
	return &EvidenceChain{
		ID:         fmt.Sprintf("CHAIN-%03d", *chainNum),
		Title:      "Privilege Escalation",
		Items:      escalationItems,
		Confidence: math.Min(0.5+float64(len(escalationItems))*0.1, 1.0),
		Narrative:  fmt.Sprintf("%d elevated/auth events detected across the trace, indicating privilege escalation", len(escalationItems)),
	}
}

// detectReconChain looks for reconnaissance patterns: scanning, listing,
// enumeration-style events.
func detectReconChain(items []EvidenceItem, chainNum *int) *EvidenceChain {
	var reconItems []EvidenceItem

	for _, item := range items {
		if item.RawEvent == nil || item.RawEvent.ToolCall == nil {
			continue
		}
		tc := item.RawEvent.ToolCall
		toolLower := strings.ToLower(tc.Tool)
		actionLower := strings.ToLower(tc.Action)

		isRecon := actionLower == "read" || actionLower == "query"
		for _, kw := range []string{"scan", "enum", "discover", "probe", "list"} {
			if strings.Contains(toolLower, kw) {
				isRecon = true
				break
			}
		}

		if isRecon {
			reconItems = append(reconItems, item)
		}
	}

	if len(reconItems) < 3 {
		return nil
	}

	*chainNum++
	return &EvidenceChain{
		ID:         fmt.Sprintf("CHAIN-%03d", *chainNum),
		Title:      "Reconnaissance",
		Items:      reconItems,
		Confidence: math.Min(0.4+float64(len(reconItems))*0.08, 1.0),
		Narrative:  fmt.Sprintf("%d reconnaissance-style events detected (scanning, enumeration, querying)", len(reconItems)),
	}
}

// detectInjectionChain looks for prompt injection followed by suspicious tool
// calls (the injection enabling unauthorized actions).
func detectInjectionChain(items []EvidenceItem, chainNum *int) *EvidenceChain {
	var injections, postInjectionActions []EvidenceItem

	injectionSeen := false
	for _, item := range items {
		if item.Type == "prompt_injection" {
			injections = append(injections, item)
			injectionSeen = true
			continue
		}
		if injectionSeen && (item.Type == "tool_call" || item.Type == "data_access" || item.Type == "auth_event") {
			postInjectionActions = append(postInjectionActions, item)
		}
	}

	if len(injections) == 0 || len(postInjectionActions) == 0 {
		return nil
	}

	*chainNum++
	chainItems := append(injections, postInjectionActions...)
	return &EvidenceChain{
		ID:         fmt.Sprintf("CHAIN-%03d", *chainNum),
		Title:      "Prompt Injection Attack",
		Items:      chainItems,
		Confidence: math.Min(0.6+float64(len(postInjectionActions))*0.1, 1.0),
		Narrative:  fmt.Sprintf("Prompt injection detected followed by %d unauthorized actions", len(postInjectionActions)),
	}
}

// detectLateralMovementChain looks for agent-to-agent communication with
// escalating access patterns.
func detectLateralMovementChain(items []EvidenceItem, chainNum *int) *EvidenceChain {
	var msgItems, escalatedItems []EvidenceItem

	for _, item := range items {
		if item.Type == "agent_message" {
			msgItems = append(msgItems, item)
		}
		for _, tag := range item.Tags {
			if tag == "elevated" || tag == "high_risk_tool" {
				escalatedItems = append(escalatedItems, item)
				break
			}
		}
	}

	if len(msgItems) == 0 || len(escalatedItems) == 0 {
		return nil
	}

	*chainNum++
	chainItems := append(msgItems, escalatedItems...)
	return &EvidenceChain{
		ID:         fmt.Sprintf("CHAIN-%03d", *chainNum),
		Title:      "Lateral Movement",
		Items:      chainItems,
		Confidence: math.Min(0.5+float64(len(msgItems)+len(escalatedItems))*0.05, 1.0),
		Narrative:  fmt.Sprintf("Agent communication (%d messages) combined with %d escalated actions suggests lateral movement", len(msgItems), len(escalatedItems)),
	}
}

// exfilConfidence computes confidence for a data exfiltration chain.
func exfilConfidence(reads, sends []EvidenceItem) float64 {
	base := 0.6
	base += math.Min(float64(len(reads))*0.05, 0.2)
	base += math.Min(float64(len(sends))*0.1, 0.2)
	return math.Min(base, 1.0)
}

// ---------------------------------------------------------------------------
// Risk assessment
// ---------------------------------------------------------------------------

// assessRisk determines the overall risk level from evidence and chains.
func assessRisk(items []EvidenceItem, chains []EvidenceChain) string {
	criticalCount := 0
	highCount := 0
	for _, item := range items {
		switch item.Severity {
		case SeverityCritical:
			criticalCount++
		case SeverityHigh:
			highCount++
		}
	}

	chainCount := len(chains)

	if criticalCount >= 3 || (criticalCount >= 1 && chainCount >= 2) {
		return SeverityCritical
	}
	if criticalCount >= 1 || highCount >= 3 || chainCount >= 2 {
		return SeverityHigh
	}
	if highCount >= 1 || chainCount >= 1 {
		return SeverityMedium
	}
	return SeverityLow
}

// ---------------------------------------------------------------------------
// Recommendation generation
// ---------------------------------------------------------------------------

func generateRecommendations(items []EvidenceItem, chains []EvidenceChain, indicators []Indicator) []string {
	var recs []string
	seen := map[string]bool{}

	add := func(r string) {
		if !seen[r] {
			seen[r] = true
			recs = append(recs, r)
		}
	}

	for _, chain := range chains {
		switch chain.Title {
		case "Data Exfiltration":
			add("Review and restrict outbound data transfer tools and targets")
			add("Implement data loss prevention (DLP) controls on agent tool calls")
		case "Privilege Escalation":
			add("Audit elevated access grants and enforce least-privilege policies")
			add("Add guardrails for privilege escalation detection")
		case "Reconnaissance":
			add("Rate-limit scanning and enumeration operations")
			add("Monitor for systematic target enumeration patterns")
		case "Prompt Injection Attack":
			add("Strengthen input validation and prompt injection guardrails")
			add("Isolate agent actions after detecting injection attempts")
		case "Lateral Movement":
			add("Restrict inter-agent communication to approved channels")
			add("Monitor agent-to-agent message content for credential sharing")
		}
	}

	for _, item := range items {
		if item.Severity == SeverityCritical {
			add("Investigate critical-severity events immediately")
			break
		}
	}

	for _, ind := range indicators {
		if ind.Type == "tool" && ind.Occurrences > 1 {
			add(fmt.Sprintf("Review repeated use of high-risk tool %q (%d occurrences)", ind.Value, ind.Occurrences))
		}
	}

	if len(recs) == 0 {
		recs = append(recs, "No specific recommendations; continue monitoring")
	}

	return recs
}

// ---------------------------------------------------------------------------
// Timeline helpers
// ---------------------------------------------------------------------------

// forensicEventSummary builds a short text summary of a trace event.
func forensicEventSummary(ev *policy.TraceEvent) string {
	switch ev.Type {
	case "tool_call":
		if ev.ToolCall != nil {
			return fmt.Sprintf("%s %s %s", ev.ToolCall.Tool, ev.ToolCall.Action, trunc(ev.ToolCall.Target, 30))
		}
		return "tool_call (no details)"
	case "prompt":
		if ev.Prompt != nil {
			return fmt.Sprintf("prompt [%s]: %s", ev.Prompt.Role, trunc(ev.Prompt.Content, 30))
		}
		return "prompt (no details)"
	case "response":
		if ev.Response != nil {
			return fmt.Sprintf("response: %s", trunc(ev.Response.Content, 40))
		}
		return "response (no details)"
	case "guardrail":
		if ev.Guardrail != nil {
			return fmt.Sprintf("guardrail %s triggered=%v", ev.Guardrail.GuardrailID, ev.Guardrail.Triggered)
		}
		return "guardrail (no details)"
	case "agent_message":
		if ev.AgentMessage != nil {
			return fmt.Sprintf("msg %s->%s", ev.AgentMessage.FromAgent, ev.AgentMessage.ToAgent)
		}
		return "agent_message (no details)"
	default:
		return ev.Type
	}
}

// forensicEventSeverity assigns a severity to a trace event for timeline display.
func forensicEventSeverity(ev *policy.TraceEvent) string {
	switch ev.Type {
	case "tool_call":
		if ev.ToolCall != nil {
			if ev.ToolCall.Elevated {
				return SeverityHigh
			}
			toolLower := strings.ToLower(ev.ToolCall.Tool)
			for _, hrt := range highRiskTools {
				if strings.Contains(toolLower, hrt) {
					return SeverityMedium
				}
			}
		}
		return SeverityInfo
	case "guardrail":
		if ev.Guardrail != nil && ev.Guardrail.Triggered {
			return SeverityHigh
		}
		return SeverityInfo
	case "prompt":
		if ev.Prompt != nil {
			lower := strings.ToLower(ev.Prompt.Content)
			for _, p := range promptInjectionPatterns {
				if strings.Contains(lower, p) {
					return SeverityCritical
				}
			}
		}
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// ---------------------------------------------------------------------------
// Indicator confidence helpers
// ---------------------------------------------------------------------------

func toolConfidence(count int) float64 {
	return math.Min(0.6+float64(count)*0.1, 1.0)
}

func targetConfidence(count int) float64 {
	return math.Min(0.7+float64(count)*0.1, 1.0)
}

func patternContext(pattern string) string {
	switch pattern {
	case "prompt_injection":
		return "prompt injection pattern detected in input"
	case "guardrail_trigger":
		return "safety guardrail was triggered"
	case "failed_call":
		return "tool call failure (possible boundary probing)"
	default:
		return "suspicious behavioural pattern"
	}
}

func patternConfidence(pattern string, count int) float64 {
	base := 0.5
	switch pattern {
	case "prompt_injection":
		base = 0.8
	case "guardrail_trigger":
		base = 0.7
	case "failed_call":
		base = 0.4
	}
	return math.Min(base+float64(count)*0.05, 1.0)
}
