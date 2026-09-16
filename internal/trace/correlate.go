// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package trace — this file implements the multi-trace correlation engine.
// While replay.go analyzes a single agent trace in isolation, correlate.go
// looks across many traces at once to find patterns that only become
// visible when traces are considered together: multiple agents converging
// on the same target, a recon→exploit→exfil sequence spread across
// independent agent sessions, a privilege escalation chain, and so on.
// This is what turns single-agent anomaly detection into detection of
// coordinated, multi-agent incidents.
package trace

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Correlation rule types
// ---------------------------------------------------------------------------

// Correlation rule Type values.
const (
	CorrelationTypeTemporal       = "temporal"
	CorrelationTypeTarget         = "target"
	CorrelationTypeToolSequence   = "tool_sequence"
	CorrelationTypeAgentCluster   = "agent_cluster"
	CorrelationTypeEscalationPath = "escalation_path"
)

// CorrelationRule describes one pattern the correlation engine looks for
// across a set of traces.
type CorrelationRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`     // temporal, target, tool_sequence, agent_cluster, escalation_path
	Severity    string `json:"severity"` // critical, high, medium, low
}

// CorrelatedEvent is a single event pulled from a trace as evidence for a
// Correlation.
type CorrelatedEvent struct {
	TraceID   string `json:"trace_id"`
	EventID   string `json:"event_id"`
	AgentName string `json:"agent_name"`
	Tool      string `json:"tool,omitempty"`
	Action    string `json:"action,omitempty"`
	Target    string `json:"target,omitempty"`
	Timestamp string `json:"timestamp"`
}

// Correlation is one detected cross-trace pattern.
type Correlation struct {
	ID          string            `json:"id"`
	Rule        CorrelationRule   `json:"rule"`
	TraceIDs    []string          `json:"trace_ids"`
	AgentNames  []string          `json:"agent_names"`
	Events      []CorrelatedEvent `json:"events"`
	Score       float64           `json:"score"` // 0–1 confidence
	Description string            `json:"description"`
}

// CorrelationReport is the result of correlating a set of traces.
type CorrelationReport struct {
	TraceCount       int           `json:"trace_count"`
	CorrelationCount int           `json:"correlation_count"`
	Correlations     []Correlation `json:"correlations"`
	RiskScore        float64       `json:"risk_score"` // 0–1
	HighestSeverity  string        `json:"highest_severity"`
}

// ---------------------------------------------------------------------------
// Default rules
// ---------------------------------------------------------------------------

// DefaultCorrelationRules returns the built-in set of correlation rules.
func DefaultCorrelationRules() []CorrelationRule {
	return []CorrelationRule{
		{
			Name:        "temporal-burst",
			Description: "multiple agents accessing the same target within a short time window",
			Type:        CorrelationTypeTemporal,
			Severity:    SeverityMedium,
		},
		{
			Name:        "tool-sequence-attack",
			Description: "a known attack sequence (recon -> exploit -> exfil) spread across traces",
			Type:        CorrelationTypeToolSequence,
			Severity:    SeverityCritical,
		},
		{
			Name:        "privilege-chain",
			Description: "escalating privilege levels observed across multiple agent traces",
			Type:        CorrelationTypeEscalationPath,
			Severity:    SeverityCritical,
		},
		{
			Name:        "data-convergence",
			Description: "multiple agents sending data to the same external target",
			Type:        CorrelationTypeTarget,
			Severity:    SeverityHigh,
		},
		{
			Name:        "target-sweep",
			Description: "an agent systematically accessing many distinct targets",
			Type:        CorrelationTypeTarget,
			Severity:    SeverityMedium,
		},
		{
			Name:        "coordinated-access",
			Description: "multiple agents simultaneously accessing a sensitive resource",
			Type:        CorrelationTypeAgentCluster,
			Severity:    SeverityHigh,
		},
		{
			Name:        "relay-attack",
			Description: "one agent's message is quickly followed by a suspicious action from the recipient agent",
			Type:        CorrelationTypeToolSequence,
			Severity:    SeverityHigh,
		},
		{
			Name:        "boundary-probe",
			Description: "multiple agents (or one agent repeatedly) testing policy/boundary restrictions",
			Type:        CorrelationTypeEscalationPath,
			Severity:    SeverityMedium,
		},
	}
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

// CorrelateTraces runs the default correlation rules across the given
// traces and returns a CorrelationReport.
func CorrelateTraces(traces []*policy.Trace) *CorrelationReport {
	return CorrelateWithRules(traces, DefaultCorrelationRules())
}

// correlationDetector finds instances of a rule's pattern across the
// pre-collected tool-call and agent-message records.
type correlationDetector func(traces []*policy.Trace, calls []toolCallRec, msgs []agentMsgRec, rule CorrelationRule) []Correlation

// correlationDetectors maps built-in rule names to their detector.
// Custom rules (a name not present here) produce no findings — the engine
// only knows how to evaluate the patterns it ships with.
var correlationDetectors = map[string]correlationDetector{
	"temporal-burst":       detectTemporalBurst,
	"tool-sequence-attack": detectToolSequenceAttack,
	"privilege-chain":      detectPrivilegeChain,
	"data-convergence":     detectDataConvergence,
	"target-sweep":         detectTargetSweep,
	"coordinated-access":   detectCoordinatedAccess,
	"relay-attack":         detectRelayAttack,
	"boundary-probe":       detectBoundaryProbe,
}

// CorrelateWithRules runs the supplied correlation rules across the given
// traces and returns a CorrelationReport.
func CorrelateWithRules(traces []*policy.Trace, rules []CorrelationRule) *CorrelationReport {
	report := &CorrelationReport{TraceCount: len(traces)}

	if len(traces) == 0 {
		return report
	}

	calls := collectToolCallRecords(traces)
	msgs := collectAgentMessageRecords(traces)

	var all []Correlation
	for _, rule := range rules {
		detector, ok := correlationDetectors[rule.Name]
		if !ok {
			continue
		}
		all = append(all, detector(traces, calls, msgs, rule)...)
	}

	for i := range all {
		all[i].ID = fmt.Sprintf("COR-%03d", i+1)
	}

	report.Correlations = all
	report.CorrelationCount = len(all)
	report.RiskScore = scoreCorrelationRisk(all)
	report.HighestSeverity = highestCorrelationSeverity(all)

	return report
}

// ---------------------------------------------------------------------------
// Record collection
// ---------------------------------------------------------------------------

// toolCallRec is a flattened, time-parsed view of a tool_call event used by
// the correlation detectors.
type toolCallRec struct {
	TraceID   string
	EventID   string
	AgentName string
	AgentType string
	Tool      string
	Action    string
	Target    string
	Elevated  bool
	Success   bool
	Timestamp string
	When      time.Time
	HasTime   bool
}

// agentMsgRec is a flattened, time-parsed view of an agent_message event.
type agentMsgRec struct {
	TraceID   string
	EventID   string
	FromAgent string
	ToAgent   string
	Content   string
	Timestamp string
	When      time.Time
	HasTime   bool
}

// collectToolCallRecords flattens tool_call events from every trace.
func collectToolCallRecords(traces []*policy.Trace) []toolCallRec {
	var out []toolCallRec
	for _, tr := range traces {
		if tr == nil {
			continue
		}
		for i := range tr.Events {
			ev := &tr.Events[i]
			if ev.Type != "tool_call" || ev.ToolCall == nil {
				continue
			}
			rec := toolCallRec{
				TraceID:   tr.ID,
				EventID:   ev.ID,
				AgentName: tr.AgentName,
				AgentType: tr.AgentType,
				Tool:      ev.ToolCall.Tool,
				Action:    ev.ToolCall.Action,
				Target:    ev.ToolCall.Target,
				Elevated:  ev.ToolCall.Elevated,
				Success:   ev.ToolCall.Success,
				Timestamp: ev.Timestamp,
			}
			if t, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
				rec.When = t
				rec.HasTime = true
			}
			out = append(out, rec)
		}
	}
	return out
}

// collectAgentMessageRecords flattens agent_message events from every trace.
func collectAgentMessageRecords(traces []*policy.Trace) []agentMsgRec {
	var out []agentMsgRec
	for _, tr := range traces {
		if tr == nil {
			continue
		}
		for i := range tr.Events {
			ev := &tr.Events[i]
			if ev.Type != "agent_message" || ev.AgentMessage == nil {
				continue
			}
			rec := agentMsgRec{
				TraceID:   tr.ID,
				EventID:   ev.ID,
				FromAgent: ev.AgentMessage.FromAgent,
				ToAgent:   ev.AgentMessage.ToAgent,
				Content:   ev.AgentMessage.Content,
				Timestamp: ev.Timestamp,
			}
			if t, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
				rec.When = t
				rec.HasTime = true
			}
			out = append(out, rec)
		}
	}
	return out
}

// correlationStage classifies a tool call into a coarse attack stage —
// "recon", "exploit", "exfil" — or "" if it doesn't match any. It reuses
// the exfiltration pattern lists already defined in replay.go.
func correlationStage(c toolCallRec) string {
	toolLower := strings.ToLower(c.Tool)
	targetLower := strings.ToLower(c.Target)
	actionLower := strings.ToLower(c.Action)

	for _, p := range dataExfilToolPatterns {
		if strings.Contains(toolLower, p) {
			return "exfil"
		}
	}
	for _, p := range dataExfilTargetPatterns {
		if strings.Contains(targetLower, p) {
			return "exfil"
		}
	}
	if actionLower == "send" {
		return "exfil"
	}

	if actionLower == "execute" ||
		strings.Contains(toolLower, "exploit") ||
		strings.Contains(toolLower, "inject") ||
		strings.Contains(toolLower, "payload") {
		return "exploit"
	}

	if actionLower == "read" || actionLower == "query" ||
		strings.Contains(toolLower, "scan") ||
		strings.Contains(toolLower, "recon") ||
		strings.Contains(toolLower, "enum") ||
		strings.Contains(toolLower, "probe") ||
		strings.Contains(toolLower, "discover") {
		return "recon"
	}

	return ""
}

// ---------------------------------------------------------------------------
// Detector: temporal-burst
// ---------------------------------------------------------------------------

const (
	temporalBurstWindow    = 30 * time.Second
	temporalBurstMinAgents = 2
)

// detectTemporalBurst flags a target hit by >= 2 distinct agents within a
// short time window.
func detectTemporalBurst(_ []*policy.Trace, calls []toolCallRec, _ []agentMsgRec, rule CorrelationRule) []Correlation {
	byTarget := map[string][]toolCallRec{}
	for _, c := range calls {
		if c.Target == "" || !c.HasTime {
			continue
		}
		byTarget[c.Target] = append(byTarget[c.Target], c)
	}

	var out []Correlation
	for _, target := range sortedKeys(byTarget) {
		recs := byTarget[target]
		sort.Slice(recs, func(i, j int) bool { return recs[i].When.Before(recs[j].When) })

		i := 0
		for i < len(recs) {
			j := i
			agents := map[string]bool{}
			for j < len(recs) && recs[j].When.Sub(recs[i].When) <= temporalBurstWindow {
				agents[recs[j].AgentName] = true
				j++
			}
			if len(agents) >= temporalBurstMinAgents {
				window := recs[i:j]
				out = append(out, buildCorrelation(rule, window, fmt.Sprintf(
					"%d agents accessed target %q within %s",
					len(agents), target, recs[j-1].When.Sub(recs[i].When))))
				i = j
			} else {
				i++
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Detector: tool-sequence-attack
// ---------------------------------------------------------------------------

const toolSequenceWindow = 10 * time.Minute

// detectToolSequenceAttack looks for a recon -> exploit -> exfil sequence,
// in time order, whose three events span at least two distinct traces.
func detectToolSequenceAttack(_ []*policy.Trace, calls []toolCallRec, _ []agentMsgRec, rule CorrelationRule) []Correlation {
	timed := make([]toolCallRec, 0, len(calls))
	for _, c := range calls {
		if c.HasTime {
			timed = append(timed, c)
		}
	}
	sort.Slice(timed, func(i, j int) bool { return timed[i].When.Before(timed[j].When) })

	var out []Correlation
	i := 0
	for i < len(timed) {
		if correlationStage(timed[i]) != "recon" {
			i++
			continue
		}
		reconIdx := i

		exploitIdx := -1
		for j := reconIdx + 1; j < len(timed); j++ {
			if timed[j].When.Sub(timed[reconIdx].When) > toolSequenceWindow {
				break
			}
			if correlationStage(timed[j]) == "exploit" {
				exploitIdx = j
				break
			}
		}
		if exploitIdx == -1 {
			i++
			continue
		}

		exfilIdx := -1
		for k := exploitIdx + 1; k < len(timed); k++ {
			if timed[k].When.Sub(timed[reconIdx].When) > toolSequenceWindow {
				break
			}
			if correlationStage(timed[k]) == "exfil" {
				exfilIdx = k
				break
			}
		}
		if exfilIdx == -1 {
			i++
			continue
		}

		triple := []toolCallRec{timed[reconIdx], timed[exploitIdx], timed[exfilIdx]}
		traceSet := map[string]bool{}
		for _, t := range triple {
			traceSet[t.TraceID] = true
		}
		if len(traceSet) >= 2 {
			out = append(out, buildCorrelation(rule, triple, fmt.Sprintf(
				"recon->exploit->exfil sequence spanning %d traces (%s -> %s -> %s)",
				len(traceSet), triple[0].Target, triple[1].Target, triple[2].Target)))
		}
		i = exfilIdx + 1
	}
	return out
}

// ---------------------------------------------------------------------------
// Detector: privilege-chain
// ---------------------------------------------------------------------------

// agentTypePrivilege gives a base numeric privilege level per agent type.
var agentTypePrivilege = map[string]int{
	"retrieval":    1,
	"llm":          2,
	"tool":         3,
	"orchestrator": 4,
}

// tracePrivilegeLevel derives a numeric privilege level for a trace from
// its agent type, bumped by one if it made any elevated tool call.
func tracePrivilegeLevel(tr *policy.Trace) int {
	lvl, ok := agentTypePrivilege[tr.AgentType]
	if !ok {
		lvl = 1
	}
	for i := range tr.Events {
		ev := &tr.Events[i]
		if ev.Type == "tool_call" && ev.ToolCall != nil && ev.ToolCall.Elevated {
			lvl++
			break
		}
	}
	return lvl
}

// traceStartWhen returns the trace's start time, falling back to the
// earliest parseable event timestamp.
func traceStartWhen(tr *policy.Trace) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, tr.StartTime); err == nil {
		return t, true
	}
	var best time.Time
	found := false
	for i := range tr.Events {
		t, err := time.Parse(time.RFC3339, tr.Events[i].Timestamp)
		if err != nil {
			continue
		}
		if !found || t.Before(best) {
			best = t
			found = true
		}
	}
	return best, found
}

// syntheticRecordForTrace builds a representative toolCallRec for a trace
// as a whole (used by detectors that correlate at trace granularity rather
// than single-event granularity, e.g. privilege-chain).
func syntheticRecordForTrace(tr *policy.Trace) toolCallRec {
	rec := toolCallRec{TraceID: tr.ID, AgentName: tr.AgentName, Timestamp: tr.StartTime}
	for i := range tr.Events {
		ev := &tr.Events[i]
		if ev.Type == "tool_call" && ev.ToolCall != nil {
			rec.EventID = ev.ID
			rec.Tool = ev.ToolCall.Tool
			rec.Action = ev.ToolCall.Action
			rec.Target = ev.ToolCall.Target
			rec.Timestamp = ev.Timestamp
			return rec
		}
	}
	if len(tr.Events) > 0 {
		rec.EventID = tr.Events[0].ID
		rec.Timestamp = tr.Events[0].Timestamp
	}
	return rec
}

// detectPrivilegeChain finds the longest chain of traces, ordered by start
// time, with non-decreasing privilege level and a distinct agent at every
// step, that shows a net increase in privilege — an escalation chain.
func detectPrivilegeChain(traces []*policy.Trace, _ []toolCallRec, _ []agentMsgRec, rule CorrelationRule) []Correlation {
	type entry struct {
		trace *policy.Trace
		level int
		when  time.Time
	}

	var entries []entry
	for _, tr := range traces {
		if tr == nil {
			continue
		}
		when, ok := traceStartWhen(tr)
		if !ok {
			continue
		}
		entries = append(entries, entry{trace: tr, level: tracePrivilegeLevel(tr), when: when})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].when.Before(entries[j].when) })

	var best []entry
	for start := range entries {
		chain := []entry{entries[start]}
		lastLevel := entries[start].level
		lastAgent := entries[start].trace.AgentName
		for j := start + 1; j < len(entries); j++ {
			if entries[j].level >= lastLevel && entries[j].trace.AgentName != lastAgent {
				chain = append(chain, entries[j])
				lastLevel = entries[j].level
				lastAgent = entries[j].trace.AgentName
			}
		}
		if len(chain) > len(best) {
			best = chain
		}
	}

	if len(best) < 3 || best[len(best)-1].level <= best[0].level {
		return nil
	}

	recs := make([]toolCallRec, 0, len(best))
	for _, e := range best {
		recs = append(recs, syntheticRecordForTrace(e.trace))
	}

	return []Correlation{buildCorrelation(rule, recs, fmt.Sprintf(
		"privilege escalates from level %d to %d across %d agent traces",
		best[0].level, best[len(best)-1].level, len(best)))}
}

// ---------------------------------------------------------------------------
// Detector: data-convergence
// ---------------------------------------------------------------------------

// detectDataConvergence flags an external target that received exfil-like
// tool calls from >= 2 distinct agents.
func detectDataConvergence(_ []*policy.Trace, calls []toolCallRec, _ []agentMsgRec, rule CorrelationRule) []Correlation {
	byTarget := map[string][]toolCallRec{}
	for _, c := range calls {
		if c.Target == "" || correlationStage(c) != "exfil" {
			continue
		}
		byTarget[c.Target] = append(byTarget[c.Target], c)
	}

	var out []Correlation
	for _, target := range sortedKeys(byTarget) {
		recs := byTarget[target]
		agents := map[string]bool{}
		for _, r := range recs {
			agents[r.AgentName] = true
		}
		if len(agents) >= 2 {
			out = append(out, buildCorrelation(rule, recs, fmt.Sprintf(
				"%d agents sent data to external target %q", len(agents), target)))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Detector: target-sweep
// ---------------------------------------------------------------------------

const targetSweepThreshold = 5

// detectTargetSweep flags an agent that touched many distinct targets,
// suggesting systematic scanning.
func detectTargetSweep(_ []*policy.Trace, calls []toolCallRec, _ []agentMsgRec, rule CorrelationRule) []Correlation {
	byAgent := map[string][]toolCallRec{}
	for _, c := range calls {
		if c.Target == "" {
			continue
		}
		byAgent[c.AgentName] = append(byAgent[c.AgentName], c)
	}

	var out []Correlation
	for _, agent := range sortedKeys(byAgent) {
		recs := byAgent[agent]
		targets := map[string]bool{}
		for _, r := range recs {
			targets[r.Target] = true
		}
		if len(targets) >= targetSweepThreshold {
			out = append(out, buildCorrelation(rule, recs, fmt.Sprintf(
				"agent %q accessed %d distinct targets (systematic sweep)", agent, len(targets))))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Detector: coordinated-access
// ---------------------------------------------------------------------------

const coordinatedAccessWindow = 60 * time.Second

// sensitiveTargetPatterns are target substrings treated as sensitive
// resources for coordinated-access detection.
var sensitiveTargetPatterns = []string{
	"secret", "credential", "password", "passwd", "token",
	"admin", "prod", "database", "confidential", "private", "pii", "key",
}

func isSensitiveTarget(target string) bool {
	lower := strings.ToLower(target)
	for _, p := range sensitiveTargetPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// detectCoordinatedAccess flags >= 2 distinct agents hitting the same
// sensitive target within a short window.
func detectCoordinatedAccess(_ []*policy.Trace, calls []toolCallRec, _ []agentMsgRec, rule CorrelationRule) []Correlation {
	byTarget := map[string][]toolCallRec{}
	for _, c := range calls {
		if c.Target == "" || !c.HasTime || !isSensitiveTarget(c.Target) {
			continue
		}
		byTarget[c.Target] = append(byTarget[c.Target], c)
	}

	var out []Correlation
	for _, target := range sortedKeys(byTarget) {
		recs := byTarget[target]
		sort.Slice(recs, func(i, j int) bool { return recs[i].When.Before(recs[j].When) })

		i := 0
		for i < len(recs) {
			j := i
			agents := map[string]bool{}
			for j < len(recs) && recs[j].When.Sub(recs[i].When) <= coordinatedAccessWindow {
				agents[recs[j].AgentName] = true
				j++
			}
			if len(agents) >= 2 {
				out = append(out, buildCorrelation(rule, recs[i:j], fmt.Sprintf(
					"%d agents simultaneously accessed sensitive target %q", len(agents), target)))
				i = j
			} else {
				i++
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Detector: relay-attack
// ---------------------------------------------------------------------------

const relayWindow = 2 * time.Minute

// detectRelayAttack flags an inter-agent message quickly followed by a
// suspicious (elevated or exfil-like) action from the recipient agent.
func detectRelayAttack(_ []*policy.Trace, calls []toolCallRec, msgs []agentMsgRec, rule CorrelationRule) []Correlation {
	var out []Correlation

	for _, m := range msgs {
		if !m.HasTime || m.ToAgent == "" {
			continue
		}
		for _, c := range calls {
			if c.AgentName != m.ToAgent || !c.HasTime {
				continue
			}
			delta := c.When.Sub(m.When)
			if delta < 0 || delta > relayWindow {
				continue
			}
			if !c.Elevated && correlationStage(c) != "exfil" {
				continue
			}

			msgEvent := CorrelatedEvent{
				TraceID: m.TraceID, EventID: m.EventID, AgentName: m.FromAgent,
				Tool: "agent_message", Action: "send", Target: m.ToAgent, Timestamp: m.Timestamp,
			}
			callEvent := CorrelatedEvent{
				TraceID: c.TraceID, EventID: c.EventID, AgentName: c.AgentName,
				Tool: c.Tool, Action: c.Action, Target: c.Target, Timestamp: c.Timestamp,
			}

			traceSet := map[string]bool{m.TraceID: true, c.TraceID: true}
			agentSet := map[string]bool{m.FromAgent: true, c.AgentName: true}

			out = append(out, Correlation{
				Rule:        rule,
				TraceIDs:    sortedKeys(traceSet),
				AgentNames:  sortedKeys(agentSet),
				Events:      []CorrelatedEvent{msgEvent, callEvent},
				Score:       computeCorrelationScore(rule, len(agentSet), len(traceSet), 2),
				Description: fmt.Sprintf("message from %q to %q followed by suspicious action %q on %q", m.FromAgent, m.ToAgent, c.Tool, c.Target),
			})
			break // one relay finding per message
		}
	}

	return out
}

// ---------------------------------------------------------------------------
// Detector: boundary-probe
// ---------------------------------------------------------------------------

const boundaryProbeMinFailures = 3

// detectBoundaryProbe flags agents repeatedly testing restrictions: either
// one agent racking up failed calls across many targets, or multiple
// agents each failing against the same target.
func detectBoundaryProbe(_ []*policy.Trace, calls []toolCallRec, _ []agentMsgRec, rule CorrelationRule) []Correlation {
	var out []Correlation

	// Pattern A: single agent, many failed attempts across distinct targets.
	byAgent := map[string][]toolCallRec{}
	for _, c := range calls {
		if c.Success {
			continue
		}
		byAgent[c.AgentName] = append(byAgent[c.AgentName], c)
	}
	for _, agent := range sortedKeys(byAgent) {
		recs := byAgent[agent]
		targets := map[string]bool{}
		for _, r := range recs {
			targets[r.Target] = true
		}
		if len(recs) >= boundaryProbeMinFailures && len(targets) >= 2 {
			out = append(out, buildCorrelation(rule, recs, fmt.Sprintf(
				"agent %q made %d failed calls across %d targets (boundary probing)",
				agent, len(recs), len(targets))))
		}
	}

	// Pattern B: multiple distinct agents failing against the same target.
	byTarget := map[string][]toolCallRec{}
	for _, c := range calls {
		if c.Success || c.Target == "" {
			continue
		}
		byTarget[c.Target] = append(byTarget[c.Target], c)
	}
	for _, target := range sortedKeys(byTarget) {
		recs := byTarget[target]
		agents := map[string]bool{}
		for _, r := range recs {
			agents[r.AgentName] = true
		}
		if len(agents) >= 2 {
			out = append(out, buildCorrelation(rule, recs, fmt.Sprintf(
				"%d agents made failed/denied attempts against target %q", len(agents), target)))
		}
	}

	return out
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// sortedKeys returns the keys of a map, sorted, for deterministic iteration.
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// buildCorrelation assembles a Correlation from a rule and the toolCallRec
// evidence that triggered it.
func buildCorrelation(rule CorrelationRule, recs []toolCallRec, description string) Correlation {
	events := make([]CorrelatedEvent, 0, len(recs))
	traceSet := map[string]bool{}
	agentSet := map[string]bool{}

	for _, r := range recs {
		events = append(events, CorrelatedEvent{
			TraceID: r.TraceID, EventID: r.EventID, AgentName: r.AgentName,
			Tool: r.Tool, Action: r.Action, Target: r.Target, Timestamp: r.Timestamp,
		})
		traceSet[r.TraceID] = true
		agentSet[r.AgentName] = true
	}

	traceIDs := sortedKeys(traceSet)
	agentNames := sortedKeys(agentSet)

	return Correlation{
		Rule:        rule,
		TraceIDs:    traceIDs,
		AgentNames:  agentNames,
		Events:      events,
		Score:       computeCorrelationScore(rule, len(agentNames), len(traceIDs), len(events)),
		Description: description,
	}
}

// computeCorrelationScore derives a 0-1 confidence score from the rule's
// severity and how broadly the pattern is corroborated (distinct agents,
// distinct traces, number of supporting events).
func computeCorrelationScore(rule CorrelationRule, distinctAgents, distinctTraces, eventCount int) float64 {
	score := 0.4

	switch rule.Severity {
	case SeverityCritical:
		score += 0.3
	case SeverityHigh:
		score += 0.2
	case SeverityMedium:
		score += 0.1
	case SeverityLow:
		score += 0.05
	}

	if distinctAgents > 1 {
		score += 0.05 * float64(distinctAgents-1)
	}
	if distinctTraces > 1 {
		score += 0.03 * float64(distinctTraces-1)
	}
	if eventCount > 1 {
		score += 0.02 * float64(eventCount-1)
	}

	if score > 1 {
		score = 1
	}
	if score < 0 {
		score = 0
	}
	return score
}

// scoreCorrelationRisk computes a 0-1 overall risk score from the
// correlations found, weighted by each correlation's rule severity.
func scoreCorrelationRisk(correlations []Correlation) float64 {
	if len(correlations) == 0 {
		return 0
	}

	var score float64
	for _, c := range correlations {
		switch c.Rule.Severity {
		case SeverityCritical:
			score += weightCritical
		case SeverityHigh:
			score += weightHigh
		case SeverityMedium:
			score += weightMedium
		case SeverityLow:
			score += weightLow
		}
	}

	return math.Min(score, 1.0)
}

// highestCorrelationSeverity returns the highest severity level present
// among the given correlations, or "" if there are none.
func highestCorrelationSeverity(correlations []Correlation) string {
	order := []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	present := map[string]bool{}
	for _, c := range correlations {
		present[c.Rule.Severity] = true
	}
	for _, s := range order {
		if present[s] {
			return s
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatCorrelationReport returns a box-drawing formatted report.
func FormatCorrelationReport(r *CorrelationReport) string {
	if r == nil {
		return "No correlation report.\n"
	}

	var b strings.Builder

	b.WriteString("┌───────────────────────────────────────────────────────┐\n")
	b.WriteString("│           Multi-Trace Correlation Report              │\n")
	b.WriteString("├───────────────────────────────────────────────────────┤\n")
	b.WriteString(fmt.Sprintf("│ Traces analyzed:   %-36d │\n", r.TraceCount))
	b.WriteString(fmt.Sprintf("│ Correlations:      %-36d │\n", r.CorrelationCount))

	sevLabel := r.HighestSeverity
	if sevLabel == "" {
		sevLabel = "none"
	}
	b.WriteString(fmt.Sprintf("│ Highest severity:  %-36s │\n", sevLabel))
	b.WriteString(fmt.Sprintf("│ Risk score:        %-36s │\n", fmt.Sprintf("%.2f", r.RiskScore)))
	b.WriteString("├───────────────────────────────────────────────────────┤\n")

	if len(r.Correlations) == 0 {
		b.WriteString("│ No cross-trace correlations detected                  │\n")
	} else {
		b.WriteString("│ Correlations:                                          │\n")
		b.WriteString("├───────────────────────────────────────────────────────┤\n")
		for _, c := range r.Correlations {
			sev := strings.ToUpper(c.Rule.Severity)
			b.WriteString(fmt.Sprintf("│ %-8s [%-8s] %-22s score=%.2f\n",
				c.ID, sev, trunc(c.Rule.Name, 22), c.Score))
			b.WriteString(fmt.Sprintf("│   %s\n", trunc(c.Description, 52)))
			b.WriteString(fmt.Sprintf("│   traces=%d agents=%s\n",
				len(c.TraceIDs), trunc(strings.Join(c.AgentNames, ","), 40)))
		}
	}

	b.WriteString("└───────────────────────────────────────────────────────┘\n")
	return b.String()
}

// SummarizeCorrelations returns a one-line summary of a CorrelationReport.
func SummarizeCorrelations(r *CorrelationReport) string {
	if r == nil {
		return "no correlation report"
	}
	if r.CorrelationCount == 0 {
		return fmt.Sprintf("%d traces analyzed: no correlations found, risk=0.00", r.TraceCount)
	}
	sev := r.HighestSeverity
	if sev == "" {
		sev = "none"
	}
	return fmt.Sprintf("%d traces analyzed: %d correlations found (highest=%s), risk=%.2f",
		r.TraceCount, r.CorrelationCount, sev, r.RiskScore)
}
