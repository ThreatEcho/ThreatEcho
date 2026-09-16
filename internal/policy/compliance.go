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

// ComplianceViolation is a single policy violation found in a trace event.
// Named ComplianceViolation to avoid conflict with the campaign-oriented
// Violation type defined in policy.go.
type ComplianceViolation struct {
	EventIndex int    `json:"event_index"`
	Tool       string `json:"tool"`
	Action     string `json:"action,omitempty"`
	Effect     string `json:"effect"`   // "deny" or "alert"
	Rule       string `json:"rule"`     // rule description
	Severity   string `json:"severity"` // "low", "medium", "high", "critical"
}

// ComplianceResult holds the evaluation of one trace against one policy.
type ComplianceResult struct {
	TraceName     string                `json:"trace_name"`
	PolicyName    string                `json:"policy_name"`
	Compliant     bool                  `json:"compliant"`
	DenyCount     int                   `json:"deny_count"`
	AlertCount    int                   `json:"alert_count"`
	AllowCount    int                   `json:"allow_count"`
	CoverageRatio float64               `json:"coverage_ratio"` // fraction of events matched by a rule
	Violations    []ComplianceViolation `json:"violations"`
	Score         float64               `json:"score"` // 0.0 to 1.0
	Grade         string                `json:"grade"` // A/B/C/D/F
}

// ComplianceReport summarizes compliance across multiple traces evaluated
// against a single policy.
type ComplianceReport struct {
	PolicyName         string             `json:"policy_name"`
	TotalTraces        int                `json:"total_traces"`
	CompliantCount     int                `json:"compliant_count"`
	NonCompliantCount  int                `json:"non_compliant_count"`
	TotalViolations    int                `json:"total_violations"`
	CriticalViolations int                `json:"critical_violations"`
	OverallScore       float64            `json:"overall_score"`
	OverallGrade       string             `json:"overall_grade"`
	Results            []ComplianceResult `json:"results"`
}

// ---------------------------------------------------------------------------
// Score penalties applied per deny and alert occurrence.
// ---------------------------------------------------------------------------

const (
	denyScorePenalty  = 0.15
	alertScorePenalty = 0.05
)

// ---------------------------------------------------------------------------
// Core evaluation
// ---------------------------------------------------------------------------

// EvaluateCompliance evaluates a single trace against a policy and returns a
// ComplianceResult. A trace is compliant if it produces zero deny results.
//
// Scoring: starts at 1.0, with -0.15 per deny and -0.05 per alert, clamped
// to [0.0, 1.0]. Coverage is the fraction of trace events matched by any
// rule (deny, alert, or explicit allow) out of total events analyzed.
// Severity comes from the matching rule's priority via effectToSeverity;
// defaults to "medium" for deny and "low" for alert when not determined.
func EvaluateCompliance(p *Policy, trace *Trace) *ComplianceResult {
	cr := &ComplianceResult{}

	// Nil policy — nothing to enforce, everything is compliant.
	if p == nil {
		cr.Compliant = true
		cr.Score = 1.0
		cr.Grade = gradeCompliance(1.0)
		return cr
	}

	// Nil trace — nothing to evaluate, vacuously compliant.
	if trace == nil {
		cr.PolicyName = p.Meta.Name
		cr.Compliant = true
		cr.Score = 1.0
		cr.Grade = gradeCompliance(1.0)
		return cr
	}

	cr.TraceName = trace.ID
	cr.PolicyName = p.Meta.Name

	// Empty trace — no events to violate anything.
	if len(trace.Events) == 0 {
		cr.Compliant = true
		cr.Score = 1.0
		cr.Grade = gradeCompliance(1.0)
		return cr
	}

	// Delegate the heavy lifting to EvaluateTrace.
	result := EvaluateTrace(p, trace)

	cr.DenyCount = result.DeniedCount
	cr.AlertCount = result.AlertedCount
	cr.AllowCount = result.AllowedCount

	// Coverage: EvaluateTrace reports coverage as a percentage (0-100);
	// we store it as a fraction (0.0-1.0).
	cr.CoverageRatio = result.Coverage / 100.0

	// Build compliance violations from trace violations.
	cr.Violations = buildComplianceViolations(trace, result.Violations)

	// A trace is compliant if and only if there are zero deny results.
	cr.Compliant = cr.DenyCount == 0

	// Score: 1.0 minus penalties, clamped to [0, 1].
	cr.Score = computeComplianceScore(cr.DenyCount, cr.AlertCount)
	cr.Grade = gradeCompliance(cr.Score)

	return cr
}

// EvaluateComplianceBatch evaluates multiple traces against a single policy
// and returns an aggregated ComplianceReport.
func EvaluateComplianceBatch(p *Policy, traces []*Trace) *ComplianceReport {
	report := &ComplianceReport{}

	if p != nil {
		report.PolicyName = p.Meta.Name
	}

	report.TotalTraces = len(traces)

	if len(traces) == 0 {
		report.OverallScore = 1.0
		report.OverallGrade = gradeCompliance(1.0)
		return report
	}

	totalScore := 0.0
	report.Results = make([]ComplianceResult, 0, len(traces))

	for _, trace := range traces {
		cr := EvaluateCompliance(p, trace)
		report.Results = append(report.Results, *cr)

		if cr.Compliant {
			report.CompliantCount++
		} else {
			report.NonCompliantCount++
		}

		report.TotalViolations += len(cr.Violations)
		report.CriticalViolations += countCritical(cr.Violations)

		totalScore += cr.Score
	}

	report.OverallScore = totalScore / float64(len(traces))
	report.OverallGrade = gradeCompliance(report.OverallScore)

	return report
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

// computeComplianceScore calculates the compliance score from deny and alert
// counts. Starts at 1.0, deducts denyScorePenalty per deny and
// alertScorePenalty per alert, clamped to [0.0, 1.0].
func computeComplianceScore(denies, alerts int) float64 {
	score := 1.0 - (float64(denies) * denyScorePenalty) - (float64(alerts) * alertScorePenalty)
	if score < 0.0 {
		score = 0.0
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// gradeCompliance converts a compliance score (0.0-1.0) to a letter grade.
//
//	A >= 0.9
//	B >= 0.7
//	C >= 0.5
//	D >= 0.3
//	F  < 0.3
func gradeCompliance(score float64) string {
	switch {
	case score >= 0.9:
		return "A"
	case score >= 0.7:
		return "B"
	case score >= 0.5:
		return "C"
	case score >= 0.3:
		return "D"
	default:
		return "F"
	}
}

// ---------------------------------------------------------------------------
// Violation mapping
// ---------------------------------------------------------------------------

// buildComplianceViolations converts trace-level TraceViolation entries into
// the compliance-oriented ComplianceViolation representation, including
// event indices relative to the trace's Events slice.
func buildComplianceViolations(trace *Trace, tvs []TraceViolation) []ComplianceViolation {
	if len(tvs) == 0 {
		return nil
	}

	out := make([]ComplianceViolation, 0, len(tvs))

	for _, tv := range tvs {
		eventIdx := findEventIndex(trace, tv.Event)

		action := ""
		if tv.Event != nil && tv.Event.ToolCall != nil {
			action = tv.Event.ToolCall.Action
		}

		ruleDesc := ""
		if tv.Rule != nil {
			ruleDesc = tv.Rule.Description
		}

		severity := tv.Severity
		if severity == "" {
			// Default severity when the trace evaluator did not assign one.
			if tv.Effect == "deny" {
				severity = "medium"
			} else {
				severity = "low"
			}
		}

		out = append(out, ComplianceViolation{
			EventIndex: eventIdx,
			Tool:       tv.Tool,
			Action:     action,
			Effect:     tv.Effect,
			Rule:       ruleDesc,
			Severity:   severity,
		})
	}

	return out
}

// findEventIndex returns the index of an event pointer within a trace's
// Events slice. Returns -1 if the event is not found.
func findEventIndex(trace *Trace, ev *TraceEvent) int {
	if trace == nil || ev == nil {
		return -1
	}
	for i := range trace.Events {
		if &trace.Events[i] == ev {
			return i
		}
	}
	return -1
}

// countCritical returns the number of critical-severity violations.
func countCritical(violations []ComplianceViolation) int {
	n := 0
	for _, v := range violations {
		if v.Severity == "critical" {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Formatting — single result
// ---------------------------------------------------------------------------

// FormatComplianceResult returns a box-drawing formatted representation of
// a single compliance evaluation result.
func FormatComplianceResult(cr *ComplianceResult) string {
	if cr == nil {
		return "No compliance result.\n"
	}

	var b strings.Builder

	// Header.
	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│           Compliance Evaluation                     │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	if cr.TraceName != "" {
		b.WriteString(fmt.Sprintf("│ Trace:    %-41s │\n", truncStr(cr.TraceName, 41)))
	}
	if cr.PolicyName != "" {
		b.WriteString(fmt.Sprintf("│ Policy:   %-41s │\n", truncStr(cr.PolicyName, 41)))
	}

	status := "COMPLIANT"
	if !cr.Compliant {
		status = "NON-COMPLIANT"
	}
	b.WriteString(fmt.Sprintf("│ Status:   %-41s │\n", status))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Score and metrics.
	b.WriteString(fmt.Sprintf("│ Score:    %-41s │\n",
		fmt.Sprintf("%.2f  Grade: %s", cr.Score, cr.Grade)))
	b.WriteString(fmt.Sprintf("│ Coverage: %-41s │\n",
		fmt.Sprintf("%.1f%%", cr.CoverageRatio*100)))
	b.WriteString(fmt.Sprintf("│ Denied: %-3d Alerted: %-3d Allowed: %-13d │\n",
		cr.DenyCount, cr.AlertCount, cr.AllowCount))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Violations section.
	if len(cr.Violations) == 0 {
		b.WriteString("│ No violations found                                 │\n")
	} else {
		b.WriteString(fmt.Sprintf("│ Violations (%d):%-37s│\n", len(cr.Violations), ""))
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for i, v := range cr.Violations {
			if i >= 20 {
				rem := fmt.Sprintf("   ... and %d more", len(cr.Violations)-20)
				b.WriteString(fmt.Sprintf("│%-53s│\n", rem))
				break
			}
			effect := strings.ToUpper(v.Effect)
			line := fmt.Sprintf(" %d. [%s] %-20s (%s)",
				i+1, effect, truncStr(v.Tool, 20), v.Severity)
			b.WriteString(fmt.Sprintf("│%-53s│\n", line))
			if v.Rule != "" {
				desc := fmt.Sprintf("    %s", truncStr(v.Rule, 49))
				b.WriteString(fmt.Sprintf("│%-53s│\n", desc))
			}
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Formatting — batch report
// ---------------------------------------------------------------------------

// FormatComplianceReport returns a box-drawing formatted representation of
// an aggregated compliance report covering multiple traces.
func FormatComplianceReport(report *ComplianceReport) string {
	if report == nil {
		return "No compliance report.\n"
	}

	var b strings.Builder

	// Header.
	b.WriteString("┌─────────────────────────────────────────────────────┐\n")
	b.WriteString("│             Compliance Report                       │\n")
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	if report.PolicyName != "" {
		b.WriteString(fmt.Sprintf("│ Policy:           %-33s │\n", truncStr(report.PolicyName, 33)))
	}
	b.WriteString(fmt.Sprintf("│ Total Traces:     %-33d │\n", report.TotalTraces))
	b.WriteString(fmt.Sprintf("│ Compliant:        %-33d │\n", report.CompliantCount))
	b.WriteString(fmt.Sprintf("│ Non-Compliant:    %-33d │\n", report.NonCompliantCount))
	b.WriteString(fmt.Sprintf("│ Total Violations: %-33d │\n", report.TotalViolations))
	b.WriteString(fmt.Sprintf("│ Critical:         %-33d │\n", report.CriticalViolations))
	b.WriteString(fmt.Sprintf("│ Overall Score:    %-33s │\n",
		fmt.Sprintf("%.2f  Grade: %s", report.OverallScore, report.OverallGrade)))
	b.WriteString("├─────────────────────────────────────────────────────┤\n")

	// Per-trace results.
	if len(report.Results) == 0 {
		b.WriteString("│ No traces evaluated                                 │\n")
	} else {
		b.WriteString("│ Results:                                            │\n")
		b.WriteString("├─────────────────────────────────────────────────────┤\n")
		for i, r := range report.Results {
			if i >= 30 {
				rem := fmt.Sprintf("   ... and %d more", len(report.Results)-30)
				b.WriteString(fmt.Sprintf("│%-53s│\n", rem))
				break
			}
			status := "PASS"
			if !r.Compliant {
				status = "FAIL"
			}
			line := fmt.Sprintf(" %d. %-15s %-4s  %.2f (%s)",
				i+1, truncStr(r.TraceName, 15), status, r.Score, r.Grade)
			b.WriteString(fmt.Sprintf("│%-53s│\n", line))

			// Show violation count for failing traces.
			if !r.Compliant && len(r.Violations) > 0 {
				detail := fmt.Sprintf("    %d violation(s): %d deny, %d alert",
					len(r.Violations), r.DenyCount, r.AlertCount)
				b.WriteString(fmt.Sprintf("│%-53s│\n", truncStr(detail, 53)))
			}
		}
	}

	b.WriteString("└─────────────────────────────────────────────────────┘\n")
	return b.String()
}
