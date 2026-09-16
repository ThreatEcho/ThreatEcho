// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// ANSI color codes.
var (
	reset  = "[0m"
	bold   = "[1m"
	dim    = "[2m"
	red    = "[31m"
	green  = "[32m"
	yellow = "[33m"
	blue   = "[34m"
	cyan   = "[36m"
	white  = "[37m"
)

func init() {
	if os.Getenv("NO_COLOR") != "" {
		reset, bold, dim = "", "", ""
		red, green, yellow, blue, cyan, white = "", "", "", "", "", ""
	}
}

// TextReport writes a formatted simulation/run report to w.
func TextReport(w io.Writer, r *engine.RunResult) {
	c := r.Campaign

	// Header.
	line := strings.Repeat("─", 64)
	fmt.Fprintf(w, "\n%s%s%s\n", bold, line, reset)
	fmt.Fprintf(w, "%s  ThreatEcho — Adversary Campaign %s%s\n", bold, titleCase(r.Mode), reset)
	fmt.Fprintf(w, "%s%s\n\n", dim, line+reset)

	fmt.Fprintf(w, "  %sCampaign:%s   %s\n", bold, reset, c.Meta.Name)
	fmt.Fprintf(w, "  %sAdversary:%s  %s\n", bold, reset, c.Meta.Adversary)
	fmt.Fprintf(w, "  %sObjective:%s  %s\n", bold, reset, c.Meta.Objective)
	fmt.Fprintf(w, "  %sSeverity:%s   %s\n", bold, reset, severityColor(c.Meta.Severity))

	techniques := c.UniqueTechniques()
	tactics := c.UniqueTactics()
	fmt.Fprintf(w, "  %sStages:%s     %d  │  %sTechniques:%s %d  │  %sTactics:%s %d/14\n",
		bold, reset, len(c.Stages),
		bold, reset, len(techniques),
		bold, reset, len(tactics))
	fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)

	// Stages.
	for _, sr := range r.Stages {
		s := sr.Stage
		techName := s.Technique
		if t := mitre.LookupTechnique(s.Technique); t != nil {
			techName = fmt.Sprintf("%s — %s", s.Technique, t.Name)
		}

		tacticName := s.Tactic
		if t := mitre.TacticByShort(s.Tactic); t != nil {
			tacticName = t.Name
		}

		if sr.Skipped {
			fmt.Fprintf(w, "  %s[%d/%d]%s %s%s%s\n", dim, sr.Order, len(r.Stages), reset, dim, s.Name, reset)
			fmt.Fprintf(w, "        %sSKIPPED: %s%s\n\n", yellow, sr.SkipMsg, reset)
			continue
		}

		fmt.Fprintf(w, "  %s[%d/%d]%s %s%s%s\n", cyan, sr.Order, len(r.Stages), reset, bold, s.Name, reset)
		fmt.Fprintf(w, "        Technique:  %s%s%s\n", white, techName, reset)
		fmt.Fprintf(w, "        Tactic:     %s\n", tacticName)

		if len(s.DependsOn) > 0 {
			fmt.Fprintf(w, "        Depends on: %s\n", strings.Join(s.DependsOn, ", "))
		}

		// Execute details.
		fmt.Fprintf(w, "        Execute:    %s%s%s", blue, s.Execute.Type, reset)
		if sr.Exec.Output != "" {
			fmt.Fprintf(w, " — %s", sr.Exec.Output)
		}
		fmt.Fprintln(w)
		if s.Execute.Elevated {
			fmt.Fprintf(w, "                    %s⚡ elevated%s\n", yellow, reset)
		}

		// Expected telemetry.
		if len(s.Expect.Telemetry) > 0 {
			fmt.Fprintf(w, "        Telemetry:  %s\n", strings.Join(s.Expect.Telemetry, ", "))
		}

		// Expected detections.
		if len(s.Expect.Detections) > 0 {
			fmt.Fprintf(w, "        Detections: %s\n", strings.Join(s.Expect.Detections, ", "))
		}

		// Transition.
		if s.OnSuccess != "" {
			fmt.Fprintf(w, "        %s───→%s on success: %s\n", dim, reset, s.OnSuccess)
		}
		if s.OnFailure != "" && s.OnFailure != "abort" {
			fmt.Fprintf(w, "        %s───✗%s on failure: %s\n", dim, reset, s.OnFailure)
		}
		fmt.Fprintln(w)
	}

	// Coverage summary.
	fmt.Fprintf(w, "%s%s%s\n\n", dim, line, reset)
	fmt.Fprintf(w, "  %sCOVERAGE SUMMARY%s\n\n", bold, reset)

	covered, missing := r.TacticCoverage()
	fmt.Fprintf(w, "  Tactic Coverage: %s%d/14%s (%d%%)\n", bold, len(covered), reset, len(covered)*100/14)

	// Print tactics in columns.
	fmt.Fprintln(w)
	allTactics := append(covered, missing...)
	coveredSet := make(map[string]bool)
	for _, t := range covered {
		coveredSet[t] = true
	}
	col := 0
	for _, t := range allTactics {
		name := t
		if tac := mitre.TacticByShort(t); tac != nil {
			name = tac.Name
		}
		if coveredSet[t] {
			fmt.Fprintf(w, "    %s✓ %-26s%s", green, name, reset)
		} else {
			fmt.Fprintf(w, "    %s✗ %-26s%s", red, name, reset)
		}
		col++
		if col%3 == 0 {
			fmt.Fprintln(w)
		}
	}
	if col%3 != 0 {
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w)
	telemetry := c.AllTelemetryTypes()
	detections := c.AllDetections()
	fmt.Fprintf(w, "  Techniques:       %d unique\n", len(techniques))
	fmt.Fprintf(w, "  Telemetry types:  %d\n", len(telemetry))
	fmt.Fprintf(w, "  Detection rules:  %d referenced\n", len(detections))
	fmt.Fprintf(w, "  Stages completed: %d  │  Skipped: %d\n", r.Completed, r.Skipped)
	fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)
}

// titleCase uppercases the first letter of s without the deprecated strings.Title.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func severityColor(sev string) string {
	switch sev {
	case "critical":
		return red + bold + "CRITICAL" + reset
	case "high":
		return red + "HIGH" + reset
	case "medium":
		return yellow + "MEDIUM" + reset
	case "low":
		return green + "LOW" + reset
	default:
		return sev
	}
}
