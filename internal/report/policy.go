// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// PolicyTextReport writes a human-readable policy evaluation report.
func PolicyTextReport(w io.Writer, r *policy.EvalResult) {
	// Header.
	fmt.Fprintf(w, "\n%s╔══ Policy Evaluation ══╗%s\n", cyan, reset)
	fmt.Fprintf(w, "  Policy:    %s%s%s\n", bold, r.Policy, reset)
	fmt.Fprintf(w, "  Campaign:  %s%s%s\n", bold, r.Campaign, reset)
	fmt.Fprintf(w, "  Stages:    %d\n", r.TotalStages)

	// Summary bar.
	fmt.Fprintf(w, "\n%s── Summary ──%s\n", cyan, reset)
	fmt.Fprintf(w, "  %s✓ Allowed:  %d%s\n", green, r.Allowed, reset)
	if r.Denied > 0 {
		fmt.Fprintf(w, "  %s✗ Denied:   %d%s\n", red, r.Denied, reset)
	} else {
		fmt.Fprintf(w, "  ✗ Denied:   0\n")
	}
	if r.Alerted > 0 {
		fmt.Fprintf(w, "  %s⚠ Alerted:  %d%s\n", yellow, r.Alerted, reset)
	} else {
		fmt.Fprintf(w, "  ⚠ Alerted:  0\n")
	}

	// Verdict.
	if r.Denied > 0 {
		fmt.Fprintf(w, "\n  Verdict: %s%sFAIL%s — %d stage(s) denied\n",
			red, bold, reset, r.Denied)
	} else if r.Alerted > 0 {
		fmt.Fprintf(w, "\n  Verdict: %s%sWARN%s — %d alert(s) raised\n",
			yellow, bold, reset, r.Alerted)
	} else {
		fmt.Fprintf(w, "\n  Verdict: %s%sPASS%s — all stages allowed\n",
			green, bold, reset)
	}

	// Violations detail.
	if len(r.Violations) > 0 {
		fmt.Fprintf(w, "\n%s── Violations ──%s\n", cyan, reset)
		for i, v := range r.Violations {
			effectColor := red
			effectSymbol := "✗"
			if v.Effect == "alert" {
				effectColor = yellow
				effectSymbol = "⚠"
			}

			fmt.Fprintf(w, "\n  %s%s %s%s\n", effectColor, effectSymbol, v.Reason, reset)
			fmt.Fprintf(w, "    Stage:     %s (%s)\n", v.StageName, v.StageID)
			if v.Technique != "" {
				fmt.Fprintf(w, "    Technique: %s\n", v.Technique)
			}
			if v.Tactic != "" {
				fmt.Fprintf(w, "    Tactic:    %s\n", v.Tactic)
			}
			if v.Tool != "" {
				fmt.Fprintf(w, "    Tool:      %s\n", v.Tool)
			}
			fmt.Fprintf(w, "    Rule:      %s\n", v.RuleID)
			if i < len(r.Violations)-1 {
				fmt.Fprintf(w, "    %s\n", strings.Repeat("·", 40))
			}
		}
	}

	fmt.Fprintln(w)
}
