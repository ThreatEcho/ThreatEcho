// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/gap"
)

// CoverageTextReport writes a technique-level coverage analysis to w.
func CoverageTextReport(w io.Writer, cr *gap.CoverageReport) {
	line := strings.Repeat("─", 64)

	// Header.
	fmt.Fprintf(w, "\n%s%s%s\n", bold, line, reset)
	fmt.Fprintf(w, "%s  ThreatEcho — Technique Coverage Report%s\n", bold, reset)
	fmt.Fprintf(w, "%s%s%s\n\n", dim, line, reset)

	// Overall stats.
	fmt.Fprintf(w, "  %sOVERALL COVERAGE%s\n\n", bold, reset)
	fmt.Fprintf(w, "    Techniques in registry:  %s%d%s\n", white, cr.TotalTechniquesInRegistry, reset)
	fmt.Fprintf(w, "    Techniques exercised:    %s%d%s", white, cr.TechniquesExercised, reset)
	if cr.TotalTechniquesInRegistry > 0 {
		pct := cr.TechniquesExercised * 100 / cr.TotalTechniquesInRegistry
		fmt.Fprintf(w, " (%d%%)", pct)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "    With detections:         %s%d%s\n", green, cr.TechniquesWithDetections, reset)
	fmt.Fprintf(w, "    With telemetry only:     %s%d%s\n", yellow, cr.TechniquesWithTelemetry-cr.TechniquesWithDetections, reset)
	fmt.Fprintf(w, "    Uncovered in registry:   %s%d%s\n", red, len(cr.TechniquesUncovered), reset)

	// Framework breakdown.
	fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)
	fmt.Fprintf(w, "  %sFRAMEWORK BREAKDOWN%s\n\n", bold, reset)
	fw := cr.ByFramework
	printFrameworkLine(w, "MITRE ATT&CK", fw.ATTACKCovered, fw.ATTACKTotal)
	printFrameworkLine(w, "MITRE ATLAS", fw.ATLASCovered, fw.ATLASTotal)
	printFrameworkLine(w, "OWASP LLM", fw.OWASPCovered, fw.OWASPTotal)

	// Per-tactic technique drill-down.
	fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)
	fmt.Fprintf(w, "  %sTECHNIQUE DETAIL BY TACTIC%s\n", bold, reset)

	// Sort tactics for stable output.
	tactics := tacticOrder()
	for _, tactic := range tactics {
		tcs, ok := cr.TechniquesByTactic[tactic]
		if !ok {
			continue
		}
		fmt.Fprintf(w, "\n    %s%s%s (%d technique%s)\n",
			cyan+bold, tacticDisplayName(tactic), reset, len(tcs), plural(len(tcs)))

		for _, tc := range tcs {
			statusIcon, statusColor := statusDisplay(tc.Status)
			fmt.Fprintf(w, "      %s%s%s %s%s%s — %s\n",
				statusColor, statusIcon, reset,
				bold, tc.TechniqueID, reset, tc.TechniqueName)

			// Campaigns.
			fmt.Fprintf(w, "          Campaigns: %s%s%s\n",
				dim, strings.Join(tc.Campaigns, ", "), reset)

			// Telemetry types.
			if len(tc.TelemetryTypes) > 0 {
				fmt.Fprintf(w, "          Telemetry: %s\n", strings.Join(tc.TelemetryTypes, ", "))
			}

			// Detection rules.
			if len(tc.DetectionRules) > 0 {
				fmt.Fprintf(w, "          Detections: %s%s%s\n",
					green, strings.Join(tc.DetectionRules, ", "), reset)
			} else {
				fmt.Fprintf(w, "          Detections: %s— none —%s\n", red, reset)
			}
		}
	}

	// Summary table.
	fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)
	fmt.Fprintf(w, "  %sCOVERAGE SUMMARY%s\n\n", bold, reset)

	// Count by status.
	statusCounts := make(map[string]int)
	for _, tc := range cr.Techniques {
		statusCounts[tc.Status]++
	}

	fmt.Fprintf(w, "    %s● Full%s         %-4d  (telemetry + detections)\n",
		green, reset, statusCounts["full"])
	fmt.Fprintf(w, "    %s● Telemetry%s    %-4d  (telemetry only, no detections)\n",
		yellow, reset, statusCounts["telemetry-only"])
	fmt.Fprintf(w, "    %s● Partial%s      %-4d  (detections without telemetry)\n",
		yellow, reset, statusCounts["partial"])
	fmt.Fprintf(w, "    %s● Uncovered%s    %-4d  (exercised but no telemetry or detections)\n",
		red, reset, statusCounts["uncovered"])
	fmt.Fprintf(w, "    %s○ Not used%s     %-4d  (in registry, not in any campaign)\n",
		dim, reset, len(cr.TechniquesUncovered))

	fmt.Fprintf(w, "\n%s%s%s\n\n", dim, line, reset)
}

// printFrameworkLine renders one framework's coverage bar.
func printFrameworkLine(w io.Writer, name string, covered, total int) {
	pct := 0
	if total > 0 {
		pct = covered * 100 / total
	}
	// Simple bar: 20 chars wide.
	const barWidth = 20
	filled := 0
	if total > 0 {
		filled = covered * barWidth / total
	}
	if filled > barWidth {
		filled = barWidth
	}

	barColor := green
	if pct < 25 {
		barColor = red
	} else if pct < 50 {
		barColor = yellow
	}

	fmt.Fprintf(w, "    %-16s %s%s%s%s%s  %d/%d (%d%%)\n",
		name,
		barColor, strings.Repeat("▓", filled), reset,
		dim, strings.Repeat("░", barWidth-filled),
		covered, total, pct)
}

func statusDisplay(status string) (icon string, color string) {
	switch status {
	case "full":
		return "✓", green
	case "partial":
		return "◐", yellow
	case "telemetry-only":
		return "◑", yellow
	case "uncovered":
		return "✗", red
	default:
		return "?", dim
	}
}

func tacticDisplayName(short string) string {
	names := map[string]string{
		"reconnaissance":       "Reconnaissance",
		"resource-development": "Resource Development",
		"initial-access":       "Initial Access",
		"execution":            "Execution",
		"persistence":          "Persistence",
		"privilege-escalation": "Privilege Escalation",
		"defense-evasion":      "Defense Evasion",
		"credential-access":    "Credential Access",
		"discovery":            "Discovery",
		"lateral-movement":     "Lateral Movement",
		"collection":           "Collection",
		"command-and-control":  "Command and Control",
		"exfiltration":         "Exfiltration",
		"impact":               "Impact",
		"ml-attack-staging":    "ML Attack Staging",
		"ml-model-access":      "ML Model Access",
	}
	if n, ok := names[short]; ok {
		return n
	}
	return short
}

func tacticOrder() []string {
	return []string{
		"reconnaissance", "resource-development", "initial-access",
		"execution", "persistence", "privilege-escalation",
		"defense-evasion", "credential-access", "discovery",
		"lateral-movement", "collection", "command-and-control",
		"exfiltration", "impact",
		"ml-attack-staging", "ml-model-access",
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// CoverageMarkdownReport writes a technique-level coverage report as GFM.
func CoverageMarkdownReport(w io.Writer, cr *gap.CoverageReport) error {
	fmt.Fprintln(w, "# Technique Coverage Report")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "## Overview")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "| Metric | Value |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| Techniques in registry | %d |\n", cr.TotalTechniquesInRegistry)
	fmt.Fprintf(w, "| Techniques exercised | %d |\n", cr.TechniquesExercised)
	fmt.Fprintf(w, "| With detections | %d |\n", cr.TechniquesWithDetections)
	fmt.Fprintf(w, "| With telemetry | %d |\n", cr.TechniquesWithTelemetry)
	fmt.Fprintf(w, "| Uncovered | %d |\n", len(cr.TechniquesUncovered))
	fmt.Fprintln(w)

	// Framework breakdown.
	fw := cr.ByFramework
	fmt.Fprintln(w, "## Framework Coverage")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Framework | Covered | Total | % |")
	fmt.Fprintln(w, "|-----------|---------|-------|---|")
	printMdFwRow(w, "MITRE ATT&CK", fw.ATTACKCovered, fw.ATTACKTotal)
	printMdFwRow(w, "MITRE ATLAS", fw.ATLASCovered, fw.ATLASTotal)
	printMdFwRow(w, "OWASP LLM", fw.OWASPCovered, fw.OWASPTotal)
	fmt.Fprintln(w)

	// Technique table.
	fmt.Fprintln(w, "## Technique Details")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Technique | Name | Tactic | Status | Campaigns | Detections |")
	fmt.Fprintln(w, "|-----------|------|--------|--------|-----------|------------|")

	// Sort by tactic order, then technique ID.
	sorted := make([]gap.TechniqueCoverage, len(cr.Techniques))
	copy(sorted, cr.Techniques)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Tactic != sorted[j].Tactic {
			return tacticIndex(sorted[i].Tactic) < tacticIndex(sorted[j].Tactic)
		}
		return sorted[i].TechniqueID < sorted[j].TechniqueID
	})

	for _, tc := range sorted {
		statusEmoji := "❌"
		switch tc.Status {
		case "full":
			statusEmoji = "✅"
		case "telemetry-only":
			statusEmoji = "🟡"
		case "partial":
			statusEmoji = "🟠"
		}
		dets := "—"
		if len(tc.DetectionRules) > 0 {
			dets = strings.Join(tc.DetectionRules, ", ")
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s %s | %s | %s |\n",
			tc.TechniqueID, tc.TechniqueName, tc.Tactic,
			statusEmoji, tc.Status,
			strings.Join(tc.Campaigns, ", "),
			dets)
	}
	fmt.Fprintln(w)

	return nil
}

func printMdFwRow(w io.Writer, name string, covered, total int) {
	pct := 0
	if total > 0 {
		pct = covered * 100 / total
	}
	fmt.Fprintf(w, "| %s | %d | %d | %d%% |\n", name, covered, total, pct)
}

func tacticIndex(short string) int {
	order := tacticOrder()
	for i, t := range order {
		if t == short {
			return i
		}
	}
	return len(order) // unknown tactics sort last
}
