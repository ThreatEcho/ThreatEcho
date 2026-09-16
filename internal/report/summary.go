// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"fmt"
	"io"
	"strings"
)

// SummaryData holds the aggregated posture data for the summary dashboard.
type SummaryData struct {
	Campaigns     []SummaryCampaign
	PolicyResults []SummaryPolicy
	GapSummary    SummaryGaps
	LintSummary   SummaryLint
}

// SummaryCampaign describes one campaign's headline stats.
type SummaryCampaign struct {
	Name       string
	Adversary  string
	Stages     int
	Techniques int
	Severity   string
	LintClean  bool
}

// SummaryPolicy describes one policy evaluation result.
type SummaryPolicy struct {
	Name    string
	Rules   int
	Denied  int
	Alerted int
	Allowed int
}

// SummaryGaps holds the aggregate gap posture.
type SummaryGaps struct {
	Total        int
	Critical     int
	High         int
	Medium       int
	Low          int
	Score        float64
	AttackCovPct int
	AtlasCovPct  int
}

// SummaryLint holds aggregate lint results.
type SummaryLint struct {
	Total    int
	Clean    int
	Warnings int
}

// SummaryTextReport writes a compact ANSI posture dashboard to w.
func SummaryTextReport(w io.Writer, s *SummaryData) {
	line := strings.Repeat("─", 64)

	// Header.
	fmt.Fprintf(w, "\n%s%s%s\n", bold, line, reset)
	fmt.Fprintf(w, "%s  ThreatEcho — Security Posture Summary%s\n", bold, reset)
	fmt.Fprintf(w, "%s%s%s\n", dim, line, reset)

	// Campaigns section.
	fmt.Fprintf(w, "\n  %sCAMPAIGNS (%d)%s\n", bold, len(s.Campaigns), reset)

	if len(s.Campaigns) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s%-28s %-12s %-7s %-10s %s%s\n",
			dim, "Name", "Adversary", "Stages", "Severity", "Lint", reset)

		for _, c := range s.Campaigns {
			lint := green + "✓" + reset
			if !c.LintClean {
				lint = yellow + "⚠" + reset
			}
			fmt.Fprintf(w, "  %-28s %-12s %-7d %-10s %s\n",
				truncate(c.Name, 28),
				truncate(c.Adversary, 12),
				c.Stages,
				summSeverityColor(c.Severity),
				lint,
			)
		}
	}

	// Lint summary.
	if s.LintSummary.Total > 0 {
		fmt.Fprintln(w)
		lintColor := green
		lintStatus := "all clean"
		if s.LintSummary.Warnings > 0 {
			lintColor = yellow
			lintStatus = fmt.Sprintf("%d with warnings", s.LintSummary.Warnings)
		}
		fmt.Fprintf(w, "  %sLint:%s %s%s%s  (%d/%d clean)\n",
			bold, reset,
			lintColor, lintStatus, reset,
			s.LintSummary.Clean, s.LintSummary.Total,
		)
	}

	// Coverage section.
	fmt.Fprintf(w, "\n%s%s%s\n", dim, line, reset)
	fmt.Fprintf(w, "\n  %sCOVERAGE%s\n\n", bold, reset)

	attackPart := fmt.Sprintf("ATT&CK Tactics:  %s%d%%", coveragePctColor(s.GapSummary.AttackCovPct), s.GapSummary.AttackCovPct)
	atlasPart := fmt.Sprintf("ATLAS Tactics:  %s%d%%", coveragePctColor(s.GapSummary.AtlasCovPct), s.GapSummary.AtlasCovPct)
	fmt.Fprintf(w, "    %s%s    %s%s\n", attackPart, reset, atlasPart, reset)

	scoreColor := green
	if s.GapSummary.Score >= 60 {
		scoreColor = red
	} else if s.GapSummary.Score >= 30 {
		scoreColor = yellow
	}
	fmt.Fprintf(w, "    Risk Score:       %s%.0f/100%s\n", scoreColor, s.GapSummary.Score, reset)

	if s.GapSummary.Total > 0 {
		fmt.Fprintf(w, "    Gaps:             %s%d critical%s",
			critColor(s.GapSummary.Critical), s.GapSummary.Critical, reset)
		fmt.Fprintf(w, " %s│%s %s%d high%s",
			dim, reset,
			highColor(s.GapSummary.High), s.GapSummary.High, reset)
		fmt.Fprintf(w, " %s│%s %s%d medium%s",
			dim, reset,
			yellow, s.GapSummary.Medium, reset)
		fmt.Fprintf(w, " %s│%s %s%d low%s\n",
			dim, reset,
			dim, s.GapSummary.Low, reset)
	} else {
		fmt.Fprintf(w, "    Gaps:             %sNone detected%s\n", green, reset)
	}

	// Policy section.
	fmt.Fprintf(w, "\n%s%s%s\n", dim, line, reset)
	fmt.Fprintf(w, "\n  %sPOLICIES (%d)%s\n\n", bold, len(s.PolicyResults), reset)

	if len(s.PolicyResults) > 0 {
		for _, p := range s.PolicyResults {
			deniedStr := fmt.Sprintf("%d denied", p.Denied)
			if p.Denied > 0 {
				deniedStr = red + deniedStr + reset
			} else {
				deniedStr = green + deniedStr + reset
			}

			alertedStr := fmt.Sprintf("%d alerted", p.Alerted)
			if p.Alerted > 0 {
				alertedStr = yellow + alertedStr + reset
			}

			fmt.Fprintf(w, "    %s%s%s: %d rules → %s, %s, %s%d allowed%s\n",
				bold, p.Name, reset,
				p.Rules,
				deniedStr,
				alertedStr,
				dim, p.Allowed, reset,
			)
		}
	} else {
		fmt.Fprintf(w, "    %sNo policies evaluated%s\n", dim, reset)
	}

	// Footer.
	fmt.Fprintf(w, "\n%s%s%s\n\n", bold, line, reset)
}

// truncate shortens a string to maxLen, appending an ellipsis if trimmed.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// summSeverityColor returns a severity string with the appropriate color.
func summSeverityColor(sev string) string {
	switch sev {
	case "critical":
		return red + bold + "critical" + reset
	case "high":
		return red + "high" + reset
	case "medium":
		return yellow + "medium" + reset
	case "low":
		return green + "low" + reset
	default:
		return sev
	}
}

// coveragePctColor picks a color based on a coverage percentage.
func coveragePctColor(pct int) string {
	if pct >= 70 {
		return green
	}
	if pct >= 40 {
		return yellow
	}
	return red
}

// critColor returns red if n > 0, dim otherwise.
func critColor(n int) string {
	if n > 0 {
		return red + bold
	}
	return dim
}

// highColor returns red if n > 0, dim otherwise.
func highColor(n int) string {
	if n > 0 {
		return red
	}
	return dim
}
