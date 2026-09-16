// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestSummaryTextReport_Output(t *testing.T) {
	data := &SummaryData{
		Campaigns: []SummaryCampaign{
			{
				Name:       "apt29-cozy-bear",
				Adversary:  "APT29",
				Stages:     8,
				Techniques: 8,
				Severity:   "critical",
				LintClean:  true,
			},
			{
				Name:       "fin7-carbanak",
				Adversary:  "FIN7",
				Stages:     10,
				Techniques: 9,
				Severity:   "critical",
				LintClean:  true,
			},
			{
				Name:       "llm-agent-hijack",
				Adversary:  "AI Threat",
				Stages:     13,
				Techniques: 12,
				Severity:   "high",
				LintClean:  false,
			},
		},
		PolicyResults: []SummaryPolicy{
			{
				Name:    "agent-default",
				Rules:   10,
				Denied:  5,
				Alerted: 3,
				Allowed: 18,
			},
		},
		GapSummary: SummaryGaps{
			Total:        14,
			Critical:     3,
			High:         2,
			Medium:       8,
			Low:          1,
			Score:        45,
			AttackCovPct: 71,
			AtlasCovPct:  85,
		},
		LintSummary: SummaryLint{
			Total:    3,
			Clean:    2,
			Warnings: 1,
		},
	}

	var buf bytes.Buffer
	SummaryTextReport(&buf, data)
	out := buf.String()

	// Verify key sections are present.
	sections := []string{
		"Security Posture Summary",
		"CAMPAIGNS (3)",
		"apt29-cozy-bear",
		"fin7-carbanak",
		"llm-agent-hijack",
		"APT29",
		"FIN7",
		"AI Threat",
		"COVERAGE",
		"71%",
		"85%",
		"45/100",
		"3 critical",
		"2 high",
		"8 medium",
		"1 low",
		"POLICIES (1)",
		"agent-default",
		"10 rules",
		"5 denied",
		"3 alerted",
		"18 allowed",
	}

	for _, section := range sections {
		if !strings.Contains(out, section) {
			t.Errorf("output missing expected content: %q", section)
		}
	}

	// Verify lint warning indicator appears.
	if !strings.Contains(out, "1 with warnings") {
		t.Error("output missing lint warning count")
	}

	// Verify lint clean count.
	if !strings.Contains(out, "2/3 clean") {
		t.Error("output missing lint clean ratio")
	}
}

func TestSummaryTextReport_Empty(t *testing.T) {
	data := &SummaryData{}

	var buf bytes.Buffer
	// Must not panic on empty data.
	SummaryTextReport(&buf, data)
	out := buf.String()

	if !strings.Contains(out, "Security Posture Summary") {
		t.Error("output missing header on empty data")
	}
	if !strings.Contains(out, "CAMPAIGNS (0)") {
		t.Error("output missing zero-campaign indicator")
	}
	if !strings.Contains(out, "POLICIES (0)") {
		t.Error("output missing zero-policy indicator")
	}
	if !strings.Contains(out, "None detected") {
		t.Error("output should show 'None detected' for zero gaps")
	}
	if !strings.Contains(out, "No policies evaluated") {
		t.Error("output should indicate no policies were evaluated")
	}
}
