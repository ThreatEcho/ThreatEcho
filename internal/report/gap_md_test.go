// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ThreatEcho/threatecho/internal/gap"
)

// sampleMdGapReport builds a realistic GapReport for Markdown report testing.
func sampleMdGapReport() *gap.GapReport {
	return &gap.GapReport{
		GeneratedAt: time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC),
		Campaigns: []gap.CampaignCoverage{
			{
				Name:           "fin6-campaign",
				Adversary:      "FIN6",
				Stages:         8,
				Completed:      7,
				Skipped:        1,
				TechniquesUsed: 5,
				AttackTactics: gap.TacticBreakdown{
					Total:   14,
					Covered: 4,
					Missing: []string{"reconnaissance", "resource-development"},
					Details: []gap.TacticDetail{
						{Short: "execution", Name: "Execution", Stages: 3},
						{Short: "initial-access", Name: "Initial Access", Stages: 2},
						{Short: "exfiltration", Name: "Exfiltration", Stages: 1},
						{Short: "discovery", Name: "Discovery", Stages: 1},
					},
				},
				AtlasTactics: gap.TacticBreakdown{Total: 7, Covered: 0},
				Framework:    gap.FrameworkBreakdown{ATTACKStages: 7},
			},
		},
		Aggregate: gap.AggregateCoverage{
			TotalCampaigns:   1,
			TotalStages:      8,
			TotalCompleted:   7,
			TotalSkipped:     1,
			UniqueTechniques: 5,
			UniqueDetections: 6,
			UniqueTelemetry:  4,
			AttackTactics: gap.TacticBreakdown{
				Total:   14,
				Covered: 4,
				Missing: []string{"reconnaissance"},
				Details: []gap.TacticDetail{
					{Short: "execution", Name: "Execution", Stages: 3},
					{Short: "initial-access", Name: "Initial Access", Stages: 2},
					{Short: "exfiltration", Name: "Exfiltration", Stages: 1},
					{Short: "discovery", Name: "Discovery", Stages: 1},
				},
			},
			AtlasTactics: gap.TacticBreakdown{Total: 7, Covered: 0},
			Framework:    gap.FrameworkBreakdown{ATTACKStages: 7},
		},
		Gaps: []gap.Gap{
			{
				CampaignName:  "fin6-campaign",
				StageID:       "s1",
				StageName:     "PowerShell Execution",
				Technique:     "T1059.001",
				TechniqueName: "PowerShell",
				Tactic:        "execution",
				Type:          gap.GapDetectionMissing,
				Risk:          "high",
				Description:   "Stage declares expected telemetry but no detection rules",
			},
			{
				CampaignName:  "fin6-campaign",
				StageID:       "s3",
				StageName:     "Credential Dump",
				Technique:     "T1003",
				TechniqueName: "OS Credential Dumping",
				Tactic:        "credential-access",
				Type:          gap.GapTelemetryMissing,
				Risk:          "medium",
				Description:   "Stage declares no expected telemetry",
			},
			{
				Tactic:      "initial-access",
				Type:        gap.GapTacticUncovered,
				Risk:        "critical",
				Description: "ATT&CK tactic \"Initial Access\" has no stage coverage across any analyzed campaign",
			},
			{
				CampaignName: "fin6-campaign",
				StageID:      "s5",
				StageName:    "Lateral Movement",
				Technique:    "T1021",
				Tactic:       "lateral-movement",
				Type:         gap.GapTelemetryMissing,
				Risk:         "low",
				Description:  "Stage declares no expected telemetry",
			},
		},
		RiskSummary: gap.RiskSummary{
			Critical: 1,
			High:     1,
			Medium:   1,
			Low:      1,
			Total:    4,
			Score:    45.0,
		},
	}
}

func TestGapMarkdownReport_ValidOutput(t *testing.T) {
	r := sampleMdGapReport()

	var buf bytes.Buffer
	err := GapMarkdownReport(&buf, r)
	if err != nil {
		t.Fatalf("GapMarkdownReport failed: %v", err)
	}

	md := buf.String()

	// Must contain the title.
	if !strings.Contains(md, "# ThreatEcho — Detection Gap Analysis") {
		t.Error("missing main title")
	}

	// Must contain section headers.
	sections := []string{
		"## Summary",
		"## Framework Coverage",
		"## ATT&CK Tactic Coverage",
		"## Campaigns",
		"## Detection Gaps",
		"## Risk Summary",
	}
	for _, s := range sections {
		if !strings.Contains(md, s) {
			t.Errorf("missing section header: %q", s)
		}
	}

	// Summary table values.
	summaryChecks := []string{
		"| Campaigns Analyzed | 1 |",
		"| Total Stages | 8 |",
		"| Unique Techniques | 5 |",
		"| Unique Detections | 6 |",
		"| Unique Telemetry | 4 |",
		"| Risk Score | 45/100 |",
	}
	for _, c := range summaryChecks {
		if !strings.Contains(md, c) {
			t.Errorf("summary table missing: %q", c)
		}
	}

	// Framework coverage.
	if !strings.Contains(md, "| MITRE ATT&CK | 7 |") {
		t.Error("missing ATT&CK framework row")
	}

	// Tactic table must have check/x marks.
	if !strings.Contains(md, "✓") {
		t.Error("missing ✓ marks in tactic table")
	}
	if !strings.Contains(md, "✗") {
		t.Error("missing ✗ marks in tactic table")
	}

	// Campaign table content.
	if !strings.Contains(md, "fin6-campaign") {
		t.Error("missing campaign name")
	}
	if !strings.Contains(md, "FIN6") {
		t.Error("missing adversary name")
	}

	// Gap content.
	if !strings.Contains(md, "T1059.001") {
		t.Error("missing technique ID in gaps")
	}
	if !strings.Contains(md, "Detection Missing") {
		t.Error("missing gap type label")
	}

	// Risk summary table.
	if !strings.Contains(md, "| **Total** | **4** |") {
		t.Error("missing total in risk summary")
	}
	if !strings.Contains(md, "| **Score** | **45/100** |") {
		t.Error("missing score in risk summary")
	}

	// Footer.
	if !strings.Contains(md, "> Generated by ThreatEcho v") {
		t.Error("missing generated-by footer")
	}
	if !strings.Contains(md, "2026-09-14") {
		t.Error("missing timestamp in footer")
	}

	// Must not contain ANSI escape codes.
	if strings.Contains(md, "[") {
		t.Error("markdown output contains ANSI escape codes")
	}
}

func TestGapMarkdownReport_EmptyReport(t *testing.T) {
	r := &gap.GapReport{
		GeneratedAt: time.Now(),
		Aggregate: gap.AggregateCoverage{
			AttackTactics: gap.TacticBreakdown{Total: 14, Covered: 14},
			AtlasTactics:  gap.TacticBreakdown{Total: 7, Covered: 7},
		},
		RiskSummary: gap.RiskSummary{},
	}

	var buf bytes.Buffer
	err := GapMarkdownReport(&buf, r)
	if err != nil {
		t.Fatalf("GapMarkdownReport failed on empty report: %v", err)
	}

	md := buf.String()

	if !strings.Contains(md, "No detection gaps found") {
		t.Error("expected 'No detection gaps found' in empty report")
	}

	// Should not contain severity subsections when there are no gaps.
	for _, sev := range []string{"### Critical", "### High", "### Medium", "### Low"} {
		if strings.Contains(md, sev) {
			t.Errorf("empty report should not contain severity section %q", sev)
		}
	}

	// Risk summary should show all zeros.
	if !strings.Contains(md, "| **Total** | **0** |") {
		t.Error("expected zero total in risk summary for empty report")
	}
}

func TestGapMarkdownReport_GapGrouping(t *testing.T) {
	r := sampleMdGapReport()

	var buf bytes.Buffer
	err := GapMarkdownReport(&buf, r)
	if err != nil {
		t.Fatalf("GapMarkdownReport failed: %v", err)
	}

	md := buf.String()

	// All four severity sections should be present since sample has one of each.
	severities := []string{"### Critical", "### High", "### Medium", "### Low"}
	for _, sev := range severities {
		if !strings.Contains(md, sev) {
			t.Errorf("missing severity section: %q", sev)
		}
	}

	// Verify ordering: Critical before High before Medium before Low.
	critIdx := strings.Index(md, "### Critical")
	highIdx := strings.Index(md, "### High")
	medIdx := strings.Index(md, "### Medium")
	lowIdx := strings.Index(md, "### Low")

	if critIdx >= highIdx {
		t.Error("Critical section should appear before High")
	}
	if highIdx >= medIdx {
		t.Error("High section should appear before Medium")
	}
	if medIdx >= lowIdx {
		t.Error("Medium section should appear before Low")
	}

	// Critical gap should contain the tactic uncovered entry.
	critSection := md[critIdx:highIdx]
	if !strings.Contains(critSection, "Tactic Uncovered") {
		t.Error("Critical section missing tactic uncovered gap")
	}
	if !strings.Contains(critSection, "Initial Access") {
		t.Error("Critical section missing Initial Access tactic")
	}

	// High gap should contain the detection missing entry.
	highSection := md[highIdx:medIdx]
	if !strings.Contains(highSection, "T1059.001") {
		t.Error("High section missing technique T1059.001")
	}
	if !strings.Contains(highSection, "Detection Missing") {
		t.Error("High section missing Detection Missing label")
	}

	// Medium gap should contain the telemetry missing entry.
	medSection := md[medIdx:lowIdx]
	if !strings.Contains(medSection, "T1003") {
		t.Error("Medium section missing technique T1003")
	}

	// Low gap should contain its entry.
	lowSection := md[lowIdx:]
	if !strings.Contains(lowSection, "T1021") {
		t.Error("Low section missing technique T1021")
	}
}
