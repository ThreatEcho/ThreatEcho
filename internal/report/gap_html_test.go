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

func TestGapHTMLReport_ValidHTML(t *testing.T) {
	r := &gap.GapReport{
		GeneratedAt: time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC),
		Campaigns: []gap.CampaignCoverage{
			{
				Name:           "test-campaign",
				Adversary:      "TestAPT",
				Stages:         5,
				Completed:      4,
				Skipped:        1,
				TechniquesUsed: 3,
				AttackTactics: gap.TacticBreakdown{
					Total:   14,
					Covered: 3,
					Missing: []string{"reconnaissance", "resource-development"},
					Details: []gap.TacticDetail{
						{Short: "execution", Name: "Execution", Stages: 2},
						{Short: "initial-access", Name: "Initial Access", Stages: 1},
						{Short: "exfiltration", Name: "Exfiltration", Stages: 1},
					},
				},
				Framework: gap.FrameworkBreakdown{ATTACKStages: 4},
			},
		},
		Aggregate: gap.AggregateCoverage{
			TotalCampaigns:   1,
			TotalStages:      5,
			TotalCompleted:   4,
			TotalSkipped:     1,
			UniqueTechniques: 3,
			UniqueDetections: 5,
			UniqueTelemetry:  4,
			AttackTactics: gap.TacticBreakdown{
				Total:   14,
				Covered: 3,
				Missing: []string{"reconnaissance"},
				Details: []gap.TacticDetail{
					{Short: "execution", Name: "Execution", Stages: 2},
					{Short: "initial-access", Name: "Initial Access", Stages: 1},
					{Short: "exfiltration", Name: "Exfiltration", Stages: 1},
				},
			},
			AtlasTactics: gap.TacticBreakdown{Total: 7, Covered: 0},
			Framework:    gap.FrameworkBreakdown{ATTACKStages: 4},
		},
		Gaps: []gap.Gap{
			{
				CampaignName: "test-campaign",
				StageID:      "s1",
				StageName:    "Shell Stage",
				Technique:    "T1059",
				Tactic:       "execution",
				Type:         gap.GapDetectionMissing,
				Risk:         "high",
				Description:  "No detection rules",
			},
			{
				Tactic:      "reconnaissance",
				Type:        gap.GapTacticUncovered,
				Risk:        "medium",
				Description: "Tactic uncovered",
			},
		},
		RiskSummary: gap.RiskSummary{
			Critical: 0,
			High:     1,
			Medium:   1,
			Low:      0,
			Total:    2,
			Score:    35.0,
		},
	}

	var buf bytes.Buffer
	err := GapHTMLReport(&buf, r)
	if err != nil {
		t.Fatalf("GapHTMLReport failed: %v", err)
	}

	html := buf.String()

	// Must be valid HTML.
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE")
	}
	if !strings.Contains(html, "<html") {
		t.Error("missing <html>")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("missing </html>")
	}

	// Must contain key content.
	checks := []string{
		"ThreatEcho",
		"Gap Analysis",
		"test-campaign",
		"TestAPT",
		"Detection Missing",
		"Tactic Uncovered",
		"Risk Score",
		"Risk Summary",
		"Framework Coverage",
		"Tactic Coverage",
	}
	for _, c := range checks {
		if !strings.Contains(html, c) {
			t.Errorf("HTML output missing expected content: %q", c)
		}
	}
}

func TestGapHTMLReport_EmptyReport(t *testing.T) {
	r := &gap.GapReport{
		GeneratedAt: time.Now(),
		Aggregate: gap.AggregateCoverage{
			AttackTactics: gap.TacticBreakdown{Total: 14, Covered: 14},
			AtlasTactics:  gap.TacticBreakdown{Total: 7, Covered: 7},
		},
		RiskSummary: gap.RiskSummary{},
	}

	var buf bytes.Buffer
	err := GapHTMLReport(&buf, r)
	if err != nil {
		t.Fatalf("GapHTMLReport failed on empty report: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "No detection gaps found") {
		t.Error("expected 'No detection gaps found' message in empty report")
	}
}

func TestGapHTMLReport_SelfContained(t *testing.T) {
	r := &gap.GapReport{
		GeneratedAt: time.Now(),
		Aggregate: gap.AggregateCoverage{
			AttackTactics: gap.TacticBreakdown{Total: 14},
			AtlasTactics:  gap.TacticBreakdown{Total: 7},
		},
		RiskSummary: gap.RiskSummary{},
	}

	var buf bytes.Buffer
	if err := GapHTMLReport(&buf, r); err != nil {
		t.Fatalf("GapHTMLReport failed: %v", err)
	}

	html := buf.String()

	// Must NOT reference external resources (self-contained).
	if strings.Contains(html, "href=\"http") || strings.Contains(html, "src=\"http") {
		// Allow the github link in the footer and informationUri but no external CSS/JS.
		lines := strings.Split(html, "\n")
		for _, line := range lines {
			if strings.Contains(line, "href=\"http") && !strings.Contains(line, "github.com/ThreatEcho") {
				t.Errorf("HTML references external resource: %s", strings.TrimSpace(line))
			}
		}
	}

	// Must have embedded <style>.
	if !strings.Contains(html, "<style>") {
		t.Error("HTML report missing embedded <style>")
	}
}

func TestGapHTMLReport_DarkModeSupport(t *testing.T) {
	r := &gap.GapReport{
		GeneratedAt: time.Now(),
		Aggregate: gap.AggregateCoverage{
			AttackTactics: gap.TacticBreakdown{Total: 14},
			AtlasTactics:  gap.TacticBreakdown{Total: 7},
		},
		RiskSummary: gap.RiskSummary{},
	}

	var buf bytes.Buffer
	if err := GapHTMLReport(&buf, r); err != nil {
		t.Fatalf("GapHTMLReport failed: %v", err)
	}

	if !strings.Contains(buf.String(), "prefers-color-scheme: dark") {
		t.Error("HTML report missing dark mode media query")
	}
}
