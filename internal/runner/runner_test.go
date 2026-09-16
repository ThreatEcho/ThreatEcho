// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package runner

import (
	"context"
	"runtime"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

func testCampaign() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name: "test-campaign",
		},
		Stages: []campaign.Stage{
			{
				ID:       "whoami",
				Name:     "Identity Check",
				Tactic:   "discovery",
				Platform: []string{runtime.GOOS},
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"whoami"},
				},
			},
			{
				ID:       "hostname",
				Name:     "Hostname",
				Tactic:   "discovery",
				Platform: []string{runtime.GOOS},
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"hostname"},
				},
				DependsOn: []string{"whoami"},
			},
		},
	}
}

func TestExecute_BasicCampaign(t *testing.T) {
	c := testCampaign()
	cfg := Config{Platform: runtime.GOOS}

	report := Execute(context.Background(), c, cfg)

	if report.Campaign != "test-campaign" {
		t.Errorf("campaign = %q, want %q", report.Campaign, "test-campaign")
	}
	if report.OS != runtime.GOOS {
		t.Errorf("os = %q, want %q", report.OS, runtime.GOOS)
	}
	if report.TotalStages != 2 {
		t.Errorf("total_stages = %d, want 2", report.TotalStages)
	}
	if report.Passed != 2 {
		t.Errorf("passed = %d, want 2", report.Passed)
	}
	if report.Hostname == "" {
		t.Error("hostname should not be empty")
	}
}

func TestExecute_PlatformFilter(t *testing.T) {
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "platform-test"},
		Stages: []campaign.Stage{
			{
				ID:       "win-only",
				Name:     "Windows Only",
				Tactic:   "discovery",
				Platform: []string{"windows"},
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"whoami"},
				},
			},
		},
	}

	cfg := Config{Platform: "linux"}
	report := Execute(context.Background(), c, cfg)

	if runtime.GOOS == "linux" {
		if report.Skipped != 1 {
			t.Errorf("skipped = %d, want 1 (windows stage on linux)", report.Skipped)
		}
	}
}

func TestExecute_ElevatedDenied(t *testing.T) {
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "elevated-test"},
		Stages: []campaign.Stage{
			{
				ID:       "needs-root",
				Name:     "Root Required",
				Tactic:   "privilege-escalation",
				Platform: []string{runtime.GOOS},
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"whoami"},
					Elevated: true,
				},
			},
		},
	}

	cfg := Config{AllowElevated: false, Platform: runtime.GOOS}
	report := Execute(context.Background(), c, cfg)

	if report.PrecondFail != 1 {
		t.Errorf("precondition_failed = %d, want 1", report.PrecondFail)
	}
	if len(report.Stages) != 1 {
		t.Fatalf("stages = %d, want 1", len(report.Stages))
	}
	if report.Stages[0].Status != "precondition_failed" {
		t.Errorf("status = %q, want %q", report.Stages[0].Status, "precondition_failed")
	}
}

func TestExecute_FailedCommand(t *testing.T) {
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "fail-test"},
		Stages: []campaign.Stage{
			{
				ID:       "bad-cmd",
				Name:     "Bad Command",
				Tactic:   "execution",
				Platform: []string{runtime.GOOS},
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"false"},
				},
			},
		},
	}

	cfg := Config{Platform: runtime.GOOS}
	report := Execute(context.Background(), c, cfg)

	if report.Failed != 1 {
		t.Errorf("failed = %d, want 1", report.Failed)
	}
	if report.Stages[0].Status != "failed" {
		t.Errorf("status = %q, want %q", report.Stages[0].Status, "failed")
	}
}

func TestExecute_ReportJSON(t *testing.T) {
	c := testCampaign()
	cfg := Config{Platform: runtime.GOOS}

	report := Execute(context.Background(), c, cfg)

	if report.StartedAt.IsZero() {
		t.Error("started_at should not be zero")
	}
	if report.FinishedAt.IsZero() {
		t.Error("finished_at should not be zero")
	}
	if report.Duration == "" {
		t.Error("duration should not be empty")
	}
	for _, sr := range report.Stages {
		if sr.DurationHuman == "" {
			t.Errorf("stage %s duration should not be empty", sr.StageID)
		}
	}
}

func TestExecute_NonShellSkipped(t *testing.T) {
	c := &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "http-test"},
		Stages: []campaign.Stage{
			{
				ID:       "http-stage",
				Name:     "HTTP Stage",
				Tactic:   "initial-access",
				Platform: []string{runtime.GOOS},
				Execute: campaign.Execute{
					Type:   "http",
					Target: "http://example.com",
				},
			},
		},
	}

	cfg := Config{Platform: runtime.GOOS}
	report := Execute(context.Background(), c, cfg)

	if report.Skipped != 1 {
		t.Errorf("skipped = %d, want 1 (http not handled by shell)", report.Skipped)
	}
}
