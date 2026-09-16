// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"context"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/executor"
)

func testCampaignForRun() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "run-test",
			Adversary: "test",
			Severity:  "high",
		},
		Stages: []campaign.Stage{
			{
				ID:        "s1",
				Name:      "Echo Test",
				Technique: "T1059",
				Tactic:    "execution",
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"echo hello"},
				},
			},
			{
				ID:        "s2",
				Name:      "HTTP Stage",
				Technique: "T1071",
				Tactic:    "command-and-control",
				DependsOn: []string{"s1"},
				Execute: campaign.Execute{
					Type:   "http",
					Target: "https://example.com",
				},
			},
		},
	}
}

func TestRun_WithNoop(t *testing.T) {
	c := testCampaignForRun()
	exec := &executor.Noop{}
	opts := Options{}

	result, err := Run(context.Background(), c, exec, opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Mode != "live" {
		t.Errorf("mode = %q, want live", result.Mode)
	}
	if len(result.Stages) != 2 {
		t.Fatalf("stages = %d, want 2", len(result.Stages))
	}
	if result.Completed != 2 {
		t.Errorf("completed = %d, want 2", result.Completed)
	}
}

func TestRun_PlatformFilter(t *testing.T) {
	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "filter-test", Adversary: "test", Severity: "high"},
		Stages: []campaign.Stage{
			{
				ID:       "linux-only",
				Name:     "Linux Stage",
				Tactic:   "execution",
				Platform: []string{"linux"},
				Execute:  campaign.Execute{Type: "shell", Commands: []string{"echo linux"}},
			},
			{
				ID:       "win-only",
				Name:     "Windows Stage",
				Tactic:   "execution",
				Platform: []string{"windows"},
				Execute:  campaign.Execute{Type: "shell", Commands: []string{"echo win"}},
			},
			{
				ID:      "any",
				Name:    "Any Platform",
				Tactic:  "execution",
				Execute: campaign.Execute{Type: "shell", Commands: []string{"echo any"}},
			},
		},
	}

	exec := &executor.Noop{}
	opts := Options{Platform: "linux"}

	result, err := Run(context.Background(), c, exec, opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Skipped != 1 {
		t.Errorf("skipped = %d, want 1 (windows-only)", result.Skipped)
	}
	if result.Completed != 2 {
		t.Errorf("completed = %d, want 2 (linux + any)", result.Completed)
	}
}

func TestRun_ProgressCallback(t *testing.T) {
	c := testCampaignForRun()
	exec := &executor.Noop{}

	var progress []string
	opts := Options{
		OnProgress: func(sr StageResult) {
			progress = append(progress, sr.Stage.ID)
		},
	}

	_, err := Run(context.Background(), c, exec, opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if len(progress) != 2 {
		t.Fatalf("progress callbacks = %d, want 2", len(progress))
	}
	if progress[0] != "s1" || progress[1] != "s2" {
		t.Errorf("progress order = %v, want [s1, s2]", progress)
	}
}

func TestRun_FailedStage(t *testing.T) {
	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "fail-test", Adversary: "test", Severity: "high"},
		Stages: []campaign.Stage{
			{
				ID:      "denied",
				Name:    "Denied Stage",
				Tactic:  "execution",
				Execute: campaign.Execute{Type: "shell", Commands: []string{"echo test"}, Elevated: true},
			},
		},
	}

	// Shell executor with DenyElevated will fail the stage.
	exec := executor.NewShell(executor.ShellConfig{DenyElevated: true})
	opts := Options{}

	result, err := Run(context.Background(), c, exec, opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Failed != 1 {
		t.Errorf("failed = %d, want 1", result.Failed)
	}
	if result.Completed != 0 {
		t.Errorf("completed = %d, want 0", result.Completed)
	}
}

func TestRun_SkippedType(t *testing.T) {
	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "skip-test", Adversary: "test", Severity: "high"},
		Stages: []campaign.Stage{
			{
				ID:      "http-stage",
				Name:    "HTTP Only",
				Tactic:  "command-and-control",
				Execute: campaign.Execute{Type: "http", Target: "https://example.com"},
			},
		},
	}

	// Shell executor skips non-shell types.
	exec := executor.NewShell(executor.ShellConfig{})
	opts := Options{}

	result, err := Run(context.Background(), c, exec, opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", result.Skipped)
	}
}
