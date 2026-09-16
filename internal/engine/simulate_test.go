// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"context"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

func twostageCampaign() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "test",
			Adversary: "TestActor",
			Severity:  "medium",
		},
		Stages: []campaign.Stage{
			{
				ID:        "recon",
				Name:      "Recon",
				Technique: "T1016",
				Tactic:    "discovery",
				Execute:   campaign.Execute{Type: "shell", Commands: []string{"echo recon"}},
			},
			{
				ID:        "access",
				Name:      "Access",
				Technique: "T1190",
				Tactic:    "initial-access",
				DependsOn: []string{"recon"},
				Execute:   campaign.Execute{Type: "shell", Commands: []string{"echo access"}},
			},
		},
	}
}

func TestSimulate_BasicRun(t *testing.T) {
	c := twostageCampaign()
	result, err := Simulate(context.Background(), c, Options{DryRun: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Mode != "simulate" {
		t.Errorf("mode = %q, want %q", result.Mode, "simulate")
	}
	if len(result.Stages) != 2 {
		t.Fatalf("got %d stage results, want 2", len(result.Stages))
	}
	if result.Completed != 2 {
		t.Errorf("completed = %d, want 2", result.Completed)
	}
	if result.Skipped != 0 {
		t.Errorf("skipped = %d, want 0", result.Skipped)
	}
	// recon should be first (order 1) because access depends on it.
	if result.Stages[0].Stage.ID != "recon" {
		t.Errorf("first stage = %q, want %q", result.Stages[0].Stage.ID, "recon")
	}
	if result.Stages[0].Order != 1 {
		t.Errorf("first stage order = %d, want 1", result.Stages[0].Order)
	}
	if result.Stages[1].Stage.ID != "access" {
		t.Errorf("second stage = %q, want %q", result.Stages[1].Stage.ID, "access")
	}
}

func TestSimulate_PlatformFilter(t *testing.T) {
	c := twostageCampaign()
	// Make recon windows-only.
	c.Stages[0].Platform = []string{"windows"}
	// Run with linux filter.
	result, err := Simulate(context.Background(), c, Options{Platform: "linux", DryRun: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", result.Skipped)
	}
	if result.Completed != 1 {
		t.Errorf("completed = %d, want 1", result.Completed)
	}
	// recon should be skipped.
	for _, sr := range result.Stages {
		if sr.Stage.ID == "recon" && !sr.Skipped {
			t.Error("recon should be skipped for linux platform")
		}
		if sr.Stage.ID == "access" && sr.Skipped {
			t.Error("access should not be skipped (no platform restriction)")
		}
	}
}

func TestSimulate_PlatformFilter_NoPlatformStage(t *testing.T) {
	c := twostageCampaign()
	// No platform set on either stage, filter should not skip anything.
	result, err := Simulate(context.Background(), c, Options{Platform: "linux", DryRun: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Skipped != 0 {
		t.Errorf("skipped = %d, want 0 (stages with no platform should run on any)", result.Skipped)
	}
}

func TestTacticCoverage(t *testing.T) {
	c := twostageCampaign()
	result, err := Simulate(context.Background(), c, Options{DryRun: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	covered, missing := result.TacticCoverage()
	if len(covered) != 2 {
		t.Errorf("covered = %d, want 2 (discovery + initial-access)", len(covered))
	}
	if len(missing) != 12 {
		t.Errorf("missing = %d, want 12", len(missing))
	}
	// Check that the covered ones are correct.
	coveredSet := make(map[string]bool)
	for _, c := range covered {
		coveredSet[c] = true
	}
	if !coveredSet["discovery"] {
		t.Error("discovery should be covered")
	}
	if !coveredSet["initial-access"] {
		t.Error("initial-access should be covered")
	}
}

func TestTacticCoverage_SkippedStagesNotCounted(t *testing.T) {
	c := twostageCampaign()
	c.Stages[0].Platform = []string{"windows"}
	result, err := Simulate(context.Background(), c, Options{Platform: "linux", DryRun: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	covered, _ := result.TacticCoverage()
	// Only access (initial-access) should be covered; recon (discovery) was skipped.
	if len(covered) != 1 {
		t.Errorf("covered = %d, want 1", len(covered))
	}
}
