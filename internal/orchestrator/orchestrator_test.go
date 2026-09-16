// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package orchestrator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/runner"
)

// mockDeployer implements Deployer for testing orchestration logic.
type mockDeployer struct {
	report *runner.RunReport
	err    error
	closed bool
}

func (m *mockDeployer) Deploy(_ context.Context, t Target, c *campaign.Campaign, _ DeployConfig) (*runner.RunReport, error) {
	if m.err != nil {
		return nil, m.err
	}
	r := *m.report
	r.Hostname = t.Host
	r.Campaign = c.Meta.Name
	return &r, nil
}

func (m *mockDeployer) Close() error {
	m.closed = true
	return nil
}

func testTargets() []Target {
	return []Target{
		{Name: "srv1", Host: "10.0.0.1", Port: 22, OS: "linux", User: "lab", Password: "pass", Mode: "agentless"},
		{Name: "srv2", Host: "10.0.0.2", Port: 22, OS: "linux", User: "lab", Password: "pass", Mode: "agentless"},
	}
}

func testCampaign() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       campaign.Meta{Name: "test-deploy"},
		Stages: []campaign.Stage{
			{
				ID:       "whoami",
				Name:     "Identity",
				Tactic:   "discovery",
				Platform: []string{"linux"},
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"whoami"},
				},
			},
		},
	}
}

func TestRunSequential(t *testing.T) {
	t.Parallel()
	targets := testTargets()
	c := testCampaign()

	results := runSequential(context.Background(), targets, c, DeployConfig{})

	// All should fail since there's no real SSH server.
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	for _, r := range results {
		if r.Error == "" {
			t.Error("expected connection error for mock target")
		}
	}
}

func TestNewDeployer_WindowsAgentless(t *testing.T) {
	t.Parallel()
	winTarget := Target{Name: "dc01", Host: "10.0.0.10", OS: "windows", User: "admin", Password: "p", Mode: "agentless"}
	d, err := NewDeployer(winTarget, DeployConfig{})
	if err != nil {
		t.Fatalf("NewDeployer should succeed for windows agentless: %v", err)
	}
	defer d.Close()
}

func TestNewDeployer_WindowsAgentNoBinary(t *testing.T) {
	t.Parallel()
	winTarget := Target{Name: "dc01", Host: "10.0.0.10", OS: "windows", User: "admin", Password: "p", Mode: "agent"}
	_, err := NewDeployer(winTarget, DeployConfig{})
	if err == nil {
		t.Fatal("expected error for windows agent mode without binary path")
	}
}

func TestNewDeployer_AgentNoBinary(t *testing.T) {
	t.Parallel()
	target := Target{Name: "srv", Host: "10.0.0.1", OS: "linux", User: "u", Password: "p", Mode: "agent"}
	_, err := NewDeployer(target, DeployConfig{})
	if err == nil {
		t.Fatal("expected error for agent mode without binary path")
	}
}

func TestBuildDeployReport(t *testing.T) {
	t.Parallel()
	started := time.Now()

	results := []TargetResult{
		{
			Target: Target{Name: "srv1", Host: "10.0.0.1", User: "lab"},
			Report: &runner.RunReport{
				Campaign:    "test",
				TotalStages: 5,
				Passed:      2,
				Failed:      1,
				PrecondFail: 2,
				Duration:    "1.5s",
			},
		},
		{
			Target: Target{Name: "srv2", Host: "10.0.0.2", User: "lab"},
			Report: &runner.RunReport{
				Campaign:    "test",
				TotalStages: 3,
				Passed:      3,
				Duration:    "2s",
			},
		},
		{
			Target: Target{Name: "srv3", Host: "10.0.0.3", User: "lab"},
			Error:  "connection refused",
		},
	}

	report := BuildDeployReport("test-campaign", started, results)

	if report.Campaign != "test-campaign" {
		t.Errorf("campaign = %q, want %q", report.Campaign, "test-campaign")
	}
	if report.Summary.TotalTargets != 3 {
		t.Errorf("total_targets = %d, want 3", report.Summary.TotalTargets)
	}
	if report.Summary.Succeeded != 2 {
		t.Errorf("succeeded = %d, want 2", report.Summary.Succeeded)
	}
	if report.Summary.Failed != 1 {
		t.Errorf("failed = %d, want 1", report.Summary.Failed)
	}
	if report.Summary.TotalStages != 8 {
		t.Errorf("total_stages = %d, want 8", report.Summary.TotalStages)
	}
	if report.Summary.Passed != 5 {
		t.Errorf("passed = %d, want 5", report.Summary.Passed)
	}
	if report.Summary.StageFailed != 1 {
		t.Errorf("stage_failed = %d, want 1", report.Summary.StageFailed)
	}
	if report.Summary.PrecondFail != 2 {
		t.Errorf("precond_failed = %d, want 2", report.Summary.PrecondFail)
	}
}

func TestFormatDeployReport(t *testing.T) {
	t.Parallel()
	report := &DeployReport{
		Campaign: "test",
		Duration: "3s",
		Targets: []TargetResult{
			{
				Target: Target{Name: "srv1", Host: "10.0.0.1", User: "lab"},
				Report: &runner.RunReport{Passed: 2, Failed: 0, Skipped: 1, PrecondFail: 3, Duration: "1s"},
			},
			{
				Target: Target{Name: "srv2", Host: "10.0.0.2", User: "lab"},
				Error:  "timeout",
			},
		},
		Summary: DeploySummary{
			TotalTargets: 2,
			Succeeded:    1,
			Failed:       1,
			TotalStages:  6,
			Passed:       2,
			Skipped:      1,
			PrecondFail:  3,
		},
	}

	out := FormatDeployReport(report)
	if out == "" {
		t.Fatal("expected non-empty output")
	}

	for _, want := range []string{"test", "srv1", "srv2", "timeout", "2 passed", "3 precond_failed"} {
		if !contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestNewDeployer_LinuxAgentless(t *testing.T) {
	t.Parallel()
	target := Target{Name: "srv", Host: "10.0.0.1", Port: 22, OS: "linux", User: "u", Password: "p", Mode: "agentless"}
	// Will fail to connect (no server) but should return the right deployer type.
	_, err := NewDeployer(target, DeployConfig{})
	// We expect a dial error, not a "not implemented" error.
	if err == nil {
		t.Fatal("expected connection error")
	}
	if contains(err.Error(), "not yet implemented") {
		t.Errorf("unexpected 'not implemented' for linux agentless: %v", err)
	}
}

func TestNewDeployer_LinuxAgent(t *testing.T) {
	t.Parallel()
	target := Target{Name: "srv", Host: "10.0.0.1", Port: 22, OS: "linux", User: "u", Password: "p", Mode: "agent"}
	_, err := NewDeployer(target, DeployConfig{AgentBinary: "/tmp/nonexistent"})
	// Should attempt SSH connection (and fail), not error on missing binary check.
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchStr(s, sub)
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Suppress unused import warning.
var _ = fmt.Sprintf
