// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package orchestrator

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/runner"
)

// Deployer pushes and executes campaigns on a remote target.
type Deployer interface {
	Deploy(ctx context.Context, target Target, c *campaign.Campaign, cfg DeployConfig) (*runner.RunReport, error)
	Close() error
}

// DeployConfig controls deployment behavior.
type DeployConfig struct {
	AllowElevated bool
	AgentBinary   string // local path to threatecho-agent binary (agent mode)
	WorkDir       string // remote working directory
	MaxOutput     int
	Parallel      bool
	Verbose       bool
}

// TargetResult pairs a target with its deployment outcome.
type TargetResult struct {
	Target Target            `json:"target"`
	Report *runner.RunReport `json:"report,omitempty"`
	Error  string            `json:"error,omitempty"`
}

// Run executes a campaign against all targets in the inventory.
func Run(ctx context.Context, targets []Target, c *campaign.Campaign, cfg DeployConfig) []TargetResult {
	if cfg.Parallel {
		return runParallel(ctx, targets, c, cfg)
	}
	return runSequential(ctx, targets, c, cfg)
}

func runSequential(ctx context.Context, targets []Target, c *campaign.Campaign, cfg DeployConfig) []TargetResult {
	results := make([]TargetResult, 0, len(targets))
	for _, t := range targets {
		results = append(results, deployOne(ctx, t, c, cfg))
	}
	return results
}

func runParallel(ctx context.Context, targets []Target, c *campaign.Campaign, cfg DeployConfig) []TargetResult {
	results := make([]TargetResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target Target) {
			defer wg.Done()
			results[idx] = deployOne(ctx, target, c, cfg)
		}(i, t)
	}
	wg.Wait()
	return results
}

func deployOne(ctx context.Context, t Target, c *campaign.Campaign, cfg DeployConfig) TargetResult {
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "→ %s: connecting (%s@%s:%d, %s/%s)\n", t.Name, t.User, t.Host, t.Port, t.OS, t.Mode)
	}
	deployer, err := NewDeployer(t, cfg)
	if err != nil {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "✗ %s: connection failed: %s\n", t.Name, err)
		}
		return TargetResult{Target: t, Error: err.Error()}
	}
	defer deployer.Close()

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "✓ %s: connected, deploying %d stage(s)\n", t.Name, len(c.Stages))
	}
	report, err := deployer.Deploy(ctx, t, c, cfg)
	if err != nil {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "✗ %s: deploy error: %s\n", t.Name, err)
		}
		return TargetResult{Target: t, Error: err.Error()}
	}
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "✓ %s: done — %d passed, %d failed, %d skipped [%s]\n",
			t.Name, report.Passed, report.Failed, report.Skipped, report.Duration)
	}
	return TargetResult{Target: t, Report: report}
}

// NewDeployer creates the appropriate deployer for a target.
func NewDeployer(t Target, cfg DeployConfig) (Deployer, error) {
	switch {
	case t.OS == "windows" && t.Mode == "agentless":
		return newWinRMDeployer(t)
	case t.OS == "windows" && t.Mode == "agent":
		if cfg.AgentBinary == "" {
			return nil, fmt.Errorf("target %q: agent mode requires -agent-binary path", t.Name)
		}
		return newAgentWinRMDeployer(t)
	case t.Mode == "agent":
		if cfg.AgentBinary == "" {
			return nil, fmt.Errorf("target %q: agent mode requires -agent-binary path", t.Name)
		}
		return newAgentSSHDeployer(t)
	default:
		return newSSHDeployer(t)
	}
}
