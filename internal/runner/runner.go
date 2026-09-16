// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package runner

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"time"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/executor"
)

// Config controls agent runner behavior.
type Config struct {
	// AllowElevated permits stages marked elevated: true to run.
	// When false (default), elevated stages fail precondition checks.
	AllowElevated bool

	// Platform filters stages by platform. Empty runs all.
	Platform string

	// WorkDir sets the working directory for shell commands.
	WorkDir string

	// MaxOutput caps output per stage in bytes (0 = 1 MiB default).
	MaxOutput int

	// Env sets additional environment variables for commands.
	Env []string
}

// Execute runs a campaign through the agent runner with full precondition
// checking and structured reporting.
func Execute(ctx context.Context, c *campaign.Campaign, cfg Config) *RunReport {
	hostname, _ := os.Hostname()
	u, _ := user.Current()
	username := ""
	if u != nil {
		username = u.Username
	}

	report := &RunReport{
		Campaign:  c.Meta.Name,
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		User:      username,
		Elevated:  isPrivileged(),
		StartedAt: time.Now(),
	}

	ordered, err := campaign.ResolveOrder(c.Stages)
	if err != nil {
		report.Error = fmt.Sprintf("resolve stage order: %s", err)
		report.FinishedAt = time.Now()
		report.Duration = report.FinishedAt.Sub(report.StartedAt).String()
		return report
	}

	shell := executor.NewShell(executor.ShellConfig{
		DenyElevated: !cfg.AllowElevated,
		MaxOutput:    cfg.MaxOutput,
		WorkDir:      cfg.WorkDir,
		Env:          cfg.Env,
	})

	report.TotalStages = len(ordered)

	for _, stage := range ordered {
		sr := runStage(ctx, stage, shell, cfg)
		report.Stages = append(report.Stages, sr)

		switch sr.Status {
		case "passed":
			report.Passed++
		case "failed":
			report.Failed++
		case "skipped":
			report.Skipped++
		case "precondition_failed":
			report.PrecondFail++
		}
	}

	report.FinishedAt = time.Now()
	report.Duration = report.FinishedAt.Sub(report.StartedAt).Round(time.Millisecond).String()
	return report
}

func runStage(ctx context.Context, stage campaign.Stage, shell *executor.Shell, cfg Config) StageReport {
	sr := StageReport{
		StageID:   stage.ID,
		Name:      stage.Name,
		Technique: stage.Technique,
		Tactic:    stage.Tactic,
		Elevated:  stage.Execute.Elevated,
		Commands:  len(stage.Execute.Commands),
	}

	// Platform filter.
	if cfg.Platform != "" && len(stage.Platform) > 0 {
		matched := false
		for _, p := range stage.Platform {
			if p == cfg.Platform {
				matched = true
				break
			}
		}
		if !matched {
			sr.Status = "skipped"
			sr.Error = "platform mismatch"
			return sr
		}
	}

	// Precondition checks.
	checks := CheckAll(stage, cfg.AllowElevated)
	sr.Preconditions = checks
	if !Passed(checks) {
		sr.Status = "precondition_failed"
		for _, c := range checks {
			if !c.Passed {
				sr.Error = c.Detail
				break
			}
		}
		return sr
	}

	// Execute.
	start := time.Now()
	result := shell.Execute(ctx, stage)
	sr.Duration = time.Since(start)
	sr.DurationHuman = sr.Duration.Round(time.Millisecond).String()
	sr.Output = result.Output

	if result.Skipped {
		sr.Status = "skipped"
		sr.Error = result.SkipNote
	} else if result.Success {
		sr.Status = "passed"
	} else {
		sr.Status = "failed"
		if result.Error != nil {
			sr.Error = result.Error.Error()
		}
	}

	// Cleanup.
	if cleanErr := shell.Cleanup(ctx, stage); cleanErr != nil {
		sr.CleanupError = cleanErr.Error()
	}

	return sr
}
