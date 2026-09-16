// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/executor"
)

// StageResult captures what happened (or would happen) for one stage.
type StageResult struct {
	Stage   campaign.Stage
	Order   int
	Exec    executor.Result
	Skipped bool
	SkipMsg string
}

// RunResult captures the full outcome of a campaign run or simulation.
type RunResult struct {
	Campaign  *campaign.Campaign
	Mode      string // "simulate", "live"
	Stages    []StageResult
	Completed int
	Skipped   int
	Failed    int
}

// TacticCoverage returns which tactics are covered and which are not.
func (r *RunResult) TacticCoverage() (covered []string, missing []string) {
	seen := make(map[string]bool)
	for _, sr := range r.Stages {
		if !sr.Skipped {
			seen[sr.Stage.Tactic] = true
		}
	}

	allTactics := []string{
		"reconnaissance", "resource-development", "initial-access",
		"execution", "persistence", "privilege-escalation",
		"defense-evasion", "credential-access", "discovery",
		"lateral-movement", "collection", "command-and-control",
		"exfiltration", "impact",
	}
	for _, t := range allTactics {
		if seen[t] {
			covered = append(covered, t)
		} else {
			missing = append(missing, t)
		}
	}
	return
}

// Options configures engine behavior.
type Options struct {
	Platform string // filter stages by platform; empty = run all
	DryRun   bool   // simulate only
	Verbose  bool

	// OnProgress is called after each stage completes (live runs).
	// Nil means no progress reporting.
	OnProgress ProgressFunc

	// OnCleanupError is called when a stage cleanup fails (live runs).
	// Nil means cleanup errors are silently ignored.
	OnCleanupError CleanupErrorFunc
}
