// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"context"
	"fmt"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/executor"
)

// ProgressFunc is called after each stage completes during a live run.
// It receives the stage result for real-time progress reporting.
type ProgressFunc func(StageResult)

// CleanupErrorFunc is called when a stage cleanup fails.
type CleanupErrorFunc func(campaign.Stage, error)

// Run executes a campaign live using the provided executor.
// It resolves topological stage order, applies platform filtering,
// executes each stage through the executor, and runs cleanup.
//
// Unlike Simulate(), Run tracks failures (Exec.Success == false)
// and invokes callbacks for real-time progress reporting.
func Run(ctx context.Context, c *campaign.Campaign, exec executor.Executor, opts Options) (*RunResult, error) {
	ordered, err := campaign.ResolveOrder(c.Stages)
	if err != nil {
		return nil, fmt.Errorf("resolving stage order: %w", err)
	}

	result := &RunResult{
		Campaign: c,
		Mode:     "live",
	}

	for i, stage := range ordered {
		sr := StageResult{
			Stage: stage,
			Order: i + 1,
		}

		// Platform filter.
		if opts.Platform != "" && len(stage.Platform) > 0 {
			matched := false
			for _, p := range stage.Platform {
				if p == opts.Platform {
					matched = true
					break
				}
			}
			if !matched {
				sr.Skipped = true
				sr.SkipMsg = fmt.Sprintf("platform %s not in %v", opts.Platform, stage.Platform)
				sr.Exec = executor.Result{
					StageID:  stage.ID,
					Skipped:  true,
					SkipNote: sr.SkipMsg,
				}
				result.Skipped++
				result.Stages = append(result.Stages, sr)
				if opts.OnProgress != nil {
					opts.OnProgress(sr)
				}
				continue
			}
		}

		sr.Exec = exec.Execute(ctx, stage)

		if sr.Exec.Skipped {
			sr.Skipped = true
			sr.SkipMsg = sr.Exec.SkipNote
			result.Skipped++
		} else if sr.Exec.Success {
			result.Completed++
		} else {
			result.Failed++
		}

		result.Stages = append(result.Stages, sr)

		// Progress callback.
		if opts.OnProgress != nil {
			opts.OnProgress(sr)
		}

		// Cleanup.
		if cleanErr := exec.Cleanup(ctx, stage); cleanErr != nil {
			if opts.OnCleanupError != nil {
				opts.OnCleanupError(stage, cleanErr)
			}
		}
	}

	return result, nil
}
