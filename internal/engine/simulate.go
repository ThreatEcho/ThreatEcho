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

// Simulate walks a campaign in topological order without executing anything.
// It returns a RunResult describing what would happen.
func Simulate(ctx context.Context, c *campaign.Campaign, opts Options) (*RunResult, error) {
	ordered, err := campaign.ResolveOrder(c.Stages)
	if err != nil {
		return nil, fmt.Errorf("resolving stage order: %w", err)
	}

	exec := &executor.Noop{}
	result := &RunResult{
		Campaign: c,
		Mode:     "simulate",
	}

	for i, stage := range ordered {
		sr := StageResult{
			Stage: stage,
			Order: i + 1,
		}

		// Check platform filter.
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
				result.Skipped++
				result.Stages = append(result.Stages, sr)
				continue
			}
		}

		sr.Exec = exec.Execute(ctx, stage)
		result.Completed++
		result.Stages = append(result.Stages, sr)
	}

	return result, nil
}
