// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package executor

import (
	"context"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

// Result captures the outcome of executing a stage.
type Result struct {
	StageID  string
	Success  bool
	Output   string
	Error    error
	Skipped  bool
	SkipNote string
}

// Executor runs a campaign stage's commands.
type Executor interface {
	// Execute runs the stage and returns a result.
	Execute(ctx context.Context, stage campaign.Stage) Result

	// Cleanup runs the stage's cleanup commands.
	Cleanup(ctx context.Context, stage campaign.Stage) error

	// Name returns the executor type for display.
	Name() string
}
