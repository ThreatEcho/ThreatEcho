// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package executor

import (
	"context"
	"fmt"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

// Noop is a dry-run executor that describes what would happen without executing anything.
type Noop struct{}

// Execute returns a simulated result describing what would happen without running anything.
func (n *Noop) Execute(_ context.Context, stage campaign.Stage) Result {
	var parts []string
	switch stage.Execute.Type {
	case "shell":
		parts = append(parts, fmt.Sprintf("would run %d command(s)", len(stage.Execute.Commands)))
		if stage.Execute.Elevated {
			parts = append(parts, "elevated")
		}
	case "http":
		method := stage.Execute.Args["method"]
		if method == "" {
			method = "GET"
		}
		parts = append(parts, fmt.Sprintf("would %s %s", method, stage.Execute.Target))
	case "file":
		if stage.Execute.Payload != "" {
			parts = append(parts, fmt.Sprintf("would deploy %s", stage.Execute.Payload))
		}
	default:
		parts = append(parts, fmt.Sprintf("would execute %s action", stage.Execute.Type))
	}

	return Result{
		StageID: stage.ID,
		Success: true,
		Output:  strings.Join(parts, "; "),
		Skipped: false,
	}
}

// Cleanup is a no-op that always returns nil.
func (n *Noop) Cleanup(_ context.Context, stage campaign.Stage) error {
	return nil
}

// Name returns "simulate" to identify this as a dry-run executor.
func (n *Noop) Name() string {
	return "simulate"
}
