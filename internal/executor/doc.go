// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package executor provides campaign stage execution backends.
//
// Two executors are available:
//   - [NoopExecutor] — records what would be executed without running anything.
//     Used by the simulate command for dry-run analysis.
//   - [ShellExecutor] — executes shell commands with safety controls:
//     process group isolation, elevated privilege denial, output capping,
//     configurable timeouts, and graceful termination.
//
// The executor interface is defined by the engine package; executors are
// plugged in at runtime based on the command (simulate vs run).
package executor
