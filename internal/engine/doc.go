// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package engine provides the simulation and live execution engine for
// adversary campaigns.
//
// The engine resolves the campaign DAG (directed acyclic graph of stage
// dependencies), topologically sorts stages, and dispatches each stage to
// an executor — either a noop executor for simulation (dry-run) or the
// live shell executor for real execution.
//
// Variable substitution ({{var}} templates and ${env:VAR} expansion) is
// applied before execution. Platform filtering skips stages not targeting
// the current platform.
package engine
