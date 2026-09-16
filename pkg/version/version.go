// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package version exposes build-time version information for the ThreatEcho CLI.
package version

import "fmt"

// Version, Commit, and BuildTime are set by the linker at build time via
// -ldflags. They default to development values when not overridden.
var (
	// Version is the semantic version tag (e.g. "0.2.0").
	Version = "dev"
	// Commit is the short Git commit hash of the build.
	Commit = "unknown"
	// BuildTime is the ISO 8601 timestamp of the build.
	BuildTime = "unknown"
)

// String returns a human-readable version string including the version,
// commit hash, and build timestamp.
func String() string {
	return fmt.Sprintf("threatecho %s (commit: %s, built: %s)", Version, Commit, BuildTime)
}
