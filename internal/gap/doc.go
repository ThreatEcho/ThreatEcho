// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package gap provides detection gap analysis for adversary campaigns.
//
// The gap analyzer examines campaign stages to identify:
//   - Uncovered tactics (ATT&CK/ATLAS tactics with zero stage coverage)
//   - Detection gaps (stages that generate telemetry but have no detection rules)
//   - Telemetry gaps (stages with no expected telemetry — complete blind spots)
//   - Risk scoring per gap (critical, high, medium, low)
//
// The [Compare] function computes deltas between two gap reports for
// before/after ROI measurement.
//
// The [TechniqueCoverage] function provides drill-down coverage per technique.
package gap
