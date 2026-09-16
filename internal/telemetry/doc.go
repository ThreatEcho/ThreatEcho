// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package telemetry manages the telemetry type registry — the canonical set
// of observable event types that campaign stages can declare as expected
// telemetry.
//
// The registry contains 58 telemetry types across 11 categories (process,
// network, file, registry, authentication, DNS, cloud, email, endpoint,
// identity, and AI/agent). Each type has a description and category for
// lint validation and typo correction.
//
// Key functions:
//   - [Lookup] — check if a telemetry type exists
//   - [SuggestCorrection] — fuzzy-match typos to known types
//   - [List] — all registered types
//   - [Categories] — all category names
package telemetry
