// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package campaign provides the core data model and operations for adversary
// simulation campaigns. A campaign is a structured YAML definition of multi-stage
// attack sequences mapped to MITRE ATT&CK, MITRE ATLAS, and OWASP LLM Top 10
// frameworks.
//
// # Data Model
//
// The central type is [Campaign], which contains metadata (Meta), an ordered
// slice of Stages (each with technique, tactic, execution steps, expected
// detections, and telemetry), and Variables for template substitution.
//
// # Loading and Validation
//
// Use [LoadFile] to load a campaign from a YAML file, or [LoadDir] to load
// from a directory containing campaign.yaml. [Validate] checks structural
// correctness; [Lint] goes further with quality checks like technique registry
// validation and telemetry type verification.
//
// # Operations
//
// The package provides a rich set of operations on campaigns:
//
//   - [Format] / [FormatFile]: canonical YAML formatting
//   - [Diff]: structural comparison between two campaigns
//   - [MergeFiles]: combine multiple campaigns into one
//   - [Search] / [SearchDir]: multi-dimensional search across stages
//   - [ComputeStats] / [ComputeStatsDir]: project-wide analytics
//   - [ImportAtomicFile] / [ImportAtomicDir]: Atomic Red Team import
//   - [AnalyzeGraph]: dependency graph analysis (entry points, depth, critical path)
//   - [Hash] / [HashDir]: SHA256 content fingerprinting
//   - [Profile] / [ProfileDir]: complexity scoring
//   - [Timeline]: DAG-aware execution time estimation
//
// # Conventions
//
// Campaign directories follow the pattern campaigns/<name>/campaign.yaml.
// Functions ending in Dir walk subdirectories looking for this convention.
// Stage IDs are kebab-case. Technique IDs follow MITRE notation (T1234.001,
// AML.T0050, LLM01).
package campaign
