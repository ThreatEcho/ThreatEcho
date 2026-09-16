// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package sigma generates Sigma detection rules from campaign stages.
//
// The generator maps campaign techniques to real Sigma detection criteria —
// process names, command-line patterns, network indicators, registry keys,
// and file operations. Currently 65 ATT&CK techniques have full detection
// signatures.
//
// The [TechniqueDetection] type hierarchy supports process-level, network,
// file, registry, and command-line detection criteria, matching the Sigma
// rule specification's logsource and detection structure.
package sigma
