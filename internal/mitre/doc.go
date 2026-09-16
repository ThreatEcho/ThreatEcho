// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package mitre provides the MITRE ATT&CK, MITRE ATLAS, and OWASP LLM Top 10
// technique and tactic registries used throughout ThreatEcho.
//
// The registry contains 155 ATT&CK techniques, 25 ATLAS techniques, and
// 10 OWASP LLM techniques. Each technique maps to a tactic and has a
// human-readable name.
//
// Key functions:
//   - [LookupTechnique] — look up a technique by ID
//   - [ResolveName] — resolve a technique ID to its display name
//   - [ValidTactic] — check if a tactic string is recognized
//   - [ClassifyFramework] — determine if a technique is ATT&CK, ATLAS, or OWASP
//   - [TacticByShort] — look up a tactic by its kebab-case short name
package mitre
