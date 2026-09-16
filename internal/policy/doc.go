// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package policy implements the agent tool-call policy engine.
//
// Policies are YAML-defined rule sets that specify deny, allow, and alert
// actions on agent tool invocations. Each rule matches on tool name, argument
// patterns, and target patterns.
//
// This is the detection engineering layer for AI agents — the core differentiator
// of ThreatEcho's "Detection Engineering for AI Agents" positioning.
//
// Key functions:
//   - [Load] — load a policy from a YAML file or directory
//   - [Validate] — validate policy structure
//   - [Evaluate] — evaluate a policy against campaign stages
package policy
