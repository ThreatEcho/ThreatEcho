// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package report provides multi-format output rendering for ThreatEcho
// analysis results.
//
// Supported formats:
//   - Text — human-readable terminal output
//   - JSON — structured data for programmatic consumption
//   - SARIF v2.1.0 — GitHub Code Scanning and VS Code integration
//   - JUnit XML — Jenkins, GitHub Actions, GitLab CI test reports
//   - HTML — standalone HTML reports with embedded CSS
//   - Markdown — GitHub wiki and documentation integration
//
// Each format is implemented as a standalone function that takes analysis
// results and returns formatted bytes.
package report
