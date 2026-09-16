// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package config implements ThreatEcho's layered configuration system.
//
// Configuration is loaded from four sources in priority order:
//   - System-wide (/etc/threatecho/config.yaml)
//   - User (~/.config/threatecho/config.yaml)
//   - Project (.threatecho.yaml in the working directory or parent)
//   - Environment variables (THREATECHO_*)
//
// Later sources override earlier ones. The [Load] function merges all layers
// and returns a resolved [Config]. The [Init] function creates a project
// config template.
package config
