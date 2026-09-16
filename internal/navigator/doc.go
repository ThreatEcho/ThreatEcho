// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package navigator generates ATT&CK Navigator layer JSON (v4.5) from
// campaign technique coverage data.
//
// The exported layer can be loaded into the MITRE ATT&CK Navigator
// (https://mitre-attack.github.io/attack-navigator/) for visual technique
// coverage analysis. Supports both coverage layers (green = covered) and
// gap layers (red = uncovered).
package navigator
