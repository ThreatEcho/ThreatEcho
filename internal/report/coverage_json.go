// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"encoding/json"
	"io"

	"github.com/ThreatEcho/threatecho/internal/gap"
)

// CoverageJSONReport writes a technique-level coverage report as JSON.
func CoverageJSONReport(w io.Writer, cr *gap.CoverageReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(cr)
}
