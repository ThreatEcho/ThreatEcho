// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package matrix renders a MITRE ATT&CK tactic×technique heat map in the terminal.
//
// BuildMatrix produces a Matrix from simulation results, mapping each technique
// to its tactic column with a coverage level derived from the campaign's expect
// blocks. Render draws the full columnar display; RenderCompact draws a compressed
// coverage summary for narrow terminals.
package matrix

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/gap"
	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// CoverageLevel classifies how well a technique is covered.
type CoverageLevel int

const (
	Uncovered CoverageLevel = iota // not exercised by any campaign
	Partial                        // has telemetry but no detection
	Detected                       // has detection rules
	Full                           // has detection + telemetry + multiple campaigns
)

// String returns a human label for the coverage level.
func (cl CoverageLevel) String() string {
	switch cl {
	case Uncovered:
		return "uncovered"
	case Partial:
		return "partial"
	case Detected:
		return "detected"
	case Full:
		return "full"
	}
	return "unknown"
}

// Matrix holds the tactic×technique grid.
type Matrix struct {
	Tactics []TacticColumn
	Legend  Legend
}

// TacticColumn is one column in the matrix — a single ATT&CK tactic.
type TacticColumn struct {
	ID         string // TA0001 etc
	Short      string // initial-access etc
	Name       string // Initial Access
	Techniques []TechniqueCell
}

// TechniqueCell is one cell — a technique within a tactic column.
type TechniqueCell struct {
	ID        string
	Name      string
	SubID     string // .001 etc, empty for parent
	Coverage  CoverageLevel
	Campaigns []string // which campaigns exercise this
}

// Legend describes the color coding.
type Legend struct {
	Entries []LegendEntry
}

// LegendEntry is a single legend item.
type LegendEntry struct {
	Label string
	Level CoverageLevel
}

// techKey tracks per-technique coverage across campaigns while building.
type techKey struct {
	tactic       string
	hasTelemetry bool
	hasDetection bool
	campaigns    map[string]bool
}

// BuildMatrix builds the matrix from one or more simulation results.
func BuildMatrix(results ...*engine.RunResult) *Matrix {
	// Collect per-technique coverage.
	techs := make(map[string]*techKey) // technique ID → key

	for _, r := range results {
		campaignName := r.Campaign.Meta.Name
		for _, sr := range r.Stages {
			if sr.Skipped {
				continue
			}
			s := sr.Stage
			// Only ATT&CK techniques go in the matrix.
			if !strings.HasPrefix(s.Technique, "T") {
				continue
			}
			tk, ok := techs[s.Technique]
			if !ok {
				tk = &techKey{
					tactic:    s.Tactic,
					campaigns: make(map[string]bool),
				}
				techs[s.Technique] = tk
			}
			tk.campaigns[campaignName] = true
			if len(s.Expect.Telemetry) > 0 {
				tk.hasTelemetry = true
			}
			if len(s.Expect.Detections) > 0 {
				tk.hasDetection = true
			}
		}
	}

	return buildFromTechKeys(techs)
}

// BuildFromGapReport builds a matrix enriched with gap-report information.
// Techniques that appear in the gap report as having gaps are marked accordingly.
func BuildFromGapReport(report *gap.GapReport, results ...*engine.RunResult) *Matrix {
	// Start from simulation results.
	techs := make(map[string]*techKey)

	for _, r := range results {
		campaignName := r.Campaign.Meta.Name
		for _, sr := range r.Stages {
			if sr.Skipped {
				continue
			}
			s := sr.Stage
			if !strings.HasPrefix(s.Technique, "T") {
				continue
			}
			tk, ok := techs[s.Technique]
			if !ok {
				tk = &techKey{
					tactic:    s.Tactic,
					campaigns: make(map[string]bool),
				}
				techs[s.Technique] = tk
			}
			tk.campaigns[campaignName] = true
			if len(s.Expect.Telemetry) > 0 {
				tk.hasTelemetry = true
			}
			if len(s.Expect.Detections) > 0 {
				tk.hasDetection = true
			}
		}
	}

	// Downgrade techniques that have gaps.
	for _, g := range report.Gaps {
		if g.Technique == "" || !strings.HasPrefix(g.Technique, "T") {
			continue
		}
		tk, ok := techs[g.Technique]
		if !ok {
			continue
		}
		switch g.Type {
		case gap.GapDetectionMissing:
			tk.hasDetection = false
		case gap.GapTelemetryMissing:
			tk.hasTelemetry = false
			tk.hasDetection = false
		}
	}

	return buildFromTechKeys(techs)
}

// buildFromTechKeys assembles the Matrix from the collected technique data.
func buildFromTechKeys(techs map[string]*techKey) *Matrix {
	m := &Matrix{
		Legend: Legend{
			Entries: []LegendEntry{
				{Label: "Full (detection + telemetry + multi-campaign)", Level: Full},
				{Label: "Detected (has detection rules)", Level: Detected},
				{Label: "Partial (telemetry only, no detection)", Level: Partial},
				{Label: "Uncovered (in registry, not exercised)", Level: Uncovered},
			},
		},
	}

	// Build one column per ATT&CK tactic (in kill-chain order).
	for _, tactic := range mitre.Tactics {
		col := TacticColumn{
			ID:    tactic.ID,
			Short: tactic.Short,
			Name:  tactic.Name,
		}

		// Gather all techniques in this tactic from the registry.
		var techIDs []string
		for id, t := range mitre.Techniques {
			if t.Tactic == tactic.Short {
				techIDs = append(techIDs, id)
			}
		}
		sort.Strings(techIDs)

		for _, id := range techIDs {
			t := mitre.Techniques[id]
			cell := TechniqueCell{
				ID:   id,
				Name: t.Name,
			}

			// Extract sub-technique suffix.
			if idx := strings.Index(id, "."); idx >= 0 {
				cell.SubID = id[idx:]
			}

			if tk, ok := techs[id]; ok {
				cell.Coverage = CoverageFromExpect(tk.hasTelemetry, tk.hasDetection, len(tk.campaigns))
				cell.Campaigns = sortedKeys(tk.campaigns)
			}
			// else Uncovered (zero value)

			col.Techniques = append(col.Techniques, cell)
		}

		m.Tactics = append(m.Tactics, col)
	}

	return m
}

// CoverageFromExpect computes the coverage level from expect-block data.
func CoverageFromExpect(hasTelemetry, hasDetection bool, campaignCount int) CoverageLevel {
	if hasDetection && hasTelemetry && campaignCount > 1 {
		return Full
	}
	if hasDetection {
		return Detected
	}
	if hasTelemetry {
		return Partial
	}
	return Uncovered
}

// ---------- Rendering ----------

// ANSI color codes.
const (
	ansiReset     = "[0m"
	ansiBold      = "[1m"
	ansiRed       = "[31m"
	ansiGreen     = "[32m"
	ansiYellow    = "[33m"
	ansiBrGreen   = "[92m"
	ansiGray      = "[90m"
	ansiBgRed     = "[41m"
	ansiBgGreen   = "[42m"
	ansiBgYellow  = "[43m"
	ansiBgBrGreen = "[102m"
	ansiWhite     = "[37m"
)

func useColor() bool {
	return os.Getenv("NO_COLOR") == ""
}

func colorForLevel(level CoverageLevel) string {
	if !useColor() {
		return ""
	}
	switch level {
	case Full:
		return ansiBrGreen
	case Detected:
		return ansiGreen
	case Partial:
		return ansiYellow
	case Uncovered:
		return ansiRed
	}
	return ""
}

func bgForLevel(level CoverageLevel) string {
	if !useColor() {
		return ""
	}
	switch level {
	case Full:
		return ansiBgBrGreen
	case Detected:
		return ansiBgGreen
	case Partial:
		return ansiBgYellow
	case Uncovered:
		return ansiBgRed
	}
	return ""
}

func reset() string {
	if !useColor() {
		return ""
	}
	return ansiReset
}

func bold(s string) string {
	if !useColor() {
		return s
	}
	return ansiBold + s + ansiReset
}

func gray(s string) string {
	if !useColor() {
		return s
	}
	return ansiGray + s + ansiReset
}

// Render draws the full ATT&CK matrix to the terminal.
// Each column is one tactic; cells show technique IDs with coverage coloring.
func Render(w io.Writer, m *Matrix) {
	if len(m.Tactics) == 0 {
		fmt.Fprintln(w, "No ATT&CK data to display.")
		return
	}

	colWidth := 12
	numCols := len(m.Tactics)

	// Title.
	fmt.Fprintln(w, bold("MITRE ATT&CK Coverage Matrix"))
	fmt.Fprintln(w)

	// Header row: tactic short names (abbreviated to fit column width).
	var headerParts []string
	for _, col := range m.Tactics {
		label := abbreviateTactic(col.Short, colWidth)
		headerParts = append(headerParts, fmt.Sprintf("%-*s", colWidth, label))
	}
	fmt.Fprintln(w, bold(strings.Join(headerParts, " ")))

	// Separator.
	var sep []string
	for range m.Tactics {
		sep = append(sep, strings.Repeat("─", colWidth))
	}
	fmt.Fprintln(w, gray(strings.Join(sep, "┬")))

	// Find max rows.
	maxRows := 0
	for _, col := range m.Tactics {
		if len(col.Techniques) > maxRows {
			maxRows = len(col.Techniques)
		}
	}

	// Technique rows.
	for row := 0; row < maxRows; row++ {
		var parts []string
		for c := 0; c < numCols; c++ {
			if row < len(m.Tactics[c].Techniques) {
				cell := m.Tactics[c].Techniques[row]
				// Compact: show technique ID only.
				label := cell.ID
				if len(label) > colWidth {
					label = label[:colWidth]
				}
				clr := colorForLevel(cell.Coverage)
				parts = append(parts, fmt.Sprintf("%s%-*s%s", clr, colWidth, label, reset()))
			} else {
				parts = append(parts, fmt.Sprintf("%-*s", colWidth, ""))
			}
		}
		fmt.Fprintln(w, strings.Join(parts, " "))
	}

	// Bottom separator.
	fmt.Fprintln(w, gray(strings.Join(sep, "┴")))

	// Legend.
	fmt.Fprintln(w)
	fmt.Fprintln(w, bold("Legend:"))
	for _, e := range m.Legend.Entries {
		marker := coverageMarker(e.Level)
		fmt.Fprintf(w, "  %s %s\n", marker, e.Label)
	}

	// Summary stats.
	fmt.Fprintln(w)
	total, covered := matrixStats(m)
	fmt.Fprintf(w, "Techniques in registry: %d  |  Exercised: %d  |  Coverage: %d%%\n",
		total, covered, pct(covered, total))
}

// RenderCompact draws a compressed matrix showing tactic headers with
// coverage counts (e.g. "8/11") — suitable for narrow terminals.
func RenderCompact(w io.Writer, m *Matrix) {
	if len(m.Tactics) == 0 {
		fmt.Fprintln(w, "No ATT&CK data to display.")
		return
	}

	fmt.Fprintln(w, bold("ATT&CK Tactic Coverage"))
	fmt.Fprintln(w)

	maxNameLen := 0
	for _, col := range m.Tactics {
		if len(col.Name) > maxNameLen {
			maxNameLen = len(col.Name)
		}
	}

	for _, col := range m.Tactics {
		total := len(col.Techniques)
		exercised := 0
		for _, t := range col.Techniques {
			if t.Coverage > Uncovered {
				exercised++
			}
		}

		bar := coverageBar(exercised, total, 20)
		ratio := fmt.Sprintf("%d/%d", exercised, total)

		var clr string
		switch {
		case total == 0:
			clr = gray("")
		case exercised == 0:
			clr = colorForLevel(Uncovered)
		case exercised < total/2:
			clr = colorForLevel(Partial)
		case exercised < total:
			clr = colorForLevel(Detected)
		default:
			clr = colorForLevel(Full)
		}

		fmt.Fprintf(w, "  %-*s  %s%-5s%s  %s\n",
			maxNameLen, col.Name, clr, ratio, reset(), bar)
	}

	fmt.Fprintln(w)
	total, covered := matrixStats(m)
	fmt.Fprintf(w, "Total: %d/%d techniques exercised (%d%%)\n",
		covered, total, pct(covered, total))
}

// ---------- Helpers ----------

// abbreviateTactic shortens a tactic short name to fit a column width.
func abbreviateTactic(short string, width int) string {
	abbrevs := map[string]string{
		"reconnaissance":       "Recon",
		"resource-development": "Res Dev",
		"initial-access":       "Init Access",
		"execution":            "Execution",
		"persistence":          "Persist",
		"privilege-escalation": "Priv Esc",
		"defense-evasion":      "Def Evasion",
		"credential-access":    "Cred Access",
		"discovery":            "Discovery",
		"lateral-movement":     "Lat Move",
		"collection":           "Collection",
		"command-and-control":  "C2",
		"exfiltration":         "Exfil",
		"impact":               "Impact",
	}
	if a, ok := abbrevs[short]; ok {
		if len(a) <= width {
			return a
		}
	}
	if len(short) <= width {
		return short
	}
	return short[:width]
}

// coverageMarker returns a colored symbol for the legend.
func coverageMarker(level CoverageLevel) string {
	symbols := map[CoverageLevel]string{
		Full:      "█",
		Detected:  "▓",
		Partial:   "▒",
		Uncovered: "░",
	}
	sym := symbols[level]
	bg := bgForLevel(level)
	if bg != "" {
		return bg + ansiWhite + " " + sym + " " + ansiReset
	}
	return " " + sym + " "
}

// coverageBar renders a horizontal bar chart.
func coverageBar(covered, total, width int) string {
	if total == 0 {
		return gray(strings.Repeat("░", width))
	}

	filled := covered * width / total
	if filled > width {
		filled = width
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)

	if useColor() {
		var clr string
		switch {
		case covered == 0:
			clr = ansiRed
		case covered < total/2:
			clr = ansiYellow
		case covered < total:
			clr = ansiGreen
		default:
			clr = ansiBrGreen
		}
		return clr + bar + ansiReset
	}
	return bar
}

// matrixStats returns total techniques in the matrix and how many are exercised.
func matrixStats(m *Matrix) (total, exercised int) {
	for _, col := range m.Tactics {
		for _, t := range col.Techniques {
			total++
			if t.Coverage > Uncovered {
				exercised++
			}
		}
	}
	return
}

func pct(n, d int) int {
	if d == 0 {
		return 0
	}
	return n * 100 / d
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// StageHasCoverage is a convenience to check coverage level from raw stage data.
// Exported for use in tests.
func StageHasCoverage(s campaign.Stage) CoverageLevel {
	hasTelemetry := len(s.Expect.Telemetry) > 0
	hasDetection := len(s.Expect.Detections) > 0
	return CoverageFromExpect(hasTelemetry, hasDetection, 1)
}
