// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package navigator generates MITRE ATT&CK Navigator layer JSON files
// from ThreatEcho simulation results and gap reports.
//
// The output conforms to Navigator layer format v4.5 and can be imported
// directly into https://mitre-attack.github.io/attack-navigator/ for
// technique coverage visualization.
//
// Only ATT&CK techniques (T-prefixed) are included. ATLAS and OWASP LLM
// techniques have no representation in the ATT&CK Navigator.
package navigator

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/gap"
	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// Navigator layer format v4.5 color palette.
const (
	ColorCovered      = "#a1d99b" // green — technique covered with detections
	ColorDetectionGap = "#fed976" // yellow — telemetry present, no detections
	ColorTelemetryGap = "#fd8d3c" // orange — no telemetry defined
	ColorUncovered    = "#fc4e2a" // red — technique in gap report, uncovered tactic
)

// Layer is the top-level ATT&CK Navigator layer document.
type Layer struct {
	Name         string       `json:"name"`
	Versions     Versions     `json:"versions"`
	Domain       string       `json:"domain"`
	Description  string       `json:"description"`
	Filters      Filters      `json:"filters"`
	Sorting      int          `json:"sorting"`
	Layout       Layout       `json:"layout"`
	HideDisabled bool         `json:"hideDisabled"`
	Techniques   []TechEntry  `json:"techniques"`
	Gradient     Gradient     `json:"gradient"`
	LegendItems  []LegendItem `json:"legendItems"`
	Metadata     []MetaEntry  `json:"metadata"`

	ShowTacticRowBackground       bool   `json:"showTacticRowBackground"`
	TacticRowBackground           string `json:"tacticRowBackground"`
	SelectTechniquesAcrossTactics bool   `json:"selectTechniquesAcrossTactics"`
	SelectSubtechniquesWithParent bool   `json:"selectSubtechniquesWithParent"`
}

// Versions declares the ATT&CK, Navigator, and layer schema versions.
type Versions struct {
	Attack    string `json:"attack"`
	Navigator string `json:"navigator"`
	Layer     string `json:"layer"`
}

// Filters limits the platforms shown in the Navigator.
type Filters struct {
	Platforms []string `json:"platforms"`
}

// Layout controls how the Navigator renders the matrix.
type Layout struct {
	Layout            string `json:"layout"`
	AggregateFunction string `json:"aggregateFunction"`
	ShowID            bool   `json:"showID"`
	ShowName          bool   `json:"showName"`
}

// TechEntry is one technique's annotation in the layer.
type TechEntry struct {
	TechniqueID       string      `json:"techniqueID"`
	Tactic            string      `json:"tactic,omitempty"`
	Color             string      `json:"color"`
	Comment           string      `json:"comment"`
	Score             int         `json:"score"`
	Enabled           bool        `json:"enabled"`
	Metadata          []MetaEntry `json:"metadata"`
	Links             []Link      `json:"links"`
	ShowSubtechniques bool        `json:"showSubtechniques"`
}

// Gradient defines the score-to-color gradient for the Navigator.
type Gradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

// LegendItem maps a color to a description in the Navigator legend.
type LegendItem struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

// MetaEntry is a key-value metadata pair.
type MetaEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Link is an external reference attached to a technique.
type Link struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// techniqueState tracks coverage state for a single technique.
type techniqueState struct {
	hasDetections bool
	hasTelemetry  bool
	stages        int
	campaigns     []string
	comment       string
}

// FromRunResult generates a Navigator layer from one or more simulation results.
// It annotates each ATT&CK technique with its coverage state based on the
// stage definitions: green if detections are defined, yellow if only telemetry,
// orange if neither.
func FromRunResult(results ...*engine.RunResult) *Layer {
	techniques := make(map[string]*techniqueState)

	for _, r := range results {
		for _, sr := range r.Stages {
			if sr.Skipped {
				continue
			}
			s := sr.Stage

			// Only ATT&CK techniques go into Navigator.
			if !isATTACK(s.Technique) {
				continue
			}

			st, ok := techniques[s.Technique]
			if !ok {
				st = &techniqueState{}
				techniques[s.Technique] = st
			}

			st.stages++
			if len(s.Expect.Detections) > 0 {
				st.hasDetections = true
			}
			if len(s.Expect.Telemetry) > 0 {
				st.hasTelemetry = true
			}

			cname := r.Campaign.Meta.Name
			found := false
			for _, c := range st.campaigns {
				if c == cname {
					found = true
					break
				}
			}
			if !found {
				st.campaigns = append(st.campaigns, cname)
			}
		}
	}

	// Build technique entries.
	var entries []TechEntry
	for id, st := range techniques {
		color := ColorTelemetryGap
		comment := "No telemetry defined"
		score := 25

		if st.hasTelemetry && !st.hasDetections {
			color = ColorDetectionGap
			comment = "Telemetry defined, no detections"
			score = 50
		}
		if st.hasDetections {
			color = ColorCovered
			comment = "Covered with detections"
			score = 100
		}

		// Add campaign and stage context.
		comment += " [campaigns: " + strings.Join(st.campaigns, ", ") +
			"; stages: " + itoa(st.stages) + "]"

		entries = append(entries, TechEntry{
			TechniqueID:       id,
			Color:             color,
			Comment:           comment,
			Score:             score,
			Enabled:           true,
			Metadata:          []MetaEntry{},
			Links:             []Link{},
			ShowSubtechniques: strings.Contains(id, "."),
		})
	}

	// Sort entries by technique ID for deterministic output.
	sortEntries(entries)

	layer := newBaseLayer("ThreatEcho Coverage", "Coverage layer generated by ThreatEcho from simulation results")
	layer.Techniques = entries
	return layer
}

// FromGapReport generates a Navigator layer from a gap analysis report.
// It overlays technique coverage from campaigns with gap information,
// color-coding each technique by its worst gap status.
func FromGapReport(r *gap.GapReport) *Layer {
	techniques := make(map[string]*techniqueState)

	// First pass: extract covered techniques from campaign coverage.
	for _, cc := range r.Campaigns {
		// We don't have direct access to stages from CampaignCoverage,
		// so we work from the gaps to derive which techniques have issues.
		_ = cc
	}

	// Populate from gaps — techniques that appear in gaps.
	gapTechniques := make(map[string]gap.GapType)
	for _, g := range r.Gaps {
		if g.Technique == "" || !isATTACK(g.Technique) {
			continue
		}

		// Keep the worst gap type for each technique.
		existing, ok := gapTechniques[g.Technique]
		if !ok || gapSeverity(g.Type) > gapSeverity(existing) {
			gapTechniques[g.Technique] = g.Type
		}

		st, ok := techniques[g.Technique]
		if !ok {
			st = &techniqueState{}
			techniques[g.Technique] = st
		}

		if g.CampaignName != "" {
			found := false
			for _, c := range st.campaigns {
				if c == g.CampaignName {
					found = true
					break
				}
			}
			if !found {
				st.campaigns = append(st.campaigns, g.CampaignName)
			}
		}
		st.stages++

		switch g.Type {
		case gap.GapDetectionMissing:
			st.hasTelemetry = true
		case gap.GapTelemetryMissing:
			// Neither telemetry nor detections.
		}
	}

	// Build technique entries from gap data.
	var entries []TechEntry
	for id, gt := range gapTechniques {
		st := techniques[id]
		var color, comment string
		var score int

		switch gt {
		case gap.GapDetectionMissing:
			color = ColorDetectionGap
			comment = "Detection gap — telemetry defined but no detection rules"
			score = 50
		case gap.GapTelemetryMissing:
			color = ColorTelemetryGap
			comment = "Telemetry gap — no expected telemetry defined"
			score = 25
		default:
			color = ColorUncovered
			comment = "Uncovered"
			score = 10
		}

		if st != nil && len(st.campaigns) > 0 {
			comment += " [campaigns: " + strings.Join(st.campaigns, ", ") + "]"
		}

		entries = append(entries, TechEntry{
			TechniqueID:       id,
			Color:             color,
			Comment:           comment,
			Score:             score,
			Enabled:           true,
			Metadata:          []MetaEntry{},
			Links:             []Link{},
			ShowSubtechniques: strings.Contains(id, "."),
		})
	}

	sortEntries(entries)

	layer := newBaseLayer("ThreatEcho Gap Analysis",
		"Gap analysis layer generated by ThreatEcho — techniques colored by detection gap severity")
	layer.Techniques = entries
	return layer
}

// WriteLayer serializes a Layer to JSON and writes it to w.
func WriteLayer(w io.Writer, l *Layer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(l)
}

// newBaseLayer returns a Layer with standard defaults filled in.
func newBaseLayer(name, description string) *Layer {
	return &Layer{
		Name:        name,
		Description: description,
		Versions: Versions{
			Attack:    "15",
			Navigator: "4.5",
			Layer:     "4.5",
		},
		Domain: "enterprise-attack",
		Filters: Filters{
			Platforms: []string{
				"Linux", "macOS", "Windows",
				"Network", "PRE", "Containers",
				"Office 365", "SaaS", "IaaS",
				"Google Workspace", "Azure AD",
			},
		},
		Sorting: 0,
		Layout: Layout{
			Layout:            "side",
			AggregateFunction: "average",
			ShowID:            true,
			ShowName:          true,
		},
		HideDisabled: false,
		Gradient: Gradient{
			Colors:   []string{ColorUncovered, ColorTelemetryGap, ColorDetectionGap, ColorCovered},
			MinValue: 0,
			MaxValue: 100,
		},
		LegendItems: []LegendItem{
			{Label: "Covered (detections defined)", Color: ColorCovered},
			{Label: "Detection gap (telemetry only)", Color: ColorDetectionGap},
			{Label: "Telemetry gap (blind spot)", Color: ColorTelemetryGap},
			{Label: "Uncovered", Color: ColorUncovered},
		},
		Metadata: []MetaEntry{
			{Name: "generated_by", Value: "ThreatEcho"},
			{Name: "generated_at", Value: time.Now().UTC().Format(time.RFC3339)},
		},
		ShowTacticRowBackground:       false,
		TacticRowBackground:           "#dddddd",
		SelectTechniquesAcrossTactics: true,
		SelectSubtechniquesWithParent: false,
	}
}

// isATTACK returns true if the technique ID is an ATT&CK technique (T-prefixed).
func isATTACK(id string) bool {
	return strings.HasPrefix(id, "T")
}

// gapSeverity returns a numeric severity for gap type ordering.
// Higher = worse.
func gapSeverity(t gap.GapType) int {
	switch t {
	case gap.GapTelemetryMissing:
		return 3
	case gap.GapDetectionMissing:
		return 2
	case gap.GapTacticUncovered:
		return 1
	}
	return 0
}

// sortEntries sorts technique entries by ID for deterministic output.
func sortEntries(entries []TechEntry) {
	// Insertion sort — small lists, no sort import needed.
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].TechniqueID < entries[j-1].TechniqueID; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
}

// itoa converts an int to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [20]byte{}
	i := len(buf) - 1
	for n > 0 {
		buf[i] = byte('0' + n%10)
		i--
		n /= 10
	}
	if neg {
		buf[i] = '-'
		i--
	}
	return string(buf[i+1:])
}

// Ensure mitre package is used (technique lookup used in tests and
// available for extensions).
var _ = mitre.LookupTechnique
