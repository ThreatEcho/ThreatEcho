// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package gap

import (
	"sort"

	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// TechniqueCoverage represents coverage data for a single technique.
type TechniqueCoverage struct {
	TechniqueID    string   `json:"technique_id"`
	TechniqueName  string   `json:"technique_name"`
	Framework      string   `json:"framework"` // "attack", "atlas", "owasp"
	Tactic         string   `json:"tactic"`
	CampaignCount  int      `json:"campaign_count"`  // how many campaigns use this technique
	Campaigns      []string `json:"campaigns"`       // campaign names that use it
	HasTelemetry   bool     `json:"has_telemetry"`   // at least one stage has telemetry expectations
	HasDetections  bool     `json:"has_detections"`  // at least one stage has detection rules
	TelemetryTypes []string `json:"telemetry_types"` // all telemetry types across stages
	DetectionRules []string `json:"detection_rules"` // all detection rules across stages
	Status         string   `json:"status"`          // "full", "partial", "telemetry-only", "uncovered"
}

// CoverageReport is the full technique-level coverage analysis.
type CoverageReport struct {
	TotalTechniquesInRegistry int                            `json:"total_techniques_in_registry"`
	TechniquesExercised       int                            `json:"techniques_exercised"`
	TechniquesWithDetections  int                            `json:"techniques_with_detections"`
	TechniquesWithTelemetry   int                            `json:"techniques_with_telemetry"`
	Techniques                []TechniqueCoverage            `json:"techniques"`
	TechniquesByTactic        map[string][]TechniqueCoverage `json:"techniques_by_tactic"`
	TechniquesUncovered       []TechniqueRef                 `json:"techniques_uncovered"`
	ByFramework               FrameworkCoverageStats         `json:"by_framework"`
}

// TechniqueRef is a minimal reference to a technique not covered by any campaign.
type TechniqueRef struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

// FrameworkCoverageStats summarizes coverage per framework.
type FrameworkCoverageStats struct {
	ATTACKTotal   int `json:"attack_total"`
	ATTACKCovered int `json:"attack_covered"`
	ATLASTotal    int `json:"atlas_total"`
	ATLASCovered  int `json:"atlas_covered"`
	OWASPTotal    int `json:"owasp_total"`
	OWASPCovered  int `json:"owasp_covered"`
}

// techAccum accumulates per-technique data during analysis.
type techAccum struct {
	campaigns  map[string]bool
	telemetry  map[string]bool
	detections map[string]bool
	tactic     string
}

// AnalyzeCoverage produces a technique-level coverage report from simulation results.
func AnalyzeCoverage(results ...*engine.RunResult) *CoverageReport {
	cr := &CoverageReport{
		TechniquesByTactic: make(map[string][]TechniqueCoverage),
	}

	if len(results) == 0 {
		cr.TotalTechniquesInRegistry = registrySize()
		cr.ByFramework = frameworkTotals()
		cr.TechniquesUncovered = allRegistryRefs()
		return cr
	}

	// Accumulate data per technique across all campaign results.
	accum := make(map[string]*techAccum)

	for _, r := range results {
		for _, sr := range r.Stages {
			if sr.Skipped {
				continue
			}
			s := sr.Stage
			tid := s.Technique

			acc, ok := accum[tid]
			if !ok {
				acc = &techAccum{
					campaigns:  make(map[string]bool),
					telemetry:  make(map[string]bool),
					detections: make(map[string]bool),
					tactic:     s.Tactic,
				}
				accum[tid] = acc
			}

			acc.campaigns[r.Campaign.Meta.Name] = true
			for _, t := range s.Expect.Telemetry {
				acc.telemetry[t] = true
			}
			for _, d := range s.Expect.Detections {
				acc.detections[d] = true
			}
		}
	}

	// Build TechniqueCoverage entries from accumulated data.
	exercisedIDs := make(map[string]bool)
	for tid, acc := range accum {
		exercisedIDs[tid] = true
		tc := buildTechniqueCoverage(tid, acc)
		cr.Techniques = append(cr.Techniques, tc)
	}

	// Sort by technique ID for stable output.
	sort.Slice(cr.Techniques, func(i, j int) bool {
		return cr.Techniques[i].TechniqueID < cr.Techniques[j].TechniqueID
	})

	// Build per-tactic map.
	for _, tc := range cr.Techniques {
		cr.TechniquesByTactic[tc.Tactic] = append(cr.TechniquesByTactic[tc.Tactic], tc)
	}

	// Compute uncovered techniques.
	cr.TechniquesUncovered = uncoveredRefs(exercisedIDs)

	// Compute stats.
	cr.TotalTechniquesInRegistry = registrySize()
	cr.TechniquesExercised = len(cr.Techniques)
	for _, tc := range cr.Techniques {
		if tc.HasDetections {
			cr.TechniquesWithDetections++
		}
		if tc.HasTelemetry {
			cr.TechniquesWithTelemetry++
		}
	}

	// Framework stats.
	cr.ByFramework = frameworkCoverage(exercisedIDs)

	return cr
}

// buildTechniqueCoverage converts accumulated data into a TechniqueCoverage.
func buildTechniqueCoverage(tid string, acc *techAccum) TechniqueCoverage {
	tc := TechniqueCoverage{
		TechniqueID:    tid,
		TechniqueName:  ResolveTechniqueName(tid),
		Framework:      classifyTechnique(tid),
		Tactic:         acc.tactic,
		CampaignCount:  len(acc.campaigns),
		Campaigns:      setToSorted(acc.campaigns),
		HasTelemetry:   len(acc.telemetry) > 0,
		HasDetections:  len(acc.detections) > 0,
		TelemetryTypes: setToSorted(acc.telemetry),
		DetectionRules: setToSorted(acc.detections),
	}
	tc.Status = computeStatus(tc.HasTelemetry, tc.HasDetections)
	return tc
}

// computeStatus determines the coverage status from telemetry/detection presence.
func computeStatus(hasTelemetry, hasDetections bool) string {
	switch {
	case hasTelemetry && hasDetections:
		return "full"
	case hasTelemetry && !hasDetections:
		return "telemetry-only"
	case !hasTelemetry && hasDetections:
		return "partial"
	default:
		return "uncovered"
	}
}

// registrySize returns the total number of techniques across all registries.
func registrySize() int {
	return len(mitre.Techniques) + len(mitre.ATLASTechniques) + len(mitre.OWASPLLMTop10)
}

// frameworkTotals returns FrameworkCoverageStats with totals only, zero coverage.
func frameworkTotals() FrameworkCoverageStats {
	return FrameworkCoverageStats{
		ATTACKTotal: len(mitre.Techniques),
		ATLASTotal:  len(mitre.ATLASTechniques),
		OWASPTotal:  len(mitre.OWASPLLMTop10),
	}
}

// frameworkCoverage computes per-framework total and covered counts.
func frameworkCoverage(exercised map[string]bool) FrameworkCoverageStats {
	fs := frameworkTotals()
	for id := range exercised {
		switch classifyTechnique(id) {
		case "attack":
			fs.ATTACKCovered++
		case "atlas":
			fs.ATLASCovered++
		case "owasp":
			fs.OWASPCovered++
		}
	}
	return fs
}

// allRegistryRefs returns all techniques from all registries as TechniqueRef slices.
func allRegistryRefs() []TechniqueRef {
	var refs []TechniqueRef
	for id, t := range mitre.Techniques {
		refs = append(refs, TechniqueRef{ID: id, Name: t.Name, Tactic: t.Tactic})
	}
	for id, t := range mitre.ATLASTechniques {
		refs = append(refs, TechniqueRef{ID: id, Name: t.Name, Tactic: t.Tactic})
	}
	for id, e := range mitre.OWASPLLMTop10 {
		refs = append(refs, TechniqueRef{ID: id, Name: e.Name})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	return refs
}

// uncoveredRefs returns registry techniques not present in exercised.
func uncoveredRefs(exercised map[string]bool) []TechniqueRef {
	var refs []TechniqueRef
	for id, t := range mitre.Techniques {
		if !exercised[id] {
			refs = append(refs, TechniqueRef{ID: id, Name: t.Name, Tactic: t.Tactic})
		}
	}
	for id, t := range mitre.ATLASTechniques {
		if !exercised[id] {
			refs = append(refs, TechniqueRef{ID: id, Name: t.Name, Tactic: t.Tactic})
		}
	}
	for id, e := range mitre.OWASPLLMTop10 {
		if !exercised[id] {
			refs = append(refs, TechniqueRef{ID: id, Name: e.Name})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	return refs
}

// setToSorted converts a bool-set map to a sorted string slice.
func setToSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
