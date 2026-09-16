// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// JSONReport is the top-level structure for JSON report output.
type JSONReport struct {
	Version     string       `json:"version"`
	GeneratedAt string       `json:"generated_at"`
	Mode        string       `json:"mode"`
	Campaign    JSONCampaign `json:"campaign"`
	Stages      []JSONStage  `json:"stages"`
	Coverage    JSONCoverage `json:"coverage"`
	Summary     JSONSummary  `json:"summary"`
}

// JSONCampaign holds campaign metadata in the JSON report.
type JSONCampaign struct {
	Name         string   `json:"name"`
	Adversary    string   `json:"adversary"`
	Description  string   `json:"description,omitempty"`
	Objective    string   `json:"objective,omitempty"`
	Severity     string   `json:"severity"`
	MitreVersion string   `json:"mitre_version,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	References   []string `json:"references,omitempty"`
}

// JSONStage holds per-stage results in the JSON report.
type JSONStage struct {
	Order         int      `json:"order"`
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Technique     string   `json:"technique"`
	TechniqueName string   `json:"technique_name"`
	Tactic        string   `json:"tactic"`
	TacticName    string   `json:"tactic_name"`
	ExecType      string   `json:"exec_type"`
	Skipped       bool     `json:"skipped"`
	SkipReason    string   `json:"skip_reason,omitempty"`
	Result        string   `json:"result,omitempty"`
	Telemetry     []string `json:"telemetry,omitempty"`
	Detections    []string `json:"detections,omitempty"`
	DependsOn     []string `json:"depends_on,omitempty"`
}

// JSONCoverage holds coverage analysis in the JSON report.
type JSONCoverage struct {
	Tactics    JSONTacticCoverage `json:"tactics"`
	Techniques JSONTechCoverage   `json:"techniques"`
	Telemetry  []string           `json:"telemetry_types"`
	Detections []string           `json:"detection_rules"`
}

// JSONTacticCoverage holds tactic coverage breakdown.
type JSONTacticCoverage struct {
	Total   int      `json:"total"`
	Covered int      `json:"covered"`
	Percent int      `json:"percent"`
	Hit     []string `json:"hit"`
	Miss    []string `json:"miss"`
}

// JSONTechCoverage holds technique coverage breakdown.
type JSONTechCoverage struct {
	Unique int             `json:"unique"`
	List   []JSONTechEntry `json:"list"`
}

// JSONTechEntry is a single technique in the coverage list.
type JSONTechEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// JSONSummary holds stage execution counts.
type JSONSummary struct {
	StagesTotal    int `json:"stages_total"`
	StagesComplete int `json:"stages_completed"`
	StagesSkipped  int `json:"stages_skipped"`
	StagesFailed   int `json:"stages_failed"`
}

// ResolveTechniqueName looks up a technique name across ATT&CK, ATLAS, and OWASP LLM.
// Returns the ID itself if no match is found.
func ResolveTechniqueName(id string) string {
	if t := mitre.LookupTechnique(id); t != nil {
		return t.Name
	}
	if t := mitre.LookupATLASTechnique(id); t != nil {
		return t.Name
	}
	if t := mitre.LookupOWASPLLM(id); t != nil {
		return t.Name
	}
	return id
}

// ResolveTacticName looks up a tactic name across ATT&CK and ATLAS.
// Returns the short name itself if no match is found.
func ResolveTacticName(short string) string {
	if t := mitre.TacticByShort(short); t != nil {
		return t.Name
	}
	if t := mitre.ATLASTacticByShort(short); t != nil {
		return t.Name
	}
	return short
}

// classifyTechnique returns "attack", "atlas", "owasp", or "unknown".
func classifyTechnique(id string) string {
	if strings.HasPrefix(id, "AML.") {
		return "atlas"
	}
	if strings.HasPrefix(id, "LLM") {
		return "owasp"
	}
	if strings.HasPrefix(id, "T") {
		return "attack"
	}
	return "unknown"
}

// JSONReportWrite writes a JSON simulation/run report to w.
func JSONReportWrite(w io.Writer, r *engine.RunResult) error {
	c := r.Campaign

	// Build stages.
	stages := make([]JSONStage, 0, len(r.Stages))
	for _, sr := range r.Stages {
		s := sr.Stage
		js := JSONStage{
			Order:         sr.Order,
			ID:            s.ID,
			Name:          s.Name,
			Technique:     s.Technique,
			TechniqueName: ResolveTechniqueName(s.Technique),
			Tactic:        s.Tactic,
			TacticName:    ResolveTacticName(s.Tactic),
			ExecType:      s.Execute.Type,
			Skipped:       sr.Skipped,
		}
		if sr.Skipped {
			js.SkipReason = sr.SkipMsg
		} else {
			js.Result = sr.Exec.Output
		}
		if len(s.Expect.Telemetry) > 0 {
			js.Telemetry = s.Expect.Telemetry
		}
		if len(s.Expect.Detections) > 0 {
			js.Detections = s.Expect.Detections
		}
		if len(s.DependsOn) > 0 {
			js.DependsOn = s.DependsOn
		}
		stages = append(stages, js)
	}

	// Tactic coverage.
	covered, missing := r.TacticCoverage()
	total := len(covered) + len(missing)
	pct := 0
	if total > 0 {
		pct = len(covered) * 100 / total
	}

	// Technique coverage.
	techniques := c.UniqueTechniques()
	techList := make([]JSONTechEntry, 0, len(techniques))
	for _, tid := range techniques {
		techList = append(techList, JSONTechEntry{
			ID:   tid,
			Name: ResolveTechniqueName(tid),
		})
	}

	report := JSONReport{
		Version:     "1.0",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Mode:        r.Mode,
		Campaign: JSONCampaign{
			Name:         c.Meta.Name,
			Adversary:    c.Meta.Adversary,
			Description:  c.Meta.Description,
			Objective:    c.Meta.Objective,
			Severity:     c.Meta.Severity,
			MitreVersion: c.Meta.MitreVersion,
			Tags:         c.Meta.Tags,
			References:   c.Meta.References,
		},
		Stages: stages,
		Coverage: JSONCoverage{
			Tactics: JSONTacticCoverage{
				Total:   total,
				Covered: len(covered),
				Percent: pct,
				Hit:     covered,
				Miss:    missing,
			},
			Techniques: JSONTechCoverage{
				Unique: len(techniques),
				List:   techList,
			},
			Telemetry:  c.AllTelemetryTypes(),
			Detections: c.AllDetections(),
		},
		Summary: JSONSummary{
			StagesTotal:    len(r.Stages),
			StagesComplete: r.Completed,
			StagesSkipped:  r.Skipped,
			StagesFailed:   r.Failed,
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}
