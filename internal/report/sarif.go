// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/gap"
	"github.com/ThreatEcho/threatecho/internal/policy"
	"github.com/ThreatEcho/threatecho/pkg/version"
)

// SARIF v2.1.0 constants.
const (
	sarifSchema   = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifVersion  = "2.1.0"
	sarifToolName = "ThreatEcho"
	sarifInfoURI  = "https://github.com/ThreatEcho/threatecho"
)

// Gap rule IDs.
const (
	gapRuleDetectionMissing = "TE-GAP-001"
	gapRuleTelemetryMissing = "TE-GAP-002"
	gapRuleTacticUncovered  = "TE-GAP-003"
)

// SARIF v2.1.0 types — unexported, internal to the report package.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  sarifMessage    `json:"fullDescription,omitempty"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
	Properties       map[string]any  `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// gapRules returns the fixed set of SARIF rules for gap analysis.
func gapRules() []sarifRule {
	return []sarifRule{
		{
			ID:               gapRuleDetectionMissing,
			Name:             "DetectionMissing",
			ShortDescription: sarifMessage{Text: "Detection rule missing for technique"},
			FullDescription:  sarifMessage{Text: "A campaign stage declares expected telemetry but no detection rules — telemetry will fire with nothing to catch it."},
			DefaultConfig:    sarifRuleConfig{Level: "warning"},
			Properties:       map[string]any{"tags": []string{"detection-engineering", "gap-analysis"}},
		},
		{
			ID:               gapRuleTelemetryMissing,
			Name:             "TelemetryMissing",
			ShortDescription: sarifMessage{Text: "Telemetry source missing for technique"},
			FullDescription:  sarifMessage{Text: "A campaign stage declares no expected telemetry — detection engineering cannot begin without observable artifacts."},
			DefaultConfig:    sarifRuleConfig{Level: "error"},
			Properties:       map[string]any{"tags": []string{"detection-engineering", "gap-analysis"}},
		},
		{
			ID:               gapRuleTacticUncovered,
			Name:             "TacticUncovered",
			ShortDescription: sarifMessage{Text: "MITRE tactic has no stage coverage"},
			FullDescription:  sarifMessage{Text: "An entire MITRE ATT&CK or ATLAS tactic has zero stage coverage across all analyzed campaigns."},
			DefaultConfig:    sarifRuleConfig{Level: "warning"},
			Properties:       map[string]any{"tags": []string{"detection-engineering", "gap-analysis"}},
		},
	}
}

// gapTypeToRule maps a GapType to its SARIF rule ID and index in gapRules().
func gapTypeToRule(t gap.GapType) (ruleID string, ruleIndex int, level string) {
	switch t {
	case gap.GapDetectionMissing:
		return gapRuleDetectionMissing, 0, "warning"
	case gap.GapTelemetryMissing:
		return gapRuleTelemetryMissing, 1, "error"
	case gap.GapTacticUncovered:
		return gapRuleTacticUncovered, 2, "warning"
	default:
		return gapRuleDetectionMissing, 0, "warning"
	}
}

// GapSARIFReport writes a SARIF v2.1.0 report for gap analysis results.
func GapSARIFReport(w io.Writer, r *gap.GapReport, campaignFile string) error {
	results := make([]sarifResult, 0, len(r.Gaps))

	for _, g := range r.Gaps {
		ruleID, ruleIndex, level := gapTypeToRule(g.Type)

		sr := sarifResult{
			RuleID:    ruleID,
			RuleIndex: ruleIndex,
			Level:     level,
			Message:   sarifMessage{Text: g.Description},
			Properties: map[string]any{
				"risk":      g.Risk,
				"tactic":    g.Tactic,
				"technique": g.Technique,
				"campaign":  g.CampaignName,
			},
		}

		if campaignFile != "" {
			sr.Locations = []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: campaignFile},
					},
				},
			}
		}

		results = append(results, sr)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           sarifToolName,
						Version:        version.Version,
						InformationURI: sarifInfoURI,
						Rules:          gapRules(),
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// ---------------------------------------------------------------------------
// Generic finding type
// ---------------------------------------------------------------------------

// Finding is a generic, source-agnostic diagnostic that can be converted to
// SARIF. Higher-level converters (LintSARIFReport, ThreatSARIFReport) are
// preferred when you have a typed report; use FindingSARIFReport when
// aggregating heterogeneous results.
type Finding struct {
	RuleID   string `json:"rule_id"`
	Level    string `json:"level"` // "error", "warning", "note", "none"
	Message  string `json:"message"`
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"`
	Category string `json:"category,omitempty"`
}

// ---------------------------------------------------------------------------
// Finding → SARIF
// ---------------------------------------------------------------------------

// normalizeSARIFLevel maps caller-supplied levels to the four SARIF levels.
func normalizeSARIFLevel(level string) string {
	switch level {
	case "error":
		return "error"
	case "warning":
		return "warning"
	case "info", "note":
		return "note"
	case "style", "none":
		return "none"
	default:
		return "warning"
	}
}

// FindingSARIFReport writes a SARIF v2.1.0 report from generic findings.
func FindingSARIFReport(w io.Writer, findings []Finding) error {
	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, f := range findings {
		if _, exists := ruleIndex[f.RuleID]; exists {
			continue
		}
		idx := len(rules)
		ruleIndex[f.RuleID] = idx
		rules = append(rules, sarifRule{
			ID:               f.RuleID,
			Name:             f.RuleID,
			ShortDescription: sarifMessage{Text: f.Category},
			DefaultConfig:    sarifRuleConfig{Level: normalizeSARIFLevel(f.Level)},
		})
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		sr := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex[f.RuleID],
			Level:     normalizeSARIFLevel(f.Level),
			Message:   sarifMessage{Text: f.Message},
		}
		if f.FilePath != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.FilePath},
				},
			}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			sr.Locations = []sarifLocation{loc}
		}
		results = append(results, sr)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           sarifToolName,
						Version:        version.Version,
						InformationURI: sarifInfoURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// ---------------------------------------------------------------------------
// Lint → SARIF
// ---------------------------------------------------------------------------

// lintSeverityToSARIF maps lint severity to SARIF level.
func lintSeverityToSARIF(s policy.LintSeverity) string {
	switch s {
	case policy.LintError:
		return "error"
	case policy.LintWarning:
		return "warning"
	case policy.LintInfo:
		return "note"
	case policy.LintStyle:
		return "none"
	default:
		return "warning"
	}
}

// LintSARIFReport writes a SARIF v2.1.0 report from policy lint results.
func LintSARIFReport(w io.Writer, r *policy.LintReport, policyPath string) error {
	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, f := range r.Findings {
		if _, exists := ruleIndex[f.Rule]; exists {
			continue
		}
		idx := len(rules)
		ruleIndex[f.Rule] = idx
		rules = append(rules, sarifRule{
			ID:               f.Rule,
			Name:             f.Rule,
			ShortDescription: sarifMessage{Text: string(f.Category)},
			DefaultConfig:    sarifRuleConfig{Level: lintSeverityToSARIF(f.Severity)},
			Properties:       map[string]any{"tags": []string{"policy-lint", string(f.Category)}},
		})
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		sr := sarifResult{
			RuleID:    f.Rule,
			RuleIndex: ruleIndex[f.Rule],
			Level:     lintSeverityToSARIF(f.Severity),
			Message:   sarifMessage{Text: f.Message},
			Properties: map[string]any{
				"category":   string(f.Category),
				"rule_id":    f.RuleID,
				"suggestion": f.Suggestion,
			},
		}
		if policyPath != "" {
			sr.Locations = []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: policyPath},
					},
				},
			}
		}
		results = append(results, sr)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           sarifToolName,
						Version:        version.Version,
						InformationURI: sarifInfoURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// ---------------------------------------------------------------------------
// Threat model → SARIF
// ---------------------------------------------------------------------------

// threatSeverityToSARIF maps threat severity to SARIF level.
func threatSeverityToSARIF(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

// ThreatSARIFReport writes a SARIF v2.1.0 report from a STRIDE threat model.
func ThreatSARIFReport(w io.Writer, m *engine.ThreatModel) error {
	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, t := range m.Threats {
		ruleID := "STRIDE-" + string(t.Category)
		if _, exists := ruleIndex[ruleID]; exists {
			continue
		}
		idx := len(rules)
		ruleIndex[ruleID] = idx
		rules = append(rules, sarifRule{
			ID:               ruleID,
			Name:             string(t.Category),
			ShortDescription: sarifMessage{Text: "STRIDE: " + string(t.Category)},
			DefaultConfig:    sarifRuleConfig{Level: "warning"},
			Properties:       map[string]any{"tags": []string{"stride", "threat-model", string(t.Category)}},
		})
	}

	results := make([]sarifResult, 0, len(m.Threats))
	for _, t := range m.Threats {
		ruleID := "STRIDE-" + string(t.Category)
		sr := sarifResult{
			RuleID:    ruleID,
			RuleIndex: ruleIndex[ruleID],
			Level:     threatSeverityToSARIF(t.Severity),
			Message:   sarifMessage{Text: t.Title + ": " + t.Description},
			Properties: map[string]any{
				"threat_id":         t.ID,
				"severity":          t.Severity,
				"likelihood":        t.Likelihood,
				"risk_score":        t.RiskScore,
				"affected_agent":    t.AffectedAgent,
				"affected_tool":     t.AffectedTool,
				"mitigation_status": t.MitigationStatus,
			},
		}
		results = append(results, sr)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           sarifToolName,
						Version:        version.Version,
						InformationURI: sarifInfoURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

// FormatSARIF marshals a sarifLog to indented JSON.
func FormatSARIF(log *sarifLog) (string, error) {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WriteSARIF writes a SARIF log to a file.
func WriteSARIF(log *sarifLog, path string) error {
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// PolicySARIFReport writes a SARIF v2.1.0 report for policy evaluation results.
func PolicySARIFReport(w io.Writer, r *policy.EvalResult, campaignFile string) error {
	// Build unique rules from violations. Preserve order of first appearance.
	ruleIndex := make(map[string]int) // ruleID -> index
	var rules []sarifRule

	for _, v := range r.Violations {
		if _, exists := ruleIndex[v.RuleID]; exists {
			continue
		}
		idx := len(rules)
		ruleIndex[v.RuleID] = idx

		level := "warning"
		if v.Effect == "deny" {
			level = "error"
		}

		rules = append(rules, sarifRule{
			ID:               v.RuleID,
			Name:             v.RuleID,
			ShortDescription: sarifMessage{Text: v.RuleDesc},
			DefaultConfig:    sarifRuleConfig{Level: level},
			Properties:       map[string]any{"tags": []string{"policy", "agent-security"}},
		})
	}

	results := make([]sarifResult, 0, len(r.Violations))

	for _, v := range r.Violations {
		level := "warning"
		if v.Effect == "deny" {
			level = "error"
		}

		idx := ruleIndex[v.RuleID]

		sr := sarifResult{
			RuleID:    v.RuleID,
			RuleIndex: idx,
			Level:     level,
			Message:   sarifMessage{Text: v.Reason},
			Properties: map[string]any{
				"stage_id":  v.StageID,
				"technique": v.Technique,
				"tactic":    v.Tactic,
				"tool":      v.Tool,
				"effect":    v.Effect,
			},
		}

		if campaignFile != "" {
			sr.Locations = []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: campaignFile},
					},
				},
			}
		}

		results = append(results, sr)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           sarifToolName,
						Version:        version.Version,
						InformationURI: sarifInfoURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
