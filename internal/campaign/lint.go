// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/mitre"
	"github.com/ThreatEcho/threatecho/internal/telemetry"
)

// LintResult holds the output of a campaign quality check.
type LintResult struct {
	Campaign string
	Warnings []string
	Info     []string
}

// Lint checks a campaign for quality issues beyond structural validation.
// Unlike Validate(), Lint returns warnings and informational notes —
// not errors that prevent execution.
//
// Checks performed:
//   - Technique IDs not found in the registry (may be valid but not yet indexed)
//   - Stages with no expected telemetry (limits gap analysis)
//   - Stages with telemetry but no detections (will flag as detection gaps)
//   - Shell stages with empty command lists
//   - Stages referencing tactics from a different framework than their technique
//   - Missing descriptions/objectives in campaign metadata
func Lint(c *Campaign) *LintResult {
	lr := &LintResult{Campaign: c.Meta.Name}

	// Meta quality.
	if c.Meta.Description == "" {
		lr.Info = append(lr.Info, "meta.description is empty — add a campaign description for documentation")
	}
	if c.Meta.Objective == "" {
		lr.Info = append(lr.Info, "meta.objective is empty — add an objective for reports")
	}
	if c.Meta.MitreVersion == "" {
		lr.Info = append(lr.Info, "meta.mitre_version is not set — pin the MITRE version for reproducibility")
	}

	for i, s := range c.Stages {
		prefix := fmt.Sprintf("stages[%d] (%s)", i, s.ID)

		// Technique exists in registry.
		if s.Technique != "" && validTechniqueID(s.Technique) {
			if !mitre.ValidTechniqueExists(s.Technique) {
				lr.Warnings = append(lr.Warnings,
					fmt.Sprintf("%s: technique %q not found in registry (may be valid but not yet indexed)", prefix, s.Technique))
			}
		}

		// Framework/tactic consistency.
		if s.Technique != "" && s.Tactic != "" {
			framework := mitre.ClassifyFramework(s.Technique)
			switch framework {
			case "attack":
				if !mitre.ValidTactic(s.Tactic) && mitre.ValidATLASTactic(s.Tactic) {
					lr.Warnings = append(lr.Warnings,
						fmt.Sprintf("%s: ATT&CK technique %s used with ATLAS tactic %q", prefix, s.Technique, s.Tactic))
				}
			case "atlas":
				if !mitre.ValidATLASTactic(s.Tactic) && mitre.ValidTactic(s.Tactic) {
					lr.Warnings = append(lr.Warnings,
						fmt.Sprintf("%s: ATLAS technique %s used with ATT&CK tactic %q", prefix, s.Technique, s.Tactic))
				}
			}
		}

		// Telemetry gaps.
		if len(s.Expect.Telemetry) == 0 {
			lr.Warnings = append(lr.Warnings,
				fmt.Sprintf("%s: no expected telemetry — gap analysis will be limited", prefix))
		}

		// Detection gaps (informational — will show in gap analysis).
		if len(s.Expect.Detections) == 0 && len(s.Expect.Telemetry) > 0 {
			lr.Info = append(lr.Info,
				fmt.Sprintf("%s: telemetry defined but no expected detections — will flag as detection gap", prefix))
		}

		// Empty shell commands.
		if s.Execute.Type == "shell" && len(s.Execute.Commands) == 0 {
			lr.Warnings = append(lr.Warnings,
				fmt.Sprintf("%s: shell stage with no commands", prefix))
		}

		// HTTP stages without target.
		if s.Execute.Type == "http" && s.Execute.Target == "" {
			lr.Warnings = append(lr.Warnings,
				fmt.Sprintf("%s: http stage with no target URL", prefix))
		}

		// Telemetry type validation against registry.
		for _, t := range s.Expect.Telemetry {
			if !telemetry.Valid(t) {
				suggestions := telemetry.Suggest(t)
				if len(suggestions) > 0 {
					names := make([]string, len(suggestions))
					for j, s := range suggestions {
						names[j] = string(s)
					}
					lr.Warnings = append(lr.Warnings,
						fmt.Sprintf("%s: unrecognized telemetry type %q — did you mean: %s?",
							prefix, t, strings.Join(names, ", ")))
				} else {
					lr.Warnings = append(lr.Warnings,
						fmt.Sprintf("%s: unrecognized telemetry type %q — see telemetry registry for valid types",
							prefix, t))
				}
			}
		}
	}

	return lr
}

// HasIssues returns true if there are any warnings.
func (lr *LintResult) HasIssues() bool {
	return len(lr.Warnings) > 0
}

// Total returns the total number of warnings + info.
func (lr *LintResult) Total() int {
	return len(lr.Warnings) + len(lr.Info)
}
