// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/mitre"
)

var (
	attackPattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`) // MITRE ATT&CK: T1566, T1566.001
	atlasPattern  = regexp.MustCompile(`^AML\.T\d{4}$`)      // MITRE ATLAS: AML.T0051
	owaspPattern  = regexp.MustCompile(`^LLM\d{2}$`)         // OWASP LLM Top 10: LLM01
)

// validTechniqueID checks if the technique matches any supported framework format.
func validTechniqueID(id string) bool {
	return attackPattern.MatchString(id) || atlasPattern.MatchString(id) || owaspPattern.MatchString(id)
}

var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
}

var validFailureModes = map[string]bool{
	"abort":    true,
	"skip":     true,
	"continue": true,
	"":         true,
}

var validExecTypes = map[string]bool{
	"shell":      true,
	"powershell": true,
	"http":       true,
	"file":       true,
	"registry":   true,
	"service":    true,
	"process":    true,
	"dns":        true,
	"manual":     true,
}

var validPlatforms = map[string]bool{
	"windows": true,
	"linux":   true,
	"macos":   true,
}

// Validate checks a campaign for structural and semantic errors.
// Returns a slice of issues; empty means valid.
func Validate(c *Campaign) []string {
	var errs []string

	// Top-level fields.
	if c.APIVersion == "" {
		errs = append(errs, "missing api_version")
	}
	if c.Kind == "" {
		errs = append(errs, "missing kind")
	} else if c.Kind != "Campaign" {
		errs = append(errs, fmt.Sprintf("kind must be \"Campaign\", got %q", c.Kind))
	}

	// Meta.
	if c.Meta.Name == "" {
		errs = append(errs, "meta.name is required")
	}
	if c.Meta.Adversary == "" {
		errs = append(errs, "meta.adversary is required")
	}
	if c.Meta.Severity != "" && !validSeverities[c.Meta.Severity] {
		errs = append(errs, fmt.Sprintf("meta.severity %q is not valid (use critical/high/medium/low/info)", c.Meta.Severity))
	}

	// Stages.
	if len(c.Stages) == 0 {
		errs = append(errs, "campaign must have at least one stage")
		return errs
	}

	ids := make(map[string]int) // id → index
	for i, s := range c.Stages {
		prefix := fmt.Sprintf("stages[%d] (%s)", i, s.ID)

		if s.ID == "" {
			errs = append(errs, fmt.Sprintf("stages[%d]: id is required", i))
			continue
		}
		if prev, dup := ids[s.ID]; dup {
			errs = append(errs, fmt.Sprintf("%s: duplicate id (first at stages[%d])", prefix, prev))
		}
		ids[s.ID] = i

		if s.Name == "" {
			errs = append(errs, fmt.Sprintf("%s: name is required", prefix))
		}
		if s.Technique == "" {
			errs = append(errs, fmt.Sprintf("%s: technique is required", prefix))
		} else if !validTechniqueID(s.Technique) {
			errs = append(errs, fmt.Sprintf("%s: technique %q doesn't match any supported format (ATT&CK: Txxxx[.xxx], ATLAS: AML.Txxxx, OWASP: LLMxx)", prefix, s.Technique))
		}
		if s.Tactic == "" {
			errs = append(errs, fmt.Sprintf("%s: tactic is required", prefix))
		} else if !mitre.ValidTactic(s.Tactic) && !mitre.ValidATLASTactic(s.Tactic) {
			allTactics := append(mitre.TacticShorts(), mitre.ATLASTacticShorts()...)
			errs = append(errs, fmt.Sprintf("%s: tactic %q is not valid (valid: %s)", prefix, s.Tactic, strings.Join(allTactics, ", ")))
		}

		if s.Execute.Type == "" {
			errs = append(errs, fmt.Sprintf("%s: execute.type is required", prefix))
		} else if !validExecTypes[s.Execute.Type] {
			errs = append(errs, fmt.Sprintf("%s: execute.type %q is not valid", prefix, s.Execute.Type))
		}

		if !validFailureModes[s.OnFailure] {
			errs = append(errs, fmt.Sprintf("%s: on_failure %q is not valid (use abort/skip/continue)", prefix, s.OnFailure))
		}

		for _, p := range s.Platform {
			if !validPlatforms[p] {
				errs = append(errs, fmt.Sprintf("%s: platform %q is not valid (use windows/linux/macos)", prefix, p))
			}
		}
	}

	// Validate cross-references (depends_on, on_success).
	for i, s := range c.Stages {
		prefix := fmt.Sprintf("stages[%d] (%s)", i, s.ID)
		for _, dep := range s.DependsOn {
			if _, ok := ids[dep]; !ok {
				errs = append(errs, fmt.Sprintf("%s: depends_on references unknown stage %q", prefix, dep))
			}
		}
		if s.OnSuccess != "" {
			if _, ok := ids[s.OnSuccess]; !ok {
				errs = append(errs, fmt.Sprintf("%s: on_success references unknown stage %q", prefix, s.OnSuccess))
			}
		}
	}

	// Check for cycles in the dependency graph.
	if cycle := detectCycle(c.Stages); cycle != "" {
		errs = append(errs, fmt.Sprintf("dependency cycle detected: %s", cycle))
	}

	return errs
}
