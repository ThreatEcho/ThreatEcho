// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/ThreatEcho/threatecho/internal/mitre"
	"gopkg.in/yaml.v3"
)

// AtomicTest represents one Atomic Red Team test from YAML.
type AtomicTest struct {
	Name               string               `yaml:"name"`
	GUID               string               `yaml:"auto_generated_guid"`
	Description        string               `yaml:"description"`
	SupportedPlatforms []string             `yaml:"supported_platforms"`
	Executor           AtomicExecutor       `yaml:"executor"`
	InputArguments     map[string]AtomicArg `yaml:"input_arguments"`
	DependencyExecutor *AtomicExecutor      `yaml:"dependency_executor_name,omitempty"`
}

// AtomicExecutor holds execution details.
type AtomicExecutor struct {
	Name           string `yaml:"name"`
	Command        string `yaml:"command"`
	CleanupCommand string `yaml:"cleanup_command"`
	ElevationReq   bool   `yaml:"elevation_required"`
}

// AtomicArg holds an input argument definition.
type AtomicArg struct {
	Description string `yaml:"description"`
	Type        string `yaml:"type"`
	Default     string `yaml:"default"`
}

// AtomicTechnique represents one ART YAML file (one technique, many tests).
type AtomicTechnique struct {
	TechniqueID string       `yaml:"attack_technique"`
	DisplayName string       `yaml:"display_name"`
	Tests       []AtomicTest `yaml:"atomic_tests"`
}

// ImportOptions configures the import.
type ImportOptions struct {
	CampaignName string   // name for the generated campaign
	Adversary    string   // default: "Atomic Red Team"
	Platforms    []string // filter to these platforms only (empty = all)
	MaxTests     int      // limit tests per technique (0 = all)
}

// nonAlphaHyphen matches anything that is not lowercase alphanumeric or hyphen.
var nonAlphaHyphen = regexp.MustCompile(`[^a-z0-9-]`)

// sanitizeStageID converts a test name to a kebab-case stage ID.
// Lowercase, spaces to hyphens, strip non-alphanumeric except hyphens,
// collapse consecutive hyphens, trim leading/trailing hyphens, truncate to 64 chars.
func sanitizeStageID(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = nonAlphaHyphen.ReplaceAllString(s, "")

	// Collapse consecutive hyphens.
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")

	if len(s) > 64 {
		s = s[:64]
		s = strings.TrimRight(s, "-")
	}
	if s == "" {
		s = "stage"
	}
	return s
}

// uniqueStageID returns a stage ID that does not collide with any key in seen.
// It appends -2, -3, etc. if needed, and records the result in seen.
func uniqueStageID(base string, seen map[string]bool) string {
	if !seen[base] {
		seen[base] = true
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if len(candidate) > 64 {
			candidate = candidate[:64]
			candidate = strings.TrimRight(candidate, "-")
		}
		if !seen[candidate] {
			seen[candidate] = true
			return candidate
		}
	}
}

// mapExecutorType maps an ART executor name to a ThreatEcho execute type.
func mapExecutorType(executor string) string {
	switch strings.ToLower(executor) {
	case "powershell", "command_prompt", "sh", "bash":
		return "shell"
	case "manual":
		return "manual"
	default:
		return "shell"
	}
}

// splitCommands splits a multi-line command string into individual non-empty lines.
func splitCommands(cmd string) []string {
	if cmd == "" {
		return nil
	}
	lines := strings.Split(cmd, "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimRightFunc(line, unicode.IsSpace)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// inferTelemetry returns expected telemetry types based on executor name.
func inferTelemetry(executor string) []string {
	switch strings.ToLower(executor) {
	case "powershell":
		return []string{"process_create", "script_block"}
	case "command_prompt", "sh", "bash":
		return []string{"process_create"}
	default:
		return nil
	}
}

// matchesPlatform checks whether a test's supported platforms intersect with the filter.
func matchesPlatform(testPlatforms, filterPlatforms []string) bool {
	if len(filterPlatforms) == 0 {
		return true
	}
	for _, fp := range filterPlatforms {
		for _, tp := range testPlatforms {
			if strings.EqualFold(fp, tp) {
				return true
			}
		}
	}
	return false
}

// resolveTactic looks up the tactic for a technique ID from the mitre registry.
// Returns the tactic short name if found, empty string otherwise.
func resolveTactic(techniqueID string) string {
	t := mitre.LookupTechnique(techniqueID)
	if t != nil {
		return t.Tactic
	}
	// For sub-techniques not in the registry, try the parent technique.
	if idx := strings.Index(techniqueID, "."); idx > 0 {
		parent := techniqueID[:idx]
		if t := mitre.LookupTechnique(parent); t != nil {
			return t.Tactic
		}
	}
	return ""
}

// ImportAtomic converts an AtomicTechnique into a ThreatEcho Campaign.
// Each atomic test becomes one stage.
func ImportAtomic(at *AtomicTechnique, opts ImportOptions) *Campaign {
	if opts.Adversary == "" {
		opts.Adversary = "Atomic Red Team"
	}
	campaignName := opts.CampaignName
	if campaignName == "" {
		campaignName = fmt.Sprintf("ART-%s", at.TechniqueID)
		if at.DisplayName != "" {
			campaignName = fmt.Sprintf("ART-%s-%s", at.TechniqueID, at.DisplayName)
		}
	}

	tactic := resolveTactic(at.TechniqueID)
	now := time.Now().UTC().Format("2006-01-02")

	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:        campaignName,
			Adversary:   opts.Adversary,
			Description: fmt.Sprintf("Imported from Atomic Red Team: %s", at.DisplayName),
			Severity:    "medium",
			Tags:        []string{"atomic-red-team", "imported"},
			References:  []string{fmt.Sprintf("https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/%s/%s.yaml", at.TechniqueID, at.TechniqueID)},
			Created:     now,
			Modified:    now,
		},
	}

	seenIDs := make(map[string]bool)
	imported := 0

	for _, test := range at.Tests {
		// Apply platform filter.
		if !matchesPlatform(test.SupportedPlatforms, opts.Platforms) {
			continue
		}

		// Apply max tests limit.
		if opts.MaxTests > 0 && imported >= opts.MaxTests {
			break
		}

		baseID := sanitizeStageID(test.Name)
		stageID := uniqueStageID(baseID, seenIDs)

		stage := Stage{
			ID:          stageID,
			Name:        test.Name,
			Description: test.Description,
			Technique:   at.TechniqueID,
			Tactic:      tactic,
			Platform:    normalizePlatforms(test.SupportedPlatforms),
			Execute: Execute{
				Type:     mapExecutorType(test.Executor.Name),
				Commands: splitCommands(test.Executor.Command),
				Cleanup:  splitCommands(test.Executor.CleanupCommand),
				Elevated: test.Executor.ElevationReq,
			},
			Expect: Expect{
				Telemetry: inferTelemetry(test.Executor.Name),
			},
		}

		// Map input arguments to campaign variables.
		if len(test.InputArguments) > 0 {
			if c.Variables == nil {
				c.Variables = make(map[string]string)
			}
			for k, arg := range test.InputArguments {
				c.Variables[k] = arg.Default
			}
		}

		c.Stages = append(c.Stages, stage)
		imported++
	}

	return c
}

// normalizePlatforms lowercases platform names for consistency.
func normalizePlatforms(platforms []string) []string {
	if len(platforms) == 0 {
		return nil
	}
	out := make([]string, len(platforms))
	for i, p := range platforms {
		out[i] = strings.ToLower(p)
	}
	return out
}

// ImportAtomicFile reads an ART YAML file and converts it to a Campaign.
func ImportAtomicFile(path string, opts ImportOptions) (*Campaign, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading atomic file %q: %w", path, err)
	}

	var at AtomicTechnique
	if err := yaml.Unmarshal(data, &at); err != nil {
		return nil, fmt.Errorf("parsing atomic YAML %q: %w", path, err)
	}

	if at.TechniqueID == "" {
		return nil, fmt.Errorf("atomic file %q: missing attack_technique field", path)
	}

	return ImportAtomic(&at, opts), nil
}

// ImportAtomicDir reads all ART YAML files in a directory and merges them
// into one Campaign. Files should be named like T1059.001.yaml or similar.
func ImportAtomicDir(dir string, opts ImportOptions) (*Campaign, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading atomic directory %q: %w", dir, err)
	}

	campaignName := opts.CampaignName
	if campaignName == "" {
		campaignName = fmt.Sprintf("ART-import-%s", filepath.Base(dir))
	}
	adversary := opts.Adversary
	if adversary == "" {
		adversary = "Atomic Red Team"
	}

	now := time.Now().UTC().Format("2006-01-02")
	merged := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:        campaignName,
			Adversary:   adversary,
			Description: fmt.Sprintf("Imported from Atomic Red Team directory: %s", filepath.Base(dir)),
			Severity:    "medium",
			Tags:        []string{"atomic-red-team", "imported"},
			Created:     now,
			Modified:    now,
		},
	}

	seenIDs := make(map[string]bool)
	fileCount := 0

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var at AtomicTechnique
		if err := yaml.Unmarshal(data, &at); err != nil {
			continue
		}
		if at.TechniqueID == "" {
			continue
		}

		fileCount++
		tactic := resolveTactic(at.TechniqueID)
		imported := 0

		for _, test := range at.Tests {
			if !matchesPlatform(test.SupportedPlatforms, opts.Platforms) {
				continue
			}
			if opts.MaxTests > 0 && imported >= opts.MaxTests {
				break
			}

			// Prefix stage IDs with technique ID to avoid cross-file collisions.
			baseID := sanitizeStageID(fmt.Sprintf("%s-%s", at.TechniqueID, test.Name))
			stageID := uniqueStageID(baseID, seenIDs)

			stage := Stage{
				ID:          stageID,
				Name:        test.Name,
				Description: test.Description,
				Technique:   at.TechniqueID,
				Tactic:      tactic,
				Platform:    normalizePlatforms(test.SupportedPlatforms),
				Execute: Execute{
					Type:     mapExecutorType(test.Executor.Name),
					Commands: splitCommands(test.Executor.Command),
					Cleanup:  splitCommands(test.Executor.CleanupCommand),
					Elevated: test.Executor.ElevationReq,
				},
				Expect: Expect{
					Telemetry: inferTelemetry(test.Executor.Name),
				},
			}

			if len(test.InputArguments) > 0 {
				if merged.Variables == nil {
					merged.Variables = make(map[string]string)
				}
				for k, arg := range test.InputArguments {
					merged.Variables[k] = arg.Default
				}
			}

			merged.Stages = append(merged.Stages, stage)
			imported++
		}
	}

	if fileCount == 0 {
		return nil, fmt.Errorf("no valid atomic YAML files found in %q", dir)
	}

	return merged, nil
}

// FormatImportSummary produces a human-readable summary of what was imported.
func FormatImportSummary(c *Campaign, source string) string {
	techniques := c.UniqueTechniques()
	tactics := c.UniqueTactics()

	var b strings.Builder
	fmt.Fprintf(&b, "Import Summary\n")
	fmt.Fprintf(&b, "  Source:     %s\n", source)
	fmt.Fprintf(&b, "  Campaign:   %s\n", c.Meta.Name)
	fmt.Fprintf(&b, "  Adversary:  %s\n", c.Meta.Adversary)
	fmt.Fprintf(&b, "  Stages:     %d\n", len(c.Stages))
	fmt.Fprintf(&b, "  Techniques: %d (%s)\n", len(techniques), strings.Join(techniques, ", "))
	fmt.Fprintf(&b, "  Tactics:    %d (%s)\n", len(tactics), strings.Join(tactics, ", "))

	if len(c.Variables) > 0 {
		fmt.Fprintf(&b, "  Variables:  %d\n", len(c.Variables))
	}

	telemetry := c.AllTelemetryTypes()
	if len(telemetry) > 0 {
		fmt.Fprintf(&b, "  Telemetry:  %s\n", strings.Join(telemetry, ", "))
	}

	return b.String()
}
