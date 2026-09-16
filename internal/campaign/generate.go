// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// GenerateConfig configures campaign generation. A campaign can be built
// from an explicit technique list, a set of tactics (one representative
// technique is selected per tactic), a predefined profile, or any
// combination of the three — resolved techniques are unioned and deduped
// in that order.
type GenerateConfig struct {
	Name        string   // campaign name; defaults to the profile name or "generated-campaign"
	Description string   // campaign description; defaults to a generated summary
	Adversary   string   // defaults to "generated" (or the profile's adversary)
	Techniques  []string // explicit technique IDs, e.g. "AML.T0051", "T1059"
	Tactics     []string // tactic short names to cover
	Severity    string   // critical/high/medium/low; defaults to "medium" (or the profile's severity)
	Profile     string   // predefined profile: "ai-red-team", "apt-simulation", "compliance-check"
	Platform    string   // defaults to "linux"
	StageType   string   // default execute.type for generated stages; defaults to "http"
}

// GenerateResult is the output of Generate.
type GenerateResult struct {
	Campaign       *Campaign
	YAML           string   // canonically-formatted campaign YAML
	TechniquesUsed []string // resolved technique IDs, in the order stages were generated
	TacticsUsed    []string // deduplicated tactics across the generated stages
	StageCount     int
	Warnings       []string // non-fatal notices (e.g. unknown tactic, technique not in registry)
}

// Generate builds a campaign from a GenerateConfig: it resolves the set of
// techniques to cover, converts each into a stage, assembles campaign
// metadata, validates the result, and renders canonical YAML.
func Generate(cfg *GenerateConfig) (*GenerateResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("generate: config is required")
	}
	working := *cfg
	var warnings []string

	var base *GenerateConfig
	if working.Profile != "" {
		base = predefinedProfile(working.Profile)
		if base == nil {
			return nil, fmt.Errorf("generate: unknown profile %q (available: ai-red-team, apt-simulation, compliance-check)", working.Profile)
		}
	}

	techniques, tacticWarnings := resolveTechniques(&working, base)
	warnings = append(warnings, tacticWarnings...)
	if len(techniques) == 0 {
		return nil, fmt.Errorf("generate: no techniques resolved; provide Techniques, Tactics, or a valid Profile")
	}

	name := firstNonEmpty(working.Name, profileField(base, func(g *GenerateConfig) string { return g.Name }), "generated-campaign")
	description := firstNonEmpty(working.Description, profileField(base, func(g *GenerateConfig) string { return g.Description }))
	adversary := firstNonEmpty(working.Adversary, profileField(base, func(g *GenerateConfig) string { return g.Adversary }), "generated")
	severity := firstNonEmpty(working.Severity, profileField(base, func(g *GenerateConfig) string { return g.Severity }), "medium")
	platform := firstNonEmpty(working.Platform, "linux")
	stageType := firstNonEmpty(working.StageType, "http")

	if !validExecTypes[stageType] {
		return nil, fmt.Errorf("generate: invalid stage type %q", stageType)
	}
	if !validPlatforms[platform] {
		return nil, fmt.Errorf("generate: invalid platform %q", platform)
	}
	if !validSeverities[severity] {
		return nil, fmt.Errorf("generate: invalid severity %q", severity)
	}

	stages, stageWarnings := buildStages(techniques, platform, stageType)
	warnings = append(warnings, stageWarnings...)

	now := nowTimestamp()
	tags := []string{"generated"}
	if working.Profile != "" {
		tags = append(tags, working.Profile)
	}

	if description == "" {
		description = fmt.Sprintf("Generated campaign covering %d technique(s)", len(techniques))
	}

	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:        name,
			Adversary:   adversary,
			Description: description,
			Severity:    severity,
			Tags:        tags,
			Created:     now,
			Modified:    now,
		},
		Stages: stages,
	}

	if errs := Validate(c); len(errs) > 0 {
		return nil, fmt.Errorf("generate: generated campaign is invalid: %s", strings.Join(errs, "; "))
	}

	yamlStr, err := GenerateYAML(c)
	if err != nil {
		return nil, fmt.Errorf("generate: %w", err)
	}

	return &GenerateResult{
		Campaign:       c,
		YAML:           yamlStr,
		TechniquesUsed: techniques,
		TacticsUsed:    c.UniqueTactics(),
		StageCount:     len(stages),
		Warnings:       warnings,
	}, nil
}

// GenerateYAML marshals a campaign to canonically-formatted YAML.
func GenerateYAML(c *Campaign) (string, error) {
	data, err := Format(c)
	if err != nil {
		return "", fmt.Errorf("generate yaml: %w", err)
	}
	return string(data), nil
}

// resolveTechniques unions explicit techniques, tactic-derived
// representative techniques, and (when nothing else was given) the
// profile's technique list — in that priority order, deduplicated.
func resolveTechniques(working, base *GenerateConfig) ([]string, []string) {
	var techniques []string
	var warnings []string
	seen := make(map[string]bool)

	add := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		techniques = append(techniques, t)
	}

	for _, t := range working.Techniques {
		add(t)
	}
	for _, tac := range working.Tactics {
		reps := representativeTechniques(tac)
		if len(reps) == 0 {
			warnings = append(warnings, fmt.Sprintf("no known technique found for tactic %q", tac))
			continue
		}
		for _, t := range reps {
			add(t)
		}
	}
	if len(techniques) == 0 && base != nil {
		for _, t := range base.Techniques {
			add(t)
		}
	}

	return techniques, warnings
}

// buildStages converts resolved technique IDs into campaign stages,
// applying the requested platform and execute type and guarding against
// stage ID collisions.
func buildStages(techniques []string, platform, stageType string) ([]Stage, []string) {
	stages := make([]Stage, 0, len(techniques))
	var warnings []string
	idCounts := make(map[string]int)

	for _, t := range techniques {
		name, tactic, known := resolveTechniqueMeta(t)
		if !known {
			warnings = append(warnings, fmt.Sprintf("technique %q not found in the MITRE registry; tactic inferred as %q", t, tactic))
		}

		st := newStage(t, name, tactic, stageType)
		st.Platform = []string{platform}

		baseID := st.ID
		idCounts[baseID]++
		if idCounts[baseID] > 1 {
			st.ID = fmt.Sprintf("%s-%d", baseID, idCounts[baseID])
		}

		stages = append(stages, st)
	}

	return stages, warnings
}

// predefinedProfile returns the built-in GenerateConfig for a named
// profile, or nil if the name isn't recognized.
func predefinedProfile(name string) *GenerateConfig {
	switch name {
	case "ai-red-team":
		return &GenerateConfig{
			Name:        "ai-red-team-simulation",
			Description: "AI red-team simulation covering prompt injection, adversarial data crafting, model inference abuse, and agent exfiltration techniques",
			Adversary:   "AI Red Team",
			Severity:    "high",
			Techniques: []string{
				"AML.T0051", // LLM Prompt Injection
				"AML.T0043", // Craft Adversarial Data
				"AML.T0040", // ML Model Inference API Access
				"AML.T0024", // Exfiltration via ML Inference API
				"AML.T0025", // Exfiltration via Cyber Means
			},
		}
	case "apt-simulation":
		return &GenerateConfig{
			Name:        "apt-simulation",
			Description: "Classic APT kill-chain simulation from scripted execution through defense evasion",
			Adversary:   "Simulated APT",
			Severity:    "high",
			Techniques: []string{
				"T1059", // Command and Scripting Interpreter
				"T1053", // Scheduled Task/Job
				"T1547", // Boot or Logon Autostart Execution
				"T1055", // Process Injection
				"T1027", // Obfuscated Files or Information
			},
		}
	case "compliance-check":
		return &GenerateConfig{
			Name:        "compliance-check",
			Description: "Broad technique coverage sweep for control validation and compliance testing",
			Adversary:   "Compliance Auditor",
			Severity:    "medium",
			Techniques: []string{
				"T1078",     // Valid Accounts
				"T1082",     // System Information Discovery
				"T1083",     // File and Directory Discovery
				"T1057",     // Process Discovery
				"T1016",     // System Network Configuration Discovery
				"T1105",     // Ingress Tool Transfer
				"T1071.001", // Application Layer Protocol: Web Protocols
				"T1560.001", // Archive Collected Data: Archive via Utility
			},
		}
	default:
		return nil
	}
}

// techniqueToStage converts a technique ID into a fully-formed campaign
// stage using http-based simulation defaults on the "linux" platform.
// Generate() further overrides platform/execute-type per its config.
func techniqueToStage(technique string) Stage {
	name, tactic, _ := resolveTechniqueMeta(technique)
	return newStage(technique, name, tactic, "http")
}

// newStage assembles a Stage from a resolved technique/name/tactic triple
// and the requested execute type.
func newStage(technique, name, tactic, execType string) Stage {
	if name == "" {
		name = technique
	}

	id := slugify(technique + " " + name)
	if id == "" {
		id = slugify(technique)
	}
	if id == "" {
		id = "stage"
	}

	return Stage{
		ID:          id,
		Name:        fmt.Sprintf("%s (%s)", name, technique),
		Description: fmt.Sprintf("Simulate %s technique %s", frameworkLabel(technique), technique),
		Technique:   technique,
		Tactic:      tactic,
		Platform:    []string{"linux"},
		Execute:     buildExecute(execType, technique, name),
		Expect: Expect{
			Telemetry: defaultTelemetry(tactic),
		},
	}
}

// buildExecute returns reasonable Execute defaults for a stage type.
func buildExecute(execType, technique, name string) Execute {
	sim := fmt.Sprintf(`echo "[SIM] %s (%s)"`, name, technique)
	e := Execute{Type: execType, Commands: []string{sim}}

	switch execType {
	case "http":
		e.Target = "https://sim.threatecho.local/simulate"
		e.Args = map[string]string{"technique": technique}
	case "file":
		e.Target = fmt.Sprintf("/tmp/threatecho-sim/%s", slugify(technique))
	case "registry":
		e.Target = `HKLM\SOFTWARE\ThreatEchoSim`
	case "service":
		e.Target = "threatecho-sim-svc"
	case "dns":
		e.Target = "sim.threatecho.local"
	case "manual":
		e.Commands = nil
		e.Payload = fmt.Sprintf("Manually perform %s (%s) and record results.", name, technique)
	}

	return e
}

// extraTechniqueTactics supplements the mitre registry for techniques
// referenced by built-in profiles that aren't in its curated subset.
var extraTechniqueTactics = map[string]string{
	"AML.T0024": "exfiltration", // Exfiltration via ML Inference API
	"AML.T0025": "exfiltration", // Exfiltration via Cyber Means
}

// owaspTactics maps OWASP LLM Top 10 entries onto the closest ATLAS tactic
// so generated stages satisfy campaign tactic validation, since OWASP LLM
// doesn't define its own tactic taxonomy.
var owaspTactics = map[string]string{
	"LLM01": "initial-access",       // Prompt Injection
	"LLM02": "exfiltration",         // Sensitive Information Disclosure
	"LLM03": "resource-development", // Supply Chain Vulnerabilities
	"LLM04": "ml-attack-staging",    // Data and Model Poisoning
	"LLM05": "impact",               // Improper Output Handling
	"LLM06": "impact",               // Excessive Agency
	"LLM07": "ml-model-access",      // System Prompt Leakage
	"LLM08": "ml-attack-staging",    // Vector and Embedding Weaknesses
	"LLM09": "impact",               // Misinformation
	"LLM10": "impact",               // Unbounded Consumption
}

// resolveTechniqueMeta resolves a human-readable name and a valid campaign
// tactic for a technique ID across all supported frameworks. known reports
// whether the technique was found in a registry (curated or supplemental);
// when false, name/tactic are still a usable best-effort fallback.
func resolveTechniqueMeta(technique string) (name, tactic string, known bool) {
	switch mitre.ClassifyFramework(technique) {
	case "atlas":
		if t := mitre.LookupATLASTechnique(technique); t != nil {
			return t.Name, t.Tactic, true
		}
		if tac, ok := extraTechniqueTactics[technique]; ok {
			return technique, tac, true
		}
		return technique, "ml-attack-staging", false

	case "attack":
		if t := mitre.LookupTechnique(technique); t != nil {
			return t.Name, t.Tactic, true
		}
		if parent := parentTechnique(technique); parent != "" {
			if t := mitre.LookupTechnique(parent); t != nil {
				return t.Name, t.Tactic, true
			}
		}
		if tac, ok := extraTechniqueTactics[technique]; ok {
			return technique, tac, true
		}
		return technique, "execution", false

	case "owasp":
		if e := mitre.LookupOWASPLLM(technique); e != nil {
			tac := owaspTactics[technique]
			if tac == "" {
				tac = "initial-access"
			}
			return e.Name, tac, true
		}
		return technique, "initial-access", false

	default:
		return technique, "execution", false
	}
}

// frameworkLabel returns a human-readable label for the framework a
// technique ID belongs to.
func frameworkLabel(technique string) string {
	switch mitre.ClassifyFramework(technique) {
	case "atlas":
		return "MITRE ATLAS"
	case "attack":
		return "MITRE ATT&CK"
	case "owasp":
		return "OWASP LLM Top 10"
	default:
		return "unknown-framework"
	}
}

// tacticTelemetry maps tactic short names to representative telemetry
// types expected from a stage exercising that tactic.
var tacticTelemetry = map[string][]string{
	"reconnaissance":       {"network_connection", "dns_query"},
	"resource-development": {"file_create"},
	"initial-access":       {"network_connection", "process_create"},
	"execution":            {"process_create", "script_execution"},
	"persistence":          {"process_create", "registry_modify"},
	"privilege-escalation": {"process_create", "process_access"},
	"defense-evasion":      {"process_create", "file_modify"},
	"credential-access":    {"process_access", "authentication"},
	"discovery":            {"process_create", "command"},
	"lateral-movement":     {"network_connection", "authentication"},
	"collection":           {"file_read", "file_create"},
	"command-and-control":  {"network_connection", "dns_query"},
	"exfiltration":         {"network_connection", "file_read"},
	"impact":               {"file_modify", "process_create"},
	"ml-attack-staging":    {"api_call", "model_inference"},
	"ml-model-access":      {"api_call", "authentication"},
}

// defaultTelemetry returns expected telemetry types for a tactic, falling
// back to a generic default when the tactic isn't in the map.
func defaultTelemetry(tactic string) []string {
	if t, ok := tacticTelemetry[tactic]; ok {
		return copyStrings(t)
	}
	return []string{"process_create"}
}

// representativeTechniques returns a single representative technique ID
// for a tactic short name, preferring ATT&CK entries and falling back to
// ATLAS for AI/ML-specific tactics ATT&CK doesn't cover (e.g.
// reconnaissance, resource-development, ml-attack-staging,
// ml-model-access). Returns nil if the tactic is unknown to both.
func representativeTechniques(tactic string) []string {
	var candidates []string
	for id, t := range mitre.Techniques {
		if t.Tactic == tactic {
			candidates = append(candidates, id)
		}
	}
	if len(candidates) == 0 {
		for id, t := range mitre.ATLASTechniques {
			if t.Tactic == tactic {
				candidates = append(candidates, id)
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Strings(candidates)
	return []string{candidates[0]}
}

// slugify converts a string to a kebab-case identifier: lowercased,
// non-alphanumeric runs collapsed to single hyphens, leading/trailing
// hyphens trimmed.
func slugify(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if b.Len() > 0 && !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// firstNonEmpty returns the first non-empty string among vals.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// profileField reads a string field off a profile GenerateConfig, safely
// handling a nil profile (no profile in use).
func profileField(base *GenerateConfig, get func(*GenerateConfig) string) string {
	if base == nil {
		return ""
	}
	return get(base)
}
