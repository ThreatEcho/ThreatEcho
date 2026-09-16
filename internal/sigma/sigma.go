// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package sigma generates Sigma detection rule scaffolds from ThreatEcho campaigns.
//
// Sigma (https://sigmahq.io) is the open standard for SIEM detection rules.
// ThreatEcho bridges adversary simulation to detection engineering by generating
// rule scaffolds from campaign expect blocks — one rule per expected detection,
// per stage.
//
// The generated rules are scaffolds, not complete detections. A detection engineer
// reviews and adds specific selection criteria based on their telemetry pipeline.
package sigma

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// Rule represents a Sigma detection rule.
type Rule struct {
	Title       string
	ID          string // deterministic UUID-like hash
	Status      string // experimental
	Level       string // informational, low, medium, high, critical
	Description string
	Author      string
	Date        string
	Modified    string
	References  []string
	Tags        []string
	LogSource   LogSource
	Detection   Detection
	FalsePos    []string
	// Source context — not in the YAML output but useful for grouping.
	Campaign  string
	StageID   string
	Technique string
	Tactic    string
}

// Detection holds the detection section of a Sigma rule.
type Detection struct {
	Selection map[string]interface{}
	Condition string
}

// GenerateOptions configures rule generation.
type GenerateOptions struct {
	Author string // default: "ThreatEcho"
	Status string // default: "experimental"
	Date   string // default: today
}

// Generate produces Sigma rule scaffolds from a campaign.
// It creates one rule per expected detection per stage.
func Generate(c *campaign.Campaign, opts GenerateOptions) []Rule {
	if opts.Author == "" {
		opts.Author = "ThreatEcho"
	}
	if opts.Status == "" {
		opts.Status = "experimental"
	}
	if opts.Date == "" {
		opts.Date = time.Now().Format("2006/01/02")
	}

	var rules []Rule

	for _, s := range c.Stages {
		if len(s.Expect.Detections) == 0 {
			continue
		}

		// Primary logsource — pick from first telemetry type, or default.
		ls := LogSource{Category: "application"}
		if len(s.Expect.Telemetry) > 0 {
			ls = ResolveLogSource(s.Expect.Telemetry[0])
		}

		// Build tags.
		tags := buildTags(s.Technique, s.Tactic)

		// Build references.
		refs := buildReferences(s.Technique)

		// Level from tactic importance.
		level := tacticLevel(s.Tactic)

		for _, det := range s.Expect.Detections {
			ruleID := deterministicID(c.Meta.Name, s.ID, det)
			title := detectionToTitle(det)

			desc := fmt.Sprintf("Detects %s. Stage: %s (%s). Campaign: %s.",
				humanize(det), s.ID, s.Name, c.Meta.Name)
			if s.Description != "" {
				desc = s.Description
			}

			// Build selection based on telemetry.
			selection := buildSelection(s, det)

			r := Rule{
				Title:       title,
				ID:          ruleID,
				Status:      opts.Status,
				Level:       level,
				Description: desc,
				Author:      opts.Author,
				Date:        opts.Date,
				Modified:    opts.Date,
				References:  refs,
				Tags:        tags,
				LogSource:   ls,
				Detection: Detection{
					Selection: selection,
					Condition: "selection",
				},
				FalsePos:  []string{"Legitimate administrative activity"},
				Campaign:  c.Meta.Name,
				StageID:   s.ID,
				Technique: s.Technique,
				Tactic:    s.Tactic,
			}
			rules = append(rules, r)
		}
	}

	return rules
}

// WriteRules writes Sigma rules as YAML to w, separated by "---\n".
func WriteRules(w io.Writer, rules []Rule) error {
	for i, r := range rules {
		if i > 0 {
			fmt.Fprintf(w, "---\n")
		}
		if err := writeRule(w, r); err != nil {
			return err
		}
	}
	return nil
}

// WriteRule writes a single Sigma rule as YAML.
func writeRule(w io.Writer, r Rule) error {
	fmt.Fprintf(w, "title: %s\n", r.Title)
	fmt.Fprintf(w, "id: %s\n", r.ID)
	fmt.Fprintf(w, "status: %s\n", r.Status)
	fmt.Fprintf(w, "level: %s\n", r.Level)
	fmt.Fprintf(w, "description: |\n  %s\n", r.Description)
	fmt.Fprintf(w, "author: %s\n", r.Author)
	fmt.Fprintf(w, "date: %s\n", r.Date)
	fmt.Fprintf(w, "modified: %s\n", r.Modified)

	if len(r.References) > 0 {
		fmt.Fprintf(w, "references:\n")
		for _, ref := range r.References {
			fmt.Fprintf(w, "  - %s\n", ref)
		}
	}

	if len(r.Tags) > 0 {
		fmt.Fprintf(w, "tags:\n")
		for _, tag := range r.Tags {
			fmt.Fprintf(w, "  - %s\n", tag)
		}
	}

	fmt.Fprintf(w, "logsource:\n")
	fmt.Fprintf(w, "  category: %s\n", r.LogSource.Category)
	if r.LogSource.Product != "" {
		fmt.Fprintf(w, "  product: %s\n", r.LogSource.Product)
	}
	if r.LogSource.Service != "" {
		fmt.Fprintf(w, "  service: %s\n", r.LogSource.Service)
	}

	fmt.Fprintf(w, "detection:\n")
	fmt.Fprintf(w, "  selection:\n")
	// Sort keys for deterministic output.
	keys := make([]string, 0, len(r.Detection.Selection))
	for k := range r.Detection.Selection {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := r.Detection.Selection[k]
		switch val := v.(type) {
		case string:
			fmt.Fprintf(w, "    %s: '%s'\n", k, val)
		case []string:
			fmt.Fprintf(w, "    %s:\n", k)
			for _, s := range val {
				fmt.Fprintf(w, "      - '%s'\n", s)
			}
		case int:
			fmt.Fprintf(w, "    %s: %d\n", k, val)
		case []int:
			fmt.Fprintf(w, "    %s:\n", k)
			for _, n := range val {
				fmt.Fprintf(w, "      - %d\n", n)
			}
		default:
			fmt.Fprintf(w, "    %s: '%v'\n", k, val)
		}
	}
	fmt.Fprintf(w, "  condition: %s\n", r.Detection.Condition)

	if len(r.FalsePos) > 0 {
		fmt.Fprintf(w, "falsepositives:\n")
		for _, fp := range r.FalsePos {
			fmt.Fprintf(w, "  - %s\n", fp)
		}
	}

	fmt.Fprintln(w)
	return nil
}

// deterministicID generates a stable, unique ID for a rule based on campaign+stage+detection.
// Format: 8-4-4-4-12 hex (UUID-like).
func deterministicID(campaignName, stageID, detection string) string {
	h := sha256.Sum256([]byte(campaignName + "|" + stageID + "|" + detection))
	hex := fmt.Sprintf("%x", h[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex[0:8], hex[8:12], hex[12:16], hex[16:20], hex[20:32])
}

// detectionToTitle converts a snake_case detection name to a human-readable title.
func detectionToTitle(det string) string {
	words := strings.Split(det, "_")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// humanize converts a snake_case string to lowercase with spaces.
func humanize(s string) string {
	return strings.ReplaceAll(s, "_", " ")
}

// buildTags generates Sigma tags from technique and tactic.
func buildTags(technique, tactic string) []string {
	var tags []string

	prefix := frameworkTagPrefix(technique)

	if tactic != "" {
		tags = append(tags, prefix+strings.ReplaceAll(tactic, "-", "_"))
	}

	if technique != "" {
		tags = append(tags, prefix+strings.ToLower(technique))
	}

	return tags
}

// frameworkTagPrefix returns the Sigma tag namespace for a technique ID.
func frameworkTagPrefix(technique string) string {
	upper := strings.ToUpper(technique)
	switch {
	case strings.HasPrefix(upper, "AML"):
		return "atlas."
	case strings.HasPrefix(upper, "LLM"):
		return "owasp."
	default:
		return "attack."
	}
}

// buildReferences generates reference URLs for the technique.
func buildReferences(technique string) []string {
	var refs []string
	fw := mitre.ClassifyFramework(technique)

	switch fw {
	case "attack":
		// Sub-technique: T1059.001 → T1059/001
		ref := strings.ReplaceAll(technique, ".", "/")
		refs = append(refs, "https://attack.mitre.org/techniques/"+ref+"/")
	case "atlas":
		refs = append(refs, "https://atlas.mitre.org/techniques/"+technique)
	case "owasp":
		refs = append(refs, "https://genai.owasp.org/llmrisk/"+strings.ToUpper(technique))
	}

	return refs
}

// buildSelection creates the detection selection based on telemetry, technique,
// and stage context. When a technique-specific detection signature is available
// in the detections registry, it produces real Sigma selection criteria. For
// unknown techniques, it falls back to generic telemetry-aware scaffolding.
func buildSelection(s campaign.Stage, detection string) map[string]interface{} {
	// Look up technique-specific detection.
	if td := LookupTechniqueDetection(s.Technique); td != nil {
		sel := buildTechniqueSelection(td, s.Expect.Telemetry)
		if len(sel) > 0 {
			return sel
		}
	}

	// Fallback: generic telemetry-aware scaffold for unknown techniques.
	return buildGenericSelection(s)
}

// buildGenericSelection produces scaffold selection criteria based on
// the stage's telemetry types and execution context.
func buildGenericSelection(s campaign.Stage) map[string]interface{} {
	sel := make(map[string]interface{})

	if len(s.Expect.Telemetry) > 0 {
		ls := ResolveLogSource(s.Expect.Telemetry[0])
		switch ls.Category {
		case "process_creation", "create_remote_thread", "process_termination":
			sel["Image|endswith"] = "EDIT_executable_path_pattern"
			if s.Execute.Type == "shell" && len(s.Execute.Commands) > 0 {
				sel["CommandLine|contains"] = "EDIT_command_line_pattern"
			}
		case "network_connection":
			if s.Execute.Target != "" {
				sel["DestinationHostname|contains"] = s.Execute.Target
			} else {
				sel["DestinationPort"] = "EDIT_destination_port"
			}
		case "file_event", "file_change", "file_access":
			sel["TargetFilename|contains"] = "EDIT_file_path_pattern"
		case "registry_set", "registry_add", "registry_event":
			sel["TargetObject|contains"] = "EDIT_registry_key_pattern"
		case "dns_query":
			sel["QueryName|contains"] = "EDIT_domain_pattern"
		case "authentication":
			sel["LogonType"] = "EDIT_logon_type"
		case "application":
			sel["EventType"] = "EDIT_application_event_type"
		default:
			sel["EventType"] = "EDIT_event_selection_criteria"
		}
	}

	if len(sel) == 0 {
		sel["EventType"] = "EDIT_selection_criteria"
	}

	return sel
}

// tacticLevel maps MITRE tactic to Sigma severity level.
func tacticLevel(tactic string) string {
	switch tactic {
	case "initial-access", "execution", "exfiltration", "impact":
		return "high"
	case "credential-access", "lateral-movement", "privilege-escalation":
		return "high"
	case "persistence", "defense-evasion", "command-and-control":
		return "medium"
	case "discovery", "collection", "reconnaissance", "resource-development":
		return "medium"
	// ATLAS tactics.
	case "ml-attack-staging", "ml-model-access":
		return "high"
	default:
		return "medium"
	}
}
