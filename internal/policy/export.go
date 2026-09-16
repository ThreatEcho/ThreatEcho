// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ExportFormat is the output format for a policy export.
type ExportFormat string

const (
	// FormatJSON exports the policy as indented JSON.
	FormatJSON ExportFormat = "json"
	// FormatYAML exports the policy as YAML.
	FormatYAML ExportFormat = "yaml"
	// FormatRego exports the policy as OPA Rego rules.
	FormatRego ExportFormat = "rego"
	// FormatSummary exports the policy as a human-readable summary.
	FormatSummary ExportFormat = "summary"
)

// PolicyExport holds the rendered output and metadata from exporting a policy.
type PolicyExport struct {
	Policy   *Policy      `json:"policy"`
	Format   ExportFormat `json:"format"`
	Rendered string       `json:"rendered"`
	Meta     ExportMeta   `json:"meta"`
}

// ExportMeta holds metadata about the export operation itself.
type ExportMeta struct {
	ExportedAt string `json:"exported_at"`
	ToolName   string `json:"tool_name"`
	Version    string `json:"version"`
}

// ExportPolicy produces a PolicyExport for the given format.
func ExportPolicy(p *Policy, format ExportFormat) (*PolicyExport, error) {
	export := &PolicyExport{
		Policy: p,
		Format: format,
		Meta: ExportMeta{
			ExportedAt: time.Now().UTC().Format(time.RFC3339),
			ToolName:   "threatecho",
			Version:    "v1",
		},
	}

	var rendered string
	var err error

	switch format {
	case FormatJSON:
		data, jerr := json.MarshalIndent(p, "", "  ")
		if jerr != nil {
			return nil, fmt.Errorf("JSON marshal: %w", jerr)
		}
		rendered = string(data)
	case FormatYAML:
		data, yerr := yaml.Marshal(p)
		if yerr != nil {
			return nil, fmt.Errorf("YAML marshal: %w", yerr)
		}
		rendered = string(data)
	case FormatRego:
		rendered, err = ExportToRego(p)
		if err != nil {
			return nil, err
		}
	case FormatSummary:
		rendered = ExportToSummary(p)
	default:
		return nil, fmt.Errorf("unknown export format: %q", format)
	}

	export.Rendered = rendered
	return export, nil
}

// ExportToRego converts a policy's rules to OPA Rego syntax.
func ExportToRego(p *Policy) (string, error) {
	var b strings.Builder

	// Package declaration.
	b.WriteString("package threatecho.policy\n\n")
	b.WriteString("default allow = false\n")

	// Group rules by effect.
	for _, rule := range p.Rules {
		b.WriteString("\n")

		switch rule.Effect {
		case "deny":
			writeRegoDenyRule(&b, rule)
		case "alert":
			writeRegoAlertRule(&b, rule)
		case "allow":
			writeRegoAllowRule(&b, rule)
		}
	}

	return b.String(), nil
}

// writeRegoDenyRule writes a deny rule in Rego syntax.
func writeRegoDenyRule(b *strings.Builder, r Rule) {
	for _, tool := range r.Match.Tools {
		b.WriteString("deny[msg] {\n")
		fmt.Fprintf(b, "    input.tool == %q\n", tool)
		fmt.Fprintf(b, "    msg := \"Rule %s: %s\"\n", r.ID, r.Description)
		b.WriteString("}\n")
	}
	for _, tactic := range r.Match.Tactics {
		b.WriteString("deny[msg] {\n")
		fmt.Fprintf(b, "    input.tactic == %q\n", tactic)
		fmt.Fprintf(b, "    msg := \"Rule %s: %s\"\n", r.ID, r.Description)
		b.WriteString("}\n")
	}
	for _, action := range r.Match.Actions {
		b.WriteString("deny[msg] {\n")
		fmt.Fprintf(b, "    input.action == %q\n", action)
		writeRegoConditions(b, r.Conditions)
		fmt.Fprintf(b, "    msg := \"Rule %s: %s\"\n", r.ID, r.Description)
		b.WriteString("}\n")
	}
	for _, target := range r.Match.Targets {
		b.WriteString("deny[msg] {\n")
		fmt.Fprintf(b, "    glob.match(%q, [\".\", \"/\"], input.target)\n", target)
		fmt.Fprintf(b, "    msg := \"Rule %s: %s\"\n", r.ID, r.Description)
		b.WriteString("}\n")
	}
	// If no specific match dimensions have entries, write a general rule.
	if len(r.Match.Tools) == 0 && len(r.Match.Tactics) == 0 &&
		len(r.Match.Actions) == 0 && len(r.Match.Targets) == 0 {
		b.WriteString("deny[msg] {\n")
		fmt.Fprintf(b, "    msg := \"Rule %s: %s\"\n", r.ID, r.Description)
		b.WriteString("}\n")
	}
}

// writeRegoAlertRule writes an alert rule in Rego syntax.
func writeRegoAlertRule(b *strings.Builder, r Rule) {
	for _, tool := range r.Match.Tools {
		b.WriteString("alert[msg] {\n")
		fmt.Fprintf(b, "    input.tool == %q\n", tool)
		fmt.Fprintf(b, "    msg := \"Rule %s: %s\"\n", r.ID, r.Description)
		b.WriteString("}\n")
	}
	for _, tactic := range r.Match.Tactics {
		b.WriteString("alert[msg] {\n")
		fmt.Fprintf(b, "    input.tactic == %q\n", tactic)
		fmt.Fprintf(b, "    msg := \"Rule %s: %s\"\n", r.ID, r.Description)
		b.WriteString("}\n")
	}
	for _, action := range r.Match.Actions {
		b.WriteString("alert[msg] {\n")
		fmt.Fprintf(b, "    input.action == %q\n", action)
		fmt.Fprintf(b, "    msg := \"Rule %s: %s\"\n", r.ID, r.Description)
		b.WriteString("}\n")
	}
	if len(r.Match.Tools) == 0 && len(r.Match.Tactics) == 0 &&
		len(r.Match.Actions) == 0 && len(r.Match.Targets) == 0 {
		b.WriteString("alert[msg] {\n")
		fmt.Fprintf(b, "    msg := \"Rule %s: %s\"\n", r.ID, r.Description)
		b.WriteString("}\n")
	}
}

// writeRegoAllowRule writes an allow rule in Rego syntax.
func writeRegoAllowRule(b *strings.Builder, r Rule) {
	for _, tool := range r.Match.Tools {
		b.WriteString("allow {\n")
		fmt.Fprintf(b, "    input.tool == %q\n", tool)
		writeRegoConditions(b, r.Conditions)
		b.WriteString("}\n")
	}
	if len(r.Match.Tools) == 0 && len(r.Match.Tactics) == 0 &&
		len(r.Match.Actions) == 0 && len(r.Match.Targets) == 0 {
		b.WriteString("allow {\n")
		writeRegoConditions(b, r.Conditions)
		b.WriteString("}\n")
	}
}

// writeRegoConditions emits Rego condition expressions.
func writeRegoConditions(b *strings.Builder, conds []Condition) {
	for _, c := range conds {
		switch c.Operator {
		case "eq":
			fmt.Fprintf(b, "    input.%s == %q\n", c.Field, c.Value)
		case "ne":
			fmt.Fprintf(b, "    input.%s != %q\n", c.Field, c.Value)
		case "in":
			vals := strings.Split(c.Value, ",")
			trimmed := make([]string, len(vals))
			for i, v := range vals {
				trimmed[i] = fmt.Sprintf("%q", strings.TrimSpace(v))
			}
			fmt.Fprintf(b, "    input.%s == {%s}[_]\n", c.Field, strings.Join(trimmed, ", "))
		case "not_in":
			vals := strings.Split(c.Value, ",")
			trimmed := make([]string, len(vals))
			for i, v := range vals {
				trimmed[i] = fmt.Sprintf("%q", strings.TrimSpace(v))
			}
			fmt.Fprintf(b, "    not input.%s == {%s}[_]\n", c.Field, strings.Join(trimmed, ", "))
		}
	}
}

// ExportToSummary produces a human-readable YAML summary of the policy.
func ExportToSummary(p *Policy) string {
	var b strings.Builder

	b.WriteString("# Policy Summary\n")
	fmt.Fprintf(&b, "name: %s\n", p.Meta.Name)
	if p.Meta.Description != "" {
		fmt.Fprintf(&b, "description: %s\n", strings.TrimSpace(p.Meta.Description))
	}
	fmt.Fprintf(&b, "agent: %s\n", p.Agent.Name)
	if p.Agent.Type != "" {
		fmt.Fprintf(&b, "agent_type: %s\n", p.Agent.Type)
	}

	// Count rules by effect.
	deny, allow, alert := 0, 0, 0
	for _, r := range p.Rules {
		switch r.Effect {
		case "deny":
			deny++
		case "allow":
			allow++
		case "alert":
			alert++
		}
	}

	fmt.Fprintf(&b, "rule_count: %d\n", len(p.Rules))
	fmt.Fprintf(&b, "deny_rules: %d\n", deny)
	fmt.Fprintf(&b, "allow_rules: %d\n", allow)
	fmt.Fprintf(&b, "alert_rules: %d\n", alert)

	b.WriteString("rules:\n")
	for _, r := range p.Rules {
		fmt.Fprintf(&b, "  - id: %s\n", r.ID)
		fmt.Fprintf(&b, "    effect: %s\n", r.Effect)
		fmt.Fprintf(&b, "    priority: %d\n", r.Priority)
		if r.Description != "" {
			fmt.Fprintf(&b, "    description: %s\n", r.Description)
		}
		if len(r.Match.Tools) > 0 {
			fmt.Fprintf(&b, "    tools: [%s]\n", strings.Join(r.Match.Tools, ", "))
		}
		if len(r.Match.Tactics) > 0 {
			fmt.Fprintf(&b, "    tactics: [%s]\n", strings.Join(r.Match.Tactics, ", "))
		}
	}

	return b.String()
}

// FormatExport returns the rendered string from a PolicyExport.
func FormatExport(e *PolicyExport) string {
	return e.Rendered
}
