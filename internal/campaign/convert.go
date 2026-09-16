// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConvertFormat specifies the target format.
type ConvertFormat string

const (
	// FormatJSON specifies JSON as the conversion target.
	FormatJSON ConvertFormat = "json"
	// FormatYAML specifies YAML as the conversion target.
	FormatYAML ConvertFormat = "yaml"
	// FormatMarkdown specifies Markdown as the conversion target.
	FormatMarkdown ConvertFormat = "markdown"
	// FormatCSV specifies CSV as the conversion target.
	FormatCSV ConvertFormat = "csv"
)

// ConvertOptions configures conversion behavior.
type ConvertOptions struct {
	Format       ConvertFormat
	Indent       int  // JSON indent spaces (default: 2)
	Compact      bool // JSON: no indent; CSV: no headers
	Normalize    bool // YAML: apply canonical field ordering
	IncludeEmpty bool // include empty/zero-value fields in output
}

// Convert converts a campaign to the specified target format.
func Convert(c *Campaign, opts ConvertOptions) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("convert: nil campaign")
	}

	switch opts.Format {
	case FormatJSON:
		return convertJSON(c, opts)
	case FormatYAML:
		return convertYAML(c, opts)
	case FormatMarkdown:
		return convertMarkdown(c)
	case FormatCSV:
		return convertCSV(c, opts)
	default:
		return nil, fmt.Errorf("convert: unsupported format %q", opts.Format)
	}
}

// ConvertFile reads a campaign from a YAML file and converts it to the target format.
func ConvertFile(path string, opts ConvertOptions) ([]byte, error) {
	c, err := Load(path)
	if err != nil {
		return nil, fmt.Errorf("convert file %q: %w", path, err)
	}
	return Convert(c, opts)
}

// ConvertDir converts all campaigns in a directory, returning a map of
// campaign-name to converted output bytes.
func ConvertDir(dir string, opts ConvertOptions) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("convert dir %q: %w", dir, err)
	}

	results := make(map[string][]byte)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cpath := filepath.Join(dir, e.Name(), "campaign.yaml")
		if _, err := os.Stat(cpath); err != nil {
			continue
		}
		c, err := Load(cpath)
		if err != nil {
			continue
		}
		data, err := Convert(c, opts)
		if err != nil {
			continue
		}
		results[c.Meta.Name] = data
	}
	return results, nil
}

// ParseJSON parses a campaign from JSON format (inverse of JSON export).
func ParseJSON(data []byte) (*Campaign, error) {
	var c Campaign
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing campaign JSON: %w", err)
	}
	return &c, nil
}

// ---------------------------------------------------------------------------
// Internal format converters
// ---------------------------------------------------------------------------

// convertJSON encodes a campaign as JSON.
func convertJSON(c *Campaign, opts ConvertOptions) ([]byte, error) {
	indent := opts.Indent
	if indent <= 0 && !opts.Compact {
		indent = 2
	}

	if opts.Compact {
		data, err := json.Marshal(c)
		if err != nil {
			return nil, fmt.Errorf("encoding campaign JSON: %w", err)
		}
		return data, nil
	}

	data, err := json.MarshalIndent(c, "", strings.Repeat(" ", indent))
	if err != nil {
		return nil, fmt.Errorf("encoding campaign JSON: %w", err)
	}
	// Append a trailing newline for consistency.
	data = append(data, '\n')
	return data, nil
}

// convertYAML formats a campaign as canonical YAML, optionally normalizing it.
func convertYAML(c *Campaign, opts ConvertOptions) ([]byte, error) {
	target := c
	if opts.Normalize {
		target = Normalize(c)
	}
	return Format(target)
}

// convertMarkdown renders a campaign as a Markdown report.
func convertMarkdown(c *Campaign) ([]byte, error) {
	var b strings.Builder

	// Title.
	b.WriteString("# ")
	b.WriteString(c.Meta.Name)
	b.WriteByte('\n')
	b.WriteByte('\n')

	// Meta badges line.
	var badges []string
	if c.Meta.Severity != "" {
		badges = append(badges, fmt.Sprintf("**Severity:** %s", c.Meta.Severity))
	}
	badges = append(badges, fmt.Sprintf("**Stages:** %d", len(c.Stages)))
	techniques := c.UniqueTechniques()
	badges = append(badges, fmt.Sprintf("**Techniques:** %d", len(techniques)))
	tactics := c.UniqueTactics()
	badges = append(badges, fmt.Sprintf("**Tactics:** %d", len(tactics)))
	b.WriteString(strings.Join(badges, " | "))
	b.WriteByte('\n')
	b.WriteByte('\n')

	// Description.
	if c.Meta.Description != "" {
		b.WriteString(c.Meta.Description)
		b.WriteByte('\n')
		b.WriteByte('\n')
	}

	// Adversary and objective.
	if c.Meta.Adversary != "" {
		b.WriteString("**Adversary:** ")
		b.WriteString(c.Meta.Adversary)
		b.WriteByte('\n')
		b.WriteByte('\n')
	}
	if c.Meta.Objective != "" {
		b.WriteString("**Objective:** ")
		b.WriteString(c.Meta.Objective)
		b.WriteByte('\n')
		b.WriteByte('\n')
	}

	// Stages table.
	b.WriteString("## Stages\n\n")
	b.WriteString("| ID | Name | Technique | Tactic | Platform | Exec Type |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, s := range c.Stages {
		platform := strings.Join(s.Platform, ", ")
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
			s.ID, s.Name, s.Technique, s.Tactic, platform, s.Execute.Type))
	}
	b.WriteByte('\n')

	// Variables section.
	if len(c.Variables) > 0 {
		b.WriteString("## Variables\n\n")
		b.WriteString("| Variable | Value |\n")
		b.WriteString("|---|---|\n")
		for k, v := range c.Variables {
			b.WriteString(fmt.Sprintf("| `%s` | `%s` |\n", k, v))
		}
		b.WriteByte('\n')
	}

	// Detection coverage section.
	detections := c.AllDetections()
	if len(detections) > 0 {
		b.WriteString("## Detection Coverage\n\n")

		// Count stages with detections.
		covered := 0
		for _, s := range c.Stages {
			if len(s.Expect.Detections) > 0 {
				covered++
			}
		}
		b.WriteString(fmt.Sprintf("**Coverage:** %d/%d stages (%d%%)\n\n",
			covered, len(c.Stages), coveragePercent(covered, len(c.Stages))))

		b.WriteString("**Detection rules:**\n\n")
		for _, d := range detections {
			b.WriteString(fmt.Sprintf("- %s\n", d))
		}
		b.WriteByte('\n')
	}

	return []byte(b.String()), nil
}

// convertCSV renders campaign stages as CSV rows.
func convertCSV(c *Campaign, opts ConvertOptions) ([]byte, error) {
	var b strings.Builder

	if !opts.Compact {
		b.WriteString("campaign_name,stage_id,stage_name,technique,tactic,platform,exec_type,severity,has_detection,has_cleanup\n")
	}

	for _, s := range c.Stages {
		platform := strings.Join(s.Platform, ";")
		hasDetection := len(s.Expect.Detections) > 0
		hasCleanup := len(s.Execute.Cleanup) > 0

		b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%t,%t\n",
			csvEscape(c.Meta.Name),
			csvEscape(s.ID),
			csvEscape(s.Name),
			csvEscape(s.Technique),
			csvEscape(s.Tactic),
			csvEscape(platform),
			csvEscape(s.Execute.Type),
			csvEscape(c.Meta.Severity),
			hasDetection,
			hasCleanup,
		))
	}

	return []byte(b.String()), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// csvEscape wraps a field in quotes if it contains commas, quotes, or newlines.
// Embedded quotes are doubled per RFC 4180.
func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// coveragePercent computes a percentage, avoiding division by zero.
func coveragePercent(covered, total int) int {
	if total == 0 {
		return 0
	}
	return (covered * 100) / total
}
