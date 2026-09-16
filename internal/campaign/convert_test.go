// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// convertTestCampaign returns a rich campaign for conversion tests.
func convertTestCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:         "convert-test",
			Adversary:    "ConvertActor",
			Description:  "Campaign for conversion tests",
			Objective:    "Validate conversion engine",
			MitreVersion: "15.1",
			Severity:     "high",
			Tags:         []string{"test", "convert"},
			Authors:      []string{"Author1"},
			References:   []string{"https://example.com"},
			Created:      "2026-01-01",
			Modified:     "2026-06-15",
		},
		Variables: map[string]string{
			"target":   "10.0.0.1",
			"username": "admin",
		},
		Stages: []Stage{
			{
				ID:          "recon",
				Name:        "Network Scan",
				Description: "Scan the network",
				Technique:   "T1016",
				Tactic:      "discovery",
				Platform:    []string{"linux", "windows"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{"nmap -sS target"},
					Cleanup:  []string{"rm /tmp/scan.log"},
					Elevated: true,
				},
				Expect: Expect{
					Telemetry:  []string{"process_create"},
					Detections: []string{"scan_detected"},
				},
				OnSuccess: "access",
				OnFailure: "abort",
				Timeout:   Duration{30 * time.Second},
				Delay:     Duration{5 * time.Second},
			},
			{
				ID:        "access",
				Name:      "Initial Access",
				Technique: "T1190",
				Tactic:    "initial-access",
				DependsOn: []string{"recon"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{"exploit target"},
				},
				Expect: Expect{
					Telemetry:  []string{"network_connection"},
					Detections: []string{"exploit_attempt"},
				},
				OnFailure: "abort",
			},
		},
	}
}

// emptyCampaign returns a campaign with no stages.
func emptyCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "empty",
			Adversary: "None",
		},
	}
}

// ---------------------------------------------------------------------------
// JSON conversion tests
// ---------------------------------------------------------------------------

func TestConvert_JSON_Default(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatJSON})
	if err != nil {
		t.Fatalf("Convert JSON error: %v", err)
	}

	// Should be valid JSON.
	if !json.Valid(data) {
		t.Fatal("output is not valid JSON")
	}

	// Should be indented (multi-line).
	if !strings.Contains(string(data), "\n") {
		t.Error("default JSON should be indented (multi-line)")
	}

	// Trailing newline.
	if data[len(data)-1] != '\n' {
		t.Error("indented JSON should end with a newline")
	}
}

func TestConvert_JSON_CustomIndent(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatJSON, Indent: 4})
	if err != nil {
		t.Fatalf("Convert JSON error: %v", err)
	}

	// Should contain 4-space indentation.
	if !strings.Contains(string(data), "    ") {
		t.Error("expected 4-space indentation")
	}
}

func TestConvert_JSON_Compact(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatJSON, Compact: true})
	if err != nil {
		t.Fatalf("Convert JSON compact error: %v", err)
	}

	// Compact JSON is a single line (no newlines in the body).
	if strings.Count(string(data), "\n") > 0 {
		t.Error("compact JSON should be a single line")
	}

	if !json.Valid(data) {
		t.Fatal("compact output is not valid JSON")
	}
}

func TestConvert_JSON_Roundtrip(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatJSON})
	if err != nil {
		t.Fatalf("Convert JSON error: %v", err)
	}

	c2, err := ParseJSON(data)
	if err != nil {
		t.Fatalf("ParseJSON error: %v", err)
	}

	if c2.Meta.Name != c.Meta.Name {
		t.Errorf("name = %q, want %q", c2.Meta.Name, c.Meta.Name)
	}
	if c2.Meta.Severity != c.Meta.Severity {
		t.Errorf("severity = %q, want %q", c2.Meta.Severity, c.Meta.Severity)
	}
	if c2.APIVersion != c.APIVersion {
		t.Errorf("api_version = %q, want %q", c2.APIVersion, c.APIVersion)
	}
	if len(c2.Stages) != len(c.Stages) {
		t.Fatalf("stages count = %d, want %d", len(c2.Stages), len(c.Stages))
	}
	if c2.Stages[0].ID != c.Stages[0].ID {
		t.Errorf("stage[0].ID = %q, want %q", c2.Stages[0].ID, c.Stages[0].ID)
	}
	if c2.Stages[0].Technique != c.Stages[0].Technique {
		t.Errorf("stage[0].technique = %q, want %q", c2.Stages[0].Technique, c.Stages[0].Technique)
	}
	if c2.Stages[0].Execute.Type != c.Stages[0].Execute.Type {
		t.Errorf("stage[0].execute.type = %q, want %q", c2.Stages[0].Execute.Type, c.Stages[0].Execute.Type)
	}
	if len(c2.Variables) != len(c.Variables) {
		t.Errorf("variables count = %d, want %d", len(c2.Variables), len(c.Variables))
	}
}

func TestConvert_JSON_EmptyCampaign(t *testing.T) {
	c := emptyCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatJSON})
	if err != nil {
		t.Fatalf("Convert JSON error: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("empty campaign JSON is not valid")
	}

	c2, err := ParseJSON(data)
	if err != nil {
		t.Fatalf("ParseJSON error: %v", err)
	}
	if c2.Meta.Name != "empty" {
		t.Errorf("name = %q, want %q", c2.Meta.Name, "empty")
	}
	if len(c2.Stages) != 0 {
		t.Errorf("stages = %d, want 0", len(c2.Stages))
	}
}

// ---------------------------------------------------------------------------
// ParseJSON tests
// ---------------------------------------------------------------------------

func TestParseJSON_Valid(t *testing.T) {
	input := `{"APIVersion":"v1","Kind":"Campaign","Meta":{"Name":"json-test","Adversary":"A"},"Stages":[]}`
	c, err := ParseJSON([]byte(input))
	if err != nil {
		t.Fatalf("ParseJSON error: %v", err)
	}
	if c.Meta.Name != "json-test" {
		t.Errorf("name = %q, want json-test", c.Meta.Name)
	}
}

func TestParseJSON_Invalid(t *testing.T) {
	_, err := ParseJSON([]byte(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// YAML conversion tests
// ---------------------------------------------------------------------------

func TestConvert_YAML_Plain(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatYAML})
	if err != nil {
		t.Fatalf("Convert YAML error: %v", err)
	}

	if !strings.Contains(string(data), "name: convert-test") {
		t.Error("YAML output missing campaign name")
	}
	if !strings.Contains(string(data), "technique: T1016") {
		t.Error("YAML output missing technique")
	}
}

func TestConvert_YAML_Normalized(t *testing.T) {
	c := convertTestCampaign()
	// Tags are already in order, add unsorted ones.
	c.Meta.Tags = []string{"zebra", "alpha"}
	c.Stages[0].Platform = []string{"windows", "linux"}

	data, err := Convert(c, ConvertOptions{Format: FormatYAML, Normalize: true})
	if err != nil {
		t.Fatalf("Convert YAML normalized error: %v", err)
	}

	s := string(data)

	// Tags should be sorted after normalization.
	alphaPos := strings.Index(s, "alpha")
	zebraPos := strings.Index(s, "zebra")
	if alphaPos < 0 || zebraPos < 0 {
		t.Fatal("tags not found in normalized output")
	}
	if alphaPos >= zebraPos {
		t.Errorf("expected alpha before zebra in normalized tags, alpha@%d, zebra@%d", alphaPos, zebraPos)
	}

	// Platform should be sorted.
	linuxPos := strings.Index(s, "linux")
	windowsPos := strings.Index(s, "windows")
	if linuxPos < 0 || windowsPos < 0 {
		t.Fatal("platforms not found in normalized output")
	}
	if linuxPos >= windowsPos {
		t.Errorf("expected linux before windows in normalized platform, linux@%d, windows@%d", linuxPos, windowsPos)
	}
}

func TestConvert_YAML_DoesNotMutateOriginal(t *testing.T) {
	c := convertTestCampaign()
	c.Meta.Tags = []string{"zebra", "alpha"}
	origTags := make([]string, len(c.Meta.Tags))
	copy(origTags, c.Meta.Tags)

	_, err := Convert(c, ConvertOptions{Format: FormatYAML, Normalize: true})
	if err != nil {
		t.Fatalf("Convert error: %v", err)
	}

	// Original tags should be unchanged.
	for i, v := range c.Meta.Tags {
		if v != origTags[i] {
			t.Errorf("Normalize mutated original tags[%d]: %q -> %q", i, origTags[i], v)
		}
	}
}

// ---------------------------------------------------------------------------
// Markdown conversion tests
// ---------------------------------------------------------------------------

func TestConvert_Markdown_Title(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatMarkdown})
	if err != nil {
		t.Fatalf("Convert Markdown error: %v", err)
	}

	s := string(data)
	if !strings.HasPrefix(s, "# convert-test\n") {
		t.Error("Markdown should start with campaign name as H1")
	}
}

func TestConvert_Markdown_Badges(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatMarkdown})
	if err != nil {
		t.Fatalf("Convert Markdown error: %v", err)
	}

	s := string(data)
	if !strings.Contains(s, "**Severity:** high") {
		t.Error("Markdown should contain severity badge")
	}
	if !strings.Contains(s, "**Stages:** 2") {
		t.Error("Markdown should contain stages count badge")
	}
	if !strings.Contains(s, "**Techniques:** 2") {
		t.Error("Markdown should contain techniques count badge")
	}
	if !strings.Contains(s, "**Tactics:** 2") {
		t.Error("Markdown should contain tactics count badge")
	}
}

func TestConvert_Markdown_StagesTable(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatMarkdown})
	if err != nil {
		t.Fatalf("Convert Markdown error: %v", err)
	}

	s := string(data)
	if !strings.Contains(s, "## Stages") {
		t.Error("Markdown should contain Stages section")
	}
	// Check table headers.
	if !strings.Contains(s, "| ID | Name | Technique | Tactic | Platform | Exec Type |") {
		t.Error("Markdown should contain stages table header")
	}
	// Check first stage row.
	if !strings.Contains(s, "| recon | Network Scan | T1016 | discovery |") {
		t.Error("Markdown missing recon stage row")
	}
	if !strings.Contains(s, "| access | Initial Access | T1190 | initial-access |") {
		t.Error("Markdown missing access stage row")
	}
}

func TestConvert_Markdown_Variables(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatMarkdown})
	if err != nil {
		t.Fatalf("Convert Markdown error: %v", err)
	}

	s := string(data)
	if !strings.Contains(s, "## Variables") {
		t.Error("Markdown should contain Variables section")
	}
	if !strings.Contains(s, "`target`") {
		t.Error("Markdown should contain target variable")
	}
}

func TestConvert_Markdown_DetectionCoverage(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatMarkdown})
	if err != nil {
		t.Fatalf("Convert Markdown error: %v", err)
	}

	s := string(data)
	if !strings.Contains(s, "## Detection Coverage") {
		t.Error("Markdown should contain Detection Coverage section")
	}
	if !strings.Contains(s, "**Coverage:** 2/2 stages (100%)") {
		t.Error("Markdown should report 100% detection coverage for test campaign")
	}
	if !strings.Contains(s, "- scan_detected") {
		t.Error("Markdown should list scan_detected detection rule")
	}
	if !strings.Contains(s, "- exploit_attempt") {
		t.Error("Markdown should list exploit_attempt detection rule")
	}
}

func TestConvert_Markdown_EmptyCampaign(t *testing.T) {
	c := emptyCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatMarkdown})
	if err != nil {
		t.Fatalf("Convert Markdown error: %v", err)
	}

	s := string(data)
	if !strings.HasPrefix(s, "# empty\n") {
		t.Error("Markdown should have campaign name as H1")
	}
	// No detection coverage section for empty campaign.
	if strings.Contains(s, "## Detection Coverage") {
		t.Error("Markdown should not contain Detection Coverage for campaigns with no detections")
	}
	// No variables section.
	if strings.Contains(s, "## Variables") {
		t.Error("Markdown should not contain Variables section for empty campaign")
	}
}

func TestConvert_Markdown_Adversary(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatMarkdown})
	if err != nil {
		t.Fatalf("Convert Markdown error: %v", err)
	}

	s := string(data)
	if !strings.Contains(s, "**Adversary:** ConvertActor") {
		t.Error("Markdown should contain adversary")
	}
	if !strings.Contains(s, "**Objective:** Validate conversion engine") {
		t.Error("Markdown should contain objective")
	}
}

// ---------------------------------------------------------------------------
// CSV conversion tests
// ---------------------------------------------------------------------------

func TestConvert_CSV_WithHeaders(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatCSV})
	if err != nil {
		t.Fatalf("Convert CSV error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// Header + 2 stage rows.
	if len(lines) != 3 {
		t.Fatalf("CSV lines = %d, want 3 (header + 2 rows)", len(lines))
	}

	// Check header.
	expectedHeader := "campaign_name,stage_id,stage_name,technique,tactic,platform,exec_type,severity,has_detection,has_cleanup"
	if lines[0] != expectedHeader {
		t.Errorf("CSV header = %q, want %q", lines[0], expectedHeader)
	}

	// Check first data row contains expected values.
	if !strings.Contains(lines[1], "convert-test") {
		t.Error("CSV row 1 should contain campaign name")
	}
	if !strings.Contains(lines[1], "recon") {
		t.Error("CSV row 1 should contain stage ID")
	}
	if !strings.Contains(lines[1], "T1016") {
		t.Error("CSV row 1 should contain technique")
	}
	if !strings.Contains(lines[1], "true") {
		t.Error("CSV row 1 should have has_detection=true")
	}
}

func TestConvert_CSV_Compact(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatCSV, Compact: true})
	if err != nil {
		t.Fatalf("Convert CSV compact error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// No header — just 2 stage rows.
	if len(lines) != 2 {
		t.Fatalf("CSV compact lines = %d, want 2 (no header)", len(lines))
	}

	// First line should be data, not header.
	if strings.HasPrefix(lines[0], "campaign_name") {
		t.Error("compact CSV should not have a header row")
	}
}

func TestConvert_CSV_EmptyCampaign(t *testing.T) {
	c := emptyCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatCSV})
	if err != nil {
		t.Fatalf("Convert CSV error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// Header only, no data rows.
	if len(lines) != 1 {
		t.Fatalf("empty CSV lines = %d, want 1 (header only)", len(lines))
	}
}

func TestConvert_CSV_EscapeCommas(t *testing.T) {
	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "campaign, with commas",
			Adversary: "Actor",
			Severity:  "high",
		},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Stage \"quoted\"",
				Technique: "T1016",
				Tactic:    "discovery",
				Execute:   Execute{Type: "shell"},
			},
		},
	}

	data, err := Convert(c, ConvertOptions{Format: FormatCSV})
	if err != nil {
		t.Fatalf("Convert CSV error: %v", err)
	}

	s := string(data)
	// Campaign name with comma should be quoted.
	if !strings.Contains(s, `"campaign, with commas"`) {
		t.Error("CSV should quote fields containing commas")
	}
	// Stage name with quotes should be escaped.
	if !strings.Contains(s, `"Stage ""quoted"""`) {
		t.Error("CSV should double-quote fields containing quotes")
	}
}

func TestConvert_CSV_HasCleanup(t *testing.T) {
	c := convertTestCampaign()
	data, err := Convert(c, ConvertOptions{Format: FormatCSV})
	if err != nil {
		t.Fatalf("Convert CSV error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// First stage has cleanup.
	fields1 := strings.Split(lines[1], ",")
	lastField1 := fields1[len(fields1)-1]
	if lastField1 != "true" {
		t.Errorf("stage 1 has_cleanup = %q, want true", lastField1)
	}
	// Second stage has no cleanup.
	fields2 := strings.Split(lines[2], ",")
	lastField2 := fields2[len(fields2)-1]
	if lastField2 != "false" {
		t.Errorf("stage 2 has_cleanup = %q, want false", lastField2)
	}
}

// ---------------------------------------------------------------------------
// ConvertFile tests
// ---------------------------------------------------------------------------

func TestConvertFile_JSON(t *testing.T) {
	data, err := ConvertFile("testdata/valid-campaign", ConvertOptions{Format: FormatJSON})
	if err != nil {
		t.Fatalf("ConvertFile error: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("ConvertFile JSON output is not valid JSON")
	}

	c, err := ParseJSON(data)
	if err != nil {
		t.Fatalf("ParseJSON error: %v", err)
	}
	if c.Meta.Name != "test-campaign" {
		t.Errorf("name = %q, want test-campaign", c.Meta.Name)
	}
}

func TestConvertFile_MissingFile(t *testing.T) {
	_, err := ConvertFile("/nonexistent/path/campaign.yaml", ConvertOptions{Format: FormatJSON})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// ConvertDir tests
// ---------------------------------------------------------------------------

func TestConvertDir_JSON(t *testing.T) {
	// Create a temp directory structure with campaign subdirectories.
	root := t.TempDir()

	// Create campaign-a.
	dirA := filepath.Join(root, "campaign-a")
	if err := os.MkdirAll(dirA, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	yamlA := `api_version: v1
kind: Campaign
meta:
  name: alpha
  adversary: ActorA
  severity: high
stages:
  - id: s1
    name: Step 1
    technique: T1016
    tactic: discovery
    execute:
      type: shell
`
	if err := os.WriteFile(filepath.Join(dirA, "campaign.yaml"), []byte(yamlA), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Create campaign-b.
	dirB := filepath.Join(root, "campaign-b")
	if err := os.MkdirAll(dirB, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	yamlB := `api_version: v1
kind: Campaign
meta:
  name: bravo
  adversary: ActorB
  severity: medium
stages:
  - id: s1
    name: Step 1
    technique: T1059
    tactic: execution
    execute:
      type: shell
`
	if err := os.WriteFile(filepath.Join(dirB, "campaign.yaml"), []byte(yamlB), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	results, err := ConvertDir(root, ConvertOptions{Format: FormatJSON})
	if err != nil {
		t.Fatalf("ConvertDir error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("ConvertDir results = %d, want 2", len(results))
	}

	if _, ok := results["alpha"]; !ok {
		t.Error("ConvertDir missing alpha campaign")
	}
	if _, ok := results["bravo"]; !ok {
		t.Error("ConvertDir missing bravo campaign")
	}

	// Verify each output is valid JSON.
	for name, data := range results {
		if !json.Valid(data) {
			t.Errorf("ConvertDir output for %q is not valid JSON", name)
		}
	}
}

func TestConvertDir_MissingDir(t *testing.T) {
	_, err := ConvertDir("/nonexistent/directory", ConvertOptions{Format: FormatJSON})
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestConvertDir_EmptyDir(t *testing.T) {
	root := t.TempDir()
	results, err := ConvertDir(root, ConvertOptions{Format: FormatJSON})
	if err != nil {
		t.Fatalf("ConvertDir empty error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("ConvertDir empty = %d results, want 0", len(results))
	}
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

func TestConvert_NilCampaign(t *testing.T) {
	_, err := Convert(nil, ConvertOptions{Format: FormatJSON})
	if err == nil {
		t.Fatal("expected error for nil campaign")
	}
}

func TestConvert_UnsupportedFormat(t *testing.T) {
	c := convertTestCampaign()
	_, err := Convert(c, ConvertOptions{Format: "xml"})
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error = %q, want 'unsupported format'", err.Error())
	}
}

func TestParseJSON_EmptyInput(t *testing.T) {
	_, err := ParseJSON([]byte{})
	if err == nil {
		t.Fatal("expected error for empty JSON input")
	}
}

// ---------------------------------------------------------------------------
// Coverage percent helper
// ---------------------------------------------------------------------------

func TestCoveragePercent(t *testing.T) {
	tests := []struct {
		covered, total, want int
	}{
		{0, 0, 0},
		{0, 5, 0},
		{5, 5, 100},
		{1, 2, 50},
		{2, 3, 66},
	}
	for _, tt := range tests {
		got := coveragePercent(tt.covered, tt.total)
		if got != tt.want {
			t.Errorf("coveragePercent(%d, %d) = %d, want %d", tt.covered, tt.total, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// CSV escape helper
// ---------------------------------------------------------------------------

func TestCsvEscape(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"simple", "simple"},
		{"has,comma", `"has,comma"`},
		{`has"quote`, `"has""quote"`},
		{"has\nnewline", `"has` + "\n" + `newline"`},
		{"", ""},
	}
	for _, tt := range tests {
		got := csvEscape(tt.input)
		if got != tt.want {
			t.Errorf("csvEscape(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
