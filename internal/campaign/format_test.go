// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fullCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:         "full-test-campaign",
			Adversary:    "FullActor",
			Description:  "A full test campaign",
			Objective:    "Test all optional fields",
			MitreVersion: "15.1",
			Severity:     "high",
			Tags:         []string{"test", "credential-access"},
			Authors:      []string{"Author1"},
			References:   []string{"https://example.com/ref"},
			Created:      "2026-01-01",
			Modified:     "2026-06-15",
		},
		Variables: map[string]string{
			"target_host": "10.0.0.1",
			"username":    "admin",
		},
		Stages: []Stage{
			{
				ID:          "recon",
				Name:        "Network Scan",
				Description: "Scan the target network",
				Technique:   "T1016",
				Tactic:      "discovery",
				Platform:    []string{"windows", "linux"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{"nmap -sS target"},
					Cleanup:  []string{"rm /tmp/scan.log"},
					Elevated: true,
				},
				Expect: Expect{
					Telemetry:  []string{"process_create", "network_connection"},
					Detections: []string{"scan_detected"},
					Artifacts:  []string{"/tmp/scan.log"},
					IOCs:       []string{"suspicious_scan"},
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
					Target:   "10.0.0.1",
					Payload:  "exploit.bin",
					Args:     map[string]string{"port": "443", "method": "POST"},
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

func minimalCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "minimal",
			Adversary: "TestActor",
		},
		Stages: []Stage{
			{
				ID:        "step1",
				Name:      "Step One",
				Technique: "T1016",
				Tactic:    "discovery",
				Execute:   Execute{Type: "shell"},
			},
		},
	}
}

// topLevelPos returns the byte offset of a top-level YAML key (i.e., at the
// start of a line with no leading whitespace). Returns -1 if not found.
func topLevelPos(data []byte, key string) int {
	needle := key + ":"
	// Check start of data.
	if bytes.HasPrefix(data, []byte(needle)) {
		return 0
	}
	// Check after a newline.
	pos := bytes.Index(data, []byte("\n"+needle))
	if pos >= 0 {
		return pos + 1 // skip the newline itself
	}
	return -1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestFormat_ValidYAML_RoundTrip(t *testing.T) {
	c := fullCampaign()
	data, err := Format(c)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	var c2 Campaign
	if err := yaml.Unmarshal(data, &c2); err != nil {
		t.Fatalf("round-trip unmarshal error: %v", err)
	}

	if c2.APIVersion != c.APIVersion {
		t.Errorf("api_version = %q, want %q", c2.APIVersion, c.APIVersion)
	}
	if c2.Kind != c.Kind {
		t.Errorf("kind = %q, want %q", c2.Kind, c.Kind)
	}
	if c2.Meta.Name != c.Meta.Name {
		t.Errorf("meta.name = %q, want %q", c2.Meta.Name, c.Meta.Name)
	}
	if c2.Meta.Severity != c.Meta.Severity {
		t.Errorf("meta.severity = %q, want %q", c2.Meta.Severity, c.Meta.Severity)
	}
	if len(c2.Stages) != len(c.Stages) {
		t.Fatalf("stages count = %d, want %d", len(c2.Stages), len(c.Stages))
	}
	if c2.Stages[0].Execute.Elevated != true {
		t.Error("elevated flag not preserved")
	}
	if c2.Stages[0].Timeout.Duration != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", c2.Stages[0].Timeout.Duration)
	}
	if c2.Stages[0].Delay.Duration != 5*time.Second {
		t.Errorf("delay = %v, want 5s", c2.Stages[0].Delay.Duration)
	}
	if len(c2.Variables) != 2 {
		t.Errorf("variables count = %d, want 2", len(c2.Variables))
	}
}

func TestFormat_CanonicalFieldOrder(t *testing.T) {
	c := fullCampaign()
	data, err := Format(c)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	topFields := []string{"api_version", "kind", "meta", "variables", "stages"}
	positions := make([]int, len(topFields))
	for i, f := range topFields {
		pos := topLevelPos(data, f)
		if pos < 0 {
			t.Fatalf("top-level field %q not found in output:\n%s", f, data)
		}
		positions[i] = pos
	}

	for i := 1; i < len(topFields); i++ {
		if positions[i-1] >= positions[i] {
			t.Errorf("%s (pos %d) should come before %s (pos %d)",
				topFields[i-1], positions[i-1], topFields[i], positions[i])
		}
	}

	// Verify meta sub-field order: name before adversary before description.
	s := string(data)
	metaName := strings.Index(s, "  name:")
	metaAdversary := strings.Index(s, "  adversary:")
	metaDesc := strings.Index(s, "  description:")
	metaSeverity := strings.Index(s, "  severity:")

	if metaName < 0 || metaAdversary < 0 || metaDesc < 0 || metaSeverity < 0 {
		t.Fatal("meta sub-fields not all found")
	}
	if metaName >= metaAdversary {
		t.Error("meta.name should come before meta.adversary")
	}
	if metaAdversary >= metaDesc {
		t.Error("meta.adversary should come before meta.description")
	}
	if metaDesc >= metaSeverity {
		t.Error("meta.description should come before meta.severity")
	}
}

func TestFormat_EmptyFieldsOmitted(t *testing.T) {
	c := minimalCampaign()
	data, err := Format(c)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	shouldBeAbsent := []string{
		"description:", "objective:", "tags:", "authors:", "references:",
		"variables:", "depends_on:", "platform:",
		"on_success:", "on_failure:", "timeout:", "delay:",
		"payload:", "target:", "elevated:", "cleanup:",
		"telemetry:", "detections:", "artifacts:", "iocs:",
	}
	for _, field := range shouldBeAbsent {
		if bytes.Contains(data, []byte(field)) {
			t.Errorf("field %q should be omitted in minimal campaign, found in output:\n%s", field, data)
		}
	}
}

func TestFormatFile(t *testing.T) {
	data, err := FormatFile("testdata/valid-campaign/campaign.yaml")
	if err != nil {
		t.Fatalf("FormatFile error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("FormatFile returned empty output")
	}

	// Verify the output is valid YAML.
	var c Campaign
	if err := yaml.Unmarshal(data, &c); err != nil {
		t.Fatalf("FormatFile output is not valid YAML: %v", err)
	}
	if c.Meta.Name != "test-campaign" {
		t.Errorf("name = %q, want %q", c.Meta.Name, "test-campaign")
	}

	// FormatFile uses loadRaw, so template markers must survive.
	if !bytes.Contains(data, []byte("{{target_host}}")) {
		t.Error("FormatFile should preserve {{target_host}} template markers")
	}
}

func TestFormatFileInPlace(t *testing.T) {
	// Copy the test campaign to a temp directory.
	dir := t.TempDir()
	src := "testdata/valid-campaign/campaign.yaml"
	orig, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading source: %v", err)
	}
	dst := filepath.Join(dir, "campaign.yaml")
	if err := os.WriteFile(dst, orig, 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	if err := FormatFileInPlace(dst); err != nil {
		t.Fatalf("FormatFileInPlace error: %v", err)
	}

	// The file on disk should now be valid, formatted YAML.
	after, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("reading formatted file: %v", err)
	}
	if len(after) == 0 {
		t.Fatal("formatted file is empty")
	}

	var c Campaign
	if err := yaml.Unmarshal(after, &c); err != nil {
		t.Fatalf("formatted file is not valid YAML: %v", err)
	}
	if c.Meta.Name != "test-campaign" {
		t.Errorf("name = %q, want %q", c.Meta.Name, "test-campaign")
	}

	// Formatting should be idempotent.
	if err := FormatFileInPlace(dst); err != nil {
		t.Fatalf("second FormatFileInPlace error: %v", err)
	}
	after2, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("reading second pass: %v", err)
	}
	if !bytes.Equal(after, after2) {
		t.Error("FormatFileInPlace is not idempotent — second pass produced different output")
	}
}

func TestNormalize_SortStagesTopological(t *testing.T) {
	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       Meta{Name: "topo-test", Adversary: "X"},
		Stages: []Stage{
			{
				ID: "c", Name: "C", Technique: "T1016", Tactic: "discovery",
				DependsOn: []string{"b"}, Execute: Execute{Type: "shell"},
			},
			{
				ID: "a", Name: "A", Technique: "T1016", Tactic: "discovery",
				Execute: Execute{Type: "shell"},
			},
			{
				ID: "b", Name: "B", Technique: "T1016", Tactic: "discovery",
				DependsOn: []string{"a"}, Execute: Execute{Type: "shell"},
			},
		},
	}

	nc := Normalize(c)

	want := []string{"a", "b", "c"}
	for i, id := range want {
		if nc.Stages[i].ID != id {
			t.Errorf("stage[%d].ID = %q, want %q", i, nc.Stages[i].ID, id)
		}
	}
}

func TestNormalize_SortStagesAlphabeticalOnCycle(t *testing.T) {
	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       Meta{Name: "cycle-test", Adversary: "X"},
		Stages: []Stage{
			{
				ID: "z", Name: "Z", Technique: "T1016", Tactic: "discovery",
				DependsOn: []string{"a"}, Execute: Execute{Type: "shell"},
			},
			{
				ID: "a", Name: "A", Technique: "T1016", Tactic: "discovery",
				DependsOn: []string{"z"}, Execute: Execute{Type: "shell"},
			},
		},
	}

	nc := Normalize(c)

	// Cycle prevents topological sort; fallback is alphabetical.
	if nc.Stages[0].ID != "a" {
		t.Errorf("stage[0].ID = %q, want %q (alphabetical fallback)", nc.Stages[0].ID, "a")
	}
	if nc.Stages[1].ID != "z" {
		t.Errorf("stage[1].ID = %q, want %q", nc.Stages[1].ID, "z")
	}
}

func TestNormalize_SortTelemetryDetections(t *testing.T) {
	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       Meta{Name: "sort-test", Adversary: "X"},
		Stages: []Stage{
			{
				ID: "s1", Name: "S1", Technique: "T1016", Tactic: "discovery",
				Execute: Execute{Type: "shell"},
				Expect: Expect{
					Telemetry:  []string{"z_event", "a_event", "m_event"},
					Detections: []string{"rule_c", "rule_a", "rule_b"},
					Artifacts:  []string{"z.log", "a.log"},
					IOCs:       []string{"ioc_b", "ioc_a"},
				},
			},
		},
	}

	nc := Normalize(c)
	s := nc.Stages[0]

	assertSorted := func(name string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Errorf("%s: len = %d, want %d", name, len(got), len(want))
			return
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s[%d] = %q, want %q", name, i, got[i], want[i])
			}
		}
	}

	assertSorted("telemetry", s.Expect.Telemetry, []string{"a_event", "m_event", "z_event"})
	assertSorted("detections", s.Expect.Detections, []string{"rule_a", "rule_b", "rule_c"})
	assertSorted("artifacts", s.Expect.Artifacts, []string{"a.log", "z.log"})
	assertSorted("iocs", s.Expect.IOCs, []string{"ioc_a", "ioc_b"})
}

func TestNormalize_SortTagsAndPlatform(t *testing.T) {
	c := baseCampaign()
	c.Meta.Tags = []string{"zebra", "apple", "mango"}
	c.Stages[0].Platform = []string{"windows", "linux", "macos"}

	nc := Normalize(c)

	wantTags := []string{"apple", "mango", "zebra"}
	for i, v := range nc.Meta.Tags {
		if v != wantTags[i] {
			t.Errorf("tags[%d] = %q, want %q", i, v, wantTags[i])
		}
	}

	wantPlatform := []string{"linux", "macos", "windows"}
	for i, v := range nc.Stages[0].Platform {
		if v != wantPlatform[i] {
			t.Errorf("platform[%d] = %q, want %q", i, v, wantPlatform[i])
		}
	}
}

func TestNormalize_DoesNotMutateOriginal(t *testing.T) {
	c := fullCampaign()

	origFirstStageID := c.Stages[0].ID
	origTags := make([]string, len(c.Meta.Tags))
	copy(origTags, c.Meta.Tags)
	origTelemetry := make([]string, len(c.Stages[0].Expect.Telemetry))
	copy(origTelemetry, c.Stages[0].Expect.Telemetry)
	origPlatform := make([]string, len(c.Stages[0].Platform))
	copy(origPlatform, c.Stages[0].Platform)

	_ = Normalize(c)

	// Stage order should not change.
	if c.Stages[0].ID != origFirstStageID {
		t.Errorf("Normalize mutated original stage order: first stage ID changed from %q to %q",
			origFirstStageID, c.Stages[0].ID)
	}
	// Tags should not be sorted.
	for i, v := range c.Meta.Tags {
		if v != origTags[i] {
			t.Errorf("Normalize mutated original tags[%d]: %q -> %q", i, origTags[i], v)
		}
	}
	// Telemetry should not be sorted.
	for i, v := range c.Stages[0].Expect.Telemetry {
		if v != origTelemetry[i] {
			t.Errorf("Normalize mutated original telemetry[%d]: %q -> %q", i, origTelemetry[i], v)
		}
	}
	// Platform should not be sorted.
	for i, v := range c.Stages[0].Platform {
		if v != origPlatform[i] {
			t.Errorf("Normalize mutated original platform[%d]: %q -> %q", i, origPlatform[i], v)
		}
	}
}

func TestFormat_MinimalCampaign(t *testing.T) {
	c := minimalCampaign()
	data, err := Format(c)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	if !bytes.Contains(data, []byte("api_version:")) {
		t.Error("missing api_version")
	}
	if !bytes.Contains(data, []byte("kind:")) {
		t.Error("missing kind")
	}
	if !bytes.Contains(data, []byte("name: minimal")) {
		t.Error("missing meta.name")
	}

	// Round-trip.
	var c2 Campaign
	if err := yaml.Unmarshal(data, &c2); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if c2.Meta.Name != "minimal" {
		t.Errorf("name = %q, want minimal", c2.Meta.Name)
	}
	if len(c2.Stages) != 1 {
		t.Errorf("stages = %d, want 1", len(c2.Stages))
	}
}

func TestFormat_AllOptionalFields(t *testing.T) {
	c := fullCampaign()
	data, err := Format(c)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	expected := []string{
		"description:", "objective:", "tags:", "authors:", "references:",
		"variables:", "platform:", "depends_on:", "commands:", "cleanup:",
		"elevated:", "telemetry:", "detections:", "artifacts:", "iocs:",
		"on_success:", "on_failure:", "timeout:", "delay:",
		"payload:", "target:", "args:",
	}
	for _, field := range expected {
		if !bytes.Contains(data, []byte(field)) {
			t.Errorf("expected field %q in full campaign output, not found in:\n%s", field, data)
		}
	}
}

func TestFormat_RoundTrip_Fingerprint(t *testing.T) {
	c1, err := Load("testdata/valid-campaign/campaign.yaml")
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	fp1 := Fingerprint(c1)

	data, err := Format(c1)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	// Write to temp file and Load back (Load expands variables on the
	// already-expanded values — a no-op, so fingerprints must match).
	dir := t.TempDir()
	tmpFile := filepath.Join(dir, "campaign.yaml")
	if err := os.WriteFile(tmpFile, data, 0o644); err != nil {
		t.Fatalf("writing temp: %v", err)
	}

	c2, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load round-trip error: %v", err)
	}
	fp2 := Fingerprint(c2)

	if fp1 != fp2 {
		t.Errorf("fingerprint mismatch after round-trip:\n  original:   %s\n  round-trip: %s\nformatted YAML:\n%s",
			fp1, fp2, data)
	}
}

func TestFormat_Duration(t *testing.T) {
	c := minimalCampaign()
	c.Stages[0].Timeout = Duration{30 * time.Second}
	c.Stages[0].Delay = Duration{5 * time.Second}

	data, err := Format(c)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	if !bytes.Contains(data, []byte("timeout: 30s")) {
		t.Errorf("expected 'timeout: 30s' in output:\n%s", data)
	}
	if !bytes.Contains(data, []byte("delay: 5s")) {
		t.Errorf("expected 'delay: 5s' in output:\n%s", data)
	}

	// Round-trip the durations.
	var c2 Campaign
	if err := yaml.Unmarshal(data, &c2); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if c2.Stages[0].Timeout.Duration != 30*time.Second {
		t.Errorf("timeout round-trip = %v, want 30s", c2.Stages[0].Timeout.Duration)
	}
	if c2.Stages[0].Delay.Duration != 5*time.Second {
		t.Errorf("delay round-trip = %v, want 5s", c2.Stages[0].Delay.Duration)
	}
}

func TestFormat_Idempotent(t *testing.T) {
	c := fullCampaign()
	first, err := Format(c)
	if err != nil {
		t.Fatalf("first Format error: %v", err)
	}

	// Parse the formatted output and format again.
	var c2 Campaign
	if err := yaml.Unmarshal(first, &c2); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	second, err := Format(&c2)
	if err != nil {
		t.Fatalf("second Format error: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("Format is not idempotent.\nFirst:\n%s\nSecond:\n%s", first, second)
	}
}

func TestFormat_VariablesSortedByKey(t *testing.T) {
	c := minimalCampaign()
	c.Variables = map[string]string{
		"z_var": "z",
		"a_var": "a",
		"m_var": "m",
	}

	data, err := Format(c)
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}

	s := string(data)
	posA := strings.Index(s, "a_var:")
	posM := strings.Index(s, "m_var:")
	posZ := strings.Index(s, "z_var:")

	if posA < 0 || posM < 0 || posZ < 0 {
		t.Fatalf("not all variables found in output:\n%s", s)
	}
	if posA >= posM || posM >= posZ {
		t.Errorf("variables not in sorted order: a@%d, m@%d, z@%d", posA, posM, posZ)
	}
}
