// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package sigma

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

func testCampaign() *campaign.Campaign {
	return &campaign.Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: campaign.Meta{
			Name:      "test-campaign",
			Adversary: "TestAPT",
			Severity:  "high",
		},
		Stages: []campaign.Stage{
			{
				ID:        "s1",
				Name:      "Spearphish Delivery",
				Technique: "T1566.001",
				Tactic:    "initial-access",
				Execute: campaign.Execute{
					Type:     "shell",
					Commands: []string{"echo payload"},
				},
				Expect: campaign.Expect{
					Telemetry:  []string{"process_create", "file_create"},
					Detections: []string{"spearphish_detected", "macro_execution"},
				},
			},
			{
				ID:        "s2",
				Name:      "C2 Beacon",
				Technique: "T1071.001",
				Tactic:    "command-and-control",
				Execute: campaign.Execute{
					Type:   "http",
					Target: "https://c2.evil.com/beacon",
				},
				Expect: campaign.Expect{
					Telemetry:  []string{"network_connection", "dns_query"},
					Detections: []string{"c2_beacon_detected"},
				},
			},
			{
				ID:        "s3",
				Name:      "No Detections Stage",
				Technique: "T1082",
				Tactic:    "discovery",
				Execute:   campaign.Execute{Type: "shell", Commands: []string{"whoami"}},
				// No detections — should produce no rules.
			},
		},
	}
}

func TestGenerate_RuleCount(t *testing.T) {
	c := testCampaign()
	rules := Generate(c, GenerateOptions{})

	// s1 has 2 detections, s2 has 1, s3 has 0 → 3 rules.
	if len(rules) != 3 {
		t.Errorf("got %d rules, want 3", len(rules))
	}
}

func TestGenerate_RuleFields(t *testing.T) {
	c := testCampaign()
	rules := Generate(c, GenerateOptions{Author: "TestAuthor"})

	r := rules[0] // spearphish_detected
	if r.Author != "TestAuthor" {
		t.Errorf("author = %q, want TestAuthor", r.Author)
	}
	if r.Status != "experimental" {
		t.Errorf("status = %q, want experimental", r.Status)
	}
	if r.Title != "Spearphish Detected" {
		t.Errorf("title = %q, want 'Spearphish Detected'", r.Title)
	}
	if r.Campaign != "test-campaign" {
		t.Errorf("campaign = %q, want test-campaign", r.Campaign)
	}
	if r.StageID != "s1" {
		t.Errorf("stageID = %q, want s1", r.StageID)
	}
	if r.Technique != "T1566.001" {
		t.Errorf("technique = %q, want T1566.001", r.Technique)
	}
}

func TestGenerate_DeterministicID(t *testing.T) {
	c := testCampaign()
	rules1 := Generate(c, GenerateOptions{})
	rules2 := Generate(c, GenerateOptions{})

	for i := range rules1 {
		if rules1[i].ID != rules2[i].ID {
			t.Errorf("rule %d: IDs not deterministic: %q vs %q", i, rules1[i].ID, rules2[i].ID)
		}
	}

	// IDs should be unique.
	seen := make(map[string]bool)
	for _, r := range rules1 {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID: %s", r.ID)
		}
		seen[r.ID] = true
	}

	// ID should look like a UUID: 8-4-4-4-12.
	id := rules1[0].ID
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Errorf("ID %q does not have 5 dash-separated parts", id)
	}
}

func TestGenerate_Tags(t *testing.T) {
	c := testCampaign()
	rules := Generate(c, GenerateOptions{})

	r := rules[0]
	foundTactic := false
	foundTech := false
	for _, tag := range r.Tags {
		if tag == "attack.initial_access" {
			foundTactic = true
		}
		if tag == "attack.t1566.001" {
			foundTech = true
		}
	}
	if !foundTactic {
		t.Errorf("missing tactic tag, got: %v", r.Tags)
	}
	if !foundTech {
		t.Errorf("missing technique tag, got: %v", r.Tags)
	}
}

func TestGenerate_LogSource(t *testing.T) {
	c := testCampaign()
	rules := Generate(c, GenerateOptions{})

	// s1 first telemetry is process_create → process_creation.
	if rules[0].LogSource.Category != "process_creation" {
		t.Errorf("s1 logsource = %q, want process_creation", rules[0].LogSource.Category)
	}

	// s2 first telemetry is network_connection.
	if rules[2].LogSource.Category != "network_connection" {
		t.Errorf("s2 logsource = %q, want network_connection", rules[2].LogSource.Category)
	}
}

func TestGenerate_References(t *testing.T) {
	c := testCampaign()
	rules := Generate(c, GenerateOptions{})

	// T1566.001 should have ATT&CK reference with sub-technique path.
	r := rules[0]
	found := false
	for _, ref := range r.References {
		if strings.Contains(ref, "attack.mitre.org/techniques/T1566/001") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing ATT&CK reference, got: %v", r.References)
	}
}

func TestGenerate_NoDetectionsSkipped(t *testing.T) {
	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "empty"},
		Stages: []campaign.Stage{
			{
				ID:      "s1",
				Tactic:  "discovery",
				Execute: campaign.Execute{Type: "shell"},
				// No Expect.Detections → no rules.
			},
		},
	}

	rules := Generate(c, GenerateOptions{})
	if len(rules) != 0 {
		t.Errorf("got %d rules, want 0 for stage with no detections", len(rules))
	}
}

func TestGenerate_ATLASReferences(t *testing.T) {
	c := &campaign.Campaign{
		Meta: campaign.Meta{Name: "atlas-test"},
		Stages: []campaign.Stage{
			{
				ID:        "s1",
				Technique: "AML.T0051",
				Tactic:    "initial-access",
				Execute:   campaign.Execute{Type: "http", Target: "https://agent.example.com"},
				Expect: campaign.Expect{
					Telemetry:  []string{"prompt_log"},
					Detections: []string{"prompt_injection_detected"},
				},
			},
		},
	}

	rules := Generate(c, GenerateOptions{})
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}

	found := false
	for _, ref := range rules[0].References {
		if strings.Contains(ref, "atlas.mitre.org") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing ATLAS reference, got: %v", rules[0].References)
	}

	// Agent telemetry → application logsource.
	if rules[0].LogSource.Category != "application" {
		t.Errorf("logsource = %q, want application", rules[0].LogSource.Category)
	}
}

func TestWriteRules_ValidYAML(t *testing.T) {
	c := testCampaign()
	rules := Generate(c, GenerateOptions{})

	var buf bytes.Buffer
	err := WriteRules(&buf, rules)
	if err != nil {
		t.Fatalf("WriteRules failed: %v", err)
	}

	output := buf.String()

	// Check YAML structure.
	checks := []string{
		"title:",
		"id:",
		"status: experimental",
		"level:",
		"description:",
		"author:",
		"date:",
		"references:",
		"tags:",
		"logsource:",
		"  category:",
		"detection:",
		"  selection:",
		"  condition: selection",
		"falsepositives:",
		"---",
	}
	for _, c := range checks {
		if !strings.Contains(output, c) {
			t.Errorf("output missing %q", c)
		}
	}
}

func TestWriteRules_MultipleRulesHaveSeparators(t *testing.T) {
	c := testCampaign()
	rules := Generate(c, GenerateOptions{})

	var buf bytes.Buffer
	WriteRules(&buf, rules)

	// 3 rules → 2 separators.
	count := strings.Count(buf.String(), "---\n")
	if count != 2 {
		t.Errorf("separator count = %d, want 2", count)
	}
}

func TestResolveLogSource_Known(t *testing.T) {
	tests := []struct {
		telemetry string
		category  string
	}{
		{"process_create", "process_creation"},
		{"network_connection", "network_connection"},
		{"file_create", "file_event"},
		{"dns_query", "dns_query"},
		{"registry_set", "registry_set"},
		{"prompt_log", "application"},
		{"tool_call", "application"},
	}
	for _, tt := range tests {
		ls := ResolveLogSource(tt.telemetry)
		if ls.Category != tt.category {
			t.Errorf("ResolveLogSource(%q).Category = %q, want %q", tt.telemetry, ls.Category, tt.category)
		}
	}
}

func TestResolveLogSource_Unknown(t *testing.T) {
	ls := ResolveLogSource("unknown_telemetry_type")
	if ls.Category != "application" {
		t.Errorf("unknown telemetry → category %q, want application", ls.Category)
	}
}

func TestBuildSelection_KnownTechnique(t *testing.T) {
	// T1059.001 (PowerShell) should produce real detection criteria, not TODOs.
	s := campaign.Stage{
		ID:        "ps-test",
		Technique: "T1059.001",
		Tactic:    "execution",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"powershell -enc ZQBj..."},
		},
		Expect: campaign.Expect{
			Telemetry:  []string{"process_create"},
			Detections: []string{"encoded_powershell"},
		},
	}

	sel := buildSelection(s, "encoded_powershell")

	// Must NOT contain TODO markers.
	for k, v := range sel {
		if str, ok := v.(string); ok {
			if strings.Contains(str, "TODO") {
				t.Errorf("known technique T1059.001 has TODO in selection: %s=%s", k, str)
			}
		}
	}

	// Must contain real PowerShell detection criteria.
	found := false
	for k := range sel {
		if strings.Contains(k, "Image") || strings.Contains(k, "CommandLine") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("T1059.001 selection missing Image or CommandLine criteria, got keys: %v", selKeys(sel))
	}

	// Verify specific content — should reference powershell.exe.
	if img, ok := sel["Image|endswith"]; ok {
		switch v := img.(type) {
		case string:
			if !strings.Contains(v, "powershell") {
				t.Errorf("Image|endswith = %q, expected powershell reference", v)
			}
		case []string:
			found := false
			for _, s := range v {
				if strings.Contains(s, "powershell") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Image|endswith = %v, expected powershell reference", v)
			}
		}
	}

	// Verify CommandLine contains encoded-command patterns.
	if cl, ok := sel["CommandLine|contains"]; ok {
		switch v := cl.(type) {
		case string:
			if !strings.Contains(v, "Encoded") && !strings.Contains(v, "enc") {
				t.Errorf("CommandLine|contains = %q, expected encoded command pattern", v)
			}
		case []string:
			found := false
			for _, s := range v {
				if strings.Contains(s, "Encoded") || strings.Contains(s, "bypass") || strings.Contains(s, "IEX") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("CommandLine|contains = %v, expected encoded/bypass/IEX patterns", v)
			}
		}
	}
}

func TestBuildSelection_UnknownTechnique(t *testing.T) {
	// An unknown technique ID should fall back to generic scaffold with TODO markers.
	s := campaign.Stage{
		ID:        "unknown-test",
		Technique: "T9999",
		Tactic:    "discovery",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"echo test"},
		},
		Expect: campaign.Expect{
			Telemetry:  []string{"process_create"},
			Detections: []string{"generic_detection"},
		},
	}

	sel := buildSelection(s, "generic_detection")

	hasPlaceholder := false
	for _, v := range sel {
		if str, ok := v.(string); ok {
			if strings.Contains(str, "EDIT_") {
				hasPlaceholder = true
				break
			}
		}
	}
	if !hasPlaceholder {
		t.Errorf("unknown technique should produce EDIT_ placeholder scaffolds, got: %v", sel)
	}
}

func TestTechniqueDetection_Coverage(t *testing.T) {
	// Verify all 65 required technique IDs have detection entries.
	required := []string{
		// Original 30
		"T1566.001", "T1566.002", "T1059.001", "T1059.003", "T1059.006",
		"T1047", "T1071.001", "T1071.004", "T1003.001", "T1003.003",
		"T1078.004", "T1053.005", "T1543.003", "T1021.001", "T1021.002",
		"T1046", "T1082", "T1016", "T1087.002", "T1190",
		"T1036.005", "T1070.004", "T1112", "T1134", "T1490",
		"T1485", "T1195.002", "T1550.002", "T1098", "T1621",
		// 35 new techniques
		"T1005", "T1018", "T1041", "T1048", "T1070.001",
		"T1074.001", "T1078", "T1087.004", "T1098.001", "T1110.003",
		"T1486", "T1489", "T1528", "T1538", "T1539",
		"T1558.003", "T1560.001", "T1562.001", "T1566.003", "T1567.002",
		"T1572", "T1573", "T1059.004", "T1059.005", "T1059.007",
		"T1547.001", "T1055", "T1548.002", "T1027", "T1218.011",
		"T1140", "T1569.002", "T1136.001", "T1057", "T1049",
	}

	ids := TechniqueDetectionIDs()
	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[id] = true
	}

	for _, req := range required {
		if !idSet[req] {
			t.Errorf("missing technique detection for %s", req)
		}
	}

	// Verify we have at least 65 entries total.
	if len(ids) < 65 {
		t.Errorf("got %d technique detections, want at least 65", len(ids))
	}
}

func TestBuildTechniqueSelection_NetworkTelemetry(t *testing.T) {
	// T1021.001 (RDP) with network telemetry should produce DestinationPort=3389.
	s := campaign.Stage{
		ID:        "rdp-test",
		Technique: "T1021.001",
		Tactic:    "lateral-movement",
		Execute:   campaign.Execute{Type: "http"},
		Expect: campaign.Expect{
			Telemetry:  []string{"network_connection"},
			Detections: []string{"rdp_connection"},
		},
	}

	sel := buildSelection(s, "rdp_connection")

	port, ok := sel["DestinationPort"]
	if !ok {
		t.Fatalf("T1021.001 with network telemetry missing DestinationPort, got keys: %v", selKeys(sel))
	}

	switch v := port.(type) {
	case int:
		if v != 3389 {
			t.Errorf("DestinationPort = %d, want 3389", v)
		}
	case []int:
		found := false
		for _, p := range v {
			if p == 3389 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DestinationPort = %v, expected 3389 in list", v)
		}
	default:
		t.Errorf("DestinationPort unexpected type %T", port)
	}
}

func TestBuildTechniqueSelection_RegistryTelemetry(t *testing.T) {
	// T1112 (Modify Registry) with registry telemetry should produce TargetObject.
	s := campaign.Stage{
		ID:        "reg-test",
		Technique: "T1112",
		Tactic:    "defense-evasion",
		Execute:   campaign.Execute{Type: "shell"},
		Expect: campaign.Expect{
			Telemetry:  []string{"registry_set"},
			Detections: []string{"registry_modification"},
		},
	}

	sel := buildSelection(s, "registry_modification")

	if _, ok := sel["TargetObject|contains"]; !ok {
		t.Errorf("T1112 with registry telemetry missing TargetObject|contains, got keys: %v", selKeys(sel))
	}
}

// selKeys returns sorted keys of a map for test error output.
func selKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestDetectionToTitle(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"spearphish_detected", "Spearphish Detected"},
		{"c2_https_beacon", "C2 Https Beacon"},
		{"prompt_injection_detected", "Prompt Injection Detected"},
	}
	for _, tt := range tests {
		got := detectionToTitle(tt.input)
		if got != tt.want {
			t.Errorf("detectionToTitle(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
