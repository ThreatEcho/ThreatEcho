// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package telemetry

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValid_KnownTypes(t *testing.T) {
	known := []string{
		"process_create", "file_create", "network_connection",
		"dns_query", "registry_create", "auth_success",
		"service_create", "script_execute", "prompt_log",
		"tool_call", "cloud_api_call", "api_call",
	}
	for _, tt := range known {
		if !Valid(tt) {
			t.Errorf("Valid(%q) = false, want true", tt)
		}
	}
}

func TestValid_UnknownTypes(t *testing.T) {
	unknown := []string{
		"", "invalid", "process_explode", "file_corrupt",
		"network_destroy", "magic_spell", "PROCESS_CREATE",
	}
	for _, tt := range unknown {
		if Valid(tt) {
			t.Errorf("Valid(%q) = true, want false", tt)
		}
	}
}

func TestAll_Sorted(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("All() returned empty slice")
	}
	for i := 1; i < len(all); i++ {
		if all[i] < all[i-1] {
			t.Errorf("All() not sorted: %q comes after %q", all[i], all[i-1])
		}
	}
}

func TestAll_NoDuplicates(t *testing.T) {
	all := All()
	seen := make(map[Type]bool)
	for _, tt := range all {
		if seen[tt] {
			t.Errorf("All() contains duplicate: %q", tt)
		}
		seen[tt] = true
	}
}

func TestAll_MinimumCount(t *testing.T) {
	all := All()
	if len(all) < 40 {
		t.Errorf("All() returned %d types, want at least 40", len(all))
	}
}

func TestCategory_Process(t *testing.T) {
	if cat := Category("process_create"); cat != "Process" {
		t.Errorf("Category(process_create) = %q, want %q", cat, "Process")
	}
}

func TestCategory_File(t *testing.T) {
	if cat := Category("file_create"); cat != "File" {
		t.Errorf("Category(file_create) = %q, want %q", cat, "File")
	}
}

func TestCategory_AIAgent(t *testing.T) {
	if cat := Category("prompt_log"); cat != "AI Agent" {
		t.Errorf("Category(prompt_log) = %q, want %q", cat, "AI Agent")
	}
}

func TestCategory_Unknown(t *testing.T) {
	if cat := Category("nonexistent"); cat != "" {
		t.Errorf("Category(nonexistent) = %q, want empty", cat)
	}
}

func TestDescription_Known(t *testing.T) {
	desc := Description("process_create")
	if desc == "" {
		t.Error("Description(process_create) returned empty string")
	}
}

func TestDescription_Unknown(t *testing.T) {
	desc := Description("nonexistent")
	if desc != "" {
		t.Errorf("Description(nonexistent) = %q, want empty", desc)
	}
}

func TestByCategory_GroupsCorrectly(t *testing.T) {
	grouped := ByCategory()

	// Check that known categories exist.
	expectedCats := []string{"Process", "File", "Network", "Registry",
		"Authentication", "Service", "Script", "AI Agent", "Cloud"}
	for _, cat := range expectedCats {
		types, ok := grouped[cat]
		if !ok {
			t.Errorf("ByCategory() missing category %q", cat)
			continue
		}
		if len(types) == 0 {
			t.Errorf("ByCategory()[%q] is empty", cat)
		}
	}

	// Check that process_create is in Process category.
	processTypes := grouped["Process"]
	found := false
	for _, tt := range processTypes {
		if tt == ProcessCreate {
			found = true
			break
		}
	}
	if !found {
		t.Error("ByCategory()[Process] does not contain process_create")
	}
}

func TestByCategory_TypesSorted(t *testing.T) {
	grouped := ByCategory()
	for cat, types := range grouped {
		for i := 1; i < len(types); i++ {
			if types[i] < types[i-1] {
				t.Errorf("ByCategory()[%q] not sorted: %q after %q",
					cat, types[i], types[i-1])
			}
		}
	}
}

func TestCategories_Sorted(t *testing.T) {
	cats := Categories()
	if len(cats) == 0 {
		t.Fatal("Categories() returned empty slice")
	}
	if !sort.StringsAreSorted(cats) {
		t.Errorf("Categories() not sorted: %v", cats)
	}
}

func TestCategories_ContainsExpected(t *testing.T) {
	cats := Categories()
	expected := []string{"AI Agent", "Authentication", "Cloud", "File",
		"Network", "Process", "Registry", "Script", "Service"}
	catSet := make(map[string]bool)
	for _, c := range cats {
		catSet[c] = true
	}
	for _, e := range expected {
		if !catSet[e] {
			t.Errorf("Categories() missing %q", e)
		}
	}
}

func TestSuggest_FindsSimilar(t *testing.T) {
	tests := []struct {
		input   string
		wantAny []Type // at least one of these should appear
	}{
		{"process", []Type{ProcessCreate, ProcessTerminate, ProcessAccess, ProcessInjection}},
		{"file_creat", []Type{FileCreate}},
		{"dns", []Type{DNSQuery, DNSResponse}},
		{"auth", []Type{AuthSuccess, AuthFailure, Authentication}},
		{"prompt", []Type{PromptLog}},
		{"registry", []Type{RegistryCreate, RegistryModify, RegistrySet}},
	}

	for _, tc := range tests {
		suggestions := Suggest(tc.input)
		if len(suggestions) == 0 {
			t.Errorf("Suggest(%q) returned empty, want matches for %v",
				tc.input, tc.wantAny)
			continue
		}
		found := false
		for _, want := range tc.wantAny {
			for _, got := range suggestions {
				if got == want {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			t.Errorf("Suggest(%q) = %v, want at least one of %v",
				tc.input, suggestions, tc.wantAny)
		}
	}
}

func TestSuggest_EmptyInput(t *testing.T) {
	suggestions := Suggest("")
	if suggestions != nil {
		t.Errorf("Suggest(\"\") = %v, want nil", suggestions)
	}
}

func TestSuggest_ResultsSorted(t *testing.T) {
	suggestions := Suggest("process")
	for i := 1; i < len(suggestions); i++ {
		if suggestions[i] < suggestions[i-1] {
			t.Errorf("Suggest results not sorted: %q after %q",
				suggestions[i], suggestions[i-1])
		}
	}
}

// TestCampaignTelemetryTypes verifies that every telemetry type used in the
// built-in campaign YAML files is present in the registry.
func TestCampaignTelemetryTypes(t *testing.T) {
	// campaignStep mirrors just enough of the campaign YAML to extract
	// telemetry types.
	type campaignExpect struct {
		Telemetry []string `yaml:"telemetry"`
	}
	type campaignStage struct {
		Expect campaignExpect `yaml:"expect"`
	}
	type campaignFile struct {
		Stages []campaignStage `yaml:"stages"`
	}

	campaignsDir := filepath.Join("..", "..", "campaigns")
	entries, err := os.ReadDir(campaignsDir)
	if err != nil {
		t.Fatalf("cannot read campaigns directory: %v", err)
	}

	var missing []string
	seen := make(map[string]bool)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		yamlPath := filepath.Join(campaignsDir, entry.Name(), "campaign.yaml")
		data, err := os.ReadFile(yamlPath)
		if err != nil {
			continue // skip directories without campaign.yaml
		}
		var cf campaignFile
		if err := yaml.Unmarshal(data, &cf); err != nil {
			t.Errorf("failed to parse %s: %v", yamlPath, err)
			continue
		}
		for _, stage := range cf.Stages {
			for _, tt := range stage.Expect.Telemetry {
				tt = strings.TrimSpace(tt)
				if tt == "" || seen[tt] {
					continue
				}
				seen[tt] = true
				if !Valid(tt) {
					missing = append(missing, tt)
				}
			}
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("campaign YAML telemetry types not in registry:\n  %s",
			strings.Join(missing, "\n  "))
	}

	if len(seen) == 0 {
		t.Error("no telemetry types found in campaign YAML files; check path")
	}
}

func TestAllTypesHaveCategory(t *testing.T) {
	for _, tt := range All() {
		cat := Category(string(tt))
		if cat == "" {
			t.Errorf("type %q has no category", tt)
		}
	}
}

func TestAllTypesHaveDescription(t *testing.T) {
	for _, tt := range All() {
		desc := Description(string(tt))
		if desc == "" {
			t.Errorf("type %q has no description", tt)
		}
	}
}
