// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Generate: technique list
// ---------------------------------------------------------------------------

func TestGenerate_TechniqueList(t *testing.T) {
	res, err := Generate(&GenerateConfig{
		Name:       "technique-list-campaign",
		Techniques: []string{"T1059", "T1053"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.StageCount != 2 {
		t.Fatalf("expected 2 stages, got %d", res.StageCount)
	}
	if len(res.Campaign.Stages) != 2 {
		t.Fatalf("expected 2 stages in campaign, got %d", len(res.Campaign.Stages))
	}

	want := []string{"T1059", "T1053"}
	for i, tech := range want {
		if res.Campaign.Stages[i].Technique != tech {
			t.Errorf("stage[%d]: expected technique %q, got %q", i, tech, res.Campaign.Stages[i].Technique)
		}
	}

	if len(res.TechniquesUsed) != 2 || res.TechniquesUsed[0] != "T1059" || res.TechniquesUsed[1] != "T1053" {
		t.Errorf("unexpected TechniquesUsed: %v", res.TechniquesUsed)
	}
}

func TestGenerate_TechniqueList_DedupesDuplicates(t *testing.T) {
	res, err := Generate(&GenerateConfig{
		Techniques: []string{"T1059", "T1059", "T1053"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StageCount != 2 {
		t.Fatalf("expected duplicates deduped to 2 stages, got %d", res.StageCount)
	}
}

func TestGenerate_TechniqueStageFields(t *testing.T) {
	res, err := Generate(&GenerateConfig{Techniques: []string{"T1059"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := res.Campaign.Stages[0]

	if s.ID == "" {
		t.Error("expected non-empty stage ID")
	}
	if s.Name == "" {
		t.Error("expected non-empty stage name")
	}
	if s.Tactic != "execution" {
		t.Errorf("expected tactic %q, got %q", "execution", s.Tactic)
	}
	if s.Execute.Type != "http" {
		t.Errorf("expected default execute type %q, got %q", "http", s.Execute.Type)
	}
	if len(s.Platform) != 1 || s.Platform[0] != "linux" {
		t.Errorf("expected default platform [linux], got %v", s.Platform)
	}
}

// ---------------------------------------------------------------------------
// Generate: tactic list
// ---------------------------------------------------------------------------

func TestGenerate_TacticList(t *testing.T) {
	res, err := Generate(&GenerateConfig{
		Tactics: []string{"discovery", "collection"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StageCount != 2 {
		t.Fatalf("expected 2 stages, got %d", res.StageCount)
	}

	wantTechniques := []string{"T1016", "T1005"}
	for i, tech := range wantTechniques {
		if res.TechniquesUsed[i] != tech {
			t.Errorf("techniquesUsed[%d]: expected %q, got %q", i, tech, res.TechniquesUsed[i])
		}
	}

	wantTactics := map[string]bool{"discovery": true, "collection": true}
	for _, tac := range res.TacticsUsed {
		if !wantTactics[tac] {
			t.Errorf("unexpected tactic in TacticsUsed: %q", tac)
		}
		delete(wantTactics, tac)
	}
	if len(wantTactics) != 0 {
		t.Errorf("missing expected tactics: %v", wantTactics)
	}
}

func TestGenerate_TacticList_ATLASFallback(t *testing.T) {
	// "ml-attack-staging" has no ATT&CK representative; must fall back to ATLAS.
	res, err := Generate(&GenerateConfig{
		Tactics: []string{"ml-attack-staging"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StageCount != 1 {
		t.Fatalf("expected 1 stage, got %d", res.StageCount)
	}
	if res.TechniquesUsed[0] != "AML.T0020" {
		t.Errorf("expected representative technique %q, got %q", "AML.T0020", res.TechniquesUsed[0])
	}
}

func TestGenerate_TacticList_UnknownTacticWarns(t *testing.T) {
	res, err := Generate(&GenerateConfig{
		Tactics: []string{"discovery", "not-a-real-tactic"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StageCount != 1 {
		t.Fatalf("expected 1 resolvable stage, got %d", res.StageCount)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "not-a-real-tactic") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning mentioning the unknown tactic, got %v", res.Warnings)
	}
}

func TestGenerate_MixedTechniquesAndTactics(t *testing.T) {
	res, err := Generate(&GenerateConfig{
		Techniques: []string{"T1059"},
		Tactics:    []string{"discovery"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StageCount != 2 {
		t.Fatalf("expected 2 stages (1 explicit + 1 from tactic), got %d", res.StageCount)
	}
	if res.TechniquesUsed[0] != "T1059" || res.TechniquesUsed[1] != "T1016" {
		t.Errorf("unexpected TechniquesUsed order: %v", res.TechniquesUsed)
	}
}

// ---------------------------------------------------------------------------
// Generate: predefined profiles
// ---------------------------------------------------------------------------

func TestGenerate_ProfileAIRedTeam(t *testing.T) {
	res, err := Generate(&GenerateConfig{Profile: "ai-red-team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StageCount != 5 {
		t.Fatalf("expected 5 stages, got %d", res.StageCount)
	}
	for _, tech := range res.TechniquesUsed {
		if !strings.HasPrefix(tech, "AML.") {
			t.Errorf("expected only ATLAS techniques, got %q", tech)
		}
	}
	if res.Campaign.Meta.Adversary != "AI Red Team" {
		t.Errorf("expected adversary %q, got %q", "AI Red Team", res.Campaign.Meta.Adversary)
	}
	if res.Campaign.Meta.Severity != "high" {
		t.Errorf("expected severity %q, got %q", "high", res.Campaign.Meta.Severity)
	}

	want := map[string]bool{
		"AML.T0051": true, "AML.T0043": true, "AML.T0040": true,
		"AML.T0024": true, "AML.T0025": true,
	}
	for _, tech := range res.TechniquesUsed {
		if !want[tech] {
			t.Errorf("unexpected technique %q in ai-red-team profile", tech)
		}
		delete(want, tech)
	}
	if len(want) != 0 {
		t.Errorf("missing expected ai-red-team techniques: %v", want)
	}
}

func TestGenerate_ProfileAPTSimulation(t *testing.T) {
	res, err := Generate(&GenerateConfig{Profile: "apt-simulation"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StageCount != 5 {
		t.Fatalf("expected 5 stages, got %d", res.StageCount)
	}
	for _, tech := range res.TechniquesUsed {
		if strings.HasPrefix(tech, "AML.") {
			t.Errorf("expected only ATT&CK techniques, got %q", tech)
		}
	}

	want := map[string]bool{
		"T1059": true, "T1053": true, "T1547": true, "T1055": true, "T1027": true,
	}
	for _, tech := range res.TechniquesUsed {
		if !want[tech] {
			t.Errorf("unexpected technique %q in apt-simulation profile", tech)
		}
		delete(want, tech)
	}
	if len(want) != 0 {
		t.Errorf("missing expected apt-simulation techniques: %v", want)
	}
}

func TestGenerate_ProfileComplianceCheck(t *testing.T) {
	res, err := Generate(&GenerateConfig{Profile: "compliance-check"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StageCount < 5 {
		t.Fatalf("expected a broad technique spread (>=5 stages), got %d", res.StageCount)
	}
	if len(res.TacticsUsed) < 3 {
		t.Errorf("expected coverage across multiple tactics, got %v", res.TacticsUsed)
	}
	if res.Campaign.Meta.Adversary != "Compliance Auditor" {
		t.Errorf("expected adversary %q, got %q", "Compliance Auditor", res.Campaign.Meta.Adversary)
	}
}

func TestGenerate_ProfileWithExplicitTechniquesOverridesTechniqueList(t *testing.T) {
	// Explicit Techniques take priority over the profile's technique list,
	// but naming/severity metadata should still come from the profile.
	res, err := Generate(&GenerateConfig{
		Profile:    "apt-simulation",
		Techniques: []string{"T1003"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StageCount != 1 || res.TechniquesUsed[0] != "T1003" {
		t.Fatalf("expected explicit technique to override profile list, got %v", res.TechniquesUsed)
	}
	if res.Campaign.Meta.Adversary != "Simulated APT" {
		t.Errorf("expected profile-derived adversary %q, got %q", "Simulated APT", res.Campaign.Meta.Adversary)
	}
}

// ---------------------------------------------------------------------------
// Generate: custom metadata
// ---------------------------------------------------------------------------

func TestGenerate_CustomMetadata(t *testing.T) {
	res, err := Generate(&GenerateConfig{
		Techniques:  []string{"T1059"},
		Name:        "my-custom-campaign",
		Description: "a hand-written description",
		Adversary:   "Custom Actor",
		Severity:    "critical",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := res.Campaign.Meta
	if m.Name != "my-custom-campaign" {
		t.Errorf("expected name %q, got %q", "my-custom-campaign", m.Name)
	}
	if m.Description != "a hand-written description" {
		t.Errorf("expected description %q, got %q", "a hand-written description", m.Description)
	}
	if m.Adversary != "Custom Actor" {
		t.Errorf("expected adversary %q, got %q", "Custom Actor", m.Adversary)
	}
	if m.Severity != "critical" {
		t.Errorf("expected severity %q, got %q", "critical", m.Severity)
	}
}

func TestGenerate_DefaultAdversaryIsGenerated(t *testing.T) {
	res, err := Generate(&GenerateConfig{Techniques: []string{"T1059"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Campaign.Meta.Adversary != "generated" {
		t.Errorf("expected default adversary %q, got %q", "generated", res.Campaign.Meta.Adversary)
	}
}

func TestGenerate_DefaultPlatformAndStageType(t *testing.T) {
	res, err := Generate(&GenerateConfig{Techniques: []string{"T1059"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := res.Campaign.Stages[0]
	if s.Execute.Type != "http" {
		t.Errorf("expected default stage type %q, got %q", "http", s.Execute.Type)
	}
	if len(s.Platform) != 1 || s.Platform[0] != "linux" {
		t.Errorf("expected default platform [linux], got %v", s.Platform)
	}
}

func TestGenerate_CustomPlatformAndStageType(t *testing.T) {
	res, err := Generate(&GenerateConfig{
		Techniques: []string{"T1059"},
		Platform:   "windows",
		StageType:  "shell",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := res.Campaign.Stages[0]
	if s.Execute.Type != "shell" {
		t.Errorf("expected stage type %q, got %q", "shell", s.Execute.Type)
	}
	if len(s.Platform) != 1 || s.Platform[0] != "windows" {
		t.Errorf("expected platform [windows], got %v", s.Platform)
	}
	if len(s.Execute.Commands) == 0 {
		t.Error("expected shell stage to have commands")
	}
}

// ---------------------------------------------------------------------------
// Generate: validation
// ---------------------------------------------------------------------------

func TestGenerate_OutputPassesValidate(t *testing.T) {
	cases := []*GenerateConfig{
		{Techniques: []string{"T1059", "T1053"}},
		{Tactics: []string{"discovery", "collection"}},
		{Profile: "ai-red-team"},
		{Profile: "apt-simulation"},
		{Profile: "compliance-check"},
	}
	for i, cfg := range cases {
		res, err := Generate(cfg)
		if err != nil {
			t.Fatalf("case %d: unexpected error: %v", i, err)
		}
		if errs := Validate(res.Campaign); len(errs) > 0 {
			t.Errorf("case %d: generated campaign failed Validate(): %v", i, errs)
		}
	}
}

// ---------------------------------------------------------------------------
// GenerateYAML
// ---------------------------------------------------------------------------

func TestGenerateYAML_ProducesValidYAML(t *testing.T) {
	res, err := Generate(&GenerateConfig{Techniques: []string{"T1059"}, Name: "yaml-test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.YAML == "" {
		t.Fatal("expected non-empty YAML")
	}
	if !strings.Contains(res.YAML, "api_version: v1") {
		t.Errorf("expected YAML to use api_version: v1, got:\n%s", res.YAML)
	}
	if strings.Contains(res.YAML, "apiVersion") {
		t.Errorf("YAML must not use apiVersion, got:\n%s", res.YAML)
	}

	var parsed Campaign
	if err := yaml.Unmarshal([]byte(res.YAML), &parsed); err != nil {
		t.Fatalf("generated YAML did not parse: %v", err)
	}
	if parsed.Meta.Name != "yaml-test" {
		t.Errorf("expected parsed name %q, got %q", "yaml-test", parsed.Meta.Name)
	}
}

func TestGenerateYAML_Roundtrip(t *testing.T) {
	res, err := Generate(&GenerateConfig{Profile: "apt-simulation"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	str, err := GenerateYAML(res.Campaign)
	if err != nil {
		t.Fatalf("GenerateYAML failed: %v", err)
	}

	var parsed Campaign
	if err := yaml.Unmarshal([]byte(str), &parsed); err != nil {
		t.Fatalf("roundtrip parse failed: %v", err)
	}

	if parsed.APIVersion != res.Campaign.APIVersion {
		t.Errorf("api_version mismatch: got %q, want %q", parsed.APIVersion, res.Campaign.APIVersion)
	}
	if parsed.Kind != res.Campaign.Kind {
		t.Errorf("kind mismatch: got %q, want %q", parsed.Kind, res.Campaign.Kind)
	}
	if parsed.Meta.Name != res.Campaign.Meta.Name {
		t.Errorf("meta.name mismatch: got %q, want %q", parsed.Meta.Name, res.Campaign.Meta.Name)
	}
	if len(parsed.Stages) != len(res.Campaign.Stages) {
		t.Fatalf("stage count mismatch: got %d, want %d", len(parsed.Stages), len(res.Campaign.Stages))
	}
	for i := range parsed.Stages {
		want := res.Campaign.Stages[i]
		got := parsed.Stages[i]
		if got.ID != want.ID || got.Technique != want.Technique || got.Tactic != want.Tactic {
			t.Errorf("stage[%d] mismatch: got %+v, want %+v", i, got, want)
		}
	}

	if errs := Validate(&parsed); len(errs) > 0 {
		t.Errorf("roundtripped campaign failed Validate(): %v", errs)
	}
}

func TestGenerateYAML_NilCampaignSafe(t *testing.T) {
	// GenerateYAML should not panic on an empty-but-non-nil campaign; it
	// simply produces YAML that would fail Validate() separately.
	c := &Campaign{}
	if _, err := GenerateYAML(c); err != nil {
		t.Fatalf("unexpected error formatting empty campaign: %v", err)
	}
}

// ---------------------------------------------------------------------------
// slugify
// ---------------------------------------------------------------------------

func TestSlugify(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Hello World", "hello-world"},
		{"AML.T0051", "aml-t0051"},
		{"  leading and trailing  ", "leading-and-trailing"},
		{"Multiple---Dashes!!", "multiple-dashes"},
		{"", ""},
		{"already-kebab-case", "already-kebab-case"},
		{"CamelCase123", "camelcase123"},
		{"T1059 Command and Scripting Interpreter", "t1059-command-and-scripting-interpreter"},
		{"!!!", ""},
	}
	for _, c := range cases {
		got := slugify(c.in)
		if got != c.want {
			t.Errorf("slugify(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// techniqueToStage
// ---------------------------------------------------------------------------

func TestTechniqueToStage_ATTACK(t *testing.T) {
	s := techniqueToStage("T1059")
	if s.Technique != "T1059" {
		t.Errorf("expected technique %q, got %q", "T1059", s.Technique)
	}
	if s.Tactic != "execution" {
		t.Errorf("expected tactic %q, got %q", "execution", s.Tactic)
	}
	if !strings.Contains(s.Name, "Command and Scripting Interpreter") {
		t.Errorf("expected name to contain technique name, got %q", s.Name)
	}
	if s.ID == "" {
		t.Error("expected non-empty ID")
	}
	if s.Execute.Type != "http" {
		t.Errorf("expected default execute type %q, got %q", "http", s.Execute.Type)
	}
}

func TestTechniqueToStage_ATLAS(t *testing.T) {
	s := techniqueToStage("AML.T0051")
	if s.Tactic != "initial-access" {
		t.Errorf("expected tactic %q, got %q", "initial-access", s.Tactic)
	}
	if !strings.Contains(s.Name, "LLM Prompt Injection") {
		t.Errorf("expected name to contain technique name, got %q", s.Name)
	}
}

func TestTechniqueToStage_ATLASNotInRegistry(t *testing.T) {
	// Well-formed but not in the curated registry — must still produce a
	// usable, validly-tacticed stage.
	s := techniqueToStage("AML.T9999")
	if s.Tactic != "ml-attack-staging" {
		t.Errorf("expected fallback tactic %q, got %q", "ml-attack-staging", s.Tactic)
	}
	if s.Technique != "AML.T9999" {
		t.Errorf("expected technique preserved, got %q", s.Technique)
	}
}

func TestTechniqueToStage_ExtraTacticMap(t *testing.T) {
	s := techniqueToStage("AML.T0024")
	if s.Tactic != "exfiltration" {
		t.Errorf("expected tactic %q, got %q", "exfiltration", s.Tactic)
	}
}

func TestTechniqueToStage_OWASP(t *testing.T) {
	s := techniqueToStage("LLM01")
	if s.Tactic != "initial-access" {
		t.Errorf("expected tactic %q, got %q", "initial-access", s.Tactic)
	}
	if !strings.Contains(s.Name, "Prompt Injection") {
		t.Errorf("expected name to reference Prompt Injection, got %q", s.Name)
	}
}

func TestTechniqueToStage_UniqueIDsForDifferentTechniques(t *testing.T) {
	s1 := techniqueToStage("T1059")
	s2 := techniqueToStage("T1053")
	if s1.ID == s2.ID {
		t.Errorf("expected different technique IDs to produce different stage IDs, both were %q", s1.ID)
	}
}

// ---------------------------------------------------------------------------
// buildStages ID collision handling
// ---------------------------------------------------------------------------

func TestBuildStages_HandlesIDCollisions(t *testing.T) {
	stages, _ := buildStages([]string{"T1059", "T1059"}, "linux", "shell")
	if len(stages) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(stages))
	}
	if stages[0].ID == stages[1].ID {
		t.Errorf("expected distinct IDs on collision, got %q twice", stages[0].ID)
	}
	if !strings.HasSuffix(stages[1].ID, "-2") {
		t.Errorf("expected second colliding stage ID to end in -2, got %q", stages[1].ID)
	}
}

func TestBuildStages_UnknownTechniqueWarns(t *testing.T) {
	_, warnings := buildStages([]string{"AML.T9999"}, "linux", "http")
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "AML.T9999") {
		t.Errorf("expected warning to mention the technique, got %q", warnings[0])
	}
}

// ---------------------------------------------------------------------------
// representativeTechniques
// ---------------------------------------------------------------------------

func TestRepresentativeTechniques(t *testing.T) {
	if got := representativeTechniques("discovery"); len(got) != 1 || got[0] != "T1016" {
		t.Errorf("discovery: expected [T1016], got %v", got)
	}
	if got := representativeTechniques("collection"); len(got) != 1 || got[0] != "T1005" {
		t.Errorf("collection: expected [T1005], got %v", got)
	}
	if got := representativeTechniques("ml-attack-staging"); len(got) != 1 || got[0] != "AML.T0020" {
		t.Errorf("ml-attack-staging: expected [AML.T0020], got %v", got)
	}
	if got := representativeTechniques("not-a-tactic"); got != nil {
		t.Errorf("expected nil for unknown tactic, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// predefinedProfile
// ---------------------------------------------------------------------------

func TestPredefinedProfile_KnownNames(t *testing.T) {
	for _, name := range []string{"ai-red-team", "apt-simulation", "compliance-check"} {
		p := predefinedProfile(name)
		if p == nil {
			t.Errorf("expected profile %q to exist", name)
			continue
		}
		if len(p.Techniques) == 0 {
			t.Errorf("profile %q: expected non-empty technique list", name)
		}
	}
}

func TestPredefinedProfile_Unknown(t *testing.T) {
	if p := predefinedProfile("does-not-exist"); p != nil {
		t.Errorf("expected nil for unknown profile, got %+v", p)
	}
}

// ---------------------------------------------------------------------------
// Edge cases and error paths
// ---------------------------------------------------------------------------

func TestGenerate_NilConfig(t *testing.T) {
	if _, err := Generate(nil); err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestGenerate_EmptyConfig(t *testing.T) {
	if _, err := Generate(&GenerateConfig{}); err == nil {
		t.Fatal("expected error for empty config with no techniques/tactics/profile")
	}
}

func TestGenerate_UnknownProfile(t *testing.T) {
	_, err := Generate(&GenerateConfig{Profile: "not-a-real-profile"})
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	if !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("expected error to mention unknown profile, got: %v", err)
	}
}

func TestGenerate_InvalidTechniqueFormat(t *testing.T) {
	_, err := Generate(&GenerateConfig{Techniques: []string{"not-a-technique-id"}})
	if err == nil {
		t.Fatal("expected error for invalid technique format")
	}
}

func TestGenerate_InvalidStageType(t *testing.T) {
	_, err := Generate(&GenerateConfig{
		Techniques: []string{"T1059"},
		StageType:  "carrier-pigeon",
	})
	if err == nil {
		t.Fatal("expected error for invalid stage type")
	}
}

func TestGenerate_InvalidPlatform(t *testing.T) {
	_, err := Generate(&GenerateConfig{
		Techniques: []string{"T1059"},
		Platform:   "amiga",
	})
	if err == nil {
		t.Fatal("expected error for invalid platform")
	}
}

func TestGenerate_InvalidSeverity(t *testing.T) {
	_, err := Generate(&GenerateConfig{
		Techniques: []string{"T1059"},
		Severity:   "apocalyptic",
	})
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestGenerate_ManualStageTypeHasNoCommands(t *testing.T) {
	res, err := Generate(&GenerateConfig{
		Techniques: []string{"T1059"},
		StageType:  "manual",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := res.Campaign.Stages[0]
	if len(s.Execute.Commands) != 0 {
		t.Errorf("expected no commands for manual stage type, got %v", s.Execute.Commands)
	}
	if s.Execute.Payload == "" {
		t.Error("expected a payload description for manual stage type")
	}
}

func TestGenerate_CampaignHasGeneratedTag(t *testing.T) {
	res, err := Generate(&GenerateConfig{Profile: "ai-red-team"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, tag := range res.Campaign.Meta.Tags {
		if tag == "generated" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected \"generated\" tag, got %v", res.Campaign.Meta.Tags)
	}
}

func TestGenerate_DefaultDescriptionWhenEmpty(t *testing.T) {
	res, err := Generate(&GenerateConfig{Techniques: []string{"T1059", "T1053"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Campaign.Meta.Description == "" {
		t.Error("expected a generated default description")
	}
}
