// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"strings"
	"testing"
)

func validCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "test",
			Adversary: "TestActor",
			Severity:  "high",
		},
		Stages: []Stage{
			{
				ID:        "stage-1",
				Name:      "First Stage",
				Technique: "T1566.001",
				Tactic:    "initial-access",
				Execute:   Execute{Type: "shell", Commands: []string{"echo test"}},
			},
			{
				ID:        "stage-2",
				Name:      "Second Stage",
				Technique: "T1021.002",
				Tactic:    "lateral-movement",
				DependsOn: []string{"stage-1"},
				Execute:   Execute{Type: "shell", Commands: []string{"echo test"}},
			},
		},
	}
}

func TestValidate_ValidCampaign(t *testing.T) {
	errs := Validate(validCampaign())
	if len(errs) > 0 {
		t.Errorf("expected no errors, got %d: %v", len(errs), errs)
	}
}

func TestValidate_MissingMetaName(t *testing.T) {
	c := validCampaign()
	c.Meta.Name = ""
	errs := Validate(c)
	if !containsError(errs, "meta.name is required") {
		t.Errorf("expected meta.name error, got: %v", errs)
	}
}

func TestValidate_MissingStages(t *testing.T) {
	c := validCampaign()
	c.Stages = nil
	errs := Validate(c)
	if !containsError(errs, "at least one stage") {
		t.Errorf("expected stages error, got: %v", errs)
	}
}

func TestValidate_InvalidTechnique(t *testing.T) {
	c := validCampaign()
	c.Stages[0].Technique = "INVALID"
	errs := Validate(c)
	if !containsError(errs, "doesn't match any supported format") {
		t.Errorf("expected technique format error, got: %v", errs)
	}
}

func TestValidate_ValidTechniqueFormats(t *testing.T) {
	tests := []struct {
		technique string
		valid     bool
	}{
		// ATT&CK
		{"T1566", true},
		{"T1566.001", true},
		{"T0000", true},
		{"T9999.999", true},
		// ATLAS
		{"AML.T0051", true},
		{"AML.T0015", true},
		// OWASP LLM
		{"LLM01", true},
		{"LLM10", true},
		// Invalid
		{"INVALID", false},
		{"T123", false},
		{"T12345", false},
		{"t1566", false},
		{"AML.T12345", false},
		{"LLM1", false},
	}
	for _, tt := range tests {
		t.Run(tt.technique, func(t *testing.T) {
			c := validCampaign()
			c.Stages[0].Technique = tt.technique
			errs := Validate(c)
			hasErr := containsError(errs, "doesn't match any supported format")
			if tt.valid && hasErr {
				t.Errorf("technique %q should be valid, got error", tt.technique)
			}
			if !tt.valid && !hasErr {
				t.Errorf("technique %q should be invalid, got no error", tt.technique)
			}
		})
	}
}

func TestValidate_InvalidTactic(t *testing.T) {
	c := validCampaign()
	c.Stages[0].Tactic = "not-a-tactic"
	errs := Validate(c)
	if !containsError(errs, "is not valid") {
		t.Errorf("expected tactic error, got: %v", errs)
	}
}

func TestValidate_ATLASTactic(t *testing.T) {
	c := validCampaign()
	c.Stages[0].Technique = "AML.T0051"
	c.Stages[0].Tactic = "ml-attack-staging"
	errs := Validate(c)
	if containsError(errs, "tactic") {
		t.Errorf("ATLAS tactic should be valid, got: %v", errs)
	}
}

func TestValidate_OWASPTechnique(t *testing.T) {
	c := validCampaign()
	c.Stages[0].Technique = "LLM01"
	errs := Validate(c)
	if containsError(errs, "doesn't match any supported format") {
		t.Errorf("OWASP LLM technique should be valid, got: %v", errs)
	}
}

func TestValidate_DuplicateStageIDs(t *testing.T) {
	c := validCampaign()
	c.Stages[1].ID = "stage-1" // same as stage 0
	c.Stages[1].DependsOn = nil
	errs := Validate(c)
	if !containsError(errs, "duplicate id") {
		t.Errorf("expected duplicate id error, got: %v", errs)
	}
}

func TestValidate_CycleDetection(t *testing.T) {
	c := &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta:       Meta{Name: "cycle-test", Adversary: "X", Severity: "low"},
		Stages: []Stage{
			{ID: "a", Name: "A", Technique: "T1566", Tactic: "initial-access", DependsOn: []string{"b"}, Execute: Execute{Type: "shell"}},
			{ID: "b", Name: "B", Technique: "T1021", Tactic: "lateral-movement", DependsOn: []string{"a"}, Execute: Execute{Type: "shell"}},
		},
	}
	errs := Validate(c)
	if !containsError(errs, "cycle") {
		t.Errorf("expected cycle error, got: %v", errs)
	}
}

func TestValidate_InvalidDependsOn(t *testing.T) {
	c := validCampaign()
	c.Stages[1].DependsOn = []string{"nonexistent"}
	errs := Validate(c)
	if !containsError(errs, "unknown stage") {
		t.Errorf("expected unknown stage error, got: %v", errs)
	}
}

func TestValidate_ValidDependsOn(t *testing.T) {
	c := validCampaign()
	// stage-2 depends on stage-1, which is valid
	errs := Validate(c)
	if containsError(errs, "unknown stage") {
		t.Errorf("did not expect unknown stage error, got: %v", errs)
	}
}

func TestValidate_InvalidSeverity(t *testing.T) {
	c := validCampaign()
	c.Meta.Severity = "extreme"
	errs := Validate(c)
	if !containsError(errs, "severity") {
		t.Errorf("expected severity error, got: %v", errs)
	}
}

func TestValidate_InvalidExecType(t *testing.T) {
	c := validCampaign()
	c.Stages[0].Execute.Type = "unknown"
	errs := Validate(c)
	if !containsError(errs, "execute.type") {
		t.Errorf("expected exec type error, got: %v", errs)
	}
}

func TestValidate_InvalidPlatform(t *testing.T) {
	c := validCampaign()
	c.Stages[0].Platform = []string{"solaris"}
	errs := Validate(c)
	if !containsError(errs, "platform") {
		t.Errorf("expected platform error, got: %v", errs)
	}
}

func TestValidate_MissingAPIVersion(t *testing.T) {
	c := validCampaign()
	c.APIVersion = ""
	errs := Validate(c)
	if !containsError(errs, "api_version") {
		t.Errorf("expected api_version error, got: %v", errs)
	}
}

func TestValidate_WrongKind(t *testing.T) {
	c := validCampaign()
	c.Kind = "Playbook"
	errs := Validate(c)
	if !containsError(errs, "kind must be") {
		t.Errorf("expected kind error, got: %v", errs)
	}
}

func containsError(errs []string, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}
