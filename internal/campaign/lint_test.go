// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"strings"
	"testing"
)

func TestLint_Clean(t *testing.T) {
	c := &Campaign{
		Meta: Meta{
			Name:         "clean-campaign",
			Adversary:    "test",
			Description:  "A well-documented campaign",
			Objective:    "Test the linter",
			MitreVersion: "15.1",
		},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Test Stage",
				Technique: "T1059",
				Tactic:    "execution",
				Execute:   Execute{Type: "shell", Commands: []string{"echo test"}},
				Expect:    Expect{Telemetry: []string{"process_create"}, Detections: []string{"cmd_detected"}},
			},
		},
	}

	lr := Lint(c)
	if lr.HasIssues() {
		t.Errorf("expected no warnings, got: %v", lr.Warnings)
	}
}

func TestLint_UnknownTechnique(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "unknown-tech", Adversary: "test", Description: "d", Objective: "o", MitreVersion: "15"},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Test",
				Technique: "T9999",
				Tactic:    "execution",
				Execute:   Execute{Type: "shell", Commands: []string{"echo"}},
				Expect:    Expect{Telemetry: []string{"x"}, Detections: []string{"y"}},
			},
		},
	}

	lr := Lint(c)
	found := false
	for _, w := range lr.Warnings {
		if strings.Contains(w, "T9999") && strings.Contains(w, "not found in registry") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about unknown technique T9999, got: %v", lr.Warnings)
	}
}

func TestLint_KnownTechniqueNoWarning(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "known-tech", Adversary: "test", Description: "d", Objective: "o", MitreVersion: "15"},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Test",
				Technique: "T1059",
				Tactic:    "execution",
				Execute:   Execute{Type: "shell", Commands: []string{"echo"}},
				Expect:    Expect{Telemetry: []string{"x"}, Detections: []string{"y"}},
			},
		},
	}

	lr := Lint(c)
	for _, w := range lr.Warnings {
		if strings.Contains(w, "T1059") && strings.Contains(w, "not found") {
			t.Errorf("should not warn about known technique T1059: %s", w)
		}
	}
}

func TestLint_MissingTelemetry(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "no-tel", Adversary: "test", Description: "d", Objective: "o", MitreVersion: "15"},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Test",
				Technique: "T1059",
				Tactic:    "execution",
				Execute:   Execute{Type: "shell", Commands: []string{"echo"}},
				// No Expect — no telemetry
			},
		},
	}

	lr := Lint(c)
	found := false
	for _, w := range lr.Warnings {
		if strings.Contains(w, "no expected telemetry") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about missing telemetry, got: %v", lr.Warnings)
	}
}

func TestLint_EmptyShellCommands(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "empty-shell", Adversary: "test", Description: "d", Objective: "o", MitreVersion: "15"},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Empty Shell",
				Technique: "T1059",
				Tactic:    "execution",
				Execute:   Execute{Type: "shell", Commands: []string{}},
				Expect:    Expect{Telemetry: []string{"x"}, Detections: []string{"y"}},
			},
		},
	}

	lr := Lint(c)
	found := false
	for _, w := range lr.Warnings {
		if strings.Contains(w, "shell stage with no commands") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about empty shell commands, got: %v", lr.Warnings)
	}
}

func TestLint_FrameworkMismatch(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "mismatch", Adversary: "test", Description: "d", Objective: "o", MitreVersion: "15"},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Mismatch",
				Technique: "T1059",           // ATT&CK
				Tactic:    "ml-model-access", // ATLAS tactic — wrong framework
				Execute:   Execute{Type: "shell", Commands: []string{"echo"}},
				Expect:    Expect{Telemetry: []string{"x"}, Detections: []string{"y"}},
			},
		},
	}

	lr := Lint(c)
	found := false
	for _, w := range lr.Warnings {
		if strings.Contains(w, "ATT&CK technique") && strings.Contains(w, "ATLAS tactic") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected framework mismatch warning, got: %v", lr.Warnings)
	}
}

func TestLint_MissingMeta(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "sparse", Adversary: "test"},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Test",
				Technique: "T1059",
				Tactic:    "execution",
				Execute:   Execute{Type: "shell", Commands: []string{"echo"}},
				Expect:    Expect{Telemetry: []string{"x"}, Detections: []string{"y"}},
			},
		},
	}

	lr := Lint(c)
	if len(lr.Info) < 3 {
		t.Errorf("expected at least 3 info (description, objective, mitre_version), got %d: %v", len(lr.Info), lr.Info)
	}
}

func TestLint_HTTPNoTarget(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "no-target", Adversary: "test", Description: "d", Objective: "o", MitreVersion: "15"},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "HTTP No Target",
				Technique: "T1071",
				Tactic:    "command-and-control",
				Execute:   Execute{Type: "http"},
				Expect:    Expect{Telemetry: []string{"network_connection"}, Detections: []string{"y"}},
			},
		},
	}

	lr := Lint(c)
	found := false
	for _, w := range lr.Warnings {
		if strings.Contains(w, "http stage with no target") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about HTTP stage with no target, got: %v", lr.Warnings)
	}
}

func TestLint_UnrecognizedTelemetry(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "bad-tel", Adversary: "test", Description: "d", Objective: "o", MitreVersion: "15"},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Bad Telemetry",
				Technique: "T1059",
				Tactic:    "execution",
				Execute:   Execute{Type: "shell", Commands: []string{"echo"}},
				Expect:    Expect{Telemetry: []string{"process_craete"}, Detections: []string{"det"}},
			},
		},
	}

	lr := Lint(c)
	found := false
	for _, w := range lr.Warnings {
		if strings.Contains(w, "unrecognized telemetry type") && strings.Contains(w, "process_craete") {
			found = true
			if !strings.Contains(w, "did you mean") {
				t.Errorf("expected suggestion for typo, got: %s", w)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected warning about unrecognized telemetry type, got: %v", lr.Warnings)
	}
}

func TestLint_ValidTelemetryNoWarning(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "good-tel", Adversary: "test", Description: "d", Objective: "o", MitreVersion: "15"},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Good Telemetry",
				Technique: "T1059",
				Tactic:    "execution",
				Execute:   Execute{Type: "shell", Commands: []string{"echo"}},
				Expect: Expect{
					Telemetry:  []string{"process_create", "file_create", "network_connection"},
					Detections: []string{"det"},
				},
			},
		},
	}

	lr := Lint(c)
	for _, w := range lr.Warnings {
		if strings.Contains(w, "unrecognized telemetry") {
			t.Errorf("should not warn about valid telemetry types: %s", w)
		}
	}
}

func TestLint_CompletelyUnknownTelemetry(t *testing.T) {
	c := &Campaign{
		Meta: Meta{Name: "unknown-tel", Adversary: "test", Description: "d", Objective: "o", MitreVersion: "15"},
		Stages: []Stage{
			{
				ID:        "s1",
				Name:      "Unknown Telemetry",
				Technique: "T1059",
				Tactic:    "execution",
				Execute:   Execute{Type: "shell", Commands: []string{"echo"}},
				Expect:    Expect{Telemetry: []string{"zzzzz_completely_unknown"}, Detections: []string{"det"}},
			},
		},
	}

	lr := Lint(c)
	found := false
	for _, w := range lr.Warnings {
		if strings.Contains(w, "unrecognized telemetry type") && strings.Contains(w, "see telemetry registry") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning with 'see telemetry registry' for completely unknown type, got: %v", lr.Warnings)
	}
}

func TestLint_BuiltinCampaignsNoUnrecognizedTelemetry(t *testing.T) {
	// All built-in campaigns should use only recognized telemetry types.
	summaries, err := LoadDir("../../campaigns")
	if err != nil {
		t.Skip("campaigns directory not found")
	}

	for _, s := range summaries {
		c, err := Load(s.Path)
		if err != nil {
			t.Fatalf("loading %s: %v", s.Path, err)
		}

		lr := Lint(c)
		for _, w := range lr.Warnings {
			if strings.Contains(w, "unrecognized telemetry type") {
				t.Errorf("built-in campaign %q has unrecognized telemetry: %s", c.Meta.Name, w)
			}
		}
	}
}
