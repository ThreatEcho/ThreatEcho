// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"strings"
	"testing"
)

func TestListTemplates(t *testing.T) {
	templates := ListTemplates()

	if len(templates) != 7 {
		t.Fatalf("expected 7 templates, got %d", len(templates))
	}

	// Verify sorted order.
	expected := []string{"agent-hijack", "apt", "cloud", "insider", "minimal", "ransomware", "supply-chain"}
	for i, tmpl := range templates {
		if tmpl.Name != expected[i] {
			t.Errorf("template[%d]: expected name %q, got %q", i, expected[i], tmpl.Name)
		}
	}

	// Every template must have a description and framework.
	for _, tmpl := range templates {
		if tmpl.Description == "" {
			t.Errorf("template %q: missing description", tmpl.Name)
		}
		if tmpl.Framework == "" {
			t.Errorf("template %q: missing framework", tmpl.Name)
		}
		if len(tmpl.Tags) == 0 {
			t.Errorf("template %q: missing tags", tmpl.Name)
		}
	}
}

func TestGenerateCampaign_APT(t *testing.T) {
	c, err := GenerateCampaign("apt", "test-apt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.Meta.Name != "test-apt" {
		t.Errorf("expected meta.name %q, got %q", "test-apt", c.Meta.Name)
	}
	if c.Meta.Adversary != "Custom APT" {
		t.Errorf("expected adversary %q, got %q", "Custom APT", c.Meta.Adversary)
	}
	if c.Meta.Severity != "critical" {
		t.Errorf("expected severity %q, got %q", "critical", c.Meta.Severity)
	}

	if len(c.Stages) != 7 {
		t.Fatalf("expected 7 stages, got %d", len(c.Stages))
	}

	// Verify techniques.
	expectedTechniques := []string{"T1566.001", "T1059.001", "T1547.001", "T1027", "T1071.001", "T1021.001", "T1041"}
	for i, stage := range c.Stages {
		if stage.Technique != expectedTechniques[i] {
			t.Errorf("stage %d (%s): expected technique %q, got %q", i, stage.ID, expectedTechniques[i], stage.Technique)
		}
	}

	// Verify dependency chain: each stage after the first depends on the previous.
	for i := 1; i < len(c.Stages); i++ {
		if len(c.Stages[i].DependsOn) == 0 {
			t.Errorf("stage %d (%s): expected depends_on, got none", i, c.Stages[i].ID)
		} else if c.Stages[i].DependsOn[0] != c.Stages[i-1].ID {
			t.Errorf("stage %d (%s): expected depends_on %q, got %q", i, c.Stages[i].ID, c.Stages[i-1].ID, c.Stages[i].DependsOn[0])
		}
	}

	// First stage has no depends_on.
	if len(c.Stages[0].DependsOn) != 0 {
		t.Errorf("first stage should have no depends_on, got %v", c.Stages[0].DependsOn)
	}

	// Verify variables.
	if c.Variables["c2_server"] == "" {
		t.Error("expected c2_server variable")
	}
	if c.Variables["payload_name"] == "" {
		t.Error("expected payload_name variable")
	}
}

func TestGenerateCampaign_Ransomware(t *testing.T) {
	c, err := GenerateCampaign("ransomware", "test-ransom")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.Meta.Adversary != "Ransomware Operator" {
		t.Errorf("expected adversary %q, got %q", "Ransomware Operator", c.Meta.Adversary)
	}
	if c.Meta.Severity != "critical" {
		t.Errorf("expected severity %q, got %q", "critical", c.Meta.Severity)
	}
	if len(c.Stages) != 7 {
		t.Fatalf("expected 7 stages, got %d", len(c.Stages))
	}

	// Last stage should be encrypt-data with T1486 (impact).
	last := c.Stages[len(c.Stages)-1]
	if last.ID != "encrypt-data" {
		t.Errorf("expected last stage ID %q, got %q", "encrypt-data", last.ID)
	}
	if last.Technique != "T1486" {
		t.Errorf("expected technique %q, got %q", "T1486", last.Technique)
	}
	if last.Tactic != "impact" {
		t.Errorf("expected tactic %q, got %q", "impact", last.Tactic)
	}

	// Verify variables.
	if c.Variables["ransom_note"] == "" {
		t.Error("expected ransom_note variable")
	}
	if c.Variables["encryption_key"] == "" {
		t.Error("expected encryption_key variable")
	}
}

func TestGenerateCampaign_Insider(t *testing.T) {
	c, err := GenerateCampaign("insider", "test-insider")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.Meta.Adversary != "Insider Threat" {
		t.Errorf("expected adversary %q, got %q", "Insider Threat", c.Meta.Adversary)
	}
	if c.Meta.Severity != "high" {
		t.Errorf("expected severity %q, got %q", "high", c.Meta.Severity)
	}
	if len(c.Stages) != 4 {
		t.Fatalf("expected 4 stages, got %d", len(c.Stages))
	}

	// Verify stage IDs.
	expectedIDs := []string{"valid-accounts", "data-collection", "staging", "exfiltration"}
	for i, stage := range c.Stages {
		if stage.ID != expectedIDs[i] {
			t.Errorf("stage %d: expected ID %q, got %q", i, expectedIDs[i], stage.ID)
		}
	}

	// No variables expected for insider template.
	if len(c.Variables) != 0 {
		t.Errorf("expected no variables for insider, got %d", len(c.Variables))
	}
}

func TestGenerateCampaign_AgentHijack(t *testing.T) {
	c, err := GenerateCampaign("agent-hijack", "test-agent-hijack")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.Meta.Adversary != "AI Threat Actor" {
		t.Errorf("expected adversary %q, got %q", "AI Threat Actor", c.Meta.Adversary)
	}
	if c.Meta.Severity != "critical" {
		t.Errorf("expected severity %q, got %q", "critical", c.Meta.Severity)
	}
	if len(c.Stages) != 5 {
		t.Fatalf("expected 5 stages, got %d", len(c.Stages))
	}

	// Verify mixed framework techniques.
	expectedTechniques := []string{"AML.T0051", "AML.T0043", "LLM06", "AML.T0024", "AML.T0020"}
	for i, stage := range c.Stages {
		if stage.Technique != expectedTechniques[i] {
			t.Errorf("stage %d (%s): expected technique %q, got %q", i, stage.ID, expectedTechniques[i], stage.Technique)
		}
	}

	// Verify first stage uses ATLAS initial-access tactic.
	if c.Stages[0].Tactic != "initial-access" {
		t.Errorf("prompt-injection stage: expected tactic %q, got %q", "initial-access", c.Stages[0].Tactic)
	}
}

func TestGenerateCampaign_SupplyChain(t *testing.T) {
	c, err := GenerateCampaign("supply-chain", "test-supply-chain")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.Meta.Adversary != "Supply Chain Attacker" {
		t.Errorf("expected adversary %q, got %q", "Supply Chain Attacker", c.Meta.Adversary)
	}
	if c.Meta.Severity != "critical" {
		t.Errorf("expected severity %q, got %q", "critical", c.Meta.Severity)
	}
	if len(c.Stages) != 5 {
		t.Fatalf("expected 5 stages, got %d", len(c.Stages))
	}

	// First stage should be supply chain compromise.
	if c.Stages[0].Technique != "T1195.002" {
		t.Errorf("expected first technique %q, got %q", "T1195.002", c.Stages[0].Technique)
	}

	// Last stage should be credential access.
	last := c.Stages[len(c.Stages)-1]
	if last.Technique != "T1003" {
		t.Errorf("expected last technique %q, got %q", "T1003", last.Technique)
	}
	if last.Tactic != "credential-access" {
		t.Errorf("expected last tactic %q, got %q", "credential-access", last.Tactic)
	}
}

func TestGenerateCampaign_Cloud(t *testing.T) {
	c, err := GenerateCampaign("cloud", "test-cloud")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.Meta.Adversary != "Cloud Threat Actor" {
		t.Errorf("expected adversary %q, got %q", "Cloud Threat Actor", c.Meta.Adversary)
	}
	if c.Meta.Severity != "high" {
		t.Errorf("expected severity %q, got %q", "high", c.Meta.Severity)
	}
	if len(c.Stages) != 5 {
		t.Fatalf("expected 5 stages, got %d", len(c.Stages))
	}

	// Verify variables.
	if c.Variables["cloud_provider"] == "" {
		t.Error("expected cloud_provider variable")
	}
	if c.Variables["target_account"] == "" {
		t.Error("expected target_account variable")
	}

	// Verify first stage uses cloud-specific technique.
	if c.Stages[0].Technique != "T1078.004" {
		t.Errorf("expected first technique %q, got %q", "T1078.004", c.Stages[0].Technique)
	}
}

func TestGenerateCampaign_Minimal(t *testing.T) {
	c, err := GenerateCampaign("minimal", "test-minimal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.Meta.Adversary != "Unknown" {
		t.Errorf("expected adversary %q, got %q", "Unknown", c.Meta.Adversary)
	}
	if c.Meta.Severity != "low" {
		t.Errorf("expected severity %q, got %q", "low", c.Meta.Severity)
	}
	if len(c.Stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(c.Stages))
	}
	if c.Stages[0].Technique != "T1190" {
		t.Errorf("expected technique %q, got %q", "T1190", c.Stages[0].Technique)
	}
}

func TestGenerateCampaign_UnknownTemplate(t *testing.T) {
	_, err := GenerateCampaign("nonexistent", "test")
	if err == nil {
		t.Fatal("expected error for unknown template, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention the unknown template name, got: %v", err)
	}
}

func TestGenerateCampaign_CustomName(t *testing.T) {
	customName := "my-custom-campaign-2024"
	for _, tmplName := range []string{"apt", "ransomware", "insider", "agent-hijack", "supply-chain", "cloud", "minimal"} {
		t.Run(tmplName, func(t *testing.T) {
			c, err := GenerateCampaign(tmplName, customName)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Meta.Name != customName {
				t.Errorf("expected meta.name %q, got %q", customName, c.Meta.Name)
			}
		})
	}
}

func TestGenerateCampaign_ValidCampaign(t *testing.T) {
	templates := ListTemplates()
	for _, tmpl := range templates {
		t.Run(tmpl.Name, func(t *testing.T) {
			c, err := GenerateCampaign(tmpl.Name, fmt.Sprintf("test-%s", tmpl.Name))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			errs := Validate(c)
			if len(errs) > 0 {
				for _, e := range errs {
					t.Errorf("validation error: %s", e)
				}
			}
		})
	}
}

func TestGenerateCampaign_AllHaveTelemetry(t *testing.T) {
	templates := ListTemplates()
	for _, tmpl := range templates {
		t.Run(tmpl.Name, func(t *testing.T) {
			c, err := GenerateCampaign(tmpl.Name, fmt.Sprintf("test-%s", tmpl.Name))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for i, stage := range c.Stages {
				if len(stage.Expect.Telemetry) == 0 {
					t.Errorf("stage %d (%s): expected telemetry entries, got none", i, stage.ID)
				}
			}
		})
	}
}

func TestGenerateCampaign_DependencyChain(t *testing.T) {
	templates := ListTemplates()
	for _, tmpl := range templates {
		t.Run(tmpl.Name, func(t *testing.T) {
			c, err := GenerateCampaign(tmpl.Name, fmt.Sprintf("test-%s", tmpl.Name))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// First stage must have no depends_on.
			if len(c.Stages[0].DependsOn) != 0 {
				t.Errorf("first stage (%s) should have no depends_on, got %v", c.Stages[0].ID, c.Stages[0].DependsOn)
			}

			// Subsequent stages must have depends_on pointing to the previous stage.
			for i := 1; i < len(c.Stages); i++ {
				if len(c.Stages[i].DependsOn) == 0 {
					t.Errorf("stage %d (%s): expected depends_on, got none", i, c.Stages[i].ID)
					continue
				}
				if c.Stages[i].DependsOn[0] != c.Stages[i-1].ID {
					t.Errorf("stage %d (%s): expected depends_on[0] = %q, got %q",
						i, c.Stages[i].ID, c.Stages[i-1].ID, c.Stages[i].DependsOn[0])
				}
			}
		})
	}
}

func TestFormatTemplateList(t *testing.T) {
	output := FormatTemplateList()

	// Must contain all template names.
	expectedNames := []string{"agent-hijack", "apt", "cloud", "insider", "minimal", "ransomware", "supply-chain"}
	for _, name := range expectedNames {
		if !strings.Contains(output, name) {
			t.Errorf("FormatTemplateList output missing template %q", name)
		}
	}

	// Must contain header.
	if !strings.Contains(output, "NAME") {
		t.Error("FormatTemplateList output missing NAME header")
	}
	if !strings.Contains(output, "FRAMEWORK") {
		t.Error("FormatTemplateList output missing FRAMEWORK header")
	}
	if !strings.Contains(output, "DESCRIPTION") {
		t.Error("FormatTemplateList output missing DESCRIPTION header")
	}

	// Must contain framework types.
	if !strings.Contains(output, "attack") {
		t.Error("FormatTemplateList output missing 'attack' framework")
	}
	if !strings.Contains(output, "mixed") {
		t.Error("FormatTemplateList output missing 'mixed' framework")
	}
}

func TestGenerateCampaign_Variables(t *testing.T) {
	tests := []struct {
		template string
		vars     []string
	}{
		{"apt", []string{"c2_server", "payload_name"}},
		{"ransomware", []string{"ransom_note", "encryption_key"}},
		{"cloud", []string{"cloud_provider", "target_account"}},
	}

	for _, tc := range tests {
		t.Run(tc.template, func(t *testing.T) {
			c, err := GenerateCampaign(tc.template, fmt.Sprintf("test-%s", tc.template))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Variables == nil {
				t.Fatalf("expected variables map, got nil")
			}
			for _, v := range tc.vars {
				if _, ok := c.Variables[v]; !ok {
					t.Errorf("expected variable %q, not found in variables map", v)
				}
			}
		})
	}
}

func TestGenerateCampaign_APIVersionAndKind(t *testing.T) {
	templates := ListTemplates()
	for _, tmpl := range templates {
		t.Run(tmpl.Name, func(t *testing.T) {
			c, err := GenerateCampaign(tmpl.Name, fmt.Sprintf("test-%s", tmpl.Name))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.APIVersion != "v1" {
				t.Errorf("expected api_version %q, got %q", "v1", c.APIVersion)
			}
			if c.Kind != "Campaign" {
				t.Errorf("expected kind %q, got %q", "Campaign", c.Kind)
			}
		})
	}
}

func TestGenerateCampaign_ExecuteType(t *testing.T) {
	templates := ListTemplates()
	for _, tmpl := range templates {
		t.Run(tmpl.Name, func(t *testing.T) {
			c, err := GenerateCampaign(tmpl.Name, fmt.Sprintf("test-%s", tmpl.Name))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for i, stage := range c.Stages {
				if stage.Execute.Type != "shell" {
					t.Errorf("stage %d (%s): expected execute.type %q, got %q", i, stage.ID, "shell", stage.Execute.Type)
				}
				if len(stage.Execute.Commands) == 0 {
					t.Errorf("stage %d (%s): expected at least one command, got none", i, stage.ID)
				}
				for _, cmd := range stage.Execute.Commands {
					if !strings.Contains(cmd, "[SIM]") {
						t.Errorf("stage %d (%s): command should contain [SIM] marker, got %q", i, stage.ID, cmd)
					}
				}
			}
		})
	}
}

func TestGenerateCampaign_Timestamps(t *testing.T) {
	templates := ListTemplates()
	for _, tmpl := range templates {
		t.Run(tmpl.Name, func(t *testing.T) {
			c, err := GenerateCampaign(tmpl.Name, fmt.Sprintf("test-%s", tmpl.Name))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.Meta.Created == "" {
				t.Error("expected meta.created to be set")
			}
			if c.Meta.Modified == "" {
				t.Error("expected meta.modified to be set")
			}
			if c.Meta.Created != c.Meta.Modified {
				t.Errorf("expected created == modified for new campaign, got %q vs %q", c.Meta.Created, c.Meta.Modified)
			}
		})
	}
}

func TestGenerateCampaign_UniqueStageIDs(t *testing.T) {
	templates := ListTemplates()
	for _, tmpl := range templates {
		t.Run(tmpl.Name, func(t *testing.T) {
			c, err := GenerateCampaign(tmpl.Name, fmt.Sprintf("test-%s", tmpl.Name))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			seen := make(map[string]bool)
			for _, stage := range c.Stages {
				if seen[stage.ID] {
					t.Errorf("duplicate stage ID %q", stage.ID)
				}
				seen[stage.ID] = true
			}
		})
	}
}
