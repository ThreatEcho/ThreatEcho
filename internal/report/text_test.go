// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/engine"
)

func makeRunResult() *engine.RunResult {
	c := &campaign.Campaign{
		Meta: campaign.Meta{
			Name:      "test-campaign",
			Adversary: "TestActor",
			Objective: "Test objective",
			Severity:  "critical",
		},
		Stages: []campaign.Stage{
			{
				ID: "s1", Name: "Stage 1", Technique: "T1059.001", Tactic: "execution",
				Execute: campaign.Execute{Type: "shell", Commands: []string{"echo test"}},
				Expect:  campaign.Expect{Telemetry: []string{"process_create"}, Detections: []string{"powershell_detected"}},
			},
			{
				ID: "s2", Name: "Stage 2", Technique: "T1566.001", Tactic: "initial-access",
				Execute: campaign.Execute{Type: "http", Target: "https://evil.com"},
				Expect:  campaign.Expect{Telemetry: []string{"network_connection"}},
			},
		},
	}

	return &engine.RunResult{
		Campaign:  c,
		Mode:      "simulate",
		Completed: 1,
		Skipped:   1,
		Stages: []engine.StageResult{
			{Stage: c.Stages[0], Order: 1, Skipped: false},
			{Stage: c.Stages[1], Order: 2, Skipped: true, SkipMsg: "platform mismatch"},
		},
	}
}

func TestTextReport_ContainsHeader(t *testing.T) {
	r := makeRunResult()
	var buf bytes.Buffer
	TextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "Adversary Campaign") {
		t.Error("missing header")
	}
}

func TestTextReport_ContainsCampaignInfo(t *testing.T) {
	r := makeRunResult()
	var buf bytes.Buffer
	TextReport(&buf, r)
	out := buf.String()
	for _, want := range []string{"test-campaign", "TestActor", "Test objective"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output", want)
		}
	}
}

func TestTextReport_ShowsSeverity(t *testing.T) {
	r := makeRunResult()
	var buf bytes.Buffer
	TextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "CRITICAL") {
		t.Error("missing severity display")
	}
}

func TestTextReport_ShowsStages(t *testing.T) {
	r := makeRunResult()
	var buf bytes.Buffer
	TextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "Stage 1") {
		t.Error("missing stage name")
	}
	if !strings.Contains(out, "SKIPPED") {
		t.Error("missing skipped indicator")
	}
}

func TestTextReport_ShowsTacticCoverage(t *testing.T) {
	r := makeRunResult()
	var buf bytes.Buffer
	TextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "COVERAGE SUMMARY") {
		t.Error("missing coverage summary section")
	}
	if !strings.Contains(out, "/14") {
		t.Error("missing tactic coverage fraction")
	}
}

func TestTextReport_ShowsTelemetry(t *testing.T) {
	r := makeRunResult()
	var buf bytes.Buffer
	TextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "process_create") {
		t.Error("missing telemetry type")
	}
}

func TestTextReport_ShowsDetections(t *testing.T) {
	r := makeRunResult()
	var buf bytes.Buffer
	TextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "powershell_detected") {
		t.Error("missing detection rule")
	}
}

func TestTextReport_ShowsExecuteType(t *testing.T) {
	r := makeRunResult()
	var buf bytes.Buffer
	TextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "shell") {
		t.Error("missing execute type")
	}
}

func TestTextReport_ShowsSkipReason(t *testing.T) {
	r := makeRunResult()
	var buf bytes.Buffer
	TextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "platform mismatch") {
		t.Error("missing skip reason")
	}
}

func TestTextReport_ShowsDependencies(t *testing.T) {
	r := makeRunResult()
	// Modify the stage and its result to have deps and not be skipped.
	r.Campaign.Stages[1].DependsOn = []string{"s1"}
	r.Stages[1] = engine.StageResult{
		Stage:   r.Campaign.Stages[1],
		Order:   2,
		Skipped: false,
	}
	r.Completed = 2
	r.Skipped = 0
	var buf bytes.Buffer
	TextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "Depends on") {
		t.Error("missing dependency display")
	}
}

func TestTitleCase(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"simulate", "Simulate"},
		{"live", "Live"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := titleCase(tt.in); got != tt.want {
			t.Errorf("titleCase(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSeverityColor(t *testing.T) {
	// Verify all severity levels produce output containing the uppercase name.
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		got := severityColor(sev)
		if !strings.Contains(got, strings.ToUpper(sev)) {
			t.Errorf("severityColor(%q) = %q, missing %q", sev, got, strings.ToUpper(sev))
		}
	}
}

func TestSeverityColor_Unknown(t *testing.T) {
	got := severityColor("unknown")
	if got != "unknown" {
		t.Errorf("severityColor(unknown) = %q, want %q", got, "unknown")
	}
}
