// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// hexSHA256 matches a 64-character lowercase hex string.
var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func baseCampaign() *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:         "test-campaign",
			Adversary:    "TestActor",
			Severity:     "medium",
			MitreVersion: "15.1",
		},
		Variables: map[string]string{
			"target_host": "10.0.0.1",
		},
		Stages: []Stage{
			{
				ID:        "recon",
				Name:      "Network Scan",
				Technique: "T1016",
				Tactic:    "discovery",
				Execute:   Execute{Type: "shell"},
				Expect: Expect{
					Telemetry:  []string{"process_create"},
					Detections: []string{"scan_detected"},
				},
			},
			{
				ID:        "access",
				Name:      "Initial Access",
				Technique: "T1190",
				Tactic:    "initial-access",
				DependsOn: []string{"recon"},
				Execute:   Execute{Type: "shell"},
				Expect: Expect{
					Telemetry:  []string{"network_connection"},
					Detections: []string{"exploit_attempt"},
				},
			},
		},
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	c := baseCampaign()
	h1 := Fingerprint(c)
	h2 := Fingerprint(c)
	if h1 != h2 {
		t.Errorf("same campaign produced different hashes: %q vs %q", h1, h2)
	}
}

func TestFingerprint_HexFormat(t *testing.T) {
	c := baseCampaign()
	h := Fingerprint(c)
	if !hexSHA256.MatchString(h) {
		t.Errorf("fingerprint %q is not a 64-char hex string", h)
	}
}

func TestFingerprint_DifferentContentDifferentHash(t *testing.T) {
	c1 := baseCampaign()
	c2 := baseCampaign()
	c2.Meta.Name = "different-campaign"

	h1 := Fingerprint(c1)
	h2 := Fingerprint(c2)
	if h1 == h2 {
		t.Error("different campaigns produced the same hash")
	}
}

func TestFingerprint_DifferentSeverityDifferentHash(t *testing.T) {
	c1 := baseCampaign()
	c2 := baseCampaign()
	c2.Meta.Severity = "critical"

	h1 := Fingerprint(c1)
	h2 := Fingerprint(c2)
	if h1 == h2 {
		t.Error("different severities produced the same hash")
	}
}

func TestFingerprint_StageOrderIndependent(t *testing.T) {
	c1 := baseCampaign()

	// Reverse the stage order.
	c2 := baseCampaign()
	c2.Stages[0], c2.Stages[1] = c2.Stages[1], c2.Stages[0]

	h1 := Fingerprint(c1)
	h2 := Fingerprint(c2)
	if h1 != h2 {
		t.Errorf("stage order affected hash: %q vs %q", h1, h2)
	}
}

func TestFingerprint_TelemetryOrderIndependent(t *testing.T) {
	c1 := baseCampaign()
	c1.Stages[0].Expect.Telemetry = []string{"alpha", "beta", "gamma"}

	c2 := baseCampaign()
	c2.Stages[0].Expect.Telemetry = []string{"gamma", "alpha", "beta"}

	h1 := Fingerprint(c1)
	h2 := Fingerprint(c2)
	if h1 != h2 {
		t.Errorf("telemetry order affected hash: %q vs %q", h1, h2)
	}
}

func TestFingerprint_DetectionsOrderIndependent(t *testing.T) {
	c1 := baseCampaign()
	c1.Stages[0].Expect.Detections = []string{"rule_b", "rule_a"}

	c2 := baseCampaign()
	c2.Stages[0].Expect.Detections = []string{"rule_a", "rule_b"}

	h1 := Fingerprint(c1)
	h2 := Fingerprint(c2)
	if h1 != h2 {
		t.Errorf("detections order affected hash: %q vs %q", h1, h2)
	}
}

func TestFingerprint_DependsOnOrderIndependent(t *testing.T) {
	c1 := baseCampaign()
	c1.Stages[1].DependsOn = []string{"recon", "enum"}

	c2 := baseCampaign()
	c2.Stages[1].DependsOn = []string{"enum", "recon"}

	h1 := Fingerprint(c1)
	h2 := Fingerprint(c2)
	if h1 != h2 {
		t.Errorf("depends_on order affected hash: %q vs %q", h1, h2)
	}
}

func TestFingerprint_EmptyCampaign(t *testing.T) {
	c := &Campaign{}
	h := Fingerprint(c)
	if !hexSHA256.MatchString(h) {
		t.Errorf("empty campaign fingerprint %q is not a 64-char hex string", h)
	}
	if h == "" {
		t.Error("empty campaign produced empty fingerprint")
	}
}

func TestFingerprint_VariablesAffectHash(t *testing.T) {
	c1 := baseCampaign()
	c2 := baseCampaign()
	c2.Variables["target_host"] = "192.168.1.1"

	h1 := Fingerprint(c1)
	h2 := Fingerprint(c2)
	if h1 == h2 {
		t.Error("different variables produced the same hash")
	}
}

func TestFingerprint_VariablesSortedByKey(t *testing.T) {
	c1 := baseCampaign()
	c1.Variables = map[string]string{"a": "1", "b": "2", "c": "3"}

	c2 := baseCampaign()
	c2.Variables = map[string]string{"c": "3", "a": "1", "b": "2"}

	h1 := Fingerprint(c1)
	h2 := Fingerprint(c2)
	if h1 != h2 {
		t.Errorf("variable map ordering affected hash: %q vs %q", h1, h2)
	}
}

func TestFingerprint_DoesNotMutateOriginal(t *testing.T) {
	c := baseCampaign()
	c.Stages[0].Expect.Telemetry = []string{"z", "a", "m"}
	original := make([]string, len(c.Stages[0].Expect.Telemetry))
	copy(original, c.Stages[0].Expect.Telemetry)

	Fingerprint(c)

	for i, v := range c.Stages[0].Expect.Telemetry {
		if v != original[i] {
			t.Errorf("Fingerprint mutated telemetry: got %v, want %v",
				c.Stages[0].Expect.Telemetry, original)
			break
		}
	}
}

func TestFingerprintFile(t *testing.T) {
	h, err := FingerprintFile("testdata/valid-campaign/campaign.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hexSHA256.MatchString(h) {
		t.Errorf("fingerprint %q is not a 64-char hex string", h)
	}
}

func TestFingerprintFile_Directory(t *testing.T) {
	h, err := FingerprintFile("testdata/valid-campaign")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hexSHA256.MatchString(h) {
		t.Errorf("fingerprint %q is not a 64-char hex string", h)
	}
}

func TestFingerprintFile_MissingFile(t *testing.T) {
	_, err := FingerprintFile("testdata/nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestFingerprintDir(t *testing.T) {
	fps, err := FingerprintDir("testdata")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fps) == 0 {
		t.Fatal("expected at least one fingerprint, got 0")
	}
	h, ok := fps["test-campaign"]
	if !ok {
		t.Fatal("test-campaign not found in FingerprintDir results")
	}
	if !hexSHA256.MatchString(h) {
		t.Errorf("fingerprint %q is not a 64-char hex string", h)
	}
}

func TestFingerprintDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	fps, err := FingerprintDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fps) != 0 {
		t.Errorf("expected 0 fingerprints for empty dir, got %d", len(fps))
	}
}

func TestFingerprintDir_NoSuchDir(t *testing.T) {
	_, err := FingerprintDir(filepath.Join(os.TempDir(), "nonexistent-hash-dir"))
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

func TestFingerprintManifest_Deterministic(t *testing.T) {
	h1, err := FingerprintManifest("testdata")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := FingerprintManifest("testdata")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 != h2 {
		t.Errorf("manifest hashes differ across calls: %q vs %q", h1, h2)
	}
	if !hexSHA256.MatchString(h1) {
		t.Errorf("manifest hash %q is not a 64-char hex string", h1)
	}
}

func TestFingerprintManifest_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	h, err := FingerprintManifest(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hexSHA256.MatchString(h) {
		t.Errorf("empty dir manifest %q is not a 64-char hex string", h)
	}
}

func TestFingerprintManifest_ChangesWithContent(t *testing.T) {
	// Create a temp dir with two campaign subdirectories.
	dir := t.TempDir()

	mkCampaign := func(subdir, name string) {
		d := filepath.Join(dir, subdir)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		yaml := "api_version: v1\nkind: Campaign\nmeta:\n  name: " + name +
			"\n  adversary: A\n  severity: low\n  mitre_version: \"15\"\nstages:\n" +
			"  - id: s1\n    name: Step\n    technique: T1001\n    tactic: exfil\n" +
			"    execute:\n      type: shell\n"
		if err := os.WriteFile(filepath.Join(d, "campaign.yaml"), []byte(yaml), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mkCampaign("camp-a", "alpha")
	mkCampaign("camp-b", "bravo")

	h1, err := FingerprintManifest(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Change one campaign's name.
	mkCampaign("camp-b", "bravo-modified")

	h2, err := FingerprintManifest(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if h1 == h2 {
		t.Error("manifest hash did not change when a campaign was modified")
	}
}
