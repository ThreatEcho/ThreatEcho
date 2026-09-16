// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.CampaignsDir != "campaigns" {
		t.Errorf("CampaignsDir = %q, want %q", c.CampaignsDir, "campaigns")
	}
	if c.PoliciesDir != "policies" {
		t.Errorf("PoliciesDir = %q, want %q", c.PoliciesDir, "policies")
	}
	if c.DefaultFormat != "text" {
		t.Errorf("DefaultFormat = %q, want %q", c.DefaultFormat, "text")
	}
	if c.Author != "ThreatEcho" {
		t.Errorf("Author = %q, want %q", c.Author, "ThreatEcho")
	}
	if c.NoColor {
		t.Error("NoColor should be false by default")
	}
	if c.DefaultPolicy != "" {
		t.Errorf("DefaultPolicy = %q, want empty", c.DefaultPolicy)
	}
	if c.Output.SARIFCategory != "threatecho" {
		t.Errorf("SARIFCategory = %q, want %q", c.Output.SARIFCategory, "threatecho")
	}
	if c.Output.JUnitSuite != "ThreatEcho" {
		t.Errorf("JUnitSuite = %q, want %q", c.Output.JUnitSuite, "ThreatEcho")
	}
}

func TestMerge_NonZeroOverrides(t *testing.T) {
	base := Default()
	other := &Config{
		CampaignsDir:  "my-campaigns",
		DefaultFormat: "json",
		Author:        "SOC Team",
		NoColor:       true,
	}
	base.Merge(other)

	if base.CampaignsDir != "my-campaigns" {
		t.Errorf("CampaignsDir = %q, want %q", base.CampaignsDir, "my-campaigns")
	}
	if base.DefaultFormat != "json" {
		t.Errorf("DefaultFormat = %q, want %q", base.DefaultFormat, "json")
	}
	if base.Author != "SOC Team" {
		t.Errorf("Author = %q, want %q", base.Author, "SOC Team")
	}
	if !base.NoColor {
		t.Error("NoColor should be true after merge")
	}
	// Unset fields should keep defaults.
	if base.PoliciesDir != "policies" {
		t.Errorf("PoliciesDir = %q, want %q (unchanged)", base.PoliciesDir, "policies")
	}
	if base.Output.SARIFCategory != "threatecho" {
		t.Errorf("SARIFCategory = %q, want %q (unchanged)", base.Output.SARIFCategory, "threatecho")
	}
}

func TestMerge_NilSafe(t *testing.T) {
	c := Default()
	c.Merge(nil) // should not panic
	if c.CampaignsDir != "campaigns" {
		t.Error("Merge(nil) should not change anything")
	}
}

func TestMerge_OutputFields(t *testing.T) {
	base := Default()
	other := &Config{
		Output: OutputConfig{
			SARIFCategory: "security",
			JUnitSuite:    "Detection Tests",
		},
	}
	base.Merge(other)

	if base.Output.SARIFCategory != "security" {
		t.Errorf("SARIFCategory = %q, want %q", base.Output.SARIFCategory, "security")
	}
	if base.Output.JUnitSuite != "Detection Tests" {
		t.Errorf("JUnitSuite = %q, want %q", base.Output.JUnitSuite, "Detection Tests")
	}
}

func TestParseYAML(t *testing.T) {
	yaml := []byte(`
campaigns_dir: /opt/campaigns
default_format: sarif
author: "Red Team"
no_color: true
output:
  sarif_category: red-team
  junit_suite: "Red Team Tests"
`)
	c, err := ParseYAML(yaml)
	if err != nil {
		t.Fatalf("ParseYAML failed: %v", err)
	}
	if c.CampaignsDir != "/opt/campaigns" {
		t.Errorf("CampaignsDir = %q, want %q", c.CampaignsDir, "/opt/campaigns")
	}
	if c.DefaultFormat != "sarif" {
		t.Errorf("DefaultFormat = %q, want %q", c.DefaultFormat, "sarif")
	}
	if c.Author != "Red Team" {
		t.Errorf("Author = %q, want %q", c.Author, "Red Team")
	}
	if !c.NoColor {
		t.Error("NoColor should be true")
	}
	if c.Output.SARIFCategory != "red-team" {
		t.Errorf("SARIFCategory = %q, want %q", c.Output.SARIFCategory, "red-team")
	}
	if c.Output.JUnitSuite != "Red Team Tests" {
		t.Errorf("JUnitSuite = %q, want %q", c.Output.JUnitSuite, "Red Team Tests")
	}
}

func TestParseYAML_InvalidYAML(t *testing.T) {
	bad := []byte(`
campaigns_dir: [invalid
  not yaml at all:::
`)
	_, err := ParseYAML(bad)
	if err == nil {
		t.Fatal("expected parse error for invalid YAML")
	}
}

func TestParseYAML_PartialFields(t *testing.T) {
	yaml := []byte(`author: "Partial"`)
	c, err := ParseYAML(yaml)
	if err != nil {
		t.Fatalf("ParseYAML failed: %v", err)
	}
	if c.Author != "Partial" {
		t.Errorf("Author = %q, want %q", c.Author, "Partial")
	}
	// Unset fields are zero-valued.
	if c.CampaignsDir != "" {
		t.Errorf("CampaignsDir = %q, want empty", c.CampaignsDir)
	}
}

func TestLoadFrom(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := []byte(`
campaigns_dir: test-campaigns
author: "CI Bot"
output:
  junit_suite: "CI Suite"
`)
	if err := os.WriteFile(cfgPath, content, 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	c, err := LoadFrom(cfgPath)
	if err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}

	// Explicit fields from file.
	if c.CampaignsDir != "test-campaigns" {
		t.Errorf("CampaignsDir = %q, want %q", c.CampaignsDir, "test-campaigns")
	}
	if c.Author != "CI Bot" {
		t.Errorf("Author = %q, want %q", c.Author, "CI Bot")
	}
	if c.Output.JUnitSuite != "CI Suite" {
		t.Errorf("JUnitSuite = %q, want %q", c.Output.JUnitSuite, "CI Suite")
	}

	// Defaults for fields not in the file.
	if c.PoliciesDir != "policies" {
		t.Errorf("PoliciesDir = %q, want default %q", c.PoliciesDir, "policies")
	}
	if c.DefaultFormat != "text" {
		t.Errorf("DefaultFormat = %q, want default %q", c.DefaultFormat, "text")
	}
}

func TestLoadFrom_MissingFile(t *testing.T) {
	c, err := LoadFrom("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("LoadFrom should not error on missing file, got: %v", err)
	}
	// Should return defaults when file is missing.
	if c.CampaignsDir != "campaigns" {
		t.Errorf("CampaignsDir = %q, want default %q", c.CampaignsDir, "campaigns")
	}
}

func TestFindProjectConfig(t *testing.T) {
	// Create a temp directory tree:
	//   root/.threatecho.yaml
	//   root/sub/deep/
	root := t.TempDir()
	sub := filepath.Join(root, "sub", "deep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("creating dirs: %v", err)
	}

	cfgPath := filepath.Join(root, ".threatecho.yaml")
	if err := os.WriteFile(cfgPath, []byte("author: project\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// findProjectConfigFrom should find the config walking up from deep.
	found := findProjectConfigFrom(sub)
	if found != cfgPath {
		t.Errorf("findProjectConfigFrom(%q) = %q, want %q", sub, found, cfgPath)
	}
}

func TestFindProjectConfig_NotFound(t *testing.T) {
	// A temp directory with no .threatecho.yaml at any level.
	dir := t.TempDir()
	found := findProjectConfigFrom(dir)
	if found != "" {
		t.Errorf("expected empty string, got %q", found)
	}
}

func TestFindProjectConfig_InCwd(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".threatecho.yaml")
	if err := os.WriteFile(cfgPath, []byte("author: here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	found := findProjectConfigFrom(dir)
	if found != cfgPath {
		t.Errorf("findProjectConfigFrom(%q) = %q, want %q", dir, found, cfgPath)
	}
}

func TestEnvOverride(t *testing.T) {
	// Set up env vars.
	envs := map[string]string{
		"THREATECHO_CAMPAIGNS_DIR":  "env-campaigns",
		"THREATECHO_POLICIES_DIR":   "env-policies",
		"THREATECHO_DEFAULT_FORMAT": "junit",
		"THREATECHO_DEFAULT_POLICY": "env-policy/",
		"THREATECHO_AUTHOR":         "Env Author",
		"THREATECHO_NO_COLOR":       "1",
		"THREATECHO_SARIF_CATEGORY": "env-sarif",
		"THREATECHO_JUNIT_SUITE":    "Env Suite",
	}
	for k, v := range envs {
		t.Setenv(k, v)
	}

	c := Default()
	c.mergeEnv()

	if c.CampaignsDir != "env-campaigns" {
		t.Errorf("CampaignsDir = %q, want %q", c.CampaignsDir, "env-campaigns")
	}
	if c.PoliciesDir != "env-policies" {
		t.Errorf("PoliciesDir = %q, want %q", c.PoliciesDir, "env-policies")
	}
	if c.DefaultFormat != "junit" {
		t.Errorf("DefaultFormat = %q, want %q", c.DefaultFormat, "junit")
	}
	if c.DefaultPolicy != "env-policy/" {
		t.Errorf("DefaultPolicy = %q, want %q", c.DefaultPolicy, "env-policy/")
	}
	if c.Author != "Env Author" {
		t.Errorf("Author = %q, want %q", c.Author, "Env Author")
	}
	if !c.NoColor {
		t.Error("NoColor should be true from env")
	}
	if c.Output.SARIFCategory != "env-sarif" {
		t.Errorf("SARIFCategory = %q, want %q", c.Output.SARIFCategory, "env-sarif")
	}
	if c.Output.JUnitSuite != "Env Suite" {
		t.Errorf("JUnitSuite = %q, want %q", c.Output.JUnitSuite, "Env Suite")
	}
}

func TestEnvOverride_Partial(t *testing.T) {
	// Only set one env var; rest should keep defaults.
	t.Setenv("THREATECHO_AUTHOR", "Just Author")

	c := Default()
	c.mergeEnv()

	if c.Author != "Just Author" {
		t.Errorf("Author = %q, want %q", c.Author, "Just Author")
	}
	if c.CampaignsDir != "campaigns" {
		t.Errorf("CampaignsDir = %q, want default %q", c.CampaignsDir, "campaigns")
	}
}

func TestMerge_FileOverriddenByEnv(t *testing.T) {
	// Simulate: file sets author, env overrides it.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("author: File Author\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := LoadFrom(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.Author != "File Author" {
		t.Fatalf("Author = %q after file load, want %q", c.Author, "File Author")
	}

	t.Setenv("THREATECHO_AUTHOR", "Env Author")
	c.mergeEnv()

	if c.Author != "Env Author" {
		t.Errorf("Author = %q, want %q (env should override file)", c.Author, "Env Author")
	}
}

func TestEnvKeys(t *testing.T) {
	keys := EnvKeys()
	if len(keys) != 8 {
		t.Errorf("EnvKeys() returned %d keys, want 8", len(keys))
	}
	// Spot-check.
	found := false
	for _, k := range keys {
		if k == "THREATECHO_AUTHOR" {
			found = true
		}
	}
	if !found {
		t.Error("EnvKeys() missing THREATECHO_AUTHOR")
	}
}

func TestString(t *testing.T) {
	c := Default()
	s := c.String()
	if s == "" {
		t.Error("String() returned empty")
	}
	// Should contain key fields.
	for _, want := range []string{"campaigns_dir", "policies_dir", "author", "ThreatEcho"} {
		if !contains(s, want) {
			t.Errorf("String() missing %q", want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
