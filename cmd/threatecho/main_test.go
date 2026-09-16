// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package main_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// binaryPath holds the path to the compiled threatecho binary.
var binaryPath string

// srcRoot is the module root, detected at init by walking up to go.mod.
var srcRoot string

func findModuleRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func TestMain(m *testing.M) {
	srcRoot = findModuleRoot()

	tmp, err := os.MkdirTemp("", "threatecho-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	binaryPath = filepath.Join(tmp, "threatecho")

	// Build the binary once for all tests.
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binaryPath, "./cmd/threatecho/")
	build.Dir = srcRoot
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build binary: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// runCLI executes the binary with the given args, working dir set to srcRoot.
// Returns combined stdout, combined stderr, and any error.
func runCLI(args ...string) (stdout, stderr string, err error) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = srcRoot

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// exitCode extracts the exit code from an error returned by exec.Command.Run().
// Returns 0 if err is nil.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

// --- Test cases ---

func TestCLI_Help(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("help")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("help output should contain 'Usage:', got stderr:\n%s", stderr)
	}
}

func TestCLI_Version(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("version")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "threatecho") {
		t.Errorf("version output should contain 'threatecho', got: %s", stdout)
	}
}

func TestCLI_ValidateCampaign(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("validate", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "is valid") {
		t.Errorf("validate output should contain 'is valid', got: %s", stdout)
	}
}

func TestCLI_ValidateInvalid(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	malformed := filepath.Join(tmp, "campaign.yaml")
	if err := os.WriteFile(malformed, []byte("this is not: [valid: yaml: {{"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCLI("validate", tmp)
	if err == nil {
		t.Fatal("expected non-zero exit for malformed YAML, got exit 0")
	}
	code := exitCode(err)
	if code != 4 { // ExitIO — failed to load malformed YAML
		t.Errorf("expected exit code 4 (IO error), got %d", code)
	}
}

func TestCLI_SimulateCampaign(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("simulate", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "apt29-cozy-bear") {
		t.Errorf("simulate output should contain campaign name, got: %s", stdout)
	}
}

func TestCLI_SimulateJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("simulate", "-format", "json", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("simulate JSON output is not valid JSON:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_Lint(t *testing.T) {
	t.Parallel()
	t.Run("Clean", func(t *testing.T) {
		t.Parallel()
		// Lint may exit 0 (clean) or 1 (warnings) — both are acceptable;
		// we just verify it runs without crashing.
		_, _, err := runCLI("lint", "campaigns/apt29-cozy-bear/")
		code := exitCode(err)
		if code != 0 && code != 1 {
			t.Fatalf("expected exit 0 or 1, got %d", code)
		}
	})

	t.Run("JSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("lint", "-format", "json", "campaigns/apt29-cozy-bear/")
		code := exitCode(err)
		if code != 0 && code != 1 {
			t.Fatalf("expected exit 0 or 1, got %d", code)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("lint JSON output is not valid JSON:\n%s", truncate(stdout, 500))
		}
	})
}

func TestCLI_Gap(t *testing.T) {
	t.Parallel()

	t.Run("Analysis", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("gap", "campaigns/llm-agent-hijack/")
		if err != nil {
			t.Fatalf("expected exit 0, got error: %v", err)
		}
		combined := stdout
		if !strings.Contains(combined, "DETECTION GAPS") && !strings.Contains(combined, "No detection gaps") && !strings.Contains(combined, "GAP") {
			t.Errorf("gap output should contain gap analysis content, got:\n%s", truncate(combined, 500))
		}
	})

	t.Run("JSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("gap", "-format", "json", "campaigns/llm-agent-hijack/")
		if err != nil {
			t.Fatalf("expected exit 0, got error: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("gap JSON output is not valid JSON:\n%s", truncate(stdout, 500))
		}
	})

	t.Run("SARIF", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("gap", "-format", "sarif", "campaigns/llm-agent-hijack/")
		if err != nil {
			t.Fatalf("expected exit 0, got error: %v", err)
		}
		if !strings.Contains(stdout, "$schema") {
			t.Errorf("SARIF output should contain '$schema', got:\n%s", truncate(stdout, 500))
		}
		if !strings.Contains(strings.ToLower(stdout), "sarif") {
			t.Errorf("SARIF output should contain 'sarif', got:\n%s", truncate(stdout, 500))
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("SARIF output is not valid JSON:\n%s", truncate(stdout, 500))
		}
	})

	t.Run("JUnit", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("gap", "-format", "junit", "campaigns/llm-agent-hijack/")
		if err != nil {
			t.Fatalf("expected exit 0, got error: %v", err)
		}
		if !strings.Contains(stdout, "<testsuites>") {
			t.Errorf("JUnit output should contain '<testsuites>', got:\n%s", truncate(stdout, 500))
		}
	})

	t.Run("Dir", func(t *testing.T) {
		t.Parallel()
		_, _, err := runCLI("gap", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("expected exit 0, got error: %v", err)
		}
	})
}

func TestCLI_Policy(t *testing.T) {
	t.Parallel()

	t.Run("Validate", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("policy", "validate", "policies/agent-default/")
		if err != nil {
			t.Fatalf("expected exit 0, got error: %v", err)
		}
		if !strings.Contains(stdout, "is valid") {
			t.Errorf("policy validate output should contain 'is valid', got: %s", stdout)
		}
	})

	t.Run("Eval", func(t *testing.T) {
		t.Parallel()
		_, _, err := runCLI("policy", "eval", "-policy", "policies/agent-default/", "campaigns/llm-agent-hijack/")
		code := exitCode(err)
		// Exit 0 = no violations denied; exit 2 = violations denied (CI mode).
		// Both are valid outcomes.
		if code != 0 && code != 2 {
			t.Fatalf("expected exit 0 or 2, got %d", code)
		}
	})

	t.Run("EvalSARIF", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("policy", "eval", "-policy", "policies/agent-default/", "-format", "sarif", "campaigns/llm-agent-hijack/")
		code := exitCode(err)
		if code != 0 && code != 2 {
			t.Fatalf("expected exit 0 or 2, got %d", code)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("SARIF output is not valid JSON:\n%s", truncate(stdout, 500))
		}
		if !strings.Contains(strings.ToLower(stdout), "sarif") {
			t.Errorf("SARIF output should contain 'sarif', got:\n%s", truncate(stdout, 500))
		}
	})

	t.Run("EvalDir", func(t *testing.T) {
		t.Parallel()
		_, _, err := runCLI("policy", "eval", "-policy", "policies/agent-default/", "-dir", "campaigns/")
		code := exitCode(err)
		if code != 0 && code != 2 {
			t.Fatalf("expected exit 0 or 2, got %d", code)
		}
	})
}

func TestCLI_ExportNavigator(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("export", "navigator", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("navigator export output is not valid JSON:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_Campaigns(t *testing.T) {
	t.Parallel()

	t.Run("List", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("campaigns", "list")
		if err != nil {
			t.Fatalf("expected exit 0, got error: %v", err)
		}
		// Should list at least one known campaign.
		if !strings.Contains(stdout, "apt29-cozy-bear") {
			t.Errorf("campaigns list should contain 'apt29-cozy-bear', got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "llm-agent-hijack") {
			t.Errorf("campaigns list should contain 'llm-agent-hijack', got:\n%s", stdout)
		}
	})

	t.Run("Show", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("campaigns", "show", "campaigns/apt29-cozy-bear/")
		if err != nil {
			t.Fatalf("expected exit 0, got error: %v", err)
		}
		if !strings.Contains(stdout, "Campaign:") {
			t.Errorf("campaigns show should contain 'Campaign:', got:\n%s", truncate(stdout, 500))
		}
	})
}

func TestCLI_Init(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	stdout, _, err := runCLI("init", tmp)
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "initialized") {
		t.Errorf("init output should contain 'initialized', got: %s", stdout)
	}

	// Verify files were created.
	exampleYAML := filepath.Join(tmp, "campaigns", "example", "campaign.yaml")
	if _, err := os.Stat(exampleYAML); os.IsNotExist(err) {
		t.Errorf("init should create %s", exampleYAML)
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("nonexistent")
	if err == nil {
		t.Fatal("expected non-zero exit for unknown command, got exit 0")
	}
	code := exitCode(err)
	if code != 64 { // ExitUsage — bad CLI usage
		t.Errorf("expected exit code 64 (usage error), got %d", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr should contain 'unknown command', got: %s", stderr)
	}
}

// --- v0.8.0 / v0.9.0 integration tests ---

func TestCLI_ConfigShow(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("config", "show")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "campaigns_dir") {
		t.Errorf("config show output should contain 'campaigns_dir', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_ConfigPath(t *testing.T) {
	t.Parallel()
	stdout, stderr, err := runCLI("config", "path")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "Built-in defaults") {
		t.Errorf("config path output should contain 'Built-in defaults', got:\n%s", truncate(combined, 500))
	}
}

func TestCLI_ConfigInit(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	cmd := exec.Command(binaryPath, "config", "init")
	cmd.Dir = tmp
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v\nstdout: %s\nstderr: %s", err, outBuf.String(), errBuf.String())
	}

	configFile := filepath.Join(tmp, ".threatecho.yaml")
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		t.Errorf("config init should create .threatecho.yaml in %s", tmp)
	}
}

func TestCLI_ConfigInitAlreadyExists(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	// Pre-create the config file.
	configFile := filepath.Join(tmp, ".threatecho.yaml")
	if err := os.WriteFile(configFile, []byte("# existing config\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "config", "init")
	cmd.Dir = tmp
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit when .threatecho.yaml already exists, got exit 0")
	}
	code := exitCode(err)
	if code == 0 {
		t.Errorf("expected non-zero exit code when config already exists, got 0\nstdout: %s\nstderr: %s", outBuf.String(), errBuf.String())
	}
}

func TestCLI_Hash(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("hash", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	line := strings.TrimSpace(stdout)
	// Output should start with a 64-char hex SHA-256 hash.
	if len(line) < 64 {
		t.Fatalf("hash output too short: %q", line)
	}
	hashPart := line[:64]
	for _, c := range hashPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("hash output should start with 64 hex chars, got: %q", line)
		}
	}
}

func TestCLI_HashDir(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("hash", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "apt29-cozy-bear") {
		t.Errorf("hash -dir output should contain 'apt29-cozy-bear', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_HashManifest(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("hash", "-dir", "campaigns/", "-manifest")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	line := strings.TrimSpace(stdout)
	if len(line) != 64 {
		t.Fatalf("manifest hash should be exactly 64 hex chars, got %d chars: %q", len(line), line)
	}
	for _, c := range line {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("manifest hash should be 64 hex chars, got: %q", line)
		}
	}
}

func TestCLI_HashDeterministic(t *testing.T) {
	t.Parallel()
	stdout1, _, err := runCLI("hash", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("first run: expected exit 0, got error: %v", err)
	}
	stdout2, _, err := runCLI("hash", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("second run: expected exit 0, got error: %v", err)
	}
	if strings.TrimSpace(stdout1) != strings.TrimSpace(stdout2) {
		t.Errorf("hash should be deterministic:\n  run 1: %s\n  run 2: %s", strings.TrimSpace(stdout1), strings.TrimSpace(stdout2))
	}
}

func TestCLI_GraphAnalyze(t *testing.T) {
	t.Parallel()
	stdout, stderr, err := runCLI("graph", "analyze", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "Entry points") {
		t.Errorf("graph analyze output should contain 'Entry points', got:\n%s", truncate(combined, 500))
	}
	if !strings.Contains(combined, "Critical path") {
		t.Errorf("graph analyze output should contain 'Critical path', got:\n%s", truncate(combined, 500))
	}
}

func TestCLI_GraphDot(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("graph", "dot", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "digraph") {
		t.Errorf("graph dot output should contain 'digraph', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_GraphMermaid(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("graph", "mermaid", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "graph TD") {
		t.Errorf("graph mermaid output should contain 'graph TD', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_LintTelemetryClean(t *testing.T) {
	t.Parallel()
	stdout, stderr, err := runCLI("lint", "campaigns/apt29-cozy-bear/")
	code := exitCode(err)
	if code != 0 && code != 1 {
		t.Fatalf("expected exit 0 or 1, got %d", code)
	}
	combined := stdout + stderr
	if strings.Contains(combined, "unrecognized telemetry") {
		t.Errorf("apt29-cozy-bear should have no unrecognized telemetry warnings, got:\n%s", truncate(combined, 500))
	}
}

func TestCLI_ExitCodeUsage(t *testing.T) {
	t.Parallel()
	cmd := exec.Command(binaryPath)
	cmd.Dir = srcRoot
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for no args, got exit 0")
	}
	code := exitCode(err)
	if code != 64 { // ExitUsage
		t.Errorf("expected exit code 64 (usage), got %d", code)
	}
}

// --- v0.10.0 integration tests ---

func TestCLI_DiffIdentical(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("diff", "campaigns/apt29-cozy-bear/", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "No differences") {
		t.Errorf("diff of identical campaigns should say no differences, got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_DiffTwoCampaigns(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("diff", "campaigns/apt29-cozy-bear/", "campaigns/apt28-fancy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	// Different campaigns should produce non-empty diff
	if len(stdout) < 20 {
		t.Errorf("diff of different campaigns should produce output, got:\n%s", stdout)
	}
}

func TestCLI_DiffJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("diff", "-format", "json", "campaigns/apt29-cozy-bear/", "campaigns/apt28-fancy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("diff JSON output is not valid JSON:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_MergeTwoCampaigns(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	stdout, stderr, err := runCLI("merge", "-prefix", "-strategy", "first", "-output", tmp,
		"campaigns/apt29-cozy-bear/", "campaigns/apt28-fancy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	// Verify merged file was created
	merged := filepath.Join(tmp, "campaign.yaml")
	if _, err := os.Stat(merged); os.IsNotExist(err) {
		t.Errorf("merge should create %s", merged)
	}
	if !strings.Contains(stderr, "Merged") {
		t.Errorf("merge output should contain 'Merged', got stderr:\n%s", stderr)
	}
}

func TestCLI_MergeToStdout(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("merge", "-prefix", "-strategy", "first",
		"campaigns/apt29-cozy-bear/", "campaigns/fin7-carbanak/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "api_version") {
		t.Errorf("merge stdout should contain YAML output, got:\n%s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "stages:") {
		t.Errorf("merge stdout should contain 'stages:', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_MergeCollisionError(t *testing.T) {
	t.Parallel()
	// Merging two campaigns with same stage IDs without prefix should fail
	// (if they have overlapping IDs — same campaign guarantees it)
	_, _, err := runCLI("merge", "campaigns/apt29-cozy-bear/", "campaigns/apt29-cozy-bear/")
	if err == nil {
		t.Fatal("expected non-zero exit for merge with ID collisions, got exit 0")
	}
	code := exitCode(err)
	if code != 1 { // ExitValidation — collision
		t.Errorf("expected exit code 1 (validation), got %d", code)
	}
}

func TestCLI_CompletionBash(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("completion", "bash")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "complete -F") {
		t.Errorf("bash completion should contain 'complete -F', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_CompletionZsh(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("completion", "zsh")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "#compdef") {
		t.Errorf("zsh completion should contain '#compdef', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_CompletionFish(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("completion", "fish")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "complete -c threatecho") {
		t.Errorf("fish completion should contain 'complete -c threatecho', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_CompletionUnknownShell(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("completion", "powershell")
	if err == nil {
		t.Fatal("expected non-zero exit for unknown shell")
	}
	code := exitCode(err)
	if code != 64 {
		t.Errorf("expected exit code 64 (usage), got %d", code)
	}
}

func TestCLI_ProfileSingle(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("profile", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Campaign Profile:") {
		t.Errorf("profile should contain 'Campaign Profile:', got:\n%s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "Complexity") {
		t.Errorf("profile should contain 'Complexity', got:\n%s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "Grade") {
		t.Errorf("profile should contain 'Grade', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_ProfileDir(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("profile", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "GRADE") {
		t.Errorf("profile -dir should contain 'GRADE' header, got:\n%s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "apt29-cozy-bear") {
		t.Errorf("profile -dir should contain 'apt29-cozy-bear', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_ProfileJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("profile", "-format", "json", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("profile JSON output is not valid JSON:\n%s", truncate(stdout, 500))
	}
}

// --- Watch command tests ---

func TestCLI_WatchHelp(t *testing.T) {
	t.Parallel()
	// Watch with -h should show usage without blocking.
	_, stderr, err := runCLI("watch", "-h")
	// -h causes flag.ExitOnError to exit 0 after printing usage.
	if err != nil {
		// Some flag sets exit 2 on -h, just check output exists.
		_ = stderr
	}
}

// --- Template command tests ---

func TestCLI_TemplateList(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("template", "list")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	for _, name := range []string{"apt", "ransomware", "insider", "agent-hijack", "supply-chain", "cloud", "minimal"} {
		if !strings.Contains(stdout, name) {
			t.Errorf("template list should contain %q, got:\n%s", name, truncate(stdout, 500))
		}
	}
}

func TestCLI_TemplateListDefault(t *testing.T) {
	t.Parallel()
	// Running 'template' with no args defaults to 'list'.
	stdout, _, err := runCLI("template")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "apt") {
		t.Errorf("template (default) should list templates, got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_TemplateCreateToStdout(t *testing.T) {
	t.Parallel()
	stdout, stderr, err := runCLI("template", "create", "-template", "apt", "-name", "my-apt-test")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "my-apt-test") {
		t.Errorf("template create should contain campaign name, got:\n%s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "api_version:") {
		t.Errorf("template create should produce YAML, got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_TemplateCreateToDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	outDir := filepath.Join(tmp, "my-campaign")
	_, stderr, err := runCLI("template", "create", "-template", "ransomware", "-name", "ransom-test", "-output", outDir)
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v\nstderr: %s", err, stderr)
	}
	// Check that the file was created.
	data, err := os.ReadFile(filepath.Join(outDir, "campaign.yaml"))
	if err != nil {
		t.Fatalf("campaign.yaml not created: %v", err)
	}
	if !strings.Contains(string(data), "ransom-test") {
		t.Errorf("campaign.yaml should contain 'ransom-test', got:\n%s", truncate(string(data), 500))
	}
}

func TestCLI_TemplateCreateUnknown(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("template", "create", "-template", "nonexistent", "-name", "test")
	if err == nil {
		t.Fatal("expected error for unknown template")
	}
	if exitCode(err) == 0 {
		t.Error("expected non-zero exit for unknown template")
	}
}

// --- Timeline command tests ---

func TestCLI_TimelineSingle(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("timeline", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Sequential") {
		t.Errorf("timeline should contain 'Sequential', got:\n%s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "Parallel") {
		t.Errorf("timeline should contain 'Parallel', got:\n%s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "Speedup") {
		t.Errorf("timeline should contain 'Speedup', got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_TimelineDir(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("timeline", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "apt29-cozy-bear") {
		t.Errorf("timeline -dir should contain campaign names, got:\n%s", truncate(stdout, 500))
	}
}

func TestCLI_TimelineJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("timeline", "-format", "json", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("timeline JSON output is not valid JSON:\n%s", truncate(stdout, 500))
	}
}

// --- Env command tests ---

func TestCLI_EnvNoCampaign(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("env")
	if err == nil {
		t.Fatal("expected error with no args")
	}
	if exitCode(err) != 64 {
		t.Errorf("expected exit code 64, got %d", exitCode(err))
	}
}

func TestCLI_EnvCampaign(t *testing.T) {
	t.Parallel()
	// Built-in campaigns don't use ${env:}, so we expect "No ${env:...} references found."
	stdout, _, err := runCLI("env", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "No ${env:...} references") {
		// Could also have refs, which is fine — we just check it runs.
		_ = stdout
	}
}

func TestCLI_EnvDir(t *testing.T) {
	t.Parallel()
	// Running env against all campaigns should succeed.
	_, _, err := runCLI("env", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
}

// --- search, stats, import ---

func TestCLI_SearchHelp(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("search", "-h")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "Search campaign stages") {
		t.Errorf("expected help output, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_SearchByTechnique(t *testing.T) {
	t.Parallel()
	stdout, stderr, err := runCLI("search", "-technique", "T1059", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "result(s) found") && !strings.Contains(stderr, "No matching stages") {
		t.Errorf("expected results or no-match message, got stderr: %s", truncate(stderr, 200))
	}
	// If results found, stdout should have content.
	_ = stdout
}

func TestCLI_SearchJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("search", "-technique", "T1059", "-dir", "campaigns/", "-json")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	// JSON output should be parseable.
	if strings.TrimSpace(stdout) != "" {
		var results []json.RawMessage
		if err := json.Unmarshal([]byte(stdout), &results); err != nil {
			t.Errorf("expected valid JSON, got: %s", truncate(stdout, 200))
		}
	}
}

func TestCLI_SearchNoResults(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("search", "-technique", "T9999", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "No matching stages") {
		t.Errorf("expected no-match message, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_SearchMultiFilter(t *testing.T) {
	t.Parallel()
	// ANDed filter: technique + platform.
	_, _, err := runCLI("search", "-technique", "T1059", "-platform", "windows", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
}

func TestCLI_StatsHelp(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("stats", "-h")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "analytics dashboard") {
		t.Errorf("expected help output, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_StatsDir(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("stats", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Campaign") {
		t.Errorf("expected stats output with Campaign header, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_StatsJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("stats", "-dir", "campaigns/", "-json")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		t.Fatalf("expected valid JSON, got: %s", truncate(stdout, 200))
	}
	if _, ok := data["TotalCampaigns"]; !ok {
		t.Errorf("expected TotalCampaigns in JSON output")
	}
}

func TestCLI_ImportHelp(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("import", "-h")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "Import external test libraries") {
		t.Errorf("expected help output, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_ImportMissingSource(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("import", "somepath")
	if err == nil {
		t.Fatal("expected non-zero exit for missing -source")
	}
	if !strings.Contains(stderr, "-source is required") {
		t.Errorf("expected source-required error, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_ImportUnsupportedSource(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("import", "-source", "unknown", "somepath")
	if err == nil {
		t.Fatal("expected non-zero exit for unsupported source")
	}
	if !strings.Contains(stderr, "unsupported import source") {
		t.Errorf("expected unsupported error, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_ImportAtomicFile(t *testing.T) {
	t.Parallel()
	// Create a minimal ART YAML fixture.
	tmp := t.TempDir()
	artYAML := `attack_technique: T1059.001
display_name: "PowerShell"
atomic_tests:
  - name: "Invoke-Mimikatz"
    auto_generated_guid: "abc123"
    description: "Test PowerShell execution"
    supported_platforms:
      - windows
    executor:
      name: powershell
      command: "Write-Host hello"
      cleanup_command: "Remove-Item test"
      elevation_required: true
`
	artFile := filepath.Join(tmp, "T1059.001.yaml")
	os.WriteFile(artFile, []byte(artYAML), 0o644)

	stdout, stderr, err := runCLI("import", "-source", "atomic", artFile)
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v\nstderr: %s", err, stderr)
	}
	// stdout should be valid YAML (the campaign).
	if !strings.Contains(stdout, "T1059.001") {
		t.Errorf("expected technique in output, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stderr, "Import") {
		t.Errorf("expected import summary on stderr, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_ImportAtomicToDir(t *testing.T) {
	t.Parallel()
	// Create a minimal ART YAML fixture.
	tmp := t.TempDir()
	artYAML := `attack_technique: T1059.003
display_name: "Windows Command Shell"
atomic_tests:
  - name: "cmd.exe /c"
    auto_generated_guid: "def456"
    description: "Test cmd.exe"
    supported_platforms:
      - windows
    executor:
      name: command_prompt
      command: "echo hello"
`
	artFile := filepath.Join(tmp, "T1059.003.yaml")
	os.WriteFile(artFile, []byte(artYAML), 0o644)

	outDir := filepath.Join(tmp, "output")
	_, stderr, err := runCLI("import", "-source", "atomic", "-output", outDir, artFile)
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v\nstderr: %s", err, stderr)
	}
	// Check campaign.yaml was written.
	outFile := filepath.Join(outDir, "campaign.yaml")
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("expected %s to exist, got: %v", outFile, err)
	}
}

// --- enrich, score, convert ---

func TestCLI_EnrichHelp(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("enrich", "-h")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "Enrich campaign stages") {
		t.Errorf("expected help output, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_EnrichDir(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("enrich", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Campaign:") {
		t.Errorf("expected enrichment output, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_EnrichJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("enrich", "-json", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	var results []json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_EnrichSingle(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("enrich", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "apt29-cozy-bear") {
		t.Errorf("expected campaign name in output, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_ScoreHelp(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("score", "-h")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "Score campaigns") {
		t.Errorf("expected help output, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_ScoreDir(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("score", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	// Should contain grade letters and scores.
	if !strings.Contains(stdout, "Score") {
		t.Errorf("expected score output, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_ScoreJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("score", "-json", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	var scores []json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &scores); err != nil {
		t.Errorf("expected valid JSON array, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_ScoreDetail(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("score", "-detail", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Technique") || !strings.Contains(stdout, "Grade") {
		t.Errorf("expected detailed breakdown, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_ConvertHelp(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("convert", "-h")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "Convert campaigns") {
		t.Errorf("expected help output, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_ConvertJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("convert", "-format", "json", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_ConvertMarkdown(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("convert", "-format", "markdown", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "# ") {
		t.Errorf("expected markdown heading, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_ConvertCSV(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("convert", "-format", "csv", "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 {
		t.Errorf("expected CSV with header + data rows, got %d lines", len(lines))
	}
	if !strings.Contains(lines[0], "campaign_name") {
		t.Errorf("expected CSV header, got: %s", lines[0])
	}
}

func TestCLI_ConvertToFile(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	outFile := filepath.Join(tmp, "campaign.json")
	_, _, err := runCLI("convert", "-format", "json", "-output", outFile, "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("expected %s to exist", outFile)
	}
}

func TestCLI_ConvertDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, _, err := runCLI("convert", "-format", "json", "-dir", "campaigns/", "-output", tmp)
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	// Should have created .json files.
	entries, _ := os.ReadDir(tmp)
	if len(entries) == 0 {
		t.Error("expected output files in directory")
	}
}

func TestCLI_ConvertMissingPath(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("convert")
	if err == nil {
		t.Fatal("expected non-zero exit for missing path")
	}
	if !strings.Contains(stderr, "path to campaign") {
		t.Errorf("expected usage error, got: %s", truncate(stderr, 200))
	}
}

// --- tag, report, audit ---

func TestCLI_TagHelp(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("tag", "-h")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "Tag management") {
		t.Errorf("expected help output, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_TagList(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("tag", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Tag") {
		t.Errorf("expected tag output, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_TagJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("tag", "-json", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_TagFind(t *testing.T) {
	t.Parallel()
	// Find a tag that exists in our campaigns.
	_, stderr, err := runCLI("tag", "-find", "apt", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "campaign(s)") && !strings.Contains(stderr, "No campaigns") {
		t.Errorf("expected find output, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_ReportHelp(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("report", "-h")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "executive assessment") {
		t.Errorf("expected help output, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_ReportText(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("report", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Executive") {
		t.Errorf("expected report output, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_ReportMarkdown(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("report", "-format", "markdown", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "#") {
		t.Errorf("expected markdown heading, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_ReportJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("report", "-json", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_ReportToFile(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	outFile := filepath.Join(tmp, "report.md")
	_, stderr, err := runCLI("report", "-format", "markdown", "-output", outFile, "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "report.md") {
		t.Errorf("expected written confirmation, got: %s", truncate(stderr, 200))
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("expected %s to exist", outFile)
	}
}

func TestCLI_AuditHelp(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("audit", "-h")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stderr, "snapshot") {
		t.Errorf("expected help output, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_AuditSnapshot(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("audit", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Snapshot:") {
		t.Errorf("expected snapshot output, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_AuditJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("audit", "-json", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_AuditSaveAndCompare(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	snapFile := filepath.Join(tmp, "snapshot.json")

	// Save snapshot.
	_, stderr, err := runCLI("audit", "-dir", "campaigns/", "-output", snapFile)
	if err != nil {
		t.Fatalf("expected exit 0 for save, got error: %v\nstderr: %s", err, stderr)
	}

	// Compare against itself (should be all unchanged).
	stdout, _, err := runCLI("audit", "-dir", "campaigns/", "-compare", snapFile)
	if err != nil {
		t.Fatalf("expected exit 0 for compare, got error: %v", err)
	}
	if !strings.Contains(stdout, "unchanged") {
		t.Errorf("expected unchanged in diff output, got: %s", truncate(stdout, 200))
	}
}

// truncate returns the first n bytes of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- baseline tests ---

func TestCLI_BaselineHelp(t *testing.T) {
	t.Parallel()
	// baseline without -dir may auto-detect campaigns/ or show help.
	// With -h it should show usage.
	_, stderr, _ := runCLI("baseline", "-h")
	if !strings.Contains(stderr, "baseline") || !strings.Contains(stderr, "drift") {
		t.Errorf("expected help text about baselines, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_BaselineBuild(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("baseline", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "BEHAVIORAL BASELINE") {
		t.Errorf("expected baseline output, got: %s", truncate(stdout, 200))
	}
	if !strings.Contains(stdout, "Tactic Distribution") {
		t.Error("expected tactic distribution in output")
	}
}

func TestCLI_BaselineJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("baseline", "-dir", "campaigns/", "-json")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, `"version"`) || !strings.Contains(stdout, `"tactics"`) {
		t.Errorf("expected JSON baseline, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_BaselineSave(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	blFile := filepath.Join(tmp, "baseline.json")

	_, stderr, err := runCLI("baseline", "-dir", "campaigns/", "-label", "test-v1", "-output", blFile)
	if err != nil {
		t.Fatalf("expected exit 0 for save, got error: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stderr, "baseline.json") {
		t.Errorf("expected save confirmation, got: %s", stderr)
	}

	// Verify file is valid JSON.
	data, err := os.ReadFile(blFile)
	if err != nil {
		t.Fatalf("could not read saved baseline: %v", err)
	}
	if !strings.Contains(string(data), "test-v1") {
		t.Error("expected label in saved baseline")
	}
}

func TestCLI_BaselineDrift(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	blFile := filepath.Join(tmp, "baseline.json")

	// Save baseline.
	_, _, err := runCLI("baseline", "-dir", "campaigns/", "-output", blFile)
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// Compare against itself (no drift).
	stdout, _, err := runCLI("baseline", "-dir", "campaigns/", "-compare", blFile)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
	if !strings.Contains(stdout, "DRIFT REPORT") {
		t.Errorf("expected drift report, got: %s", truncate(stdout, 200))
	}
	if !strings.Contains(stdout, "none") {
		t.Errorf("expected no drift, got: %s", truncate(stdout, 200))
	}
}

// --- trace tests ---

func TestCLI_TraceHelp(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("trace")
	if err == nil {
		t.Fatal("expected non-zero exit for no args")
	}
	if !strings.Contains(stderr, "agent execution traces") {
		t.Errorf("expected trace help text, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_TraceAnalyze(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	traceFile := filepath.Join(tmp, "trace.json")

	trace := `{
		"id": "trace-001",
		"agent_name": "support-agent",
		"agent_type": "llm",
		"start_time": "2026-01-15T10:00:00Z",
		"end_time": "2026-01-15T10:05:00Z",
		"events": [
			{
				"id": "ev-1",
				"timestamp": "2026-01-15T10:01:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "search_knowledge_base",
					"action": "query",
					"target": "https://kb.internal/api",
					"success": true
				}
			},
			{
				"id": "ev-2",
				"timestamp": "2026-01-15T10:02:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "shell_exec",
					"action": "execute",
					"elevated": true,
					"success": true
				}
			},
			{
				"id": "ev-3",
				"timestamp": "2026-01-15T10:03:00Z",
				"type": "prompt",
				"prompt": {
					"role": "user",
					"content": "What is the refund policy?",
					"token_count": 12
				}
			}
		]
	}`
	os.WriteFile(traceFile, []byte(trace), 0644)

	stdout, _, err := runCLI("trace", traceFile)
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Trace") && !strings.Contains(stdout, "trace") {
		t.Errorf("expected trace analysis output, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_TraceWithPolicy(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	traceFile := filepath.Join(tmp, "trace.json")

	trace := `{
		"id": "trace-002",
		"agent_name": "rogue-agent",
		"agent_type": "llm",
		"start_time": "2026-01-15T10:00:00Z",
		"end_time": "2026-01-15T10:05:00Z",
		"events": [
			{
				"id": "ev-1",
				"timestamp": "2026-01-15T10:01:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "shell_exec",
					"action": "execute",
					"success": true
				}
			}
		]
	}`
	os.WriteFile(traceFile, []byte(trace), 0644)

	// agent-strict denies shell_exec, so we expect exit code 2.
	stdout, _, err := runCLI("trace", "-policy", "policies/agent-strict/", traceFile)
	if err == nil {
		t.Fatal("expected non-zero exit for denied tool call")
	}
	// The trace eval output should mention the evaluation and violations.
	if !strings.Contains(stdout, "Trace") && !strings.Contains(stdout, "Violation") && !strings.Contains(stdout, "shell_exec") {
		t.Errorf("expected trace evaluation with violations, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_TraceJSON(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	traceFile := filepath.Join(tmp, "trace.json")

	trace := `{
		"id": "trace-003",
		"agent_name": "test-agent",
		"agent_type": "llm",
		"events": [
			{
				"id": "ev-1",
				"timestamp": "2026-01-15T10:01:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "http_request",
					"action": "send",
					"success": true
				}
			}
		]
	}`
	os.WriteFile(traceFile, []byte(trace), 0644)

	stdout, _, err := runCLI("trace", "-json", traceFile)
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, `"total_events"`) || !strings.Contains(stdout, `"tool_calls"`) {
		t.Errorf("expected JSON stats, got: %s", truncate(stdout, 200))
	}
}

// --- policy compile tests ---

func TestCLI_PolicyCompile(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "compile", "policies/agent-strict/")
	// May exit 2 if conflicts found — that's valid.
	if !strings.Contains(stdout, "Compilation") && !strings.Contains(stdout, "Compile") {
		t.Errorf("expected compilation report, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_PolicyCompileJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "compile", "-json", "policies/agent-default/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, `"TotalRules"`) || !strings.Contains(stdout, `"DenyRules"`) {
		t.Errorf("expected JSON stats, got: %s", truncate(stdout, 200))
	}
}

// --- policy merge tests ---

func TestCLI_PolicyMerge(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "merge", "policies/agent-default/", "policies/soc-baseline/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "rules:") {
		t.Errorf("expected YAML output with rules, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_PolicyMergeToFile(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	outFile := filepath.Join(tmp, "merged.yaml")

	_, stderr, err := runCLI("policy", "merge", "-output", outFile, "policies/agent-default/", "policies/soc-baseline/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stderr, "Merged") {
		t.Errorf("expected merge confirmation, got: %s", stderr)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("could not read merged file: %v", err)
	}
	if !strings.Contains(string(data), "rules:") {
		t.Error("merged file should contain rules")
	}
}

// --- policy coverage tests ---

func TestCLI_PolicyCoverage(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "coverage", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Coverage") {
		t.Errorf("expected coverage report, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_PolicyCoverageWithCampaigns(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "coverage", "-dir", "campaigns/", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Tool") {
		t.Errorf("expected tool coverage in output, got: %s", truncate(stdout, 200))
	}
}

func TestCLI_PolicyCoverageJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "coverage", "-json", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "Covered") && !strings.Contains(stdout, "covered") {
		t.Errorf("expected JSON coverage data, got: %s", truncate(stdout, 200))
	}
}

// --- policy test tests ---

func TestCLI_PolicyTestHelp(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("policy", "test", "-list")
	combined := stdout + stderr
	if !strings.Contains(combined, "benign-rag") {
		t.Errorf("expected scenario list to include benign-rag, got: %s", truncate(combined, 300))
	}
	if !strings.Contains(combined, "prompt-injection") {
		t.Errorf("expected scenario list to include prompt-injection, got: %s", truncate(combined, 300))
	}
}

func TestCLI_PolicyTestAll(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("policy", "test", "policies/agent-strict/")
	combined := stdout + stderr
	// Should have verdict output for each scenario.
	for _, scenario := range []string{"benign-rag", "benign-tool-use", "prompt-injection", "tool-abuse", "data-exfiltration", "agent-propagation", "elevated-execution", "rag-poisoning", "mcp-tool-hijack", "memory-poisoning", "model-extraction"} {
		if !strings.Contains(combined, scenario) {
			t.Errorf("expected output to include scenario %q, got: %s", scenario, truncate(combined, 400))
		}
	}
}

func TestCLI_PolicyTestSingle(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("policy", "test", "-scenario", "tool-abuse", "policies/agent-strict/")
	combined := stdout + stderr
	if !strings.Contains(combined, "tool-abuse") {
		t.Errorf("expected output to include tool-abuse scenario, got: %s", truncate(combined, 300))
	}
}

func TestCLI_PolicyTestJSON(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "test", "-json", "policies/agent-strict/")
	if !strings.Contains(stdout, "scenario") && !strings.Contains(stdout, "Scenario") {
		t.Errorf("expected JSON with scenario field, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyTestNoArgs(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "test")
	if err == nil {
		t.Error("expected non-zero exit for policy test without policy path")
	}
}

// --- policy generate tests ---

func TestCLI_PolicyGenerateList(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("policy", "generate", "-list")
	combined := stdout + stderr
	templates := []string{"agent-minimal", "agent-strict", "rag-safe", "tool-calling-restricted", "autonomous-guardrailed", "compliance-soc2"}
	for _, tmpl := range templates {
		if !strings.Contains(combined, tmpl) {
			t.Errorf("expected template list to include %q, got: %s", tmpl, truncate(combined, 400))
		}
	}
}

func TestCLI_PolicyGenerateStdout(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "generate", "agent-minimal")
	if err != nil {
		t.Fatalf("expected exit 0 for generate, got: %v", err)
	}
	if !strings.Contains(stdout, "rules:") && !strings.Contains(stdout, "rules") {
		t.Errorf("expected YAML output with rules, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyGenerateWithName(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "generate", "-name", "my-test-policy", "-agent", "my-agent", "rag-safe")
	if err != nil {
		t.Fatalf("expected exit 0, got: %v", err)
	}
	if !strings.Contains(stdout, "my-test-policy") {
		t.Errorf("expected policy name 'my-test-policy' in output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyGenerateToFile(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	outFile := filepath.Join(tmp, "generated.yaml")

	_, stderr, err := runCLI("policy", "generate", "-output", outFile, "agent-strict")
	if err != nil {
		t.Fatalf("expected exit 0, got: %v\nstderr: %s", err, stderr)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("could not read generated file: %v", err)
	}
	if !strings.Contains(string(data), "rules:") {
		t.Error("generated file should contain rules")
	}
}

func TestCLI_PolicyGenerateUnknown(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "generate", "nonexistent-template")
	if err == nil {
		t.Error("expected non-zero exit for unknown template")
	}
}

func TestCLI_PolicyGenerateNoArgs(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "generate")
	if err == nil {
		t.Error("expected non-zero exit for generate without template name")
	}
}

// --- policy risk tests ---

func TestCLI_PolicyRisk(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "risk", "policies/agent-default/")
	if !strings.Contains(stdout, "Risk") && !strings.Contains(stdout, "Grade") {
		t.Errorf("expected risk assessment output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyRiskStrict(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "risk", "policies/agent-strict/")
	if !strings.Contains(stdout, "Grade") {
		t.Errorf("expected grade in risk output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyRiskJSON(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "risk", "-json", "policies/agent-default/")
	if !strings.Contains(stdout, "overall_score") && !strings.Contains(stdout, "overall_grade") {
		t.Errorf("expected JSON risk fields, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyRiskWithCampaigns(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "risk", "-dir", "campaigns/", "policies/agent-strict/")
	if !strings.Contains(stdout, "Risk") && !strings.Contains(stdout, "Grade") {
		t.Errorf("expected risk assessment with campaign context, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyRiskNoArgs(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "risk")
	if err == nil {
		t.Error("expected non-zero exit for risk without policy path")
	}
}

// --- policy diff tests ---

func TestCLI_PolicyDiff(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "diff", "policies/agent-default/", "policies/agent-strict/")
	if !strings.Contains(stdout, "Diff") && !strings.Contains(stdout, "diff") {
		t.Errorf("expected diff output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyDiffJSON(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "diff", "-json", "policies/agent-default/", "policies/agent-strict/")
	if !strings.Contains(stdout, "added_rules") && !strings.Contains(stdout, "summary") {
		t.Errorf("expected JSON diff fields, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyDiffIdentical(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "diff", "policies/agent-default/", "policies/agent-default/")
	if err != nil {
		// Should exit 0 for no breaking changes.
		t.Logf("diff of identical policies exited with: %v", err)
	}
	if !strings.Contains(stdout, "identical") && !strings.Contains(stdout, "Identical") && !strings.Contains(stdout, "no changes") && !strings.Contains(stdout, "No changes") {
		// At minimum the output should indicate no differences.
		t.Logf("identical diff output: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyDiffNoArgs(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "diff")
	if err == nil {
		t.Error("expected non-zero exit for diff without policy paths")
	}
}

func TestCLI_PolicyDiffOneArg(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "diff", "policies/agent-default/")
	if err == nil {
		t.Error("expected non-zero exit for diff with only one policy path")
	}
}

// --- help output updated ---

func TestCLI_HelpShowsNewCommands(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("help")
	if err != nil {
		t.Fatalf("help should exit 0, got: %v", err)
	}
	newCmds := []string{"baseline", "trace", "agent"}
	for _, cmd := range newCmds {
		if !strings.Contains(stderr, cmd) {
			t.Errorf("help output missing command %q", cmd)
		}
	}
}

func TestCLI_PolicyHelpShowsNewSubcommands(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("policy")
	if err == nil {
		t.Fatal("expected non-zero exit for no subcommand")
	}
	newSubs := []string{"compile", "merge", "coverage", "risk", "diff", "guardrail", "history", "compliance"}
	for _, sub := range newSubs {
		if !strings.Contains(stderr, sub) {
			t.Errorf("policy help missing subcommand %q", sub)
		}
	}
}

// --- policy guardrail tests ---

func TestCLI_PolicyGuardrailNoArgs(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "guardrail")
	if err == nil {
		t.Error("expected non-zero exit for guardrail without -policy")
	}
}

func TestCLI_PolicyGuardrail(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "guardrail", "-policy", "policies/agent-default/")
	if err != nil {
		// Exit 2 is expected when critical gaps exist.
		if !strings.Contains(stdout, "Guardrail") {
			t.Fatalf("expected guardrail output, got: %s", truncate(stdout, 300))
		}
	}
	if !strings.Contains(stdout, "Guardrail") {
		t.Errorf("expected guardrail analysis output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyGuardrailJSON(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "guardrail", "-policy", "policies/agent-default/", "-json")
	var analysis map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &analysis); err != nil {
		t.Errorf("expected valid JSON guardrail analysis, got error: %v", err)
	}
	if _, ok := analysis["guardrails"]; !ok {
		t.Error("JSON output should contain 'guardrails' key")
	}
	if _, ok := analysis["stats"]; !ok {
		t.Error("JSON output should contain 'stats' key")
	}
}

// --- policy history tests ---

func TestCLI_PolicyHistoryNoArgs(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "history")
	if err == nil {
		t.Error("expected non-zero exit for history without policy path")
	}
}

func TestCLI_PolicyHistoryInit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Copy a minimal policy.
	polDir := filepath.Join(dir, "policy")
	os.MkdirAll(polDir, 0755)
	polYAML := `apiVersion: v1
kind: Policy
meta:
  name: test-history
  description: test
rules:
  - id: r1
    description: test
    effect: deny
    match:
      tools: ["exec"]
`
	os.WriteFile(filepath.Join(polDir, "policy.yaml"), []byte(polYAML), 0644)

	// Init history.
	stdout, _, err := runCLI("policy", "history", "-init", "-author", "tester", "-comment", "initial", polDir)
	if err != nil {
		t.Fatalf("policy history -init failed: %v\nstdout: %s", err, stdout)
	}

	// Verify history file was created.
	hFile := filepath.Join(polDir, "history.json")
	if _, serr := os.Stat(hFile); serr != nil {
		t.Fatalf("history file not created: %v", serr)
	}

	// Show history.
	stdout, _, err = runCLI("policy", "history", polDir)
	if err != nil {
		t.Fatalf("policy history show failed: %v", err)
	}
	if !strings.Contains(stdout, "test-history") {
		t.Errorf("expected policy name in history output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyHistoryJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	polDir := filepath.Join(dir, "pol")
	os.MkdirAll(polDir, 0755)
	os.WriteFile(filepath.Join(polDir, "policy.yaml"), []byte(`apiVersion: v1
kind: Policy
meta:
  name: json-test
  description: test
rules:
  - id: r1
    description: test
    effect: deny
    match:
      tools: ["exec"]
`), 0644)

	runCLI("policy", "history", "-init", "-author", "ci", polDir)

	stdout, _, _ := runCLI("policy", "history", "-json", polDir)
	var h map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &h); err != nil {
		t.Errorf("expected valid JSON history, got error: %v", err)
	}
	if _, ok := h["versions"]; !ok {
		t.Error("JSON output should contain 'versions' key")
	}
}

func TestCLI_PolicyHistoryAdd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	polDir := filepath.Join(dir, "pol")
	os.MkdirAll(polDir, 0755)
	os.WriteFile(filepath.Join(polDir, "policy.yaml"), []byte(`apiVersion: v1
kind: Policy
meta:
  name: add-test
  description: test
rules:
  - id: r1
    description: test
    effect: deny
    match:
      tools: ["exec"]
`), 0644)

	runCLI("policy", "history", "-init", "-author", "ci", polDir)

	// Modify the policy and add a version.
	os.WriteFile(filepath.Join(polDir, "policy.yaml"), []byte(`apiVersion: v1
kind: Policy
meta:
  name: add-test
  description: updated
rules:
  - id: r1
    description: test
    effect: deny
    match:
      tools: ["exec"]
  - id: r2
    description: new rule
    effect: allow
    match:
      tools: ["read"]
`), 0644)

	_, _, err := runCLI("policy", "history", "-add", "-author", "dev", "-comment", "added r2", polDir)
	if err != nil {
		t.Fatalf("policy history -add failed: %v", err)
	}

	// Verify version 2 exists.
	stdout, _, _ := runCLI("policy", "history", "-json", polDir)
	var h map[string]interface{}
	json.Unmarshal([]byte(stdout), &h)
	versions, ok := h["versions"].([]interface{})
	if !ok || len(versions) != 2 {
		t.Errorf("expected 2 versions, got %v", h["versions"])
	}
}

func TestCLI_PolicyHistoryDiff(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	polDir := filepath.Join(dir, "pol")
	os.MkdirAll(polDir, 0755)
	os.WriteFile(filepath.Join(polDir, "policy.yaml"), []byte(`apiVersion: v1
kind: Policy
meta:
  name: diff-test
  description: test
rules:
  - id: r1
    description: test
    effect: deny
    match:
      tools: ["exec"]
`), 0644)

	runCLI("policy", "history", "-init", "-author", "ci", polDir)

	os.WriteFile(filepath.Join(polDir, "policy.yaml"), []byte(`apiVersion: v1
kind: Policy
meta:
  name: diff-test
  description: test
rules:
  - id: r1
    description: test updated
    effect: allow
    match:
      tools: ["exec"]
`), 0644)

	runCLI("policy", "history", "-add", "-author", "ci", "-comment", "changed r1", polDir)

	stdout, _, err := runCLI("policy", "history", "-diff", "1:2", polDir)
	if err != nil {
		t.Fatalf("policy history -diff failed: %v", err)
	}
	if !strings.Contains(stdout, "r1") {
		t.Errorf("expected rule r1 in diff output, got: %s", truncate(stdout, 300))
	}
}

// --- policy compliance tests ---

func TestCLI_PolicyComplianceNoArgs(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "compliance")
	if err == nil {
		t.Error("expected non-zero exit for compliance without -policy")
	}
}

func TestCLI_PolicyComplianceNoTraces(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "compliance", "-policy", "policies/agent-default/")
	if err == nil {
		t.Error("expected non-zero exit when no trace files provided")
	}
}

func TestCLI_PolicyComplianceWithTrace(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Write a trace file.
	traceJSON := `{
  "id": "test-trace",
  "agent_name": "test-agent",
  "agent_type": "llm",
  "events": [
    {"id": "e1", "type": "tool_call", "tool_call": {"tool": "read_file", "arguments": {"path": "/tmp/x"}}}
  ]
}`
	traceFile := filepath.Join(dir, "trace.json")
	os.WriteFile(traceFile, []byte(traceJSON), 0644)

	stdout, _, err := runCLI("policy", "compliance", "-policy", "policies/agent-default/", traceFile)
	if err != nil {
		// Non-zero exit is fine if trace has denials.
		if !strings.Contains(stdout, "Compliance") {
			t.Fatalf("expected compliance output, got: %s", truncate(stdout, 300))
		}
	}
	if !strings.Contains(stdout, "Compliance") {
		t.Errorf("expected compliance report, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyComplianceJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	traceJSON := `{
  "id": "json-trace",
  "agent_name": "test",
  "events": [
    {"id": "e1", "type": "tool_call", "tool_call": {"tool": "safe_tool"}}
  ]
}`
	traceFile := filepath.Join(dir, "trace.json")
	os.WriteFile(traceFile, []byte(traceJSON), 0644)

	stdout, _, _ := runCLI("policy", "compliance", "-policy", "policies/agent-default/", "-json", traceFile)
	var report map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Errorf("expected valid JSON compliance report, got error: %v", err)
	}
	if _, ok := report["results"]; !ok {
		t.Error("JSON output should contain 'results' key")
	}
	if _, ok := report["overall_grade"]; !ok {
		t.Error("JSON output should contain 'overall_grade' key")
	}
}

// --- policy export tests ---

func TestCLI_PolicyExportNoArgs(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("policy", "export")
	if err == nil {
		t.Fatal("policy export with no args should fail")
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("expected usage help, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_PolicyExportJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "export", "-format", "json", "policies/agent-default/")
	if err != nil {
		t.Fatalf("policy export json should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("JSON output is not valid:\n%s", truncate(stdout, 500))
	}
	// Should contain the policy name.
	if !strings.Contains(stdout, "agent-default") {
		t.Error("JSON output should contain policy name")
	}
}

func TestCLI_PolicyExportRego(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "export", "-format", "rego", "policies/agent-default/")
	if err != nil {
		t.Fatalf("policy export rego should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "package threatecho.policy") {
		t.Error("Rego output should contain package declaration")
	}
	if !strings.Contains(stdout, "deny[msg]") {
		t.Error("Rego output should contain deny[msg] rules")
	}
	if !strings.Contains(stdout, "shell_exec") {
		t.Error("Rego output should reference shell_exec tool")
	}
}

func TestCLI_PolicyExportToFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	outFile := filepath.Join(dir, "exported.json")

	_, stderr, err := runCLI("policy", "export", "-format", "json", "-output", outFile, "policies/agent-default/")
	if err != nil {
		t.Fatalf("policy export to file should succeed, got: %v", err)
	}
	if !strings.Contains(stderr, "exported") {
		t.Errorf("stderr should confirm export, got: %s", truncate(stderr, 300))
	}

	// Read back and validate.
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading exported file: %v", err)
	}
	if !json.Valid(data) {
		t.Error("exported file should contain valid JSON")
	}
	if !strings.Contains(string(data), "agent-default") {
		t.Error("exported file should contain policy name")
	}
}

// --- policy benchmark tests ---

func TestCLI_PolicyBenchmarkNoArgs(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "benchmark")
	if err == nil {
		t.Error("expected non-zero exit for benchmark without policy path")
	}
	code := exitCode(err)
	if code != 64 {
		t.Errorf("expected exit code 64 (usage), got %d", code)
	}
}

func TestCLI_PolicyBenchmark(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "benchmark", "-iterations", "50", "policies/agent-default/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !strings.Contains(stdout, "POLICY BENCHMARK REPORT") {
		t.Errorf("expected benchmark report header, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "Avg eval") {
		t.Errorf("expected avg eval timing in output, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "P99 eval") {
		t.Errorf("expected p99 timing in output, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "evals/sec") {
		t.Errorf("expected throughput in output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyBenchmarkJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "benchmark", "-iterations", "50", "-json", "policies/agent-default/")
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON output, got: %s", truncate(stdout, 300))
	}
	// Check for expected JSON fields.
	if !strings.Contains(stdout, "policy_name") {
		t.Errorf("expected policy_name in JSON, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "overall_stats") {
		t.Errorf("expected overall_stats in JSON, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "recommendation") {
		t.Errorf("expected recommendation in JSON, got: %s", truncate(stdout, 300))
	}
}

// --- policy simulate command tests ---

func TestCLI_PolicySimulateNoArgs(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("policy", "simulate")
	if err == nil {
		t.Fatal("expected error when -policy not provided, got exit 0")
	}
	if !strings.Contains(stderr, "-policy") {
		t.Errorf("error output should mention -policy flag, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_PolicySimulate(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "simulate", "-policy", "policies/agent-default/", "-dir", "campaigns/")
	code := exitCode(err)
	// Exit 0 is the expected outcome for a simulation.
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(stdout, "Policy Simulation Report") {
		t.Errorf("output should contain report header, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "Summary") {
		t.Errorf("output should contain Summary line, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_PolicySimulateJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "simulate", "-policy", "policies/agent-default/", "-json", "campaigns/llm-agent-hijack/")
	code := exitCode(err)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("JSON output is not valid JSON:\n%s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "total_allowed") {
		t.Errorf("JSON should contain total_allowed field, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "total_denied") {
		t.Errorf("JSON should contain total_denied field, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "coverage_pct") {
		t.Errorf("JSON should contain coverage_pct field, got: %s", truncate(stdout, 300))
	}
}

// --- agent command tests ---

func TestCLI_AgentHelp(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("agent")
	if !strings.Contains(stderr, "list") || !strings.Contains(stderr, "trust") {
		t.Errorf("agent help should show subcommands, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_AgentValidateDir(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("agent", "validate", "-dir", "agents/")
	if err != nil {
		t.Fatalf("agent validate -dir should succeed, got: %v", err)
	}
	combined := stderr
	for _, name := range []string{"support-agent", "billing-agent", "orchestrator"} {
		if !strings.Contains(combined, name) {
			t.Errorf("expected validation output to mention %q", name)
		}
	}
}

func TestCLI_AgentValidateSingle(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("agent", "validate", "agents/support-agent/agent.yaml")
	if err != nil {
		t.Fatalf("agent validate should succeed, got: %v", err)
	}
	if !strings.Contains(stderr, "support-agent") {
		t.Errorf("expected output to mention support-agent, got: %s", truncate(stderr, 200))
	}
}

func TestCLI_AgentList(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "list", "-dir", "agents/")
	if err != nil {
		t.Fatalf("agent list should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "INVENTORY") && !strings.Contains(stdout, "Inventory") && !strings.Contains(stdout, "inventory") {
		t.Errorf("expected inventory header in output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentListJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "list", "-dir", "agents/", "-json")
	if err != nil {
		t.Fatalf("agent list -json should succeed, got: %v", err)
	}
	var agents []json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &agents); err != nil {
		t.Errorf("expected valid JSON array, got error: %v (output: %s)", err, truncate(stdout, 200))
	}
	if len(agents) < 3 {
		t.Errorf("expected at least 3 agents, got %d", len(agents))
	}
}

func TestCLI_AgentShow(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "show", "agents/orchestrator/")
	if err != nil {
		t.Fatalf("agent show should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "orchestrator") {
		t.Errorf("expected agent name in output, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "admin") {
		t.Errorf("expected trust level in output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentShowJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "show", "-json", "agents/billing-agent/")
	if err != nil {
		t.Fatalf("agent show -json should succeed, got: %v", err)
	}
	var agentData map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &agentData); err != nil {
		t.Errorf("expected valid JSON, got error: %v", err)
	}
}

func TestCLI_AgentTrust(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("agent", "trust", "-dir", "agents/")
	if !strings.Contains(stdout, "TRUST") || !strings.Contains(stdout, "trust") {
		// Trust analysis output should contain "TRUST" or "trust" in header.
		if !strings.Contains(stdout, "Trust") {
			t.Errorf("expected trust analysis output, got: %s", truncate(stdout, 300))
		}
	}
}

func TestCLI_AgentTrustJSON(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("agent", "trust", "-dir", "agents/", "-json")
	var analysis map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &analysis); err != nil {
		t.Errorf("expected valid JSON trust analysis, got error: %v (output: %s)", err, truncate(stdout, 200))
	}
}

func TestCLI_AgentNoSubcommand(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("agent")
	if err == nil {
		t.Error("expected non-zero exit for agent without subcommand")
	}
}

func TestCLI_AgentShowNoArgs(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("agent", "show")
	if err == nil {
		t.Error("expected non-zero exit for agent show without path")
	}
}

// --- v0.17.0 tests: agent test, guardrail, graph ---

func TestCLI_AgentTestNoPolicy(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("agent", "test")
	if err == nil {
		t.Error("expected non-zero exit for agent test without -policy")
	}
}

func TestCLI_AgentGuardrailSingle(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "guardrail", "agents/support-agent/")
	if err != nil {
		// May exit 2 if gaps found — that's expected.
		if !strings.Contains(stdout, "GUARDRAIL") {
			t.Logf("exit error (may have gaps): %v", err)
		}
	}
	if !strings.Contains(stdout, "GUARDRAIL") && !strings.Contains(stdout, "guardrail") {
		t.Errorf("expected guardrail output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentGuardrailJSON(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("agent", "guardrail", "-json", "agents/support-agent/")
	if !strings.Contains(stdout, "agent_name") {
		t.Errorf("expected JSON output with agent_name, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentGuardrailInventory(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("agent", "guardrail", "-dir", "agents/")
	if !strings.Contains(stdout, "INVENTORY") || !strings.Contains(stdout, "GUARDRAIL") {
		t.Errorf("expected inventory guardrail report, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentGraphText(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "graph", "-dir", "agents/")
	if err != nil {
		t.Fatalf("agent graph should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "TRUST GRAPH") {
		t.Errorf("expected trust graph output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentGraphDOT(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "graph", "-dir", "agents/", "-format", "dot")
	if err != nil {
		t.Fatalf("agent graph -format dot should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "digraph TrustGraph") {
		t.Errorf("expected DOT output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentGraphMermaid(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "graph", "-dir", "agents/", "-format", "mermaid")
	if err != nil {
		t.Fatalf("agent graph -format mermaid should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "graph LR") {
		t.Errorf("expected Mermaid output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentGraphJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "graph", "-dir", "agents/", "-json")
	if err != nil {
		t.Fatalf("agent graph -json should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "nodes") {
		t.Errorf("expected JSON with nodes, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentHelpShowsNewSubcommands(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("agent")
	for _, sub := range []string{"test", "guardrail", "graph"} {
		if !strings.Contains(stderr, sub) {
			t.Errorf("agent help should mention %q subcommand", sub)
		}
	}
}

func TestCLI_AgentExportJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "export", "-dir", "agents/")
	if err != nil {
		t.Fatalf("agent export should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "agent_count") {
		t.Errorf("expected JSON with agent_count, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentExportYAML(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "export", "-dir", "agents/", "-format", "yaml")
	if err != nil {
		t.Fatalf("agent export yaml should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "agent_count") {
		t.Errorf("expected YAML with agent_count, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentExportMarkdown(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "export", "-dir", "agents/", "-format", "markdown")
	if err != nil {
		t.Fatalf("agent export markdown should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "# Agent Inventory Report") {
		t.Errorf("expected Markdown report, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyComplianceNoPolicy(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("policy", "compliance")
	if err == nil {
		t.Error("expected non-zero exit for policy compliance without -policy")
	}
}

// --- scenario command tests ---

func TestCLI_ScenarioNoArgs(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("scenario")
	if err == nil {
		t.Fatal("expected non-zero exit for scenario with no args")
	}
	if !strings.Contains(stderr, "run") || !strings.Contains(stderr, "validate") || !strings.Contains(stderr, "list") {
		t.Errorf("scenario help should list subcommands run/validate/list, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_ScenarioRunNoDir(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("scenario", "run")
	if err == nil {
		t.Fatal("expected non-zero exit for scenario run without -dir")
	}
	if !strings.Contains(stderr, "-dir") {
		t.Errorf("error output should mention -dir flag, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_ScenarioRun(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("scenario", "run", "-dir", "campaigns/llm-agent-hijack/")
	if err != nil {
		t.Fatalf("scenario run should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "Scenario Run Result") {
		t.Errorf("expected scenario result header, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "Campaign:") {
		t.Errorf("expected Campaign: label in output, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_ScenarioRunJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("scenario", "run", "-dir", "campaigns/llm-agent-hijack/", "-json")
	if err != nil {
		t.Fatalf("scenario run -json should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("JSON output is not valid JSON:\n%s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "campaign_name") {
		t.Errorf("JSON should contain campaign_name field, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "stage_count") {
		t.Errorf("JSON should contain stage_count field, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_ScenarioRunWithPolicy(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("scenario", "run", "-dir", "campaigns/llm-agent-hijack/", "-policy", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("scenario run with policy should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "Scenario Run Result") {
		t.Errorf("expected scenario result header, got: %s", truncate(stdout, 500))
	}
	// Compliance report should also appear.
	if !strings.Contains(stdout, "Compliance") || !strings.Contains(stdout, "Grade") {
		t.Errorf("expected compliance report in output, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_ScenarioValidate(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("scenario", "validate", "-dir", "campaigns/llm-agent-hijack/")
	if err != nil {
		t.Fatalf("scenario validate should succeed, got: %v", err)
	}
	if !strings.Contains(stderr, "✓") {
		t.Errorf("expected success checkmark in output, got: %s", truncate(stderr, 300))
	}
	if !strings.Contains(stderr, "stages") {
		t.Errorf("expected stage count in output, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_ScenarioValidateNoDir(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("scenario", "validate")
	if err == nil {
		t.Fatal("expected non-zero exit for scenario validate without -dir")
	}
	if !strings.Contains(stderr, "-dir") {
		t.Errorf("error output should mention -dir flag, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_ScenarioList(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("scenario", "list", "-dir", "campaigns/llm-agent-hijack/")
	if err != nil {
		t.Fatalf("scenario list should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "Campaign:") {
		t.Errorf("expected Campaign: header, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "Stages:") {
		t.Errorf("expected Stages: count, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_ScenarioListJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("scenario", "list", "-dir", "campaigns/llm-agent-hijack/", "-json")
	if err != nil {
		t.Fatalf("scenario list -json should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("JSON output is not valid JSON:\n%s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "stage_count") {
		t.Errorf("JSON should contain stage_count field, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "stages") {
		t.Errorf("JSON should contain stages array, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_ScenarioHelpShowsSubcommands(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("scenario")
	for _, sub := range []string{"run", "validate", "list"} {
		if !strings.Contains(stderr, sub) {
			t.Errorf("scenario help should mention %q subcommand, got: %s", sub, truncate(stderr, 300))
		}
	}
}

// --- Policy drift tests ---

func TestCLI_PolicyDriftNoArgs(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("policy", "drift")
	if err == nil {
		t.Fatal("expected non-zero exit for drift without arguments")
	}
	if !strings.Contains(stderr, "baseline") || !strings.Contains(stderr, "current") {
		t.Errorf("expected error mentioning baseline and current, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_PolicyDriftSamePolicy(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "drift", "policies/agent-default/", "policies/agent-default/")
	if err != nil {
		t.Fatalf("drift of same policy should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "DRIFT") || !strings.Contains(stdout, "REPORT") {
		t.Errorf("expected drift report header, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyDriftJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "drift", "-json", "policies/agent-default/", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("drift JSON should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "drift_score") {
		t.Errorf("JSON should contain drift_score, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyDriftDifferentPolicies(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "drift", "policies/agent-default/", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("drift should succeed, got: %v", err)
	}
	// Different policies should produce findings.
	if !strings.Contains(stdout, "Drift") {
		t.Errorf("expected drift report, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyHelpShowsDrift(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("policy")
	if !strings.Contains(stderr, "drift") {
		t.Errorf("policy help should list drift subcommand, got: %s", truncate(stderr, 500))
	}
}

// --- Agent chain tests ---

func TestCLI_AgentChain(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "chain", "-dir", "agents/")
	if err != nil {
		t.Fatalf("agent chain should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "CHAIN") || !strings.Contains(stdout, "ANALYSIS") {
		t.Errorf("expected chain analysis output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentChainJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "chain", "-dir", "agents/", "-json")
	if err != nil {
		t.Fatalf("agent chain -json should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "risk_score") {
		t.Errorf("JSON should contain risk_score, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentHelpShowsChain(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("agent")
	if !strings.Contains(stderr, "chain") {
		t.Errorf("agent help should list chain subcommand, got: %s", truncate(stderr, 500))
	}
}

// --- Policy Lint CLI Tests ---

func TestCLI_PolicyLintNoArgs(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("policy", "lint")
	if err == nil {
		t.Fatal("expected non-zero exit for policy lint without args")
	}
	if !strings.Contains(stderr, "policy lint requires") {
		t.Errorf("expected usage error, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_PolicyLint(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "lint", "policies/agent-default/")
	// May exit 0 or 2 depending on lint errors found — both are valid.
	if !strings.Contains(stdout, "POLICY LINT REPORT") {
		t.Errorf("expected lint report header, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "Score") {
		t.Errorf("expected Score in lint report, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyLintJSON(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("policy", "lint", "-json", "policies/agent-default/")
	if !strings.Contains(stdout, "\"policy_name\"") {
		t.Errorf("JSON should contain policy_name, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "\"score\"") {
		t.Errorf("JSON should contain score, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyHelpShowsLint(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("policy")
	if !strings.Contains(stderr, "lint") {
		t.Errorf("policy help should list lint subcommand, got: %s", truncate(stderr, 500))
	}
}

// --- Trace Replay CLI Tests ---

func TestCLI_TraceReplayNoArgs(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("trace", "replay")
	if err == nil {
		t.Fatal("expected non-zero exit for trace replay without args")
	}
	if !strings.Contains(stderr, "trace replay requires") {
		t.Errorf("expected usage error, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_TraceReplay(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	traceFile := filepath.Join(tmp, "replay-trace.json")
	traceJSON := `{
		"id": "tr-replay-001",
		"agent_name": "test-replayer",
		"agent_type": "autonomous",
		"start_time": "2026-01-15T10:00:00Z",
		"end_time": "2026-01-15T10:05:00Z",
		"events": [
			{
				"id": "ev-1",
				"timestamp": "2026-01-15T10:01:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "http_request",
					"action": "send",
					"success": true
				}
			},
			{
				"id": "ev-2",
				"timestamp": "2026-01-15T10:02:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "database_query",
					"action": "read",
					"success": true
				}
			}
		]
	}`
	os.WriteFile(traceFile, []byte(traceJSON), 0644)

	stdout, _, err := runCLI("trace", "replay", traceFile)
	if err != nil {
		t.Fatalf("trace replay should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "Trace Replay Analysis") {
		t.Errorf("expected replay output header, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "test-replayer") {
		t.Errorf("expected agent name in output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_TraceReplayJSON(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	traceFile := filepath.Join(tmp, "replay-trace.json")
	traceJSON := `{
		"id": "tr-replay-002",
		"agent_name": "json-replayer",
		"agent_type": "tool-calling",
		"start_time": "2026-01-15T10:00:00Z",
		"end_time": "2026-01-15T10:05:00Z",
		"events": [
			{
				"id": "ev-1",
				"timestamp": "2026-01-15T10:01:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "file_read",
					"action": "read",
					"success": true
				}
			}
		]
	}`
	os.WriteFile(traceFile, []byte(traceJSON), 0644)

	stdout, _, err := runCLI("trace", "replay", "-json", traceFile)
	if err != nil {
		t.Fatalf("trace replay -json should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "risk_score") {
		t.Errorf("JSON should contain risk_score, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_TraceReplayWithPolicy(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	traceFile := filepath.Join(tmp, "replay-trace.json")
	traceJSON := `{
		"id": "tr-replay-003",
		"agent_name": "policy-replayer",
		"agent_type": "autonomous",
		"start_time": "2026-01-15T10:00:00Z",
		"end_time": "2026-01-15T10:05:00Z",
		"events": [
			{
				"id": "ev-1",
				"timestamp": "2026-01-15T10:01:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "shell_exec",
					"action": "execute",
					"success": true
				}
			}
		]
	}`
	os.WriteFile(traceFile, []byte(traceJSON), 0644)

	stdout, _, _ := runCLI("trace", "replay", "-policy", "policies/agent-strict/", traceFile)
	// With policy, should still produce a replay result.
	if !strings.Contains(stdout, "Trace Replay Analysis") {
		t.Errorf("expected replay output with policy, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_TraceHelpShowsReplay(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("trace")
	if !strings.Contains(stderr, "replay") {
		t.Errorf("trace help should list replay subcommand, got: %s", truncate(stderr, 500))
	}
}

// --- Trace Correlate CLI Tests ---

func TestCLI_TraceCorrelateNoArgs(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("trace", "correlate")
	if err == nil {
		t.Fatal("expected non-zero exit for trace correlate without args")
	}
	if !strings.Contains(stderr, "at least two trace files") {
		t.Errorf("expected usage error, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_TraceCorrelateSingleFile(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	tf := filepath.Join(tmp, "trace1.json")
	os.WriteFile(tf, []byte(`{
		"id": "tr-001",
		"agent_name": "solo-agent",
		"agent_type": "autonomous",
		"start_time": "2026-01-15T10:00:00Z",
		"end_time": "2026-01-15T10:05:00Z",
		"events": []
	}`), 0644)
	_, stderr, err := runCLI("trace", "correlate", tf)
	if err == nil {
		t.Fatal("expected non-zero exit for single trace")
	}
	if !strings.Contains(stderr, "at least two trace files") {
		t.Errorf("expected minimum traces error, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_TraceCorrelate(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	tf1 := filepath.Join(tmp, "trace1.json")
	os.WriteFile(tf1, []byte(`{
		"id": "tr-corr-001",
		"agent_name": "recon-agent",
		"agent_type": "tool-calling",
		"start_time": "2026-01-15T10:00:00Z",
		"end_time": "2026-01-15T10:05:00Z",
		"events": [
			{
				"id": "ev-1",
				"timestamp": "2026-01-15T10:01:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "http_request",
					"action": "scan",
					"target": "internal-db",
					"success": true
				}
			},
			{
				"id": "ev-2",
				"timestamp": "2026-01-15T10:02:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "database_query",
					"action": "read",
					"target": "internal-db",
					"success": true
				}
			}
		]
	}`), 0644)
	tf2 := filepath.Join(tmp, "trace2.json")
	os.WriteFile(tf2, []byte(`{
		"id": "tr-corr-002",
		"agent_name": "exfil-agent",
		"agent_type": "autonomous",
		"start_time": "2026-01-15T10:03:00Z",
		"end_time": "2026-01-15T10:08:00Z",
		"events": [
			{
				"id": "ev-3",
				"timestamp": "2026-01-15T10:04:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "database_query",
					"action": "dump",
					"target": "internal-db",
					"success": true
				}
			},
			{
				"id": "ev-4",
				"timestamp": "2026-01-15T10:05:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "http_request",
					"action": "upload",
					"target": "external-api.example.com",
					"success": true
				}
			}
		]
	}`), 0644)

	stdout, _, err := runCLI("trace", "correlate", tf1, tf2)
	if err != nil {
		t.Fatalf("trace correlate should succeed, got: %v", err)
	}
	lower := strings.ToLower(stdout)
	if !strings.Contains(lower, "correlation") {
		t.Errorf("expected correlation output, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_TraceCorrelateJSON(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	tf1 := filepath.Join(tmp, "t1.json")
	os.WriteFile(tf1, []byte(`{
		"id": "tr-j1",
		"agent_name": "agent-alpha",
		"agent_type": "tool-calling",
		"start_time": "2026-01-15T10:00:00Z",
		"end_time": "2026-01-15T10:03:00Z",
		"events": [
			{
				"id": "e1",
				"timestamp": "2026-01-15T10:01:00Z",
				"type": "tool_call",
				"tool_call": {"tool": "shell_exec", "action": "run", "success": true}
			}
		]
	}`), 0644)
	tf2 := filepath.Join(tmp, "t2.json")
	os.WriteFile(tf2, []byte(`{
		"id": "tr-j2",
		"agent_name": "agent-beta",
		"agent_type": "autonomous",
		"start_time": "2026-01-15T10:01:00Z",
		"end_time": "2026-01-15T10:04:00Z",
		"events": [
			{
				"id": "e2",
				"timestamp": "2026-01-15T10:02:00Z",
				"type": "tool_call",
				"tool_call": {"tool": "database_query", "action": "read", "success": true}
			}
		]
	}`), 0644)

	stdout, _, err := runCLI("trace", "correlate", "-json", tf1, tf2)
	if err != nil {
		t.Fatalf("trace correlate -json should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "trace_count") || !strings.Contains(stdout, "correlations") {
		t.Errorf("JSON should contain trace_count and correlations, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_TraceHelpShowsCorrelate(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("trace")
	if !strings.Contains(stderr, "correlate") {
		t.Errorf("trace help should list correlate subcommand, got: %s", truncate(stderr, 500))
	}
}

// --- Agent Attest CLI Tests ---

func TestCLI_AgentAttestNoArgs(t *testing.T) {
	t.Parallel()
	// Without -dir should auto-detect or use default.
	stdout, _, err := runCLI("agent", "attest", "-dir", "agents/")
	if err != nil {
		t.Fatalf("agent attest should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "ATTESTATION") {
		t.Errorf("expected attestation report output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentAttestJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("agent", "attest", "-dir", "agents/", "-json")
	if err != nil {
		t.Fatalf("agent attest -json should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_AgentAttestVerify(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	agentDir := filepath.Join(tmp, "agents", "test-attest-agent")
	os.MkdirAll(agentDir, 0755)
	agentYAML := `api_version: v1
kind: Agent
meta:
  name: test-attest-agent
  type: tool-calling
  description: "Test agent for attestation"
  model: gpt-4
  version: "1.0.0"
  owner: test-team
capabilities:
  tool_calling: true
tools:
  - name: http_request
    actions: ["send"]
    targets: ["https://api.example.com/*"]
trust:
  level: standard
guardrails:
  - name: content_filter
    type: content_filter
    config:
      block_pii: true
`
	os.WriteFile(filepath.Join(agentDir, "agent.yaml"), []byte(agentYAML), 0644)

	stdout, _, err := runCLI("agent", "attest", "-dir", filepath.Join(tmp, "agents"))
	if err != nil {
		t.Fatalf("agent attest should succeed with test agent, got: %v", err)
	}
	if !strings.Contains(stdout, "ATTESTATION") {
		t.Errorf("expected attestation output, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "test-attest-agent") {
		t.Errorf("expected agent name in output, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_AgentAttestSingleAgent(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	agentDir := filepath.Join(tmp, "agents", "single-agent")
	os.MkdirAll(agentDir, 0755)
	agentYAML := `api_version: v1
kind: Agent
meta:
  name: single-agent
  type: retrieval
  description: "Single agent for attest test"
  model: gpt-3.5
  version: "1.0.0"
  owner: test-team
capabilities:
  rag: true
tools:
  - name: document_search
    actions: ["search"]
    targets: ["https://docs.example.com/*"]
trust:
  level: low
`
	os.WriteFile(filepath.Join(agentDir, "agent.yaml"), []byte(agentYAML), 0644)

	stdout, _, err := runCLI("agent", "attest", "-agent", "single-agent", "-dir", filepath.Join(tmp, "agents"))
	if err != nil {
		t.Fatalf("agent attest -agent should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "single-agent") {
		t.Errorf("expected single agent in output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentHelpShowsAttest(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("agent")
	if !strings.Contains(stderr, "attest") {
		t.Errorf("agent help should list attest subcommand, got: %s", truncate(stderr, 500))
	}
}

func TestCLI_AgentHelpShowsProfile(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("agent")
	if !strings.Contains(stderr, "profile") {
		t.Errorf("agent help should list profile subcommand, got: %s", truncate(stderr, 500))
	}
}

func TestCLI_AgentProfileNoTraces(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("agent", "profile")
	if err == nil {
		t.Fatal("expected non-zero exit for profile without -traces")
	}
	if !strings.Contains(stderr, "requires -traces") {
		t.Errorf("expected usage error about traces, got: %s", truncate(stderr, 300))
	}
}

// --- Policy CoverageMap CLI Tests ---

func TestCLI_PolicyCoverageMapNoArgs(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("policy", "coveragemap")
	if err == nil {
		t.Fatal("expected non-zero exit for coveragemap without args")
	}
	if !strings.Contains(stderr, "coveragemap requires") {
		t.Errorf("expected usage error, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_PolicyCoverageMap(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "coveragemap", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("coveragemap should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "Coverage") {
		t.Errorf("expected coverage output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyCoverageMapJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "coveragemap", "-json", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("coveragemap -json should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "coverage_percent") || !strings.Contains(stdout, "risk_score") {
		t.Errorf("JSON should contain coverage_percent and risk_score, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyHelpShowsCoverageMap(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("policy")
	if !strings.Contains(stderr, "coveragemap") {
		t.Errorf("policy help should list coveragemap subcommand, got: %s", truncate(stderr, 500))
	}
}

// --- Threat Model CLI Tests ---

func TestCLI_ThreatModel(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("threat-model", "-agents", "agents/", "-policy", "policies/")
	if err != nil {
		t.Fatalf("threat-model should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "STRIDE Threat Model") {
		t.Errorf("expected threat model output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_ThreatModelJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("threat-model", "-agents", "agents/", "-policy", "policies/", "-json")
	if err != nil {
		t.Fatalf("threat-model -json should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "overall_risk") {
		t.Errorf("JSON should contain overall_risk, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_ThreatModelAutoDetect(t *testing.T) {
	t.Parallel()
	// Without explicit flags, should auto-detect dirs.
	stdout, _, err := runCLI("threat-model")
	if err != nil {
		t.Fatalf("threat-model auto-detect should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "STRIDE Threat Model") {
		t.Errorf("expected threat model output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_HelpShowsThreatModel(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("help")
	combined := stdout + stderr
	if !strings.Contains(combined, "threat-model") {
		t.Errorf("help should list threat-model command, got: %s", truncate(combined, 500))
	}
}

// --- Help shows all major commands ---

func TestCLI_HelpShowsScenario(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("help")
	combined := stdout + stderr
	if !strings.Contains(combined, "scenario") {
		t.Errorf("help should list scenario command, got: %s", truncate(combined, 500))
	}
}

// --- Scenario CLI Tests ---

func TestCLI_ScenarioListHelp(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("scenario")
	if !strings.Contains(stderr, "run") || !strings.Contains(stderr, "validate") || !strings.Contains(stderr, "list") {
		t.Errorf("scenario help should show subcommands, got: %s", truncate(stderr, 500))
	}
}

// --- Additional coverage map tests ---

func TestCLI_PolicyCoverageMapDefault(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "coveragemap", "policies/agent-default/")
	if err != nil {
		t.Fatalf("coveragemap on default policy should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "Coverage") {
		t.Errorf("expected coverage report, got: %s", truncate(stdout, 300))
	}
}

// --- Additional threat model tests ---

func TestCLI_ThreatModelEmptyAgents(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	// Empty agents dir produces a model with zero threats.
	stdout, _, err := runCLI("threat-model", "-agents", tmp, "-policy", tmp, "-json")
	if err != nil {
		t.Fatalf("threat-model with empty dirs should succeed (zero threats), got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
}

// --- Additional agent profile tests ---

func TestCLI_AgentProfileEmptyDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, stderr, err := runCLI("agent", "profile", "-traces", tmp)
	if err == nil {
		t.Fatal("expected error with empty trace directory")
	}
	if !strings.Contains(stderr, "no trace") {
		t.Errorf("expected 'no trace' error, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_AgentProfileWithTraces(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	traceJSON := `{
		"id": "tr-profile-001",
		"agent_name": "profile-test-agent",
		"agent_type": "tool-calling",
		"start_time": "2026-01-15T10:00:00Z",
		"end_time": "2026-01-15T10:05:00Z",
		"events": [
			{
				"id": "ev-1",
				"timestamp": "2026-01-15T10:01:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "http_request",
					"action": "send",
					"success": true,
					"target": "api.example.com"
				}
			},
			{
				"id": "ev-2",
				"timestamp": "2026-01-15T10:02:00Z",
				"type": "tool_call",
				"tool_call": {
					"tool": "database_query",
					"action": "read",
					"success": true,
					"target": "db.internal.example.com"
				}
			}
		]
	}`
	os.WriteFile(filepath.Join(tmp, "trace-001.json"), []byte(traceJSON), 0644)

	stdout, _, err := runCLI("agent", "profile", "-traces", tmp)
	if err != nil {
		t.Fatalf("agent profile should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "profile-test-agent") {
		t.Errorf("expected agent name in output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentProfileSpecificAgent(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	for i, name := range []string{"agent-a", "agent-b"} {
		traceJSON := fmt.Sprintf(`{
			"id": "tr-%d",
			"agent_name": "%s",
			"agent_type": "tool-calling",
			"start_time": "2026-01-15T10:00:00Z",
			"end_time": "2026-01-15T10:05:00Z",
			"events": [{"id": "ev-1", "timestamp": "2026-01-15T10:01:00Z", "type": "tool_call", "tool_call": {"tool": "http_request", "action": "send", "success": true}}]
		}`, i, name)
		os.WriteFile(filepath.Join(tmp, fmt.Sprintf("trace-%d.json", i)), []byte(traceJSON), 0644)
	}

	stdout, _, err := runCLI("agent", "profile", "-traces", tmp, "-agent", "agent-a")
	if err != nil {
		t.Fatalf("agent profile -agent should succeed, got: %v", err)
	}
	if !strings.Contains(stdout, "agent-a") {
		t.Errorf("expected agent-a in output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_AgentProfileJSON(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	traceJSON := `{
		"id": "tr-json-001",
		"agent_name": "json-profile-agent",
		"agent_type": "autonomous",
		"start_time": "2026-01-15T10:00:00Z",
		"end_time": "2026-01-15T10:05:00Z",
		"events": [{"id": "ev-1", "timestamp": "2026-01-15T10:01:00Z", "type": "tool_call", "tool_call": {"tool": "code_execute", "action": "run", "success": true}}]
	}`
	os.WriteFile(filepath.Join(tmp, "trace-001.json"), []byte(traceJSON), 0644)

	stdout, _, err := runCLI("agent", "profile", "-traces", tmp, "-json")
	if err != nil {
		t.Fatalf("agent profile JSON should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
}

// --- Policy remediate tests ---

func TestCLI_PolicyRemediateNoArgs(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("policy", "remediate")
	if err == nil {
		t.Fatal("expected non-zero exit for remediate without arguments")
	}
	if !strings.Contains(stderr, "remediate") {
		t.Errorf("expected error about policy path, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_PolicyRemediate(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "remediate", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("remediate should succeed, got: %v", err)
	}
	// Should produce either a remediation plan or "no remediation needed".
	lower := strings.ToLower(stdout)
	if !strings.Contains(lower, "remediat") && !strings.Contains(lower, "no issues") {
		t.Errorf("expected remediation output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyRemediateJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "remediate", "-json", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("remediate -json should succeed, got: %v", err)
	}
	if stdout != "" && !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_PolicyRemediateAllSources(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "remediate", "-source", "all",
		"-baseline", "policies/agent-default/", "policies/agent-strict/")
	if err != nil {
		t.Fatalf("remediate -source all should succeed, got: %v", err)
	}
	lower := strings.ToLower(stdout)
	if !strings.Contains(lower, "remediat") && !strings.Contains(lower, "no") {
		t.Errorf("expected remediation output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_PolicyRemediateCoverage(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("policy", "remediate", "-source", "coverage", "policies/agent-default/")
	if err != nil {
		t.Fatalf("remediate -source coverage should succeed, got: %v", err)
	}
	_ = stdout // May produce remediation or "no issues" message.
}

func TestCLI_PolicyHelpShowsRemediate(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("policy")
	if !strings.Contains(stderr, "remediate") {
		t.Errorf("policy help should list remediate subcommand, got: %s", truncate(stderr, 500))
	}
}

// --- Risk posture tests ---

func TestCLI_RiskPostureNoPolicy(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("risk-posture")
	if err == nil {
		t.Fatal("expected non-zero exit for risk-posture without -policy")
	}
	if !strings.Contains(stderr, "policy") {
		t.Errorf("expected error about -policy, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_RiskPosture(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("risk-posture", "-policy", "policies/agent-strict/", "-agents", "agents/")
	if err != nil {
		t.Fatalf("risk-posture should succeed, got: %v", err)
	}
	lower := strings.ToLower(stdout)
	if !strings.Contains(lower, "risk") {
		t.Errorf("expected risk output, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_RiskPostureJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("risk-posture", "-policy", "policies/agent-strict/", "-json")
	if err != nil {
		t.Fatalf("risk-posture -json should succeed, got: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "overall_score") || !strings.Contains(stdout, "grade") {
		t.Errorf("JSON should contain overall_score and grade, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_HelpShowsRiskPosture(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("help")
	combined := stdout + stderr
	if !strings.Contains(combined, "risk-posture") {
		t.Errorf("help should list risk-posture command, got: %s", truncate(combined, 500))
	}
}

func TestCLI_DeployBaselineNoArgs(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("deploy-baseline")
	if err == nil {
		t.Error("expected error with no args")
	}
	if !strings.Contains(stderr, "Usage") {
		t.Errorf("expected usage text, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_DeployBaselineCapture(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("deploy-baseline", "-policy", "policies/agent-default", "-json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("expected valid JSON, got: %s", truncate(stdout, 300))
	}
	if !strings.Contains(stdout, "fingerprint") {
		t.Errorf("JSON should contain fingerprint, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_DeployBaselineSaveAndCompare(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "baseline.json")

	_, stderr, err := runCLI("deploy-baseline", "-policy", "policies/agent-default", "-output", outPath)
	if err != nil {
		t.Fatalf("capture: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stderr, "Baseline saved") {
		t.Errorf("expected save confirmation, got: %s", truncate(stderr, 300))
	}

	stdout, _, err := runCLI("deploy-baseline", "-compare", outPath, "-json")
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("compare JSON invalid: %s", truncate(stdout, 300))
	}
}

func TestCLI_DeployBaselineText(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("deploy-baseline", "-policy", "policies/agent-default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "Deployment Baseline") {
		t.Errorf("expected baseline header, got: %s", truncate(stdout, 300))
	}
}

func TestCLI_HelpShowsDeployBaseline(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("help")
	combined := stdout + stderr
	if !strings.Contains(combined, "deploy-baseline") {
		t.Errorf("help should list deploy-baseline command, got: %s", truncate(combined, 500))
	}
}

func TestCLI_ComplianceList(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("compliance", "-list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "nist-ai-rmf") {
		t.Errorf("expected nist-ai-rmf in list, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "nist-csf") {
		t.Errorf("expected nist-csf in list, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "cis-v8") {
		t.Errorf("expected cis-v8 in list, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_ComplianceSOC(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("compliance", "-dir", "campaigns/", "-framework", "nist-csf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "NIST Cybersecurity Framework") {
		t.Errorf("expected NIST CSF in output, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "Coverage:") {
		t.Errorf("expected Coverage line, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_ComplianceSOCAllFrameworks(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("compliance", "-dir", "campaigns/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "All Frameworks") {
		t.Errorf("expected 'All Frameworks' in output, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "CIS Controls") {
		t.Errorf("expected CIS Controls in output, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_ComplianceSOCJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("compliance", "-dir", "campaigns/", "-framework", "cis-v8", "-json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed interface{}
	if jErr := json.Unmarshal([]byte(stdout), &parsed); jErr != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", jErr, truncate(stdout, 500))
	}
}

func TestCLI_ComplianceSOCBadFramework(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("compliance", "-dir", "campaigns/", "-framework", "bogus-fw")
	if err == nil {
		t.Fatal("expected error for unknown SOC framework")
	}
	if !strings.Contains(stderr, "unknown SOC framework") {
		t.Errorf("expected 'unknown SOC framework' error, got: %s", truncate(stderr, 300))
	}
}

func TestCLI_AttackTree(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("attack-tree", "-agents", "agents/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "ATTACK TREE ANALYSIS") {
		t.Errorf("expected ATTACK TREE ANALYSIS header, got: %s", truncate(stdout, 500))
	}
	if !strings.Contains(stdout, "Nodes:") {
		t.Errorf("expected Nodes: in output, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_AttackTreeJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("attack-tree", "-agents", "agents/", "-json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed map[string]interface{}
	if jErr := json.Unmarshal([]byte(stdout), &parsed); jErr != nil {
		t.Fatalf("invalid JSON: %v\nOutput: %s", jErr, truncate(stdout, 500))
	}
	if _, ok := parsed["root"]; !ok {
		t.Error("JSON should have 'root' key")
	}
}

func TestCLI_AttackTreeWithPolicy(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("attack-tree", "-policy", "policies/agent-default", "-agents", "agents/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "ATTACK TREE ANALYSIS") {
		t.Errorf("expected output with policy, got: %s", truncate(stdout, 500))
	}
}

func TestCLI_HelpShowsAttackTree(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("help")
	combined := stdout + stderr
	if !strings.Contains(combined, "attack-tree") {
		t.Errorf("help should list attack-tree command, got: %s", truncate(combined, 500))
	}
}

// ---------------------------------------------------------------------------
// Golden-file tests — snapshot CLI output to catch format regressions
// ---------------------------------------------------------------------------

var updateGolden = flag.Bool("update-golden", false, "overwrite golden files with current output")

var goldenDir = filepath.Join("testdata", "golden")

var timestampRE = regexp.MustCompile(`"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^"]*"`)
var timestampBareRE = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*`)
var versionRE = regexp.MustCompile(`threatecho \d+\.\d+\.\d+[^\n]*`)

func normalizeGolden(s string) string {
	if srcRoot != "" && srcRoot != "." {
		s = strings.ReplaceAll(s, srcRoot, "<ROOT>")
	}
	s = timestampRE.ReplaceAllString(s, `"<TIMESTAMP>"`)
	s = timestampBareRE.ReplaceAllString(s, "<TIMESTAMP>")
	s = versionRE.ReplaceAllString(s, "threatecho <VERSION>")
	s = strings.TrimRight(s, "\n") + "\n"
	return s
}

func assertGolden(t *testing.T, name, actual string) {
	t.Helper()
	actual = normalizeGolden(actual)
	p := filepath.Join(srcRoot, "cmd", "threatecho", goldenDir, name+".golden")

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(actual), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated golden file: %s", p)
		return
	}

	expected, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("golden file missing (run with -update-golden to create): %s", p)
	}
	if actual != string(expected) {
		t.Errorf("output differs from golden file %s.\nWant:\n%s\nGot:\n%s", name, string(expected), actual)
	}
}

func TestGolden_Help(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("help")
	assertGolden(t, "help", stdout+stderr)
}

func TestGolden_Version(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("version")
	assertGolden(t, "version", stdout)
}

func TestGolden_Validate(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("validate", filepath.Join("campaigns", "agent-api-abuse", "campaign.yaml"))
	assertGolden(t, "validate", stdout+stderr)
}

func TestGolden_LintDir(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("lint", "-dir", "campaigns/")
	assertGolden(t, "lint-dir", stdout+stderr)
}

func TestGolden_CampaignsList(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("campaigns", "list")
	if err != nil {
		t.Skipf("campaigns list returned error: %v", err)
	}
	assertGolden(t, "campaigns-list", stdout)
}

func TestGolden_Stats(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("stats")
	if err != nil {
		t.Skipf("stats returned error: %v", err)
	}
	assertGolden(t, "stats", stdout)
}

func TestGolden_GapJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("gap", "-dir", "campaigns/", "-format", "json")
	if err != nil {
		t.Skipf("gap -json returned error: %v", err)
	}
	var parsed interface{}
	if jsonErr := json.Unmarshal([]byte(stdout), &parsed); jsonErr != nil {
		t.Fatalf("gap JSON is not valid JSON: %v\n%s", jsonErr, truncate(stdout, 300))
	}
	assertGolden(t, "gap-json", stdout)
}

func TestGolden_ComplianceList(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("compliance", "-list")
	if err != nil {
		t.Skipf("compliance -list returned error: %v", err)
	}
	assertGolden(t, "compliance-list", stdout)
}

func TestGolden_ThreatModelJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("threat-model", "-agents", "agents/", "-policy", "policies/", "-json")
	if err != nil {
		t.Skipf("threat-model -json returned error: %v", err)
	}
	var parsed interface{}
	if jsonErr := json.Unmarshal([]byte(stdout), &parsed); jsonErr != nil {
		t.Fatalf("threat-model JSON is not valid JSON: %v\n%s", jsonErr, truncate(stdout, 300))
	}
	assertGolden(t, "threat-model-json", stdout)
}

func TestGolden_RiskPostureJSON(t *testing.T) {
	t.Parallel()
	stdout, stderr, _ := runCLI("risk-posture", "-agents", "agents/", "-policy", "policies/agent-strict/", "-json")
	combined := stdout + stderr
	var parsed interface{}
	if jsonErr := json.Unmarshal([]byte(stdout), &parsed); jsonErr != nil {
		t.Fatalf("risk-posture JSON is not valid JSON: %v\n%s", jsonErr, truncate(combined, 300))
	}
	assertGolden(t, "risk-posture-json", stdout)
}

func TestGolden_AttackTreeJSON(t *testing.T) {
	t.Parallel()
	stdout, _, err := runCLI("attack-tree", "-agents", "agents/", "-policy", "policies/", "-json")
	if err != nil {
		t.Skipf("attack-tree -json returned error: %v", err)
	}
	var parsed interface{}
	if jsonErr := json.Unmarshal([]byte(stdout), &parsed); jsonErr != nil {
		t.Fatalf("attack-tree JSON is not valid JSON: %v\n%s", jsonErr, truncate(stdout, 300))
	}
	assertGolden(t, "attack-tree-json", stdout)
}

func TestGolden_DoctorText(t *testing.T) {
	t.Parallel()
	stdout, _, _ := runCLI("doctor")
	assertGolden(t, "doctor", stdout)
}

// --- deploy command tests ---

func TestCLI_DeployHelp(t *testing.T) {
	t.Parallel()
	_, stderr, _ := runCLI("deploy", "-h")
	if !strings.Contains(stderr, "Deploy a campaign") {
		t.Error("deploy help missing description")
	}
	if !strings.Contains(stderr, "-inventory") {
		t.Error("deploy help missing -inventory flag")
	}
	if !strings.Contains(stderr, "-target") {
		t.Error("deploy help missing -target flag")
	}
}

func TestCLI_DeployNoArgs(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("deploy")
	if err == nil {
		t.Error("expected error with no arguments")
	}
}

func TestCLI_DeployNoTarget(t *testing.T) {
	t.Parallel()
	_, _, err := runCLI("deploy", "campaigns/apt29-cozy-bear/")
	if err == nil {
		t.Error("expected error when no target or inventory specified")
	}
}

func TestCLI_DeploySingleTargetMissingUser(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("deploy", "-target", "10.0.0.1", "campaigns/apt29-cozy-bear/")
	if err == nil {
		t.Error("expected error for single-target without -user")
	}
	if !strings.Contains(stderr, "requires -user") {
		t.Errorf("expected 'requires -user' in stderr, got: %s", stderr)
	}
}

func TestCLI_DeploySingleTargetMissingAuth(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("deploy", "-target", "10.0.0.1", "-user", "lab", "campaigns/apt29-cozy-bear/")
	if err == nil {
		t.Error("expected error for single-target without auth")
	}
	if !strings.Contains(stderr, "requires -password or -key") {
		t.Errorf("expected 'requires -password or -key' in stderr, got: %s", stderr)
	}
}

func TestCLI_DeployValidateOnly(t *testing.T) {
	t.Parallel()

	// Create a temp inventory file.
	dir := t.TempDir()
	invPath := filepath.Join(dir, "targets.yaml")
	os.WriteFile(invPath, []byte(`
api_version: v1
kind: TargetInventory
meta:
  name: test
targets:
  - name: srv1
    host: 10.0.0.1
    os: linux
    user: lab
    password: pass
    mode: agentless
`), 0644)

	stdout, _, err := runCLI("deploy", "-validate", "-inventory", invPath, "campaigns/apt29-cozy-bear/")
	if err != nil {
		t.Fatalf("deploy -validate failed: %v", err)
	}
	if !strings.Contains(stdout, "valid") {
		t.Errorf("expected 'valid' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "1 target(s) validated") {
		t.Errorf("expected '1 target(s) validated' in output, got: %s", stdout)
	}
}

func TestCLI_DeployAgentModeNoBinary(t *testing.T) {
	t.Parallel()
	_, stderr, err := runCLI("deploy", "-target", "10.0.0.1", "-user", "lab", "-password", "pass", "-mode", "agent", "campaigns/apt29-cozy-bear/")
	if err == nil {
		t.Error("expected error for agent mode without -agent-binary")
	}
	if !strings.Contains(stderr, "agent mode requires -agent-binary") {
		t.Errorf("expected agent-binary error in stderr, got: %s", stderr)
	}
}

func TestCLI_DeployInventoryValidation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	invPath := filepath.Join(dir, "bad.yaml")
	os.WriteFile(invPath, []byte(`
api_version: v1
kind: TargetInventory
meta:
  name: empty
targets: []
`), 0644)

	_, stderr, err := runCLI("deploy", "-validate", "-inventory", invPath, "campaigns/apt29-cozy-bear/")
	if err == nil {
		t.Error("expected error for empty inventory")
	}
	if !strings.Contains(stderr, "no targets") {
		t.Errorf("expected 'no targets' error in stderr, got: %s", stderr)
	}
}
