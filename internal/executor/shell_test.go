// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package executor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

func skipIfWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("test uses POSIX shell commands")
	}
}

func TestShellSimpleCommand(t *testing.T) {
	skipIfWindows(t)
	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "echo-test",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"echo hello"},
		},
	}

	r := sh.Execute(context.Background(), stage)
	if !r.Success {
		t.Fatalf("expected success, got error: %v", r.Error)
	}
	if !strings.Contains(r.Output, "hello") {
		t.Fatalf("expected output to contain 'hello', got: %q", r.Output)
	}
	if r.StageID != "echo-test" {
		t.Fatalf("expected StageID echo-test, got %q", r.StageID)
	}
}

func TestShellMultipleCommands(t *testing.T) {
	skipIfWindows(t)
	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "multi",
		Execute: campaign.Execute{
			Type: "shell",
			Commands: []string{
				"echo first",
				"echo second",
				"echo third",
			},
		},
	}

	r := sh.Execute(context.Background(), stage)
	if !r.Success {
		t.Fatalf("expected success, got error: %v", r.Error)
	}
	if !strings.Contains(r.Output, "first") || !strings.Contains(r.Output, "third") {
		t.Fatalf("expected all command outputs, got: %q", r.Output)
	}
}

func TestShellCommandFailure(t *testing.T) {
	skipIfWindows(t)
	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "fail",
		Execute: campaign.Execute{
			Type: "shell",
			Commands: []string{
				"echo before",
				"false",      // exits 1
				"echo after", // should not run
			},
		},
	}

	r := sh.Execute(context.Background(), stage)
	if r.Success {
		t.Fatal("expected failure on 'false' command")
	}
	if r.Error == nil {
		t.Fatal("expected non-nil error")
	}
	if !strings.Contains(r.Error.Error(), "command 2 failed") {
		t.Fatalf("expected 'command 2 failed' in error, got: %v", r.Error)
	}
	// The "after" command should not have run.
	if strings.Contains(r.Output, "after") {
		t.Fatal("commands after failure should not execute")
	}
}

func TestShellTimeout(t *testing.T) {
	skipIfWindows(t)
	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "timeout",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"sleep 30"},
		},
		Timeout: campaign.Duration{Duration: 200 * time.Millisecond},
	}

	start := time.Now()
	r := sh.Execute(context.Background(), stage)
	elapsed := time.Since(start)

	if r.Success {
		t.Fatal("expected timeout failure")
	}
	// Should complete well under 30 seconds.
	if elapsed > 5*time.Second {
		t.Fatalf("timeout did not kill process in time: elapsed %v", elapsed)
	}
}

func TestShellDenyElevated(t *testing.T) {
	sh := NewShell(ShellConfig{DenyElevated: true})
	stage := campaign.Stage{
		ID: "elevated",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"echo should not run"},
			Elevated: true,
		},
	}

	r := sh.Execute(context.Background(), stage)
	if r.Success {
		t.Fatal("expected denial for elevated stage")
	}
	if r.Error == nil || !strings.Contains(r.Error.Error(), "DenyElevated") {
		t.Fatalf("expected DenyElevated error, got: %v", r.Error)
	}
}

func TestShellAllowElevated(t *testing.T) {
	skipIfWindows(t)
	sh := NewShell(ShellConfig{DenyElevated: false})
	stage := campaign.Stage{
		ID: "elevated-ok",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"echo allowed"},
			Elevated: true,
		},
	}

	r := sh.Execute(context.Background(), stage)
	if !r.Success {
		t.Fatalf("expected success when DenyElevated=false, got: %v", r.Error)
	}
}

func TestShellNonShellType(t *testing.T) {
	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "http-stage",
		Execute: campaign.Execute{
			Type:   "http",
			Target: "https://example.com",
		},
	}

	r := sh.Execute(context.Background(), stage)
	if !r.Skipped {
		t.Fatal("expected non-shell type to be skipped")
	}
	if !strings.Contains(r.SkipNote, "http") {
		t.Fatalf("expected skip note about http type, got: %q", r.SkipNote)
	}
}

func TestShellCleanup(t *testing.T) {
	skipIfWindows(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "cleanup-marker")

	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "cleanup-test",
		Execute: campaign.Execute{
			Type:    "shell",
			Cleanup: []string{"touch " + marker},
		},
	}

	err := sh.Cleanup(context.Background(), stage)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if _, err := os.Stat(marker); os.IsNotExist(err) {
		t.Fatal("cleanup command did not create marker file")
	}
}

func TestShellCleanupPartialFailure(t *testing.T) {
	skipIfWindows(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "second-marker")

	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "cleanup-partial",
		Execute: campaign.Execute{
			Type: "shell",
			Cleanup: []string{
				"false",           // fails
				"touch " + marker, // should still run
			},
		},
	}

	err := sh.Cleanup(context.Background(), stage)
	if err == nil {
		t.Fatal("expected error from failing cleanup command")
	}
	// Second cleanup should still have run (best-effort).
	if _, err := os.Stat(marker); os.IsNotExist(err) {
		t.Fatal("second cleanup command should run even after first fails")
	}
}

func TestShellContextCancel(t *testing.T) {
	skipIfWindows(t)
	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "cancel-test",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"sleep 30"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	r := sh.Execute(ctx, stage)
	elapsed := time.Since(start)

	if r.Success {
		t.Fatal("expected cancellation failure")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("context cancel did not kill process: elapsed %v", elapsed)
	}
}

func TestShellWorkDir(t *testing.T) {
	skipIfWindows(t)
	dir := t.TempDir()
	sh := NewShell(ShellConfig{WorkDir: dir})
	stage := campaign.Stage{
		ID: "workdir",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"pwd"},
		},
	}

	r := sh.Execute(context.Background(), stage)
	if !r.Success {
		t.Fatalf("expected success, got: %v", r.Error)
	}
	// pwd output should contain the temp dir path.
	if !strings.Contains(r.Output, dir) {
		t.Fatalf("expected output to contain workdir %q, got: %q", dir, r.Output)
	}
}

func TestShellOutputCap(t *testing.T) {
	skipIfWindows(t)
	// Set a tiny cap so we can trigger truncation easily.
	sh := NewShell(ShellConfig{MaxOutput: 64})
	stage := campaign.Stage{
		ID: "cap-test",
		Execute: campaign.Execute{
			Type: "shell",
			Commands: []string{
				// Generate output larger than 64 bytes.
				"head -c 200 /dev/zero | tr '\\0' 'A'",
			},
		},
	}

	r := sh.Execute(context.Background(), stage)
	if !r.Success {
		t.Fatalf("expected success, got: %v", r.Error)
	}
	if !strings.Contains(r.Output, "truncated") {
		t.Fatalf("expected truncation marker in output, got %d bytes: %q", len(r.Output), r.Output)
	}
	// Total output should be well under 200 bytes.
	if len(r.Output) > 200 {
		t.Fatalf("output not capped: %d bytes", len(r.Output))
	}
}

func TestShellEmptyCommands(t *testing.T) {
	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "empty",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{},
		},
	}

	r := sh.Execute(context.Background(), stage)
	if !r.Success {
		t.Fatalf("expected success for empty commands, got: %v", r.Error)
	}
	if r.Output != "(no commands)" {
		t.Fatalf("expected '(no commands)', got: %q", r.Output)
	}
}

func TestShellName(t *testing.T) {
	sh := NewShell(ShellConfig{})
	if sh.Name() != "live" {
		t.Fatalf("expected Name() = 'live', got %q", sh.Name())
	}
}

func TestShellDelay(t *testing.T) {
	skipIfWindows(t)
	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "delay-test",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"echo delayed"},
		},
		Delay: campaign.Duration{Duration: 200 * time.Millisecond},
	}

	start := time.Now()
	r := sh.Execute(context.Background(), stage)
	elapsed := time.Since(start)

	if !r.Success {
		t.Fatalf("expected success, got: %v", r.Error)
	}
	if elapsed < 150*time.Millisecond {
		t.Fatalf("delay was not applied: elapsed %v", elapsed)
	}
}

func TestShellDelayCancelled(t *testing.T) {
	sh := NewShell(ShellConfig{})
	stage := campaign.Stage{
		ID: "delay-cancel",
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"echo should-not-run"},
		},
		Delay: campaign.Duration{Duration: 30 * time.Second},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	r := sh.Execute(ctx, stage)
	elapsed := time.Since(start)

	if r.Success {
		t.Fatal("expected failure on cancelled delay")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("cancel during delay took too long: %v", elapsed)
	}
}
