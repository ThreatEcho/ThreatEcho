// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package executor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

// ShellConfig controls live shell execution behavior.
type ShellConfig struct {
	// DenyElevated refuses to run stages with execute.elevated: true.
	// Default true — operator must explicitly opt in to privileged execution.
	DenyElevated bool

	// MaxOutput caps combined stdout+stderr per stage (bytes).
	// 0 means use DefaultMaxOutput.
	MaxOutput int

	// ShellPath overrides the shell binary. Empty means auto-detect:
	// "cmd" on Windows, "sh" on everything else.
	ShellPath string

	// WorkDir sets the working directory for commands. Empty means
	// inherit the process working directory.
	WorkDir string

	// Env sets additional environment variables for commands.
	// Each entry is "KEY=VALUE". These are appended to the inherited env.
	Env []string
}

// DefaultMaxOutput is the output cap when ShellConfig.MaxOutput is 0.
const DefaultMaxOutput = 1 << 20 // 1 MiB

// Shell is a live executor that runs shell commands from campaign stages.
type Shell struct {
	cfg ShellConfig
}

// NewShell creates a live shell executor with the given configuration.
func NewShell(cfg ShellConfig) *Shell {
	return &Shell{cfg: cfg}
}

// Name returns the executor type for display.
func (s *Shell) Name() string {
	return "live"
}

// Execute runs the stage's commands via the system shell.
//
// Safety controls:
//   - DenyElevated: refuses stages marked elevated unless the operator opted in.
//   - Context cancellation: kills the process group on ctx.Done().
//   - Stage timeout: applies stage.Timeout as a deadline on top of ctx.
//   - Stage delay: waits stage.Delay before execution (cancellable).
//   - Output capping: truncates combined stdout+stderr at MaxOutput bytes.
//   - Non-shell types: skips stages with execute.type != "shell".
func (s *Shell) Execute(ctx context.Context, stage campaign.Stage) Result {
	// Only handle shell/powershell-type stages.
	if stage.Execute.Type != "shell" && stage.Execute.Type != "powershell" {
		return Result{
			StageID:  stage.ID,
			Skipped:  true,
			SkipNote: fmt.Sprintf("executor does not handle type %q", stage.Execute.Type),
		}
	}

	// Safety: deny elevated execution unless the operator opted in.
	if stage.Execute.Elevated && s.cfg.DenyElevated {
		return Result{
			StageID: stage.ID,
			Success: false,
			Error:   fmt.Errorf("stage requests elevated execution but DenyElevated is set"),
		}
	}

	// No commands → nothing to do.
	if len(stage.Execute.Commands) == 0 {
		return Result{
			StageID: stage.ID,
			Success: true,
			Output:  "(no commands)",
		}
	}

	// Apply stage delay (cancellable).
	if stage.Delay.Duration > 0 {
		select {
		case <-time.After(stage.Delay.Duration):
		case <-ctx.Done():
			return Result{
				StageID: stage.ID,
				Success: false,
				Error:   ctx.Err(),
			}
		}
	}

	// Apply stage timeout on top of the parent context.
	if stage.Timeout.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, stage.Timeout.Duration)
		defer cancel()
	}

	// Determine shell binary and invocation flag.
	shell, flag := s.shellCmd()
	if stage.Execute.Type == "powershell" {
		shell, flag = "powershell", "-Command"
	}

	maxOutput := s.cfg.MaxOutput
	if maxOutput <= 0 {
		maxOutput = DefaultMaxOutput
	}

	// Run each command sequentially; stop on first failure.
	var allOutput strings.Builder
	for i, cmdStr := range stage.Execute.Commands {
		if i > 0 {
			allOutput.WriteString("\n")
		}

		cmd := exec.CommandContext(ctx, shell, flag, cmdStr)
		setProcGroup(cmd)
		if s.cfg.WorkDir != "" {
			cmd.Dir = s.cfg.WorkDir
		}
		if len(s.cfg.Env) > 0 {
			cmd.Env = append(cmd.Environ(), s.cfg.Env...)
		}

		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf

		err := cmd.Run()

		// Cap the output from this command.
		out := buf.String()
		remaining := maxOutput - allOutput.Len()
		if remaining <= 0 {
			allOutput.WriteString("\n... output truncated (cap reached) ...")
			break
		}
		if len(out) > remaining {
			allOutput.WriteString(out[:remaining])
			allOutput.WriteString("\n... output truncated (cap reached) ...")
		} else {
			allOutput.WriteString(out)
		}

		if err != nil {
			return Result{
				StageID: stage.ID,
				Success: false,
				Output:  allOutput.String(),
				Error:   fmt.Errorf("command %d failed: %w", i+1, err),
			}
		}
	}

	return Result{
		StageID: stage.ID,
		Success: true,
		Output:  allOutput.String(),
	}
}

// Cleanup runs the stage's cleanup commands. Best-effort: runs all commands
// even if some fail, returns the first error encountered.
func (s *Shell) Cleanup(ctx context.Context, stage campaign.Stage) error {
	if len(stage.Execute.Cleanup) == 0 {
		return nil
	}

	shell, flag := s.shellCmd()
	if stage.Execute.Type == "powershell" {
		shell, flag = "powershell", "-Command"
	}
	var firstErr error

	for _, cmdStr := range stage.Execute.Cleanup {
		cmd := exec.CommandContext(ctx, shell, flag, cmdStr)
		setProcGroup(cmd)
		if s.cfg.WorkDir != "" {
			cmd.Dir = s.cfg.WorkDir
		}
		if len(s.cfg.Env) > 0 {
			cmd.Env = append(cmd.Environ(), s.cfg.Env...)
		}
		if err := cmd.Run(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("cleanup %q: %w", cmdStr, err)
		}
	}
	return firstErr
}

// shellCmd returns the shell binary and its command-string flag.
func (s *Shell) shellCmd() (string, string) {
	if s.cfg.ShellPath != "" {
		// Custom shell: detect Windows cmd by name.
		base := s.cfg.ShellPath
		if strings.HasSuffix(base, "cmd") || strings.HasSuffix(base, "cmd.exe") {
			return s.cfg.ShellPath, "/c"
		}
		return s.cfg.ShellPath, "-c"
	}
	if runtime.GOOS == "windows" {
		return "cmd", "/c"
	}
	return "sh", "-c"
}
