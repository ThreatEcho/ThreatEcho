// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

//go:build !windows

package executor

import (
	"os/exec"
	"syscall"
	"time"
)

// setProcGroup configures the command to run in its own process group
// and kills the entire group on context cancellation. This ensures child
// processes (e.g. sleep spawned by sh -c) are also terminated.
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			// Kill the entire process group (negative PID).
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	// WaitDelay lets cmd.Wait return after Cancel fires, even if child
	// processes keep the pipe open (e.g. "sleep" outliving "sh").
	cmd.WaitDelay = 3 * time.Second
}
