// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

//go:build windows

package executor

import (
	"os/exec"
	"time"
)

// setProcGroup configures WaitDelay on Windows so that orphaned child
// processes (e.g. rundll32.exe surviving a killed cmd.exe) do not block
// cmd.Wait indefinitely. Go's default CommandContext already calls
// TerminateProcess on cancel; WaitDelay ensures the wait returns even
// when children hold stdout/stderr pipes open.
func setProcGroup(cmd *exec.Cmd) {
	cmd.WaitDelay = 5 * time.Second
}
