// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package runner

import (
	"fmt"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

// Precondition describes a requirement that must hold before a stage runs.
type Precondition struct {
	Type    string `yaml:"type" json:"type"`
	Value   string `yaml:"value" json:"value"`
	Message string `yaml:"message,omitempty" json:"message,omitempty"`
}

// CheckResult reports whether a precondition passed.
type CheckResult struct {
	Precondition Precondition `json:"precondition"`
	Passed       bool         `json:"passed"`
	Detail       string       `json:"detail,omitempty"`
}

// CheckAll evaluates all preconditions for a stage. Stops on the first failure
// and returns all results evaluated so far.
func CheckAll(stage campaign.Stage, elevated bool) []CheckResult {
	pcs := InferPreconditions(stage)
	var results []CheckResult
	for _, pc := range pcs {
		cr := Evaluate(pc, elevated)
		results = append(results, cr)
		if !cr.Passed {
			break
		}
	}
	return results
}

// Passed returns true if all check results passed.
func Passed(results []CheckResult) bool {
	for _, r := range results {
		if !r.Passed {
			return false
		}
	}
	return true
}

// InferPreconditions derives preconditions from a campaign stage's metadata.
// This is the ThreatEcho approach: preconditions are inferred from stage
// fields (elevated, platform, commands) rather than declared in a separate
// block with a custom DSL.
func InferPreconditions(stage campaign.Stage) []Precondition {
	var pcs []Precondition

	// Platform check.
	if len(stage.Platform) > 0 {
		pcs = append(pcs, Precondition{
			Type:    "platform",
			Value:   strings.Join(stage.Platform, ","),
			Message: fmt.Sprintf("stage requires platform %v", stage.Platform),
		})
	}

	// Elevation check.
	if stage.Execute.Elevated {
		pcs = append(pcs, Precondition{
			Type:    "elevated",
			Value:   "true",
			Message: "stage requires elevated privileges (root/Administrator)",
		})
	}

	// Tool availability: scan commands for known binaries.
	if stage.Execute.Type == "shell" || stage.Execute.Type == "powershell" {
		for _, tool := range extractTools(stage.Execute.Commands) {
			pcs = append(pcs, Precondition{
				Type:    "tool",
				Value:   tool,
				Message: fmt.Sprintf("command requires %q in PATH", tool),
			})
		}
	}

	return pcs
}

// Evaluate checks a single precondition against the current environment.
func Evaluate(pc Precondition, elevated bool) CheckResult {
	switch pc.Type {
	case "platform":
		return checkPlatform(pc)
	case "elevated":
		return checkElevated(pc, elevated)
	case "tool":
		return checkTool(pc)
	default:
		return CheckResult{
			Precondition: pc,
			Passed:       false,
			Detail:       fmt.Sprintf("unknown precondition type %q", pc.Type),
		}
	}
}

func checkPlatform(pc Precondition) CheckResult {
	platforms := strings.Split(pc.Value, ",")
	got := runtime.GOOS
	for _, want := range platforms {
		if matchPlatform(got, strings.TrimSpace(want)) {
			return CheckResult{Precondition: pc, Passed: true, Detail: got}
		}
	}
	return CheckResult{
		Precondition: pc,
		Passed:       false,
		Detail:       fmt.Sprintf("running on %s, need %s", got, pc.Value),
	}
}

func matchPlatform(goos, want string) bool {
	switch want {
	case "linux":
		return goos == "linux"
	case "windows":
		return goos == "windows"
	case "macos", "darwin":
		return goos == "darwin"
	default:
		return goos == want
	}
}

func checkElevated(pc Precondition, allowed bool) CheckResult {
	if !allowed {
		return CheckResult{
			Precondition: pc,
			Passed:       false,
			Detail:       "elevated execution not permitted by operator",
		}
	}

	privileged := isPrivileged()
	if !privileged {
		return CheckResult{
			Precondition: pc,
			Passed:       false,
			Detail:       "process is not running with elevated privileges",
		}
	}

	return CheckResult{Precondition: pc, Passed: true, Detail: "running elevated"}
}

func isPrivileged() bool {
	if runtime.GOOS == "windows" {
		// On Windows, check if running as Administrator via net session.
		cmd := exec.Command("cmd", "/c", "net session >nul 2>&1")
		return cmd.Run() == nil
	}
	u, err := user.Current()
	if err != nil {
		return false
	}
	return u.Uid == "0"
}

func checkTool(pc Precondition) CheckResult {
	_, err := exec.LookPath(pc.Value)
	if err != nil {
		return CheckResult{
			Precondition: pc,
			Passed:       false,
			Detail:       fmt.Sprintf("%q not found in PATH", pc.Value),
		}
	}
	return CheckResult{Precondition: pc, Passed: true, Detail: "found"}
}

// hasORFallback returns true if the command contains a shell OR (||) fallback,
// meaning the primary tool is optional.
func hasORFallback(cmd string) bool {
	return strings.Contains(cmd, "||")
}

// isScriptFile returns true if the name has a script/file extension,
// indicating it is an inline script rather than a system tool.
func isScriptFile(name string) bool {
	exts := []string{".sh", ".py", ".pl", ".rb", ".ps1", ".bat", ".cmd", ".vbs", ".js"}
	lower := strings.ToLower(name)
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// isPSCmdlet returns true if the token matches PowerShell Verb-Noun cmdlet
// naming (e.g. Start-Process, Get-ChildItem, Invoke-WmiMethod). These are
// built into PowerShell and will not be found via exec.LookPath.
func isPSCmdlet(token string) bool {
	psVerbs := []string{
		"Add-", "Clear-", "Close-", "Compare-", "Convert", "Copy-",
		"Debug-", "Disable-", "Enable-", "Enter-", "Exit-", "Export-",
		"Find-", "ForEach-", "Format-", "Get-", "Group-", "Import-",
		"Install-", "Invoke-", "Join-", "Measure-", "Move-", "New-",
		"Open-", "Out-", "Pop-", "Push-", "Read-", "Receive-",
		"Register-", "Remove-", "Rename-", "Repair-", "Restart-",
		"Restore-", "Resume-", "Save-", "Select-", "Send-", "Set-",
		"Show-", "Sort-", "Split-", "Start-", "Stop-", "Suspend-",
		"Switch-", "Test-", "Uninstall-", "Unregister-", "Update-",
		"Wait-", "Where-", "Write-",
	}
	for _, v := range psVerbs {
		if strings.HasPrefix(token, v) {
			return true
		}
	}
	return false
}

// isPSVarAssignment returns true if the command starts with a PowerShell
// variable assignment ($var = ...). The RHS is a string literal, not
// executable code, so scanning it for tool names produces false positives.
func isPSVarAssignment(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if !strings.HasPrefix(cmd, "$") {
		return false
	}
	parts := strings.SplitN(cmd, "=", 2)
	if len(parts) < 2 {
		return false
	}
	lhs := strings.TrimSpace(parts[0])
	return !strings.ContainsAny(lhs, " \t(")
}

// extractTools pulls the first token (binary name) from shell commands,
// filtering out shell builtins, redirections, and common prefixes.
func extractTools(commands []string) []string {
	seen := make(map[string]bool)
	var tools []string

	builtins := map[string]bool{
		"echo": true, "cd": true, "set": true, "export": true,
		"if": true, "for": true, "while": true, "case": true,
		"true": true, "false": true, "exit": true, "return": true,
		"test": true, "[": true, "read": true, "shift": true,
		"unset": true, "local": true, "declare": true,
		"type": true, "source": true, "pushd": true, "popd": true,
	}

	for _, cmd := range commands {
		if hasORFallback(cmd) {
			continue
		}
		if isPSVarAssignment(cmd) {
			continue
		}
		bin := firstBinary(cmd)
		if bin == "" || builtins[bin] || seen[bin] || isScriptFile(bin) {
			continue
		}
		seen[bin] = true
		tools = append(tools, bin)
	}
	return tools
}

// firstBinary extracts the binary name from a shell command string.
// Handles env prefixes (VAR=val cmd), sudo/su prefixes, and pipes.
func firstBinary(cmd string) string {
	cmd = strings.TrimSpace(cmd)

	// Strip leading subshell/group syntax.
	cmd = strings.TrimLeft(cmd, "({")

	// Take only the first pipeline segment.
	if idx := strings.Index(cmd, "|"); idx >= 0 {
		cmd = cmd[:idx]
	}

	parts := strings.Fields(cmd)
	for _, p := range parts {
		// Strip surrounding syntax early so checks see the actual token.
		p = strings.TrimRight(p, ");}")
		p = strings.Trim(p, "'\"")
		if p == "" {
			continue
		}
		// Skip environment variable assignments.
		if strings.Contains(p, "=") && !strings.HasPrefix(p, "-") {
			continue
		}
		// Skip sudo/su wrappers.
		if p == "sudo" || p == "su" {
			continue
		}
		// Skip flags (start with -).
		if strings.HasPrefix(p, "-") {
			continue
		}
		// Skip shell redirections and XML/markup.
		if strings.HasPrefix(p, ">") || strings.HasPrefix(p, "<") || p == "2>/dev/null" || p == "2>&1" {
			continue
		}
		// Skip PowerShell variables and expressions.
		if strings.HasPrefix(p, "$") || strings.HasPrefix(p, "@") {
			continue
		}
		// Skip semicolons (command separators).
		if p == ";" {
			continue
		}
		// Skip PowerShell cmdlets (Verb-Noun pattern).
		if isPSCmdlet(p) {
			continue
		}

		// Extract basename from path.
		if idx := strings.LastIndex(p, "/"); idx >= 0 {
			p = p[idx+1:]
		}
		if idx := strings.LastIndex(p, "\\"); idx >= 0 {
			p = p[idx+1:]
		}

		if p != "" {
			return p
		}
	}
	return ""
}
