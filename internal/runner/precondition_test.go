// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package runner

import (
	"runtime"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/campaign"
)

func TestCheckPlatform(t *testing.T) {
	pc := Precondition{Type: "platform", Value: runtime.GOOS}
	cr := Evaluate(pc, false)
	if !cr.Passed {
		t.Fatalf("expected platform check to pass for %s", runtime.GOOS)
	}

	pc.Value = "nonexistentos"
	cr = Evaluate(pc, false)
	if cr.Passed {
		t.Fatal("expected platform check to fail for nonexistentos")
	}
}

func TestCheckPlatformMulti(t *testing.T) {
	pc := Precondition{Type: "platform", Value: "linux,windows,darwin"}
	cr := Evaluate(pc, false)
	if !cr.Passed {
		t.Fatalf("expected multi-platform check to pass, got: %s", cr.Detail)
	}
}

func TestCheckElevated_Denied(t *testing.T) {
	pc := Precondition{Type: "elevated", Value: "true"}
	cr := Evaluate(pc, false)
	if cr.Passed {
		t.Fatal("expected elevated check to fail when not allowed")
	}
	if cr.Detail != "elevated execution not permitted by operator" {
		t.Fatalf("unexpected detail: %s", cr.Detail)
	}
}

func TestCheckTool_Exists(t *testing.T) {
	// "sh" exists on all Unix, "cmd" on Windows.
	tool := "sh"
	if runtime.GOOS == "windows" {
		tool = "cmd"
	}
	pc := Precondition{Type: "tool", Value: tool}
	cr := Evaluate(pc, false)
	if !cr.Passed {
		t.Fatalf("expected %s to be found", tool)
	}
}

func TestCheckTool_Missing(t *testing.T) {
	pc := Precondition{Type: "tool", Value: "nonexistent_binary_xyz"}
	cr := Evaluate(pc, false)
	if cr.Passed {
		t.Fatal("expected missing tool check to fail")
	}
}

func TestInferPreconditions(t *testing.T) {
	stage := campaign.Stage{
		ID:       "test",
		Platform: []string{"linux"},
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"whoami", "cat /etc/passwd"},
			Elevated: true,
		},
	}

	pcs := InferPreconditions(stage)
	types := map[string]int{}
	for _, pc := range pcs {
		types[pc.Type]++
	}

	if types["platform"] != 1 {
		t.Errorf("expected 1 platform precondition, got %d", types["platform"])
	}
	if types["elevated"] != 1 {
		t.Errorf("expected 1 elevated precondition, got %d", types["elevated"])
	}
	if types["tool"] < 1 {
		t.Error("expected at least 1 tool precondition")
	}
}

func TestCheckAll_StopsOnFailure(t *testing.T) {
	stage := campaign.Stage{
		ID:       "test",
		Platform: []string{"nonexistentos"},
		Execute: campaign.Execute{
			Type:     "shell",
			Commands: []string{"whoami"},
			Elevated: true,
		},
	}

	results := CheckAll(stage, false)
	if len(results) != 1 {
		t.Fatalf("expected 1 result (stop on first failure), got %d", len(results))
	}
	if results[0].Passed {
		t.Fatal("expected platform check to fail")
	}
}

func TestExtractTools(t *testing.T) {
	commands := []string{
		"whoami",
		"cat /etc/passwd",
		"sudo -l 2>/dev/null",
		"ip addr show",
		"find / -perm -4000 -type f 2>/dev/null | head -30",
		"echo 'test'",
		"VAR=value somecommand --flag",
		"/usr/bin/systemctl list-units",
	}

	tools := extractTools(commands)
	toolSet := make(map[string]bool)
	for _, t := range tools {
		toolSet[t] = true
	}

	expected := []string{"whoami", "cat", "ip", "find", "somecommand", "systemctl"}
	for _, e := range expected {
		if !toolSet[e] {
			t.Errorf("expected tool %q in results, got %v", e, tools)
		}
	}

	// echo is a builtin, should be excluded.
	if toolSet["echo"] {
		t.Error("echo should be excluded as a builtin")
	}
	// sudo should be excluded as a wrapper.
	if toolSet["sudo"] {
		t.Error("sudo should be excluded as a wrapper")
	}
}

func TestExtractToolsSubshellSyntax(t *testing.T) {
	commands := []string{
		`(crontab -l 2>/dev/null; echo "test") | crontab -`,
		"{find / -perm -4000 2>/dev/null; echo done;}",
	}
	tools := extractTools(commands)
	toolSet := make(map[string]bool)
	for _, tool := range tools {
		toolSet[tool] = true
	}

	if !toolSet["crontab"] {
		t.Error("crontab should be extracted from subshell")
	}
	if toolSet["(crontab"] {
		t.Error("(crontab should not appear — parens must be stripped")
	}
	if !toolSet["find"] {
		t.Error("find should be extracted from brace group")
	}
}

func TestHasORFallback(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{"whoami", false},
		{"cat /etc/passwd", false},
		{"last || echo 'not available'", true},
		{"iptables -L -n || echo 'iptables not found'", true},
		{"crontab -l || true", true},
		{"getcap -r / 2>/dev/null || echo 'getcap not installed'", true},
		{"find / -perm -4000 2>/dev/null", false},
		{"echo test", false},
	}
	for _, tt := range tests {
		got := hasORFallback(tt.cmd)
		if got != tt.want {
			t.Errorf("hasORFallback(%q) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}

func TestIsScriptFile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"whoami", false},
		{"cat", false},
		{"bash", false},
		{"test.sh", true},
		{"deploy.py", true},
		{"run.pl", true},
		{"script.ps1", true},
		{"setup.bat", true},
		{"install.cmd", true},
		{"payload.vbs", true},
		{"te_exec_test.sh", true},
		{"SCRIPT.SH", true},
	}
	for _, tt := range tests {
		got := isScriptFile(tt.name)
		if got != tt.want {
			t.Errorf("isScriptFile(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestExtractToolsSkipsFallbackCommands(t *testing.T) {
	commands := []string{
		"whoami",
		"last || echo 'not available'",
		"iptables -L -n || echo 'iptables not found'",
		"cat /etc/passwd",
		"getcap -r / 2>/dev/null || echo 'not installed'",
	}

	tools := extractTools(commands)
	toolSet := make(map[string]bool)
	for _, tool := range tools {
		toolSet[tool] = true
	}

	if !toolSet["whoami"] {
		t.Error("whoami should be extracted (no fallback)")
	}
	if !toolSet["cat"] {
		t.Error("cat should be extracted (no fallback)")
	}
	if toolSet["last"] {
		t.Error("last should be skipped (has || fallback)")
	}
	if toolSet["iptables"] {
		t.Error("iptables should be skipped (has || fallback)")
	}
	if toolSet["getcap"] {
		t.Error("getcap should be skipped (has || fallback)")
	}
}

func TestExtractToolsSkipsScriptFiles(t *testing.T) {
	commands := []string{
		"chmod +x /tmp/te_exec_test.sh",
		"/tmp/te_exec_test.sh",
		"whoami",
		"./deploy.py --target prod",
	}

	tools := extractTools(commands)
	toolSet := make(map[string]bool)
	for _, tool := range tools {
		toolSet[tool] = true
	}

	if !toolSet["chmod"] {
		t.Error("chmod should be extracted")
	}
	if !toolSet["whoami"] {
		t.Error("whoami should be extracted")
	}
	if toolSet["te_exec_test.sh"] {
		t.Error("te_exec_test.sh should be skipped (script file)")
	}
	if toolSet["deploy.py"] {
		t.Error("deploy.py should be skipped (script file)")
	}
}

func TestExtractToolsSkipsBuiltins(t *testing.T) {
	commands := []string{
		"type C:\\Windows\\Temp\\file.txt",
		"echo hello",
		"certutil.exe -encode foo bar",
		"source ~/.bashrc",
	}
	tools := extractTools(commands)
	toolSet := make(map[string]bool)
	for _, t := range tools {
		toolSet[t] = true
	}
	if toolSet["type"] {
		t.Error("type should be skipped (shell builtin)")
	}
	if toolSet["echo"] {
		t.Error("echo should be skipped (shell builtin)")
	}
	if toolSet["source"] {
		t.Error("source should be skipped (shell builtin)")
	}
	if !toolSet["certutil.exe"] {
		t.Error("certutil.exe should be extracted")
	}
}

func TestExtractToolsSkipsPSVariables(t *testing.T) {
	commands := []string{
		`$sct = 'xml content'; Set-Content -Path C:\test.sct -Value $sct`,
		`Start-Process regsvr32.exe -ArgumentList "/s foo"`,
		`@results = Get-ChildItem`,
		`regsvr32.exe /s /n foo.dll`,
	}
	tools := extractTools(commands)
	toolSet := make(map[string]bool)
	for _, t := range tools {
		toolSet[t] = true
	}
	if toolSet["$sct"] {
		t.Error("$sct should be skipped (PS variable)")
	}
	if toolSet["@results"] {
		t.Error("@results should be skipped (PS expression)")
	}
	if toolSet["Start-Process"] {
		t.Error("Start-Process should be skipped (PS cmdlet)")
	}
	if !toolSet["regsvr32.exe"] {
		t.Error("regsvr32.exe should be extracted (real binary)")
	}
}

func TestIsPSVarAssignment(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{`$sct = '<?XML...'; Set-Content ...`, true},
		{`$x = "hello"`, true},
		{`$result = Get-Process`, true},
		{`Start-Process regsvr32.exe`, false},
		{`echo hello`, false},
		{`$(Get-Date)`, false},
	}
	for _, tt := range tests {
		got := isPSVarAssignment(tt.cmd)
		if got != tt.want {
			t.Errorf("isPSVarAssignment(%q) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}

func TestExtractToolsPowerShellSetContent(t *testing.T) {
	commands := []string{
		`$sct = '<?XML version="1.0"?><scriptlet></scriptlet>'; Set-Content -Path C:\test.sct -Value $sct`,
		`Start-Process regsvr32.exe -ArgumentList "/s foo"`,
		`Get-ChildItem C:\Temp`,
	}
	tools := extractTools(commands)
	toolSet := make(map[string]bool)
	for _, t := range tools {
		toolSet[t] = true
	}
	if toolSet["<?XML"] {
		t.Error("<?XML should be skipped")
	}
	if toolSet["$sct"] {
		t.Error("$sct should be skipped (PS variable)")
	}
	if toolSet["Set-Content"] {
		t.Error("Set-Content should be skipped (inside PS var assignment line)")
	}
	if toolSet["Start-Process"] {
		t.Error("Start-Process should be skipped (PS cmdlet)")
	}
	if toolSet["Get-ChildItem"] {
		t.Error("Get-ChildItem should be skipped (PS cmdlet)")
	}
}

func TestPassed(t *testing.T) {
	pass := []CheckResult{{Passed: true}, {Passed: true}}
	if !Passed(pass) {
		t.Fatal("expected Passed to return true for all-passing")
	}

	fail := []CheckResult{{Passed: true}, {Passed: false}}
	if Passed(fail) {
		t.Fatal("expected Passed to return false with a failure")
	}

	if !Passed(nil) {
		t.Fatal("expected Passed to return true for empty slice")
	}
}
