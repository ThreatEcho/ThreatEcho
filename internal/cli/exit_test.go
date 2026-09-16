// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestError_Message(t *testing.T) {
	e := Validation("campaign %q invalid", "apt29")
	if e.Error() != `campaign "apt29" invalid` {
		t.Errorf("got %q", e.Error())
	}
}

func TestError_WithCause(t *testing.T) {
	cause := fmt.Errorf("file not found")
	e := ValidationWrap(cause, "loading campaign")
	want := "loading campaign: file not found"
	if e.Error() != want {
		t.Errorf("got %q, want %q", e.Error(), want)
	}
	if !errors.Is(e, cause) {
		t.Error("Unwrap did not return cause")
	}
}

func TestError_Codes(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		code int
	}{
		{"validation", Validation("bad"), ExitValidation},
		{"policy_denied", PolicyDenied("denied"), ExitPolicyDenied},
		{"runtime", Runtime("crash"), ExitRuntime},
		{"io", IOError("no file"), ExitIO},
		{"usage", UsageError("missing arg"), ExitUsage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.code {
				t.Errorf("Code = %d, want %d", tt.err.Code, tt.code)
			}
		})
	}
}

func TestDieCode_NilError(t *testing.T) {
	if code := DieCode(nil); code != ExitOK {
		t.Errorf("DieCode(nil) = %d, want %d", code, ExitOK)
	}
}

func TestDieCode_CLIError(t *testing.T) {
	e := PolicyDenied("blocked")
	if code := DieCode(e); code != ExitPolicyDenied {
		t.Errorf("DieCode = %d, want %d", code, ExitPolicyDenied)
	}
}

func TestDieCode_PlainError(t *testing.T) {
	e := fmt.Errorf("something broke")
	if code := DieCode(e); code != ExitRuntime {
		t.Errorf("DieCode = %d, want %d", code, ExitRuntime)
	}
}

func TestDieW_FormatsOutput(t *testing.T) {
	var buf bytes.Buffer
	e := IOError("disk full")
	DieW(&buf, e)
	if got := buf.String(); got != "✗ disk full\n" {
		t.Errorf("DieW output = %q", got)
	}
}

func TestDieW_NilDoesNothing(t *testing.T) {
	var buf bytes.Buffer
	DieW(&buf, nil)
	if buf.Len() != 0 {
		t.Error("DieW(nil) should produce no output")
	}
}

func TestDieW_PlainError(t *testing.T) {
	var buf bytes.Buffer
	DieW(&buf, fmt.Errorf("oops"))
	if got := buf.String(); got != "✗ oops\n" {
		t.Errorf("DieW output = %q", got)
	}
}

func TestValidationErrors_Format(t *testing.T) {
	errs := []string{"missing name", "bad technique"}
	got := ValidationErrors("test-campaign", errs)
	if len(got) == 0 {
		t.Fatal("empty output")
	}
	// Should contain the count and both errors.
	for _, sub := range []string{"2 issue(s)", "missing name", "bad technique"} {
		if !bytes.Contains([]byte(got), []byte(sub)) {
			t.Errorf("output missing %q", sub)
		}
	}
}

func TestWrapFunctions(t *testing.T) {
	cause := fmt.Errorf("underlying")
	tests := []struct {
		name string
		err  *Error
		code int
	}{
		{"ValidationWrap", ValidationWrap(cause, "ctx"), ExitValidation},
		{"RuntimeWrap", RuntimeWrap(cause, "ctx"), ExitRuntime},
		{"IOWrap", IOWrap(cause, "ctx"), ExitIO},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.code {
				t.Errorf("Code = %d, want %d", tt.err.Code, tt.code)
			}
			if !errors.Is(tt.err, cause) {
				t.Error("cause not preserved")
			}
		})
	}
}

func TestErrorHint(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{"campaign not found by name", IOError("campaign not found: %s", "apt28"), "campaigns list"},
		{"campaign not found", IOWrap(fmt.Errorf("open campaign.yaml: no such file or directory"), "loading campaign"), "threatecho init"},
		{"policy not found", IOWrap(fmt.Errorf("open policy.yaml: no such file or directory"), "loading policy"), "policy generate"},
		{"agent not found", IOWrap(fmt.Errorf("open agents/: no such file or directory"), "loading agent inventory"), "agents/ directory"},
		{"permission denied", IOWrap(fmt.Errorf("open x: permission denied"), "loading"), "file permissions"},
		{"yaml parse error", IOWrap(fmt.Errorf("yaml: line 5: mapping values are not allowed"), "parsing campaign YAML"), "YAML syntax"},
		{"connection refused", RuntimeWrap(fmt.Errorf("dial tcp 10.0.0.1:22: connection refused"), "deploying"), "target host is reachable"},
		{"auth failure", RuntimeWrap(fmt.Errorf("401 Unauthorized"), "WinRM authentication failed"), "credentials"},
		{"timeout", RuntimeWrap(fmt.Errorf("context deadline exceeded"), "stage execution"), "timed out"},
		{"no hint", Runtime("something broke"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errorHint(tt.err)
			if tt.want == "" && got != "" {
				t.Errorf("expected no hint, got %q", got)
			}
			if tt.want != "" && got == "" {
				t.Errorf("expected hint containing %q, got empty", tt.want)
			}
			if tt.want != "" && got != "" {
				if !contains(got, tt.want) {
					t.Errorf("hint %q should contain %q", got, tt.want)
				}
			}
		})
	}
}

func TestDieW_ShowsHint(t *testing.T) {
	var buf bytes.Buffer
	e := IOWrap(fmt.Errorf("open campaigns/: no such file or directory"), "loading campaign")
	DieW(&buf, e)
	out := buf.String()
	if !contains(out, "hint:") {
		t.Errorf("DieW should print a hint for file-not-found errors, got: %s", out)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || findSubstring(s, sub))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
