// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package cli provides shared CLI infrastructure: exit codes, error types,
// and output helpers used across all ThreatEcho commands.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Exit codes used by ThreatEcho CLI. Each code signals a distinct failure class
// so CI pipelines can branch on the result without parsing stderr.
const (
	ExitOK           = 0  // Success.
	ExitValidation   = 1  // Campaign/policy YAML validation failed.
	ExitPolicyDenied = 2  // Policy evaluation found denied violations.
	ExitRuntime      = 3  // Execution error (simulation, run, export).
	ExitIO           = 4  // File I/O error (read, write, directory).
	ExitUsage        = 64 // Bad CLI usage (missing args, unknown command). Follows sysexits.h.
)

// Error wraps an error with a CLI exit code.
type Error struct {
	Code    int
	Message string
	Cause   error
}

// Error returns the formatted error message, including the cause if present.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// Unwrap returns the underlying cause for use with errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.Cause }

// Validation returns a validation error (exit code 1).
func Validation(msg string, args ...interface{}) *Error {
	return &Error{Code: ExitValidation, Message: fmt.Sprintf(msg, args...)}
}

// ValidationWrap returns a validation error wrapping a cause.
func ValidationWrap(cause error, msg string, args ...interface{}) *Error {
	return &Error{Code: ExitValidation, Message: fmt.Sprintf(msg, args...), Cause: cause}
}

// PolicyDenied returns a policy-denied error (exit code 2).
func PolicyDenied(msg string, args ...interface{}) *Error {
	return &Error{Code: ExitPolicyDenied, Message: fmt.Sprintf(msg, args...)}
}

// Runtime returns a runtime error (exit code 3).
func Runtime(msg string, args ...interface{}) *Error {
	return &Error{Code: ExitRuntime, Message: fmt.Sprintf(msg, args...)}
}

// RuntimeWrap returns a runtime error wrapping a cause.
func RuntimeWrap(cause error, msg string, args ...interface{}) *Error {
	return &Error{Code: ExitRuntime, Message: fmt.Sprintf(msg, args...), Cause: cause}
}

// IOError returns an I/O error (exit code 4).
func IOError(msg string, args ...interface{}) *Error {
	return &Error{Code: ExitIO, Message: fmt.Sprintf(msg, args...)}
}

// IOWrap returns an I/O error wrapping a cause.
func IOWrap(cause error, msg string, args ...interface{}) *Error {
	return &Error{Code: ExitIO, Message: fmt.Sprintf(msg, args...), Cause: cause}
}

// UsageError returns a usage error (exit code 64).
func UsageError(msg string, args ...interface{}) *Error {
	return &Error{Code: ExitUsage, Message: fmt.Sprintf(msg, args...)}
}

// Die prints an error message to stderr and exits with the appropriate code.
// If err is a *Error, its code is used; otherwise ExitRuntime.
func Die(err error) {
	DieW(os.Stderr, err)
}

// DieW is like Die but writes to a custom writer (for testing).
func DieW(w io.Writer, err error) {
	if err == nil {
		return
	}
	cliErr, ok := err.(*Error)
	if !ok {
		cliErr = &Error{Code: ExitRuntime, Message: err.Error()}
	}
	fmt.Fprintf(w, "✗ %s\n", cliErr.Error())
	if hint := errorHint(cliErr); hint != "" {
		fmt.Fprintf(w, "  hint: %s\n", hint)
	}
}

func errorHint(e *Error) string {
	msg := e.Error()
	if strings.Contains(msg, "campaign not found") {
		return "run 'threatecho campaigns list' to see available campaigns, or check the path"
	}
	if strings.Contains(msg, "no such file or directory") {
		if strings.Contains(msg, "campaign") {
			return "run 'threatecho init' to scaffold a workspace, or check the campaign path"
		}
		if strings.Contains(msg, "polic") {
			return "create a policy with 'threatecho policy generate', or pass -policy to specify the policy path"
		}
		if strings.Contains(msg, "agent") {
			return "place agent YAML files in an agents/ directory, or pass -agents to specify the path"
		}
		return "check the file path and ensure the file exists"
	}
	if strings.Contains(msg, "permission denied") {
		return "check file permissions — you may need to run with appropriate access"
	}
	if strings.Contains(msg, "parsing campaign YAML") || strings.Contains(msg, "parsing policy YAML") {
		return "check YAML syntax — try 'threatecho lint' or validate with an online YAML checker"
	}
	if strings.Contains(msg, "connection refused") {
		return "verify the target host is reachable and the service (SSH/WinRM) is running"
	}
	if strings.Contains(msg, "authentication") || strings.Contains(msg, "401") || strings.Contains(msg, "credential") {
		return "check credentials — verify username, password/key, and that the account has access"
	}
	if strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") {
		return "the operation timed out — try increasing -timeout or check network connectivity"
	}
	if strings.Contains(msg, "inventory") && strings.Contains(msg, "no such file") {
		return "check the -inventory path — use examples/inventory.yaml as a template"
	}
	return ""
}

// DieCode extracts the exit code from an error.
func DieCode(err error) int {
	if err == nil {
		return ExitOK
	}
	if cliErr, ok := err.(*Error); ok {
		return cliErr.Code
	}
	return ExitRuntime
}

// ValidationErrors formats a list of validation errors for display.
func ValidationErrors(name string, errs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%q has %d issue(s):\n", name, len(errs))
	for _, e := range errs {
		fmt.Fprintf(&b, "  • %s\n", e)
	}
	return b.String()
}
