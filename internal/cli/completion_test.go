// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestBashCompletion_Contains(t *testing.T) {
	var buf bytes.Buffer
	BashCompletion(&buf)
	out := buf.String()

	if !strings.Contains(out, "complete -F") {
		t.Error("bash completion should contain 'complete -F' directive")
	}
	if !strings.Contains(out, "_threatecho_completions") {
		t.Error("bash completion should define _threatecho_completions function")
	}
	for _, cmd := range []string{"validate", "simulate", "gap", "diff", "merge", "completion"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("bash completion should contain command %q", cmd)
		}
	}
}

func TestZshCompletion_Contains(t *testing.T) {
	var buf bytes.Buffer
	ZshCompletion(&buf)
	out := buf.String()

	if !strings.Contains(out, "#compdef threatecho") {
		t.Error("zsh completion should start with #compdef directive")
	}
	if !strings.Contains(out, "_threatecho") {
		t.Error("zsh completion should define _threatecho function")
	}
	for _, cmd := range []string{"validate", "simulate", "gap", "diff", "merge"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("zsh completion should contain command %q", cmd)
		}
	}
}

func TestFishCompletion_Contains(t *testing.T) {
	var buf bytes.Buffer
	FishCompletion(&buf)
	out := buf.String()

	if !strings.Contains(out, "complete -c threatecho") {
		t.Error("fish completion should contain 'complete -c threatecho'")
	}
	for _, cmd := range []string{"validate", "simulate", "gap", "diff", "merge", "completion"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("fish completion should contain command %q", cmd)
		}
	}
}

func TestBashCompletion_Subcommands(t *testing.T) {
	var buf bytes.Buffer
	BashCompletion(&buf)
	out := buf.String()

	for parent, subs := range subcommands {
		for _, sub := range subs {
			if !strings.Contains(out, sub) {
				t.Errorf("bash completion should contain subcommand %q for %q", sub, parent)
			}
		}
	}
}

func TestFishCompletion_Flags(t *testing.T) {
	var buf bytes.Buffer
	FishCompletion(&buf)
	out := buf.String()

	// Check that some key flags appear
	for _, flag := range []string{"format", "dir", "platform", "policy"} {
		if !strings.Contains(out, flag) {
			t.Errorf("fish completion should contain flag %q", flag)
		}
	}
}

func TestCommandDescription_Known(t *testing.T) {
	desc := commandDescription("validate")
	if desc == "" || desc == "validate" {
		t.Error("known command should have a meaningful description")
	}
}

func TestCommandDescription_Unknown(t *testing.T) {
	desc := commandDescription("nonexistent")
	if desc != "nonexistent" {
		t.Errorf("unknown command description should return the command name, got %q", desc)
	}
}

func TestCompletion_AllCommandsHaveDescriptions(t *testing.T) {
	for _, cmd := range commands {
		desc := commandDescription(cmd)
		if desc == "" {
			t.Errorf("command %q has no description", cmd)
		}
	}
}

func TestBashCompletion_NonEmpty(t *testing.T) {
	var buf bytes.Buffer
	BashCompletion(&buf)
	if buf.Len() < 100 {
		t.Errorf("bash completion too short: %d bytes", buf.Len())
	}
}

func TestZshCompletion_NonEmpty(t *testing.T) {
	var buf bytes.Buffer
	ZshCompletion(&buf)
	if buf.Len() < 100 {
		t.Errorf("zsh completion too short: %d bytes", buf.Len())
	}
}

func TestFishCompletion_NonEmpty(t *testing.T) {
	var buf bytes.Buffer
	FishCompletion(&buf)
	if buf.Len() < 100 {
		t.Errorf("fish completion too short: %d bytes", buf.Len())
	}
}
