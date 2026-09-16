// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package orchestrator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadInventory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yaml")
	os.WriteFile(path, []byte(`
api_version: v1
kind: TargetInventory
meta:
  name: test-lab
targets:
  - name: linux-ws
    host: 10.0.0.1
    port: 22
    os: linux
    user: testuser
    password: testpass
    mode: agentless
  - name: linux-srv
    host: 10.0.0.2
    os: linux
    user: root
    key_path: /tmp/id_rsa
    mode: agent
`), 0644)

	inv, err := LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if inv.Meta.Name != "test-lab" {
		t.Errorf("meta.name = %q, want %q", inv.Meta.Name, "test-lab")
	}
	if len(inv.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(inv.Targets))
	}
	if inv.Targets[0].Port != 22 {
		t.Errorf("target[0].port = %d, want 22", inv.Targets[0].Port)
	}
	if inv.Targets[1].Port != 22 {
		t.Errorf("target[1].port = %d, want 22 (default)", inv.Targets[1].Port)
	}
	if inv.Targets[1].Mode != "agent" {
		t.Errorf("target[1].mode = %q, want %q", inv.Targets[1].Mode, "agent")
	}
}

func TestLoadInventory_Defaults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yaml")
	os.WriteFile(path, []byte(`
api_version: v1
kind: TargetInventory
meta:
  name: defaults
targets:
  - name: win-dc
    host: 10.0.0.3
    os: windows
    user: admin
    password: pass
`), 0644)

	inv, err := LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if inv.Targets[0].Port != 5985 {
		t.Errorf("windows default port = %d, want 5985", inv.Targets[0].Port)
	}
	if inv.Targets[0].Mode != "agentless" {
		t.Errorf("default mode = %q, want %q", inv.Targets[0].Mode, "agentless")
	}
}

func TestLoadInventory_EnvExpansion(t *testing.T) {
	t.Setenv("TE_TEST_PASSWORD", "secret123")

	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yaml")
	os.WriteFile(path, []byte(`
api_version: v1
kind: TargetInventory
meta:
  name: env-test
targets:
  - name: srv
    host: 10.0.0.1
    os: linux
    user: lab
    password: "${env:TE_TEST_PASSWORD}"
    mode: agentless
`), 0644)

	inv, err := LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if inv.Targets[0].Password != "secret123" {
		t.Errorf("password = %q, want %q", inv.Targets[0].Password, "secret123")
	}
}

func TestValidateTarget(t *testing.T) {
	t.Parallel()

	valid := Target{
		Name:     "test",
		Host:     "10.0.0.1",
		OS:       "linux",
		User:     "root",
		Password: "pass",
		Mode:     "agentless",
	}
	if err := ValidateTarget(valid); err != nil {
		t.Errorf("valid target: %v", err)
	}

	tests := []struct {
		name   string
		modify func(*Target)
	}{
		{"no name", func(t *Target) { t.Name = "" }},
		{"no host", func(t *Target) { t.Host = "" }},
		{"no user", func(t *Target) { t.User = "" }},
		{"no os", func(t *Target) { t.OS = "" }},
		{"bad os", func(t *Target) { t.OS = "plan9" }},
		{"bad mode", func(t *Target) { t.Mode = "magic" }},
		{"no auth", func(t *Target) { t.Password = ""; t.KeyPath = "" }},
		{"windows no password", func(t *Target) { t.OS = "windows"; t.Password = ""; t.KeyPath = "/k" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bad := valid
			tt.modify(&bad)
			if err := ValidateTarget(bad); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestValidateInventory(t *testing.T) {
	t.Parallel()

	inv := &TargetInventory{
		APIVersion: "v1",
		Kind:       "TargetInventory",
		Targets: []Target{
			{Name: "a", Host: "1.2.3.4", OS: "linux", User: "u", Password: "p", Mode: "agentless"},
			{Name: "b", Host: "1.2.3.5", OS: "linux", User: "u", Password: "p", Mode: "agent"},
		},
	}
	if err := ValidateInventory(inv); err != nil {
		t.Errorf("valid inventory: %v", err)
	}

	// Duplicate names.
	dup := *inv
	dup.Targets = []Target{
		{Name: "x", Host: "1.2.3.4", OS: "linux", User: "u", Password: "p", Mode: "agentless"},
		{Name: "x", Host: "1.2.3.5", OS: "linux", User: "u", Password: "p", Mode: "agentless"},
	}
	if err := ValidateInventory(&dup); err == nil {
		t.Error("expected error for duplicate names")
	}

	// Empty targets.
	empty := &TargetInventory{APIVersion: "v1", Kind: "TargetInventory"}
	if err := ValidateInventory(empty); err == nil {
		t.Error("expected error for empty targets")
	}

	// Wrong kind.
	bad := *inv
	bad.Kind = "Campaign"
	if err := ValidateInventory(&bad); err == nil {
		t.Error("expected error for wrong kind")
	}
}

func TestSetDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		os       string
		mode     string
		port     int
		wantOS   string
		wantMode string
		wantPort int
	}{
		{"linux defaults", "linux", "", 0, "linux", "agentless", 22},
		{"windows defaults", "windows", "", 0, "windows", "agentless", 5985},
		{"uppercase OS", "Linux", "", 0, "linux", "agentless", 22},
		{"mixed case OS", "Windows", "", 0, "windows", "agentless", 5985},
		{"uppercase mode", "linux", "Agent", 0, "linux", "agent", 22},
		{"explicit port kept", "linux", "", 9022, "linux", "agentless", 9022},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target := &Target{OS: tt.os, Mode: tt.mode, Port: tt.port}
			SetDefaults(target)
			if target.OS != tt.wantOS {
				t.Errorf("OS = %q, want %q", target.OS, tt.wantOS)
			}
			if target.Mode != tt.wantMode {
				t.Errorf("Mode = %q, want %q", target.Mode, tt.wantMode)
			}
			if target.Port != tt.wantPort {
				t.Errorf("Port = %d, want %d", target.Port, tt.wantPort)
			}
		})
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("TE_VAR_A", "hello")
	t.Setenv("TE_VAR_B", "world")

	tests := []struct {
		input string
		want  string
	}{
		{"plain", "plain"},
		{"${env:TE_VAR_A}", "hello"},
		{"pre-${env:TE_VAR_A}-post", "pre-hello-post"},
		{"${env:TE_VAR_A}+${env:TE_VAR_B}", "hello+world"},
		{"${env:NONEXISTENT}", ""},
	}

	for _, tt := range tests {
		got := expandEnv(tt.input)
		if got != tt.want {
			t.Errorf("expandEnv(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
