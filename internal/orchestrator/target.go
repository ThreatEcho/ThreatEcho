// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package orchestrator

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Target describes a remote machine for campaign deployment.
type Target struct {
	Name     string `yaml:"name" json:"name"`
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	OS       string `yaml:"os" json:"os"`
	User     string `yaml:"user" json:"user"`
	Password string `yaml:"password,omitempty" json:"-"`
	KeyPath  string `yaml:"key_path,omitempty" json:"key_path,omitempty"`
	Mode     string `yaml:"mode" json:"mode"`
}

// TargetMeta holds inventory metadata.
type TargetMeta struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// TargetInventory holds a collection of deployment targets.
type TargetInventory struct {
	APIVersion string     `yaml:"api_version" json:"api_version"`
	Kind       string     `yaml:"kind" json:"kind"`
	Meta       TargetMeta `yaml:"meta" json:"meta"`
	Targets    []Target   `yaml:"targets" json:"targets"`
}

// LoadInventory reads a target inventory from a YAML file.
func LoadInventory(path string) (*TargetInventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory: %w", err)
	}

	var inv TargetInventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse inventory: %w", err)
	}

	for i := range inv.Targets {
		inv.Targets[i].Password = expandEnv(inv.Targets[i].Password)
		SetDefaults(&inv.Targets[i])
	}

	return &inv, nil
}

// LoadTarget reads a single target definition from YAML.
func LoadTarget(path string) (*Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read target: %w", err)
	}

	var t Target
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}

	t.Password = expandEnv(t.Password)
	SetDefaults(&t)
	return &t, nil
}

// ValidateTarget checks that a target has the required fields.
func ValidateTarget(t Target) error {
	if t.Name == "" {
		return fmt.Errorf("target name is required")
	}
	if t.Host == "" {
		return fmt.Errorf("target %q: host is required", t.Name)
	}
	if t.User == "" {
		return fmt.Errorf("target %q: user is required", t.Name)
	}
	if t.OS == "" {
		return fmt.Errorf("target %q: os is required", t.Name)
	}
	switch t.OS {
	case "linux", "windows", "darwin":
	default:
		return fmt.Errorf("target %q: unsupported os %q", t.Name, t.OS)
	}
	switch t.Mode {
	case "agentless", "agent":
	default:
		return fmt.Errorf("target %q: mode must be 'agentless' or 'agent', got %q", t.Name, t.Mode)
	}
	if t.Password == "" && t.KeyPath == "" {
		return fmt.Errorf("target %q: password or key_path is required", t.Name)
	}
	if t.OS == "windows" && t.Password == "" {
		return fmt.Errorf("target %q: Windows targets require password (WinRM uses NTLM authentication)", t.Name)
	}
	return nil
}

// ValidateInventory checks all targets in an inventory.
func ValidateInventory(inv *TargetInventory) error {
	if inv.APIVersion != "v1" {
		return fmt.Errorf("unsupported api_version %q", inv.APIVersion)
	}
	if inv.Kind != "TargetInventory" {
		return fmt.Errorf("expected kind TargetInventory, got %q", inv.Kind)
	}
	if len(inv.Targets) == 0 {
		return fmt.Errorf("inventory has no targets")
	}
	seen := make(map[string]bool)
	for _, t := range inv.Targets {
		if err := ValidateTarget(t); err != nil {
			return err
		}
		if seen[t.Name] {
			return fmt.Errorf("duplicate target name %q", t.Name)
		}
		seen[t.Name] = true
	}
	return nil
}

// SetDefaults fills in default port and mode for a target.
func SetDefaults(t *Target) {
	t.OS = strings.ToLower(t.OS)
	if t.Port == 0 {
		switch t.OS {
		case "windows":
			t.Port = 5985
		default:
			t.Port = 22
		}
	}
	t.Mode = strings.ToLower(t.Mode)
	if t.Mode == "" {
		t.Mode = "agentless"
	}
}

// expandEnv expands ${env:VAR} references in a string value.
func expandEnv(s string) string {
	const prefix = "${env:"
	const suffix = "}"
	for {
		start := strings.Index(s, prefix)
		if start < 0 {
			return s
		}
		end := strings.Index(s[start:], suffix)
		if end < 0 {
			return s
		}
		end += start
		varName := s[start+len(prefix) : end]
		s = s[:start] + os.Getenv(varName) + s[end+1:]
	}
}
