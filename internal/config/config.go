// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package config handles layered configuration for the ThreatEcho CLI.
//
// Configuration is loaded from multiple sources in priority order (later wins):
//  1. Built-in defaults
//  2. System config: /etc/threatecho/config.yaml
//  3. User config: ~/.config/threatecho/config.yaml
//  4. Project config: .threatecho.yaml (walks up from cwd, like .gitignore)
//  5. Environment variables: THREATECHO_*
//  6. CLI flags (applied by the caller after Load)
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all ThreatEcho CLI configuration.
type Config struct {
	CampaignsDir  string       `yaml:"campaigns_dir"`  // default: "campaigns"
	PoliciesDir   string       `yaml:"policies_dir"`   // default: "policies"
	DefaultFormat string       `yaml:"default_format"` // default: "text"
	DefaultPolicy string       `yaml:"default_policy"` // path to default policy for eval/summary
	Author        string       `yaml:"author"`         // author for sigma rules, reports
	NoColor       bool         `yaml:"no_color"`       // disable ANSI colors
	Output        OutputConfig `yaml:"output"`
}

// OutputConfig holds output-specific settings.
type OutputConfig struct {
	SARIFCategory string `yaml:"sarif_category"` // default SARIF category for Code Scanning
	JUnitSuite    string `yaml:"junit_suite"`    // default JUnit test suite name
}

// Default returns a Config populated with built-in defaults.
func Default() *Config {
	return &Config{
		CampaignsDir:  "campaigns",
		PoliciesDir:   "policies",
		DefaultFormat: "text",
		Author:        "ThreatEcho",
		Output: OutputConfig{
			SARIFCategory: "threatecho",
			JUnitSuite:    "ThreatEcho",
		},
	}
}

// Load reads configuration from all sources and returns the merged result.
// Missing config files are silently ignored — only parse errors are returned.
// The merge order is: defaults → system → user → project → env.
// CLI flags are not applied here; the caller merges them after Load.
func Load() (*Config, error) {
	cfg := Default()

	// 1. System config.
	if err := cfg.mergeFile("/etc/threatecho/config.yaml"); err != nil {
		return nil, fmt.Errorf("system config: %w", err)
	}

	// 2. User config.
	if userDir, err := os.UserConfigDir(); err == nil {
		userPath := filepath.Join(userDir, "threatecho", "config.yaml")
		if err := cfg.mergeFile(userPath); err != nil {
			return nil, fmt.Errorf("user config %s: %w", userPath, err)
		}
	}

	// 3. Project config — walk up from cwd.
	if projPath := FindProjectConfig(); projPath != "" {
		if err := cfg.mergeFile(projPath); err != nil {
			return nil, fmt.Errorf("project config %s: %w", projPath, err)
		}
	}

	// 4. Environment variables.
	cfg.mergeEnv()

	return cfg, nil
}

// LoadFrom reads configuration from a specific YAML file merged onto defaults.
// Useful for testing or explicit --config flags.
func LoadFrom(path string) (*Config, error) {
	cfg := Default()
	if err := cfg.mergeFile(path); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ParseYAML parses a YAML byte slice into a Config, returning only the
// fields that were explicitly set (zero values for unset fields).
func ParseYAML(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing config YAML: %w", err)
	}
	return &c, nil
}

// Merge applies non-zero fields from other onto c. Fields in other that are
// zero-valued (empty string, false, empty struct) do not overwrite c.
func (c *Config) Merge(other *Config) {
	if other == nil {
		return
	}
	if other.CampaignsDir != "" {
		c.CampaignsDir = other.CampaignsDir
	}
	if other.PoliciesDir != "" {
		c.PoliciesDir = other.PoliciesDir
	}
	if other.DefaultFormat != "" {
		c.DefaultFormat = other.DefaultFormat
	}
	if other.DefaultPolicy != "" {
		c.DefaultPolicy = other.DefaultPolicy
	}
	if other.Author != "" {
		c.Author = other.Author
	}
	if other.NoColor {
		c.NoColor = true
	}
	if other.Output.SARIFCategory != "" {
		c.Output.SARIFCategory = other.Output.SARIFCategory
	}
	if other.Output.JUnitSuite != "" {
		c.Output.JUnitSuite = other.Output.JUnitSuite
	}
}

// FindProjectConfig walks up from the current working directory looking for
// .threatecho.yaml. Returns the full path if found, or "" if not.
func FindProjectConfig() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return findProjectConfigFrom(dir)
}

// findProjectConfigFrom walks up from dir looking for .threatecho.yaml.
func findProjectConfigFrom(dir string) string {
	for {
		candidate := filepath.Join(dir, ".threatecho.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// mergeFile reads a YAML config file and merges it onto c.
// If the file does not exist, it silently returns nil.
func (c *Config) mergeFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %s: %w", path, err)
	}
	other, err := ParseYAML(data)
	if err != nil {
		return err
	}
	c.Merge(other)
	return nil
}

// mergeEnv reads THREATECHO_* environment variables and applies them.
//
// Supported variables:
//
//	THREATECHO_CAMPAIGNS_DIR  → CampaignsDir
//	THREATECHO_POLICIES_DIR   → PoliciesDir
//	THREATECHO_DEFAULT_FORMAT → DefaultFormat
//	THREATECHO_DEFAULT_POLICY → DefaultPolicy
//	THREATECHO_AUTHOR         → Author
//	THREATECHO_NO_COLOR       → NoColor (any non-empty value = true)
//	THREATECHO_SARIF_CATEGORY → Output.SARIFCategory
//	THREATECHO_JUNIT_SUITE    → Output.JUnitSuite
func (c *Config) mergeEnv() {
	envStr := func(key string) string {
		return os.Getenv(key)
	}

	if v := envStr("THREATECHO_CAMPAIGNS_DIR"); v != "" {
		c.CampaignsDir = v
	}
	if v := envStr("THREATECHO_POLICIES_DIR"); v != "" {
		c.PoliciesDir = v
	}
	if v := envStr("THREATECHO_DEFAULT_FORMAT"); v != "" {
		c.DefaultFormat = v
	}
	if v := envStr("THREATECHO_DEFAULT_POLICY"); v != "" {
		c.DefaultPolicy = v
	}
	if v := envStr("THREATECHO_AUTHOR"); v != "" {
		c.Author = v
	}
	if v := envStr("THREATECHO_NO_COLOR"); v != "" {
		c.NoColor = true
	}
	if v := envStr("THREATECHO_SARIF_CATEGORY"); v != "" {
		c.Output.SARIFCategory = v
	}
	if v := envStr("THREATECHO_JUNIT_SUITE"); v != "" {
		c.Output.JUnitSuite = v
	}
}

// EnvKeys returns all recognized THREATECHO_* environment variable names.
func EnvKeys() []string {
	return []string{
		"THREATECHO_CAMPAIGNS_DIR",
		"THREATECHO_POLICIES_DIR",
		"THREATECHO_DEFAULT_FORMAT",
		"THREATECHO_DEFAULT_POLICY",
		"THREATECHO_AUTHOR",
		"THREATECHO_NO_COLOR",
		"THREATECHO_SARIF_CATEGORY",
		"THREATECHO_JUNIT_SUITE",
	}
}

// String returns a human-readable summary of the config for debugging.
func (c *Config) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "campaigns_dir:  %s\n", c.CampaignsDir)
	fmt.Fprintf(&b, "policies_dir:   %s\n", c.PoliciesDir)
	fmt.Fprintf(&b, "default_format: %s\n", c.DefaultFormat)
	fmt.Fprintf(&b, "default_policy: %s\n", c.DefaultPolicy)
	fmt.Fprintf(&b, "author:         %s\n", c.Author)
	fmt.Fprintf(&b, "no_color:       %v\n", c.NoColor)
	fmt.Fprintf(&b, "sarif_category: %s\n", c.Output.SARIFCategory)
	fmt.Fprintf(&b, "junit_suite:    %s\n", c.Output.JUnitSuite)
	return b.String()
}
