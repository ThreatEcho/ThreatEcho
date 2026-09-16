// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"time"
)

// Campaign is the top-level definition of an adversary emulation plan.
type Campaign struct {
	APIVersion string            `yaml:"api_version"`
	Kind       string            `yaml:"kind"`
	Meta       Meta              `yaml:"meta"`
	Variables  map[string]string `yaml:"variables,omitempty"`
	Stages     []Stage           `yaml:"stages"`
}

// Meta holds campaign metadata.
type Meta struct {
	Name         string   `yaml:"name"`
	Adversary    string   `yaml:"adversary"`
	Description  string   `yaml:"description"`
	Objective    string   `yaml:"objective"`
	MitreVersion string   `yaml:"mitre_version"`
	Severity     string   `yaml:"severity"` // critical, high, medium, low, info
	Tags         []string `yaml:"tags,omitempty"`
	Authors      []string `yaml:"authors,omitempty"`
	References   []string `yaml:"references,omitempty"`
	Created      string   `yaml:"created"`
	Modified     string   `yaml:"modified"`
}

// Stage is a single step in a campaign.
type Stage struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Technique   string   `yaml:"technique"`
	Tactic      string   `yaml:"tactic"`
	Platform    []string `yaml:"platform,omitempty"`
	DependsOn   []string `yaml:"depends_on,omitempty"`
	Execute     Execute  `yaml:"execute"`
	Expect      Expect   `yaml:"expect,omitempty"`
	OnSuccess   string   `yaml:"on_success,omitempty"`
	OnFailure   string   `yaml:"on_failure,omitempty"` // abort, skip, continue
	Timeout     Duration `yaml:"timeout,omitempty"`
	Delay       Duration `yaml:"delay,omitempty"`
}

// Execute describes what a stage does.
type Execute struct {
	Type     string            `yaml:"type"` // shell, powershell, http, file, registry, service, process, dns, manual
	Commands []string          `yaml:"commands,omitempty"`
	Payload  string            `yaml:"payload,omitempty"`
	Target   string            `yaml:"target,omitempty"`
	Args     map[string]string `yaml:"args,omitempty"`
	Cleanup  []string          `yaml:"cleanup,omitempty"`
	Elevated bool              `yaml:"elevated,omitempty"`
}

// Expect describes what telemetry and detections a stage should produce.
type Expect struct {
	Telemetry  []string `yaml:"telemetry,omitempty"`
	Detections []string `yaml:"detections,omitempty"`
	Artifacts  []string `yaml:"artifacts,omitempty"`
	IOCs       []string `yaml:"iocs,omitempty"`
}

// Duration wraps time.Duration for YAML unmarshaling from strings like "30s".
type Duration struct {
	time.Duration
}

// UnmarshalYAML parses a YAML string value (e.g. "30s") into a Duration.
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if s == "" {
		d.Duration = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = parsed
	return nil
}

// MarshalYAML encodes the Duration as a human-readable string for YAML output.
func (d Duration) MarshalYAML() (interface{}, error) {
	if d.Duration == 0 {
		return "", nil
	}
	return d.Duration.String(), nil
}

// UniqueTechniques returns deduplicated technique IDs across all stages.
func (c *Campaign) UniqueTechniques() []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range c.Stages {
		if !seen[s.Technique] {
			seen[s.Technique] = true
			out = append(out, s.Technique)
		}
	}
	return out
}

// UniqueTactics returns deduplicated tactic names across all stages.
func (c *Campaign) UniqueTactics() []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range c.Stages {
		if !seen[s.Tactic] {
			seen[s.Tactic] = true
			out = append(out, s.Tactic)
		}
	}
	return out
}

// AllTelemetryTypes returns deduplicated telemetry types across all stages.
func (c *Campaign) AllTelemetryTypes() []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range c.Stages {
		for _, t := range s.Expect.Telemetry {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// AllDetections returns deduplicated detection rule references across all stages.
func (c *Campaign) AllDetections() []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range c.Stages {
		for _, d := range s.Expect.Detections {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}
