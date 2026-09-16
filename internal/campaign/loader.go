// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads and parses a campaign from a YAML file or directory.
// If path is a directory, it looks for campaign.yaml inside it.
func Load(path string) (*Campaign, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("campaign path %q: %w", path, err)
	}
	if info.IsDir() {
		path = filepath.Join(path, "campaign.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading campaign: %w", err)
	}

	var c Campaign
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing campaign YAML: %w", err)
	}

	// Expand variables in stage fields.
	if len(c.Variables) > 0 {
		expandVariables(&c)
	}

	return &c, nil
}

// LoadDir scans a directory for campaign subdirectories (each containing campaign.yaml)
// and returns metadata for each found campaign.
func LoadDir(dir string) ([]CampaignSummary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading campaigns directory: %w", err)
	}

	var summaries []CampaignSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cpath := filepath.Join(dir, e.Name(), "campaign.yaml")
		if _, err := os.Stat(cpath); err != nil {
			continue
		}
		c, err := Load(cpath)
		if err != nil {
			continue
		}
		summaries = append(summaries, CampaignSummary{
			Name:       c.Meta.Name,
			Adversary:  c.Meta.Adversary,
			Severity:   c.Meta.Severity,
			Stages:     len(c.Stages),
			Techniques: len(c.UniqueTechniques()),
			Tactics:    len(c.UniqueTactics()),
			Path:       filepath.Join(dir, e.Name()),
		})
	}
	return summaries, nil
}

// CampaignSummary is a compact view of a campaign for listing.
type CampaignSummary struct {
	Name       string
	Adversary  string
	Severity   string
	Stages     int
	Techniques int
	Tactics    int
	Path       string
}

// expandVariables replaces {{var}} placeholders in string fields with variable values.
func expandVariables(c *Campaign) {
	for i := range c.Stages {
		s := &c.Stages[i]
		s.Name = expand(s.Name, c.Variables)
		s.Description = expand(s.Description, c.Variables)
		s.Execute.Target = expand(s.Execute.Target, c.Variables)
		s.Execute.Payload = expand(s.Execute.Payload, c.Variables)
		for j := range s.Execute.Commands {
			s.Execute.Commands[j] = expand(s.Execute.Commands[j], c.Variables)
		}
		for j := range s.Execute.Cleanup {
			s.Execute.Cleanup[j] = expand(s.Execute.Cleanup[j], c.Variables)
		}
		for k, v := range s.Execute.Args {
			s.Execute.Args[k] = expand(v, c.Variables)
		}
		for j := range s.Expect.Artifacts {
			s.Expect.Artifacts[j] = expand(s.Expect.Artifacts[j], c.Variables)
		}
		for j := range s.Expect.IOCs {
			s.Expect.IOCs[j] = expand(s.Expect.IOCs[j], c.Variables)
		}
	}
}

func expand(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}
