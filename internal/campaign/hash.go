// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Fingerprint returns a hex-encoded SHA256 hash of the campaign's canonical
// content. The hash is deterministic: same campaign content always produces
// the same hash regardless of file path, load order, or stage ordering.
//
// Canonical representation hashes these fields in order:
//   - api_version, kind
//   - meta: name, adversary, severity, mitre_version
//   - variables sorted by key
//   - stages sorted by ID: id, name, technique, tactic, execute.type,
//     expect.telemetry (sorted), expect.detections (sorted), depends_on (sorted)
func Fingerprint(c *Campaign) string {
	h := sha256.New()

	// write emits a field=value line into the hash.
	write := func(key, value string) {
		fmt.Fprintf(h, "%s=%s\n", key, value)
	}

	// Top-level fields.
	write("api_version", c.APIVersion)
	write("kind", c.Kind)

	// Meta fields in specified order.
	write("meta.name", c.Meta.Name)
	write("meta.adversary", c.Meta.Adversary)
	write("meta.severity", c.Meta.Severity)
	write("meta.mitre_version", c.Meta.MitreVersion)

	// Variables sorted by key.
	if len(c.Variables) > 0 {
		varKeys := make([]string, 0, len(c.Variables))
		for k := range c.Variables {
			varKeys = append(varKeys, k)
		}
		sort.Strings(varKeys)
		for _, k := range varKeys {
			write("var."+k, c.Variables[k])
		}
	}

	// Stages sorted by ID for order independence.
	sorted := make([]Stage, len(c.Stages))
	copy(sorted, c.Stages)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	for _, s := range sorted {
		p := "stage." + s.ID
		write(p+".id", s.ID)
		write(p+".name", s.Name)
		write(p+".technique", s.Technique)
		write(p+".tactic", s.Tactic)
		write(p+".execute.type", s.Execute.Type)

		telemetry := sortedCopy(s.Expect.Telemetry)
		write(p+".expect.telemetry", strings.Join(telemetry, ","))

		detections := sortedCopy(s.Expect.Detections)
		write(p+".expect.detections", strings.Join(detections, ","))

		deps := sortedCopy(s.DependsOn)
		write(p+".depends_on", strings.Join(deps, ","))
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// FingerprintFile loads a campaign from path and returns its fingerprint.
func FingerprintFile(path string) (string, error) {
	c, err := Load(path)
	if err != nil {
		return "", fmt.Errorf("fingerprint file %q: %w", path, err)
	}
	return Fingerprint(c), nil
}

// FingerprintDir loads all campaigns in a directory and returns a map of
// campaign name to fingerprint. It follows the same directory convention as
// LoadDir: each subdirectory containing a campaign.yaml is treated as a
// campaign.
func FingerprintDir(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("fingerprint dir %q: %w", dir, err)
	}

	result := make(map[string]string)
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
		result[c.Meta.Name] = Fingerprint(c)
	}
	return result, nil
}

// FingerprintManifest returns a single SHA256 hash representing the entire
// campaign directory. It hashes the sorted name=fingerprint pairs of all
// campaigns found. Useful for CI caching: if the manifest hash hasn't
// changed, no campaign content has changed.
func FingerprintManifest(dir string) (string, error) {
	fps, err := FingerprintDir(dir)
	if err != nil {
		return "", fmt.Errorf("fingerprint manifest: %w", err)
	}

	// Sort by campaign name for determinism.
	names := make([]string, 0, len(fps))
	for name := range fps {
		names = append(names, name)
	}
	sort.Strings(names)

	h := sha256.New()
	for _, name := range names {
		fmt.Fprintf(h, "%s=%s\n", name, fps[name])
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// sortedCopy returns a sorted copy of a string slice without modifying the original.
func sortedCopy(ss []string) []string {
	cp := make([]string, len(ss))
	copy(cp, ss)
	sort.Strings(cp)
	return cp
}
