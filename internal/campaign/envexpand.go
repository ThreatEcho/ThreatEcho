// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"os"
	"regexp"
	"sort"
	"strings"
)

// envPattern matches ${env:VAR_NAME} where VAR_NAME is uppercase letters, digits, and underscores.
var envPattern = regexp.MustCompile(`\$\{env:([A-Z0-9_]+)\}`)

// escapeSentinel is an internal placeholder used during expansion to preserve $${env:...} escapes.
const escapeSentinel = "\x00ENVESC\x00"

// ExpandEnvOptions controls environment variable expansion behavior.
type ExpandEnvOptions struct {
	// AllowMissing controls behavior when an env var isn't set.
	// If true, missing vars expand to empty string.
	// If false (default), missing vars are left as-is (${env:X}) and reported.
	AllowMissing bool
}

// ExpandEnvResult holds the outcome of environment variable expansion.
type ExpandEnvResult struct {
	// Expanded is the number of ${env:X} references that were resolved.
	Expanded int
	// Missing lists env var names that were referenced but not set.
	Missing []string
}

// ExpandEnv expands ${env:VAR_NAME} references in all string fields of a campaign.
// It modifies the campaign in place and returns a result summary.
func ExpandEnv(c *Campaign, opts ExpandEnvOptions) *ExpandEnvResult {
	if c == nil {
		return &ExpandEnvResult{}
	}

	result := &ExpandEnvResult{}
	missingSet := make(map[string]bool)

	expandStr := func(s string) string {
		if !strings.Contains(s, "${env:") {
			return s
		}

		// Step 1: Replace $${env: escape sequences with sentinel.
		s = strings.ReplaceAll(s, "$${env:", escapeSentinel)

		// Step 2: Expand ${env:VAR} references.
		s = envPattern.ReplaceAllStringFunc(s, func(match string) string {
			subs := envPattern.FindStringSubmatch(match)
			if len(subs) < 2 {
				return match
			}
			varName := subs[1]
			val, ok := os.LookupEnv(varName)
			if !ok {
				missingSet[varName] = true
				if opts.AllowMissing {
					result.Expanded++
					return ""
				}
				return match // leave as-is
			}
			result.Expanded++
			return val
		})

		// Step 3: Restore escaped sequences.
		s = strings.ReplaceAll(s, escapeSentinel, "${env:")

		return s
	}

	// Expand in campaign variable values first.
	for k, v := range c.Variables {
		c.Variables[k] = expandStr(v)
	}

	// Expand in stage fields (same fields as expandVariables, plus the ones specified).
	for i := range c.Stages {
		s := &c.Stages[i]
		s.Name = expandStr(s.Name)
		s.Description = expandStr(s.Description)
		s.Execute.Target = expandStr(s.Execute.Target)
		s.Execute.Payload = expandStr(s.Execute.Payload)
		for j := range s.Execute.Commands {
			s.Execute.Commands[j] = expandStr(s.Execute.Commands[j])
		}
		for j := range s.Execute.Cleanup {
			s.Execute.Cleanup[j] = expandStr(s.Execute.Cleanup[j])
		}
		for k, v := range s.Execute.Args {
			s.Execute.Args[k] = expandStr(v)
		}
		for j := range s.Expect.Artifacts {
			s.Expect.Artifacts[j] = expandStr(s.Expect.Artifacts[j])
		}
		for j := range s.Expect.IOCs {
			s.Expect.IOCs[j] = expandStr(s.Expect.IOCs[j])
		}
		// Structural fields NOT expanded: s.ID, s.Technique, s.Tactic
		// Also not expanded: s.Expect.Telemetry, s.Expect.Detections
	}

	// Build sorted Missing slice from the set.
	if len(missingSet) > 0 {
		for name := range missingSet {
			result.Missing = append(result.Missing, name)
		}
		sort.Strings(result.Missing)
	}

	return result
}

// ListEnvRefs scans a campaign and returns all unique ${env:VAR_NAME} references found,
// without expanding them. Useful for documentation and pre-flight checks.
func ListEnvRefs(c *Campaign) []string {
	if c == nil {
		return nil
	}

	seen := make(map[string]bool)
	var refs []string

	collect := func(s string) {
		matches := envPattern.FindAllStringSubmatch(s, -1)
		for _, m := range matches {
			if len(m) >= 2 && !seen[m[1]] {
				seen[m[1]] = true
				refs = append(refs, m[1])
			}
		}
	}

	// Scan variable values.
	for _, v := range c.Variables {
		collect(v)
	}

	// Scan stage fields.
	for _, s := range c.Stages {
		collect(s.Name)
		collect(s.Description)
		collect(s.Execute.Target)
		collect(s.Execute.Payload)
		for _, cmd := range s.Execute.Commands {
			collect(cmd)
		}
		for _, cl := range s.Execute.Cleanup {
			collect(cl)
		}
		for _, v := range s.Execute.Args {
			collect(v)
		}
		for _, a := range s.Expect.Artifacts {
			collect(a)
		}
		for _, ioc := range s.Expect.IOCs {
			collect(ioc)
		}
	}

	sort.Strings(refs)
	return refs
}

// ValidateEnvRefs checks that all ${env:X} references in a campaign have corresponding
// environment variables set. Returns the list of missing variable names.
func ValidateEnvRefs(c *Campaign) []string {
	refs := ListEnvRefs(c)
	var missing []string
	for _, name := range refs {
		if _, ok := os.LookupEnv(name); !ok {
			missing = append(missing, name)
		}
	}
	return missing
}
