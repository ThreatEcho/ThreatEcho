// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package mitre

import "strings"

// ValidTechniqueExists checks whether a technique ID exists in any
// registered framework (ATT&CK, ATLAS, OWASP LLM). This goes beyond
// format validation — it confirms the ID maps to a known technique.
//
// Returns false for valid-format IDs that aren't in the registry
// (the registry is a representative subset, not exhaustive).
func ValidTechniqueExists(id string) bool {
	switch {
	case strings.HasPrefix(id, "AML."):
		return LookupATLASTechnique(id) != nil
	case strings.HasPrefix(id, "LLM"):
		return LookupOWASPLLM(id) != nil
	case strings.HasPrefix(id, "T"):
		return LookupTechnique(id) != nil
	}
	return false
}

// ClassifyFramework returns which framework a technique belongs to
// based on its ID prefix: "attack", "atlas", "owasp", or "unknown".
func ClassifyFramework(id string) string {
	switch {
	case strings.HasPrefix(id, "AML."):
		return "atlas"
	case strings.HasPrefix(id, "LLM"):
		return "owasp"
	case strings.HasPrefix(id, "T"):
		return "attack"
	}
	return "unknown"
}

// ResolveName returns the human-readable name for any technique ID
// across all frameworks. Returns "" if not found.
func ResolveName(id string) string {
	switch ClassifyFramework(id) {
	case "attack":
		if t := LookupTechnique(id); t != nil {
			return t.Name
		}
	case "atlas":
		if t := LookupATLASTechnique(id); t != nil {
			return t.Name
		}
	case "owasp":
		if e := LookupOWASPLLM(id); e != nil {
			return e.Name
		}
	}
	return ""
}
