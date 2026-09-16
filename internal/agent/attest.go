// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Attestation is a signed proof of an agent's identity and capabilities.
type Attestation struct {
	AgentName     string        `json:"agent_name"`
	AgentType     string        `json:"agent_type"`
	Version       string        `json:"version"`
	TrustLevel    string        `json:"trust_level"`
	Fingerprint   string        `json:"fingerprint"`    // SHA-256 of canonical config
	ToolHash      string        `json:"tool_hash"`      // SHA-256 of tool list
	CapHash       string        `json:"cap_hash"`       // SHA-256 of capabilities
	GuardrailHash string        `json:"guardrail_hash"` // SHA-256 of guardrail config
	BoundaryHash  string        `json:"boundary_hash"`  // SHA-256 of trust boundaries
	Claims        []AttestClaim `json:"claims"`         // what this agent claims it can/cannot do
	CreatedAt     string        `json:"created_at"`
	Valid         bool          `json:"valid"`
}

// AttestClaim is a specific claim in the attestation.
type AttestClaim struct {
	Type        string `json:"type"` // tool_access, trust_boundary, capability, guardrail
	Description string `json:"description"`
	Verified    bool   `json:"verified"`
}

// AttestationReport covers an entire inventory.
type AttestationReport struct {
	AgentCount        int           `json:"agent_count"`
	Attestations      []Attestation `json:"attestations"`
	FullyAttested     int           `json:"fully_attested"`     // agents with all claims verified
	PartiallyAttested int           `json:"partially_attested"` // agents with some claims unverified
	UnverifiedCount   int           `json:"unverified_count"`   // agents with zero claims verified
	IntegrityScore    float64       `json:"integrity_score"`    // 0-1
	Warnings          []string      `json:"warnings,omitempty"`
}

// AttestConfig controls attestation behavior.
type AttestConfig struct {
	RequireGuardrails   bool   // agents without guardrails get warnings
	RequireBoundaries   bool   // agents without boundaries get warnings
	MinTrustForElevated string // minimum trust level for elevated tools (default: "elevated")
}

// DefaultAttestConfig returns sensible defaults for attestation configuration.
func DefaultAttestConfig() *AttestConfig {
	return &AttestConfig{
		RequireGuardrails:   true,
		RequireBoundaries:   true,
		MinTrustForElevated: TrustElevated,
	}
}

// AttestAgent creates an attestation for a single agent. It computes
// cryptographic hashes of the agent's tools, capabilities, guardrails, and
// boundaries, builds claims based on the configuration, verifies those
// claims, and returns a complete Attestation with an overall fingerprint.
func AttestAgent(a *Agent, cfg *AttestConfig) *Attestation {
	if a == nil {
		return &Attestation{
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			Valid:     false,
		}
	}
	if cfg == nil {
		cfg = DefaultAttestConfig()
	}

	att := &Attestation{
		AgentName:     a.Meta.Name,
		AgentType:     a.Meta.Type,
		Version:       a.Meta.Version,
		TrustLevel:    a.Trust.Level,
		ToolHash:      computeToolHash(a.Tools),
		CapHash:       computeCapHash(a.Capabilities),
		GuardrailHash: computeGuardrailHash(a.Guardrails),
		BoundaryHash:  computeBoundaryHash(a.Trust.Boundaries),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	// Build and verify claims.
	claims := buildClaims(a, cfg)
	att.Claims = verifyClaims(a, claims, cfg)

	// Generate overall fingerprint from all components.
	att.Fingerprint = computeFingerprint(a)

	// An attestation is valid only when every claim is verified.
	att.Valid = allClaimsVerified(att.Claims)

	return att
}

// AttestInventory creates attestations for every agent in the inventory and
// produces a summary report with an integrity score.
func AttestInventory(inv *Inventory, cfg *AttestConfig) *AttestationReport {
	if inv == nil {
		return &AttestationReport{}
	}
	if cfg == nil {
		cfg = DefaultAttestConfig()
	}

	report := &AttestationReport{
		AgentCount: len(inv.Agents),
	}

	if len(inv.Agents) == 0 {
		report.IntegrityScore = 1.0
		return report
	}

	totalClaims := 0
	verifiedClaims := 0

	for _, a := range inv.Agents {
		att := AttestAgent(a, cfg)
		report.Attestations = append(report.Attestations, *att)

		claimCount := len(att.Claims)
		vCount := countVerified(att.Claims)
		totalClaims += claimCount
		verifiedClaims += vCount

		switch {
		case vCount == claimCount:
			// All claims verified (including the vacuous case of 0 claims).
			report.FullyAttested++
		case vCount > 0:
			report.PartiallyAttested++
		default:
			report.UnverifiedCount++
		}

		// Collect warnings.
		if cfg.RequireGuardrails && len(a.Guardrails) == 0 {
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("agent %q has no guardrails", a.Meta.Name))
		}
		if cfg.RequireBoundaries && len(a.Trust.Boundaries) == 0 {
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("agent %q has no trust boundaries", a.Meta.Name))
		}
		if !att.Valid {
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("agent %q has unverified claims", a.Meta.Name))
		}
	}

	// Integrity score = fraction of all claims that are verified.
	if totalClaims > 0 {
		report.IntegrityScore = float64(verifiedClaims) / float64(totalClaims)
	} else {
		report.IntegrityScore = 1.0
	}

	return report
}

// VerifyAttestation checks whether an attestation still matches the current
// state of the agent by regenerating all hashes and comparing them.
func VerifyAttestation(a *Agent, att *Attestation) bool {
	if a == nil || att == nil {
		return false
	}

	if computeFingerprint(a) != att.Fingerprint {
		return false
	}
	if computeToolHash(a.Tools) != att.ToolHash {
		return false
	}
	if computeCapHash(a.Capabilities) != att.CapHash {
		return false
	}
	if computeGuardrailHash(a.Guardrails) != att.GuardrailHash {
		return false
	}
	if computeBoundaryHash(a.Trust.Boundaries) != att.BoundaryHash {
		return false
	}

	return true
}

// computeFingerprint produces a canonical SHA-256 hash of the entire agent
// configuration. It concatenates identity, tools, capabilities, guardrails,
// and boundaries into a deterministic string before hashing.
func computeFingerprint(a *Agent) string {
	if a == nil {
		return sha256Hex("")
	}

	var parts []string

	// Identity.
	parts = append(parts, "name="+a.Meta.Name)
	parts = append(parts, "type="+a.Meta.Type)
	parts = append(parts, "version="+a.Meta.Version)
	parts = append(parts, "model="+a.Meta.Model)
	parts = append(parts, "trust="+a.Trust.Level)

	// Tools (sorted for determinism).
	parts = append(parts, "tools="+canonicalTools(a.Tools))

	// Capabilities.
	parts = append(parts, "caps="+canonicalCaps(a.Capabilities))

	// Guardrails (sorted by name).
	parts = append(parts, "guardrails="+canonicalGuardrails(a.Guardrails))

	// Boundaries (sorted).
	parts = append(parts, "boundaries="+canonicalBoundaries(a.Trust.Boundaries))

	return sha256Hex(strings.Join(parts, "|"))
}

// computeToolHash returns the SHA-256 of a deterministic tool-list string.
func computeToolHash(tools []ToolAccess) string {
	return sha256Hex(canonicalTools(tools))
}

// computeCapHash returns the SHA-256 of a deterministic capabilities string.
func computeCapHash(caps AgentCapabilities) string {
	return sha256Hex(canonicalCaps(caps))
}

// computeGuardrailHash returns the SHA-256 of a deterministic guardrail string.
func computeGuardrailHash(guardrails []Guardrail) string {
	return sha256Hex(canonicalGuardrails(guardrails))
}

// computeBoundaryHash returns the SHA-256 of sorted, joined boundaries.
func computeBoundaryHash(boundaries []string) string {
	return sha256Hex(canonicalBoundaries(boundaries))
}

// buildClaims constructs the set of attestation claims for an agent based on
// its tools, capabilities, guardrails, and boundaries.
func buildClaims(a *Agent, cfg *AttestConfig) []AttestClaim {
	if a == nil {
		return nil
	}
	if cfg == nil {
		cfg = DefaultAttestConfig()
	}

	var claims []AttestClaim

	// Tool access claims.
	for _, t := range a.Tools {
		desc := fmt.Sprintf("can access tool %q", t.Name)
		claimType := "tool_access"
		if t.Elevated {
			desc = fmt.Sprintf("can access elevated tool %q", t.Name)
		}
		claims = append(claims, AttestClaim{
			Type:        claimType,
			Description: desc,
			Verified:    false,
		})
	}

	// Boundary claims.
	for _, b := range a.Trust.Boundaries {
		claims = append(claims, AttestClaim{
			Type:        "trust_boundary",
			Description: fmt.Sprintf("operates within boundary %q", b),
			Verified:    false,
		})
	}

	// Capability claims.
	for _, capName := range activeCapabilities(a) {
		claims = append(claims, AttestClaim{
			Type:        "capability",
			Description: fmt.Sprintf("has capability %q", capName),
			Verified:    false,
		})
	}

	// Guardrail claims.
	for _, g := range a.Guardrails {
		claims = append(claims, AttestClaim{
			Type:        "guardrail",
			Description: fmt.Sprintf("protected by guardrail %q", g.Name),
			Verified:    false,
		})
	}

	return claims
}

// verifyClaims walks the claim list and marks each as verified or not
// according to the agent's actual configuration and the attestation policy.
func verifyClaims(a *Agent, claims []AttestClaim, cfg *AttestConfig) []AttestClaim {
	if a == nil || cfg == nil {
		return claims
	}

	minLevel := cfg.MinTrustForElevated
	if minLevel == "" {
		minLevel = TrustElevated
	}
	agentOrder, minOrder := trustLevelOrder[a.Trust.Level], trustLevelOrder[minLevel]

	// Index tools by name for quick lookup.
	toolSet := make(map[string]ToolAccess)
	for _, t := range a.Tools {
		toolSet[t.Name] = t
	}

	// Index guardrail names.
	guardrailSet := make(map[string]bool)
	for _, g := range a.Guardrails {
		guardrailSet[g.Name] = true
	}

	// Index boundaries.
	boundarySet := make(map[string]bool)
	for _, b := range a.Trust.Boundaries {
		boundarySet[b] = true
	}

	// Index capabilities.
	capSet := make(map[string]bool)
	for _, c := range activeCapabilities(a) {
		capSet[c] = true
	}

	// Determine whether the agent has any external-facing capability.
	hasExternalCap := a.Capabilities.WebAccess || a.Capabilities.CodeExecution || a.Capabilities.FileAccess

	verified := make([]AttestClaim, len(claims))
	copy(verified, claims)

	for i := range verified {
		c := &verified[i]
		switch c.Type {
		case "tool_access":
			// Extract tool name from description.
			toolName := extractQuoted(c.Description)
			tool, exists := toolSet[toolName]
			if !exists {
				continue
			}
			if tool.Elevated {
				// Elevated tools require sufficient trust.
				c.Verified = agentOrder >= minOrder
			} else {
				c.Verified = true
			}

		case "trust_boundary":
			bName := extractQuoted(c.Description)
			// A boundary claim is verified when the boundary exists.
			// If the agent has external capabilities and RequireBoundaries
			// is set, the boundary must be present.
			if boundarySet[bName] {
				c.Verified = true
			}

		case "capability":
			capName := extractQuoted(c.Description)
			if capSet[capName] {
				// If the capability is external-facing and boundaries are
				// required, at least one boundary must exist.
				if hasExternalCap && cfg.RequireBoundaries && len(a.Trust.Boundaries) == 0 {
					c.Verified = false
				} else {
					c.Verified = true
				}
			}

		case "guardrail":
			gName := extractQuoted(c.Description)
			if guardrailSet[gName] {
				// Guardrail exists; verify it is enforced.
				for _, g := range a.Guardrails {
					if g.Name == gName {
						c.Verified = g.Enforced
						break
					}
				}
			}
		}
	}

	return verified
}

// FormatAttestation renders a single attestation as a box-drawing report.
func FormatAttestation(att *Attestation) string {
	if att == nil {
		return "No attestation.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│             AGENT ATTESTATION                   │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Agent:       %-35s │\n", truncate(att.AgentName, 35))
	fmt.Fprintf(&sb, "│ Type:        %-35s │\n", truncate(att.AgentType, 35))
	fmt.Fprintf(&sb, "│ Version:     %-35s │\n", truncate(att.Version, 35))
	fmt.Fprintf(&sb, "│ Trust:       %-35s │\n", truncate(att.TrustLevel, 35))
	validStr := "YES"
	if !att.Valid {
		validStr = "NO"
	}
	fmt.Fprintf(&sb, "│ Valid:       %-35s │\n", validStr)
	fmt.Fprintf(&sb, "│ Created:     %-35s │\n", truncate(att.CreatedAt, 35))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	sb.WriteString("│ Hashes                                          │\n")
	fmt.Fprintf(&sb, "│  fingerprint:  %-33s │\n", truncate(att.Fingerprint, 33))
	fmt.Fprintf(&sb, "│  tools:        %-33s │\n", truncate(att.ToolHash, 33))
	fmt.Fprintf(&sb, "│  capabilities: %-33s │\n", truncate(att.CapHash, 33))
	fmt.Fprintf(&sb, "│  guardrails:   %-33s │\n", truncate(att.GuardrailHash, 33))
	fmt.Fprintf(&sb, "│  boundaries:   %-33s │\n", truncate(att.BoundaryHash, 33))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	if len(att.Claims) == 0 {
		sb.WriteString("│ No claims                                       │\n")
	} else {
		sb.WriteString("│ Claims                                          │\n")
		for _, c := range att.Claims {
			icon := "✓"
			if !c.Verified {
				icon = "✗"
			}
			fmt.Fprintf(&sb, "│  %s %-46s │\n", icon, truncate(c.Description, 46))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// FormatAttestationReport renders an inventory attestation report as a
// box-drawing summary.
func FormatAttestationReport(r *AttestationReport) string {
	if r == nil {
		return "No attestation report.\n"
	}

	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│          ATTESTATION REPORT                     │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Agent Count:        %-28d │\n", r.AgentCount)
	fmt.Fprintf(&sb, "│ Fully Attested:     %-28d │\n", r.FullyAttested)
	fmt.Fprintf(&sb, "│ Partially Attested: %-28d │\n", r.PartiallyAttested)
	fmt.Fprintf(&sb, "│ Unverified:         %-28d │\n", r.UnverifiedCount)
	fmt.Fprintf(&sb, "│ Integrity Score:    %-28s │\n",
		fmt.Sprintf("%.2f", r.IntegrityScore))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	if len(r.Attestations) > 0 {
		sb.WriteString("│ Agents                                          │\n")
		for _, att := range r.Attestations {
			status := "✓"
			if !att.Valid {
				status = "✗"
			}
			fmt.Fprintf(&sb, "│  %s %-20s %-12s %-10s │\n",
				status,
				truncate(att.AgentName, 20),
				truncate(att.TrustLevel, 12),
				truncate(att.Fingerprint, 10))
		}
	}

	if len(r.Warnings) > 0 {
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
		sb.WriteString("│ Warnings                                        │\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&sb, "│  ! %-45s │\n", truncate(w, 45))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// --- internal helpers ---

// sha256Hex computes a hex-encoded SHA-256 digest of the input string.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// canonicalTools builds a deterministic string from a tool list by sorting
// tools alphabetically by name and encoding each as "name:elevated".
func canonicalTools(tools []ToolAccess) string {
	if len(tools) == 0 {
		return ""
	}
	names := make([]string, len(tools))
	lookup := make(map[string]ToolAccess)
	for i, t := range tools {
		names[i] = t.Name
		lookup[t.Name] = t
	}
	sort.Strings(names)

	var parts []string
	for _, n := range names {
		t := lookup[n]
		elev := "false"
		if t.Elevated {
			elev = "true"
		}
		sortedActions := make([]string, len(t.Actions))
		copy(sortedActions, t.Actions)
		sort.Strings(sortedActions)
		sortedTargets := make([]string, len(t.Targets))
		copy(sortedTargets, t.Targets)
		sort.Strings(sortedTargets)
		parts = append(parts, fmt.Sprintf("%s:elevated=%s:actions=%s:targets=%s",
			n, elev,
			strings.Join(sortedActions, ","),
			strings.Join(sortedTargets, ",")))
	}
	return strings.Join(parts, ";")
}

// canonicalCaps builds a deterministic capabilities string by listing each
// boolean field in a fixed order.
func canonicalCaps(caps AgentCapabilities) string {
	return fmt.Sprintf("tc=%t|rag=%t|ce=%t|wa=%t|fa=%t|mp=%t|mem=%t|auto=%t",
		caps.ToolCalling,
		caps.RAG,
		caps.CodeExecution,
		caps.WebAccess,
		caps.FileAccess,
		caps.MessagePassing,
		caps.Memory,
		caps.Autonomous,
	)
}

// canonicalGuardrails builds a deterministic guardrail string, sorted by
// guardrail name.
func canonicalGuardrails(guardrails []Guardrail) string {
	if len(guardrails) == 0 {
		return ""
	}
	sorted := make([]Guardrail, len(guardrails))
	copy(sorted, guardrails)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})
	var parts []string
	for _, g := range sorted {
		enforced := "false"
		if g.Enforced {
			enforced = "true"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", g.Name, g.Type, enforced))
	}
	return strings.Join(parts, ";")
}

// canonicalBoundaries builds a deterministic boundaries string.
func canonicalBoundaries(boundaries []string) string {
	if len(boundaries) == 0 {
		return ""
	}
	sorted := make([]string, len(boundaries))
	copy(sorted, boundaries)
	sort.Strings(sorted)
	return strings.Join(sorted, ";")
}

// allClaimsVerified returns true when every claim in the list is marked verified.
// An empty claim list is considered fully verified.
func allClaimsVerified(claims []AttestClaim) bool {
	for _, c := range claims {
		if !c.Verified {
			return false
		}
	}
	return true
}

// countVerified counts the number of verified claims.
func countVerified(claims []AttestClaim) int {
	n := 0
	for _, c := range claims {
		if c.Verified {
			n++
		}
	}
	return n
}

// extractQuoted extracts the first double-quoted substring from s.
func extractQuoted(s string) string {
	start := strings.Index(s, "\"")
	if start < 0 {
		return ""
	}
	end := strings.Index(s[start+1:], "\"")
	if end < 0 {
		return ""
	}
	return s[start+1 : start+1+end]
}
