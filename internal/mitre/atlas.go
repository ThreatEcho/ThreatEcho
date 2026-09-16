// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package mitre

// ATLASTactic represents a MITRE ATLAS tactic for adversarial ML threats.
type ATLASTactic struct {
	ID    string
	Name  string
	Short string // kebab-case identifier used in campaign YAML
}

// ATLASTechnique represents a MITRE ATLAS technique.
type ATLASTechnique struct {
	ID     string
	Name   string
	Tactic string // tactic short name
}

// ATLASTactics lists all ATLAS tactics in operational order.
var ATLASTactics = []ATLASTactic{
	{ID: "AML.TA0000", Name: "Reconnaissance", Short: "reconnaissance"},
	{ID: "AML.TA0001", Name: "Resource Development", Short: "resource-development"},
	{ID: "AML.TA0002", Name: "Initial Access", Short: "initial-access"},
	{ID: "AML.TA0003", Name: "ML Attack Staging", Short: "ml-attack-staging"},
	{ID: "AML.TA0004", Name: "ML Model Access", Short: "ml-model-access"},
	{ID: "AML.TA0005", Name: "Exfiltration", Short: "exfiltration"},
	{ID: "AML.TA0006", Name: "Impact", Short: "impact"},
}

// ATLASTacticByShort returns the ATLAS tactic for a short name, or nil if not found.
func ATLASTacticByShort(short string) *ATLASTactic {
	for i := range ATLASTactics {
		if ATLASTactics[i].Short == short {
			return &ATLASTactics[i]
		}
	}
	return nil
}

// ValidATLASTactic reports whether short is a known ATLAS tactic identifier.
func ValidATLASTactic(short string) bool {
	return ATLASTacticByShort(short) != nil
}

// ATLASTacticShorts returns all valid ATLAS tactic short names.
func ATLASTacticShorts() []string {
	out := make([]string, len(ATLASTactics))
	for i, t := range ATLASTactics {
		out[i] = t.Short
	}
	return out
}

// ATLASTechniques maps ATLAS technique IDs to their definitions.
var ATLASTechniques = map[string]ATLASTechnique{
	// Reconnaissance
	"AML.T0049": {ID: "AML.T0049", Name: "Search for Victim's Publicly Available Research Materials", Tactic: "reconnaissance"},

	// Resource Development
	"AML.T0016": {ID: "AML.T0016", Name: "Obtain Capabilities", Tactic: "resource-development"},
	"AML.T0048": {ID: "AML.T0048", Name: "Pre-Trained Model", Tactic: "resource-development"},

	// Initial Access
	"AML.T0047": {ID: "AML.T0047", Name: "ML-Enabled Product or Service", Tactic: "initial-access"},
	"AML.T0051": {ID: "AML.T0051", Name: "LLM Prompt Injection", Tactic: "initial-access"},
	"AML.T0052": {ID: "AML.T0052", Name: "Phishing via AI", Tactic: "initial-access"},
	"AML.T0054": {ID: "AML.T0054", Name: "LLM Jailbreaking", Tactic: "initial-access"},
	"AML.T0056": {ID: "AML.T0056", Name: "LLM Meta Prompt Extraction", Tactic: "initial-access"},

	// ML Attack Staging
	"AML.T0020": {ID: "AML.T0020", Name: "Poison Training Data", Tactic: "ml-attack-staging"},
	"AML.T0037": {ID: "AML.T0037", Name: "Data Poisoning", Tactic: "ml-attack-staging"},
	"AML.T0043": {ID: "AML.T0043", Name: "Craft Adversarial Data", Tactic: "ml-attack-staging"},
	"AML.T0053": {ID: "AML.T0053", Name: "Data Poisoning", Tactic: "ml-attack-staging"},
	"AML.T0055": {ID: "AML.T0055", Name: "Unsafe Deployment", Tactic: "ml-attack-staging"},

	// ML Model Access
	"AML.T0040": {ID: "AML.T0040", Name: "ML Model Inference API Access", Tactic: "ml-model-access"},
	"AML.T0044": {ID: "AML.T0044", Name: "Full ML Model Access", Tactic: "ml-model-access"},

	// Exfiltration / Impact
	"AML.T0015": {ID: "AML.T0015", Name: "Evade ML Model", Tactic: "impact"},
	"AML.T0042": {ID: "AML.T0042", Name: "Verify Attack", Tactic: "impact"},
	"AML.T0050": {ID: "AML.T0050", Name: "Command and Control via AI Agent", Tactic: "impact"},
}

// LookupATLASTechnique returns the ATLAS technique for an ID, or nil if unknown.
func LookupATLASTechnique(id string) *ATLASTechnique {
	if t, ok := ATLASTechniques[id]; ok {
		return &t
	}
	return nil
}

// ValidATLASTechnique reports whether id matches a known ATLAS technique.
func ValidATLASTechnique(id string) bool {
	return LookupATLASTechnique(id) != nil
}
