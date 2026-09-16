// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package mitre

// OWASPLLMEntry represents an OWASP Top 10 for LLM Applications item.
type OWASPLLMEntry struct {
	ID          string
	Name        string
	Description string
}

// OWASPLLMTop10 contains the OWASP Top 10 for LLM Applications (2025).
var OWASPLLMTop10 = map[string]OWASPLLMEntry{
	"LLM01": {ID: "LLM01", Name: "Prompt Injection", Description: "Manipulating LLM behavior through crafted inputs or external content"},
	"LLM02": {ID: "LLM02", Name: "Sensitive Information Disclosure", Description: "Unintended revelation of confidential data through LLM responses"},
	"LLM03": {ID: "LLM03", Name: "Supply Chain Vulnerabilities", Description: "Risks from third-party components, pre-trained models, and training data"},
	"LLM04": {ID: "LLM04", Name: "Data and Model Poisoning", Description: "Corruption of training data or fine-tuning to introduce vulnerabilities"},
	"LLM05": {ID: "LLM05", Name: "Improper Output Handling", Description: "Failure to validate or sanitize LLM outputs before downstream use"},
	"LLM06": {ID: "LLM06", Name: "Excessive Agency", Description: "Granting LLM agents too much autonomy, permissions, or functionality"},
	"LLM07": {ID: "LLM07", Name: "System Prompt Leakage", Description: "Exposure of system prompts revealing internal logic and security controls"},
	"LLM08": {ID: "LLM08", Name: "Vector and Embedding Weaknesses", Description: "Exploiting RAG pipelines through adversarial embeddings or retrieval manipulation"},
	"LLM09": {ID: "LLM09", Name: "Misinformation", Description: "LLM generating false or misleading content presented as factual"},
	"LLM10": {ID: "LLM10", Name: "Unbounded Consumption", Description: "Resource exhaustion through uncontrolled LLM inference or token usage"},
}

// LookupOWASPLLM returns the OWASP LLM entry for an ID, or nil if unknown.
func LookupOWASPLLM(id string) *OWASPLLMEntry {
	if e, ok := OWASPLLMTop10[id]; ok {
		return &e
	}
	return nil
}

// ValidOWASPLLM reports whether id matches a known OWASP LLM Top 10 entry.
func ValidOWASPLLM(id string) bool {
	return LookupOWASPLLM(id) != nil
}
