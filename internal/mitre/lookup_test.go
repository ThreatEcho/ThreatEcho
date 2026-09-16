// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package mitre

import "testing"

func TestValidTechniqueExists_ATTACKKnown(t *testing.T) {
	known := []string{"T1059", "T1190", "T1071", "T1003", "T1566"}
	for _, id := range known {
		if !ValidTechniqueExists(id) {
			t.Errorf("ValidTechniqueExists(%q) = false, want true", id)
		}
	}
}

func TestValidTechniqueExists_ATTACKUnknown(t *testing.T) {
	if ValidTechniqueExists("T9999") {
		t.Error("ValidTechniqueExists(T9999) = true, want false")
	}
}

func TestValidTechniqueExists_ATLASKnown(t *testing.T) {
	known := []string{"AML.T0043", "AML.T0051", "AML.T0054"}
	for _, id := range known {
		if !ValidTechniqueExists(id) {
			t.Errorf("ValidTechniqueExists(%q) = false, want true", id)
		}
	}
}

func TestValidTechniqueExists_ATLASUnknown(t *testing.T) {
	if ValidTechniqueExists("AML.T9999") {
		t.Error("ValidTechniqueExists(AML.T9999) = true, want false")
	}
}

func TestValidTechniqueExists_OWASPKnown(t *testing.T) {
	known := []string{"LLM01", "LLM05", "LLM10"}
	for _, id := range known {
		if !ValidTechniqueExists(id) {
			t.Errorf("ValidTechniqueExists(%q) = false, want true", id)
		}
	}
}

func TestValidTechniqueExists_OWASPUnknown(t *testing.T) {
	if ValidTechniqueExists("LLM99") {
		t.Error("ValidTechniqueExists(LLM99) = true, want false")
	}
}

func TestValidTechniqueExists_Invalid(t *testing.T) {
	invalid := []string{"", "X1234", "NOPE", "123"}
	for _, id := range invalid {
		if ValidTechniqueExists(id) {
			t.Errorf("ValidTechniqueExists(%q) = true, want false", id)
		}
	}
}

func TestClassifyFramework(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"T1059", "attack"},
		{"T1059.001", "attack"},
		{"T9999", "attack"},
		{"AML.T0043", "atlas"},
		{"AML.T9999", "atlas"},
		{"LLM01", "owasp"},
		{"LLM10", "owasp"},
		{"", "unknown"},
		{"X123", "unknown"},
		{"NOPE", "unknown"},
	}
	for _, tt := range tests {
		got := ClassifyFramework(tt.id)
		if got != tt.want {
			t.Errorf("ClassifyFramework(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestResolveName_ATTACKKnown(t *testing.T) {
	name := ResolveName("T1059")
	if name == "" {
		t.Error("ResolveName(T1059) = empty, want a name")
	}
	if name != "Command and Scripting Interpreter" {
		t.Errorf("ResolveName(T1059) = %q, want 'Command and Scripting Interpreter'", name)
	}
}

func TestResolveName_ATLASKnown(t *testing.T) {
	name := ResolveName("AML.T0043")
	if name == "" {
		t.Error("ResolveName(AML.T0043) = empty, want a name")
	}
}

func TestResolveName_OWASPKnown(t *testing.T) {
	name := ResolveName("LLM01")
	if name == "" {
		t.Error("ResolveName(LLM01) = empty, want a name")
	}
}

func TestResolveName_Unknown(t *testing.T) {
	name := ResolveName("T9999")
	if name != "" {
		t.Errorf("ResolveName(T9999) = %q, want empty", name)
	}
}
