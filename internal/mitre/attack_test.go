// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package mitre

import "testing"

func TestValidTactic(t *testing.T) {
	t.Run("valid tactics", func(t *testing.T) {
		valid := []string{
			"reconnaissance", "resource-development", "initial-access",
			"execution", "persistence", "privilege-escalation",
			"defense-evasion", "credential-access", "discovery",
			"lateral-movement", "collection", "command-and-control",
			"exfiltration", "impact",
		}
		for _, tactic := range valid {
			if !ValidTactic(tactic) {
				t.Errorf("ValidTactic(%q) = false, want true", tactic)
			}
		}
	})

	t.Run("invalid tactics", func(t *testing.T) {
		invalid := []string{"not-a-tactic", "IMPACT", "Initial Access", "", "recon"}
		for _, tactic := range invalid {
			if ValidTactic(tactic) {
				t.Errorf("ValidTactic(%q) = true, want false", tactic)
			}
		}
	})
}

func TestTacticByShort(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		tac := TacticByShort("initial-access")
		if tac == nil {
			t.Fatal("expected tactic, got nil")
		}
		if tac.Name != "Initial Access" {
			t.Errorf("Name = %q, want %q", tac.Name, "Initial Access")
		}
		if tac.ID != "TA0001" {
			t.Errorf("ID = %q, want %q", tac.ID, "TA0001")
		}
	})

	t.Run("not found", func(t *testing.T) {
		tac := TacticByShort("nonexistent")
		if tac != nil {
			t.Errorf("expected nil, got %+v", tac)
		}
	})
}

func TestLookupTechnique(t *testing.T) {
	t.Run("known technique", func(t *testing.T) {
		tech := LookupTechnique("T1566.001")
		if tech == nil {
			t.Fatal("expected technique, got nil")
		}
		if tech.Name != "Spearphishing Attachment" {
			t.Errorf("Name = %q, want %q", tech.Name, "Spearphishing Attachment")
		}
	})

	t.Run("known parent technique", func(t *testing.T) {
		tech := LookupTechnique("T1566")
		if tech == nil {
			t.Fatal("expected technique, got nil")
		}
		if tech.Name != "Phishing" {
			t.Errorf("Name = %q, want %q", tech.Name, "Phishing")
		}
	})

	t.Run("unknown technique", func(t *testing.T) {
		tech := LookupTechnique("T9999")
		if tech != nil {
			t.Errorf("expected nil for unknown technique, got %+v", tech)
		}
	})
}

func TestTacticShorts(t *testing.T) {
	shorts := TacticShorts()
	if len(shorts) != 14 {
		t.Errorf("got %d tactics, want 14", len(shorts))
	}
	// Spot-check a few.
	found := make(map[string]bool)
	for _, s := range shorts {
		found[s] = true
	}
	for _, want := range []string{"initial-access", "impact", "exfiltration"} {
		if !found[want] {
			t.Errorf("tactic %q not found in TacticShorts()", want)
		}
	}
}

func TestTacticsCount(t *testing.T) {
	if len(Tactics) != 14 {
		t.Errorf("len(Tactics) = %d, want 14", len(Tactics))
	}
}
