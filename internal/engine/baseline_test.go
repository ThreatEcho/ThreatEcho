// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mkPolicy(name string, rules []policy.Rule) *policy.Policy {
	return &policy.Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       policy.PolicyMeta{Name: name},
		Rules:      rules,
	}
}

func mkDenyRule(tool, tactic string) policy.Rule {
	return policy.Rule{
		ID:     "r-" + tool,
		Effect: "deny",
		Match:  policy.RuleMatch{Tools: []string{tool}, Tactics: []string{tactic}},
	}
}

func mkAlertRule(tool, tactic string) policy.Rule {
	return policy.Rule{
		ID:     "r-alert-" + tool,
		Effect: "alert",
		Match:  policy.RuleMatch{Tools: []string{tool}, Tactics: []string{tactic}},
	}
}

func mkAllowRule(tool string) policy.Rule {
	return policy.Rule{
		ID:     "r-allow-" + tool,
		Effect: "allow",
		Match:  policy.RuleMatch{Tools: []string{tool}},
	}
}

func mkAgent(name, typ, trustLevel string, tools []string) *agent.Agent {
	a := &agent.Agent{
		APIVersion: "v1",
		Kind:       "Agent",
		Meta:       agent.AgentMeta{Name: name, Type: typ},
		Trust:      agent.TrustConfig{Level: trustLevel},
	}
	for _, t := range tools {
		a.Tools = append(a.Tools, agent.ToolAccess{Name: t})
	}
	return a
}

func mkInventory(agents ...*agent.Agent) *agent.Inventory {
	return &agent.Inventory{Agents: agents}
}

// ---------------------------------------------------------------------------
// CaptureBaseline
// ---------------------------------------------------------------------------

func TestCaptureBaseline_EmptyInput(t *testing.T) {
	b := CaptureBaseline(nil, nil, "empty")
	if b == nil {
		t.Fatal("expected non-nil baseline")
	}
	if b.Label != "empty" {
		t.Errorf("label = %q, want %q", b.Label, "empty")
	}
	if b.Summary.TotalPolicies != 0 {
		t.Errorf("total policies = %d, want 0", b.Summary.TotalPolicies)
	}
	if b.Summary.TotalAgents != 0 {
		t.Errorf("total agents = %d, want 0", b.Summary.TotalAgents)
	}
	if b.ID == "" {
		t.Error("expected non-empty ID")
	}
	if b.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
	if b.CreatedAt == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestCaptureBaseline_SinglePolicy(t *testing.T) {
	p := mkPolicy("test-policy", []policy.Rule{
		mkDenyRule("shell_exec", "execution"),
		mkAlertRule("file_read", "collection"),
	})
	b := CaptureBaseline([]*policy.Policy{p}, nil, "v1")

	if len(b.Policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(b.Policies))
	}
	bp := b.Policies[0]
	if bp.Name != "test-policy" {
		t.Errorf("name = %q, want %q", bp.Name, "test-policy")
	}
	if bp.RuleCount != 2 {
		t.Errorf("rule count = %d, want 2", bp.RuleCount)
	}
	if bp.DenyRules != 1 {
		t.Errorf("deny rules = %d, want 1", bp.DenyRules)
	}
	if bp.AlertRules != 1 {
		t.Errorf("alert rules = %d, want 1", bp.AlertRules)
	}
	if bp.Hash == "" {
		t.Error("expected non-empty hash")
	}
	if b.Summary.TotalPolicies != 1 {
		t.Errorf("summary total policies = %d, want 1", b.Summary.TotalPolicies)
	}
	if b.Summary.TotalRules != 2 {
		t.Errorf("summary total rules = %d, want 2", b.Summary.TotalRules)
	}
}

func TestCaptureBaseline_MultiplePolicies(t *testing.T) {
	policies := []*policy.Policy{
		mkPolicy("beta-policy", []policy.Rule{mkDenyRule("x", "y")}),
		mkPolicy("alpha-policy", []policy.Rule{mkDenyRule("a", "b"), mkAlertRule("c", "d")}),
	}
	b := CaptureBaseline(policies, nil, "multi")

	if len(b.Policies) != 2 {
		t.Fatalf("policies = %d, want 2", len(b.Policies))
	}
	// Sorted by name.
	if b.Policies[0].Name != "alpha-policy" {
		t.Errorf("first policy = %q, want %q", b.Policies[0].Name, "alpha-policy")
	}
	if b.Summary.TotalRules != 3 {
		t.Errorf("total rules = %d, want 3", b.Summary.TotalRules)
	}
	if b.Summary.TotalDenyRules != 2 {
		t.Errorf("total deny rules = %d, want 2", b.Summary.TotalDenyRules)
	}
}

func TestCaptureBaseline_WithAgents(t *testing.T) {
	p := mkPolicy("p1", []policy.Rule{mkDenyRule("shell", "exec")})
	inv := mkInventory(
		mkAgent("agent-b", "orchestrator", "high", []string{"shell_exec", "file_read"}),
		mkAgent("agent-a", "llm", "medium", []string{"web_search"}),
	)
	b := CaptureBaseline([]*policy.Policy{p}, inv, "with-agents")

	if len(b.Agents) != 2 {
		t.Fatalf("agents = %d, want 2", len(b.Agents))
	}
	// Sorted by name.
	if b.Agents[0].Name != "agent-a" {
		t.Errorf("first agent = %q, want %q", b.Agents[0].Name, "agent-a")
	}
	if b.Agents[1].ToolCount != 2 {
		t.Errorf("agent-b tool count = %d, want 2", b.Agents[1].ToolCount)
	}
	if b.Summary.TotalAgents != 2 {
		t.Errorf("total agents = %d, want 2", b.Summary.TotalAgents)
	}
}

func TestCaptureBaseline_AgentTrustLevel(t *testing.T) {
	inv := mkInventory(mkAgent("a1", "llm", "high", nil))
	b := CaptureBaseline(nil, inv, "trust")
	if b.Agents[0].TrustLevel != "high" {
		t.Errorf("trust level = %q, want %q", b.Agents[0].TrustLevel, "high")
	}
}

func TestCaptureBaseline_AgentDelegations(t *testing.T) {
	a := mkAgent("a1", "orchestrator", "high", nil)
	a.Trust.TrustsFrom = []string{"agent-x", "agent-y"}
	inv := mkInventory(a)
	b := CaptureBaseline(nil, inv, "delegations")
	if len(b.Agents[0].Delegations) != 2 {
		t.Fatalf("delegations = %d, want 2", len(b.Agents[0].Delegations))
	}
}

func TestCaptureBaseline_Deterministic(t *testing.T) {
	p := mkPolicy("p", []policy.Rule{mkDenyRule("tool", "tactic")})
	inv := mkInventory(mkAgent("a", "llm", "medium", []string{"tool"}))

	b1 := CaptureBaseline([]*policy.Policy{p}, inv, "")
	b2 := CaptureBaseline([]*policy.Policy{p}, inv, "")

	if b1.Fingerprint != b2.Fingerprint {
		t.Errorf("fingerprints differ: %s != %s", b1.Fingerprint, b2.Fingerprint)
	}
}

func TestCaptureBaseline_ToolsAndTacticsCollected(t *testing.T) {
	p := mkPolicy("p", []policy.Rule{
		mkDenyRule("shell_exec", "execution"),
		mkDenyRule("file_write", "persistence"),
		mkAlertRule("shell_exec", "execution"),
	})
	b := CaptureBaseline([]*policy.Policy{p}, nil, "")
	bp := b.Policies[0]

	if len(bp.Tools) != 2 {
		t.Errorf("unique tools = %d, want 2", len(bp.Tools))
	}
	if len(bp.Tactics) != 2 {
		t.Errorf("unique tactics = %d, want 2", len(bp.Tactics))
	}
}

func TestCaptureBaseline_AllowRuleCounted(t *testing.T) {
	p := mkPolicy("p", []policy.Rule{mkAllowRule("read_file")})
	b := CaptureBaseline([]*policy.Policy{p}, nil, "")
	if b.Policies[0].AllowRules != 1 {
		t.Errorf("allow rules = %d, want 1", b.Policies[0].AllowRules)
	}
}

// ---------------------------------------------------------------------------
// DiffBaselines
// ---------------------------------------------------------------------------

func TestDiffBaselines_Identical(t *testing.T) {
	p := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y")})
	b := CaptureBaseline([]*policy.Policy{p}, nil, "")
	d := DiffBaselines(b, b)

	if d.Verdict != "stable" {
		t.Errorf("verdict = %q, want %q", d.Verdict, "stable")
	}
	if len(d.Changes) != 0 {
		t.Errorf("changes = %d, want 0", len(d.Changes))
	}
}

func TestDiffBaselines_PolicyAdded(t *testing.T) {
	before := CaptureBaseline(nil, nil, "before")
	p := mkPolicy("new-policy", []policy.Rule{mkDenyRule("tool", "tactic")})
	after := CaptureBaseline([]*policy.Policy{p}, nil, "after")

	d := DiffBaselines(before, after)
	if len(d.Changes) == 0 {
		t.Fatal("expected changes")
	}

	found := false
	for _, c := range d.Changes {
		if c.Category == "policy_added" && c.Entity == "new-policy" {
			found = true
			if c.Severity != "info" {
				t.Errorf("severity = %q, want %q", c.Severity, "info")
			}
		}
	}
	if !found {
		t.Error("missing policy_added change")
	}
}

func TestDiffBaselines_PolicyRemoved(t *testing.T) {
	p := mkPolicy("old-policy", []policy.Rule{mkDenyRule("tool", "tactic")})
	before := CaptureBaseline([]*policy.Policy{p}, nil, "before")
	after := CaptureBaseline(nil, nil, "after")

	d := DiffBaselines(before, after)
	found := false
	for _, c := range d.Changes {
		if c.Category == "policy_removed" && c.Entity == "old-policy" {
			found = true
			if c.Severity != "high" {
				t.Errorf("severity = %q, want %q", c.Severity, "high")
			}
		}
	}
	if !found {
		t.Error("missing policy_removed change")
	}
}

func TestDiffBaselines_PolicyModified(t *testing.T) {
	p1 := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y")})
	before := CaptureBaseline([]*policy.Policy{p1}, nil, "")

	p2 := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y"), mkAlertRule("z", "w")})
	after := CaptureBaseline([]*policy.Policy{p2}, nil, "")

	d := DiffBaselines(before, after)
	found := false
	for _, c := range d.Changes {
		if c.Category == "policy_modified" && c.Entity == "p" {
			found = true
			if !strings.Contains(c.Description, "rules") {
				t.Errorf("description should mention rules: %q", c.Description)
			}
		}
	}
	if !found {
		t.Error("missing policy_modified change")
	}
}

func TestDiffBaselines_PolicyModified_LostDenyRules(t *testing.T) {
	p1 := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y"), mkDenyRule("z", "w")})
	before := CaptureBaseline([]*policy.Policy{p1}, nil, "")

	p2 := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y")})
	after := CaptureBaseline([]*policy.Policy{p2}, nil, "")

	d := DiffBaselines(before, after)
	for _, c := range d.Changes {
		if c.Category == "policy_modified" {
			if c.Severity != "high" {
				t.Errorf("losing deny rules should be high severity, got %q", c.Severity)
			}
		}
	}
}

func TestDiffBaselines_AgentAdded(t *testing.T) {
	before := CaptureBaseline(nil, nil, "")
	inv := mkInventory(mkAgent("new-agent", "llm", "medium", []string{"tool"}))
	after := CaptureBaseline(nil, inv, "")

	d := DiffBaselines(before, after)
	found := false
	for _, c := range d.Changes {
		if c.Category == "agent_added" && c.Entity == "new-agent" {
			found = true
		}
	}
	if !found {
		t.Error("missing agent_added change")
	}
}

func TestDiffBaselines_AgentAddedHighTrust(t *testing.T) {
	before := CaptureBaseline(nil, nil, "")
	inv := mkInventory(mkAgent("risky", "orchestrator", "high", nil))
	after := CaptureBaseline(nil, inv, "")

	d := DiffBaselines(before, after)
	for _, c := range d.Changes {
		if c.Category == "agent_added" && c.Entity == "risky" {
			if c.Severity != "medium" {
				t.Errorf("high-trust agent added should be medium severity, got %q", c.Severity)
			}
		}
	}
}

func TestDiffBaselines_AgentRemoved(t *testing.T) {
	inv := mkInventory(mkAgent("old-agent", "llm", "low", nil))
	before := CaptureBaseline(nil, inv, "")
	after := CaptureBaseline(nil, nil, "")

	d := DiffBaselines(before, after)
	found := false
	for _, c := range d.Changes {
		if c.Category == "agent_removed" && c.Entity == "old-agent" {
			found = true
		}
	}
	if !found {
		t.Error("missing agent_removed change")
	}
}

func TestDiffBaselines_AgentModified_TrustChange(t *testing.T) {
	inv1 := mkInventory(mkAgent("a", "llm", "low", []string{"tool"}))
	before := CaptureBaseline(nil, inv1, "")

	inv2 := mkInventory(mkAgent("a", "llm", "high", []string{"tool"}))
	after := CaptureBaseline(nil, inv2, "")

	d := DiffBaselines(before, after)
	found := false
	for _, c := range d.Changes {
		if c.Category == "agent_modified" && c.Entity == "a" {
			found = true
			if c.Severity != "high" {
				t.Errorf("trust change should be high severity, got %q", c.Severity)
			}
			if !strings.Contains(c.Description, "trust") {
				t.Errorf("should mention trust change: %q", c.Description)
			}
		}
	}
	if !found {
		t.Error("missing agent_modified change")
	}
}

func TestDiffBaselines_AgentModified_ToolChange(t *testing.T) {
	inv1 := mkInventory(mkAgent("a", "llm", "medium", []string{"tool1"}))
	before := CaptureBaseline(nil, inv1, "")

	inv2 := mkInventory(mkAgent("a", "llm", "medium", []string{"tool1", "tool2"}))
	after := CaptureBaseline(nil, inv2, "")

	d := DiffBaselines(before, after)
	found := false
	for _, c := range d.Changes {
		if c.Category == "agent_modified" {
			found = true
			if c.Severity != "low" {
				t.Errorf("tool-only change should be low severity, got %q", c.Severity)
			}
		}
	}
	if !found {
		t.Error("missing agent_modified change")
	}
}

func TestDiffBaselines_ScoreChange(t *testing.T) {
	p1 := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y")})
	before := CaptureBaseline([]*policy.Policy{p1}, nil, "")

	p2 := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y")})
	p2.Meta.Description = "added description for better lint score"
	after := CaptureBaseline([]*policy.Policy{p2}, nil, "")

	d := DiffBaselines(before, after)
	for _, c := range d.Changes {
		if c.Category == "score_change" {
			if !strings.Contains(c.Description, "→") {
				t.Errorf("score change should show transition: %q", c.Description)
			}
			return
		}
	}
	// Score changes are only emitted if scores actually differ; acceptable to have none.
}

func TestDiffBaselines_SeveritySorting(t *testing.T) {
	p1 := mkPolicy("removed-policy", []policy.Rule{mkDenyRule("x", "y")})
	inv1 := mkInventory(mkAgent("a", "llm", "low", nil))
	before := CaptureBaseline([]*policy.Policy{p1}, inv1, "")

	p2 := mkPolicy("new-policy", []policy.Rule{mkDenyRule("z", "w")})
	after := CaptureBaseline([]*policy.Policy{p2}, nil, "")

	d := DiffBaselines(before, after)
	if len(d.Changes) < 2 {
		t.Fatalf("expected at least 2 changes, got %d", len(d.Changes))
	}
	// High-severity changes should come first.
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	for i := 1; i < len(d.Changes); i++ {
		prev := sevOrder[d.Changes[i-1].Severity]
		curr := sevOrder[d.Changes[i].Severity]
		if prev > curr {
			t.Errorf("change %d (%s) has lower priority than change %d (%s)",
				i-1, d.Changes[i-1].Severity, i, d.Changes[i].Severity)
		}
	}
}

func TestDiffBaselines_VerdictDegraded(t *testing.T) {
	p1 := mkPolicy("p1", []policy.Rule{mkDenyRule("a", "b"), mkDenyRule("c", "d")})
	p2 := mkPolicy("p2", []policy.Rule{mkDenyRule("e", "f")})
	inv := mkInventory(mkAgent("a1", "llm", "low", nil))
	before := CaptureBaseline([]*policy.Policy{p1, p2}, inv, "")

	// Remove both policies, remove agent → high risk delta.
	after := CaptureBaseline(nil, nil, "")

	d := DiffBaselines(before, after)
	if d.Verdict != "degraded" {
		t.Errorf("verdict = %q, want %q", d.Verdict, "degraded")
	}
	if d.RiskDelta <= 0 {
		t.Errorf("risk delta = %f, want positive", d.RiskDelta)
	}
}

func TestDiffBaselines_SummaryFormat(t *testing.T) {
	before := CaptureBaseline(nil, nil, "")
	p := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y")})
	after := CaptureBaseline([]*policy.Policy{p}, nil, "")

	d := DiffBaselines(before, after)
	if d.Summary == "" {
		t.Error("expected non-empty summary")
	}
	if !strings.Contains(d.Summary, "Verdict:") {
		t.Errorf("summary should contain verdict: %q", d.Summary)
	}
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

func TestSaveAndLoadBaseline(t *testing.T) {
	p := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y")})
	inv := mkInventory(mkAgent("a", "llm", "medium", []string{"tool"}))
	original := CaptureBaseline([]*policy.Policy{p}, inv, "test-save")

	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	if err := SaveBaseline(original, path); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.Fingerprint != original.Fingerprint {
		t.Errorf("fingerprints differ after roundtrip")
	}
	if loaded.Label != original.Label {
		t.Errorf("label = %q, want %q", loaded.Label, original.Label)
	}
	if loaded.Summary.TotalPolicies != original.Summary.TotalPolicies {
		t.Errorf("policies = %d, want %d", loaded.Summary.TotalPolicies, original.Summary.TotalPolicies)
	}
	if loaded.Summary.TotalAgents != original.Summary.TotalAgents {
		t.Errorf("agents = %d, want %d", loaded.Summary.TotalAgents, original.Summary.TotalAgents)
	}
}

func TestSaveBaseline_ValidJSON(t *testing.T) {
	b := CaptureBaseline(nil, nil, "json-test")
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")

	if err := SaveBaseline(b, path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if _, ok := raw["fingerprint"]; !ok {
		t.Error("missing fingerprint in JSON output")
	}
}

func TestLoadBaseline_FileNotFound(t *testing.T) {
	_, err := LoadBaseline("/nonexistent/baseline.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadBaseline_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := LoadBaseline(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

func TestFormatBaseline_ContainsInfo(t *testing.T) {
	p := mkPolicy("fmt-policy", []policy.Rule{mkDenyRule("x", "y")})
	inv := mkInventory(mkAgent("fmt-agent", "llm", "medium", []string{"tool"}))
	b := CaptureBaseline([]*policy.Policy{p}, inv, "format-test")

	out := FormatBaseline(b)
	for _, want := range []string{"Deployment Baseline", "format-test", "fmt-policy", "fmt-agent", "Policies", "Agents"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestFormatBaseline_NoLabel(t *testing.T) {
	b := CaptureBaseline(nil, nil, "")
	out := FormatBaseline(b)
	if strings.Contains(out, "Label:") {
		t.Error("should not show Label field when empty")
	}
}

func TestFormatBaselineDiff_Stable(t *testing.T) {
	b := CaptureBaseline(nil, nil, "")
	d := DiffBaselines(b, b)
	out := FormatBaselineDiff(d)
	if !strings.Contains(out, "No changes") {
		t.Errorf("stable diff should say no changes: %q", out)
	}
}

func TestFormatBaselineDiff_WithChanges(t *testing.T) {
	before := CaptureBaseline(nil, nil, "")
	p := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y")})
	after := CaptureBaseline([]*policy.Policy{p}, nil, "")

	d := DiffBaselines(before, after)
	out := FormatBaselineDiff(d)
	for _, want := range []string{"Baseline Comparison", "Before:", "After:", "Changes:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestSummarizeBaseline(t *testing.T) {
	b := CaptureBaseline(nil, nil, "")
	s := SummarizeBaseline(b)
	if !strings.Contains(s, "Baseline") {
		t.Errorf("summary missing 'Baseline': %q", s)
	}
	if !strings.Contains(s, b.ID) {
		t.Errorf("summary missing ID: %q", s)
	}
}

func TestSummarizeDiff(t *testing.T) {
	before := CaptureBaseline(nil, nil, "")
	p := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y")})
	after := CaptureBaseline([]*policy.Policy{p}, nil, "")
	d := DiffBaselines(before, after)

	s := SummarizeDiff(d)
	if s != d.Summary {
		t.Errorf("SummarizeDiff = %q, want %q", s, d.Summary)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{100, "A"},
		{95, "A"},
		{94.9, "B"},
		{85, "B"},
		{70, "C"},
		{50, "D"},
		{49, "F"},
		{0, "F"},
	}
	for _, tt := range tests {
		got := scoreToGrade(tt.score)
		if got != tt.want {
			t.Errorf("scoreToGrade(%g) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestTruncStr(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 8, "hello..."},
		{"ab", 5, "ab"},
	}
	for _, tt := range tests {
		got := truncStr(tt.in, tt.n)
		if got != tt.want {
			t.Errorf("truncStr(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
		}
	}
}

func TestComputeVerdict_AllInfoIsStable(t *testing.T) {
	d := &BaselineDiff{
		Changes: []BaselineChange{
			{Severity: "info", Category: "policy_added"},
			{Severity: "info", Category: "agent_added"},
		},
		RiskDelta: 0,
	}
	v := computeVerdict(d)
	if v != "stable" {
		t.Errorf("all-info changes should be stable, got %q", v)
	}
}

func TestBaselineFingerprint_OrderIndependent(t *testing.T) {
	p1 := mkPolicy("a", []policy.Rule{mkDenyRule("x", "y")})
	p2 := mkPolicy("b", []policy.Rule{mkDenyRule("z", "w")})

	b1 := CaptureBaseline([]*policy.Policy{p1, p2}, nil, "")
	b2 := CaptureBaseline([]*policy.Policy{p2, p1}, nil, "")

	if b1.Fingerprint != b2.Fingerprint {
		t.Error("fingerprint should be order-independent")
	}
}

func TestDiffBaselines_MixedChanges(t *testing.T) {
	p := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y")})
	inv := mkInventory(mkAgent("a", "llm", "low", []string{"t"}))
	before := CaptureBaseline([]*policy.Policy{p}, inv, "")

	// Modify policy and agent.
	p2 := mkPolicy("p", []policy.Rule{mkDenyRule("x", "y"), mkDenyRule("z", "w")})
	inv2 := mkInventory(mkAgent("a", "llm", "low", []string{"t", "t2"}))
	after := CaptureBaseline([]*policy.Policy{p2}, inv2, "")

	d := DiffBaselines(before, after)
	if len(d.Changes) == 0 {
		t.Fatal("expected changes")
	}

	categories := make(map[string]bool)
	for _, c := range d.Changes {
		categories[c.Category] = true
	}
	if !categories["policy_modified"] {
		t.Error("missing policy_modified")
	}
	if !categories["agent_modified"] {
		t.Error("missing agent_modified")
	}
}

func TestDiffBaselines_MultipleRemovals(t *testing.T) {
	policies := []*policy.Policy{
		mkPolicy("a", []policy.Rule{mkDenyRule("x", "y")}),
		mkPolicy("b", []policy.Rule{mkDenyRule("z", "w")}),
	}
	before := CaptureBaseline(policies, nil, "")
	after := CaptureBaseline(nil, nil, "")

	d := DiffBaselines(before, after)
	removals := 0
	for _, c := range d.Changes {
		if c.Category == "policy_removed" {
			removals++
		}
	}
	if removals != 2 {
		t.Errorf("policy removals = %d, want 2", removals)
	}
}
