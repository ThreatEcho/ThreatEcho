// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// helper to build a minimal campaign from stages.
func campaignFromStages(stages []Stage) *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:      "test",
			Adversary: "TestActor",
			Severity:  "medium",
		},
		Stages: stages,
	}
}

// --- AnalyzeGraph tests ---

func TestAnalyzeGraph_LinearChain(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
		{ID: "c", Technique: "T1003", DependsOn: []string{"b"}},
	})
	a := AnalyzeGraph(c)

	if a.StageCount != 3 {
		t.Errorf("StageCount = %d, want 3", a.StageCount)
	}
	if a.EdgeCount != 2 {
		t.Errorf("EdgeCount = %d, want 2", a.EdgeCount)
	}
	if len(a.EntryPoints) != 1 || a.EntryPoints[0] != "a" {
		t.Errorf("EntryPoints = %v, want [a]", a.EntryPoints)
	}
	if len(a.TerminalStages) != 1 || a.TerminalStages[0] != "c" {
		t.Errorf("TerminalStages = %v, want [c]", a.TerminalStages)
	}
	if a.MaxDepth != 3 {
		t.Errorf("MaxDepth = %d, want 3", a.MaxDepth)
	}
	if len(a.CriticalPath) != 3 {
		t.Errorf("CriticalPath length = %d, want 3", len(a.CriticalPath))
	} else {
		want := "a,b,c"
		got := strings.Join(a.CriticalPath, ",")
		if got != want {
			t.Errorf("CriticalPath = %s, want %s", got, want)
		}
	}
	if a.HasCycles {
		t.Error("HasCycles should be false for a linear chain")
	}
}

func TestAnalyzeGraph_Diamond(t *testing.T) {
	//   a
	//  / \
	// b   c
	//  \ /
	//   d
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
		{ID: "c", Technique: "T1003", DependsOn: []string{"a"}},
		{ID: "d", Technique: "T1004", DependsOn: []string{"b", "c"}},
	})
	a := AnalyzeGraph(c)

	if a.StageCount != 4 {
		t.Errorf("StageCount = %d, want 4", a.StageCount)
	}
	if a.EdgeCount != 4 {
		t.Errorf("EdgeCount = %d, want 4", a.EdgeCount)
	}
	if len(a.EntryPoints) != 1 || a.EntryPoints[0] != "a" {
		t.Errorf("EntryPoints = %v, want [a]", a.EntryPoints)
	}
	if len(a.TerminalStages) != 1 || a.TerminalStages[0] != "d" {
		t.Errorf("TerminalStages = %v, want [d]", a.TerminalStages)
	}
	if a.MaxDepth != 3 {
		t.Errorf("MaxDepth = %d, want 3", a.MaxDepth)
	}
	// Parallel: depth 1=[a], depth 2=[b,c], depth 3=[d]
	// b and c should be in the same parallel group.
	foundParallel := false
	for _, group := range a.Parallel {
		if len(group) == 2 {
			ids := map[string]bool{group[0]: true, group[1]: true}
			if ids["b"] && ids["c"] {
				foundParallel = true
			}
		}
	}
	if !foundParallel {
		t.Errorf("expected b and c in same parallel group, got %v", a.Parallel)
	}
}

func TestAnalyzeGraph_OrphanDependencies(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a", "ghost"}},
	})
	a := AnalyzeGraph(c)

	if len(a.OrphanDeps) != 1 || a.OrphanDeps[0] != "ghost" {
		t.Errorf("OrphanDeps = %v, want [ghost]", a.OrphanDeps)
	}
}

func TestAnalyzeGraph_DeadTransitions(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001", OnSuccess: "nonexistent"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}, OnFailure: "missing-fallback"},
	})
	a := AnalyzeGraph(c)

	if len(a.DeadTransitions) != 2 {
		t.Fatalf("DeadTransitions count = %d, want 2; got %+v", len(a.DeadTransitions), a.DeadTransitions)
	}
	// First should be on_success from a.
	if a.DeadTransitions[0].StageID != "a" || a.DeadTransitions[0].Field != "on_success" || a.DeadTransitions[0].Target != "nonexistent" {
		t.Errorf("DeadTransitions[0] = %+v, want {a, on_success, nonexistent}", a.DeadTransitions[0])
	}
	// Second should be on_failure from b (not a mode string, so treated as stage reference).
	if a.DeadTransitions[1].StageID != "b" || a.DeadTransitions[1].Field != "on_failure" || a.DeadTransitions[1].Target != "missing-fallback" {
		t.Errorf("DeadTransitions[1] = %+v, want {b, on_failure, missing-fallback}", a.DeadTransitions[1])
	}
}

func TestAnalyzeGraph_DeadTransitions_ModeNotFlagged(t *testing.T) {
	// on_failure with mode strings (abort/skip/continue) should NOT be dead transitions.
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001", OnFailure: "abort"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}, OnFailure: "continue"},
	})
	a := AnalyzeGraph(c)

	if len(a.DeadTransitions) != 0 {
		t.Errorf("DeadTransitions = %+v, want none for mode strings", a.DeadTransitions)
	}
}

func TestAnalyzeGraph_EntryPoints(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001"},
		{ID: "b", Technique: "T1002"},
		{ID: "c", Technique: "T1003", DependsOn: []string{"a", "b"}},
	})
	a := AnalyzeGraph(c)

	if len(a.EntryPoints) != 2 {
		t.Fatalf("EntryPoints count = %d, want 2", len(a.EntryPoints))
	}
	epSet := map[string]bool{a.EntryPoints[0]: true, a.EntryPoints[1]: true}
	if !epSet["a"] || !epSet["b"] {
		t.Errorf("EntryPoints = %v, want [a, b]", a.EntryPoints)
	}
}

func TestAnalyzeGraph_TerminalStages(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
		{ID: "c", Technique: "T1003", DependsOn: []string{"a"}},
	})
	a := AnalyzeGraph(c)

	if len(a.TerminalStages) != 2 {
		t.Fatalf("TerminalStages count = %d, want 2", len(a.TerminalStages))
	}
	tsSet := map[string]bool{a.TerminalStages[0]: true, a.TerminalStages[1]: true}
	if !tsSet["b"] || !tsSet["c"] {
		t.Errorf("TerminalStages = %v, want [b, c]", a.TerminalStages)
	}
}

func TestAnalyzeGraph_CriticalPath_LongestChain(t *testing.T) {
	// Two paths: a->b->c (depth 3) and a->d (depth 2).
	// Critical path should be a->b->c.
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
		{ID: "c", Technique: "T1003", DependsOn: []string{"b"}},
		{ID: "d", Technique: "T1004", DependsOn: []string{"a"}},
	})
	a := AnalyzeGraph(c)

	if a.MaxDepth != 3 {
		t.Errorf("MaxDepth = %d, want 3", a.MaxDepth)
	}
	want := "a,b,c"
	got := strings.Join(a.CriticalPath, ",")
	if got != want {
		t.Errorf("CriticalPath = %s, want %s", got, want)
	}
}

func TestAnalyzeGraph_ParallelDetection(t *testing.T) {
	// a -> b, c, d (all at depth 2) -> e
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
		{ID: "c", Technique: "T1003", DependsOn: []string{"a"}},
		{ID: "d", Technique: "T1004", DependsOn: []string{"a"}},
		{ID: "e", Technique: "T1005", DependsOn: []string{"b", "c", "d"}},
	})
	a := AnalyzeGraph(c)

	// Depth 2 should contain b, c, d.
	found := false
	for _, group := range a.Parallel {
		if len(group) == 3 {
			ids := make(map[string]bool)
			for _, id := range group {
				ids[id] = true
			}
			if ids["b"] && ids["c"] && ids["d"] {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected [b, c, d] in same parallel group, got %v", a.Parallel)
	}
}

func TestAnalyzeGraph_Unreachable(t *testing.T) {
	// a->b is the main chain. c is an island with no deps and nothing depends on it
	// via depends_on, but it's still an entry point. Actually, c IS reachable because
	// it is an entry point. For a true unreachable test, we need a cycle or isolated
	// non-entry node.
	// A stage is unreachable when it's not an entry and not connected via depends_on
	// from any entry. Let's make c depend on a phantom (orphan dep).
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
		{ID: "c", Technique: "T1003", DependsOn: []string{"phantom"}},
	})
	a := AnalyzeGraph(c)

	// c has a dependency on "phantom" (orphan), so c has deps and is not an entry point.
	// The walk from entry point "a" reaches a and b. c is never reached.
	if len(a.Unreachable) != 1 || a.Unreachable[0] != "c" {
		t.Errorf("Unreachable = %v, want [c]", a.Unreachable)
	}
}

func TestAnalyzeGraph_HasCycles(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001", DependsOn: []string{"b"}},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
	})
	a := AnalyzeGraph(c)

	if !a.HasCycles {
		t.Error("HasCycles should be true for a cycle")
	}
}

func TestAnalyzeGraph_EmptyCampaign(t *testing.T) {
	c := &Campaign{}
	a := AnalyzeGraph(c)

	if a.StageCount != 0 {
		t.Errorf("StageCount = %d, want 0", a.StageCount)
	}
	if a.EdgeCount != 0 {
		t.Errorf("EdgeCount = %d, want 0", a.EdgeCount)
	}
	if a.MaxDepth != 0 {
		t.Errorf("MaxDepth = %d, want 0", a.MaxDepth)
	}
	if len(a.EntryPoints) != 0 {
		t.Errorf("EntryPoints = %v, want empty", a.EntryPoints)
	}
	if a.HasCycles {
		t.Error("HasCycles should be false for empty campaign")
	}
}

func TestAnalyzeGraph_NilCampaign(t *testing.T) {
	a := AnalyzeGraph(nil)
	if a.StageCount != 0 {
		t.Errorf("StageCount = %d, want 0", a.StageCount)
	}
}

// --- GraphDOT tests ---

func TestGraphDOT_ValidSyntax(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
	})
	dot := GraphDOT(c)

	if !strings.Contains(dot, "digraph") {
		t.Error("DOT output should contain 'digraph'")
	}
	if !strings.Contains(dot, "->") {
		t.Error("DOT output should contain '->'")
	}
}

func TestGraphDOT_LabelsIncludeTechnique(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "recon", Technique: "T1595"},
	})
	dot := GraphDOT(c)

	if !strings.Contains(dot, "T1595") {
		t.Error("DOT output should contain technique T1595 in label")
	}
	if !strings.Contains(dot, "recon") {
		t.Error("DOT output should contain stage ID 'recon'")
	}
}

func TestGraphDOT_TransitionEdges(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001", OnSuccess: "b"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
	})
	dot := GraphDOT(c)

	if !strings.Contains(dot, "green") {
		t.Error("DOT output should contain green edge for on_success")
	}
	if !strings.Contains(dot, "dashed") {
		t.Error("DOT output should contain dashed style for transition edges")
	}
}

func TestGraphDOT_EmptyCampaign(t *testing.T) {
	c := &Campaign{}
	dot := GraphDOT(c)

	if !strings.Contains(dot, "digraph") {
		t.Error("DOT output should contain 'digraph' even for empty campaign")
	}
}

// --- GraphMermaid tests ---

func TestGraphMermaid_ValidSyntax(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
	})
	mmd := GraphMermaid(c)

	if !strings.Contains(mmd, "graph TD") {
		t.Error("Mermaid output should contain 'graph TD'")
	}
}

func TestGraphMermaid_IncludesAllStages(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "recon", Technique: "T1595"},
		{ID: "access", Technique: "T1190", DependsOn: []string{"recon"}},
		{ID: "persist", Technique: "T1053", DependsOn: []string{"access"}},
	})
	mmd := GraphMermaid(c)

	for _, id := range []string{"recon", "access", "persist"} {
		if !strings.Contains(mmd, id) {
			t.Errorf("Mermaid output should contain stage %q", id)
		}
	}
	for _, tech := range []string{"T1595", "T1190", "T1053"} {
		if !strings.Contains(mmd, tech) {
			t.Errorf("Mermaid output should contain technique %q", tech)
		}
	}
}

func TestGraphMermaid_TransitionEdges(t *testing.T) {
	c := campaignFromStages([]Stage{
		{ID: "a", Technique: "T1001", OnSuccess: "b"},
		{ID: "b", Technique: "T1002", DependsOn: []string{"a"}},
	})
	mmd := GraphMermaid(c)

	if !strings.Contains(mmd, "success") {
		t.Error("Mermaid output should contain 'success' label for on_success transition")
	}
	if !strings.Contains(mmd, "-.->") {
		t.Error("Mermaid output should contain '-.->'' for dashed transition edges")
	}
}

// --- Real campaign test ---

func TestAnalyzeGraph_RealAPT29(t *testing.T) {
	// Locate the campaigns directory relative to the test file.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	// Navigate from internal/campaign/ to the repo root campaigns/ dir.
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	apt29Dir := filepath.Join(repoRoot, "campaigns", "apt29-cozy-bear")

	if _, err := os.Stat(filepath.Join(apt29Dir, "campaign.yaml")); err != nil {
		t.Skipf("apt29 campaign not found at %s: %v", apt29Dir, err)
	}

	c, err := Load(apt29Dir)
	if err != nil {
		t.Fatalf("failed to load apt29 campaign: %v", err)
	}

	a := AnalyzeGraph(c)

	// The APT29 campaign has 8 stages in a linear chain.
	if a.StageCount != 8 {
		t.Errorf("StageCount = %d, want 8", a.StageCount)
	}
	if len(a.EntryPoints) != 1 {
		t.Errorf("EntryPoints count = %d, want 1", len(a.EntryPoints))
	}
	if a.EntryPoints[0] != "initial-access" {
		t.Errorf("EntryPoints[0] = %q, want %q", a.EntryPoints[0], "initial-access")
	}
	if len(a.TerminalStages) != 1 {
		t.Errorf("TerminalStages count = %d, want 1", len(a.TerminalStages))
	}
	if a.TerminalStages[0] != "exfiltration" {
		t.Errorf("TerminalStages[0] = %q, want %q", a.TerminalStages[0], "exfiltration")
	}
	if a.MaxDepth != 8 {
		t.Errorf("MaxDepth = %d, want 8", a.MaxDepth)
	}
	if len(a.OrphanDeps) != 0 {
		t.Errorf("OrphanDeps = %v, want empty", a.OrphanDeps)
	}
	if a.HasCycles {
		t.Error("HasCycles should be false for apt29")
	}
	if len(a.Unreachable) != 0 {
		t.Errorf("Unreachable = %v, want empty", a.Unreachable)
	}
	// Critical path should be all 8 stages for a linear chain.
	if len(a.CriticalPath) != 8 {
		t.Errorf("CriticalPath length = %d, want 8", len(a.CriticalPath))
	}

	// Verify DOT and Mermaid output for the real campaign.
	dot := GraphDOT(c)
	if !strings.Contains(dot, "initial-access") {
		t.Error("DOT should contain initial-access stage")
	}
	mmd := GraphMermaid(c)
	if !strings.Contains(mmd, "exfiltration") {
		t.Error("Mermaid should contain exfiltration stage")
	}
}
