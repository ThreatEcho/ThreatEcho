// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"testing"
)

func TestResolveOrder_LinearChain(t *testing.T) {
	stages := []Stage{
		{ID: "a"},
		{ID: "b", DependsOn: []string{"a"}},
		{ID: "c", DependsOn: []string{"b"}},
	}
	ordered, err := ResolveOrder(stages)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ordered) != 3 {
		t.Fatalf("got %d stages, want 3", len(ordered))
	}
	// a must come before b, b before c.
	idx := make(map[string]int)
	for i, s := range ordered {
		idx[s.ID] = i
	}
	if idx["a"] >= idx["b"] {
		t.Errorf("a (pos %d) should come before b (pos %d)", idx["a"], idx["b"])
	}
	if idx["b"] >= idx["c"] {
		t.Errorf("b (pos %d) should come before c (pos %d)", idx["b"], idx["c"])
	}
}

func TestResolveOrder_Diamond(t *testing.T) {
	//   a
	//  / \
	// b   c
	//  \ /
	//   d
	stages := []Stage{
		{ID: "a"},
		{ID: "b", DependsOn: []string{"a"}},
		{ID: "c", DependsOn: []string{"a"}},
		{ID: "d", DependsOn: []string{"b", "c"}},
	}
	ordered, err := ResolveOrder(stages)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ordered) != 4 {
		t.Fatalf("got %d stages, want 4", len(ordered))
	}
	idx := make(map[string]int)
	for i, s := range ordered {
		idx[s.ID] = i
	}
	if idx["a"] >= idx["b"] || idx["a"] >= idx["c"] {
		t.Error("a should come before b and c")
	}
	if idx["b"] >= idx["d"] || idx["c"] >= idx["d"] {
		t.Error("b and c should come before d")
	}
}

func TestResolveOrder_SingleNode(t *testing.T) {
	stages := []Stage{{ID: "only"}}
	ordered, err := ResolveOrder(stages)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ordered) != 1 {
		t.Fatalf("got %d stages, want 1", len(ordered))
	}
	if ordered[0].ID != "only" {
		t.Errorf("got ID %q, want %q", ordered[0].ID, "only")
	}
}

func TestResolveOrder_Cycle(t *testing.T) {
	stages := []Stage{
		{ID: "a", DependsOn: []string{"c"}},
		{ID: "b", DependsOn: []string{"a"}},
		{ID: "c", DependsOn: []string{"b"}},
	}
	_, err := ResolveOrder(stages)
	if err == nil {
		t.Fatal("expected cycle error, got nil")
	}
}

func TestDetectCycle_NoCycle(t *testing.T) {
	stages := []Stage{
		{ID: "a"},
		{ID: "b", DependsOn: []string{"a"}},
	}
	cycle := detectCycle(stages)
	if cycle != "" {
		t.Errorf("expected no cycle, got %q", cycle)
	}
}

func TestDetectCycle_WithCycle(t *testing.T) {
	stages := []Stage{
		{ID: "a", DependsOn: []string{"b"}},
		{ID: "b", DependsOn: []string{"a"}},
	}
	cycle := detectCycle(stages)
	if cycle == "" {
		t.Error("expected cycle to be detected, got empty string")
	}
}

func TestResolveOrder_ParallelRoots(t *testing.T) {
	stages := []Stage{
		{ID: "a"},
		{ID: "b"},
		{ID: "c", DependsOn: []string{"a", "b"}},
	}
	ordered, err := ResolveOrder(stages)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ordered) != 3 {
		t.Fatalf("got %d stages, want 3", len(ordered))
	}
	idx := make(map[string]int)
	for i, s := range ordered {
		idx[s.ID] = i
	}
	if idx["a"] >= idx["c"] || idx["b"] >= idx["c"] {
		t.Error("a and b should come before c")
	}
}
