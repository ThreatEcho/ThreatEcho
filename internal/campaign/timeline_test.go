// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"strings"
	"testing"
	"time"
)

// helper to build a minimal stage.
func timelineStage(id string, dependsOn []string, timeout, delay time.Duration) Stage {
	return Stage{
		ID:        id,
		Name:      id,
		Technique: "T1059",
		Tactic:    "execution",
		DependsOn: dependsOn,
		Timeout:   Duration{Duration: timeout},
		Delay:     Duration{Duration: delay},
	}
}

// helper to wrap stages in a Campaign.
func timelineCampaign(stages ...Stage) *Campaign {
	return &Campaign{
		APIVersion: "v1",
		Kind:       "campaign",
		Meta:       Meta{Name: "test-campaign"},
		Stages:     stages,
	}
}

func TestEstimateTimeline_SingleStage(t *testing.T) {
	c := timelineCampaign(timelineStage("a", nil, 0, 0))
	est := EstimateTimeline(c)

	if est.TotalSequential != 30*time.Second {
		t.Errorf("TotalSequential = %v, want 30s", est.TotalSequential)
	}
	if est.TotalParallel != 30*time.Second {
		t.Errorf("TotalParallel = %v, want 30s", est.TotalParallel)
	}
	if est.Speedup != 1.0 {
		t.Errorf("Speedup = %v, want 1.0", est.Speedup)
	}
	if len(est.Stages) != 1 {
		t.Fatalf("len(Stages) = %d, want 1", len(est.Stages))
	}
	if est.Stages[0].ID != "a" {
		t.Errorf("Stages[0].ID = %q, want %q", est.Stages[0].ID, "a")
	}
}

func TestEstimateTimeline_LinearChain(t *testing.T) {
	// A -> B -> C: no parallelism, speedup = 1.0
	c := timelineCampaign(
		timelineStage("a", nil, 0, 0),
		timelineStage("b", []string{"a"}, 0, 0),
		timelineStage("c", []string{"b"}, 0, 0),
	)
	est := EstimateTimeline(c)

	want := 90 * time.Second
	if est.TotalSequential != want {
		t.Errorf("TotalSequential = %v, want %v", est.TotalSequential, want)
	}
	if est.TotalParallel != want {
		t.Errorf("TotalParallel = %v, want %v", est.TotalParallel, want)
	}
	if est.Speedup != 1.0 {
		t.Errorf("Speedup = %v, want 1.0", est.Speedup)
	}
	if len(est.ParallelLevels) != 3 {
		t.Errorf("len(ParallelLevels) = %d, want 3", len(est.ParallelLevels))
	}
}

func TestEstimateTimeline_FullyParallel(t *testing.T) {
	// A, B, C: all independent, speedup = 3.0
	c := timelineCampaign(
		timelineStage("a", nil, 0, 0),
		timelineStage("b", nil, 0, 0),
		timelineStage("c", nil, 0, 0),
	)
	est := EstimateTimeline(c)

	if est.TotalSequential != 90*time.Second {
		t.Errorf("TotalSequential = %v, want 90s", est.TotalSequential)
	}
	if est.TotalParallel != 30*time.Second {
		t.Errorf("TotalParallel = %v, want 30s", est.TotalParallel)
	}
	if est.Speedup != 3.0 {
		t.Errorf("Speedup = %v, want 3.0", est.Speedup)
	}
	if len(est.ParallelLevels) != 1 {
		t.Errorf("len(ParallelLevels) = %d, want 1", len(est.ParallelLevels))
	}
}

func TestEstimateTimeline_DiamondDAG(t *testing.T) {
	// A -> B, A -> C, B -> D, C -> D
	// Depth 1: A, Depth 2: B+C, Depth 3: D
	// Sequential: 4 * 30s = 120s
	// Parallel: 3 * 30s = 90s (3 levels, each 30s)
	// Speedup: 120/90 = 1.333...
	c := timelineCampaign(
		timelineStage("a", nil, 0, 0),
		timelineStage("b", []string{"a"}, 0, 0),
		timelineStage("c", []string{"a"}, 0, 0),
		timelineStage("d", []string{"b", "c"}, 0, 0),
	)
	est := EstimateTimeline(c)

	if est.TotalSequential != 120*time.Second {
		t.Errorf("TotalSequential = %v, want 2m0s", est.TotalSequential)
	}
	if est.TotalParallel != 90*time.Second {
		t.Errorf("TotalParallel = %v, want 1m30s", est.TotalParallel)
	}
	if est.Speedup <= 1.0 || est.Speedup >= 2.0 {
		t.Errorf("Speedup = %v, want between 1.0 and 2.0", est.Speedup)
	}
}

func TestEstimateTimeline_WithTimeouts(t *testing.T) {
	// Stages with explicit timeouts should use those as duration estimates.
	c := timelineCampaign(
		timelineStage("a", nil, 10*time.Second, 0),
		timelineStage("b", []string{"a"}, 45*time.Second, 0),
	)
	est := EstimateTimeline(c)

	if est.TotalSequential != 55*time.Second {
		t.Errorf("TotalSequential = %v, want 55s", est.TotalSequential)
	}
	if est.TotalParallel != 55*time.Second {
		t.Errorf("TotalParallel = %v, want 55s", est.TotalParallel)
	}

	// Check individual stage durations.
	if len(est.Stages) != 2 {
		t.Fatalf("len(Stages) = %d, want 2", len(est.Stages))
	}
	if est.Stages[0].Duration != 10*time.Second {
		t.Errorf("stage a duration = %v, want 10s", est.Stages[0].Duration)
	}
	if est.Stages[1].Duration != 45*time.Second {
		t.Errorf("stage b duration = %v, want 45s", est.Stages[1].Duration)
	}
}

func TestEstimateTimeline_WithDelays(t *testing.T) {
	// Delay adds to stage timeline.
	c := timelineCampaign(
		timelineStage("a", nil, 0, 5*time.Second),
		timelineStage("b", []string{"a"}, 0, 10*time.Second),
	)
	est := EstimateTimeline(c)

	// Sequential: (30+5) + (30+10) = 75s
	if est.TotalSequential != 75*time.Second {
		t.Errorf("TotalSequential = %v, want 1m15s", est.TotalSequential)
	}
	// Parallel (linear chain): same as sequential = 75s
	if est.TotalParallel != 75*time.Second {
		t.Errorf("TotalParallel = %v, want 1m15s", est.TotalParallel)
	}

	// Stage a: EarliestStart=0, EarliestEnd=35s
	if est.Stages[0].EarliestStart != 0 {
		t.Errorf("stage a EarliestStart = %v, want 0s", est.Stages[0].EarliestStart)
	}
	if est.Stages[0].EarliestEnd != 35*time.Second {
		t.Errorf("stage a EarliestEnd = %v, want 35s", est.Stages[0].EarliestEnd)
	}

	// Stage b: EarliestStart=35s, EarliestEnd=75s
	if est.Stages[1].EarliestStart != 35*time.Second {
		t.Errorf("stage b EarliestStart = %v, want 35s", est.Stages[1].EarliestStart)
	}
	if est.Stages[1].EarliestEnd != 75*time.Second {
		t.Errorf("stage b EarliestEnd = %v, want 1m15s", est.Stages[1].EarliestEnd)
	}
}

func TestEstimateTimeline_DefaultDuration(t *testing.T) {
	// Stages without timeout use 30s default.
	c := timelineCampaign(
		timelineStage("a", nil, 0, 0),
	)
	est := EstimateTimeline(c)

	if est.Stages[0].Duration != DefaultStageDuration {
		t.Errorf("duration = %v, want %v (DefaultStageDuration)", est.Stages[0].Duration, DefaultStageDuration)
	}
}

func TestEstimateTimeline_CriticalPath(t *testing.T) {
	// Diamond: A -> B -> D, A -> C -> D
	// Give B a longer timeout so path A->B->D is critical.
	c := timelineCampaign(
		timelineStage("a", nil, 10*time.Second, 0),
		timelineStage("b", []string{"a"}, 60*time.Second, 0),
		timelineStage("c", []string{"a"}, 20*time.Second, 0),
		timelineStage("d", []string{"b", "c"}, 10*time.Second, 0),
	)
	est := EstimateTimeline(c)

	if len(est.CriticalPath) != 3 {
		t.Fatalf("CriticalPath length = %d, want 3; got %v", len(est.CriticalPath), est.CriticalPath)
	}
	if est.CriticalPath[0] != "a" || est.CriticalPath[1] != "b" || est.CriticalPath[2] != "d" {
		t.Errorf("CriticalPath = %v, want [a b d]", est.CriticalPath)
	}
}

func TestEstimateTimeline_EarliestStart(t *testing.T) {
	// A (10s) -> B (20s) -> C (30s)
	c := timelineCampaign(
		timelineStage("a", nil, 10*time.Second, 0),
		timelineStage("b", []string{"a"}, 20*time.Second, 0),
		timelineStage("c", []string{"b"}, 30*time.Second, 0),
	)
	est := EstimateTimeline(c)

	expected := []struct {
		id    string
		start time.Duration
		end   time.Duration
	}{
		{"a", 0, 10 * time.Second},
		{"b", 10 * time.Second, 30 * time.Second},
		{"c", 30 * time.Second, 60 * time.Second},
	}

	for i, exp := range expected {
		if est.Stages[i].ID != exp.id {
			t.Errorf("Stages[%d].ID = %q, want %q", i, est.Stages[i].ID, exp.id)
		}
		if est.Stages[i].EarliestStart != exp.start {
			t.Errorf("%s EarliestStart = %v, want %v", exp.id, est.Stages[i].EarliestStart, exp.start)
		}
		if est.Stages[i].EarliestEnd != exp.end {
			t.Errorf("%s EarliestEnd = %v, want %v", exp.id, est.Stages[i].EarliestEnd, exp.end)
		}
	}
}

func TestEstimateTimeline_EmptyCampaign(t *testing.T) {
	// nil campaign.
	est := EstimateTimeline(nil)
	if est == nil {
		t.Fatal("EstimateTimeline(nil) returned nil, want non-nil empty estimate")
	}
	if est.TotalSequential != 0 {
		t.Errorf("TotalSequential = %v, want 0", est.TotalSequential)
	}
	if est.TotalParallel != 0 {
		t.Errorf("TotalParallel = %v, want 0", est.TotalParallel)
	}
	if len(est.Stages) != 0 {
		t.Errorf("len(Stages) = %d, want 0", len(est.Stages))
	}

	// Empty stages.
	est2 := EstimateTimeline(&Campaign{Stages: nil})
	if est2 == nil {
		t.Fatal("EstimateTimeline(&Campaign{}) returned nil")
	}
	if est2.TotalSequential != 0 {
		t.Errorf("TotalSequential = %v, want 0", est2.TotalSequential)
	}
}

func TestEstimateTimeline_ParallelLevels(t *testing.T) {
	// A, B (level 1) -> C (level 2) -> D, E (level 3)
	c := timelineCampaign(
		timelineStage("a", nil, 0, 0),
		timelineStage("b", nil, 0, 0),
		timelineStage("c", []string{"a", "b"}, 0, 0),
		timelineStage("d", []string{"c"}, 0, 0),
		timelineStage("e", []string{"c"}, 0, 0),
	)
	est := EstimateTimeline(c)

	if len(est.ParallelLevels) != 3 {
		t.Fatalf("len(ParallelLevels) = %d, want 3", len(est.ParallelLevels))
	}

	// Level 1 should have a and b.
	l1 := est.ParallelLevels[0]
	if l1.Level != 1 {
		t.Errorf("Level[0].Level = %d, want 1", l1.Level)
	}
	if len(l1.StageIDs) != 2 {
		t.Errorf("Level 1 stages = %v, want 2 stages", l1.StageIDs)
	}

	// Level 2 should have c.
	l2 := est.ParallelLevels[1]
	if len(l2.StageIDs) != 1 || l2.StageIDs[0] != "c" {
		t.Errorf("Level 2 stages = %v, want [c]", l2.StageIDs)
	}

	// Level 3 should have d and e.
	l3 := est.ParallelLevels[2]
	if len(l3.StageIDs) != 2 {
		t.Errorf("Level 3 stages = %v, want 2 stages", l3.StageIDs)
	}
}

func TestEstimateTimeline_SpeedupRatio(t *testing.T) {
	// 4 independent stages: speedup should be 4.0.
	c := timelineCampaign(
		timelineStage("a", nil, 0, 0),
		timelineStage("b", nil, 0, 0),
		timelineStage("c", nil, 0, 0),
		timelineStage("d", nil, 0, 0),
	)
	est := EstimateTimeline(c)

	if est.Speedup != 4.0 {
		t.Errorf("Speedup = %v, want 4.0", est.Speedup)
	}

	// Linear chain of 2: speedup = 1.0.
	c2 := timelineCampaign(
		timelineStage("a", nil, 0, 0),
		timelineStage("b", []string{"a"}, 0, 0),
	)
	est2 := EstimateTimeline(c2)

	if est2.Speedup != 1.0 {
		t.Errorf("Speedup = %v, want 1.0", est2.Speedup)
	}
}

func TestFormatTimeline_ContainsKey(t *testing.T) {
	c := timelineCampaign(
		timelineStage("a", nil, 0, 0),
		timelineStage("b", []string{"a"}, 0, 0),
	)
	est := EstimateTimeline(c)
	out := FormatTimeline(est)

	for _, key := range []string{"Sequential:", "Parallel:", "Speedup:"} {
		if !strings.Contains(out, key) {
			t.Errorf("output missing %q", key)
		}
	}
}

func TestFormatTimeline_ContainsCriticalPath(t *testing.T) {
	c := timelineCampaign(
		timelineStage("a", nil, 0, 0),
		timelineStage("b", []string{"a"}, 0, 0),
		timelineStage("c", []string{"b"}, 0, 0),
	)
	est := EstimateTimeline(c)
	out := FormatTimeline(est)

	if !strings.Contains(out, "Critical Path:") {
		t.Error("output missing 'Critical Path:'")
	}
	// All three stages should appear on the critical path line.
	for _, id := range []string{"a", "b", "c"} {
		if !strings.Contains(out, id) {
			t.Errorf("critical path output missing stage %q", id)
		}
	}
}

func TestEstimateTimeline_MixedTimeouts(t *testing.T) {
	// Mix: a has timeout 10s, b uses default 30s, c has timeout 1m.
	c := timelineCampaign(
		timelineStage("a", nil, 10*time.Second, 0),
		timelineStage("b", nil, 0, 0),
		timelineStage("c", nil, 60*time.Second, 0),
	)
	est := EstimateTimeline(c)

	// All three are independent (no deps) => all at depth 1.
	// Sequential: 10 + 30 + 60 = 100s
	if est.TotalSequential != 100*time.Second {
		t.Errorf("TotalSequential = %v, want 1m40s", est.TotalSequential)
	}
	// Parallel: max(10, 30, 60) = 60s
	if est.TotalParallel != 60*time.Second {
		t.Errorf("TotalParallel = %v, want 1m0s", est.TotalParallel)
	}

	// Verify individual durations.
	durMap := make(map[string]time.Duration)
	for _, s := range est.Stages {
		durMap[s.ID] = s.Duration
	}
	if durMap["a"] != 10*time.Second {
		t.Errorf("a duration = %v, want 10s", durMap["a"])
	}
	if durMap["b"] != 30*time.Second {
		t.Errorf("b duration = %v, want 30s", durMap["b"])
	}
	if durMap["c"] != 60*time.Second {
		t.Errorf("c duration = %v, want 1m0s", durMap["c"])
	}
}

func TestFormatTimeline_NilEstimate(t *testing.T) {
	out := FormatTimeline(nil)
	if out == "" {
		t.Error("FormatTimeline(nil) returned empty string")
	}
}

func TestFormatTimeline_StageDetails(t *testing.T) {
	c := timelineCampaign(
		timelineStage("recon", nil, 15*time.Second, 5*time.Second),
		timelineStage("exploit", []string{"recon"}, 45*time.Second, 0),
	)
	est := EstimateTimeline(c)
	out := FormatTimeline(est)

	// Check that stage details section exists.
	if !strings.Contains(out, "Stage Details:") {
		t.Error("output missing 'Stage Details:'")
	}
	// Check delay is shown for the stage that has one.
	if !strings.Contains(out, "delay") {
		t.Error("output missing delay information for recon stage")
	}
	// Check depth info.
	if !strings.Contains(out, "depth 1") {
		t.Error("output missing depth 1")
	}
	if !strings.Contains(out, "depth 2") {
		t.Error("output missing depth 2")
	}
}

func TestFormatTimeline_ExecutionLevels(t *testing.T) {
	c := timelineCampaign(
		timelineStage("a", nil, 0, 0),
		timelineStage("b", nil, 0, 0),
		timelineStage("c", []string{"a", "b"}, 0, 0),
	)
	est := EstimateTimeline(c)
	out := FormatTimeline(est)

	if !strings.Contains(out, "Execution Levels:") {
		t.Error("output missing 'Execution Levels:'")
	}
	if !strings.Contains(out, "Level 1") {
		t.Error("output missing Level 1")
	}
	if !strings.Contains(out, "Level 2") {
		t.Error("output missing Level 2")
	}
}

func TestEstimateTimeline_ParallelDelays(t *testing.T) {
	// Two parallel stages with different delays — the level delay = max.
	c := timelineCampaign(
		timelineStage("a", nil, 0, 5*time.Second),
		timelineStage("b", nil, 0, 10*time.Second),
	)
	est := EstimateTimeline(c)

	if len(est.ParallelLevels) != 1 {
		t.Fatalf("len(ParallelLevels) = %d, want 1", len(est.ParallelLevels))
	}
	// Level delay = max(5s, 10s) = 10s.
	if est.ParallelLevels[0].Delay != 10*time.Second {
		t.Errorf("level delay = %v, want 10s", est.ParallelLevels[0].Delay)
	}
	// Level duration = max(5+30, 10+30) = 40s.
	if est.ParallelLevels[0].Duration != 40*time.Second {
		t.Errorf("level duration = %v, want 40s", est.ParallelLevels[0].Duration)
	}
}

func TestEstimateTimeline_WideDAG(t *testing.T) {
	// Fan-out: A -> B, C, D, E (4 parallel at depth 2).
	c := timelineCampaign(
		timelineStage("a", nil, 10*time.Second, 0),
		timelineStage("b", []string{"a"}, 20*time.Second, 0),
		timelineStage("c", []string{"a"}, 30*time.Second, 0),
		timelineStage("d", []string{"a"}, 40*time.Second, 0),
		timelineStage("e", []string{"a"}, 50*time.Second, 0),
	)
	est := EstimateTimeline(c)

	// Sequential: 10+20+30+40+50 = 150s
	if est.TotalSequential != 150*time.Second {
		t.Errorf("TotalSequential = %v, want 2m30s", est.TotalSequential)
	}
	// Parallel: 10s (level 1) + max(20,30,40,50)=50s (level 2) = 60s
	if est.TotalParallel != 60*time.Second {
		t.Errorf("TotalParallel = %v, want 1m0s", est.TotalParallel)
	}
	// Speedup: 150/60 = 2.5
	if est.Speedup != 2.5 {
		t.Errorf("Speedup = %v, want 2.5", est.Speedup)
	}
}
