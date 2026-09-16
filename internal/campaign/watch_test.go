// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const testPollInterval = 50 * time.Millisecond

// writeCampaignFile creates a campaign subdirectory and writes campaign.yaml
// into it. Returns the full path to the campaign.yaml file.
func writeCampaignFile(t *testing.T, dir, subdir, content string) string {
	t.Helper()
	d := filepath.Join(dir, subdir)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "campaign.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// minimalValidCampaign returns a well-formed campaign YAML that passes both
// validation and lint cleanly.
func minimalValidCampaign(name string) string {
	return fmt.Sprintf(`api_version: "1.0"
kind: Campaign
meta:
  name: %s
  adversary: test-adversary
  description: A test campaign
  objective: Testing the watch engine
  mitre_version: "15.1"
  severity: high
stages:
  - id: s1
    name: Test Stage
    technique: T1059
    tactic: execution
    execute:
      type: shell
      commands:
        - echo test
    expect:
      telemetry:
        - process_create
      detections:
        - test_detection
`, name)
}

// waitForEvent blocks until one event arrives on ch or timeout elapses.
func waitForEvent(ch <-chan WatchEvent, timeout time.Duration) (WatchEvent, bool) {
	select {
	case evt := <-ch:
		return evt, true
	case <-time.After(timeout):
		return WatchEvent{}, false
	}
}

// waitForEvents collects up to count events from ch within timeout.
func waitForEvents(ch <-chan WatchEvent, count int, timeout time.Duration) []WatchEvent {
	var events []WatchEvent
	deadline := time.After(timeout)
	for range count {
		select {
		case evt := <-ch:
			events = append(events, evt)
		case <-deadline:
			return events
		}
	}
	return events
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestWatch_DetectsNewFile(t *testing.T) {
	dir := t.TempDir()
	events := make(chan WatchEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = Watch(ctx, WatchOptions{
			Dir:      dir,
			Interval: testPollInterval,
			OnChange: func(evt WatchEvent) { events <- evt },
		})
	}()

	// Let the initial scan complete and the ticker start.
	time.Sleep(20 * time.Millisecond)

	// Create a new campaign after baseline.
	writeCampaignFile(t, dir, "new-campaign", minimalValidCampaign("new-campaign"))

	evt, ok := waitForEvent(events, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for new file event")
	}
	if evt.Type != "added" {
		t.Errorf("expected type 'added', got %q", evt.Type)
	}
	if evt.Campaign != "new-campaign" {
		t.Errorf("expected campaign 'new-campaign', got %q", evt.Campaign)
	}
	if evt.Path == "" {
		t.Error("expected non-empty Path")
	}
}

func TestWatch_DetectsModifiedFile(t *testing.T) {
	dir := t.TempDir()

	// Create campaign before starting watcher so it enters the baseline.
	p := writeCampaignFile(t, dir, "existing", minimalValidCampaign("existing"))

	events := make(chan WatchEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = Watch(ctx, WatchOptions{
			Dir:      dir,
			Interval: testPollInterval,
			OnChange: func(evt WatchEvent) { events <- evt },
		})
	}()

	time.Sleep(20 * time.Millisecond)

	// Modify the file — different content changes both size and modtime.
	modified := minimalValidCampaign("existing-v2") + "# modification marker\n"
	if err := os.WriteFile(p, []byte(modified), 0o644); err != nil {
		t.Fatal(err)
	}

	evt, ok := waitForEvent(events, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for modified file event")
	}
	if evt.Type != "modified" {
		t.Errorf("expected type 'modified', got %q", evt.Type)
	}
	if evt.Campaign != "existing-v2" {
		t.Errorf("expected campaign 'existing-v2', got %q", evt.Campaign)
	}
}

func TestWatch_DetectsRemovedFile(t *testing.T) {
	dir := t.TempDir()

	// Create campaign before starting watcher.
	p := writeCampaignFile(t, dir, "to-remove", minimalValidCampaign("to-remove"))

	events := make(chan WatchEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = Watch(ctx, WatchOptions{
			Dir:      dir,
			Interval: testPollInterval,
			OnChange: func(evt WatchEvent) { events <- evt },
		})
	}()

	time.Sleep(20 * time.Millisecond)

	// Remove just the campaign.yaml file (directory stays).
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}

	evt, ok := waitForEvent(events, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for removed file event")
	}
	if evt.Type != "removed" {
		t.Errorf("expected type 'removed', got %q", evt.Type)
	}
	if evt.Campaign != "to-remove" {
		t.Errorf("expected campaign 'to-remove', got %q", evt.Campaign)
	}
}

func TestWatch_CancelledByContext(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- Watch(ctx, WatchOptions{
			Dir:      dir,
			Interval: testPollInterval,
			OnChange: func(evt WatchEvent) {},
		})
	}()

	// Let the watcher start.
	time.Sleep(20 * time.Millisecond)

	cancel()

	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not return after context cancellation")
	}
}

func TestWatch_RunsValidation(t *testing.T) {
	dir := t.TempDir()
	events := make(chan WatchEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = Watch(ctx, WatchOptions{
			Dir:      dir,
			Interval: testPollInterval,
			OnChange: func(evt WatchEvent) { events <- evt },
			Validate: true,
		})
	}()

	time.Sleep(20 * time.Millisecond)

	// Campaign with wrong kind — triggers validation error.
	invalidYAML := `api_version: "1.0"
kind: NotCampaign
meta:
  name: invalid-campaign
  adversary: test
stages:
  - id: s1
    name: Test
    technique: T1059
    tactic: execution
    execute:
      type: shell
      commands:
        - echo test
`
	writeCampaignFile(t, dir, "invalid", invalidYAML)

	evt, ok := waitForEvent(events, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for validation event")
	}
	if len(evt.Errors) == 0 {
		t.Fatal("expected validation errors, got none")
	}

	found := false
	for _, e := range evt.Errors {
		if strings.Contains(e.Error(), "kind must be") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about invalid kind, got: %v", evt.Errors)
	}
}

func TestWatch_RunsLint(t *testing.T) {
	dir := t.TempDir()
	events := make(chan WatchEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = Watch(ctx, WatchOptions{
			Dir:      dir,
			Interval: testPollInterval,
			OnChange: func(evt WatchEvent) { events <- evt },
			Lint:     true,
		})
	}()

	time.Sleep(20 * time.Millisecond)

	// Campaign with lint warnings: no telemetry, shell with no commands,
	// missing description/objective/mitre_version.
	lintableYAML := `api_version: "1.0"
kind: Campaign
meta:
  name: lint-test
  adversary: test
stages:
  - id: s1
    name: Test
    technique: T1059
    tactic: execution
    execute:
      type: shell
`
	writeCampaignFile(t, dir, "lintable", lintableYAML)

	evt, ok := waitForEvent(events, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for lint event")
	}
	if evt.LintResult == nil {
		t.Fatal("expected LintResult, got nil")
	}
	if !evt.LintResult.HasIssues() {
		t.Error("expected lint warnings, got none")
	}
	// Should have at least a warning about missing telemetry and empty commands.
	if len(evt.LintResult.Warnings) < 2 {
		t.Errorf("expected at least 2 lint warnings, got %d: %v",
			len(evt.LintResult.Warnings), evt.LintResult.Warnings)
	}
}

func TestWatch_DefaultInterval(t *testing.T) {
	// Verify the exported constant.
	if DefaultWatchInterval != 2*time.Second {
		t.Errorf("expected DefaultWatchInterval to be 2s, got %v", DefaultWatchInterval)
	}

	// Verify that zero Interval is accepted and defaults internally.
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately — Watch should still succeed past validation.

	err := Watch(ctx, WatchOptions{
		Dir:      dir,
		Interval: 0, // should default to 2s
		OnChange: func(evt WatchEvent) {},
	})
	if err != context.Canceled {
		t.Errorf("expected context.Canceled with zero Interval, got %v", err)
	}
}

func TestWatch_FormatDrift(t *testing.T) {
	dir := t.TempDir()
	events := make(chan WatchEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = Watch(ctx, WatchOptions{
			Dir:      dir,
			Interval: testPollInterval,
			OnChange: func(evt WatchEvent) { events <- evt },
			Format:   true,
		})
	}()

	time.Sleep(20 * time.Millisecond)

	// Non-canonical field order: kind before api_version, adversary before
	// name in meta. The canonical formatter produces a different byte sequence.
	nonCanonical := `kind: Campaign
api_version: "1.0"
meta:
  adversary: test-adversary
  name: drift-campaign
  severity: high
stages:
  - id: s1
    name: Test Stage
    technique: T1059
    tactic: execution
    execute:
      type: shell
      commands:
        - echo test
`
	writeCampaignFile(t, dir, "drifted", nonCanonical)

	evt, ok := waitForEvent(events, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for format drift event")
	}
	if !evt.FormatDrift {
		t.Error("expected FormatDrift=true for non-canonical YAML")
	}
}

func TestWatch_SkipsNonCampaignFiles(t *testing.T) {
	dir := t.TempDir()
	events := make(chan WatchEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = Watch(ctx, WatchOptions{
			Dir:      dir,
			Interval: testPollInterval,
			OnChange: func(evt WatchEvent) { events <- evt },
		})
	}()

	time.Sleep(20 * time.Millisecond)

	// A regular file in the watched directory (not in a subdir).
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a campaign"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A subdirectory with a non-campaign file.
	sub := filepath.Join(dir, "other-stuff")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "config.yaml"), []byte("key: value"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A subdirectory with a file named differently.
	sub2 := filepath.Join(dir, "almost")
	if err := os.MkdirAll(sub2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub2, "campaign.yml"), []byte("key: val"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Wait several poll cycles — should produce no events.
	time.Sleep(300 * time.Millisecond)

	select {
	case evt := <-events:
		t.Errorf("expected no events for non-campaign files, got: type=%q path=%q", evt.Type, evt.Path)
	default:
		// Correct — no events fired.
	}
}

func TestWatch_MultipleChanges(t *testing.T) {
	dir := t.TempDir()
	events := make(chan WatchEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = Watch(ctx, WatchOptions{
			Dir:      dir,
			Interval: testPollInterval,
			OnChange: func(evt WatchEvent) { events <- evt },
		})
	}()

	time.Sleep(20 * time.Millisecond)

	// Create two campaigns at once.
	writeCampaignFile(t, dir, "campaign-alpha", minimalValidCampaign("campaign-alpha"))
	writeCampaignFile(t, dir, "campaign-beta", minimalValidCampaign("campaign-beta"))

	evts := waitForEvents(events, 2, 2*time.Second)
	if len(evts) < 2 {
		t.Fatalf("expected at least 2 events, got %d", len(evts))
	}

	names := make(map[string]bool)
	for _, e := range evts {
		names[e.Campaign] = true
		if e.Type != "added" {
			t.Errorf("expected type 'added', got %q for campaign %q", e.Type, e.Campaign)
		}
	}
	if !names["campaign-alpha"] {
		t.Error("missing event for campaign-alpha")
	}
	if !names["campaign-beta"] {
		t.Error("missing event for campaign-beta")
	}
}

// ---------------------------------------------------------------------------
// Additional coverage
// ---------------------------------------------------------------------------

func TestWatch_ErrorMissingDir(t *testing.T) {
	err := Watch(context.Background(), WatchOptions{
		OnChange: func(evt WatchEvent) {},
	})
	if err == nil || !strings.Contains(err.Error(), "Dir is required") {
		t.Errorf("expected 'Dir is required' error, got %v", err)
	}
}

func TestWatch_ErrorMissingOnChange(t *testing.T) {
	err := Watch(context.Background(), WatchOptions{
		Dir: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "OnChange") {
		t.Errorf("expected 'OnChange' error, got %v", err)
	}
}

func TestWatch_OnErrorCallback(t *testing.T) {
	// Start watcher on a directory that will be removed to trigger OnError.
	dir := t.TempDir()
	sub := filepath.Join(dir, "inner")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 10)
	events := make(chan WatchEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = Watch(ctx, WatchOptions{
			Dir:      sub,
			Interval: testPollInterval,
			OnChange: func(evt WatchEvent) { events <- evt },
			OnError:  func(err error) { errCh <- err },
		})
	}()

	time.Sleep(20 * time.Millisecond)

	// Remove the watched directory to trigger a poll error.
	if err := os.RemoveAll(sub); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected non-nil error from OnError")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OnError callback")
	}
}
