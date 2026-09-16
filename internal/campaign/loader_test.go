// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidFile(t *testing.T) {
	c, err := Load("testdata/valid-campaign/campaign.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Meta.Name != "test-campaign" {
		t.Errorf("meta.name = %q, want %q", c.Meta.Name, "test-campaign")
	}
	if c.APIVersion != "v1" {
		t.Errorf("api_version = %q, want %q", c.APIVersion, "v1")
	}
	if len(c.Stages) != 2 {
		t.Errorf("got %d stages, want 2", len(c.Stages))
	}
}

func TestLoad_Directory(t *testing.T) {
	c, err := Load("testdata/valid-campaign")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Meta.Name != "test-campaign" {
		t.Errorf("meta.name = %q, want %q", c.Meta.Name, "test-campaign")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("testdata/nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoad_VariableExpansion(t *testing.T) {
	c, err := Load("testdata/valid-campaign/campaign.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Network Scan of 10.0.0.1"
	if c.Stages[0].Name != want {
		t.Errorf("stage name after expansion = %q, want %q", c.Stages[0].Name, want)
	}
	wantCmd := `echo "scanning 10.0.0.1"`
	if c.Stages[0].Execute.Commands[0] != wantCmd {
		t.Errorf("command after expansion = %q, want %q", c.Stages[0].Execute.Commands[0], wantCmd)
	}
}

func TestLoadDir(t *testing.T) {
	summaries, err := LoadDir("testdata")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summaries) == 0 {
		t.Fatal("expected at least one campaign summary, got 0")
	}
	found := false
	for _, s := range summaries {
		if s.Name == "test-campaign" {
			found = true
			if s.Stages != 2 {
				t.Errorf("stages = %d, want 2", s.Stages)
			}
			if s.Adversary != "TestActor" {
				t.Errorf("adversary = %q, want %q", s.Adversary, "TestActor")
			}
		}
	}
	if !found {
		t.Error("test-campaign not found in LoadDir results")
	}
}

func TestLoadDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	summaries, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries for empty dir, got %d", len(summaries))
	}
}

func TestLoadDir_NoSuchDir(t *testing.T) {
	_, err := LoadDir(filepath.Join(os.TempDir(), "nonexistent-campaign-dir"))
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}
