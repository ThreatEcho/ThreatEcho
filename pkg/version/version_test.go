// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package version

import (
	"strings"
	"testing"
)

func TestString_DefaultValues(t *testing.T) {
	s := String()
	if !strings.HasPrefix(s, "threatecho ") {
		t.Errorf("String() = %q, should start with %q", s, "threatecho ")
	}
	if !strings.Contains(s, "dev") {
		t.Errorf("String() = %q, should contain default version %q", s, "dev")
	}
	if !strings.Contains(s, "commit:") {
		t.Errorf("String() = %q, should contain %q", s, "commit:")
	}
	if !strings.Contains(s, "built:") {
		t.Errorf("String() = %q, should contain %q", s, "built:")
	}
}

func TestString_CustomValues(t *testing.T) {
	// Save and restore originals.
	origVersion, origCommit, origBuild := Version, Commit, BuildTime
	defer func() {
		Version, Commit, BuildTime = origVersion, origCommit, origBuild
	}()

	Version = "1.2.3"
	Commit = "abc1234"
	BuildTime = "2026-01-01T00:00:00Z"

	s := String()
	if !strings.Contains(s, "1.2.3") {
		t.Errorf("String() = %q, should contain version %q", s, "1.2.3")
	}
	if !strings.Contains(s, "abc1234") {
		t.Errorf("String() = %q, should contain commit %q", s, "abc1234")
	}
	if !strings.Contains(s, "2026-01-01T00:00:00Z") {
		t.Errorf("String() = %q, should contain build time %q", s, "2026-01-01T00:00:00Z")
	}
}
