// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package main

import "testing"

func TestSplitHostPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		target   string
		flagPort int
		wantHost string
		wantPort int
	}{
		{"10.0.0.1", 0, "10.0.0.1", 0},
		{"10.0.0.1:5985", 0, "10.0.0.1", 5985},
		{"10.0.0.1:5985", 9022, "10.0.0.1", 9022},
		{"myhost", 22, "myhost", 22},
		{"myhost:8080", 0, "myhost", 8080},
		{"10.0.0.1:0", 0, "10.0.0.1:0", 0},
		{"10.0.0.1:abc", 0, "10.0.0.1:abc", 0},
		{"10.0.0.1:99999", 0, "10.0.0.1:99999", 0},
	}
	for _, tt := range tests {
		h, p := splitHostPort(tt.target, tt.flagPort)
		if h != tt.wantHost || p != tt.wantPort {
			t.Errorf("splitHostPort(%q, %d) = (%q, %d), want (%q, %d)",
				tt.target, tt.flagPort, h, p, tt.wantHost, tt.wantPort)
		}
	}
}
