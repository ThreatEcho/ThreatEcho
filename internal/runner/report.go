// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package runner

import (
	"time"
)

// StageReport captures the full outcome of executing one stage.
type StageReport struct {
	StageID       string        `json:"stage_id"`
	Name          string        `json:"name"`
	Technique     string        `json:"technique"`
	Tactic        string        `json:"tactic"`
	Status        string        `json:"status"` // passed, failed, skipped, precondition_failed
	Elevated      bool          `json:"elevated"`
	Preconditions []CheckResult `json:"preconditions,omitempty"`
	Output        string        `json:"output,omitempty"`
	Error         string        `json:"error,omitempty"`
	Duration      time.Duration `json:"duration_ns"`
	DurationHuman string        `json:"duration"`
	Commands      int           `json:"commands"`
	CleanupError  string        `json:"cleanup_error,omitempty"`
}

// RunReport captures the full outcome of an agent campaign run.
type RunReport struct {
	Campaign    string        `json:"campaign"`
	Hostname    string        `json:"hostname"`
	OS          string        `json:"os"`
	Arch        string        `json:"arch"`
	User        string        `json:"user"`
	Elevated    bool          `json:"elevated"`
	StartedAt   time.Time     `json:"started_at"`
	FinishedAt  time.Time     `json:"finished_at"`
	Duration    string        `json:"duration"`
	Error       string        `json:"error,omitempty"`
	Stages      []StageReport `json:"stages"`
	TotalStages int           `json:"total_stages"`
	Passed      int           `json:"passed"`
	Failed      int           `json:"failed"`
	Skipped     int           `json:"skipped"`
	PrecondFail int           `json:"precondition_failed"`
}
