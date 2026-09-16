// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package orchestrator

import (
	"fmt"
	"strings"
	"time"
)

// DeployReport aggregates results from a multi-target deployment.
type DeployReport struct {
	Campaign   string         `json:"campaign"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Duration   string         `json:"duration"`
	Targets    []TargetResult `json:"targets"`
	Summary    DeploySummary  `json:"summary"`
}

// DeploySummary provides aggregate counts across all targets.
type DeploySummary struct {
	TotalTargets int `json:"total_targets"`
	Succeeded    int `json:"succeeded"`
	Failed       int `json:"failed"`
	TotalStages  int `json:"total_stages"`
	Passed       int `json:"passed"`
	StageFailed  int `json:"stage_failed"`
	Skipped      int `json:"skipped"`
	PrecondFail  int `json:"precondition_failed"`
}

// BuildDeployReport creates an aggregate report from target results.
func BuildDeployReport(campaignName string, started time.Time, results []TargetResult) *DeployReport {
	r := &DeployReport{
		Campaign:   campaignName,
		StartedAt:  started,
		FinishedAt: time.Now(),
		Targets:    results,
	}
	r.Duration = r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond).String()

	r.Summary.TotalTargets = len(results)
	for _, tr := range results {
		if tr.Error != "" {
			r.Summary.Failed++
			continue
		}
		r.Summary.Succeeded++
		if tr.Report != nil {
			r.Summary.TotalStages += tr.Report.TotalStages
			r.Summary.Passed += tr.Report.Passed
			r.Summary.StageFailed += tr.Report.Failed
			r.Summary.Skipped += tr.Report.Skipped
			r.Summary.PrecondFail += tr.Report.PrecondFail
		}
	}
	return r
}

// FormatDeployReport renders a human-readable deployment summary.
func FormatDeployReport(r *DeployReport) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Campaign: %s\n", r.Campaign))
	b.WriteString(fmt.Sprintf("Duration: %s\n", r.Duration))
	b.WriteString(fmt.Sprintf("Targets:  %d (%d succeeded, %d failed)\n\n",
		r.Summary.TotalTargets, r.Summary.Succeeded, r.Summary.Failed))

	for _, tr := range r.Targets {
		if tr.Error != "" {
			b.WriteString(fmt.Sprintf("  ✗ %s (%s@%s) — %s\n", tr.Target.Name, tr.Target.User, tr.Target.Host, tr.Error))
			continue
		}
		if tr.Report == nil {
			b.WriteString(fmt.Sprintf("  ? %s (%s@%s) — no report\n", tr.Target.Name, tr.Target.User, tr.Target.Host))
			continue
		}
		b.WriteString(fmt.Sprintf("  ✓ %s (%s@%s) — %d passed, %d failed, %d skipped, %d precond_failed (%s)\n",
			tr.Target.Name, tr.Target.User, tr.Target.Host,
			tr.Report.Passed, tr.Report.Failed, tr.Report.Skipped, tr.Report.PrecondFail,
			tr.Report.Duration))
	}

	if r.Summary.TotalStages > 0 {
		b.WriteString(fmt.Sprintf("\nStages: %d total, %d passed, %d failed, %d skipped, %d precond_failed\n",
			r.Summary.TotalStages, r.Summary.Passed, r.Summary.StageFailed, r.Summary.Skipped, r.Summary.PrecondFail))
	}

	return b.String()
}
