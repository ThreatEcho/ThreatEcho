// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/ThreatEcho/threatecho/internal/gap"
)

// JSONGapReport is the structured JSON output for gap analysis.
type JSONGapReport struct {
	Version     string             `json:"version"`
	GeneratedAt string             `json:"generated_at"`
	Campaigns   []JSONGapCampaign  `json:"campaigns"`
	Aggregate   JSONGapAggregate   `json:"aggregate"`
	Gaps        []JSONGapEntry     `json:"gaps"`
	RiskSummary JSONGapRiskSummary `json:"risk_summary"`
}

// JSONGapCampaign summarizes one campaign's coverage.
type JSONGapCampaign struct {
	Name          string           `json:"name"`
	Adversary     string           `json:"adversary"`
	Stages        int              `json:"stages"`
	Completed     int              `json:"completed"`
	Skipped       int              `json:"skipped"`
	Techniques    int              `json:"techniques"`
	AttackTactics JSONGapTactics   `json:"attack_tactics"`
	AtlasTactics  JSONGapTactics   `json:"atlas_tactics"`
	Framework     JSONGapFramework `json:"framework"`
}

// JSONGapTactics shows tactic coverage for one framework.
type JSONGapTactics struct {
	Total   int                  `json:"total"`
	Covered int                  `json:"covered"`
	Percent int                  `json:"percent"`
	Details []JSONGapTacticEntry `json:"details"`
	Missing []string             `json:"missing"`
}

// JSONGapTacticEntry is a covered tactic with stage count.
type JSONGapTacticEntry struct {
	Short  string `json:"short"`
	Name   string `json:"name"`
	Stages int    `json:"stages"`
}

// JSONGapFramework shows which frameworks campaign stages use.
type JSONGapFramework struct {
	ATTACKStages int `json:"attack_stages"`
	ATLASStages  int `json:"atlas_stages"`
	OWASPStages  int `json:"owasp_stages"`
}

// JSONGapAggregate is the merged coverage across all campaigns.
type JSONGapAggregate struct {
	TotalCampaigns   int              `json:"total_campaigns"`
	TotalStages      int              `json:"total_stages"`
	TotalCompleted   int              `json:"total_completed"`
	TotalSkipped     int              `json:"total_skipped"`
	UniqueTechniques int              `json:"unique_techniques"`
	UniqueDetections int              `json:"unique_detections"`
	UniqueTelemetry  int              `json:"unique_telemetry"`
	AttackTactics    JSONGapTactics   `json:"attack_tactics"`
	AtlasTactics     JSONGapTactics   `json:"atlas_tactics"`
	Framework        JSONGapFramework `json:"framework"`
}

// JSONGapEntry is a single detection gap finding.
type JSONGapEntry struct {
	Campaign      string `json:"campaign"`
	StageID       string `json:"stage_id"`
	StageName     string `json:"stage_name"`
	Technique     string `json:"technique"`
	TechniqueName string `json:"technique_name"`
	Tactic        string `json:"tactic"`
	Type          string `json:"type"`
	Risk          string `json:"risk"`
	Description   string `json:"description"`
}

// JSONGapRiskSummary is the aggregate risk assessment.
type JSONGapRiskSummary struct {
	Critical int     `json:"critical"`
	High     int     `json:"high"`
	Medium   int     `json:"medium"`
	Low      int     `json:"low"`
	Total    int     `json:"total"`
	Score    float64 `json:"score"`
}

// GapJSONReport writes a JSON gap analysis report to w.
func GapJSONReport(w io.Writer, r *gap.GapReport) error {
	out := JSONGapReport{
		Version:     "1.0",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Campaigns.
	for _, c := range r.Campaigns {
		jc := JSONGapCampaign{
			Name:          c.Name,
			Adversary:     c.Adversary,
			Stages:        c.Stages,
			Completed:     c.Completed,
			Skipped:       c.Skipped,
			Techniques:    c.TechniquesUsed,
			AttackTactics: convertTactics(c.AttackTactics),
			AtlasTactics:  convertTactics(c.AtlasTactics),
			Framework: JSONGapFramework{
				ATTACKStages: c.Framework.ATTACKStages,
				ATLASStages:  c.Framework.ATLASStages,
				OWASPStages:  c.Framework.OWASPStages,
			},
		}
		out.Campaigns = append(out.Campaigns, jc)
	}

	// Aggregate.
	a := r.Aggregate
	out.Aggregate = JSONGapAggregate{
		TotalCampaigns:   a.TotalCampaigns,
		TotalStages:      a.TotalStages,
		TotalCompleted:   a.TotalCompleted,
		TotalSkipped:     a.TotalSkipped,
		UniqueTechniques: a.UniqueTechniques,
		UniqueDetections: a.UniqueDetections,
		UniqueTelemetry:  a.UniqueTelemetry,
		AttackTactics:    convertTactics(a.AttackTactics),
		AtlasTactics:     convertTactics(a.AtlasTactics),
		Framework: JSONGapFramework{
			ATTACKStages: a.Framework.ATTACKStages,
			ATLASStages:  a.Framework.ATLASStages,
			OWASPStages:  a.Framework.OWASPStages,
		},
	}

	// Gaps.
	for _, g := range r.Gaps {
		out.Gaps = append(out.Gaps, JSONGapEntry{
			Campaign:      g.CampaignName,
			StageID:       g.StageID,
			StageName:     g.StageName,
			Technique:     g.Technique,
			TechniqueName: g.TechniqueName,
			Tactic:        g.Tactic,
			Type:          string(g.Type),
			Risk:          g.Risk,
			Description:   g.Description,
		})
	}

	// Risk summary.
	out.RiskSummary = JSONGapRiskSummary{
		Critical: r.RiskSummary.Critical,
		High:     r.RiskSummary.High,
		Medium:   r.RiskSummary.Medium,
		Low:      r.RiskSummary.Low,
		Total:    r.RiskSummary.Total,
		Score:    r.RiskSummary.Score,
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

func convertTactics(tb gap.TacticBreakdown) JSONGapTactics {
	pct := 0
	if tb.Total > 0 {
		pct = tb.Covered * 100 / tb.Total
	}
	jt := JSONGapTactics{
		Total:   tb.Total,
		Covered: tb.Covered,
		Percent: pct,
		Missing: tb.Missing,
	}
	for _, d := range tb.Details {
		jt.Details = append(jt.Details, JSONGapTacticEntry{
			Short:  d.Short,
			Name:   d.Name,
			Stages: d.Stages,
		})
	}
	return jt
}
