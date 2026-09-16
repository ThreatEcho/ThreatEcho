// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"encoding/json"
	"io"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

// policyJSON is the JSON-serializable form of a policy evaluation result.
type policyJSON struct {
	Policy      string          `json:"policy"`
	Campaign    string          `json:"campaign"`
	TotalStages int             `json:"total_stages"`
	Allowed     int             `json:"allowed"`
	Denied      int             `json:"denied"`
	Alerted     int             `json:"alerted"`
	Verdict     string          `json:"verdict"` // "pass", "warn", "fail"
	Violations  []violationJSON `json:"violations,omitempty"`
}

type violationJSON struct {
	RuleID    string `json:"rule_id"`
	RuleDesc  string `json:"rule_description"`
	Effect    string `json:"effect"`
	StageID   string `json:"stage_id"`
	StageName string `json:"stage_name"`
	Technique string `json:"technique,omitempty"`
	Tactic    string `json:"tactic,omitempty"`
	Tool      string `json:"tool,omitempty"`
	Reason    string `json:"reason"`
}

// PolicyJSONReport writes a JSON policy evaluation report.
func PolicyJSONReport(w io.Writer, r *policy.EvalResult) error {
	verdict := "pass"
	if r.Denied > 0 {
		verdict = "fail"
	} else if r.Alerted > 0 {
		verdict = "warn"
	}

	out := policyJSON{
		Policy:      r.Policy,
		Campaign:    r.Campaign,
		TotalStages: r.TotalStages,
		Allowed:     r.Allowed,
		Denied:      r.Denied,
		Alerted:     r.Alerted,
		Verdict:     verdict,
	}

	for _, v := range r.Violations {
		out.Violations = append(out.Violations, violationJSON{
			RuleID:    v.RuleID,
			RuleDesc:  v.RuleDesc,
			Effect:    v.Effect,
			StageID:   v.StageID,
			StageName: v.StageName,
			Technique: v.Technique,
			Tactic:    v.Tactic,
			Tool:      v.Tool,
			Reason:    v.Reason,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
