// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/policy"
)

func makePolicyResult(denied, alerted, allowed int) *policy.EvalResult {
	r := &policy.EvalResult{
		Policy:      "test-policy",
		Campaign:    "test-campaign",
		Denied:      denied,
		Alerted:     alerted,
		Allowed:     allowed,
		TotalStages: denied + alerted + allowed,
	}
	if denied > 0 {
		r.Violations = append(r.Violations, policy.Violation{
			RuleID:    "R-001",
			RuleDesc:  "Block shell execution",
			Effect:    "deny",
			StageID:   "s1",
			StageName: "Stage 1",
			Technique: "T1059.001",
			Tactic:    "execution",
			Tool:      "shell_exec",
			Reason:    "denied by rule \"R-001\": Block shell execution",
		})
	}
	if alerted > 0 {
		r.Violations = append(r.Violations, policy.Violation{
			RuleID:    "R-002",
			RuleDesc:  "Alert on exfiltration",
			Effect:    "alert",
			StageID:   "s2",
			StageName: "Stage 2",
			Technique: "T1041",
			Tactic:    "exfiltration",
			Tool:      "http_request",
			Reason:    "alert from rule \"R-002\": Alert on exfiltration",
		})
	}
	return r
}

func TestPolicyTextReport_Pass(t *testing.T) {
	r := makePolicyResult(0, 0, 5)
	var buf bytes.Buffer
	PolicyTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "PASS") {
		t.Error("expected PASS verdict")
	}
	if !strings.Contains(out, "test-policy") {
		t.Error("missing policy name")
	}
}

func TestPolicyTextReport_Fail(t *testing.T) {
	r := makePolicyResult(2, 0, 3)
	var buf bytes.Buffer
	PolicyTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "FAIL") {
		t.Error("expected FAIL verdict")
	}
	if !strings.Contains(out, "denied") {
		t.Error("missing denied count")
	}
}

func TestPolicyTextReport_Warn(t *testing.T) {
	r := makePolicyResult(0, 1, 4)
	var buf bytes.Buffer
	PolicyTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "WARN") {
		t.Error("expected WARN verdict")
	}
}

func TestPolicyTextReport_ShowsViolations(t *testing.T) {
	r := makePolicyResult(1, 1, 3)
	var buf bytes.Buffer
	PolicyTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "Violations") {
		t.Error("missing violations section")
	}
	if !strings.Contains(out, "R-001") {
		t.Error("missing deny rule ID")
	}
	if !strings.Contains(out, "R-002") {
		t.Error("missing alert rule ID")
	}
	if !strings.Contains(out, "shell_exec") {
		t.Error("missing tool name")
	}
}

func TestPolicyTextReport_ShowsTechnique(t *testing.T) {
	r := makePolicyResult(1, 0, 4)
	var buf bytes.Buffer
	PolicyTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "T1059.001") {
		t.Error("missing technique in violation")
	}
	if !strings.Contains(out, "execution") {
		t.Error("missing tactic in violation")
	}
}

func TestPolicyTextReport_NoViolationsSection(t *testing.T) {
	r := makePolicyResult(0, 0, 5)
	var buf bytes.Buffer
	PolicyTextReport(&buf, r)
	out := buf.String()
	if strings.Contains(out, "Violations") {
		t.Error("should not show violations section when none exist")
	}
}

func TestPolicyTextReport_Header(t *testing.T) {
	r := makePolicyResult(0, 0, 5)
	var buf bytes.Buffer
	PolicyTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "Policy Evaluation") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "test-campaign") {
		t.Error("missing campaign name")
	}
}
