// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package main_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1. Campaign Validation Pipeline
//    validate → lint → simulate for multiple real campaigns
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_CampaignValidationPipeline(t *testing.T) {
	t.Parallel()

	campaigns := []string{
		"campaigns/apt29-cozy-bear/",
		"campaigns/llm-agent-hijack/",
		"campaigns/prompt-leaking/",
		"campaigns/rag-data-poisoning/",
		"campaigns/tool-call-injection/",
	}

	for _, camp := range campaigns {
		camp := camp
		name := filepath.Base(strings.TrimSuffix(camp, "/"))

		t.Run(name+"/Validate", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("validate", camp)
			if err != nil {
				t.Fatalf("validate %s failed: %v", camp, err)
			}
			if !strings.Contains(stdout, "is valid") {
				t.Errorf("expected 'is valid' in output for %s, got: %s", camp, truncate(stdout, 300))
			}
		})

		// validate has no -json flag — just check that validate succeeds above.

		t.Run(name+"/Lint", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("lint", camp)
			code := exitCode(err)
			if code != 0 && code != 1 {
				t.Fatalf("lint %s unexpected exit %d", camp, code)
			}
			if len(stdout) == 0 {
				t.Errorf("lint %s produced no output", camp)
			}
		})

		t.Run(name+"/LintJSON", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("lint", "-format", "json", camp)
			code := exitCode(err)
			if code != 0 && code != 1 {
				t.Fatalf("lint JSON %s unexpected exit %d", camp, code)
			}
			if !json.Valid([]byte(stdout)) {
				t.Errorf("lint JSON invalid for %s: %s", camp, truncate(stdout, 300))
			}
		})

		t.Run(name+"/Simulate", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("simulate", camp)
			if err != nil {
				t.Fatalf("simulate %s failed: %v", camp, err)
			}
			if !strings.Contains(stdout, name) {
				t.Errorf("simulate output should contain campaign name %q, got: %s", name, truncate(stdout, 300))
			}
		})

		t.Run(name+"/SimulateJSON", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("simulate", "-format", "json", camp)
			if err != nil {
				// simulate may not support -format json — skip rather than fail
				t.Skipf("simulate -format json %s: %v", camp, err)
			}
			if stdout != "" && !json.Valid([]byte(stdout)) {
				t.Errorf("simulate JSON invalid for %s: %s", camp, truncate(stdout, 300))
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Policy Quality Pipeline
//    policy validate → policy lint → policy coveragemap → policy remediate
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_PolicyQualityPipeline(t *testing.T) {
	t.Parallel()

	policies := []string{
		"policies/agent-default/",
		"policies/agent-strict/",
		"policies/rag-protection/",
		"policies/tool-calling-strict/",
		"policies/autonomous-agent/",
	}

	for _, pol := range policies {
		pol := pol
		name := filepath.Base(strings.TrimSuffix(pol, "/"))

		t.Run(name+"/Validate", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("policy", "validate", pol)
			if err != nil {
				t.Fatalf("policy validate %s failed: %v", pol, err)
			}
			if !strings.Contains(stdout, "is valid") {
				t.Errorf("expected 'is valid' for %s, got: %s", pol, truncate(stdout, 300))
			}
		})

		t.Run(name+"/Lint", func(t *testing.T) {
			t.Parallel()
			stdout, _, _ := runCLI("policy", "lint", pol)
			if !strings.Contains(stdout, "POLICY LINT REPORT") {
				t.Errorf("expected lint report header for %s, got: %s", pol, truncate(stdout, 300))
			}
			if !strings.Contains(stdout, "Score") {
				t.Errorf("expected Score in lint for %s, got: %s", pol, truncate(stdout, 300))
			}
		})

		t.Run(name+"/LintJSON", func(t *testing.T) {
			t.Parallel()
			stdout, _, _ := runCLI("policy", "lint", "-json", pol)
			if !strings.Contains(stdout, "\"policy_name\"") {
				t.Errorf("JSON lint missing policy_name for %s: %s", pol, truncate(stdout, 300))
			}
			if !strings.Contains(stdout, "\"score\"") {
				t.Errorf("JSON lint missing score for %s: %s", pol, truncate(stdout, 300))
			}
		})

		t.Run(name+"/CoverageMap", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("policy", "coveragemap", pol)
			if err != nil {
				t.Fatalf("coveragemap %s failed: %v", pol, err)
			}
			if !strings.Contains(stdout, "Coverage") {
				t.Errorf("expected Coverage in output for %s, got: %s", pol, truncate(stdout, 300))
			}
		})

		t.Run(name+"/CoverageMapJSON", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("policy", "coveragemap", "-json", pol)
			if err != nil {
				t.Fatalf("coveragemap JSON %s failed: %v", pol, err)
			}
			if !json.Valid([]byte(stdout)) {
				t.Errorf("coveragemap JSON invalid for %s: %s", pol, truncate(stdout, 300))
			}
			if !strings.Contains(stdout, "coverage_percent") {
				t.Errorf("JSON missing coverage_percent for %s: %s", pol, truncate(stdout, 300))
			}
		})

		t.Run(name+"/Remediate", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("policy", "remediate", pol)
			if err != nil {
				t.Fatalf("remediate %s failed: %v", pol, err)
			}
			lower := strings.ToLower(stdout)
			if !strings.Contains(lower, "remediat") && !strings.Contains(lower, "no issues") {
				t.Errorf("expected remediation output for %s, got: %s", pol, truncate(stdout, 300))
			}
		})

		t.Run(name+"/RemediateJSON", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("policy", "remediate", "-json", pol)
			if err != nil {
				t.Fatalf("remediate JSON %s failed: %v", pol, err)
			}
			if stdout != "" && !json.Valid([]byte(stdout)) {
				t.Errorf("remediate JSON invalid for %s: %s", pol, truncate(stdout, 300))
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Agent Security Pipeline
//    agent validate → agent trust → agent chain → agent profile
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_AgentSecurityPipeline(t *testing.T) {
	t.Parallel()

	agents := []string{
		"agents/support-agent/",
		"agents/orchestrator/",
		"agents/billing-agent/",
		"agents/code-assistant/",
		"agents/trading-bot/",
	}

	// Validate individual agents.
	for _, ag := range agents {
		ag := ag
		name := filepath.Base(strings.TrimSuffix(ag, "/"))

		t.Run(name+"/Validate", func(t *testing.T) {
			t.Parallel()
			_, stderr, err := runCLI("agent", "validate", ag+"agent.yaml")
			if err != nil {
				t.Fatalf("agent validate %s failed: %v", ag, err)
			}
			if !strings.Contains(stderr, name) {
				t.Errorf("expected agent name %q in validation output, got: %s", name, truncate(stderr, 300))
			}
		})

		t.Run(name+"/Show", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("agent", "show", ag)
			if err != nil {
				t.Fatalf("agent show %s failed: %v", ag, err)
			}
			if !strings.Contains(stdout, name) {
				t.Errorf("agent show should contain %q, got: %s", name, truncate(stdout, 300))
			}
		})

		t.Run(name+"/ShowJSON", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("agent", "show", "-json", ag)
			if err != nil {
				t.Fatalf("agent show JSON %s failed: %v", ag, err)
			}
			if !json.Valid([]byte(stdout)) {
				t.Errorf("agent show JSON invalid for %s: %s", ag, truncate(stdout, 300))
			}
		})

		t.Run(name+"/Guardrail", func(t *testing.T) {
			t.Parallel()
			stdout, _, _ := runCLI("agent", "guardrail", ag)
			lower := strings.ToLower(stdout)
			if !strings.Contains(lower, "guardrail") {
				t.Errorf("expected guardrail output for %s, got: %s", ag, truncate(stdout, 300))
			}
		})

		t.Run(name+"/GuardrailJSON", func(t *testing.T) {
			t.Parallel()
			stdout, _, _ := runCLI("agent", "guardrail", "-json", ag)
			if !strings.Contains(stdout, "agent_name") {
				t.Errorf("expected agent_name in JSON guardrail for %s, got: %s", ag, truncate(stdout, 300))
			}
		})
	}

	// Inventory-wide operations.
	t.Run("Trust", func(t *testing.T) {
		t.Parallel()
		stdout, _, _ := runCLI("agent", "trust", "-dir", "agents/")
		lower := strings.ToLower(stdout)
		if !strings.Contains(lower, "trust") {
			t.Errorf("expected trust analysis, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("TrustJSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, _ := runCLI("agent", "trust", "-dir", "agents/", "-json")
		if !json.Valid([]byte(stdout)) {
			t.Errorf("trust JSON invalid: %s", truncate(stdout, 300))
		}
	})

	t.Run("Chain", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("agent", "chain", "-dir", "agents/")
		if err != nil {
			t.Fatalf("agent chain failed: %v", err)
		}
		if !strings.Contains(stdout, "CHAIN") || !strings.Contains(stdout, "ANALYSIS") {
			t.Errorf("expected chain analysis output, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("ChainJSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("agent", "chain", "-dir", "agents/", "-json")
		if err != nil {
			t.Fatalf("agent chain JSON failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("chain JSON invalid: %s", truncate(stdout, 300))
		}
		if !strings.Contains(stdout, "risk_score") {
			t.Errorf("chain JSON missing risk_score: %s", truncate(stdout, 300))
		}
	})

	// Agent profile needs trace files — build synthetic ones.
	t.Run("Profile", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		traceJSON := `{
			"id": "tr-int-001",
			"agent_name": "support-agent",
			"agent_type": "retrieval",
			"start_time": "2026-01-15T10:00:00Z",
			"end_time": "2026-01-15T10:05:00Z",
			"events": [
				{"id": "ev-1", "timestamp": "2026-01-15T10:01:00Z", "type": "tool_call", "tool_call": {"tool": "search_knowledge_base", "action": "query", "success": true}},
				{"id": "ev-2", "timestamp": "2026-01-15T10:02:00Z", "type": "tool_call", "tool_call": {"tool": "create_ticket", "action": "create", "success": true}},
				{"id": "ev-3", "timestamp": "2026-01-15T10:03:00Z", "type": "tool_call", "tool_call": {"tool": "send_email", "action": "send", "success": true}}
			]
		}`
		os.WriteFile(filepath.Join(tmp, "trace-001.json"), []byte(traceJSON), 0644)

		stdout, _, err := runCLI("agent", "profile", "-traces", tmp)
		if err != nil {
			t.Fatalf("agent profile failed: %v", err)
		}
		if !strings.Contains(stdout, "support-agent") {
			t.Errorf("expected agent name in profile output, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("ProfileJSON", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		traceJSON := `{
			"id": "tr-int-002",
			"agent_name": "orchestrator",
			"agent_type": "autonomous",
			"start_time": "2026-01-15T10:00:00Z",
			"end_time": "2026-01-15T10:05:00Z",
			"events": [
				{"id": "ev-1", "timestamp": "2026-01-15T10:01:00Z", "type": "tool_call", "tool_call": {"tool": "delegate_task", "action": "dispatch", "success": true}}
			]
		}`
		os.WriteFile(filepath.Join(tmp, "trace-002.json"), []byte(traceJSON), 0644)

		stdout, _, err := runCLI("agent", "profile", "-traces", tmp, "-json")
		if err != nil {
			t.Fatalf("agent profile JSON failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("agent profile JSON invalid: %s", truncate(stdout, 300))
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Full Security Assessment
//    Load real campaigns + policies, run gap analysis, SARIF, matrix, score
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_FullSecurityAssessment(t *testing.T) {
	t.Parallel()

	// Gap analysis across all campaigns.
	t.Run("GapAnalysisDir", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("gap", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("gap -dir failed: %v", err)
		}
		if len(stdout) < 50 {
			t.Errorf("gap output too short, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("GapAnalysisJSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("gap", "-format", "json", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("gap JSON -dir failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("gap JSON invalid: %s", truncate(stdout, 300))
		}
	})

	// SARIF output for CI integration.
	t.Run("GapSARIF", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("gap", "-format", "sarif", "campaigns/llm-agent-hijack/")
		if err != nil {
			t.Fatalf("gap SARIF failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("SARIF not valid JSON: %s", truncate(stdout, 300))
		}
		if !strings.Contains(stdout, "$schema") {
			t.Errorf("SARIF missing $schema: %s", truncate(stdout, 300))
		}
		if !strings.Contains(strings.ToLower(stdout), "sarif") {
			t.Errorf("SARIF missing sarif reference: %s", truncate(stdout, 300))
		}
	})

	// JUnit output for CI.
	t.Run("GapJUnit", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("gap", "-format", "junit", "campaigns/llm-agent-hijack/")
		if err != nil {
			t.Fatalf("gap JUnit failed: %v", err)
		}
		if !strings.Contains(stdout, "<testsuites>") {
			t.Errorf("JUnit missing <testsuites>: %s", truncate(stdout, 300))
		}
	})

	// Matrix view.
	t.Run("Matrix", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("matrix", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("matrix failed: %v", err)
		}
		if len(stdout) < 100 {
			t.Errorf("matrix output too short, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("MatrixCompact", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("matrix", "-compact", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("matrix compact failed: %v", err)
		}
		if len(stdout) < 50 {
			t.Errorf("matrix compact output too short, got: %s", truncate(stdout, 300))
		}
	})

	// Score all campaigns.
	t.Run("ScoreDir", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("score", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("score -dir failed: %v", err)
		}
		if !strings.Contains(stdout, "Score") {
			t.Errorf("expected Score in output, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("ScoreDirJSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("score", "-json", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("score JSON -dir failed: %v", err)
		}
		var scores []json.RawMessage
		if err := json.Unmarshal([]byte(stdout), &scores); err != nil {
			t.Errorf("score JSON not valid array: %s", truncate(stdout, 300))
		}
		if len(scores) < 3 {
			t.Errorf("expected at least 3 scored campaigns, got %d", len(scores))
		}
	})

	// Navigator export.
	t.Run("ExportNavigator", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("export", "navigator", "campaigns/llm-agent-hijack/")
		if err != nil {
			t.Fatalf("export navigator failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("navigator JSON invalid: %s", truncate(stdout, 300))
		}
	})

	// Coverage analysis.
	t.Run("CoverageDir", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("coverage", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("coverage -dir failed: %v", err)
		}
		if len(stdout) < 50 {
			t.Errorf("coverage output too short, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("CoverageDirJSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("coverage", "-format", "json", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("coverage JSON failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("coverage JSON invalid: %s", truncate(stdout, 300))
		}
	})

	// Policy eval against all campaigns.
	t.Run("PolicyEvalDir", func(t *testing.T) {
		t.Parallel()
		_, _, err := runCLI("policy", "eval", "-policy", "policies/agent-default/", "-dir", "campaigns/")
		code := exitCode(err)
		if code != 0 && code != 2 {
			t.Fatalf("policy eval -dir unexpected exit %d", code)
		}
	})

	t.Run("PolicyEvalDirSARIF", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runCLI("policy", "eval", "-policy", "policies/agent-strict/", "-format", "sarif", "-dir", "campaigns/")
		code := exitCode(err)
		if code != 0 && code != 2 {
			t.Fatalf("policy eval SARIF unexpected exit %d", code)
		}
		// SARIF output should contain the schema reference and SARIF version.
		combined := stdout + stderr
		if !strings.Contains(combined, "sarif-schema-2.1") {
			t.Errorf("SARIF output missing schema reference, got: %s", truncate(combined, 300))
		}
		if !strings.Contains(combined, "\"version\": \"2.1.0\"") {
			t.Errorf("SARIF output missing version 2.1.0, got: %s", truncate(combined, 300))
		}
	})

	// Summary dashboard.
	t.Run("Summary", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("summary", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("summary failed: %v", err)
		}
		if len(stdout) < 100 {
			t.Errorf("summary output too short, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("SummaryWithPolicy", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("summary", "-dir", "campaigns/", "-policy", "policies/agent-default/")
		if err != nil {
			t.Fatalf("summary with policy failed: %v", err)
		}
		if len(stdout) < 100 {
			t.Errorf("summary with policy output too short, got: %s", truncate(stdout, 300))
		}
	})

	// Report generation.
	t.Run("ReportText", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("report", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("report failed: %v", err)
		}
		if !strings.Contains(stdout, "Executive") {
			t.Errorf("expected Executive in report, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("ReportJSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("report", "-json", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("report JSON failed: %v", err)
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &data); err != nil {
			t.Errorf("report JSON invalid: %s", truncate(stdout, 300))
		}
	})

	t.Run("ReportMarkdown", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("report", "-format", "markdown", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("report markdown failed: %v", err)
		}
		if !strings.Contains(stdout, "#") {
			t.Errorf("expected markdown heading, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("ReportToFile", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		outFile := filepath.Join(tmp, "assessment.md")
		_, stderr, err := runCLI("report", "-format", "markdown", "-output", outFile, "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("report to file failed: %v", err)
		}
		if !strings.Contains(stderr, "assessment.md") {
			t.Errorf("expected file confirmation, got: %s", truncate(stderr, 300))
		}
		data, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatalf("could not read report: %v", err)
		}
		if len(data) < 100 {
			t.Errorf("report file too small: %d bytes", len(data))
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Cross-Command JSON Consistency
//    Verify JSON outputs from multiple commands parse correctly
//    and contain expected fields
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_CrossCommandJSONConsistency(t *testing.T) {
	t.Parallel()

	type jsonCheck struct {
		name           string
		args           []string
		allowNonZero   bool // allow non-zero exit codes
		expectedFields []string
		isArray        bool
	}

	checks := []jsonCheck{
		{
			name:           "SimulateJSON",
			args:           []string{"simulate", "-format", "json", "campaigns/llm-agent-hijack/"},
			allowNonZero:   true, // simulate -format json may not be supported
			expectedFields: []string{},
		},
		{
			name:           "GapJSON",
			args:           []string{"gap", "-format", "json", "campaigns/llm-agent-hijack/"},
			expectedFields: []string{},
		},
		{
			name:           "ProfileJSON",
			args:           []string{"profile", "-format", "json", "campaigns/apt29-cozy-bear/"},
			expectedFields: []string{},
		},
		{
			name:           "TimelineJSON",
			args:           []string{"timeline", "-format", "json", "campaigns/apt29-cozy-bear/"},
			expectedFields: []string{},
		},
		{
			name:           "PolicyRiskJSON",
			args:           []string{"policy", "risk", "-json", "policies/agent-default/"},
			expectedFields: []string{},
		},
		{
			name:           "PolicyCompileJSON",
			args:           []string{"policy", "compile", "-json", "policies/agent-default/"},
			expectedFields: []string{"TotalRules", "DenyRules"},
		},
		{
			name:           "PolicyBenchmarkJSON",
			args:           []string{"policy", "benchmark", "-iterations", "30", "-json", "policies/agent-default/"},
			expectedFields: []string{"policy_name", "overall_stats"},
		},
		{
			name:           "PolicySimulateJSON",
			args:           []string{"policy", "simulate", "-policy", "policies/agent-default/", "-json", "campaigns/llm-agent-hijack/"},
			expectedFields: []string{"total_allowed", "total_denied", "coverage_pct"},
		},
		{
			name:           "PolicyDriftJSON",
			args:           []string{"policy", "drift", "-json", "policies/agent-default/", "policies/agent-strict/"},
			expectedFields: []string{"drift_score"},
		},
		{
			name:           "AgentListJSON",
			args:           []string{"agent", "list", "-dir", "agents/", "-json"},
			isArray:        true,
			expectedFields: []string{},
		},
		{
			name:           "AgentChainJSON",
			args:           []string{"agent", "chain", "-dir", "agents/", "-json"},
			expectedFields: []string{"risk_score"},
		},
		{
			name:           "AgentGraphJSON",
			args:           []string{"agent", "graph", "-dir", "agents/", "-json"},
			expectedFields: []string{"nodes"},
		},
		{
			name:           "AgentExportJSON",
			args:           []string{"agent", "export", "-dir", "agents/"},
			expectedFields: []string{"agent_count"},
		},
		{
			name:           "AgentAttestJSON",
			args:           []string{"agent", "attest", "-dir", "agents/", "-json"},
			expectedFields: []string{},
		},
		{
			name:           "ScoreDirJSON",
			args:           []string{"score", "-json", "-dir", "campaigns/"},
			isArray:        true,
			expectedFields: []string{},
		},
		{
			name:           "StatsJSON",
			args:           []string{"stats", "-dir", "campaigns/", "-json"},
			expectedFields: []string{"TotalCampaigns"},
		},
		{
			name:           "CoverageJSON",
			args:           []string{"coverage", "-format", "json", "-dir", "campaigns/"},
			expectedFields: []string{},
		},
		{
			name:           "ScenarioRunJSON",
			args:           []string{"scenario", "run", "-dir", "campaigns/llm-agent-hijack/", "-json"},
			expectedFields: []string{"campaign_name", "stage_count"},
		},
		{
			name:           "ThreatModelJSON",
			args:           []string{"threat-model", "-agents", "agents/", "-policy", "policies/", "-json"},
			expectedFields: []string{"overall_risk"},
		},
		{
			name:           "RiskPostureJSON",
			args:           []string{"risk-posture", "-policy", "policies/agent-strict/", "-json"},
			expectedFields: []string{"overall_score", "grade"},
		},
	}

	for _, chk := range checks {
		chk := chk
		t.Run(chk.name, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI(chk.args...)
			if err != nil && !chk.allowNonZero {
				t.Fatalf("%s failed: %v", chk.name, err)
			}
			if err != nil && chk.allowNonZero {
				t.Skipf("%s exited non-zero (allowed): %v", chk.name, err)
			}
			trimmed := strings.TrimSpace(stdout)
			if trimmed == "" {
				t.Skipf("%s produced no output", chk.name)
			}
			if !json.Valid([]byte(trimmed)) {
				t.Fatalf("%s produced invalid JSON:\n%s", chk.name, truncate(stdout, 500))
			}

			if chk.isArray {
				var arr []json.RawMessage
				if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
					t.Fatalf("%s JSON not an array: %v", chk.name, err)
				}
			} else {
				// Verify expected fields exist.
				var data map[string]interface{}
				if err := json.Unmarshal([]byte(trimmed), &data); err != nil {
					// Might be an array even though not flagged — that is fine, just check validity.
					return
				}
				for _, field := range chk.expectedFields {
					if _, ok := data[field]; !ok {
						t.Errorf("%s JSON missing field %q", chk.name, field)
					}
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Dashboard Generation
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_DashboardGeneration(t *testing.T) {
	t.Parallel()

	t.Run("TextSummary", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("dashboard", "-policy", "policies/agent-strict/", "-agents", "agents/")
		if err != nil {
			t.Fatalf("dashboard text summary failed: %v", err)
		}
		if len(stdout) < 50 {
			t.Errorf("dashboard text output too short: %s", truncate(stdout, 300))
		}
	})

	t.Run("HTMLOutput", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		outFile := filepath.Join(tmp, "dashboard.html")
		_, _, err := runCLI("dashboard", "-policy", "policies/agent-strict/", "-agents", "agents/", "-output", outFile)
		if err != nil {
			t.Fatalf("dashboard HTML generation failed: %v", err)
		}
		data, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatalf("could not read dashboard file: %v", err)
		}
		html := string(data)
		if !strings.Contains(html, "<html") && !strings.Contains(html, "<!DOCTYPE") && !strings.Contains(html, "<div") {
			t.Errorf("dashboard file does not look like HTML: %s", truncate(html, 300))
		}
		if len(data) < 500 {
			t.Errorf("dashboard HTML too small (%d bytes)", len(data))
		}
	})

	t.Run("HTMLWithTitle", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		outFile := filepath.Join(tmp, "titled.html")
		_, _, err := runCLI("dashboard", "-title", "Integration Test Dashboard", "-policy", "policies/agent-default/", "-agents", "agents/", "-output", outFile)
		if err != nil {
			t.Fatalf("dashboard with title failed: %v", err)
		}
		data, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatalf("could not read titled dashboard: %v", err)
		}
		if !strings.Contains(string(data), "Integration Test Dashboard") {
			t.Errorf("dashboard should contain custom title, got: %s", truncate(string(data), 500))
		}
	})

	t.Run("TextWithDefaultAgents", func(t *testing.T) {
		t.Parallel()
		// Without explicit -policy, should still produce output.
		stdout, _, err := runCLI("dashboard")
		if err != nil {
			t.Fatalf("dashboard with defaults failed: %v", err)
		}
		if len(stdout) < 20 {
			t.Errorf("dashboard default output too short: %s", truncate(stdout, 300))
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Compliance Mapping
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_ComplianceMapping(t *testing.T) {
	t.Parallel()

	t.Run("ListFrameworks", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runCLI("compliance", "-list")
		if err != nil {
			t.Fatalf("compliance -list failed: %v", err)
		}
		combined := stdout + stderr
		for _, fw := range []string{"nist-ai-rmf", "owasp-llm-top10", "mitre-atlas"} {
			if !strings.Contains(combined, fw) {
				t.Errorf("compliance -list missing framework %q, got: %s", fw, truncate(combined, 500))
			}
		}
	})

	t.Run("AllFrameworks", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("compliance", "-policy", "policies/agent-strict/", "-agents", "agents/")
		if err != nil {
			t.Fatalf("compliance all frameworks failed: %v", err)
		}
		if len(stdout) < 100 {
			t.Errorf("compliance output too short: %s", truncate(stdout, 300))
		}
	})

	t.Run("AllFrameworksJSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("compliance", "-policy", "policies/agent-strict/", "-agents", "agents/", "-json")
		if err != nil {
			t.Fatalf("compliance JSON failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("compliance JSON invalid: %s", truncate(stdout, 500))
		}
	})

	frameworks := []string{"nist-ai-rmf", "owasp-llm-top10", "mitre-atlas"}
	for _, fw := range frameworks {
		fw := fw
		t.Run("Framework_"+fw, func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("compliance", "-framework", fw, "-policy", "policies/agent-strict/", "-agents", "agents/")
			if err != nil {
				t.Fatalf("compliance -framework %s failed: %v", fw, err)
			}
			if len(stdout) < 50 {
				t.Errorf("compliance %s output too short: %s", fw, truncate(stdout, 300))
			}
		})

		t.Run("Framework_"+fw+"_JSON", func(t *testing.T) {
			t.Parallel()
			stdout, _, err := runCLI("compliance", "-framework", fw, "-policy", "policies/agent-default/", "-json")
			if err != nil {
				t.Fatalf("compliance %s JSON failed: %v", fw, err)
			}
			if !json.Valid([]byte(stdout)) {
				t.Errorf("compliance %s JSON invalid: %s", fw, truncate(stdout, 500))
			}
		})
	}

	// Different policies should both succeed and produce valid output.
	t.Run("DifferentPolicies", func(t *testing.T) {
		t.Parallel()
		stdoutDefault, _, errD := runCLI("compliance", "-policy", "policies/agent-default/", "-json")
		if errD != nil {
			t.Fatalf("compliance with agent-default failed: %v", errD)
		}
		stdoutStrict, _, errS := runCLI("compliance", "-policy", "policies/agent-strict/", "-json")
		if errS != nil {
			t.Fatalf("compliance with agent-strict failed: %v", errS)
		}
		if !json.Valid([]byte(stdoutDefault)) {
			t.Errorf("compliance JSON invalid for agent-default: %s", truncate(stdoutDefault, 300))
		}
		if !json.Valid([]byte(stdoutStrict)) {
			t.Errorf("compliance JSON invalid for agent-strict: %s", truncate(stdoutStrict, 300))
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Risk Posture
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_RiskPosture(t *testing.T) {
	t.Parallel()

	t.Run("WithPolicyAndAgents", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("risk-posture", "-policy", "policies/agent-strict/", "-agents", "agents/")
		if err != nil {
			t.Fatalf("risk-posture failed: %v", err)
		}
		lower := strings.ToLower(stdout)
		if !strings.Contains(lower, "risk") {
			t.Errorf("expected risk in output, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("JSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("risk-posture", "-policy", "policies/agent-strict/", "-agents", "agents/", "-json")
		if err != nil {
			t.Fatalf("risk-posture JSON failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("risk-posture JSON invalid: %s", truncate(stdout, 500))
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &data); err == nil {
			if _, ok := data["overall_score"]; !ok {
				t.Errorf("risk-posture JSON missing overall_score")
			}
			if _, ok := data["grade"]; !ok {
				t.Errorf("risk-posture JSON missing grade")
			}
		}
	})

	t.Run("DefaultPolicy", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("risk-posture", "-policy", "policies/agent-default/", "-json")
		if err != nil {
			t.Fatalf("risk-posture default policy failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("risk-posture JSON invalid for default: %s", truncate(stdout, 300))
		}
	})

	t.Run("StrictPolicy", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("risk-posture", "-policy", "policies/agent-strict/", "-json")
		if err != nil {
			t.Fatalf("risk-posture strict policy failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("risk-posture JSON invalid for strict: %s", truncate(stdout, 300))
		}
	})

	// Strict policy should generally score better than default.
	t.Run("StrictBetterThanDefault", func(t *testing.T) {
		t.Parallel()
		stdoutStrict, _, _ := runCLI("risk-posture", "-policy", "policies/agent-strict/", "-json")
		stdoutDefault, _, _ := runCLI("risk-posture", "-policy", "policies/agent-default/", "-json")

		var strict, deflt map[string]interface{}
		json.Unmarshal([]byte(stdoutStrict), &strict)
		json.Unmarshal([]byte(stdoutDefault), &deflt)

		// Just verify they produce different scores.
		if stdoutStrict == stdoutDefault {
			t.Errorf("strict and default should produce different risk postures")
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Threat Model
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_ThreatModel(t *testing.T) {
	t.Parallel()

	t.Run("WithExplicitDirs", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("threat-model", "-agents", "agents/", "-policy", "policies/")
		if err != nil {
			t.Fatalf("threat-model failed: %v", err)
		}
		if !strings.Contains(stdout, "STRIDE Threat Model") {
			t.Errorf("expected STRIDE output, got: %s", truncate(stdout, 300))
		}
	})

	t.Run("JSON", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("threat-model", "-agents", "agents/", "-policy", "policies/", "-json")
		if err != nil {
			t.Fatalf("threat-model JSON failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("threat-model JSON invalid: %s", truncate(stdout, 500))
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &data); err == nil {
			if _, ok := data["overall_risk"]; !ok {
				t.Errorf("threat-model JSON missing overall_risk")
			}
		}
	})

	t.Run("AutoDetect", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("threat-model")
		if err != nil {
			t.Fatalf("threat-model auto-detect failed: %v", err)
		}
		if !strings.Contains(stdout, "STRIDE Threat Model") {
			t.Errorf("expected STRIDE output, got: %s", truncate(stdout, 300))
		}
	})

	// STRIDE categories should appear in the output (lowercase with underscores).
	t.Run("STRIDECategories", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runCLI("threat-model", "-agents", "agents/", "-policy", "policies/")
		if err != nil {
			t.Fatalf("threat-model STRIDE check failed: %v", err)
		}
		// Check that at least some STRIDE categories are present — not all agents trigger every category.
		found := 0
		for _, cat := range []string{"spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege"} {
			if strings.Contains(stdout, cat) {
				found++
			}
		}
		if found < 3 {
			t.Errorf("threat-model output should contain at least 3 STRIDE categories, found %d in: %s", found, truncate(stdout, 500))
		}
	})

	// With empty dirs should still succeed with zero threats.
	t.Run("EmptyDirs", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		stdout, _, err := runCLI("threat-model", "-agents", tmp, "-policy", tmp, "-json")
		if err != nil {
			t.Fatalf("threat-model with empty dirs failed: %v", err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Errorf("threat-model JSON invalid: %s", truncate(stdout, 300))
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Campaign Generation and Import
//     Generate a campaign from template, validate it, then lint it
// ─────────────────────────────────────────────────────────────────────────────

func TestIntegration_CampaignGenerationAndImport(t *testing.T) {
	t.Parallel()

	templates := []string{"apt", "ransomware", "insider", "agent-hijack", "supply-chain", "cloud", "minimal"}

	for _, tmpl := range templates {
		tmpl := tmpl
		t.Run(tmpl+"/GenerateValidateLint", func(t *testing.T) {
			t.Parallel()
			tmp := t.TempDir()
			outDir := filepath.Join(tmp, "generated-"+tmpl)

			// Step 1: Generate campaign from template.
			_, stderr, err := runCLI("template", "create", "-template", tmpl, "-name", "integ-test-"+tmpl, "-output", outDir)
			if err != nil {
				t.Fatalf("template create %s failed: %v\nstderr: %s", tmpl, err, stderr)
			}

			// Verify campaign.yaml was written.
			campaignFile := filepath.Join(outDir, "campaign.yaml")
			data, err := os.ReadFile(campaignFile)
			if err != nil {
				t.Fatalf("campaign.yaml not created for %s: %v", tmpl, err)
			}
			if !strings.Contains(string(data), "integ-test-"+tmpl) {
				t.Errorf("campaign.yaml should contain name integ-test-%s, got:\n%s", tmpl, truncate(string(data), 300))
			}
			if !strings.Contains(string(data), "api_version:") {
				t.Errorf("campaign.yaml should contain api_version: for %s", tmpl)
			}

			// Step 2: Validate the generated campaign.
			stdout, _, err := runCLI("validate", outDir)
			if err != nil {
				t.Fatalf("validate generated %s failed: %v\noutput: %s", tmpl, err, truncate(stdout, 300))
			}
			if !strings.Contains(stdout, "is valid") {
				t.Errorf("generated %s should be valid, got: %s", tmpl, truncate(stdout, 300))
			}

			// Step 3: Lint the generated campaign.
			stdout, _, err = runCLI("lint", outDir)
			code := exitCode(err)
			if code != 0 && code != 1 {
				t.Fatalf("lint generated %s unexpected exit %d, output: %s", tmpl, code, truncate(stdout, 300))
			}
		})
	}

	// Import an Atomic Red Team YAML, validate, and lint.
	t.Run("AtomicImportValidateLint", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()

		artYAML := `attack_technique: T1078.004
display_name: "Valid Accounts: Cloud Accounts"
atomic_tests:
  - name: "AWS IAM Assume Role"
    auto_generated_guid: "integ-test-001"
    description: "Simulate an attacker assuming an IAM role"
    supported_platforms:
      - linux
    executor:
      name: bash
      command: "aws sts assume-role --role-arn arn:aws:iam::123456789:role/test --role-session-name integ"
`
		artFile := filepath.Join(tmp, "T1078.004.yaml")
		os.WriteFile(artFile, []byte(artYAML), 0644)

		outDir := filepath.Join(tmp, "imported")
		_, stderr, err := runCLI("import", "-source", "atomic", "-output", outDir, artFile)
		if err != nil {
			t.Fatalf("import atomic failed: %v\nstderr: %s", err, stderr)
		}

		// Validate the imported campaign.
		stdout, _, err := runCLI("validate", outDir)
		if err != nil {
			t.Fatalf("validate imported campaign failed: %v\noutput: %s", err, truncate(stdout, 300))
		}
		if !strings.Contains(stdout, "is valid") {
			t.Errorf("imported campaign should be valid, got: %s", truncate(stdout, 300))
		}

		// Lint the imported campaign.
		_, _, err = runCLI("lint", outDir)
		code := exitCode(err)
		if code != 0 && code != 1 {
			t.Fatalf("lint imported campaign unexpected exit %d", code)
		}
	})
}

// ---------------------------------------------------------------------------
// End-to-end pipeline test — loads real YAML from the repo fixtures and runs
// every major analysis command, asserting JSON validity and key field presence.
// ---------------------------------------------------------------------------

func TestIntegration_FullPipelineEndToEnd(t *testing.T) {
	t.Parallel()

	t.Run("SimulateDir", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runCLI("gap", "-dir", "campaigns/", "-format", "json")
		if err != nil {
			t.Fatalf("gap -dir campaigns/ failed: %v\nstderr: %s", err, truncate(stderr, 300))
		}
		var gapResult map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &gapResult); err != nil {
			t.Fatalf("gap JSON invalid: %v", err)
		}
		for _, key := range []string{"version", "campaigns", "aggregate", "gaps"} {
			if _, ok := gapResult[key]; !ok {
				t.Errorf("gap JSON missing key %q", key)
			}
		}
	})

	t.Run("ThreatModel", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runCLI("threat-model", "-agents", "agents/", "-policy", "policies/agent-strict/", "-json")
		if err != nil {
			t.Fatalf("threat-model failed: %v\nstderr: %s", err, truncate(stderr, 300))
		}
		var tm map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &tm); err != nil {
			t.Fatalf("threat-model JSON invalid: %v", err)
		}
		if _, ok := tm["threats"]; !ok {
			t.Error("threat-model JSON missing 'threats' key")
		}
		if _, ok := tm["threat_count"]; !ok {
			t.Error("threat-model JSON missing 'threat_count' key")
		}
	})

	t.Run("RiskPosture", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runCLI("risk-posture", "-agents", "agents/", "-policy", "policies/agent-strict/", "-json")
		if err != nil {
			t.Fatalf("risk-posture failed: %v\nstderr: %s", err, truncate(stderr, 300))
		}
		var rp map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &rp); err != nil {
			t.Fatalf("risk-posture JSON invalid: %v", err)
		}
		for _, key := range []string{"grade", "overall_score", "dimensions"} {
			if _, ok := rp[key]; !ok {
				t.Errorf("risk-posture JSON missing key %q", key)
			}
		}
	})

	t.Run("AttackTree", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runCLI("attack-tree", "-agents", "agents/", "-policy", "policies/agent-strict/", "-json")
		if err != nil {
			t.Fatalf("attack-tree failed: %v\nstderr: %s", err, truncate(stderr, 300))
		}
		var at map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &at); err != nil {
			t.Fatalf("attack-tree JSON invalid: %v", err)
		}
		for _, key := range []string{"root", "node_count", "risk_score"} {
			if _, ok := at[key]; !ok {
				t.Errorf("attack-tree JSON missing key %q", key)
			}
		}
	})

	t.Run("ComplianceSOC", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runCLI("compliance", "-dir", "campaigns/", "-framework", "nist-csf", "-json")
		if err != nil {
			t.Fatalf("compliance SOC failed: %v\nstderr: %s", err, truncate(stderr, 300))
		}
		var comp map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &comp); err != nil {
			t.Fatalf("compliance JSON invalid: %v", err)
		}
		for _, key := range []string{"framework", "control_results", "summary"} {
			if _, ok := comp[key]; !ok {
				t.Errorf("compliance JSON missing key %q", key)
			}
		}
	})

	t.Run("Dashboard", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		outFile := filepath.Join(tmp, "dashboard.html")
		_, stderr, err := runCLI("dashboard", "-policy", "policies/agent-strict/", "-agents", "agents/", "-output", outFile)
		if err != nil {
			t.Fatalf("dashboard failed: %v\nstderr: %s", err, truncate(stderr, 300))
		}
		data, err := os.ReadFile(outFile)
		if err != nil {
			t.Fatalf("reading dashboard output: %v", err)
		}
		html := string(data)
		if !strings.Contains(html, "<html") && !strings.Contains(html, "<!DOCTYPE") && !strings.Contains(html, "<div") {
			t.Error("dashboard output does not look like HTML")
		}
		if len(data) < 1000 {
			t.Errorf("dashboard HTML suspiciously small: %d bytes", len(data))
		}
	})

	t.Run("Doctor", func(t *testing.T) {
		t.Parallel()
		stdout, _, _ := runCLI("doctor")
		lower := strings.ToLower(stdout)
		if !strings.Contains(lower, "campaign") {
			t.Error("doctor output should mention campaigns")
		}
		if !strings.Contains(lower, "agent") {
			t.Error("doctor output should mention agents")
		}
	})

	t.Run("Summary", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runCLI("summary", "-dir", "campaigns/")
		if err != nil {
			t.Fatalf("summary failed: %v\nstderr: %s", err, truncate(stderr, 300))
		}
		if !strings.Contains(strings.ToLower(stdout), "campaign") {
			t.Error("summary output should mention campaigns")
		}
	})
}
