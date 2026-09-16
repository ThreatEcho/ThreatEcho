// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// ---------------------------------------------------------------------------
// Test helpers — all prefixed mkDash to avoid clashes with other test files.
// ---------------------------------------------------------------------------

func mkDashRiskPosture() *engine.RiskPosture {
	return &engine.RiskPosture{
		OverallScore:     0.42,
		Grade:            "C",
		Verdict:          "at_risk",
		TotalFindings:    12,
		CriticalFindings: 3,
		Dimensions: []engine.RiskDimension{
			{Name: "policy_lint", Score: 0.30, Weight: 0.15, Findings: 4, CriticalFindings: 1, Details: "lint score C (4 findings)", Available: true},
			{Name: "coverage_gaps", Score: 0.55, Weight: 0.25, Findings: 5, CriticalFindings: 2, Details: "60% coverage (5 gaps)", Available: true},
			{Name: "threat_model", Score: 0.40, Weight: 0.25, Findings: 3, CriticalFindings: 0, Details: "3 threats (overall risk 4.0/10)", Available: true},
		},
		TopRisks:        []string{"[coverage_gaps] 60% coverage (5 gaps) (score 0.55)", "[threat_model] 3 threats (score 0.40)"},
		Recommendations: []string{"HIGH: reduce coverage_gaps risk (5 findings)", "Review threat_model findings (3 issues)", "Resolve 3 critical findings before deployment"},
	}
}

func mkDashLintReport() *policy.LintReport {
	return &policy.LintReport{
		PolicyName:   "agent-security-policy",
		TotalRules:   8,
		FindingCount: 5,
		ErrorCount:   2,
		WarningCount: 2,
		InfoCount:    1,
		StyleCount:   0,
		Score:        0.78,
		Grade:        "C",
		Summary:      "Policy \"agent-security-policy\": 8 rules, 5 findings (2 errors, 2 warnings) — grade C (78%).",
		Findings: []policy.LintFinding{
			{Rule: "SEC-003", Severity: policy.LintError, Category: policy.LintCatSecurity, Message: "Unconditional allow on shell_exec", Suggestion: "Add conditions"},
			{Rule: "RED-001", Severity: policy.LintError, Category: policy.LintCatRedundancy, Message: "Duplicate rule ID", Suggestion: "Rename rule"},
			{Rule: "SEC-002", Severity: policy.LintWarning, Category: policy.LintCatSecurity, Message: "No deny rules", Suggestion: "Add deny rules"},
			{Rule: "BP-001", Severity: policy.LintWarning, Category: policy.LintCatBestPractice, Message: "No default rule", Suggestion: "Add default-deny"},
			{Rule: "COV-003", Severity: policy.LintInfo, Category: policy.LintCatCoverage, Message: "No tactic-based rules", Suggestion: "Add tactic rules"},
		},
	}
}

func mkDashThreatModel() *engine.ThreatModel {
	return &engine.ThreatModel{
		Name:             "Test Deployment Threat Model",
		GeneratedAt:      "2026-09-14T10:00:00Z",
		ThreatCount:      4,
		CriticalCount:    1,
		HighCount:        2,
		MediumCount:      1,
		LowCount:         0,
		MitigatedCount:   1,
		PartialCount:     1,
		UnmitigatedCount: 2,
		OverallRisk:      6.5,
		CategoryBreakdown: map[engine.ThreatCategory]int{
			engine.Spoofing:              1,
			engine.Tampering:             1,
			engine.ElevationOfPrivilege:  1,
			engine.InformationDisclosure: 1,
		},
		Threats: []engine.Threat{
			{ID: "THR-001", Category: engine.Spoofing, Title: "Unattested agent identity", AffectedAgent: "data-agent", Severity: "high", MitigationStatus: "partial", RiskScore: 5.6},
			{ID: "THR-002", Category: engine.Tampering, Title: "Unauthorized write access", AffectedAgent: "data-agent", AffectedTool: "db_write", Severity: "high", MitigationStatus: "unmitigated", RiskScore: 5.6},
			{ID: "THR-003", Category: engine.ElevationOfPrivilege, Title: "Trust escalation path", AffectedAgent: "admin-agent", Severity: "critical", MitigationStatus: "unmitigated", RiskScore: 10.0},
			{ID: "THR-004", Category: engine.InformationDisclosure, Title: "RAG index disclosure", AffectedAgent: "search-agent", Severity: "medium", MitigationStatus: "mitigated", RiskScore: 2.0},
		},
	}
}

func mkDashInventory() *agent.Inventory {
	return &agent.Inventory{
		Agents: []*agent.Agent{
			{
				Meta:         agent.AgentMeta{Name: "data-agent", Type: agent.TypeToolCalling, Description: "Data pipeline agent"},
				Capabilities: agent.AgentCapabilities{ToolCalling: true, FileAccess: true},
				Tools: []agent.ToolAccess{
					{Name: "db_read", Actions: []string{"read"}},
					{Name: "db_write", Actions: []string{"write"}, Elevated: true},
				},
				Trust: agent.TrustConfig{Level: agent.TrustStandard},
			},
			{
				Meta:         agent.AgentMeta{Name: "admin-agent", Type: agent.TypeOrchestrator, Description: "Admin orchestrator"},
				Capabilities: agent.AgentCapabilities{ToolCalling: true, MessagePassing: true, Autonomous: true},
				Tools: []agent.ToolAccess{
					{Name: "shell_exec", Actions: []string{"execute"}, Elevated: true},
				},
				Trust: agent.TrustConfig{Level: agent.TrustAdmin, CanEscalate: true},
			},
			{
				Meta:         agent.AgentMeta{Name: "search-agent", Type: agent.TypeRetrieval, Description: "Search assistant"},
				Capabilities: agent.AgentCapabilities{RAG: true},
				Trust:        agent.TrustConfig{Level: agent.TrustLow},
			},
		},
	}
}

func mkDashPolicies() []*policy.Policy {
	return []*policy.Policy{
		{
			Meta:  policy.PolicyMeta{Name: "agent-security-policy", Description: "Security policy for agents"},
			Agent: policy.AgentScope{Name: "*"},
			Rules: []policy.Rule{
				{ID: "deny-shell", Effect: "deny", Match: policy.RuleMatch{Tools: []string{"shell_exec"}}},
				{ID: "allow-read", Effect: "allow", Match: policy.RuleMatch{Tools: []string{"db_read"}}},
				{ID: "alert-write", Effect: "alert", Match: policy.RuleMatch{Tools: []string{"db_write"}}},
			},
		},
		{
			Meta:  policy.PolicyMeta{Name: "admin-override", Description: "Admin agent overrides"},
			Agent: policy.AgentScope{Name: "admin-agent"},
			Rules: []policy.Rule{
				{ID: "allow-shell-admin", Effect: "allow", Match: policy.RuleMatch{Tools: []string{"shell_exec"}}, Priority: 100},
			},
		},
	}
}

func mkDashConfig() DashboardConfig {
	return DefaultDashboardConfig()
}

// ---------------------------------------------------------------------------
// DefaultDashboardConfig tests
// ---------------------------------------------------------------------------

func TestDashDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultDashboardConfig()
	if cfg.Title == "" {
		t.Error("expected non-empty default title")
	}
	if !cfg.IncludeRisk {
		t.Error("expected IncludeRisk true by default")
	}
	if !cfg.IncludeLint {
		t.Error("expected IncludeLint true by default")
	}
	if !cfg.IncludeThreats {
		t.Error("expected IncludeThreats true by default")
	}
	if !cfg.IncludeAgents {
		t.Error("expected IncludeAgents true by default")
	}
	if !cfg.IncludePolicy {
		t.Error("expected IncludePolicy true by default")
	}
}

// ---------------------------------------------------------------------------
// BuildDashboard tests
// ---------------------------------------------------------------------------

func TestDashBuildAllOptions(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg,
		WithRiskPosture(mkDashRiskPosture()),
		WithLintReport(mkDashLintReport()),
		WithThreatModel(mkDashThreatModel()),
		WithAgentInventory(mkDashInventory()),
		WithPolicies(mkDashPolicies()),
	)
	if d == nil {
		t.Fatal("expected non-nil dashboard")
	}
	if d.Title != cfg.Title {
		t.Errorf("title = %q, want %q", d.Title, cfg.Title)
	}
	if d.AgentCount != 3 {
		t.Errorf("agent count = %d, want 3", d.AgentCount)
	}
	if d.PolicyCount != 2 {
		t.Errorf("policy count = %d, want 2", d.PolicyCount)
	}
	if d.RiskGrade != "C" {
		t.Errorf("risk grade = %q, want C", d.RiskGrade)
	}
	if d.RiskScore != 0.42 {
		t.Errorf("risk score = %.2f, want 0.42", d.RiskScore)
	}
	if d.GeneratedAt == "" {
		t.Error("expected non-empty generated_at")
	}
	if d.Version == "" {
		t.Error("expected non-empty version")
	}
}

func TestDashBuildNoOptions(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg)
	if d == nil {
		t.Fatal("expected non-nil dashboard")
	}
	if d.AgentCount != 0 {
		t.Errorf("agent count = %d, want 0", d.AgentCount)
	}
	if d.PolicyCount != 0 {
		t.Errorf("policy count = %d, want 0", d.PolicyCount)
	}
	if d.RiskGrade != "" {
		t.Errorf("risk grade = %q, want empty", d.RiskGrade)
	}
	// Should have at least executive summary and recommendations.
	if len(d.Sections) < 1 {
		t.Errorf("expected at least 1 section, got %d", len(d.Sections))
	}
}

func TestDashBuildPartialOptions(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg,
		WithRiskPosture(mkDashRiskPosture()),
		WithLintReport(mkDashLintReport()),
	)
	if d == nil {
		t.Fatal("expected non-nil dashboard")
	}
	if d.RiskGrade != "C" {
		t.Errorf("risk grade = %q, want C", d.RiskGrade)
	}

	// Should include: exec-summary, risk-assessment, policy-quality, recommendations.
	sectionIDs := mkDashSectionIDs(d)
	for _, want := range []string{"exec-summary", "risk-assessment", "policy-quality"} {
		if !sectionIDs[want] {
			t.Errorf("expected section %q to be present", want)
		}
	}
	// Should not include threat-analysis or agent-inventory.
	for _, absent := range []string{"threat-analysis", "agent-inventory", "policy-overview"} {
		if sectionIDs[absent] {
			t.Errorf("expected section %q to be absent (no input provided)", absent)
		}
	}
}

func TestDashBuildOnlyRisk(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithRiskPosture(mkDashRiskPosture()))
	sectionIDs := mkDashSectionIDs(d)
	if !sectionIDs["risk-assessment"] {
		t.Error("expected risk-assessment section")
	}
	if sectionIDs["policy-quality"] {
		t.Error("unexpected policy-quality section without lint report")
	}
}

func TestDashBuildOnlyLint(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithLintReport(mkDashLintReport()))
	sectionIDs := mkDashSectionIDs(d)
	if !sectionIDs["policy-quality"] {
		t.Error("expected policy-quality section")
	}
	if sectionIDs["risk-assessment"] {
		t.Error("unexpected risk-assessment section without risk posture")
	}
}

func TestDashBuildOnlyThreats(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithThreatModel(mkDashThreatModel()))
	sectionIDs := mkDashSectionIDs(d)
	if !sectionIDs["threat-analysis"] {
		t.Error("expected threat-analysis section")
	}
}

func TestDashBuildOnlyAgents(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithAgentInventory(mkDashInventory()))
	sectionIDs := mkDashSectionIDs(d)
	if !sectionIDs["agent-inventory"] {
		t.Error("expected agent-inventory section")
	}
	if d.AgentCount != 3 {
		t.Errorf("agent count = %d, want 3", d.AgentCount)
	}
}

func TestDashBuildOnlyPolicies(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithPolicies(mkDashPolicies()))
	sectionIDs := mkDashSectionIDs(d)
	if !sectionIDs["policy-overview"] {
		t.Error("expected policy-overview section")
	}
	if d.PolicyCount != 2 {
		t.Errorf("policy count = %d, want 2", d.PolicyCount)
	}
}

func TestDashBuildNilOption(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	// Passing a nil option should not panic.
	d := BuildDashboard(cfg, nil, WithRiskPosture(mkDashRiskPosture()), nil)
	if d == nil {
		t.Fatal("expected non-nil dashboard")
	}
}

func TestDashBuildEmptyTitle(t *testing.T) {
	t.Parallel()
	cfg := DashboardConfig{
		IncludeRisk: true,
	}
	d := BuildDashboard(cfg)
	if d.Title == "" {
		t.Error("expected default title when empty string provided")
	}
}

// ---------------------------------------------------------------------------
// Config toggle tests
// ---------------------------------------------------------------------------

func TestDashConfigDisableRisk(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	cfg.IncludeRisk = false
	d := BuildDashboard(cfg, WithRiskPosture(mkDashRiskPosture()))
	sectionIDs := mkDashSectionIDs(d)
	if sectionIDs["risk-assessment"] {
		t.Error("risk-assessment should be excluded when IncludeRisk is false")
	}
}

func TestDashConfigDisableLint(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	cfg.IncludeLint = false
	d := BuildDashboard(cfg, WithLintReport(mkDashLintReport()))
	sectionIDs := mkDashSectionIDs(d)
	if sectionIDs["policy-quality"] {
		t.Error("policy-quality should be excluded when IncludeLint is false")
	}
}

func TestDashConfigDisableThreats(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	cfg.IncludeThreats = false
	d := BuildDashboard(cfg, WithThreatModel(mkDashThreatModel()))
	sectionIDs := mkDashSectionIDs(d)
	if sectionIDs["threat-analysis"] {
		t.Error("threat-analysis should be excluded when IncludeThreats is false")
	}
}

func TestDashConfigDisableAgents(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	cfg.IncludeAgents = false
	d := BuildDashboard(cfg, WithAgentInventory(mkDashInventory()))
	sectionIDs := mkDashSectionIDs(d)
	if sectionIDs["agent-inventory"] {
		t.Error("agent-inventory should be excluded when IncludeAgents is false")
	}
}

func TestDashConfigDisablePolicy(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	cfg.IncludePolicy = false
	d := BuildDashboard(cfg, WithPolicies(mkDashPolicies()))
	sectionIDs := mkDashSectionIDs(d)
	if sectionIDs["policy-overview"] {
		t.Error("policy-overview should be excluded when IncludePolicy is false")
	}
}

func TestDashConfigAllDisabled(t *testing.T) {
	t.Parallel()
	cfg := DashboardConfig{
		Title: "Minimal Dashboard",
	}
	d := BuildDashboard(cfg,
		WithRiskPosture(mkDashRiskPosture()),
		WithLintReport(mkDashLintReport()),
		WithThreatModel(mkDashThreatModel()),
		WithAgentInventory(mkDashInventory()),
		WithPolicies(mkDashPolicies()),
	)
	sectionIDs := mkDashSectionIDs(d)
	// Only exec-summary and recommendations should be present.
	if !sectionIDs["exec-summary"] {
		t.Error("exec-summary should always be present")
	}
	for _, absent := range []string{"risk-assessment", "policy-quality", "threat-analysis", "agent-inventory", "policy-overview"} {
		if sectionIDs[absent] {
			t.Errorf("section %q should be absent when all toggles are off", absent)
		}
	}
}

// ---------------------------------------------------------------------------
// Section content tests
// ---------------------------------------------------------------------------

func TestDashExecSummarySection(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg,
		WithRiskPosture(mkDashRiskPosture()),
		WithThreatModel(mkDashThreatModel()),
	)
	sec := mkDashFindSection(d, "exec-summary")
	if sec == nil {
		t.Fatal("expected exec-summary section")
	}
	if sec.Type != "summary" {
		t.Errorf("type = %q, want summary", sec.Type)
	}
	// Should contain risk grade, agents, policies items at minimum.
	if len(sec.Items) < 3 {
		t.Errorf("expected at least 3 items, got %d", len(sec.Items))
	}
}

func TestDashRiskSectionMetrics(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithRiskPosture(mkDashRiskPosture()))
	sec := mkDashFindSection(d, "risk-assessment")
	if sec == nil {
		t.Fatal("expected risk-assessment section")
	}
	if len(sec.Metrics) == 0 {
		t.Error("expected metrics in risk section")
	}
	// First metric should be Risk Score.
	if sec.Metrics[0].Label != "Risk Score" {
		t.Errorf("first metric label = %q, want Risk Score", sec.Metrics[0].Label)
	}
	if sec.Metrics[0].Max != 100 {
		t.Errorf("first metric max = %.0f, want 100", sec.Metrics[0].Max)
	}
}

func TestDashLintSectionFindings(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithLintReport(mkDashLintReport()))
	sec := mkDashFindSection(d, "policy-quality")
	if sec == nil {
		t.Fatal("expected policy-quality section")
	}
	if sec.Type != "findings" {
		t.Errorf("type = %q, want findings", sec.Type)
	}
	// Should contain the 5 findings plus the header items.
	foundFindings := 0
	for _, it := range sec.Items {
		if strings.Contains(it.Label, "[") {
			foundFindings++
		}
	}
	if foundFindings != 5 {
		t.Errorf("expected 5 lint findings, got %d", foundFindings)
	}
}

func TestDashThreatSectionSTRIDE(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithThreatModel(mkDashThreatModel()))
	sec := mkDashFindSection(d, "threat-analysis")
	if sec == nil {
		t.Fatal("expected threat-analysis section")
	}
	if sec.Type != "table" {
		t.Errorf("type = %q, want table", sec.Type)
	}
	// Should have threats as items.
	hasThreat := false
	for _, it := range sec.Items {
		if strings.Contains(it.Label, "THR-") {
			hasThreat = true
			break
		}
	}
	if !hasThreat {
		t.Error("expected threat items with THR- prefix")
	}
}

func TestDashAgentSectionContent(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithAgentInventory(mkDashInventory()))
	sec := mkDashFindSection(d, "agent-inventory")
	if sec == nil {
		t.Fatal("expected agent-inventory section")
	}
	// Should have 3 agent items.
	if len(sec.Items) != 3 {
		t.Errorf("expected 3 agent items, got %d", len(sec.Items))
	}
	// First agent should be data-agent.
	if sec.Items[0].Label != "data-agent" {
		t.Errorf("first agent label = %q, want data-agent", sec.Items[0].Label)
	}
}

func TestDashPolicySectionContent(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithPolicies(mkDashPolicies()))
	sec := mkDashFindSection(d, "policy-overview")
	if sec == nil {
		t.Fatal("expected policy-overview section")
	}
	if len(sec.Items) != 2 {
		t.Errorf("expected 2 policy items, got %d", len(sec.Items))
	}
}

func TestDashRecommendationsSection(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg,
		WithRiskPosture(mkDashRiskPosture()),
		WithLintReport(mkDashLintReport()),
		WithThreatModel(mkDashThreatModel()),
	)
	sec := mkDashFindSection(d, "recommendations")
	if sec == nil {
		t.Fatal("expected recommendations section")
	}
	if sec.Type != "checklist" {
		t.Errorf("type = %q, want checklist", sec.Type)
	}
	if len(sec.Items) == 0 {
		t.Error("expected at least one recommendation")
	}
}

func TestDashRecommendationsIncludesMissing(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	// No agents and no policies provided.
	d := BuildDashboard(cfg)
	sec := mkDashFindSection(d, "recommendations")
	if sec == nil {
		t.Fatal("expected recommendations section")
	}
	hasAgentRec := false
	hasPolicyRec := false
	for _, it := range sec.Items {
		if it.Label == "Agents" {
			hasAgentRec = true
		}
		if it.Label == "Policy" {
			hasPolicyRec = true
		}
	}
	if !hasAgentRec {
		t.Error("expected agent assessment recommendation")
	}
	if !hasPolicyRec {
		t.Error("expected policy recommendation")
	}
}

// ---------------------------------------------------------------------------
// Status badge logic tests
// ---------------------------------------------------------------------------

func TestDashGradeStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		grade string
		want  string
	}{
		{"A", "pass"},
		{"B", "pass"},
		{"C", "warn"},
		{"D", "warn"},
		{"F", "fail"},
		{"N/A", "info"},
		{"", "info"},
	}
	for _, tt := range tests {
		if got := gradeStatus(tt.grade); got != tt.want {
			t.Errorf("gradeStatus(%q) = %q, want %q", tt.grade, got, tt.want)
		}
	}
}

func TestDashCritStatus(t *testing.T) {
	t.Parallel()
	if got := critStatus(0); got != "pass" {
		t.Errorf("critStatus(0) = %q, want pass", got)
	}
	if got := critStatus(5); got != "fail" {
		t.Errorf("critStatus(5) = %q, want fail", got)
	}
}

func TestDashSeverityStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sev  string
		want string
	}{
		{"critical", "fail"},
		{"high", "warn"},
		{"medium", "info"},
		{"low", "info"},
		{"unknown", "info"},
	}
	for _, tt := range tests {
		if got := severityStatus(tt.sev); got != tt.want {
			t.Errorf("severityStatus(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestDashTrustStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		level string
		want  string
	}{
		{agent.TrustAdmin, "warn"},
		{agent.TrustElevated, "warn"},
		{agent.TrustStandard, "info"},
		{agent.TrustLow, "info"},
		{agent.TrustUntrusted, "fail"},
	}
	for _, tt := range tests {
		if got := trustStatus(tt.level); got != tt.want {
			t.Errorf("trustStatus(%q) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestDashLintSevStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sev  policy.LintSeverity
		want string
	}{
		{policy.LintError, "fail"},
		{policy.LintWarning, "warn"},
		{policy.LintInfo, "info"},
		{policy.LintStyle, "info"},
	}
	for _, tt := range tests {
		if got := lintSevStatus(tt.sev); got != tt.want {
			t.Errorf("lintSevStatus(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// RenderDashboard tests
// ---------------------------------------------------------------------------

func TestDashRenderNil(t *testing.T) {
	t.Parallel()
	_, err := RenderDashboard(nil)
	if err == nil {
		t.Error("expected error for nil dashboard data")
	}
}

func TestDashRenderValidHTML(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig(),
		WithRiskPosture(mkDashRiskPosture()),
		WithLintReport(mkDashLintReport()),
		WithThreatModel(mkDashThreatModel()),
		WithAgentInventory(mkDashInventory()),
		WithPolicies(mkDashPolicies()),
	)
	html, err := RenderDashboard(d)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	mkDashAssertHTMLContains(t, html, "<!DOCTYPE html>")
	mkDashAssertHTMLContains(t, html, "<head>")
	mkDashAssertHTMLContains(t, html, "<body>")
	mkDashAssertHTMLContains(t, html, "<style>")
	mkDashAssertHTMLContains(t, html, "</html>")
}

func TestDashRenderContainsTitle(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	cfg.Title = "My Test Dashboard"
	d := BuildDashboard(cfg)
	html, err := RenderDashboard(d)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	mkDashAssertHTMLContains(t, html, "My Test Dashboard")
	mkDashAssertHTMLContains(t, html, "<title>My Test Dashboard</title>")
}

func TestDashRenderContainsSectionHeaders(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig(),
		WithRiskPosture(mkDashRiskPosture()),
		WithLintReport(mkDashLintReport()),
		WithThreatModel(mkDashThreatModel()),
		WithAgentInventory(mkDashInventory()),
		WithPolicies(mkDashPolicies()),
	)
	html, err := RenderDashboard(d)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	for _, title := range []string{
		"Executive Summary",
		"Risk Assessment",
		"Policy Quality",
		"Threat Analysis",
		"Agent Inventory",
		"Policy Overview",
		"Recommendations",
	} {
		mkDashAssertHTMLContains(t, html, title)
	}
}

func TestDashRenderResponsiveStyles(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig())
	html, err := RenderDashboard(d)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	// Check responsive and dark mode CSS.
	mkDashAssertHTMLContains(t, html, "prefers-color-scheme: dark")
	mkDashAssertHTMLContains(t, html, "@media (max-width:")
	mkDashAssertHTMLContains(t, html, "@media print")
}

func TestDashRenderStatusBadges(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig(), WithRiskPosture(mkDashRiskPosture()))
	html, err := RenderDashboard(d)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	mkDashAssertHTMLContains(t, html, "status-pass")
	mkDashAssertHTMLContains(t, html, "status-warn")
}

func TestDashRenderProgressBars(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig(), WithRiskPosture(mkDashRiskPosture()))
	html, err := RenderDashboard(d)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	mkDashAssertHTMLContains(t, html, "metric-bar")
	mkDashAssertHTMLContains(t, html, "metric-fill")
}

func TestDashRenderEmptyDashboard(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(DashboardConfig{Title: "Empty"})
	html, err := RenderDashboard(d)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	mkDashAssertHTMLContains(t, html, "Empty")
	mkDashAssertHTMLContains(t, html, "<!DOCTYPE html>")
}

func TestDashRenderFooter(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig())
	html, err := RenderDashboard(d)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	mkDashAssertHTMLContains(t, html, "Detection Engineering for AI Agents")
}

func TestDashRenderDarkThemeTokens(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig())
	html, err := RenderDashboard(d)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	mkDashAssertHTMLContains(t, html, `data-theme="light"`)
	mkDashAssertHTMLContains(t, html, `data-theme="dark"`)
}

// ---------------------------------------------------------------------------
// WriteDashboard tests
// ---------------------------------------------------------------------------

func TestDashWriteCreatesFile(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig(), WithRiskPosture(mkDashRiskPosture()))
	dir := t.TempDir()
	path := filepath.Join(dir, "dashboard.html")
	if err := WriteDashboard(d, path); err != nil {
		t.Fatalf("write error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back error: %v", err)
	}
	if !strings.Contains(string(data), "<!DOCTYPE html>") {
		t.Error("written file does not contain DOCTYPE")
	}
}

func TestDashWriteNilReturnsError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "nil.html")
	if err := WriteDashboard(nil, path); err == nil {
		t.Error("expected error for nil dashboard data")
	}
}

func TestDashWriteInvalidPath(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig())
	if err := WriteDashboard(d, "/nonexistent/dir/dashboard.html"); err == nil {
		t.Error("expected error for invalid path")
	}
}

// ---------------------------------------------------------------------------
// FormatDashboardText tests
// ---------------------------------------------------------------------------

func TestDashTextFormatNil(t *testing.T) {
	t.Parallel()
	out := FormatDashboardText(nil)
	if !strings.Contains(out, "No dashboard data") {
		t.Errorf("expected 'No dashboard data' message, got: %q", out)
	}
}

func TestDashTextFormatContainsTitle(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	cfg.Title = "Text Test Dashboard"
	d := BuildDashboard(cfg, WithRiskPosture(mkDashRiskPosture()))
	out := FormatDashboardText(d)
	if !strings.Contains(out, "Text Test Dashboard") {
		t.Error("text output should contain the title")
	}
}

func TestDashTextFormatContainsSections(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig(),
		WithRiskPosture(mkDashRiskPosture()),
		WithLintReport(mkDashLintReport()),
		WithThreatModel(mkDashThreatModel()),
		WithAgentInventory(mkDashInventory()),
		WithPolicies(mkDashPolicies()),
	)
	out := FormatDashboardText(d)
	for _, title := range []string{
		"Executive Summary",
		"Risk Assessment",
		"Policy Quality",
		"Threat Analysis",
		"Agent Inventory",
		"Policy Overview",
		"Recommendations",
	} {
		if !strings.Contains(out, title) {
			t.Errorf("text output should contain section %q", title)
		}
	}
}

func TestDashTextFormatContainsMetrics(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig(), WithRiskPosture(mkDashRiskPosture()))
	out := FormatDashboardText(d)
	if !strings.Contains(out, "Risk Score") {
		t.Error("text output should contain 'Risk Score'")
	}
	if !strings.Contains(out, "%") {
		t.Error("text output should contain percentage values")
	}
}

func TestDashTextFormatRiskGrade(t *testing.T) {
	t.Parallel()
	d := BuildDashboard(mkDashConfig(), WithRiskPosture(mkDashRiskPosture()))
	out := FormatDashboardText(d)
	if !strings.Contains(out, "Risk Grade: C") {
		t.Error("text output should contain 'Risk Grade: C'")
	}
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestDashNilRiskPosture(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithRiskPosture(nil))
	if d.RiskGrade != "" {
		t.Errorf("expected empty risk grade for nil posture, got %q", d.RiskGrade)
	}
}

func TestDashNilLintReport(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithLintReport(nil))
	sectionIDs := mkDashSectionIDs(d)
	if sectionIDs["policy-quality"] {
		t.Error("policy-quality should not appear for nil lint report")
	}
}

func TestDashNilThreatModel(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithThreatModel(nil))
	sectionIDs := mkDashSectionIDs(d)
	if sectionIDs["threat-analysis"] {
		t.Error("threat-analysis should not appear for nil threat model")
	}
}

func TestDashNilInventory(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithAgentInventory(nil))
	sectionIDs := mkDashSectionIDs(d)
	if sectionIDs["agent-inventory"] {
		t.Error("agent-inventory should not appear for nil inventory")
	}
}

func TestDashEmptyPolicies(t *testing.T) {
	t.Parallel()
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithPolicies(nil))
	sectionIDs := mkDashSectionIDs(d)
	if sectionIDs["policy-overview"] {
		t.Error("policy-overview should not appear for nil policies")
	}
}

func TestDashInventoryWithNilAgents(t *testing.T) {
	t.Parallel()
	inv := &agent.Inventory{
		Agents: []*agent.Agent{nil, mkDashInventory().Agents[0], nil},
	}
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithAgentInventory(inv))
	sec := mkDashFindSection(d, "agent-inventory")
	if sec == nil {
		t.Fatal("expected agent-inventory section")
	}
	// Should only have 1 item (nil agents skipped).
	if len(sec.Items) != 1 {
		t.Errorf("expected 1 agent item (nils skipped), got %d", len(sec.Items))
	}
}

func TestDashPoliciesWithNils(t *testing.T) {
	t.Parallel()
	policies := []*policy.Policy{nil, mkDashPolicies()[0], nil}
	cfg := mkDashConfig()
	d := BuildDashboard(cfg, WithPolicies(policies))
	sec := mkDashFindSection(d, "policy-overview")
	if sec == nil {
		t.Fatal("expected policy-overview section")
	}
	// Should only have 1 item (nil policies skipped).
	if len(sec.Items) != 1 {
		t.Errorf("expected 1 policy item (nils skipped), got %d", len(sec.Items))
	}
}

func TestDashAgentCapList(t *testing.T) {
	t.Parallel()
	a := &agent.Agent{
		Capabilities: agent.AgentCapabilities{
			ToolCalling: true, RAG: true, CodeExecution: true,
		},
	}
	got := agentCapList(a)
	if !strings.Contains(got, "tool-calling") {
		t.Errorf("expected 'tool-calling' in %q", got)
	}
	if !strings.Contains(got, "RAG") {
		t.Errorf("expected 'RAG' in %q", got)
	}
	if !strings.Contains(got, "code-exec") {
		t.Errorf("expected 'code-exec' in %q", got)
	}
}

func TestDashAgentCapListNone(t *testing.T) {
	t.Parallel()
	a := &agent.Agent{}
	got := agentCapList(a)
	if got != "none" {
		t.Errorf("expected 'none', got %q", got)
	}
}

func TestDashThreatOverallStatusCritical(t *testing.T) {
	t.Parallel()
	tm := &engine.ThreatModel{CriticalCount: 1}
	if got := threatOverallStatus(tm); got != "fail" {
		t.Errorf("expected fail, got %q", got)
	}
}

func TestDashThreatOverallStatusHigh(t *testing.T) {
	t.Parallel()
	tm := &engine.ThreatModel{HighCount: 2}
	if got := threatOverallStatus(tm); got != "warn" {
		t.Errorf("expected warn, got %q", got)
	}
}

func TestDashThreatOverallStatusClean(t *testing.T) {
	t.Parallel()
	tm := &engine.ThreatModel{}
	if got := threatOverallStatus(tm); got != "pass" {
		t.Errorf("expected pass, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Test utility helpers
// ---------------------------------------------------------------------------

func mkDashSectionIDs(d *DashboardData) map[string]bool {
	m := make(map[string]bool, len(d.Sections))
	for _, s := range d.Sections {
		m[s.ID] = true
	}
	return m
}

func mkDashFindSection(d *DashboardData, id string) *DashboardSection {
	for i := range d.Sections {
		if d.Sections[i].ID == id {
			return &d.Sections[i]
		}
	}
	return nil
}

func mkDashAssertHTMLContains(t *testing.T, html, substr string) {
	t.Helper()
	if !strings.Contains(html, substr) {
		t.Errorf("HTML output does not contain %q (length=%d)", substr, len(html))
	}
}
