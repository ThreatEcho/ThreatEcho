// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/policy"
	"github.com/ThreatEcho/threatecho/pkg/version"
)

// ---------------------------------------------------------------------------
// Dashboard types
// ---------------------------------------------------------------------------

// DashboardData is the top-level structure passed to the HTML template.
type DashboardData struct {
	Title       string             `json:"title"`
	GeneratedAt string             `json:"generated_at"`
	Version     string             `json:"version"`
	AgentCount  int                `json:"agent_count"`
	PolicyCount int                `json:"policy_count"`
	RiskGrade   string             `json:"risk_grade"`
	RiskScore   float64            `json:"risk_score"`
	Sections    []DashboardSection `json:"sections"`
}

// DashboardSection is one visual block in the dashboard.
type DashboardSection struct {
	ID      string            `json:"id"`
	Title   string            `json:"title"`
	Type    string            `json:"type"`   // summary, table, chart_data, findings, checklist
	Status  string            `json:"status"` // pass, warn, fail, info
	Items   []DashboardItem   `json:"items"`
	Metrics []DashboardMetric `json:"metrics,omitempty"`
}

// DashboardItem is one row inside a section.
type DashboardItem struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Status string `json:"status,omitempty"` // pass, warn, fail, info
	Detail string `json:"detail,omitempty"`
}

// DashboardMetric is a numeric gauge with a max (for progress bars).
type DashboardMetric struct {
	Label string  `json:"label"`
	Value float64 `json:"value"`
	Max   float64 `json:"max"`
	Unit  string  `json:"unit"` // percent, count, score
}

// DashboardConfig controls which sections are included.
type DashboardConfig struct {
	Title          string `json:"title"`
	IncludeRisk    bool   `json:"include_risk"`
	IncludeLint    bool   `json:"include_lint"`
	IncludeThreats bool   `json:"include_threats"`
	IncludeAgents  bool   `json:"include_agents"`
	IncludePolicy  bool   `json:"include_policy"`
}

// DashboardOption is a functional option for BuildDashboard.
type DashboardOption func(*dashboardBuilder)

// dashboardBuilder accumulates optional inputs.
type dashboardBuilder struct {
	riskPosture *engine.RiskPosture
	lintReport  *policy.LintReport
	threatModel *engine.ThreatModel
	inventory   *agent.Inventory
	policies    []*policy.Policy
}

// ---------------------------------------------------------------------------
// Functional option constructors
// ---------------------------------------------------------------------------

// WithRiskPosture attaches a risk posture to the dashboard.
func WithRiskPosture(rp *engine.RiskPosture) DashboardOption {
	return func(b *dashboardBuilder) { b.riskPosture = rp }
}

// WithLintReport attaches a lint report to the dashboard.
func WithLintReport(lr *policy.LintReport) DashboardOption {
	return func(b *dashboardBuilder) { b.lintReport = lr }
}

// WithThreatModel attaches a threat model to the dashboard.
func WithThreatModel(tm *engine.ThreatModel) DashboardOption {
	return func(b *dashboardBuilder) { b.threatModel = tm }
}

// WithAgentInventory attaches an agent inventory to the dashboard.
func WithAgentInventory(inv *agent.Inventory) DashboardOption {
	return func(b *dashboardBuilder) { b.inventory = inv }
}

// WithPolicies attaches a slice of policies to the dashboard.
func WithPolicies(policies []*policy.Policy) DashboardOption {
	return func(b *dashboardBuilder) { b.policies = policies }
}

// ---------------------------------------------------------------------------
// Default config
// ---------------------------------------------------------------------------

// DefaultDashboardConfig returns a config with all sections enabled and a
// sensible default title.
func DefaultDashboardConfig() DashboardConfig {
	return DashboardConfig{
		Title:          "ThreatEcho Security Dashboard",
		IncludeRisk:    true,
		IncludeLint:    true,
		IncludeThreats: true,
		IncludeAgents:  true,
		IncludePolicy:  true,
	}
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

// BuildDashboard assembles a DashboardData from the supplied config and
// optional inputs. Nil options are silently ignored; sections that lack the
// required input are omitted even when enabled in the config.
func BuildDashboard(cfg DashboardConfig, opts ...DashboardOption) *DashboardData {
	b := &dashboardBuilder{}
	for _, o := range opts {
		if o != nil {
			o(b)
		}
	}

	d := &DashboardData{
		Title:       cfg.Title,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Version:     version.Version,
	}

	if d.Title == "" {
		d.Title = "ThreatEcho Security Dashboard"
	}

	// Populate counts.
	if b.inventory != nil {
		d.AgentCount = len(b.inventory.Agents)
	}
	d.PolicyCount = len(b.policies)

	if b.riskPosture != nil {
		d.RiskGrade = b.riskPosture.Grade
		d.RiskScore = b.riskPosture.OverallScore
	}

	// Executive summary is always included.
	d.Sections = append(d.Sections, buildExecSummary(d, b))

	if cfg.IncludeRisk && b.riskPosture != nil {
		d.Sections = append(d.Sections, buildRiskSection(b.riskPosture))
	}
	if cfg.IncludeLint && b.lintReport != nil {
		d.Sections = append(d.Sections, buildLintSection(b.lintReport))
	}
	if cfg.IncludeThreats && b.threatModel != nil {
		d.Sections = append(d.Sections, buildThreatSection(b.threatModel))
	}
	if cfg.IncludeAgents && b.inventory != nil {
		d.Sections = append(d.Sections, buildAgentSection(b.inventory))
	}
	if cfg.IncludePolicy && len(b.policies) > 0 {
		d.Sections = append(d.Sections, buildPolicySection(b.policies))
	}

	// Recommendations are always included when there is something to say.
	if rec := buildRecommendations(b); len(rec.Items) > 0 {
		d.Sections = append(d.Sections, rec)
	}

	return d
}

// ---------------------------------------------------------------------------
// Section builders
// ---------------------------------------------------------------------------

func buildExecSummary(d *DashboardData, b *dashboardBuilder) DashboardSection {
	sec := DashboardSection{
		ID:    "exec-summary",
		Title: "Executive Summary",
		Type:  "summary",
	}

	grade := d.RiskGrade
	if grade == "" {
		grade = "N/A"
	}

	sec.Items = []DashboardItem{
		{Label: "Risk Grade", Value: grade, Status: gradeStatus(grade)},
		{Label: "Agents Assessed", Value: fmt.Sprintf("%d", d.AgentCount)},
		{Label: "Policies Evaluated", Value: fmt.Sprintf("%d", d.PolicyCount)},
	}

	if b.riskPosture != nil {
		sec.Items = append(sec.Items, DashboardItem{
			Label:  "Overall Score",
			Value:  fmt.Sprintf("%.0f%%", (1.0-b.riskPosture.OverallScore)*100),
			Status: gradeStatus(b.riskPosture.Grade),
		})
		sec.Items = append(sec.Items, DashboardItem{
			Label: "Total Findings",
			Value: fmt.Sprintf("%d", b.riskPosture.TotalFindings),
		})
		sec.Items = append(sec.Items, DashboardItem{
			Label:  "Critical Findings",
			Value:  fmt.Sprintf("%d", b.riskPosture.CriticalFindings),
			Status: critStatus(b.riskPosture.CriticalFindings),
		})
	}

	if b.threatModel != nil {
		sec.Items = append(sec.Items, DashboardItem{
			Label: "Threats Identified",
			Value: fmt.Sprintf("%d", b.threatModel.ThreatCount),
		})
	}

	sec.Status = overallStatus(b)
	return sec
}

func buildRiskSection(rp *engine.RiskPosture) DashboardSection {
	sec := DashboardSection{
		ID:     "risk-assessment",
		Title:  "Risk Assessment",
		Type:   "chart_data",
		Status: gradeStatus(rp.Grade),
	}

	sec.Metrics = []DashboardMetric{
		{Label: "Risk Score", Value: rp.OverallScore * 100, Max: 100, Unit: "percent"},
	}

	sec.Items = []DashboardItem{
		{Label: "Grade", Value: rp.Grade, Status: gradeStatus(rp.Grade)},
		{Label: "Verdict", Value: rp.Verdict},
		{Label: "Total Findings", Value: fmt.Sprintf("%d", rp.TotalFindings)},
		{Label: "Critical Findings", Value: fmt.Sprintf("%d", rp.CriticalFindings), Status: critStatus(rp.CriticalFindings)},
	}

	for _, dim := range rp.Dimensions {
		status := "info"
		if !dim.Available {
			status = "info"
		} else if dim.Score >= 0.70 {
			status = "fail"
		} else if dim.Score >= 0.30 {
			status = "warn"
		} else {
			status = "pass"
		}
		sec.Items = append(sec.Items, DashboardItem{
			Label:  dim.Name,
			Value:  fmt.Sprintf("%.0f%%", dim.Score*100),
			Status: status,
			Detail: dim.Details,
		})
		sec.Metrics = append(sec.Metrics, DashboardMetric{
			Label: dim.Name,
			Value: dim.Score * 100,
			Max:   100,
			Unit:  "percent",
		})
	}

	for _, r := range rp.TopRisks {
		sec.Items = append(sec.Items, DashboardItem{
			Label:  "Top Risk",
			Value:  r,
			Status: "warn",
		})
	}

	return sec
}

func buildLintSection(lr *policy.LintReport) DashboardSection {
	sec := DashboardSection{
		ID:     "policy-quality",
		Title:  "Policy Quality",
		Type:   "findings",
		Status: gradeStatus(lr.Grade),
	}

	sec.Metrics = []DashboardMetric{
		{Label: "Lint Score", Value: lr.Score * 100, Max: 100, Unit: "percent"},
	}

	sec.Items = []DashboardItem{
		{Label: "Policy", Value: lr.PolicyName},
		{Label: "Grade", Value: lr.Grade, Status: gradeStatus(lr.Grade)},
		{Label: "Total Rules", Value: fmt.Sprintf("%d", lr.TotalRules)},
		{Label: "Findings", Value: fmt.Sprintf("%d", lr.FindingCount)},
		{Label: "Errors", Value: fmt.Sprintf("%d", lr.ErrorCount), Status: critStatus(lr.ErrorCount)},
		{Label: "Warnings", Value: fmt.Sprintf("%d", lr.WarningCount), Status: warnStatus(lr.WarningCount)},
		{Label: "Info", Value: fmt.Sprintf("%d", lr.InfoCount)},
		{Label: "Style", Value: fmt.Sprintf("%d", lr.StyleCount)},
	}

	for _, f := range lr.Findings {
		sec.Items = append(sec.Items, DashboardItem{
			Label:  fmt.Sprintf("[%s] %s", f.Severity, f.Rule),
			Value:  f.Message,
			Status: lintSevStatus(f.Severity),
			Detail: f.Suggestion,
		})
	}

	return sec
}

func buildThreatSection(tm *engine.ThreatModel) DashboardSection {
	sec := DashboardSection{
		ID:     "threat-analysis",
		Title:  "Threat Analysis",
		Type:   "table",
		Status: threatOverallStatus(tm),
	}

	sec.Metrics = []DashboardMetric{
		{Label: "Overall Risk", Value: tm.OverallRisk, Max: 10, Unit: "score"},
		{Label: "Threat Count", Value: float64(tm.ThreatCount), Max: float64(tm.ThreatCount), Unit: "count"},
	}

	sec.Items = []DashboardItem{
		{Label: "Threats", Value: fmt.Sprintf("%d", tm.ThreatCount)},
		{Label: "Critical", Value: fmt.Sprintf("%d", tm.CriticalCount), Status: critStatus(tm.CriticalCount)},
		{Label: "High", Value: fmt.Sprintf("%d", tm.HighCount), Status: warnStatus(tm.HighCount)},
		{Label: "Medium", Value: fmt.Sprintf("%d", tm.MediumCount)},
		{Label: "Low", Value: fmt.Sprintf("%d", tm.LowCount)},
		{Label: "Mitigated", Value: fmt.Sprintf("%d", tm.MitigatedCount), Status: "pass"},
		{Label: "Partial", Value: fmt.Sprintf("%d", tm.PartialCount), Status: "warn"},
		{Label: "Unmitigated", Value: fmt.Sprintf("%d", tm.UnmitigatedCount), Status: critStatus(tm.UnmitigatedCount)},
	}

	// STRIDE breakdown.
	for _, cat := range strideCategories {
		if c, ok := tm.CategoryBreakdown[engine.ThreatCategory(cat)]; ok && c > 0 {
			sec.Items = append(sec.Items, DashboardItem{
				Label: cat,
				Value: fmt.Sprintf("%d", c),
			})
		}
	}

	// Top threats.
	for _, t := range tm.Threats {
		sec.Items = append(sec.Items, DashboardItem{
			Label:  fmt.Sprintf("%s [%s]", t.ID, t.Severity),
			Value:  t.Title,
			Status: severityStatus(t.Severity),
			Detail: fmt.Sprintf("Agent: %s | Status: %s | Risk: %.1f", t.AffectedAgent, t.MitigationStatus, t.RiskScore),
		})
	}

	return sec
}

func buildAgentSection(inv *agent.Inventory) DashboardSection {
	sec := DashboardSection{
		ID:     "agent-inventory",
		Title:  "Agent Inventory",
		Type:   "table",
		Status: "info",
	}

	sec.Metrics = []DashboardMetric{
		{Label: "Total Agents", Value: float64(len(inv.Agents)), Max: float64(len(inv.Agents)), Unit: "count"},
	}

	for _, a := range inv.Agents {
		if a == nil {
			continue
		}
		toolCount := len(a.Tools)
		capList := agentCapList(a)
		status := trustStatus(a.Trust.Level)
		sec.Items = append(sec.Items, DashboardItem{
			Label:  a.Meta.Name,
			Value:  fmt.Sprintf("%s | Trust: %s | Tools: %d", a.Meta.Type, a.Trust.Level, toolCount),
			Status: status,
			Detail: capList,
		})
	}

	return sec
}

func buildPolicySection(policies []*policy.Policy) DashboardSection {
	sec := DashboardSection{
		ID:     "policy-overview",
		Title:  "Policy Overview",
		Type:   "table",
		Status: "info",
	}

	sec.Metrics = []DashboardMetric{
		{Label: "Total Policies", Value: float64(len(policies)), Max: float64(len(policies)), Unit: "count"},
	}

	for _, p := range policies {
		if p == nil {
			continue
		}
		effects := map[string]int{}
		for _, r := range p.Rules {
			effects[r.Effect]++
		}
		summary := fmt.Sprintf("%d rules (deny:%d allow:%d alert:%d)",
			len(p.Rules), effects["deny"], effects["allow"], effects["alert"])
		sec.Items = append(sec.Items, DashboardItem{
			Label:  p.Meta.Name,
			Value:  summary,
			Status: "info",
			Detail: fmt.Sprintf("Agent: %s", p.Agent.Name),
		})
	}

	return sec
}

func buildRecommendations(b *dashboardBuilder) DashboardSection {
	sec := DashboardSection{
		ID:     "recommendations",
		Title:  "Recommendations",
		Type:   "checklist",
		Status: "info",
	}

	if b.riskPosture != nil {
		for _, r := range b.riskPosture.Recommendations {
			pri := "info"
			if strings.HasPrefix(r, "CRITICAL:") {
				pri = "fail"
			} else if strings.HasPrefix(r, "HIGH:") {
				pri = "warn"
			}
			sec.Items = append(sec.Items, DashboardItem{
				Label:  "Risk",
				Value:  r,
				Status: pri,
			})
		}
	}

	if b.lintReport != nil && b.lintReport.ErrorCount > 0 {
		sec.Items = append(sec.Items, DashboardItem{
			Label:  "Lint",
			Value:  fmt.Sprintf("Fix %d lint errors in policy %q", b.lintReport.ErrorCount, b.lintReport.PolicyName),
			Status: "fail",
		})
	}

	if b.threatModel != nil && b.threatModel.UnmitigatedCount > 0 {
		sec.Items = append(sec.Items, DashboardItem{
			Label:  "Threats",
			Value:  fmt.Sprintf("Address %d unmitigated threats", b.threatModel.UnmitigatedCount),
			Status: "warn",
		})
	}

	if b.inventory == nil {
		sec.Items = append(sec.Items, DashboardItem{
			Label:  "Agents",
			Value:  "Run agent inventory assessment",
			Status: "info",
		})
	}

	if len(b.policies) == 0 {
		sec.Items = append(sec.Items, DashboardItem{
			Label:  "Policy",
			Value:  "Define and evaluate agent policies",
			Status: "info",
		})
	}

	return sec
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

// strideCategories lists the STRIDE category strings for dashboard display.
var strideCategories = []string{
	"spoofing", "tampering", "repudiation",
	"information_disclosure", "denial_of_service", "elevation_of_privilege",
}

func gradeStatus(grade string) string {
	switch grade {
	case "A":
		return "pass"
	case "B":
		return "pass"
	case "C":
		return "warn"
	case "D":
		return "warn"
	case "F":
		return "fail"
	default:
		return "info"
	}
}

func critStatus(count int) string {
	if count > 0 {
		return "fail"
	}
	return "pass"
}

func warnStatus(count int) string {
	if count > 0 {
		return "warn"
	}
	return "pass"
}

func lintSevStatus(sev policy.LintSeverity) string {
	switch sev {
	case policy.LintError:
		return "fail"
	case policy.LintWarning:
		return "warn"
	case policy.LintInfo:
		return "info"
	default:
		return "info"
	}
}

func severityStatus(sev string) string {
	switch sev {
	case "critical":
		return "fail"
	case "high":
		return "warn"
	case "medium":
		return "info"
	default:
		return "info"
	}
}

func trustStatus(level string) string {
	switch level {
	case agent.TrustAdmin, agent.TrustElevated:
		return "warn"
	case agent.TrustUntrusted:
		return "fail"
	default:
		return "info"
	}
}

func threatOverallStatus(tm *engine.ThreatModel) string {
	switch {
	case tm.CriticalCount > 0:
		return "fail"
	case tm.HighCount > 0:
		return "warn"
	default:
		return "pass"
	}
}

func overallStatus(b *dashboardBuilder) string {
	if b.riskPosture != nil {
		return gradeStatus(b.riskPosture.Grade)
	}
	return "info"
}

func agentCapList(a *agent.Agent) string {
	var caps []string
	if a.Capabilities.ToolCalling {
		caps = append(caps, "tool-calling")
	}
	if a.Capabilities.RAG {
		caps = append(caps, "RAG")
	}
	if a.Capabilities.CodeExecution {
		caps = append(caps, "code-exec")
	}
	if a.Capabilities.WebAccess {
		caps = append(caps, "web")
	}
	if a.Capabilities.FileAccess {
		caps = append(caps, "files")
	}
	if a.Capabilities.MessagePassing {
		caps = append(caps, "messaging")
	}
	if a.Capabilities.Memory {
		caps = append(caps, "memory")
	}
	if a.Capabilities.Autonomous {
		caps = append(caps, "autonomous")
	}
	if len(caps) == 0 {
		return "none"
	}
	return strings.Join(caps, ", ")
}

// ---------------------------------------------------------------------------
// Render to HTML
// ---------------------------------------------------------------------------

// RenderDashboard renders a DashboardData to an HTML string using the
// embedded template. The output is a self-contained HTML document with
// inline CSS; no external dependencies are required.
func RenderDashboard(d *DashboardData) (string, error) {
	if d == nil {
		return "", fmt.Errorf("dashboard data is nil")
	}

	funcs := template.FuncMap{
		"statusIcon": func(s string) template.HTML {
			switch s {
			case "pass":
				return "&#x2713;"
			case "warn":
				return "&#x26A0;"
			case "fail":
				return "&#x2717;"
			default:
				return "&#x2139;"
			}
		},
		"statusClass": func(s string) string {
			switch s {
			case "pass":
				return "status-pass"
			case "warn":
				return "status-warn"
			case "fail":
				return "status-fail"
			default:
				return "status-info"
			}
		},
		"gradeStatusFn": func(grade string) string {
			return gradeStatus(grade)
		},
		"metricPct": func(m DashboardMetric) int {
			if m.Max <= 0 {
				return 0
			}
			pct := int(m.Value * 100 / m.Max)
			if pct > 100 {
				pct = 100
			}
			if pct < 0 {
				pct = 0
			}
			return pct
		},
		"metricDisplay": func(m DashboardMetric) string {
			switch m.Unit {
			case "percent":
				return fmt.Sprintf("%.0f%%", m.Value)
			case "score":
				return fmt.Sprintf("%.1f / %.0f", m.Value, m.Max)
			default:
				return fmt.Sprintf("%.0f", m.Value)
			}
		},
	}

	tmpl, err := template.New("dashboard").Funcs(funcs).Parse(dashboardHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("parsing dashboard template: %w", err)
	}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, d); err != nil {
		return "", fmt.Errorf("executing dashboard template: %w", err)
	}

	return sb.String(), nil
}

// ---------------------------------------------------------------------------
// Write to file
// ---------------------------------------------------------------------------

// WriteDashboard renders the dashboard to HTML and writes it to path.
func WriteDashboard(d *DashboardData, path string) error {
	html, err := RenderDashboard(d)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(html), 0o644)
}

// ---------------------------------------------------------------------------
// Text fallback
// ---------------------------------------------------------------------------

// FormatDashboardText renders a plain-text version of the dashboard,
// suitable for terminal output or piping into other tools.
func FormatDashboardText(d *DashboardData) string {
	if d == nil {
		return "No dashboard data available.\n"
	}

	var sb strings.Builder

	sb.WriteString("=============================================================\n")
	sb.WriteString(fmt.Sprintf("  %s\n", d.Title))
	sb.WriteString(fmt.Sprintf("  Generated: %s   Version: %s\n", d.GeneratedAt, d.Version))
	sb.WriteString("=============================================================\n\n")

	sb.WriteString(fmt.Sprintf("  Risk Grade: %-4s  Score: %.2f\n", d.RiskGrade, d.RiskScore))
	sb.WriteString(fmt.Sprintf("  Agents: %-6d  Policies: %d\n\n", d.AgentCount, d.PolicyCount))

	for _, sec := range d.Sections {
		icon := "i"
		switch sec.Status {
		case "pass":
			icon = "+"
		case "warn":
			icon = "!"
		case "fail":
			icon = "x"
		}

		sb.WriteString(fmt.Sprintf("[%s] %s\n", icon, sec.Title))
		sb.WriteString(strings.Repeat("-", 60) + "\n")

		for _, m := range sec.Metrics {
			switch m.Unit {
			case "percent":
				sb.WriteString(fmt.Sprintf("  %-30s %.0f%%\n", m.Label, m.Value))
			case "score":
				sb.WriteString(fmt.Sprintf("  %-30s %.1f / %.0f\n", m.Label, m.Value, m.Max))
			default:
				sb.WriteString(fmt.Sprintf("  %-30s %.0f\n", m.Label, m.Value))
			}
		}

		for _, it := range sec.Items {
			marker := " "
			switch it.Status {
			case "pass":
				marker = "+"
			case "warn":
				marker = "!"
			case "fail":
				marker = "x"
			}
			sb.WriteString(fmt.Sprintf("  %s %-28s %s\n", marker, it.Label, it.Value))
			if it.Detail != "" {
				sb.WriteString(fmt.Sprintf("    %s\n", it.Detail))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// ---------------------------------------------------------------------------
// HTML template
// ---------------------------------------------------------------------------

const dashboardHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root {
  --bg: #f8f9fa;
  --bg-card: #ffffff;
  --fg: #1a1a2e;
  --fg-muted: #6c757d;
  --border: #dee2e6;
  --accent: #0d6efd;
  --pass: #198754;
  --warn: #fd7e14;
  --fail: #dc3545;
  --info: #0dcaf0;
  --bar-bg: #e9ecef;
  --shadow: 0 1px 3px rgba(0,0,0,0.08);
  color-scheme: light dark;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #121212;
    --bg-card: #1e1e2e;
    --fg: #e0e0e0;
    --fg-muted: #9e9e9e;
    --border: #333;
    --accent: #4dabf7;
    --pass: #40c057;
    --warn: #ffa94d;
    --fail: #ff6b6b;
    --info: #66d9ef;
    --bar-bg: #2a2a3a;
    --shadow: 0 1px 3px rgba(0,0,0,0.3);
  }
}

:root[data-theme="dark"] {
  --bg: #121212;
  --bg-card: #1e1e2e;
  --fg: #e0e0e0;
  --fg-muted: #9e9e9e;
  --border: #333;
  --accent: #4dabf7;
  --pass: #40c057;
  --warn: #ffa94d;
  --fail: #ff6b6b;
  --info: #66d9ef;
  --bar-bg: #2a2a3a;
  --shadow: 0 1px 3px rgba(0,0,0,0.3);
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--fg);
  line-height: 1.5;
  padding: 16px;
  max-width: 1200px;
  margin: 0 auto;
}

header {
  text-align: center;
  padding: 24px 0;
  border-bottom: 2px solid var(--border);
  margin-bottom: 24px;
}

header h1 { font-size: 1.8rem; margin-bottom: 4px; }
header .meta { color: var(--fg-muted); font-size: 0.85rem; }

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}

.summary-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
  box-shadow: var(--shadow);
}

.summary-card .label { font-size: 0.75rem; color: var(--fg-muted); text-transform: uppercase; letter-spacing: 0.05em; }
.summary-card .value { font-size: 1.6rem; font-weight: 700; margin-top: 4px; }

.section {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 20px;
  box-shadow: var(--shadow);
  overflow: hidden;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
  font-weight: 600;
  font-size: 1.05rem;
}

.badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px; height: 24px;
  border-radius: 50%;
  font-size: 0.8rem;
  flex-shrink: 0;
}

.status-pass  { color: var(--pass); }
.status-warn  { color: var(--warn); }
.status-fail  { color: var(--fail); }
.status-info  { color: var(--info); }

.badge.status-pass { background: var(--pass); color: #fff; }
.badge.status-warn { background: var(--warn); color: #fff; }
.badge.status-fail { background: var(--fail); color: #fff; }
.badge.status-info { background: var(--info); color: #fff; }

.section-body { padding: 16px; }

.metric-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
}

.metric-label { flex: 0 0 180px; font-size: 0.85rem; color: var(--fg-muted); }

.metric-bar {
  flex: 1;
  height: 20px;
  background: var(--bar-bg);
  border-radius: 4px;
  overflow: hidden;
  position: relative;
}

.metric-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.3s ease;
  background: var(--accent);
}

.metric-value { flex: 0 0 60px; text-align: right; font-size: 0.85rem; font-weight: 600; }

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.85rem;
}

th, td {
  padding: 8px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

th {
  font-weight: 600;
  color: var(--fg-muted);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.item-detail { font-size: 0.8rem; color: var(--fg-muted); margin-top: 2px; }

footer {
  text-align: center;
  padding: 20px 0;
  color: var(--fg-muted);
  font-size: 0.8rem;
  border-top: 1px solid var(--border);
  margin-top: 24px;
}

@media (max-width: 600px) {
  body { padding: 12px; }
  .summary-grid { grid-template-columns: repeat(2, 1fr); }
  .metric-label { flex: 0 0 100px; }
  .section-body { overflow-x: auto; }
}

@media print {
  body { background: #fff; color: #000; }
  .section { break-inside: avoid; box-shadow: none; border-color: #ccc; }
  header { border-bottom-color: #ccc; }
  footer { border-top-color: #ccc; }
}
</style>
</head>
<body>

<header>
  <h1>{{.Title}}</h1>
  <div class="meta">Generated {{.GeneratedAt}} &middot; ThreatEcho {{.Version}}</div>
</header>

<div class="summary-grid">
  <div class="summary-card">
    <div class="label">Risk Grade</div>
    <div class="value {{if .RiskGrade}}{{statusClass (gradeStatusFn .RiskGrade)}}{{end}}">{{if .RiskGrade}}{{.RiskGrade}}{{else}}N/A{{end}}</div>
  </div>
  <div class="summary-card">
    <div class="label">Risk Score</div>
    <div class="value">{{printf "%.0f" .RiskScore}}</div>
  </div>
  <div class="summary-card">
    <div class="label">Agents</div>
    <div class="value">{{.AgentCount}}</div>
  </div>
  <div class="summary-card">
    <div class="label">Policies</div>
    <div class="value">{{.PolicyCount}}</div>
  </div>
</div>

{{range .Sections}}
<div class="section">
  <div class="section-header">
    <span class="badge {{statusClass .Status}}">{{statusIcon .Status}}</span>
    {{.Title}}
  </div>
  <div class="section-body">
    {{if .Metrics}}
    {{range .Metrics}}
    <div class="metric-row">
      <span class="metric-label">{{.Label}}</span>
      <div class="metric-bar"><div class="metric-fill" style="width:{{metricPct .}}%"></div></div>
      <span class="metric-value">{{metricDisplay .}}</span>
    </div>
    {{end}}
    {{end}}

    {{if .Items}}
    <table>
      <thead><tr><th>Status</th><th>Label</th><th>Value</th></tr></thead>
      <tbody>
      {{range .Items}}
      <tr>
        <td><span class="{{statusClass .Status}}">{{statusIcon .Status}}</span></td>
        <td>{{.Label}}</td>
        <td>
          {{.Value}}
          {{if .Detail}}<div class="item-detail">{{.Detail}}</div>{{end}}
        </td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{end}}
  </div>
</div>
{{end}}

<footer>
  ThreatEcho {{.Version}} &middot; Detection Engineering for AI Agents
</footer>

</body>
</html>`
