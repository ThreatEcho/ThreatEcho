// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"fmt"
	"html/template"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ThreatEcho/threatecho/internal/gap"
	"github.com/ThreatEcho/threatecho/pkg/version"
)

// htmlReportData is the view model passed to the HTML template.
type htmlReportData struct {
	Version      string
	GeneratedAt  string
	GeneratedISO string

	// Summary cards.
	TotalCampaigns   int
	TotalStages      int
	TotalCompleted   int
	TotalSkipped     int
	UniqueTechniques int
	UniqueDetections int
	UniqueTelemetry  int

	// Risk.
	RiskScore    int
	RiskLevel    string
	RiskCritical int
	RiskHigh     int
	RiskMedium   int
	RiskLow      int
	TotalGaps    int

	// Framework.
	ATTACKStages int
	ATLASStages  int
	OWASPStages  int

	// Tactic grids.
	AttackTactics []htmlTactic
	AttackCovered int
	AttackTotal   int
	AttackPct     int

	AtlasTactics []htmlTactic
	AtlasCovered int
	AtlasTotal   int
	AtlasPct     int

	// Campaigns.
	Campaigns []htmlCampaign

	// Gaps grouped by risk.
	CriticalGaps []htmlGap
	HighGaps     []htmlGap
	MediumGaps   []htmlGap
	LowGaps      []htmlGap
}

type htmlTactic struct {
	Short   string
	Name    string
	Covered bool
	Stages  int
}

type htmlCampaign struct {
	Name      string
	Adversary string
	Stages    int
	Completed int
	Skipped   int
	Techs     int
	ATTACKCov string
	ATLASCov  string
}

type htmlGap struct {
	Campaign    string
	StageID     string
	StageName   string
	Technique   string
	TechName    string
	Tactic      string
	Type        string
	TypeLabel   string
	Risk        string
	Description string
}

// GapHTMLReport writes a self-contained HTML gap analysis report to w.
// The output is a single-file HTML document with embedded CSS — no external
// dependencies. Suitable for sharing with stakeholders, archiving, or
// uploading to dashboards.
func GapHTMLReport(w io.Writer, r *gap.GapReport) error {
	data := buildHTMLData(r)

	funcs := template.FuncMap{
		"fwPct": func(count, total int) int {
			if total == 0 {
				return 0
			}
			return count * 100 / total
		},
		"riskPct": func(count, total int) int {
			if total == 0 {
				return 0
			}
			return count * 100 / total
		},
	}

	tmpl, err := template.New("gap-report").Funcs(funcs).Parse(gapHTMLTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	return tmpl.Execute(w, data)
}

func buildHTMLData(r *gap.GapReport) htmlReportData {
	agg := r.Aggregate
	rs := r.RiskSummary

	d := htmlReportData{
		Version:      version.Version,
		GeneratedAt:  r.GeneratedAt.Format(time.RFC1123),
		GeneratedISO: r.GeneratedAt.Format(time.RFC3339),

		TotalCampaigns:   agg.TotalCampaigns,
		TotalStages:      agg.TotalStages,
		TotalCompleted:   agg.TotalCompleted,
		TotalSkipped:     agg.TotalSkipped,
		UniqueTechniques: agg.UniqueTechniques,
		UniqueDetections: agg.UniqueDetections,
		UniqueTelemetry:  agg.UniqueTelemetry,

		RiskScore:    int(math.Round(rs.Score)),
		RiskLevel:    riskLevel(rs.Score),
		RiskCritical: rs.Critical,
		RiskHigh:     rs.High,
		RiskMedium:   rs.Medium,
		RiskLow:      rs.Low,
		TotalGaps:    rs.Total,

		ATTACKStages: agg.Framework.ATTACKStages,
		ATLASStages:  agg.Framework.ATLASStages,
		OWASPStages:  agg.Framework.OWASPStages,
	}

	// ATT&CK tactics.
	d.AttackTotal = agg.AttackTactics.Total
	d.AttackCovered = agg.AttackTactics.Covered
	if d.AttackTotal > 0 {
		d.AttackPct = d.AttackCovered * 100 / d.AttackTotal
	}
	coveredSet := make(map[string]int)
	for _, dt := range agg.AttackTactics.Details {
		coveredSet[dt.Short] = dt.Stages
	}
	for _, short := range attackTacticOrder() {
		stages, ok := coveredSet[short]
		d.AttackTactics = append(d.AttackTactics, htmlTactic{
			Short:   short,
			Name:    formatTacticName(short),
			Covered: ok,
			Stages:  stages,
		})
	}

	// ATLAS tactics.
	d.AtlasTotal = agg.AtlasTactics.Total
	d.AtlasCovered = agg.AtlasTactics.Covered
	if d.AtlasTotal > 0 {
		d.AtlasPct = d.AtlasCovered * 100 / d.AtlasTotal
	}
	coveredSet = make(map[string]int)
	for _, dt := range agg.AtlasTactics.Details {
		coveredSet[dt.Short] = dt.Stages
	}
	for _, short := range atlasTacticOrder() {
		stages, ok := coveredSet[short]
		d.AtlasTactics = append(d.AtlasTactics, htmlTactic{
			Short:   short,
			Name:    formatTacticName(short),
			Covered: ok,
			Stages:  stages,
		})
	}

	// Campaigns.
	for _, c := range r.Campaigns {
		hc := htmlCampaign{
			Name:      c.Name,
			Adversary: c.Adversary,
			Stages:    c.Stages,
			Completed: c.Completed,
			Skipped:   c.Skipped,
			Techs:     c.TechniquesUsed,
		}
		if c.AttackTactics.Total > 0 {
			hc.ATTACKCov = fmt.Sprintf("%d/%d", c.AttackTactics.Covered, c.AttackTactics.Total)
		}
		if c.AtlasTactics.Total > 0 {
			hc.ATLASCov = fmt.Sprintf("%d/%d", c.AtlasTactics.Covered, c.AtlasTactics.Total)
		}
		d.Campaigns = append(d.Campaigns, hc)
	}

	// Gaps sorted by risk.
	for _, g := range r.Gaps {
		hg := htmlGap{
			Campaign:    g.CampaignName,
			StageID:     g.StageID,
			StageName:   g.StageName,
			Technique:   g.Technique,
			TechName:    g.TechniqueName,
			Tactic:      g.Tactic,
			Type:        string(g.Type),
			TypeLabel:   gapTypeHTMLLabel(g.Type),
			Risk:        g.Risk,
			Description: g.Description,
		}
		switch g.Risk {
		case "critical":
			d.CriticalGaps = append(d.CriticalGaps, hg)
		case "high":
			d.HighGaps = append(d.HighGaps, hg)
		case "medium":
			d.MediumGaps = append(d.MediumGaps, hg)
		case "low":
			d.LowGaps = append(d.LowGaps, hg)
		}
	}

	return d
}

func riskLevel(score float64) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 20:
		return "medium"
	default:
		return "low"
	}
}

func attackTacticOrder() []string {
	return []string{
		"reconnaissance", "resource-development", "initial-access",
		"execution", "persistence", "privilege-escalation",
		"defense-evasion", "credential-access", "discovery",
		"lateral-movement", "collection", "command-and-control",
		"exfiltration", "impact",
	}
}

func atlasTacticOrder() []string {
	return []string{
		"reconnaissance", "resource-development", "initial-access",
		"ml-attack-staging", "ml-model-access", "exfiltration", "impact",
	}
}

func formatTacticName(short string) string {
	parts := strings.Split(short, "-")
	for i, p := range parts {
		if p == "ml" {
			parts[i] = "ML"
		} else if p == "and" || p == "c2" {
			// keep lowercase
		} else if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

func gapTypeHTMLLabel(t gap.GapType) string {
	switch t {
	case gap.GapDetectionMissing:
		return "Detection Missing"
	case gap.GapTelemetryMissing:
		return "Telemetry Missing"
	case gap.GapTacticUncovered:
		return "Tactic Uncovered"
	default:
		return string(t)
	}
}

// sortGaps sorts gaps by tactic then technique for stable output.
func sortGaps(gaps []htmlGap) []htmlGap {
	sorted := make([]htmlGap, len(gaps))
	copy(sorted, gaps)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Tactic != sorted[j].Tactic {
			return sorted[i].Tactic < sorted[j].Tactic
		}
		return sorted[i].Technique < sorted[j].Technique
	})
	return sorted
}

const gapHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatEcho — Gap Analysis Report</title>
<style>
  :root {
    --bg: #f6f8fa;
    --surface: #ffffff;
    --surface-border: #d0d7de;
    --text: #1f2328;
    --text-secondary: #656d76;
    --text-muted: #8b949e;
    --green: #1a7f37;
    --green-bg: #dafbe1;
    --yellow: #9a6700;
    --yellow-bg: #fff8c5;
    --orange: #bc4c00;
    --orange-bg: #fff1e5;
    --red: #cf222e;
    --red-bg: #ffebe9;
    --blue: #0969da;
    --blue-bg: #ddf4ff;
    --accent: #0969da;
    --shadow: 0 1px 3px rgba(27,31,36,0.12), 0 1px 2px rgba(27,31,36,0.06);
    --radius: 8px;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --surface-border: #30363d;
      --text: #c9d1d9;
      --text-secondary: #8b949e;
      --text-muted: #656d76;
      --green: #3fb950;
      --green-bg: #0d2818;
      --yellow: #d29922;
      --yellow-bg: #2d1e00;
      --orange: #e3b341;
      --orange-bg: #341a00;
      --red: #f85149;
      --red-bg: #3d0c0c;
      --blue: #58a6ff;
      --blue-bg: #0c2d6b;
      --accent: #58a6ff;
      --shadow: 0 1px 3px rgba(0,0,0,0.3);
    }
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    padding: 24px;
    max-width: 1200px;
    margin: 0 auto;
  }

  /* Header */
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 32px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--surface-border);
    flex-wrap: wrap;
    gap: 8px;
  }
  .header h1 {
    font-size: 24px;
    font-weight: 700;
    letter-spacing: -0.5px;
  }
  .header h1 .accent { color: var(--accent); }
  .header .meta {
    font-size: 13px;
    color: var(--text-muted);
  }

  /* Summary cards */
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--surface-border);
    border-radius: var(--radius);
    padding: 20px;
    box-shadow: var(--shadow);
  }
  .card .label {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin-bottom: 4px;
  }
  .card .value {
    font-size: 32px;
    font-weight: 700;
    line-height: 1.2;
  }
  .card .sub {
    font-size: 13px;
    color: var(--text-secondary);
    margin-top: 4px;
  }
  .card.risk .value.critical { color: var(--red); }
  .card.risk .value.high { color: var(--orange); }
  .card.risk .value.medium { color: var(--yellow); }
  .card.risk .value.low { color: var(--green); }

  /* Sections */
  .section {
    background: var(--surface);
    border: 1px solid var(--surface-border);
    border-radius: var(--radius);
    padding: 24px;
    margin-bottom: 24px;
    box-shadow: var(--shadow);
  }
  .section h2 {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .section h2 .badge {
    font-size: 12px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 12px;
    color: white;
  }
  .badge-green { background: var(--green); }
  .badge-yellow { background: var(--yellow); }
  .badge-red { background: var(--red); }

  /* Framework bars */
  .fw-bars {
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
  }
  .fw-bar {
    flex: 1;
    min-width: 200px;
  }
  .fw-bar .fw-label {
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 6px;
    display: flex;
    justify-content: space-between;
  }
  .fw-bar .fw-track {
    height: 8px;
    background: var(--bg);
    border-radius: 4px;
    overflow: hidden;
  }
  .fw-bar .fw-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.3s;
  }
  .fw-fill.attack { background: var(--blue); }
  .fw-fill.atlas { background: var(--accent); }
  .fw-fill.owasp { background: var(--orange); }

  /* Tactic grid */
  .tactic-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }
  .tactic-header h2 { margin-bottom: 0; }
  .tactic-pct {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-secondary);
  }
  .tactic-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 8px;
  }
  .tactic-cell {
    padding: 12px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 500;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .tactic-cell.covered {
    background: var(--green-bg);
    color: var(--green);
    border: 1px solid var(--green);
  }
  .tactic-cell.missing {
    background: var(--red-bg);
    color: var(--red);
    border: 1px solid var(--red);
  }
  .tactic-cell .tactic-name { font-weight: 600; }
  .tactic-cell .tactic-count { font-size: 12px; opacity: 0.8; }

  /* Campaigns table */
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }
  th, td {
    text-align: left;
    padding: 10px 12px;
    border-bottom: 1px solid var(--surface-border);
  }
  th {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    background: var(--bg);
    position: sticky;
    top: 0;
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--bg); }
  td.mono { font-family: 'SF Mono', 'Consolas', 'Liberation Mono', monospace; font-size: 13px; }

  /* Gap list */
  .gap-group {
    margin-bottom: 20px;
  }
  .gap-group:last-child { margin-bottom: 0; }
  .gap-group-header {
    font-size: 14px;
    font-weight: 600;
    padding: 8px 0;
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
  }
  .gap-item {
    padding: 12px 16px;
    border-radius: 6px;
    margin-bottom: 6px;
    font-size: 13px;
  }
  .gap-item.critical {
    background: var(--red-bg);
    border-left: 3px solid var(--red);
  }
  .gap-item.high {
    background: var(--orange-bg);
    border-left: 3px solid var(--orange);
  }
  .gap-item.medium {
    background: var(--yellow-bg);
    border-left: 3px solid var(--yellow);
  }
  .gap-item.low {
    background: var(--green-bg);
    border-left: 3px solid var(--green);
  }
  .gap-title {
    font-weight: 600;
    margin-bottom: 4px;
  }
  .gap-detail {
    color: var(--text-secondary);
    font-size: 12px;
  }
  .gap-detail span { margin-right: 16px; }
  .gap-tag {
    display: inline-block;
    font-size: 11px;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  .gap-tag.detection_missing { background: var(--yellow-bg); color: var(--yellow); }
  .gap-tag.telemetry_missing { background: var(--orange-bg); color: var(--orange); }
  .gap-tag.tactic_uncovered { background: var(--red-bg); color: var(--red); }

  /* Risk bar */
  .risk-bar-container {
    margin-top: 16px;
  }
  .risk-bar-track {
    height: 12px;
    background: var(--bg);
    border-radius: 6px;
    overflow: hidden;
    display: flex;
    margin-bottom: 8px;
  }
  .risk-bar-segment {
    height: 100%;
    transition: width 0.3s;
  }
  .risk-bar-segment.critical { background: var(--red); }
  .risk-bar-segment.high { background: var(--orange); }
  .risk-bar-segment.medium { background: var(--yellow); }
  .risk-bar-segment.low { background: var(--green); }

  .risk-legend {
    display: flex;
    gap: 24px;
    font-size: 13px;
    flex-wrap: wrap;
  }
  .risk-legend-item {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .risk-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
  }
  .risk-dot.critical { background: var(--red); }
  .risk-dot.high { background: var(--orange); }
  .risk-dot.medium { background: var(--yellow); }
  .risk-dot.low { background: var(--green); }

  /* Footer */
  .footer {
    text-align: center;
    padding: 24px 0 8px;
    font-size: 12px;
    color: var(--text-muted);
    border-top: 1px solid var(--surface-border);
    margin-top: 16px;
  }

  /* Print */
  @media print {
    body { padding: 0; }
    .section { box-shadow: none; break-inside: avoid; }
    .card { box-shadow: none; }
    th { position: static; }
  }

  /* Responsive */
  @media (max-width: 600px) {
    body { padding: 12px; }
    .cards { grid-template-columns: repeat(2, 1fr); gap: 8px; }
    .card .value { font-size: 24px; }
    .tactic-grid { grid-template-columns: repeat(2, 1fr); }
    .fw-bars { flex-direction: column; }
    .header { flex-direction: column; align-items: flex-start; }
  }
</style>
</head>
<body>

<div class="header">
  <h1><span class="accent">ThreatEcho</span> — Detection Gap Analysis</h1>
  <div class="meta">
    <time datetime="{{.GeneratedISO}}">{{.GeneratedAt}}</time>
  </div>
</div>

<!-- Summary Cards -->
<div class="cards">
  <div class="card">
    <div class="label">Campaigns</div>
    <div class="value">{{.TotalCampaigns}}</div>
    <div class="sub">{{.TotalStages}} stages analyzed</div>
  </div>
  <div class="card">
    <div class="label">Techniques</div>
    <div class="value">{{.UniqueTechniques}}</div>
    <div class="sub">{{.UniqueDetections}} detections, {{.UniqueTelemetry}} telemetry</div>
  </div>
  <div class="card">
    <div class="label">Gaps Found</div>
    <div class="value">{{.TotalGaps}}</div>
    <div class="sub">{{.RiskCritical}} critical, {{.RiskHigh}} high</div>
  </div>
  <div class="card risk">
    <div class="label">Risk Score</div>
    <div class="value {{.RiskLevel}}">{{.RiskScore}}<span style="font-size:16px;font-weight:400">/100</span></div>
    <div class="sub">{{.RiskLevel}} risk</div>
  </div>
</div>

<!-- Framework Coverage -->
{{if or .ATTACKStages (or .ATLASStages .OWASPStages)}}
<div class="section">
  <h2>Framework Coverage</h2>
  <div class="fw-bars">
    {{if .ATTACKStages}}
    <div class="fw-bar">
      <div class="fw-label"><span>MITRE ATT&amp;CK</span><span>{{.ATTACKStages}} stages</span></div>
      <div class="fw-track"><div class="fw-fill attack" style="width: {{fwPct .ATTACKStages .TotalCompleted}}%"></div></div>
    </div>
    {{end}}
    {{if .ATLASStages}}
    <div class="fw-bar">
      <div class="fw-label"><span>MITRE ATLAS</span><span>{{.ATLASStages}} stages</span></div>
      <div class="fw-track"><div class="fw-fill atlas" style="width: {{fwPct .ATLASStages .TotalCompleted}}%"></div></div>
    </div>
    {{end}}
    {{if .OWASPStages}}
    <div class="fw-bar">
      <div class="fw-label"><span>OWASP LLM Top 10</span><span>{{.OWASPStages}} stages</span></div>
      <div class="fw-track"><div class="fw-fill owasp" style="width: {{fwPct .OWASPStages .TotalCompleted}}%"></div></div>
    </div>
    {{end}}
  </div>
</div>
{{end}}

<!-- ATT&CK Tactic Coverage -->
{{if .AttackTactics}}
<div class="section">
  <div class="tactic-header">
    <h2>ATT&amp;CK Tactic Coverage
      {{if ge .AttackPct 80}}<span class="badge badge-green">{{.AttackPct}}%</span>
      {{else if ge .AttackPct 50}}<span class="badge badge-yellow">{{.AttackPct}}%</span>
      {{else}}<span class="badge badge-red">{{.AttackPct}}%</span>
      {{end}}
    </h2>
    <span class="tactic-pct">{{.AttackCovered}} / {{.AttackTotal}} tactics</span>
  </div>
  <div class="tactic-grid">
    {{range .AttackTactics}}
    <div class="tactic-cell {{if .Covered}}covered{{else}}missing{{end}}">
      <span class="tactic-name">{{if .Covered}}✓{{else}}✗{{end}} {{.Name}}</span>
      {{if .Covered}}<span class="tactic-count">{{.Stages}} stage{{if ne .Stages 1}}s{{end}}</span>{{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}

<!-- ATLAS Tactic Coverage -->
{{if .AtlasTactics}}
<div class="section">
  <div class="tactic-header">
    <h2>ATLAS Tactic Coverage
      {{if ge .AtlasPct 80}}<span class="badge badge-green">{{.AtlasPct}}%</span>
      {{else if ge .AtlasPct 50}}<span class="badge badge-yellow">{{.AtlasPct}}%</span>
      {{else}}<span class="badge badge-red">{{.AtlasPct}}%</span>
      {{end}}
    </h2>
    <span class="tactic-pct">{{.AtlasCovered}} / {{.AtlasTotal}} tactics</span>
  </div>
  <div class="tactic-grid">
    {{range .AtlasTactics}}
    <div class="tactic-cell {{if .Covered}}covered{{else}}missing{{end}}">
      <span class="tactic-name">{{if .Covered}}✓{{else}}✗{{end}} {{.Name}}</span>
      {{if .Covered}}<span class="tactic-count">{{.Stages}} stage{{if ne .Stages 1}}s{{end}}</span>{{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}

<!-- Campaigns -->
{{if .Campaigns}}
<div class="section">
  <h2>Campaigns Analyzed</h2>
  <div style="overflow-x:auto">
  <table>
    <thead>
      <tr>
        <th>Campaign</th>
        <th>Adversary</th>
        <th>Stages</th>
        <th>Techniques</th>
        <th>ATT&amp;CK</th>
        <th>ATLAS</th>
      </tr>
    </thead>
    <tbody>
      {{range .Campaigns}}
      <tr>
        <td><strong>{{.Name}}</strong></td>
        <td>{{.Adversary}}</td>
        <td>{{.Completed}}{{if .Skipped}} <span style="color:var(--text-muted)">(+{{.Skipped}} skipped)</span>{{end}}</td>
        <td>{{.Techs}}</td>
        <td>{{if .ATTACKCov}}{{.ATTACKCov}}{{else}}—{{end}}</td>
        <td>{{if .ATLASCov}}{{.ATLASCov}}{{else}}—{{end}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  </div>
</div>
{{end}}

<!-- Gaps -->
<div class="section">
  <h2>Detection Gaps <span class="badge {{if ge .TotalGaps 10}}badge-red{{else if ge .TotalGaps 5}}badge-yellow{{else}}badge-green{{end}}">{{.TotalGaps}} issues</span></h2>

  {{if eq .TotalGaps 0}}
  <p style="color:var(--green);font-weight:600">✓ No detection gaps found — full coverage.</p>
  {{end}}

  {{if .CriticalGaps}}
  <div class="gap-group">
    <div class="gap-group-header"><span class="risk-dot critical"></span> Critical ({{len .CriticalGaps}})</div>
    {{range .CriticalGaps}}
    <div class="gap-item critical">
      <div class="gap-title">
        {{if .StageName}}{{.StageName}}{{else}}{{.Tactic}}{{end}}
        <span class="gap-tag {{.Type}}">{{.TypeLabel}}</span>
      </div>
      <div class="gap-detail">
        {{if .Campaign}}<span>📋 {{.Campaign}}</span>{{end}}
        {{if .StageID}}<span>🔗 {{.StageID}}</span>{{end}}
        {{if .Technique}}<span class="mono">{{.Technique}}</span>{{end}}
        {{if .TechName}}<span>{{.TechName}}</span>{{end}}
      </div>
      {{if .Description}}<div class="gap-detail" style="margin-top:4px">{{.Description}}</div>{{end}}
    </div>
    {{end}}
  </div>
  {{end}}

  {{if .HighGaps}}
  <div class="gap-group">
    <div class="gap-group-header"><span class="risk-dot high"></span> High ({{len .HighGaps}})</div>
    {{range .HighGaps}}
    <div class="gap-item high">
      <div class="gap-title">
        {{if .StageName}}{{.StageName}}{{else}}{{.Tactic}}{{end}}
        <span class="gap-tag {{.Type}}">{{.TypeLabel}}</span>
      </div>
      <div class="gap-detail">
        {{if .Campaign}}<span>📋 {{.Campaign}}</span>{{end}}
        {{if .StageID}}<span>🔗 {{.StageID}}</span>{{end}}
        {{if .Technique}}<span class="mono">{{.Technique}}</span>{{end}}
        {{if .TechName}}<span>{{.TechName}}</span>{{end}}
      </div>
      {{if .Description}}<div class="gap-detail" style="margin-top:4px">{{.Description}}</div>{{end}}
    </div>
    {{end}}
  </div>
  {{end}}

  {{if .MediumGaps}}
  <div class="gap-group">
    <div class="gap-group-header"><span class="risk-dot medium"></span> Medium ({{len .MediumGaps}})</div>
    {{range .MediumGaps}}
    <div class="gap-item medium">
      <div class="gap-title">
        {{if .StageName}}{{.StageName}}{{else}}{{.Tactic}}{{end}}
        <span class="gap-tag {{.Type}}">{{.TypeLabel}}</span>
      </div>
      <div class="gap-detail">
        {{if .Campaign}}<span>📋 {{.Campaign}}</span>{{end}}
        {{if .StageID}}<span>🔗 {{.StageID}}</span>{{end}}
        {{if .Technique}}<span class="mono">{{.Technique}}</span>{{end}}
        {{if .TechName}}<span>{{.TechName}}</span>{{end}}
      </div>
      {{if .Description}}<div class="gap-detail" style="margin-top:4px">{{.Description}}</div>{{end}}
    </div>
    {{end}}
  </div>
  {{end}}

  {{if .LowGaps}}
  <div class="gap-group">
    <div class="gap-group-header"><span class="risk-dot low"></span> Low ({{len .LowGaps}})</div>
    {{range .LowGaps}}
    <div class="gap-item low">
      <div class="gap-title">
        {{if .StageName}}{{.StageName}}{{else}}{{.Tactic}}{{end}}
        <span class="gap-tag {{.Type}}">{{.TypeLabel}}</span>
      </div>
      <div class="gap-detail">
        {{if .Campaign}}<span>📋 {{.Campaign}}</span>{{end}}
        {{if .StageID}}<span>🔗 {{.StageID}}</span>{{end}}
        {{if .Technique}}<span class="mono">{{.Technique}}</span>{{end}}
        {{if .TechName}}<span>{{.TechName}}</span>{{end}}
      </div>
      {{if .Description}}<div class="gap-detail" style="margin-top:4px">{{.Description}}</div>{{end}}
    </div>
    {{end}}
  </div>
  {{end}}
</div>

<!-- Risk Summary -->
<div class="section">
  <h2>Risk Summary</h2>
  <div class="risk-bar-container">
    <div class="risk-bar-track">
      {{if .RiskCritical}}<div class="risk-bar-segment critical" style="width: {{riskPct .RiskCritical .TotalGaps}}%"></div>{{end}}
      {{if .RiskHigh}}<div class="risk-bar-segment high" style="width: {{riskPct .RiskHigh .TotalGaps}}%"></div>{{end}}
      {{if .RiskMedium}}<div class="risk-bar-segment medium" style="width: {{riskPct .RiskMedium .TotalGaps}}%"></div>{{end}}
      {{if .RiskLow}}<div class="risk-bar-segment low" style="width: {{riskPct .RiskLow .TotalGaps}}%"></div>{{end}}
    </div>
    <div class="risk-legend">
      <div class="risk-legend-item"><span class="risk-dot critical"></span> Critical: {{.RiskCritical}}</div>
      <div class="risk-legend-item"><span class="risk-dot high"></span> High: {{.RiskHigh}}</div>
      <div class="risk-legend-item"><span class="risk-dot medium"></span> Medium: {{.RiskMedium}}</div>
      <div class="risk-legend-item"><span class="risk-dot low"></span> Low: {{.RiskLow}}</div>
    </div>
  </div>
</div>

<div class="footer">
  Generated by ThreatEcho v{{.Version}} · <a href="https://github.com/ThreatEcho/threatecho" style="color:var(--accent)">github.com/ThreatEcho/threatecho</a>
</div>

</body>
</html>`
