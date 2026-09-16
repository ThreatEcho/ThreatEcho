// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

// Baseline represents the expected behavioral profile of a set of campaigns.
// It captures the "normal" state — which tools, tactics, techniques, and
// execution patterns are used — so that deviations can be detected as drift.
type Baseline struct {
	Version      string            `json:"version"`
	Label        string            `json:"label"`
	Campaigns    int               `json:"campaigns"`
	Stages       int               `json:"stages"`
	Tools        map[string]int    `json:"tools"`      // exec type → count
	Tactics      map[string]int    `json:"tactics"`    // tactic → count
	Techniques   map[string]int    `json:"techniques"` // technique ID → count
	Severities   map[string]int    `json:"severities"` // severity → count
	Platforms    map[string]int    `json:"platforms"`  // platform → count
	ExecTypes    map[string]int    `json:"exec_types"` // execute.type → count
	Tags         map[string]int    `json:"tags"`       // tag → count
	Telemetry    map[string]int    `json:"telemetry"`  // telemetry type → count
	Detections   map[string]int    `json:"detections"` // detection → count
	Elevated     int               `json:"elevated"`   // stages with elevated=true
	AvgStages    float64           `json:"avg_stages"` // average stages per campaign
	MaxStages    int               `json:"max_stages"`
	MinStages    int               `json:"min_stages"`
	Fingerprints map[string]string `json:"fingerprints"` // campaign name → hash
}

// DriftReport describes how the current state of campaigns differs from a
// recorded baseline.
type DriftReport struct {
	Baseline          string          `json:"baseline_label"`
	NewTools          []string        `json:"new_tools,omitempty"`
	RemovedTools      []string        `json:"removed_tools,omitempty"`
	NewTactics        []string        `json:"new_tactics,omitempty"`
	RemovedTactics    []string        `json:"removed_tactics,omitempty"`
	NewTechniques     []string        `json:"new_techniques,omitempty"`
	RemovedTechniques []string        `json:"removed_techniques,omitempty"`
	NewCampaigns      []string        `json:"new_campaigns,omitempty"`
	RemovedCampaigns  []string        `json:"removed_campaigns,omitempty"`
	ModifiedCampaigns []string        `json:"modified_campaigns,omitempty"`
	StageCountDelta   int             `json:"stage_count_delta"`
	SeverityShifts    []SeverityShift `json:"severity_shifts,omitempty"`
	DriftScore        float64         `json:"drift_score"` // 0.0 = identical, 1.0 = completely different
	DriftLevel        string          `json:"drift_level"` // "none", "low", "medium", "high", "critical"
	Details           []DriftDetail   `json:"details,omitempty"`
}

// SeverityShift records a change in severity distribution.
type SeverityShift struct {
	Severity      string `json:"severity"`
	BaselineCount int    `json:"baseline_count"`
	CurrentCount  int    `json:"current_count"`
	Delta         int    `json:"delta"`
}

// DriftDetail is a specific drift observation.
type DriftDetail struct {
	Category    string `json:"category"` // "tool", "tactic", "technique", "campaign", "severity", "telemetry"
	Change      string `json:"change"`   // "added", "removed", "modified", "shifted"
	Item        string `json:"item"`
	Description string `json:"description"`
	Risk        string `json:"risk"` // "critical", "high", "medium", "low", "info"
}

// BuildBaseline constructs a behavioral baseline from a set of campaigns.
func BuildBaseline(campaigns []*Campaign, label string) *Baseline {
	b := &Baseline{
		Version:      "1",
		Label:        label,
		Campaigns:    len(campaigns),
		Tools:        make(map[string]int),
		Tactics:      make(map[string]int),
		Techniques:   make(map[string]int),
		Severities:   make(map[string]int),
		Platforms:    make(map[string]int),
		ExecTypes:    make(map[string]int),
		Tags:         make(map[string]int),
		Telemetry:    make(map[string]int),
		Detections:   make(map[string]int),
		Fingerprints: make(map[string]string),
	}

	if len(campaigns) == 0 {
		return b
	}

	b.MinStages = math.MaxInt32
	totalStages := 0

	for _, c := range campaigns {
		if c == nil {
			continue
		}

		stageCount := len(c.Stages)
		totalStages += stageCount
		if stageCount > b.MaxStages {
			b.MaxStages = stageCount
		}
		if stageCount < b.MinStages {
			b.MinStages = stageCount
		}

		b.Fingerprints[c.Meta.Name] = Fingerprint(c)

		if c.Meta.Severity != "" {
			b.Severities[c.Meta.Severity]++
		}

		for _, tag := range c.Meta.Tags {
			b.Tags[tag]++
		}

		for _, s := range c.Stages {
			if s.Tactic != "" {
				b.Tactics[s.Tactic]++
			}
			if s.Technique != "" {
				b.Techniques[s.Technique]++
			}
			if s.Execute.Type != "" {
				b.ExecTypes[s.Execute.Type]++
			}
			if s.Execute.Elevated {
				b.Elevated++
			}
			for _, p := range s.Platform {
				b.Platforms[p]++
			}
			for _, t := range s.Expect.Telemetry {
				b.Telemetry[t]++
			}
			for _, d := range s.Expect.Detections {
				b.Detections[d]++
			}

			// Map execute types to tool names using the same conventions as
			// the policy engine.
			toolName := execTypeToToolName(s.Execute.Type)
			if toolName != "" {
				b.Tools[toolName]++
			}
		}
	}

	b.Stages = totalStages
	if b.Campaigns > 0 {
		b.AvgStages = float64(totalStages) / float64(b.Campaigns)
	}
	if b.MinStages == math.MaxInt32 {
		b.MinStages = 0
	}

	return b
}

// BuildBaselineDir builds a baseline from all campaigns in a directory.
func BuildBaselineDir(dir string, label string) (*Baseline, error) {
	summaries, err := LoadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("building baseline from %q: %w", dir, err)
	}

	var campaigns []*Campaign
	for _, s := range summaries {
		c, loadErr := Load(s.Path)
		if loadErr != nil {
			continue
		}
		campaigns = append(campaigns, c)
	}

	return BuildBaseline(campaigns, label), nil
}

// DetectDrift compares a current set of campaigns against a recorded baseline
// and produces a drift report.
func DetectDrift(baseline *Baseline, current []*Campaign) *DriftReport {
	dr := &DriftReport{
		Baseline: baseline.Label,
	}

	// Build current state.
	currentBaseline := BuildBaseline(current, "current")

	// Campaign changes.
	baseNames := mapKeys(baseline.Fingerprints)
	currNames := mapKeys(currentBaseline.Fingerprints)
	dr.NewCampaigns = setDiff(currNames, baseNames)
	dr.RemovedCampaigns = setDiff(baseNames, currNames)

	for name, currFP := range currentBaseline.Fingerprints {
		if baseFP, ok := baseline.Fingerprints[name]; ok && baseFP != currFP {
			dr.ModifiedCampaigns = append(dr.ModifiedCampaigns, name)
		}
	}
	sort.Strings(dr.ModifiedCampaigns)

	// Tool changes.
	baseTools := sortedMapKeys(baseline.Tools)
	currTools := sortedMapKeys(currentBaseline.Tools)
	dr.NewTools = setDiff(currTools, baseTools)
	dr.RemovedTools = setDiff(baseTools, currTools)

	// Tactic changes.
	baseTactics := sortedMapKeys(baseline.Tactics)
	currTactics := sortedMapKeys(currentBaseline.Tactics)
	dr.NewTactics = setDiff(currTactics, baseTactics)
	dr.RemovedTactics = setDiff(baseTactics, currTactics)

	// Technique changes.
	baseTechs := sortedMapKeys(baseline.Techniques)
	currTechs := sortedMapKeys(currentBaseline.Techniques)
	dr.NewTechniques = setDiff(currTechs, baseTechs)
	dr.RemovedTechniques = setDiff(baseTechs, currTechs)

	// Stage count delta.
	dr.StageCountDelta = currentBaseline.Stages - baseline.Stages

	// Severity shifts.
	allSevs := mergeKeySet(baseline.Severities, currentBaseline.Severities)
	for _, sev := range allSevs {
		baseCount := baseline.Severities[sev]
		currCount := currentBaseline.Severities[sev]
		if baseCount != currCount {
			dr.SeverityShifts = append(dr.SeverityShifts, SeverityShift{
				Severity:      sev,
				BaselineCount: baseCount,
				CurrentCount:  currCount,
				Delta:         currCount - baseCount,
			})
		}
	}

	// Build detailed drift observations.
	dr.Details = buildDriftDetails(dr)

	// Compute drift score (0.0 to 1.0).
	dr.DriftScore = computeDriftScore(dr, baseline, currentBaseline)
	dr.DriftLevel = classifyDrift(dr.DriftScore)

	return dr
}

// DetectDriftDir compares the current campaign directory against a baseline.
func DetectDriftDir(baseline *Baseline, dir string) (*DriftReport, error) {
	summaries, err := LoadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("detecting drift from %q: %w", dir, err)
	}

	var campaigns []*Campaign
	for _, s := range summaries {
		c, loadErr := Load(s.Path)
		if loadErr != nil {
			continue
		}
		campaigns = append(campaigns, c)
	}

	return DetectDrift(baseline, campaigns), nil
}

// BaselineToJSON serializes a baseline to JSON.
func BaselineToJSON(b *Baseline) ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// BaselineFromJSON deserializes a baseline from JSON.
func BaselineFromJSON(data []byte) (*Baseline, error) {
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing baseline JSON: %w", err)
	}
	return &b, nil
}

// BaselineFromFile reads a baseline from a JSON file.
func BaselineFromFile(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline %q: %w", path, err)
	}
	return BaselineFromJSON(data)
}

// FormatBaseline renders a baseline as a human-readable box-drawing report.
func FormatBaseline(b *Baseline) string {
	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│             BEHAVIORAL BASELINE                 │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Label:     %-37s │\n", baselineTruncate(b.Label, 37))
	fmt.Fprintf(&sb, "│ Campaigns: %-37d │\n", b.Campaigns)
	fmt.Fprintf(&sb, "│ Stages:    %-37d │\n", b.Stages)
	fmt.Fprintf(&sb, "│ Avg/Camp:  %-37.1f │\n", b.AvgStages)
	fmt.Fprintf(&sb, "│ Elevated:  %-37d │\n", b.Elevated)
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Techniques.
	sb.WriteString("│ Techniques                                      │\n")
	sb.WriteString("│ ")
	techs := sortedMapKeys(b.Techniques)
	if len(techs) > 0 {
		for i, t := range techs {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%s(%d)", t, b.Techniques[t])
		}
	} else {
		sb.WriteString("none")
	}
	sb.WriteString("\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Tactics distribution.
	sb.WriteString("│ Tactic Distribution                             │\n")
	tactics := sortedMapKeys(b.Tactics)
	for _, t := range tactics {
		count := b.Tactics[t]
		bar := strings.Repeat("█", min(count, 30))
		fmt.Fprintf(&sb, "│  %-22s %3d %s\n", t, count, bar)
	}
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Severity distribution.
	sb.WriteString("│ Severity Distribution                           │\n")
	sevOrder := []string{"critical", "high", "medium", "low"}
	for _, sev := range sevOrder {
		if count, ok := b.Severities[sev]; ok {
			bar := strings.Repeat("█", min(count*3, 30))
			fmt.Fprintf(&sb, "│  %-22s %3d %s\n", sev, count, bar)
		}
	}
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Exec types.
	sb.WriteString("│ Execution Types                                 │\n")
	execs := sortedMapKeys(b.ExecTypes)
	for _, e := range execs {
		fmt.Fprintf(&sb, "│  %-22s %3d\n", e, b.ExecTypes[e])
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// FormatDriftReport renders a drift report as a human-readable box-drawing report.
func FormatDriftReport(dr *DriftReport) string {
	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────┐\n")
	sb.WriteString("│               DRIFT REPORT                      │\n")
	sb.WriteString("├─────────────────────────────────────────────────┤\n")
	fmt.Fprintf(&sb, "│ Baseline:    %-35s │\n", baselineTruncate(dr.Baseline, 35))
	fmt.Fprintf(&sb, "│ Drift Score: %-35s │\n", fmt.Sprintf("%.2f (%s)", dr.DriftScore, dr.DriftLevel))
	fmt.Fprintf(&sb, "│ Stage Delta: %-35s │\n", formatDelta(dr.StageCountDelta))
	sb.WriteString("├─────────────────────────────────────────────────┤\n")

	// Campaign changes.
	if len(dr.NewCampaigns) > 0 || len(dr.RemovedCampaigns) > 0 || len(dr.ModifiedCampaigns) > 0 {
		sb.WriteString("│ Campaign Changes                                │\n")
		for _, c := range dr.NewCampaigns {
			fmt.Fprintf(&sb, "│  + %-45s │\n", baselineTruncate(c, 45))
		}
		for _, c := range dr.RemovedCampaigns {
			fmt.Fprintf(&sb, "│  - %-45s │\n", baselineTruncate(c, 45))
		}
		for _, c := range dr.ModifiedCampaigns {
			fmt.Fprintf(&sb, "│  ~ %-45s │\n", baselineTruncate(c, 45))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Technique changes.
	if len(dr.NewTechniques) > 0 || len(dr.RemovedTechniques) > 0 {
		sb.WriteString("│ Technique Changes                               │\n")
		for _, t := range dr.NewTechniques {
			fmt.Fprintf(&sb, "│  + %-45s │\n", t)
		}
		for _, t := range dr.RemovedTechniques {
			fmt.Fprintf(&sb, "│  - %-45s │\n", t)
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Tactic changes.
	if len(dr.NewTactics) > 0 || len(dr.RemovedTactics) > 0 {
		sb.WriteString("│ Tactic Changes                                  │\n")
		for _, t := range dr.NewTactics {
			fmt.Fprintf(&sb, "│  + %-45s │\n", t)
		}
		for _, t := range dr.RemovedTactics {
			fmt.Fprintf(&sb, "│  - %-45s │\n", t)
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Severity shifts.
	if len(dr.SeverityShifts) > 0 {
		sb.WriteString("│ Severity Shifts                                 │\n")
		for _, ss := range dr.SeverityShifts {
			fmt.Fprintf(&sb, "│  %-12s %d → %d (%s)\n", ss.Severity, ss.BaselineCount, ss.CurrentCount, formatDelta(ss.Delta))
		}
		sb.WriteString("├─────────────────────────────────────────────────┤\n")
	}

	// Drift details.
	if len(dr.Details) > 0 {
		sb.WriteString("│ Drift Details                                   │\n")
		for _, d := range dr.Details {
			riskIcon := riskIcon(d.Risk)
			fmt.Fprintf(&sb, "│  %s %-44s │\n", riskIcon, baselineTruncate(d.Description, 44))
		}
	}

	sb.WriteString("└─────────────────────────────────────────────────┘\n")

	return sb.String()
}

// execTypeToToolName maps execute types to tool names matching the policy engine
// convention. Must stay in sync with policy.execTypeToTool.
func execTypeToToolName(execType string) string {
	m := map[string]string{
		"http":     "http_request",
		"shell":    "shell_exec",
		"dns":      "dns_query",
		"file":     "file_access",
		"registry": "registry_access",
		"service":  "service_control",
		"process":  "process_exec",
	}
	return m[execType]
}

// buildDriftDetails creates detailed drift observations from the drift report fields.
func buildDriftDetails(dr *DriftReport) []DriftDetail {
	var details []DriftDetail

	for _, c := range dr.NewCampaigns {
		details = append(details, DriftDetail{
			Category:    "campaign",
			Change:      "added",
			Item:        c,
			Description: fmt.Sprintf("New campaign: %s", c),
			Risk:        "info",
		})
	}
	for _, c := range dr.RemovedCampaigns {
		details = append(details, DriftDetail{
			Category:    "campaign",
			Change:      "removed",
			Item:        c,
			Description: fmt.Sprintf("Campaign removed: %s", c),
			Risk:        "medium",
		})
	}
	for _, c := range dr.ModifiedCampaigns {
		details = append(details, DriftDetail{
			Category:    "campaign",
			Change:      "modified",
			Item:        c,
			Description: fmt.Sprintf("Campaign modified: %s", c),
			Risk:        "low",
		})
	}
	for _, t := range dr.NewTechniques {
		risk := "low"
		if strings.HasPrefix(t, "LLM") || strings.HasPrefix(t, "AML") {
			risk = "high"
		}
		details = append(details, DriftDetail{
			Category:    "technique",
			Change:      "added",
			Item:        t,
			Description: fmt.Sprintf("New technique: %s", t),
			Risk:        risk,
		})
	}
	for _, t := range dr.RemovedTechniques {
		details = append(details, DriftDetail{
			Category:    "technique",
			Change:      "removed",
			Item:        t,
			Description: fmt.Sprintf("Technique removed: %s", t),
			Risk:        "medium",
		})
	}
	for _, t := range dr.NewTactics {
		risk := "medium"
		highRiskTactics := map[string]bool{
			"exfiltration": true, "impact": true, "credential-access": true,
			"lateral-movement": true,
		}
		if highRiskTactics[t] {
			risk = "high"
		}
		details = append(details, DriftDetail{
			Category:    "tactic",
			Change:      "added",
			Item:        t,
			Description: fmt.Sprintf("New tactic: %s", t),
			Risk:        risk,
		})
	}
	for _, t := range dr.RemovedTactics {
		details = append(details, DriftDetail{
			Category:    "tactic",
			Change:      "removed",
			Item:        t,
			Description: fmt.Sprintf("Tactic removed: %s", t),
			Risk:        "low",
		})
	}
	for _, ss := range dr.SeverityShifts {
		risk := "low"
		if ss.Severity == "critical" && ss.Delta > 0 {
			risk = "high"
		} else if ss.Severity == "high" && ss.Delta > 0 {
			risk = "medium"
		}
		details = append(details, DriftDetail{
			Category:    "severity",
			Change:      "shifted",
			Item:        ss.Severity,
			Description: fmt.Sprintf("Severity %s: %d → %d", ss.Severity, ss.BaselineCount, ss.CurrentCount),
			Risk:        risk,
		})
	}

	return details
}

// computeDriftScore calculates a 0.0-1.0 drift score based on the magnitude of changes.
func computeDriftScore(dr *DriftReport, baseline, current *Baseline) float64 {
	if baseline.Campaigns == 0 && current.Campaigns == 0 {
		return 0.0
	}

	// Weight different types of changes.
	var score float64
	totalWeight := 0.0

	// Campaign-level changes (weight: 3).
	campaignChanges := float64(len(dr.NewCampaigns) + len(dr.RemovedCampaigns) + len(dr.ModifiedCampaigns))
	totalCampaigns := float64(max(baseline.Campaigns, current.Campaigns))
	if totalCampaigns > 0 {
		score += 3.0 * (campaignChanges / totalCampaigns)
		totalWeight += 3.0
	}

	// Technique changes (weight: 2).
	techChanges := float64(len(dr.NewTechniques) + len(dr.RemovedTechniques))
	totalTechs := float64(max(len(baseline.Techniques), len(current.Techniques)))
	if totalTechs > 0 {
		score += 2.0 * (techChanges / totalTechs)
		totalWeight += 2.0
	}

	// Tactic changes (weight: 2).
	tacticChanges := float64(len(dr.NewTactics) + len(dr.RemovedTactics))
	totalTactics := float64(max(len(baseline.Tactics), len(current.Tactics)))
	if totalTactics > 0 {
		score += 2.0 * (tacticChanges / totalTactics)
		totalWeight += 2.0
	}

	// Tool changes (weight: 1).
	toolChanges := float64(len(dr.NewTools) + len(dr.RemovedTools))
	totalTools := float64(max(len(baseline.Tools), len(current.Tools)))
	if totalTools > 0 {
		score += 1.0 * (toolChanges / totalTools)
		totalWeight += 1.0
	}

	// Severity shifts (weight: 1.5).
	if len(dr.SeverityShifts) > 0 {
		sevScore := float64(len(dr.SeverityShifts)) / 4.0 // max 4 severity levels
		if sevScore > 1.0 {
			sevScore = 1.0
		}
		score += 1.5 * sevScore
		totalWeight += 1.5
	}

	if totalWeight == 0 {
		return 0.0
	}

	result := score / totalWeight
	if result > 1.0 {
		result = 1.0
	}
	return math.Round(result*100) / 100
}

// classifyDrift maps a drift score to a human-readable level.
func classifyDrift(score float64) string {
	switch {
	case score == 0:
		return "none"
	case score <= 0.1:
		return "low"
	case score <= 0.3:
		return "medium"
	case score <= 0.6:
		return "high"
	default:
		return "critical"
	}
}

// --- Helpers ---

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func setDiff(a, b []string) []string {
	bSet := make(map[string]bool, len(b))
	for _, v := range b {
		bSet[v] = true
	}
	var diff []string
	for _, v := range a {
		if !bSet[v] {
			diff = append(diff, v)
		}
	}
	sort.Strings(diff)
	return diff
}

func mergeKeySet(a, b map[string]int) []string {
	seen := make(map[string]bool)
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func baselineTruncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatDelta(d int) string {
	if d > 0 {
		return fmt.Sprintf("+%d", d)
	}
	return fmt.Sprintf("%d", d)
}

func riskIcon(risk string) string {
	switch risk {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "🔵"
	}
}

// min and max are builtins in Go 1.21+; no local definitions needed.
