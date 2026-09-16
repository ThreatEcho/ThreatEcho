// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"sort"
	"strings"
)

// FieldChange records a single field-level difference between two campaigns.
type FieldChange struct {
	Field string
	Left  string
	Right string
}

// StageDiff captures field-level changes within a single stage (matched by ID).
type StageDiff struct {
	StageID string
	Changes []FieldChange
}

// DiffReport is the result of comparing two Campaign structs.
type DiffReport struct {
	LeftName  string
	RightName string

	MetaChanges []FieldChange

	VariablesAdded    map[string]string
	VariablesRemoved  map[string]string
	VariablesModified map[string][2]string // key → [old, new]

	StagesAdded    []Stage
	StagesRemoved  []Stage
	StagesModified []StageDiff
}

// HasChanges returns true if the diff report contains any differences.
func (d *DiffReport) HasChanges() bool {
	if len(d.MetaChanges) > 0 {
		return true
	}
	if len(d.VariablesAdded) > 0 || len(d.VariablesRemoved) > 0 || len(d.VariablesModified) > 0 {
		return true
	}
	if len(d.StagesAdded) > 0 || len(d.StagesRemoved) > 0 || len(d.StagesModified) > 0 {
		return true
	}
	return false
}

// Summary returns a compact human-readable summary of what changed.
func (d *DiffReport) Summary() string {
	if !d.HasChanges() {
		return "no changes"
	}

	var parts []string

	if n := len(d.MetaChanges); n > 0 {
		parts = append(parts, fmt.Sprintf("%d meta field(s) changed", n))
	}

	varChanges := len(d.VariablesAdded) + len(d.VariablesRemoved) + len(d.VariablesModified)
	if varChanges > 0 {
		parts = append(parts, fmt.Sprintf("%d variable(s) changed", varChanges))
	}

	if n := len(d.StagesModified); n > 0 {
		parts = append(parts, fmt.Sprintf("%d stage(s) modified", n))
	}
	if n := len(d.StagesAdded); n > 0 {
		parts = append(parts, fmt.Sprintf("%d stage(s) added", n))
	}
	if n := len(d.StagesRemoved); n > 0 {
		parts = append(parts, fmt.Sprintf("%d stage(s) removed", n))
	}

	return strings.Join(parts, ", ")
}

// Diff compares two Campaign structs and returns a detailed DiffReport.
// Stages are matched by ID, not by position in the slice.
func Diff(left, right *Campaign) *DiffReport {
	report := &DiffReport{
		LeftName:          left.Meta.Name,
		RightName:         right.Meta.Name,
		VariablesAdded:    make(map[string]string),
		VariablesRemoved:  make(map[string]string),
		VariablesModified: make(map[string][2]string),
	}

	// --- Meta comparison ---
	diffMeta(&left.Meta, &right.Meta, report)

	// --- Variables comparison ---
	diffMaps(left.Variables, right.Variables, report.VariablesAdded, report.VariablesRemoved, report.VariablesModified)

	// --- Stages comparison ---
	diffStages(left.Stages, right.Stages, report)

	return report
}

// DiffFiles loads two campaign YAML files and diffs them.
func DiffFiles(leftPath, rightPath string) (*DiffReport, error) {
	left, err := Load(leftPath)
	if err != nil {
		return nil, fmt.Errorf("loading left campaign: %w", err)
	}
	right, err := Load(rightPath)
	if err != nil {
		return nil, fmt.Errorf("loading right campaign: %w", err)
	}
	return Diff(left, right), nil
}

// diffMeta compares two Meta structs field by field.
func diffMeta(left, right *Meta, report *DiffReport) {
	cmpField := func(name, l, r string) {
		if l != r {
			report.MetaChanges = append(report.MetaChanges, FieldChange{
				Field: name,
				Left:  l,
				Right: r,
			})
		}
	}

	cmpField("name", left.Name, right.Name)
	cmpField("adversary", left.Adversary, right.Adversary)
	cmpField("description", left.Description, right.Description)
	cmpField("objective", left.Objective, right.Objective)
	cmpField("mitre_version", left.MitreVersion, right.MitreVersion)
	cmpField("severity", left.Severity, right.Severity)
	cmpField("created", left.Created, right.Created)
	cmpField("modified", left.Modified, right.Modified)

	// Slice fields on Meta
	if ch := diffSliceField("tags", left.Tags, right.Tags); ch != nil {
		report.MetaChanges = append(report.MetaChanges, *ch)
	}
	if ch := diffSliceField("authors", left.Authors, right.Authors); ch != nil {
		report.MetaChanges = append(report.MetaChanges, *ch)
	}
	if ch := diffSliceField("references", left.References, right.References); ch != nil {
		report.MetaChanges = append(report.MetaChanges, *ch)
	}
}

// diffMaps compares two string maps, populating added/removed/modified buckets.
func diffMaps(left, right map[string]string, added, removed map[string]string, modified map[string][2]string) {
	for k, lv := range left {
		if rv, ok := right[k]; ok {
			if lv != rv {
				modified[k] = [2]string{lv, rv}
			}
		} else {
			removed[k] = lv
		}
	}
	for k, rv := range right {
		if _, ok := left[k]; !ok {
			added[k] = rv
		}
	}
}

// diffStages compares two stage slices, matching by ID.
func diffStages(left, right []Stage, report *DiffReport) {
	leftByID := make(map[string]*Stage, len(left))
	for i := range left {
		leftByID[left[i].ID] = &left[i]
	}
	rightByID := make(map[string]*Stage, len(right))
	for i := range right {
		rightByID[right[i].ID] = &right[i]
	}

	// Find removed and modified stages (iterate left order).
	for i := range left {
		ls := &left[i]
		rs, ok := rightByID[ls.ID]
		if !ok {
			report.StagesRemoved = append(report.StagesRemoved, *ls)
			continue
		}
		sd := diffSingleStage(ls, rs)
		if len(sd.Changes) > 0 {
			report.StagesModified = append(report.StagesModified, sd)
		}
	}

	// Find added stages (iterate right order).
	for i := range right {
		rs := &right[i]
		if _, ok := leftByID[rs.ID]; !ok {
			report.StagesAdded = append(report.StagesAdded, *rs)
		}
	}
}

// diffSingleStage compares two stages that share the same ID.
func diffSingleStage(left, right *Stage) StageDiff {
	sd := StageDiff{StageID: left.ID}

	cmpField := func(name, l, r string) {
		if l != r {
			sd.Changes = append(sd.Changes, FieldChange{Field: name, Left: l, Right: r})
		}
	}

	cmpField("name", left.Name, right.Name)
	cmpField("description", left.Description, right.Description)
	cmpField("technique", left.Technique, right.Technique)
	cmpField("tactic", left.Tactic, right.Tactic)
	cmpField("on_success", left.OnSuccess, right.OnSuccess)
	cmpField("on_failure", left.OnFailure, right.OnFailure)

	// Duration fields — only report a change if at least one is non-zero.
	if left.Timeout.Duration != right.Timeout.Duration {
		if left.Timeout.Duration != 0 || right.Timeout.Duration != 0 {
			sd.Changes = append(sd.Changes, FieldChange{
				Field: "timeout",
				Left:  durationStr(left.Timeout),
				Right: durationStr(right.Timeout),
			})
		}
	}
	if left.Delay.Duration != right.Delay.Duration {
		if left.Delay.Duration != 0 || right.Delay.Duration != 0 {
			sd.Changes = append(sd.Changes, FieldChange{
				Field: "delay",
				Left:  durationStr(left.Delay),
				Right: durationStr(right.Delay),
			})
		}
	}

	// Slice fields on Stage.
	if ch := diffSliceField("platform", left.Platform, right.Platform); ch != nil {
		sd.Changes = append(sd.Changes, *ch)
	}
	if ch := diffSliceField("depends_on", left.DependsOn, right.DependsOn); ch != nil {
		sd.Changes = append(sd.Changes, *ch)
	}

	// Execute sub-struct.
	cmpField("execute.type", left.Execute.Type, right.Execute.Type)
	cmpField("execute.payload", left.Execute.Payload, right.Execute.Payload)
	cmpField("execute.target", left.Execute.Target, right.Execute.Target)

	if left.Execute.Elevated != right.Execute.Elevated {
		sd.Changes = append(sd.Changes, FieldChange{
			Field: "execute.elevated",
			Left:  fmt.Sprintf("%v", left.Execute.Elevated),
			Right: fmt.Sprintf("%v", right.Execute.Elevated),
		})
	}

	if ch := diffSliceField("execute.commands", left.Execute.Commands, right.Execute.Commands); ch != nil {
		sd.Changes = append(sd.Changes, *ch)
	}
	if ch := diffSliceField("execute.cleanup", left.Execute.Cleanup, right.Execute.Cleanup); ch != nil {
		sd.Changes = append(sd.Changes, *ch)
	}

	// Execute.Args map.
	argsAdded := make(map[string]string)
	argsRemoved := make(map[string]string)
	argsModified := make(map[string][2]string)
	diffMaps(left.Execute.Args, right.Execute.Args, argsAdded, argsRemoved, argsModified)
	if len(argsAdded) > 0 || len(argsRemoved) > 0 || len(argsModified) > 0 {
		sd.Changes = append(sd.Changes, FieldChange{
			Field: "execute.args",
			Left:  formatMapDelta(argsRemoved, argsModified, true),
			Right: formatMapDelta(argsAdded, argsModified, false),
		})
	}

	// Expect sub-struct.
	if ch := diffSliceField("telemetry", left.Expect.Telemetry, right.Expect.Telemetry); ch != nil {
		sd.Changes = append(sd.Changes, *ch)
	}
	if ch := diffSliceField("detections", left.Expect.Detections, right.Expect.Detections); ch != nil {
		sd.Changes = append(sd.Changes, *ch)
	}
	if ch := diffSliceField("artifacts", left.Expect.Artifacts, right.Expect.Artifacts); ch != nil {
		sd.Changes = append(sd.Changes, *ch)
	}
	if ch := diffSliceField("iocs", left.Expect.IOCs, right.Expect.IOCs); ch != nil {
		sd.Changes = append(sd.Changes, *ch)
	}

	return sd
}

// diffSliceField compares two string slices (order-insensitive, set-based).
// Returns nil when the slices contain the same elements.
// Left shows "-item" for removals; Right shows "+item" for additions.
func diffSliceField(name string, left, right []string) *FieldChange {
	leftSet := make(map[string]bool, len(left))
	for _, v := range left {
		leftSet[v] = true
	}
	rightSet := make(map[string]bool, len(right))
	for _, v := range right {
		rightSet[v] = true
	}

	var removed, added []string
	for _, v := range left {
		if !rightSet[v] {
			removed = append(removed, v)
		}
	}
	for _, v := range right {
		if !leftSet[v] {
			added = append(added, v)
		}
	}

	if len(removed) == 0 && len(added) == 0 {
		return nil
	}

	var leftParts, rightParts []string
	for _, v := range removed {
		leftParts = append(leftParts, "-"+v)
	}
	for _, v := range added {
		rightParts = append(rightParts, "+"+v)
	}

	return &FieldChange{
		Field: name,
		Left:  strings.Join(leftParts, ", "),
		Right: strings.Join(rightParts, ", "),
	}
}

// durationStr returns a human string for a Duration, or "" for zero.
func durationStr(d Duration) string {
	if d.Duration == 0 {
		return ""
	}
	return d.Duration.String()
}

// formatMapDelta builds a compact string for map additions/removals/modifications.
// When isLeft is true it shows removed keys and old values of modified keys;
// when false it shows added keys and new values.
func formatMapDelta(plain map[string]string, modified map[string][2]string, isLeft bool) string {
	var parts []string

	keys := sortedKeys(plain)
	for _, k := range keys {
		if isLeft {
			parts = append(parts, fmt.Sprintf("-%s=%s", k, plain[k]))
		} else {
			parts = append(parts, fmt.Sprintf("+%s=%s", k, plain[k]))
		}
	}

	modKeys := sortedModKeys(modified)
	for _, k := range modKeys {
		pair := modified[k]
		if isLeft {
			parts = append(parts, fmt.Sprintf("~%s=%s", k, pair[0]))
		} else {
			parts = append(parts, fmt.Sprintf("~%s=%s", k, pair[1]))
		}
	}

	return strings.Join(parts, ", ")
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedModKeys(m map[string][2]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// FormatDiff produces a human-readable text representation of a DiffReport.
func FormatDiff(d *DiffReport) string {
	if !d.HasChanges() {
		return fmt.Sprintf("Campaigns %q and %q are identical.\n", d.LeftName, d.RightName)
	}

	var b strings.Builder

	b.WriteString(fmt.Sprintf("Diff: %q vs %q\n", d.LeftName, d.RightName))
	b.WriteString(fmt.Sprintf("Summary: %s\n", d.Summary()))
	b.WriteString("\n")

	// Meta changes.
	if len(d.MetaChanges) > 0 {
		b.WriteString("=== Meta Changes ===\n")
		for _, c := range d.MetaChanges {
			b.WriteString(fmt.Sprintf("  ~ %-16s  %q -> %q\n", c.Field, c.Left, c.Right))
		}
		b.WriteString("\n")
	}

	// Variable changes.
	if len(d.VariablesAdded) > 0 || len(d.VariablesRemoved) > 0 || len(d.VariablesModified) > 0 {
		b.WriteString("=== Variable Changes ===\n")
		for _, k := range sortedKeys(d.VariablesAdded) {
			b.WriteString(fmt.Sprintf("  + %s = %q\n", k, d.VariablesAdded[k]))
		}
		for _, k := range sortedKeys(d.VariablesRemoved) {
			b.WriteString(fmt.Sprintf("  - %s = %q\n", k, d.VariablesRemoved[k]))
		}
		for _, k := range sortedModKeys(d.VariablesModified) {
			pair := d.VariablesModified[k]
			b.WriteString(fmt.Sprintf("  ~ %s  %q -> %q\n", k, pair[0], pair[1]))
		}
		b.WriteString("\n")
	}

	// Stages added.
	if len(d.StagesAdded) > 0 {
		b.WriteString("=== Stages Added ===\n")
		for _, s := range d.StagesAdded {
			b.WriteString(fmt.Sprintf("  + [%s] %s (%s / %s)\n", s.ID, s.Name, s.Technique, s.Tactic))
		}
		b.WriteString("\n")
	}

	// Stages removed.
	if len(d.StagesRemoved) > 0 {
		b.WriteString("=== Stages Removed ===\n")
		for _, s := range d.StagesRemoved {
			b.WriteString(fmt.Sprintf("  - [%s] %s (%s / %s)\n", s.ID, s.Name, s.Technique, s.Tactic))
		}
		b.WriteString("\n")
	}

	// Stages modified.
	if len(d.StagesModified) > 0 {
		b.WriteString("=== Stages Modified ===\n")
		for _, sd := range d.StagesModified {
			b.WriteString(fmt.Sprintf("  Stage %q:\n", sd.StageID))
			for _, c := range sd.Changes {
				b.WriteString(fmt.Sprintf("    ~ %-20s  %q -> %q\n", c.Field, c.Left, c.Right))
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}
