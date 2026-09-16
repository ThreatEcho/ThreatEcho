// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Format returns the campaign as canonically-formatted YAML.
// Fields are emitted in a fixed canonical order with consistent 2-space
// indentation. Empty/zero fields are omitted.
func Format(c *Campaign) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	addScalar(root, "api_version", c.APIVersion)
	addScalar(root, "kind", c.Kind)

	if meta := buildMetaNode(&c.Meta); meta != nil {
		addMapping(root, "meta", meta)
	}

	if vars := buildSortedMapNode(c.Variables); vars != nil {
		addMapping(root, "variables", vars)
	}

	if stages := buildStagesNode(c.Stages); stages != nil {
		addMapping(root, "stages", stages)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("encoding campaign YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("closing YAML encoder: %w", err)
	}
	return buf.Bytes(), nil
}

// FormatFile loads a campaign from path (without expanding variables),
// formats it canonically, and returns the resulting YAML bytes.
func FormatFile(path string) ([]byte, error) {
	c, err := loadRaw(path)
	if err != nil {
		return nil, fmt.Errorf("format file %q: %w", path, err)
	}
	return Format(c)
}

// FormatFileInPlace loads a campaign from path, formats it canonically,
// and writes the result back to the same file.
func FormatFileInPlace(path string) error {
	resolved, err := resolveYAMLPath(path)
	if err != nil {
		return err
	}
	data, err := FormatFile(resolved)
	if err != nil {
		return err
	}
	return os.WriteFile(resolved, data, 0o644)
}

// Normalize returns a deep copy of the campaign with deterministic ordering:
//   - Stages sorted by topological order (if DAG is acyclic) or alphabetically by ID
//   - Telemetry, detections, artifacts, IOCs sorted alphabetically per stage
//   - Tags sorted alphabetically
//   - Platform lists sorted alphabetically
//   - DependsOn lists sorted alphabetically per stage
//
// The original campaign is never modified.
func Normalize(c *Campaign) *Campaign {
	nc := &Campaign{
		APIVersion: c.APIVersion,
		Kind:       c.Kind,
		Meta: Meta{
			Name:         c.Meta.Name,
			Adversary:    c.Meta.Adversary,
			Description:  c.Meta.Description,
			Objective:    c.Meta.Objective,
			MitreVersion: c.Meta.MitreVersion,
			Severity:     c.Meta.Severity,
			Created:      c.Meta.Created,
			Modified:     c.Meta.Modified,
		},
	}

	// Deep copy and sort tags.
	if len(c.Meta.Tags) > 0 {
		nc.Meta.Tags = sortedCopy(c.Meta.Tags)
	}
	// Deep copy authors (preserve insertion order — they are people, not data).
	if len(c.Meta.Authors) > 0 {
		nc.Meta.Authors = make([]string, len(c.Meta.Authors))
		copy(nc.Meta.Authors, c.Meta.Authors)
	}
	// Deep copy references (preserve insertion order).
	if len(c.Meta.References) > 0 {
		nc.Meta.References = make([]string, len(c.Meta.References))
		copy(nc.Meta.References, c.Meta.References)
	}

	// Deep copy variables (map is a reference type).
	if len(c.Variables) > 0 {
		nc.Variables = make(map[string]string, len(c.Variables))
		for k, v := range c.Variables {
			nc.Variables[k] = v
		}
	}

	// Deep copy and normalize each stage.
	nc.Stages = make([]Stage, len(c.Stages))
	for i, s := range c.Stages {
		ns := Stage{
			ID:          s.ID,
			Name:        s.Name,
			Description: s.Description,
			Technique:   s.Technique,
			Tactic:      s.Tactic,
			OnSuccess:   s.OnSuccess,
			OnFailure:   s.OnFailure,
			Timeout:     s.Timeout,
			Delay:       s.Delay,
			Execute: Execute{
				Type:     s.Execute.Type,
				Payload:  s.Execute.Payload,
				Target:   s.Execute.Target,
				Elevated: s.Execute.Elevated,
			},
		}

		// Sort and copy slices within Expect.
		if len(s.Expect.Telemetry) > 0 {
			ns.Expect.Telemetry = sortedCopy(s.Expect.Telemetry)
		}
		if len(s.Expect.Detections) > 0 {
			ns.Expect.Detections = sortedCopy(s.Expect.Detections)
		}
		if len(s.Expect.Artifacts) > 0 {
			ns.Expect.Artifacts = sortedCopy(s.Expect.Artifacts)
		}
		if len(s.Expect.IOCs) > 0 {
			ns.Expect.IOCs = sortedCopy(s.Expect.IOCs)
		}

		// Sort platform and depends_on.
		if len(s.Platform) > 0 {
			ns.Platform = sortedCopy(s.Platform)
		}
		if len(s.DependsOn) > 0 {
			ns.DependsOn = sortedCopy(s.DependsOn)
		}

		// Deep copy commands (order matters — execution sequence).
		if len(s.Execute.Commands) > 0 {
			ns.Execute.Commands = make([]string, len(s.Execute.Commands))
			copy(ns.Execute.Commands, s.Execute.Commands)
		}
		// Deep copy cleanup (order matters).
		if len(s.Execute.Cleanup) > 0 {
			ns.Execute.Cleanup = make([]string, len(s.Execute.Cleanup))
			copy(ns.Execute.Cleanup, s.Execute.Cleanup)
		}
		// Deep copy args.
		if len(s.Execute.Args) > 0 {
			ns.Execute.Args = make(map[string]string, len(s.Execute.Args))
			for k, v := range s.Execute.Args {
				ns.Execute.Args[k] = v
			}
		}

		nc.Stages[i] = ns
	}

	// Sort stages: topological order if the DAG is valid, alphabetical by ID otherwise.
	ordered, err := ResolveOrder(nc.Stages)
	if err == nil {
		nc.Stages = ordered
	} else {
		sort.Slice(nc.Stages, func(i, j int) bool {
			return nc.Stages[i].ID < nc.Stages[j].ID
		})
	}

	return nc
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// loadRaw reads and parses a campaign YAML without expanding variables,
// preserving {{var}} template markers in stage fields.
func loadRaw(path string) (*Campaign, error) {
	resolved, err := resolveYAMLPath(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("reading campaign: %w", err)
	}
	var c Campaign
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing campaign YAML: %w", err)
	}
	return &c, nil
}

// resolveYAMLPath returns the campaign.yaml file path, appending the
// filename when path is a directory.
func resolveYAMLPath(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("campaign path %q: %w", path, err)
	}
	if info.IsDir() {
		return filepath.Join(path, "campaign.yaml"), nil
	}
	return path, nil
}

// ---------------------------------------------------------------------------
// yaml.Node tree builders — each returns nil when there is nothing to emit.
// ---------------------------------------------------------------------------

// addScalar appends a string key-value pair to a mapping node.
// Skips the field entirely when value is empty.
func addScalar(m *yaml.Node, key, value string) {
	if value == "" {
		return
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: value, Tag: "!!str"},
	)
}

// addMapping appends a key with an arbitrary child node (mapping, sequence, …).
func addMapping(m *yaml.Node, key string, child *yaml.Node) {
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"},
		child,
	)
}

// addBool appends a boolean field, omitting false values.
func addBool(m *yaml.Node, key string, value bool) {
	if !value {
		return
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: "true", Tag: "!!bool"},
	)
}

// seqNode builds a block-style YAML sequence from a string slice.
func seqNode(items []string) *yaml.Node {
	if len(items) == 0 {
		return nil
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, item := range items {
		seq.Content = append(seq.Content, &yaml.Node{
			Kind: yaml.ScalarNode, Value: item, Tag: "!!str",
		})
	}
	return seq
}

// flowSeqNode builds a flow-style sequence ([a, b, c]) for compact lists.
func flowSeqNode(items []string) *yaml.Node {
	n := seqNode(items)
	if n != nil {
		n.Style = yaml.FlowStyle
	}
	return n
}

// buildSortedMapNode builds a mapping node with keys in sorted order.
func buildSortedMapNode(m map[string]string) *yaml.Node {
	if len(m) == 0 {
		return nil
	}
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: k, Tag: "!!str"},
			&yaml.Node{Kind: yaml.ScalarNode, Value: m[k], Tag: "!!str"},
		)
	}
	return node
}

// buildMetaNode builds the meta mapping in canonical field order:
// name, adversary, description, objective, mitre_version, severity,
// tags, authors, references, created, modified.
func buildMetaNode(meta *Meta) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	addScalar(m, "name", meta.Name)
	addScalar(m, "adversary", meta.Adversary)
	addScalar(m, "description", meta.Description)
	addScalar(m, "objective", meta.Objective)
	addScalar(m, "mitre_version", meta.MitreVersion)
	addScalar(m, "severity", meta.Severity)

	if tags := flowSeqNode(meta.Tags); tags != nil {
		addMapping(m, "tags", tags)
	}
	if authors := seqNode(meta.Authors); authors != nil {
		addMapping(m, "authors", authors)
	}
	if refs := seqNode(meta.References); refs != nil {
		addMapping(m, "references", refs)
	}

	addScalar(m, "created", meta.Created)
	addScalar(m, "modified", meta.Modified)

	if len(m.Content) == 0 {
		return nil
	}
	return m
}

// buildStagesNode builds the stages sequence with each stage in canonical
// field order.
func buildStagesNode(stages []Stage) *yaml.Node {
	if len(stages) == 0 {
		return nil
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for i := range stages {
		seq.Content = append(seq.Content, buildStageNode(&stages[i]))
	}
	return seq
}

// buildStageNode builds a single stage mapping in canonical field order:
// id, name, description, technique, tactic, platform, depends_on,
// execute, expect, on_success, on_failure, timeout, delay.
func buildStageNode(s *Stage) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	addScalar(m, "id", s.ID)
	addScalar(m, "name", s.Name)
	addScalar(m, "description", s.Description)
	addScalar(m, "technique", s.Technique)
	addScalar(m, "tactic", s.Tactic)

	if p := flowSeqNode(s.Platform); p != nil {
		addMapping(m, "platform", p)
	}
	if d := flowSeqNode(s.DependsOn); d != nil {
		addMapping(m, "depends_on", d)
	}

	if exec := buildExecuteNode(&s.Execute); exec != nil {
		addMapping(m, "execute", exec)
	}
	if expect := buildExpectNode(&s.Expect); expect != nil {
		addMapping(m, "expect", expect)
	}

	addScalar(m, "on_success", s.OnSuccess)
	addScalar(m, "on_failure", s.OnFailure)

	if s.Timeout.Duration != 0 {
		addScalar(m, "timeout", s.Timeout.Duration.String())
	}
	if s.Delay.Duration != 0 {
		addScalar(m, "delay", s.Delay.Duration.String())
	}

	return m
}

// buildExecuteNode builds the execute mapping in canonical field order:
// type, commands, payload, target, args, cleanup, elevated.
func buildExecuteNode(e *Execute) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	addScalar(m, "type", e.Type)

	if cmds := seqNode(e.Commands); cmds != nil {
		addMapping(m, "commands", cmds)
	}

	addScalar(m, "payload", e.Payload)
	addScalar(m, "target", e.Target)

	if args := buildSortedMapNode(e.Args); args != nil {
		addMapping(m, "args", args)
	}

	if cleanup := seqNode(e.Cleanup); cleanup != nil {
		addMapping(m, "cleanup", cleanup)
	}

	addBool(m, "elevated", e.Elevated)

	if len(m.Content) == 0 {
		return nil
	}
	return m
}

// buildExpectNode builds the expect mapping in canonical field order:
// telemetry, detections, artifacts, iocs.
func buildExpectNode(e *Expect) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	if tel := seqNode(e.Telemetry); tel != nil {
		addMapping(m, "telemetry", tel)
	}
	if det := seqNode(e.Detections); det != nil {
		addMapping(m, "detections", det)
	}
	if art := seqNode(e.Artifacts); art != nil {
		addMapping(m, "artifacts", art)
	}
	if iocs := seqNode(e.IOCs); iocs != nil {
		addMapping(m, "iocs", iocs)
	}

	if len(m.Content) == 0 {
		return nil
	}
	return m
}
