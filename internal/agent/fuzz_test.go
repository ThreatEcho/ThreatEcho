// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package agent

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzAgentYAMLParse(f *testing.F) {
	f.Add([]byte(`api_version: v1
kind: Agent
meta:
  name: fuzz-agent
  type: tool-calling
  description: seed agent
trust:
  level: standard
tools:
  - name: exec
    elevated: false
`))
	f.Add([]byte(`api_version: v1
kind: Agent
meta:
  name: empty
  type: retrieval
trust:
  level: low
`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var a Agent
		if err := yaml.Unmarshal(data, &a); err != nil {
			return
		}
		if a.Meta.Name != "" {
			_ = ValidateAgent(&a)
		}
	})
}

func FuzzInventoryAnalyzeTrust(f *testing.F) {
	f.Add([]byte(`api_version: v1
kind: Agent
meta:
  name: admin-agent
  type: orchestrator
trust:
  level: admin
  trusts_from: [low-agent]
  can_escalate: true
tools:
  - name: deploy
    elevated: true
guardrails:
  - type: content_filter
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var a Agent
		if err := yaml.Unmarshal(data, &a); err != nil {
			return
		}
		if a.Meta.Name == "" {
			return
		}
		inv := &Inventory{Agents: []*Agent{&a}}
		_ = inv.AnalyzeTrust()
	})
}
