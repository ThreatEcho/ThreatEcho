// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzCampaignYAMLParse(f *testing.F) {
	f.Add([]byte(`api_version: v1
kind: Campaign
meta:
  name: test
  description: fuzz seed
stages:
  - id: s1
    name: stage one
    tactic: execution
    technique: T1059
    execute:
      type: shell
      command: echo hello
`))
	f.Add([]byte(`api_version: v1
kind: Campaign
meta:
  name: empty
stages: []
`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var c Campaign
		_ = yaml.Unmarshal(data, &c)

		if c.Meta.Name != "" {
			_ = Validate(&c)
		}
	})
}

func FuzzCampaignJSONParse(f *testing.F) {
	f.Add([]byte(`{"api_version":"v1","kind":"Campaign","meta":{"name":"test"},"stages":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseJSON(data)
	})
}
