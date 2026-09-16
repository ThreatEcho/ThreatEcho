// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzPolicyYAMLParse(f *testing.F) {
	f.Add([]byte(`api_version: v1
kind: Policy
meta:
  name: fuzz-test
  description: seed policy
rules:
  - id: r1
    effect: deny
    match:
      tools: ["exec"]
`))
	f.Add([]byte(`api_version: v1
kind: Policy
meta:
  name: empty
rules: []
`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Policy
		if err := yaml.Unmarshal(data, &p); err != nil {
			return
		}
		if p.Meta.Name != "" {
			_ = LintPolicy(&p)
		}
	})
}

func FuzzTestSuiteYAMLParse(f *testing.F) {
	f.Add([]byte(`api_version: v1
kind: PolicyTestSuite
meta:
  name: fuzz-suite
  policy: test
tests:
  - id: t1
    name: test one
    input:
      tool: exec
    expect:
      effect: deny
`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var suite TestSuite
		if err := yaml.Unmarshal(data, &suite); err != nil {
			return
		}
		if len(suite.Tests) > 0 {
			_ = ValidateTestSuite(&suite)
		}
	})
}

func FuzzMatchPattern(f *testing.F) {
	f.Add("hello", "hello")
	f.Add("hello", "hel*")
	f.Add("hello", "*llo")
	f.Add("hello", "*")
	f.Add("hello", "world")
	f.Add("", "")
	f.Add("", "*")

	f.Fuzz(func(t *testing.T, input, pattern string) {
		_ = matchPattern(pattern, input)
	})
}
