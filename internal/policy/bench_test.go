// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"testing"

	"gopkg.in/yaml.v3"
)

var benchPolicyYAML = []byte(`api_version: v1
kind: Policy
meta:
  name: bench-policy
  description: Benchmark policy with realistic structure
rules:
  - id: deny-exec
    description: Block all execution tools
    effect: deny
    priority: 100
    match:
      tools: ["code-exec", "shell-exec", "eval"]
      tactics: ["execution"]
      actions: ["execute"]
  - id: deny-exfil
    description: Block exfiltration to external
    effect: deny
    priority: 90
    match:
      tools: ["http-client", "smtp-send"]
      tactics: ["exfiltration"]
      targets: ["*.external.com", "*.evil.io"]
  - id: alert-priv-esc
    description: Alert on privilege escalation attempts
    effect: alert
    priority: 80
    match:
      tactics: ["privilege-escalation"]
  - id: allow-read
    description: Allow standard reads
    effect: allow
    priority: 50
    match:
      tools: ["file-read", "db-query"]
      actions: ["read", "query"]
  - id: deny-write-prod
    description: Block writes to production
    effect: deny
    priority: 95
    match:
      tools: ["*"]
      actions: ["write"]
      targets: ["prod-*"]
agent:
  name: bench-agent
  trust_level: standard
`)

func BenchmarkPolicyYAMLParse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var p Policy
		if err := yaml.Unmarshal(benchPolicyYAML, &p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPolicyLint(b *testing.B) {
	var p Policy
	if err := yaml.Unmarshal(benchPolicyYAML, &p); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LintPolicy(&p)
	}
}

func BenchmarkMatchPattern(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = matchPattern("code-*", "code-exec")
		_ = matchPattern("*.external.com", "api.external.com")
		_ = matchPattern("*", "anything")
		_ = matchPattern("exact", "exact")
		_ = matchPattern("miss", "other")
	}
}
