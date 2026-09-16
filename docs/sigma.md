<p align="center">
  <img src="../assets/logo-circle-800.jpg" alt="ThreatEcho" width="120" />
</p>

# Sigma Integration

ThreatEcho bridges adversary simulation to detection engineering by generating [Sigma](https://sigmahq.io) detection rule scaffolds from campaign expected detections.

Sigma is the open standard for SIEM detection rules. Rules written in Sigma can be converted to Splunk SPL, Elastic KQL, Microsoft Sentinel KQL, QRadar AQL, and dozens of other SIEM query languages using tools like [sigma-cli](https://github.com/SigmaHQ/sigma-cli) or [pySigma](https://github.com/SigmaHQ/pySigma).

## How it works

```
Campaign YAML                    Sigma Rules
┌─────────────────┐             ┌─────────────────┐
│ stages:         │             │ title: ...      │
│   - expect:     │  generate   │ id: ...         │
│       telemetry │ ─────────→  │ logsource:      │
│       detections│             │   category: ... │
│                 │             │ detection:      │
│                 │             │   selection: ...│
└─────────────────┘             └─────────────────┘
```

Each campaign stage declares expected detections in its `expect` block. The Sigma generator creates one rule per expected detection per stage, with:

- **Logsource** derived from the stage's telemetry type
- **Tags** from the technique and tactic
- **References** linking to the MITRE technique page
- **Selection scaffolding** based on the logsource category
- **Deterministic IDs** for stable cross-run references

## Usage

```bash
# Generate rules from a single campaign
threatecho export sigma campaigns/apt29-cozy-bear/

# Generate rules from all campaigns
threatecho export sigma -dir campaigns/

# Write to a file
threatecho export sigma -dir campaigns/ -output rules.yml

# Custom author
threatecho export sigma -author "SOC Team" campaigns/llm-agent-hijack/
```

## Generated rule structure

Each rule follows the [Sigma specification](https://github.com/SigmaHQ/sigma-specification):

```yaml
title: Spearphishing Attachment Execution
id: a0e003e4-50e3-ebb2-8c4b-c589df9d895f
status: experimental
level: high
description: |
  Deliver macro-enabled document to establish initial foothold
author: ThreatEcho
date: 2026/09/14
modified: 2026/09/14
references:
  - https://attack.mitre.org/techniques/T1566/001/
tags:
  - attack.initial_access
  - attack.t1566.001
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: '# Derived from campaign commands'
    Image|endswith: '# Add executable path pattern'
  condition: selection
falsepositives:
  - Legitimate administrative activity
```

### Field details

| Field | Source | Description |
|-------|--------|-------------|
| `title` | Detection name | Snake_case converted to Title Case |
| `id` | SHA256 hash | Deterministic from campaign name + stage ID + detection name |
| `status` | Default | Always `experimental` — review before promoting |
| `level` | Tactic mapping | High for initial-access/execution/exfil; medium for discovery/recon |
| `description` | Stage description | Falls back to auto-generated text if stage has no description |
| `author` | `-author` flag | Default: "ThreatEcho" |
| `references` | Technique ID | ATT&CK, ATLAS, or OWASP URL |
| `tags` | Technique + tactic | Framework-aware: `attack.<tactic>` / `atlas.<tactic>` / `owasp.<tactic>` |
| `logsource` | First telemetry type | Mapped via telemetry-to-logsource table |
| `detection` | Logsource-aware | Scaffold with edit markers for the detection engineer |

## Telemetry-to-logsource mapping

ThreatEcho maps campaign telemetry types to Sigma logsource categories. The first telemetry type in a stage's `expect.telemetry` list determines the rule's logsource.

### Process telemetry

| Telemetry Type | Sigma Category | Product |
|---------------|----------------|---------|
| `process_create` | `process_creation` | — |
| `process_access` | `process_access` | — |
| `process_injection` | `create_remote_thread` | — |
| `process_terminate` | `process_termination` | — |

### File telemetry

| Telemetry Type | Sigma Category | Product |
|---------------|----------------|---------|
| `file_create` | `file_event` | — |
| `file_modify` | `file_change` | — |
| `file_delete` | `file_delete` | — |
| `file_read` | `file_access` | — |
| `file_rename` | `file_rename` | — |

### Network telemetry

| Telemetry Type | Sigma Category | Product |
|---------------|----------------|---------|
| `network_connection` | `network_connection` | — |
| `dns_query` | `dns_query` | — |
| `tls_handshake` | `network_connection` | — |

### Registry telemetry (Windows)

| Telemetry Type | Sigma Category | Product |
|---------------|----------------|---------|
| `registry_set` | `registry_set` | windows |
| `registry_create` | `registry_add` | windows |
| `registry_delete` | `registry_delete` | windows |
| `registry_modify` | `registry_event` | windows |

### Authentication

| Telemetry Type | Sigma Category | Product | Service |
|---------------|----------------|---------|---------|
| `logon_event` | `authentication` | windows | security |
| `auth_logoff` | `authentication` | windows | security |

### AI agent telemetry

| Telemetry Type | Sigma Category | Service |
|---------------|----------------|---------|
| `prompt_log` | `application` | agent |
| `guardrail_trigger` | `application` | agent |
| `tool_call` | `application` | agent |
| `api_call` | `application` | agent |
| `embedding_query` | `application` | agent |
| `vector_store_write` | `application` | agent |
| `inter_agent_message` | `application` | agent |

### Execution / scheduling

| Telemetry Type | Sigma Category | Product |
|---------------|----------------|---------|
| `script_execution` | `process_creation` | — |
| `command_execute` | `process_creation` | — |
| `scheduled_task_create` | `process_creation` | windows |

### Unmapped types

Any telemetry type not in the table maps to `category: application` by default.

## Selection scaffolding

The generator creates logsource-aware skeleton selection criteria:

| Logsource Category | Generated Fields |
|-------------------|-----------------|
| `process_creation` / `create_remote_thread` / `process_termination` | `Image\|endswith`, `CommandLine\|contains` (if shell commands exist) |
| `network_connection` | `DestinationHostname\|contains` (if target URL exists) or `DestinationPort` |
| `file_event` / `file_change` / `file_access` | `TargetFilename\|contains` |
| `registry_set` / `registry_add` / `registry_event` | `TargetObject\|contains` |
| `dns_query` | `QueryName\|contains` |
| `authentication` | `LogonType` |
| `application` | `EventType` |

## Severity mapping

| Level | Tactics |
|-------|---------|
| `high` | initial-access, execution, exfiltration, impact, credential-access, lateral-movement, privilege-escalation, ml-attack-staging, ml-model-access |
| `medium` | persistence, defense-evasion, command-and-control, discovery, collection, reconnaissance, resource-development |

## Working with generated rules

Generated rules are scaffolds. Before deploying to a SIEM:

1. **Replace selection placeholders** — fill in `Image|endswith`, `CommandLine|contains`, etc. with patterns from your environment
2. **Adjust logsource** — add `product:` (windows, linux) and `service:` (sysmon, security) if needed
3. **Tune false positives** — replace the generic "Legitimate administrative activity" with specific exclusions
4. **Promote status** — change `experimental` to `test` or `stable` after validation

### Converting to SIEM queries

```bash
# Install sigma-cli
pip install sigma-cli pySigma-backend-splunk

# Convert to Splunk SPL
sigma convert -t splunk rules.yml

# Convert to Elastic KQL
sigma convert -t elasticsearch rules.yml

# Convert to Microsoft Sentinel
sigma convert -t microsoft365defender rules.yml
```

## Deterministic rule IDs

Rule IDs are SHA256-based UUIDs: `SHA256(campaign_name + "|" + stage_id + "|" + detection_name)`, formatted as `8-4-4-4-12` hex. The same campaign always produces the same rule IDs, making it safe to re-run exports without creating duplicate rules in your SIEM.
