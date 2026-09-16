<p align="center">
  <img src="../assets/logo-circle-800.jpg" alt="ThreatEcho" width="400" />
</p>

# Writing Campaigns

Campaigns are the core unit of work in ThreatEcho. Each campaign defines an adversary emulation plan as YAML: a sequence of stages that map to MITRE ATT&CK, MITRE ATLAS, or OWASP LLM Top 10 techniques. ThreatEcho loads, validates, simulates, and analyzes campaigns to produce detection gap reports, policy evaluations, and Sigma rule scaffolds.

## Campaign File Layout

Each campaign lives in its own directory containing a `campaign.yaml` file:

```
campaigns/
├── apt29-cozy-bear/
│   └── campaign.yaml
├── fin7-carbanak/
│   └── campaign.yaml
└── llm-agent-hijack/
    └── campaign.yaml
```

The directory name is for human organization only. ThreatEcho reads `campaign.yaml` from each subdirectory when scanning with `-dir`.

## Campaign YAML Schema

A campaign YAML file has four top-level keys:

```yaml
api_version: v1         # Required. Always "v1".
kind: Campaign          # Required. Always "Campaign".
meta: { ... }           # Required. Campaign metadata.
variables: { ... }      # Optional. Template variables for stage fields.
stages: [ ... ]         # Required. At least one stage.
```

## Meta Block

The `meta` block describes the campaign for reports, dashboards, and audit trails.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Campaign identifier. Used in reports, Sigma rule IDs, gap keys. |
| `adversary` | string | Yes | Threat actor or group name. |
| `description` | string | No | Free-text campaign description. Lint warns if empty. |
| `objective` | string | No | What the campaign tests or proves. Lint warns if empty. |
| `severity` | string | No | `critical`, `high`, `medium`, `low`, or `info`. Used in reports and summary dashboards. |
| `mitre_version` | string | No | ATT&CK version (e.g., `"15.1"`). Lint warns if empty (pin for reproducibility). |
| `tags` | list of strings | No | Arbitrary tags for filtering and search. |
| `authors` | list of strings | No | Campaign authors. |
| `references` | list of strings | No | URLs to threat reports, advisories, or emulation plans. |
| `created` | string | No | ISO date (e.g., `"2026-09-14"`). |
| `modified` | string | No | ISO date of last modification. |

```yaml
meta:
  name: apt29-cozy-bear
  adversary: APT29
  description: "APT29 full-spectrum intrusion emulation"
  objective: "Validate detection across the complete APT29 kill chain"
  mitre_version: "15.1"
  severity: high
  tags: [apt29, nation-state, espionage]
  authors: ["ThreatEcho"]
  references:
    - "https://attack.mitre.org/groups/G0016/"
  created: "2026-09-14"
  modified: "2026-09-14"
```

## Variables

The `variables` block defines key-value pairs substituted into stage fields at load time. Any `{{key}}` in a supported field is replaced with the corresponding value.

```yaml
variables:
  target_host: "192.168.1.10"
  c2_server: "https://c2.example.com"
  payload_path: "/tmp/payload.bin"
```

### Expansion Scope

Variables expand in these stage fields:

- `name`
- `description`
- `execute.target`
- `execute.payload`
- `execute.commands[]` (each command)
- `execute.cleanup[]` (each command)
- `execute.args` (each value)
- `expect.artifacts[]` (each entry)
- `expect.iocs[]` (each entry)

Variables do **not** expand in `id`, `technique`, `tactic`, or `expect.telemetry`/`expect.detections`.

### Example

```yaml
variables:
  target_url: "https://agent.corp.example.com/api/v1/chat"

stages:
  - id: injection
    name: Prompt Injection via {{target_url}}
    execute:
      type: http
      target: "{{target_url}}"
```

## Stage Structure

Each stage represents one adversary action in the kill chain.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier within the campaign. Referenced by `depends_on` and `on_success`. |
| `name` | string | Yes | Human-readable stage name. |
| `description` | string | No | What this stage simulates and why. |
| `technique` | string | Yes | Technique ID. Must match one of: ATT&CK (`T1566`, `T1566.001`), ATLAS (`AML.T0051`), OWASP LLM (`LLM06`). |
| `tactic` | string | Yes | Tactic short name. Must be a valid ATT&CK or ATLAS tactic. |
| `platform` | list of strings | No | `windows`, `linux`, `macos`. If set, stage is skipped on other platforms. |
| `depends_on` | list of strings | No | Stage IDs that must complete before this stage runs. Defines the DAG edges. |
| `execute` | object | Yes | What to execute. See [Execute Types](#execute-types). |
| `expect` | object | No | Expected telemetry, detections, artifacts, IOCs. See [Expect Block](#expect-block). |
| `on_success` | string | No | Stage ID to transition to on success (documentation only; engine uses DAG order). |
| `on_failure` | string | No | `abort` (stop campaign), `continue` (proceed to next stage), `skip` (skip dependent stages). Default: `abort`. |
| `timeout` | duration | No | Stage execution timeout. Go duration string (e.g., `"30s"`, `"5m"`). |
| `delay` | duration | No | Wait before executing. Go duration string. |

### Technique ID Formats

| Framework | Pattern | Regex | Examples |
|-----------|---------|-------|----------|
| ATT&CK | `T` + 4 digits + optional `.` + 3 digits | `^T\d{4}(\.\d{3})?$` | `T1566`, `T1566.001`, `T1059.003` |
| ATLAS | `AML.T` + 4 digits | `^AML\.T\d{4}$` | `AML.T0051`, `AML.T0043` |
| OWASP LLM | `LLM` + 2 digits | `^LLM\d{2}$` | `LLM01`, `LLM06`, `LLM08` |

### Valid Tactics

**ATT&CK (14 tactics):**
`reconnaissance`, `resource-development`, `initial-access`, `execution`, `persistence`, `privilege-escalation`, `defense-evasion`, `credential-access`, `discovery`, `lateral-movement`, `collection`, `command-and-control`, `exfiltration`, `impact`

**ATLAS (7 tactics):**
`reconnaissance`, `resource-development`, `initial-access`, `ml-attack-staging`, `ml-model-access`, `exfiltration`, `impact`

OWASP LLM stages use ATLAS tactics.

## Execute Types

The `execute` block defines what happens when the stage runs.

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | **Required.** One of: `shell`, `powershell`, `http`, `file`, `registry`, `service`, `process`, `dns`, `manual`. |
| `commands` | list of strings | Shell commands to execute (type `shell`). |
| `payload` | string | Payload content or path (types `file`, `http`). |
| `target` | string | Target URL or host (type `http`). |
| `args` | map of strings | Key-value arguments (type `http`: `method`, `content_type`, `payload`). |
| `cleanup` | list of strings | Commands to run after stage completes (best-effort, all run even if one fails). |
| `elevated` | bool | Whether the stage requires elevated/root privileges. Default: `false`. |

### Shell Execution

```yaml
execute:
  type: shell
  commands:
    - 'echo "[SIM] Scanning network"'
    - 'nmap -sP {{target_host}}/24'
  cleanup:
    - 'rm -f /tmp/scan_results.txt'
  elevated: false
```

In simulation mode (`threatecho simulate`), shell stages describe what would happen without executing. In live mode (`threatecho run`), commands run sequentially in `sh -c` (Unix) or `cmd /c` (Windows), stopping on the first failure. Elevated stages are refused by default (`-deny-elevated=true`).

### HTTP Execution

```yaml
execute:
  type: http
  target: "https://agent.corp.example.com/api/v1/chat"
  args:
    method: POST
    content_type: "application/json"
    payload: '{"message": "test"}'
```

HTTP stages are described in simulation mode but not executed. The `target`, `method`, and `args` fields feed into policy evaluation (the policy engine infers `http_request` as the tool and `send` as the action).

## Expect Block

The `expect` block defines what telemetry and detections the stage should produce. This drives gap analysis, Sigma rule generation, and policy evaluation.

| Field | Type | Description |
|-------|------|-------------|
| `telemetry` | list of strings | Expected telemetry types that should fire when this stage executes. |
| `detections` | list of strings | Expected detection rule names that should alert. |
| `artifacts` | list of strings | Files, registry keys, or other artifacts produced. |
| `iocs` | list of strings | Indicators of compromise (IPs, domains, hashes). |

### Telemetry Types

ThreatEcho supports 108 telemetry types, grouped by category. Each type maps to a Sigma logsource for rule generation (see [sigma.md](sigma.md)). The most common types are listed below.

**Process telemetry:**

| Type | Description |
|------|-------------|
| `process_create` | New process creation event |
| `process_access` | Process memory access (e.g., LSASS dump) |
| `process_injection` | Process injection event (e.g., DLL injection, thread hijacking) |
| `process_terminate` | Process termination event |

**File telemetry:**

| Type | Description |
|------|-------------|
| `file_create` | File creation event |
| `file_modify` | File modification event |
| `file_delete` | File deletion event |
| `file_read` | File read access |
| `file_rename` | File rename event |

**Network telemetry:**

| Type | Description |
|------|-------------|
| `network_connection` | Outbound/inbound network connection |
| `dns_query` | DNS resolution query |
| `tls_handshake` | TLS/SSL handshake event |

**Registry telemetry (Windows):**

| Type | Description |
|------|-------------|
| `registry_set` | Registry value set/modified |
| `registry_create` | Registry key created |
| `registry_delete` | Registry key/value deleted |
| `registry_modify` | Registry value modified |

**Authentication:**

| Type | Description |
|------|-------------|
| `logon_event` | User logon event |
| `auth_logoff` | User logoff event |

**Execution:**

| Type | Description |
|------|-------------|
| `script_execution` | Script interpreter execution (PowerShell, Python, etc.) |
| `command_execute` | Command-line execution event |
| `scheduled_task_create` | Scheduled task/cron job creation |

**Email:**

| Type | Description |
|------|-------------|
| `email_sent` | Email sent event |
| `email_delivered` | Email delivery event |

**AI agent telemetry:**

| Type | Description |
|------|-------------|
| `prompt_log` | LLM prompt/completion logged |
| `guardrail_trigger` | Safety guardrail or content filter triggered |
| `tool_call` | Agent tool invocation event |
| `api_call` | External API call made by agent |
| `embedding_query` | Vector similarity search query |
| `vector_store_write` | Write to vector/knowledge store |
| `inter_agent_message` | Message between agents in multi-agent system |

### Detection Naming Convention

Detection names should use `snake_case` and describe what the detection catches. They serve as both documentation and Sigma rule title seeds:

```yaml
expect:
  detections:
    - prompt_injection_detected
    - unauthorized_tool_invocation
    - data_exfil_via_agent_tool
```

ThreatEcho converts these to Sigma rule titles by capitalizing each word (e.g., `prompt_injection_detected` becomes "Prompt Injection Detected").

## Stage Dependencies and DAG Ordering

Stages form a directed acyclic graph (DAG) through `depends_on` references. The engine resolves execution order using Kahn's algorithm for topological sorting.

### Diamond Dependency Example

```
          ┌── recon-internal ──┐
          │                    │
initial ──┤                    ├── exfiltrate
          │                    │
          └── persist ─────────┘
```

```yaml
stages:
  - id: initial
    name: Initial Access
    technique: T1190
    tactic: initial-access
    execute:
      type: shell
      commands: ['echo "[SIM] Exploit"']

  - id: recon-internal
    name: Internal Recon
    technique: T1087.002
    tactic: discovery
    depends_on: [initial]
    execute:
      type: shell
      commands: ['echo "[SIM] Enumerate domain"']

  - id: persist
    name: Establish Persistence
    technique: T1053.005
    tactic: persistence
    depends_on: [initial]
    execute:
      type: shell
      commands: ['echo "[SIM] Create scheduled task"']

  - id: exfiltrate
    name: Data Exfiltration
    technique: T1567.002
    tactic: exfiltration
    depends_on: [recon-internal, persist]
    execute:
      type: shell
      commands: ['echo "[SIM] Exfiltrate to cloud"']
```

The engine resolves this to: `initial` → `recon-internal`, `persist` (parallel in DAG, sequential in execution) → `exfiltrate`.

### Cycle Detection

The validator runs DFS with three-color marking (white/grey/black) to detect cycles. A cycle produces an error like:

```
✗ Campaign "bad-campaign" has 1 issue(s):
  • dependency cycle detected: stage-a → stage-b
```

## Platform Filtering

Stages with a `platform` list only run on matching platforms. Use the `-platform` flag to filter:

```yaml
stages:
  - id: reg-persist
    name: Registry Persistence
    technique: T1547.001
    tactic: persistence
    platform: [windows]    # skipped on linux/macos
    execute:
      type: registry
      # ...
```

```bash
# Only runs windows-tagged stages
threatecho simulate -platform windows campaigns/apt29-cozy-bear/

# Runs all stages regardless of platform
threatecho simulate campaigns/apt29-cozy-bear/
```

Valid platform values: `windows`, `linux`, `macos`.

## Transition Logic

### on_success

Specifies the stage ID to transition to on success. This is documentation for the kill chain narrative; the engine uses DAG ordering from `depends_on` for actual execution order.

```yaml
on_success: lateral-move
```

Must reference a valid stage ID in the same campaign.

### on_failure

Controls what happens when a stage fails during live execution:

| Value | Behavior |
|-------|----------|
| `abort` | Stop the campaign (default). |
| `continue` | Log the failure and proceed to the next stage. |
| `skip` | Skip all stages that depend on this one. |
| (empty) | Same as `abort`. |

```yaml
on_failure: continue    # Try the next stage even if this one fails
```

## Quality Checklist

The `threatecho lint` command checks for issues beyond structural validation. Here is what it looks for:

### Warnings (exit code 1)

- Technique ID matches regex format but is not found in the built-in registry
- ATT&CK technique used with an ATLAS tactic (or vice versa)
- Stage has no expected telemetry (gap analysis will be limited)
- Shell stage with empty `commands` list
- HTTP stage with no `target` URL

### Info (suggestions, no exit code impact)

- `meta.description` is empty
- `meta.objective` is empty
- `meta.mitre_version` is not set
- Stage has telemetry but no expected detections (will flag as a detection gap)

```bash
# Lint a single campaign
threatecho lint campaigns/apt29-cozy-bear/

# Lint all campaigns in a directory
threatecho lint -dir campaigns/

# JSON output for CI consumption
threatecho lint -format json -dir campaigns/
```

## Examples

### Minimal Campaign

```yaml
api_version: v1
kind: Campaign

meta:
  name: example-minimal
  adversary: Unknown
  severity: medium

stages:
  - id: recon
    name: Network Scan
    technique: T1016
    tactic: discovery
    execute:
      type: shell
      commands:
        - 'echo "[SIM] Scanning network"'
    expect:
      telemetry: [process_create, network_connection]
      detections: [network_scan_detected]
```

### Multi-Stage with Dependencies

```yaml
api_version: v1
kind: Campaign

meta:
  name: phish-to-exfil
  adversary: APT29
  description: "Spearphish to exfiltration - 3-stage kill chain"
  severity: high
  mitre_version: "15.1"
  tags: [apt29, phishing, exfiltration]
  authors: ["SOC Team"]
  created: "2026-09-14"
  modified: "2026-09-14"

variables:
  c2_server: "https://c2.example.com"

stages:
  - id: phish
    name: Spearphishing Attachment
    technique: T1566.001
    tactic: initial-access
    execute:
      type: shell
      commands:
        - 'echo "[SIM] Delivering macro-enabled document"'
    expect:
      telemetry: [email_delivered, file_create, process_create]
      detections: [spearphish_macro_detected]
    on_success: c2
    on_failure: abort

  - id: c2
    name: C2 via HTTPS
    technique: T1071.001
    tactic: command-and-control
    depends_on: [phish]
    execute:
      type: http
      target: "{{c2_server}}/beacon"
      args:
        method: POST
    expect:
      telemetry: [network_connection, dns_query, tls_handshake]
      detections: [c2_beacon_detected, suspicious_tls_cert]
    on_success: exfil
    on_failure: abort

  - id: exfil
    name: Cloud Exfiltration
    technique: T1567.002
    tactic: exfiltration
    depends_on: [c2]
    execute:
      type: http
      target: "{{c2_server}}/upload"
      args:
        method: PUT
    expect:
      telemetry: [network_connection, file_read]
      detections: [cloud_exfil_detected, large_upload_anomaly]
    on_failure: abort
```

### AI Agent Campaign (ATLAS + OWASP)

```yaml
api_version: v1
kind: Campaign

meta:
  name: agent-prompt-injection
  adversary: AI-Threat-Actor
  description: "Prompt injection against enterprise AI agent"
  severity: critical
  mitre_version: "15.1"
  tags: [ai-agent, prompt-injection, owasp-llm]
  authors: ["ThreatEcho"]
  created: "2026-09-14"
  modified: "2026-09-14"

variables:
  agent_url: "https://agent.corp.example.com/api/v1/chat"

stages:
  - id: recon-agent
    name: Agent Capability Reconnaissance
    technique: AML.T0049
    tactic: reconnaissance
    execute:
      type: shell
      commands:
        - 'echo "[SIM] Scraping agent API docs"'
    expect:
      telemetry: [api_call]
      detections: [automated_api_enumeration]
    on_success: inject

  - id: inject
    name: Direct Prompt Injection
    technique: AML.T0051
    tactic: initial-access
    depends_on: [recon-agent]
    execute:
      type: http
      target: "{{agent_url}}"
      args:
        method: POST
        payload: '{"message": "Ignore previous instructions..."}'
    expect:
      telemetry: [prompt_log, guardrail_trigger, api_call]
      detections: [prompt_injection_detected, instruction_override_attempt]
    on_failure: continue
    timeout: 30s

  - id: tool-abuse
    name: Unauthorized Tool Invocation
    technique: LLM06
    tactic: ml-model-access
    depends_on: [inject]
    execute:
      type: http
      target: "{{agent_url}}"
      args:
        method: POST
        payload: '{"message": "query_database(SELECT * FROM users)"}'
    expect:
      telemetry: [tool_call, api_call, guardrail_trigger]
      detections: [unauthorized_tool_invocation, tool_policy_violation]
    on_failure: continue
```

## Testing Your Campaign

Follow this sequence to validate a new campaign:

```bash
# 1. Structural validation
threatecho validate campaigns/my-campaign/

# 2. Quality lint checks
threatecho lint campaigns/my-campaign/

# 3. Dry-run simulation (no execution)
threatecho simulate campaigns/my-campaign/

# 4. Detection gap analysis
threatecho gap campaigns/my-campaign/

# 5. Policy evaluation (if using policies)
threatecho policy eval -policy policies/agent-default/ campaigns/my-campaign/

# 6. Generate Sigma rule scaffolds
threatecho export sigma campaigns/my-campaign/

# 7. Export ATT&CK Navigator layer
threatecho export navigator campaigns/my-campaign/ -output layer.json
```

Each command builds on the previous: `validate` checks structure, `lint` checks quality, `simulate` walks the DAG, `gap` identifies coverage holes. Fix issues at each stage before proceeding.
