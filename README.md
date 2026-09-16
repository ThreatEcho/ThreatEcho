<p align="center">
  <a href="https://threatecho.com">
    <img src="assets/banner.png" alt="ThreatEcho — Advanced Threats Simulations & Detection Engineering for AI Agents" width="600" />
  </a>
</p>

<p align="center">
  <img src="assets/logo-circle-800.jpg" alt="ThreatEcho" width="160" />
</p>

<h1 align="center">ThreatEcho</h1>

<p align="center">
  <strong>Detection Engineering for AI Agents</strong>
</p>

<p align="center">
  <a href="#install">Install</a> •
  <a href="#quick-start">Quickstart</a> •
  <a href="#features">Features</a> •
  <a href="#commands">Commands</a> •
  <a href="CHANGELOG.md">Changelog</a> •
  <a href="docs/architecture.md">Architecture</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/go-1.26+-00ADD8?logo=go" alt="Go 1.26+" />
  <img src="https://img.shields.io/badge/tests-3%2C539_passing-brightgreen" alt="Tests" />
  <img src="https://img.shields.io/badge/campaigns-72-blue" alt="Campaigns" />
  <img src="https://img.shields.io/badge/license-AGPL--3.0-purple" alt="License" />
</p>

---

Adversary campaign simulation engine for AI agent security. Define multi-stage attack campaigns as code, enforce tool-call policies, analyze delegation chains, generate STRIDE threat models, and validate detection coverage — across both AI agent systems and classical infrastructure.

Mapped to **MITRE ATT&CK**, **MITRE ATLAS**, and **OWASP LLM Top 10**.

## Install

```bash
go install github.com/ThreatEcho/threatecho/cmd/threatecho@latest
```

Or build from source:

```bash
git clone https://github.com/ThreatEcho/threatecho.git
cd threatecho
make build
```

## Quick start

```bash
# 1. Initialize a workspace with an example campaign
threatecho init

# 2. Validate and lint the built-in campaigns
threatecho validate campaigns/apt29-cozy-bear/
threatecho lint campaigns/apt29-cozy-bear/

# 3. Simulate a full kill chain (dry-run, no execution)
threatecho simulate campaigns/apt29-cozy-bear/

# 4. Analyze detection gaps across all campaigns
threatecho gap -dir campaigns/

# 5. Evaluate an agent tool-call policy
threatecho policy eval -policy policies/agent-default/ campaigns/llm-agent-hijack/
```

For CI pipelines, use structured output:

```bash
threatecho gap -format sarif -dir campaigns/ > gaps.sarif    # GitHub Code Scanning
threatecho gap -format junit -dir campaigns/ > gaps.xml      # Jenkins / GitHub Actions
threatecho simulate -format json campaigns/apt29-cozy-bear/  # Machine-readable
threatecho deploy -q -inventory targets.yaml campaigns/      # Exit code only
```

<details>
<summary><strong>Full command examples</strong> (click to expand)</summary>

```bash
# Campaign management
threatecho campaigns list
threatecho search -technique T1059 -dir campaigns/
threatecho search -tactic execution -platform windows
threatecho stats -dir campaigns/
threatecho profile -dir campaigns/
threatecho diff campaigns/apt29-cozy-bear/ campaigns/apt29-v2/
threatecho merge -prefix campaigns/apt29-cozy-bear/ campaigns/apt28-fancy-bear/
threatecho convert -format json campaigns/apt29-cozy-bear/
threatecho enrich -dir campaigns/
threatecho score -dir campaigns/

# Policy engine
threatecho policy test policies/agent-strict/
threatecho policy test -suite tests.yaml policies/agent-strict/
threatecho policy test -generate policies/agent-strict/ > policy-tests.yaml
threatecho policy lint policies/agent-default/
threatecho policy drift policies/v1/ policies/v2/
threatecho policy impact -before policies/v1/ -after policies/v2/ -agents agents/

# Risk and compliance
threatecho threat-model -policy policies/agent-strict/ -agents agents/
threatecho risk-posture -policy policies/agent-strict/ -agents agents/
threatecho compliance -policy policies/ -agents agents/ -framework nist-ai-rmf
threatecho dashboard -policy policies/ -agents agents/ -output report.html

# Agent analysis
threatecho agent trust -dir agents/
threatecho agent chain -dir agents/
threatecho agent dependency -dir agents/

# Remote deployment (SSH + WinRM)
threatecho deploy -target 10.0.0.1 -user operator -key ~/.ssh/id_rsa campaigns/art-discovery-linux/
threatecho deploy -target 10.0.0.5 -os windows -user 'DOMAIN\Admin' -password P@ss campaigns/art-discovery-windows/
threatecho deploy -inventory targets.yaml -parallel -verbose campaigns/apt29-cozy-bear/
threatecho deploy -validate -inventory targets.yaml campaigns/apt29-cozy-bear/

# Exports
threatecho export navigator -dir campaigns/ -output coverage.json
threatecho export sigma -dir campaigns/ -output rules.yml
threatecho matrix -dir campaigns/

# Baseline and drift
threatecho deploy-baseline -policy policies/ -agents agents/ -label "v1.0" -output baseline.json
threatecho deploy-baseline -policy policies/ -agents agents/ -compare baseline.json

# Workspace tools
threatecho doctor
threatecho config show
threatecho config init
threatecho watch -dir campaigns/
threatecho template list
threatecho template create -template apt -name my-apt-campaign
threatecho import -source atomic path/to/atomics/
threatecho completion bash > /etc/bash_completion.d/threatecho
```

</details>

## Detection gap analysis

The `gap` command is the core detection engineering tool. It simulates campaigns and produces a risk-scored gap report:

```bash
# Analyze all campaigns, output as text
threatecho gap -dir campaigns/

# Analyze specific campaigns with JSON output
threatecho gap -format json campaigns/apt29-cozy-bear/ campaigns/llm-agent-hijack/

# SARIF output for GitHub Code Scanning / VS Code
threatecho gap -format sarif -dir campaigns/ > gaps.sarif

# JUnit XML for Jenkins / GitHub Actions / GitLab CI
threatecho gap -format junit -dir campaigns/ > gaps.xml

# Filter by platform
threatecho gap -platform linux -dir campaigns/
```

The gap report identifies:
- **Uncovered tactics** — ATT&CK and ATLAS tactics with zero stage coverage
- **Detection gaps** — stages that generate telemetry but have no detection rules
- **Telemetry gaps** — stages with no expected telemetry (blind spots)
- **Risk scoring** — each gap rated critical/high/medium/low with an aggregate score

## Campaign as code

Campaigns are defined in YAML with a structured schema:

```yaml
api_version: v1
kind: Campaign

meta:
  name: apt29-cozy-bear
  adversary: APT29
  severity: critical
  mitre_version: "15.1"

variables:
  c2_server: "10.0.0.50"

stages:
  - id: initial-access
    name: Spearphishing Attachment
    technique: T1566.001
    tactic: initial-access
    execute:
      type: shell
      commands:
        - 'echo "[SIM] Delivering payload via email"'
    expect:
      telemetry: [file_create, process_create]
      detections: [spearphish_attachment_detected]
    on_success: c2-beacon
    on_failure: abort

  - id: c2-beacon
    name: HTTPS C2 Beacon
    technique: T1071.001
    tactic: command-and-control
    depends_on: [initial-access]
    execute:
      type: http
      target: "https://{{c2_server}}/beacon"
      args:
        method: POST
    expect:
      telemetry: [network_connection, dns_query]
      detections: [c2_https_beacon]
    on_failure: abort
```

AI agent campaigns use MITRE ATLAS and OWASP LLM techniques:

```yaml
stages:
  - id: prompt-injection
    name: Direct Prompt Injection
    technique: AML.T0051
    tactic: initial-access
    execute:
      type: http
      target: "https://agent.target.com/api/v1/chat"
    expect:
      telemetry: [prompt_log, guardrail_trigger, api_call]
      detections: [prompt_injection_detected, instruction_override_attempt]

  - id: tool-abuse
    name: Unauthorized Tool Invocation
    technique: LLM06
    tactic: ml-model-access
    depends_on: [prompt-injection]
    execute:
      type: http
      target: "https://agent.target.com/api/v1/chat"
    expect:
      telemetry: [tool_call, api_call, guardrail_trigger]
      detections: [unauthorized_tool_invocation, tool_policy_violation]
```

## Policy assertion testing

Write declarative test suites to verify your policies behave as expected:

```yaml
api_version: v1
kind: PolicyTestSuite
meta:
  name: agent-strict-tests
  policy: agent-strict
tests:
  - id: deny-shell
    name: Must deny shell execution
    input:
      tool: shell_exec
      tactic: execution
    expect:
      effect: deny
      rule_id: deny-shell-exec

  - id: allow-search
    name: Must allow knowledge base search
    input:
      tool: search_knowledge_base
    expect:
      effect: allow

  - id: no-match-safe
    name: Harmless tools should not match
    input:
      tool: get_weather
    expect:
      no_match: true
```

Run with `threatecho policy test -suite tests.yaml policies/agent-strict/`.

## Features

- **Campaign as code**: YAML-defined adversary campaigns with dependencies, branching, variables, platform targeting
- **Full kill chain simulation**: Multi-stage operations from initial access through exfiltration
- **Detection gap analysis**: Risk-scored gap reports showing uncovered tactics, missing detections, telemetry blind spots
- **Agent tool-call policies**: Declarative YAML DSL for deny/allow/alert rules on agent tool invocations — the detection engineering layer for AI agents
- **Policy assertion testing**: Write YAML test suites with effect/rule-id/no-match expectations to verify policy behavior — auto-generate from rules
- **Deployment baseline & drift**: Capture point-in-time posture snapshots, diff baselines with severity-ranked change detection and risk delta scoring
- **Policy impact analysis**: Before/after policy comparison showing exactly what changes in agent coverage
- **Agent dependency graph**: Visualize trust relationships, delegation chains, and capability dependencies
- **Compliance framework mapping**: Map policies and agents to NIST AI RMF, OWASP LLM Top 10, MITRE ATLAS (AI), plus NIST CSF, NIST 800-53, CIS v8 (SOC) — 6 frameworks total
- **HTML security dashboard**: One-command assessment report with all analysis dimensions
- **Sigma rule generation**: Export Sigma detection rules with real selection criteria (65 techniques mapped) — bridges simulation to detection engineering
- **ATT&CK Navigator export**: Generate Navigator layer v4.5 JSON for technique coverage visualization
- **ATT&CK coverage matrix**: Terminal-rendered technique×tactic heatmap with color-coded coverage levels
- **Technique-level coverage**: Drill-down analysis showing each technique's detection readiness across campaigns
- **Security posture dashboard**: Aggregate view across all campaigns, gaps, policies, and lint results
- **Configuration file**: Layered config system — project `.threatecho.yaml`, user config, env vars
- **Campaign linting**: Quality checks beyond validation — technique registry verification, framework/tactic consistency, telemetry readiness
- **Coverage comparison**: Before/after delta analysis for ROI measurement
- **Remote deployment**: Deploy campaigns to remote targets via SSH (Linux/macOS) and WinRM/NTLM (Windows) — agentless command execution on all platforms, or push agent binary + pull JSON report (Linux/Windows), multi-target inventory with parallel execution, per-stage timeout enforcement, mixed-OS deploys
- **Live execution**: Run campaigns against real systems with safety controls (process group isolation, elevated denial, output capping)
- **AI agent security**: First-class support for MITRE ATLAS and OWASP LLM Top 10 techniques
- **Multi-framework coverage**: MITRE ATT&CK (classical), MITRE ATLAS (adversarial AI), OWASP LLM Top 10 (agent security)
- **Campaign fingerprinting**: SHA256 content hashing for reproducibility, caching, change detection, CI cache keys
- **Dependency graph analysis**: Entry points, critical path, parallel levels, dead transitions, DOT/Mermaid export
- **Telemetry type registry**: 108 recognized types across 16 categories with lint validation and typo correction
- **Campaign diff**: Structural comparison between two campaigns — stage-level field diff, variable changes, meta changes
- **Campaign merge**: Combine multiple campaigns into composite assessments with namespace prefixing and collision strategies
- **Complexity profiling**: Multi-factor complexity scoring (0-100) with letter grades, execution profiles, coverage metrics
- **Shell completions**: bash, zsh, and fish completion scripts for all commands and flags
- **Watch mode**: Live re-validation on file save with cross-platform polling-based file watcher
- **Campaign templates**: 7 built-in scaffolds (APT, ransomware, insider, AI agent, supply chain, cloud, minimal)
- **Execution timeline**: DAG-aware duration estimation with critical path, speedup ratio, and parallel execution levels
- **Environment variable expansion**: `${env:VAR}` syntax for runtime secret injection alongside `{{variable}}` templates
- **Campaign search**: Multi-dimensional search across all campaigns — 9 filter fields (technique, tactic, adversary, tag, keyword, severity, stage, platform, exec type) with AND logic and prefix matching
- **Project analytics**: Aggregate dashboard with technique frequency, tactic distribution, detection coverage percentages, execution complexity, and dependency graph metrics
- **Atomic Red Team import**: Import ART YAML tests directly into ThreatEcho campaigns — executor mapping, tactic resolution, telemetry inference, platform filtering, stage ID sanitization
- **ATT&CK enrichment**: Auto-annotate campaign stages with data sources, mitigations, detection notes, and severity inference — 60 techniques with real ATT&CK metadata, sub-technique inheritance
- **Risk scoring**: Five-dimension campaign scoring (technique complexity, tactic breadth, detection difficulty, execution complexity, evasion sophistication) with A-F grades and score factor auditability
- **Format conversion**: Convert campaigns between JSON, YAML (normalized), Markdown (badges + tables), and CSV (RFC 4180) — single-file and bulk directory conversion with JSON round-trip support
- **DAG execution**: Topologically-sorted stage execution with dependency resolution
- **CI/CD output formats**: Text, JSON, SARIF v2.1.0 (GitHub Code Scanning, VS Code), JUnit XML (Jenkins, GitHub Actions, GitLab CI), HTML, Markdown
- **Tag management**: Taxonomy across campaigns with usage counts, content-based tag suggestions (10 rules), and tag-based campaign search
- **Executive reports**: Combined assessment report pulling stats, risk scores, coverage data, and auto-generated recommendations into one stakeholder-ready document (text + Markdown)
- **Campaign auditing**: Point-in-time snapshots with SHA256 fingerprints, JSON persistence, and diff comparison (added/removed/modified tracking)
- **Policy lint**: 25 best-practice rules across 6 categories with A-F grading — CI-ready (exit 2 on errors)
- **Policy drift detection**: 9 drift types, 5 severity levels — catch policy regressions between versions
- **Policy coverage mapping**: Maps every rule to MITRE ATT&CK techniques, identifies uncovered gaps
- **Policy remediation**: Generates concrete fix suggestions (YAML before/after) from lint, drift, and coverage findings
- **Policy templates**: 6 built-in templates (agent-minimal, agent-strict, rag-safe, autonomous-guardrailed, compliance-soc2, tool-calling-restricted) with parameterized rendering
- **STRIDE threat modeling**: Auto-generates per-agent threat models across all 6 STRIDE categories with mitigation status assessment
- **Unified risk posture**: Combines lint, coverage, chain analysis, and threat model into a single A-F risk grade
- **Agent behavior profiling**: Builds baselines from traces, detects 7 deviation types (new tool, frequency spike, timing anomaly, etc.)
- **Agent chain analysis**: Enumerates delegation chains, detects 5 violation types (escalation, boundary cross, confused deputy)
- **Agent attestation**: Cryptographic SHA-256 fingerprinting of agent configurations with 4 claim types (tool access, trust boundary, capability, guardrail)
- **Multi-trace correlation**: Cross-agent attack pattern detection with 8 built-in correlation rules
- **Scenario engine**: YAML-defined test cases binding campaigns to policies with pass criteria evaluation
- **SARIF v2.1.0 export**: Standard security output for GitHub Code Scanning, GitLab SAST, VS Code integration
- **Pure Go, two binaries**: No Python, no Docker, cross-compiled for Linux, Windows, macOS (CLI + optional agent)
- **Production CI pipeline**: GitHub Actions workflow with SARIF → Code Scanning, cross-platform build matrix

## Commands

| Command | Description |
|---------|-------------|
| `validate <path>` | Validate a campaign YAML file or directory |
| `lint <path...>` | Run quality checks beyond structural validation |
| `simulate <path>` | Dry-run a campaign without executing anything |
| `run <path>` | Execute a campaign live (shell stages only) |
| `deploy <campaign>` | Deploy campaign to remote targets via SSH/WinRM (agentless or agent mode) |
| `gap <path...>` | Analyze detection coverage gaps across campaigns |
| `compare <before> <after>` | Compare detection coverage between two campaign sets |
| `summary` | Security posture dashboard across all campaigns |
| `matrix` | ATT&CK technique coverage matrix (terminal heatmap) |
| `coverage` | Technique-level coverage analysis (text/JSON) |
| `policy validate <path>` | Validate a policy YAML file |
| `policy eval -policy <p> <c>` | Evaluate a policy against campaigns |
| `policy test <path>` | Test policy against built-in attack scenarios |
| `policy test -suite <file>` | Run assertion test suite against a policy |
| `policy test -generate` | Auto-generate test suite from policy rules |
| `policy lint <path>` | 25-rule best-practice check with A-F grading |
| `policy impact` | Before/after impact analysis of policy changes |
| `policy coveragemap <path>` | Map rules to MITRE ATT&CK techniques |
| `policy drift <old> <new>` | Detect semantic drift between policy versions |
| `policy remediate <path>` | Generate fix suggestions from analysis findings |
| `policy compile <path>` | Compile policy and detect rule conflicts |
| `policy merge <a> <b>` | Merge multiple policies |
| `policy generate` | Generate policy from built-in templates |
| `policy risk <path>` | Risk posture of a single policy |
| `policy diff <old> <new>` | Compare two policies and show differences |
| `policy coverage <path>` | Analyze policy coverage vs reference set |
| `policy simulate` | Dry-run a campaign against a policy (no execution) |
| `policy export <path>` | Export policy in JSON, YAML, or Rego format |
| `policy guardrail <path>` | Analyze guardrail coverage against traces |
| `policy history <path>` | Policy version history and change tracking |
| `policy compliance <path>` | Trace compliance evaluation |
| `policy benchmark <path>` | Performance benchmarking |
| `export navigator [paths]` | Export ATT&CK Navigator layer JSON (v4.5) |
| `export sigma [paths]` | Generate Sigma detection rule scaffolds |
| `campaigns list` | List available campaigns |
| `campaigns show <name>` | Show campaign details |
| `config show` | Display resolved configuration |
| `config path` | Show config file search paths |
| `config init` | Create `.threatecho.yaml` project config |
| `hash <path>` | SHA256 content fingerprint for reproducibility |
| `graph analyze <path>` | Dependency graph analysis (entry points, depth, critical path) |
| `graph dot <path>` | Export Graphviz DOT diagram |
| `graph mermaid <path>` | Export Mermaid diagram (GitHub rendering) |
| `fmt <path>` | Canonically format campaign YAML |
| `doctor` | Workspace health check (campaigns, policies, config, telemetry) |
| `telemetry list` | List all 108 recognized telemetry types |
| `telemetry categories` | Show telemetry categories with type counts |
| `telemetry check <type>` | Validate a telemetry type (with typo correction) |
| `telemetry stats` | Telemetry usage report across campaigns |
| `diff <a> <b>` | Structural diff between two campaigns |
| `merge <a> <b> [...]` | Combine campaigns into composite assessment |
| `profile <path>` | Campaign complexity profile and metrics |
| `completion bash\|zsh\|fish` | Generate shell completion scripts |
| `watch` | Watch campaign files for live re-validation |
| `template list` | List available campaign templates |
| `template create` | Generate campaign scaffold from template |
| `timeline <path>` | Estimate campaign execution time from DAG |
| `search` | Search campaigns by technique, tactic, adversary, keyword |
| `stats` | Project-wide campaign analytics dashboard |
| `import -source atomic <path>` | Import Atomic Red Team tests as campaigns |
| `enrich [path]` | Enrich stages with ATT&CK metadata |
| `score [path]` | Campaign risk/complexity scoring (5 dimensions, A-F grade) |
| `convert -format <fmt> <path>` | Convert campaigns (JSON, YAML, Markdown, CSV) |
| `env <path>` | Show environment variable references |
| `init [dir]` | Initialize a new campaign workspace |
| `agent list` | List agents in inventory |
| `agent show <name>` | Show agent details |
| `agent validate <path>` | Validate an agent definition file |
| `agent test -policy <p>` | Evaluate agent tool coverage against a policy |
| `agent dependency` | Agent dependency graph |
| `agent chain` | Delegation chain analysis (5 violation types) |
| `agent attest` | Cryptographic config fingerprinting |
| `agent profile` | Behavioral profiling from execution traces |
| `agent trust` | Trust level assessment |
| `agent graph` | Agent relationship graph |
| `agent guardrail` | Analyze guardrail coverage and gaps |
| `agent export` | Export inventory report (JSON/YAML/Markdown) |
| `threat-model` | STRIDE-based threat model for agent deployments |
| `risk-posture` | Unified A-F risk grade across all dimensions |
| `compliance` | Map to 6 frameworks (NIST AI RMF, OWASP LLM, ATLAS, NIST CSF, 800-53, CIS v8) |
| `dashboard` | Generate HTML security assessment dashboard |
| `deploy-baseline` | Capture/diff deployment posture snapshots |
| `scenario run` | Execute YAML-defined test scenarios |
| `scenario validate` | Validate scenario definitions |
| `scenario list` | List available scenarios |
| `trace replay` | Replay and analyze agent execution traces |
| `trace correlate` | Cross-agent attack pattern detection |
| `trace forensics` | Forensic analysis with evidence chains and IOC extraction |
| `report` | Executive assessment report (text/Markdown) combining analytics and recommendations |
| `attack-tree` | Build attack trees from agent inventory with probabilistic risk scoring |
| `tag` | Tag management — list tags, find campaigns by tag, get suggestions |
| `audit` | Campaign state snapshot and change tracking |
| `baseline` | Behavioral baseline and drift detection across campaigns |
| `version` | Print version information |

### Exit codes

| Code | Name | Meaning |
|------|------|---------|
| 0 | OK | Successful execution |
| 1 | Validation | Campaign/policy YAML validation failed, lint warnings |
| 2 | PolicyDenied | Policy evaluation found denied violations |
| 3 | Runtime | Simulation, execution, or export error |
| 4 | IO | File/directory not found or unreadable |
| 64 | Usage | Missing arguments, unknown command |

CI pipelines can branch on exit code without parsing stderr.

## Built-in campaigns

### Classical adversary emulation

| Campaign | Adversary | Origin | Stages | Techniques | Severity |
|----------|-----------|--------|--------|------------|----------|
| apt28-fancy-bear | APT28 | Russia / GRU | 11 | 11 ATT&CK | Critical |
| apt29-cozy-bear | APT29 | Russia / SVR | 8 | 8 ATT&CK | Critical |
| fin7-carbanak | FIN7 | Financial crime | 10 | 10 ATT&CK | Critical |
| lazarus-group | Lazarus | DPRK | 12 | 12 ATT&CK | Critical |
| lockbit-ransomware | LockBit | RaaS | 12 | 12 ATT&CK | Critical |
| volt-typhoon | Volt Typhoon | China / PRC | 11 | 11 ATT&CK | High |
| scattered-spider | Scattered Spider | Identity / Cloud | 11 | 11 ATT&CK | Critical |
| apt-lateral-movement | APT29 | Lateral movement focus | 5 | 5 ATT&CK | Critical |
| api-key-compromise | FIN7 | API key theft chain | 5 | 4 ATT&CK | High |
| cloud-privilege-escalation | Scattered Spider | Cloud account takeover | 4 | 4 ATT&CK | Critical |
| credential-spray | APT33 | Password spray campaign | 4 | 4 ATT&CK | High |
| data-staging-exfil | APT1 | Data staging to exfiltration | 5 | 5 ATT&CK | Critical |
| insider-threat | Insider | Valid accounts abuse | 5 | 5 ATT&CK | High |
| living-off-the-land | Volt Typhoon | LOLBins-only chain | 5 | 5 ATT&CK | High |
| ransomware-simulation | LockBit | Ransomware kill chain | 5 | 4 ATT&CK | Critical |
| supply-chain-compromise | Lazarus | Supply chain backdoor | 4 | 2 ATT&CK | Critical |
| zero-day-web-exploit | Hafnium | Web server exploitation | 5 | 4 ATT&CK | Critical |

### AI agent security

| Campaign | Attack Vector | Techniques | Severity |
|----------|--------------|------------|----------|
| llm-agent-hijack | Agent takeover via prompt injection | ATLAS + OWASP | Critical |
| rag-poisoning | RAG manipulation | ATLAS + OWASP | High |
| rag-data-poisoning | Training data poisoning | ATLAS | High |
| rag-index-poisoning | Vector store index corruption | ATLAS | Critical |
| tool-call-injection | Malicious tool invocations | ATLAS + ATT&CK | Critical |
| prompt-leaking | Prompt extraction | ATLAS | Medium |
| agent-identity-spoofing | Agent impersonation | ATLAS + ATT&CK | High |
| agent-jailbreak | Guardrail bypass | ATLAS | Critical |
| agent-memory-attack | Memory/context manipulation | ATLAS | High |
| agent-memory-manipulation | Persistent memory store attacks | ATLAS | High |
| agent-supply-chain | Plugin/extension backdoor | ATT&CK + ATLAS | Critical |
| agent-tool-confusion | Tool name squatting | ATLAS | High |
| agent-credential-harvest | API key/token extraction | ATT&CK + ATLAS | Critical |
| agent-orchestrator-takeover | Orchestration layer compromise | ATLAS | Critical |
| agent-state-desync | Distributed agent state inconsistency | ATLAS | High |
| context-window-stuffing | Safety instruction eviction | ATLAS + OWASP | Critical |
| function-calling-overflow | Oversized function schema injection | ATLAS + OWASP | High |
| llm-output-parsing-exploit | Structured output parser exploitation | ATLAS + OWASP | High |
| multi-model-arbitrage | Multi-LLM model switching exploits | ATLAS | High |
| mcp-server-attack | MCP protocol exploitation | ATLAS + ATT&CK | Critical |
| mcp-server-impersonation | MCP tool server impersonation | ATT&CK + ATLAS | Critical |
| multi-agent-attack | Multi-agent coordination attack | ATLAS | Critical |
| model-extraction | Model weight theft | ATLAS | High |
| agent-api-abuse | API endpoint abuse via agent | ATT&CK | High |
| agent-capability-probing | Agent capability discovery | ATLAS | Medium |
| agent-context-manipulation | Context window manipulation | ATLAS | High |
| agent-credential-theft | Agent credential extraction | ATLAS + OWASP | Critical |
| agent-data-exfiltration | Data theft via agent tools | ATT&CK + ATLAS | Critical |
| agent-delegation-abuse | Delegation chain exploitation | ATLAS | Critical |
| agent-feedback-loop-attack | Feedback loop poisoning | ATLAS | High |
| agent-function-squatting | Tool function name squatting | ATLAS | High |
| agent-guardrail-bypass | Guardrail evasion techniques | ATLAS | Critical |
| agent-model-fingerprint | LLM model fingerprinting | ATLAS | Medium |
| agent-multi-tenant-escape | Multi-tenant isolation bypass | ATT&CK + ATLAS | Critical |
| agent-output-poisoning | Agent output manipulation | ATLAS + OWASP | High |
| agent-plugin-backdoor | Plugin/extension backdoor | ATT&CK + ATLAS | Critical |
| agent-privilege-escalation | Agent privilege escalation | ATLAS + OWASP | Critical |
| agent-prompt-injection-indirect | Indirect prompt injection | ATLAS | Critical |
| agent-session-hijack | Agent session takeover | ATT&CK + ATLAS | Critical |
| agent-tool-abuse | Authorized tool misuse | ATT&CK + ATLAS | High |
| agent-tool-injection | Malicious tool injection | ATLAS | Critical |
| agent-trust-exploitation | Inter-agent trust abuse | ATLAS | Critical |

### Atomic Red Team campaigns

Live-executable campaigns mapped from [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests, grouped by tactic and platform.

| Campaign | Platform | Stages | Techniques | Severity |
|----------|----------|--------|------------|----------|
| art-discovery-linux | Linux | 6 | 6 ATT&CK | Medium |
| art-discovery-windows | Windows | 7 | 7 ATT&CK | Medium |
| art-execution-linux | Linux | 6 | 6 ATT&CK | High |
| art-execution-windows | Windows | 7 | 7 ATT&CK | High |
| art-persistence-linux | Linux | 6 | 6 ATT&CK | High |
| art-persistence-windows | Windows | 7 | 6 ATT&CK | High |
| art-credential-access-linux | Linux | 6 | 5 ATT&CK | Critical |
| art-credential-access-windows | Windows | 7 | 6 ATT&CK | Critical |
| art-defense-evasion-linux | Linux | 6 | 6 ATT&CK | High |
| art-defense-evasion-windows | Windows | 6 | 6 ATT&CK | High |
| art-lateral-movement-linux | Linux | 6 | 6 ATT&CK | High |
| art-lateral-movement-windows | Windows | 6 | 6 ATT&CK | Critical |
| art-exfiltration-multi | Cross-platform | 7 | 7 ATT&CK | Critical |

### Built-in policies

| Policy | Rules | Posture | Use Case |
|--------|-------|---------|----------|
| agent-default | 10 | Balanced | Default agent tool-call enforcement |
| agent-strict | 17 | Zero-trust | High-security agent environments |
| soc-baseline | 14 | SOC-gated | Classical SOC simulation gating |
| api-gateway | 10 | API-focused | API gateway tool-call filtering |
| autonomous-agent | 11 | Autonomous | Self-directed agent guardrails |
| compliance-hipaa | 10 | Regulated | HIPAA-aligned agent controls |
| compliance-pci | 10 | Regulated | PCI DSS agent controls |
| data-classification | 10 | Data-aware | Data handling policy enforcement |
| development-sandbox | 10 | Permissive | Development/testing environments |
| incident-response | 11 | IR-focused | Incident response agent operations |
| ml-pipeline | 11 | ML-ops | ML pipeline tool-call governance |
| multi-agent-governance | 10 | Multi-agent | Cross-agent coordination rules |
| production-lockdown | 12 | Hardened | Production deployment lockdown |
| rag-protection | 10 | RAG-focused | RAG pipeline security controls |
| tool-calling-strict | 10 | Strict | Minimal tool-call allowlist |

## Architecture

```
cmd/threatecho/           CLI entry point
cmd/threatecho-agent/     Agent binary (run, check, version)
internal/
├── agent/                Agent inventory, trust, chain analysis, attestation, behavior profiling
├── campaign/             Campaign loading, validation, generation, diffing, linting
├── cli/                  Shell completion, error formatting, exit codes
├── compliance/           Compliance framework mapping (NIST AI RMF, CSF, 800-53, CIS, OWASP, ATLAS)
├── config/               Layered config (system → user → project → env)
├── engine/               Simulation, execution, STRIDE, risk, compliance, baseline, attack trees
├── executor/             Campaign execution runtime (noop + live shell)
├── gap/                  Detection gap analysis, comparison, technique coverage
├── matrix/               ATT&CK coverage matrix (terminal heatmap)
├── mitre/                ATT&CK (155), ATLAS (25), OWASP LLM (10) technique registries
├── navigator/            ATT&CK Navigator layer export (v4.5)
├── orchestrator/         Remote deployment engine (SSH + WinRM, agentless + agent mode)
├── policy/               Policy engine: eval, lint, drift, impact, coverage, remediation, testing
├── report/               Reports, SARIF v2.1.0, HTML dashboard
├── runner/               Precondition engine (platform, elevation, tool checks)
├── scenario/             Scenario engine (YAML test cases with pass criteria)
├── sigma/                Sigma detection rule generation (65 techniques mapped)
├── telemetry/            Telemetry type registry (108 types)
└── trace/                Trace parsing, replay, multi-trace correlation
pkg/version/              Build version info
campaigns/                Built-in campaign library (72)
policies/                 Built-in policy library (15)
agents/                   Agent inventory definitions (10)
assets/                   Logo and branding
.github/workflows/        CI/CD pipeline
Makefile                  Build targets
```

- **Pure Go**, minimal dependencies (`gopkg.in/yaml.v3`, `golang.org/x/crypto`, `github.com/masterzen/winrm`)
- **22 packages**, ~120K LOC, **3,539 tests**
- No runtime network calls in simulation mode — `simulate`, `gap`, `policy eval` run fully offline. The `deploy` command connects to remote targets via SSH/WinRM

## License

AGPL-3.0. See [LICENSE](LICENSE).

Copyright (c) 2024-2026 ThreatEcho. All rights reserved.

## Links

- Website: [threatecho.com](https://threatecho.com)
- GitHub: [github.com/ThreatEcho](https://github.com/ThreatEcho)
