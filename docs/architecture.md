<p align="center">
  <img src="../assets/logo-circle-800.jpg" alt="ThreatEcho" width="400" />
</p>

# Architecture

Technical architecture overview of ThreatEcho - detection engineering for AI agents. Adversary campaign simulation, tool-call policy enforcement, and detection gap analysis across MITRE ATT&CK, MITRE ATLAS, and OWASP LLM Top 10.

## High-Level Pipeline

```
 ┌──────────────────────────────────────────────────────────────────┐
 │                          CLI (main.go)                           │
 │  validate│lint│simulate│run│deploy│gap│policy│export│agent│ ...  │
 └───────────────────────────────┬──────────────────────────────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            ▼                    ▼                    ▼
    ┌───────────────┐    ┌──────────────┐    ┌────────────────┐
    │   Campaign    │    │    Policy    │    │   Campaign     │
    │   Loader      │    │    Loader    │    │   Loader       │
    │  (YAML parse, │    │ (YAML parse, │    │   + Validator  │
    │   var expand) │    │   validate)  │    │   + Lint       │
    └──────┬────────┘    └───────┬──────┘    └────────┬───────┘
           │                     │                    │
           ▼                     │                    │
    ┌───────────────┐            │           ┌────────────────┐
    │ DAG Resolver  │            │           │     MITRE      │
    │ (Kahn's alg)  │            │           │     Lookup     │
    └──────┬────────┘            │           │  ATT&CK/ATLAS  │
           │                     │           │   /OWASP LLM   │
           ▼                     │           └────────┬───────┘
    ┌──────────────┐             │                    │
    │    Engine    │             │                    │
    │  Simulate or │             │                    │
    │      Run     │             │                    │
    └──────┬───────┘             │                    │
           │                     │                    │
    ┌──────┴───────┐             │                    │
    │  Executor    │             │                    │
    │  Noop (sim)  │             │                    │
    │  Shell (live)│             │                    │
    └──────┬───────┘             │                    │
           │                     │                    │
           ▼                     ▼                    ▼
    ┌─────────────────────────────────────────────────────────┐
    │                     Report Pipeline                     │
    │  ┌──────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌─────┐ ┌────┐ │
    │  │Gap Report│ │ Text │ │ JSON │ │SARIF │ │JUnit│ │HTML│ │
    │  │ (risk    │ │      │ │      │ │v2.1.0│ │ XML │ │ MD │ │
    │  │  scored) │ │      │ │      │ │      │ │     │ │    │ │
    │  └──────────┘ └──────┘ └──────┘ └──────┘ └─────┘ └────┘ │
    └────────────────────────────┬────────────────────────────┘
                                 │
                  ┌──────────────┼──────────────┐
                  ▼              ▼              ▼
           ┌─────────────┐ ┌───────────┐ ┌────────────┐
           │  Navigator  │ │   Sigma   │ │  Compare   │
           │  Layer JSON │ │   Rules   │ │  (delta)   │
           └─────────────┘ └───────────┘ └────────────┘
```
## Package Structure

```
src/
├── cmd/threatecho/          CLI entry point, command routing, flag parsing
├── internal/
│   ├── campaign/            Campaign loading, validation, linting, DAG resolution
│   │   ├── types.go         Core types: Campaign, Meta, Stage, Execute, Expect, Duration
│   │   ├── loader.go        YAML loading, variable expansion ({{var}} templates)
│   │   ├── validator.go     Structural + semantic validation (technique format, tactic validity)
│   │   ├── lint.go          Quality checks beyond validation (warnings, suggestions)
│   │   ├── graph.go         DAG resolution: Kahn's algorithm + DFS cycle detection
│   │   └── ...              22 additional files: scoring, search, import, stats, audit, etc.
│   ├── engine/              Campaign execution + analysis (STRIDE, risk, compliance, baseline, attack trees)
│   │   ├── engine.go        RunResult, StageResult, Options, TacticCoverage
│   │   ├── simulate.go      Dry-run: walks DAG with Noop executor
│   │   ├── run.go           Live execution: walks DAG with Shell executor
│   │   ├── threatmodel.go   STRIDE threat model generation per agent
│   │   ├── risk.go          Unified risk posture scoring (A-F grade)
│   │   ├── compliance.go    Framework mapping (NIST AI RMF, CSF, 800-53, CIS, OWASP, ATLAS)
│   │   ├── baseline.go      Deployment baseline capture and drift detection
│   │   ├── attacktree.go    Attack tree generation with probabilistic risk scoring
│   │   └── runner.go        Precondition evaluation delegator
│   ├── executor/            Stage execution backends
│   │   ├── executor.go      Executor interface: Execute, Cleanup, Name
│   │   ├── noop.go          Simulation executor (describes what would happen)
│   │   ├── shell.go         Live shell executor (sh -c / cmd /c)
│   │   ├── shell_unix.go    Unix process group handling (syscall.SysProcAttr)
│   │   └── shell_windows.go Windows process group handling
│   ├── gap/                 Detection gap analysis
│   │   ├── gap.go           Analyze(): produces GapReport with risk scoring
│   │   └── compare.go       Compare(): before/after delta between two GapReports
│   ├── matrix/              ATT&CK technique×tactic coverage heatmap
│   ├── mitre/               Framework registries and lookup
│   │   ├── attack.go        ATT&CK technique and tactic registry
│   │   ├── atlas.go         MITRE ATLAS technique and tactic registry
│   │   ├── owasp_llm.go     OWASP LLM Top 10 registry
│   │   └── lookup.go        Unified lookup: ValidTechniqueExists, ClassifyFramework
│   ├── navigator/           ATT&CK Navigator layer v4.5 generation
│   │   └── navigator.go     FromRunResult (coverage), FromGapReport (gap overlay)
│   ├── policy/              Agent tool-call policy engine
│   │   ├── policy.go        Policy types, LoadPolicy, ValidatePolicy, Evaluate
│   │   └── ...              21 additional files: lint, drift, compliance, simulation, etc.
│   ├── report/              Output format renderers
│   │   ├── text.go          ANSI text report for simulate/run results
│   │   ├── json.go          JSON report for simulate/run results
│   │   ├── gap.go           ANSI text gap analysis report
│   │   ├── gap_json.go      JSON gap analysis report
│   │   ├── gap_html.go      Self-contained HTML gap report (embedded CSS, dark mode)
│   │   ├── gap_md.go        GitHub-Flavored Markdown gap report
│   │   ├── sarif.go         SARIF v2.1.0 for gap and policy results
│   │   ├── junit.go         JUnit XML for gap and policy results
│   │   ├── policy.go        ANSI text policy evaluation report
│   │   ├── policy_json.go   JSON policy evaluation report
│   │   ├── compare.go       Text and JSON delta reports
│   │   ├── summary.go       Security posture dashboard
│   │   ├── coverage.go      Technique coverage text report
│   │   ├── coverage_json.go Technique coverage JSON report
│   │   ├── dashboard.go     HTML executive dashboard
│   │   └── doc.go           Package documentation
│   ├── orchestrator/        Remote deployment engine
│   │   ├── orchestrator.go  Run, runParallel, runSequential, deployOne, Deployer interface + NewDeployer factory
│   │   ├── ssh.go           SSHDeployer (agentless) + AgentSSHDeployer (agent)
│   │   ├── winrm.go         WinRMDeployer (agentless) + AgentWinRMDeployer (agent)
│   │   ├── target.go        Target, TargetInventory, LoadInventory, SetDefaults
│   │   └── report.go        DeployReport, BuildDeployReport, FormatDeployReport
│   ├── runner/              Precondition engine (platform, elevation, tool checks)
│   ├── trace/               Agent execution trace analysis, replay, multi-trace correlation
│   ├── agent/               Agent inventory, trust, chain analysis, attestation, behavior profiling
│   ├── scenario/            Scenario store (campaign→trace→policy-eval pipeline)
│   ├── compliance/          Compliance framework mapping (NIST CSF, 800-53, CIS, AI RMF, OWASP LLM, ATLAS)
│   ├── cli/                 Shared CLI infrastructure (exit codes, error types, hints)
│   ├── config/              Layered configuration system (.threatecho.yaml, env vars)
│   ├── sigma/               Sigma detection rule scaffold generation
│   │   ├── sigma.go         Generate(): campaigns → Sigma YAML rule scaffolds
│   │   ├── logsource.go     Telemetry-to-logsource mapping table
│   │   └── detections.go    Technique-to-detection lookup (LookupTechniqueDetection)
│   └── telemetry/           Telemetry type registry (108 types, 16 categories)
├── cmd/threatecho-agent/    Agent binary (run, check, version commands)
└── pkg/
    └── version/             Build-time version injection (ldflags)
```

## Data Flow

### Campaign Loading

```
campaign.yaml ──► Load(path)
                   │
                   ├── os.ReadFile + yaml.Unmarshal → Campaign struct
                   ├── expandVariables: {{key}} → value in stage fields
                   │     (Name, Description, Target, Payload, Commands,
                   │      Cleanup, Args values, Artifacts, IOCs)
                   └── Return *Campaign
```

### Validation Pipeline

```
*Campaign ──► Validate(c)
               │
               ├── api_version: required, non-empty
               ├── kind: must equal "Campaign"
               ├── meta.name: required
               ├── meta.adversary: required
               ├── meta.severity: if set, must be critical|high|medium|low|info
               ├── stages: at least one required
               ├── per-stage:
               │   ├── id: required, unique across campaign
               │   ├── name: required
               │   ├── technique: required, must match:
               │   │   ├── ATT&CK: ^T\d{4}(\.\d{3})?$
               │   │   ├── ATLAS:  ^AML\.T\d{4}$
               │   │   └── OWASP:  ^LLM\d{2}$
               │   ├── tactic: required, must pass mitre.ValidTactic or ValidATLASTactic
               │   ├── execute.type: required, one of shell|powershell|http|file|registry|service|process|dns|manual
               │   ├── on_failure: if set, must be abort|skip|continue
               │   └── platform[]: each must be windows|linux|macos
               ├── cross-references:
               │   ├── depends_on[]: each must reference a known stage ID
               │   └── on_success: must reference a known stage ID
               └── cycle detection: DFS three-color algorithm
```

### Lint Checks

Lint runs after validation and produces warnings (actionable) and info (suggestions):

| Level | Check |
|-------|-------|
| Info | `meta.description` empty |
| Info | `meta.objective` empty |
| Info | `meta.mitre_version` not set |
| Info | Stage has telemetry but no detections (will flag as gap) |
| Warning | Technique ID not found in registry (valid format but not indexed) |
| Warning | Framework/tactic cross-mismatch (ATT&CK technique with ATLAS tactic or vice versa) |
| Warning | Stage has no expected telemetry (gap analysis will be limited) |
| Warning | Shell stage with no commands |
| Warning | HTTP stage with no target URL |

## DAG Execution Model

Stages form a directed acyclic graph through `depends_on` references. The engine resolves execution order using **Kahn's algorithm** for topological sorting.

```
1. Build in-degree map and adjacency list from depends_on edges
2. Seed queue with all zero-in-degree stages (no dependencies)
3. BFS loop:
   a. Dequeue stage
   b. Append to ordered list
   c. For each child: decrement in-degree; if zero, enqueue
4. If len(ordered) != len(stages) → error: dependency cycle detected
```

The separate `detectCycle()` function uses DFS with three-color marking (white/grey/black) to produce human-readable cycle descriptions for error messages (e.g., `"stage-a → stage-b"`).

### Execution Sequence

```
ordered stages ──► Engine (simulate or run)
                     │
                     for each stage in topological order:
                     │
                     ├── Platform filter: skip if stage platforms
                     │   don't include opts.Platform
                     ├── Delay: sleep stage.Delay (live only)
                     ├── Timeout: context.WithTimeout(stage.Timeout)
                     ├── Execute: Noop (sim) or Shell (live)
                     │   └── Shell: sequential commands, stop on first failure
                     ├── Record: StageResult (Order, Exec, Skipped, SkipMsg)
                     ├── Cleanup: best-effort, runs ALL cleanup commands
                     └── Progress callback (live runs)
```

## Framework Abstraction

ThreatEcho unifies three security frameworks through a common `Stage` type. The `technique` field accepts IDs from any framework; the `tactic` field uses shared tactic short names.

| Framework | Technique Pattern | Example | Tactic Source |
|-----------|------------------|---------|---------------|
| MITRE ATT&CK | `T\d{4}(.\d{3})?` | `T1566.001` | ATT&CK 14 tactics |
| MITRE ATLAS | `AML.T\d{4}` | `AML.T0051` | ATLAS 7 tactics |
| OWASP LLM Top 10 | `LLM\d{2}` | `LLM06` | Uses ATLAS tactics |

Classification is prefix-based (`T` → ATT&CK, `AML.` → ATLAS, `LLM` → OWASP). The `mitre.ClassifyFramework()` function routes to the correct registry for name resolution, tactic validation, and reference URL generation.

### ATT&CK Tactics (14)

```
reconnaissance → resource-development → initial-access → execution →
persistence → privilege-escalation → defense-evasion → credential-access →
discovery → lateral-movement → collection → command-and-control →
exfiltration → impact
```

### ATLAS Tactics (7)

```
reconnaissance → resource-development → initial-access →
ml-attack-staging → ml-model-access → exfiltration → impact
```

## Output Format Pipeline

The same analysis result feeds multiple output renderers. Each format serves a different consumer.

### Simulation/Run Reports

| Format | Function | Consumer |
|--------|----------|----------|
| Text (ANSI) | `report.TextReport()` | Terminal, human review |
| JSON | `report.JSONReportWrite()` | Programmatic consumption, dashboards |

### Gap Analysis Reports

| Format | Function | Consumer |
|--------|----------|----------|
| Text (ANSI) | `report.GapTextReport()` | Terminal, human review |
| JSON | `report.GapJSONReport()` | APIs, dashboards, downstream tooling |
| SARIF v2.1.0 | `report.GapSARIFReport()` | GitHub Code Scanning, VS Code, SARIF viewers |
| JUnit XML | `report.GapJUnitReport()` | Jenkins, GitHub Actions, GitLab CI test reporters |
| HTML | `report.GapHTMLReport()` | Stakeholder reports, email attachments, archival |
| Markdown | `report.GapMarkdownReport()` | GitHub wikis, READMEs, pull request comments |

### Policy Evaluation Reports

| Format | Function | Consumer |
|--------|----------|----------|
| Text (ANSI) | `report.PolicyTextReport()` | Terminal, human review |
| JSON | `report.PolicyJSONReport()` | Programmatic consumption |
| SARIF v2.1.0 | `report.PolicySARIFReport()` | GitHub Code Scanning |
| JUnit XML | `report.PolicyJUnitReport()` | CI test reporters |

### Gap Comparison Reports

| Format | Function | Consumer |
|--------|----------|----------|
| Text (ANSI) | `report.CompareTextReport()` | Terminal, human review |
| JSON | `report.CompareJSONReport()` | Programmatic consumption |

### SARIF Rule IDs

Gap analysis maps to three fixed SARIF rules:

| Rule ID | Name | Level | Gap Type |
|---------|------|-------|----------|
| `TE-GAP-001` | DetectionMissing | warning | Telemetry defined, no detection rules |
| `TE-GAP-002` | TelemetryMissing | error | No expected telemetry at all |
| `TE-GAP-003` | TacticUncovered | warning | Entire tactic has zero stage coverage |

## Policy Engine Architecture

The policy engine evaluates agent tool-call policies against campaign stages. See [policies.md](policies.md) for the DSL reference.

```
LoadPolicy(path)
  │
  ├── Read YAML (Policy struct)
  └── ValidatePolicy: structural + semantic checks

Evaluate(policy, campaign)
  │
  ├── Sort rules by priority (descending - highest first)
  │
  └── For each campaign stage:
       │
       ├── InferTools(stage):
       │   ├── execTypeToTool: shell→shell_exec, http→http_request, ...
       │   └── telemetryToTool: tool_call→tool_call, embedding_query→search_knowledge_base, ...
       │
       ├── inferActions(stage):
       │   └── execTypeToAction: shell→execute, http→send, dns→query, ...
       │
       ├── For each rule (priority order):
       │   ├── Match check (AND across dimensions, OR within each):
       │   │   ├── tools: glob match (GlobMatch)
       │   │   ├── tactics: exact match
       │   │   ├── actions: exact match
       │   │   └── targets: glob match (URL patterns)
       │   ├── Condition check (all must pass):
       │   │   └── field + operator + value against stage fields
       │   └── First match wins → effect applied
       │
       └── No match → implicit allow
```

## Sigma Generation Pipeline

See [sigma.md](sigma.md) for the full integration guide.

```
campaign.Stages
  │
  └── For each stage with Expect.Detections:
       │
       ├── Resolve LogSource from first Expect.Telemetry type
       │   (telemetryToLogSource map: process_create→process_creation, etc.)
       │
       ├── Build MITRE tags (framework-aware prefix):
       │   ├── ATT&CK:  attack.<tactic_underscored>, attack.<technique_lower>
       │   ├── ATLAS:   atlas.<tactic_underscored>, atlas.<technique_lower>
       │   └── OWASP:   owasp.<tactic_underscored>, owasp.<technique_lower>
       │
       ├── Build reference URLs:
       │   ├── ATT&CK: https://attack.mitre.org/techniques/{id}/
       │   ├── ATLAS:  https://atlas.mitre.org/techniques/{id}
       │   └── OWASP:  https://genai.owasp.org/llmrisk/{id}
       │
       ├── Determine severity level from tactic:
       │   ├── high: initial-access, execution, exfiltration, impact,
       │   │         credential-access, lateral-movement, privilege-escalation,
       │   │         ml-attack-staging, ml-model-access
       │   └── medium: everything else
       │
       ├── Generate deterministic rule ID:
       │   └── SHA256(campaign_name|stage_id|detection_name) → UUID-format hex
       │
       └── Build selection scaffold from telemetry type
           (process_creation→Image, network_connection→DestinationHostname, etc.)
```

## Risk Scoring

Gap analysis assigns risk based on gap type and tactic:

### Risk Assignment

| Gap Type | Tactic Category | Risk Level |
|----------|----------------|------------|
| Tactic uncovered | initial-access, execution, exfiltration | critical |
| Tactic uncovered | credential-access, lateral-movement, impact | high |
| Tactic uncovered | all other tactics | medium |
| Detection missing | initial-access, execution, exfiltration | high |
| Detection missing | all other tactics | medium |
| Telemetry missing | any tactic | medium |

### Score Calculation

```
weighted = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
max_possible = total_gaps * 10
score = (weighted / max_possible) * 100
```

Score ranges: 0-19 = low, 20-39 = medium, 40-69 = high, 70-100 = critical.

## Extension Points

### Adding a New Campaign

Create a directory under `campaigns/` with a `campaign.yaml` file. See [campaigns.md](campaigns.md) for the schema reference. The loader auto-discovers campaigns via `LoadDir()`, which scans for subdirectories containing `campaign.yaml`.

### Adding a New Output Format

1. Create a new file in `internal/report/` (e.g., `gap_csv.go`)
2. Implement a function matching the pattern: `GapCSVReport(w io.Writer, r *gap.GapReport) error`
3. Add the format string to the `gap` command's switch statement in `main.go`
4. Add it to the help text and `-format` flag description

### Adding a New Execute Type

1. Add the type name to `validExecTypes` in `internal/campaign/validator.go`
2. Add the tool mapping in `internal/policy/policy.go` (`execTypeToTool`, `execTypeToAction`)
3. Handle the type in `executor/shell.go` (or create a new executor)
4. Handle the type in `executor/noop.go` for simulation descriptions

### Adding a New Framework

1. Create a registry file in `internal/mitre/` (e.g., `new_framework.go`)
2. Implement lookup and validation functions matching the existing pattern
3. Add a prefix check to `ClassifyFramework()` in `lookup.go`
4. Add technique regex to `validator.go`
5. Add tactic validation to `validator.go`
6. Update gap analysis tactic ordering in `gap.go`
7. Update report renderers to display the new framework

## Design Principles

- **Pure Go.** `CGO_ENABLED=0`, statically compiled. The release ships a CLI and an optional agent binary.
- **Minimal dependencies.** Build dependencies are `gopkg.in/yaml.v3`, `golang.org/x/crypto` (SSH), and `github.com/masterzen/winrm` (WinRM). No database, no daemon, no config server.
- **Deterministic output.** Same inputs produce identical outputs. Sigma rule IDs are SHA256-derived. Navigator layers sort entries by technique ID. Reports use stable ordering.
- **CI-first.** Every output format maps to a CI integration: SARIF → GitHub Code Scanning, JUnit → test reporters, exit code 2 → policy deny. The CI pipeline has six jobs: test, lint-campaigns, gap-analysis, policy-eval, build matrix, release.
- **Separation of analysis from execution.** Simulation (Noop executor) and live execution (Shell executor) share the same engine, options, and report pipeline. Analysis commands (`gap`, `policy eval`, `export`) use simulation internally.
- **Cross-platform.** Build matrix covers linux/darwin/windows on amd64/arm64. Shell executor adapts to OS-specific process group handling. GoReleaser produces archives (tar.gz, zip).
