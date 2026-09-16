# Changelog

All notable changes to ThreatEcho are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0]

### Added

#### PowerShell Execute Type — Agent + Executor Support
- `execute.type: powershell` now supported by local executor (`cmd/threatecho-agent`) — runs commands via `powershell -Command`
- Cleanup commands for `powershell` type stages also execute via PowerShell
- Precondition engine scans `powershell` type stages for tool availability (same as `shell`)
- `powershell` added as valid `execute.type` in campaign validator

#### Precondition Engine Hardening
- `hasORFallback`: commands with `||` fallback patterns skip precondition tool checks (the tool is optional)
- `isScriptFile`: script files (`.sh`, `.py`, `.ps1`, etc.) no longer flagged as required PATH tools
- Subshell/brace-group syntax stripping in `firstBinary` parser (e.g. `(crontab -l ...)` correctly extracts `crontab`)
- PowerShell cmdlet detection (`isPSCmdlet`): `Start-Process`, `Get-ChildItem`, etc. skipped — they are PowerShell builtins, not PATH binaries
- PowerShell variable assignment detection (`isPSVarAssignment`): `$var = '...'` lines skipped entirely — RHS is string data, not executable code
- Shell builtins expanded: `type`, `source`, `pushd`, `popd` added to skip list
- Quote stripping moved before redirection/variable checks to handle `'<xml'` tokens correctly
- 10 precondition engine unit tests

#### CLI Help Text Grouping
- Help output reorganized into 6 semantic categories: Execution, Campaign Management, Analysis, Risk & Compliance, Agent, Workspace
- `deploy` command now appears in first group (Execution) for discoverability

#### WinRM Authentication Error Detection
- WinRM deployers detect 401/NTLM failures on first command and report a clear, actionable error
- Error message includes username, host:port, and suggests checking credentials, DC availability, and WinRM service

#### `-target host:port` Parsing
- `splitHostPort` function added: `-target 127.0.0.1:5985` now correctly separates host and port
- Explicit `-port` flag takes precedence when both are specified
- 8 unit tests covering edge cases (no port, explicit port override, invalid port, out-of-range)

#### Target Input Normalization
- `SetDefaults` normalizes `-os` and `-mode` to lowercase (e.g. `-os Linux` → `linux`, `-mode Agent` → `agent`)
- 6 unit tests for `TestSetDefaults` covering case normalization and port defaults

### Fixed

#### Exit Code Documentation in Help
- Main help text now includes exit code table for CI integration: 0 (success), 1 (validation), 2 (policy denied), 3 (runtime), 4 (I/O), 64 (usage)

#### CLI Help Text Examples
- Added usage examples to 6 commands: `validate`, `simulate`, `campaigns`, `init`, `policy validate`, `export navigator`
- Improved descriptions for `simulate` and `init` help text

#### Error Message Hints
- `errorHint` system expanded: YAML parse errors, connection refused, authentication failures, timeouts, and "campaign not found" now produce actionable hints
- All 8 "unknown subcommand" error messages now list valid subcommands (campaigns, config, graph, telemetry, policy, agent, export, scenario)
- 5 new hint test cases (YAML syntax, connection refused, auth 401, timeout, campaign not found by name)

#### Quiet Mode (`-quiet` / `-q`)
- `threatecho deploy -q` suppresses all text output — exit code only
- JSON output still emitted with `-format json -q` for CI pipeline parsing
- Applies to deploy banner, text report, and validate output

#### `--version` / `-v` Flag
- `threatecho --version` and `threatecho -v` now work as aliases for `threatecho version`

#### MITRE ATT&CK Registry Expansion
- Added 48 technique/sub-technique IDs to the internal registry
- All 12 ART campaigns now lint clean (zero warnings)
- Doctor warnings reduced from 58 to 42 (remaining: AI campaign templates + intentional trust boundary warnings)
- Added MITRE ATLAS IDs: AML.T0020 (Poison Training Data), AML.T0037 (Data Poisoning)

#### `run` Exit Code Fix
- `threatecho run` now exits with code 3 (ExitRuntime) when any campaign stage fails, enabling CI pipeline gating

#### `init` Help Text Fix
- `init` help text accurately reflects generated directory structure

#### Shell Completion for Deploy Command
- Full shell completion coverage for `deploy` command (bash, zsh, fish)
- All 16 deploy flags registered: `inventory`, `target`, `user`, `password`, `key`, `os`, `port`, `mode`, `agent-binary`, `elevated`, `parallel`, `workdir`, `format`, `timeout`, `verbose`, `validate`
- Command descriptions for all commands in zsh/fish completions

### Validated

#### CLI Exit Code Consistency
- All 15 `os.Exit(2)` call sites in main.go now use `cli.ExitPolicyDenied` named constant instead of raw magic number

#### Sigma Rule Generator Placeholders
- Sigma rules for unknown techniques use `EDIT_` prefixed placeholder values for clear operator guidance
- Network connection selections use actual `Execute.Target` value when available

#### Windows Campaign Fixes
- `art-execution-windows`: self-contained stages (no internet dependencies), PowerShell file writes for WinRM compatibility
- `art-lateral-movement-windows`: self-contained local equivalents (SMB share enum, `Invoke-WmiMethod`, `Invoke-Command`), PowerShell WMI throughout
- `art-persistence-windows`: proper `%APPDATA%` resolution over WinRM via `[Environment]::GetFolderPath`
- `art-credential-access-windows`: dynamic VSS shadow copy volume parsing for NTDS.dit, `cmd /c copy` for locked file access, `||` fallback for restricted SECURITY hive, LSASS/procdump/SAM stages use PowerShell execute type with descriptive error output

#### Windows Agent WaitDelay Fix
- `setProcGroup` on Windows sets `WaitDelay = 5s` for clean child-process reaping
- Agent mode gracefully terminates long-running child processes (rundll32, mshta) after stage timeout

#### Agent Mode Precondition False Positives
- Commands with `|| echo "..."` or `|| true` fallbacks no longer generate tool precondition checks
- Script files executed by path (e.g. `/tmp/te_exec_test.sh`) no longer require matching PATH entry
- Subshell commands (e.g. `(crontab -l; echo ...) | crontab -`) correctly parsed

### Stats
- 239 Go files (131 source + 108 test), ~120K LOC
- 3,539 tests across 22 packages — all passing
- 72 campaigns (17 classical + 42 AI agent + 13 ART live-execution), 15 policies, 10 agents

## [0.1.0]

### Added

#### Remote Deployment — `internal/orchestrator` (NEW PACKAGE)
- `threatecho deploy` CLI command for remote campaign deployment
- Dual-mode deployment: agentless (SSH commands) and agent (push binary + pull report)
- Target inventory YAML format with `${env:VAR}` password expansion
- `SSHDeployer`: runs each stage command directly via SSH session
- `AgentSSHDeployer`: uploads binary + campaign, runs `threatecho-agent run`, downloads JSON report, cleans up
- Signal handling: Ctrl-C cancels in-flight deployments gracefully
- Multi-target deployment with `-parallel` flag
- `-validate` flag for dry-check of inventory + campaign without connecting
- Aggregate `DeployReport` with per-target results and summary counts
- Human-readable and JSON output formats
- Native SSH via `golang.org/x/crypto/ssh` (password + key auth)
- Mixed-mode inventory: targets can each specify `agentless` or `agent` independently

#### WinRM Deployers — Windows Support
- `WinRMDeployer`: agentless Windows deployment via WinRM/NTLM over PowerShell
- `AgentWinRMDeployer`: push agent binary + campaign over WinRM, pull JSON report
- NTLM authentication via `github.com/masterzen/winrm`
- Shell-type stages run through `cmd /c` (native cmd.exe); PowerShell-type stages through encoded PowerShell
- Binary upload via stdin pipe + base64 decode (avoids command-line length limits)
- Base64-encoded file download for report retrieval
- Precondition checks (platform, elevation) consistent with SSH deployers

#### Deploy CLI Flags
- `-inventory <path>` for multi-target deployment from YAML
- `-target <host>` for single-target ad-hoc deployment
- `-mode agentless|agent` deployment strategy
- `-agent-binary <path>` for agent mode binary
- `-elevated` to allow privileged execution
- `-workdir` remote working directory override
- `-timeout <duration>` for overall deploy wall-clock limit (e.g. `30m`, `1h`)
- `-verbose` for per-target connection status and per-stage progress output
- Example inventory YAML (`examples/inventory.yaml`) with Linux SSH + Windows WinRM targets, env expansion, both modes

#### Per-Stage Timeout Enforcement
- All deployers (SSH + WinRM) enforce campaign `timeout:` field per stage
- Default 5-minute timeout per stage when campaign doesn't specify
- Context-based cancellation propagates to SSH/WinRM commands

#### on_failure: "abort" Handling
- All deployers respect `on_failure: abort` — deployment stops on first failed stage
- Consistent across SSH and WinRM, agentless and agent modes

#### New Linux Campaigns (3)
- `art-execution-linux`: bash, python, perl, at, cron, tmp file execution (6 stages)
- `art-defense-evasion-linux`: timestomping, history evasion, hidden files, process masquerading, log discovery, permission modification (6 stages)
- `art-lateral-movement-linux`: SSH config, key enumeration, remote host discovery, network shares, SSH agent recon, lateral tool check (6 stages)

### Fixed

#### Agent-Mode Deployment
- Agent-mode flag ordering: `--out` and `--platform` correctly parsed in all positions
- Mode display header shows actual per-target mode or "mixed" for heterogeneous inventories
- Agent binary validation covers both CLI `-mode` flag and per-target inventory modes
- Shell-quoted `--platform` value in remote agent commands
- Clean `go vet ./...` on Go 1.26 — all format strings use `%s` args
- `precondition_failed` stages counted in `DeploySummary` and displayed in deploy report
- SSH deployer platform/elevation checks report `precondition_failed` consistently with runner
- `art-discovery-windows` campaign: uses PowerShell `Get-CimInstance` throughout, proper `net` exit-code handling
- `SetDefaults` applied consistently for both single-target and inventory modes
- Windows targets validated for password auth (WinRM requires NTLM, not SSH keys)
- Deploy exit code uses `ExitRuntime` (3) for deployment failures
- Deploy usage text covers SSH and WinRM
- `art-discovery-linux` campaign: guarded commands for non-root compatibility (`last`, `systemctl`, `ls *.service`, `ls /etc/shadow`, `getcap`)
- `art-execution-linux` campaign: guarded `cron.d` and `crontab` commands
- Verbose output gracefully handles empty duration for skipped/precondition_failed stages
- Agent binary version uses `pkg/version` — GoReleaser ldflags apply correctly
- Makefile `cross` and `build` targets build both `threatecho` and `threatecho-agent`

### Stats
- 234 Go files (128 source + 106 test), ~119K LOC
- 3,370 tests across 22 packages — all passing
- 72 campaigns (17 classical + 42 AI agent + 13 ART live-execution), 15 policies, 10 agents

## [0.0.27]

### Added

#### Precondition Engine — `internal/runner` (NEW PACKAGE)
- Runner functions extracted from engine into dedicated `internal/runner` package
- Platform check: validates runtime OS matches stage requirements
- Elevation check: two-layer — operator must allow AND process must be privileged
- Tool availability check: extracts binaries from shell commands, verifies via PATH lookup
- Smart command parser: skips builtins (echo, cd, etc.), wrappers (sudo, su), flags, redirections, env vars
- `CheckAll()` stops on first failure for fast feedback
- `InferPreconditions()` derives checks from stage YAML fields — no custom DSL needed

#### Structured Run Reports — `internal/runner`
- JSON output with: hostname, OS, arch, user, elevation status, timestamps, per-stage results
- Each stage reports: status (passed/failed/skipped/precondition_failed), precondition details, output, duration, command count, cleanup errors
- `--out <file>` flag on agent binary for report persistence
- Exit code 1 on any failure or precondition failure

#### Agent Binary Hardening (`cmd/threatecho-agent`)
- Two-layer elevation check: `--elevated` flag (operator permission) + runtime privilege verification (uid 0 / Administrator)
- `--env` flag for environment variable injection
- `--max-output` flag for output capping
- `--workdir` flag for working directory override
- Precondition-aware: `check` subcommand now uses full precondition engine

### Stats
- 229 Go files (125 source + 104 test), ~117K LOC
- 3,070 tests across 20 packages — all passing
- 69 campaigns (17 classical + 42 AI agent + 10 ART live-execution), 15 policies, 10 agents

## [0.0.26]

### Added

#### Golden-File CLI Tests (12 snapshots)
- Snapshot regression tests for: help, version, validate, lint-dir, campaigns-list, stats, gap-json, compliance-list, threat-model-json, risk-posture-json, attack-tree-json, doctor
- Timestamp/version normalization prevents false-positive diffs
- Run `go test -update-golden` to regenerate after intentional output changes

#### End-to-End Pipeline Integration Test (8 subtests)
- `TestIntegration_FullPipelineEndToEnd` loads real YAML fixtures (campaigns/, agents/, policies/) and runs the full analysis pipeline end-to-end
- Validates JSON structure for gap, threat-model, risk-posture, attack-tree, and compliance outputs
- Tests HTML dashboard generation and doctor workspace health check
- Asserts key field presence in all JSON outputs — the integration capstone

#### CLI Error Hints
- Contextual hints on common errors: missing campaign/policy/agent directories suggest init, generate, or correct flag usage
- Permission denied errors suggest checking file access
- Hints appear as `hint:` line below the error message
- 7 new tests for hint system

### Fixed

#### Flag Consistency
- Normalized `-policies` → `-policy` across `doctor` and `threat-model` commands (14 commands now use `-policy` consistently)
- Updated shell completions, help text, and all test references

#### ART Live-Execution Campaigns (10 campaigns)
- `art-credential-access-windows` — LSASS dump (comsvcs + ProcDump), SAM registry, NTDS.dit via VSS, cached creds, credential vault, browser creds
- `art-credential-access-linux` — /etc/shadow, unshadow, shell history, /proc memory, SSH key theft, cloud credentials
- `art-discovery-windows` — systeminfo, user/group, network, remote systems, processes, security software, domain trusts
- `art-discovery-linux` — system info, users/groups, network, processes, SUID/capabilities/sudo, SSH keys
- `art-persistence-windows` — registry Run key, scheduled task, service, startup folder, WMI event subscription + cleanup
- `art-persistence-linux` — cron, systemd service, .bashrc, SSH authorized_keys, at jobs, rc.local
- `art-defense-evasion-windows` — disable Defender, clear event logs, disable ETW, timestomping, disable firewall, process masquerading
- `art-execution-windows` — encoded PowerShell, MSHTA, CertUtil download, BITSAdmin, Rundll32, WScript, Regsvr32 (Squiblydoo)
- `art-lateral-movement-windows` — SMB admin shares, WMI remote exec, WinRM, PsExec-style service, RDP enable, pass-the-hash indicators
- `art-exfiltration-multi` — data staging, archive compression, HTTP/DNS/ICMP exfiltration, clipboard collection

#### Telemetry Registry Expansion
- 11 new detection types: `event_log_clear`, `event_log_query`, `firewall_rule_add`, `registry_access`, `registry_write`, `scheduled_task_create`, `scheduled_task_delete`, `script_block_logging`, `service_delete`, `wmi_create`, `wmi_event`
- 9 types registered alongside v0.0.23–v0.0.25 feature and campaign additions: `authentication_event`, `ci_event`, `database_query`, `feedback_log`, `legacy_protocol_auth`, `rate_limit`, `rdp_session`, `waf_event`, `web_log`
- 3 compatibility aliases formalized: `process_creation`, `file_deletion`, `file_modification`
- Total telemetry types: 108 (was 85 at v0.0.22)

### Stats
- 225 Go files (122 source + 103 test), 116,787 LOC
- 2,966 tests + 7 fuzz targets + 16 benchmarks across 19 packages — all passing
- 69 campaigns (17 classical + 42 AI agent + 10 ART live-execution), 12 golden snapshot files

## [0.0.25]

### Added

#### Behavior Profile → Risk Posture Integration
- `buildBehaviorDimension()` wired into `AssessRisk()` for live behavior scoring
- Added `BehaviorReports []*agent.DeviationReport` to `RiskInputs`
- Scoring: 60% worst-case agent risk + 40% anomaly ratio across all agents
- Counts total deviations, critical deviations, anomalous agents
- 6 new risk engine tests for behavior dimension (nil, empty, clean, anomalous, multi-agent, nil entries)

#### Go-Native Fuzz Targets (7 targets)
- `FuzzCampaignYAMLParse` / `FuzzCampaignJSONParse` — campaign YAML and JSON parser fuzzing
- `FuzzPolicyYAMLParse` / `FuzzTestSuiteYAMLParse` / `FuzzMatchPattern` — policy parser + pattern matcher
- `FuzzAgentYAMLParse` / `FuzzInventoryAnalyzeTrust` — agent parser + trust analysis
- All targets pass with zero crashes across ~63K executions

#### Go-Native Benchmarks (16 benchmarks)
- Engine: `BenchmarkBuildAttackTree`, `BenchmarkGenerateThreatModel`, `BenchmarkAssessRisk`, `BenchmarkSimulate`, `BenchmarkCaptureBaseline`
- Campaign: `BenchmarkCampaignYAMLParse`, `BenchmarkCampaignValidate`, `BenchmarkResolveOrder`
- Policy: `BenchmarkPolicyYAMLParse`, `BenchmarkPolicyLint`, `BenchmarkMatchPattern`
- Agent: `BenchmarkAgentYAMLParse`, `BenchmarkAgentValidate`, `BenchmarkTrustAnalysis`, `BenchmarkBuildTrustGraph`, `BenchmarkDependencyGraph`

### Fixed
- `main_test.go` — replaced hardcoded `const srcRoot` with `findModuleRoot()` for Docker/CI portability

### Stats
- 225 Go files (122 source + 103 test), 116K LOC
- 2,951 tests, 7 fuzz targets, 16 benchmarks across 19 packages — all green
- 59 campaigns, 15 policies, 10 agents

## [0.0.24]

### Added

#### SOC Compliance Mapping Engine — `compliance -dir` (NEW)
- `internal/compliance/` — new package mapping campaign detection coverage to enterprise compliance frameworks
- NIST Cybersecurity Framework 2.0 (19 controls across Govern/Identify/Protect/Detect/Respond/Recover)
- NIST SP 800-53 Rev.5 (20 control families: AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR)
- CIS Controls v8 (18 controls)
- `Assess()` — maps gap analysis coverage to a single framework with per-control results
- `AssessAll()` — maps against all three frameworks
- Posture scoring: weighted coverage score (0-100) with strong/moderate/developing/weak ratings
- Per-control risk classification: critical/high/medium/low based on mapped tactic severity
- `FormatAssessment()`, `FormatAssessmentJSON()`, `FormatMultiAssessment()` — text and JSON output
- CLI: `compliance -dir campaigns/ -framework nist-csf` (single), `compliance -dir campaigns/` (all)
- `compliance -list` now shows both AI agent and SOC/enterprise frameworks
- 26 tests for the compliance package + 5 CLI integration tests

#### Attack Tree Engine — `internal/engine/attacktree.go` (NEW)
- AND/OR attack tree construction from agent inventories with probabilistic risk scoring
- `BuildAttackTree()` — decomposes "compromise the deployment" into per-agent sub-goals: tool exploitation, trust abuse, prompt injection, guardrail evasion
- Probability propagation: AND nodes multiply, OR nodes use complement product
- Impact scoring scaled by trust level (untrusted=2, admin=10)
- Policy mitigation detection — marks leaves blocked by deny rules
- `extractTopPaths()` — top N root-to-leaf paths ranked by risk
- `FormatAttackTree()`, `FormatAttackTreeJSON()`, `SummarizeAttackTree()` — text/JSON/one-line output
- 32 tests covering nil/empty/single/multi-agent, mitigation, AND/OR propagation, formatting

#### Attack Tree CLI — `attack-tree` (NEW)
- Wired `BuildAttackTree()` into CLI
- `attack-tree -agents agents/` — build attack trees from agent inventory
- `-policy` flag for mitigation analysis (marks policy-blocked leaves)
- `-json` flag for machine-readable output
- 4 CLI integration tests

#### Code of Conduct — Ethical Adversary Simulation
- `CODE_OF_CONDUCT.md` — focused on responsible use, safe simulation principles, no-weaponization policy
- Ethical AI agent testing guidelines (tool-call policy testing, trust validation, delegation chain risks, baseline drift)
- No generic boilerplate — specific to adversary simulation and detection engineering

### Stats
- 225 Go files (122 source + 103 test), 116,394 LOC
- 2,930 tests across 19 packages — all green
- 59 campaigns, 15 policies, 10 agents, 6 compliance frameworks

## [0.0.23]

### Added

#### Deployment Baseline Engine — `deploy-baseline` (NEW)
- `CaptureBaseline()` — point-in-time snapshot of policies, agents, lint scores, rule counts, tools, tactics
- `DiffBaselines()` — compares two snapshots with severity-ranked change detection (policy added/removed/modified, agent added/removed/modified, score changes)
- `SaveBaseline()` / `LoadBaseline()` — JSON persistence for baseline snapshots
- `FormatBaseline()` / `FormatBaselineDiff()` — box-drawing formatted text output
- `SummarizeBaseline()` / `SummarizeDiff()` — one-line summaries
- Risk delta computation with severity weighting and verdict assignment (improved/degraded/stable/mixed)
- Deterministic fingerprinting (SHA-256, order-independent)
- CLI `deploy-baseline` command with capture/compare/view modes, JSON output

#### Policy Assertion Testing — `policy test -suite` (NEW)
- `TestSuite`, `TestCase`, `TestExpectation` — declarative YAML-based policy test definitions
- `RunTestSuite()` — executes assertion tests against a policy, verifying effect/rule-id/no-match expectations
- `ValidateTestSuite()` — structural validation of test suite files
- `GenerateTestSuite()` — auto-generates test suite skeleton from policy rules
- `FilterTestsByTag()` — tag-based test filtering
- `LoadTestSuite()` / `LoadTestSuiteDir()` — YAML loading for test suites
- Wildcard pattern matching for tool names (prefix `shell_*` and suffix `*_exec`)
- CLI: `policy test -suite <file>`, `policy test -generate`, with JSON output support

#### Campaigns — 9 new AI agent attack campaigns (59 total)
- `agent-memory-manipulation` — attacking agent persistent memory stores
- `multi-model-arbitrage` — exploiting model switching in multi-LLM architectures
- `function-calling-overflow` — tool definition injection via oversized function schemas
- `agent-state-desync` — causing inconsistent state across distributed agent components
- `context-window-stuffing` — filling context to evict safety instructions
- `rag-index-poisoning` — corrupting vector store indices to control retrieval results
- `agent-credential-harvest` — extracting API keys and tokens from agent configs
- `llm-output-parsing-exploit` — exploiting structured output parsers (JSON/XML injection)
- `agent-orchestrator-takeover` — compromising the orchestration layer of multi-agent systems

#### Documentation — Go doc comments
- Complete Go doc comments on all exported types, functions, methods, and constants across all 18 packages

### Stats
- 213 Go files (119 source + 94 test), 112,832 LOC
- 2,900 tests across 18 packages — all green
- 59 campaigns, 15 policies, 10 agents

## [0.0.22]

### Added

#### Policy Impact Analysis — `policy impact` (NEW)
- `PolicyChange`, `ImpactAssessment`, `ImpactReport`, `TraceImpact` types
- `DiffPolicyChanges()` — detects 7 change types between policy versions (add/remove/modify rule, change effect/trust, add/remove guardrail)
- `AnalyzeImpact()` — full impact assessment: severity, affected agents, breaking changes, risk delta
- `AnalyzeTraceImpact()` — replay traces against policy changes, detect new violations and resolved ones
- `AssessChange()` — per-change severity scoring (critical/high/medium/low)
- `ComputeRiskDelta()` — quantified risk score difference between policy versions
- `FindAffectedAgents()`, `FindAffectedTools()` — blast radius estimation
- `IsBreakingChange()` — identifies changes that would break existing agent workflows
- `FormatImpactReport()`, `SummarizeImpact()` — formatted output
- 80 unit tests

#### Agent Dependency Graph — `agent dependency` (NEW)
- `DependencyGraph`, `DependencyEdge`, `BlastRadius`, `SinglePointOfFailure`, `EscalationPath` types
- `BuildDependencyGraph()` — maps inter-agent delegation, tool sharing, and trust relationships
- `AnalyzeBlastRadius()` — per-agent blast radius with risk scoring and severity
- `FindSinglePointsOfFailure()` — detects agents whose failure cascades
- `FindEscalationPaths()` — privilege escalation chains across agent delegations
- `GenerateDependencyReport()` — full dependency analysis with clusters, SPOFs, paths, recommendations
- `FormatDependencyReport()`, `FormatBlastRadius()`, `SummarizeDependencies()` — formatted output
- 60 unit tests

#### Policy Compliance Mapping — `policy compliance` (EXTENDED)
- `ComplianceMapping`, `ComplianceControl`, `ComplianceReport` types
- Framework mappings: NIST AI RMF, OWASP LLM Top 10, MITRE ATLAS, NIST CSF, NIST 800-53, CIS v8
- `EvaluateCompliance()` — maps policy rules to compliance controls, identifies gaps
- `FormatComplianceReport()` — formatted output with control coverage percentages
- 25 unit tests

#### HTML Dashboard Report — `dashboard` (NEW)
- `DashboardData`, `DashboardSection`, `DashboardConfig` types
- `BuildDashboard()` — aggregates risk posture, lint, threat model, agent inventory, policies
- Functional options: `WithRiskPosture()`, `WithLintReport()`, `WithThreatModel()`, `WithAgentInventory()`, `WithPolicies()`
- Executive summary with overall grade, risk dimensions, recommendations
- 60 unit tests

#### Maturity Content
- 30 new AI agent campaigns (total: 50) covering supply chain, model poisoning, credential theft, insider threat, cloud exfiltration, RAG exploitation, MCP abuse, and more
- 12 new policies (total: 15): api-gateway, autonomous-agent, compliance-hipaa, compliance-pci, data-classification, development-sandbox, incident-response, ml-pipeline, multi-agent-governance, production-lockdown, rag-protection, tool-calling-strict
- 7 new agent definitions (total: 10): code-assistant, customer-service, data-analyst, deployment-bot, research-agent, security-scanner, trading-bot

#### Infrastructure
- `Makefile` — 30+ targets (build, test, test-race, coverage, vet, fmt, lint, cross-compile, docker, CI pipeline)
- `Dockerfile` — multi-stage build (builder + alpine runtime)
- `.goreleaser.yml` — release automation for Linux/macOS/Windows amd64/arm64
- `.github/workflows/ci.yml` — CI pipeline (fmt, vet, race tests, campaign lint, release)
- `.golangci.yml` — linter configuration
- `.gitignore` — standard Go gitignore

#### Documentation
- `docs/architecture.md` — comprehensive 18-package architecture guide with data flow diagrams
- `docs/campaigns.md` — campaign authoring guide with execute types, DAG dependencies, variables
- `docs/policies.md` — policy authoring guide with lint rules, templates, remediation workflows

#### Telemetry Registry
- 13 new telemetry types: Windows Event Log (4624/4625/4662/4778, Sysmon, NTLM, ScriptBlock), Active Directory (LDAP, replication), Cloud (CloudTrail, IAM, STS), Web/WAF, CI/CD, and more
- Total registered types: 85 (was 72)

### Changed
- README.md overhauled with logo, full feature list, command tree
- `assets/` directory: logo.svg (favicon), logo-title.png, logo-circle.png

### Stats
- 208 Go files, ~108,303 LOC
- 2,780 tests across 18 packages — all passing
- 50 campaigns, 15 policies, 10 agent definitions

## [0.0.21]

### Added

#### Policy Remediation Engine — `policy remediate` (NEW)
- `RemediationAction`, `RemediationPlan` types with YAML before/after snippets
- `RemediateFromLint()` — generates fixes from all 25 lint rules (SEC→add deny, COV→add coverage, etc.)
- `RemediateFromDrift()` — generates fixes from all 9 drift types (restore effects, scope, conditions)
- `RemediateFromCoverage()` — generates rules to close technique gaps
- `MergeRemediations()` — combines multiple plans, deduplicates by source, keeps higher priority
- `ApplyRemediation()` — applies add_rule, remove_rule, add_metadata actions to policy (deep copy)
- `FormatRemediationPlan()` — box-drawing output with priority icons and auto-apply indicators
- Effort estimation: minimal/moderate/significant based on action count and severity
- CLI: `-source lint|drift|coverage|all`, `-baseline` for drift, `-json` output
- 68 unit tests including full lint→remediate→apply integration test

#### Policy Template Engine — `policy generate` (REWRITTEN)
- `PolicyTemplate`, `TemplateParam`, `TemplateConfig`, `TemplateCatalog` types
- 6 built-in templates: agent-minimal, agent-strict, rag-safe, tool-calling-restricted, autonomous-guardrailed, compliance-soc2
- `ListTemplates()`, `GetTemplate()` — template discovery and retrieval
- `RenderTemplate()` — parameterized policy generation with deep-copy isolation
- `ValidateTemplateConfig()` — parameter type/required validation with defaults
- `DefaultTemplateConfig()` — universal `agent_name`/`policy_name` overrides
- `FormatTemplateCatalog()`, `FormatTemplateDetail()` — formatted output
- Template parameters: string, bool, int, list types with defaults and required semantics
- Each template produces a fully valid `Policy` per `ValidatePolicy()`
- 39 unit tests

#### Multi-Trace Correlation Engine — `trace correlate` (NEW)
- `CorrelationRule`, `Correlation`, `CorrelatedEvent`, `CorrelationReport` types
- `CorrelateTraces()` — detects cross-agent attack patterns invisible in single-trace analysis
- `CorrelateWithRules()` — custom correlation rule support
- `DefaultCorrelationRules()` — 8 built-in rules:
  - temporal-burst (coordinated rapid activity within 30s window)
  - tool-sequence-attack (recon → exploit → exfil chains within 10min)
  - privilege-chain (escalation across agents)
  - data-convergence (multiple agents touching same targets)
  - target-sweep (systematic scanning, 5+ targets)
  - coordinated-access (concurrent access within 60s window)
  - relay-attack (agent-to-agent delegation abuse within 2min)
  - boundary-probe (repeated authorization failures, 3+ threshold)
- 5 correlation types: temporal, target, tool_sequence, agent_cluster, escalation_path
- Risk scoring (0-1), severity classification, correlation confidence
- `FormatCorrelationReport()` — box-drawing output consistent with replay.go style
- `SummarizeCorrelations()` — one-line summary
- 53 unit tests

#### SARIF Export — `export sarif` (NEW)
- `Finding`, `SARIFLog`, `SARIFRun`, `SARIFResult`, `SARIFRule` types (SARIF v2.1.0)
- `FindingSARIFReport()` — generic findings to SARIF
- `LintSARIFReport()` — lint results to SARIF
- `ThreatSARIFReport()` — STRIDE threat model to SARIF
- `FormatSARIF()`, `WriteSARIF()` — JSON serialization and file output
- Rule deduplication, severity mapping (error→error, warning→warning, info→note, style→none)
- CI/CD integration ready (SARIF is the standard for security tooling output)
- 30 unit tests

#### Risk Posture Assessment — `risk-posture` (NEW)
- `RiskInputs`, `RiskPosture`, `RiskConfig` types
- `AssessRisk()` — unified risk scoring combining lint, coverage, chain analysis, and threat model
- A-F grading based on weighted composite risk score
- `FormatRiskPosture()` — box-drawing summary
- CLI: `-policy`, `-agents`, `-json` flags
- Unit tests in `engine/risk_test.go`

### Changed
- Policy subcommands: 18 → 19 (added `remediate`)
- Trace subcommands: 1 → 2 (added `correlate`)
- Top-level commands: 44 → 45 (added `risk-posture`)

### Stats
- 198 Go files, ~97,500 LOC
- 2,427 tests across 18 packages — all passing
- 20 campaigns, 3 policies, 3 agent definitions

## [0.0.20]

### Added

#### Scenario Engine — NEW PACKAGE `internal/scenario/`
- `Scenario`, `ScenarioMeta`, `StageExpectation`, `Precondition`, `PassCriteria` types
- `Load()`, `LoadDir()`, `Validate()`, `Evaluate()` — scenario store with campaign-policy binding
- `FormatResult()`, `FormatSummaryTable()` — box-drawing formatted output
- Pass criteria: `min_blocked_ratio`, `max_allowed`, `require_all_expectations`
- Outcome derivation: deny > alert > allow priority
- 45 unit tests

#### Campaign Generation Engine — `campaigns generate` (NEW)
- `Generate()`, `GenerateYAML()` — create campaigns from technique IDs, tactics, or profiles
- 3 built-in profiles: `ai-red-team` (5 ATLAS), `apt-simulation` (5 ATT&CK), `compliance-check` (8 mixed)
- Tactic-based generation: auto-selects representative techniques per tactic
- Generated campaigns pass `Validate()` automatically
- `slugify()`, `techniqueToStage()` helpers for stage ID generation
- 20+ unit tests

#### Campaign Diff Engine — `campaigns diff` (from prior version, verified)
- `Diff()`, `FormatDiff()`, `DiffFiles()` — structural comparison of two campaigns
- Stage matching by ID with field-level change tracking
- 22 unit tests

#### Policy Lint Engine — `policy lint` (NEW)
- `LintPolicy()`, `FormatLintReport()` — best-practice quality checking and scoring
- 25 lint rules across 6 categories: security, coverage, redundancy, naming, complexity, best-practice
- 4 severity levels: error, warning, info, style
- A/B/C/D/F grading with percentage score
- Actionable suggestions for each finding
- Exit code 2 for CI when errors found
- 40+ unit tests, 4 CLI integration tests

#### Agent Attestation — `agent attest` (NEW)
- `AttestAgent()`, `AttestInventory()`, `VerifyAttestation()` — cryptographic fingerprinting
- SHA-256 fingerprints for tools, capabilities, guardrails, boundaries
- Claims system with verification (8 claim types)
- Single-agent and full-inventory attestation modes
- 30 unit tests, 5 CLI integration tests

#### Trace Replay Engine — `trace replay` (NEW)
- `ReplayTrace()`, `ReplayTraceWithPolicy()` — anomaly detection on execution traces
- 8 anomaly types: elevated_tool, rapid_calls, unusual_target, timestamp_gap, denied_action, prompt_injection, privilege_escalation, data_exfiltration
- Timeline reconstruction with duration computation
- Risk scoring from anomaly severity
- 38 unit tests, 5 CLI integration tests

#### Policy Coverage Map — `policy coveragemap` (NEW)
- `MapCoverage()`, `FormatCoverageReport()`, `SummarizeCoverage()` — MITRE technique mapping
- Maps policy rules to ATT&CK techniques and agent-specific pseudo-techniques (TE001-TE008)
- 17 techniques tracked (9 ATT&CK + 8 ThreatEcho)
- Per-tactic coverage percentages
- Gap identification with recommendations
- Coverage risk scoring (gap-weighted)
- 59 unit tests, 4 CLI integration tests

#### Agent Behavior Profiling — `agent profile` (NEW)
- `BuildProfile()`, `DetectDeviations()` — behavioral baseline from traces
- Tool usage stats, action pattern mining, time profiling
- 7 deviation types: new_tool, frequency_spike, unusual_target, timing_anomaly, pattern_break, boundary_expansion, risk_elevation
- Profile and deviation report formatting
- CLI: `-traces`, `-agent`, `-json` flags

#### STRIDE Threat Model Generator — `threat-model` (NEW top-level)
- `GenerateThreatModel()`, `FormatThreatModel()`, `SummarizeThreatModel()` — STRIDE analysis
- 6 STRIDE categories with agent-specific threat patterns
- Automatic mitigation assessment from policies and guardrails
- Risk scoring (severity × likelihood, 0-10 scale)
- Mitigation status: mitigated / partial / unmitigated
- Category breakdown and overall risk aggregation
- 72 unit tests, 4 CLI integration tests

#### Scenario Package Tests — 82 tests (expanded)
- Rewrote scenario_test.go: 78 test functions (82 total with subtests)
- Full coverage: Load, LoadDir, Validate, Evaluate, Format, internal matchers
- All tests parallelized with `t.Parallel()`

### Changed
- Policy subcommands expanded from 16 to 18 (added: lint, coveragemap)
- Agent subcommands expanded from 9 to 11 (added: attest, profile)
- Trace subcommand: replay (1 new)
- New top-level command: threat-model
- Scenario subcommands: run, validate, list (3 from prior)
- Total CLI commands: 97 (44 top-level + 53 subcommands)
- Shell completions updated for all new subcommands and flags
- New package: `internal/trace/` (trace replay engine)
- Help text updated for trace, agent commands

### Stats
- 191 Go files, ~89K LOC
- 2,293 tests across 18 packages (all passing)
- 20 campaigns, 3 policies, 3 agent definitions, 97 commands

## [0.0.19]

### Added

#### Scenario Runner — `scenario` command (NEW top-level)
- `threatecho scenario run -dir <campaign> [-policy <path>]` — generate synthetic traces from campaigns, optionally evaluate compliance
- `threatecho scenario validate -dir <campaign>` — validate a campaign can produce traces
- `threatecho scenario list -dir <campaign>` — list stages and expected event counts
- `engine.RunScenario()`, `engine.RunScenarioFromDir()` — closed-loop campaign→trace→policy-eval pipeline
- Command→tool_call mapping, telemetry→event type mapping, execute-type inference
- 24 engine tests + 10 CLI integration tests

#### Policy Simulation — `policy simulate` command (NEW)
- `threatecho policy simulate -policy <path> <campaign>` — dry-run campaign against policy
- Per-stage tool inference, rule matching, and allow/deny/alert decisions
- `SimulatePolicy()`, `FormatSimulationReport()` — core engine + box-drawing report
- 9 unit tests + 5 integration tests

#### Policy Export — `policy export` command (NEW)
- `threatecho policy export -format <fmt> <policy-path>` — export policy for CI/CD
- 4 formats: JSON (machine-readable), YAML summary, OPA Rego, human summary
- `ExportToRego()` — converts policy rules to OPA/Rego `deny[msg]`/`alert[msg]` blocks
- `ExportToSummary()` — simplified view with rule counts by effect
- `-output` flag for writing to file
- 11 unit tests + 4 integration tests

#### Policy Benchmark — `policy benchmark` command (NEW)
- `threatecho policy benchmark <policy-path>` — benchmark policy evaluation latency
- Per-tool and aggregate timing: avg, p99, max, tools/sec
- Synthetic tool generation: matching tools, non-matching tools, wildcard tests
- Tiered recommendations: "Excellent" (<10µs) to "Critical" (>10ms)
- Default 1000 iterations, configurable via `-iterations`
- 7 unit tests + 3 integration tests

#### Policy Drift Detection — `policy drift` command (NEW)
- `threatecho policy drift <baseline> <current>` — detect semantic drift between policy versions
- 9 drift types: rule added/removed, effect changed, scope widened/narrowed, priority shift, condition changed, meta changed
- 5 severity levels with impact scoring: critical (deny→allow), high (scope widened), medium, low, info
- `DetectDrift()`, `FormatDriftReport()`, `SummarizeDrift()` — engine + formatted output
- Weighted drift score (0.0–1.0) with per-severity weights
- 43 unit tests + 5 integration tests

#### Agent Chain Analysis — `agent chain` command (NEW)
- `threatecho agent chain [-dir <agents>]` — analyze multi-agent delegation chains
- 5 violation types: trust escalation, boundary crossing, confused deputy, over-delegation, unguarded chain
- Chain enumeration with cycle detection, trust level tracking, boundary analysis
- `AnalyzeChains()`, `FormatChainAnalysis()`, `SummarizeChains()` — engine + formatted output
- Weighted risk score (0.0–1.0) with per-severity weights
- 32 unit tests + 3 integration tests

#### New AI Security Campaigns
- `prompt-leaking` — 9-stage campaign: system prompt extraction and instruction leaking
- `agent-identity-spoofing` — 8-stage campaign: multi-agent identity verification attacks
- `tool-call-injection` — 9-stage campaign: tool parameter injection and tool name confusion

### Changed
- Policy subcommands expanded from 12 to 16 (added: simulate, export, benchmark, drift)
- Agent subcommands expanded from 8 to 9 (added: chain)
- New top-level command: `scenario` with 3 subcommands (run, validate, list)
- Shell completions updated for all new subcommands and flags

### Stats
- 176 Go files, ~75,800 LOC
- 1,741 tests across 16 packages (all passing)
- 20 campaigns, 3 policies, 3 agent definitions, 92 commands

## [0.0.18]

### Added

#### Guardrail Analysis Engine — `policy guardrail` command (NEW)
- `threatecho policy guardrail` — analyze guardrail coverage against traces and policy
- 8 recommended default guardrails: prompt injection, output toxicity, PII detection, content safety, jailbreak detection, data leakage monitoring, credential filtering, instruction hierarchy
- `AnalyzeGuardrails()` — evaluates guardrail setup against traces and policy
- `DefaultGuardrails()` — recommended guardrail configurations for AI agents
- `FormatGuardrailAnalysis()` — box-drawing guardrail report with alignment and gap analysis
- Guardrail-policy alignment checking: detects conflicts between guardrails and deny/allow rules
- Gap detection for mandatory guardrail categories with risk ratings
- Coverage and alignment scoring
- 43 unit tests + 3 integration tests

#### Policy Compliance Engine — `policy compliance` command (NEW)
- `threatecho policy compliance` — batch compliance evaluation of traces against policy
- `EvaluateComplianceBatch()` — evaluates multiple traces, produces per-trace and overall grades (A-F)
- `FormatComplianceReport()` — box-drawing compliance report with violation details
- Scoring: deny events reduce score fully, alerts reduce at 0.3x weight
- Exit code 2 on non-compliance for CI/CD integration
- 8 unit tests + 4 integration tests

#### Policy Version History — `policy history` command (NEW)
- `threatecho policy history -init` — initialize version tracking for a policy
- `threatecho policy history -add` — snapshot current policy as new version
- `threatecho policy history -diff 1:2` — compare any two versions
- `threatecho policy history` — show version timeline with stats
- SHA256 fingerprinting for each version, author and comment tracking
- `NewHistory()`, `AddVersion()`, `DiffVersions()`, `GetStats()`
- `HistoryToJSON()`, `HistoryFromJSON()` — serialization to/from history files
- `FormatHistory()`, `FormatVersionDiff()` — box-drawing reports
- 28 unit tests + 5 integration tests

#### Agent Guardrail Analysis — `agent guardrail` command (NEW)
- `threatecho agent guardrail` — evaluate guardrail coverage for individual agents or inventory
- Capability-based guardrail requirements: tool_calling, rag, code_execution, web_access, file_access, message_passing, memory, autonomous
- Trust-level minimum enforced guardrail checks per agent
- Elevated tool guardrail enforcement detection
- Unenforced and redundant guardrail detection
- Severity-weighted scoring (critical -0.20, high -0.12, medium -0.06, low -0.03) with A-F grades
- `AnalyzeGuardrails()`, `AnalyzeAllGuardrails()` — single and inventory-wide analysis
- `FormatGuardrailReport()`, `FormatInventoryGuardrailReport()` — box-drawing reports
- 42 unit tests

#### Agent-Policy Binding — `agent test` command (NEW)
- `threatecho agent test -policy <path>` — evaluate policy coverage for agent tool declarations
- Single agent or full inventory evaluation mode
- Tool coverage analysis using glob pattern matching against policy rules
- Elevated tool deny-rule and overpermissive access detection
- Capability-guardrail alignment (code_execution→tool-call, rag→input, message_passing→agent_message)
- Rate limit gap detection for elevated tools
- Coverage scoring (A-F) with per-tool breakdown
- `EvaluateBinding()`, `EvaluateAll()` — single and inventory-wide evaluation
- `FormatBinding()`, `FormatInventoryBinding()` — box-drawing reports
- 52 unit tests

#### Agent Trust Graph — `agent graph` command (NEW)
- `threatecho agent graph` — visualize trust relationships between agents
- Three output formats: text (box-drawing), DOT (Graphviz), Mermaid
- Trust level color coding, risk edge highlighting, escalation path marking
- `BuildTrustGraph()` — constructs directed trust graph from inventory
- `FormatDOT()`, `FormatMermaid()`, `FormatText()` — multi-format output
- JSON output for programmatic consumption
- 17 unit tests + 4 integration tests

#### New AI Security Campaigns
- `agent-memory-attack` — 8-stage campaign: agent memory corruption and manipulation attacks
- `agent-tool-confusion` — 7-stage campaign: tool confusion and parameter injection attacks

#### New Telemetry Types
- `memory_write`, `memory_access`, `preferences_update` — agent memory operation telemetry

### Changed
- Policy subcommands expanded from 9 to 12 (added: guardrail, history, compliance)
- Agent subcommands expanded from 5 to 8 (added: test, guardrail, graph)
- Total user-facing commands: 78 (34 top-level + 44 subcommands)
- Shell completions updated for all new subcommands and flags

### Stats
- 162 Go files, ~67,000 LOC
- 1,680 tests across 16 packages (all passing)
- 17 campaigns, 3 policies, 3 agent definitions, 78 commands

## [0.0.17]

### Added

#### Agent Inventory and Trust Analysis — `agent` command (NEW)
- `threatecho agent list` — list all agents in the inventory with type and trust level
- `threatecho agent show <path>` — detailed view of a single agent definition
- `threatecho agent validate` — validate agent YAML definitions (single or directory)
- `threatecho agent trust` — analyze trust relationships, detect escalation paths and risks
- New `internal/agent/` package (~780 LOC): `Agent`, `AgentMeta`, `AgentCapabilities`, `ToolAccess`, `TrustConfig`, `Guardrail`, `Inventory`, `TrustAnalysis`, `TrustRisk` types
- `LoadAgent()`, `LoadInventory()` — YAML loading from files/directories
- `ValidateAgent()` — 14+ validation rules (type, trust level, capabilities, guardrails)
- `AnalyzeTrust()` — full trust graph analysis: escalation paths, over-trusted agents, boundary gaps, missing guardrails
- `FormatInventory()`, `FormatTrustAnalysis()`, `FormatAgent()` — box-drawing reports
- 3 example agent definitions: support-agent, billing-agent, orchestrator
- 56 unit tests + 11 integration tests

#### Policy Inheritance and Composition
- `BuildChain()` — resolve policy inheritance chains with circular dependency detection
- `ResolveChain()` — flatten layered policies into a single resolved policy
- `DetectOverrides()` — track which child rules override parent rules
- `FormatChain()` — box-drawing inheritance chain visualization
- `ValidateChain()` — inheritance chain validation
- Policy extends support for layered policy architectures

#### Policy Diff Engine
- `DiffPolicies()` — structural diff between two policy versions
- Added/removed/modified rule detection with field-level change tracking
- `FormatDiff()` — box-drawing diff visualization
- Agent scope and metadata change detection

#### Policy Risk Assessment
- `AssessRisk()` — automated risk scoring for policy configurations
- Multi-dimensional scoring: conflict density, overpermissive rules, coverage gaps
- A/B/C/D/F grading with per-dimension breakdowns
- Actionable findings generation

#### Policy Templates and Generation — `policy generate`
- `threatecho policy generate <template>` — generate policies from built-in templates
- `threatecho policy generate -list` — list all available templates with descriptions
- 5 built-in templates: agent-minimal (4 rules), agent-rag (8 rules), agent-multi (8 rules), agent-production (14 rules), soc-baseline (8 rules)
- `-agent` and `-name` customize the generated policy for a specific agent
- `-output` saves generated YAML to file
- 16 unit tests + 6 integration tests

#### Policy Testing — `policy test`
- `threatecho policy test <path>` — test against 11 built-in attack scenarios (expanded from 6)
- 5 new scenarios: benign-tool-use, rag-poisoning, mcp-tool-hijack, memory-poisoning, model-extraction
- Each new fixture models real AI-agent attack patterns with realistic events
- Cross-evaluation: all attack traces tested against strict policies

#### New AI Security Campaigns
- `agent-supply-chain` — 9 stages covering supply chain attacks on AI agent tool plugins and MCP servers
- `model-extraction` — 9 stages covering model extraction and IP theft from AI agents
- `multi-agent-attack` — 11 stages covering multi-agent orchestration attacks, trust graph exploitation, shared memory poisoning, cascade failures, and coordinated exfiltration

#### Telemetry Registry Expansion
- 11 new AI agent telemetry types: mcp_request, mcp_response, capability_negotiation, conversation_trajectory, data_transfer, file_access, rate_limit_trigger, resource_access, token_count_anomaly, document_upload, embedding_computation

#### Additional AI Security Campaigns
- `agent-jailbreak` — 10 stages covering systematic jailbreak escalation: instruction override, persona injection, encoding bypass, context stuffing, multi-turn manipulation, few-shot attack, constraint exhaustion, tool escalation, guardrail error exploitation, cross-context injection
- `mcp-server-attack` — 8 stages covering MCP protocol attacks: server discovery, schema manipulation, tool description poisoning, capability escalation, resource template injection, transport-layer attack, cross-server pivoting, notification-channel exfiltration
- `rag-data-poisoning` — 9 stages covering RAG pipeline poisoning: pipeline recon, document injection, embedding space manipulation, chunk boundary exploit, metadata poisoning, retrieval manipulation, context overflow, cross-query persistence, output manipulation

### Stats
- 150 Go files, ~59,300 LOC
- 1,599 tests across 16 packages
- 15 campaigns (6 new AI-security campaigns)
- 48 commands (added agent subcommands + policy generate/diff/risk; expanded policy test from 6 to 11 scenarios)
- 3 example agent inventory definitions

## [0.0.16]

### Added

#### Policy Engine Expansion — Compiler, Merge, Coverage
- `threatecho policy compile <path>` — compile a policy, detect conflicting rules, show stats
- `Compile()` indexes rules by tool/tactic/action/target for O(1) lookup
- `CheckConflicts()` finds rules with overlapping matches but different effects (deny vs allow)
- Glob-aware pattern overlap detection (`patternsOverlap()`)
- `CompiledPolicy`, `Conflict`, `CompileStats` types
- Box-drawing compilation report with conflict warnings
- JSON output for CI integration (`-json`)
- `threatecho policy merge <path> <path> [...]` — merge multiple policies into one
- `MergePolicies()` combines rules from all policies with unique ID resolution
- `-output` saves merged YAML to file
- `threatecho policy coverage <path>` — analyze what a policy covers
- `AnalyzeCoverage()` compares rules against reference tool/tactic/action sets
- `-dir campaigns/` extracts reference tools from actual campaign data
- Coverage percentages with ASCII bar charts, high-risk gap identification
- `CoverageReport`, `CoverageGap` types
- 23 unit tests for compiler, 22 integration tests

#### Agent Execution Trace Analysis — `trace` Command
- `threatecho trace <trace.json>` — analyze agent execution trace files
- `threatecho trace -policy <path> <trace.json>` — evaluate traces against policies
- `Trace`, `TraceEvent`, `ToolCallEvent`, `PromptEvent`, `ResponseEvent`, `GuardrailEvent`, `AgentMessageEvent` types
- JSON trace format for recording AI agent behavior (tool calls, prompts, responses, guardrails, inter-agent messages)
- `ParseTrace()` / `ParseTraceFile()` — JSON trace parsing with validation
- `EvaluateTrace()` — full policy evaluation against actual agent traces
- Reuses policy rule matching (glob patterns, conditions, priorities) against trace events
- `AnalyzeTrace()` — aggregate statistics (event counts, unique tools, guardrail triggers)
- Box-drawing evaluation and statistics reports
- Exit code 2 when denied tool calls detected (CI-friendly)
- `TraceViolation`, `TraceEvalResult`, `TraceStats` types
- 34 unit tests + 4 integration tests

#### Behavioral Baseline and Drift Detection — `baseline` Command
- `threatecho baseline -dir campaigns/ [-label name] [-output file]` — build behavioral baselines
- `threatecho baseline -dir campaigns/ -compare baseline.json` — detect drift
- `BuildBaseline()` / `BuildBaselineDir()` — capture behavioral profiles from campaigns
- Tracks tools, tactics, techniques, severities, platforms, exec types, tags, telemetry, detections
- SHA256 fingerprints per campaign for tamper detection
- `DetectDrift()` / `DetectDriftDir()` — compare current state against recorded baseline
- Drift scoring (0.0–1.0) with risk-weighted dimensions and classification (none/low/medium/high/critical)
- Campaign add/remove/modify tracking, technique/tactic/tool change tracking, severity shift detection
- Risk-tagged drift details (AI/ATLAS techniques = high risk, exfiltration/impact tactics = high)
- JSON round-trip serialization for baseline persistence
- Box-drawing baseline profile and drift reports with risk icons
- Exit code 2 for high/critical drift (CI-friendly)
- `Baseline`, `DriftReport`, `SeverityShift`, `DriftDetail` types
- 30 unit tests + 5 integration tests

### Stats
- 136 Go files, ~47,900 LOC
- 1,285 tests across 15 packages (115 new tests)
- 42 commands (2 new top-level: baseline, trace; 3 new policy subcommands: compile, merge, coverage)

## [0.0.15]

### Added

#### `tag` Command — Tag Management
- `threatecho tag [flags]` — tag taxonomy across all campaigns
- List all unique tags with usage counts and campaign associations
- `-find <tag>` — find campaigns with a specific tag (case-insensitive)
- `-suggest` — content-based tag suggestions for untagged campaigns
- 10 suggestion rules (ransomware, credential-theft, lateral-movement, apt, ai-security, llm-security, critical, data-theft, phishing, cloud)
- Box-drawing report with proportional bars
- 42 unit tests + 4 integration tests

#### `report` Command — Executive Assessment Reports
- `threatecho report [flags]` — comprehensive executive report combining stats, scores, and coverage
- Five report sections: Executive Summary, Risk Assessment, Coverage Overview, Detection Readiness, Recommendations
- Auto-generated recommendations based on coverage gaps and risk profiles
- `-format text` (rich terminal with box-drawing) and `-format markdown` (GitHub-compatible)
- `-output` saves to file, `-json` for programmatic consumption
- Overall risk grade computed from campaign score averages
- 47 unit tests + 5 integration tests

#### `audit` Command — Campaign State Snapshots
- `threatecho audit [flags]` — point-in-time campaign state snapshots and change tracking
- `TakeSnapshot()`/`TakeSnapshotDir()` — capture campaign hashes, techniques, tactics, severity
- `DiffSnapshots()` — detect added, removed, modified, and unchanged campaigns
- `-output snapshot.json` — save snapshot for future comparison
- `-compare old.json` — diff current state against a saved snapshot
- SHA256 content hashing per campaign for tamper detection
- JSON round-trip serialization for snapshot persistence
- 29 unit tests + 4 integration tests

#### Package Documentation
- Added `doc.go` for all 13 internal packages (campaign, cli, config, engine, executor, gap, matrix, mitre, navigator, policy, report, sigma, telemetry)

### Stats
- 130 Go files, ~43,200 LOC
- 1,170 tests across 15 packages (133 new tests)
- 40 commands (search, stats, import, enrich, score, convert, tag, report, audit)

## [0.0.14]

### Added

#### `enrich` Command — ATT&CK Metadata Enrichment
- `threatecho enrich [flags] [path]` — auto-annotate campaign stages with ATT&CK metadata
- 60-technique enrichment database with data sources, mitigations, detection notes, platforms
- Falls back to MITRE registry for unknown techniques (name + tactic resolution)
- Sub-technique inheritance from parent technique enrichment data
- Severity inference from tactic (impact → critical, initial-access/execution → high, etc.)
- `-json` output for programmatic consumption
- Single-campaign and directory-wide enrichment
- `FormatEnrichment()` renders readable report with stage-by-stage metadata
- 29 tests (103 including subtests)

#### `score` Command — Risk & Complexity Scoring
- `threatecho score [flags] [path]` — multi-dimensional risk scoring for campaigns
- Five scoring dimensions (0-100 each):
  - Technique Complexity (25%): unique techniques, sub-techniques, credential-access/lateral-movement
  - Tactic Breadth (20%): tactic coverage ratio, full kill-chain bonus
  - Detection Difficulty (25%): detection rules, telemetry, cleanup, evasion techniques
  - Execution Complexity (15%): elevated privileges, dependencies, exec type diversity, HTTP/C2
  - Evasion Sophistication (15%): defense-evasion, privilege-escalation, persistence, cleanup
- Weighted composite score with A-F letter grade
- Score factors tracked for auditability
- `-detail` shows per-dimension breakdown with contributing factors
- `-json` for programmatic consumption
- Directory scoring sorted by risk (highest first)
- Rich ASCII bar charts in terminal output
- 44 tests

#### `convert` Command — Format Conversion
- `threatecho convert [flags] [path]` — convert campaigns between formats
- Supported targets: JSON, YAML, Markdown, CSV
- JSON: configurable indent, compact mode
- YAML: optional normalization (canonical field ordering)
- Markdown: H1 title, severity/stage/technique badges, stages table, variables table, detection coverage section
- CSV: RFC 4180 compliant, header row (toggleable with -compact), one row per stage
- `ParseJSON()` for JSON → Campaign round-trip
- `-output` for file/directory output
- `-dir` for bulk conversion of all campaigns
- `ConvertFile()` and `ConvertDir()` for programmatic use
- 32 tests

#### Package Documentation
- Added `doc.go` for campaign package with godoc-compatible overview
- Updated CONTRIBUTING.md with current test baseline

### Stats
- 112 Go files, ~39,400 LOC
- 1,037 tests across 15 packages (194 new tests)
- 37 commands (3 new: enrich, score, convert)

## [0.0.13]

### Added

#### `search` Command — Campaign Search Engine
- `threatecho search [flags]` — search campaign stages across all campaigns
- 9 search criteria: `-technique`, `-tactic`, `-adversary`, `-tag`, `-keyword`, `-severity`, `-stage`, `-platform`, `-exec-type`
- All non-empty fields are ANDed for precise multi-dimensional queries
- Technique prefix matching (e.g. `T1059` matches `T1059.001`, `T1059.003` etc.) with dot-boundary precision
- `-json` output for tooling integration
- `-dir` override for campaign directory
- `SearchDir()` walks subdirectories automatically
- `FormatSearchResults()` renders human-readable table with dynamic column widths
- Match reasons tracked per result (e.g. `technique:T1059.001`, `tactic:execution`)
- 35 unit tests + 5 integration tests

#### `stats` Command — Project Analytics Dashboard
- `threatecho stats [flags]` — project-wide campaign analytics
- Campaign-level metrics: total campaigns, stages, severity counts, adversary list
- Technique analysis: frequency ranking, tactic distribution, framework breakdown (ATT&CK/ATLAS/OWASP)
- Execution analysis: exec type counts, elevated stages, total commands
- Detection readiness: detection/telemetry coverage percentages, gap identification
- Dependency complexity: graph depth, average depth across campaigns
- Content metrics: variable counts, cleanup commands, timeout/delay stages
- Rich box-drawing dashboard with proportional bar charts
- Technique name resolution via MITRE registry
- `-json` output for programmatic consumption
- 25 unit tests + 3 integration tests

#### `import` Command — Atomic Red Team Importer
- `threatecho import -source atomic <path>` — import ART YAML as ThreatEcho campaigns
- Single-file import (`ImportAtomicFile`) and directory import (`ImportAtomicDir`)
- Maps each Atomic test to a campaign stage with technique/tactic resolution
- Executor-type mapping: powershell, command_prompt, sh, bash, manual
- Command splitting, cleanup extraction, elevation flag propagation
- Input argument → variable conversion
- Telemetry inference per executor type (process_create, script_block, etc.)
- Stage ID sanitization: kebab-case, 64-char limit, uniqueness via numeric suffix
- `-platforms` filter, `-max-tests` limit, `-name` and `-adversary` overrides
- `-output` writes campaign.yaml to directory
- `FormatImportSummary()` renders import statistics
- `manual` added to valid exec types in validator
- 24 unit tests + 5 integration tests

### Stats
- 105 Go files, ~34,900 LOC
- 843 tests across 15 packages (101 new tests)
- 34 commands (3 new: search, stats, import)

## [0.0.12]

### Added

#### `watch` Command — Live Campaign Re-Validation
- `threatecho watch [-dir campaigns/]` — polls campaign files for changes and re-validates on save
- Detects file additions, modifications, and removals in real-time
- `-validate` (default: true) runs structural validation on changed campaigns
- `-lint` (default: true) runs quality checks on changed campaigns
- `-format` checks for canonical formatting drift
- `-interval` configurable polling interval (default: 2s)
- Cross-platform file polling (os.Stat based, no inotify/fsnotify dependency)
- First scan establishes baseline without firing events; subsequent polls detect changes
- Graceful Ctrl+C shutdown via context cancellation

#### `template` Command — Campaign Scaffolding
- `threatecho template list` — shows all 7 built-in campaign templates
- `threatecho template create -template <name> -name <campaign-name>` — generates a scaffold campaign
- `-output <dir>` writes campaign.yaml to directory, or stdout without it
- 7 built-in templates:
  - **apt** — 7-stage classic APT kill chain (spearphish → execution → persistence → defense evasion → C2 → lateral movement → exfiltration)
  - **ransomware** — 7-stage RaaS chain (initial access → execution → priv esc → defense evasion → discovery → lateral movement → encrypt)
  - **insider** — 4-stage insider threat (valid accounts → data collection → staging → exfiltration)
  - **agent-hijack** — 5-stage AI agent attack (prompt injection → model manipulation → tool abuse → data theft → persistence) using ATLAS + OWASP
  - **supply-chain** — 5-stage supply chain compromise (trojanized update → execution → persistence → C2 → credential harvest)
  - **cloud** — 5-stage cloud attack (cloud accounts → discovery → storage → API → exfiltration)
  - **minimal** — 1-stage blank canvas for quick prototyping
- All templates produce valid Campaign structs that pass `Validate()`
- Real ATT&CK/ATLAS/OWASP technique IDs, proper dependency chains, telemetry on every stage

#### `timeline` Command — Execution Time Estimation
- `threatecho timeline <campaign-path>` — estimates campaign execution time from DAG structure
- `threatecho timeline -dir campaigns/` — timeline estimates for all campaigns
- Sequential vs parallel execution time comparison with speedup ratio
- Duration-weighted critical path (not just depth-based)
- Per-stage earliest start/end times computed from dependency resolution
- Execution levels showing which stages run concurrently
- Stage timeouts used as duration estimates; DefaultStageDuration (30s) as fallback
- `-format json` for machine-readable output

#### `env` Command — Environment Variable References
- `threatecho env <campaign-path>` — lists all `${env:VAR}` references with set/unset status
- `threatecho env -dir campaigns/` — scan all campaigns for env var references
- `-check` flag exits 1 if any referenced env vars are not set (CI gate)
- Pre-flight check for secret injection before execution

#### Environment Variable Expansion (`internal/campaign`)
- `${env:VAR_NAME}` syntax in campaign YAML for runtime secret injection
- Expands in all operational fields: commands, targets, payloads, args, cleanup, artifacts, IOCs, variable values
- Does NOT expand in structural fields: stage IDs, technique IDs, tactic names, telemetry types, detection names
- `AllowMissing` mode: missing vars expand to empty string, or left as-is (default)
- `$$` escape: `$${env:X}` produces literal `${env:X}` in output
- `ListEnvRefs()` for documentation/pre-flight scanning
- `ValidateEnvRefs()` for CI validation of required env vars

#### Campaign Template Engine (`internal/campaign`)
- `ListTemplates()` — returns all 7 built-in templates with metadata
- `GenerateCampaign(templateName, campaignName)` — produces a complete Campaign struct
- `FormatTemplateList()` — human-readable template table
- Templates use real technique IDs, proper dependency chains, shell execute with `[SIM]` placeholders

#### Campaign Timeline Engine (`internal/campaign`)
- `EstimateTimeline(c *Campaign) *TimelineEstimate` — full DAG-aware timing analysis
- `FormatTimeline(est *TimelineEstimate)` — human-readable report with levels and critical path
- Uses `AnalyzeGraph()` for DAG structure, processes levels in topological order
- Duration-weighted critical path via `findDurationCriticalPath()` backward trace

#### Campaign Watch Engine (`internal/campaign`)
- `Watch(ctx, opts WatchOptions)` — blocking file watcher with context cancellation
- `WatchEvent` with campaign name, path, type (added/modified/removed), validation errors, lint results, format drift
- Polling-based for cross-platform compatibility (no inotify/fsnotify dependency)
- Baseline scan on first run (no spurious events)

#### Sigma Detection Expansion — 30 → 65 Techniques
- 35 new technique detection signatures added to `internal/sigma/detections.go`
- New techniques by tactic:
  - Initial Access: T1566.003
  - Execution: T1059.004, T1059.005, T1059.007, T1569.002
  - Persistence: T1547.001, T1136.001
  - Privilege Escalation: T1078, T1548.002, T1055
  - Defense Evasion: T1562.001, T1070.001, T1027, T1218.011, T1140
  - Credential Access: T1558.003, T1110.003, T1528, T1539
  - Discovery: T1018, T1087.004, T1538, T1057, T1049
  - Collection: T1005, T1560.001, T1074.001
  - Command and Control: T1572, T1573
  - Exfiltration: T1041, T1048, T1567.002
  - Impact: T1486, T1489
  - Cloud/Identity: T1098.001
- All 22 campaign techniques that lacked Sigma coverage now have real detection signatures
- Plus 13 additional high-value techniques for broader coverage

### Tests Added
- `internal/campaign`: 13 watch tests — file add/modify/remove detection, context cancellation, validation, lint, format drift, skip non-campaigns, multiple changes, error callbacks
- `internal/campaign`: 24 env expansion tests — basic/multi/same-var, missing strict/permissive, structural field protection, commands/target/args/variables, escape, list/validate refs
- `internal/campaign`: 19 template tests — list all 7, generate each template, unknown template, custom name, valid campaigns, telemetry on all stages, dependency chains, variables, format list
- `internal/campaign`: 20 timeline tests — single/linear/parallel/diamond/wide DAG, timeouts, delays, default duration, critical path, earliest start, parallel levels, speedup, format output
- `internal/sigma`: Sigma coverage test updated from 30 to 65 required technique IDs
- `cmd/threatecho`: 12 integration tests — watch help, template (list/default/create stdout/dir/unknown), timeline (single/dir/JSON), env (no args/campaign/dir)

### Stats
- 99 Go source files, ~31,400 lines of code
- 742 test runs across 15 packages, all passing
- 31 commands (8 with subcommands)
- 7 output formats: text, JSON, SARIF v2.1.0, JUnit XML, HTML, Markdown, Sigma YAML
- 9 built-in campaigns (7 classical + 2 AI agent) — all lint clean
- 7 built-in campaign templates (apt, ransomware, insider, agent-hijack, supply-chain, cloud, minimal)
- 3 built-in policies (agent-default, agent-strict, soc-baseline)
- 109 ATT&CK + 16 ATLAS + 10 OWASP = 135 techniques in registry
- 65 techniques with real Sigma detection signatures (was 30)
- 58 telemetry types across 11 categories
- 6 structured exit codes for CI integration
- Shell completions for bash, zsh, fish (31 commands)
- 4 documentation guides + CONTRIBUTING.md + SECURITY.md

## [0.0.11]

### Added

#### `diff` Command — Campaign Structural Diff
- `threatecho diff <campaign-a> <campaign-b>` — structural comparison between two campaigns
- Stages matched by ID (not position) — handles reordering gracefully
- Field-level diff: technique, tactic, telemetry, detections, dependencies, execute config, transitions
- Variable changes: additions, removals, value modifications
- Meta field changes: name, severity, adversary, tags, authors, etc.
- Slice fields (telemetry, commands, etc.) show individual item additions/removals
- Map fields (variables, execute.args) show per-key changes
- Duration values compared correctly (zero values ignored)
- `-format json` for machine-readable output
- Human-readable text output with `+`/`-`/`~` markers grouped by section
- `DiffFiles()` convenience function for path-based comparison
- `HasChanges()` and `Summary()` methods on diff report

#### `merge` Command — Campaign Composition
- `threatecho merge <campaign-a> <campaign-b> [...]` — combine multiple campaigns into one
- Stage namespace control: `-prefix` prefixes IDs with campaign name (e.g. `apt29/initial-access`)
- Prefix mode auto-updates all internal references: `depends_on`, `on_success`, `on_failure`
- Collision strategies: `-strategy error` (fail, default) or `-strategy first` (keep first)
- Variable namespace merge with collision detection and strategy-aware resolution
- Meta composition: highest severity, joined adversaries, union of tags/authors/references
- MITRE version: highest version string wins
- Deep cloning: mutations to merged result never leak to source campaigns
- `-output <dir>` writes merged campaign YAML to directory
- Without `-output`, prints canonical YAML to stdout
- `-name` flag to override merged campaign name

#### `completion` Command — Shell Completion Scripts
- `threatecho completion bash` — Bash completion (source in .bashrc or /etc/bash_completion.d/)
- `threatecho completion zsh` — Zsh completion (add to fpath)
- `threatecho completion fish` — Fish completion (save to completions dir)
- All 27 commands and subcommands with tab completion
- Flag completion per command with context-aware subcommand flags
- File/directory completion for campaign path arguments
- Compound subcommand flag completion (e.g. `policy eval -` completes policy eval flags)

#### `profile` Command — Campaign Complexity Profiling
- `threatecho profile <campaign-path>` — detailed campaign metrics and complexity analysis
- `threatecho profile -dir campaigns/` — comparison table of all campaigns sorted by complexity
- Size metrics: stages, techniques, tactics, telemetry types, detection rules, variables
- Framework breakdown: ATT&CK, ATLAS, OWASP technique lists
- Execution profile: shell/http/file/registry/service/elevated stage counts
- Dependency graph metrics: depth, width, entry points, terminal nodes
- Quality indicators: detection coverage %, telemetry coverage %
- Telemetry usage ranking with frequency bars
- Complexity score (0-100) with letter grade (A=simple through E=very complex)
- Scoring factors: stage count, technique diversity, tactic breadth, dependency density, graph depth, execution type diversity, multi-framework bonus
- `-format json` for machine-readable output
- `ProfileDir()` for batch profiling with complexity-sorted output

#### Campaign Diff Engine (`internal/campaign`)
- `Diff()` — structural comparison between two Campaign structs
- `DiffReport` with meta changes, variable diffs, stage additions/removals/modifications
- `StageDiff` with per-field changes within modified stages
- `FormatDiff()` — human-readable text formatter with section grouping
- Slice comparison with set-difference (additions/removals per item)
- Map comparison with per-key tracking

#### Campaign Merge Engine (`internal/campaign`)
- `Merge()` — combines multiple campaigns with configurable strategy
- Deep clone infrastructure: `cloneCampaign()`, `cloneStage()`, `cloneStrings()`
- `mergeMeta()` — composites metadata from multiple sources
- `mergeVariables()` — strategy-aware variable namespace merge
- `highestSeverity()` — picks most severe across campaigns
- `sanitizeName()` — produces ID-safe campaign name prefixes

#### Campaign Profile Engine (`internal/campaign`)
- `ProfileCampaign()` — computes comprehensive metrics for a single campaign
- `Profile` struct with 30+ fields across 6 categories
- `computeComplexity()` — multi-factor scoring algorithm
- `FormatProfile()` — detailed human-readable report
- `ProfileDir()` — batch profiling sorted by complexity
- `FormatProfileSummary()` — compact comparison table
- `TelemetryUsage` struct for frequency ranking

#### Shell Completion Generator (`internal/cli`)
- `BashCompletion()` — generates bash completion with command/subcommand/flag awareness
- `ZshCompletion()` — generates zsh completion with command descriptions
- `FishCompletion()` — generates fish completion with subcommand and flag support
- Centralized command/subcommand/flag registries for consistency

### Tests Added
- `internal/campaign`: 22 diff tests — identical, meta changes, variables (add/remove/modify), stages (add/remove/technique/telemetry/detections/depends/commands/args), multiple changes, HasChanges, Summary, FormatDiff
- `internal/campaign`: 25 merge tests — single campaign, no collisions, collision strategies (error/first/prefix), prefix reference updates (depends/on_success/on_failure), variable merge (no collision/same value/different value), meta composition (severity/tags/authors/references/adversary/version), empty input, nil campaign, deep copy, cross-campaign deps
- `internal/campaign`: 15 profile tests — basic metrics, technique classification (ATT&CK/ATLAS/OWASP/multi-framework), detection/telemetry coverage, elevated stages, telemetry usage sorting, empty campaign, graph metrics, complexity grade, format output, summary table, complex campaign scoring
- `internal/cli`: 11 completion tests — bash/zsh/fish content and subcommand/flag presence, command descriptions, non-empty output
- `cmd/threatecho`: 14 integration tests — diff (identical/different/JSON), merge (output dir/stdout/collision), completion (bash/zsh/fish/unknown), profile (single/dir/JSON)

### Stats
- 91 Go source files, ~26,600 lines of code
- 595 tests across 15 packages, all passing
- 27 commands (7 with subcommands)
- 7 output formats: text, JSON, SARIF v2.1.0, JUnit XML, HTML, Markdown, Sigma YAML
- 9 built-in campaigns (7 classical + 2 AI agent) — all lint clean
- 3 built-in policies (agent-default, agent-strict, soc-baseline)
- 109 ATT&CK + 16 ATLAS + 10 OWASP = 135 techniques in registry
- 30 techniques with real Sigma detection signatures
- 58 telemetry types across 11 categories
- 6 structured exit codes for CI integration
- Shell completions for bash, zsh, fish
- 4 documentation guides + CONTRIBUTING.md + SECURITY.md

## [0.0.10]

### Added

#### `fmt` Command — Canonical YAML Formatter
- `threatecho fmt <campaign-path>` — prints canonically formatted campaign YAML to stdout
- `threatecho fmt -w <campaign-path>` — writes formatted output back to source file
- `threatecho fmt -w -dir campaigns/` — format all campaigns in a directory
- `threatecho fmt -normalize -w <campaign-path>` — also normalize stage order and sort lists
- Canonical ordering: api_version → kind → meta → variables → stages
- Within stages: id → name → description → technique → tactic → platform → depends_on → execute → expect → transitions
- Empty fields omitted, consistent 2-space indentation
- Normalize mode: topological stage ordering, sorted telemetry/detections/tags/platform

#### `hash` Command — Campaign Content Fingerprinting
- `threatecho hash <campaign-path>` — SHA256 fingerprint of a campaign's canonical content
- `threatecho hash -dir campaigns/` — fingerprint all campaigns in a directory
- `threatecho hash -dir campaigns/ -manifest` — single hash for the entire directory (CI cache key)
- Output format: `<sha256>  <name-or-path>` (sha256sum compatible)
- Deterministic: same content = same hash regardless of field ordering

#### `graph` Command — Campaign Dependency Graph Analysis
- `threatecho graph analyze <campaign-path>` — comprehensive graph analysis showing:
  - Entry points and terminal stages
  - Critical path (longest dependency chain)
  - Parallel execution levels (stages at same depth)
  - Unreachable stages, orphan dependencies, dead transitions
  - Stage count, edge count, max depth
- `threatecho graph dot <campaign-path>` — Graphviz DOT export with:
  - Box nodes labeled with stage ID and technique
  - Solid edges for depends_on, dashed green for on_success, dashed red for on_failure
  - Green-filled entry points, pink-filled terminal stages
- `threatecho graph mermaid <campaign-path>` — Mermaid diagram export for GitHub/docs embedding
- Smart handling: on_failure mode strings (abort/skip/continue) not treated as stage references

#### `doctor` Command — Workspace Health Check
- Comprehensive workspace diagnostics in one command
- Config file detection (project config found/not found)
- Campaign validation and lint for all campaigns in directory
- Graph integrity: cycle detection, orphan dependencies, dead transitions, unreachable stages
- Policy validation for all policies in directory
- Telemetry registry utilization report (types used vs available)
- Exit code 1 when issues found (CI-friendly)

#### `telemetry` Command — Registry Inspection (4 subcommands)
- `telemetry list` — list all 58 registered types with descriptions
- `telemetry list -category <name>` — filter by category
- `telemetry categories` — show category names with type counts
- `telemetry check <type>` — validate a type string, show category and description, suggest alternatives for typos
- `telemetry stats -dir campaigns/` — usage report showing which types are used by which campaigns, sorted by frequency

#### Telemetry Type Validation in Lint
- `lint` now validates telemetry types against the 58-type registry
- Unrecognized types produce warnings with typo suggestions (substring/prefix matching)
- Example: `process_craete` → "did you mean: process_create?"
- All 9 built-in campaigns pass telemetry validation (verified by test)

#### Campaign YAML Formatter Engine (`internal/campaign`)
- `Format()` — canonical YAML serialization using `yaml.Node` tree for field ordering control
- `FormatFile()` — loads and formats, preserving template markers
- `FormatFileInPlace()` — load, format, write back (idempotent)
- `Normalize()` — deep copy with topological stage ordering, sorted lists, variable key ordering

### Tests Added
- `internal/campaign`: 21 graph analysis tests — linear chain, diamond, orphan deps, dead transitions, critical path, parallel levels, cycle detection, DOT/Mermaid output, real APT29 integration
- `internal/campaign`: 16 format tests — round-trip, field ordering, empty fields, normalize, idempotence, fingerprint preservation
- `internal/campaign`: 4 lint telemetry tests — unrecognized with suggestion, valid no warning, completely unknown, built-in campaigns pass
- `cmd/threatecho`: 13 integration tests — config (show/path/init), hash (single/dir/manifest/deterministic), graph (analyze/dot/mermaid), lint telemetry, exit codes

### Stats
- 83 Go source files, ~23,000 lines of code
- 502 tests across 15 packages, all passing
- 7 output formats: text, JSON, SARIF v2.1.0, JUnit XML, HTML, Markdown, Sigma YAML
- 9 built-in campaigns (7 classical + 2 AI agent) — all lint clean
- 3 built-in policies (agent-default, agent-strict, soc-baseline)
- 109 ATT&CK + 16 ATLAS + 10 OWASP = 135 techniques in registry
- 30 techniques with real Sigma detection signatures
- 58 telemetry types across 11 categories
- 6 structured exit codes for CI integration
- 4 documentation guides + CONTRIBUTING.md + SECURITY.md

## [0.0.9]

### Added

#### Config Integration
- All commands now load configuration from the layered config system (system → user → project → env → CLI flags)
- `campaigns_dir` config setting respected by `gap`, `matrix`, `coverage`, `summary`, `campaigns list` commands
- `default_format` config setting used as fallback when `-format` flag isn't explicitly set
- `default_policy` config setting used by `policy eval` and `summary` when no `-policy` flag given
- `author` config setting used by `export sigma` as default rule author
- `no_color` config setting merged with `NO_COLOR` environment variable
- Config is loaded once at startup and shared across all commands

#### `config` Command — Configuration Inspection
- `threatecho config show` — displays fully resolved configuration with merge-order comment
- `threatecho config path` — shows all config file search paths with "found" indicators
- `threatecho config init` — creates a `.threatecho.yaml` project config template

#### Structured Exit Codes
- All 17 commands now use typed `cli.Error` exit codes instead of raw `os.Exit(1)`
- Exit code 0 (OK): successful execution
- Exit code 1 (Validation): campaign/policy YAML validation failures, lint warnings
- Exit code 2 (PolicyDenied): policy evaluation found denied violations
- Exit code 3 (Runtime): simulation errors, export failures, JSON serialization errors
- Exit code 4 (IO): file not found, directory missing, campaign load failures
- Exit code 64 (Usage): missing arguments, unknown commands, bad subcommands
- CI pipelines can now branch on exit code without parsing stderr

#### Telemetry Type Registry (`internal/telemetry`)
- Formal taxonomy of 58 telemetry types across 11 categories
- Categories: Process (4), File (7), Network (7), Registry (5), Authentication (9), Service (5), Script (5), AI Agent (9), Cloud (3), Email (2), Operational (2)
- All 28 telemetry types used in the 9 built-in campaigns are registered
- Functions: `Valid()`, `All()`, `Category()`, `Description()`, `ByCategory()`, `Categories()`, `Suggest()`
- `Suggest()` provides typo correction with substring, prefix, and segment matching
- Ready for lint integration: campaigns can be checked against the registry

#### Campaign Content Hashing (`internal/campaign`)
- SHA256 fingerprinting for reproducibility, caching, and change detection
- `Fingerprint(c *Campaign) string` — deterministic hash of canonical campaign content
- `FingerprintFile(path string)` — loads and fingerprints a campaign file
- `FingerprintDir(dir string)` — fingerprints all campaigns in a directory (name → hash map)
- `FingerprintManifest(dir string)` — single hash representing entire campaign directory for CI cache keys
- Stage order independent: stages sorted by ID before hashing
- Telemetry, detections, depends_on all sorted for determinism
- Variables sorted by key (map iteration order irrelevant)

### Changed
- CLI dispatch uses `cli.ExitUsage` (64) for unknown commands instead of exit 1
- Validate command uses `cli.ValidationErrors()` for consistent error formatting
- Policy eval exit code changed from raw `os.Exit(2)` to `cli.ExitPolicyDenied` (2)
- `export sigma -author` flag defaults to config `author` setting instead of hardcoded "ThreatEcho"
- All shared helpers (`collectCampaignPaths`, `simulateCampaigns`, `loadAndSimulateDir`) use typed errors
- Integration tests updated to expect new structured exit codes (64 for usage, 4 for IO)

### Tests Added
- `internal/telemetry`: 21 tests — valid/invalid types, categories, descriptions, suggestions, campaign coverage
- `internal/campaign`: 22 tests — fingerprint determinism, format, content sensitivity, stage/telemetry/variable order independence, file/dir/manifest operations
- Integration test assertions updated for structured exit codes

### Stats
- 79 Go source files, ~20,000 lines of code
- 448 tests across 15 packages, all passing
- 7 output formats: text, JSON, SARIF v2.1.0, JUnit XML, HTML, Markdown, Sigma YAML
- 9 built-in campaigns (7 classical + 2 AI agent) — all lint clean
- 3 built-in policies (agent-default, agent-strict, soc-baseline)
- 109 ATT&CK + 16 ATLAS + 10 OWASP = 135 techniques in registry
- 30 techniques with real Sigma detection signatures
- 58 telemetry types across 11 categories
- 6 structured exit codes for CI integration
- 4 documentation guides + CONTRIBUTING.md + SECURITY.md

## [0.0.8]

### Added

#### `matrix` — ATT&CK Technique Coverage Matrix
- Terminal-rendered ATT&CK tactic×technique heat map with ANSI color coding
- Coverage levels: Uncovered (red), Partial (yellow), Detected (green), Full (bright green)
- Full render mode: 14 tactic columns with technique IDs vertically, unicode box-drawing borders
- Compact render mode: tactic names with coverage ratios and horizontal bar charts
- Gap report enrichment: techniques with detection gaps downgraded to Partial
- `-compact` flag for narrower terminals
- Respects `NO_COLOR` environment variable

#### `coverage` — Technique-Level Coverage Analysis
- Drill-down coverage report showing each technique's detection status
- Per-technique detail: which campaigns exercise it, telemetry types, detection rules
- Coverage status: full (detections + telemetry + multi-campaign), detected, telemetry-only, uncovered
- Framework breakdown with visual bars (ATT&CK, ATLAS, OWASP)
- Uncovered techniques listed by tactic for gap prioritization
- JSON output for pipeline consumption (`-format json`)

#### Real Sigma Detection Logic — 30 Technique Signatures
- Real Sigma selection criteria for all 30 mapped techniques
- 30 ATT&CK techniques mapped to detection signatures: process image paths, parent processes, command-line patterns, network ports, registry keys, file paths
- Technique-specific detections: T1059.001 (PowerShell encoded commands), T1003.001 (LSASS access via procdump/mimikatz), T1490 (vssadmin shadow delete), T1021.001 (RDP port 3389), T1566.001 (Office child processes), T1071.004 (DNS tunneling long subdomains), and 24 more
- Fallback to generic scaffolding only for unmapped techniques
- New `internal/sigma/detections.go` with `TechniqueDetection` map

#### Configuration File System (`internal/config`)
- Layered config loading: system → user → project → environment → CLI flags
- System config: `/etc/threatecho/config.yaml`
- User config: `~/.config/threatecho/config.yaml`
- Project config: `.threatecho.yaml` (walks parent directories like git)
- Environment overrides: `THREATECHO_CAMPAIGNS_DIR`, `THREATECHO_DEFAULT_FORMAT`, `THREATECHO_AUTHOR`, etc.
- Config fields: campaigns_dir, policies_dir, default_format, default_policy, author, no_color, output.sarif_category, output.junit_suite

#### Structured Exit Codes (`internal/cli`)
- Typed exit codes: OK (0), Validation (1), PolicyDenied (2), Runtime (3), IO (4), Usage (64)
- Typed `cli.Error` with code, message, and wrapped cause
- Constructor functions: `Validation()`, `PolicyDenied()`, `Runtime()`, `IOError()`, `UsageError()`
- `DieCode()` extracts exit code from any error for CI integration

### Changed
- CLI `help` and dispatch updated with `matrix` and `coverage` commands
- Sigma `buildSelection()` now checks technique-specific detections before falling back to generic
- Sigma `writeRule()` handles `int` and `[]int` types for port numbers in detection criteria

### Tests Added
- `internal/cli`: 11 tests — exit codes, error wrapping, DieW output, nil handling
- `internal/config`: 17 tests — defaults, merge, YAML parsing, project config discovery, env overrides
- `internal/matrix`: 11 tests — empty/single/multi-campaign matrix, coverage levels, compact render, gap enrichment
- `internal/gap`: 8 tests — technique coverage empty/single/multi, status logic, framework stats
- `internal/report`: 47 tests — gap report (14), compare report (8), policy report (7), text report (13), coverage (5)
- `internal/sigma`: 5 new tests — known technique selection, unknown fallback, 30-technique coverage check

### Stats
- 75 Go source files, ~18,800 lines of code
- 389 tests across 14 packages, all passing
- 7 output formats: text, JSON, SARIF v2.1.0, JUnit XML, HTML, Markdown, Sigma YAML
- 9 built-in campaigns (7 classical + 2 AI agent) — all lint clean
- 3 built-in policies (agent-default, agent-strict, soc-baseline)
- 109 ATT&CK + 16 ATLAS + 10 OWASP = 135 techniques in registry
- 30 techniques with real Sigma detection signatures
- 4 documentation guides + CONTRIBUTING.md + SECURITY.md

## [0.0.7]

### Added

#### Campaign Library Expansion — 9 Built-in Campaigns
- **APT28 / Fancy Bear** — 11-stage Russian GRU campaign: spearphishing links, OAuth token theft, PowerShell execution, Kerberoasting, NTDS.dit extraction, SMB lateral movement
- **Lazarus Group** — 12-stage DPRK campaign: supply chain compromise, Python RAT, masquerading, service persistence, internal scanning, credential harvesting, financial data theft, disk wiper
- **Volt Typhoon** — 11-stage Chinese LOTL campaign: VPN appliance exploit, valid accounts, exclusively built-in Windows tools (netsh/wmic/nltest), protocol tunneling C2, no custom malware
- **LockBit Ransomware** — 12-stage RaaS double extortion: RDP brute force, Defender disablement, LSASS dump, RDP lateral movement, shadow copy deletion, service stop, GPO encryption deployment
- **Scattered Spider** — 11-stage identity/cloud campaign: vishing, SIM swap MFA bypass, MFA fatigue, session cookie theft, OAuth token theft, cloud dashboard recon, cloud persistence
- **RAG Poisoning** — 9-stage AI agent campaign: RAG architecture recon, embedding model probing, adversarial document crafting, metadata/invisible-text injection, cross-user propagation

#### Policy Library — 3 Built-in Policies
- **agent-strict** — 17-rule zero-trust policy: denies all tool calls by default, only allows read-only KB search and HTTP GET
- **soc-baseline** — 14-rule SOC policy: blocks elevated execution, credential access, privilege escalation; alerts on lateral movement, exfiltration, C2

#### ATT&CK Registry Expansion — 109 Techniques
- Added 44 new techniques: supply chain compromise, drive-by compromise, cloud accounts, Python execution, WMI, service execution, account manipulation, Windows service persistence, access token manipulation, masquerading, registry modification, MFA request generation, credential file search, cloud account discovery, network service discovery, pass the hash, external proxy, inhibit system recovery, and more

#### Documentation
- `docs/architecture.md` — technical architecture with ASCII diagrams, package structure, data flow, DAG execution model, risk scoring algorithm
- `docs/campaigns.md` — campaign YAML schema reference, telemetry types, dependency DAG ordering, lint checklist, examples
- `docs/policies.md` — policy DSL reference, evaluation flow, tool inference, glob matching, CI integration
- `docs/sigma.md` — Sigma integration guide, telemetry-to-logsource mapping, SIEM conversion

#### Project Files
- `CONTRIBUTING.md` — development workflow, campaign/policy contribution guide, code standards
- `SECURITY.md` — vulnerability reporting, scope, safe usage guidelines

#### Agent Binary — `cmd/threatecho-agent` (NEW)
- Standalone Go binary for deployment on target VMs
- `threatecho-agent run <campaign.yaml>` — execute campaigns with shell executor, collect results
- `threatecho-agent check <campaign.yaml>` — dry-run prerequisite validation
- `threatecho-agent version` — reports version, OS, architecture
- `--elevated` flag with operator permission check
- `--platform` flag with auto-detection
- Signal handling (SIGINT/SIGTERM) for clean cancellation

### Changed
- CI workflow validates all campaigns and policies dynamically (not hardcoded)
- Makefile `lint-campaigns` target uses dynamic campaign discovery
- Makefile adds `sigma-rules`, `gap-report-md`, `summary` targets
- README updated: expanded campaign table (classical + AI), policy table, Sigma/summary examples, project structure

### Stats
- 60 Go source files, ~14,500 lines of code
- 290 tests across 11 packages, all passing
- 7 output formats: text, JSON, SARIF v2.1.0, JUnit XML, HTML, Markdown, Sigma YAML
- 9 built-in campaigns (7 classical + 2 AI agent) — all lint clean
- 3 built-in policies (agent-default, agent-strict, soc-baseline)
- 109 ATT&CK + 16 ATLAS + 10 OWASP = 135 techniques in registry
- 4 documentation guides (architecture, campaigns, policies, sigma)
- ~2,600 lines of campaign/policy YAML
- ~1,800 lines of documentation

## [0.0.6]

### Added

#### `export sigma` — Sigma Detection Rule Generation
- Generate Sigma detection rule scaffolds from campaign expected detections
- One rule per expected detection per stage across all campaigns
- Deterministic rule IDs (SHA256-based) for stable cross-run references
- Telemetry-to-logsource mapping: 27 telemetry types → Sigma logsource categories
- Covers process, file, network, registry, authentication, script, agent telemetry
- AI agent telemetry (prompt_log, tool_call, etc.) maps to application logsource
- MITRE tag generation: `attack.<tactic>`, `attack.<technique>`
- Reference URL generation for ATT&CK, ATLAS, and OWASP techniques
- Selection scaffolding: telemetry-aware skeleton criteria per logsource type
- Severity mapping: tactic importance → Sigma level (high/medium)
- Multi-campaign export: `export sigma -dir campaigns/`
- `-author` flag to customize rule author field
- `-output` flag to write rules to file
- YAML output with `---` separators between rules

#### `summary` — Security Posture Dashboard
- Aggregate posture dashboard across all campaigns in a directory
- Campaign table with lint status, stage counts, severity
- Coverage section: ATT&CK and ATLAS tactic coverage percentages
- Risk score display with color-coded severity
- Gap breakdown: critical/high/medium/low counts
- Policy evaluation section (optional `-policy` flag)
- Lint summary: clean/warning counts
- ANSI-colored terminal output with `NO_COLOR` support

#### `gap -format md` — Markdown Gap Report
- GitHub-Flavored Markdown gap report output
- Summary table, framework coverage, tactic coverage tables
- Campaign details table with per-campaign ATT&CK/ATLAS coverage
- Detection gaps grouped by severity (Critical/High/Medium/Low)
- Risk summary table
- Timestamped footer with version
- No ANSI codes — clean for GitHub wikis, READMEs, docs

#### Sigma Rule Engine (`internal/sigma`)
- `sigma.Generate()` — produces rules from campaign expected detections
- `sigma.WriteRules()` — writes multi-rule YAML with separators
- `sigma.ResolveLogSource()` — telemetry-to-logsource mapping
- `sigma.AllMappedTelemetry()` — lists all mapped telemetry types
- 13 tests covering rule generation, deterministic IDs, tags, logsource mapping, references, YAML output

### Changed
- `export` subcommand now accepts `sigma` in addition to `navigator`
- `gap` command accepts `-format md` and `-format markdown`
- Help text updated with `summary`, `export sigma`, and Markdown format
- `.gitignore` added for build artifacts, IDE files, coverage output

### Stats
- 59 Go source files, ~14,000 lines of code
- 290 tests across 11 packages, all passing
- 7 output formats: text, JSON, SARIF v2.1.0, JUnit XML, HTML, Markdown, Sigma YAML
- 1 built-in policy (agent-default, 10 rules)
- 3 built-in campaigns (APT29, FIN7, LLM Agent Hijack) — all lint clean
- 65 ATT&CK techniques in registry

## [0.0.5]

### Added

#### `gap -format html` — Standalone HTML Coverage Report
- Self-contained single-file HTML gap report with embedded CSS
- Summary dashboard: campaigns, techniques, gaps, risk score
- Framework coverage bars (ATT&CK, ATLAS, OWASP stage distribution)
- ATT&CK tactic heatmap: 14 tactics as visual grid (covered/missing)
- ATLAS tactic heatmap: 7 tactics grid
- Campaign table with per-campaign coverage stats
- Gap breakdown grouped by risk severity with color-coded cards
- Risk distribution bar with legend
- Light/dark mode support via `prefers-color-scheme`
- Print-friendly CSS (no shadows, no sticky headers)
- Responsive layout down to 400px width
- `make gap-report` target generates `bin/gap-report.html`

#### CLI Integration Tests
- End-to-end binary tests in `cmd/threatecho/main_test.go`
- `TestMain` builds binary once, all tests execute against real binary
- 22 test cases covering all commands: validate, lint, simulate, gap (text/json/sarif/junit), policy (validate/eval/sarif/dir), export navigator, campaigns (list/show), init, version, help, unknown command
- Exit code validation, JSON/SARIF/JUnit format verification
- Parallel test execution for speed

#### GitHub Actions Workflow — Production CI Pipeline
- 6-job pipeline: test, lint-campaigns, gap-analysis, policy-eval, build, release
- **test**: `go vet` + `go test -race -coverprofile`, coverage artifact upload
- **lint-campaigns**: validates all 3 campaigns, runs `lint -dir campaigns/`
- **gap-analysis**: SARIF output → GitHub Code Scanning upload, JUnit test report via `dorny/test-reporter`
- **policy-eval**: policy SARIF → Code Scanning (separate category), JUnit report
- **build**: 6-target matrix (linux/darwin/windows × amd64/arm64), binary artifact upload
- **release**: GoReleaser on `v*` tag push
- Per-job scoped permissions: `security-events: write`, `checks: write`, `contents: write`

#### Makefile Overhaul
- `make install` — copies binary to `$GOPATH/bin`
- `make test-race` — tests with race detector
- `make test-verbose` — verbose test output
- `make coverage` — generates coverage profile with summary
- `make fmt-check` — verifies all files are gofmt'd (CI gate)
- `make lint-campaigns` — validates + lints all built-in campaigns
- `make gap-report` — generates HTML gap report to `bin/gap-report.html`
- `make ci` — full local CI pipeline (fmt-check + vet + test-race + lint-campaigns)
- Version auto-detected from git tags via `git describe --tags --always --dirty`

### Fixed
- **FIN7 campaign**: `url:` fields changed to `target:` (matching Execute struct schema)
- **FIN7 campaign**: removed orphaned `headers:` block from exfiltration stage
- **MITRE registry**: added T1018 (Remote System Discovery) — used by FIN7 campaign

### Changed
- `gap` command accepts `-format html` in addition to text/json/sarif/junit
- README updated with HTML report examples, lint output format note
- GitHub Actions workflow rewritten from 2 jobs to 6 with SARIF/JUnit integration

### Stats
- 52 Go source files, ~12,000 lines of code
- 175 tests across 10 packages, all passing
- 5 output formats: text, JSON, SARIF v2.1.0, JUnit XML, HTML
- 1 built-in policy (agent-default, 10 rules)
- 3 built-in campaigns (APT29, FIN7, LLM Agent Hijack) — all lint clean
- 65 ATT&CK techniques in registry

## [0.0.4]

### Added

#### `lint` command — Campaign Quality Checks
- `lint` command runs quality checks beyond structural validation
- Technique registry verification: flags technique IDs not found in ATT&CK/ATLAS/OWASP registries
- Framework/tactic consistency: warns when ATT&CK techniques use ATLAS tactics or vice versa
- Missing telemetry/detection warnings for gap analysis readiness
- Empty shell command detection, HTTP stages without targets
- Incomplete metadata info (description, objective, mitre_version)
- `-dir` flag to scan all campaigns in a directory
- `-format json` for machine-readable lint output
- Exit code 1 when warnings found (CI-friendly)

#### Engine.Run() — Proper Live Execution Engine
- `engine.Run()` function replaces manual execution loop in `run` command
- Topological stage ordering with platform filtering
- Progress callbacks (`OnProgress`) for real-time stage reporting
- Cleanup error callbacks (`OnCleanupError`) for non-fatal cleanup failures
- Completed/Skipped/Failed counters tracked by engine
- `cmdRun` refactored to use `engine.Run()` instead of manual loop

#### Runner Functions — Stage Execution for Target Deployment
- `Execute()` and run-report helpers for real campaign execution on target machines
- Config struct for execution control: AllowElevated, Platform, WorkDir, MaxOutput
- Stage status tracking: passed, failed, skipped
- Non-shell execute types gracefully skipped
- Basic run reports: campaign name, OS, hostname, per-stage status and output

#### SARIF v2.1.0 Output — CI/CD Integration
- `gap -format sarif` — gap analysis as SARIF v2.1.0 (GitHub Code Scanning, GitLab SAST, VS Code)
- `policy eval -format sarif` — policy violations as SARIF
- Three fixed gap rules: TE-GAP-001 (detection missing), TE-GAP-002 (telemetry missing), TE-GAP-003 (tactic uncovered)
- Policy rules derived from violation rule IDs with deny → error, alert → warning mapping
- Artifact locations pointing to campaign files
- Tool metadata: name, version, informationUri

#### JUnit XML Output — CI Test Reporting
- `gap -format junit` — gap analysis as JUnit XML (Jenkins, GitHub Actions, GitLab CI)
- `policy eval -format junit` — policy violations as JUnit XML
- Gap test cases: one per gap, classified by type (detection_missing, telemetry_missing, tactic_uncovered)
- Policy test cases: one per violation with effect as failure type
- Risk level in failure messages, rule IDs in descriptions
- Standard `<testsuites>` / `<testsuite>` / `<testcase>` structure

#### Technique Validation Library
- `mitre.ValidTechniqueExists(id)` — checks existence across ATT&CK, ATLAS, OWASP registries
- `mitre.ClassifyFramework(id)` — returns "attack"/"atlas"/"owasp"/"unknown" by ID prefix
- `mitre.ResolveName(id)` — human-readable technique name across all frameworks

#### Multi-Campaign Policy Evaluation
- `policy eval -dir` flag to evaluate a policy against all campaigns in a directory
- Per-campaign output with individual verdicts

### Changed
- `cmdRun` refactored: uses `engine.Run()` with progress callbacks instead of manual loop
- `gap` command accepts `-format sarif` and `-format junit` in addition to text/json
- `policy eval` accepts `-format sarif` and `-format junit`
- `policy eval` accepts `-dir` flag for batch campaign evaluation
- Help text updated with `lint` command and new format options
- CLI imports now include `encoding/json` for lint JSON output

### Stats
- 49 Go source files, ~10,500 lines of code
- 158 tests across 10 packages, all passing
- 4 output formats: text, JSON, SARIF v2.1.0, JUnit XML
- 1 built-in policy (agent-default, 10 rules)
- 3 built-in campaigns (APT29, FIN7, LLM Agent Hijack)

## [0.0.3]

### Added

#### `policy` command — Agent Tool-Call Policy Engine
- Declarative YAML policy DSL for agent tool-call enforcement
- `policy validate` — validate policy structure, rules, conditions, effects
- `policy eval` — evaluate a policy against a campaign, returns deny/allow/alert per stage
- Priority-sorted first-match-wins rule evaluation with conditions
- Tool inference from campaign stages: exec types → tools, telemetry → tools
- Glob matching for tools, targets (URL patterns), and conditions
- Effects: `deny` (block + exit 2), `allow` (explicit permit), `alert` (warn + continue)
- Conditions: field matching on elevated, technique, tactic, platform, exec_type
- Operators: eq, ne, in, not_in, matches (glob)
- Text report with ANSI-colored violations detail
- JSON report with verdict (pass/warn/fail) for CI/CD pipelines
- Built-in `agent-default` policy: blocks shell exec, KB writes, agent messaging, C2 domains; alerts on exfiltration

#### `export navigator` — ATT&CK Navigator Layer Export
- ATT&CK Navigator layer format v4.5 JSON output
- `export navigator` from simulation results (coverage layer)
- `export navigator -gap` from gap analysis (gap layer)
- `-output` flag to write to file instead of stdout
- Color scheme: green (detections) → yellow (detection gap) → orange (telemetry gap) → red (uncovered)
- Only ATT&CK techniques (T-prefixed); ATLAS/OWASP excluded (no Navigator representation)
- Full legend, gradient, metadata, platform filters
- Deterministic sorted output for diff-friendly layers

#### `compare` command — Gap Report Delta Analysis
- Compares two campaign directories (before/after) for coverage delta
- Shows resolved gaps, new gaps, unchanged count
- Risk score delta with direction indicator (improved/regressed/unchanged)
- Tactic coverage delta (ATT&CK and ATLAS, before→after)
- Text report with color-coded direction and gap changes
- JSON report for pipeline consumption
- Stable gap fingerprinting for reliable matching across analyses

#### `run` command — Live Campaign Execution
- Execute campaign stages live via system shell (sh -c / cmd /c)
- Process group isolation: kills child processes on timeout/cancel (Setpgid + SIGKILL to pgid)
- Safety controls: DenyElevated (default: true), stage timeout, output capping (1 MiB default)
- Stage delay support with cancellable wait
- Cleanup command execution (best-effort, runs all even if some fail)
- Non-shell types gracefully skipped (http, file, dns, etc.)
- Live progress output to stderr during execution
- Full simulation report (text/JSON) after completion
- `-deny-elevated`, `-max-output`, `-workdir` flags

### Changed
- Help text updated with all new commands (policy, export, compare, run)
- CLI refactored: shared helpers for campaign loading/simulation across commands

### Stats
- 39 Go source files, ~8,100 lines of code
- 104 tests across 10 packages, all passing
- 1 built-in policy (agent-default, 10 rules)
- 3 built-in campaigns (APT29, FIN7, LLM Agent Hijack)

## [0.0.2]

### Added

#### `gap` command — Detection Gap Analysis
- `gap` command analyzes detection coverage gaps across one or more campaigns
- Accepts single campaigns, multiple campaigns, or `-dir` to scan a directory
- ATT&CK tactic coverage analysis (14 tactics)
- ATLAS tactic coverage analysis (7 tactics)
- Framework breakdown: stages by MITRE ATT&CK vs ATLAS vs OWASP LLM
- Detection gaps: stages with expected telemetry but no detection rules
- Telemetry gaps: stages with no expected telemetry at all
- Tactic-uncovered gaps: tactics with zero stage coverage across all campaigns
- Risk scoring per gap (critical/high/medium/low) based on tactic importance
- Aggregate risk score (0-100 weighted)
- Multi-campaign aggregation with merged coverage
- `-format json` for pipeline integration
- `-format text` (default) with ANSI-colored terminal output

#### JSON report output
- `-format json` flag on `simulate` command
- Structured JSON output with campaign metadata, per-stage details, technique/tactic name resolution, and coverage summary
- Cross-framework technique name lookup (ATT&CK, ATLAS, OWASP LLM)
- Machine-readable for CI/CD pipeline consumption

#### AI Agent Campaign — `llm-agent-hijack`
- 13-stage agent hijacking campaign using MITRE ATLAS + OWASP LLM Top 10
- Kill chain: recon → payload crafting → prompt injection → system prompt extraction → jailbreak → tool policy violation → RAG poisoning → sensitive data extraction → agent-to-agent propagation → C2 via agent → classifier evasion → data exfiltration → impact verification
- 12 unique techniques: 8 ATLAS (AML.T0049, AML.T0043, AML.T0051, AML.T0056, AML.T0054, AML.T0050, AML.T0015, AML.T0042) + 4 OWASP (LLM02, LLM05, LLM06, LLM08)
- 6/7 ATLAS tactic coverage (85%)
- Agent-specific telemetry types: prompt_log, guardrail_trigger, tool_call, embedding_query, vector_store_write, inter_agent_message
- 46 unique detection rule references

#### GoReleaser
- `.goreleaser.yml` for automated cross-platform releases
- 6 build targets: linux/darwin/windows × amd64/arm64
- Archive includes campaigns, LICENSE, README, CHANGELOG
- SHA-256 checksums

### Fixed
- Deprecated `strings.Title` replaced with `unicode.ToUpper` (Go vet warning)

### Changed
- Help text updated to include `gap` command
- CLI accepts `-format` flag on `simulate` (text or json)
- Gap analysis correctly counts OWASP LLM stages under ATLAS tactic coverage

### Stats
- 26 Go source files, ~4,250 lines of code
- 58 tests across 7 packages, all passing
- 3 built-in campaigns (APT29, FIN7, LLM Agent Hijack)

## [0.0.1]

### Added

#### CLI
- `validate` command to validate campaign YAML files and directories
- `simulate` command for dry-run campaign execution with full coverage report
- `simulate -platform` flag for platform-filtered simulation (linux, windows, macos)
- `campaigns list` command to browse available campaigns with summary table
- `campaigns show` command to inspect campaign details, stages, and references
- `init` command to scaffold a new campaign workspace with example YAML
- `version` command with build metadata (version, commit, build time)
- `help` command and `-h`/`--help` flags on all subcommands
- ANSI-colored terminal output with `NO_COLOR` env var support
- Makefile with `build`, `test`, `vet`, `fmt`, `clean` targets
- Cross-compilation support: linux, windows, macOS (amd64 + arm64)

#### Campaign Engine
- YAML-based campaign schema (`api_version: v1`, `kind: Campaign`)
- Campaign metadata: name, adversary, description, objective, severity, tags, authors, references, MITRE version
- Multi-stage campaign definition with per-stage technique, tactic, platform targeting
- Stage dependencies via `depends_on` with DAG resolution (Kahn's algorithm)
- Cycle detection in stage dependency graphs
- Variable expansion (`{{var}}` syntax) across stage fields
- Execute types: `shell`, `http`, `file`, `registry`, `service`
- Execute options: commands, payload, target, args, cleanup, elevated
- Expected telemetry and detection declarations per stage
- Stage transition logic: `on_success`, `on_failure` (abort/skip/continue)
- Timeout and delay support per stage (duration parsing)
- Noop executor for dry-run simulation (describes actions without executing)
- Campaign directory scanning (`LoadDir`) for multi-campaign workspaces

#### Validation
- Required field checks: api_version, kind, meta.name, meta.adversary, meta.severity
- ATT&CK technique format validation (`T\d{4}` and `T\d{4}.\d{3}`)
- MITRE ATLAS technique format validation (`AML.T\d{4}`)
- OWASP LLM Top 10 technique format validation (`LLM\d{2}`)
- Tactic validation against ATT&CK (14 tactics) and ATLAS (7 tactics) registries
- Duplicate stage ID detection
- Dependency cross-reference validation (unknown stage references)
- Dependency cycle detection with descriptive error messages
- Severity validation (critical, high, medium, low)
- Execute type validation (shell, http, file, registry, service)
- Platform validation (linux, windows, macos)

#### Framework Support
- **MITRE ATT&CK**: 14 tactics, 60+ techniques with ID-to-name lookup
- **MITRE ATLAS**: 7 tactics (reconnaissance through impact), 16 adversarial ML techniques
- **OWASP LLM Top 10 (2025)**: 10 entries (LLM01 through LLM10) with full descriptions
- Tactic-to-short-name mapping for both ATT&CK and ATLAS
- Technique lookup functions for ATT&CK (`LookupTechnique`), ATLAS (`LookupATLASTechnique`), OWASP (`LookupOWASPLLM`)
- Tactic validation functions for both ATT&CK (`ValidTactic`) and ATLAS (`ValidATLASTactic`)

#### Reporting
- Text-based simulation report with ANSI colors
- Campaign summary header (name, adversary, objective, severity, stage/technique/tactic counts)
- Per-stage detail: technique name, tactic name, dependencies, execute type, telemetry, detections, transitions
- Tactic coverage matrix (covered vs missing, 3-column layout)
- Coverage statistics: unique techniques, telemetry types, detection rules referenced, stages completed/skipped
- Platform-filtered stage skip reporting with reason
- Severity color coding (critical=red+bold, high=red, medium=yellow, low=green)

#### Built-in Campaigns
- **APT29 Cozy Bear**: 8-stage kill chain (spearphishing, C2 beacon, domain recon, credential dumping, lateral movement, data collection, defense evasion, exfiltration). 8 techniques, 8/14 tactics, critical severity.
- **FIN7 Carbanak**: 10-stage financial crime campaign (spearphish document, PowerShell payload, C2 establish, internal recon, credential harvest, lateral POS movement, POS scraper, data staging, scheduled task persistence, exfiltration). 10 techniques, 9/14 tactics, Windows-only, critical severity.

#### Testing
- 43 tests across 5 packages, all passing
- Campaign loader tests (7): file loading, directory loading, variable expansion, error handling
- Validator tests (16): required fields, technique formats (ATT&CK/ATLAS/OWASP), tactic validation, duplicate IDs, cycle detection, dependency validation, severity, execute type, platform
- Graph tests (7): topological sort, cycle detection, single stage, linear chains, diamond dependencies
- Engine tests (5): simulation, platform filtering, stage skipping
- MITRE tests (7): technique lookup, tactic validation, tactic-to-short mapping
- Version tests (2): string format, default values
- Test fixtures: `testdata/valid-campaign/campaign.yaml`

#### CI/CD
- GitHub Actions workflow (`.github/workflows/ci.yml`)
- Test job: `go vet` + `go test -race`
- Build job: cross-compilation matrix (linux/windows/darwin x amd64/arm64)
- Triggered on push and pull request to main

#### Documentation
- README with install instructions, quick start, campaign schema example, feature list, command table, campaign table, project structure
- AGPL-3.0 license
- This changelog

### Technical Details
- Pure Go, single external dependency (`gopkg.in/yaml.v3`)
- Single binary output, no runtime dependencies
- ~1,400 lines of code across 12 Go source files
- Build version injection via ldflags (`-X pkg/version.Version=...`)
