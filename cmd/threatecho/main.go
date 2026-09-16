// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ThreatEcho/threatecho/internal/agent"
	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/cli"
	"github.com/ThreatEcho/threatecho/internal/compliance"
	"github.com/ThreatEcho/threatecho/internal/config"
	"github.com/ThreatEcho/threatecho/internal/engine"
	"github.com/ThreatEcho/threatecho/internal/executor"
	"github.com/ThreatEcho/threatecho/internal/gap"
	"github.com/ThreatEcho/threatecho/internal/matrix"
	"github.com/ThreatEcho/threatecho/internal/navigator"
	"github.com/ThreatEcho/threatecho/internal/orchestrator"
	"github.com/ThreatEcho/threatecho/internal/policy"
	"github.com/ThreatEcho/threatecho/internal/report"
	"github.com/ThreatEcho/threatecho/internal/sigma"
	"github.com/ThreatEcho/threatecho/internal/telemetry"
	"github.com/ThreatEcho/threatecho/internal/trace"
	"github.com/ThreatEcho/threatecho/pkg/version"
)

// cfg is the resolved configuration loaded at startup from
// system → user → project → environment sources. CLI flags
// override these defaults per-command.
var cfg *config.Config
var helpRequested bool

func main() {
	// Load layered config before dispatch. A parse error in an
	// existing config file is fatal; missing files are fine.
	var err error
	cfg, err = config.Load()
	if err != nil {
		cli.Die(cli.RuntimeWrap(err, "loading config"))
		os.Exit(cli.DieCode(cli.RuntimeWrap(err, "loading config")))
	}

	// Honour NO_COLOR from config and environment.
	if cfg.NoColor || os.Getenv("NO_COLOR") != "" {
		cfg.NoColor = true
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(cli.ExitUsage)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "validate":
		cmdValidate(args)
	case "simulate":
		cmdSimulate(args)
	case "gap":
		cmdGap(args)
	case "lint":
		cmdLint(args)
	case "policy":
		cmdPolicy(args)
	case "export":
		cmdExport(args)
	case "compare":
		cmdCompare(args)
	case "run":
		cmdRun(args)
	case "summary":
		cmdSummary(args)
	case "matrix":
		cmdMatrix(args)
	case "coverage":
		cmdCoverage(args)
	case "campaigns":
		cmdCampaigns(args)
	case "config":
		cmdConfig(args)
	case "hash":
		cmdHash(args)
	case "graph":
		cmdGraph(args)
	case "fmt":
		cmdFmt(args)
	case "doctor":
		cmdDoctor(args)
	case "telemetry":
		cmdTelemetry(args)
	case "diff":
		cmdDiff(args)
	case "merge":
		cmdMerge(args)
	case "search":
		cmdSearch(args)
	case "stats":
		cmdStats(args)
	case "import":
		cmdImport(args)
	case "enrich":
		cmdEnrich(args)
	case "score":
		cmdScore(args)
	case "convert":
		cmdConvert(args)
	case "tag":
		cmdTag(args)
	case "report":
		cmdReport(args)
	case "audit":
		cmdAudit(args)
	case "baseline":
		cmdBaseline(args)
	case "trace":
		cmdTrace(args)
	case "agent":
		cmdAgent(args)
	case "scenario":
		cmdScenario(args)
	case "threat-model":
		cmdThreatModel(args)
	case "risk-posture":
		cmdRiskPosture(args)
	case "compliance":
		cmdCompliance(args)
	case "dashboard":
		cmdDashboard(args)
	case "deploy":
		cmdDeploy(args)
	case "deploy-baseline":
		cmdDeployBaseline(args)
	case "attack-tree":
		cmdAttackTree(args)
	case "completion":
		cmdCompletion(args)
	case "profile":
		cmdProfile(args)
	case "watch":
		cmdWatch(args)
	case "template":
		cmdTemplate(args)
	case "timeline":
		cmdTimeline(args)
	case "env":
		cmdEnv(args)
	case "init":
		cmdInit(args)
	case "version", "--version", "-v":
		fmt.Println(version.String())
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(cli.ExitUsage)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `ThreatEcho — Adversary Campaign Simulation Engine

Usage:
  threatecho <command> [flags] [args]

Execution:
  simulate        Dry-run a campaign (no execution)
  run             Execute a campaign live (shell stages only)
  deploy          Deploy a campaign to remote targets (SSH/WinRM, agentless or agent)
  deploy-baseline Capture and diff deployment posture snapshots

Campaign Management:
  validate    Validate a campaign file or directory
  lint        Run quality checks beyond structural validation
  fmt         Canonically format campaign YAML files
  campaigns   List and inspect campaigns
  diff        Compare two campaign files (structural diff)
  merge       Combine multiple campaigns into one
  search      Search campaigns by technique, tactic, adversary, keyword
  import      Import Atomic Red Team tests as ThreatEcho campaigns
  convert     Convert campaigns between formats (JSON, Markdown, CSV)
  template    List and generate campaign scaffolds from built-in templates

Analysis:
  gap         Analyze detection coverage gaps across campaigns
  compare     Compare detection coverage between two campaign sets (before/after delta)
  matrix      Display ATT&CK technique coverage matrix
  coverage    Technique-level coverage analysis
  score       Campaign risk and complexity scoring
  enrich      Enrich campaign stages with ATT&CK metadata
  graph       Campaign dependency graph analysis and export
  profile     Campaign complexity profile and metrics
  timeline    Estimate campaign execution time from DAG structure
  tag         Tag management and suggestions across campaigns

Risk & Compliance:
  policy      Validate or evaluate agent tool-call policies
  summary     Security posture dashboard across all campaigns
  report      Generate executive assessment reports
  compliance  Map to compliance frameworks (NIST CSF, 800-53, CIS, AI RMF, OWASP LLM, ATLAS)
  risk-posture Unified risk assessment across all analysis dimensions
  threat-model Generate STRIDE threat models for agent deployments
  attack-tree Build attack trees from agent inventory with probability analysis
  dashboard   Generate HTML security assessment dashboard

Agent:
  agent       Agent inventory, trust, attestation, and capability mapping
  scenario    Generate and analyze agent execution traces from campaigns
  trace       Agent execution trace analysis and anomaly replay
  baseline    Behavioral baseline and drift detection

Workspace:
  init        Initialize a new campaign workspace
  config      Show or initialize project configuration
  doctor      Workspace health check (campaigns, policies, config)
  stats       Project-wide campaign analytics dashboard
  export      Export to ATT&CK Navigator or Sigma rule scaffolds
  audit       Campaign state snapshot and change tracking
  hash        Campaign content fingerprinting (SHA256)
  telemetry   Inspect the telemetry type registry
  env         Show environment variable references in campaigns
  watch       Watch campaign files for changes (live re-validation)
  completion  Generate shell completion scripts (bash/zsh/fish)
  version     Print version information
  help        Show this help

Exit codes (for CI integration):
  0   Success
  1   Validation error (campaign/policy YAML invalid)
  2   Policy denied (risk/compliance violations found)
  3   Runtime error (execution or processing failure)
  4   I/O error (file read/write failure)
  64  Usage error (bad arguments, unknown command)

Run 'threatecho <command> -h' for command-specific help.
`)
}

// --- exit helpers ---
// These replace the previous raw fmt.Fprintf+os.Exit(1) pattern
// with typed exit codes for CI pipeline integration.

func exitErr(err *cli.Error) {
	cli.Die(err)
	os.Exit(err.Code)
}

func exitValidation(msg string, args ...interface{}) {
	exitErr(cli.Validation(msg, args...))
}

func exitIO(msg string, args ...interface{}) {
	exitErr(cli.IOError(msg, args...))
}

func exitRuntime(msg string, args ...interface{}) {
	exitErr(cli.Runtime(msg, args...))
}

func exitUsage() {
	if helpRequested {
		os.Exit(0)
	}
	os.Exit(cli.ExitUsage)
}

func splitHostPort(target string, flagPort int) (string, int) {
	if i := strings.LastIndex(target, ":"); i > 0 {
		if p, err := strconv.Atoi(target[i+1:]); err == nil && p > 0 && p <= 65535 {
			if flagPort == 0 {
				return target[:i], p
			}
			return target[:i], flagPort
		}
	}
	return target, flagPort
}

func checkFormat(format string, allowed ...string) {
	for _, a := range allowed {
		if format == a {
			return
		}
	}
	fmt.Fprintf(os.Stderr, "unknown output format: %s\nValid formats: %s\n", format, strings.Join(allowed, ", "))
	exitUsage()
}

// resolveFormat returns the format flag value, falling back to config default.
func resolveFormat(flagVal string) string {
	if flagVal != "" && flagVal != "text" {
		return flagVal
	}
	// If the flag wasn't explicitly changed from default, use config.
	if cfg.DefaultFormat != "" && cfg.DefaultFormat != "text" && flagVal == "text" {
		return cfg.DefaultFormat
	}
	return flagVal
}

// resolveCampaignDir returns the dir flag value, falling back to config and auto-detection.
func resolveCampaignDir(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if cfg.CampaignsDir != "" && cfg.CampaignsDir != "campaigns" {
		return cfg.CampaignsDir
	}
	return findCampaignDir()
}

// --- validate ---

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho validate <campaign-path>

Validate a campaign YAML file or directory.

Examples:
  threatecho validate campaigns/apt29/
  threatecho validate campaigns/apt29/campaign.yaml
`)
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	path := fs.Arg(0)
	c, err := campaign.Load(path)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign"))
	}

	errs := campaign.Validate(c)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(c.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	techniques := c.UniqueTechniques()
	tactics := c.UniqueTactics()
	fmt.Printf("✓ Campaign %q is valid (%d stages, %d techniques, %d/%d tactics)\n",
		c.Meta.Name, len(c.Stages), len(techniques), len(tactics), 14)
}

// --- lint ---

func cmdLint(args []string) {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	dir := fs.String("dir", "", "scan a directory for all campaigns")
	format := fs.String("format", "text", "output format: text, json")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho lint [flags] <campaign-path> [campaign-path...]

Run quality checks beyond structural validation. Lint checks for:
  - Technique IDs not found in the registry
  - Framework/tactic mismatches
  - Missing telemetry or detections
  - Empty shell commands, HTTP stages without targets
  - Incomplete metadata

Lint produces warnings and informational notes — not hard errors.
Exit code 0 = clean, 1 = warnings found.

Examples:
  threatecho lint campaigns/apt29-cozy-bear/
  threatecho lint -dir campaigns/
  threatecho lint -format json campaigns/llm-agent-hijack/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	paths := collectCampaignPaths(fs, *dir)
	outFmt := resolveFormat(*format)

	type lintOutput struct {
		Campaign string   `json:"campaign"`
		Warnings []string `json:"warnings"`
		Info     []string `json:"info"`
	}

	var allResults []lintOutput
	hasWarnings := false

	for _, path := range paths {
		c, err := campaign.Load(path)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading %s", path))
		}

		lr := campaign.Lint(c)
		allResults = append(allResults, lintOutput{
			Campaign: lr.Campaign,
			Warnings: lr.Warnings,
			Info:     lr.Info,
		})

		if lr.HasIssues() {
			hasWarnings = true
		}

		if outFmt == "text" {
			if lr.Total() == 0 {
				fmt.Printf("✓ %s — clean\n", lr.Campaign)
				continue
			}
			fmt.Printf("⚠ %s — %d warning(s), %d info\n", lr.Campaign, len(lr.Warnings), len(lr.Info))
			for _, w := range lr.Warnings {
				fmt.Printf("  ⚠ %s\n", w)
			}
			for _, info := range lr.Info {
				fmt.Printf("  ℹ %s\n", info)
			}
		}
	}

	if outFmt == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(allResults); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
	}

	if hasWarnings {
		os.Exit(cli.ExitValidation)
	}
}

// --- simulate ---

func cmdSimulate(args []string) {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	platform := fs.String("platform", "", "filter stages by platform (windows, linux, macos)")
	format := fs.String("format", "text", "output format: text, json")
	quiet := fs.Bool("quiet", false, "suppress text output (exit code only); JSON output still emitted with -format json")
	fs.BoolVar(quiet, "q", false, "suppress text output (shorthand for -quiet)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho simulate [flags] <campaign-path>

Dry-run a campaign without executing anything. Shows the execution plan,
technique mappings, and detection expectations.

Examples:
  threatecho simulate campaigns/apt29/
  threatecho simulate -platform windows campaigns/apt29/
  threatecho simulate -format json campaigns/apt29/
  threatecho simulate -q -format json campaigns/apt29/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	outFmt := resolveFormat(*format)
	checkFormat(outFmt, "text", "json")

	path := fs.Arg(0)
	c, err := campaign.Load(path)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign"))
	}

	errs := campaign.Validate(c)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(c.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	opts := engine.Options{
		Platform: *platform,
		DryRun:   true,
	}

	result, err := engine.Simulate(context.Background(), c, opts)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "simulation failed"))
	}

	switch outFmt {
	case "json":
		if err := report.JSONReportWrite(os.Stdout, result); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
	default:
		if !*quiet {
			report.TextReport(os.Stdout, result)
		}
	}
}

// --- gap ---

func cmdGap(args []string) {
	fs := flag.NewFlagSet("gap", flag.ExitOnError)
	platform := fs.String("platform", "", "filter stages by platform (windows, linux, macos)")
	format := fs.String("format", "text", "output format: text, json, sarif, junit, html, md")
	dir := fs.String("dir", "", "scan a directory for all campaigns (overrides positional args)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho gap [flags] <campaign-path> [campaign-path...]

Analyze detection coverage gaps across one or more campaigns.
Produces a risk-scored gap report showing missing detections,
uncovered tactics, and telemetry blind spots.

Output formats:
  text     Human-readable ANSI report (default)
  json     Machine-readable JSON
  sarif    SARIF v2.1.0 (GitHub Code Scanning, VS Code)
  junit    JUnit XML (Jenkins, GitHub Actions, GitLab CI)
  html     Self-contained HTML report (shareable, print-friendly)
  md       GitHub-Flavored Markdown (wikis, READMEs, docs)

Examples:
  threatecho gap campaigns/apt29-cozy-bear/
  threatecho gap -dir campaigns/ -format sarif
  threatecho gap -format html -dir campaigns/ > coverage.html

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	paths := collectCampaignPaths(fs, *dir)
	results := simulateCampaigns(paths, *platform)

	outFmt := resolveFormat(*format)
	checkFormat(outFmt, "text", "json", "sarif", "junit", "html", "md")

	// Analyze gaps.
	gapReport := gap.Analyze(results...)

	// Derive campaign file for SARIF location.
	campaignFile := ""
	if len(paths) == 1 {
		campaignFile = paths[0]
	}

	switch outFmt {
	case "json":
		if err := report.GapJSONReport(os.Stdout, gapReport); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
	case "sarif":
		if err := report.GapSARIFReport(os.Stdout, gapReport, campaignFile); err != nil {
			exitRuntime("SARIF output failed: %s", err)
		}
	case "junit":
		if err := report.GapJUnitReport(os.Stdout, gapReport); err != nil {
			exitRuntime("JUnit output failed: %s", err)
		}
	case "html":
		if err := report.GapHTMLReport(os.Stdout, gapReport); err != nil {
			exitRuntime("HTML output failed: %s", err)
		}
	case "md", "markdown":
		if err := report.GapMarkdownReport(os.Stdout, gapReport); err != nil {
			exitRuntime("Markdown output failed: %s", err)
		}
	default:
		report.GapTextReport(os.Stdout, gapReport)
	}
}

// --- campaigns ---

func cmdCampaigns(args []string) {
	fs := flag.NewFlagSet("campaigns", flag.ExitOnError)
	dir := fs.String("dir", "", "campaigns directory (default: from config or auto-detected)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho campaigns [list|show] [flags]

Browse available campaigns.

Subcommands:
  list    List all campaigns (default)
  show    Show campaign details

Examples:
  threatecho campaigns list
  threatecho campaigns list -dir ./my-campaigns
  threatecho campaigns show apt29

Flags:
`)
		fs.PrintDefaults()
	}

	subcmd := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		subcmd = args[0]
		args = args[1:]
	}
	fs.Parse(args)

	campaignDir := resolveCampaignDir(*dir)

	switch subcmd {
	case "list":
		campaignsList(campaignDir)
	case "show":
		if fs.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "Usage: threatecho campaigns show <name-or-path>\n")
			exitUsage()
		}
		campaignsShow(campaignDir, fs.Arg(0))
	case "-h", "--help", "help":
		fmt.Fprintf(os.Stderr, "Usage: threatecho campaigns <subcommand> [flags]\n\nSubcommands: list, show\n")
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown campaigns subcommand: %s\nValid subcommands: list, show\n", subcmd)
		exitUsage()
	}
}

func campaignsList(dir string) {
	summaries, err := campaign.LoadDir(dir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaigns"))
	}
	if len(summaries) == 0 {
		fmt.Println("No campaigns found in", dir)
		return
	}

	fmt.Printf("%-28s %-12s %-8s %-6s %-10s %s\n", "NAME", "ADVERSARY", "SEVERITY", "STAGES", "TECHNIQUES", "PATH")
	fmt.Println(strings.Repeat("─", 90))
	for _, s := range summaries {
		fmt.Printf("%-28s %-12s %-8s %-6d %-10d %s\n",
			s.Name, s.Adversary, s.Severity, s.Stages, s.Techniques, s.Path)
	}
}

func campaignsShow(dir, nameOrPath string) {
	// Try as path first.
	path := nameOrPath
	if _, err := os.Stat(path); err != nil {
		// Try as name within campaign dir.
		path = filepath.Join(dir, nameOrPath)
		if _, err := os.Stat(path); err != nil {
			exitErr(cli.IOError("campaign not found: %s", nameOrPath))
		}
	}

	c, err := campaign.Load(path)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign"))
	}

	fmt.Printf("Campaign: %s\n", c.Meta.Name)
	fmt.Printf("Adversary: %s\n", c.Meta.Adversary)
	fmt.Printf("Description: %s\n", c.Meta.Description)
	fmt.Printf("Objective: %s\n", c.Meta.Objective)
	fmt.Printf("Severity: %s\n", c.Meta.Severity)
	fmt.Printf("MITRE ATT&CK: v%s\n", c.Meta.MitreVersion)
	if len(c.Meta.Tags) > 0 {
		fmt.Printf("Tags: %s\n", strings.Join(c.Meta.Tags, ", "))
	}
	fmt.Printf("Stages: %d\n", len(c.Stages))
	fmt.Printf("Techniques: %d unique\n", len(c.UniqueTechniques()))
	fmt.Printf("Tactics: %d/14\n", len(c.UniqueTactics()))
	fmt.Println()
	fmt.Println("Stages:")
	for i, s := range c.Stages {
		fmt.Printf("  %d. [%s] %s — %s (%s)\n", i+1, s.Tactic, s.ID, s.Name, s.Technique)
	}
	if len(c.Meta.References) > 0 {
		fmt.Println("\nReferences:")
		for _, r := range c.Meta.References {
			fmt.Printf("  - %s\n", r)
		}
	}
}

// --- config ---

func cmdConfig(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: threatecho config <subcommand>

Subcommands:
  show    Display resolved configuration (merged from all sources)
  path    Show config file search paths
  init    Create a .threatecho.yaml project config template

Examples:
  threatecho config show
  threatecho config path
  threatecho config init
`)
		exitUsage()
	}

	subcmd := args[0]
	switch subcmd {
	case "show":
		cmdConfigShow()
	case "path":
		cmdConfigPath()
	case "init":
		cmdConfigInit(args[1:])
	case "-h", "--help", "help":
		helpRequested = true
		cmdConfig(nil)
	default:
		fmt.Fprintf(os.Stderr, "unknown config subcommand: %s\nValid subcommands: show, path, init\n", subcmd)
		exitUsage()
	}
}

func cmdConfigShow() {
	fmt.Println("# ThreatEcho — Resolved Configuration")
	fmt.Println("# Merged from: defaults → system → user → project → environment")
	fmt.Println()
	fmt.Print(cfg.String())
}

func cmdConfigPath() {
	fmt.Println("Config file search paths (higher priority = later):")
	fmt.Println()
	fmt.Println("  1. Built-in defaults")

	fmt.Printf("  2. System:  /etc/threatecho/config.yaml")
	if _, err := os.Stat("/etc/threatecho/config.yaml"); err == nil {
		fmt.Print("  ← found")
	}
	fmt.Println()

	if userDir, err := os.UserConfigDir(); err == nil {
		userPath := filepath.Join(userDir, "threatecho", "config.yaml")
		fmt.Printf("  3. User:    %s", userPath)
		if _, err := os.Stat(userPath); err == nil {
			fmt.Print("  ← found")
		}
		fmt.Println()
	}

	projPath := config.FindProjectConfig()
	if projPath != "" {
		fmt.Printf("  4. Project: %s  ← found\n", projPath)
	} else {
		fmt.Println("  4. Project: .threatecho.yaml (not found, walks up from cwd)")
	}

	fmt.Println("  5. Environment: THREATECHO_* variables")
	for _, key := range config.EnvKeys() {
		if v := os.Getenv(key); v != "" {
			fmt.Printf("     %s=%s\n", key, v)
		}
	}
	fmt.Println("  6. CLI flags (applied per-command)")
}

func cmdConfigInit(args []string) {
	fs := flag.NewFlagSet("config init", flag.ExitOnError)
	fs.Parse(args)

	path := ".threatecho.yaml"
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "✗ %s already exists\n", path)
		os.Exit(cli.ExitValidation)
	}

	template := `# ThreatEcho project configuration
# Docs: threatecho config show
#
# Values here override user and system config.
# CLI flags override everything.

campaigns_dir: campaigns
policies_dir: policies
default_format: text
# default_policy: policies/agent-default/
author: ThreatEcho
# no_color: false

# output:
#   sarif_category: threatecho
#   junit_suite: ThreatEcho
`
	if err := os.WriteFile(path, []byte(template), 0o644); err != nil {
		exitErr(cli.IOWrap(err, "writing %s", path))
	}
	fmt.Printf("✓ Created %s\n", path)
}

// --- hash ---

func cmdHash(args []string) {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	dir := fs.String("dir", "", "hash all campaigns in directory")
	manifest := fs.Bool("manifest", false, "output single manifest hash for the directory")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho hash [flags] [campaign-path...]

Compute SHA256 content fingerprints for campaigns.
Fingerprints are deterministic: same content = same hash,
regardless of field ordering or whitespace.

Use for:
  - CI cache keys (--manifest for a single directory hash)
  - Change detection across versions
  - Reproducibility verification

Examples:
  threatecho hash campaigns/apt29-cozy-bear/
  threatecho hash -dir campaigns/
  threatecho hash -dir campaigns/ -manifest

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *dir != "" {
		if *manifest {
			hash, err := campaign.FingerprintManifest(*dir)
			if err != nil {
				exitErr(cli.IOWrap(err, "fingerprinting directory"))
			}
			fmt.Println(hash)
			return
		}

		hashes, err := campaign.FingerprintDir(*dir)
		if err != nil {
			exitErr(cli.IOWrap(err, "fingerprinting directory"))
		}
		// Sort names for deterministic output.
		names := make([]string, 0, len(hashes))
		for name := range hashes {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Printf("%s  %s\n", hashes[name], name)
		}
		return
	}

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	for i := 0; i < fs.NArg(); i++ {
		path := fs.Arg(i)
		hash, err := campaign.FingerprintFile(path)
		if err != nil {
			exitErr(cli.IOWrap(err, "fingerprinting %s", path))
		}
		fmt.Printf("%s  %s\n", hash, path)
	}
}

// --- graph ---

func cmdGraph(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: threatecho graph <subcommand> [flags] <campaign-path>

Subcommands:
  analyze   Show dependency graph analysis (entry points, depth, critical path)
  dot       Export Graphviz DOT representation
  mermaid   Export Mermaid diagram

Examples:
  threatecho graph analyze campaigns/apt29-cozy-bear/
  threatecho graph dot campaigns/apt29-cozy-bear/ > campaign.dot
  threatecho graph mermaid campaigns/apt29-cozy-bear/
`)
		exitUsage()
	}

	subcmd := args[0]
	args = args[1:]

	switch subcmd {
	case "analyze":
		cmdGraphAnalyze(args)
	case "dot":
		cmdGraphDOT(args)
	case "mermaid":
		cmdGraphMermaid(args)
	case "-h", "--help", "help":
		helpRequested = true
		cmdGraph(nil)
	default:
		fmt.Fprintf(os.Stderr, "unknown graph subcommand: %s\nValid subcommands: analyze, dot, mermaid\n", subcmd)
		exitUsage()
	}
}

func loadCampaignForGraph(args []string, cmd string) *campaign.Campaign {
	fs := flag.NewFlagSet("graph "+cmd, flag.ExitOnError)
	descs := map[string]string{
		"analyze": "Dependency graph analysis showing entry points, terminal stages,\ncritical path, parallel execution levels, and structural warnings.",
		"dot":     "Export campaign dependency graph as Graphviz DOT diagram.",
		"mermaid": "Export campaign dependency graph as Mermaid diagram (GitHub rendering).",
	}
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: threatecho graph %s <campaign-path>\n\n%s\n\nExamples:\n  threatecho graph %s campaigns/apt29-cozy-bear/\n", cmd, descs[cmd], cmd)
	}
	fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}
	c, err := campaign.Load(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign"))
	}
	return c
}

func cmdGraphAnalyze(args []string) {
	c := loadCampaignForGraph(args, "analyze")
	ga := campaign.AnalyzeGraph(c)

	fmt.Printf("Campaign: %s\n", c.Meta.Name)
	fmt.Printf("Stages: %d  Edges: %d  Max depth: %d\n", ga.StageCount, ga.EdgeCount, ga.MaxDepth)
	fmt.Println()

	fmt.Printf("Entry points (%d):  %s\n", len(ga.EntryPoints), strings.Join(ga.EntryPoints, ", "))
	fmt.Printf("Terminal stages (%d): %s\n", len(ga.TerminalStages), strings.Join(ga.TerminalStages, ", "))
	fmt.Printf("Critical path: %s\n", strings.Join(ga.CriticalPath, " → "))

	if len(ga.Parallel) > 0 {
		fmt.Println("\nParallel execution levels:")
		for i, level := range ga.Parallel {
			fmt.Printf("  Level %d: %s\n", i, strings.Join(level, ", "))
		}
	}

	if len(ga.Unreachable) > 0 {
		fmt.Printf("\n⚠ Unreachable stages: %s\n", strings.Join(ga.Unreachable, ", "))
	}
	if len(ga.OrphanDeps) > 0 {
		fmt.Printf("⚠ Orphan dependencies: %s\n", strings.Join(ga.OrphanDeps, ", "))
	}
	if len(ga.DeadTransitions) > 0 {
		fmt.Println("⚠ Dead transitions:")
		for _, dt := range ga.DeadTransitions {
			fmt.Printf("  %s.%s → %q (not found)\n", dt.StageID, dt.Field, dt.Target)
		}
	}
	if ga.HasCycles {
		fmt.Println("⚠ Dependency cycle detected")
	}
}

func cmdGraphDOT(args []string) {
	c := loadCampaignForGraph(args, "dot")
	fmt.Print(campaign.GraphDOT(c))
}

func cmdGraphMermaid(args []string) {
	c := loadCampaignForGraph(args, "mermaid")
	fmt.Print(campaign.GraphMermaid(c))
}

// --- fmt ---

func cmdFmt(args []string) {
	fs := flag.NewFlagSet("fmt", flag.ExitOnError)
	write := fs.Bool("w", false, "write result to (source) file instead of stdout")
	dir := fs.String("dir", "", "format all campaigns in directory")
	normalize := fs.Bool("normalize", false, "also normalize stage order (topological/alphabetical)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho fmt [flags] [campaign-path...]

Canonically format campaign YAML files. Without -w, prints the
formatted output to stdout. With -w, overwrites the source file.

Canonical formatting:
  - Fields in standard order (api_version, kind, meta, variables, stages)
  - Empty fields omitted
  - Consistent 2-space indentation
  - With -normalize: stages sorted topologically, telemetry/detections sorted

Examples:
  threatecho fmt campaigns/apt29-cozy-bear/
  threatecho fmt -w campaigns/apt29-cozy-bear/
  threatecho fmt -w -dir campaigns/
  threatecho fmt -normalize -w campaigns/apt29-cozy-bear/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	var paths []string
	if *dir != "" {
		summaries, err := campaign.LoadDir(*dir)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading campaigns"))
		}
		for _, s := range summaries {
			paths = append(paths, s.Path)
		}
	} else {
		if fs.NArg() < 1 {
			fs.Usage()
			exitUsage()
		}
		for i := 0; i < fs.NArg(); i++ {
			paths = append(paths, fs.Arg(i))
		}
	}

	for _, path := range paths {
		if *normalize {
			// Load, normalize, then format.
			c, err := campaign.Load(path)
			if err != nil {
				exitErr(cli.IOWrap(err, "loading %s", path))
			}
			c = campaign.Normalize(c)
			data, err := campaign.Format(c)
			if err != nil {
				exitRuntime("formatting %s: %s", path, err)
			}
			if *write {
				// Determine the actual file to write.
				fpath := path
				info, err := os.Stat(path)
				if err == nil && info.IsDir() {
					fpath = filepath.Join(path, "campaign.yaml")
				}
				if err := os.WriteFile(fpath, data, 0o644); err != nil {
					exitErr(cli.IOWrap(err, "writing %s", fpath))
				}
				fmt.Fprintf(os.Stderr, "✓ %s\n", fpath)
			} else {
				os.Stdout.Write(data)
			}
		} else if *write {
			if err := campaign.FormatFileInPlace(path); err != nil {
				exitErr(cli.IOWrap(err, "formatting %s", path))
			}
			fmt.Fprintf(os.Stderr, "✓ %s\n", path)
		} else {
			data, err := campaign.FormatFile(path)
			if err != nil {
				exitErr(cli.IOWrap(err, "formatting %s", path))
			}
			os.Stdout.Write(data)
		}
	}
}

// --- doctor ---

func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	dir := fs.String("dir", "", "campaigns directory (default: from config or auto-detected)")
	policyDir := fs.String("policy", "", "policies directory (default: from config)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho doctor [flags]

Perform a comprehensive workspace health check:
  - Config file detection and validation
  - Campaign validation and lint
  - Policy validation
  - Agent inventory validation and trust analysis
  - Telemetry type coverage
  - Graph integrity (cycles, orphans, unreachable stages)

Examples:
  threatecho doctor
  threatecho doctor -dir campaigns/ -policy policies/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	campaignDir := resolveCampaignDir(*dir)
	polDir := *policyDir
	if polDir == "" {
		polDir = cfg.PoliciesDir
	}

	issues := 0
	warnings := 0

	fmt.Printf("ThreatEcho Doctor — Workspace Health Check (%s)\n", version.String())
	fmt.Println(strings.Repeat("─", 50))

	// 1. Config check.
	fmt.Print("\n🔧 Configuration\n")
	projConfig := config.FindProjectConfig()
	if projConfig != "" {
		fmt.Printf("  ✓ Project config found: %s\n", projConfig)
	} else {
		fmt.Println("  ℹ No project config (.threatecho.yaml) — using defaults")
	}

	// 2. Campaign directory check.
	fmt.Print("\n📁 Campaigns\n")
	summaries, err := campaign.LoadDir(campaignDir)
	if err != nil {
		fmt.Printf("  ✗ Cannot read campaign directory %s: %v\n", campaignDir, err)
		issues++
	} else if len(summaries) == 0 {
		fmt.Printf("  ✗ No campaigns found in %s\n", campaignDir)
		issues++
	} else {
		fmt.Printf("  ✓ Found %d campaigns in %s\n", len(summaries), campaignDir)

		// Validate and lint each campaign.
		for _, s := range summaries {
			c, err := campaign.Load(s.Path)
			if err != nil {
				fmt.Printf("  ✗ %s — load error: %v\n", s.Name, err)
				issues++
				continue
			}

			errs := campaign.Validate(c)
			if len(errs) > 0 {
				fmt.Printf("  ✗ %s — %d validation error(s)\n", c.Meta.Name, len(errs))
				for _, e := range errs {
					fmt.Printf("    • %s\n", e)
				}
				issues++
				continue
			}

			lr := campaign.Lint(c)
			if lr.HasIssues() {
				fmt.Printf("  ⚠ %s — %d lint warning(s)\n", c.Meta.Name, len(lr.Warnings))
				warnings++
			} else {
				fmt.Printf("  ✓ %s — valid, lint clean\n", c.Meta.Name)
			}

			// Graph integrity check.
			ga := campaign.AnalyzeGraph(c)
			if ga.HasCycles {
				fmt.Printf("    ✗ dependency cycle detected\n")
				issues++
			}
			if len(ga.OrphanDeps) > 0 {
				fmt.Printf("    ⚠ orphan dependencies: %s\n", strings.Join(ga.OrphanDeps, ", "))
				warnings++
			}
			if len(ga.DeadTransitions) > 0 {
				for _, dt := range ga.DeadTransitions {
					fmt.Printf("    ⚠ dead transition: %s.%s → %q\n", dt.StageID, dt.Field, dt.Target)
				}
				warnings++
			}
			if len(ga.Unreachable) > 0 {
				fmt.Printf("    ⚠ unreachable stages: %s\n", strings.Join(ga.Unreachable, ", "))
				warnings++
			}
		}
	}

	// 3. Policy check.
	fmt.Print("\n🛡️  Policies\n")
	if _, err := os.Stat(polDir); err != nil {
		fmt.Printf("  ℹ No policies directory at %s\n", polDir)
	} else {
		entries, err := os.ReadDir(polDir)
		if err != nil {
			fmt.Printf("  ✗ Cannot read policies directory: %v\n", err)
			issues++
		} else {
			polCount := 0
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				polPath := filepath.Join(polDir, entry.Name())
				p, err := policy.LoadPolicy(polPath)
				if err != nil {
					fmt.Printf("  ✗ %s — load error: %v\n", entry.Name(), err)
					issues++
					continue
				}
				errs := policy.ValidatePolicy(p)
				if len(errs) > 0 {
					fmt.Printf("  ✗ %s — %d validation error(s)\n", p.Meta.Name, len(errs))
					issues++
				} else {
					fmt.Printf("  ✓ %s — valid (%d rules)\n", p.Meta.Name, len(p.Rules))
				}
				polCount++
			}
			if polCount == 0 {
				fmt.Println("  ℹ No policies found")
			}
		}
	}

	// 4. Telemetry coverage.
	fmt.Print("\n📊 Telemetry Registry\n")
	allTypes := telemetry.All()
	fmt.Printf("  %d registered types across %d categories\n", len(allTypes), len(telemetry.Categories()))

	// Check campaign telemetry coverage.
	if len(summaries) > 0 {
		usedTypes := make(map[string]bool)
		for _, s := range summaries {
			c, err := campaign.Load(s.Path)
			if err != nil {
				continue
			}
			for _, t := range c.AllTelemetryTypes() {
				usedTypes[t] = true
			}
		}
		registeredUsed := 0
		for t := range usedTypes {
			if telemetry.Valid(t) {
				registeredUsed++
			}
		}
		fmt.Printf("  %d/%d types used by campaigns (%d%% registry utilization)\n",
			registeredUsed, len(allTypes), registeredUsed*100/len(allTypes))
	}

	// 5. Agent inventory check.
	fmt.Print("\n🤖 Agent Inventory\n")
	agentDir := findAgentDir()
	if agentDir == "" {
		fmt.Println("  ℹ No agents directory found")
	} else {
		inv, err := agent.LoadInventory(agentDir)
		if err != nil {
			fmt.Printf("  ✗ Cannot read agents directory %s: %v\n", agentDir, err)
			issues++
		} else if len(inv.Agents) == 0 {
			fmt.Printf("  ℹ No agents found in %s\n", agentDir)
		} else {
			fmt.Printf("  ✓ Found %d agents in %s\n", len(inv.Agents), agentDir)

			for _, a := range inv.Agents {
				errs := agent.ValidateAgent(a)
				if len(errs) > 0 {
					fmt.Printf("  ✗ %s — %d validation error(s)\n", a.Meta.Name, len(errs))
					for _, e := range errs {
						fmt.Printf("    • %s\n", e)
					}
					issues++
				} else {
					fmt.Printf("  ✓ %s — valid (%s, %s trust, %d tools)\n",
						a.Meta.Name, a.Meta.Type, a.Trust.Level, len(a.Tools))
				}
			}

			// Trust analysis.
			ta := inv.AnalyzeTrust()
			if len(ta.Risks) > 0 {
				fmt.Printf("  ⚠ Trust analysis found %d risk(s):\n", len(ta.Risks))
				for _, r := range ta.Risks {
					fmt.Printf("    • [%s] %s: %s\n", r.Severity, r.AgentName, r.Description)
				}
				warnings++
			} else if len(inv.Agents) > 1 {
				fmt.Println("  ✓ Trust analysis clean — no risks detected")
			}
		}
	}

	// Summary.
	fmt.Print("\n")
	fmt.Println(strings.Repeat("─", 50))
	if issues == 0 && warnings == 0 {
		fmt.Println("✓ Workspace is healthy — no issues found")
	} else if issues == 0 {
		fmt.Printf("⚠ Workspace is functional — %d warning(s)\n", warnings)
	} else {
		fmt.Printf("✗ Workspace has %d issue(s) and %d warning(s)\n", issues, warnings)
		os.Exit(cli.ExitValidation)
	}
}

// --- telemetry ---

func cmdTelemetry(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: threatecho telemetry <subcommand>

Subcommands:
  list        List all recognized telemetry types
  categories  List telemetry categories
  check       Validate a telemetry type string
  stats       Show telemetry type usage across campaigns

Examples:
  threatecho telemetry list
  threatecho telemetry categories
  threatecho telemetry check process_create
  threatecho telemetry stats -dir campaigns/
`)
		exitUsage()
	}

	subcmd := args[0]
	args = args[1:]

	switch subcmd {
	case "list":
		cmdTelemetryList(args)
	case "categories":
		cmdTelemetryCategories()
	case "check":
		cmdTelemetryCheck(args)
	case "stats":
		cmdTelemetryStats(args)
	case "-h", "--help", "help":
		helpRequested = true
		cmdTelemetry(nil)
	default:
		fmt.Fprintf(os.Stderr, "unknown telemetry subcommand: %s\nValid subcommands: list, categories, check, stats\n", subcmd)
		exitUsage()
	}
}

func cmdTelemetryList(args []string) {
	fs := flag.NewFlagSet("telemetry list", flag.ExitOnError)
	cat := fs.String("category", "", "filter by category")
	fs.Parse(args)

	if *cat != "" {
		byCategory := telemetry.ByCategory()
		types, ok := byCategory[*cat]
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown category: %s\n", *cat)
			fmt.Fprintf(os.Stderr, "valid categories: %s\n", strings.Join(telemetry.Categories(), ", "))
			exitUsage()
		}
		for _, t := range types {
			fmt.Printf("  %-30s %s\n", string(t), telemetry.Description(string(t)))
		}
		return
	}

	for _, cat := range telemetry.Categories() {
		types := telemetry.ByCategory()[cat]
		fmt.Printf("\n%s (%d types)\n", cat, len(types))
		for _, t := range types {
			fmt.Printf("  %-30s %s\n", string(t), telemetry.Description(string(t)))
		}
	}
	fmt.Printf("\nTotal: %d types across %d categories\n", len(telemetry.All()), len(telemetry.Categories()))
}

func cmdTelemetryCategories() {
	byCategory := telemetry.ByCategory()
	for _, cat := range telemetry.Categories() {
		fmt.Printf("%-20s %d types\n", cat, len(byCategory[cat]))
	}
	fmt.Printf("\nTotal: %d types across %d categories\n", len(telemetry.All()), len(telemetry.Categories()))
}

func cmdTelemetryCheck(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: threatecho telemetry check <type>\n")
		exitUsage()
	}

	t := args[0]
	if t == "-h" || t == "--help" || t == "help" {
		helpRequested = true
		fmt.Fprintf(os.Stderr, "Usage: threatecho telemetry check <type>\n\nValidate a telemetry type string against the registry.\nSuggests alternatives for typos.\n\nExamples:\n  threatecho telemetry check process_create\n  threatecho telemetry check process_craete\n")
		exitUsage()
	}
	if telemetry.Valid(t) {
		cat := telemetry.Category(t)
		desc := telemetry.Description(t)
		fmt.Printf("✓ %s — category: %s\n", t, cat)
		if desc != "" {
			fmt.Printf("  %s\n", desc)
		}
	} else {
		fmt.Printf("✗ %q is not a recognized telemetry type\n", t)
		suggestions := telemetry.Suggest(t)
		if len(suggestions) > 0 {
			fmt.Print("  Did you mean: ")
			names := make([]string, len(suggestions))
			for i, s := range suggestions {
				names[i] = string(s)
			}
			fmt.Println(strings.Join(names, ", "))
		}
		os.Exit(cli.ExitValidation)
	}
}

func cmdTelemetryStats(args []string) {
	fs := flag.NewFlagSet("telemetry stats", flag.ExitOnError)
	dir := fs.String("dir", "", "campaigns directory (default: from config or auto-detected)")
	fs.Parse(args)

	campaignDir := resolveCampaignDir(*dir)
	summaries, err := campaign.LoadDir(campaignDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaigns"))
	}

	// Gather telemetry usage across all campaigns.
	typeUsage := make(map[string][]string) // type → campaign names
	for _, s := range summaries {
		c, err := campaign.Load(s.Path)
		if err != nil {
			continue
		}
		for _, t := range c.AllTelemetryTypes() {
			typeUsage[t] = append(typeUsage[t], c.Meta.Name)
		}
	}

	// Sort by usage count (descending).
	type entry struct {
		name      string
		campaigns []string
	}
	var entries []entry
	for name, campaigns := range typeUsage {
		entries = append(entries, entry{name, campaigns})
	}
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].campaigns) != len(entries[j].campaigns) {
			return len(entries[i].campaigns) > len(entries[j].campaigns)
		}
		return entries[i].name < entries[j].name
	})

	fmt.Printf("Telemetry type usage across %d campaigns:\n\n", len(summaries))
	fmt.Printf("%-30s %-6s %-10s %s\n", "TYPE", "USED", "STATUS", "CAMPAIGNS")
	fmt.Println(strings.Repeat("─", 80))
	for _, e := range entries {
		status := "✓ known"
		if !telemetry.Valid(e.name) {
			status = "⚠ unknown"
		}
		campaignNames := strings.Join(e.campaigns, ", ")
		if len(campaignNames) > 30 {
			campaignNames = campaignNames[:27] + "..."
		}
		fmt.Printf("%-30s %-6d %-10s %s\n", e.name, len(e.campaigns), status, campaignNames)
	}

	// Summary.
	allTypes := telemetry.All()
	usedRegistered := 0
	usedUnregistered := 0
	for name := range typeUsage {
		if telemetry.Valid(name) {
			usedRegistered++
		} else {
			usedUnregistered++
		}
	}
	fmt.Printf("\n%d types used, %d in registry, %d unregistered\n",
		len(typeUsage), usedRegistered, usedUnregistered)
	fmt.Printf("Registry coverage: %d/%d types used (%d%%)\n",
		usedRegistered, len(allTypes), usedRegistered*100/len(allTypes))
}

// --- init ---

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho init [directory]

Initialize a new campaign workspace with a campaigns/ directory
and a sample campaign you can validate, simulate, and deploy.

Examples:
  threatecho init
  threatecho init ./my-project
`)
	}
	fs.Parse(args)

	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}

	campaignDir := filepath.Join(dir, "campaigns")
	exampleDir := filepath.Join(campaignDir, "example")

	if err := os.MkdirAll(exampleDir, 0o755); err != nil {
		exitErr(cli.IOWrap(err, "creating directories"))
	}

	exampleCampaign := `api_version: v1
kind: Campaign

meta:
  name: example-campaign
  adversary: Unknown
  description: "Example campaign — replace with your adversary emulation plan"
  objective: "Demonstrate campaign structure"
  mitre_version: "15.1"
  severity: medium
  tags: [example]
  authors: ["Your Name"]
  created: "2026-01-01"
  modified: "2026-01-01"

variables:
  target_host: "192.168.1.10"

stages:
  - id: recon
    name: Network Scan
    technique: T1016
    tactic: discovery
    execute:
      type: shell
      commands:
        - 'echo "[SIM] Scanning {{target_host}}"'
    expect:
      telemetry: [process_create, network_connection]
      detections: [network_scan_detected]
    on_success: access
    on_failure: abort

  - id: access
    name: Initial Access
    technique: T1190
    tactic: initial-access
    depends_on: [recon]
    execute:
      type: shell
      commands:
        - 'echo "[SIM] Exploiting web application on {{target_host}}"'
    expect:
      telemetry: [network_connection, process_create]
      detections: [web_exploit_attempt]
    on_failure: abort
`

	examplePath := filepath.Join(exampleDir, "campaign.yaml")
	if err := os.WriteFile(examplePath, []byte(exampleCampaign), 0o644); err != nil {
		exitErr(cli.IOWrap(err, "writing example campaign"))
	}

	fmt.Printf("✓ Workspace initialized\n")
	fmt.Printf("  Created: %s\n", examplePath)
	fmt.Printf("\n  Next steps:\n")
	fmt.Printf("    threatecho validate %s\n", examplePath)
	fmt.Printf("    threatecho simulate %s\n", filepath.Join(exampleDir))
	fmt.Printf("    threatecho campaigns list\n")
}

// --- policy ---

func cmdPolicy(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy <subcommand> [flags] [args]

Subcommands:
  validate    Validate a policy YAML file
  eval        Evaluate a policy against campaigns
  compile     Compile a policy, detect conflicts, show stats
  merge       Merge multiple policies into one
  coverage    Analyze what a policy covers vs reference set
  test        Test a policy against built-in attack scenarios
  generate    Generate a policy from built-in templates
  risk        Assess the risk posture of a policy
  diff        Compare two policies and show differences
  guardrail   Analyze guardrail coverage against traces and policy
  history     Policy version history and change tracking
  export      Export a policy in machine-readable formats (JSON, YAML, Rego)
  simulate    Dry-run a campaign against a policy (no execution)
  compliance  Evaluate trace compliance against a policy
  benchmark   Benchmark policy evaluation performance
  drift       Detect semantic drift between two policy versions
  lint        Best-practice quality checks and scoring
  coveragemap Map policy rules to MITRE techniques and find gaps
  remediate   Generate fix suggestions from lint, drift, or coverage findings
  impact      Analyze the impact of policy changes on agents and traces

Examples:
  threatecho policy validate policies/agent-default/
  threatecho policy eval -policy policies/agent-default/ campaigns/llm-agent-hijack/
  threatecho policy export -format rego policies/agent-default/
  threatecho policy compile policies/agent-strict/
  threatecho policy merge policies/agent-default/ policies/agent-strict/ -output merged.yaml
  threatecho policy coverage policies/agent-strict/ -dir campaigns/
  threatecho policy risk policies/agent-default/
  threatecho policy diff policies/agent-default/ policies/agent-strict/
  threatecho policy guardrail -policy policies/agent-strict/ traces/
  threatecho policy history -init policies/agent-default/
`)
		exitUsage()
	}

	subcmd := args[0]
	args = args[1:]

	switch subcmd {
	case "validate":
		cmdPolicyValidate(args)
	case "eval":
		cmdPolicyEval(args)
	case "export":
		cmdPolicyExport(args)
	case "compile":
		cmdPolicyCompile(args)
	case "merge":
		cmdPolicyMerge(args)
	case "coverage":
		cmdPolicyCoverage(args)
	case "test":
		cmdPolicyTest(args)
	case "generate":
		cmdPolicyGenerate(args)
	case "risk":
		cmdPolicyRisk(args)
	case "diff":
		cmdPolicyDiff(args)
	case "guardrail":
		cmdPolicyGuardrail(args)
	case "history":
		cmdPolicyHistory(args)
	case "simulate":
		cmdPolicySimulate(args)
	case "compliance":
		cmdPolicyCompliance(args)
	case "benchmark":
		cmdPolicyBenchmark(args)
	case "drift":
		cmdPolicyDrift(args)
	case "lint":
		cmdPolicyLint(args)
	case "coveragemap":
		cmdPolicyCoverageMap(args)
	case "remediate":
		cmdPolicyRemediate(args)
	case "impact":
		cmdPolicyImpact(args)
	case "-h", "--help", "help":
		helpRequested = true
		cmdPolicy(nil)
	default:
		fmt.Fprintf(os.Stderr, "unknown policy subcommand: %s\nRun 'threatecho policy' for available subcommands\n", subcmd)
		exitUsage()
	}
}

func cmdPolicyValidate(args []string) {
	fs := flag.NewFlagSet("policy validate", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy validate <policy-path>

Validate a policy YAML file or directory.

Examples:
  threatecho policy validate policies/default/
  threatecho policy validate policies/strict/policy.yaml
`)
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	p, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	errs := policy.ValidatePolicy(p)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(p.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	fmt.Printf("✓ Policy %q is valid (%d rules, agent: %s)\n",
		p.Meta.Name, len(p.Rules), p.Agent.Name)
}

func cmdPolicyEval(args []string) {
	fs := flag.NewFlagSet("policy eval", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to policy YAML file or directory (required)")
	format := fs.String("format", "text", "output format: text, json, sarif, junit")
	dir := fs.String("dir", "", "scan directory for campaigns (evaluate all)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy eval -policy <path> [flags] <campaign-path> [campaign-path...]

Evaluate a policy against one or more campaigns.
Exit code 2 when any violations are denied (CI-friendly).

Output formats:
  text     Human-readable ANSI report (default)
  json     Machine-readable JSON
  sarif    SARIF v2.1.0 (GitHub Code Scanning, VS Code)
  junit    JUnit XML (Jenkins, GitHub Actions, GitLab CI)

Examples:
  threatecho policy eval -policy policies/agent-default/ campaigns/llm-agent-hijack/
  threatecho policy eval -policy policies/agent-default/ -dir campaigns/
  threatecho policy eval -policy policies/agent-default/ -format sarif campaigns/llm-agent-hijack/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	// Default policy from config if not specified.
	polPath := *policyPath
	if polPath == "" && cfg.DefaultPolicy != "" {
		polPath = cfg.DefaultPolicy
	}
	if polPath == "" {
		fs.Usage()
		exitUsage()
	}

	// Collect campaign paths.
	paths := collectCampaignPaths(fs, *dir)

	p, err := policy.LoadPolicy(polPath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	errs := policy.ValidatePolicy(p)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(p.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	outFmt := resolveFormat(*format)
	anyDenied := false
	for _, path := range paths {
		c, err := campaign.Load(path)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading campaign"))
		}

		result := policy.Evaluate(p, c)
		if result.Denied > 0 {
			anyDenied = true
		}

		// Derive campaign file for SARIF.
		campaignFile := path

		switch outFmt {
		case "json":
			if err := report.PolicyJSONReport(os.Stdout, result); err != nil {
				exitRuntime("JSON output failed: %s", err)
			}
		case "sarif":
			if err := report.PolicySARIFReport(os.Stdout, result, campaignFile); err != nil {
				exitRuntime("SARIF output failed: %s", err)
			}
		case "junit":
			if err := report.PolicyJUnitReport(os.Stdout, result); err != nil {
				exitRuntime("JUnit output failed: %s", err)
			}
		default:
			report.PolicyTextReport(os.Stdout, result)
		}
	}

	if anyDenied {
		os.Exit(cli.ExitPolicyDenied)
	}
}

// --- export ---

func cmdExport(args []string) {
	usage := `Usage: threatecho export <format> [flags] [args]

Formats:
  navigator    Export ATT&CK Navigator layer JSON (v4.5)
  sigma        Export Sigma detection rule scaffolds

Examples:
  threatecho export navigator campaigns/apt29-cozy-bear/
  threatecho export navigator -dir campaigns/ -output layer.json
  threatecho export navigator -gap -dir campaigns/
  threatecho export sigma campaigns/llm-agent-hijack/
  threatecho export sigma -dir campaigns/ -output rules.yml
`
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, usage)
		exitUsage()
	}

	subcmd := args[0]
	if subcmd == "-h" || subcmd == "-help" || subcmd == "--help" {
		fmt.Fprint(os.Stderr, usage)
		return
	}
	args = args[1:]

	switch subcmd {
	case "navigator":
		cmdExportNavigator(args)
	case "sigma":
		cmdExportSigma(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown export format: %s\nValid formats: navigator, sigma\n", subcmd)
		exitUsage()
	}
}

func cmdExportNavigator(args []string) {
	fs := flag.NewFlagSet("export navigator", flag.ExitOnError)
	dir := fs.String("dir", "", "scan directory for campaigns")
	platform := fs.String("platform", "", "filter stages by platform")
	output := fs.String("output", "", "output file (default: stdout)")
	useGap := fs.Bool("gap", false, "generate gap analysis layer instead of coverage")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho export navigator [flags] [campaign-path...]

Export an ATT&CK Navigator layer (v4.5 JSON).

Examples:
  threatecho export navigator campaigns/apt29/
  threatecho export navigator -dir campaigns/ -output layer.json
  threatecho export navigator -gap -dir campaigns/ -output gaps.json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	paths := collectCampaignPaths(fs, *dir)
	results := simulateCampaigns(paths, *platform)

	var layer *navigator.Layer
	if *useGap {
		gapReport := gap.Analyze(results...)
		layer = navigator.FromGapReport(gapReport)
	} else {
		layer = navigator.FromRunResult(results...)
	}

	w := os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			exitErr(cli.IOWrap(err, "creating output file"))
		}
		defer f.Close()
		w = f
	}

	if err := navigator.WriteLayer(w, layer); err != nil {
		exitRuntime("writing layer: %s", err)
	}

	if *output != "" {
		fmt.Fprintf(os.Stderr, "✓ Navigator layer written to %s\n", *output)
	}
}

// --- export sigma ---

func cmdExportSigma(args []string) {
	fs := flag.NewFlagSet("export sigma", flag.ExitOnError)
	dir := fs.String("dir", "", "scan directory for campaigns")
	output := fs.String("output", "", "output file (default: stdout)")
	author := fs.String("author", "", "rule author (default: from config)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho export sigma [flags] [campaign-path...]

Generate Sigma detection rule scaffolds from campaigns.
Produces one rule per expected detection per stage.

Rules are scaffolds — a detection engineer reviews and adds
specific selection criteria for their telemetry pipeline.

Supports ATT&CK, ATLAS, and OWASP techniques with telemetry-aware
logsource mapping (process, network, file, registry, agent events).

Examples:
  threatecho export sigma campaigns/apt29-cozy-bear/
  threatecho export sigma -dir campaigns/ -output rules.yml
  threatecho export sigma -author "SOC Team" campaigns/llm-agent-hijack/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	// Resolve author: flag → config → default.
	sigmaAuthor := *author
	if sigmaAuthor == "" {
		sigmaAuthor = cfg.Author
	}

	paths := collectCampaignPaths(fs, *dir)

	var allRules []sigma.Rule
	for _, path := range paths {
		c, err := campaign.Load(path)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading %s", path))
		}
		errs := campaign.Validate(c)
		if len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(c.Meta.Name, errs))
			os.Exit(cli.ExitValidation)
		}
		rules := sigma.Generate(c, sigma.GenerateOptions{Author: sigmaAuthor})
		allRules = append(allRules, rules...)
	}

	w := os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			exitErr(cli.IOWrap(err, "creating output file"))
		}
		defer f.Close()
		w = f
	}

	if err := sigma.WriteRules(w, allRules); err != nil {
		exitRuntime("writing rules: %s", err)
	}

	if *output != "" {
		fmt.Fprintf(os.Stderr, "✓ %d Sigma rules written to %s\n", len(allRules), *output)
	}
}

// --- summary ---

func cmdSummary(args []string) {
	fs := flag.NewFlagSet("summary", flag.ExitOnError)
	dir := fs.String("dir", "", "campaigns directory (default: from config or auto-detected)")
	policyPath := fs.String("policy", "", "policy YAML to include in summary")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho summary [flags]

Display a security posture dashboard aggregating campaigns,
detection gaps, policy evaluations, and lint results.

Examples:
  threatecho summary -dir campaigns/
  threatecho summary -dir campaigns/ -policy policies/agent-default/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	campaignDir := resolveCampaignDir(*dir)

	summaries, err := campaign.LoadDir(campaignDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaigns"))
	}
	if len(summaries) == 0 {
		exitIO("no campaigns found in %s", campaignDir)
	}

	data := &report.SummaryData{}

	// Load all campaigns, build summaries.
	var results []*engine.RunResult
	for _, s := range summaries {
		c, err := campaign.Load(s.Path)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading %s", s.Path))
		}

		lr := campaign.Lint(c)

		data.Campaigns = append(data.Campaigns, report.SummaryCampaign{
			Name:       c.Meta.Name,
			Adversary:  c.Meta.Adversary,
			Stages:     len(c.Stages),
			Techniques: len(c.UniqueTechniques()),
			Severity:   c.Meta.Severity,
			LintClean:  !lr.HasIssues(),
		})

		if lr.HasIssues() {
			data.LintSummary.Warnings++
		} else {
			data.LintSummary.Clean++
		}
		data.LintSummary.Total++

		errs := campaign.Validate(c)
		if len(errs) > 0 {
			continue
		}

		opts := engine.Options{DryRun: true}
		result, err := engine.Simulate(context.Background(), c, opts)
		if err != nil {
			continue
		}
		results = append(results, result)
	}

	// Gap analysis.
	if len(results) > 0 {
		gapReport := gap.Analyze(results...)
		data.GapSummary = report.SummaryGaps{
			Total:    gapReport.RiskSummary.Total,
			Critical: gapReport.RiskSummary.Critical,
			High:     gapReport.RiskSummary.High,
			Medium:   gapReport.RiskSummary.Medium,
			Low:      gapReport.RiskSummary.Low,
			Score:    gapReport.RiskSummary.Score,
		}
		if gapReport.Aggregate.AttackTactics.Total > 0 {
			data.GapSummary.AttackCovPct = gapReport.Aggregate.AttackTactics.Covered * 100 / gapReport.Aggregate.AttackTactics.Total
		}
		if gapReport.Aggregate.AtlasTactics.Total > 0 {
			data.GapSummary.AtlasCovPct = gapReport.Aggregate.AtlasTactics.Covered * 100 / gapReport.Aggregate.AtlasTactics.Total
		}
	}

	// Policy evaluation: flag → config → skip.
	polPath := *policyPath
	if polPath == "" {
		polPath = cfg.DefaultPolicy
	}
	if polPath != "" {
		p, err := policy.LoadPolicy(polPath)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading policy"))
		}
		for _, s := range summaries {
			c, err := campaign.Load(s.Path)
			if err != nil {
				continue
			}
			result := policy.Evaluate(p, c)
			data.PolicyResults = append(data.PolicyResults, report.SummaryPolicy{
				Name:    p.Meta.Name + " → " + c.Meta.Name,
				Rules:   len(p.Rules),
				Denied:  result.Denied,
				Alerted: result.Alerted,
				Allowed: result.Allowed,
			})
		}
	}

	report.SummaryTextReport(os.Stdout, data)
}

// --- compare ---

func cmdCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	platform := fs.String("platform", "", "filter stages by platform")
	format := fs.String("format", "text", "output format: text, json")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho compare [flags] <before-dir> <after-dir>

Compare detection coverage between two campaign sets.
Produces a delta report showing improvements, regressions, and unchanged gaps.

The 'before' and 'after' arguments are directories containing campaign YAML files.
Typically used to measure the ROI of adding new campaigns or detection rules.

Examples:
  threatecho compare campaigns-v1/ campaigns-v2/
  threatecho compare -format json campaigns-before/ campaigns-after/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fs.Usage()
		exitUsage()
	}

	beforeDir := fs.Arg(0)
	afterDir := fs.Arg(1)

	// Load and analyze "before".
	beforeResults := loadAndSimulateDir(beforeDir, *platform)
	beforeReport := gap.Analyze(beforeResults...)

	// Load and analyze "after".
	afterResults := loadAndSimulateDir(afterDir, *platform)
	afterReport := gap.Analyze(afterResults...)

	// Compare.
	cr := gap.Compare(beforeReport, afterReport)

	cmpFmt := resolveFormat(*format)
	checkFormat(cmpFmt, "text", "json")
	switch cmpFmt {
	case "json":
		if err := report.CompareJSONReport(os.Stdout, cr); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
	default:
		report.CompareTextReport(os.Stdout, cr)
	}
}

// --- run ---

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	platform := fs.String("platform", "", "filter stages by platform")
	denyElevated := fs.Bool("deny-elevated", true, "refuse stages requiring elevated privileges")
	maxOutput := fs.Int("max-output", 0, "max output per stage in bytes (default: 1 MiB)")
	workDir := fs.String("workdir", "", "working directory for commands")
	format := fs.String("format", "text", "output format: text, json")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho run [flags] <campaign-path>

Execute a campaign live. Only 'shell' type stages are executed; other types
are skipped. Commands run in the system shell (sh -c on Unix, cmd /c on Windows).

⚠  This executes real commands. Use -deny-elevated (default: true) to prevent
   privileged operations. Review the campaign YAML before running.

Examples:
  threatecho run campaigns/apt29-cozy-bear/
  threatecho run -deny-elevated=false -workdir /tmp campaigns/example/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	path := fs.Arg(0)
	c, err := campaign.Load(path)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign"))
	}

	errs := campaign.Validate(c)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(c.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	shellCfg := executor.ShellConfig{
		DenyElevated: *denyElevated,
		MaxOutput:    *maxOutput,
		WorkDir:      *workDir,
	}
	shellExec := executor.NewShell(shellCfg)

	opts := engine.Options{
		Platform: *platform,
		OnProgress: func(sr engine.StageResult) {
			if sr.Skipped {
				fmt.Fprintf(os.Stderr, "  ⊘ %s — skipped (%s)\n", sr.Stage.ID, sr.SkipMsg)
			} else if sr.Exec.Success {
				fmt.Fprintf(os.Stderr, "  ✓ %s — %s\n", sr.Stage.ID, sr.Stage.Name)
			} else {
				fmt.Fprintf(os.Stderr, "  ✗ %s — %s: %v\n", sr.Stage.ID, sr.Stage.Name, sr.Exec.Error)
			}
		},
		OnCleanupError: func(s campaign.Stage, err error) {
			fmt.Fprintf(os.Stderr, "    cleanup warning [%s]: %v\n", s.ID, err)
		},
	}

	runResult, err := engine.Run(context.Background(), c, shellExec, opts)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "run failed"))
	}

	runFmt := resolveFormat(*format)
	checkFormat(runFmt, "text", "json")
	switch runFmt {
	case "json":
		if err := report.JSONReportWrite(os.Stdout, runResult); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
	default:
		report.TextReport(os.Stdout, runResult)
	}

	if runResult.Failed > 0 {
		os.Exit(cli.ExitRuntime)
	}
}

// --- matrix ---

func cmdMatrix(args []string) {
	fs := flag.NewFlagSet("matrix", flag.ExitOnError)
	dir := fs.String("dir", "", "campaigns directory (default: from config or auto-detected)")
	platform := fs.String("platform", "", "filter stages by platform")
	compact := fs.Bool("compact", false, "compact view (tactic summary only)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho matrix [flags]

Display ATT&CK tactic×technique coverage matrix in the terminal.
Shows which techniques are covered by your campaigns with
color-coded coverage levels.

Coverage levels:
  Full       Multiple campaigns + detections + telemetry (bright green)
  Detected   Has detection rules (green)
  Partial    Has telemetry but no detection rules (yellow)
  Uncovered  Not exercised by any campaign (red)

Examples:
  threatecho matrix -dir campaigns/
  threatecho matrix -compact -dir campaigns/
  threatecho matrix -platform linux -dir campaigns/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	campaignDir := resolveCampaignDir(*dir)

	results := loadAndSimulateDir(campaignDir, *platform)
	gapReport := gap.Analyze(results...)
	m := matrix.BuildFromGapReport(gapReport, results...)

	if *compact {
		matrix.RenderCompact(os.Stdout, m)
	} else {
		matrix.Render(os.Stdout, m)
	}
}

// --- coverage ---

func cmdCoverage(args []string) {
	fs := flag.NewFlagSet("coverage", flag.ExitOnError)
	dir := fs.String("dir", "", "campaigns directory (default: from config or auto-detected)")
	platform := fs.String("platform", "", "filter stages by platform")
	format := fs.String("format", "text", "output format: text, json")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho coverage [flags]

Technique-level coverage analysis showing which specific ATT&CK,
ATLAS, and OWASP techniques are exercised across your campaigns,
their detection status, and which campaigns cover them.

Unlike 'gap' (which reports what's missing at tactic level),
'coverage' drills down to individual techniques: which are
exercised, by whom, and with what detection readiness.

Output formats:
  text     Human-readable ANSI report (default)
  json     Machine-readable JSON

Examples:
  threatecho coverage -dir campaigns/
  threatecho coverage -format json -dir campaigns/
  threatecho coverage -platform linux -dir campaigns/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	campaignDir := resolveCampaignDir(*dir)

	covFmt := resolveFormat(*format)
	checkFormat(covFmt, "text", "json")

	results := loadAndSimulateDir(campaignDir, *platform)
	cr := gap.AnalyzeCoverage(results...)

	switch covFmt {
	case "json":
		if err := report.CoverageJSONReport(os.Stdout, cr); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
	default:
		report.CoverageTextReport(os.Stdout, cr)
	}
}

// --- diff ---

func cmdDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text, json")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho diff [flags] <campaign-a> <campaign-b>

Compare two campaign files and show structural differences.
Stages are matched by ID, so reordering is handled gracefully.

Shows:
  - Meta field changes (name, severity, tags, etc.)
  - Variable additions, removals, modifications
  - Stage additions, removals, and field-level modifications
  - Telemetry, detection, and dependency changes

Output formats:
  text     Human-readable diff with +/- markers (default)
  json     Machine-readable JSON

Examples:
  threatecho diff campaigns/apt29-cozy-bear/ campaigns/apt29-v2/
  threatecho diff -format json old/campaign.yaml new/campaign.yaml

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fs.Usage()
		exitUsage()
	}

	leftPath := fs.Arg(0)
	rightPath := fs.Arg(1)

	dr, err := campaign.DiffFiles(leftPath, rightPath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaigns for diff"))
	}

	diffFmt := resolveFormat(*format)
	checkFormat(diffFmt, "text", "json")
	switch diffFmt {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(dr); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
	default:
		if !dr.HasChanges() {
			fmt.Println("No differences found.")
			return
		}
		fmt.Print(campaign.FormatDiff(dr))
	}
}

// --- merge ---

func cmdMerge(args []string) {
	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	name := fs.String("name", "", "name for the merged campaign (default: merged-campaign)")
	prefix := fs.Bool("prefix", false, "prefix stage IDs with campaign name to avoid collisions")
	strategy := fs.String("strategy", "error", "collision strategy: error, first")
	output := fs.String("output", "", "output directory for merged campaign YAML")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho merge [flags] <campaign-a> <campaign-b> [campaign-c...]

Combine multiple campaigns into a single composite campaign.
Merges stages, variables, and metadata from all input campaigns.

Stage ID collision handling:
  -strategy error   Fail on duplicate stage IDs (default)
  -strategy first   Keep the first occurrence, skip duplicates
  -prefix           Prefix stage IDs with campaign name (e.g. apt29/initial-access)

Metadata composition:
  - Severity: highest wins (critical > high > medium > low)
  - Tags, authors, references: union, sorted, deduplicated
  - Adversary: joined with " + " (deduplicated)

Examples:
  threatecho merge campaigns/apt29-cozy-bear/ campaigns/fin7-carbanak/
  threatecho merge -prefix campaigns/apt29-cozy-bear/ campaigns/apt28-fancy-bear/
  threatecho merge -name full-assessment -output merged/ campaigns/*/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fs.Usage()
		exitUsage()
	}

	var paths []string
	for i := 0; i < fs.NArg(); i++ {
		paths = append(paths, fs.Arg(i))
	}

	opts := campaign.MergeOptions{
		Name:     *name,
		Prefix:   *prefix,
		Strategy: *strategy,
	}

	mr, err := campaign.MergeFiles(paths, opts)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "merging campaigns"))
	}

	// Report conflicts.
	if len(mr.Conflicts) > 0 {
		fmt.Fprintf(os.Stderr, "✗ Merge failed — %d conflict(s):\n", len(mr.Conflicts))
		for _, c := range mr.Conflicts {
			fmt.Fprintf(os.Stderr, "  %s %q (in: %s)\n", c.Type, c.Key, strings.Join(c.Sources, ", "))
		}
		fmt.Fprintf(os.Stderr, "\nUse -prefix to auto-namespace stage IDs, or -strategy first to keep first occurrence.\n")
		os.Exit(cli.ExitValidation)
	}

	// Report warnings.
	for _, w := range mr.Warnings {
		fmt.Fprintf(os.Stderr, "⚠ %s\n", w)
	}

	// Format and output.
	data, err := campaign.Format(mr.Campaign)
	if err != nil {
		exitRuntime("formatting merged campaign: %s", err)
	}

	if *output != "" {
		if err := os.MkdirAll(*output, 0o755); err != nil {
			exitErr(cli.IOWrap(err, "creating output directory"))
		}
		outPath := filepath.Join(*output, "campaign.yaml")
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			exitErr(cli.IOWrap(err, "writing merged campaign"))
		}
		fmt.Fprintf(os.Stderr, "✓ Merged %d campaigns → %s (%d stages)\n",
			len(paths), outPath, len(mr.Campaign.Stages))
	} else {
		os.Stdout.Write(data)
	}
}

// --- search ---

func cmdSearch(args []string) {
	fs := flag.NewFlagSet("search", flag.ExitOnError)
	technique := fs.String("technique", "", "match technique ID (exact or prefix, e.g. T1059)")
	tactic := fs.String("tactic", "", "match tactic name (case-insensitive)")
	adversary := fs.String("adversary", "", "match adversary name (substring)")
	tag := fs.String("tag", "", "match tag (case-insensitive substring)")
	keyword := fs.String("keyword", "", "free-text search across names, descriptions, IDs")
	severity := fs.String("severity", "", "match severity (critical/high/medium/low)")
	stageID := fs.String("stage", "", "match stage ID (exact or contains)")
	platform := fs.String("platform", "", "match platform (e.g. windows, linux)")
	execType := fs.String("exec-type", "", "match execution type (shell, http, registry)")
	dir := fs.String("dir", "", "campaign directory (default: auto-detect)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho search [flags]

Search campaign stages across all campaigns in a project.
All non-empty fields are ANDed together.

Examples:
  threatecho search -technique T1059
  threatecho search -tactic execution -platform windows
  threatecho search -adversary APT29 -severity critical
  threatecho search -keyword "lateral movement"

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	campDir := *dir
	if campDir == "" {
		campDir = findCampaignDir()
	}

	query := campaign.SearchQuery{
		Technique: *technique,
		Tactic:    *tactic,
		Adversary: *adversary,
		Tag:       *tag,
		Keyword:   *keyword,
		Severity:  *severity,
		StageID:   *stageID,
		Platform:  *platform,
		ExecType:  *execType,
	}

	results, err := campaign.SearchDir(campDir, query)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "searching campaigns"))
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
		return
	}

	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "No matching stages found.\n")
		return
	}

	fmt.Print(campaign.FormatSearchResults(results))
	fmt.Fprintf(os.Stderr, "\n%d result(s) found.\n", len(results))
}

// --- stats ---

func cmdStats(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory (default: auto-detect)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho stats [flags]

Project-wide campaign analytics dashboard.
Aggregates technique frequency, tactic distribution, detection readiness,
execution complexity, and content metrics across all campaigns.

Examples:
  threatecho stats
  threatecho stats -dir /path/to/campaigns
  threatecho stats -json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	campDir := *dir
	if campDir == "" {
		campDir = findCampaignDir()
	}

	stats, err := campaign.ComputeStatsDir(campDir)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "computing stats"))
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(stats)
		return
	}

	fmt.Print(campaign.FormatStats(stats))
}

// --- import ---

func cmdImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	source := fs.String("source", "", "source format (currently: atomic)")
	name := fs.String("name", "", "name for the generated campaign")
	adversary := fs.String("adversary", "Atomic Red Team", "adversary attribution")
	platforms := fs.String("platforms", "", "comma-separated platform filter (e.g. windows,linux)")
	maxTests := fs.Int("max-tests", 0, "limit tests per technique (0 = all)")
	output := fs.String("output", "", "output directory for generated campaign YAML")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho import [flags] <path>

Import external test libraries as ThreatEcho campaigns.

Sources:
  atomic    Atomic Red Team YAML (single file or directory of technique files)

Import maps each test to a campaign stage with technique/tactic resolution,
executor mapping, cleanup extraction, and variable conversion.

Examples:
  threatecho import -source atomic path/to/T1059.001.yaml
  threatecho import -source atomic -platforms windows,linux path/to/atomics/
  threatecho import -source atomic -name "my-atomics" -output campaigns/imported/ path/to/atomics/
  threatecho import -source atomic -max-tests 3 path/to/atomics/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *source == "" {
		fmt.Fprintf(os.Stderr, "Error: -source is required (currently supported: atomic)\n\n")
		fs.Usage()
		exitUsage()
	}

	if *source != "atomic" {
		fmt.Fprintf(os.Stderr, "Error: unsupported import source %q (supported: atomic)\n", *source)
		exitUsage()
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: path to source file or directory is required\n\n")
		fs.Usage()
		exitUsage()
	}

	path := fs.Arg(0)
	opts := campaign.ImportOptions{
		CampaignName: *name,
		Adversary:    *adversary,
		MaxTests:     *maxTests,
	}
	if *platforms != "" {
		opts.Platforms = strings.Split(*platforms, ",")
	}

	info, err := os.Stat(path)
	if err != nil {
		exitErr(cli.IOWrap(err, "reading import source"))
	}

	var c *campaign.Campaign
	if info.IsDir() {
		c, err = campaign.ImportAtomicDir(path, opts)
	} else {
		c, err = campaign.ImportAtomicFile(path, opts)
	}
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "importing atomic tests"))
	}

	// Format and output.
	data, fmtErr := campaign.Format(c)
	if fmtErr != nil {
		exitRuntime("formatting imported campaign: %s", fmtErr)
	}

	if *output != "" {
		if err := os.MkdirAll(*output, 0o755); err != nil {
			exitErr(cli.IOWrap(err, "creating output directory"))
		}
		outPath := filepath.Join(*output, "campaign.yaml")
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			exitErr(cli.IOWrap(err, "writing imported campaign"))
		}
		fmt.Fprintln(os.Stderr, campaign.FormatImportSummary(c, path))
		fmt.Fprintf(os.Stderr, "✓ Written to %s\n", outPath)
	} else {
		fmt.Fprintln(os.Stderr, campaign.FormatImportSummary(c, path))
		os.Stdout.Write(data)
	}
}

// --- enrich ---

func cmdEnrich(args []string) {
	fs := flag.NewFlagSet("enrich", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory (default: auto-detect)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho enrich [flags] [path]

Enrich campaign stages with ATT&CK metadata — data sources, mitigations,
detection notes, and severity inference for each technique.

Without arguments, enriches all campaigns in the project.
With a path, enriches a single campaign.

Examples:
  threatecho enrich
  threatecho enrich -dir campaigns/
  threatecho enrich campaigns/apt29-cozy-bear/
  threatecho enrich -json campaigns/apt29-cozy-bear/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() > 0 {
		// Single campaign.
		c, err := campaign.Load(filepath.Join(fs.Arg(0), "campaign.yaml"))
		if err != nil {
			c, err = campaign.Load(fs.Arg(0))
		}
		if err != nil {
			exitErr(cli.IOWrap(err, "loading campaign"))
		}
		result := campaign.EnrichCampaign(c)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(result)
			return
		}
		fmt.Print(campaign.FormatEnrichment([]*campaign.EnrichResult{result}))
		return
	}

	campDir := *dir
	if campDir == "" {
		campDir = findCampaignDir()
	}

	results, err := campaign.EnrichDir(campDir)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "enriching campaigns"))
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
		return
	}

	fmt.Print(campaign.FormatEnrichment(results))
}

// --- score ---

func cmdScore(args []string) {
	fs := flag.NewFlagSet("score", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory (default: auto-detect)")
	detail := fs.Bool("detail", false, "show detailed breakdown for each campaign")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho score [flags] [path]

Score campaigns on risk and complexity across five dimensions:
technique complexity, tactic breadth, detection difficulty,
execution complexity, and evasion sophistication.

Without arguments, scores all campaigns in the project.
With a path, scores a single campaign.

Examples:
  threatecho score
  threatecho score -dir campaigns/
  threatecho score -detail campaigns/apt29-cozy-bear/
  threatecho score -json -dir campaigns/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() > 0 {
		// Single campaign.
		c, err := campaign.Load(filepath.Join(fs.Arg(0), "campaign.yaml"))
		if err != nil {
			c, err = campaign.Load(fs.Arg(0))
		}
		if err != nil {
			exitErr(cli.IOWrap(err, "loading campaign"))
		}
		sc := campaign.ScoreCampaign(c)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(sc)
			return
		}
		if *detail {
			fmt.Print(campaign.FormatScoreDetail(sc))
		} else {
			fmt.Print(campaign.FormatScores([]*campaign.ScoredCampaign{sc}))
		}
		return
	}

	campDir := *dir
	if campDir == "" {
		campDir = findCampaignDir()
	}

	scores, err := campaign.ScoreDir(campDir)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "scoring campaigns"))
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(scores)
		return
	}

	fmt.Print(campaign.FormatScores(scores))
	if *detail {
		for _, sc := range scores {
			fmt.Println()
			fmt.Print(campaign.FormatScoreDetail(sc))
		}
	}
}

// --- convert ---

func cmdConvert(args []string) {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	format := fs.String("format", "json", "target format: json, yaml, markdown, csv")
	indent := fs.Int("indent", 2, "JSON indent spaces")
	compact := fs.Bool("compact", false, "compact output (JSON: no indent; CSV: no headers)")
	normalize := fs.Bool("normalize", false, "normalize YAML field ordering")
	output := fs.String("output", "", "output file (default: stdout)")
	dir := fs.String("dir", "", "convert all campaigns in directory")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho convert [flags] [path]

Convert campaigns between formats.

Formats:
  json       JSON with configurable indent
  yaml       YAML (optionally normalized)
  markdown   Markdown report with badges, tables, coverage
  csv        CSV with one row per stage

Examples:
  threatecho convert campaigns/apt29-cozy-bear/
  threatecho convert -format markdown campaigns/apt29-cozy-bear/
  threatecho convert -format csv -dir campaigns/
  threatecho convert -format json -compact campaigns/apt29-cozy-bear/
  threatecho convert -format yaml -normalize campaigns/apt29-cozy-bear/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	opts := campaign.ConvertOptions{
		Format:    campaign.ConvertFormat(*format),
		Indent:    *indent,
		Compact:   *compact,
		Normalize: *normalize,
	}

	if *dir != "" {
		results, err := campaign.ConvertDir(*dir, opts)
		if err != nil {
			exitErr(cli.RuntimeWrap(err, "converting campaigns"))
		}
		if *output != "" {
			if err := os.MkdirAll(*output, 0o755); err != nil {
				exitErr(cli.IOWrap(err, "creating output directory"))
			}
			ext := "." + *format
			for name, data := range results {
				outPath := filepath.Join(*output, name+ext)
				if err := os.WriteFile(outPath, data, 0o644); err != nil {
					exitErr(cli.IOWrap(err, "writing %s", outPath))
				}
				fmt.Fprintf(os.Stderr, "✓ %s → %s\n", name, outPath)
			}
		} else {
			first := true
			for name, data := range results {
				fmt.Fprintf(os.Stderr, "=== %s ===\n", name)
				if !first && *format == "csv" {
					if i := bytes.IndexByte(data, '\n'); i >= 0 {
						data = data[i+1:]
					}
				}
				os.Stdout.Write(data)
				if *format != "csv" {
					fmt.Println()
				}
				first = false
			}
		}
		return
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: path to campaign or -dir is required\n\n")
		fs.Usage()
		exitUsage()
	}

	path := fs.Arg(0)
	data, err := campaign.ConvertFile(path, opts)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "converting campaign"))
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0o644); err != nil {
			exitErr(cli.IOWrap(err, "writing output"))
		}
		fmt.Fprintf(os.Stderr, "✓ Written to %s\n", *output)
	} else {
		os.Stdout.Write(data)
	}
}

// --- tag ---

func cmdTag(args []string) {
	fs := flag.NewFlagSet("tag", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory (default: auto-detect)")
	find := fs.String("find", "", "find campaigns with this tag")
	suggest := fs.Bool("suggest", false, "suggest tags for untagged campaigns")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho tag [flags]

Tag management across campaigns — list tags, find campaigns by tag,
and get suggestions for untagged campaigns.

Examples:
  threatecho tag                          # list all tags
  threatecho tag -dir campaigns/
  threatecho tag -find ransomware         # find campaigns with "ransomware" tag
  threatecho tag -suggest                 # suggest tags for untagged campaigns
  threatecho tag -json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	campDir := *dir
	if campDir == "" {
		campDir = findCampaignDir()
	}

	if *find != "" {
		// Load all campaigns and find by tag.
		entries, err := os.ReadDir(campDir)
		if err != nil {
			exitErr(cli.IOWrap(err, "reading campaign directory"))
		}
		var campaigns []*campaign.Campaign
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			c, err := campaign.Load(filepath.Join(campDir, e.Name(), "campaign.yaml"))
			if err != nil {
				continue
			}
			campaigns = append(campaigns, c)
		}
		found := campaign.FindByTag(campaigns, *find)
		if len(found) == 0 {
			fmt.Fprintf(os.Stderr, "No campaigns found with tag %q\n", *find)
			return
		}
		for _, c := range found {
			fmt.Printf("  %s [%s]\n", c.Meta.Name, c.Meta.Severity)
		}
		fmt.Fprintf(os.Stderr, "\n%d campaign(s) with tag %q\n", len(found), *find)
		return
	}

	summary, err := campaign.ListTagsDir(campDir)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "analyzing tags"))
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(summary)
		return
	}

	fmt.Print(campaign.FormatTagSummary(summary))

	if *suggest && len(summary.Suggestions) > 0 {
		fmt.Println("\nSuggestions:")
		for _, s := range summary.Suggestions {
			fmt.Printf("  %s → %s\n", s.CampaignName, strings.Join(s.Suggested, ", "))
			for _, r := range s.Reasons {
				fmt.Printf("    %s\n", r)
			}
		}
	}
}

// --- report ---

func cmdReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory (default: auto-detect)")
	format := fs.String("format", "text", "output format: text, markdown")
	output := fs.String("output", "", "output file (default: stdout)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho report [flags]

Generate an executive assessment report combining analytics, risk scores,
coverage data, and recommendations into one comprehensive document.

Examples:
  threatecho report
  threatecho report -format markdown -output report.md
  threatecho report -json
  threatecho report -dir campaigns/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	campDir := *dir
	if campDir == "" {
		campDir = findCampaignDir()
	}

	rpt, err := campaign.GenerateReportDir(campDir)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "generating report"))
	}

	var data []byte
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rpt)
		return
	}

	checkFormat(*format, "text", "markdown", "md")

	switch *format {
	case "text":
		data = []byte(campaign.FormatReportText(rpt))
	case "markdown", "md":
		data = []byte(campaign.FormatReportMarkdown(rpt))
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0o644); err != nil {
			exitErr(cli.IOWrap(err, "writing report"))
		}
		fmt.Fprintf(os.Stderr, "✓ Report written to %s\n", *output)
	} else {
		os.Stdout.Write(data)
	}
}

// --- audit ---

func cmdAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory (default: auto-detect)")
	output := fs.String("output", "", "save snapshot JSON to file")
	compareTo := fs.String("compare", "", "compare against a previous snapshot JSON file")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho audit [flags]

Campaign state snapshot and change tracking.
Creates a point-in-time snapshot of all campaigns, or compares the current
state against a previous snapshot to detect changes.

Examples:
  threatecho audit                         # show current snapshot
  threatecho audit -output snapshot.json   # save snapshot to file
  threatecho audit -compare old.json       # compare current state vs saved snapshot
  threatecho audit -json                   # snapshot as JSON to stdout

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	campDir := *dir
	if campDir == "" {
		campDir = findCampaignDir()
	}

	snap, err := campaign.TakeSnapshotDir(campDir)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "taking snapshot"))
	}

	// If comparing, load old snapshot and diff.
	if *compareTo != "" {
		oldData, err := os.ReadFile(*compareTo)
		if err != nil {
			exitErr(cli.IOWrap(err, "reading previous snapshot"))
		}
		oldSnap, err := campaign.SnapshotFromJSON(oldData)
		if err != nil {
			exitErr(cli.RuntimeWrap(err, "parsing previous snapshot"))
		}
		diff := campaign.DiffSnapshots(oldSnap, snap)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(diff)
			return
		}
		fmt.Print(campaign.FormatSnapshotDiff(diff))
		return
	}

	// Save or display snapshot.
	if *output != "" {
		data, err := campaign.SnapshotToJSON(snap)
		if err != nil {
			exitErr(cli.RuntimeWrap(err, "serializing snapshot"))
		}
		if err := os.WriteFile(*output, data, 0o644); err != nil {
			exitErr(cli.IOWrap(err, "writing snapshot"))
		}
		fmt.Fprintf(os.Stderr, "✓ Snapshot saved to %s (%d campaigns, %d stages)\n",
			*output, snap.CampaignCount, snap.TotalStages)
		return
	}

	if *jsonOut {
		data, err := campaign.SnapshotToJSON(snap)
		if err != nil {
			exitErr(cli.RuntimeWrap(err, "serializing snapshot"))
		}
		os.Stdout.Write(data)
		fmt.Fprintln(os.Stdout)
		return
	}

	fmt.Print(campaign.FormatSnapshot(snap))
}

// --- baseline ---

func cmdBaseline(args []string) {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory to build baseline from")
	label := fs.String("label", "baseline", "label for the baseline snapshot")
	output := fs.String("output", "", "save baseline to JSON file")
	compare := fs.String("compare", "", "compare current state against a saved baseline JSON")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho baseline [flags]

Build behavioral baselines from campaigns and detect drift over time.
Captures tools, tactics, techniques, severities, platforms, and execution
patterns as a "normal" profile. Subsequent runs compare against a saved
baseline to detect meaningful changes.

Modes:
  Build:   threatecho baseline -dir campaigns/ -output baseline.json
  Drift:   threatecho baseline -dir campaigns/ -compare baseline.json
  View:    threatecho baseline -dir campaigns/

Examples:
  threatecho baseline -dir campaigns/ -label "v1.0-release" -output baseline.json
  threatecho baseline -dir campaigns/ -compare baseline.json
  threatecho baseline -dir campaigns/ -json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	campaignDir := resolveCampaignDir(*dir)
	if campaignDir == "" {
		fs.Usage()
		exitUsage()
	}

	// Drift comparison mode.
	if *compare != "" {
		savedBaseline, err := campaign.BaselineFromFile(*compare)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading baseline"))
		}

		dr, err := campaign.DetectDriftDir(savedBaseline, campaignDir)
		if err != nil {
			exitErr(cli.IOWrap(err, "detecting drift"))
		}

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(dr); err != nil {
				exitRuntime("JSON output failed: %s", err)
			}
			return
		}

		fmt.Print(campaign.FormatDriftReport(dr))

		// Exit non-zero if drift is high or critical for CI usage.
		if dr.DriftLevel == "high" || dr.DriftLevel == "critical" {
			os.Exit(cli.ExitPolicyDenied)
		}
		return
	}

	// Build baseline mode.
	bl, err := campaign.BuildBaselineDir(campaignDir, *label)
	if err != nil {
		exitErr(cli.IOWrap(err, "building baseline"))
	}

	if *output != "" {
		data, err := campaign.BaselineToJSON(bl)
		if err != nil {
			exitErr(cli.RuntimeWrap(err, "serializing baseline"))
		}
		if err := os.WriteFile(*output, data, 0o644); err != nil {
			exitErr(cli.IOWrap(err, "writing baseline"))
		}
		fmt.Fprintf(os.Stderr, "✓ Baseline saved to %s (%d campaigns, %d stages, label: %s)\n",
			*output, bl.Campaigns, bl.Stages, bl.Label)
		return
	}

	if *jsonOut {
		data, err := campaign.BaselineToJSON(bl)
		if err != nil {
			exitErr(cli.RuntimeWrap(err, "serializing baseline"))
		}
		os.Stdout.Write(data)
		fmt.Fprintln(os.Stdout)
		return
	}

	fmt.Print(campaign.FormatBaseline(bl))
}

// --- trace ---

func cmdTrace(args []string) {
	// Check if the first arg is a subcommand.
	if len(args) > 0 {
		switch args[0] {
		case "replay":
			cmdTraceReplay(args[1:])
			return
		case "correlate":
			cmdTraceCorrelate(args[1:])
			return
		case "forensics":
			cmdTraceForensics(args[1:])
			return
		}
	}

	// Default behavior: analyze trace file (backward compatible).
	cmdTraceAnalyze(args)
}

func cmdTraceAnalyze(args []string) {
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	policyPath := fs.String("policy", "", "policy to evaluate trace against")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho trace [flags] <trace-file.json>
       threatecho trace replay [flags] <trace-file.json>

Analyze agent execution traces against policies. Traces are JSON files
recording what an AI agent actually did — tool calls, prompts, responses,
guardrail triggers, and inter-agent messages.

Without -policy, shows trace statistics (event counts, tools used, etc.).
With -policy, evaluates the trace against the policy and reports violations.
Exit code 2 when any tool calls are denied by the policy.

Subcommands:
  replay      Replay a trace and detect anomalies
  correlate   Correlate multiple traces to detect cross-agent attack patterns
  forensics   Forensic analysis with evidence chains and IOC extraction

Examples:
  threatecho trace agent-trace.json
  threatecho trace -policy policies/agent-strict/ agent-trace.json
  threatecho trace replay agent-trace.json
  threatecho trace correlate trace1.json trace2.json trace3.json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	tr, err := policy.ParseTraceFile(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "parsing trace"))
	}

	// Without policy: show trace statistics.
	if *policyPath == "" {
		stats := policy.AnalyzeTrace(tr)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(stats); err != nil {
				exitRuntime("JSON output failed: %s", err)
			}
			return
		}
		fmt.Print(policy.FormatTraceStats(stats))
		return
	}

	// With policy: evaluate trace against policy.
	polPath := *policyPath
	if polPath == "" && cfg.DefaultPolicy != "" {
		polPath = cfg.DefaultPolicy
	}

	p, err := policy.LoadPolicy(polPath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	errs := policy.ValidatePolicy(p)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(p.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	result := policy.EvaluateTrace(p, tr)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
		return
	}

	fmt.Print(policy.FormatTraceEval(result))

	if result.DeniedCount > 0 {
		os.Exit(cli.ExitPolicyDenied)
	}
}

func cmdTraceReplay(args []string) {
	fs := flag.NewFlagSet("trace replay", flag.ExitOnError)
	policyPath := fs.String("policy", "", "optional policy to check denied actions")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho trace replay [flags] <trace-file.json>

Replay an agent execution trace and detect anomalies:
  - elevated tool calls without proper authorization
  - rapid tool calls (burst detection)
  - timestamp gaps and ordering issues
  - prompt injection patterns
  - data exfiltration indicators
  - privilege escalation attempts

With -policy, also checks tool calls against policy for denied actions.

Examples:
  threatecho trace replay agent-trace.json
  threatecho trace replay -policy policies/agent-strict/ agent-trace.json
  threatecho trace replay -json agent-trace.json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "✗ trace replay requires a trace file path")
		os.Exit(cli.ExitUsage)
	}

	tr, err := policy.ParseTraceFile(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "parsing trace"))
	}

	cfg := trace.DefaultReplayConfig()

	var result *trace.ReplayResult
	if *policyPath != "" {
		p, pErr := policy.LoadPolicy(*policyPath)
		if pErr != nil {
			exitErr(cli.IOWrap(pErr, "loading policy"))
		}
		result = trace.ReplayTraceWithPolicy(tr, p, cfg)
	} else {
		result = trace.ReplayTrace(tr, cfg)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(result); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(trace.FormatReplayResult(result))
	}
}

func cmdTraceCorrelate(args []string) {
	fs := flag.NewFlagSet("trace correlate", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho trace correlate [flags] <trace1.json> [trace2.json ...]

Correlate multiple agent execution traces to detect cross-agent attack
patterns that are invisible when analyzing traces in isolation:
  - temporal bursts (coordinated rapid activity)
  - tool sequence attacks (recon → exploit → exfil chains)
  - privilege escalation chains across agents
  - data convergence (multiple agents touching same targets)
  - target sweeps (systematic scanning)
  - coordinated access patterns
  - relay attacks (agent-to-agent delegation abuse)
  - boundary probing (repeated authorization failures)

Requires at least two trace files.

Examples:
  threatecho trace correlate agent-a.json agent-b.json agent-c.json
  threatecho trace correlate -json traces/*.json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "✗ trace correlate requires at least two trace files")
		os.Exit(cli.ExitUsage)
	}

	var traces []*policy.Trace
	for _, path := range fs.Args() {
		tr, err := policy.ParseTraceFile(path)
		if err != nil {
			exitErr(cli.IOWrap(err, "parsing trace %s", path))
		}
		traces = append(traces, tr)
	}

	report := trace.CorrelateTraces(traces)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(report); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(trace.FormatCorrelationReport(report))
	}
}

func cmdTraceForensics(args []string) {
	fs := flag.NewFlagSet("trace forensics", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho trace forensics [flags] <trace1.json> [trace2.json ...]

Perform forensic analysis on agent execution traces for incident response:
  - evidence extraction and chain building (exfil, escalation, recon, injection, lateral)
  - chronological timeline reconstruction across traces
  - indicator of compromise (IOC) extraction
  - SHA-256 checksums for chain-of-custody integrity

Examples:
  threatecho trace forensics agent-trace.json
  threatecho trace forensics -json trace1.json trace2.json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "✗ trace forensics requires at least one trace file")
		os.Exit(cli.ExitUsage)
	}

	var traces []*policy.Trace
	for _, path := range fs.Args() {
		tr, err := policy.ParseTraceFile(path)
		if err != nil {
			exitErr(cli.IOWrap(err, "parsing trace %s", path))
		}
		traces = append(traces, tr)
	}

	rpt := trace.AnalyzeForensics(traces)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(rpt); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(trace.FormatForensicReport(rpt))
	}
}

// --- agent ---

func cmdAgent(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent <subcommand> [flags] [args]

Manage the agent inventory and analyze trust relationships between
AI agents in the monitored environment.

Subcommands:
  list       List agents in the inventory
  show       Show details of a specific agent
  validate   Validate an agent definition file
  trust      Analyze trust relationships and risks
  test       Evaluate agent tool coverage against a policy
  guardrail  Analyze guardrail coverage and gaps
  graph      Visualize agent trust graph (DOT/Mermaid/text)
  export     Export inventory report (JSON/YAML/Markdown)
  chain      Analyze multi-agent delegation chains for violations
  attest     Generate cryptographic attestations for agent configurations
  profile    Build behavioral profiles from agent traces
  dependency Map inter-agent dependencies and compute blast radius

Examples:
  threatecho agent list -dir agents/
  threatecho agent show agents/billing-agent/
  threatecho agent validate agents/support-agent/agent.yaml
  threatecho agent trust -dir agents/ -json
  threatecho agent test -policy policies/agent-strict/ agents/billing-agent/
  threatecho agent guardrail agents/billing-agent/

`)
		exitUsage()
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		cmdAgentList(rest)
	case "show":
		cmdAgentShow(rest)
	case "validate":
		cmdAgentValidate(rest)
	case "trust":
		cmdAgentTrust(rest)
	case "test":
		cmdAgentTest(rest)
	case "guardrail":
		cmdAgentGuardrail(rest)
	case "graph":
		cmdAgentGraph(rest)
	case "export":
		cmdAgentExport(rest)
	case "chain":
		cmdAgentChain(rest)
	case "attest":
		cmdAgentAttest(rest)
	case "profile":
		cmdAgentProfile(rest)
	case "dependency":
		cmdAgentDependency(rest)
	case "-h", "--help", "help":
		helpRequested = true
		cmdAgent(nil)
	default:
		fmt.Fprintf(os.Stderr, "unknown agent subcommand: %s\nValid subcommands: list, show, validate, trust, test, guardrail, graph, export, chain, attest, profile, dependency\n", sub)
		exitUsage()
	}
}

func cmdAgentList(args []string) {
	fs := flag.NewFlagSet("agent list", flag.ExitOnError)
	dir := fs.String("dir", "", "agents directory (default: auto-detect)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent list [flags]

List all agents found in the inventory directory. Each agent is defined
in an agent.yaml file.

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	agentDir := *dir
	if agentDir == "" {
		agentDir = findAgentDir()
	}
	if agentDir == "" {
		exitValidation("no agents directory found (use -dir to specify)")
	}

	inv, err := agent.LoadInventory(agentDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading agent inventory"))
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(inv.Agents)
		return
	}

	fmt.Print(agent.FormatInventory(inv))
}

func cmdAgentShow(args []string) {
	fs := flag.NewFlagSet("agent show", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent show [flags] <agent-path>

Show detailed information about a single agent definition.

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	a, err := agent.LoadAgent(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading agent"))
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(a)
		return
	}

	fmt.Print(agent.FormatAgent(a))
}

func cmdAgentValidate(args []string) {
	fs := flag.NewFlagSet("agent validate", flag.ExitOnError)
	dir := fs.String("dir", "", "validate all agents in directory")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent validate [flags] [agent-path...]

Validate agent definition files for correctness. Checks:
  • Required fields (name, type, trust level)
  • Valid agent type and trust level values
  • Tool access declarations
  • Guardrail configuration

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *dir != "" {
		inv, err := agent.LoadInventory(*dir)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading agents"))
		}
		anyErrors := false
		for _, a := range inv.Agents {
			errs := agent.ValidateAgent(a)
			if len(errs) > 0 {
				anyErrors = true
				fmt.Fprintf(os.Stderr, "✗ Agent %q: %d errors\n", a.Meta.Name, len(errs))
				for _, e := range errs {
					fmt.Fprintf(os.Stderr, "    • %s\n", e)
				}
			} else {
				fmt.Fprintf(os.Stderr, "✓ Agent %q is valid\n", a.Meta.Name)
			}
		}
		if anyErrors {
			os.Exit(cli.ExitValidation)
		}
		return
	}

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	for _, path := range fs.Args() {
		a, err := agent.LoadAgent(path)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading agent"))
		}
		errs := agent.ValidateAgent(a)
		if len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "✗ Agent %q: %d errors\n", a.Meta.Name, len(errs))
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "    • %s\n", e)
			}
			os.Exit(cli.ExitValidation)
		}
		fmt.Fprintf(os.Stderr, "✓ Agent %q is valid (%d tools, trust: %s)\n",
			a.Meta.Name, len(a.Tools), a.Trust.Level)
	}
}

func cmdAgentTrust(args []string) {
	fs := flag.NewFlagSet("agent trust", flag.ExitOnError)
	dir := fs.String("dir", "", "agents directory (default: auto-detect)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent trust [flags]

Analyze trust relationships between agents in the inventory. Detects:
  • Escalation paths (low-trust → high-trust chains)
  • Over-trusted agents (trusted by many + high capabilities)
  • Missing guardrails on tool-calling agents
  • Trust boundary gaps

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	agentDir := *dir
	if agentDir == "" {
		agentDir = findAgentDir()
	}
	if agentDir == "" {
		exitValidation("no agents directory found (use -dir to specify)")
	}

	inv, err := agent.LoadInventory(agentDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading agent inventory"))
	}

	if len(inv.Agents) == 0 {
		fmt.Fprintf(os.Stderr, "no agents found in %s\n", agentDir)
		return
	}

	analysis := inv.AnalyzeTrust()

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(analysis)
		return
	}

	fmt.Print(agent.FormatTrustAnalysis(analysis))

	if len(analysis.Risks) > 0 {
		os.Exit(cli.ExitPolicyDenied)
	}
}

func cmdAgentTest(args []string) {
	fs := flag.NewFlagSet("agent test", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to policy directory to test against (required)")
	dir := fs.String("dir", "", "agents directory for inventory-wide test (default: auto-detect)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent test [flags] [agent-path]

Evaluate how well a policy covers an agent's declared tools and capabilities.
Reports tool coverage gaps, missing guardrails, overpermissive access, and
rate limit issues. Each agent-policy binding receives a coverage score (A-F).

When an agent-path is provided, tests that single agent. Without one, tests
the entire inventory (equivalent to -dir).

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *policyPath == "" {
		exitValidation("-policy is required (path to the policy to test against)")
	}

	// Load the policy.
	p, err := policy.LoadPolicy(*policyPath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy from %s", *policyPath))
	}

	// Single agent mode.
	if fs.NArg() > 0 {
		agentPath := fs.Arg(0)
		a, loadErr := agent.LoadAgent(agentPath)
		if loadErr != nil {
			exitErr(cli.IOWrap(loadErr, "loading agent from %s", agentPath))
		}

		result := agent.EvaluateBinding(a, p)

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(result)
			return
		}

		fmt.Print(agent.FormatBinding(result))

		if len(result.UncoveredTools) > 0 || len(result.ElevatedUncovered) > 0 {
			os.Exit(cli.ExitPolicyDenied)
		}
		return
	}

	// Inventory mode.
	agentDir := *dir
	if agentDir == "" {
		agentDir = findAgentDir()
	}
	if agentDir == "" {
		exitValidation("no agents directory found (use -dir or provide an agent-path)")
	}

	inv, loadErr := agent.LoadInventory(agentDir)
	if loadErr != nil {
		exitErr(cli.IOWrap(loadErr, "loading agent inventory"))
	}

	if len(inv.Agents) == 0 {
		fmt.Fprintf(os.Stderr, "no agents found in %s\n", agentDir)
		return
	}

	report := inv.EvaluateAll(p)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		return
	}

	fmt.Print(agent.FormatInventoryBinding(report))

	if report.FullyCovered < report.TotalAgents {
		os.Exit(cli.ExitPolicyDenied)
	}
}

func cmdAgentGuardrail(args []string) {
	fs := flag.NewFlagSet("agent guardrail", flag.ExitOnError)
	dir := fs.String("dir", "", "agents directory for inventory-wide analysis (default: auto-detect)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent guardrail [flags] [agent-path]

Analyze guardrail coverage for an agent or the entire inventory.
Detects missing, unenforced, insufficient, and redundant guardrails
based on the agent's capabilities, trust level, and tool access.

When an agent-path is provided, analyzes that single agent. Without
one, analyzes the entire inventory.

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	// Single agent mode.
	if fs.NArg() > 0 {
		agentPath := fs.Arg(0)
		a, err := agent.LoadAgent(agentPath)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading agent from %s", agentPath))
		}

		report := agent.AnalyzeGuardrails(a)

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(report)
			return
		}

		fmt.Print(agent.FormatGuardrailReport(report))

		if len(report.Gaps) > 0 {
			os.Exit(cli.ExitPolicyDenied)
		}
		return
	}

	// Inventory mode.
	agentDir := *dir
	if agentDir == "" {
		agentDir = findAgentDir()
	}
	if agentDir == "" {
		exitValidation("no agents directory found (use -dir or provide an agent-path)")
	}

	inv, err := agent.LoadInventory(agentDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading agent inventory"))
	}

	if len(inv.Agents) == 0 {
		fmt.Fprintf(os.Stderr, "no agents found in %s\n", agentDir)
		return
	}

	report := inv.AnalyzeAllGuardrails()

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		return
	}

	fmt.Print(agent.FormatInventoryGuardrailReport(report))

	if report.CriticalGaps > 0 {
		os.Exit(cli.ExitPolicyDenied)
	}
}

func cmdAgentExport(args []string) {
	fs := flag.NewFlagSet("agent export", flag.ExitOnError)
	dir := fs.String("dir", "", "agents directory (default: auto-detect)")
	format := fs.String("format", "json", "output format: json, yaml, markdown")
	output := fs.String("output", "", "write to file instead of stdout")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent export [flags]

Export the agent inventory as a structured report including trust analysis
and guardrail coverage. Useful for documentation, auditing, and CI/CD.

Output formats:
  json       JSON document (default)
  yaml       YAML document
  markdown   Markdown report with tables and sections

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	agentDir := *dir
	if agentDir == "" {
		agentDir = findAgentDir()
	}
	if agentDir == "" {
		exitValidation("no agents directory found (use -dir to specify)")
	}

	inv, err := agent.LoadInventory(agentDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading agent inventory"))
	}

	snap := agent.ExportInventory(inv)

	checkFormat(*format, "json", "yaml", "markdown")

	var data []byte
	switch *format {
	case "yaml":
		data, err = agent.ExportYAML(snap)
	case "markdown":
		data = []byte(agent.ExportMarkdown(snap))
	default:
		data, err = agent.ExportJSON(snap)
	}

	if err != nil {
		exitErr(cli.IOWrap(err, "exporting inventory"))
	}

	if *output != "" {
		if writeErr := os.WriteFile(*output, data, 0644); writeErr != nil {
			exitErr(cli.IOWrap(writeErr, "writing output file"))
		}
		fmt.Fprintf(os.Stderr, "✓ Exported %d agents to %s\n", snap.AgentCount, *output)
		return
	}

	fmt.Print(string(data))
}

func cmdAgentGraph(args []string) {
	fs := flag.NewFlagSet("agent graph", flag.ExitOnError)
	dir := fs.String("dir", "", "agents directory (default: auto-detect)")
	format := fs.String("format", "text", "output format: text, dot, mermaid")
	jsonOut := fs.Bool("json", false, "output graph data as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent graph [flags]

Visualize the trust graph between agents in the inventory. Shows trust
relationships, escalation paths, and risk indicators.

Output formats:
  text      Terminal-friendly box-drawing report (default)
  dot       Graphviz DOT format (pipe to 'dot -Tpng' for images)
  mermaid   Mermaid diagram format (paste into Mermaid-compatible viewers)

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	agentDir := *dir
	if agentDir == "" {
		agentDir = findAgentDir()
	}
	if agentDir == "" {
		exitValidation("no agents directory found (use -dir to specify)")
	}

	inv, err := agent.LoadInventory(agentDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading agent inventory"))
	}

	if len(inv.Agents) == 0 {
		fmt.Fprintf(os.Stderr, "no agents found in %s\n", agentDir)
		return
	}

	graph := agent.BuildTrustGraph(inv)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(graph)
		return
	}

	checkFormat(*format, "text", "dot", "mermaid")

	switch *format {
	case "dot":
		fmt.Print(graph.FormatDOT())
	case "mermaid":
		fmt.Print(graph.FormatMermaid())
	default:
		fmt.Print(graph.FormatText())
	}
}

func findAgentDir() string {
	candidates := []string{"agents", "agents/", "../agents"}
	for _, d := range candidates {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			return d
		}
	}
	return ""
}

// findCampaignDir walks up from cwd looking for a campaigns/ directory.
func findCampaignDir() string {
	dir, _ := os.Getwd()
	for {
		candidate := filepath.Join(dir, "campaigns")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "campaigns"
}

// --- policy compile ---

func cmdPolicyCompile(args []string) {
	fs := flag.NewFlagSet("policy compile", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy compile [flags] <policy-path>

Compile a policy, detect rule conflicts, and show compilation statistics.
Conflict detection finds rules that match the same tool/tactic/action
with different effects (e.g., one deny and one allow for the same tool).

Examples:
  threatecho policy compile policies/agent-strict/
  threatecho policy compile -json policies/agent-default/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	p, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	errs := policy.ValidatePolicy(p)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(p.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	cp := policy.Compile(p)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(cp.Stats); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
		return
	}

	fmt.Print(policy.FormatCompileResult(cp))

	if len(cp.Conflicts) > 0 {
		os.Exit(cli.ExitPolicyDenied)
	}
}

// --- policy merge ---

func cmdPolicyMerge(args []string) {
	fs := flag.NewFlagSet("policy merge", flag.ExitOnError)
	output := fs.String("output", "", "write merged policy to file")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy merge [flags] <policy-path> <policy-path> [...]

Merge multiple policies into one. Rules from all policies are combined
with unique IDs (prefixed with source policy name if there are collisions).
The first policy's metadata and agent scope are used as the base.

Examples:
  threatecho policy merge policies/agent-default/ policies/agent-strict/
  threatecho policy merge -output merged.yaml policies/soc-baseline/ policies/agent-default/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fs.Usage()
		exitUsage()
	}

	var policies []*policy.Policy
	for i := 0; i < fs.NArg(); i++ {
		p, err := policy.LoadPolicy(fs.Arg(i))
		if err != nil {
			exitErr(cli.IOWrap(err, "loading policy %s", fs.Arg(i)))
		}
		policies = append(policies, p)
	}

	merged := policy.MergePolicies(policies...)

	data, err := marshalYAML(merged)
	if err != nil {
		exitRuntime("serializing merged policy: %s", err)
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0o644); err != nil {
			exitErr(cli.IOWrap(err, "writing merged policy"))
		}
		fmt.Fprintf(os.Stderr, "✓ Merged %d policies (%d rules) → %s\n",
			len(policies), len(merged.Rules), *output)
		return
	}

	os.Stdout.Write(data)
}

// --- policy coverage ---

func cmdPolicyCoverage(args []string) {
	fs := flag.NewFlagSet("policy coverage", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory for reference tool extraction")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy coverage [flags] <policy-path>

Analyze what a policy covers — which tools, tactics, and actions have
explicit rules and which are unprotected. With -dir, extracts the
reference tool set from actual campaigns.

Examples:
  threatecho policy coverage policies/agent-strict/
  threatecho policy coverage -dir campaigns/ policies/agent-strict/
  threatecho policy coverage -json policies/agent-default/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	p, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	// Build reference tool list from campaigns if -dir is provided.
	var refTools []string
	campaignDir := resolveCampaignDir(*dir)
	if campaignDir != "" {
		summaries, loadErr := campaign.LoadDir(campaignDir)
		if loadErr == nil {
			toolSet := make(map[string]bool)
			for _, s := range summaries {
				c, cErr := campaign.Load(s.Path)
				if cErr != nil {
					continue
				}
				for _, stage := range c.Stages {
					tools := policy.InferTools(stage)
					for _, t := range tools {
						toolSet[t] = true
					}
				}
			}
			for t := range toolSet {
				refTools = append(refTools, t)
			}
			sort.Strings(refTools)
		}
	}

	cr := policy.AnalyzeCoverage(p, refTools)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(cr); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
		return
	}

	fmt.Print(policy.FormatCoverage(cr))
}

// --- policy test ---

func cmdPolicyTest(args []string) {
	fs := flag.NewFlagSet("policy test", flag.ExitOnError)
	scenario := fs.String("scenario", "", "specific scenario to test (default: all)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	listScenarios := fs.Bool("list", false, "list available test scenarios")
	suiteFile := fs.String("suite", "", "run assertion test suite from YAML file")
	generateSuite := fs.Bool("generate", false, "generate a test suite skeleton for the policy")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy test [flags] <policy-path>

Test a policy against built-in agent attack scenarios or custom
assertion test suites.

Modes:
  Scenarios:  threatecho policy test policies/agent-strict/
  Assertions: threatecho policy test -suite tests.yaml policies/agent-strict/
  Generate:   threatecho policy test -generate policies/agent-strict/

Built-in scenarios model common attack patterns:
  benign-rag          Normal RAG agent behavior (should pass)
  prompt-injection    Prompt injection via user input
  tool-abuse          Unauthorized shell/file operations
  data-exfiltration   Sensitive data sent to external endpoints
  agent-propagation   Inter-agent message injection
  elevated-execution  Commands with elevated privileges

Assertion test suites define explicit expectations per tool call:
  - Expected effect (deny/allow/alert) per tool+tactic combination
  - Expected matching rule ID
  - Expected no-match for uncovered tools
  - YAML format: see 'threatecho policy test -generate' for examples

Examples:
  threatecho policy test policies/agent-strict/
  threatecho policy test -scenario tool-abuse policies/agent-default/
  threatecho policy test -suite policy-tests.yaml policies/agent-default/
  threatecho policy test -generate policies/agent-strict/
  threatecho policy test -list
  threatecho policy test -json policies/agent-strict/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *listScenarios {
		scenarios := policy.ExampleScenarios()
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(scenarios)
			return
		}
		fmt.Println("Available test scenarios:")
		fmt.Println()
		for _, s := range scenarios {
			risk := s.Risk
			switch risk {
			case "critical":
				risk = "🔴 " + risk
			case "high":
				risk = "🟠 " + risk
			case "none":
				risk = "🟢 " + risk
			}
			fmt.Printf("  %-22s %-12s %s\n", s.Name, risk, s.Description)
		}
		fmt.Println()
		return
	}

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	p, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	errs := policy.ValidatePolicy(p)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(p.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	// Generate test suite skeleton.
	if *generateSuite {
		ts := policy.GenerateTestSuite(p)
		data, _ := yaml.Marshal(ts)
		fmt.Print(string(data))
		return
	}

	// Run assertion test suite.
	if *suiteFile != "" {
		ts, err := policy.LoadTestSuite(*suiteFile)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading test suite"))
		}
		validErrs := policy.ValidateTestSuite(ts)
		if len(validErrs) > 0 {
			fmt.Fprintf(os.Stderr, "✗ Test suite validation errors:\n")
			for _, e := range validErrs {
				fmt.Fprintf(os.Stderr, "  - %s\n", e)
			}
			os.Exit(cli.ExitValidation)
		}
		result := policy.RunTestSuite(p, ts)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(result)
		} else {
			fmt.Print(policy.FormatTestResults(result))
		}
		if result.Failed > 0 {
			os.Exit(cli.ExitPolicyDenied)
		}
		return
	}

	// Determine which scenarios to run.
	scenarios := policy.ExampleScenarios()
	if *scenario != "" {
		found := false
		for _, s := range scenarios {
			if s.Name == *scenario {
				scenarios = []policy.ScenarioInfo{s}
				found = true
				break
			}
		}
		if !found {
			exitValidation("unknown scenario: %s (use -list to see available)", *scenario)
		}
	}

	type testResult struct {
		Scenario    string `json:"scenario"`
		Description string `json:"description"`
		Risk        string `json:"risk"`
		Denied      int    `json:"denied"`
		Alerted     int    `json:"alerted"`
		Allowed     int    `json:"allowed"`
		Verdict     string `json:"verdict"`
	}

	var results []testResult
	anyFail := false

	for _, s := range scenarios {
		trace := policy.ExampleTrace(s.Name)
		if trace == nil {
			continue
		}

		evalResult := policy.EvaluateTrace(p, trace)

		verdict := "PASS"
		if s.Risk == "none" {
			// Benign scenario: should have zero denials.
			if evalResult.DeniedCount > 0 {
				verdict = "FAIL (false positive)"
				anyFail = true
			}
		} else {
			// Attack scenario: should have denials.
			if evalResult.DeniedCount > 0 {
				verdict = "BLOCKED"
			} else if evalResult.AlertedCount > 0 {
				verdict = "ALERTED"
			} else {
				verdict = "MISSED"
				anyFail = true
			}
		}

		results = append(results, testResult{
			Scenario:    s.Name,
			Description: s.Description,
			Risk:        s.Risk,
			Denied:      evalResult.DeniedCount,
			Alerted:     evalResult.AlertedCount,
			Allowed:     evalResult.AllowedCount,
			Verdict:     verdict,
		})
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
		if anyFail {
			os.Exit(cli.ExitPolicyDenied)
		}
		return
	}

	// Print formatted results.
	fmt.Printf("┌─────────────────────────────────────────────────────────────┐\n")
	fmt.Printf("│         Policy Test Results: %-30s │\n", p.Meta.Name)
	fmt.Printf("├─────────────────────────────────────────────────────────────┤\n")

	passed := 0
	blocked := 0
	alerted := 0
	missed := 0

	for _, r := range results {
		icon := "✓"
		switch r.Verdict {
		case "BLOCKED":
			icon = "🛡"
			blocked++
		case "ALERTED":
			icon = "⚠"
			alerted++
		case "MISSED":
			icon = "✗"
			missed++
		case "PASS":
			icon = "✓"
			passed++
		case "FAIL (false positive)":
			icon = "✗"
			missed++
		}

		fmt.Printf("│ %s %-24s %-10s %-20s │\n", icon, r.Scenario, r.Risk, r.Verdict)
	}

	fmt.Printf("├─────────────────────────────────────────────────────────────┤\n")
	fmt.Printf("│ Summary: %d passed, %d blocked, %d alerted, %d missed       │\n",
		passed, blocked, alerted, missed)
	fmt.Printf("└─────────────────────────────────────────────────────────────┘\n")

	if anyFail {
		os.Exit(cli.ExitPolicyDenied)
	}
}

// --- policy generate ---

func cmdPolicyGenerate(args []string) {
	fs := flag.NewFlagSet("policy generate", flag.ExitOnError)
	agent := fs.String("agent", "*", "agent name for the generated policy")
	name := fs.String("name", "", "policy name (defaults to template name)")
	output := fs.String("output", "", "write policy to file")
	listTemplates := fs.Bool("list", false, "list available templates")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy generate [flags] <template-name>

Generate a policy from a built-in template. Templates provide pre-configured,
parameterized rule sets for common agent architectures and security postures.

Templates:
  agent-minimal            Basic deny-by-default policy (4 rules)
  agent-strict             Comprehensive strict policy (9 rules)
  rag-safe                 RAG-specific policy (7 rules)
  tool-calling-restricted  Allowlist-only tool calling policy (2 rules)
  autonomous-guardrailed   Guardrailed autonomous agent policy (6 rules)
  compliance-soc2          SOC 2 compliance-oriented policy (8 rules)

Examples:
  threatecho policy generate agent-strict
  threatecho policy generate -agent "my-agent" -name "prod-v1" agent-strict
  threatecho policy generate -output policy.yaml rag-safe
  threatecho policy generate -list

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *listTemplates {
		catalog := policy.ListTemplates()
		fmt.Print(policy.FormatTemplateCatalog(catalog))
		return
	}

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	templateName := fs.Arg(0)
	policyName := *name
	if policyName == "" {
		policyName = templateName
	}

	cfg := policy.DefaultTemplateConfig()
	cfg.Values["agent_name"] = *agent
	cfg.Values["policy_name"] = policyName

	p, err := policy.RenderTemplate(templateName, cfg)
	if err != nil {
		exitValidation("template error: %s", err)
	}

	data, err := marshalYAML(p)
	if err != nil {
		exitRuntime("serializing policy: %s", err)
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0o644); err != nil {
			exitErr(cli.IOWrap(err, "writing policy"))
		}
		fmt.Fprintf(os.Stderr, "✓ Generated %q policy from template %q → %s (%d rules)\n",
			policyName, templateName, *output, len(p.Rules))
		return
	}

	os.Stdout.Write(data)
}

// --- completion ---

func cmdCompletion(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: threatecho completion <shell>

Generate shell completion scripts for threatecho.

Shells:
  bash    Bash completion (source in .bashrc)
  zsh     Zsh completion (add to fpath)
  fish    Fish completion (save to completions dir)

Setup:
  # Bash
  threatecho completion bash > /etc/bash_completion.d/threatecho
  # or
  source <(threatecho completion bash)

  # Zsh
  threatecho completion zsh > "${fpath[1]}/_threatecho"

  # Fish
  threatecho completion fish > ~/.config/fish/completions/threatecho.fish
`)
		exitUsage()
	}

	shell := args[0]
	switch shell {
	case "bash":
		cli.BashCompletion(os.Stdout)
	case "zsh":
		cli.ZshCompletion(os.Stdout)
	case "fish":
		cli.FishCompletion(os.Stdout)
	case "-h", "--help", "help":
		helpRequested = true
		cmdCompletion(nil)
	default:
		fmt.Fprintf(os.Stderr, "unknown shell: %s (supported: bash, zsh, fish)\n", shell)
		exitUsage()
	}
}

// --- profile ---

func cmdProfile(args []string) {
	fs := flag.NewFlagSet("profile", flag.ExitOnError)
	dir := fs.String("dir", "", "profile all campaigns in directory")
	format := fs.String("format", "text", "output format: text, json")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho profile [flags] [campaign-path...]

Detailed campaign complexity profile with metrics:
  - Size: stages, techniques, tactics, telemetry, detections
  - Framework coverage: ATT&CK, ATLAS, OWASP breakdown
  - Execution profile: shell/http/file/registry/service/elevated
  - Dependency graph: depth, width, entry/terminal nodes
  - Quality: detection and telemetry coverage percentages
  - Complexity score (0-100) and grade (A-E)

With -dir, profiles all campaigns and shows a comparison table
sorted by complexity score.

Examples:
  threatecho profile campaigns/apt29-cozy-bear/
  threatecho profile -dir campaigns/
  threatecho profile -format json campaigns/llm-agent-hijack/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	outFmt := resolveFormat(*format)

	if *dir != "" {
		profiles, err := campaign.ProfileDir(*dir)
		if err != nil {
			exitErr(cli.IOWrap(err, "profiling campaigns"))
		}
		if len(profiles) == 0 {
			exitIO("no campaigns found in %s", *dir)
		}

		switch outFmt {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(profiles); err != nil {
				exitRuntime("JSON output failed: %s", err)
			}
		default:
			fmt.Print(campaign.FormatProfileSummary(profiles))
		}
		return
	}

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	for i := 0; i < fs.NArg(); i++ {
		path := fs.Arg(i)
		c, err := campaign.Load(path)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading %s", path))
		}

		p := campaign.ProfileCampaign(c)

		switch outFmt {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(p); err != nil {
				exitRuntime("JSON output failed: %s", err)
			}
		default:
			fmt.Print(campaign.FormatProfile(p))
			if i < fs.NArg()-1 {
				fmt.Println()
			}
		}
	}
}

// --- Shared helpers ---

// collectCampaignPaths gathers campaign paths from flags and positional args.
func collectCampaignPaths(fs *flag.FlagSet, dir string) []string {
	var paths []string
	if dir != "" {
		summaries, err := campaign.LoadDir(dir)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading campaigns"))
		}
		if len(summaries) == 0 {
			exitIO("no campaigns found in %s", dir)
		}
		for _, s := range summaries {
			paths = append(paths, s.Path)
		}
	} else {
		if fs.NArg() < 1 {
			fs.Usage()
			exitUsage()
		}
		for i := 0; i < fs.NArg(); i++ {
			paths = append(paths, fs.Arg(i))
		}
	}
	return paths
}

// simulateCampaigns loads, validates, and simulates campaigns from the given paths.
func simulateCampaigns(paths []string, platform string) []*engine.RunResult {
	var results []*engine.RunResult
	for _, path := range paths {
		c, err := campaign.Load(path)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading %s", path))
		}
		errs := campaign.Validate(c)
		if len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(c.Meta.Name, errs))
			os.Exit(cli.ExitValidation)
		}
		opts := engine.Options{Platform: platform, DryRun: true}
		result, err := engine.Simulate(context.Background(), c, opts)
		if err != nil {
			exitErr(cli.RuntimeWrap(err, "simulation of %q failed", c.Meta.Name))
		}
		results = append(results, result)
	}
	return results
}

// loadAndSimulateDir loads all campaigns from a directory and simulates them.
func loadAndSimulateDir(dir, platform string) []*engine.RunResult {
	summaries, err := campaign.LoadDir(dir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaigns"))
	}
	if len(summaries) == 0 {
		exitIO("no campaigns found in %s", dir)
	}
	var paths []string
	for _, s := range summaries {
		paths = append(paths, s.Path)
	}
	return simulateCampaigns(paths, platform)
}

// --- watch command ---

func cmdWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	dir := fs.String("dir", "", "Directory to watch (default: campaigns/)")
	validate := fs.Bool("validate", true, "Run validation on changed campaigns")
	lint := fs.Bool("lint", true, "Run lint checks on changed campaigns")
	formatCheck := fs.Bool("format", false, "Check for canonical formatting drift")
	interval := fs.String("interval", "2s", "Polling interval (e.g. 1s, 500ms)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: threatecho watch [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Watch campaign files for changes and re-validate on save.\n")
		fmt.Fprintf(os.Stderr, "Uses polling-based file watching (cross-platform).\n")
		fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  threatecho watch -dir campaigns/\n")
		fmt.Fprintf(os.Stderr, "  threatecho watch -interval 5s -lint=false\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	watchDir := *dir
	if watchDir == "" {
		if cfg.CampaignsDir != "" {
			watchDir = cfg.CampaignsDir
		} else {
			watchDir = findCampaignDir()
		}
	}

	pollInterval, err := parseInterval(*interval)
	if err != nil {
		exitErr(cli.UsageError("invalid interval: %s", err))
	}

	fmt.Fprintf(os.Stderr, "👁  Watching %s (interval: %s, validate: %v, lint: %v, format: %v)\n",
		watchDir, pollInterval, *validate, *lint, *formatCheck)
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop.\n\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt for graceful shutdown.
	go func() {
		c := make(chan os.Signal, 1)
		signalNotify(c, os.Interrupt)
		<-c
		cancel()
	}()

	opts := campaign.WatchOptions{
		Dir:      watchDir,
		Interval: pollInterval,
		Validate: *validate,
		Lint:     *lint,
		Format:   *formatCheck,
		OnChange: func(evt campaign.WatchEvent) {
			switch evt.Type {
			case "added":
				fmt.Fprintf(os.Stderr, "✚ %s (%s)\n", evt.Campaign, evt.Path)
			case "modified":
				fmt.Fprintf(os.Stderr, "~ %s (%s)\n", evt.Campaign, evt.Path)
			case "removed":
				fmt.Fprintf(os.Stderr, "✗ %s (removed)\n", evt.Campaign)
				return
			}
			if len(evt.Errors) > 0 {
				for _, e := range evt.Errors {
					fmt.Fprintf(os.Stderr, "  ✘ %s\n", e)
				}
			} else if *validate {
				fmt.Fprintf(os.Stderr, "  ✓ valid\n")
			}
			if evt.LintResult != nil && evt.LintResult.HasIssues() {
				for _, w := range evt.LintResult.Warnings {
					fmt.Fprintf(os.Stderr, "  ⚠ %s\n", w)
				}
			}
			if evt.FormatDrift {
				fmt.Fprintf(os.Stderr, "  ⚠ format drift (run threatecho fmt -w to fix)\n")
			}
		},
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "  ⚠ watch error: %s\n", err)
		},
	}

	if err := campaign.Watch(ctx, opts); err != nil && err != context.Canceled {
		exitErr(cli.RuntimeWrap(err, "watch"))
	}
}

// parseInterval parses a duration string for the watch interval.
func parseInterval(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// signalNotify wraps signal.Notify for testability.
var signalNotify = signal.Notify

// --- template command ---

func cmdTemplate(args []string) {
	if len(args) == 0 {
		// Default: list templates.
		cmdTemplateList()
		return
	}

	switch args[0] {
	case "list":
		cmdTemplateList()
	case "create":
		cmdTemplateCreate(args[1:])
	case "-h", "--help", "help":
		fmt.Fprintf(os.Stderr, "Usage: threatecho template [list|create]\n\nSubcommands:\n  list    List available campaign templates\n  create  Generate a campaign scaffold from a template\n")
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown template subcommand: %s\nUsage: threatecho template [list|create]\n", args[0])
		os.Exit(cli.ExitUsage)
	}
}

func cmdTemplateList() {
	fmt.Println(campaign.FormatTemplateList())
}

func cmdTemplateCreate(args []string) {
	fs := flag.NewFlagSet("template create", flag.ExitOnError)
	tmpl := fs.String("template", "", "Template name (use 'template list' to see available)")
	name := fs.String("name", "", "Campaign name (required)")
	output := fs.String("output", "", "Output directory (writes campaign.yaml inside it)")
	fs.Parse(args)

	if *tmpl == "" || *name == "" {
		fmt.Fprintf(os.Stderr, "Usage: threatecho template create -template <name> -name <campaign-name> [-output <dir>]\n\n")
		fmt.Fprintf(os.Stderr, "Available templates:\n")
		for _, t := range campaign.ListTemplates() {
			fmt.Fprintf(os.Stderr, "  %-14s %s\n", t.Name, t.Description)
		}
		os.Exit(cli.ExitUsage)
	}

	c, err := campaign.GenerateCampaign(*tmpl, *name)
	if err != nil {
		exitErr(cli.UsageError("%s", err))
	}

	formatted, err := campaign.Format(c)
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "formatting template"))
	}

	if *output != "" {
		outDir := *output
		if err := os.MkdirAll(outDir, 0755); err != nil {
			exitErr(cli.IOWrap(err, "creating output directory"))
		}
		outPath := filepath.Join(outDir, "campaign.yaml")
		if err := os.WriteFile(outPath, formatted, 0644); err != nil {
			exitErr(cli.IOWrap(err, "writing campaign"))
		}
		fmt.Fprintf(os.Stderr, "✓ Created %s from template %q\n", outPath, *tmpl)
	} else {
		os.Stdout.Write(formatted)
	}
}

// --- timeline command ---

func cmdTimeline(args []string) {
	fs := flag.NewFlagSet("timeline", flag.ExitOnError)
	dir := fs.String("dir", "", "Scan directory for campaigns")
	formatFlag := fs.String("format", "text", "Output format: text, json")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho timeline [flags] <campaign-path>
       threatecho timeline -dir <dir>

Estimate campaign execution time from the DAG structure. Shows sequential
vs parallel timing, critical path duration, per-level breakdown, and
individual stage estimates.

With -dir, estimates all campaigns and shows a comparison table.

Examples:
  threatecho timeline campaigns/apt29-cozy-bear/
  threatecho timeline -dir campaigns/
  threatecho timeline -format json campaigns/llm-agent-hijack/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *dir != "" {
		cmdTimelineDir(*dir, *formatFlag)
		return
	}

	paths := fs.Args()
	if len(paths) == 0 {
		fs.Usage()
		os.Exit(cli.ExitUsage)
	}

	c, err := campaign.Load(paths[0])
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign"))
	}

	est := campaign.EstimateTimeline(c)

	checkFormat(*formatFlag, "text", "json")

	switch *formatFlag {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(est); err != nil {
			exitErr(cli.RuntimeWrap(err, "encoding JSON"))
		}
	default:
		fmt.Print(campaign.FormatTimeline(est))
	}
}

func cmdTimelineDir(dir, format string) {
	summaries, err := campaign.LoadDir(dir)
	if err != nil {
		exitErr(cli.IOWrap(err, "scanning directory"))
	}
	if len(summaries) == 0 {
		fmt.Fprintf(os.Stderr, "no campaigns found in %s\n", dir)
		os.Exit(cli.ExitIO)
	}

	checkFormat(format, "text", "json")

	for _, s := range summaries {
		c, err := campaign.Load(s.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", s.Name, err)
			continue
		}
		est := campaign.EstimateTimeline(c)

		switch format {
		case "json":
			data := map[string]interface{}{
				"campaign": s.Name,
				"timeline": est,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(data)
		default:
			fmt.Printf("═══ %s ═══\n", s.Name)
			fmt.Print(campaign.FormatTimeline(est))
			fmt.Println()
		}
	}
}

// --- env command ---

func cmdEnv(args []string) {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	dir := fs.String("dir", "", "Scan directory for campaigns")
	check := fs.Bool("check", false, "Exit 1 if any referenced env vars are missing")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: threatecho env [flags] <campaign-path>\n")
		fmt.Fprintf(os.Stderr, "       threatecho env -dir <dir> [-check]\n\n")
		fmt.Fprintf(os.Stderr, "Show environment variable references (${env:VAR}) in campaigns.\n")
		fmt.Fprintf(os.Stderr, "With -check, exits 1 if any referenced variables are missing.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  threatecho env campaigns/apt29-cozy-bear/\n")
		fmt.Fprintf(os.Stderr, "  threatecho env -dir campaigns/ -check\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *dir != "" {
		cmdEnvDir(*dir, *check)
		return
	}

	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: threatecho env <campaign-path> [-check]\n       threatecho env -dir <dir> [-check]\n")
		os.Exit(cli.ExitUsage)
	}

	c, err := campaign.Load(paths[0])
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign"))
	}

	refs := campaign.ListEnvRefs(c)
	if len(refs) == 0 {
		fmt.Println("No ${env:...} references found.")
		return
	}

	missing := campaign.ValidateEnvRefs(c)
	missingSet := make(map[string]bool)
	for _, m := range missing {
		missingSet[m] = true
	}

	for _, ref := range refs {
		if missingSet[ref] {
			fmt.Printf("  ✘ ${env:%s} — not set\n", ref)
		} else {
			fmt.Printf("  ✓ ${env:%s} — set\n", ref)
		}
	}

	if *check && len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d environment variable(s) not set\n", len(missing))
		os.Exit(cli.ExitValidation)
	}
}

func cmdEnvDir(dir string, check bool) {
	summaries, err := campaign.LoadDir(dir)
	if err != nil {
		exitErr(cli.IOWrap(err, "scanning directory"))
	}
	if len(summaries) == 0 {
		fmt.Fprintf(os.Stderr, "no campaigns found in %s\n", dir)
		os.Exit(cli.ExitIO)
	}

	anyMissing := false
	for _, s := range summaries {
		c, err := campaign.Load(s.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", s.Name, err)
			continue
		}
		refs := campaign.ListEnvRefs(c)
		if len(refs) == 0 {
			continue
		}
		missing := campaign.ValidateEnvRefs(c)
		fmt.Printf("%s:\n", s.Name)
		missingSet := make(map[string]bool)
		for _, m := range missing {
			missingSet[m] = true
		}
		for _, ref := range refs {
			if missingSet[ref] {
				fmt.Printf("  ✘ ${env:%s} — not set\n", ref)
				anyMissing = true
			} else {
				fmt.Printf("  ✓ ${env:%s} — set\n", ref)
			}
		}
	}

	if check && anyMissing {
		fmt.Fprintf(os.Stderr, "\nSome environment variables are not set\n")
		os.Exit(cli.ExitValidation)
	}
}

// --- policy risk ---

func cmdPolicyRisk(args []string) {
	fs := flag.NewFlagSet("policy risk", flag.ExitOnError)
	dir := fs.String("dir", "", "campaigns directory for reference tool extraction")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy risk [flags] <policy-path>

Assess the risk posture of a policy. Evaluates coverage gaps, conflict
density, deny/allow balance, structural quality, and elevated access risks.

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	p, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	var assessment *policy.RiskAssessment
	if *dir != "" {
		campaigns, cerr := campaign.LoadDir(*dir)
		if cerr != nil {
			exitErr(cli.IOWrap(cerr, "loading campaigns for reference tools"))
		}
		var refTools []string
		seen := make(map[string]bool)
		for _, cs := range campaigns {
			c, lerr := campaign.Load(cs.Path)
			if lerr != nil {
				continue
			}
			for _, s := range c.Stages {
				tools := policy.InferTools(s)
				for _, t := range tools {
					if !seen[t] {
						seen[t] = true
						refTools = append(refTools, t)
					}
				}
			}
		}
		assessment = policy.AssessRiskWithCoverage(p, refTools)
	} else {
		assessment = policy.AssessRisk(p)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(assessment)
		return
	}

	fmt.Print(policy.FormatRiskAssessment(assessment))

	// Exit 2 for grade D or F (high risk).
	if assessment.OverallGrade == "D" || assessment.OverallGrade == "F" {
		os.Exit(cli.ExitPolicyDenied)
	}
}

// --- policy diff ---

func cmdPolicyDiff(args []string) {
	fs := flag.NewFlagSet("policy diff", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy diff [flags] <old-policy-path> <new-policy-path>

Compare two policies and show the differences: added/removed/modified rules,
scope changes, and breaking change detection.

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fs.Usage()
		exitUsage()
	}

	oldP, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading old policy"))
	}

	newP, err := policy.LoadPolicy(fs.Arg(1))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading new policy"))
	}

	diff := policy.DiffPolicies(oldP, newP)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(diff)
		return
	}

	fmt.Print(policy.FormatPolicyDiff(diff))

	// Exit 2 if there are breaking changes.
	if diff.Summary.BreakingChanges > 0 {
		os.Exit(cli.ExitPolicyDenied)
	}
}

// --- policy guardrail ---

func cmdPolicyGuardrail(args []string) {
	fs := flag.NewFlagSet("policy guardrail", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to policy directory (required)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	defaults := fs.Bool("defaults", false, "include recommended default guardrails")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy guardrail [flags] [trace-file...]

Analyze guardrail coverage against agent execution traces and a policy.
Evaluates how well guardrails protect the agent pipeline — checking for
input/output filtering, content moderation, PII handling, and rate limiting.

Without trace files, analyzes the policy's guardrail alignment using the
recommended default guardrail set. With trace files, also evaluates actual
guardrail behavior from recorded executions.

Exit code 2 when critical guardrail gaps are detected.

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *policyPath == "" {
		exitValidation("-policy is required")
	}

	p, err := policy.LoadPolicy(*policyPath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	// Collect guardrails — always start with defaults.
	guardrails := policy.DefaultGuardrails()
	if !*defaults && fs.NArg() == 0 {
		// No traces and no explicit -defaults: still use defaults for
		// policy alignment analysis.
	}

	// Load traces if provided.
	var traces []*policy.Trace
	for i := 0; i < fs.NArg(); i++ {
		tr, terr := policy.ParseTraceFile(fs.Arg(i))
		if terr != nil {
			exitErr(cli.IOWrap(terr, "parsing trace %s", fs.Arg(i)))
		}
		traces = append(traces, tr)
	}

	analysis := policy.AnalyzeGuardrails(guardrails, traces, p)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(analysis)
		return
	}

	fmt.Print(policy.FormatGuardrailAnalysis(analysis))

	// Exit 2 if there are critical gaps.
	for _, g := range analysis.GapAnalysis {
		if g.Risk == "critical" || g.Risk == "high" {
			os.Exit(cli.ExitPolicyDenied)
		}
	}
}

// --- policy history ---

func cmdPolicyHistory(args []string) {
	fs := flag.NewFlagSet("policy history", flag.ExitOnError)
	initH := fs.Bool("init", false, "initialize version history for a policy")
	addV := fs.Bool("add", false, "add the current policy as a new version")
	diffV := fs.String("diff", "", "show diff between two versions (e.g. 1:2)")
	author := fs.String("author", "", "author name for version tracking")
	comment := fs.String("comment", "", "change description for this version")
	historyFile := fs.String("file", "", "history file path (default: <policy-dir>/history.json)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy history [flags] <policy-path>

Track policy changes over time with versioned snapshots. Each version records
the full policy state, a SHA256 fingerprint, author, and comment.

Modes:
  -init             Create a new history file for the policy (version 1)
  -add              Snapshot the current policy as a new version
  -diff 1:2         Show the diff between version 1 and version 2
  (no flag)         Show version history and statistics

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	policyPath := fs.Arg(0)
	p, err := policy.LoadPolicy(policyPath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	// Resolve history file path.
	hFile := *historyFile
	if hFile == "" {
		hFile = filepath.Join(policyPath, "history.json")
	}

	authorName := *author
	if authorName == "" {
		authorName = "threatecho"
	}

	commentText := *comment
	if commentText == "" {
		commentText = "snapshot"
	}

	if *initH {
		// Create a new history.
		if _, serr := os.Stat(hFile); serr == nil {
			exitValidation("history file already exists: %s (use -add to append a version)", hFile)
		}
		h := policy.NewHistory(p, authorName, commentText)
		data, jerr := policy.HistoryToJSON(h)
		if jerr != nil {
			exitRuntime("serializing history: %s", jerr)
		}
		if werr := os.WriteFile(hFile, data, 0644); werr != nil {
			exitErr(cli.IOWrap(werr, "writing history file"))
		}
		fmt.Fprintf(os.Stderr, "✓ Initialized history for %q at %s (version 1)\n", p.Meta.Name, hFile)
		return
	}

	// Load existing history.
	hData, err := os.ReadFile(hFile)
	if err != nil {
		exitErr(cli.IOWrap(err, "reading history file (use -init to create)"))
	}
	h, err := policy.HistoryFromJSON(hData)
	if err != nil {
		exitErr(cli.IOWrap(err, "parsing history file"))
	}

	if *addV {
		ver := h.AddVersion(p, authorName, commentText)
		data, jerr := policy.HistoryToJSON(h)
		if jerr != nil {
			exitRuntime("serializing history: %s", jerr)
		}
		if werr := os.WriteFile(hFile, data, 0644); werr != nil {
			exitErr(cli.IOWrap(werr, "writing history file"))
		}
		fmt.Fprintf(os.Stderr, "✓ Added version %d to history (%s)\n", ver, hFile)
		return
	}

	if *diffV != "" {
		// Parse "old:new" format.
		parts := strings.SplitN(*diffV, ":", 2)
		if len(parts) != 2 {
			exitValidation("-diff requires format old:new (e.g. -diff 1:2)")
		}
		var oldV, newV int
		if _, serr := fmt.Sscanf(parts[0], "%d", &oldV); serr != nil {
			exitValidation("invalid old version: %s", parts[0])
		}
		if _, serr := fmt.Sscanf(parts[1], "%d", &newV); serr != nil {
			exitValidation("invalid new version: %s", parts[1])
		}
		vdiff, derr := h.DiffVersions(oldV, newV)
		if derr != nil {
			exitRuntime("computing version diff: %s", derr)
		}
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(vdiff)
			return
		}
		fmt.Print(policy.FormatVersionDiff(vdiff))
		return
	}

	// Default: show history.
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(h)
		return
	}

	fmt.Print(policy.FormatHistory(h))
}

func cmdPolicyCompliance(args []string) {
	fs := flag.NewFlagSet("policy compliance", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to the policy to evaluate against (required)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy compliance [flags] <trace-file>...

Evaluate whether execution traces comply with a policy. Produces a
compliance report with violation details, coverage metrics, and a
grade (A-F) for each trace and the overall batch.

A trace is compliant if no events trigger deny rules. Alerts reduce
the score but do not cause non-compliance.

Exit code 2 when any trace is non-compliant.

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *policyPath == "" {
		exitValidation("-policy is required")
	}

	p, err := policy.LoadPolicy(*policyPath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	var traces []*policy.Trace
	for i := 0; i < fs.NArg(); i++ {
		tr, terr := policy.ParseTraceFile(fs.Arg(i))
		if terr != nil {
			exitErr(cli.IOWrap(terr, "parsing trace %s", fs.Arg(i)))
		}
		traces = append(traces, tr)
	}

	report := policy.EvaluateComplianceBatch(p, traces)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
		return
	}

	fmt.Print(policy.FormatComplianceReport(report))

	if report.NonCompliantCount > 0 {
		os.Exit(cli.ExitPolicyDenied)
	}
}

func cmdPolicyExport(args []string) {
	fs := flag.NewFlagSet("policy export", flag.ExitOnError)
	format := fs.String("format", "json", "export format: json, yaml, rego, summary")
	output := fs.String("output", "", "output file path (default: stdout)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy export [flags] <policy-path>

Export a policy in machine-readable formats for CI/CD integration
and policy-as-code workflows.

Formats:
  json       Full policy as JSON (default)
  yaml       Full policy as YAML
  rego       OPA Rego rules for policy-as-code enforcement
  summary    Human-readable YAML summary (rule counts, IDs, effects)

Examples:
  threatecho policy export policies/agent-default/
  threatecho policy export -format rego policies/agent-strict/
  threatecho policy export -format summary policies/agent-default/
  threatecho policy export -format json -output policy.json policies/agent-default/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	p, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	exp, err := policy.ExportPolicy(p, policy.ExportFormat(*format))
	if err != nil {
		exitErr(cli.RuntimeWrap(err, "exporting policy"))
	}

	rendered := policy.FormatExport(exp)

	if *output != "" {
		if err := os.WriteFile(*output, []byte(rendered), 0o644); err != nil {
			exitErr(cli.IOWrap(err, "writing %s", *output))
		}
		fmt.Fprintf(os.Stderr, "✓ Policy exported to %s (%s)\n", *output, *format)
		return
	}

	fmt.Print(rendered)
}

// --- policy benchmark ---

func cmdPolicyBenchmark(args []string) {
	fs := flag.NewFlagSet("policy benchmark", flag.ExitOnError)
	iterations := fs.Int("iterations", policy.DefaultBenchmarkIterations, "number of evaluation iterations per tool")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy benchmark [flags] <policy-path>

Benchmark policy evaluation performance. Measures how long it takes
to evaluate tool calls against all policy rules, critical for production
deployments where policies must evaluate in microseconds to avoid
blocking agent tool calls.

Generates a mix of matching and non-matching synthetic tool calls and
evaluates them against the policy rules for N iterations, collecting
per-evaluation timing statistics (avg, p99, max).

Examples:
  threatecho policy benchmark policies/agent-default/
  threatecho policy benchmark -iterations 5000 policies/agent-strict/
  threatecho policy benchmark -json policies/agent-default/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	p, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	errs := policy.ValidatePolicy(p)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(p.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	report := policy.BenchmarkPolicy(p, *iterations)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
		return
	}

	fmt.Print(policy.FormatBenchmarkReport(report))
}

// --- policy simulate ---

func cmdPolicySimulate(args []string) {
	fs := flag.NewFlagSet("policy simulate", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to policy YAML file or directory (required)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	dir := fs.String("dir", "", "campaigns directory (simulate all campaigns)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy simulate -policy <path> [flags] [campaign-path...]

Dry-run a campaign against a policy without executing anything.
Loads each campaign, infers tool calls per stage, and evaluates
each against the policy rules. Produces a report showing which
tool calls would be allowed, denied, or alerted.

This is the "what-if" mode — use it before deploying a policy
to predict its impact on your campaign portfolio.

Examples:
  threatecho policy simulate -policy policies/agent-strict/ campaigns/llm-agent-hijack/
  threatecho policy simulate -policy policies/agent-default/ -dir campaigns/
  threatecho policy simulate -policy policies/agent-strict/ -json campaigns/llm-agent-hijack/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	// Resolve policy path: flag → config → error.
	polPath := *policyPath
	if polPath == "" && cfg.DefaultPolicy != "" {
		polPath = cfg.DefaultPolicy
	}
	if polPath == "" {
		fmt.Fprintf(os.Stderr, "Error: -policy is required\n\n")
		fs.Usage()
		exitUsage()
	}

	// Load and validate the policy.
	p, err := policy.LoadPolicy(polPath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy"))
	}

	errs := policy.ValidatePolicy(p)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(p.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	// Collect campaign paths.
	paths := collectCampaignPaths(fs, *dir)

	for _, path := range paths {
		c, loadErr := campaign.Load(path)
		if loadErr != nil {
			exitErr(cli.IOWrap(loadErr, "loading campaign %s", path))
		}

		report := policy.SimulatePolicy(p, c)

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(report); encErr != nil {
				exitRuntime("JSON output failed: %s", encErr)
			}
		} else {
			fmt.Print(policy.FormatSimulationReport(report))
		}
	}
}

// ---------------------------------------------------------------------------
// scenario command — generate and analyze agent execution traces
// ---------------------------------------------------------------------------

func cmdScenario(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `Usage: threatecho scenario <subcommand> [flags] [args]

Generate and analyze agent execution traces from campaign scenarios.
Traces represent the tool calls, messages, and events an AI agent would
produce when executing a campaign's stages.

Subcommands:
  run        Generate traces from a campaign scenario
  validate   Validate a scenario can generate traces
  list       List stages that would be simulated

Examples:
  threatecho scenario run -dir campaigns/llm-agent-hijack/
  threatecho scenario run -dir campaigns/llm-agent-hijack/ -policy policies/agent-strict/
  threatecho scenario validate -dir campaigns/rag-poisoning/
  threatecho scenario list -dir campaigns/multi-agent-attack/ -json

`)
		exitUsage()
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "run":
		cmdScenarioRun(rest)
	case "validate":
		cmdScenarioValidate(rest)
	case "list":
		cmdScenarioList(rest)
	case "-h", "--help", "help":
		helpRequested = true
		cmdScenario(nil)
	default:
		fmt.Fprintf(os.Stderr, "unknown scenario subcommand: %s\nValid subcommands: run, validate, list\n", sub)
		exitUsage()
	}
}

func cmdScenarioRun(args []string) {
	fs := flag.NewFlagSet("scenario run", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory (required)")
	agentName := fs.String("agent", "simulated-agent", "agent name for generated traces")
	agentType := fs.String("type", "llm", "agent type: llm, retrieval, orchestrator, tool")
	policyPath := fs.String("policy", "", "optional policy file for compliance evaluation")
	jsonOut := fs.Bool("json", false, "output as JSON")
	metadata := fs.Bool("metadata", false, "include stage metadata in trace events")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho scenario run -dir <campaign-path> [flags]

Generate agent execution traces from a campaign scenario. Each stage
in the campaign produces trace events representing the tool calls and
actions an agent would perform.

When -policy is provided, each generated trace is also evaluated against
the policy for compliance. The output includes both the trace data and
the compliance results.

Examples:
  threatecho scenario run -dir campaigns/llm-agent-hijack/
  threatecho scenario run -dir campaigns/llm-agent-hijack/ -agent my-agent -type orchestrator
  threatecho scenario run -dir campaigns/llm-agent-hijack/ -policy policies/agent-strict/
  threatecho scenario run -dir campaigns/llm-agent-hijack/ -json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *dir == "" {
		fmt.Fprintf(os.Stderr, "Error: -dir is required\n\n")
		fs.Usage()
		exitUsage()
	}

	// Load campaign.
	c, err := campaign.Load(*dir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign from %s", *dir))
	}

	// Build run config.
	rcfg := engine.DefaultRunConfig()
	rcfg.AgentName = *agentName
	rcfg.AgentType = *agentType
	rcfg.IncludeMetadata = *metadata

	// Generate traces.
	result, err := engine.RunScenario(c, rcfg)
	if err != nil {
		exitRuntime("scenario run failed: %s", err)
	}

	// Optional policy evaluation.
	if *policyPath != "" {
		p, polErr := policy.LoadPolicy(*policyPath)
		if polErr != nil {
			exitErr(cli.IOWrap(polErr, "loading policy"))
		}

		compReport := policy.EvaluateComplianceBatch(p, result.Traces)

		if *jsonOut {
			out := struct {
				Scenario   *engine.ScenarioResult   `json:"scenario"`
				Compliance *policy.ComplianceReport `json:"compliance"`
			}{
				Scenario:   result,
				Compliance: compReport,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(out); encErr != nil {
				exitRuntime("JSON output failed: %s", encErr)
			}
		} else {
			fmt.Print(engine.FormatScenarioResult(result))
			fmt.Println()
			fmt.Print(policy.FormatComplianceReport(compReport))
		}
		return
	}

	// No policy — just output scenario result.
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(result); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(engine.FormatScenarioResult(result))
	}
}

func cmdScenarioValidate(args []string) {
	fs := flag.NewFlagSet("scenario validate", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory (required)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho scenario validate -dir <campaign-path>

Validate that a campaign can produce agent execution traces. Loads
the campaign, runs the scenario engine, and reports whether trace
generation succeeded.

Examples:
  threatecho scenario validate -dir campaigns/llm-agent-hijack/
  threatecho scenario validate -dir campaigns/rag-poisoning/

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *dir == "" {
		fmt.Fprintf(os.Stderr, "Error: -dir is required\n\n")
		fs.Usage()
		exitUsage()
	}

	c, err := campaign.Load(*dir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign from %s", *dir))
	}

	rcfg := engine.DefaultRunConfig()
	result, runErr := engine.RunScenario(c, rcfg)
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "✗ Scenario validation failed for %s: %s\n", c.Meta.Name, runErr)
		os.Exit(cli.ExitValidation)
	}

	fmt.Fprintf(os.Stderr, "✓ %s: %d stages, %d traces, %d events\n",
		c.Meta.Name, result.StageCount, len(result.Traces), result.EventCount)
}

func cmdScenarioList(args []string) {
	fs := flag.NewFlagSet("scenario list", flag.ExitOnError)
	dir := fs.String("dir", "", "campaign directory (required)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho scenario list -dir <campaign-path> [flags]

List the stages that would be simulated and the expected event count
per stage. Runs the scenario engine and reports per-stage details
without the full trace output.

Examples:
  threatecho scenario list -dir campaigns/llm-agent-hijack/
  threatecho scenario list -dir campaigns/multi-agent-attack/ -json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *dir == "" {
		fmt.Fprintf(os.Stderr, "Error: -dir is required\n\n")
		fs.Usage()
		exitUsage()
	}

	c, err := campaign.Load(*dir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign from %s", *dir))
	}

	rcfg := engine.DefaultRunConfig()
	result, runErr := engine.RunScenario(c, rcfg)
	if runErr != nil {
		exitRuntime("scenario list failed: %s", runErr)
	}

	if *jsonOut {
		out := struct {
			CampaignName string                       `json:"campaign_name"`
			StageCount   int                          `json:"stage_count"`
			EventCount   int                          `json:"event_count"`
			Stages       []engine.ScenarioStageResult `json:"stages"`
		}{
			CampaignName: result.CampaignName,
			StageCount:   result.StageCount,
			EventCount:   result.EventCount,
			Stages:       result.StageResults,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(out); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Printf("Campaign: %s\n", result.CampaignName)
		fmt.Printf("Stages:   %d\n", result.StageCount)
		fmt.Printf("Events:   %d (total)\n\n", result.EventCount)

		for i, sr := range result.StageResults {
			fmt.Printf("  %2d. %-40s %d events\n", i+1, sr.StageName, sr.EventCount)
		}
	}
}

func cmdPolicyDrift(args []string) {
	fs := flag.NewFlagSet("policy drift", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: threatecho policy drift <baseline-policy> <current-policy>\n\n")
		fmt.Fprintf(os.Stderr, "Compare two policy versions and detect semantic drift.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "✗ policy drift requires two policy paths: baseline and current")
		os.Exit(cli.ExitUsage)
	}

	baseline, loadErr := policy.LoadPolicy(fs.Arg(0))
	if loadErr != nil {
		exitErr(cli.IOWrap(loadErr, "loading baseline policy %s", fs.Arg(0)))
	}
	current, loadErr := policy.LoadPolicy(fs.Arg(1))
	if loadErr != nil {
		exitErr(cli.IOWrap(loadErr, "loading current policy %s", fs.Arg(1)))
	}

	report := policy.DetectDrift(baseline, current)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(report); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(policy.FormatDriftReport(report))
	}
}

func cmdPolicyLint(args []string) {
	fs := flag.NewFlagSet("policy lint", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: threatecho policy lint <policy-path>\n\n")
		fmt.Fprintf(os.Stderr, "Run best-practice quality checks on a policy beyond structural validation.\n")
		fmt.Fprintf(os.Stderr, "Checks security, coverage, redundancy, naming, complexity, and best practices.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "✗ policy lint requires a policy path")
		os.Exit(cli.ExitUsage)
	}

	p, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy %s", fs.Arg(0)))
	}

	report := policy.LintPolicy(p)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(report); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(policy.FormatLintReport(report))
	}

	// Exit non-zero if errors found, for CI usage.
	if report.ErrorCount > 0 {
		os.Exit(cli.ExitPolicyDenied)
	}
}

func cmdAgentChain(args []string) {
	fs := flag.NewFlagSet("agent chain", flag.ExitOnError)
	dir := fs.String("dir", "", "agents directory (default: auto-detect)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: threatecho agent chain [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Analyze multi-agent delegation chains for trust violations.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	agentDir := *dir
	if agentDir == "" {
		agentDir = findAgentDir()
	}

	inv, err := agent.LoadInventory(agentDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading agent inventory from %s", agentDir))
	}

	analysis := agent.AnalyzeChains(inv)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(analysis); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(agent.FormatChainAnalysis(analysis))
	}
}

func cmdAgentAttest(args []string) {
	fs := flag.NewFlagSet("agent attest", flag.ExitOnError)
	dir := fs.String("dir", "", "agents directory (default: auto-detect)")
	agentName := fs.String("agent", "", "attest a single agent by name")
	verify := fs.Bool("verify", false, "verify existing attestations")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent attest [flags]

Generate cryptographic attestations for agent configurations.

Attestations create a tamper-evident fingerprint of each agent's
configuration — tools, capabilities, guardrails, and boundaries.
Use them to detect configuration drift and verify agent integrity.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  threatecho agent attest -dir agents/
  threatecho agent attest -agent billing-agent -dir agents/
  threatecho agent attest -verify -dir agents/
  threatecho agent attest -json -dir agents/
`)
	}
	fs.Parse(args)

	agentDir := *dir
	if agentDir == "" {
		agentDir = findAgentDir()
	}

	inv, err := agent.LoadInventory(agentDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading agent inventory from %s", agentDir))
	}

	cfg := agent.DefaultAttestConfig()

	if *agentName != "" {
		// Single agent mode.
		var target *agent.Agent
		for _, a := range inv.Agents {
			if a.Meta.Name == *agentName {
				target = a
				break
			}
		}
		if target == nil {
			exitRuntime("agent %q not found in inventory", *agentName)
		}
		att := agent.AttestAgent(target, cfg)
		if *verify {
			ok := agent.VerifyAttestation(target, att)
			if *jsonOut {
				result := map[string]interface{}{
					"agent":       *agentName,
					"verified":    ok,
					"attestation": att,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(result); encErr != nil {
					exitRuntime("JSON output failed: %s", encErr)
				}
			} else {
				fmt.Print(agent.FormatAttestation(att))
				if ok {
					fmt.Println("\n✓ Attestation verified")
				} else {
					fmt.Println("\n✗ Attestation verification FAILED")
				}
			}
		} else {
			if *jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(att); encErr != nil {
					exitRuntime("JSON output failed: %s", encErr)
				}
			} else {
				fmt.Print(agent.FormatAttestation(att))
			}
		}
		return
	}

	// Full inventory attestation.
	report := agent.AttestInventory(inv, cfg)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(report); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(agent.FormatAttestationReport(report))
	}
}

func cmdPolicyCoverageMap(args []string) {
	fs := flag.NewFlagSet("policy coveragemap", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy coveragemap [flags] <policy-path>

Map policy rules to MITRE ATT&CK techniques and identify coverage gaps.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  threatecho policy coveragemap policies/agent-strict/
  threatecho policy coveragemap -json policies/agent-default/
`)
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "✗ policy coveragemap requires a policy path")
		exitUsage()
	}

	p, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy from %s", fs.Arg(0)))
	}

	report := policy.MapCoverage(p)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(report); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(policy.FormatCoverageReport(report))
	}
}

func cmdAgentProfile(args []string) {
	fs := flag.NewFlagSet("agent profile", flag.ExitOnError)
	dir := fs.String("dir", "", "agents directory (default: auto-detect)")
	agentName := fs.String("agent", "", "profile a single agent")
	traceDir := fs.String("traces", "", "directory containing trace files (required)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent profile [flags]

Build behavioral profiles from agent execution traces. Profiles capture
baseline patterns — tool usage, call frequency, targets, timing — that
can be used to detect anomalous behavior.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  threatecho agent profile -traces traces/ -dir agents/
  threatecho agent profile -agent billing-agent -traces traces/
  threatecho agent profile -json -traces traces/
`)
	}
	fs.Parse(args)

	if *traceDir == "" {
		fmt.Fprintln(os.Stderr, "✗ agent profile requires -traces directory")
		exitUsage()
	}

	// Load trace files from directory.
	var traces []*policy.Trace
	err := filepath.Walk(*traceDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		t, loadErr := policy.ParseTraceFile(path)
		if loadErr != nil {
			return nil // Skip non-trace JSON files.
		}
		traces = append(traces, t)
		return nil
	})
	if err != nil {
		exitErr(cli.IOWrap(err, "scanning trace directory %s", *traceDir))
	}

	if len(traces) == 0 {
		fmt.Fprintln(os.Stderr, "✗ no trace files found in", *traceDir)
		exitUsage()
	}

	if *agentName != "" {
		// Filter traces for a specific agent.
		var filtered []*policy.Trace
		for _, t := range traces {
			if t.AgentName == *agentName {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			exitRuntime("no traces found for agent %q", *agentName)
		}

		profile := agent.BuildProfile(*agentName, filtered)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(profile); encErr != nil {
				exitRuntime("JSON output failed: %s", encErr)
			}
		} else {
			fmt.Print(agent.FormatProfile(profile))
		}
		return
	}

	// Build profiles for all agents.
	_ = dir // dir is unused when building profiles from traces alone.
	agentTraces := make(map[string][]*policy.Trace)
	for _, t := range traces {
		agentTraces[t.AgentName] = append(agentTraces[t.AgentName], t)
	}

	for name, ats := range agentTraces {
		profile := agent.BuildProfile(name, ats)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(profile); encErr != nil {
				exitRuntime("JSON output failed: %s", encErr)
			}
		} else {
			fmt.Print(agent.FormatProfile(profile))
			fmt.Println()
		}
	}
}

func cmdThreatModel(args []string) {
	fs := flag.NewFlagSet("threat-model", flag.ExitOnError)
	agentDir := fs.String("agents", "", "agents directory (default: auto-detect)")
	policyDir := fs.String("policy", "", "policies directory (default: auto-detect)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho threat-model [flags]

Generate a STRIDE-based threat model for an AI agent deployment.

Analyzes the agent inventory and policy definitions to identify
threats across all six STRIDE categories — Spoofing, Tampering,
Repudiation, Information Disclosure, Denial of Service, and
Elevation of Privilege — with agent-specific threat patterns.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  threatecho threat-model -agents agents/ -policy policies/
  threatecho threat-model -agents agents/ -json
`)
	}
	fs.Parse(args)

	aDir := *agentDir
	if aDir == "" {
		aDir = findAgentDir()
	}

	inv, err := agent.LoadInventory(aDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading agent inventory from %s", aDir))
	}

	pDir := *policyDir
	if pDir == "" {
		pDir = findPolicyDir()
	}

	var policies []*policy.Policy
	filepath.Walk(pDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		if filepath.Base(path) == "policy.yaml" || filepath.Ext(path) == ".yaml" {
			p, loadErr := policy.LoadPolicy(filepath.Dir(path))
			if loadErr == nil {
				policies = append(policies, p)
			}
		}
		return nil
	})

	model := engine.GenerateThreatModel(inv, policies)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(model); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(engine.FormatThreatModel(model))
	}
}

// findPolicyDir looks for a policies/ directory walking up from cwd.
func findPolicyDir() string {
	dir, _ := os.Getwd()
	for {
		candidate := filepath.Join(dir, "policies")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "policies"
}

// marshalYAML marshals a value to YAML bytes.
func marshalYAML(v interface{}) ([]byte, error) {
	return yaml.Marshal(v)
}

func cmdPolicyRemediate(args []string) {
	fs := flag.NewFlagSet("policy remediate", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output as JSON")
	source := fs.String("source", "lint", "analysis source: lint, drift, coverage, all")
	baseline := fs.String("baseline", "", "baseline policy path (required for drift source)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy remediate [flags] <policy-path>

Generate fix suggestions from analysis findings. Examines lint issues,
drift from a baseline, or coverage gaps and produces a remediation plan
with concrete rule additions, modifications, and restructuring advice.

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  threatecho policy remediate policies/agent-strict/
  threatecho policy remediate -source coverage policies/agent-default/
  threatecho policy remediate -source drift -baseline policies/agent-default/ policies/agent-strict/
  threatecho policy remediate -source all -baseline policies/agent-default/ policies/agent-strict/
  threatecho policy remediate -json policies/agent-strict/
`)
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "✗ policy remediate requires a policy path")
		exitUsage()
	}

	p, err := policy.LoadPolicy(fs.Arg(0))
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy from %s", fs.Arg(0)))
	}

	var plans []*policy.RemediationPlan

	doLint := *source == "lint" || *source == "all"
	doDrift := *source == "drift" || *source == "all"
	doCoverage := *source == "coverage" || *source == "all"

	if doLint {
		lintReport := policy.LintPolicy(p)
		if lintReport.FindingCount > 0 {
			plans = append(plans, policy.RemediateFromLint(p, lintReport))
		}
	}

	if doDrift {
		if *baseline == "" {
			fmt.Fprintln(os.Stderr, "✗ drift source requires -baseline <policy-path>")
			exitUsage()
		}
		base, loadErr := policy.LoadPolicy(*baseline)
		if loadErr != nil {
			exitErr(cli.IOWrap(loadErr, "loading baseline policy from %s", *baseline))
		}
		driftReport := policy.DetectDrift(base, p)
		if len(driftReport.Findings) > 0 {
			plans = append(plans, policy.RemediateFromDrift(p, driftReport))
		}
	}

	if doCoverage {
		coverageReport := policy.MapCoverage(p)
		if len(coverageReport.Gaps) > 0 {
			plans = append(plans, policy.RemediateFromCoverage(p, coverageReport))
		}
	}

	if len(plans) == 0 {
		fmt.Println("✓ No remediation needed — no issues found.")
		return
	}

	merged := policy.MergeRemediations(plans...)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(merged); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(policy.FormatRemediationPlan(merged))
	}
}

func cmdRiskPosture(args []string) {
	fs := flag.NewFlagSet("risk-posture", flag.ExitOnError)
	policyPath := fs.String("policy", "", "policy path (required)")
	agentDir := fs.String("agents", "", "agents directory (default: auto-detect)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho risk-posture [flags]

Unified risk assessment that combines all analysis dimensions —
policy lint score, MITRE coverage gaps, STRIDE threat model, and
agent chain analysis — into a single risk posture grade (A-F).

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  threatecho risk-posture -policy policies/agent-strict/ -agents agents/
  threatecho risk-posture -policy policies/agent-default/ -json
`)
	}
	fs.Parse(args)

	if *policyPath == "" {
		fmt.Fprintln(os.Stderr, "✗ risk-posture requires -policy <path>")
		exitUsage()
	}

	p, err := policy.LoadPolicy(*policyPath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading policy from %s", *policyPath))
	}

	inputs := &engine.RiskInputs{}

	// Lint dimension.
	inputs.LintReport = policy.LintPolicy(p)

	// Coverage dimension.
	inputs.CoverageMap = policy.MapCoverage(p)

	// Agent dimensions (optional).
	aDir := *agentDir
	if aDir == "" {
		aDir = findAgentDir()
	}
	inv, invErr := agent.LoadInventory(aDir)
	if invErr == nil && len(inv.Agents) > 0 {
		// Chain analysis.
		inputs.ChainAnalysis = agent.AnalyzeChains(inv)

		// Threat model — load policies for mitigation assessment.
		var policies []*policy.Policy
		policies = append(policies, p)
		inputs.ThreatModel = engine.GenerateThreatModel(inv, policies)
	}

	cfg := engine.DefaultRiskConfig()
	posture := engine.AssessRisk(cfg, inputs)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(posture); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(engine.FormatRiskPosture(posture))
	}
}

func cmdAgentDependency(args []string) {
	fs := flag.NewFlagSet("agent dependency", flag.ExitOnError)
	dir := fs.String("dir", "", "agents directory (default: auto-detect)")
	agentName := fs.String("agent", "", "show blast radius for a specific agent")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho agent dependency [flags]

Map inter-agent dependencies, detect single points of failure,
privilege escalation paths, and compute blast radius.

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	agentDir := *dir
	if agentDir == "" {
		agentDir = findAgentDir()
	}

	inv, err := agent.LoadInventory(agentDir)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading agent inventory from %s", agentDir))
	}

	if *agentName != "" {
		br := agent.AnalyzeBlastRadius(inv, *agentName)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(br); encErr != nil {
				exitRuntime("JSON output failed: %s", encErr)
			}
		} else {
			fmt.Print(agent.FormatBlastRadius(br))
		}
		return
	}

	report := agent.GenerateDependencyReport(inv)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(report); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(agent.FormatDependencyReport(report))
	}
}

func cmdCompliance(args []string) {
	fs := flag.NewFlagSet("compliance", flag.ExitOnError)
	policyDir := fs.String("policy", "", "policy directory to evaluate")
	agentDir := fs.String("agents", "agents/", "agent inventory directory")
	framework := fs.String("framework", "", "specific framework (see -list)")
	jsonOut := fs.Bool("json", false, "output as JSON")
	listFw := fs.Bool("list", false, "list available frameworks")
	campaignDir := fs.String("dir", "", "campaign directory for SOC compliance assessment")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho compliance [flags]

Map agent policies and configurations against security compliance frameworks.

AI Agent Frameworks (default, uses -policy and -agents):
  nist-ai-rmf       NIST AI Risk Management Framework (10 controls)
  owasp-llm-top10   OWASP Top 10 for LLM Applications (10 controls)
  mitre-atlas       MITRE ATLAS Adversarial ML (8 controls)

SOC/Enterprise Frameworks (uses -dir for campaign gap analysis):
  nist-csf          NIST Cybersecurity Framework 2.0 (19 controls)
  nist-800-53       NIST SP 800-53 Rev.5 (20 control families)
  cis-v8            CIS Controls v8 (18 controls)

Without -framework, maps against all frameworks and shows summary.
With -framework, shows detailed per-control mapping.
With -dir, runs campaign gap analysis and maps to SOC frameworks.

Examples:
  threatecho compliance -policy policies/agent-strict/ -agents agents/
  threatecho compliance -framework owasp-llm-top10 -policy policies/agent-strict/
  threatecho compliance -dir campaigns/ -framework nist-csf
  threatecho compliance -dir campaigns/ -json
  threatecho compliance -list

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *listFw {
		fmt.Println("AI Agent Frameworks:")
		for _, fw := range engine.ListFrameworks() {
			fmt.Printf("  %-20s %s (%d controls)\n", fw.ID, fw.Name, len(fw.Controls))
		}
		fmt.Println("\nSOC/Enterprise Frameworks:")
		for _, id := range compliance.ValidFrameworks() {
			def := compliance.LookupFramework(compliance.Framework(id))
			if def != nil {
				fmt.Printf("  %-20s %s %s (%d controls)\n", def.ID, def.Name, def.Version, len(def.Controls))
			}
		}
		return
	}

	// SOC/enterprise compliance via campaign gap analysis.
	if *campaignDir != "" {
		cmdComplianceSOC(*campaignDir, *framework, *jsonOut)
		return
	}

	// AI agent compliance via policy/agent mapping.
	var policies []*policy.Policy
	polPath := *policyDir
	if polPath == "" {
		polPath = findPolicyDir()
	}
	if polPath != "" {
		p, pErr := policy.LoadPolicy(polPath)
		if pErr == nil {
			policies = append(policies, p)
		}
	}

	inv, _ := agent.LoadInventory(*agentDir)

	if *framework != "" {
		fw, ok := engine.GetFramework(*framework)
		if !ok {
			exitValidation("unknown framework: %s (use -list to see available)", *framework)
		}
		rpt := engine.MapCompliance(fw, policies, inv)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(rpt); encErr != nil {
				exitRuntime("JSON output failed: %s", encErr)
			}
		} else {
			fmt.Print(engine.FormatComplianceReport(rpt))
		}
		return
	}

	summary := engine.MapAllFrameworks(policies, inv)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(summary); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(engine.FormatComplianceSummary(summary))
	}
}

func cmdComplianceSOC(dir, fw string, jsonOut bool) {
	results := loadAndSimulateDir(dir, "")
	if len(results) == 0 {
		exitValidation("no campaigns found in %s", dir)
	}

	gapReport := gap.Analyze(results...)

	if fw != "" {
		if !compliance.ValidFramework(fw) {
			exitValidation("unknown SOC framework: %s (use -list to see available)", fw)
		}
		assessment, aErr := compliance.Assess(gapReport, compliance.Framework(fw))
		if aErr != nil {
			exitRuntime("compliance assessment: %s", aErr)
		}
		if jsonOut {
			out, jErr := compliance.FormatAssessmentJSON(assessment)
			if jErr != nil {
				exitRuntime("JSON output: %s", jErr)
			}
			fmt.Println(out)
		} else {
			fmt.Print(compliance.FormatAssessment(assessment))
		}
		return
	}

	assessments, aErr := compliance.AssessAll(gapReport)
	if aErr != nil {
		exitRuntime("compliance assessment: %s", aErr)
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(assessments); encErr != nil {
			exitRuntime("JSON output: %s", encErr)
		}
	} else {
		fmt.Print(compliance.FormatMultiAssessment(assessments))
	}
}

func cmdDashboard(args []string) {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	policyDir := fs.String("policy", "", "policy directory")
	agentDir := fs.String("agents", "agents/", "agent inventory directory")
	output := fs.String("output", "", "HTML output file (default: stdout as text)")
	title := fs.String("title", "ThreatEcho Security Dashboard", "dashboard title")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho dashboard [flags]

Generate a comprehensive HTML security dashboard combining risk assessment,
policy quality, threat analysis, and agent inventory into one report.

Without -output, prints a text summary to stdout.
With -output, writes a self-contained HTML file.

Examples:
  threatecho dashboard -policy policies/agent-strict/ -agents agents/
  threatecho dashboard -output report.html
  threatecho dashboard -title "Q3 Security Review" -output review.html

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	cfg := report.DefaultDashboardConfig()
	cfg.Title = *title

	var opts []report.DashboardOption

	// Load agents if available.
	inv, _ := agent.LoadInventory(*agentDir)
	if inv != nil {
		opts = append(opts, report.WithAgentInventory(inv))
	}

	// Load policy if available.
	polPath := *policyDir
	if polPath == "" {
		polPath = findPolicyDir()
	}
	if polPath != "" {
		p, pErr := policy.LoadPolicy(polPath)
		if pErr == nil {
			policies := []*policy.Policy{p}
			opts = append(opts, report.WithPolicies(policies))

			// Add lint report.
			lr := policy.LintPolicy(p)
			opts = append(opts, report.WithLintReport(lr))
		}
	}

	dash := report.BuildDashboard(cfg, opts...)

	if *output != "" {
		if err := report.WriteDashboard(dash, *output); err != nil {
			exitRuntime("writing dashboard: %s", err)
		}
		fmt.Fprintf(os.Stderr, "✓ Dashboard written to %s\n", *output)
	} else {
		fmt.Print(report.FormatDashboardText(dash))
	}
}

func cmdPolicyImpact(args []string) {
	fs := flag.NewFlagSet("policy impact", flag.ExitOnError)
	beforePath := fs.String("before", "", "baseline policy path (required)")
	afterPath := fs.String("after", "", "updated policy path (required)")
	agentDir := fs.String("agents", "agents/", "agent inventory directory")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho policy impact [flags]

Analyze the impact of policy changes on agents and historical traces.
Compares two policy versions and reports what would change: new denials,
lifted restrictions, breaking changes, and lint score deltas.

Examples:
  threatecho policy impact -before policies/v1/ -after policies/v2/ -agents agents/
  threatecho policy impact -before old.yaml -after new.yaml -json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *beforePath == "" || *afterPath == "" {
		fmt.Fprintln(os.Stderr, "✗ both -before and -after are required")
		os.Exit(cli.ExitUsage)
	}

	before, err := policy.LoadPolicy(*beforePath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading baseline policy"))
	}
	after, aErr := policy.LoadPolicy(*afterPath)
	if aErr != nil {
		exitErr(cli.IOWrap(aErr, "loading updated policy"))
	}

	// Convert agents to ImpactAgent projections.
	var agents []policy.ImpactAgent
	inv, _ := agent.LoadInventory(*agentDir)
	if inv != nil {
		for _, a := range inv.Agents {
			ia := policy.ImpactAgent{Name: a.Meta.Name}
			for _, t := range a.Tools {
				ia.Tools = append(ia.Tools, t.Name)
			}
			agents = append(agents, ia)
		}
	}

	rpt := policy.AnalyzeImpact(before, after, agents)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(rpt); encErr != nil {
			exitRuntime("JSON output failed: %s", encErr)
		}
	} else {
		fmt.Print(policy.FormatImpactReport(rpt))
	}
}

func cmdAttackTree(args []string) {
	fs := flag.NewFlagSet("attack-tree", flag.ExitOnError)
	policyDir := fs.String("policy", "", "policy directory for mitigation analysis")
	agentDir := fs.String("agents", "agents/", "agent inventory directory")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho attack-tree [flags]

Build attack trees from an agent inventory with probabilistic risk scoring.
Decomposes "compromise the agent deployment" into per-agent sub-goals,
tool exploitation, trust abuse, prompt injection, and guardrail evasion
vectors. Policies mark mitigated attack leaves.

Output includes:
  - Tree structure with AND/OR decomposition and probability propagation
  - Per-node probability, impact, and risk score
  - Top attack paths ranked by risk
  - Mitigation coverage (mitigated/unmitigated leaf counts)

Examples:
  threatecho attack-tree -agents agents/
  threatecho attack-tree -policy policies/agent-strict/ -agents agents/
  threatecho attack-tree -json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	inv, invErr := agent.LoadInventory(*agentDir)
	if invErr != nil {
		exitRuntime("loading agents: %s", invErr)
	}

	var policies []*policy.Policy
	polPath := *policyDir
	if polPath == "" {
		polPath = findPolicyDir()
	}
	if polPath != "" {
		p, pErr := policy.LoadPolicy(polPath)
		if pErr == nil {
			policies = append(policies, p)
		}
	}

	tree := engine.BuildAttackTree(inv, policies)

	if *jsonOut {
		out, jErr := engine.FormatAttackTreeJSON(tree)
		if jErr != nil {
			exitRuntime("JSON output: %s", jErr)
		}
		fmt.Println(out)
	} else {
		fmt.Print(engine.FormatAttackTree(tree))
	}
}

// --- deploy ---

func cmdDeploy(args []string) {
	fs := flag.NewFlagSet("deploy", flag.ExitOnError)
	inventory := fs.String("inventory", "", "target inventory YAML file")
	target := fs.String("target", "", "single target host (alternative to -inventory)")
	user := fs.String("user", "", "SSH user (single-target mode)")
	password := fs.String("password", "", "SSH password (single-target mode, or use -key)")
	keyPath := fs.String("key", "", "SSH private key path (single-target mode)")
	targetOS := fs.String("os", "linux", "target OS: linux, windows, darwin (single-target mode)")
	port := fs.Int("port", 0, "SSH/WinRM port (default: auto from OS)")
	mode := fs.String("mode", "agentless", "deployment mode: agentless, agent")
	agentBinary := fs.String("agent-binary", "", "path to threatecho-agent binary (required for agent mode)")
	elevated := fs.Bool("elevated", false, "allow elevated execution on targets")
	parallel := fs.Bool("parallel", false, "deploy to targets in parallel")
	workDir := fs.String("workdir", "", "remote working directory")
	format := fs.String("format", "text", "output format: text, json")
	timeout := fs.Duration("timeout", 0, "overall deploy timeout (e.g. 30m, 1h); 0 means no limit")
	verbose := fs.Bool("verbose", false, "show per-target and per-stage progress")
	quiet := fs.Bool("quiet", false, "suppress text output (exit code only); JSON output still emitted with -format json")
	fs.BoolVar(quiet, "q", false, "suppress text output (shorthand for -quiet)")
	validateOnly := fs.Bool("validate", false, "validate inventory and campaign only, do not deploy")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho deploy [flags] <campaign-path>

Deploy a campaign to remote targets. Linux/macOS targets use SSH;
Windows targets use WinRM with NTLM authentication. Supports two modes:

  agentless   Run each stage command directly over SSH/WinRM (default)
  agent       Push the threatecho-agent binary + campaign to target,
              run remotely, pull JSON report back

Target selection (pick one):
  -inventory <path>   Deploy to all targets in inventory YAML
  -target <host>      Deploy to a single target (requires -user, -os)

⚠  This executes real commands on remote machines. Review your campaign
   and target inventory before deploying. Use -validate for a dry check.

Examples:
  threatecho deploy -target 10.0.0.1 -user operator -key ~/.ssh/id_rsa campaigns/apt29/
  threatecho deploy -target 10.0.0.5 -os windows -user 'DOMAIN\Admin' -password P@ss campaigns/apt29/
  threatecho deploy -inventory targets.yaml campaigns/apt29/
  threatecho deploy -inventory targets.yaml -mode agent -agent-binary ./threatecho-agent campaigns/apt29/
  threatecho deploy -inventory targets.yaml -parallel -format json campaigns/apt29/
  threatecho deploy -validate -inventory targets.yaml campaigns/apt29/
  threatecho deploy -q -inventory targets.yaml campaigns/apt29/  # CI: exit code only

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		exitUsage()
	}

	campaignPath := fs.Arg(0)

	// Load and validate campaign.
	c, err := campaign.Load(campaignPath)
	if err != nil {
		exitErr(cli.IOWrap(err, "loading campaign"))
	}
	errs := campaign.Validate(c)
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "✗ %s", cli.ValidationErrors(c.Meta.Name, errs))
		os.Exit(cli.ExitValidation)
	}

	// Build target list.
	var targets []orchestrator.Target

	switch {
	case *inventory != "":
		inv, loadErr := orchestrator.LoadInventory(*inventory)
		if loadErr != nil {
			exitErr(cli.IOWrap(loadErr, "loading inventory"))
		}
		if valErr := orchestrator.ValidateInventory(inv); valErr != nil {
			exitValidation("inventory: %s", valErr)
		}
		targets = inv.Targets

	case *target != "":
		if *user == "" {
			exitValidation("single-target mode requires -user")
		}
		if *password == "" && *keyPath == "" {
			exitValidation("single-target mode requires -password or -key")
		}
		if *targetOS == "windows" && *password == "" {
			exitValidation("Windows targets require -password (WinRM uses NTLM authentication)")
		}
		tHost, tPort := splitHostPort(*target, *port)
		t := orchestrator.Target{
			Name:     *target,
			Host:     tHost,
			Port:     tPort,
			OS:       *targetOS,
			User:     *user,
			Password: *password,
			KeyPath:  *keyPath,
			Mode:     *mode,
		}
		orchestrator.SetDefaults(&t)
		if valErr := orchestrator.ValidateTarget(t); valErr != nil {
			exitValidation("target: %s", valErr)
		}
		targets = []orchestrator.Target{t}

	default:
		fmt.Fprintf(os.Stderr, "✗ Specify -target <host> or -inventory <path>\n\n")
		fs.Usage()
		exitUsage()
	}

	// Validate-only mode.
	if *validateOnly {
		if !*quiet {
			fmt.Printf("✓ Campaign %q valid (%d stages)\n", c.Meta.Name, len(c.Stages))
			fmt.Printf("✓ %d target(s) validated\n", len(targets))
			for _, t := range targets {
				fmt.Printf("  • %s (%s@%s:%d, %s, %s)\n", t.Name, t.User, t.Host, t.Port, t.OS, t.Mode)
			}
		}
		return
	}

	// Build deploy config.
	deployCfg := orchestrator.DeployConfig{
		AllowElevated: *elevated,
		AgentBinary:   *agentBinary,
		WorkDir:       *workDir,
		Parallel:      *parallel,
		Verbose:       *verbose,
	}

	needsAgent := *mode == "agent"
	for _, t := range targets {
		if t.Mode == "agent" {
			needsAgent = true
			break
		}
	}
	if needsAgent && *agentBinary == "" {
		exitValidation("agent mode requires -agent-binary <path>")
	}

	// Set up signal handling and optional overall timeout.
	var ctx context.Context
	var cancel context.CancelFunc
	if *timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), *timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n⚠ Interrupted — cancelling deployments...\n")
		cancel()
	}()

	// Deploy.
	displayMode := *mode
	if *inventory != "" {
		modes := make(map[string]bool)
		for _, t := range targets {
			modes[t.Mode] = true
		}
		if len(modes) == 1 {
			for m := range modes {
				displayMode = m
			}
		} else {
			displayMode = "mixed"
		}
	}
	if !*quiet {
		if *timeout > 0 {
			fmt.Fprintf(os.Stderr, "Deploying %q to %d target(s) [mode=%s, timeout=%s]\n\n",
				c.Meta.Name, len(targets), displayMode, *timeout)
		} else {
			fmt.Fprintf(os.Stderr, "Deploying %q to %d target(s) [mode=%s]\n\n",
				c.Meta.Name, len(targets), displayMode)
		}
	}

	started := time.Now()
	results := orchestrator.Run(ctx, targets, c, deployCfg)

	// Build and display report.
	deployReport := orchestrator.BuildDeployReport(c.Meta.Name, started, results)

	deployFmt := resolveFormat(*format)
	checkFormat(deployFmt, "text", "json")
	switch deployFmt {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(deployReport); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
	default:
		if !*quiet {
			fmt.Print(orchestrator.FormatDeployReport(deployReport))
		}
	}

	if deployReport.Summary.Failed > 0 {
		os.Exit(cli.ExitRuntime)
	}
	if deployReport.Summary.StageFailed > 0 {
		os.Exit(cli.ExitRuntime)
	}
}

func cmdDeployBaseline(args []string) {
	fs := flag.NewFlagSet("deploy-baseline", flag.ExitOnError)
	policyDir := fs.String("policy", "", "policy directory")
	agentDir := fs.String("agents", "", "agent inventory directory")
	label := fs.String("label", "", "label for the baseline snapshot")
	output := fs.String("output", "", "save baseline to JSON file")
	compare := fs.String("compare", "", "compare current state against a saved baseline JSON")
	jsonOut := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: threatecho deploy-baseline [flags]

Capture a point-in-time snapshot of the deployment security posture
(policies and agents) and compare snapshots to detect drift.

Modes:
  Capture:  threatecho deploy-baseline -policy policies/ -agents agents/
  Compare:  threatecho deploy-baseline -policy policies/ -agents agents/ -compare baseline.json
  View:     threatecho deploy-baseline -compare baseline.json

Examples:
  threatecho deploy-baseline -policy policies/ -agents agents/ -label "v1.0" -output baseline.json
  threatecho deploy-baseline -policy policies/ -agents agents/ -compare baseline.json
  threatecho deploy-baseline -compare baseline.json -json

Flags:
`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	needCapture := *policyDir != "" || *agentDir != ""
	needCompare := *compare != ""

	if !needCapture && !needCompare {
		fs.Usage()
		exitUsage()
	}

	// Compare-only mode: load and display a saved baseline.
	if !needCapture && needCompare {
		saved, err := engine.LoadBaseline(*compare)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading baseline"))
		}
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(saved); err != nil {
				exitRuntime("JSON output failed: %s", err)
			}
		} else {
			fmt.Print(engine.FormatBaseline(saved))
		}
		return
	}

	// Load policies.
	var policies []*policy.Policy
	if *policyDir != "" {
		loaded, err := policy.LoadDir(*policyDir)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading policies"))
		}
		policies = loaded
	}

	// Load agents.
	var inv *agent.Inventory
	if *agentDir != "" {
		loaded, err := agent.LoadInventory(*agentDir)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading agent inventory"))
		}
		inv = loaded
	}

	current := engine.CaptureBaseline(policies, inv, *label)

	// Compare mode.
	if needCompare {
		saved, err := engine.LoadBaseline(*compare)
		if err != nil {
			exitErr(cli.IOWrap(err, "loading baseline for comparison"))
		}
		diff := engine.DiffBaselines(saved, current)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(diff); err != nil {
				exitRuntime("JSON output failed: %s", err)
			}
		} else {
			fmt.Print(engine.FormatBaselineDiff(diff))
		}
		return
	}

	// Capture mode.
	if *output != "" {
		if err := engine.SaveBaseline(current, *output); err != nil {
			exitErr(cli.IOWrap(err, "saving baseline"))
		}
		fmt.Fprintf(os.Stderr, "✓ Baseline saved to %s\n", *output)
		fmt.Fprintln(os.Stderr, engine.SummarizeBaseline(current))
		return
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(current); err != nil {
			exitRuntime("JSON output failed: %s", err)
		}
	} else {
		fmt.Print(engine.FormatBaseline(current))
	}
}
