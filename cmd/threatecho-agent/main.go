// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/runner"
	"github.com/ThreatEcho/threatecho/pkg/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 1
	}

	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "check":
		return cmdCheck(args[1:])
	case "version":
		fmt.Printf("threatecho-agent %s %s/%s\n", version.Version, runtime.GOOS, runtime.GOARCH)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		usage()
		return 1
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `threatecho-agent — local campaign executor for target VMs

Usage:
  threatecho-agent run [flags] <campaign.yaml>
  threatecho-agent check <campaign.yaml>
  threatecho-agent version

Commands:
  run      Execute a campaign and report results as JSON
  check    Evaluate preconditions without executing anything
  version  Print version

`)
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	elevated := fs.Bool("elevated", false, "allow stages that require elevated privileges")
	platform := fs.String("platform", "", "filter stages by platform (auto-detected if empty)")
	workdir := fs.String("workdir", "", "working directory for commands")
	maxOutput := fs.Int("max-output", 0, "max output per stage in bytes (default 1 MiB)")
	outFile := fs.String("out", "", "write JSON report to file (default: stdout)")
	env := fs.String("env", "", "extra environment variables (comma-separated KEY=VAL)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: threatecho-agent run [flags] <campaign.yaml>\n\n")
		fmt.Fprintf(os.Stderr, "Execute a campaign live with precondition checks.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "error: campaign path required\n")
		fs.Usage()
		return 1
	}

	campaignPath := fs.Arg(0)

	c, err := loadCampaign(campaignPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	cfg := runner.Config{
		AllowElevated: *elevated,
		Platform:      *platform,
		WorkDir:       *workdir,
		MaxOutput:     *maxOutput,
	}

	if *env != "" {
		cfg.Env = strings.Split(*env, ",")
	}

	// Auto-detect platform if not specified.
	if cfg.Platform == "" {
		cfg.Platform = runtime.GOOS
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	report := runner.Execute(ctx, c, cfg)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling report: %v\n", err)
		return 1
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing report: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "report written to %s\n", *outFile)
	} else {
		fmt.Println(string(data))
	}

	if report.Failed > 0 || report.PrecondFail > 0 {
		return 1
	}
	return 0
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	elevated := fs.Bool("elevated", false, "check as if elevated is permitted")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: threatecho-agent check [flags] <campaign.yaml>\n\n")
		fmt.Fprintf(os.Stderr, "Evaluate preconditions without executing anything.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "error: campaign path required\n")
		fs.Usage()
		return 1
	}

	c, err := loadCampaign(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	allPassed := true
	for _, stage := range c.Stages {
		checks := runner.CheckAll(stage, *elevated)
		passed := runner.Passed(checks)
		if !passed {
			allPassed = false
		}

		mark := "PASS"
		if !passed {
			mark = "FAIL"
		}
		fmt.Printf("[%s] %s (%s)\n", mark, stage.Name, stage.ID)
		for _, cr := range checks {
			icon := "+"
			if !cr.Passed {
				icon = "!"
			}
			fmt.Printf("  [%s] %s: %s — %s\n", icon, cr.Precondition.Type, cr.Precondition.Value, cr.Detail)
		}
	}

	if !allPassed {
		return 1
	}
	return 0
}

func loadCampaign(path string) (*campaign.Campaign, error) {
	// Accept directory containing campaign.yaml.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", path, err)
	}
	if info.IsDir() {
		path = filepath.Join(path, "campaign.yaml")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var c campaign.Campaign
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &c, nil
}
