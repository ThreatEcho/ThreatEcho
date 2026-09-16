// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package cli

import (
	"fmt"
	"io"
	"strings"
)

// commands lists all top-level commands for completion.
var commands = []string{
	"validate", "lint", "simulate", "run", "gap", "compare",
	"policy", "export", "summary", "matrix", "coverage",
	"campaigns", "config", "hash", "graph", "fmt", "doctor",
	"telemetry", "init", "version", "help", "diff", "merge",
	"completion", "profile", "watch", "template", "timeline", "env",
	"search", "stats", "import", "enrich", "score", "convert",
	"tag", "report", "audit", "baseline", "trace", "agent", "scenario",
	"threat-model",
	"risk-posture",
	"compliance",
	"dashboard",
	"deploy",
	"deploy-baseline",
	"attack-tree",
}

// subcommands maps parent commands to their subcommands.
var subcommands = map[string][]string{
	"agent":      {"list", "show", "validate", "trust", "test", "guardrail", "graph", "export", "chain", "attest", "profile", "dependency"},
	"policy":     {"validate", "eval", "export", "compile", "merge", "coverage", "test", "generate", "risk", "diff", "guardrail", "history", "simulate", "compliance", "benchmark", "drift", "lint", "coveragemap", "remediate", "impact"},
	"export":     {"navigator", "sigma"},
	"campaigns":  {"list", "show"},
	"config":     {"show", "path", "init"},
	"graph":      {"analyze", "dot", "mermaid"},
	"telemetry":  {"list", "categories", "check", "stats"},
	"completion": {"bash", "zsh", "fish"},
	"template":   {"list", "create"},
	"scenario":   {"run", "validate", "list"},
	"trace":      {"replay", "correlate", "forensics"},
}

// flagsByCommand maps commands to their flags (without leading -).
var flagsByCommand = map[string][]string{
	"simulate":           {"platform", "format"},
	"gap":                {"platform", "format", "dir"},
	"lint":               {"dir", "format"},
	"run":                {"platform", "format", "deny-elevated", "max-output", "workdir"},
	"compare":            {"platform", "format"},
	"summary":            {"dir", "policy"},
	"matrix":             {"dir", "platform", "compact"},
	"coverage":           {"dir", "platform", "format"},
	"campaigns":          {"dir"},
	"hash":               {"dir", "manifest"},
	"fmt":                {"w", "dir", "normalize"},
	"doctor":             {"dir", "policy"},
	"diff":               {"format"},
	"merge":              {"name", "prefix", "strategy", "output"},
	"profile":            {"dir", "format"},
	"export navigator":   {"dir", "platform", "output", "gap"},
	"export sigma":       {"dir", "output", "author"},
	"policy eval":        {"policy", "format", "dir"},
	"telemetry list":     {"category"},
	"telemetry stats":    {"dir"},
	"watch":              {"dir", "validate", "lint", "format", "interval"},
	"template create":    {"template", "name", "output"},
	"timeline":           {"dir", "format"},
	"env":                {"dir", "check"},
	"search":             {"technique", "tactic", "adversary", "tag", "keyword", "severity", "stage", "platform", "exec-type", "dir", "json"},
	"stats":              {"dir", "json"},
	"import":             {"source", "name", "adversary", "platforms", "max-tests", "output"},
	"enrich":             {"dir", "json"},
	"score":              {"dir", "detail", "json"},
	"convert":            {"format", "indent", "compact", "normalize", "output", "dir"},
	"tag":                {"dir", "find", "suggest", "json"},
	"report":             {"dir", "format", "output", "json"},
	"audit":              {"dir", "output", "compare", "json"},
	"baseline":           {"dir", "label", "output", "compare", "json"},
	"agent list":         {"dir", "json"},
	"agent show":         {"json"},
	"agent validate":     {"dir"},
	"agent trust":        {"dir", "json"},
	"agent test":         {"policy", "dir", "json"},
	"agent guardrail":    {"dir", "json"},
	"agent graph":        {"dir", "format", "json"},
	"agent export":       {"dir", "format", "output"},
	"trace":              {"policy", "json"},
	"trace replay":       {"policy", "json"},
	"trace correlate":    {"json"},
	"trace forensics":    {"json"},
	"agent dependency":   {"dir", "agent", "json"},
	"policy impact":      {"before", "after", "agents", "json"},
	"compliance":         {"policy", "agents", "framework", "json", "list", "dir"},
	"dashboard":          {"policy", "agents", "output", "title"},
	"deploy":             {"inventory", "target", "user", "password", "key", "os", "port", "mode", "agent-binary", "elevated", "parallel", "workdir", "format", "timeout", "verbose", "validate", "quiet", "q"},
	"deploy-baseline":    {"policy", "agents", "label", "output", "compare", "json"},
	"attack-tree":        {"policy", "agents", "json"},
	"policy export":      {"format", "output"},
	"policy compile":     {"json"},
	"policy merge":       {"output"},
	"policy coverage":    {"dir", "json"},
	"policy test":        {"scenario", "json", "list"},
	"policy generate":    {"agent", "name", "output", "list"},
	"policy risk":        {"dir", "json"},
	"policy diff":        {"json"},
	"policy guardrail":   {"policy", "json", "defaults"},
	"policy history":     {"init", "add", "diff", "author", "comment", "file", "json"},
	"policy simulate":    {"policy", "dir", "json"},
	"policy compliance":  {"policy", "json"},
	"policy benchmark":   {"iterations", "json"},
	"policy drift":       {"json"},
	"policy lint":        {"json"},
	"agent chain":        {"dir", "json"},
	"agent attest":       {"dir", "agent", "verify", "json"},
	"agent profile":      {"dir", "agent", "traces", "json"},
	"policy coveragemap": {"json"},
	"policy remediate":   {"json", "source", "baseline"},
	"threat-model":       {"agents", "policies", "json"},
	"risk-posture":       {"policy", "agents", "json"},
	"scenario run":       {"dir", "agent", "type", "policy", "json", "metadata"},
	"scenario validate":  {"dir"},
	"scenario list":      {"dir", "json"},
}

// BashCompletion writes a bash completion script for threatecho.
func BashCompletion(w io.Writer) {
	// Header and function opening.
	fmt.Fprint(w, "# bash completion for threatecho -*- shell-script -*-\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "_threatecho_completions() {\n")
	fmt.Fprint(w, "    local cur prev words cword\n")
	fmt.Fprint(w, "    _init_completion || return\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "    # Top-level commands\n")
	fmt.Fprintf(w, "    local commands=\"%s\"\n", strings.Join(commands, " "))
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "    # If we're completing the first argument, show commands\n")
	fmt.Fprint(w, "    if [[ ${cword} -eq 1 ]]; then\n")
	fmt.Fprint(w, "        COMPREPLY=($(compgen -W \"${commands}\" -- \"${cur}\"))\n")
	fmt.Fprint(w, "        return\n")
	fmt.Fprint(w, "    fi\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "    local cmd=\"${words[1]}\"\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "    # Handle subcommands\n")
	fmt.Fprint(w, "    case \"${cmd}\" in\n")

	for parent, subs := range subcommands {
		fmt.Fprintf(w, "        %s)\n", parent)
		fmt.Fprint(w, "            if [[ ${cword} -eq 2 ]]; then\n")
		fmt.Fprintf(w, "                COMPREPLY=($(compgen -W \"%s\" -- \"${cur}\"))\n", strings.Join(subs, " "))
		fmt.Fprint(w, "                return\n")
		fmt.Fprint(w, "            fi\n")
		fmt.Fprint(w, "            ;;\n")
	}

	fmt.Fprint(w, "    esac\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "    # Handle flags\n")
	fmt.Fprint(w, "    if [[ \"${cur}\" == -* ]]; then\n")
	fmt.Fprint(w, "        local flags=\"\"\n")
	fmt.Fprint(w, "        local subcmd=\"\"\n")
	fmt.Fprint(w, "        if [[ ${cword} -ge 3 ]]; then\n")
	fmt.Fprint(w, "            subcmd=\"${cmd} ${words[2]}\"\n")
	fmt.Fprint(w, "        fi\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "        case \"${subcmd}\" in\n")

	for compound, flags := range flagsByCommand {
		if !strings.Contains(compound, " ") {
			continue
		}
		dashed := make([]string, len(flags))
		for i, f := range flags {
			dashed[i] = "-" + f
		}
		fmt.Fprintf(w, "            \"%s\")\n", compound)
		fmt.Fprintf(w, "                flags=\"%s\"\n", strings.Join(dashed, " "))
		fmt.Fprint(w, "                ;;\n")
	}

	fmt.Fprint(w, "        esac\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "        if [[ -z \"${flags}\" ]]; then\n")
	fmt.Fprint(w, "            case \"${cmd}\" in\n")

	for cmd, flags := range flagsByCommand {
		if strings.Contains(cmd, " ") {
			continue
		}
		dashed := make([]string, len(flags))
		for i, f := range flags {
			dashed[i] = "-" + f
		}
		fmt.Fprintf(w, "                %s)\n", cmd)
		fmt.Fprintf(w, "                    flags=\"%s\"\n", strings.Join(dashed, " "))
		fmt.Fprint(w, "                    ;;\n")
	}

	fmt.Fprint(w, "            esac\n")
	fmt.Fprint(w, "        fi\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "        if [[ -n \"${flags}\" ]]; then\n")
	fmt.Fprint(w, "            COMPREPLY=($(compgen -W \"${flags}\" -- \"${cur}\"))\n")
	fmt.Fprint(w, "            return\n")
	fmt.Fprint(w, "        fi\n")
	fmt.Fprint(w, "    fi\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "    # Default to file/directory completion for campaign paths\n")
	fmt.Fprint(w, "    _filedir\n")
	fmt.Fprint(w, "}\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "complete -F _threatecho_completions threatecho\n")
}

// ZshCompletion writes a zsh completion script for threatecho.
func ZshCompletion(w io.Writer) {
	fmt.Fprint(w, "#compdef threatecho\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "_threatecho() {\n")
	fmt.Fprint(w, "    local -a commands\n")
	fmt.Fprint(w, "    commands=(\n")

	for _, cmd := range commands {
		desc := commandDescription(cmd)
		fmt.Fprintf(w, "        '%s:%s'\n", cmd, desc)
	}

	fmt.Fprint(w, "    )\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "    _arguments -C \\\n")
	fmt.Fprint(w, "        '1:command:->command' \\\n")
	fmt.Fprint(w, "        '*::arg:->args'\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "    case $state in\n")
	fmt.Fprint(w, "        command)\n")
	fmt.Fprint(w, "            _describe 'command' commands\n")
	fmt.Fprint(w, "            ;;\n")
	fmt.Fprint(w, "        args)\n")
	fmt.Fprint(w, "            case $words[1] in\n")

	for parent, subs := range subcommands {
		fmt.Fprintf(w, "                %s)\n", parent)
		fmt.Fprint(w, "                    local -a subcmds\n")
		fmt.Fprint(w, "                    subcmds=(\n")
		for _, sub := range subs {
			fmt.Fprintf(w, "                        '%s'\n", sub)
		}
		fmt.Fprint(w, "                    )\n")
		fmt.Fprint(w, "                    _describe 'subcommand' subcmds\n")

		// Add flags for the parent.
		if flags, ok := flagsByCommand[parent]; ok {
			fmt.Fprint(w, "                    _arguments \\\n")
			for i, f := range flags {
				if i == len(flags)-1 {
					fmt.Fprintf(w, "                        '-%s[%s flag]'\n", f, f)
				} else {
					fmt.Fprintf(w, "                        '-%s[%s flag]' \\\n", f, f)
				}
			}
		}

		fmt.Fprint(w, "                    _files\n")
		fmt.Fprint(w, "                    ;;\n")
	}

	// Commands without subcommands.
	for cmd, flags := range flagsByCommand {
		if strings.Contains(cmd, " ") {
			continue
		}
		if _, hasSub := subcommands[cmd]; hasSub {
			continue
		}
		fmt.Fprintf(w, "                %s)\n", cmd)
		fmt.Fprint(w, "                    _arguments \\\n")
		for i, f := range flags {
			if i == len(flags)-1 {
				fmt.Fprintf(w, "                        '-%s[%s flag]'\n", f, f)
			} else {
				fmt.Fprintf(w, "                        '-%s[%s flag]' \\\n", f, f)
			}
		}
		fmt.Fprint(w, "                    _files\n")
		fmt.Fprint(w, "                    ;;\n")
	}

	fmt.Fprint(w, "                *)\n")
	fmt.Fprint(w, "                    _files\n")
	fmt.Fprint(w, "                    ;;\n")
	fmt.Fprint(w, "            esac\n")
	fmt.Fprint(w, "            ;;\n")
	fmt.Fprint(w, "    esac\n")
	fmt.Fprint(w, "}\n")
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, "_threatecho \"$@\"\n")
}

// FishCompletion writes a fish completion script for threatecho.
func FishCompletion(w io.Writer) {
	fmt.Fprint(w, "# fish completion for threatecho\n\n")

	// Disable file completion by default.
	fmt.Fprint(w, "complete -c threatecho -f\n\n")

	// Top-level commands.
	for _, cmd := range commands {
		desc := commandDescription(cmd)
		fmt.Fprintf(w, "complete -c threatecho -n '__fish_use_subcommand' -a '%s' -d '%s'\n", cmd, desc)
	}

	fmt.Fprint(w, "\n# Subcommands\n")
	for parent, subs := range subcommands {
		for _, sub := range subs {
			fmt.Fprintf(w, "complete -c threatecho -n '__fish_seen_subcommand_from %s' -a '%s'\n", parent, sub)
		}
	}

	fmt.Fprint(w, "\n# Flags\n")
	for cmd, flags := range flagsByCommand {
		condition := fmt.Sprintf("__fish_seen_subcommand_from %s", cmd)
		if strings.Contains(cmd, " ") {
			parts := strings.SplitN(cmd, " ", 2)
			condition = fmt.Sprintf("__fish_seen_subcommand_from %s; and __fish_seen_subcommand_from %s", parts[0], parts[1])
		}
		for _, f := range flags {
			fmt.Fprintf(w, "complete -c threatecho -n '%s' -l '%s'\n", condition, f)
		}
	}

	fmt.Fprint(w, "\n# Enable file completion for path arguments\n")
	pathCommands := []string{"validate", "simulate", "run", "deploy", "compare", "hash", "fmt", "diff", "merge", "profile", "timeline", "env", "trace"}
	for _, cmd := range pathCommands {
		fmt.Fprintf(w, "complete -c threatecho -n '__fish_seen_subcommand_from %s' -F\n", cmd)
	}
}

// commandDescription returns a short description for a command.
func commandDescription(cmd string) string {
	descriptions := map[string]string{
		"validate":        "Validate campaign YAML",
		"lint":            "Run quality checks",
		"simulate":        "Dry-run a campaign",
		"run":             "Execute campaign live",
		"gap":             "Detection gap analysis",
		"compare":         "Compare gap reports",
		"policy":          "Policy validation and evaluation",
		"export":          "Export Navigator or Sigma",
		"summary":         "Security posture dashboard",
		"matrix":          "ATT&CK coverage matrix",
		"coverage":        "Technique coverage analysis",
		"campaigns":       "List and inspect campaigns",
		"config":          "Configuration management",
		"hash":            "Campaign fingerprinting",
		"graph":           "Dependency graph analysis",
		"fmt":             "Format campaign YAML",
		"doctor":          "Workspace health check",
		"telemetry":       "Telemetry registry",
		"init":            "Initialize workspace",
		"version":         "Print version",
		"help":            "Show help",
		"diff":            "Compare two campaigns",
		"merge":           "Merge campaigns",
		"completion":      "Generate shell completions",
		"profile":         "Campaign complexity profile",
		"watch":           "Watch files for changes",
		"template":        "Campaign scaffolding templates",
		"timeline":        "Execution time estimate",
		"env":             "Environment variable references",
		"search":          "Search campaigns by technique, tactic, keyword",
		"stats":           "Campaign analytics dashboard",
		"import":          "Import Atomic Red Team tests",
		"enrich":          "ATT&CK metadata enrichment",
		"score":           "Campaign risk and complexity scoring",
		"convert":         "Convert campaign formats",
		"tag":             "Tag management and suggestions",
		"report":          "Executive assessment reports",
		"audit":           "Campaign state snapshots",
		"baseline":        "Behavioral baseline and drift detection",
		"trace":           "Agent execution trace analysis, replay, and correlation",
		"agent":           "Agent inventory, trust, and attestation",
		"scenario":        "Agent execution trace generation",
		"deploy":          "Deploy campaign to remote targets",
		"deploy-baseline": "Deployment state baseline and drift",
		"threat-model":    "Threat model from agents and policies",
		"risk-posture":    "Risk posture assessment",
		"compliance":      "Compliance framework mapping",
		"dashboard":       "Security posture dashboard",
		"attack-tree":     "Attack tree analysis",
	}
	if d, ok := descriptions[cmd]; ok {
		return d
	}
	return cmd
}
