<p align="center">
  <img src="assets/logo-circle-800.jpg" alt="ThreatEcho" width="100" />
</p>

# Security Policy

## Reporting vulnerabilities

If you discover a security vulnerability in ThreatEcho, please report it responsibly.

**Email:** security@threatecho.com

Do **not** open a public GitHub issue for security vulnerabilities.

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We aim to acknowledge receipt within 48 hours and provide an initial assessment within 7 days.

## Scope

ThreatEcho is a simulation and analysis tool — it does not connect to production infrastructure by default. Security concerns include:

- **Campaign execution safety** — the `run` command executes real shell commands. The `-deny-elevated` flag (default: true) blocks privileged operations, but operators should review campaign YAML before live execution.
- **Policy bypass** — the policy engine is an analysis tool, not an enforcement runtime. It evaluates what *would* happen, not what *is* happening. Do not use it as a substitute for actual agent sandboxing.
- **YAML parsing** — campaign and policy YAML files are parsed with `gopkg.in/yaml.v3`. Maliciously crafted YAML could trigger excessive memory allocation (yaml bomb). Only load trusted campaign files.
- **Output injection** — campaign field values (names, descriptions, IOCs) flow into SARIF, JUnit, HTML, and Markdown reports. Values are escaped where formats require it, but review generated reports before publishing them to untrusted consumers.
- **Remote deployment** — the `deploy` command connects to targets via SSH and WinRM, transfers files, and executes commands remotely. Review your inventory file and campaign YAML before deploying. Use `-validate` for a dry check. Never deploy to machines you do not own or have authorization to test.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest  | ✓         |
| Older   | Best effort |

## Safe usage guidelines

1. **Review before running.** Always read a campaign YAML before using `threatecho run`. The `simulate` command is safe — it never executes commands.
2. **Isolate live execution.** Run `threatecho run` in a VM, container, or test environment — never on production systems.
3. **Audit policies, don't trust them.** Policy evaluation shows what rules *would* match. It does not enforce them at runtime.
4. **Validate SARIF before upload.** If uploading SARIF to GitHub Code Scanning, verify the results represent real findings, not campaign simulation artifacts.
