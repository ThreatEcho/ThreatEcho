<p align="center">
  <img src="assets/logo-circle-800.jpg" alt="ThreatEcho" width="400" />
</p>

# Contributing to ThreatEcho

Thank you for your interest in ThreatEcho. This document covers the mechanics of contributing campaigns, policies, code, and documentation.

## Quick links

- [Writing Campaigns](docs/campaigns.md) - YAML schema reference
- [Policy DSL Reference](docs/policies.md) - rule authoring
- [Sigma Integration](docs/sigma.md) - detection rule generation
- [Architecture](docs/architecture.md) - package structure and data flow

## Prerequisites

- Go 1.26 or later
- Make (GNU Make recommended)
- A working understanding of MITRE ATT&CK, MITRE ATLAS, or OWASP LLM Top 10

## Development workflow

```bash
# Clone the repo
git clone https://github.com/ThreatEcho/threatecho.git
cd threatecho

# Build
make build

# Run full CI locally
make ci
# → fmt-check, vet, test-race, lint-campaigns

# Run tests
make test          # standard
make test-race     # with race detector
make test-verbose  # verbose output

# Check formatting
make fmt-check

# Generate coverage
make coverage
```

## Contributing campaigns

Campaigns are the highest-impact contribution. Each campaign maps real adversary TTPs to detectable telemetry.

### Campaign requirements

1. **Realistic TTPs** - based on published threat intelligence (MITRE group profiles, CISA advisories, vendor reports)
2. **Valid technique IDs** - every `technique:` field must be in the ATT&CK/ATLAS/OWASP registry
3. **Expected detections** - every stage with telemetry should declare what detections *should* fire
4. **Lint clean** - `threatecho lint <path>` must exit 0

### Steps

1. Create a directory: `campaigns/<adversary-name>/campaign.yaml`
2. Follow the schema documented in [campaigns.md](docs/campaigns.md)
3. Validate: `threatecho validate campaigns/<name>/`
4. Lint: `threatecho lint campaigns/<name>/`
5. Verify gap analysis: `threatecho gap campaigns/<name>/`
6. Submit a PR with your campaign

### Naming conventions

- Campaign directory: `kebab-case-adversary-name/`
- Stage IDs: `kebab-case-action` (e.g., `initial-access`, `c2-beacon`)
- Detection names: `snake_case_detection_name` (e.g., `lsass_memory_access`)
- Telemetry types: use existing types from [the mapping table](docs/sigma.md#telemetry-to-logsource-mapping)

## Contributing policies

Policies define enforcement rules for AI agent tool calls or SOC simulation gating.

1. Create: `policies/<policy-name>/policy.yaml`
2. Follow the DSL documented in [policies.md](docs/policies.md)
3. Validate: `threatecho policy validate policies/<name>/`
4. Test against campaigns: `threatecho policy eval -policy policies/<name>/ -dir campaigns/`
5. Submit a PR

## Contributing code

### Package responsibilities

| Package | Responsibility | OK to modify? |
|---------|---------------|---------------|
| `cmd/threatecho` | CLI entry point, flag parsing, command dispatch | Yes - add new commands here |
| `internal/campaign` | YAML loading, validation, linting, DAG | Yes |
| `internal/engine` | Simulation + live execution | Yes |
| `internal/executor` | Noop + shell executors | Yes - add new executor types |
| `internal/gap` | Gap analysis + comparison | Yes |
| `internal/mitre` | ATT&CK, ATLAS, OWASP registries | Yes - add techniques as campaigns need them |
| `internal/navigator` | ATT&CK Navigator export | Yes |
| `internal/matrix` | ATT&CK coverage matrix | Yes |
| `internal/policy` | Policy engine: eval, lint, drift, impact, coverage, testing | Yes |
| `internal/report` | All output formatters + HTML dashboard | Yes - add new formats here |
| `internal/scenario` | Scenario engine (YAML test cases) | Yes |
| `internal/sigma` | Sigma rule generation | Yes |
| `internal/telemetry` | Telemetry type registry | Yes - add new types as campaigns need them |
| `internal/trace` | Trace parsing, replay, correlation | Yes |
| `internal/orchestrator` | Remote deployment (SSH/WinRM deployers, inventory) | Yes |
| `internal/runner` | Precondition engine (platform, elevation, tool checks) | Yes |
| `internal/agent` | Agent inventory, trust, attestation, dependency graph | Yes |
| `internal/compliance` | Classical compliance mapping (NIST CSF, 800-53, CIS v8); AI frameworks (NIST AI RMF, OWASP LLM, ATLAS) are in `internal/engine/compliance.go` | Yes |
| `internal/cli` | Exit codes, error types, hints | Yes |
| `internal/config` | Layered configuration system | Yes |
| `cmd/threatecho-agent` | Agent binary (run, check, version) | Yes |
| `pkg/version` | Build version info | Rarely |

### Code standards

- **No new dependencies** unless there is no reasonable alternative. Current deps: `gopkg.in/yaml.v3`, `golang.org/x/crypto` (SSH), `github.com/masterzen/winrm` (WinRM/NTLM).
- **Deterministic output** - given the same input, every output format must produce identical results (exception: timestamps in reports). Sort maps, use stable IDs.
- **Tests required** - every new package function needs tests. Current baseline: 3,539 tests across 22 packages. Run `make test-race` before submitting.
- **`go vet` clean** - no vet warnings.
- **`gofmt`** - all files must be formatted with `gofmt`. `make fmt-check` verifies this.
- Match the style of surrounding code. No linter config wars.

### Adding a new output format

1. Create `internal/report/<format>.go` with the format function
2. Create `internal/report/<format>_test.go` with tests
3. Wire it into the CLI command (`cmdGap`, `cmdPolicyEval`, etc.)
4. Add to help text and README format tables
5. Add to CHANGELOG

### Adding ATT&CK techniques

When a campaign needs a technique not in the registry:

1. Add the entry to `internal/mitre/attack.go` → `Techniques` map
2. Use the exact MITRE ID, name, and primary tactic
3. Run `make test` to verify no regressions

For ATLAS techniques, add entries to `internal/mitre/atlas.go`. For OWASP LLM techniques, add entries to `internal/mitre/owasp_llm.go`.

## Pull request process

1. Branch from `main`
2. Make your changes
3. Ensure `make ci` passes
4. Write a descriptive PR title: `feat: add APT28 campaign` or `fix: SARIF output tool version field`
5. Reference any related issues

## Reporting bugs

Open an issue with:
- ThreatEcho version (`threatecho version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior
- Campaign YAML if relevant (redact sensitive values)

## Questions

If you have any questions or concerns regarding contributions, please feel free to reach out:

**Email:** contribution@threatecho.com

## License

By contributing, you agree that your contributions are licensed under the AGPL-3.0 license.
