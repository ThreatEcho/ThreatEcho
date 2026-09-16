<p align="center">
  <img src="assets/logo-circle-800.jpg" alt="ThreatEcho" width="400" />
</p>

# Code of Conduct

## Responsible use

ThreatEcho is an adversary simulation and detection engineering tool. It is designed to **strengthen** defensive posture - never to enable attacks against systems you do not own or have explicit authorization to test.

### Safe simulation principles

1. **Authorization first.** Only run campaigns against systems where you have written permission from the system owner. This includes internal test environments, purple team exercises, and contracted penetration tests.

2. **Never weaken production defenses.** Policy modifications, guardrail changes, and baseline snapshots should always trend toward stronger security posture. If a change degrades defenses, flag it - do not silently merge it.

3. **Simulations are not attacks.** Campaign stages model adversary behavior for detection engineering. The `simulate` command runs in dry-run mode by default. Live execution (`run`) should only target isolated, non-production environments.

4. **Protect sensitive findings.** Gap reports, policy evaluations, and SARIF outputs may reveal detection blind spots. Treat them as confidential vulnerability data. Do not publish unredacted gap analysis for production systems.

5. **Agent security is real security.** AI agent tool-call policies define intended enforcement boundaries. When ThreatEcho identifies that an agent can bypass a policy, that is a real finding - treat it with the same urgency as a network misconfiguration.

6. **No weaponization.** Do not use campaign definitions, policy bypass findings, or gap analysis to craft actual attacks. ThreatEcho exists to help defenders, not attackers.

### Ethical AI agent testing

AI agents operating with tool-calling capabilities present unique risks:

- **Tool-call policies must be tested before deployment.** Use `policy test` with assertion suites to verify that deny rules actually fire.
- **Trust levels are assumptions, not guarantees.** Validate agent trust configurations with `agent chain` analysis and `threat-model` output.
- **Delegation chains create transitive risk.** An agent with "low" trust that delegates to a "high" trust agent inherits capabilities. Map this with `agent dependency`.
- **Baseline drift is silent regression.** Use `deploy-baseline` to capture snapshots and detect when your security posture degrades between releases.

### Reporting vulnerabilities in ThreatEcho itself

If you discover a security vulnerability in ThreatEcho, see [SECURITY.md](SECURITY.md) for responsible disclosure guidance.

### Community standards

- Provide constructive feedback on campaigns, policies, and detection logic.
- Share detection engineering knowledge - the more defenders know, the harder adversaries work.
- Respect the work of other contributors. Campaign authoring is a skill that combines threat intelligence, detection engineering, and operational security experience.
- When in doubt about whether a campaign or policy configuration is appropriate, ask before submitting.

## Scope

This code of conduct applies to all project spaces: the repository, issues, pull requests, discussions, and any channel where you represent ThreatEcho or interact with the community.

## Enforcement

Violations of these principles - especially unauthorized use, weaponization, or reckless handling of vulnerability data - will result in removal from the project.

Reports of unacceptable behavior can be sent to **security@threatecho.com**. All reports will be reviewed. The project maintainer will determine appropriate action, which may include a warning, temporary ban, or permanent removal from the project.
