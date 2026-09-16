// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"fmt"
	"sort"
	"strings"
)

// TemplateParam describes a single customizable parameter of a policy
// template. Values supplied through a TemplateConfig are validated against
// Type and Required before a template is rendered.
type TemplateParam struct {
	Name        string
	Description string
	Type        string // "string", "bool", "int", "list"
	Default     interface{}
	Required    bool
}

// PolicyTemplate is a named, parameterized policy scaffold that RenderTemplate
// turns into a concrete Policy. BasePolicy holds the skeleton (metadata, agent
// scope, and rules) that parameter values are applied on top of.
type PolicyTemplate struct {
	Name        string
	Description string
	Category    string // "agent", "rag", "tool-control", "autonomous", "compliance"
	Tags        []string
	Parameters  []TemplateParam
	BasePolicy  *Policy
}

// TemplateConfig carries parameter overrides supplied when rendering a
// template. Values not present here fall back to each parameter's Default.
type TemplateConfig struct {
	Values map[string]interface{}
}

// TemplateCatalog is a collection of available policy templates, as returned
// by ListTemplates.
type TemplateCatalog struct {
	Templates []PolicyTemplate
}

// builtinTemplates holds all shipped policy templates. Do not mutate entries
// directly — GetTemplate and RenderTemplate return copies.
var builtinTemplates = []PolicyTemplate{
	{
		Name:        "agent-minimal",
		Description: "Basic deny-by-default policy — blocks shell and code execution, allows everything else",
		Category:    "agent",
		Tags:        []string{"development", "testing", "minimal", "deny-by-default"},
		Parameters: []TemplateParam{
			{Name: "agent_name", Description: "Agent name or pattern this policy applies to", Type: "string", Default: "*", Required: false},
			{Name: "alert_on_http", Description: "Emit an alert rule for outbound HTTP requests", Type: "bool", Default: true, Required: false},
		},
		BasePolicy: &Policy{
			APIVersion: "v1",
			Kind:       "Policy",
			Meta: PolicyMeta{
				Name:        "agent-minimal",
				Description: "Minimal deny-by-default agent policy. Blocks shell and code execution; allows all other tool calls. Suitable as a starting point for dev/test agents.",
				Authors:     []string{"ThreatEcho"},
			},
			Agent: AgentScope{Name: "*", Type: "llm"},
			Rules: []Rule{
				{
					ID:          "deny-shell-exec",
					Description: "Block shell command execution",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tools: []string{"shell_exec"}},
				},
				{
					ID:          "deny-code-exec",
					Description: "Block arbitrary code execution",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tools: []string{"code_exec", "process_exec"}},
				},
				{
					ID:          "alert-http",
					Description: "Alert on outbound HTTP requests",
					Effect:      "alert",
					Priority:    50,
					Match:       RuleMatch{Tools: []string{"http_request"}},
				},
				{
					ID:          "allow-all",
					Description: "Allow all other operations",
					Effect:      "allow",
					Priority:    1,
					Match:       RuleMatch{Tools: []string{"*"}},
				},
			},
		},
	},
	{
		Name:        "agent-strict",
		Description: "Comprehensive strict policy — denies dangerous tools, audits data access, enforces rate limits",
		Category:    "agent",
		Tags:        []string{"production", "zero-trust", "hardened", "security"},
		Parameters: []TemplateParam{
			{Name: "agent_name", Description: "Agent name or pattern this policy applies to", Type: "string", Default: "*", Required: false},
			{Name: "rate_limit_per_min", Description: "Max tool calls per minute before rate-limit alerting kicks in", Type: "int", Default: 60, Required: false},
			{Name: "audit_data_access", Description: "Alert on every file/data read operation", Type: "bool", Default: true, Required: false},
		},
		BasePolicy: &Policy{
			APIVersion: "v1",
			Kind:       "Policy",
			Meta: PolicyMeta{
				Name:        "agent-strict",
				Description: "Zero-trust agent policy. Denies all dangerous tool calls by default, audits data access, and rate-limits tool calling. Suitable for production agents handling sensitive data.",
				Authors:     []string{"ThreatEcho"},
			},
			Agent: AgentScope{Name: "*", Type: "llm"},
			Rules: []Rule{
				{
					ID:          "deny-shell-exec",
					Description: "Block all shell command execution",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tools: []string{"shell_exec"}},
				},
				{
					ID:          "deny-process-exec",
					Description: "Block all process execution",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tools: []string{"process_exec"}},
				},
				{
					ID:          "deny-file-write",
					Description: "Block all file write operations",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tools: []string{"file_write"}},
				},
				{
					ID:          "deny-registry-access",
					Description: "Block all registry access",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tools: []string{"registry_access"}},
				},
				{
					ID:          "deny-credential-access",
					Description: "Block credential access tactic stages",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tactics: []string{"credential-access"}},
				},
				{
					ID:          "deny-lateral-movement",
					Description: "Block lateral movement tactic stages",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tactics: []string{"lateral-movement"}},
				},
				{
					ID:          "alert-elevated-tool-call",
					Description: "Alert on elevated tool calls",
					Effect:      "alert",
					Priority:    60,
					Match:       RuleMatch{Tools: []string{"tool_call"}},
					Conditions:  []Condition{{Field: "elevated", Operator: "eq", Value: "true"}},
				},
				{
					ID:          "audit-file-read",
					Description: "Audit (alert on) file read operations",
					Effect:      "alert",
					Priority:    50,
					Match:       RuleMatch{Tools: []string{"file_read"}},
				},
				{
					ID:          "allow-search",
					Description: "Allow read-only search operations",
					Effect:      "allow",
					Priority:    10,
					Match:       RuleMatch{Tools: []string{"search_knowledge_base"}},
				},
			},
		},
	},
	{
		Name:        "rag-safe",
		Description: "RAG-specific policy — denies prompt injection vectors, audits RAG queries",
		Category:    "rag",
		Tags:        []string{"rag", "knowledge-base", "retrieval", "prompt-injection", "llm-security"},
		Parameters: []TemplateParam{
			{Name: "agent_name", Description: "Agent name or pattern this policy applies to", Type: "string", Default: "*", Required: false},
			{Name: "embedding_alert", Description: "Alert on embedding/vector queries for anomaly monitoring", Type: "bool", Default: true, Required: false},
		},
		BasePolicy: &Policy{
			APIVersion: "v1",
			Kind:       "Policy",
			Meta: PolicyMeta{
				Name:        "rag-safe",
				Description: "Protects RAG knowledge base pipelines from prompt injection and poisoning. Blocks vector store writes and inter-agent propagation, audits embedding queries and file uploads.",
				Authors:     []string{"ThreatEcho"},
			},
			Agent: AgentScope{Name: "*", Type: "retrieval"},
			Rules: []Rule{
				{
					ID:          "deny-kb-write",
					Description: "Block writes to the vector store / knowledge base (RAG poisoning vector)",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tools: []string{"write_knowledge_base"}},
				},
				{
					ID:          "deny-agent-message",
					Description: "Block inter-agent messaging (indirect prompt injection propagation vector)",
					Effect:      "deny",
					Priority:    95,
					Match:       RuleMatch{Tools: []string{"agent_message"}},
				},
				{
					ID:          "deny-injected-c2-targets",
					Description: "Block requests to known C2 / exfiltration infrastructure patterns",
					Effect:      "deny",
					Priority:    95,
					Match:       RuleMatch{Targets: []string{"https://*.evil.com/*", "http://*:4444/*", "https://*.onion/*"}},
				},
				{
					ID:          "deny-shell-exec",
					Description: "Block shell execution reachable via retrieved-content injection",
					Effect:      "deny",
					Priority:    90,
					Match:       RuleMatch{Tools: []string{"shell_exec"}},
				},
				{
					ID:          "alert-embedding-query",
					Description: "Alert on embedding/vector queries for anomaly monitoring",
					Effect:      "alert",
					Priority:    50,
					Match:       RuleMatch{Tools: []string{"embedding_query"}},
				},
				{
					ID:          "alert-file-upload",
					Description: "Alert on file uploads into the knowledge base",
					Effect:      "alert",
					Priority:    50,
					Match:       RuleMatch{Tools: []string{"file_upload"}},
				},
				{
					ID:          "allow-kb-search",
					Description: "Allow knowledge base search (read-only)",
					Effect:      "allow",
					Priority:    10,
					Match:       RuleMatch{Tools: []string{"search_knowledge_base"}},
				},
			},
		},
	},
	{
		Name:        "tool-calling-restricted",
		Description: "Limits tool calling to an explicit set of approved tools; denies everything else",
		Category:    "tool-control",
		Tags:        []string{"allowlist", "tool-calling", "least-privilege"},
		Parameters: []TemplateParam{
			{Name: "agent_name", Description: "Agent name or pattern this policy applies to", Type: "string", Default: "*", Required: false},
			{Name: "approved_tools", Description: "Tool names permitted for this agent; all other tools are denied", Type: "list", Default: []string{"search_knowledge_base", "http_request"}, Required: true},
		},
		BasePolicy: &Policy{
			APIVersion: "v1",
			Kind:       "Policy",
			Meta: PolicyMeta{
				Name:        "tool-calling-restricted",
				Description: "Restricts tool calling to an explicit allowlist of approved tools. Every tool not on the allowlist is denied by default.",
				Authors:     []string{"ThreatEcho"},
			},
			Agent: AgentScope{Name: "*", Type: "llm"},
			Rules: []Rule{
				{
					ID:          "allow-approved-tools",
					Description: "Allow the explicitly approved tool set",
					Effect:      "allow",
					Priority:    100,
					Match:       RuleMatch{Tools: []string{"search_knowledge_base", "http_request"}},
				},
				{
					ID:          "deny-all-other-tools",
					Description: "Deny any tool call not on the approved allowlist",
					Effect:      "deny",
					Priority:    1,
					Match:       RuleMatch{Tools: []string{"*"}},
				},
			},
		},
	},
	{
		Name:        "autonomous-guardrailed",
		Description: "Policy for autonomous agents — denies privilege escalation, requires human approval for high-risk actions",
		Category:    "autonomous",
		Tags:        []string{"autonomous", "human-in-the-loop", "escalation", "guardrails"},
		Parameters: []TemplateParam{
			{Name: "agent_name", Description: "Agent name or pattern this policy applies to", Type: "string", Default: "*", Required: false},
			{Name: "require_approval", Description: "Require human approval before elevated tool calls (enforced via alert-and-gate)", Type: "bool", Default: true, Required: false},
			{Name: "max_actions_per_session", Description: "Advisory cap on autonomous actions per session, recorded in the policy description", Type: "int", Default: 25, Required: false},
		},
		BasePolicy: &Policy{
			APIVersion: "v1",
			Kind:       "Policy",
			Meta: PolicyMeta{
				Name:        "autonomous-guardrailed",
				Description: "Guardrails for autonomous agents operating without a human in the direct loop. Denies privilege escalation and persistence, gates elevated actions behind human approval alerts.",
				Authors:     []string{"ThreatEcho"},
			},
			Agent: AgentScope{Name: "*", Type: "orchestrator"},
			Rules: []Rule{
				{
					ID:          "deny-privilege-escalation",
					Description: "Block privilege escalation tactic stages",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tactics: []string{"privilege-escalation"}},
				},
				{
					ID:          "deny-persistence",
					Description: "Block persistence tactic stages",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tactics: []string{"persistence"}},
				},
				{
					ID:          "deny-elevated-shell",
					Description: "Block elevated shell command execution",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tools: []string{"shell_exec"}},
					Conditions:  []Condition{{Field: "elevated", Operator: "eq", Value: "true"}},
				},
				{
					ID:          "require-approval-elevated-tool",
					Description: "Alert to gate elevated tool calls behind human approval",
					Effect:      "alert",
					Priority:    80,
					Match:       RuleMatch{Tools: []string{"tool_call"}},
					Conditions:  []Condition{{Field: "elevated", Operator: "eq", Value: "true"}},
				},
				{
					ID:          "alert-agent-message",
					Description: "Alert on inter-agent communication for oversight",
					Effect:      "alert",
					Priority:    50,
					Match:       RuleMatch{Tools: []string{"agent_message"}},
				},
				{
					ID:          "allow-discovery",
					Description: "Allow read-only discovery tactic stages",
					Effect:      "allow",
					Priority:    10,
					Match:       RuleMatch{Tactics: []string{"discovery"}},
				},
			},
		},
	},
	{
		Name:        "compliance-soc2",
		Description: "SOC 2 compliance-oriented policy — audits all data access, denies exfiltration paths",
		Category:    "compliance",
		Tags:        []string{"compliance", "soc2", "audit", "data-governance"},
		Parameters: []TemplateParam{
			{Name: "agent_name", Description: "Agent name or pattern this policy applies to", Type: "string", Default: "*", Required: false},
			{Name: "audit_retention_days", Description: "Advisory audit log retention window in days, recorded in the policy description", Type: "int", Default: 90, Required: false},
		},
		BasePolicy: &Policy{
			APIVersion: "v1",
			Kind:       "Policy",
			Meta: PolicyMeta{
				Name:        "compliance-soc2",
				Description: "SOC 2-oriented compliance policy. Audits (alerts on) all data access and exfiltration-adjacent tool calls, denies unauthorized data egress, supports evidentiary logging for control CC6/CC7.",
				Authors:     []string{"ThreatEcho"},
			},
			Agent: AgentScope{Name: "*", Type: "llm"},
			Rules: []Rule{
				{
					ID:          "deny-email-exfil",
					Description: "Block email sending (exfiltration vector)",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tools: []string{"send_email"}},
				},
				{
					ID:          "deny-exfiltration-tactic",
					Description: "Block all exfiltration-tactic stages",
					Effect:      "deny",
					Priority:    100,
					Match:       RuleMatch{Tactics: []string{"exfiltration"}},
				},
				{
					ID:          "deny-unapproved-egress",
					Description: "Block outbound requests to unapproved external targets",
					Effect:      "deny",
					Priority:    90,
					Match:       RuleMatch{Targets: []string{"https://*.evil.com/*", "http://*:4444/*", "https://*.onion/*"}},
				},
				{
					ID:          "audit-file-read",
					Description: "Audit (alert on) all file read operations",
					Effect:      "alert",
					Priority:    60,
					Match:       RuleMatch{Tools: []string{"file_read"}},
				},
				{
					ID:          "audit-file-write",
					Description: "Audit (alert on) all file write operations",
					Effect:      "alert",
					Priority:    60,
					Match:       RuleMatch{Tools: []string{"file_write"}},
				},
				{
					ID:          "audit-data-query",
					Description: "Audit (alert on) knowledge base / data query operations",
					Effect:      "alert",
					Priority:    50,
					Match:       RuleMatch{Actions: []string{"query"}},
				},
				{
					ID:          "audit-http-egress",
					Description: "Audit (alert on) outbound HTTP requests",
					Effect:      "alert",
					Priority:    50,
					Match:       RuleMatch{Tools: []string{"http_request"}},
				},
				{
					ID:          "allow-kb-search",
					Description: "Allow knowledge base search (read-only)",
					Effect:      "allow",
					Priority:    10,
					Match:       RuleMatch{Tools: []string{"search_knowledge_base"}},
				},
			},
		},
	},
}

// ListTemplates returns the catalog of all built-in policy templates.
func ListTemplates() *TemplateCatalog {
	out := make([]PolicyTemplate, len(builtinTemplates))
	for i := range builtinTemplates {
		out[i] = clonePolicyTemplate(&builtinTemplates[i])
	}
	return &TemplateCatalog{Templates: out}
}

// GetTemplate looks up a built-in template by name. Returns an error if no
// template with that name exists.
func GetTemplate(name string) (*PolicyTemplate, error) {
	for i := range builtinTemplates {
		if builtinTemplates[i].Name == name {
			cloned := clonePolicyTemplate(&builtinTemplates[i])
			return &cloned, nil
		}
	}
	return nil, fmt.Errorf("unknown policy template %q", name)
}

// DefaultTemplateConfig returns an empty TemplateConfig, causing
// RenderTemplate to use every parameter's default value.
func DefaultTemplateConfig() *TemplateConfig {
	return &TemplateConfig{Values: map[string]interface{}{}}
}

// RenderTemplate renders a named template into a concrete Policy, applying
// parameter overrides from cfg on top of each parameter's default. A nil cfg
// is equivalent to DefaultTemplateConfig().
func RenderTemplate(name string, cfg *TemplateConfig) (*Policy, error) {
	tmpl, err := GetTemplate(name)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = DefaultTemplateConfig()
	}

	if issues := ValidateTemplateConfig(tmpl, cfg); len(issues) > 0 {
		return nil, fmt.Errorf("invalid template config for %q: %s", name, strings.Join(issues, "; "))
	}

	values := resolveTemplateValues(tmpl, cfg)

	p := clonePolicy(tmpl.BasePolicy)

	if v, ok := values["agent_name"].(string); ok && v != "" {
		p.Agent.Name = v
	}
	if v, ok := values["policy_name"].(string); ok && v != "" {
		p.Meta.Name = v
	}

	switch tmpl.Name {
	case "agent-minimal":
		if v, ok := values["alert_on_http"].(bool); ok && !v {
			p.Rules = removeRuleByID(p.Rules, "alert-http")
		}
	case "agent-strict":
		if v, ok := values["audit_data_access"].(bool); ok && !v {
			p.Rules = removeRuleByID(p.Rules, "audit-file-read")
		}
		if v, ok := values["rate_limit_per_min"].(int); ok {
			p.Meta.Description = fmt.Sprintf("%s Rate limit: %d calls/min.", p.Meta.Description, v)
		}
	case "rag-safe":
		if v, ok := values["embedding_alert"].(bool); ok && !v {
			p.Rules = removeRuleByID(p.Rules, "alert-embedding-query")
		}
	case "tool-calling-restricted":
		tools := asStringList(values["approved_tools"])
		if len(tools) > 0 {
			for i := range p.Rules {
				if p.Rules[i].ID == "allow-approved-tools" {
					p.Rules[i].Match.Tools = tools
				}
			}
		}
	case "autonomous-guardrailed":
		if v, ok := values["require_approval"].(bool); ok && !v {
			p.Rules = removeRuleByID(p.Rules, "require-approval-elevated-tool")
		}
		if v, ok := values["max_actions_per_session"].(int); ok {
			p.Meta.Description = fmt.Sprintf("%s Advisory session cap: %d actions.", p.Meta.Description, v)
		}
	case "compliance-soc2":
		if v, ok := values["audit_retention_days"].(int); ok {
			p.Meta.Description = fmt.Sprintf("%s Audit retention: %d days.", p.Meta.Description, v)
		}
	}

	return p, nil
}

// ValidateTemplateConfig checks a TemplateConfig against a template's
// parameter definitions. It returns a slice of human-readable issues; an
// empty slice means the config is valid for that template.
func ValidateTemplateConfig(t *PolicyTemplate, cfg *TemplateConfig) []string {
	var issues []string
	if t == nil {
		return []string{"template is nil"}
	}

	var values map[string]interface{}
	if cfg != nil {
		values = cfg.Values
	}

	known := make(map[string]bool, len(t.Parameters))
	for _, p := range t.Parameters {
		known[p.Name] = true

		v, present := values[p.Name]
		if !present {
			// Required-but-absent is only an error when the template has no
			// usable default to fall back on.
			if p.Required && p.Default == nil {
				issues = append(issues, fmt.Sprintf("parameter %q is required", p.Name))
			}
			continue
		}

		if !valueMatchesType(v, p.Type) {
			issues = append(issues, fmt.Sprintf("parameter %q expects type %s, got %T", p.Name, p.Type, v))
		}
	}

	for name := range values {
		if name == "agent_name" || name == "policy_name" {
			continue // universal overrides accepted by every template
		}
		if !known[name] {
			issues = append(issues, fmt.Sprintf("unknown parameter %q for template %q", name, t.Name))
		}
	}

	return issues
}

// resolveTemplateValues merges a template's parameter defaults with the
// overrides supplied in cfg. Universal parameters (agent_name, policy_name)
// are included even when the template does not declare them explicitly.
func resolveTemplateValues(t *PolicyTemplate, cfg *TemplateConfig) map[string]interface{} {
	values := make(map[string]interface{})
	for _, p := range t.Parameters {
		values[p.Name] = p.Default
	}
	if cfg != nil {
		for k, v := range cfg.Values {
			values[k] = v
		}
	}
	return values
}

// valueMatchesType reports whether v is an acceptable value for the given
// template parameter type.
func valueMatchesType(v interface{}, typ string) bool {
	switch typ {
	case "string":
		_, ok := v.(string)
		return ok
	case "bool":
		_, ok := v.(bool)
		return ok
	case "int":
		switch v.(type) {
		case int, int64:
			return true
		default:
			return false
		}
	case "list":
		switch v.(type) {
		case []string:
			return true
		case []interface{}:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// asStringList normalizes a "list"-typed parameter value into []string.
func asStringList(v interface{}) []string {
	switch vv := v.(type) {
	case []string:
		out := make([]string, len(vv))
		copy(out, vv)
		return out
	case []interface{}:
		out := make([]string, 0, len(vv))
		for _, e := range vv {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// removeRuleByID returns rules with the rule matching id removed.
func removeRuleByID(rules []Rule, id string) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.ID == id {
			continue
		}
		out = append(out, r)
	}
	return out
}

// clonePolicyTemplate returns a deep copy of a PolicyTemplate so callers
// cannot mutate the built-in catalog.
func clonePolicyTemplate(t *PolicyTemplate) PolicyTemplate {
	out := PolicyTemplate{
		Name:        t.Name,
		Description: t.Description,
		Category:    t.Category,
		Tags:        copyStrings(t.Tags),
		Parameters:  make([]TemplateParam, len(t.Parameters)),
		BasePolicy:  clonePolicy(t.BasePolicy),
	}
	copy(out.Parameters, t.Parameters)
	return out
}

// clonePolicy returns a deep copy of a Policy.
func clonePolicy(p *Policy) *Policy {
	if p == nil {
		return nil
	}
	out := &Policy{
		APIVersion: p.APIVersion,
		Kind:       p.Kind,
		Meta: PolicyMeta{
			Name:        p.Meta.Name,
			Description: p.Meta.Description,
			Authors:     copyStrings(p.Meta.Authors),
			Created:     p.Meta.Created,
			Modified:    p.Meta.Modified,
		},
		Agent: AgentScope{
			Name:  p.Agent.Name,
			Type:  p.Agent.Type,
			Tools: copyStrings(p.Agent.Tools),
		},
		Rules: make([]Rule, len(p.Rules)),
	}
	for i, r := range p.Rules {
		out.Rules[i] = Rule{
			ID:          r.ID,
			Description: r.Description,
			Effect:      r.Effect,
			Priority:    r.Priority,
			Match: RuleMatch{
				Tools:   copyStrings(r.Match.Tools),
				Tactics: copyStrings(r.Match.Tactics),
				Actions: copyStrings(r.Match.Actions),
				Targets: copyStrings(r.Match.Targets),
			},
			Conditions: make([]Condition, len(r.Conditions)),
		}
		copy(out.Rules[i].Conditions, r.Conditions)
	}
	return out
}

// copyStrings returns a copy of a string slice, or nil if the input is nil.
func copyStrings(ss []string) []string {
	if ss == nil {
		return nil
	}
	cp := make([]string, len(ss))
	copy(cp, ss)
	return cp
}

// FormatTemplateCatalog renders a template catalog as a box-drawing table.
func FormatTemplateCatalog(c *TemplateCatalog) string {
	var sb strings.Builder

	if c == nil || len(c.Templates) == 0 {
		sb.WriteString("┌──────────────────────────────────────────────────────────────┐\n")
		sb.WriteString("│                     Policy Templates                          │\n")
		sb.WriteString("├──────────────────────────────────────────────────────────────┤\n")
		sb.WriteString("│ (no templates available)                                      │\n")
		sb.WriteString("└──────────────────────────────────────────────────────────────┘\n")
		return sb.String()
	}

	templates := make([]PolicyTemplate, len(c.Templates))
	copy(templates, c.Templates)
	sort.Slice(templates, func(i, j int) bool { return templates[i].Name < templates[j].Name })

	sb.WriteString("┌─────────────────────────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│                                  Policy Templates                                     │\n")
	sb.WriteString("├────────────────────────┬──────────────┬───────┬────────┬────────────────────────────────┤\n")
	sb.WriteString("│ Name                   │ Category     │ Rules │ Params │ Description                    │\n")
	sb.WriteString("├────────────────────────┼──────────────┼───────┼────────┼────────────────────────────────┤\n")

	for _, t := range templates {
		rules := 0
		if t.BasePolicy != nil {
			rules = len(t.BasePolicy.Rules)
		}
		desc := t.Description
		if len(desc) > 30 {
			desc = desc[:27] + "..."
		}
		fmt.Fprintf(&sb, "│ %-22s │ %-12s │ %5d │ %6d │ %-30s │\n",
			t.Name, t.Category, rules, len(t.Parameters), desc)
	}

	sb.WriteString("└────────────────────────┴──────────────┴───────┴────────┴────────────────────────────────┘\n")
	return sb.String()
}

// FormatTemplateDetail renders a single template's full detail, including
// its parameters, as human-readable text.
func FormatTemplateDetail(t *PolicyTemplate) string {
	var sb strings.Builder

	if t == nil {
		return "(no template)\n"
	}

	fmt.Fprintf(&sb, "Template: %s\n", t.Name)
	fmt.Fprintf(&sb, "Category: %s\n", t.Category)
	if len(t.Tags) > 0 {
		fmt.Fprintf(&sb, "Tags:     %s\n", strings.Join(t.Tags, ", "))
	}
	fmt.Fprintf(&sb, "\n%s\n", t.Description)

	rules := 0
	if t.BasePolicy != nil {
		rules = len(t.BasePolicy.Rules)
	}
	fmt.Fprintf(&sb, "\nRules: %d\n", rules)

	if len(t.Parameters) == 0 {
		sb.WriteString("\nParameters: (none)\n")
		return sb.String()
	}

	sb.WriteString("\nParameters:\n")
	for _, p := range t.Parameters {
		req := "optional"
		if p.Required {
			req = "required"
		}
		fmt.Fprintf(&sb, "  - %-24s type=%-6s default=%-12v %s\n", p.Name, p.Type, p.Default, req)
		if p.Description != "" {
			fmt.Fprintf(&sb, "      %s\n", p.Description)
		}
	}

	return sb.String()
}
