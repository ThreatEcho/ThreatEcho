// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"strings"
	"testing"
)

// --- ListTemplates ---

func TestListTemplates_ReturnsAtLeastSix(t *testing.T) {
	t.Parallel()
	catalog := ListTemplates()
	if catalog == nil {
		t.Fatal("ListTemplates returned nil")
	}
	if len(catalog.Templates) < 6 {
		t.Fatalf("expected at least 6 templates, got %d", len(catalog.Templates))
	}
}

func TestListTemplates_ContainsAllRequiredNames(t *testing.T) {
	t.Parallel()
	catalog := ListTemplates()
	names := map[string]bool{}
	for _, tmpl := range catalog.Templates {
		names[tmpl.Name] = true
	}
	required := []string{
		"agent-minimal",
		"agent-strict",
		"rag-safe",
		"tool-calling-restricted",
		"autonomous-guardrailed",
		"compliance-soc2",
	}
	for _, name := range required {
		if !names[name] {
			t.Errorf("missing required template %q", name)
		}
	}
}

func TestListTemplates_DoesNotMutateBuiltins(t *testing.T) {
	t.Parallel()
	catalog := ListTemplates()
	catalog.Templates[0].Name = "mutated"
	catalog.Templates[0].BasePolicy.Meta.Name = "mutated"

	catalog2 := ListTemplates()
	if catalog2.Templates[0].Name == "mutated" {
		t.Error("mutating a returned catalog mutated the builtin templates")
	}
}

// --- GetTemplate ---

func TestGetTemplate_Found(t *testing.T) {
	t.Parallel()
	names := []string{
		"agent-minimal", "agent-strict", "rag-safe",
		"tool-calling-restricted", "autonomous-guardrailed", "compliance-soc2",
	}
	for _, name := range names {
		tmpl, err := GetTemplate(name)
		if err != nil {
			t.Errorf("GetTemplate(%q) returned error: %v", name, err)
			continue
		}
		if tmpl.Name != name {
			t.Errorf("GetTemplate(%q).Name = %q", name, tmpl.Name)
		}
		if tmpl.BasePolicy == nil {
			t.Errorf("GetTemplate(%q).BasePolicy is nil", name)
		}
	}
}

func TestGetTemplate_MissingName(t *testing.T) {
	t.Parallel()
	tmpl, err := GetTemplate("does-not-exist")
	if err == nil {
		t.Error("expected error for unknown template name")
	}
	if tmpl != nil {
		t.Error("expected nil template for unknown name")
	}
}

func TestGetTemplate_EmptyName(t *testing.T) {
	t.Parallel()
	_, err := GetTemplate("")
	if err == nil {
		t.Error("expected error for empty template name")
	}
}

func TestGetTemplate_DoesNotMutateBuiltin(t *testing.T) {
	t.Parallel()
	tmpl, err := GetTemplate("agent-minimal")
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	origLen := len(tmpl.BasePolicy.Rules)
	tmpl.BasePolicy.Rules = append(tmpl.BasePolicy.Rules, Rule{ID: "injected"})
	tmpl.Name = "mutated"

	tmpl2, err := GetTemplate("agent-minimal")
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if len(tmpl2.BasePolicy.Rules) != origLen {
		t.Error("mutating a returned template mutated the builtin catalog")
	}
	if tmpl2.Name != "agent-minimal" {
		t.Error("mutating a returned template's Name mutated the builtin catalog")
	}
}

// --- RenderTemplate: defaults ---

func TestRenderTemplate_WithNilConfigUsesDefaults(t *testing.T) {
	t.Parallel()
	p, err := RenderTemplate("agent-minimal", nil)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	if p.Agent.Name != "*" {
		t.Errorf("expected default agent name '*', got %q", p.Agent.Name)
	}
}

func TestRenderTemplate_WithEmptyConfigUsesDefaults(t *testing.T) {
	t.Parallel()
	p, err := RenderTemplate("agent-minimal", &TemplateConfig{})
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	if p.Agent.Name != "*" {
		t.Errorf("expected default agent name '*', got %q", p.Agent.Name)
	}
}

func TestRenderTemplate_DefaultConfigHelper(t *testing.T) {
	t.Parallel()
	cfg := DefaultTemplateConfig()
	if cfg == nil {
		t.Fatal("DefaultTemplateConfig returned nil")
	}
	if cfg.Values == nil {
		t.Fatal("DefaultTemplateConfig returned nil Values map")
	}
	if len(cfg.Values) != 0 {
		t.Errorf("expected empty Values map, got %d entries", len(cfg.Values))
	}
}

// --- RenderTemplate: overrides ---

func TestRenderTemplate_AgentNameOverride(t *testing.T) {
	t.Parallel()
	cfg := DefaultTemplateConfig()
	cfg.Values["agent_name"] = "billing-agent-v2"
	p, err := RenderTemplate("agent-strict", cfg)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	if p.Agent.Name != "billing-agent-v2" {
		t.Errorf("expected agent name 'billing-agent-v2', got %q", p.Agent.Name)
	}
}

func TestRenderTemplate_PolicyNameOverride(t *testing.T) {
	t.Parallel()
	cfg := DefaultTemplateConfig()
	cfg.Values["policy_name"] = "custom-policy-name"
	p, err := RenderTemplate("agent-minimal", cfg)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	if p.Meta.Name != "custom-policy-name" {
		t.Errorf("expected policy name 'custom-policy-name', got %q", p.Meta.Name)
	}
}

func TestRenderTemplate_BoolOverrideRemovesRule(t *testing.T) {
	t.Parallel()
	cfg := DefaultTemplateConfig()
	cfg.Values["alert_on_http"] = false
	p, err := RenderTemplate("agent-minimal", cfg)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	for _, r := range p.Rules {
		if r.ID == "alert-http" {
			t.Error("expected alert-http rule to be removed when alert_on_http=false")
		}
	}
}

func TestRenderTemplate_ListOverrideAppliesApprovedTools(t *testing.T) {
	t.Parallel()
	cfg := DefaultTemplateConfig()
	cfg.Values["approved_tools"] = []string{"calculator", "web_search"}
	p, err := RenderTemplate("tool-calling-restricted", cfg)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	found := false
	for _, r := range p.Rules {
		if r.ID == "allow-approved-tools" {
			found = true
			if len(r.Match.Tools) != 2 || r.Match.Tools[0] != "calculator" || r.Match.Tools[1] != "web_search" {
				t.Errorf("expected approved tools to be applied, got %v", r.Match.Tools)
			}
		}
	}
	if !found {
		t.Error("allow-approved-tools rule not found")
	}
}

func TestRenderTemplate_IntOverrideAffectsDescription(t *testing.T) {
	t.Parallel()
	cfg := DefaultTemplateConfig()
	cfg.Values["rate_limit_per_min"] = 120
	p, err := RenderTemplate("agent-strict", cfg)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	if !strings.Contains(p.Meta.Description, "120") {
		t.Errorf("expected description to mention rate limit 120, got %q", p.Meta.Description)
	}
}

func TestRenderTemplate_UnknownTemplate(t *testing.T) {
	t.Parallel()
	_, err := RenderTemplate("nonexistent-template", nil)
	if err == nil {
		t.Error("expected error for unknown template")
	}
}

func TestRenderTemplate_WrongTypedOverride(t *testing.T) {
	t.Parallel()
	cfg := DefaultTemplateConfig()
	cfg.Values["agent_name"] = 123 // wrong type, should fail validation
	_, err := RenderTemplate("tool-calling-restricted", cfg)
	if err == nil {
		t.Error("expected error for wrong-typed agent_name override")
	}
}

func TestRenderTemplate_RequiredParamSatisfiedByDefault(t *testing.T) {
	t.Parallel()
	// tool-calling-restricted declares approved_tools as required, but it has
	// a non-empty Default, so omitting it from the config must still succeed.
	p, err := RenderTemplate("tool-calling-restricted", nil)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	if len(p.Rules) == 0 {
		t.Error("expected rendered policy to have rules")
	}
}

func TestRenderTemplate_DoesNotMutateBuiltinTemplate(t *testing.T) {
	t.Parallel()
	before, err := GetTemplate("agent-minimal")
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	origRuleCount := len(before.BasePolicy.Rules)

	cfg := DefaultTemplateConfig()
	cfg.Values["alert_on_http"] = false
	p, err := RenderTemplate("agent-minimal", cfg)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	p.Rules = append(p.Rules, Rule{ID: "injected"})
	p.Agent.Name = "mutated"

	after, err := GetTemplate("agent-minimal")
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if len(after.BasePolicy.Rules) != origRuleCount {
		t.Error("RenderTemplate mutated the builtin template's rule set")
	}
	if after.BasePolicy.Agent.Name != "*" {
		t.Error("RenderTemplate mutated the builtin template's agent name")
	}
}

// --- Each template produces a valid policy ---

func TestAllTemplates_ProduceValidPolicies(t *testing.T) {
	t.Parallel()
	catalog := ListTemplates()
	for _, tmpl := range catalog.Templates {
		tmpl := tmpl
		t.Run(tmpl.Name, func(t *testing.T) {
			t.Parallel()
			p, err := RenderTemplate(tmpl.Name, nil)
			if err != nil {
				t.Fatalf("RenderTemplate(%q): %v", tmpl.Name, err)
			}
			if p == nil {
				t.Fatal("RenderTemplate returned nil policy")
			}
			if len(p.Rules) == 0 {
				t.Error("rendered policy has no rules")
			}
			if p.Meta.Name != tmpl.Name {
				t.Errorf("expected policy name %q, got %q", tmpl.Name, p.Meta.Name)
			}
			if errs := ValidatePolicy(p); len(errs) > 0 {
				t.Errorf("template %q produced an invalid policy: %v", tmpl.Name, errs)
			}
		})
	}
}

func TestAllTemplates_HaveBasePolicySetInCatalog(t *testing.T) {
	t.Parallel()
	catalog := ListTemplates()
	for _, tmpl := range catalog.Templates {
		if tmpl.BasePolicy == nil {
			t.Errorf("template %q has nil BasePolicy", tmpl.Name)
		}
	}
}

func TestAllTemplates_HaveNonEmptyDescription(t *testing.T) {
	t.Parallel()
	catalog := ListTemplates()
	for _, tmpl := range catalog.Templates {
		if strings.TrimSpace(tmpl.Description) == "" {
			t.Errorf("template %q has an empty description", tmpl.Name)
		}
	}
}

func TestAllTemplates_HaveCategory(t *testing.T) {
	t.Parallel()
	catalog := ListTemplates()
	for _, tmpl := range catalog.Templates {
		if strings.TrimSpace(tmpl.Category) == "" {
			t.Errorf("template %q has an empty category", tmpl.Name)
		}
	}
}

func TestAgentMinimal_DeniesShellAndCodeExec(t *testing.T) {
	t.Parallel()
	p, err := RenderTemplate("agent-minimal", nil)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	deniedTools := map[string]bool{}
	for _, r := range p.Rules {
		if r.Effect != "deny" {
			continue
		}
		for _, tool := range r.Match.Tools {
			deniedTools[tool] = true
		}
	}
	if !deniedTools["shell_exec"] {
		t.Error("agent-minimal should deny shell_exec")
	}
	if !deniedTools["code_exec"] && !deniedTools["process_exec"] {
		t.Error("agent-minimal should deny code/process execution")
	}
}

func TestAgentStrict_HasRateLimitAndAuditParams(t *testing.T) {
	t.Parallel()
	tmpl, err := GetTemplate("agent-strict")
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	names := paramNames(tmpl.Parameters)
	if !names["rate_limit_per_min"] {
		t.Error("agent-strict should declare a rate_limit_per_min parameter")
	}
	if !names["audit_data_access"] {
		t.Error("agent-strict should declare an audit_data_access parameter")
	}
}

func TestRagSafe_DeniesKBWriteAllowsKBSearch(t *testing.T) {
	t.Parallel()
	p, err := RenderTemplate("rag-safe", nil)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	hasDenyWrite := false
	hasAllowSearch := false
	for _, r := range p.Rules {
		for _, tool := range r.Match.Tools {
			if tool == "write_knowledge_base" && r.Effect == "deny" {
				hasDenyWrite = true
			}
			if tool == "search_knowledge_base" && r.Effect == "allow" {
				hasAllowSearch = true
			}
		}
	}
	if !hasDenyWrite {
		t.Error("rag-safe should deny write_knowledge_base")
	}
	if !hasAllowSearch {
		t.Error("rag-safe should allow search_knowledge_base")
	}
}

func TestToolCallingRestricted_DeniesUnlistedTools(t *testing.T) {
	t.Parallel()
	p, err := RenderTemplate("tool-calling-restricted", nil)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	hasCatchAllDeny := false
	for _, r := range p.Rules {
		if r.Effect == "deny" {
			for _, tool := range r.Match.Tools {
				if tool == "*" {
					hasCatchAllDeny = true
				}
			}
		}
	}
	if !hasCatchAllDeny {
		t.Error("tool-calling-restricted should deny all tools not on the allowlist")
	}
}

func TestAutonomousGuardrailed_DeniesPrivilegeEscalation(t *testing.T) {
	t.Parallel()
	p, err := RenderTemplate("autonomous-guardrailed", nil)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	hasDenyPrivEsc := false
	for _, r := range p.Rules {
		if r.Effect != "deny" {
			continue
		}
		for _, tac := range r.Match.Tactics {
			if tac == "privilege-escalation" {
				hasDenyPrivEsc = true
			}
		}
	}
	if !hasDenyPrivEsc {
		t.Error("autonomous-guardrailed should deny privilege-escalation tactic stages")
	}
}

func TestComplianceSOC2_AuditsDataAccessDeniesExfil(t *testing.T) {
	t.Parallel()
	p, err := RenderTemplate("compliance-soc2", nil)
	if err != nil {
		t.Fatalf("RenderTemplate: %v", err)
	}
	hasAuditRead := false
	hasDenyExfil := false
	for _, r := range p.Rules {
		if r.Effect == "alert" {
			for _, tool := range r.Match.Tools {
				if tool == "file_read" {
					hasAuditRead = true
				}
			}
		}
		if r.Effect == "deny" {
			for _, tac := range r.Match.Tactics {
				if tac == "exfiltration" {
					hasDenyExfil = true
				}
			}
		}
	}
	if !hasAuditRead {
		t.Error("compliance-soc2 should audit (alert on) file_read")
	}
	if !hasDenyExfil {
		t.Error("compliance-soc2 should deny exfiltration tactic stages")
	}
}

// --- Parameter validation ---

func TestValidateTemplateConfig_MissingRequiredParam(t *testing.T) {
	t.Parallel()
	tmpl := &PolicyTemplate{
		Name: "test-tmpl",
		Parameters: []TemplateParam{
			{Name: "required_field", Type: "string", Required: true},
		},
	}
	issues := ValidateTemplateConfig(tmpl, &TemplateConfig{Values: map[string]interface{}{}})
	if len(issues) == 0 {
		t.Fatal("expected an issue for missing required parameter")
	}
	if !strings.Contains(issues[0], "required_field") {
		t.Errorf("expected issue to mention 'required_field', got %q", issues[0])
	}
}

func TestValidateTemplateConfig_WrongType(t *testing.T) {
	t.Parallel()
	tmpl := &PolicyTemplate{
		Name: "test-tmpl",
		Parameters: []TemplateParam{
			{Name: "count", Type: "int", Default: 1},
		},
	}
	issues := ValidateTemplateConfig(tmpl, &TemplateConfig{Values: map[string]interface{}{"count": "not-an-int"}})
	if len(issues) == 0 {
		t.Fatal("expected an issue for wrong-typed parameter")
	}
}

func TestValidateTemplateConfig_CorrectTypesPass(t *testing.T) {
	t.Parallel()
	tmpl := &PolicyTemplate{
		Name: "test-tmpl",
		Parameters: []TemplateParam{
			{Name: "s", Type: "string", Default: "x"},
			{Name: "b", Type: "bool", Default: true},
			{Name: "i", Type: "int", Default: 1},
			{Name: "l", Type: "list", Default: []string{"a"}},
		},
	}
	cfg := &TemplateConfig{Values: map[string]interface{}{
		"s": "hello",
		"b": false,
		"i": 42,
		"l": []string{"x", "y"},
	}}
	issues := ValidateTemplateConfig(tmpl, cfg)
	if len(issues) != 0 {
		t.Errorf("expected no issues, got %v", issues)
	}
}

func TestValidateTemplateConfig_ListAcceptsInterfaceSlice(t *testing.T) {
	t.Parallel()
	tmpl := &PolicyTemplate{
		Name: "test-tmpl",
		Parameters: []TemplateParam{
			{Name: "l", Type: "list", Default: []string{"a"}},
		},
	}
	cfg := &TemplateConfig{Values: map[string]interface{}{"l": []interface{}{"a", "b"}}}
	issues := ValidateTemplateConfig(tmpl, cfg)
	if len(issues) != 0 {
		t.Errorf("expected no issues for []interface{} list value, got %v", issues)
	}
}

func TestValidateTemplateConfig_UnknownParameter(t *testing.T) {
	t.Parallel()
	tmpl := &PolicyTemplate{
		Name:       "test-tmpl",
		Parameters: []TemplateParam{{Name: "known", Type: "string", Default: "x"}},
	}
	cfg := &TemplateConfig{Values: map[string]interface{}{"totally_unknown": "value"}}
	issues := ValidateTemplateConfig(tmpl, cfg)
	if len(issues) == 0 {
		t.Fatal("expected an issue for an unknown parameter")
	}
}

func TestValidateTemplateConfig_UniversalOverridesAlwaysAllowed(t *testing.T) {
	t.Parallel()
	tmpl := &PolicyTemplate{Name: "test-tmpl"}
	cfg := &TemplateConfig{Values: map[string]interface{}{
		"agent_name":  "foo",
		"policy_name": "bar",
	}}
	issues := ValidateTemplateConfig(tmpl, cfg)
	if len(issues) != 0 {
		t.Errorf("expected no issues for universal overrides, got %v", issues)
	}
}

func TestValidateTemplateConfig_NilTemplate(t *testing.T) {
	t.Parallel()
	issues := ValidateTemplateConfig(nil, &TemplateConfig{})
	if len(issues) == 0 {
		t.Error("expected an issue for a nil template")
	}
}

func TestValidateTemplateConfig_NilConfigUsesDefaults(t *testing.T) {
	t.Parallel()
	tmpl := &PolicyTemplate{
		Name:       "test-tmpl",
		Parameters: []TemplateParam{{Name: "opt", Type: "string", Default: "x", Required: false}},
	}
	issues := ValidateTemplateConfig(tmpl, nil)
	if len(issues) != 0 {
		t.Errorf("expected no issues when cfg is nil and no required params, got %v", issues)
	}
}

func TestValidateTemplateConfig_RequiredParamSatisfiedByOverride(t *testing.T) {
	t.Parallel()
	tmpl := &PolicyTemplate{
		Name:       "test-tmpl",
		Parameters: []TemplateParam{{Name: "req", Type: "string", Required: true}},
	}
	cfg := &TemplateConfig{Values: map[string]interface{}{"req": "supplied"}}
	issues := ValidateTemplateConfig(tmpl, cfg)
	if len(issues) != 0 {
		t.Errorf("expected no issues when required param is supplied, got %v", issues)
	}
}

func TestToolCallingRestricted_ApprovedToolsRequired(t *testing.T) {
	t.Parallel()
	tmpl, err := GetTemplate("tool-calling-restricted")
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	var found *TemplateParam
	for i := range tmpl.Parameters {
		if tmpl.Parameters[i].Name == "approved_tools" {
			found = &tmpl.Parameters[i]
		}
	}
	if found == nil {
		t.Fatal("tool-calling-restricted should declare an approved_tools parameter")
	}
	if !found.Required {
		t.Error("approved_tools should be marked Required")
	}
	if found.Type != "list" {
		t.Errorf("approved_tools should be type 'list', got %q", found.Type)
	}
}

// --- FormatTemplateCatalog ---

func TestFormatTemplateCatalog_ContainsAllNames(t *testing.T) {
	t.Parallel()
	catalog := ListTemplates()
	out := FormatTemplateCatalog(catalog)
	if !strings.Contains(out, "Policy Templates") {
		t.Error("missing header")
	}
	for _, tmpl := range catalog.Templates {
		if !strings.Contains(out, tmpl.Name) {
			t.Errorf("missing template name %q in catalog output", tmpl.Name)
		}
	}
}

func TestFormatTemplateCatalog_EmptyCatalog(t *testing.T) {
	t.Parallel()
	out := FormatTemplateCatalog(&TemplateCatalog{})
	if !strings.Contains(out, "no templates") {
		t.Errorf("expected placeholder text for empty catalog, got %q", out)
	}
}

func TestFormatTemplateCatalog_NilCatalog(t *testing.T) {
	t.Parallel()
	out := FormatTemplateCatalog(nil)
	if out == "" {
		t.Error("expected non-empty output for nil catalog")
	}
}

func TestFormatTemplateCatalog_IsBoxDrawn(t *testing.T) {
	t.Parallel()
	catalog := ListTemplates()
	out := FormatTemplateCatalog(catalog)
	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Error("expected box-drawing characters in catalog output")
	}
}

// --- FormatTemplateDetail ---

func TestFormatTemplateDetail_ContainsNameAndParams(t *testing.T) {
	t.Parallel()
	tmpl, err := GetTemplate("agent-strict")
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	out := FormatTemplateDetail(tmpl)
	if !strings.Contains(out, "agent-strict") {
		t.Error("expected template name in detail output")
	}
	for _, p := range tmpl.Parameters {
		if !strings.Contains(out, p.Name) {
			t.Errorf("expected parameter %q in detail output", p.Name)
		}
	}
}

func TestFormatTemplateDetail_NilTemplate(t *testing.T) {
	t.Parallel()
	out := FormatTemplateDetail(nil)
	if out == "" {
		t.Error("expected non-empty output for nil template")
	}
}

func TestFormatTemplateDetail_NoParameters(t *testing.T) {
	t.Parallel()
	tmpl := &PolicyTemplate{Name: "bare", Category: "test", BasePolicy: &Policy{}}
	out := FormatTemplateDetail(tmpl)
	if !strings.Contains(out, "none") {
		t.Errorf("expected 'none' placeholder for a template with no parameters, got %q", out)
	}
}

// --- helpers ---

func paramNames(params []TemplateParam) map[string]bool {
	out := make(map[string]bool, len(params))
	for _, p := range params {
		out[p.Name] = true
	}
	return out
}
