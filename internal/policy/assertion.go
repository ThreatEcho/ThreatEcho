// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// TestSuite is a collection of test cases for a policy.
type TestSuite struct {
	APIVersion string     `yaml:"api_version" json:"api_version"`
	Kind       string     `yaml:"kind"        json:"kind"`
	Meta       TestMeta   `yaml:"meta"        json:"meta"`
	Tests      []TestCase `yaml:"tests"       json:"tests"`
}

// TestMeta contains metadata for a test suite.
type TestMeta struct {
	Name        string `yaml:"name"        json:"name"`
	Description string `yaml:"description" json:"description"`
	Policy      string `yaml:"policy"      json:"policy"` // policy name this suite targets
}

// TestCase is a single policy test — a tool call with expected behavior.
type TestCase struct {
	ID          string          `yaml:"id"          json:"id"`
	Name        string          `yaml:"name"        json:"name"`
	Description string          `yaml:"description,omitempty" json:"description,omitempty"`
	Input       TestInput       `yaml:"input"       json:"input"`
	Expect      TestExpectation `yaml:"expect"      json:"expect"`
	Tags        []string        `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// TestInput defines the tool call being tested.
type TestInput struct {
	Tool   string `yaml:"tool"              json:"tool"`
	Tactic string `yaml:"tactic,omitempty"  json:"tactic,omitempty"`
	Agent  string `yaml:"agent,omitempty"   json:"agent,omitempty"`
}

// TestExpectation defines what we expect the policy to do with this input.
type TestExpectation struct {
	Effect  string `yaml:"effect"              json:"effect"`             // deny, allow, alert
	RuleID  string `yaml:"rule_id,omitempty"   json:"rule_id,omitempty"`  // specific rule expected to match
	NoMatch bool   `yaml:"no_match,omitempty"  json:"no_match,omitempty"` // expect no rule to match at all
}

// TestResult captures the outcome of running one test case.
type TestResult struct {
	TestID      string `json:"test_id"`
	TestName    string `json:"test_name"`
	Passed      bool   `json:"passed"`
	Expected    string `json:"expected"`
	Actual      string `json:"actual"`
	MatchedRule string `json:"matched_rule,omitempty"`
	Message     string `json:"message,omitempty"`
}

// TestSuiteResult captures the outcome of running a full test suite.
type TestSuiteResult struct {
	Suite   string       `json:"suite"`
	Policy  string       `json:"policy"`
	Total   int          `json:"total"`
	Passed  int          `json:"passed"`
	Failed  int          `json:"failed"`
	Skipped int          `json:"skipped"`
	Results []TestResult `json:"results"`
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// LoadTestSuite loads a test suite from a YAML file.
func LoadTestSuite(path string) (*TestSuite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading test suite: %w", err)
	}
	var ts TestSuite
	if err := yaml.Unmarshal(data, &ts); err != nil {
		return nil, fmt.Errorf("parsing test suite: %w", err)
	}
	return &ts, nil
}

// LoadTestSuiteDir loads all test suite YAML files from a directory.
func LoadTestSuiteDir(dir string) ([]*TestSuite, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading test directory: %w", err)
	}

	var suites []*TestSuite
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		ts, err := LoadTestSuite(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		suites = append(suites, ts)
	}
	return suites, nil
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

// RunTestSuite executes a test suite against a policy.
func RunTestSuite(p *Policy, suite *TestSuite) *TestSuiteResult {
	result := &TestSuiteResult{
		Suite:  suite.Meta.Name,
		Policy: p.Meta.Name,
		Total:  len(suite.Tests),
	}

	for _, tc := range suite.Tests {
		tr := runSingleTest(p, tc)
		result.Results = append(result.Results, tr)
		if tr.Passed {
			result.Passed++
		} else {
			result.Failed++
		}
	}

	return result
}

func runSingleTest(p *Policy, tc TestCase) TestResult {
	tr := TestResult{
		TestID:   tc.ID,
		TestName: tc.Name,
	}

	// Find which rule matches the given tool call.
	matched, matchedRule := evaluateToolCall(p, tc.Input)

	if tc.Expect.NoMatch {
		tr.Expected = "no_match"
		if matched == "" {
			tr.Passed = true
			tr.Actual = "no_match"
			tr.Message = "No rule matched, as expected"
		} else {
			tr.Passed = false
			tr.Actual = matched
			tr.MatchedRule = matchedRule
			tr.Message = fmt.Sprintf("Expected no match, but rule %q matched with effect %q", matchedRule, matched)
		}
		return tr
	}

	tr.Expected = tc.Expect.Effect

	if matched == "" {
		tr.Passed = false
		tr.Actual = "no_match"
		tr.Message = fmt.Sprintf("Expected effect %q, but no rule matched", tc.Expect.Effect)
		return tr
	}

	tr.Actual = matched
	tr.MatchedRule = matchedRule

	// Check effect.
	if matched != tc.Expect.Effect {
		tr.Passed = false
		tr.Message = fmt.Sprintf("Expected effect %q, got %q (rule %s)", tc.Expect.Effect, matched, matchedRule)
		return tr
	}

	// Check specific rule if required.
	if tc.Expect.RuleID != "" && matchedRule != tc.Expect.RuleID {
		tr.Passed = false
		tr.Message = fmt.Sprintf("Expected rule %q, but rule %q matched", tc.Expect.RuleID, matchedRule)
		return tr
	}

	tr.Passed = true
	tr.Message = "OK"
	return tr
}

// evaluateToolCall checks a single tool call against a policy and returns
// the first matching rule's effect and ID.
func evaluateToolCall(p *Policy, input TestInput) (effect, ruleID string) {
	for _, r := range p.Rules {
		if matchesRule(r, input) {
			return r.Effect, r.ID
		}
	}
	return "", ""
}

func matchesRule(r Rule, input TestInput) bool {
	toolMatched := false
	tacticMatched := false

	// Tool matching.
	if len(r.Match.Tools) == 0 {
		toolMatched = true
	} else {
		for _, pattern := range r.Match.Tools {
			if matchPattern(pattern, input.Tool) {
				toolMatched = true
				break
			}
		}
	}

	// Tactic matching.
	if len(r.Match.Tactics) == 0 {
		tacticMatched = true
	} else if input.Tactic == "" {
		tacticMatched = true
	} else {
		for _, t := range r.Match.Tactics {
			if t == input.Tactic {
				tacticMatched = true
				break
			}
		}
	}

	return toolMatched && tacticMatched
}

func matchPattern(pattern, value string) bool {
	if pattern == value {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(value, pattern[1:])
	}
	return false
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// ValidateTestSuite checks a test suite for structural errors.
func ValidateTestSuite(ts *TestSuite) []string {
	var errs []string

	if ts.Meta.Name == "" {
		errs = append(errs, "test suite missing name")
	}
	if len(ts.Tests) == 0 {
		errs = append(errs, "test suite has no test cases")
	}

	ids := make(map[string]bool)
	for i, tc := range ts.Tests {
		if tc.ID == "" {
			errs = append(errs, fmt.Sprintf("test %d missing ID", i+1))
		} else if ids[tc.ID] {
			errs = append(errs, fmt.Sprintf("duplicate test ID %q", tc.ID))
		}
		ids[tc.ID] = true

		if tc.Input.Tool == "" {
			errs = append(errs, fmt.Sprintf("test %q missing input tool", tc.ID))
		}

		if !tc.Expect.NoMatch && tc.Expect.Effect == "" {
			errs = append(errs, fmt.Sprintf("test %q missing expected effect", tc.ID))
		}
		if tc.Expect.NoMatch && tc.Expect.Effect != "" {
			errs = append(errs, fmt.Sprintf("test %q has both no_match and effect set", tc.ID))
		}
		if !tc.Expect.NoMatch && tc.Expect.Effect != "" {
			if !validEffects[tc.Expect.Effect] {
				errs = append(errs, fmt.Sprintf("test %q has invalid expected effect %q", tc.ID, tc.Expect.Effect))
			}
		}
	}

	return errs
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

// FilterTestsByTag returns tests matching the given tag.
func FilterTestsByTag(suite *TestSuite, tag string) []TestCase {
	var filtered []TestCase
	for _, tc := range suite.Tests {
		for _, t := range tc.Tags {
			if t == tag {
				filtered = append(filtered, tc)
				break
			}
		}
	}
	return filtered
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// FormatTestResults renders test results as a human-readable report.
func FormatTestResults(r *TestSuiteResult) string {
	var sb strings.Builder

	sb.WriteString("┌─────────────────────────────────────────────────────┐\n")
	sb.WriteString("│              Policy Test Results                     │\n")
	sb.WriteString("├─────────────────────────────────────────────────────┤\n")
	sb.WriteString(fmt.Sprintf("│ Suite:   %-43s │\n", truncStr(r.Suite, 43)))
	sb.WriteString(fmt.Sprintf("│ Policy:  %-43s │\n", truncStr(r.Policy, 43)))
	sb.WriteString(fmt.Sprintf("│ Total: %-3d  Passed: %-3d  Failed: %-3d              │\n",
		r.Total, r.Passed, r.Failed))
	sb.WriteString("├─────────────────────────────────────────────────────┤\n")

	for _, tr := range r.Results {
		icon := "✓"
		if !tr.Passed {
			icon = "✗"
		}
		sb.WriteString(fmt.Sprintf("│ [%s] %-47s │\n", icon, truncStr(tr.TestName, 47)))
		if !tr.Passed {
			sb.WriteString(fmt.Sprintf("│     expected: %-38s │\n", tr.Expected))
			sb.WriteString(fmt.Sprintf("│     actual:   %-38s │\n", tr.Actual))
			if tr.Message != "" {
				sb.WriteString(fmt.Sprintf("│     %s\n", tr.Message))
			}
		}
	}

	sb.WriteString("├─────────────────────────────────────────────────────┤\n")
	status := "PASS"
	if r.Failed > 0 {
		status = "FAIL"
	}
	sb.WriteString(fmt.Sprintf("│ Result: %-4s  (%d/%d passed)                       │\n",
		status, r.Passed, r.Total))
	sb.WriteString("└─────────────────────────────────────────────────────┘\n")

	return sb.String()
}

// FormatTestResultsJSON returns test results as indented JSON.
func FormatTestResultsJSON(r *TestSuiteResult) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SummarizeTestResults returns a one-line summary.
func SummarizeTestResults(r *TestSuiteResult) string {
	status := "PASS"
	if r.Failed > 0 {
		status = "FAIL"
	}
	return fmt.Sprintf("%s: %d/%d tests passed for policy %q (suite: %s)",
		status, r.Passed, r.Total, r.Policy, r.Suite)
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

// GenerateTestSuite creates a test suite skeleton from a policy.
func GenerateTestSuite(p *Policy) *TestSuite {
	ts := &TestSuite{
		APIVersion: "v1",
		Kind:       "PolicyTestSuite",
		Meta: TestMeta{
			Name:        p.Meta.Name + "-tests",
			Description: fmt.Sprintf("Auto-generated test suite for policy %q", p.Meta.Name),
			Policy:      p.Meta.Name,
		},
	}

	// Generate one test per rule.
	toolsSeen := make(map[string]bool)
	for _, r := range p.Rules {
		for _, tool := range r.Match.Tools {
			if toolsSeen[tool] {
				continue
			}
			toolsSeen[tool] = true

			tc := TestCase{
				ID:   fmt.Sprintf("test-%s-%s", r.ID, sanitizeID(tool)),
				Name: fmt.Sprintf("%s should %s %s", p.Meta.Name, r.Effect, tool),
				Input: TestInput{
					Tool: tool,
				},
				Expect: TestExpectation{
					Effect: r.Effect,
					RuleID: r.ID,
				},
			}

			if len(r.Match.Tactics) > 0 {
				tc.Input.Tactic = r.Match.Tactics[0]
			}

			ts.Tests = append(ts.Tests, tc)
		}
	}

	sort.Slice(ts.Tests, func(i, j int) bool {
		return ts.Tests[i].ID < ts.Tests[j].ID
	})

	return ts
}

func sanitizeID(s string) string {
	var out strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			out.WriteRune(c)
		} else if c >= 'A' && c <= 'Z' {
			out.WriteRune(c + 32)
		} else {
			out.WriteRune('-')
		}
	}
	return out.String()
}
