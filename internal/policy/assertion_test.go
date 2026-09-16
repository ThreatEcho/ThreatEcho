// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mkAssertPolicy(rules []Rule) *Policy {
	return &Policy{
		APIVersion: "v1",
		Kind:       "Policy",
		Meta:       PolicyMeta{Name: "test-policy"},
		Rules:      rules,
	}
}

func assertDeny(id, tool, tactic string) Rule {
	return Rule{
		ID:     id,
		Effect: "deny",
		Match:  RuleMatch{Tools: []string{tool}, Tactics: []string{tactic}},
	}
}

func assertAlert(id, tool string) Rule {
	return Rule{
		ID:     id,
		Effect: "alert",
		Match:  RuleMatch{Tools: []string{tool}},
	}
}

func assertAllow(id, tool string) Rule {
	return Rule{
		ID:     id,
		Effect: "allow",
		Match:  RuleMatch{Tools: []string{tool}},
	}
}

// ---------------------------------------------------------------------------
// RunTestSuite
// ---------------------------------------------------------------------------

func TestRunTestSuite_AllPass(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertDeny("r1", "shell_exec", "execution"),
		assertAlert("r2", "file_read"),
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "basic"},
		Tests: []TestCase{
			{ID: "t1", Name: "deny shell", Input: TestInput{Tool: "shell_exec", Tactic: "execution"}, Expect: TestExpectation{Effect: "deny"}},
			{ID: "t2", Name: "alert file_read", Input: TestInput{Tool: "file_read"}, Expect: TestExpectation{Effect: "alert"}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Total != 2 {
		t.Errorf("total = %d, want 2", result.Total)
	}
	if result.Passed != 2 {
		t.Errorf("passed = %d, want 2", result.Passed)
	}
	if result.Failed != 0 {
		t.Errorf("failed = %d, want 0", result.Failed)
	}
}

func TestRunTestSuite_EffectMismatch(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertDeny("r1", "shell_exec", "execution"),
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "mismatch"},
		Tests: []TestCase{
			{ID: "t1", Name: "expect alert", Input: TestInput{Tool: "shell_exec", Tactic: "execution"}, Expect: TestExpectation{Effect: "alert"}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Passed != 0 {
		t.Errorf("passed = %d, want 0", result.Passed)
	}
	if result.Failed != 1 {
		t.Errorf("failed = %d, want 1", result.Failed)
	}
	if result.Results[0].Expected != "alert" {
		t.Errorf("expected = %q, want %q", result.Results[0].Expected, "alert")
	}
	if result.Results[0].Actual != "deny" {
		t.Errorf("actual = %q, want %q", result.Results[0].Actual, "deny")
	}
}

func TestRunTestSuite_NoMatch(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertDeny("r1", "shell_exec", "execution"),
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "no-match"},
		Tests: []TestCase{
			{ID: "t1", Name: "expect no match", Input: TestInput{Tool: "web_search"}, Expect: TestExpectation{NoMatch: true}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Passed != 1 {
		t.Errorf("passed = %d, want 1", result.Passed)
	}
}

func TestRunTestSuite_NoMatchButMatched(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertDeny("r1", "shell_exec", "execution"),
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "no-match-fail"},
		Tests: []TestCase{
			{ID: "t1", Name: "should not match", Input: TestInput{Tool: "shell_exec", Tactic: "execution"}, Expect: TestExpectation{NoMatch: true}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Failed != 1 {
		t.Errorf("failed = %d, want 1", result.Failed)
	}
	if !strings.Contains(result.Results[0].Message, "Expected no match") {
		t.Errorf("message = %q, want mention of expected no match", result.Results[0].Message)
	}
}

func TestRunTestSuite_ExpectedRuleID(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertDeny("r1", "shell_exec", "execution"),
		assertDeny("r2", "file_write", "persistence"),
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "rule-id"},
		Tests: []TestCase{
			{ID: "t1", Name: "match r1", Input: TestInput{Tool: "shell_exec", Tactic: "execution"}, Expect: TestExpectation{Effect: "deny", RuleID: "r1"}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Passed != 1 {
		t.Errorf("passed = %d, want 1", result.Passed)
	}
	if result.Results[0].MatchedRule != "r1" {
		t.Errorf("matched rule = %q, want %q", result.Results[0].MatchedRule, "r1")
	}
}

func TestRunTestSuite_WrongRuleID(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertDeny("r1", "shell_exec", "execution"),
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "wrong-rule"},
		Tests: []TestCase{
			{ID: "t1", Name: "expect r2", Input: TestInput{Tool: "shell_exec", Tactic: "execution"}, Expect: TestExpectation{Effect: "deny", RuleID: "r2"}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Failed != 1 {
		t.Errorf("failed = %d, want 1", result.Failed)
	}
	if !strings.Contains(result.Results[0].Message, "Expected rule") {
		t.Errorf("message = %q, want mention of expected rule", result.Results[0].Message)
	}
}

func TestRunTestSuite_ExpectedEffectButNoMatch(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertDeny("r1", "shell_exec", "execution"),
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "effect-no-match"},
		Tests: []TestCase{
			{ID: "t1", Name: "unmatched tool", Input: TestInput{Tool: "unknown_tool"}, Expect: TestExpectation{Effect: "deny"}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Failed != 1 {
		t.Errorf("failed = %d, want 1", result.Failed)
	}
	if result.Results[0].Actual != "no_match" {
		t.Errorf("actual = %q, want %q", result.Results[0].Actual, "no_match")
	}
}

func TestRunTestSuite_AllowRule(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertAllow("r1", "read_file"),
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "allow"},
		Tests: []TestCase{
			{ID: "t1", Name: "allow read", Input: TestInput{Tool: "read_file"}, Expect: TestExpectation{Effect: "allow"}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Passed != 1 {
		t.Errorf("passed = %d, want 1", result.Passed)
	}
}

func TestRunTestSuite_WildcardToolPattern(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		{ID: "r1", Effect: "deny", Match: RuleMatch{Tools: []string{"shell_*"}}},
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "wildcard"},
		Tests: []TestCase{
			{ID: "t1", Name: "prefix match", Input: TestInput{Tool: "shell_exec"}, Expect: TestExpectation{Effect: "deny"}},
			{ID: "t2", Name: "no prefix match", Input: TestInput{Tool: "file_read"}, Expect: TestExpectation{NoMatch: true}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Passed != 2 {
		for _, r := range result.Results {
			if !r.Passed {
				t.Errorf("test %s failed: %s", r.TestID, r.Message)
			}
		}
	}
}

func TestRunTestSuite_SuffixWildcard(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		{ID: "r1", Effect: "alert", Match: RuleMatch{Tools: []string{"*_exec"}}},
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "suffix"},
		Tests: []TestCase{
			{ID: "t1", Name: "suffix match", Input: TestInput{Tool: "shell_exec"}, Expect: TestExpectation{Effect: "alert"}},
			{ID: "t2", Name: "no suffix match", Input: TestInput{Tool: "shell_read"}, Expect: TestExpectation{NoMatch: true}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Passed != 2 {
		for _, r := range result.Results {
			if !r.Passed {
				t.Errorf("test %s failed: %s", r.TestID, r.Message)
			}
		}
	}
}

func TestRunTestSuite_TacticOnlyRule(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		{ID: "r1", Effect: "deny", Match: RuleMatch{Tactics: []string{"execution"}}},
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "tactic-only"},
		Tests: []TestCase{
			{ID: "t1", Name: "any tool execution", Input: TestInput{Tool: "anything", Tactic: "execution"}, Expect: TestExpectation{Effect: "deny"}},
			{ID: "t2", Name: "no tactic no match", Input: TestInput{Tool: "anything", Tactic: "collection"}, Expect: TestExpectation{NoMatch: true}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Passed != 2 {
		for _, r := range result.Results {
			if !r.Passed {
				t.Errorf("test %s failed: %s", r.TestID, r.Message)
			}
		}
	}
}

func TestRunTestSuite_EmptySuite(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy(nil)
	suite := &TestSuite{Meta: TestMeta{Name: "empty"}}

	result := RunTestSuite(p, suite)
	if result.Total != 0 {
		t.Errorf("total = %d, want 0", result.Total)
	}
	if result.Failed != 0 {
		t.Errorf("failed = %d, want 0", result.Failed)
	}
}

func TestRunTestSuite_MixedResults(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertDeny("r1", "shell_exec", "execution"),
		assertAlert("r2", "file_read"),
	})
	suite := &TestSuite{
		Meta: TestMeta{Name: "mixed"},
		Tests: []TestCase{
			{ID: "t1", Name: "passes", Input: TestInput{Tool: "shell_exec", Tactic: "execution"}, Expect: TestExpectation{Effect: "deny"}},
			{ID: "t2", Name: "fails", Input: TestInput{Tool: "file_read"}, Expect: TestExpectation{Effect: "deny"}}, // wrong, should be alert
			{ID: "t3", Name: "also passes", Input: TestInput{Tool: "file_read"}, Expect: TestExpectation{Effect: "alert"}},
		},
	}

	result := RunTestSuite(p, suite)
	if result.Passed != 2 {
		t.Errorf("passed = %d, want 2", result.Passed)
	}
	if result.Failed != 1 {
		t.Errorf("failed = %d, want 1", result.Failed)
	}
}

// ---------------------------------------------------------------------------
// matchPattern
// ---------------------------------------------------------------------------

func TestMatchPattern_Exact(t *testing.T) {
	t.Parallel()
	if !matchPattern("shell_exec", "shell_exec") {
		t.Error("exact match should pass")
	}
	if matchPattern("shell_exec", "file_read") {
		t.Error("different should not match")
	}
}

func TestMatchPattern_Prefix(t *testing.T) {
	t.Parallel()
	if !matchPattern("shell_*", "shell_exec") {
		t.Error("prefix wildcard should match")
	}
	if matchPattern("shell_*", "file_read") {
		t.Error("prefix wildcard should not match different prefix")
	}
}

func TestMatchPattern_Suffix(t *testing.T) {
	t.Parallel()
	if !matchPattern("*_exec", "shell_exec") {
		t.Error("suffix wildcard should match")
	}
	if matchPattern("*_exec", "shell_read") {
		t.Error("suffix wildcard should not match different suffix")
	}
}

// ---------------------------------------------------------------------------
// ValidateTestSuite
// ---------------------------------------------------------------------------

func TestValidateTestSuite_Valid(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{
		Meta: TestMeta{Name: "valid"},
		Tests: []TestCase{
			{ID: "t1", Name: "test", Input: TestInput{Tool: "x"}, Expect: TestExpectation{Effect: "deny"}},
		},
	}
	errs := ValidateTestSuite(ts)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateTestSuite_MissingName(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{
		Tests: []TestCase{
			{ID: "t1", Input: TestInput{Tool: "x"}, Expect: TestExpectation{Effect: "deny"}},
		},
	}
	errs := ValidateTestSuite(ts)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "missing name") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected missing name error, got: %v", errs)
	}
}

func TestValidateTestSuite_NoTests(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{Meta: TestMeta{Name: "empty"}}
	errs := ValidateTestSuite(ts)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "no test cases") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected no test cases error, got: %v", errs)
	}
}

func TestValidateTestSuite_DuplicateIDs(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{
		Meta: TestMeta{Name: "dups"},
		Tests: []TestCase{
			{ID: "t1", Input: TestInput{Tool: "x"}, Expect: TestExpectation{Effect: "deny"}},
			{ID: "t1", Input: TestInput{Tool: "y"}, Expect: TestExpectation{Effect: "allow"}},
		},
	}
	errs := ValidateTestSuite(ts)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "duplicate") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected duplicate ID error, got: %v", errs)
	}
}

func TestValidateTestSuite_MissingTool(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{
		Meta: TestMeta{Name: "no-tool"},
		Tests: []TestCase{
			{ID: "t1", Expect: TestExpectation{Effect: "deny"}},
		},
	}
	errs := ValidateTestSuite(ts)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "missing input tool") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected missing tool error, got: %v", errs)
	}
}

func TestValidateTestSuite_NoMatchWithEffect(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{
		Meta: TestMeta{Name: "conflict"},
		Tests: []TestCase{
			{ID: "t1", Input: TestInput{Tool: "x"}, Expect: TestExpectation{NoMatch: true, Effect: "deny"}},
		},
	}
	errs := ValidateTestSuite(ts)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "both no_match and effect") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected conflict error, got: %v", errs)
	}
}

func TestValidateTestSuite_InvalidEffect(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{
		Meta: TestMeta{Name: "invalid-effect"},
		Tests: []TestCase{
			{ID: "t1", Input: TestInput{Tool: "x"}, Expect: TestExpectation{Effect: "block"}},
		},
	}
	errs := ValidateTestSuite(ts)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "invalid expected effect") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected invalid effect error, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// FilterTestsByTag
// ---------------------------------------------------------------------------

func TestFilterTestsByTag(t *testing.T) {
	t.Parallel()
	suite := &TestSuite{
		Tests: []TestCase{
			{ID: "t1", Tags: []string{"execution", "critical"}},
			{ID: "t2", Tags: []string{"persistence"}},
			{ID: "t3", Tags: []string{"execution"}},
		},
	}

	filtered := FilterTestsByTag(suite, "execution")
	if len(filtered) != 2 {
		t.Errorf("filtered = %d, want 2", len(filtered))
	}
}

func TestFilterTestsByTag_NoMatch(t *testing.T) {
	t.Parallel()
	suite := &TestSuite{
		Tests: []TestCase{
			{ID: "t1", Tags: []string{"execution"}},
		},
	}
	filtered := FilterTestsByTag(suite, "nonexistent")
	if len(filtered) != 0 {
		t.Errorf("filtered = %d, want 0", len(filtered))
	}
}

// ---------------------------------------------------------------------------
// GenerateTestSuite
// ---------------------------------------------------------------------------

func TestGenerateTestSuite(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertDeny("r1", "shell_exec", "execution"),
		assertAlert("r2", "file_read"),
	})

	ts := GenerateTestSuite(p)
	if ts.Meta.Name != "test-policy-tests" {
		t.Errorf("name = %q, want %q", ts.Meta.Name, "test-policy-tests")
	}
	if ts.Meta.Policy != "test-policy" {
		t.Errorf("policy = %q, want %q", ts.Meta.Policy, "test-policy")
	}
	if len(ts.Tests) != 2 {
		t.Fatalf("tests = %d, want 2", len(ts.Tests))
	}

	// Verify generated tests actually pass.
	result := RunTestSuite(p, ts)
	if result.Failed > 0 {
		for _, r := range result.Results {
			if !r.Passed {
				t.Errorf("generated test %q failed: %s", r.TestID, r.Message)
			}
		}
	}
}

func TestGenerateTestSuite_DeduplicatesTools(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy([]Rule{
		assertDeny("r1", "shell_exec", "execution"),
		assertAlert("r2", "shell_exec"),
	})

	ts := GenerateTestSuite(p)
	if len(ts.Tests) != 1 {
		t.Errorf("tests = %d, want 1 (deduplicated)", len(ts.Tests))
	}
}

func TestGenerateTestSuite_EmptyPolicy(t *testing.T) {
	t.Parallel()
	p := mkAssertPolicy(nil)
	ts := GenerateTestSuite(p)
	if len(ts.Tests) != 0 {
		t.Errorf("tests = %d, want 0", len(ts.Tests))
	}
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

func TestFormatTestResults_AllPass(t *testing.T) {
	t.Parallel()
	r := &TestSuiteResult{
		Suite:  "basic",
		Policy: "test-policy",
		Total:  2,
		Passed: 2,
		Results: []TestResult{
			{TestID: "t1", TestName: "test one", Passed: true},
			{TestID: "t2", TestName: "test two", Passed: true},
		},
	}

	out := FormatTestResults(r)
	if !strings.Contains(out, "PASS") {
		t.Error("should contain PASS")
	}
	if !strings.Contains(out, "2/2") {
		t.Error("should contain 2/2")
	}
}

func TestFormatTestResults_WithFailure(t *testing.T) {
	t.Parallel()
	r := &TestSuiteResult{
		Suite:  "failing",
		Policy: "test-policy",
		Total:  1,
		Failed: 1,
		Results: []TestResult{
			{TestID: "t1", TestName: "fail test", Passed: false, Expected: "deny", Actual: "alert", Message: "wrong effect"},
		},
	}

	out := FormatTestResults(r)
	if !strings.Contains(out, "FAIL") {
		t.Error("should contain FAIL")
	}
	if !strings.Contains(out, "expected") {
		t.Error("should show expected")
	}
}

func TestFormatTestResultsJSON(t *testing.T) {
	t.Parallel()
	r := &TestSuiteResult{
		Suite:  "json-test",
		Policy: "p",
		Total:  1,
		Passed: 1,
		Results: []TestResult{
			{TestID: "t1", TestName: "test", Passed: true},
		},
	}

	out, err := FormatTestResultsJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "json-test") {
		t.Error("JSON should contain suite name")
	}
}

func TestSummarizeTestResults_Pass(t *testing.T) {
	t.Parallel()
	r := &TestSuiteResult{Suite: "s", Policy: "p", Total: 3, Passed: 3}
	s := SummarizeTestResults(r)
	if !strings.HasPrefix(s, "PASS") {
		t.Errorf("summary should start with PASS: %q", s)
	}
}

func TestSummarizeTestResults_Fail(t *testing.T) {
	t.Parallel()
	r := &TestSuiteResult{Suite: "s", Policy: "p", Total: 3, Passed: 2, Failed: 1}
	s := SummarizeTestResults(r)
	if !strings.HasPrefix(s, "FAIL") {
		t.Errorf("summary should start with FAIL: %q", s)
	}
}

// ---------------------------------------------------------------------------
// Load/Save roundtrip
// ---------------------------------------------------------------------------

func TestLoadTestSuite_YAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `api_version: v1
kind: PolicyTestSuite
meta:
  name: sample-tests
  policy: agent-default
tests:
  - id: t1
    name: deny shell
    input:
      tool: shell_exec
      tactic: execution
    expect:
      effect: deny
  - id: t2
    name: no match
    input:
      tool: harmless
    expect:
      no_match: true
`
	os.WriteFile(path, []byte(content), 0644)

	ts, err := LoadTestSuite(path)
	if err != nil {
		t.Fatal(err)
	}
	if ts.Meta.Name != "sample-tests" {
		t.Errorf("name = %q, want %q", ts.Meta.Name, "sample-tests")
	}
	if len(ts.Tests) != 2 {
		t.Errorf("tests = %d, want 2", len(ts.Tests))
	}
	if ts.Tests[0].Expect.Effect != "deny" {
		t.Errorf("first test effect = %q, want %q", ts.Tests[0].Expect.Effect, "deny")
	}
	if !ts.Tests[1].Expect.NoMatch {
		t.Error("second test should be no_match")
	}
}

func TestLoadTestSuite_NotFound(t *testing.T) {
	t.Parallel()
	_, err := LoadTestSuite("/nonexistent/test.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadTestSuiteDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	for _, name := range []string{"a.yaml", "b.yml"} {
		content := `meta:
  name: ` + name + `
tests:
  - id: t1
    name: test
    input:
      tool: x
    expect:
      effect: deny
`
		os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
	}
	os.WriteFile(filepath.Join(dir, "skip.txt"), []byte("not yaml"), 0644)

	suites, err := LoadTestSuiteDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(suites) != 2 {
		t.Errorf("suites = %d, want 2", len(suites))
	}
}

func TestLoadTestSuiteDir_NotFound(t *testing.T) {
	t.Parallel()
	_, err := LoadTestSuiteDir("/nonexistent/dir")
	if err == nil {
		t.Error("expected error for missing directory")
	}
}

// ---------------------------------------------------------------------------
// sanitizeID
// ---------------------------------------------------------------------------

func TestSanitizeID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"shell_exec", "shell-exec"},
		{"File.Read", "file-read"},
		{"abc123", "abc123"},
		{"a b c", "a-b-c"},
	}
	for _, tt := range tests {
		got := sanitizeID(tt.in)
		if got != tt.want {
			t.Errorf("sanitizeID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
