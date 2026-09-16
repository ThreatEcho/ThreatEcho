// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/gap"
	"github.com/ThreatEcho/threatecho/internal/policy"
)

// JUnit XML types — unexported, used only for marshalling.

type junitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	XMLName  xml.Name        `xml:"testsuite"`
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Errors   int             `xml:"errors,attr"`
	Skipped  int             `xml:"skipped,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr,omitempty"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr,omitempty"`
}

// xmlHeader is the standard XML declaration prepended to all JUnit output.
var xmlHeader = []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")

// GapJUnitReport writes a JUnit XML representation of a gap analysis report.
// Every gap becomes a failing test case inside a single suite named
// "threatecho-gap-analysis". CI platforms surface the failures as test
// regressions, giving security teams a familiar review workflow.
func GapJUnitReport(w io.Writer, r *gap.GapReport) error {
	suite := junitTestSuite{
		Name:     "threatecho-gap-analysis",
		Tests:    len(r.Gaps),
		Failures: len(r.Gaps),
	}

	for _, g := range r.Gaps {
		tc := junitTestCase{
			Name:      gapTestCaseName(g),
			ClassName: gapClassName(g),
			Failure: &junitFailure{
				Type:    string(g.Type),
				Message: gapFailureMessage(g),
				Text:    g.Description,
			},
		}
		suite.Cases = append(suite.Cases, tc)
	}

	suites := junitTestSuites{
		Suites: []junitTestSuite{suite},
	}
	return marshalJUnit(w, suites)
}

// PolicyJUnitReport writes a JUnit XML representation of a policy evaluation.
// Each violation becomes a failing test case inside a single suite named
// "threatecho-policy-eval". The suite's test count reflects TotalStages so
// CI dashboards show the full scope even though only violations carry detail.
func PolicyJUnitReport(w io.Writer, r *policy.EvalResult) error {
	suite := junitTestSuite{
		Name:     "threatecho-policy-eval",
		Tests:    r.TotalStages,
		Failures: r.Denied + r.Alerted,
	}

	for _, v := range r.Violations {
		tc := junitTestCase{
			Name:      v.StageName,
			ClassName: r.Campaign,
			Failure: &junitFailure{
				Type:    v.Effect,
				Message: policyFailureMessage(v),
				Text:    v.Reason,
			},
		}
		suite.Cases = append(suite.Cases, tc)
	}

	suites := junitTestSuites{
		Suites: []junitTestSuite{suite},
	}
	return marshalJUnit(w, suites)
}

// marshalJUnit writes the XML header followed by indented XML to w.
func marshalJUnit(w io.Writer, v interface{}) error {
	if _, err := w.Write(xmlHeader); err != nil {
		return err
	}
	data, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// gapTestCaseName produces the test case name from a gap entry.
func gapTestCaseName(g gap.Gap) string {
	switch g.Type {
	case gap.GapTacticUncovered:
		return "tactic: " + g.Tactic
	case gap.GapDetectionMissing:
		return g.StageID + ": detection for " + g.Technique
	case gap.GapTelemetryMissing:
		return g.StageID + ": telemetry for " + g.Technique
	}
	return g.StageID + ": " + string(g.Type)
}

// gapClassName returns the suite class for a gap test case.
func gapClassName(g gap.Gap) string {
	if g.CampaignName != "" {
		return g.CampaignName
	}
	return "aggregate"
}

// gapFailureMessage builds a human-readable failure message including risk.
func gapFailureMessage(g gap.Gap) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("[%s]", strings.ToUpper(g.Risk)))
	switch g.Type {
	case gap.GapTacticUncovered:
		parts = append(parts, fmt.Sprintf("tactic %q has no stage coverage", g.Tactic))
	case gap.GapDetectionMissing:
		parts = append(parts, fmt.Sprintf("no detection rules for technique %s", g.Technique))
	case gap.GapTelemetryMissing:
		parts = append(parts, fmt.Sprintf("no telemetry for technique %s", g.Technique))
	}
	return strings.Join(parts, " ")
}

// policyFailureMessage builds a human-readable failure message for a violation.
func policyFailureMessage(v policy.Violation) string {
	return fmt.Sprintf("[%s] rule %s: %s", strings.ToUpper(v.Effect), v.RuleID, v.RuleDesc)
}
