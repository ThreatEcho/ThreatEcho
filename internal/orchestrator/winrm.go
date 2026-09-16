// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package orchestrator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/masterzen/winrm"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/runner"
)

type winrmClient struct {
	client *winrm.Client
}

func dialWinRM(t Target) (*winrmClient, error) {
	port := t.Port
	if port == 0 {
		port = 5985
	}

	endpoint := winrm.NewEndpoint(t.Host, port, false, true, nil, nil, nil, 30*time.Second)
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return &winrm.ClientNTLM{}
	}
	client, err := winrm.NewClientWithParameters(endpoint, t.User, t.Password, params)
	if err != nil {
		return nil, fmt.Errorf("winrm client %s:%d: %w", t.Host, port, err)
	}
	return &winrmClient{client: client}, nil
}

func (c *winrmClient) close() error {
	return nil
}

func (c *winrmClient) run(ctx context.Context, cmd string) (string, error) {
	return c.runShell(ctx, cmd)
}

func (c *winrmClient) runShell(ctx context.Context, cmd string) (string, error) {
	wrapped := fmt.Sprintf("cmd /c %s", cmd)
	var stdout, stderr bytes.Buffer
	exitCode, err := c.client.RunWithContext(ctx, wrapped, &stdout, &stderr)
	if err != nil {
		return stdout.String(), fmt.Errorf("winrm exec: %w", err)
	}
	if exitCode != 0 {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = fmt.Sprintf("exit code %d", exitCode)
		}
		return stdout.String(), fmt.Errorf("%s", errMsg)
	}
	return stdout.String(), nil
}

func (c *winrmClient) runPS(ctx context.Context, cmd string) (string, error) {
	ps := winrm.Powershell(cmd)
	var stdout, stderr bytes.Buffer
	exitCode, err := c.client.RunWithContext(ctx, ps, &stdout, &stderr)
	if err != nil {
		return stdout.String(), fmt.Errorf("winrm exec: %w", err)
	}
	if exitCode != 0 {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = fmt.Sprintf("exit code %d", exitCode)
		}
		return stdout.String(), fmt.Errorf("%s", errMsg)
	}
	return stdout.String(), nil
}

func (c *winrmClient) upload(ctx context.Context, data []byte, remotePath string) error {
	dir := psEscape(psParent(remotePath))
	if _, err := c.runPS(ctx, fmt.Sprintf("New-Item -ItemType Directory -Force -Path %s | Out-Null", dir)); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Kill any running agent process before overwriting and remove stale file.
	baseName := remotePath
	for i := len(remotePath) - 1; i >= 0; i-- {
		if remotePath[i] == '\\' || remotePath[i] == '/' {
			baseName = remotePath[i+1:]
			break
		}
	}
	c.runPS(ctx, fmt.Sprintf("Get-Process -Name '%s' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue",
		strings.TrimSuffix(baseName, ".exe")))
	c.runPS(ctx, fmt.Sprintf("Remove-Item %s -Force -ErrorAction SilentlyContinue", psEscape(remotePath)))

	encoded := base64.StdEncoding.EncodeToString(data)
	b64Path := remotePath + ".b64"

	ps := winrm.Powershell(fmt.Sprintf(
		"$input | Set-Content -Path %s -NoNewline",
		psEscape(b64Path),
	))

	var stdout, stderr bytes.Buffer
	exitCode, err := c.client.RunWithContextWithInput(ctx, ps, &stdout, &stderr, strings.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("upload via stdin: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("upload via stdin: exit %d: %s", exitCode, stderr.String())
	}

	decodeCmd := fmt.Sprintf(
		"$b = [IO.File]::ReadAllText(%s); [IO.File]::WriteAllBytes(%s, [Convert]::FromBase64String($b)); Remove-Item %s",
		psEscape(b64Path), psEscape(remotePath), psEscape(b64Path),
	)
	if _, err := c.runPS(ctx, decodeCmd); err != nil {
		return fmt.Errorf("decode uploaded file: %w", err)
	}

	return nil
}

func (c *winrmClient) download(ctx context.Context, remotePath string) ([]byte, error) {
	cmd := fmt.Sprintf("[Convert]::ToBase64String([IO.File]::ReadAllBytes(%s))", psEscape(remotePath))
	out, err := c.runPS(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", remotePath, err)
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(out))
}

func psEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func psParent(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// WinRMDeployer runs campaigns in agentless mode over WinRM (PowerShell).
type WinRMDeployer struct {
	conn *winrmClient
}

func newWinRMDeployer(t Target) (*WinRMDeployer, error) {
	conn, err := dialWinRM(t)
	if err != nil {
		return nil, err
	}
	return &WinRMDeployer{conn: conn}, nil
}

func (d *WinRMDeployer) Close() error {
	return d.conn.close()
}

func (d *WinRMDeployer) Deploy(ctx context.Context, t Target, c *campaign.Campaign, cfg DeployConfig) (*runner.RunReport, error) {
	hostname, err := d.conn.runShell(ctx, "hostname")
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "401") || strings.Contains(errStr, "invalid content type") {
			return nil, fmt.Errorf("winrm authentication failed for %s@%s:%d — verify credentials, domain controller availability, and WinRM service", t.User, t.Host, t.Port)
		}
		return nil, fmt.Errorf("winrm connectivity check failed: %w", err)
	}
	whoami, _ := d.conn.runShell(ctx, "whoami")

	report := &runner.RunReport{
		Campaign:  c.Meta.Name,
		Hostname:  strings.TrimSpace(hostname),
		OS:        t.OS,
		User:      strings.TrimSpace(whoami),
		Elevated:  cfg.AllowElevated,
		StartedAt: time.Now(),
	}

	ordered, err := campaign.ResolveOrder(c.Stages)
	if err != nil {
		report.FinishedAt = time.Now()
		report.Duration = report.FinishedAt.Sub(report.StartedAt).String()
		return report, fmt.Errorf("resolve stage order: %w", err)
	}

	report.TotalStages = len(ordered)

	aborted := false
	for i, stage := range ordered {
		if aborted {
			break
		}
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "  [%d/%d] %s (%s)... ", i+1, len(ordered), stage.Name, stage.ID)
		}
		sr := d.runStageWithTimeout(ctx, stage, t, cfg)
		report.Stages = append(report.Stages, sr)

		if cfg.Verbose {
			if sr.DurationHuman != "" {
				fmt.Fprintf(os.Stderr, "%s [%s]\n", sr.Status, sr.DurationHuman)
			} else {
				fmt.Fprintf(os.Stderr, "%s\n", sr.Status)
			}
		}

		switch sr.Status {
		case "passed":
			report.Passed++
		case "failed":
			report.Failed++
			if stage.OnFailure == "abort" {
				aborted = true
			}
		case "skipped":
			report.Skipped++
		case "precondition_failed":
			report.PrecondFail++
		}
	}

	report.FinishedAt = time.Now()
	report.Duration = report.FinishedAt.Sub(report.StartedAt).Round(time.Millisecond).String()
	return report, nil
}

func (d *WinRMDeployer) runStageWithTimeout(ctx context.Context, stage campaign.Stage, t Target, cfg DeployConfig) runner.StageReport {
	timeout := defaultStageTimeout
	if stage.Timeout.Duration > 0 {
		timeout = stage.Timeout.Duration
	}
	stageCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.runStage(stageCtx, stage, t, cfg)
}

func (d *WinRMDeployer) runStage(ctx context.Context, stage campaign.Stage, t Target, cfg DeployConfig) runner.StageReport {
	sr := runner.StageReport{
		StageID:   stage.ID,
		Name:      stage.Name,
		Technique: stage.Technique,
		Tactic:    stage.Tactic,
		Elevated:  stage.Execute.Elevated,
		Commands:  len(stage.Execute.Commands),
	}

	if len(stage.Platform) > 0 {
		matched := false
		for _, p := range stage.Platform {
			if p == t.OS {
				matched = true
				break
			}
		}
		if !matched {
			sr.Status = "precondition_failed"
			sr.Error = fmt.Sprintf("platform mismatch: stage requires %v, target is %s", stage.Platform, t.OS)
			return sr
		}
	}

	if stage.Execute.Elevated && !cfg.AllowElevated {
		sr.Status = "precondition_failed"
		sr.Error = "elevated execution not permitted"
		return sr
	}

	if stage.Execute.Type != "shell" && stage.Execute.Type != "powershell" && stage.Execute.Type != "" {
		sr.Status = "skipped"
		sr.Error = fmt.Sprintf("execute type %q not supported in WinRM agentless mode", stage.Execute.Type)
		return sr
	}

	runFn := d.conn.runShell
	if stage.Execute.Type == "powershell" {
		runFn = d.conn.runPS
	}

	start := time.Now()
	var outputs []string

	for _, cmd := range stage.Execute.Commands {
		out, err := runFn(ctx, cmd)
		outputs = append(outputs, out)
		if err != nil {
			sr.Status = "failed"
			sr.Error = fmt.Sprintf("command failed: %s", err)
			sr.Output = strings.Join(outputs, "\n")
			sr.Duration = time.Since(start)
			sr.DurationHuman = sr.Duration.Round(time.Millisecond).String()
			return sr
		}
	}

	sr.Status = "passed"
	sr.Output = strings.Join(outputs, "\n")
	sr.Duration = time.Since(start)
	sr.DurationHuman = sr.Duration.Round(time.Millisecond).String()

	for _, cmd := range stage.Execute.Cleanup {
		if _, err := runFn(ctx, cmd); err != nil {
			sr.CleanupError = err.Error()
		}
	}

	return sr
}

// AgentWinRMDeployer pushes the threatecho-agent binary and campaign to a
// Windows target over WinRM, runs the agent, and pulls the JSON report back.
type AgentWinRMDeployer struct {
	conn *winrmClient
}

func newAgentWinRMDeployer(t Target) (*AgentWinRMDeployer, error) {
	conn, err := dialWinRM(t)
	if err != nil {
		return nil, err
	}
	return &AgentWinRMDeployer{conn: conn}, nil
}

func (d *AgentWinRMDeployer) Close() error {
	return d.conn.close()
}

func (d *AgentWinRMDeployer) Deploy(ctx context.Context, t Target, c *campaign.Campaign, cfg DeployConfig) (*runner.RunReport, error) {
	workDir := cfg.WorkDir
	if workDir == "" {
		workDir = `C:\Windows\Temp\threatecho-deploy`
	}

	if _, err := d.conn.runPS(ctx, fmt.Sprintf("New-Item -ItemType Directory -Force -Path %s | Out-Null", psEscape(workDir))); err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "401") || strings.Contains(errStr, "invalid content type") {
			return nil, fmt.Errorf("winrm authentication failed for %s@%s:%d — verify credentials, domain controller availability, and WinRM service", t.User, t.Host, t.Port)
		}
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	agentBin, err := os.ReadFile(cfg.AgentBinary)
	if err != nil {
		return nil, fmt.Errorf("read agent binary: %w", err)
	}
	remoteBin := workDir + `\threatecho-agent.exe`
	if err := d.conn.upload(ctx, agentBin, remoteBin); err != nil {
		return nil, fmt.Errorf("upload agent binary: %w", err)
	}

	campaignData, err := campaignToYAML(c)
	if err != nil {
		return nil, fmt.Errorf("marshal campaign: %w", err)
	}
	remoteCampaign := workDir + `\campaign.yaml`
	if err := d.conn.upload(ctx, campaignData, remoteCampaign); err != nil {
		return nil, fmt.Errorf("upload campaign: %w", err)
	}

	remoteReport := workDir + `\report.json`
	cmd := fmt.Sprintf("%s run --out %s --platform windows",
		remoteBin,
		remoteReport,
	)
	if cfg.AllowElevated {
		cmd += " --elevated"
	}
	cmd += " " + remoteCampaign

	d.conn.runShell(ctx, cmd)

	reportData, err := d.conn.download(ctx, remoteReport)
	if err != nil {
		return nil, fmt.Errorf("download report: %w", err)
	}

	d.conn.runPS(ctx, fmt.Sprintf("Remove-Item -Recurse -Force %s", psEscape(workDir)))

	var report runner.RunReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		return nil, fmt.Errorf("parse report: %w", err)
	}
	return &report, nil
}
