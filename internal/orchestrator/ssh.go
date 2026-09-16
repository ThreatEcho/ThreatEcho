// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ThreatEcho/threatecho/internal/campaign"
	"github.com/ThreatEcho/threatecho/internal/runner"
)

// sshClient wraps an SSH connection with helper methods.
type sshClient struct {
	client *ssh.Client
}

func dialSSH(t Target) (*sshClient, error) {
	config := &ssh.ClientConfig{
		User:            t.User,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	if t.KeyPath != "" {
		key, err := os.ReadFile(t.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("read key %s: %w", t.KeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", t.KeyPath, err)
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else if t.Password != "" {
		config.Auth = []ssh.AuthMethod{ssh.Password(t.Password)}
	}

	addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	return &sshClient{client: client}, nil
}

func (c *sshClient) close() error {
	return c.client.Close()
}

// run executes a command and returns combined stdout+stderr.
func (c *sshClient) run(ctx context.Context, cmd string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out
	session.Stderr = &out

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()

	select {
	case err := <-done:
		return out.String(), err
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		return out.String(), ctx.Err()
	}
}

// upload writes data to a remote file path.
func (c *sshClient) upload(ctx context.Context, data []byte, remotePath string) error {
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	session.Stdin = bytes.NewReader(data)
	return session.Run(fmt.Sprintf("cat > %s", shellQuote(remotePath)))
}

// download reads a remote file's contents.
func (c *sshClient) download(ctx context.Context, remotePath string) ([]byte, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out
	if err := session.Run(fmt.Sprintf("cat %s", shellQuote(remotePath))); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// SSHDeployer runs campaigns remotely in agentless mode (one SSH command per stage).
type SSHDeployer struct {
	conn *sshClient
}

func newSSHDeployer(t Target) (*SSHDeployer, error) {
	conn, err := dialSSH(t)
	if err != nil {
		return nil, err
	}
	return &SSHDeployer{conn: conn}, nil
}

func (d *SSHDeployer) Close() error {
	return d.conn.close()
}

func (d *SSHDeployer) Deploy(ctx context.Context, t Target, c *campaign.Campaign, cfg DeployConfig) (*runner.RunReport, error) {
	hostname, _ := d.conn.run(ctx, "hostname")
	whoami, _ := d.conn.run(ctx, "whoami")

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

const defaultStageTimeout = 5 * time.Minute

func (d *SSHDeployer) runStageWithTimeout(ctx context.Context, stage campaign.Stage, t Target, cfg DeployConfig) runner.StageReport {
	timeout := defaultStageTimeout
	if stage.Timeout.Duration > 0 {
		timeout = stage.Timeout.Duration
	}
	stageCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.runStage(stageCtx, stage, t, cfg)
}

func (d *SSHDeployer) runStage(ctx context.Context, stage campaign.Stage, t Target, cfg DeployConfig) runner.StageReport {
	sr := runner.StageReport{
		StageID:   stage.ID,
		Name:      stage.Name,
		Technique: stage.Technique,
		Tactic:    stage.Tactic,
		Elevated:  stage.Execute.Elevated,
		Commands:  len(stage.Execute.Commands),
	}

	// Platform filter.
	if len(stage.Platform) > 0 {
		matched := false
		for _, p := range stage.Platform {
			if p == t.OS || (p == "macos" && t.OS == "darwin") {
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

	// Elevation filter.
	if stage.Execute.Elevated && !cfg.AllowElevated {
		sr.Status = "precondition_failed"
		sr.Error = "elevated execution not permitted"
		return sr
	}

	// Only execute shell stages.
	if stage.Execute.Type != "shell" && stage.Execute.Type != "" {
		sr.Status = "skipped"
		sr.Error = fmt.Sprintf("execute type %q not supported in agentless mode", stage.Execute.Type)
		return sr
	}

	start := time.Now()
	var outputs []string

	for _, cmd := range stage.Execute.Commands {
		out, err := d.conn.run(ctx, cmd)
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

	// Cleanup commands.
	for _, cmd := range stage.Execute.Cleanup {
		if _, err := d.conn.run(ctx, cmd); err != nil {
			sr.CleanupError = err.Error()
		}
	}

	return sr
}

// AgentSSHDeployer pushes the threatecho-agent binary and campaign to the target,
// runs the agent remotely, and pulls the JSON report back.
type AgentSSHDeployer struct {
	conn *sshClient
}

func newAgentSSHDeployer(t Target) (*AgentSSHDeployer, error) {
	conn, err := dialSSH(t)
	if err != nil {
		return nil, err
	}
	return &AgentSSHDeployer{conn: conn}, nil
}

func (d *AgentSSHDeployer) Close() error {
	return d.conn.close()
}

func (d *AgentSSHDeployer) Deploy(ctx context.Context, t Target, c *campaign.Campaign, cfg DeployConfig) (*runner.RunReport, error) {
	workDir := cfg.WorkDir
	if workDir == "" {
		workDir = "/tmp/threatecho-deploy"
	}

	if _, err := d.conn.run(ctx, fmt.Sprintf("mkdir -p %s", shellQuote(workDir))); err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	// Upload agent binary.
	agentBin, err := os.ReadFile(cfg.AgentBinary)
	if err != nil {
		return nil, fmt.Errorf("read agent binary: %w", err)
	}
	remoteBin := filepath.Join(workDir, "threatecho-agent")
	if err := d.conn.upload(ctx, agentBin, remoteBin); err != nil {
		return nil, fmt.Errorf("upload agent binary: %w", err)
	}
	if _, err := d.conn.run(ctx, fmt.Sprintf("chmod +x %s", shellQuote(remoteBin))); err != nil {
		return nil, fmt.Errorf("chmod agent binary: %w", err)
	}

	// Upload campaign YAML.
	campaignData, err := campaignToYAML(c)
	if err != nil {
		return nil, fmt.Errorf("marshal campaign: %w", err)
	}
	remoteCampaign := filepath.Join(workDir, "campaign.yaml")
	if err := d.conn.upload(ctx, campaignData, remoteCampaign); err != nil {
		return nil, fmt.Errorf("upload campaign: %w", err)
	}

	// Run agent. Flags must precede the positional campaign path
	// because Go's flag package stops parsing at the first non-flag argument.
	remoteReport := filepath.Join(workDir, "report.json")
	cmd := fmt.Sprintf("%s run --out %s --platform %s",
		shellQuote(remoteBin),
		shellQuote(remoteReport),
		shellQuote(t.OS),
	)
	if cfg.AllowElevated {
		cmd += " --elevated"
	}
	cmd += " " + shellQuote(remoteCampaign)

	d.conn.run(ctx, cmd) // agent may exit non-zero on failures; report still gets written

	// Pull report back.
	reportData, err := d.conn.download(ctx, remoteReport)
	if err != nil {
		return nil, fmt.Errorf("download report: %w", err)
	}

	// Cleanup remote files.
	d.conn.run(ctx, fmt.Sprintf("rm -rf %s", shellQuote(workDir)))

	var report runner.RunReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		return nil, fmt.Errorf("parse report: %w", err)
	}
	return &report, nil
}

func campaignToYAML(c *campaign.Campaign) ([]byte, error) {
	return campaign.Format(c)
}
