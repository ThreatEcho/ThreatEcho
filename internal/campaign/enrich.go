// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ThreatEcho/threatecho/internal/mitre"
)

// EnrichmentData holds ATT&CK metadata for one stage.
type EnrichmentData struct {
	TechniqueName  string
	Tactic         string
	DataSources    []string // e.g. ["Process Creation", "Network Traffic", "File Creation"]
	DetectionNotes string   // brief detection guidance
	Mitigations    []string // e.g. ["Application Isolation", "Code Signing"]
	Severity       string   // inferred from technique characteristics
	Platforms      []string // relevant platforms
}

// EnrichedStage is a stage with its enrichment data.
type EnrichedStage struct {
	Stage      Stage
	Enrichment *EnrichmentData
}

// EnrichResult holds the full enrichment output for a campaign.
type EnrichResult struct {
	CampaignName  string
	TotalStages   int
	EnrichedCount int
	SkippedCount  int // stages without technique IDs
	Stages        []EnrichedStage
}

// techniqueEnrichment maps technique IDs to their enrichment metadata.
// This covers the top 40+ ATT&CK techniques with real data sources and mitigations
// sourced from the MITRE ATT&CK knowledge base.
var techniqueEnrichment = map[string]EnrichmentData{
	// Initial Access
	"T1566": {
		DataSources:    []string{"Application Log", "Network Traffic", "File Creation"},
		DetectionNotes: "Monitor for suspicious email attachments and links. Inspect mail gateway logs for anomalous content types.",
		Mitigations:    []string{"User Training", "Antivirus/Antimalware", "Restrict Web-Based Content"},
		Platforms:      []string{"Windows", "macOS", "Linux"},
	},
	"T1566.001": {
		DataSources:    []string{"Application Log", "File Creation", "Network Traffic", "Process Creation"},
		DetectionNotes: "Monitor for newly created files from email clients. Inspect Office documents for macros and embedded objects.",
		Mitigations:    []string{"User Training", "Antivirus/Antimalware", "Restrict Web-Based Content"},
		Platforms:      []string{"Windows", "macOS", "Linux"},
	},
	"T1566.002": {
		DataSources:    []string{"Application Log", "Network Traffic"},
		DetectionNotes: "Monitor for clicked URLs from email clients. Inspect URL reputations and redirects.",
		Mitigations:    []string{"User Training", "Restrict Web-Based Content"},
		Platforms:      []string{"Windows", "macOS", "Linux"},
	},
	"T1566.003": {
		DataSources:    []string{"Application Log", "Network Traffic"},
		DetectionNotes: "Monitor third-party service messages for suspicious links and attachments.",
		Mitigations:    []string{"User Training", "Restrict Web-Based Content"},
		Platforms:      []string{"Windows", "macOS", "Linux"},
	},
	"T1190": {
		DataSources:    []string{"Application Log", "Network Traffic"},
		DetectionNotes: "Monitor web application logs for exploitation indicators. Look for unusual parameter patterns and error codes.",
		Mitigations:    []string{"Application Isolation and Sandboxing", "Exploit Protection", "Network Segmentation", "Update Software", "Vulnerability Scanning"},
		Platforms:      []string{"Windows", "Linux", "macOS", "Containers"},
	},
	"T1078": {
		DataSources:    []string{"Logon Session", "User Account"},
		DetectionNotes: "Monitor for anomalous logon activity: unusual times, source IPs, or concurrent sessions across geographies.",
		Mitigations:    []string{"Multi-factor Authentication", "Password Policies", "Privileged Account Management"},
		Platforms:      []string{"Windows", "Linux", "macOS", "Azure AD", "Google Workspace"},
	},
	"T1189": {
		DataSources:    []string{"File Creation", "Network Traffic", "Process Creation"},
		DetectionNotes: "Monitor browser process creation of child processes. Inspect network traffic for exploit kit patterns.",
		Mitigations:    []string{"Application Isolation and Sandboxing", "Exploit Protection", "Restrict Web-Based Content", "Update Software"},
		Platforms:      []string{"Windows", "macOS", "Linux"},
	},
	"T1195": {
		DataSources:    []string{"File Creation", "Network Traffic"},
		DetectionNotes: "Monitor for unauthorized modifications to software installers and update packages. Verify software signatures.",
		Mitigations:    []string{"Update Software", "Vulnerability Scanning"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1195.002": {
		DataSources:    []string{"File Creation", "Network Traffic"},
		DetectionNotes: "Verify software hashes and signatures against known-good values. Monitor for unexpected software update activity.",
		Mitigations:    []string{"Update Software", "Vulnerability Scanning"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1199": {
		DataSources:    []string{"Application Log", "Logon Session", "Network Traffic"},
		DetectionNotes: "Monitor for anomalous access from third-party partner networks. Review VPN and remote access logs.",
		Mitigations:    []string{"Network Segmentation", "User Account Management"},
		Platforms:      []string{"Windows", "Linux", "macOS", "SaaS"},
	},

	// Execution
	"T1059": {
		DataSources:    []string{"Command", "Process Creation", "Script Execution"},
		DetectionNotes: "Monitor for command interpreter invocations. Log command-line arguments and script content.",
		Mitigations:    []string{"Code Signing", "Disable or Remove Feature or Program", "Execution Prevention"},
		Platforms:      []string{"Windows", "macOS", "Linux"},
	},
	"T1059.001": {
		DataSources:    []string{"Command", "Process Creation", "Script Execution"},
		DetectionNotes: "Enable PowerShell Script Block Logging and Module Logging. Monitor for encoded commands (-EncodedCommand), download cradles, and AMSI bypass attempts.",
		Mitigations:    []string{"Code Signing", "Disable or Remove Feature or Program", "Execution Prevention"},
		Platforms:      []string{"Windows"},
	},
	"T1059.003": {
		DataSources:    []string{"Command", "Process Creation"},
		DetectionNotes: "Monitor cmd.exe spawning with unusual arguments. Watch for obfuscation patterns (carets, environment variable abuse).",
		Mitigations:    []string{"Execution Prevention"},
		Platforms:      []string{"Windows"},
	},
	"T1059.004": {
		DataSources:    []string{"Command", "Process Creation"},
		DetectionNotes: "Monitor shell invocations with unusual arguments. Watch for reverse shell patterns and encoded payloads.",
		Mitigations:    []string{"Execution Prevention"},
		Platforms:      []string{"macOS", "Linux"},
	},
	"T1059.006": {
		DataSources:    []string{"Command", "Process Creation", "Script Execution"},
		DetectionNotes: "Monitor python/python3 process creation. Watch for suspicious imports (os, subprocess, socket) and obfuscation.",
		Mitigations:    []string{"Execution Prevention", "Disable or Remove Feature or Program"},
		Platforms:      []string{"Windows", "macOS", "Linux"},
	},
	"T1204": {
		DataSources:    []string{"File Creation", "Network Traffic", "Process Creation"},
		DetectionNotes: "Monitor for user-initiated execution of suspicious files. Track file origin metadata (Mark-of-the-Web).",
		Mitigations:    []string{"User Training", "Execution Prevention", "Network Intrusion Prevention"},
		Platforms:      []string{"Windows", "macOS", "Linux"},
	},
	"T1204.002": {
		DataSources:    []string{"File Creation", "Process Creation"},
		DetectionNotes: "Monitor for execution of files downloaded from the internet. Check for recently written executables in user directories.",
		Mitigations:    []string{"User Training", "Execution Prevention"},
		Platforms:      []string{"Windows", "macOS", "Linux"},
	},
	"T1047": {
		DataSources:    []string{"Command", "Network Traffic", "Process Creation"},
		DetectionNotes: "Monitor WMI process creation events (WmiPrvSE.exe). Log WMI activity via Windows event logs (Microsoft-Windows-WMI-Activity).",
		Mitigations:    []string{"Privileged Account Management", "User Account Management"},
		Platforms:      []string{"Windows"},
	},
	"T1569.002": {
		DataSources:    []string{"Command", "Process Creation", "Windows Registry"},
		DetectionNotes: "Monitor for new service installations. Watch sc.exe and services.exe for unusual child processes.",
		Mitigations:    []string{"Privileged Account Management", "Restrict File and Directory Permissions"},
		Platforms:      []string{"Windows"},
	},

	// Persistence
	"T1053.005": {
		DataSources:    []string{"Command", "Process Creation", "Scheduled Job"},
		DetectionNotes: "Monitor for schtasks.exe usage. Audit scheduled task creation events (Event ID 4698).",
		Mitigations:    []string{"Audit", "Operating System Configuration", "Privileged Account Management", "User Account Management"},
		Platforms:      []string{"Windows"},
	},
	"T1547.001": {
		DataSources:    []string{"Command", "Process Creation", "Windows Registry"},
		DetectionNotes: "Monitor registry Run/RunOnce key modifications. Watch for new startup folder entries.",
		Mitigations:    []string{"Restrict Registry Permissions"},
		Platforms:      []string{"Windows"},
	},
	"T1136": {
		DataSources:    []string{"Command", "Process Creation", "User Account"},
		DetectionNotes: "Monitor for account creation events (Event ID 4720). Watch for net user /add commands.",
		Mitigations:    []string{"Multi-factor Authentication", "Network Segmentation", "Privileged Account Management"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1098": {
		DataSources:    []string{"Command", "Group Membership", "User Account"},
		DetectionNotes: "Monitor for account permission changes. Watch for unusual group membership additions.",
		Mitigations:    []string{"Multi-factor Authentication", "Network Segmentation", "Privileged Account Management"},
		Platforms:      []string{"Windows", "Linux", "macOS", "Azure AD"},
	},
	"T1543.003": {
		DataSources:    []string{"Command", "Process Creation", "Service", "Windows Registry"},
		DetectionNotes: "Monitor for new Windows service installations. Watch for sc.exe create commands and registry changes under HKLM\\SYSTEM\\CurrentControlSet\\Services.",
		Mitigations:    []string{"Audit", "User Account Management"},
		Platforms:      []string{"Windows"},
	},

	// Privilege Escalation
	"T1055": {
		DataSources:    []string{"Module Load", "OS API Execution", "Process Access", "Process Creation"},
		DetectionNotes: "Monitor for unusual process access patterns. Watch for processes writing to other process memory (WriteProcessMemory, NtWriteVirtualMemory).",
		Mitigations:    []string{"Behavior Prevention on Endpoint", "Privileged Account Management"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1068": {
		DataSources:    []string{"Application Log", "Process Creation"},
		DetectionNotes: "Monitor for processes spawning with unexpected integrity levels. Watch for known exploit payload patterns.",
		Mitigations:    []string{"Application Isolation and Sandboxing", "Exploit Protection", "Threat Intelligence Program", "Update Software"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1548.002": {
		DataSources:    []string{"Command", "Process Creation", "Windows Registry"},
		DetectionNotes: "Monitor for eventvwr.exe, fodhelper.exe, and other UAC bypass binaries spawning unexpected children.",
		Mitigations:    []string{"Audit", "Privileged Account Management", "Update Software", "User Account Control"},
		Platforms:      []string{"Windows"},
	},

	// Defense Evasion
	"T1070.001": {
		DataSources:    []string{"Command", "Process Creation", "Windows Registry"},
		DetectionNotes: "Monitor for wevtutil cl or Clear-EventLog commands. Watch for Event ID 1102 (audit log cleared).",
		Mitigations:    []string{"Encrypt Sensitive Information", "Remote Data Storage", "Restrict File and Directory Permissions"},
		Platforms:      []string{"Windows"},
	},
	"T1070.004": {
		DataSources:    []string{"Command", "File Deletion"},
		DetectionNotes: "Monitor for bulk file deletion operations. Watch for use of SDelete, cipher /w, or rm -rf on sensitive paths.",
		Mitigations:    []string{"Remote Data Storage"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1027": {
		DataSources:    []string{"Command", "File Creation", "Process Creation"},
		DetectionNotes: "Monitor for files with high entropy or unusual encoding. Watch for base64/XOR patterns in scripts and executables.",
		Mitigations:    []string{"Antivirus/Antimalware", "Behavior Prevention on Endpoint"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1036": {
		DataSources:    []string{"File Creation", "File Metadata", "Process Creation", "Process Metadata"},
		DetectionNotes: "Monitor for processes running from unusual paths that mimic legitimate system binaries. Check binary signatures.",
		Mitigations:    []string{"Code Signing", "Restrict File and Directory Permissions"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1112": {
		DataSources:    []string{"Command", "Process Creation", "Windows Registry"},
		DetectionNotes: "Monitor registry modifications via Sysmon Event ID 13. Watch for reg.exe add commands targeting security-relevant keys.",
		Mitigations:    []string{"Restrict Registry Permissions"},
		Platforms:      []string{"Windows"},
	},
	"T1140": {
		DataSources:    []string{"File Creation", "Process Creation", "Script Execution"},
		DetectionNotes: "Monitor for certutil -decode, base64 -d, and similar decoding utilities. Watch for decoded files written to disk.",
		Mitigations:    []string{"Antivirus/Antimalware", "Behavior Prevention on Endpoint"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1218.011": {
		DataSources:    []string{"Command", "Module Load", "Process Creation"},
		DetectionNotes: "Monitor rundll32.exe invocations with unusual DLLs or ordinal numbers. Watch for rundll32 loading DLLs from temp directories.",
		Mitigations:    []string{"Exploit Protection"},
		Platforms:      []string{"Windows"},
	},
	"T1562.001": {
		DataSources:    []string{"Command", "Process Creation", "Service", "Windows Registry"},
		DetectionNotes: "Monitor for security tool processes being terminated. Watch for modifications to security software registry keys.",
		Mitigations:    []string{"Restrict File and Directory Permissions", "Restrict Registry Permissions", "User Account Management"},
		Platforms:      []string{"Windows", "macOS", "Linux"},
	},

	// Credential Access
	"T1003": {
		DataSources:    []string{"Command", "OS API Execution", "Process Access", "Process Creation"},
		DetectionNotes: "Monitor for access to LSASS (svchost, mimikatz). Watch for NTDS.dit access and shadow copy creation.",
		Mitigations:    []string{"Active Directory Configuration", "Credential Access Protection", "Operating System Configuration", "Password Policies", "Privileged Account Management", "User Training"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1003.001": {
		DataSources:    []string{"Command", "OS API Execution", "Process Access"},
		DetectionNotes: "Monitor for processes accessing lsass.exe. Watch for Sysmon Event ID 10 targeting LSASS. Detect procdump, mimikatz, comsvcs.dll MiniDump.",
		Mitigations:    []string{"Credential Access Protection", "Operating System Configuration", "Privileged Account Management", "Privileged Process Integrity"},
		Platforms:      []string{"Windows"},
	},
	"T1003.003": {
		DataSources:    []string{"Command", "File Access", "Process Creation"},
		DetectionNotes: "Monitor for ntdsutil.exe and vssadmin shadow copy creation targeting the NTDS.dit file. Watch for volume shadow copy access.",
		Mitigations:    []string{"Active Directory Configuration", "Encrypt Sensitive Information", "Password Policies", "Privileged Account Management"},
		Platforms:      []string{"Windows"},
	},
	"T1110": {
		DataSources:    []string{"Application Log", "Logon Session", "User Account"},
		DetectionNotes: "Monitor for multiple failed authentication attempts. Watch for lockout events and distributed login attempts.",
		Mitigations:    []string{"Account Lockout Policies", "Multi-factor Authentication", "Password Policies"},
		Platforms:      []string{"Windows", "Linux", "macOS", "Azure AD"},
	},
	"T1110.003": {
		DataSources:    []string{"Application Log", "Logon Session", "User Account"},
		DetectionNotes: "Monitor for a single password tried against many accounts. Watch for distributed authentication failures across user accounts.",
		Mitigations:    []string{"Account Lockout Policies", "Multi-factor Authentication", "Password Policies"},
		Platforms:      []string{"Windows", "Linux", "macOS", "Azure AD"},
	},
	"T1558.003": {
		DataSources:    []string{"Active Directory", "Network Traffic"},
		DetectionNotes: "Monitor for TGS requests for service accounts with weak encryption (RC4). Watch for Kerberos Event ID 4769 anomalies.",
		Mitigations:    []string{"Active Directory Configuration", "Encrypt Sensitive Information", "Password Policies"},
		Platforms:      []string{"Windows"},
	},

	// Discovery
	"T1018": {
		DataSources:    []string{"Command", "Network Traffic", "Process Creation"},
		DetectionNotes: "Monitor for net view, nltest, and ping sweep commands. Watch for ARP scan and DNS enumeration activity.",
		Mitigations:    []string{"Network Segmentation", "Operating System Configuration"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1082": {
		DataSources:    []string{"Command", "OS API Execution", "Process Creation"},
		DetectionNotes: "Monitor for systeminfo, uname, and similar system enumeration commands in rapid succession.",
		Mitigations:    []string{},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1083": {
		DataSources:    []string{"Command", "Process Creation"},
		DetectionNotes: "Monitor for dir, find, ls, and tree commands with recursive flags targeting sensitive directories.",
		Mitigations:    []string{},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},

	// Lateral Movement
	"T1021.001": {
		DataSources:    []string{"Logon Session", "Network Traffic", "Process Creation"},
		DetectionNotes: "Monitor for RDP connections from unusual sources. Watch for mstsc.exe execution and Event ID 4624 Type 10 logons.",
		Mitigations:    []string{"Audit", "Disable or Remove Feature or Program", "Multi-factor Authentication", "Network Segmentation", "Privileged Account Management", "User Account Management"},
		Platforms:      []string{"Windows"},
	},
	"T1021.002": {
		DataSources:    []string{"Command", "Logon Session", "Network Traffic"},
		DetectionNotes: "Monitor for SMB connections to admin shares (C$, ADMIN$). Watch for Event ID 5140/5145 for share access.",
		Mitigations:    []string{"Privileged Account Management", "Password Policies"},
		Platforms:      []string{"Windows"},
	},
	"T1550.002": {
		DataSources:    []string{"Active Directory", "Logon Session", "User Account"},
		DetectionNotes: "Monitor for NTLM authentication from unusual hosts. Watch for pass-the-hash indicators in Event ID 4624 (logon type 9).",
		Mitigations:    []string{"Privileged Account Management", "Update Software", "User Account Management"},
		Platforms:      []string{"Windows"},
	},
	"T1570": {
		DataSources:    []string{"Command", "File Creation", "Network Traffic", "Process Creation"},
		DetectionNotes: "Monitor for file transfers between internal hosts. Watch for use of SMB, WinRM, and PsExec for file staging.",
		Mitigations:    []string{"Network Intrusion Prevention", "Network Segmentation"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},

	// Collection
	"T1005": {
		DataSources:    []string{"Command", "File Access", "Process Creation"},
		DetectionNotes: "Monitor for bulk file reads from sensitive directories. Watch for data staging activity prior to exfiltration.",
		Mitigations:    []string{"Data Loss Prevention"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1560.001": {
		DataSources:    []string{"Command", "File Creation", "Process Creation"},
		DetectionNotes: "Monitor for 7z.exe, rar.exe, zip, and tar invocations targeting collected data directories.",
		Mitigations:    []string{"Audit"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},

	// Command and Control
	"T1071.001": {
		DataSources:    []string{"Network Traffic"},
		DetectionNotes: "Monitor for unusual HTTP/HTTPS traffic patterns: beaconing intervals, large POST bodies, uncommon User-Agent strings.",
		Mitigations:    []string{"Network Intrusion Prevention"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1105": {
		DataSources:    []string{"File Creation", "Network Traffic"},
		DetectionNotes: "Monitor for certutil, bitsadmin, curl, wget downloading executables. Watch for new files created after network activity.",
		Mitigations:    []string{"Network Intrusion Prevention"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1573": {
		DataSources:    []string{"Network Traffic"},
		DetectionNotes: "Monitor for encrypted traffic to unusual destinations. Inspect TLS certificate anomalies and JA3/JA3S fingerprints.",
		Mitigations:    []string{"Network Intrusion Prevention", "SSL/TLS Inspection"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1219": {
		DataSources:    []string{"Network Traffic", "Process Creation"},
		DetectionNotes: "Monitor for known remote access tool processes (TeamViewer, AnyDesk, ScreenConnect). Watch for outbound connections to tool vendor infrastructure.",
		Mitigations:    []string{"Execution Prevention", "Network Segmentation", "Filter Network Traffic"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},

	// Exfiltration
	"T1041": {
		DataSources:    []string{"Command", "File Access", "Network Traffic"},
		DetectionNotes: "Monitor for large outbound data transfers over the C2 channel. Watch for unusual data volume in beaconing sessions.",
		Mitigations:    []string{"Data Loss Prevention", "Network Intrusion Prevention"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1567.002": {
		DataSources:    []string{"Command", "File Access", "Network Traffic"},
		DetectionNotes: "Monitor for uploads to cloud storage services (S3, Azure Blob, GCS, Dropbox). Watch for rclone and cloud CLI tools.",
		Mitigations:    []string{"Data Loss Prevention", "Restrict Web-Based Content"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1048": {
		DataSources:    []string{"Command", "File Access", "Network Traffic"},
		DetectionNotes: "Monitor for data transfers over non-standard protocols (DNS, ICMP). Watch for large DNS TXT queries or unusual ICMP payload sizes.",
		Mitigations:    []string{"Data Loss Prevention", "Filter Network Traffic", "Network Segmentation"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},

	// Impact
	"T1486": {
		DataSources:    []string{"Command", "File Creation", "File Modification", "Process Creation"},
		DetectionNotes: "Monitor for mass file encryption operations. Watch for known ransomware file extensions and ransom notes.",
		Mitigations:    []string{"Behavior Prevention on Endpoint", "Data Backup"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1489": {
		DataSources:    []string{"Command", "Process Creation", "Service"},
		DetectionNotes: "Monitor for net stop, sc stop, and Stop-Service targeting critical services. Watch for rapid sequential service stops.",
		Mitigations:    []string{"Network Segmentation", "Restrict File and Directory Permissions", "Restrict Registry Permissions", "User Account Management"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1490": {
		DataSources:    []string{"Command", "Process Creation", "Service", "Windows Registry"},
		DetectionNotes: "Monitor for vssadmin delete shadows, wbadmin delete catalog, and bcdedit /set recoveryenabled no commands.",
		Mitigations:    []string{"Data Backup", "Operating System Configuration"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
	"T1485": {
		DataSources:    []string{"Command", "File Deletion", "Process Creation"},
		DetectionNotes: "Monitor for mass file deletion or overwrite operations. Watch for use of wipe utilities and bulk rm/del commands.",
		Mitigations:    []string{"Data Backup"},
		Platforms:      []string{"Windows", "Linux", "macOS"},
	},
}

// tacticSeverity maps tactic short names to a default severity level.
var tacticSeverity = map[string]string{
	"reconnaissance":       "low",
	"resource-development": "low",
	"initial-access":       "high",
	"execution":            "high",
	"persistence":          "medium",
	"privilege-escalation": "high",
	"defense-evasion":      "medium",
	"credential-access":    "high",
	"discovery":            "low",
	"lateral-movement":     "high",
	"collection":           "medium",
	"command-and-control":  "medium",
	"exfiltration":         "high",
	"impact":               "critical",
}

// EnrichStage enriches a single stage with ATT&CK metadata.
// Returns nil if the stage has no technique ID.
func EnrichStage(s Stage) *EnrichmentData {
	if s.Technique == "" {
		return nil
	}

	// Check the detailed enrichment map first.
	if data, ok := techniqueEnrichment[s.Technique]; ok {
		return buildEnrichment(s, &data)
	}

	// Fall back to MITRE registry lookup for name and tactic.
	return buildFallbackEnrichment(s)
}

// buildEnrichment creates a complete EnrichmentData from the map entry,
// filling in the technique name and tactic from the MITRE registry.
func buildEnrichment(s Stage, data *EnrichmentData) *EnrichmentData {
	result := &EnrichmentData{
		DataSources:    copyStrings(data.DataSources),
		DetectionNotes: data.DetectionNotes,
		Mitigations:    copyStrings(data.Mitigations),
		Platforms:      copyStrings(data.Platforms),
	}

	// Resolve name from MITRE registry.
	result.TechniqueName = mitre.ResolveName(s.Technique)
	if result.TechniqueName == "" {
		result.TechniqueName = s.Technique
	}

	// Resolve tactic: prefer the stage's own tactic, then MITRE lookup.
	result.Tactic = enrichResolveTactic(s)

	// Infer severity from tactic.
	result.Severity = inferSeverity(result.Tactic)

	return result
}

// buildFallbackEnrichment creates enrichment for techniques not in the map.
func buildFallbackEnrichment(s Stage) *EnrichmentData {
	result := &EnrichmentData{}

	result.TechniqueName = mitre.ResolveName(s.Technique)
	if result.TechniqueName == "" {
		result.TechniqueName = s.Technique
	}

	result.Tactic = enrichResolveTactic(s)
	result.Severity = inferSeverity(result.Tactic)

	// Attempt to inherit parent technique enrichment for sub-techniques.
	if parent := parentTechnique(s.Technique); parent != "" {
		if data, ok := techniqueEnrichment[parent]; ok {
			result.DataSources = copyStrings(data.DataSources)
			result.DetectionNotes = data.DetectionNotes
			result.Mitigations = copyStrings(data.Mitigations)
			result.Platforms = copyStrings(data.Platforms)
			return result
		}
	}

	return result
}

// EnrichCampaign enriches all stages in a campaign.
func EnrichCampaign(c *Campaign) *EnrichResult {
	if c == nil {
		return &EnrichResult{}
	}

	result := &EnrichResult{
		CampaignName: c.Meta.Name,
		TotalStages:  len(c.Stages),
		Stages:       make([]EnrichedStage, len(c.Stages)),
	}

	for i, stage := range c.Stages {
		enrichment := EnrichStage(stage)
		result.Stages[i] = EnrichedStage{
			Stage:      stage,
			Enrichment: enrichment,
		}
		if enrichment != nil {
			result.EnrichedCount++
		} else {
			result.SkippedCount++
		}
	}

	return result
}

// EnrichDir enriches all campaigns in a directory.
// It walks subdirectories looking for campaign.yaml files (same convention as LoadDir).
func EnrichDir(dir string) ([]*EnrichResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %q: %w", dir, err)
	}

	var results []*EnrichResult
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cpath := filepath.Join(dir, e.Name(), "campaign.yaml")
		if _, err := os.Stat(cpath); err != nil {
			continue
		}
		c, err := Load(cpath)
		if err != nil {
			continue
		}
		results = append(results, EnrichCampaign(c))
	}
	return results, nil
}

// FormatEnrichment formats enrichment results as a readable report.
func FormatEnrichment(results []*EnrichResult) string {
	if len(results) == 0 {
		return "No enrichment results.\n"
	}

	var b strings.Builder

	written := false
	for _, r := range results {
		if r == nil {
			continue
		}
		if written {
			b.WriteByte('\n')
		}
		written = true
		b.WriteString(fmt.Sprintf("Campaign: %s\n", r.CampaignName))
		b.WriteString(fmt.Sprintf("Stages: %d total, %d enriched, %d skipped\n",
			r.TotalStages, r.EnrichedCount, r.SkippedCount))
		b.WriteString(strings.Repeat("─", 60))
		b.WriteByte('\n')

		for _, es := range r.Stages {
			b.WriteString(fmt.Sprintf("\n  Stage: %s\n", es.Stage.ID))
			if es.Enrichment == nil {
				b.WriteString("    (no technique ID — skipped)\n")
				continue
			}
			e := es.Enrichment
			b.WriteString(fmt.Sprintf("    Technique:  %s (%s)\n", es.Stage.Technique, e.TechniqueName))
			b.WriteString(fmt.Sprintf("    Tactic:     %s\n", e.Tactic))
			b.WriteString(fmt.Sprintf("    Severity:   %s\n", e.Severity))
			if len(e.DataSources) > 0 {
				b.WriteString(fmt.Sprintf("    Data Sources: %s\n", strings.Join(e.DataSources, ", ")))
			}
			if e.DetectionNotes != "" {
				b.WriteString(fmt.Sprintf("    Detection:  %s\n", e.DetectionNotes))
			}
			if len(e.Mitigations) > 0 {
				b.WriteString(fmt.Sprintf("    Mitigations: %s\n", strings.Join(e.Mitigations, ", ")))
			}
			if len(e.Platforms) > 0 {
				b.WriteString(fmt.Sprintf("    Platforms:  %s\n", strings.Join(e.Platforms, ", ")))
			}
		}
	}
	if !written {
		return "No enrichment results.\n"
	}
	return b.String()
}

// enrichResolveTactic returns the tactic name for a stage, preferring the stage's
// own tactic field, then falling back to the MITRE registry.
func enrichResolveTactic(s Stage) string {
	if s.Tactic != "" {
		return s.Tactic
	}
	t := mitre.LookupTechnique(s.Technique)
	if t != nil {
		return t.Tactic
	}
	return ""
}

// inferSeverity returns a severity level based on the tactic.
func inferSeverity(tactic string) string {
	if sev, ok := tacticSeverity[tactic]; ok {
		return sev
	}
	return "medium"
}

// parentTechnique returns the parent technique ID for a sub-technique,
// or "" if the ID is not a sub-technique.
func parentTechnique(id string) string {
	if idx := strings.LastIndex(id, "."); idx > 0 {
		return id[:idx]
	}
	return ""
}

// copyStrings returns a shallow copy of a string slice.
func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}
