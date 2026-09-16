// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package sigma

import "sort"

// TechniqueDetection provides realistic Sigma selection criteria for a specific
// ATT&CK technique. Fields are nil when a technique doesn't produce that
// telemetry category. When multiple detection facets apply (e.g. process
// creation AND command line), they are combined as a logical AND in the
// generated Sigma selection.
type TechniqueDetection struct {
	ProcessCreation   *ProcessDetection
	NetworkConnection *NetworkDetection
	FileEvent         *FileDetection
	RegistryEvent     *RegistryDetection
	CommandLine       *CommandLineDetection
}

// ProcessDetection holds process-creation selection criteria.
type ProcessDetection struct {
	Image       []string // executable path patterns (|endswith or |contains)
	ParentImage []string // parent process patterns
	CommandLine []string // command-line argument patterns
	User        []string // user context patterns
}

// NetworkDetection holds network-connection selection criteria.
type NetworkDetection struct {
	DestinationPort []int
	Protocol        []string
	Initiated       string // "true" or "false"
}

// FileDetection holds file-event selection criteria.
type FileDetection struct {
	TargetFilename []string
	EventType      []string // create, modify, delete
}

// RegistryDetection holds registry-event selection criteria.
type RegistryDetection struct {
	TargetObject []string
	Details      []string
	EventType    string
}

// CommandLineDetection holds command-line matching criteria.
type CommandLineDetection struct {
	Contains   []string
	StartsWith []string
	EndsWith   []string
}

// techniqueDetections maps ATT&CK technique IDs to realistic Sigma detection
// signatures. These are derived from public Sigma rule repositories and
// real-world detection engineering practice.
var techniqueDetections = map[string]*TechniqueDetection{

	// ── Initial Access ──────────────────────────────────────────────────

	"T1566.001": { // Spearphishing Attachment
		ProcessCreation: &ProcessDetection{
			ParentImage: []string{
				`\outlook.exe`,
				`\thunderbird.exe`,
				`\winword.exe`,
				`\excel.exe`,
				`\powerpnt.exe`,
			},
			Image: []string{
				`\cmd.exe`,
				`\powershell.exe`,
				`\wscript.exe`,
				`\cscript.exe`,
				`\mshta.exe`,
			},
		},
		FileEvent: &FileDetection{
			TargetFilename: []string{
				`\AppData\Local\Temp\`,
				`.hta`,
				`.vbs`,
				`.js`,
				`.wsf`,
			},
			EventType: []string{"create"},
		},
	},

	"T1566.002": { // Spearphishing Link
		ProcessCreation: &ProcessDetection{
			ParentImage: []string{
				`\chrome.exe`,
				`\firefox.exe`,
				`\msedge.exe`,
				`\iexplore.exe`,
			},
			Image: []string{
				`\cmd.exe`,
				`\powershell.exe`,
				`\mshta.exe`,
			},
		},
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{80, 443, 8080},
			Initiated:       "true",
		},
	},

	"T1566.003": { // Spearphishing via Service
		ProcessCreation: &ProcessDetection{
			ParentImage: []string{
				`\slack.exe`,
				`\teams.exe`,
				`\discord.exe`,
				`\telegram.exe`,
			},
			Image: []string{
				`\cmd.exe`,
				`\powershell.exe`,
				`\wscript.exe`,
			},
		},
	},

	"T1190": { // Exploit Public-Facing Application
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{80, 443, 8443, 8080},
			Initiated:       "false",
		},
		ProcessCreation: &ProcessDetection{
			ParentImage: []string{
				`\w3wp.exe`,
				`\httpd.exe`,
				`\nginx.exe`,
				`\tomcat`,
				`\java.exe`,
			},
			Image: []string{
				`\cmd.exe`,
				`\powershell.exe`,
				`\whoami.exe`,
				`\net.exe`,
			},
		},
	},

	"T1195.002": { // Supply Chain Compromise: Compromise Software Supply Chain
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\pip.exe`,
				`\pip3.exe`,
				`\npm.exe`,
				`\node.exe`,
			},
			CommandLine: []string{
				"install",
				"--pre",
			},
		},
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{443, 8080},
			Initiated:       "true",
		},
	},

	// ── Execution ───────────────────────────────────────────────────────

	"T1059.001": { // PowerShell
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\powershell.exe`,
				`\pwsh.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"-EncodedCommand",
				"-ExecutionPolicy Bypass",
				"IEX",
				"Invoke-Expression",
				"DownloadString",
				"-nop",
				"-w hidden",
				"[System.Convert]::FromBase64String",
			},
		},
	},

	"T1059.003": { // Windows Command Shell
		ProcessCreation: &ProcessDetection{
			Image: []string{`\cmd.exe`},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"/c ",
				"/k ",
				"certutil",
				"bitsadmin",
				"wmic",
				"whoami",
			},
		},
	},

	"T1059.004": { // Unix Shell
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`/bin/bash`,
				`/bin/sh`,
				`/bin/zsh`,
				`/bin/dash`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"-c ",
				"curl ",
				"wget ",
				"/dev/tcp/",
				"base64 -d",
				"| bash",
				"| sh",
			},
		},
	},

	"T1059.005": { // Visual Basic
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\wscript.exe`,
				`\cscript.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				".vbs",
				".vbe",
				"//E:VBScript",
				"CreateObject",
			},
		},
	},

	"T1059.006": { // Python
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\python.exe`,
				`\python3.exe`,
				`/usr/bin/python`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"-c ",
				"import os",
				"import subprocess",
				"import socket",
				"exec(",
				"eval(",
			},
		},
	},

	"T1059.007": { // JavaScript
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\node.exe`,
				`\wscript.exe`,
				`\cscript.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				".js",
				"//E:JScript",
				"-e ",
				"child_process",
				"require(",
			},
		},
	},

	"T1047": { // WMI
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\wmic.exe`,
				`\wmiprvse.exe`,
			},
			ParentImage: []string{
				`\wmiprvse.exe`,
				`\svchost.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"process call create",
				"wmic",
				"/node:",
				"Win32_Process",
			},
		},
	},

	// ── Persistence ─────────────────────────────────────────────────────

	"T1053.005": { // Scheduled Task
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\schtasks.exe`,
				`\at.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"/create",
				"/sc ",
				"/tn ",
				"/tr ",
				"Register-ScheduledTask",
			},
		},
	},

	"T1543.003": { // Windows Service
		ProcessCreation: &ProcessDetection{
			Image: []string{`\sc.exe`},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"create",
				"binpath=",
				"start= auto",
				"New-Service",
			},
		},
		RegistryEvent: &RegistryDetection{
			TargetObject: []string{
				`\SYSTEM\CurrentControlSet\Services\`,
			},
			EventType: "SetValue",
		},
	},

	"T1547.001": { // Registry Run Keys / Startup Folder
		RegistryEvent: &RegistryDetection{
			TargetObject: []string{
				`\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
				`\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
				`\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
			},
			EventType: "SetValue",
		},
		FileEvent: &FileDetection{
			TargetFilename: []string{
				`\Start Menu\Programs\Startup\`,
				`\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`,
			},
			EventType: []string{"create"},
		},
	},

	"T1098": { // Account Manipulation
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\net.exe`,
				`\net1.exe`,
				`\dsmod.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"group /add",
				"localgroup",
				"administrators",
				"Set-ADUser",
				"Add-ADGroupMember",
			},
		},
	},

	"T1098.001": { // Additional Cloud Credentials
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\az.cmd`,
				`\gcloud.cmd`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"iam service-account",
				"ad sp create-rbac",
				"role assignment create",
				"create-for-rbac",
			},
		},
	},

	"T1136.001": { // Create Account: Local Account
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\net.exe`,
				`\net1.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"user /add",
				"New-LocalUser",
				"useradd",
				"adduser",
			},
		},
	},

	// ── Privilege Escalation ────────────────────────────────────────────

	"T1134": { // Access Token Manipulation
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\whoami.exe`,
				`\RunAs.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"runas",
				"ImpersonateLoggedOnUser",
				"DuplicateToken",
				"AdjustTokenPrivileges",
				"SeDebugPrivilege",
			},
		},
	},

	"T1548.002": { // Bypass UAC
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\fodhelper.exe`,
				`\eventvwr.exe`,
				`\sdclt.exe`,
				`\computerdefaults.exe`,
			},
			ParentImage: []string{
				`\explorer.exe`,
			},
		},
		RegistryEvent: &RegistryDetection{
			TargetObject: []string{
				`\Software\Classes\ms-settings\Shell\Open\command`,
				`\Software\Classes\mscfile\Shell\Open\command`,
			},
			EventType: "SetValue",
		},
	},

	"T1078": { // Valid Accounts
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\runas.exe`,
				`\net.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"/user:",
				"runas /profile",
				"su -",
				"sudo ",
			},
		},
	},

	"T1078.004": { // Cloud Accounts
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"aws sts assume-role",
				"az login",
				"gcloud auth",
				"az account set",
			},
		},
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{443},
			Initiated:       "true",
		},
	},

	// ── Defense Evasion ─────────────────────────────────────────────────

	"T1036.005": { // Masquerading: Match Legitimate Name or Location
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\svchost.exe`,
				`\explorer.exe`,
				`\lsass.exe`,
				`\csrss.exe`,
			},
		},
	},

	"T1070.001": { // Indicator Removal: Clear Windows Event Logs
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\wevtutil.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"cl Security",
				"cl System",
				"cl Application",
				"Clear-EventLog",
				"wevtutil cl",
			},
		},
	},

	"T1070.004": { // File Deletion
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\cmd.exe`,
				`\powershell.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"del /f",
				"Remove-Item -Force",
				"rm -rf",
				"shred",
				"SDelete",
			},
		},
		FileEvent: &FileDetection{
			EventType: []string{"delete"},
		},
	},

	"T1112": { // Modify Registry
		RegistryEvent: &RegistryDetection{
			TargetObject: []string{
				`\SOFTWARE\Microsoft\Windows\CurrentVersion\`,
				`\SYSTEM\CurrentControlSet\`,
				`\SOFTWARE\Policies\`,
			},
			EventType: "SetValue",
		},
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\reg.exe`,
				`\regedit.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"reg add",
				"reg import",
				"Set-ItemProperty",
			},
		},
	},

	"T1027": { // Obfuscated Files or Information
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\certutil.exe`,
				`\powershell.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"-encode",
				"-decode",
				"FromBase64String",
				"ToBase64String",
				"[char]",
				"-replace",
				"-join",
			},
		},
	},

	"T1140": { // Deobfuscate/Decode Files or Information
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\certutil.exe`,
				`\powershell.exe`,
				`\cmd.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"certutil -decode",
				"certutil -urlcache",
				"FromBase64String",
				"base64 -d",
				"openssl enc -d",
			},
		},
	},

	"T1218.011": { // Signed Binary Proxy Execution: Rundll32
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\rundll32.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"javascript:",
				"vbscript:",
				"shell32.dll,ShellExec_RunDLL",
				"url.dll,OpenURL",
				"url.dll,FileProtocolHandler",
				"advpack.dll,LaunchINFSection",
			},
		},
	},

	"T1562.001": { // Impair Defenses: Disable or Modify Tools
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\powershell.exe`,
				`\cmd.exe`,
				`\sc.exe`,
				`\net.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"Set-MpPreference -DisableRealtimeMonitoring",
				"sc stop WinDefend",
				"sc delete WinDefend",
				"net stop",
				"Uninstall-WindowsFeature",
				"tamperprotection",
			},
		},
		RegistryEvent: &RegistryDetection{
			TargetObject: []string{
				`\SOFTWARE\Policies\Microsoft\Windows Defender\`,
				`\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\`,
			},
			EventType: "SetValue",
		},
	},

	"T1055": { // Process Injection
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\powershell.exe`,
				`\rundll32.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"VirtualAllocEx",
				"WriteProcessMemory",
				"CreateRemoteThread",
				"NtCreateThreadEx",
				"QueueUserAPC",
				"SetThreadContext",
			},
		},
	},

	// ── Credential Access ───────────────────────────────────────────────

	"T1003.001": { // LSASS Memory
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\procdump.exe`,
				`\mimikatz.exe`,
				`\rundll32.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"sekurlsa",
				"lsass",
				"procdump",
				"MiniDump",
				"comsvcs.dll",
			},
		},
	},

	"T1003.003": { // NTDS
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\ntdsutil.exe`,
				`\vssadmin.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"ntdsutil",
				"ifm",
				"create full",
				"vssadmin create shadow",
				"ntds.dit",
			},
		},
	},

	"T1110.003": { // Brute Force: Password Spraying
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{389, 636, 88, 445},
			Initiated:       "true",
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"spray",
				"Invoke-DomainPasswordSpray",
				"crackmapexec",
				"hydra",
				"kerbrute",
			},
		},
	},

	"T1558.003": { // Kerberoasting
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\powershell.exe`,
				`\rubeus.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"Invoke-Kerberoast",
				"kerberoast",
				"GetUserSPNs",
				"Request-SPNTicket",
				"asreproast",
			},
		},
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{88},
			Initiated:       "true",
		},
	},

	"T1528": { // Steal Application Access Token
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"access_token",
				"bearer",
				"oauth",
				"jwt",
				"refresh_token",
			},
		},
		FileEvent: &FileDetection{
			TargetFilename: []string{
				`token`,
				`.token`,
				`credentials`,
				`access_tokens.db`,
			},
			EventType: []string{"access"},
		},
	},

	"T1539": { // Steal Web Session Cookie
		FileEvent: &FileDetection{
			TargetFilename: []string{
				`\Google\Chrome\User Data\Default\Cookies`,
				`\Mozilla\Firefox\Profiles\`,
				`\Microsoft\Edge\User Data\Default\Cookies`,
				`cookies.sqlite`,
			},
			EventType: []string{"access"},
		},
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\powershell.exe`,
				`\python.exe`,
			},
		},
	},

	"T1550.002": { // Pass the Hash
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\mimikatz.exe`,
				`\sekurlsa.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"sekurlsa::pth",
				"pth-winexe",
				"/ntlm:",
				"Invoke-SMBExec",
				"Invoke-WMIExec",
			},
		},
	},

	"T1621": { // Multi-Factor Authentication Request Generation
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{443},
			Initiated:       "true",
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"mfa",
				"push",
				"otp",
				"totp",
			},
		},
	},

	// ── Discovery ───────────────────────────────────────────────────────

	"T1046": { // Network Service Scanning
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\nmap.exe`,
				`\masscan.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"nmap",
				"-sS",
				"-sV",
				"masscan",
				"Test-NetConnection",
				"portscan",
			},
		},
	},

	"T1082": { // System Information Discovery
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\systeminfo.exe`,
				`\hostname.exe`,
				`\whoami.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"systeminfo",
				"hostname",
				"Get-ComputerInfo",
				"uname -a",
				"cat /etc/os-release",
			},
		},
	},

	"T1016": { // System Network Configuration Discovery
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\ipconfig.exe`,
				`\netstat.exe`,
				`\route.exe`,
				`\arp.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"ipconfig /all",
				"ifconfig",
				"netstat -an",
				"route print",
				"arp -a",
				"Get-NetIPConfiguration",
			},
		},
	},

	"T1018": { // Remote System Discovery
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\net.exe`,
				`\dsquery.exe`,
				`\nltest.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"net view",
				"nltest /dclist",
				"dsquery computer",
				"Get-ADComputer",
				"ping -c",
				"nslookup",
			},
		},
	},

	"T1087.002": { // Domain Account
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\net.exe`,
				`\net1.exe`,
				`\dsquery.exe`,
				`\ldapsearch`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"net user /domain",
				"net group /domain",
				"Get-ADUser",
				"dsquery user",
				"ldapsearch",
			},
		},
	},

	"T1087.004": { // Cloud Account
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"aws iam list-users",
				"az ad user list",
				"gcloud iam service-accounts list",
				"Get-AzADUser",
				"aws iam get-account-authorization-details",
			},
		},
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{443},
			Initiated:       "true",
		},
	},

	"T1538": { // Cloud Service Dashboard
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"aws console",
				"az portal",
				"gcloud",
				"aws organizations describe-organization",
			},
		},
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{443},
			Initiated:       "true",
		},
	},

	"T1057": { // Process Discovery
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\tasklist.exe`,
				`\wmic.exe`,
				`\ps.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"tasklist",
				"Get-Process",
				"wmic process list",
				"ps aux",
				"ps -ef",
			},
		},
	},

	"T1049": { // System Network Connections Discovery
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\netstat.exe`,
				`\net.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"netstat -ano",
				"netstat -an",
				"Get-NetTCPConnection",
				"net session",
				"ss -tulnp",
			},
		},
	},

	// ── Lateral Movement ────────────────────────────────────────────────

	"T1021.001": { // Remote Desktop Protocol
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{3389},
			Initiated:       "true",
		},
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\mstsc.exe`,
				`\tscon.exe`,
			},
		},
	},

	"T1021.002": { // SMB/Windows Admin Shares
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{445, 139},
			Initiated:       "true",
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				`net use \\`,
				"IPC$",
				"ADMIN$",
				"C$",
			},
		},
	},

	// ── Collection ──────────────────────────────────────────────────────

	"T1005": { // Data from Local System
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\cmd.exe`,
				`\powershell.exe`,
				`\findstr.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"findstr /si password",
				"dir /s",
				"Get-ChildItem -Recurse",
				"find / -name",
				"grep -r",
			},
		},
		FileEvent: &FileDetection{
			TargetFilename: []string{
				`.docx`,
				`.xlsx`,
				`.pdf`,
				`.pst`,
				`.kdbx`,
				`password`,
			},
			EventType: []string{"access"},
		},
	},

	"T1074.001": { // Data Staged: Local Data Staging
		FileEvent: &FileDetection{
			TargetFilename: []string{
				`\Temp\staging\`,
				`\AppData\Local\Temp\`,
				`\ProgramData\`,
				`.dmp`,
				`.zip`,
				`.rar`,
			},
			EventType: []string{"create"},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"copy ",
				"xcopy",
				"robocopy",
				"Move-Item",
				"cp ",
			},
		},
	},

	"T1560.001": { // Archive Collected Data: Archive via Utility
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\7z.exe`,
				`\7za.exe`,
				`\winrar.exe`,
				`\rar.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"a -p",
				"-password",
				"Compress-Archive",
				"tar czf",
				"zip -r",
			},
		},
	},

	// ── Command and Control ─────────────────────────────────────────────

	"T1071.001": { // Application Layer Protocol: Web Protocols
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{80, 443, 8080, 8443},
			Protocol:        []string{"tcp"},
			Initiated:       "true",
		},
	},

	"T1071.004": { // DNS
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{53, 5353},
			Protocol:        []string{"udp", "tcp"},
			Initiated:       "true",
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"nslookup",
				"Resolve-DnsName",
				"dig ",
			},
		},
	},

	"T1572": { // Protocol Tunneling
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{22, 443, 53},
			Initiated:       "true",
		},
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\plink.exe`,
				`\ssh.exe`,
				`\chisel.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"ssh -D",
				"ssh -L",
				"ssh -R",
				"-tunnel",
				"ngrok",
				"chisel",
			},
		},
	},

	"T1573": { // Encrypted Channel
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{443, 8443, 4443},
			Protocol:        []string{"tcp"},
			Initiated:       "true",
		},
	},

	// ── Exfiltration ────────────────────────────────────────────────────

	"T1041": { // Exfiltration Over C2 Channel
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{443, 80, 8080},
			Initiated:       "true",
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"Invoke-WebRequest",
				"curl",
				"wget",
				"Invoke-RestMethod",
			},
		},
	},

	"T1048": { // Exfiltration Over Alternative Protocol
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{53, 25, 587, 993, 21},
			Initiated:       "true",
		},
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\ftp.exe`,
				`\nslookup.exe`,
			},
		},
	},

	"T1567.002": { // Exfiltration to Cloud Storage
		NetworkConnection: &NetworkDetection{
			DestinationPort: []int{443},
			Initiated:       "true",
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"aws s3 cp",
				"azcopy",
				"gsutil cp",
				"rclone",
				"mega-put",
			},
		},
	},

	// ── Impact ──────────────────────────────────────────────────────────

	"T1490": { // Inhibit System Recovery
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\vssadmin.exe`,
				`\wmic.exe`,
				`\bcdedit.exe`,
				`\wbadmin.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"delete shadows",
				"resize shadowstorage",
				"bcdedit /set",
				"recoveryenabled no",
				"wbadmin delete catalog",
			},
		},
	},

	"T1485": { // Data Destruction
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\cipher.exe`,
				`\sdelete.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"cipher /w:",
				"format",
				"dd if=/dev/zero",
				"shred",
				"rm -rf /",
			},
		},
		FileEvent: &FileDetection{
			EventType: []string{"delete"},
		},
	},

	"T1486": { // Data Encrypted for Impact
		FileEvent: &FileDetection{
			TargetFilename: []string{
				`.encrypted`,
				`.locked`,
				`.crypt`,
				`.ransom`,
				`DECRYPT_INSTRUCTIONS`,
				`README_RECOVERY`,
			},
			EventType: []string{"create", "modify"},
		},
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\powershell.exe`,
				`\cmd.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"AES",
				"Encrypt",
				"cipher",
				"-encryptall",
			},
		},
	},

	"T1489": { // Service Stop
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\net.exe`,
				`\sc.exe`,
				`\taskkill.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"net stop",
				"sc stop",
				"taskkill /f",
				"Stop-Service",
				"systemctl stop",
			},
		},
	},

	// ── Execution (additional) ──────────────────────────────────────────

	"T1569.002": { // System Services: Service Execution
		ProcessCreation: &ProcessDetection{
			Image: []string{
				`\psexec.exe`,
				`\PsExec64.exe`,
				`\sc.exe`,
			},
		},
		CommandLine: &CommandLineDetection{
			Contains: []string{
				"psexec",
				"sc start",
				"-s cmd",
				"\\\\",
			},
		},
	},
}

// LookupTechniqueDetection returns the detection signature for a technique ID,
// or nil if no specific detection is registered.
func LookupTechniqueDetection(techniqueID string) *TechniqueDetection {
	return techniqueDetections[techniqueID]
}

// TechniqueDetectionIDs returns a sorted list of all technique IDs that have
// detection signatures.
func TechniqueDetectionIDs() []string {
	ids := make([]string, 0, len(techniqueDetections))
	for id := range techniqueDetections {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// buildTechniqueSelection produces a Sigma selection map from a technique
// detection and the stage's telemetry types. It picks the most relevant
// detection facets based on what telemetry the stage expects.
func buildTechniqueSelection(td *TechniqueDetection, telemetry []string) map[string]interface{} {
	sel := make(map[string]interface{})

	// Determine which telemetry categories are relevant.
	wantProcess := false
	wantNetwork := false
	wantFile := false
	wantRegistry := false

	for _, t := range telemetry {
		ls := ResolveLogSource(t)
		switch ls.Category {
		case "process_creation", "process_access", "create_remote_thread", "process_termination":
			wantProcess = true
		case "network_connection", "dns_query":
			wantNetwork = true
		case "file_event", "file_change", "file_delete", "file_access", "file_rename":
			wantFile = true
		case "registry_set", "registry_add", "registry_delete", "registry_event":
			wantRegistry = true
		}
	}

	// If no specific telemetry is specified, include everything available.
	if len(telemetry) == 0 {
		wantProcess = true
		wantNetwork = true
		wantFile = true
		wantRegistry = true
	}

	// Build selection from matching detection facets.
	if wantProcess && td.ProcessCreation != nil {
		if len(td.ProcessCreation.Image) > 0 {
			sel["Image|endswith"] = td.ProcessCreation.Image
		}
		if len(td.ProcessCreation.ParentImage) > 0 {
			sel["ParentImage|endswith"] = td.ProcessCreation.ParentImage
		}
		if len(td.ProcessCreation.CommandLine) > 0 {
			sel["CommandLine|contains"] = td.ProcessCreation.CommandLine
		}
		if len(td.ProcessCreation.User) > 0 {
			sel["User|contains"] = td.ProcessCreation.User
		}
	}

	// CommandLine detection is also process-relevant.
	if wantProcess && td.CommandLine != nil {
		if len(td.CommandLine.Contains) > 0 {
			// Merge with existing CommandLine|contains if present.
			if existing, ok := sel["CommandLine|contains"]; ok {
				if existingSlice, ok := existing.([]string); ok {
					sel["CommandLine|contains"] = append(existingSlice, td.CommandLine.Contains...)
				}
			} else {
				sel["CommandLine|contains"] = td.CommandLine.Contains
			}
		}
		if len(td.CommandLine.StartsWith) > 0 {
			sel["CommandLine|startswith"] = td.CommandLine.StartsWith
		}
		if len(td.CommandLine.EndsWith) > 0 {
			sel["CommandLine|endswith"] = td.CommandLine.EndsWith
		}
	}

	if wantNetwork && td.NetworkConnection != nil {
		if len(td.NetworkConnection.DestinationPort) > 0 {
			if len(td.NetworkConnection.DestinationPort) == 1 {
				sel["DestinationPort"] = td.NetworkConnection.DestinationPort[0]
			} else {
				sel["DestinationPort"] = td.NetworkConnection.DestinationPort
			}
		}
		if len(td.NetworkConnection.Protocol) > 0 {
			sel["Protocol"] = td.NetworkConnection.Protocol
		}
		if td.NetworkConnection.Initiated != "" {
			sel["Initiated"] = td.NetworkConnection.Initiated
		}
	}

	if wantFile && td.FileEvent != nil {
		if len(td.FileEvent.TargetFilename) > 0 {
			sel["TargetFilename|contains"] = td.FileEvent.TargetFilename
		}
		if len(td.FileEvent.EventType) > 0 {
			sel["EventType"] = td.FileEvent.EventType
		}
	}

	if wantRegistry && td.RegistryEvent != nil {
		if len(td.RegistryEvent.TargetObject) > 0 {
			sel["TargetObject|contains"] = td.RegistryEvent.TargetObject
		}
		if len(td.RegistryEvent.Details) > 0 {
			sel["Details|contains"] = td.RegistryEvent.Details
		}
		if td.RegistryEvent.EventType != "" {
			sel["EventType"] = td.RegistryEvent.EventType
		}
	}

	return sel
}
