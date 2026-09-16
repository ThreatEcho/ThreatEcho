// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package mitre

// Tactic represents a MITRE ATT&CK tactic.
type Tactic struct {
	ID    string
	Name  string
	Short string // kebab-case identifier used in campaign YAML
}

// Technique represents a MITRE ATT&CK technique or sub-technique.
type Technique struct {
	ID     string
	Name   string
	Tactic string // tactic short name
}

// Tactics lists all ATT&CK tactics in kill-chain order.
var Tactics = []Tactic{
	{ID: "TA0043", Name: "Reconnaissance", Short: "reconnaissance"},
	{ID: "TA0042", Name: "Resource Development", Short: "resource-development"},
	{ID: "TA0001", Name: "Initial Access", Short: "initial-access"},
	{ID: "TA0002", Name: "Execution", Short: "execution"},
	{ID: "TA0003", Name: "Persistence", Short: "persistence"},
	{ID: "TA0004", Name: "Privilege Escalation", Short: "privilege-escalation"},
	{ID: "TA0005", Name: "Defense Evasion", Short: "defense-evasion"},
	{ID: "TA0006", Name: "Credential Access", Short: "credential-access"},
	{ID: "TA0007", Name: "Discovery", Short: "discovery"},
	{ID: "TA0008", Name: "Lateral Movement", Short: "lateral-movement"},
	{ID: "TA0009", Name: "Collection", Short: "collection"},
	{ID: "TA0011", Name: "Command and Control", Short: "command-and-control"},
	{ID: "TA0010", Name: "Exfiltration", Short: "exfiltration"},
	{ID: "TA0040", Name: "Impact", Short: "impact"},
}

// TacticByShort returns the tactic for a short name, or nil if not found.
func TacticByShort(short string) *Tactic {
	for i := range Tactics {
		if Tactics[i].Short == short {
			return &Tactics[i]
		}
	}
	return nil
}

// ValidTactic reports whether short is a known tactic identifier.
func ValidTactic(short string) bool {
	return TacticByShort(short) != nil
}

// TacticShorts returns all valid tactic short names.
func TacticShorts() []string {
	out := make([]string, len(Tactics))
	for i, t := range Tactics {
		out[i] = t.Short
	}
	return out
}

// Techniques is a representative subset of ATT&CK techniques.
// Expanded as campaigns reference new techniques.
var Techniques = map[string]Technique{
	// Initial Access
	"T1566":     {ID: "T1566", Name: "Phishing", Tactic: "initial-access"},
	"T1566.001": {ID: "T1566.001", Name: "Spearphishing Attachment", Tactic: "initial-access"},
	"T1566.002": {ID: "T1566.002", Name: "Spearphishing Link", Tactic: "initial-access"},
	"T1566.003": {ID: "T1566.003", Name: "Spearphishing via Service", Tactic: "initial-access"},
	"T1190":     {ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "initial-access"},
	"T1078":     {ID: "T1078", Name: "Valid Accounts", Tactic: "initial-access"},
	"T1078.004": {ID: "T1078.004", Name: "Cloud Accounts", Tactic: "initial-access"},
	"T1189":     {ID: "T1189", Name: "Drive-by Compromise", Tactic: "initial-access"},
	"T1078.002": {ID: "T1078.002", Name: "Domain Accounts", Tactic: "initial-access"},
	"T1195":     {ID: "T1195", Name: "Supply Chain Compromise", Tactic: "initial-access"},
	"T1195.001": {ID: "T1195.001", Name: "Compromise Software Dependencies and Development Tools", Tactic: "initial-access"},
	"T1195.002": {ID: "T1195.002", Name: "Compromise Software Supply Chain", Tactic: "initial-access"},
	"T1199":     {ID: "T1199", Name: "Trusted Relationship", Tactic: "initial-access"},

	// Execution
	"T1059":     {ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "execution"},
	"T1059.001": {ID: "T1059.001", Name: "PowerShell", Tactic: "execution"},
	"T1059.003": {ID: "T1059.003", Name: "Windows Command Shell", Tactic: "execution"},
	"T1059.004": {ID: "T1059.004", Name: "Unix Shell", Tactic: "execution"},
	"T1059.005": {ID: "T1059.005", Name: "Visual Basic", Tactic: "execution"},
	"T1059.006": {ID: "T1059.006", Name: "Python", Tactic: "execution"},
	"T1204":     {ID: "T1204", Name: "User Execution", Tactic: "execution"},
	"T1204.002": {ID: "T1204.002", Name: "Malicious File", Tactic: "execution"},
	"T1047":     {ID: "T1047", Name: "Windows Management Instrumentation", Tactic: "execution"},
	"T1569":     {ID: "T1569", Name: "System Services", Tactic: "execution"},
	"T1569.002": {ID: "T1569.002", Name: "Service Execution", Tactic: "execution"},

	// Persistence
	"T1037.004": {ID: "T1037.004", Name: "RC Scripts", Tactic: "persistence"},
	"T1053":     {ID: "T1053", Name: "Scheduled Task/Job", Tactic: "persistence"},
	"T1053.002": {ID: "T1053.002", Name: "At", Tactic: "persistence"},
	"T1053.003": {ID: "T1053.003", Name: "Cron", Tactic: "persistence"},
	"T1053.005": {ID: "T1053.005", Name: "Scheduled Task", Tactic: "persistence"},
	"T1098":     {ID: "T1098", Name: "Account Manipulation", Tactic: "persistence"},
	"T1098.001": {ID: "T1098.001", Name: "Additional Cloud Credentials", Tactic: "persistence"},
	"T1098.004": {ID: "T1098.004", Name: "SSH Authorized Keys", Tactic: "persistence"},
	"T1136":     {ID: "T1136", Name: "Create Account", Tactic: "persistence"},
	"T1505.003": {ID: "T1505.003", Name: "Web Shell", Tactic: "persistence"},
	"T1543":     {ID: "T1543", Name: "Create or Modify System Process", Tactic: "persistence"},
	"T1543.002": {ID: "T1543.002", Name: "Systemd Service", Tactic: "persistence"},
	"T1543.003": {ID: "T1543.003", Name: "Windows Service", Tactic: "persistence"},
	"T1546.003": {ID: "T1546.003", Name: "Windows Management Instrumentation Event Subscription", Tactic: "persistence"},
	"T1546.004": {ID: "T1546.004", Name: "Unix Shell Configuration Modification", Tactic: "persistence"},
	"T1547":     {ID: "T1547", Name: "Boot or Logon Autostart Execution", Tactic: "persistence"},
	"T1547.001": {ID: "T1547.001", Name: "Registry Run Keys / Startup Folder", Tactic: "persistence"},

	// Privilege Escalation
	"T1055":     {ID: "T1055", Name: "Process Injection", Tactic: "privilege-escalation"},
	"T1068":     {ID: "T1068", Name: "Exploitation for Privilege Escalation", Tactic: "privilege-escalation"},
	"T1548":     {ID: "T1548", Name: "Abuse Elevation Control Mechanism", Tactic: "privilege-escalation"},
	"T1548.002": {ID: "T1548.002", Name: "Bypass User Account Control", Tactic: "privilege-escalation"},
	"T1134":     {ID: "T1134", Name: "Access Token Manipulation", Tactic: "privilege-escalation"},

	// Defense Evasion
	"T1027":     {ID: "T1027", Name: "Obfuscated Files or Information", Tactic: "defense-evasion"},
	"T1036":     {ID: "T1036", Name: "Masquerading", Tactic: "defense-evasion"},
	"T1036.004": {ID: "T1036.004", Name: "Masquerade Task or Service", Tactic: "defense-evasion"},
	"T1036.005": {ID: "T1036.005", Name: "Match Legitimate Name or Location", Tactic: "defense-evasion"},
	"T1070":     {ID: "T1070", Name: "Indicator Removal", Tactic: "defense-evasion"},
	"T1070.001": {ID: "T1070.001", Name: "Clear Windows Event Logs", Tactic: "defense-evasion"},
	"T1070.002": {ID: "T1070.002", Name: "Clear Linux or Mac System Logs", Tactic: "defense-evasion"},
	"T1070.003": {ID: "T1070.003", Name: "Clear Command History", Tactic: "defense-evasion"},
	"T1070.004": {ID: "T1070.004", Name: "File Deletion", Tactic: "defense-evasion"},
	"T1070.006": {ID: "T1070.006", Name: "Timestomp", Tactic: "defense-evasion"},
	"T1112":     {ID: "T1112", Name: "Modify Registry", Tactic: "defense-evasion"},
	"T1140":     {ID: "T1140", Name: "Deobfuscate/Decode Files or Information", Tactic: "defense-evasion"},
	"T1197":     {ID: "T1197", Name: "BITS Jobs", Tactic: "defense-evasion"},
	"T1218":     {ID: "T1218", Name: "System Binary Proxy Execution", Tactic: "defense-evasion"},
	"T1218.005": {ID: "T1218.005", Name: "Mshta", Tactic: "defense-evasion"},
	"T1218.010": {ID: "T1218.010", Name: "Regsvr32", Tactic: "defense-evasion"},
	"T1218.011": {ID: "T1218.011", Name: "Rundll32", Tactic: "defense-evasion"},
	"T1222.002": {ID: "T1222.002", Name: "Linux and Mac File and Directory Permissions Modification", Tactic: "defense-evasion"},
	"T1497":     {ID: "T1497", Name: "Virtualization/Sandbox Evasion", Tactic: "defense-evasion"},
	"T1562":     {ID: "T1562", Name: "Impair Defenses", Tactic: "defense-evasion"},
	"T1562.001": {ID: "T1562.001", Name: "Disable or Modify Tools", Tactic: "defense-evasion"},
	"T1562.004": {ID: "T1562.004", Name: "Disable or Modify System Firewall", Tactic: "defense-evasion"},
	"T1562.006": {ID: "T1562.006", Name: "Disable or Modify Cloud Logs", Tactic: "defense-evasion"},
	"T1564.001": {ID: "T1564.001", Name: "Hidden Files and Directories", Tactic: "defense-evasion"},

	// Credential Access
	"T1003":     {ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
	"T1003.001": {ID: "T1003.001", Name: "LSASS Memory", Tactic: "credential-access"},
	"T1003.002": {ID: "T1003.002", Name: "Security Account Manager", Tactic: "credential-access"},
	"T1003.003": {ID: "T1003.003", Name: "NTDS", Tactic: "credential-access"},
	"T1003.005": {ID: "T1003.005", Name: "Cached Domain Credentials", Tactic: "credential-access"},
	"T1003.006": {ID: "T1003.006", Name: "DCSync", Tactic: "credential-access"},
	"T1003.008": {ID: "T1003.008", Name: "/etc/passwd and /etc/shadow", Tactic: "credential-access"},
	"T1110":     {ID: "T1110", Name: "Brute Force", Tactic: "credential-access"},
	"T1110.003": {ID: "T1110.003", Name: "Password Spraying", Tactic: "credential-access"},
	"T1528":     {ID: "T1528", Name: "Steal Application Access Token", Tactic: "credential-access"},
	"T1539":     {ID: "T1539", Name: "Steal Web Session Cookie", Tactic: "credential-access"},
	"T1552":     {ID: "T1552", Name: "Unsecured Credentials", Tactic: "credential-access"},
	"T1552.001": {ID: "T1552.001", Name: "Credentials In Files", Tactic: "credential-access"},
	"T1552.003": {ID: "T1552.003", Name: "Bash History", Tactic: "credential-access"},
	"T1552.004": {ID: "T1552.004", Name: "Private Keys", Tactic: "credential-access"},
	"T1552.005": {ID: "T1552.005", Name: "Cloud Instance Metadata API", Tactic: "credential-access"},
	"T1555.003": {ID: "T1555.003", Name: "Credentials from Web Browsers", Tactic: "credential-access"},
	"T1555.004": {ID: "T1555.004", Name: "Windows Credential Manager", Tactic: "credential-access"},
	"T1556":     {ID: "T1556", Name: "Modify Authentication Process", Tactic: "credential-access"},
	"T1557":     {ID: "T1557", Name: "Adversary-in-the-Middle", Tactic: "credential-access"},
	"T1558":     {ID: "T1558", Name: "Steal or Forge Kerberos Tickets", Tactic: "credential-access"},
	"T1558.003": {ID: "T1558.003", Name: "Kerberoasting", Tactic: "credential-access"},
	"T1621":     {ID: "T1621", Name: "Multi-Factor Authentication Request Generation", Tactic: "credential-access"},

	// Discovery
	"T1016":     {ID: "T1016", Name: "System Network Configuration Discovery", Tactic: "discovery"},
	"T1018":     {ID: "T1018", Name: "Remote System Discovery", Tactic: "discovery"},
	"T1033":     {ID: "T1033", Name: "System Owner/User Discovery", Tactic: "discovery"},
	"T1046":     {ID: "T1046", Name: "Network Service Discovery", Tactic: "discovery"},
	"T1049":     {ID: "T1049", Name: "System Network Connections Discovery", Tactic: "discovery"},
	"T1057":     {ID: "T1057", Name: "Process Discovery", Tactic: "discovery"},
	"T1069":     {ID: "T1069", Name: "Permission Groups Discovery", Tactic: "discovery"},
	"T1082":     {ID: "T1082", Name: "System Information Discovery", Tactic: "discovery"},
	"T1083":     {ID: "T1083", Name: "File and Directory Discovery", Tactic: "discovery"},
	"T1087":     {ID: "T1087", Name: "Account Discovery", Tactic: "discovery"},
	"T1087.001": {ID: "T1087.001", Name: "Local Account", Tactic: "discovery"},
	"T1087.002": {ID: "T1087.002", Name: "Domain Account", Tactic: "discovery"},
	"T1087.004": {ID: "T1087.004", Name: "Cloud Account", Tactic: "discovery"},
	"T1135":     {ID: "T1135", Name: "Network Share Discovery", Tactic: "discovery"},
	"T1201":     {ID: "T1201", Name: "Password Policy Discovery", Tactic: "discovery"},
	"T1482":     {ID: "T1482", Name: "Domain Trust Discovery", Tactic: "discovery"},
	"T1518.001": {ID: "T1518.001", Name: "Security Software Discovery", Tactic: "discovery"},
	"T1538":     {ID: "T1538", Name: "Cloud Service Dashboard", Tactic: "discovery"},
	"T1580":     {ID: "T1580", Name: "Cloud Infrastructure Discovery", Tactic: "discovery"},

	// Lateral Movement
	"T1021":     {ID: "T1021", Name: "Remote Services", Tactic: "lateral-movement"},
	"T1021.001": {ID: "T1021.001", Name: "Remote Desktop Protocol", Tactic: "lateral-movement"},
	"T1021.002": {ID: "T1021.002", Name: "SMB/Windows Admin Shares", Tactic: "lateral-movement"},
	"T1021.004": {ID: "T1021.004", Name: "SSH", Tactic: "lateral-movement"},
	"T1021.006": {ID: "T1021.006", Name: "Windows Remote Management", Tactic: "lateral-movement"},
	"T1080":     {ID: "T1080", Name: "Taint Shared Content", Tactic: "lateral-movement"},
	"T1550":     {ID: "T1550", Name: "Use Alternate Authentication Material", Tactic: "lateral-movement"},
	"T1550.002": {ID: "T1550.002", Name: "Pass the Hash", Tactic: "lateral-movement"},
	"T1563.001": {ID: "T1563.001", Name: "SSH Hijacking", Tactic: "lateral-movement"},
	"T1563.002": {ID: "T1563.002", Name: "RDP Hijacking", Tactic: "lateral-movement"},
	"T1570":     {ID: "T1570", Name: "Lateral Tool Transfer", Tactic: "lateral-movement"},

	// Collection
	"T1005":     {ID: "T1005", Name: "Data from Local System", Tactic: "collection"},
	"T1039":     {ID: "T1039", Name: "Data from Network Shared Drive", Tactic: "collection"},
	"T1074":     {ID: "T1074", Name: "Data Staged", Tactic: "collection"},
	"T1074.001": {ID: "T1074.001", Name: "Local Data Staging", Tactic: "collection"},
	"T1115":     {ID: "T1115", Name: "Clipboard Data", Tactic: "collection"},
	"T1213.002": {ID: "T1213.002", Name: "Sharepoint", Tactic: "collection"},
	"T1530":     {ID: "T1530", Name: "Data from Cloud Storage", Tactic: "collection"},
	"T1560":     {ID: "T1560", Name: "Archive Collected Data", Tactic: "collection"},
	"T1560.001": {ID: "T1560.001", Name: "Archive via Utility", Tactic: "collection"},

	// Command and Control
	"T1071":     {ID: "T1071", Name: "Application Layer Protocol", Tactic: "command-and-control"},
	"T1071.001": {ID: "T1071.001", Name: "Web Protocols", Tactic: "command-and-control"},
	"T1071.004": {ID: "T1071.004", Name: "DNS", Tactic: "command-and-control"},
	"T1105":     {ID: "T1105", Name: "Ingress Tool Transfer", Tactic: "command-and-control"},
	"T1573":     {ID: "T1573", Name: "Encrypted Channel", Tactic: "command-and-control"},
	"T1572":     {ID: "T1572", Name: "Protocol Tunneling", Tactic: "command-and-control"},
	"T1090":     {ID: "T1090", Name: "Proxy", Tactic: "command-and-control"},
	"T1090.002": {ID: "T1090.002", Name: "External Proxy", Tactic: "command-and-control"},
	"T1219":     {ID: "T1219", Name: "Remote Access Software", Tactic: "command-and-control"},

	// Exfiltration
	"T1041":     {ID: "T1041", Name: "Exfiltration Over C2 Channel", Tactic: "exfiltration"},
	"T1048":     {ID: "T1048", Name: "Exfiltration Over Alternative Protocol", Tactic: "exfiltration"},
	"T1048.001": {ID: "T1048.001", Name: "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", Tactic: "exfiltration"},
	"T1048.002": {ID: "T1048.002", Name: "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", Tactic: "exfiltration"},
	"T1048.003": {ID: "T1048.003", Name: "Exfiltration Over Unencrypted Non-C2 Protocol", Tactic: "exfiltration"},
	"T1567":     {ID: "T1567", Name: "Exfiltration Over Web Service", Tactic: "exfiltration"},
	"T1567.002": {ID: "T1567.002", Name: "Exfiltration to Cloud Storage", Tactic: "exfiltration"},

	// Impact
	"T1485": {ID: "T1485", Name: "Data Destruction", Tactic: "impact"},
	"T1486": {ID: "T1486", Name: "Data Encrypted for Impact", Tactic: "impact"},
	"T1489": {ID: "T1489", Name: "Service Stop", Tactic: "impact"},
	"T1490": {ID: "T1490", Name: "Inhibit System Recovery", Tactic: "impact"},
	"T1491": {ID: "T1491", Name: "Defacement", Tactic: "impact"},
	"T1499": {ID: "T1499", Name: "Endpoint Denial of Service", Tactic: "impact"},
	"T1529": {ID: "T1529", Name: "System Shutdown/Reboot", Tactic: "impact"},
}

// LookupTechnique returns the technique for an ATT&CK ID, or nil if unknown.
func LookupTechnique(id string) *Technique {
	if t, ok := Techniques[id]; ok {
		return &t
	}
	return nil
}
