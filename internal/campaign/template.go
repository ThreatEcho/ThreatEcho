// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package campaign

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Template describes a built-in campaign scaffold.
type Template struct {
	Name        string   // e.g. "apt", "ransomware"
	Description string   // one-line description
	Framework   string   // "attack", "atlas", "mixed"
	Tags        []string // metadata tags
}

// builtinTemplates holds all template metadata keyed by name.
var builtinTemplates = map[string]Template{
	"agent-hijack": {
		Name:        "agent-hijack",
		Description: "AI agent attack: prompt injection to data exfiltration",
		Framework:   "mixed",
		Tags:        []string{"ai", "agent", "prompt-injection", "llm"},
	},
	"apt": {
		Name:        "apt",
		Description: "Classic APT campaign: spearphishing to exfiltration",
		Framework:   "attack",
		Tags:        []string{"apt", "nation-state", "multi-stage"},
	},
	"cloud": {
		Name:        "cloud",
		Description: "Cloud attack: cloud account compromise to data exfiltration",
		Framework:   "attack",
		Tags:        []string{"cloud", "saas", "iaas"},
	},
	"insider": {
		Name:        "insider",
		Description: "Insider threat: valid accounts to data exfiltration",
		Framework:   "attack",
		Tags:        []string{"insider", "data-theft"},
	},
	"minimal": {
		Name:        "minimal",
		Description: "Blank canvas: single customizable stage",
		Framework:   "attack",
		Tags:        []string{"starter", "template"},
	},
	"ransomware": {
		Name:        "ransomware",
		Description: "Ransomware kill chain: initial access to data encryption",
		Framework:   "attack",
		Tags:        []string{"ransomware", "encryption", "impact"},
	},
	"supply-chain": {
		Name:        "supply-chain",
		Description: "Supply chain compromise: trojanized software to credential theft",
		Framework:   "attack",
		Tags:        []string{"supply-chain", "software", "compromise"},
	},
}

// templateGenerators maps template names to their campaign generator functions.
var templateGenerators = map[string]func(string) *Campaign{
	"agent-hijack": generateAgentHijack,
	"apt":          generateAPT,
	"cloud":        generateCloud,
	"insider":      generateInsider,
	"minimal":      generateMinimal,
	"ransomware":   generateRansomware,
	"supply-chain": generateSupplyChain,
}

// ListTemplates returns all available built-in templates, sorted by name.
func ListTemplates() []Template {
	templates := make([]Template, 0, len(builtinTemplates))
	for _, t := range builtinTemplates {
		templates = append(templates, t)
	}
	sort.Slice(templates, func(i, j int) bool {
		return templates[i].Name < templates[j].Name
	})
	return templates
}

// GenerateCampaign creates a scaffold Campaign from a built-in template.
// The campaignName is used as meta.name. Returns error if templateName is unknown.
func GenerateCampaign(templateName, campaignName string) (*Campaign, error) {
	gen, ok := templateGenerators[templateName]
	if !ok {
		available := make([]string, 0, len(templateGenerators))
		for k := range templateGenerators {
			available = append(available, k)
		}
		sort.Strings(available)
		return nil, fmt.Errorf("unknown template %q; available: %s", templateName, strings.Join(available, ", "))
	}
	return gen(campaignName), nil
}

// FormatTemplateList returns a human-readable table of available templates.
func FormatTemplateList() string {
	templates := ListTemplates()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-15s %-10s %s\n", "NAME", "FRAMEWORK", "DESCRIPTION"))
	sb.WriteString(fmt.Sprintf("%-15s %-10s %s\n",
		strings.Repeat("-", 15),
		strings.Repeat("-", 10),
		strings.Repeat("-", 40)))
	for _, t := range templates {
		sb.WriteString(fmt.Sprintf("%-15s %-10s %s\n", t.Name, t.Framework, t.Description))
	}
	return sb.String()
}

// nowTimestamp returns the current UTC time formatted as RFC3339.
func nowTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// generateAPT builds a 7-stage classic APT campaign scaffold.
// Chain: spearphishing → execution → persistence → defense-evasion → c2-beacon → lateral-movement → exfiltration
func generateAPT(name string) *Campaign {
	now := nowTimestamp()
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:        name,
			Adversary:   "Custom APT",
			Description: "Classic APT campaign simulating spearphishing through exfiltration",
			Objective:   "Test detection coverage across the full APT kill chain",
			Severity:    "critical",
			Tags:        []string{"apt", "nation-state", "multi-stage"},
			Created:     now,
			Modified:    now,
		},
		Variables: map[string]string{
			"c2_server":    "https://c2.example.com",
			"payload_name": "update.exe",
		},
		Stages: []Stage{
			{
				ID:          "spearphishing",
				Name:        "Spearphishing Attachment",
				Description: "Deliver phishing email with malicious attachment",
				Technique:   "T1566.001",
				Tactic:      "initial-access",
				Platform:    []string{"windows"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Delivering phishing payload {{payload_name}}"`},
				},
				Expect: Expect{
					Telemetry: []string{"email_delivered", "file_create"},
				},
			},
			{
				ID:          "execution",
				Name:        "PowerShell Execution",
				Description: "Execute payload via PowerShell",
				Technique:   "T1059.001",
				Tactic:      "execution",
				Platform:    []string{"windows"},
				DependsOn:   []string{"spearphishing"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Executing PowerShell payload"`},
				},
				Expect: Expect{
					Telemetry: []string{"process_create", "script_execution"},
				},
			},
			{
				ID:          "persistence",
				Name:        "Registry Run Key Persistence",
				Description: "Establish persistence via registry run key",
				Technique:   "T1547.001",
				Tactic:      "persistence",
				Platform:    []string{"windows"},
				DependsOn:   []string{"execution"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Adding registry run key for persistence"`},
				},
				Expect: Expect{
					Telemetry: []string{"registry_modify", "process_create"},
				},
			},
			{
				ID:          "defense-evasion",
				Name:        "Obfuscated Files",
				Description: "Obfuscate payload to evade detection",
				Technique:   "T1027",
				Tactic:      "defense-evasion",
				Platform:    []string{"windows"},
				DependsOn:   []string{"persistence"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Obfuscating payload files"`},
				},
				Expect: Expect{
					Telemetry: []string{"file_modify", "process_create"},
				},
			},
			{
				ID:          "c2-beacon",
				Name:        "C2 via Web Protocols",
				Description: "Establish command and control channel over HTTP/S",
				Technique:   "T1071.001",
				Tactic:      "command-and-control",
				Platform:    []string{"windows"},
				DependsOn:   []string{"defense-evasion"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Establishing C2 beacon to {{c2_server}}"`},
				},
				Expect: Expect{
					Telemetry: []string{"network_connection", "dns_query"},
				},
			},
			{
				ID:          "lateral-movement",
				Name:        "Remote Desktop Protocol",
				Description: "Move laterally via RDP",
				Technique:   "T1021.001",
				Tactic:      "lateral-movement",
				Platform:    []string{"windows"},
				DependsOn:   []string{"c2-beacon"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Initiating RDP lateral movement"`},
				},
				Expect: Expect{
					Telemetry: []string{"network_connection", "authentication"},
				},
			},
			{
				ID:          "exfiltration",
				Name:        "Exfiltration Over C2",
				Description: "Exfiltrate collected data over C2 channel",
				Technique:   "T1041",
				Tactic:      "exfiltration",
				Platform:    []string{"windows"},
				DependsOn:   []string{"lateral-movement"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Exfiltrating data over C2 channel"`},
				},
				Expect: Expect{
					Telemetry: []string{"network_connection", "file_read"},
				},
			},
		},
	}
}

// generateRansomware builds a 7-stage ransomware kill chain scaffold.
// Chain: initial-access → execution → privilege-escalation → defense-evasion → discovery → lateral-movement → encrypt-data
func generateRansomware(name string) *Campaign {
	now := nowTimestamp()
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:        name,
			Adversary:   "Ransomware Operator",
			Description: "Ransomware kill chain from initial access to data encryption for impact",
			Objective:   "Test detection and response capabilities against ransomware operations",
			Severity:    "critical",
			Tags:        []string{"ransomware", "encryption", "impact"},
			Created:     now,
			Modified:    now,
		},
		Variables: map[string]string{
			"ransom_note":    "README_DECRYPT.txt",
			"encryption_key": "CHANGEME_BASE64_KEY",
		},
		Stages: []Stage{
			{
				ID:          "initial-access",
				Name:        "Spearphishing Link",
				Description: "Deliver phishing email with malicious link",
				Technique:   "T1566.002",
				Tactic:      "initial-access",
				Platform:    []string{"windows"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Delivering phishing link to target"`},
				},
				Expect: Expect{
					Telemetry: []string{"email_delivered", "network_connection"},
				},
			},
			{
				ID:          "execution",
				Name:        "Windows Command Shell",
				Description: "Execute malware via Windows command shell",
				Technique:   "T1059.003",
				Tactic:      "execution",
				Platform:    []string{"windows"},
				DependsOn:   []string{"initial-access"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Executing ransomware dropper via cmd.exe"`},
				},
				Expect: Expect{
					Telemetry: []string{"process_create", "file_create"},
				},
			},
			{
				ID:          "privilege-escalation",
				Name:        "Bypass UAC",
				Description: "Escalate privileges by bypassing User Account Control",
				Technique:   "T1548.002",
				Tactic:      "privilege-escalation",
				Platform:    []string{"windows"},
				DependsOn:   []string{"execution"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Bypassing UAC for privilege escalation"`},
					Elevated: true,
				},
				Expect: Expect{
					Telemetry: []string{"process_create", "registry_modify"},
				},
			},
			{
				ID:          "defense-evasion",
				Name:        "Disable Security Tools",
				Description: "Disable or tamper with security software",
				Technique:   "T1562.001",
				Tactic:      "defense-evasion",
				Platform:    []string{"windows"},
				DependsOn:   []string{"privilege-escalation"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Disabling endpoint security tools"`},
					Elevated: true,
				},
				Expect: Expect{
					Telemetry: []string{"process_terminate", "service_modify"},
				},
			},
			{
				ID:          "discovery",
				Name:        "File and Directory Discovery",
				Description: "Enumerate files and directories for encryption targets",
				Technique:   "T1083",
				Tactic:      "discovery",
				Platform:    []string{"windows"},
				DependsOn:   []string{"defense-evasion"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Enumerating files for encryption"`},
				},
				Expect: Expect{
					Telemetry: []string{"file_read", "process_create"},
				},
			},
			{
				ID:          "lateral-movement",
				Name:        "SMB/Windows Admin Shares",
				Description: "Spread to other hosts via SMB admin shares",
				Technique:   "T1021.002",
				Tactic:      "lateral-movement",
				Platform:    []string{"windows"},
				DependsOn:   []string{"discovery"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Spreading via SMB admin shares"`},
				},
				Expect: Expect{
					Telemetry: []string{"network_connection", "authentication", "file_create"},
				},
			},
			{
				ID:          "encrypt-data",
				Name:        "Data Encrypted for Impact",
				Description: "Encrypt data and drop ransom note",
				Technique:   "T1486",
				Tactic:      "impact",
				Platform:    []string{"windows"},
				DependsOn:   []string{"lateral-movement"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Encrypting files and dropping {{ransom_note}}"`},
				},
				Expect: Expect{
					Telemetry: []string{"file_modify", "file_create"},
				},
			},
		},
	}
}

// generateInsider builds a 4-stage insider threat scaffold.
// Chain: valid-accounts → data-collection → staging → exfiltration
func generateInsider(name string) *Campaign {
	now := nowTimestamp()
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:        name,
			Adversary:   "Insider Threat",
			Description: "Insider threat scenario using valid credentials for data theft",
			Objective:   "Test detection of insider threat behaviors and data exfiltration",
			Severity:    "high",
			Tags:        []string{"insider", "data-theft"},
			Created:     now,
			Modified:    now,
		},
		Stages: []Stage{
			{
				ID:          "valid-accounts",
				Name:        "Valid Accounts",
				Description: "Use legitimate credentials to access systems",
				Technique:   "T1078",
				Tactic:      "initial-access",
				Platform:    []string{"windows", "linux"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Authenticating with valid credentials"`},
				},
				Expect: Expect{
					Telemetry: []string{"authentication", "logon_event"},
				},
			},
			{
				ID:          "data-collection",
				Name:        "Data from Local System",
				Description: "Collect sensitive data from the local file system",
				Technique:   "T1005",
				Tactic:      "collection",
				Platform:    []string{"windows", "linux"},
				DependsOn:   []string{"valid-accounts"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Collecting sensitive files from local system"`},
				},
				Expect: Expect{
					Telemetry: []string{"file_read", "process_create"},
				},
			},
			{
				ID:          "staging",
				Name:        "Local Data Staging",
				Description: "Stage collected data in a local directory before exfiltration",
				Technique:   "T1074.001",
				Tactic:      "collection",
				Platform:    []string{"windows", "linux"},
				DependsOn:   []string{"data-collection"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Staging collected data for exfiltration"`},
				},
				Expect: Expect{
					Telemetry: []string{"file_create", "file_modify"},
				},
			},
			{
				ID:          "exfiltration",
				Name:        "Exfiltration to Cloud Storage",
				Description: "Exfiltrate staged data to external cloud storage",
				Technique:   "T1567.002",
				Tactic:      "exfiltration",
				Platform:    []string{"windows", "linux"},
				DependsOn:   []string{"staging"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Uploading data to cloud storage service"`},
				},
				Expect: Expect{
					Telemetry: []string{"network_connection", "dns_query"},
				},
			},
		},
	}
}

// generateAgentHijack builds a 5-stage AI agent attack scaffold.
// Chain: prompt-injection → model-manipulation → tool-abuse → data-theft → persistence
// Uses ATLAS + OWASP technique IDs (mixed framework).
func generateAgentHijack(name string) *Campaign {
	now := nowTimestamp()
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:        name,
			Adversary:   "AI Threat Actor",
			Description: "AI agent attack simulating prompt injection through data exfiltration",
			Objective:   "Test detection of AI/ML-specific attack patterns against agent systems",
			Severity:    "critical",
			Tags:        []string{"ai", "agent", "prompt-injection", "llm"},
			Created:     now,
			Modified:    now,
		},
		Stages: []Stage{
			{
				ID:          "prompt-injection",
				Name:        "LLM Prompt Injection",
				Description: "Inject adversarial prompts to manipulate agent behavior",
				Technique:   "AML.T0051",
				Tactic:      "initial-access",
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Injecting adversarial prompt into agent input"`},
				},
				Expect: Expect{
					Telemetry: []string{"api_call", "prompt_log"},
				},
			},
			{
				ID:          "model-manipulation",
				Name:        "Craft Adversarial Data",
				Description: "Manipulate model inputs to alter agent decision-making",
				Technique:   "AML.T0043",
				Tactic:      "ml-model-access",
				DependsOn:   []string{"prompt-injection"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Crafting adversarial data for model manipulation"`},
				},
				Expect: Expect{
					Telemetry: []string{"api_call", "model_inference"},
				},
			},
			{
				ID:          "tool-abuse",
				Name:        "Tool Call Policy Violation",
				Description: "Abuse agent tool-calling capabilities beyond authorized scope",
				Technique:   "LLM06",
				Tactic:      "ml-model-access",
				DependsOn:   []string{"model-manipulation"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Triggering unauthorized tool calls via agent"`},
				},
				Expect: Expect{
					Telemetry: []string{"tool_call", "guardrail_trigger"},
				},
			},
			{
				ID:          "data-theft",
				Name:        "Exfiltration via ML Service",
				Description: "Exfiltrate sensitive data through the compromised agent",
				Technique:   "AML.T0024",
				Tactic:      "exfiltration",
				DependsOn:   []string{"tool-abuse"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Exfiltrating data through agent tool calls"`},
				},
				Expect: Expect{
					Telemetry: []string{"resource_access", "network_connection"},
				},
			},
			{
				ID:          "persistence",
				Name:        "Poison Training Pipeline",
				Description: "Establish persistence by poisoning the model training pipeline",
				Technique:   "AML.T0020",
				Tactic:      "persistence",
				DependsOn:   []string{"data-theft"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Poisoning training data for persistent access"`},
				},
				Expect: Expect{
					Telemetry: []string{"vector_store_write", "model_inference"},
				},
			},
		},
	}
}

// generateSupplyChain builds a 5-stage supply chain compromise scaffold.
// Chain: compromise-supply-chain → trojanized-update → establish-persistence → c2-channel → collect-credentials
func generateSupplyChain(name string) *Campaign {
	now := nowTimestamp()
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:        name,
			Adversary:   "Supply Chain Attacker",
			Description: "Supply chain compromise from trojanized software to credential theft",
			Objective:   "Test detection of supply chain attack patterns",
			Severity:    "critical",
			Tags:        []string{"supply-chain", "software", "compromise"},
			Created:     now,
			Modified:    now,
		},
		Stages: []Stage{
			{
				ID:          "compromise-supply-chain",
				Name:        "Compromise Software Supply Chain",
				Description: "Compromise a trusted software distribution channel",
				Technique:   "T1195.002",
				Tactic:      "initial-access",
				Platform:    []string{"windows", "linux"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Distributing trojanized software update"`},
				},
				Expect: Expect{
					Telemetry: []string{"file_create", "process_create"},
				},
			},
			{
				ID:          "trojanized-update",
				Name:        "Execute Trojanized Payload",
				Description: "Execute malicious code embedded in the software update",
				Technique:   "T1059.001",
				Tactic:      "execution",
				Platform:    []string{"windows"},
				DependsOn:   []string{"compromise-supply-chain"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Executing trojanized payload via PowerShell"`},
				},
				Expect: Expect{
					Telemetry: []string{"process_create", "script_execution"},
				},
			},
			{
				ID:          "establish-persistence",
				Name:        "Boot or Logon Autostart",
				Description: "Establish persistence via autostart execution at boot or logon",
				Technique:   "T1547.001",
				Tactic:      "persistence",
				Platform:    []string{"windows"},
				DependsOn:   []string{"trojanized-update"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Installing persistence mechanism"`},
				},
				Expect: Expect{
					Telemetry: []string{"registry_modify", "file_create"},
				},
			},
			{
				ID:          "c2-channel",
				Name:        "C2 via Web Protocols",
				Description: "Establish command and control using web protocols",
				Technique:   "T1071.001",
				Tactic:      "command-and-control",
				Platform:    []string{"windows", "linux"},
				DependsOn:   []string{"establish-persistence"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Establishing C2 channel over HTTPS"`},
				},
				Expect: Expect{
					Telemetry: []string{"network_connection", "dns_query"},
				},
			},
			{
				ID:          "collect-credentials",
				Name:        "OS Credential Dumping",
				Description: "Dump credentials from the operating system",
				Technique:   "T1003",
				Tactic:      "credential-access",
				Platform:    []string{"windows"},
				DependsOn:   []string{"c2-channel"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Dumping OS credentials"`},
					Elevated: true,
				},
				Expect: Expect{
					Telemetry: []string{"process_create", "file_read"},
				},
			},
		},
	}
}

// generateCloud builds a 5-stage cloud attack scaffold.
// Chain: cloud-accounts → cloud-discovery → cloud-storage → cloud-api → cloud-exfil
func generateCloud(name string) *Campaign {
	now := nowTimestamp()
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:        name,
			Adversary:   "Cloud Threat Actor",
			Description: "Cloud attack from account compromise to data exfiltration",
			Objective:   "Test detection of cloud-based attack techniques",
			Severity:    "high",
			Tags:        []string{"cloud", "saas", "iaas"},
			Created:     now,
			Modified:    now,
		},
		Variables: map[string]string{
			"cloud_provider": "aws",
			"target_account": "target-account-id",
		},
		Stages: []Stage{
			{
				ID:          "cloud-accounts",
				Name:        "Cloud Account Compromise",
				Description: "Gain access using compromised cloud credentials",
				Technique:   "T1078.004",
				Tactic:      "initial-access",
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Authenticating to {{cloud_provider}} with compromised credentials"`},
				},
				Expect: Expect{
					Telemetry: []string{"authentication", "api_call"},
				},
			},
			{
				ID:          "cloud-discovery",
				Name:        "Cloud Infrastructure Discovery",
				Description: "Enumerate cloud infrastructure and resources",
				Technique:   "T1580",
				Tactic:      "discovery",
				DependsOn:   []string{"cloud-accounts"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Enumerating cloud resources for {{target_account}}"`},
				},
				Expect: Expect{
					Telemetry: []string{"api_call", "cloud_trail_event"},
				},
			},
			{
				ID:          "cloud-storage",
				Name:        "Data from Cloud Storage",
				Description: "Access and collect data from cloud storage services",
				Technique:   "T1530",
				Tactic:      "collection",
				DependsOn:   []string{"cloud-discovery"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Accessing cloud storage objects"`},
				},
				Expect: Expect{
					Telemetry: []string{"api_call", "resource_access"},
				},
			},
			{
				ID:          "cloud-api",
				Name:        "Cloud API Execution",
				Description: "Execute commands via cloud provider API and scripting",
				Technique:   "T1059.006",
				Tactic:      "execution",
				DependsOn:   []string{"cloud-storage"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Executing commands via cloud API"`},
				},
				Expect: Expect{
					Telemetry: []string{"api_call", "process_create"},
				},
			},
			{
				ID:          "cloud-exfil",
				Name:        "Exfiltration to Cloud Storage",
				Description: "Exfiltrate data to external cloud storage",
				Technique:   "T1567.002",
				Tactic:      "exfiltration",
				DependsOn:   []string{"cloud-api"},
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Exfiltrating data to external cloud storage"`},
				},
				Expect: Expect{
					Telemetry: []string{"network_connection", "api_call"},
				},
			},
		},
	}
}

// generateMinimal builds a single-stage blank canvas scaffold.
func generateMinimal(name string) *Campaign {
	now := nowTimestamp()
	return &Campaign{
		APIVersion: "v1",
		Kind:       "Campaign",
		Meta: Meta{
			Name:        name,
			Adversary:   "Unknown",
			Description: "Minimal campaign scaffold — customize stages as needed",
			Objective:   "Define campaign objective",
			Severity:    "low",
			Tags:        []string{"starter", "template"},
			Created:     now,
			Modified:    now,
		},
		Stages: []Stage{
			{
				ID:          "initial-access",
				Name:        "Initial Access",
				Description: "Describe the initial access vector",
				Technique:   "T1190",
				Tactic:      "initial-access",
				Execute: Execute{
					Type:     "shell",
					Commands: []string{`echo "[SIM] Initial access simulation"`},
				},
				Expect: Expect{
					Telemetry: []string{"network_connection"},
				},
			},
		},
	}
}
