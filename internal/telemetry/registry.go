// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

// Package telemetry provides a formal taxonomy of all recognized telemetry
// types used in ThreatEcho campaign definitions. It validates telemetry type
// strings and provides lookup, grouping, and suggestion capabilities.
package telemetry

import (
	"sort"
	"strings"
)

// Type represents a recognized telemetry event type.
type Type string

// typeInfo holds metadata about a registered telemetry type.
type typeInfo struct {
	Category    string
	Description string
}

// ProcessCreate, ProcessTerminate, ProcessAccess, and ProcessInjection
// are process lifecycle telemetry types.
const (
	ProcessCreate    Type = "process_create"
	ProcessTerminate Type = "process_terminate"
	ProcessAccess    Type = "process_access"
	ProcessInjection Type = "process_injection"
)

// FileCreate and related constants are file-system event telemetry types.
const (
	FileCreate Type = "file_create"
	FileModify Type = "file_modify"
	FileDelete Type = "file_delete"
	FileRead   Type = "file_read"
	FileRename Type = "file_rename"
	FileWrite  Type = "file_write"
	FileUpload Type = "file_upload"
)

// NetworkConnection and related constants are network event telemetry types.
const (
	NetworkConnection Type = "network_connection"
	DNSQuery          Type = "dns_query"
	DNSResponse       Type = "dns_response"
	NetworkListen     Type = "network_listen"
	HTTPRequest       Type = "http_request"
	HTTPResponse      Type = "http_response"
	TLSHandshake      Type = "tls_handshake"
)

// RegistryCreate and related constants are Windows registry event telemetry types.
const (
	RegistryCreate Type = "registry_create"
	RegistryModify Type = "registry_modify"
	RegistryDelete Type = "registry_delete"
	RegistryRead   Type = "registry_read"
	RegistrySet    Type = "registry_set"
	RegistryAccess Type = "registry_access"
	RegistryWrite  Type = "registry_write"
)

// AuthSuccess and related constants are authentication event telemetry types.
const (
	AuthSuccess       Type = "auth_success"
	AuthFailure       Type = "auth_failure"
	AuthLogon         Type = "auth_logon"
	AuthLogoff        Type = "auth_logoff"
	AuthMFAChallenge  Type = "auth_mfa_challenge"
	AuthTokenCreate   Type = "auth_token_create"
	AuthSessionCreate Type = "auth_session_create"
	Authentication    Type = "authentication"
	LogonEvent        Type = "logon_event"
)

// ServiceCreate and related constants are service and persistence telemetry types.
const (
	ServiceCreate       Type = "service_create"
	ServiceModify       Type = "service_modify"
	ServiceStart        Type = "service_start"
	ServiceStop         Type = "service_stop"
	ServiceDelete       Type = "service_delete"
	ScheduledTaskCreate Type = "scheduled_task_create"
	ScheduledTaskDelete Type = "scheduled_task_delete"
)

// ScriptExecute and related constants are script and command execution telemetry types.
const (
	ScriptExecute      Type = "script_execute"
	ScriptExecution    Type = "script_execution"
	ScriptBlockLogging Type = "script_block_logging"
	PowershellExecute  Type = "powershell_execute"
	WMIExecute         Type = "wmi_execute"
	WMICreate          Type = "wmi_create"
	CommandExecute     Type = "command_execute"
)

// PromptLog and related constants are AI agent telemetry types covering
// tool calls, guardrails, model inference, and inter-agent communication.
const (
	PromptLog              Type = "prompt_log"
	GuardrailTrigger       Type = "guardrail_trigger"
	ToolCall               Type = "tool_call"
	EmbeddingQuery         Type = "embedding_query"
	VectorStoreWrite       Type = "vector_store_write"
	VectorStoreRead        Type = "vector_store_read"
	InterAgentMessage      Type = "inter_agent_message"
	ModelInference         Type = "model_inference"
	APICall                Type = "api_call"
	MCPRequest             Type = "mcp_request"
	MCPResponse            Type = "mcp_response"
	CapabilityNegotiation  Type = "capability_negotiation"
	ConversationTrajectory Type = "conversation_trajectory"
	DataTransfer           Type = "data_transfer"
	FileAccess             Type = "file_access"
	RateLimitTrigger       Type = "rate_limit_trigger"
	ResourceAccess         Type = "resource_access"
	TokenCountAnomaly      Type = "token_count_anomaly"
	DocumentUpload         Type = "document_upload"
	EmbeddingComputation   Type = "embedding_computation"
	MemoryWrite            Type = "memory_write"
	MemoryAccess           Type = "memory_access"
	PreferencesUpdate      Type = "preferences_update"
)

// LogonEvent4624 and related constants are Windows Event Log telemetry types.
const (
	LogonEvent4624             Type = "logon_event_4624"
	LogonEvent4778             Type = "logon_event_4778"
	LogonFailure4625           Type = "logon_failure_4625"
	DirectoryServiceAccess4662 Type = "directory_service_access_4662"
	SysmonEvent10              Type = "sysmon_event_10"
	ScriptBlockLog             Type = "script_block_log"
	NTLMAuth                   Type = "ntlm_auth"
	LegacyProtocolAuth         Type = "legacy_protocol_auth"
)

// LDAPQuery and ReplicationEvent are Active Directory telemetry types.
const (
	LDAPQuery        Type = "ldap_query"
	ReplicationEvent Type = "replication_event"
)

// CloudAPICall and related constants are cloud provider telemetry types.
const (
	CloudAPICall        Type = "cloud_api_call"
	CloudConfigChange   Type = "cloud_config_change"
	CloudIdentityChange Type = "cloud_identity_change"
	CloudTrailEvent     Type = "cloud_trail_event"
	IAMEvent            Type = "iam_event"
	STSEvent            Type = "sts_event"
)

// EmailDelivered and EmailSent are email event telemetry types.
const (
	EmailDelivered Type = "email_delivered"
	EmailSent      Type = "email_sent"
)

// CIEvent is a CI/CD pipeline telemetry type.
const (
	CIEvent Type = "ci_event"
)

// ProcessCreation and CommandLine are extended process telemetry types.
const (
	ProcessCreation Type = "process_creation"
	CommandLine     Type = "command_line"
)

// FileDeletion and FileModification are extended file event telemetry types.
const (
	FileDeletion     Type = "file_deletion"
	FileModification Type = "file_modification"
)

// WAFEvent, WebLog, and DatabaseQuery are web and WAF telemetry types.
const (
	WAFEvent      Type = "waf_event"
	WebLog        Type = "web_log"
	DatabaseQuery Type = "database_query"
)

// AuthenticationEvent and related constants are miscellaneous telemetry types.
const (
	AuthenticationEvent   Type = "authentication_event"
	FeedbackLog           Type = "feedback_log"
	RateLimit             Type = "rate_limit"
	RDPSession            Type = "rdp_session"
	ScheduledTaskCreation Type = "scheduled_task_creation"
	WMIEvent              Type = "wmi_event"
)

// LogClear and related constants are operational telemetry types.
const (
	LogClear      Type = "log_clear"
	EventLogClear Type = "event_log_clear"
	EventLogQuery Type = "event_log_query"
	WebScrape     Type = "web_scrape"
)

// FirewallRuleAdd is a firewall event telemetry type.
const (
	FirewallRuleAdd Type = "firewall_rule_add"
)

// registry maps every recognized telemetry type to its metadata.
var registry = map[Type]typeInfo{
	// Process
	ProcessCreate:    {Category: "Process", Description: "A new process was created"},
	ProcessTerminate: {Category: "Process", Description: "A process was terminated"},
	ProcessAccess:    {Category: "Process", Description: "A process opened a handle to another process"},
	ProcessInjection: {Category: "Process", Description: "Code was injected into a running process"},

	// File
	FileCreate: {Category: "File", Description: "A new file was created on disk"},
	FileModify: {Category: "File", Description: "An existing file was modified"},
	FileDelete: {Category: "File", Description: "A file was deleted"},
	FileRead:   {Category: "File", Description: "A file was read"},
	FileRename: {Category: "File", Description: "A file was renamed or moved"},
	FileWrite:  {Category: "File", Description: "Data was written to a file"},
	FileUpload: {Category: "File", Description: "A file was uploaded to a remote destination"},

	// Network
	NetworkConnection: {Category: "Network", Description: "A network connection was established"},
	DNSQuery:          {Category: "Network", Description: "A DNS query was issued"},
	DNSResponse:       {Category: "Network", Description: "A DNS response was received"},
	NetworkListen:     {Category: "Network", Description: "A socket began listening for connections"},
	HTTPRequest:       {Category: "Network", Description: "An HTTP request was sent"},
	HTTPResponse:      {Category: "Network", Description: "An HTTP response was received"},
	TLSHandshake:      {Category: "Network", Description: "A TLS handshake was performed"},

	// Registry
	RegistryCreate: {Category: "Registry", Description: "A registry key was created"},
	RegistryModify: {Category: "Registry", Description: "A registry value was modified"},
	RegistryDelete: {Category: "Registry", Description: "A registry key or value was deleted"},
	RegistryRead:   {Category: "Registry", Description: "A registry key or value was read"},
	RegistrySet:    {Category: "Registry", Description: "A registry value was set"},
	RegistryAccess: {Category: "Registry", Description: "A registry key or value was accessed"},
	RegistryWrite:  {Category: "Registry", Description: "A registry key or value was written"},

	// Authentication
	AuthSuccess:       {Category: "Authentication", Description: "An authentication attempt succeeded"},
	AuthFailure:       {Category: "Authentication", Description: "An authentication attempt failed"},
	AuthLogon:         {Category: "Authentication", Description: "A user logon event occurred"},
	AuthLogoff:        {Category: "Authentication", Description: "A user logoff event occurred"},
	AuthMFAChallenge:  {Category: "Authentication", Description: "An MFA challenge was presented"},
	AuthTokenCreate:   {Category: "Authentication", Description: "An authentication token was created"},
	AuthSessionCreate: {Category: "Authentication", Description: "A new session was created"},
	Authentication:    {Category: "Authentication", Description: "A generic authentication event occurred"},
	LogonEvent:        {Category: "Authentication", Description: "A logon event was recorded"},

	// Service/Persistence
	ServiceCreate:       {Category: "Service", Description: "A system service was created"},
	ServiceModify:       {Category: "Service", Description: "A system service was modified"},
	ServiceStart:        {Category: "Service", Description: "A system service was started"},
	ServiceStop:         {Category: "Service", Description: "A system service was stopped"},
	ServiceDelete:       {Category: "Service", Description: "A system service was deleted"},
	ScheduledTaskCreate: {Category: "Service", Description: "A scheduled task was created"},
	ScheduledTaskDelete: {Category: "Service", Description: "A scheduled task was deleted"},

	// Script/Execution
	ScriptExecute:      {Category: "Script", Description: "A script was executed"},
	ScriptExecution:    {Category: "Script", Description: "A script execution event was observed"},
	PowershellExecute:  {Category: "Script", Description: "A PowerShell command or script was executed"},
	ScriptBlockLogging: {Category: "Script", Description: "A PowerShell script block was logged"},
	WMIExecute:         {Category: "Script", Description: "A WMI query or method was executed"},
	WMICreate:          {Category: "Script", Description: "A WMI object or event subscription was created"},
	CommandExecute:     {Category: "Script", Description: "A system command was executed"},

	// AI Agent
	PromptLog:              {Category: "AI Agent", Description: "A prompt was sent to an AI model"},
	GuardrailTrigger:       {Category: "AI Agent", Description: "An AI guardrail or safety filter was triggered"},
	ToolCall:               {Category: "AI Agent", Description: "An AI agent invoked a tool"},
	EmbeddingQuery:         {Category: "AI Agent", Description: "An embedding/vector query was executed"},
	VectorStoreWrite:       {Category: "AI Agent", Description: "Data was written to a vector store"},
	VectorStoreRead:        {Category: "AI Agent", Description: "Data was read from a vector store"},
	InterAgentMessage:      {Category: "AI Agent", Description: "A message was exchanged between AI agents"},
	ModelInference:         {Category: "AI Agent", Description: "An AI model inference was performed"},
	APICall:                {Category: "AI Agent", Description: "An API call was made by an agent or process"},
	MCPRequest:             {Category: "AI Agent", Description: "An MCP (Model Context Protocol) request was sent to a tool server"},
	MCPResponse:            {Category: "AI Agent", Description: "An MCP tool server returned a response"},
	CapabilityNegotiation:  {Category: "AI Agent", Description: "MCP or tool capability negotiation was performed"},
	ConversationTrajectory: {Category: "AI Agent", Description: "Agent conversation trajectory or flow change was detected"},
	DataTransfer:           {Category: "AI Agent", Description: "Data was transferred between agent components or external endpoints"},
	FileAccess:             {Category: "AI Agent", Description: "An agent accessed a file on the host filesystem"},
	RateLimitTrigger:       {Category: "AI Agent", Description: "An API or tool rate limit was triggered"},
	ResourceAccess:         {Category: "AI Agent", Description: "An agent accessed a protected resource"},
	TokenCountAnomaly:      {Category: "AI Agent", Description: "Anomalous token usage was detected in agent input or output"},
	DocumentUpload:         {Category: "AI Agent", Description: "A document was uploaded by or to an agent"},
	EmbeddingComputation:   {Category: "AI Agent", Description: "An embedding computation was performed on input data"},
	MemoryWrite:            {Category: "AI Agent", Description: "An agent wrote to persistent memory or context store"},
	MemoryAccess:           {Category: "AI Agent", Description: "An agent read from persistent memory or context store"},
	PreferencesUpdate:      {Category: "AI Agent", Description: "An agent modified user or system preferences"},

	// Windows Event Log
	LogonEvent4624:             {Category: "Windows", Description: "Windows Security Event 4624: successful logon"},
	LogonEvent4778:             {Category: "Windows", Description: "Windows Security Event 4778: session reconnected"},
	LogonFailure4625:           {Category: "Windows", Description: "Windows Security Event 4625: failed logon attempt"},
	DirectoryServiceAccess4662: {Category: "Windows", Description: "Windows Security Event 4662: directory service object access"},
	SysmonEvent10:              {Category: "Windows", Description: "Sysmon Event 10: process access (OpenProcess)"},
	ScriptBlockLog:             {Category: "Windows", Description: "PowerShell script block logging event"},
	NTLMAuth:                   {Category: "Windows", Description: "NTLM authentication event"},
	LegacyProtocolAuth:         {Category: "Windows", Description: "Legacy protocol authentication (NTLMv1, WDigest)"},

	// Active Directory
	LDAPQuery:        {Category: "Active Directory", Description: "An LDAP query was executed against a directory service"},
	ReplicationEvent: {Category: "Active Directory", Description: "An Active Directory replication event occurred"},

	// Cloud
	CloudAPICall:        {Category: "Cloud", Description: "A cloud provider API call was made"},
	CloudConfigChange:   {Category: "Cloud", Description: "A cloud resource configuration was changed"},
	CloudIdentityChange: {Category: "Cloud", Description: "A cloud identity or IAM change was made"},
	CloudTrailEvent:     {Category: "Cloud", Description: "An AWS CloudTrail audit event was recorded"},
	IAMEvent:            {Category: "Cloud", Description: "An IAM identity or permission change event"},
	STSEvent:            {Category: "Cloud", Description: "An AWS STS token or role assumption event"},

	// Email
	EmailDelivered: {Category: "Email", Description: "An email was delivered to a recipient"},
	EmailSent:      {Category: "Email", Description: "An email was sent"},

	// Web/WAF
	WAFEvent:      {Category: "Web", Description: "A WAF (Web Application Firewall) event was triggered"},
	WebLog:        {Category: "Web", Description: "A web server access or error log entry was recorded"},
	DatabaseQuery: {Category: "Database", Description: "A database query was executed"},

	// CI/CD
	CIEvent: {Category: "CI/CD", Description: "A CI/CD pipeline event was triggered or observed"},

	// Process (extended)
	ProcessCreation: {Category: "Process", Description: "A process creation event was logged (alias for process_create)"},
	CommandLine:     {Category: "Process", Description: "A command-line execution was observed"},

	// File (extended)
	FileDeletion:     {Category: "File", Description: "A file deletion event was observed (alias for file_delete)"},
	FileModification: {Category: "File", Description: "A file modification event was observed (alias for file_modify)"},

	// Misc
	AuthenticationEvent:   {Category: "Authentication", Description: "A generic authentication event was recorded"},
	FeedbackLog:           {Category: "AI Agent", Description: "An AI agent feedback or RLHF log entry was recorded"},
	RateLimit:             {Category: "Operational", Description: "A rate limit threshold was hit"},
	RDPSession:            {Category: "Network", Description: "An RDP session was established or observed"},
	ScheduledTaskCreation: {Category: "Service", Description: "A scheduled task creation event was logged"},
	WMIEvent:              {Category: "Script", Description: "A WMI event was observed"},

	// Operational
	LogClear:      {Category: "Operational", Description: "A log was cleared or deleted"},
	EventLogClear: {Category: "Operational", Description: "A Windows event log was cleared"},
	EventLogQuery: {Category: "Operational", Description: "A Windows event log was queried"},
	WebScrape:     {Category: "Operational", Description: "A web scraping operation was performed"},

	// Firewall
	FirewallRuleAdd: {Category: "Network", Description: "A firewall rule was created or modified"},
}

// Valid reports whether the given string is a recognized telemetry type.
func Valid(t string) bool {
	_, ok := registry[Type(t)]
	return ok
}

// All returns every registered telemetry type in sorted order.
func All() []Type {
	types := make([]Type, 0, len(registry))
	for t := range registry {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool {
		return types[i] < types[j]
	})
	return types
}

// Category returns the category name for a registered telemetry type.
// It returns an empty string if the type is not recognized.
func Category(t string) string {
	info, ok := registry[Type(t)]
	if !ok {
		return ""
	}
	return info.Category
}

// Description returns the human-readable description for a registered
// telemetry type. It returns an empty string if the type is not recognized.
func Description(t string) string {
	info, ok := registry[Type(t)]
	if !ok {
		return ""
	}
	return info.Description
}

// ByCategory returns all registered telemetry types grouped by their
// category name. Types within each category are sorted.
func ByCategory() map[string][]Type {
	m := make(map[string][]Type)
	for t, info := range registry {
		m[info.Category] = append(m[info.Category], t)
	}
	for cat := range m {
		sort.Slice(m[cat], func(i, j int) bool {
			return m[cat][i] < m[cat][j]
		})
	}
	return m
}

// Categories returns all category names in sorted order.
func Categories() []string {
	seen := make(map[string]bool)
	for _, info := range registry {
		seen[info.Category] = true
	}
	cats := make([]string, 0, len(seen))
	for c := range seen {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	return cats
}

// Suggest returns registered types that are similar to the given input,
// useful for typo correction. It matches on substring containment and
// shared prefix. Results are sorted and deduplicated.
func Suggest(t string) []Type {
	if t == "" {
		return nil
	}
	lower := strings.ToLower(t)
	seen := make(map[Type]bool)
	var matches []Type

	for registered := range registry {
		s := string(registered)

		// Substring match in either direction.
		if strings.Contains(s, lower) || strings.Contains(lower, s) {
			if !seen[registered] {
				seen[registered] = true
				matches = append(matches, registered)
			}
			continue
		}

		// Shared prefix of at least 4 characters.
		prefixLen := sharedPrefix(s, lower)
		if prefixLen >= 4 {
			if !seen[registered] {
				seen[registered] = true
				matches = append(matches, registered)
			}
			continue
		}

		// Match on individual segments split by underscore.
		inputParts := strings.Split(lower, "_")
		registeredParts := strings.Split(s, "_")
		for _, ip := range inputParts {
			if len(ip) < 3 {
				continue
			}
			for _, rp := range registeredParts {
				if strings.Contains(rp, ip) || strings.Contains(ip, rp) {
					if !seen[registered] {
						seen[registered] = true
						matches = append(matches, registered)
					}
				}
			}
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i] < matches[j]
	})
	return matches
}

// sharedPrefix returns the length of the common prefix between two strings.
func sharedPrefix(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
