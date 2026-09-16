// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package sigma

// LogSource describes a Sigma rule's logsource section, mapping a telemetry
// type to the Sigma category, product, and service triple.
type LogSource struct {
	Category string // e.g. "process_creation", "network_connection"
	Product  string // e.g. "windows", "linux", ""
	Service  string // e.g. "sysmon", "security", ""
}

// telemetryToLogSource maps ThreatEcho telemetry type names to Sigma logsource definitions.
// This is the bridge between campaign expected telemetry and Sigma rule structure.
var telemetryToLogSource = map[string]LogSource{
	// Process telemetry.
	"process_create":    {Category: "process_creation"},
	"process_access":    {Category: "process_access"},
	"process_injection": {Category: "create_remote_thread"},
	"process_terminate": {Category: "process_termination"},

	// File telemetry.
	"file_create": {Category: "file_event"},
	"file_modify": {Category: "file_change"},
	"file_delete": {Category: "file_delete"},
	"file_read":   {Category: "file_access"},
	"file_rename": {Category: "file_rename"},

	// Network telemetry.
	"network_connection": {Category: "network_connection"},
	"dns_query":          {Category: "dns_query"},
	"tls_handshake":      {Category: "network_connection"},

	// Registry telemetry (Windows).
	"registry_set":    {Category: "registry_set", Product: "windows"},
	"registry_create": {Category: "registry_add", Product: "windows"},
	"registry_delete": {Category: "registry_delete", Product: "windows"},
	"registry_modify": {Category: "registry_event", Product: "windows"},

	// Authentication / logon.
	"logon_event": {Category: "authentication", Product: "windows", Service: "security"},
	"auth_logoff": {Category: "authentication", Product: "windows", Service: "security"},

	// Script / execution.
	"script_execution": {Category: "process_creation"},
	"command_execute":  {Category: "process_creation"},

	// Scheduled task.
	"scheduled_task_create": {Category: "process_creation", Product: "windows"},

	// Email.
	"email_delivered": {Category: "application"},

	// AI agent telemetry — these map to application-level logs.
	"prompt_log":          {Category: "application", Service: "agent"},
	"guardrail_trigger":   {Category: "application", Service: "agent"},
	"tool_call":           {Category: "application", Service: "agent"},
	"api_call":            {Category: "application", Service: "agent"},
	"embedding_query":     {Category: "application", Service: "agent"},
	"vector_store_write":  {Category: "application", Service: "agent"},
	"inter_agent_message": {Category: "application", Service: "agent"},
}

// ResolveLogSource returns the Sigma logsource for a telemetry type.
// Returns a generic application logsource for unknown types.
func ResolveLogSource(telemetry string) LogSource {
	if ls, ok := telemetryToLogSource[telemetry]; ok {
		return ls
	}
	return LogSource{Category: "application"}
}

// AllMappedTelemetry returns all telemetry types that have a logsource mapping.
func AllMappedTelemetry() []string {
	out := make([]string, 0, len(telemetryToLogSource))
	for k := range telemetryToLogSource {
		out = append(out, k)
	}
	return out
}
