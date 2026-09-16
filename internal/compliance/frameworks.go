// Copyright (c) 2024-2026 ThreatEcho. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
// https://threatecho.com

package compliance

// nistCSFDef returns the NIST Cybersecurity Framework 2.0 definition.
// Mapping: ATT&CK tactics to CSF functions/categories based on NIST's published
// ATT&CK-to-CSF crosswalk and MITRE's ATT&CK Evaluations methodology.
func nistCSFDef() *FrameworkDef {
	return &FrameworkDef{
		ID:          NISTCSF,
		Name:        "NIST Cybersecurity Framework",
		Version:     "2.0",
		Description: "Framework for improving critical infrastructure cybersecurity",
		Controls: []*Control{
			// GOVERN (GV) — organizational context
			{ID: "GV.OC", Name: "Organizational Context", Description: "Understanding of organizational mission and stakeholder expectations to inform cybersecurity risk management", Tactics: nil},
			{ID: "GV.RM", Name: "Risk Management Strategy", Description: "Organization's priorities, constraints, and risk appetite as context for managing cybersecurity risk", Tactics: nil},
			{ID: "GV.SC", Name: "Supply Chain Risk Management", Description: "Supply chain risk management processes", Tactics: []string{"initial-access", "resource-development"}},

			// IDENTIFY (ID) — asset management, risk assessment
			{ID: "ID.AM", Name: "Asset Management", Description: "Data, personnel, devices, systems, and facilities are identified and managed", Tactics: []string{"discovery", "reconnaissance"}},
			{ID: "ID.RA", Name: "Risk Assessment", Description: "Organization understands the cybersecurity risk to operations, assets, and individuals", Tactics: []string{"reconnaissance"}},
			{ID: "ID.IM", Name: "Improvement", Description: "Improvements to organizational cybersecurity risk management are identified", Tactics: nil},

			// PROTECT (PR) — access control, training, data security
			{ID: "PR.AA", Name: "Identity Management and Access Control", Description: "Access to assets is managed consistent with assessed risk", Tactics: []string{"credential-access", "privilege-escalation", "initial-access"}},
			{ID: "PR.AT", Name: "Awareness and Training", Description: "Personnel are provided cybersecurity awareness and training", Tactics: []string{"initial-access"}},
			{ID: "PR.DS", Name: "Data Security", Description: "Data is managed consistent with risk strategy to protect confidentiality, integrity, and availability", Tactics: []string{"collection", "exfiltration", "impact"}},
			{ID: "PR.PS", Name: "Platform Security", Description: "Hardware, software, and services of physical and virtual platforms are managed", Tactics: []string{"execution", "persistence", "privilege-escalation", "defense-evasion"}},
			{ID: "PR.IR", Name: "Technology Infrastructure Resilience", Description: "Security architectures are managed with the organization's risk strategy", Tactics: []string{"impact", "command-and-control"}},

			// DETECT (DE) — continuous monitoring, detection processes
			{ID: "DE.CM", Name: "Continuous Monitoring", Description: "Assets are monitored to find anomalies, indicators of compromise, and other potentially adverse events", Tactics: []string{"execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration"}},
			{ID: "DE.AE", Name: "Adverse Event Analysis", Description: "Anomalies, indicators of compromise, and other potentially adverse events are analyzed", Tactics: []string{"execution", "lateral-movement", "exfiltration", "impact"}},

			// RESPOND (RS) — incident management, analysis, mitigation
			{ID: "RS.MA", Name: "Incident Management", Description: "Responses to detected cybersecurity incidents are managed", Tactics: []string{"impact", "exfiltration"}},
			{ID: "RS.AN", Name: "Incident Analysis", Description: "Investigations are conducted to ensure effective response and support forensics/recovery", Tactics: []string{"execution", "lateral-movement", "command-and-control"}},
			{ID: "RS.CO", Name: "Incident Response Reporting and Communication", Description: "Response activities are coordinated with internal and external stakeholders", Tactics: nil},
			{ID: "RS.MI", Name: "Incident Mitigation", Description: "Activities are performed to prevent expansion of an event and mitigate its effects", Tactics: []string{"lateral-movement", "privilege-escalation", "persistence"}},

			// RECOVER (RC) — recovery planning, improvements
			{ID: "RC.RP", Name: "Incident Recovery Plan Execution", Description: "Restoration activities are performed to ensure operational availability", Tactics: []string{"impact"}},
			{ID: "RC.CO", Name: "Incident Recovery Communication", Description: "Restoration activities are coordinated with internal and external parties", Tactics: nil},
		},
	}
}

// nist80053Def returns NIST SP 800-53 Rev.5 key control families mapped to ATT&CK.
// Based on MITRE's published ATT&CK-to-800-53 mapping (center for threat-informed defense).
func nist80053Def() *FrameworkDef {
	return &FrameworkDef{
		ID:          NIST80053,
		Name:        "NIST SP 800-53",
		Version:     "Rev. 5",
		Description: "Security and Privacy Controls for Information Systems and Organizations",
		Controls: []*Control{
			{ID: "AC", Name: "Access Control", Description: "Policies and procedures for access to organizational information systems", Tactics: []string{"credential-access", "privilege-escalation", "initial-access", "lateral-movement"}},
			{ID: "AT", Name: "Awareness and Training", Description: "Security awareness training policies and procedures", Tactics: []string{"initial-access"}},
			{ID: "AU", Name: "Audit and Accountability", Description: "Audit record generation, review, analysis, and reporting", Tactics: []string{"defense-evasion", "execution", "persistence"}},
			{ID: "CA", Name: "Assessment, Authorization, and Monitoring", Description: "Security assessment policies, system interconnections, and continuous monitoring", Tactics: []string{"discovery", "reconnaissance"}},
			{ID: "CM", Name: "Configuration Management", Description: "Baseline configurations, change control, and security settings", Tactics: []string{"execution", "persistence", "privilege-escalation", "defense-evasion"}},
			{ID: "CP", Name: "Contingency Planning", Description: "Business continuity and disaster recovery", Tactics: []string{"impact"}},
			{ID: "IA", Name: "Identification and Authentication", Description: "User identification and authentication policies", Tactics: []string{"credential-access", "initial-access"}},
			{ID: "IR", Name: "Incident Response", Description: "Incident response training, testing, handling, monitoring, and reporting", Tactics: []string{"impact", "exfiltration", "lateral-movement", "execution"}},
			{ID: "MA", Name: "Maintenance", Description: "System maintenance policies and remote maintenance", Tactics: []string{"persistence", "privilege-escalation"}},
			{ID: "MP", Name: "Media Protection", Description: "Media access, marking, storage, transport, and sanitization", Tactics: []string{"collection", "exfiltration"}},
			{ID: "PE", Name: "Physical and Environmental Protection", Description: "Physical access authorizations and monitoring", Tactics: nil},
			{ID: "PL", Name: "Planning", Description: "Security planning policies and system security plans", Tactics: nil},
			{ID: "PM", Name: "Program Management", Description: "Information security program plan and governance", Tactics: nil},
			{ID: "PS", Name: "Personnel Security", Description: "Position risk designations and personnel screening", Tactics: nil},
			{ID: "PT", Name: "PII Processing and Transparency", Description: "Privacy policies and data processing", Tactics: nil},
			{ID: "RA", Name: "Risk Assessment", Description: "Risk assessment policies, vulnerability monitoring, and threat awareness", Tactics: []string{"reconnaissance", "discovery"}},
			{ID: "SA", Name: "System and Services Acquisition", Description: "System development lifecycle, acquisition, and supply chain", Tactics: []string{"initial-access", "resource-development"}},
			{ID: "SC", Name: "System and Communications Protection", Description: "Network separation, cryptographic protection, and boundary defense", Tactics: []string{"command-and-control", "exfiltration", "lateral-movement"}},
			{ID: "SI", Name: "System and Information Integrity", Description: "Flaw remediation, malicious code protection, and monitoring", Tactics: []string{"execution", "defense-evasion", "persistence", "privilege-escalation"}},
			{ID: "SR", Name: "Supply Chain Risk Management", Description: "Supply chain controls and provenance", Tactics: []string{"initial-access", "resource-development"}},
		},
	}
}

// cisV8Def returns CIS Controls v8 mapped to ATT&CK tactics.
// Based on the CIS Controls v8 Mapping to ATT&CK published by the Center for
// Internet Security and MITRE's Center for Threat-Informed Defense.
func cisV8Def() *FrameworkDef {
	return &FrameworkDef{
		ID:          CISv8,
		Name:        "CIS Controls",
		Version:     "v8",
		Description: "Center for Internet Security Critical Security Controls",
		Controls: []*Control{
			{ID: "CIS.01", Name: "Inventory and Control of Enterprise Assets", Description: "Actively manage all enterprise assets connected to the infrastructure", Tactics: []string{"discovery", "reconnaissance"}},
			{ID: "CIS.02", Name: "Inventory and Control of Software Assets", Description: "Actively manage all software on the network", Tactics: []string{"execution", "persistence"}},
			{ID: "CIS.03", Name: "Data Protection", Description: "Develop processes and technical controls to identify, classify, handle, retain, and dispose of data", Tactics: []string{"collection", "exfiltration", "impact"}},
			{ID: "CIS.04", Name: "Secure Configuration of Enterprise Assets and Software", Description: "Establish and maintain secure configurations", Tactics: []string{"execution", "persistence", "privilege-escalation", "defense-evasion"}},
			{ID: "CIS.05", Name: "Account Management", Description: "Use processes and tools to assign and manage authorization to credentials", Tactics: []string{"credential-access", "initial-access", "privilege-escalation"}},
			{ID: "CIS.06", Name: "Access Control Management", Description: "Use processes and tools to create, assign, manage, and revoke access credentials", Tactics: []string{"credential-access", "privilege-escalation", "lateral-movement"}},
			{ID: "CIS.07", Name: "Continuous Vulnerability Management", Description: "Develop a plan to continuously assess and track vulnerabilities", Tactics: []string{"initial-access", "privilege-escalation"}},
			{ID: "CIS.08", Name: "Audit Log Management", Description: "Collect, alert, review, and retain audit logs of events", Tactics: []string{"defense-evasion", "execution"}},
			{ID: "CIS.09", Name: "Email and Web Browser Protections", Description: "Improve protections and detections of threats from email and web vectors", Tactics: []string{"initial-access"}},
			{ID: "CIS.10", Name: "Malware Defenses", Description: "Prevent or control the installation, spread, and execution of malicious applications", Tactics: []string{"execution", "persistence", "defense-evasion"}},
			{ID: "CIS.11", Name: "Data Recovery", Description: "Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets", Tactics: []string{"impact"}},
			{ID: "CIS.12", Name: "Network Infrastructure Management", Description: "Establish and maintain network infrastructure management", Tactics: []string{"command-and-control", "lateral-movement"}},
			{ID: "CIS.13", Name: "Network Monitoring and Defense", Description: "Operate processes and tooling to establish and maintain comprehensive network monitoring and defense", Tactics: []string{"command-and-control", "lateral-movement", "exfiltration", "execution"}},
			{ID: "CIS.14", Name: "Security Awareness and Skills Training", Description: "Establish and maintain a security awareness program", Tactics: []string{"initial-access"}},
			{ID: "CIS.15", Name: "Service Provider Management", Description: "Develop a process to evaluate service providers who hold sensitive data", Tactics: []string{"initial-access", "resource-development"}},
			{ID: "CIS.16", Name: "Application Software Security", Description: "Manage the security life cycle of in-house developed, hosted, or acquired software", Tactics: []string{"execution", "initial-access"}},
			{ID: "CIS.17", Name: "Incident Response Management", Description: "Establish a program to develop and maintain an incident response capability", Tactics: []string{"impact", "exfiltration"}},
			{ID: "CIS.18", Name: "Penetration Testing", Description: "Test the effectiveness and resiliency of enterprise assets through identifying and exploiting weaknesses", Tactics: []string{"initial-access", "execution", "privilege-escalation", "lateral-movement", "exfiltration"}},
		},
	}
}
