"""
Compliance Auditor Module
~~~~~~~~~~~~~~~~~~~~~~~~~
Evaluates network device configurations against enterprise CIS Benchmark
and NIST hardening rules to identify vulnerabilities and security regressions.
"""

from __future__ import annotations
import re
from typing import Dict, Any, List


class AuditRule:
    """Represents an individual security compliance rule."""
    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str,
        description: str,
        remediation: str,
    ):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.description = description
        self.remediation = remediation


class AuditFinding:
    """Represents the evaluation outcome of an AuditRule against a config."""
    def __init__(
        self,
        rule: AuditRule,
        passed: bool,
        evidence: str = "",
        details: str = "",
    ):
        self.rule = rule
        self.passed = passed
        self.evidence = evidence
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule.rule_id,
            "name": self.rule.name,
            "severity": self.rule.severity,
            "passed": self.passed,
            "description": self.rule.description,
            "remediation": self.rule.remediation,
            "evidence": self.evidence,
            "details": self.details,
        }


class DeviceAuditReport:
    """Holds all audit findings and score metrics for a single device."""
    def __init__(self, hostname: str, ip: str, findings: List[AuditFinding]):
        self.hostname = hostname
        self.ip = ip
        self.findings = findings
        self.total_rules = len(findings)
        self.passed_rules = sum(1 for f in findings if f.passed)
        self.failed_rules = self.total_rules - self.passed_rules

        # Severity weights
        weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
        total_possible = sum(weights.get(f.rule.severity, 10) for f in findings)
        total_earned = sum(weights.get(f.rule.severity, 10) for f in findings if f.passed)
        
        self.score = round((total_earned / total_possible) * 100, 1) if total_possible > 0 else 0.0

        if self.score >= 90:
            self.grade = "A"
            self.status = "COMPLIANT"
        elif self.score >= 75:
            self.grade = "B"
            self.status = "MINOR_RISK"
        elif self.score >= 60:
            self.grade = "C"
            self.status = "WARNING"
        elif self.score >= 40:
            self.grade = "D"
            self.status = "NON_COMPLIANT"
        else:
            self.grade = "F"
            self.status = "CRITICAL_RISK"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "score": self.score,
            "grade": self.grade,
            "status": self.status,
            "passed_rules": self.passed_rules,
            "failed_rules": self.failed_rules,
            "findings": [f.to_dict() for f in self.findings],
        }


class ComplianceAuditor:
    """Applies security hardening rules on Cisco and multivendor configurations."""

    RULES: List[AuditRule] = [
        AuditRule(
            rule_id="SEC-001",
            name="Disable Telnet on VTY Lines",
            severity="CRITICAL",
            description="Telnet transmits credentials and payload in cleartext. Only SSH must be accepted.",
            remediation="configure terminal\nline vty 0 15\ntransport input ssh",
        ),
        AuditRule(
            rule_id="SEC-002",
            name="Enforce Strong Enable Secret",
            severity="HIGH",
            description="Legacy 'enable password' is vulnerable to rainbow table attacks. Use 'enable secret' (Type 5/8/9).",
            remediation="configure terminal\nno enable password\nenable secret <STRONG_PASSWORD>",
        ),
        AuditRule(
            rule_id="SEC-003",
            name="Enable Local Password Encryption",
            severity="MEDIUM",
            description="Service password-encryption hides cleartext strings in the running configuration.",
            remediation="configure terminal\nservice password-encryption",
        ),
        AuditRule(
            rule_id="SEC-004",
            name="Enforce SSH Version 2",
            severity="HIGH",
            description="SSH Version 1 suffers from known cryptographic flaws (CRC-32 compensation attack).",
            remediation="configure terminal\nip ssh version 2",
        ),
        AuditRule(
            rule_id="SEC-005",
            name="Enable AAA New-Model Authentication",
            severity="MEDIUM",
            description="AAA new-model provides standardized authentication, authorization, and accounting controls.",
            remediation="configure terminal\naaa new-model\naaa authentication login default local",
        ),
        AuditRule(
            rule_id="SEC-006",
            name="Configure Legal Login Banner (MOTD)",
            severity="LOW",
            description="A legal warning banner is required for legal enforcement against unauthorized access.",
            remediation="configure terminal\nbanner motd ^C AUTHORIZED ACCESS ONLY ^C",
        ),
        AuditRule(
            rule_id="SEC-007",
            name="Configure Centralized NTP Synchronization",
            severity="MEDIUM",
            description="Synchronized clocks are essential for accurate incident response and forensic log correlation.",
            remediation="configure terminal\nntp server 192.168.10.254",
        ),
        AuditRule(
            rule_id="SEC-008",
            name="Configure Centralized Remote Syslog",
            severity="MEDIUM",
            description="Log buffers fill quickly; events must be forwarded offsite to a SIEM/Syslog server.",
            remediation="configure terminal\nlogging host <SYSLOG_IP>\nlogging trap warnings",
        ),
        AuditRule(
            rule_id="SEC-009",
            name="Avoid Default VLAN 1 for User Traffic",
            severity="HIGH",
            description="VLAN 1 is the default native VLAN and a common target for VLAN hopping / STP manipulation.",
            remediation="configure terminal\ninterface <INT>\nswitchport access vlan <VLAN_ID>",
        ),
        AuditRule(
            rule_id="SEC-010",
            name="Implement Switchport Port-Security",
            severity="MEDIUM",
            description="Port-Security mitigates MAC-flooding and rogue device attachment on access ports.",
            remediation="configure terminal\ninterface <INT>\nswitchport port-security\nswitchport port-security violation shutdown",
        ),
    ]

    def audit_config(self, hostname: str, ip: str, config: str) -> DeviceAuditReport:
        """Evaluates a raw configuration text and returns an audit report."""
        findings: List[AuditFinding] = []
        lines = [line.strip() for line in config.splitlines()]

        # SEC-001: Telnet check
        has_telnet = any(
            re.search(r"transport\s+input.*telnet", l, re.IGNORECASE) for l in lines
        )
        has_ssh_only = any(
            re.search(r"transport\s+input\s+ssh\b", l, re.IGNORECASE) for l in lines
        )
        if has_telnet:
            findings.append(AuditFinding(
                self.RULES[0], passed=False,
                evidence="transport input includes 'telnet'",
                details="Cleartext Telnet detected in VTY lines. Vulnerable to credential sniffing."
            ))
        elif has_ssh_only:
            findings.append(AuditFinding(
                self.RULES[0], passed=True,
                evidence="transport input ssh",
                details="VTY lines strictly restricted to encrypted SSH connections."
            ))
        else:
            findings.append(AuditFinding(
                self.RULES[0], passed=False,
                evidence="No explicit 'transport input ssh' found",
                details="VTY lines may default to insecure transports."
            ))

        # SEC-002: Enable secret check
        has_enable_secret = any(l.startswith("enable secret") for l in lines)
        has_enable_pw = any(l.startswith("enable password") for l in lines)
        if has_enable_secret and not has_enable_pw:
            findings.append(AuditFinding(
                self.RULES[1], passed=True,
                evidence="enable secret configured",
                details="Strong cryptographic hash used for privileged EXEC access."
            ))
        elif has_enable_pw:
            findings.append(AuditFinding(
                self.RULES[1], passed=False,
                evidence="enable password found in config",
                details="Weak reversible password hash detected. Upgrade to enable secret."
            ))
        else:
            findings.append(AuditFinding(
                self.RULES[1], passed=False,
                evidence="No enable secret defined",
                details="Privileged EXEC access is unauthenticated or insufficiently hardened."
            ))

        # SEC-003: Password encryption
        has_pw_encrypt = "service password-encryption" in lines
        findings.append(AuditFinding(
            self.RULES[2], passed=has_pw_encrypt,
            evidence="service password-encryption" if has_pw_encrypt else "no service password-encryption",
            details="Type 7 obfuscation active." if has_pw_encrypt else "Passwords stored in plain text."
        ))

        # SEC-004: SSH version 2
        has_ssh_v2 = any("ip ssh version 2" in l for l in lines)
        findings.append(AuditFinding(
            self.RULES[3], passed=has_ssh_v2,
            evidence="ip ssh version 2" if has_ssh_v2 else "SSH v2 not explicitly enforced",
            details="SSH v2 cryptographic suite active." if has_ssh_v2 else "Vulnerable to SSH v1 fallback."
        ))

        # SEC-005: AAA new-model
        has_aaa = any("aaa new-model" in l for l in lines)
        findings.append(AuditFinding(
            self.RULES[4], passed=has_aaa,
            evidence="aaa new-model" if has_aaa else "No AAA new-model defined",
            details="Modern access control architecture." if has_aaa else "Legacy line-based login active."
        ))

        # SEC-006: Banner MOTD
        has_banner = any("banner motd" in l.lower() for l in lines)
        findings.append(AuditFinding(
            self.RULES[5], passed=has_banner,
            evidence="banner motd present" if has_banner else "No legal banner configured",
            details="Advisory warning active." if has_banner else "Legal disclaimer missing."
        ))

        # SEC-007: NTP Server
        has_ntp = any(re.match(r"^ntp\s+server\s+\S+", l) for l in lines)
        findings.append(AuditFinding(
            self.RULES[6], passed=has_ntp,
            evidence="ntp server configured" if has_ntp else "No NTP server detected",
            details="Time-sync enables accurate syslog forensics." if has_ntp else "Clock drifts will compromise logs."
        ))

        # SEC-008: Remote Syslog
        has_logging = any(re.match(r"^logging\s+host\s+\S+", l) for l in lines)
        findings.append(AuditFinding(
            self.RULES[7], passed=has_logging,
            evidence="logging host configured" if has_logging else "No centralized syslog host",
            details="Events streamed to SIEM/central collector." if has_logging else "Local buffer only; logs lost on reboot."
        ))

        # SEC-009: VLAN 1 Usage
        has_vlan1_access = any("switchport access vlan 1" in l for l in lines)
        findings.append(AuditFinding(
            self.RULES[8], passed=not has_vlan1_access,
            evidence="VLAN 1 access ports found" if has_vlan1_access else "User ports segregated from VLAN 1",
            details="Interfaces assigned to default VLAN 1. Segregate traffic." if has_vlan1_access else "VLAN segmentation compliant."
        ))

        # SEC-010: Port-Security
        has_port_sec = any("switchport port-security" in l for l in lines)
        findings.append(AuditFinding(
            self.RULES[9], passed=has_port_sec,
            evidence="switchport port-security active" if has_port_sec else "No port-security found",
            details="MAC address limiters and violation actions configured." if has_port_sec else "Switch vulnerable to MAC flooding."
        ))

        return DeviceAuditReport(hostname=hostname, ip=ip, findings=findings)
