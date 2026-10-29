# 🛡️ PyNetAudit - Network Backup & Compliance Report
**Execution Timestamp:** `2026-10-28 22:52:39`  
**Total Devices Audited:** `5` | **Average Compliance Score:** `54.5%`

---

## 📊 Executive Summary Table

| Hostname | IP Address | Backup | Compliance Score | Grade | Status |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **rtr-wan-gateway.corp** | `192.168.1.1` | ✅ (0.4s) | **86.2%** | `B` | `MINOR_RISK` |
| **sw-access-floor1.corp** | `192.168.10.11` | ✅ (0.4s) | **6.9%** | `F` | `CRITICAL_RISK` |
| **sw-access-floor2.corp** | `192.168.10.12` | ✅ (0.4s) | **6.9%** | `F` | `CRITICAL_RISK` |
| **sw-core-01.corp** | `192.168.10.1` | ✅ (0.4s) | **86.2%** | `B` | `MINOR_RISK` |
| **sw-dmz-leaf.corp** | `192.168.20.5` | ✅ (0.4s) | **86.2%** | `B` | `MINOR_RISK` |

---

## 🔍 Detailed Findings & Remediation Guide

### 🖥️ rtr-wan-gateway.corp (`192.168.1.1`) — Score: 86.2% (Grade B)

- **Passed Checks:** 9/10
- **Failed Checks:** 1/10

| Rule ID | Severity | Failure Description | Recommended Cisco Remediation |
| :---: | :---: | :--- | :--- |
| **SEC-009** | `HIGH` | VLAN 1 is the default native VLAN and a common target for VLAN hopping / STP manipulation. | `configure terminal ; interface <INT> ; switchport access vlan <VLAN_ID>` |


### 🖥️ sw-access-floor1.corp (`192.168.10.11`) — Score: 6.9% (Grade F)

- **Passed Checks:** 1/10
- **Failed Checks:** 9/10

| Rule ID | Severity | Failure Description | Recommended Cisco Remediation |
| :---: | :---: | :--- | :--- |
| **SEC-001** | `CRITICAL` | Telnet transmits credentials and payload in cleartext. Only SSH must be accepted. | `configure terminal ; line vty 0 15 ; transport input ssh` |
| **SEC-002** | `HIGH` | Legacy 'enable password' is vulnerable to rainbow table attacks. Use 'enable secret' (Type 5/8/9). | `configure terminal ; no enable password ; enable secret <STRONG_PASSWORD>` |
| **SEC-003** | `MEDIUM` | Service password-encryption hides cleartext strings in the running configuration. | `configure terminal ; service password-encryption` |
| **SEC-004** | `HIGH` | SSH Version 1 suffers from known cryptographic flaws (CRC-32 compensation attack). | `configure terminal ; ip ssh version 2` |
| **SEC-006** | `LOW` | A legal warning banner is required for legal enforcement against unauthorized access. | `configure terminal ; banner motd ^C AUTHORIZED ACCESS ONLY ^C` |
| **SEC-007** | `MEDIUM` | Synchronized clocks are essential for accurate incident response and forensic log correlation. | `configure terminal ; ntp server 192.168.10.254` |
| **SEC-008** | `MEDIUM` | Log buffers fill quickly; events must be forwarded offsite to a SIEM/Syslog server. | `configure terminal ; logging host <SYSLOG_IP> ; logging trap warnings` |
| **SEC-009** | `HIGH` | VLAN 1 is the default native VLAN and a common target for VLAN hopping / STP manipulation. | `configure terminal ; interface <INT> ; switchport access vlan <VLAN_ID>` |
| **SEC-010** | `MEDIUM` | Port-Security mitigates MAC-flooding and rogue device attachment on access ports. | `configure terminal ; interface <INT> ; switchport port-security ; switchport port-security violation shutdown` |


### 🖥️ sw-access-floor2.corp (`192.168.10.12`) — Score: 6.9% (Grade F)

- **Passed Checks:** 1/10
- **Failed Checks:** 9/10

| Rule ID | Severity | Failure Description | Recommended Cisco Remediation |
| :---: | :---: | :--- | :--- |
| **SEC-001** | `CRITICAL` | Telnet transmits credentials and payload in cleartext. Only SSH must be accepted. | `configure terminal ; line vty 0 15 ; transport input ssh` |
| **SEC-002** | `HIGH` | Legacy 'enable password' is vulnerable to rainbow table attacks. Use 'enable secret' (Type 5/8/9). | `configure terminal ; no enable password ; enable secret <STRONG_PASSWORD>` |
| **SEC-003** | `MEDIUM` | Service password-encryption hides cleartext strings in the running configuration. | `configure terminal ; service password-encryption` |
| **SEC-004** | `HIGH` | SSH Version 1 suffers from known cryptographic flaws (CRC-32 compensation attack). | `configure terminal ; ip ssh version 2` |
| **SEC-006** | `LOW` | A legal warning banner is required for legal enforcement against unauthorized access. | `configure terminal ; banner motd ^C AUTHORIZED ACCESS ONLY ^C` |
| **SEC-007** | `MEDIUM` | Synchronized clocks are essential for accurate incident response and forensic log correlation. | `configure terminal ; ntp server 192.168.10.254` |
| **SEC-008** | `MEDIUM` | Log buffers fill quickly; events must be forwarded offsite to a SIEM/Syslog server. | `configure terminal ; logging host <SYSLOG_IP> ; logging trap warnings` |
| **SEC-009** | `HIGH` | VLAN 1 is the default native VLAN and a common target for VLAN hopping / STP manipulation. | `configure terminal ; interface <INT> ; switchport access vlan <VLAN_ID>` |
| **SEC-010** | `MEDIUM` | Port-Security mitigates MAC-flooding and rogue device attachment on access ports. | `configure terminal ; interface <INT> ; switchport port-security ; switchport port-security violation shutdown` |


### 🖥️ sw-core-01.corp (`192.168.10.1`) — Score: 86.2% (Grade B)

- **Passed Checks:** 9/10
- **Failed Checks:** 1/10

| Rule ID | Severity | Failure Description | Recommended Cisco Remediation |
| :---: | :---: | :--- | :--- |
| **SEC-009** | `HIGH` | VLAN 1 is the default native VLAN and a common target for VLAN hopping / STP manipulation. | `configure terminal ; interface <INT> ; switchport access vlan <VLAN_ID>` |


### 🖥️ sw-dmz-leaf.corp (`192.168.20.5`) — Score: 86.2% (Grade B)

- **Passed Checks:** 9/10
- **Failed Checks:** 1/10

| Rule ID | Severity | Failure Description | Recommended Cisco Remediation |
| :---: | :---: | :--- | :--- |
| **SEC-009** | `HIGH` | VLAN 1 is the default native VLAN and a common target for VLAN hopping / STP manipulation. | `configure terminal ; interface <INT> ; switchport access vlan <VLAN_ID>` |

