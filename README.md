# 🛡️ PyNetAudit — Enterprise Network Automation & Security Compliance Engine

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Netmiko](https://img.shields.io/badge/Automation-Netmiko%20SSH-orange.svg)](https://github.com/ktbyers/netmiko)
[![Security Standard](https://img.shields.io/badge/Security-CIS%20Cisco%20Benchmark-brightgreen.svg)](https://www.cisecurity.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Rood%20Kerry%20Lucien-0ea5e9.svg)](https://github.com/RoodKerryL)

> **PyNetAudit** is a production-grade NetDevOps automation engine built in Python. It automates concurrent configuration backups across multi-vendor network fleets (Cisco IOS, Arista EOS, Juniper JunOS) and performs automated security compliance audits against **CIS Benchmarks** and **NIST SP 800-123** hardening guidelines.

---

## 🎯 The Real-World Engineering Problem

In medium-to-large enterprise networks, network administrators frequently face two major risks:
1. **Unreliable Disaster Recovery:** Configuration changes are made ad-hoc without automated, versioned daily backups.
2. **Security Regressions & Blind Spots:** Switches and routers accumulate insecure legacy settings over time (Telnet left open, weak passwords, unencrypted passwords in running-configs, default VLAN 1 on active user access ports, missing Syslog forwarding).

**PyNetAudit** solves both challenges simultaneously in a single, fast, automated multi-threaded pipeline.

---

## 🏗️ Architecture & Workflow

```text
  +-------------------------+
  |   inventory/devices     |
  |      (YAML / JSON)      |
  +------------+------------+
               |
               v
  +-----------------------------------------------------------+
  |               PyNetAudit Orchestrator                     |
  |     Concurrent Multi-Threading (ThreadPoolExecutor)       |
  +------------+------------------------------+---------------+
               |                              |
               v (SSH / Netmiko)              v (Lab / Demo)
  +-------------------------+    +-------------------------+
  |   Live Network Fleet    |    |     Mock Simulation     |
  |  - Core & Distribution  |    |   - Hardened Switches   |
  |  - Access Switches      |    |   - Vulnerable Switches |
  |  - WAN Edge Routers     |    +------------+------------+
  +------------+------------+                 |
               |                              |
               +--------------+---------------+
                              |
                              v
             +--------------------------------+
             | Running-Configuration Snapshot |
             |   Saved: backups/YYYY-MM-DD/   |
             +----------------+---------------+
                              |
                              v
             +--------------------------------+
             |    Security Compliance Audit   |
             |   10 CIS Baseline Hardening    |
             |   Rules Evaluated with Regex   |
             +----------------+---------------+
                              |
            +-----------------+-----------------+
            |                                   |
            v                                   v
+-----------------------+           +-----------------------+
|  Markdown Executive   |           | Modern HTML Dashboard |
|        Report         |           | (Dark Mode + Actions) |
|  audit_summary.md     |           |   audit_report.html   |
+-----------------------+           +-----------------------+
```

---

## ✨ Key Features

- ⚡ **High-Speed Multi-Threading:** Backs up dozens of network appliances in parallel using Python's `concurrent.futures.ThreadPoolExecutor`.
- 🔒 **CIS & NIST Compliance Engine:** Automatically audits 10 critical security criteria per device and calculates a compliance score (0–100%) and letter grade (`A`, `B`, `C`, `D`, `F`).
- 📁 **Structured Archiving:** Organizes configuration snapshots by date (`backups/YYYY-MM-DD/{hostname}_{timestamp}.cfg`) with a persistent `latest/` symlink/directory for Git diffing.
- 🛠️ **Actionable Remediation Snippets:** Every detected vulnerability includes the exact copy-paste Cisco CLI commands required to resolve it.
- 📊 **Multi-Format Reporting:**
  - Executive **Markdown Report** (`reports/YYYY-MM-DD/audit_summary.md`)
  - Standalone, responsive **HTML Dashboard** (`reports/YYYY-MM-DD/audit_report.html`) in modern dark mode.
  - JSON data export (`audit_summary.json`) for SIEM or webhook integrations.
- 🧪 **Zero-Hardware Mock Mode:** Built-in `--mock` flag simulates enterprise devices and vulnerability detection immediately without requiring physical switches.

---

## 📋 Security Audit Rules Catalog

PyNetAudit evaluates running configurations against 10 fundamental hardening baselines:

| Rule ID | Severity | Audit Target | Objective / Vulnerability Addressed |
| :---: | :---: | :--- | :--- |
| **SEC-001** | `CRITICAL` | VTY Transports | Enforce `transport input ssh`. Rejects cleartext Telnet. |
| **SEC-002** | `HIGH` | Privileged EXEC | Enforces `enable secret` (SHA-256/Type 5/8/9). Flags weak `enable password`. |
| **SEC-003** | `MEDIUM` | Password Encryption | Verifies `service password-encryption` is enabled. |
| **SEC-004** | `HIGH` | SSH Protocol | Requires `ip ssh version 2` to prevent SSH v1 fallback attacks. |
| **SEC-005** | `MEDIUM` | AAA Architecture | Checks for `aaa new-model` and centralized authentication. |
| **SEC-006** | `LOW` | Warning Banner | Verifies legal login warning banner (`banner motd`). |
| **SEC-007** | `MEDIUM` | Clock Sync (NTP) | Ensures centralized `ntp server` is configured for log correlation. |
| **SEC-008** | `MEDIUM` | Remote Syslog | Checks for external `logging host` forwarding to a SIEM/collector. |
| **SEC-009** | `HIGH` | VLAN 1 Containment | Detects and flags active switchports assigned to default native VLAN 1. |
| **SEC-010** | `MEDIUM` | Port-Security | Verifies MAC limiting and shutdown violation actions on access ports. |

---

## 🚀 Quick Start Guide

### 1. Clone the Repository
```bash
git clone https://github.com/RoodKerryL/PyNetAudit.git
cd PyNetAudit
```

### 2. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 3. Run the Demonstration (Mock Simulation Mode)
No live physical network equipment is required to test the entire pipeline:
```bash
python main.py --mock
```

**Expected Terminal Output:**
```text
  ____        _   _      _      _             _ _ _   
 |  _ \ _   _| \ | | ___| |_   / \  _   _  __| (_) |_ 
 | |_) | | | |  \| |/ _ \ __| / _ \| | | |/ _` | | __|
 |  __/| |_| | |\  |  __/ |_ / ___ \ |_| | (_| | | |_ 
 |_|    \__, |_| \_|\___|\__/_/   \_\__,_|\__,_|_|\__|
        |___/   Automated Network Hardening & Backup Engine
    
Author: Rood Kerry Lucien | Network & Systems Engineer
=================================================================
[*] Loaded 5 target device(s) from 'inventory/devices.yaml'
[*] Running in MOCK / LAB SIMULATION mode.

[1/3] Initiating concurrent configuration backups (workers=5)...
[OK] Backups completed: 5/5 successful.

[2/3] Evaluating security compliance against CIS Benchmarks...
[OK] Security audit completed for 5 device(s).

[3/3] Generating executive reports and HTML dashboard...
[+] Markdown summary generated : reports/2026-10-28/audit_summary.md
[+] Modern HTML dashboard      : reports/2026-10-28/audit_report.html

=================================================================
Hostname                 IP               Backup   Score      Grade
=================================================================
rtr-wan-gateway.corp     192.168.1.1      OK       86.2%      B
sw-access-floor1.corp    192.168.10.11    OK       6.9%       F
sw-access-floor2.corp    192.168.10.12    OK       6.9%       F
sw-core-01.corp          192.168.10.1     OK       86.2%      B
sw-dmz-leaf.corp         192.168.20.5     OK       86.2%      B
=================================================================
```

---

## ⚙️ Configuration & Live Production Usage

### 1. Configure Target Inventory (`inventory/devices.yaml`)
Define your switches, routers, and firewalls:
```yaml
devices:
  - hostname: "sw-core-01.corp"
    ip: "10.100.1.1"
    device_type: "cisco_ios"
    role: "Core Switch"
    site: "HQ-Datacenter"
    port: 22

  - hostname: "sw-access-01.corp"
    ip: "10.100.2.10"
    device_type: "cisco_ios"
    role: "Access Switch"
    site: "Branch-North"
    port: 22
```

### 2. Set Credentials via Environment Variables (`.env`)
```bash
cp .env.example .env
```
Edit `.env` with your SSH administrative credentials:
```env
NET_DEFAULT_USERNAME=admin
NET_DEFAULT_PASSWORD=YourSecurePasswordHere!
NET_DEFAULT_SECRET=YourEnableSecretHere!
```

### 3. Run Live Execution
```bash
# Run full backup and audit on all devices
python main.py

# Filter by a specific geographic site
python main.py --site "Branch-North"

# Run with 10 parallel threads
python main.py --workers 10

# Backup only (skip audit)
python main.py --backup-only
```

---

## 📈 HTML Dashboard Preview

The generated `reports/YYYY-MM-DD/audit_report.html` file provides a self-contained, interactive audit report featuring:
- **Global KPI Cards:** Total audited devices, average network compliance percentage, total validated rules, and active security vulnerabilities.
- **Per-Device Cards:** Compliance score percentage, letter grade badge (`A` to `F`), and backup status indicator.
- **Interactive Rule Grid:** Expandable breakdown of each rule with pass/fail indicators, detected configuration evidence, and remediation CLI commands.

---

## 👨‍💻 Author

**Rood Kerry Lucien**  
*Systems & Network Engineer | IT Infrastructure Specialist | Web Developer*  
- **Portfolio:** [roodkerryl.github.io](https://roodkerryl.github.io)
- **LinkedIn:** [linkedin.com/in/jean-rood-kerry-l](https://www.linkedin.com/in/jean-rood-kerry-l/)
- **GitHub:** [@RoodKerryL](https://github.com/RoodKerryL)

---

## 📄 License
This project is open-source under the [MIT License](LICENSE).
