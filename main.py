#!/usr/bin/env python3
"""
PyNetAudit - Multi-Vendor Network Automation & Security Compliance Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Author: Rood Kerry Lucien
Repository: https://github.com/RoodKerryL/PyNetAudit
License: MIT
"""

from __future__ import annotations
import os
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import json
import argparse
import logging
from datetime import datetime
from typing import Dict, Any, List

# Optional PyYAML import with seamless JSON/simple parser fallback
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Core modules
from core.backup_manager import BackupManager, BackupResult
from core.compliance_auditor import ComplianceAuditor, DeviceAuditReport
from core.report_generator import ReportGenerator

# Optional Rich library for colorful terminal presentation
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def print_banner():
    """Prints the application startup header."""
    banner = r"""
  ____        _   _      _      _             _ _ _   
 |  _ \ _   _| \ | | ___| |_   / \  _   _  __| (_) |_ 
 | |_) | | | |  \| |/ _ \ __| / _ \| | | |/ _` | | __|
 |  __/| |_| | |\  |  __/ |_ / ___ \ |_| | (_| | | |_ 
 |_|    \__, |_| \_|\___|\__/_/   \_\__,_|\__,_|_|\__|
        |___/   Automated Network Hardening & Backup Engine
    """
    if RICH_AVAILABLE:
        console.print(Panel(
            f"[bold cyan]{banner}[/bold cyan]\n"
            f"[bold white]Author:[/bold white] Rood Kerry Lucien | [bold white]Role:[/bold white] Network & Systems Engineer\n"
            f"[bold green]Standards:[/bold green] CIS Cisco Benchmarks, NIST SP 800-123 Hardening",
            border_style="cyan"
        ))
    else:
        print(banner)
        print("Author: Rood Kerry Lucien | Network & Systems Engineer\n" + "=" * 65)


def load_inventory(inventory_path: str) -> List[Dict[str, Any]]:
    """Loads and validates the YAML or JSON inventory file."""
    # If YAML is requested but PyYAML is not installed, fallback to JSON companion if present
    target_path = inventory_path
    if not YAML_AVAILABLE and inventory_path.endswith((".yaml", ".yml")):
        json_alt = os.path.splitext(inventory_path)[0] + ".json"
        if os.path.exists(json_alt):
            target_path = json_alt

    if not os.path.exists(target_path):
        raise FileNotFoundError(f"Inventory file not found: {target_path}")

    with open(target_path, "r", encoding="utf-8") as f:
        if target_path.endswith(".json") or not YAML_AVAILABLE:
            data = json.load(f)
        else:
            data = yaml.safe_load(f)

    devices = data.get("devices", [])
    if not devices:
        raise ValueError(f"Inventory file '{target_path}' does not contain any devices under 'devices:' key.")
    return devices


def main():
    parser = argparse.ArgumentParser(
        description="PyNetAudit: Automated network device backup and security compliance engine."
    )
    parser.add_argument(
        "--inventory", "-i",
        default="inventory/devices.yaml",
        help="Path to the YAML device inventory file (default: inventory/devices.yaml)"
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=5,
        help="Maximum concurrent SSH connections (default: 5)"
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run in mock/dry-run mode without live hardware (ideal for demonstrations)"
    )
    parser.add_argument(
        "--site",
        type=str,
        default=None,
        help="Filter execution to devices matching a specific site"
    )
    parser.add_argument(
        "--backup-only",
        action="store_true",
        help="Perform configuration backups only, skip security compliance audit"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging output"
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
        datefmt="%H:%M:%S",
    )

    print_banner()

    # 1. Load Inventory
    try:
        devices = load_inventory(args.inventory)
        if args.site:
            devices = [d for d in devices if d.get("site", "").lower() == args.site.lower()]
            if not devices:
                print(f"[!] No devices found matching site '{args.site}'.")
                sys.exit(1)
        print(f"[*] Loaded {len(devices)} target device(s) from '{args.inventory}'")
        if args.mock:
            print("[*] Running in MOCK / LAB SIMULATION mode.")
    except Exception as e:
        print(f"[ERROR] Failed to load inventory: {e}")
        sys.exit(1)

    # 2. Execute Backups
    print(f"\n[1/3] Initiating concurrent configuration backups (workers={args.workers})...")
    backup_mgr = BackupManager(
        backup_dir="backups",
        max_workers=args.workers,
        mock_mode=args.mock,
    )

    backup_results: List[BackupResult] = []

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Connecting and pulling configurations...", total=len(devices))

            def on_backup_done(result: BackupResult):
                progress.advance(task)

            backup_results = backup_mgr.run_all(devices, callback=on_backup_done)
    else:
        backup_results = backup_mgr.run_all(devices)

    success_count = sum(1 for b in backup_results if b.success)
    print(f"[OK] Backups completed: {success_count}/{len(devices)} successful.")

    # 3. Execute Compliance Audit
    audit_reports: List[DeviceAuditReport] = []
    if not args.backup_only:
        print(f"\n[2/3] Evaluating security compliance against CIS Benchmarks...")
        auditor = ComplianceAuditor()

        for backup in backup_results:
            if backup.success and backup.config:
                report = auditor.audit_config(backup.hostname, backup.ip, backup.config)
                audit_reports.append(report)
            else:
                # Placeholder for failed device
                report = auditor.audit_config(backup.hostname, backup.ip, "! Backup failed")
                audit_reports.append(report)

        print(f"[OK] Security audit completed for {len(audit_reports)} device(s).")

        # 4. Generate Reports
        print(f"\n[3/3] Generating executive reports and HTML dashboard...")
        rep_gen = ReportGenerator(reports_dir="reports")
        md_path = rep_gen.generate_markdown(backup_results, audit_reports)
        html_path = rep_gen.generate_html(backup_results, audit_reports)

        print(f"[+] Markdown summary generated : {md_path}")
        print(f"[+] Modern HTML dashboard      : {html_path}")

    # 5. Display Terminal Summary Table
    if RICH_AVAILABLE and audit_reports:
        table = Table(title="PyNetAudit - Execution Summary", show_header=True, header_style="bold magenta")
        table.add_column("Hostname", style="bold")
        table.add_column("IP Address", style="dim")
        table.add_column("Backup", justify="center")
        table.add_column("Score", justify="right")
        table.add_column("Grade", justify="center")
        table.add_column("Status", justify="left")

        for audit, backup in zip(audit_reports, backup_results):
            b_str = "[green]OK[/green]" if backup.success else "[red]FAIL[/red]"
            grade_color = "green" if audit.grade in ("A", "B") else ("yellow" if audit.grade == "C" else "red")
            table.add_row(
                audit.hostname,
                audit.ip,
                b_str,
                f"{audit.score}%",
                f"[{grade_color}]{audit.grade}[/{grade_color}]",
                f"[{grade_color}]{audit.status}[/{grade_color}]"
            )

        console.print("\n", table)
    else:
        print("\n" + "=" * 65)
        print(f"{'Hostname':<24} {'IP':<16} {'Backup':<8} {'Score':<8} {'Grade'}")
        print("=" * 65)
        for audit, backup in zip(audit_reports, backup_results):
            b_str = "OK" if backup.success else "FAIL"
            score_str = f"{audit.score}%"
            print(f"{audit.hostname:<24} {audit.ip:<16} {b_str:<8} {score_str:<10} {audit.grade}")
        print("=" * 65)

    print("\n[+] Audit session finished successfully! Open the HTML report in your browser to inspect details.")


if __name__ == "__main__":
    main()
