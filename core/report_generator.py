"""
Report Generator Module
~~~~~~~~~~~~~~~~~~~~~~~
Generates clean Markdown summaries and modern HTML compliance dashboards
with charts, pass/fail badges, and copyable remediation snippets.
"""

from __future__ import annotations
import os
import json
from datetime import datetime
from typing import List, Dict, Any
from .backup_manager import BackupResult
from .compliance_auditor import DeviceAuditReport


class ReportGenerator:
    """Produces Markdown and modern HTML reports from audit outcomes."""

    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        self.today_str = datetime.now().strftime("%Y-%m-%d")
        self.session_dir = os.path.join(self.reports_dir, self.today_str)
        os.makedirs(self.session_dir, exist_ok=True)

    def generate_markdown(
        self,
        backup_results: List[BackupResult],
        audit_reports: List[DeviceAuditReport],
    ) -> str:
        """Builds a GitHub-flavored Markdown report."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_dev = len(audit_reports)
        avg_score = round(sum(r.score for r in audit_reports) / total_dev, 1) if total_dev > 0 else 0

        md = []
        md.append(f"# 🛡️ PyNetAudit - Network Backup & Compliance Report")
        md.append(f"**Execution Timestamp:** `{now}`  ")
        md.append(f"**Total Devices Audited:** `{total_dev}` | **Average Compliance Score:** `{avg_score}%`\n")
        md.append("---\n")

        md.append("## 📊 Executive Summary Table\n")
        md.append("| Hostname | IP Address | Backup | Compliance Score | Grade | Status |")
        md.append("| :--- | :--- | :---: | :---: | :---: | :--- |")

        for audit, backup in zip(audit_reports, backup_results):
            b_icon = "✅" if backup.success else "❌"
            status_badge = f"`{audit.status}`"
            md.append(
                f"| **{audit.hostname}** | `{audit.ip}` | {b_icon} ({backup.duration:.1f}s) | "
                f"**{audit.score}%** | `{audit.grade}` | {status_badge} |"
            )

        md.append("\n---\n")
        md.append("## 🔍 Detailed Findings & Remediation Guide\n")

        for audit in audit_reports:
            md.append(f"### 🖥️ {audit.hostname} (`{audit.ip}`) — Score: {audit.score}% (Grade {audit.grade})\n")
            md.append(f"- **Passed Checks:** {audit.passed_rules}/{audit.total_rules}")
            md.append(f"- **Failed Checks:** {audit.failed_rules}/{audit.total_rules}\n")

            failed_findings = [f for f in audit.findings if not f.passed]
            if not failed_findings:
                md.append("> ✅ **Device is fully compliant with all security hardening baseline rules.**\n")
                continue

            md.append("| Rule ID | Severity | Failure Description | Recommended Cisco Remediation |")
            md.append("| :---: | :---: | :--- | :--- |")
            for f in failed_findings:
                clean_remed = f.rule.remediation.replace("\n", " ; ")
                md.append(
                    f"| **{f.rule.rule_id}** | `{f.rule.severity}` | {f.rule.description} | "
                    f"`{clean_remed}` |"
                )
            md.append("\n")

        filepath = os.path.join(self.session_dir, "audit_summary.md")
        with open(filepath, "w", encoding="utf-8") as file:
            file.write("\n".join(md))

        # Also write JSON summary
        json_path = os.path.join(self.session_dir, "audit_summary.json")
        with open(json_path, "w", encoding="utf-8") as jfile:
            json.dump([a.to_dict() for a in audit_reports], jfile, indent=2)

        return filepath

    def generate_html(
        self,
        backup_results: List[BackupResult],
        audit_reports: List[DeviceAuditReport],
    ) -> str:
        """Generates a standalone, responsive, premium dark-mode HTML dashboard."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_dev = len(audit_reports)
        avg_score = round(sum(r.score for r in audit_reports) / total_dev, 1) if total_dev > 0 else 0
        total_passed = sum(r.passed_rules for r in audit_reports)
        total_failed = sum(r.failed_rules for r in audit_reports)

        # Build device cards HTML
        cards_html = []
        for audit, backup in zip(audit_reports, backup_results):
            b_badge = '<span class="badge badge-success">Backup OK</span>' if backup.success else '<span class="badge badge-danger">Backup Failed</span>'
            grade_class = f"grade-{audit.grade.lower()}"
            
            failed_list_html = []
            for f in audit.findings:
                status_icon = "✅" if f.passed else "⚠️"
                row_class = "row-pass" if f.passed else "row-fail"
                sev_badge = f'<span class="badge badge-{f.rule.severity.lower()}">{f.rule.severity}</span>'
                failed_list_html.append(f"""
                <tr class="{row_class}">
                    <td><strong>{f.rule.rule_id}</strong></td>
                    <td>{sev_badge}</td>
                    <td>{f.rule.name}</td>
                    <td>{status_icon} {f.details}</td>
                    <td><code>{f.rule.remediation.replace(chr(10), '<br>')}</code></td>
                </tr>
                """)

            cards_html.append(f"""
            <div class="device-card">
                <div class="device-header">
                    <div class="device-title">
                        <h3>{audit.hostname}</h3>
                        <span class="device-ip">{audit.ip}</span>
                    </div>
                    <div class="device-badges">
                        {b_badge}
                        <div class="grade-pill {grade_class}">Grade {audit.grade} ({audit.score}%)</div>
                    </div>
                </div>

                <div class="device-stats">
                    <div class="stat-box">
                        <span class="stat-label">Conformité</span>
                        <span class="stat-val">{audit.score}%</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">Règles Valides</span>
                        <span class="stat-val text-success">{audit.passed_rules} / {audit.total_rules}</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">Vulnérabilités</span>
                        <span class="stat-val text-danger">{audit.failed_rules}</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">Fichier Sauvegarde</span>
                        <span class="stat-val stat-file">{os.path.basename(backup.filepath) if backup.filepath else 'N/A'}</span>
                    </div>
                </div>

                <details class="findings-details">
                    <summary>Afficher la grille d'évaluation des règles ({len(audit.findings)} vérifications)</summary>
                    <div class="table-wrap">
                        <table class="findings-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Sévérité</th>
                                    <th>Règle Hardening</th>
                                    <th>Constat & Détails</th>
                                    <th>Action Corrective (CLI)</th>
                                </tr>
                            </thead>
                            <tbody>
                                {"".join(failed_list_html)}
                            </tbody>
                        </table>
                    </div>
                </details>
            </div>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyNetAudit - Rapport de Sauvegarde & Conformité Réseau</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-hover: #1f2937;
            --border: rgba(255, 255, 255, 0.08);
            --text: #f9fafb;
            --muted: #9ca3af;
            --accent: #2563eb;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --critical: #dc2626;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 2.5rem 1.5rem; line-height: 1.5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ margin-bottom: 2.5rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }}
        .header-top {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }}
        h1 {{ font-size: 1.85rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.6rem; }}
        .meta {{ color: var(--muted); font-size: 0.9rem; margin-top: 0.4rem; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.25rem; margin-bottom: 2.5rem; }}
        .kpi-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; }}
        .kpi-label {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .kpi-val {{ font-size: 2rem; font-weight: 700; margin-top: 0.35rem; color: #fff; }}
        .device-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .device-header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.25rem; }}
        .device-title h3 {{ font-size: 1.3rem; color: #fff; }}
        .device-ip {{ color: var(--muted); font-size: 0.85rem; font-family: monospace; }}
        .device-badges {{ display: flex; align-items: center; gap: 0.75rem; }}
        .badge {{ padding: 0.35rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
        .badge-success {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-critical {{ background: rgba(220, 38, 38, 0.25); color: #fca5a5; }}
        .badge-high {{ background: rgba(245, 158, 11, 0.2); color: #fcd34d; }}
        .badge-medium {{ background: rgba(59, 130, 246, 0.2); color: #93c5fd; }}
        .badge-low {{ background: rgba(107, 114, 128, 0.2); color: #d1d5db; }}
        .grade-pill {{ font-weight: 700; font-size: 0.9rem; padding: 0.35rem 0.9rem; border-radius: 8px; }}
        .grade-a {{ background: #065f46; color: #a7f3d0; }}
        .grade-b {{ background: #1e3a8a; color: #bfdbfe; }}
        .grade-c {{ background: #78350f; color: #fde68a; }}
        .grade-d {{ background: #831843; color: #fbcfe8; }}
        .grade-f {{ background: #7f1d1d; color: #fecaca; }}
        .device-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; background: rgba(0,0,0,0.25); padding: 1rem; border-radius: 10px; margin-bottom: 1.25rem; }}
        .stat-label {{ font-size: 0.75rem; color: var(--muted); }}
        .stat-val {{ font-size: 1.15rem; font-weight: 600; margin-top: 0.2rem; display: block; }}
        .stat-file {{ font-family: monospace; font-size: 0.85rem; color: #93c5fd; }}
        .text-success {{ color: #34d399; }}
        .text-danger {{ color: #f87171; }}
        details {{ border-top: 1px solid var(--border); padding-top: 1rem; }}
        summary {{ cursor: pointer; color: #60a5fa; font-weight: 500; font-size: 0.9rem; }}
        summary:hover {{ text-decoration: underline; }}
        .table-wrap {{ overflow-x: auto; margin-top: 1rem; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left; }}
        th, td {{ padding: 0.75rem 0.85rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
        th {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; }}
        tr.row-fail {{ background: rgba(239, 68, 68, 0.05); }}
        code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: rgba(0,0,0,0.4); padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.8rem; color: #e2e8f0; line-height: 1.4; display: inline-block; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-top">
                <h1>🛡️ PyNetAudit — Rapport de Conformité Réseau</h1>
                <span class="badge badge-success">Moteur v1.0.0</span>
            </div>
            <p class="meta">Généré le {now} | Ingénieur : <strong>Rood Kerry Lucien</strong></p>
        </header>

        <section class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Équipements Audités</div>
                <div class="kpi-val">{total_dev}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Score Moyen Conformité</div>
                <div class="kpi-val" style="color: {'#34d399' if avg_score >= 80 else '#fcd34d'};">{avg_score}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Règles Validées</div>
                <div class="kpi-val text-success">{total_passed}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Vulnérabilités Détectées</div>
                <div class="kpi-val text-danger">{total_failed}</div>
            </div>
        </section>

        <section>
            {"".join(cards_html)}
        </section>
    </div>
</body>
</html>
"""
        filepath = os.path.join(self.session_dir, "audit_report.html")
        with open(filepath, "w", encoding="utf-8") as hfile:
            hfile.write(html_content)

        return filepath
