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
            risk_cat = "compliant" if audit.grade in ("A", "B") else "vulnerable"
            
            failed_list_html = []
            for f in audit.findings:
                status_icon = "✅" if f.passed else "⚠️"
                row_class = "row-pass" if f.passed else "row-fail"
                sev_badge = f'<span class="badge badge-{f.rule.severity.lower()}">{f.rule.severity}</span>'
                escaped_remed = f.rule.remediation.replace('"', '&quot;').replace("'", "&#39;")
                failed_list_html.append(f"""
                <tr class="{row_class}">
                    <td><strong>{f.rule.rule_id}</strong></td>
                    <td>{sev_badge}</td>
                    <td>{f.rule.name}</td>
                    <td>{status_icon} {f.details}</td>
                    <td>
                        <code>{f.rule.remediation.replace(chr(10), '<br>')}</code>
                        <button class="btn-copy-cli" onclick="copyCli('{escaped_remed}', this)">Copier CLI</button>
                    </td>
                </tr>
                """)

            cards_html.append(f"""
            <div class="device-card" data-risk="{risk_cat}">
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

                <details class="findings-details" open>
                    <summary>Afficher la grille d'évaluation des règles ({len(audit.findings)} vérifications)</summary>
                    <div class="table-wrap">
                        <table class="findings-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Sévérité</th>
                                    <th>Règle Hardening</th>
                                    <th>Constat & Détails</th>
                                    <th>Action Corrective (CLI Cisco)</th>
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
    <title>PyNetAudit - Dashboard & Bac à Sable Interactif</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-hover: #1f2937;
            --border: rgba(255, 255, 255, 0.08);
            --text: #f9fafb;
            --muted: #9ca3af;
            --accent: #0ea5e9;
            --accent-glow: rgba(14, 165, 233, 0.25);
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --critical: #dc2626;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 2.5rem 1.5rem; line-height: 1.5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }}
        .header-top {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }}
        h1 {{ font-size: 1.85rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.6rem; }}
        .meta {{ color: var(--muted); font-size: 0.9rem; margin-top: 0.4rem; }}
        
        /* Actions Bar */
        .interactive-bar {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; background: var(--surface); border: 1px solid var(--border); padding: 1rem 1.25rem; border-radius: 12px; margin-bottom: 2rem; }}
        .action-btns {{ display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }}
        .btn {{ padding: 0.65rem 1.2rem; border-radius: 8px; font-weight: 600; font-size: 0.9rem; cursor: pointer; transition: all 0.2s ease; border: none; display: inline-flex; align-items: center; gap: 0.5rem; }}
        .btn-primary {{ background: var(--accent); color: #fff; box-shadow: 0 4px 14px var(--accent-glow); }}
        .btn-primary:hover {{ background: #0284c7; transform: translateY(-1px); }}
        .btn-secondary {{ background: rgba(255,255,255,0.06); color: #fff; border: 1px solid var(--border); }}
        .btn-secondary:hover {{ background: rgba(255,255,255,0.1); }}
        
        /* Filter tabs */
        .filter-tabs {{ display: flex; gap: 0.5rem; }}
        .filter-tab {{ background: transparent; border: 1px solid var(--border); color: var(--muted); padding: 0.45rem 0.85rem; border-radius: 6px; font-size: 0.82rem; cursor: pointer; font-weight: 500; }}
        .filter-tab.active {{ background: rgba(14, 165, 233, 0.15); color: var(--accent); border-color: var(--accent); }}

        /* KPI Grid */
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.25rem; margin-bottom: 2.5rem; }}
        .kpi-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; transition: transform 0.2s ease; }}
        .kpi-card:hover {{ transform: translateY(-2px); }}
        .kpi-label {{ color: var(--muted); font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .kpi-val {{ font-size: 2rem; font-weight: 700; margin-top: 0.35rem; color: #fff; }}
        
        /* Interactive Sandbox Section */
        .sandbox-box {{ display: none; background: #0b1120; border: 1px solid var(--accent); border-radius: 14px; padding: 1.5rem; margin-bottom: 2.5rem; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
        .sandbox-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }}
        .sandbox-title {{ font-size: 1.15rem; font-weight: 600; color: #fff; display: flex; align-items: center; gap: 0.5rem; }}
        .sandbox-textarea {{ width: 100%; height: 180px; background: #050811; border: 1px solid var(--border); border-radius: 8px; color: #34d399; font-family: monospace; font-size: 0.85rem; padding: 1rem; line-height: 1.4; resize: vertical; margin-bottom: 1rem; outline: none; }}
        .sandbox-textarea:focus {{ border-color: var(--accent); }}
        .sandbox-controls {{ display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: center; }}
        .sandbox-result {{ margin-top: 1.5rem; display: none; }}

        /* Terminal Simulation Modal */
        .terminal-overlay {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.85); backdrop-filter: blur(8px); z-index: 9999; align-items: center; justify-content: center; padding: 1.5rem; }}
        .terminal-box {{ width: 100%; max-width: 800px; background: #050811; border: 1px solid rgba(14, 165, 233, 0.4); border-radius: 12px; overflow: hidden; box-shadow: 0 20px 50px rgba(0,0,0,0.8); }}
        .terminal-top {{ background: #0b1120; padding: 0.75rem 1rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); }}
        .terminal-dots {{ display: flex; gap: 6px; }}
        .terminal-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
        .dot-red {{ background: #ef4444; }} .dot-yellow {{ background: #f59e0b; }} .dot-green {{ background: #10b981; }}
        .terminal-body {{ padding: 1.25rem; font-family: monospace; font-size: 0.85rem; height: 350px; overflow-y: auto; color: #f9fafb; line-height: 1.5; }}
        .log-info {{ color: #38bdf8; }} .log-ok {{ color: #34d399; }} .log-warn {{ color: #fbbf24; }} .log-err {{ color: #f87171; }}
        
        /* Device Cards */
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
        
        .btn-copy-cli {{ background: rgba(255,255,255,0.08); border: 1px solid var(--border); color: #cbd5e1; padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.75rem; cursor: pointer; margin-top: 0.4rem; display: block; }}
        .btn-copy-cli:hover {{ background: rgba(255,255,255,0.15); color: #fff; }}
        
        /* Toast notification */
        .toast-notif {{ position: fixed; bottom: 20px; right: 20px; background: #10b981; color: #fff; padding: 0.75rem 1.25rem; border-radius: 8px; font-weight: 600; font-size: 0.85rem; display: none; z-index: 10000; box-shadow: 0 10px 25px rgba(0,0,0,0.4); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-top">
                <h1>🛡️ PyNetAudit — Rapport & Centre de Test Réseau</h1>
                <span class="badge badge-success">Moteur v1.0.0</span>
            </div>
            <p class="meta">Généré le {now} | Ingénieur : <strong>Rood Kerry Lucien</strong></p>
        </header>

        <!-- Barre d'actions interactives -->
        <div class="interactive-bar">
            <div class="action-btns">
                <button class="btn btn-primary" onclick="startLiveSimulation()">
                    <span>▶ Relancer la Simulation en Direct</span>
                </button>
                <button class="btn btn-secondary" onclick="toggleSandbox()">
                    <span>🧪 Bac à Sable (Tester une config personnalisée)</span>
                </button>
                <a href="/#projects" class="btn btn-secondary" style="text-decoration:none;">
                    <span>⬅ Retour au Portfolio</span>
                </a>
            </div>

            <div class="filter-tabs">
                <button class="filter-tab active" onclick="filterDevices('all', this)">Tous ({total_dev})</button>
                <button class="filter-tab" onclick="filterDevices('compliant', this)">Conformes (3)</button>
                <button class="filter-tab" onclick="filterDevices('vulnerable', this)">À Corriger (2)</button>
            </div>
        </div>

        <!-- Bac à Sable de Test Interactif -->
        <div class="sandbox-box" id="sandbox-box">
            <div class="sandbox-header">
                <div class="sandbox-title">🧪 Testeur de Sécurité CIS en Direct (Analyse Instantanée)</div>
                <button class="btn-copy-cli" onclick="toggleSandbox()">✕ Fermer</button>
            </div>
            <p style="color:var(--muted); font-size:0.85rem; margin-bottom:0.75rem;">
                Collez n'importe quelle configuration Cisco ou chargez un exemple pour exécuter instantanément le moteur de détection des 10 règles CIS :
            </p>
            <textarea class="sandbox-textarea" id="sandbox-input" placeholder="Collez votre configuration Cisco ici..."></textarea>
            <div class="sandbox-controls">
                <button class="btn btn-primary" onclick="runSandboxAudit()">🔍 Analyser cette configuration</button>
                <button class="btn btn-secondary" onclick="loadSampleConfig('vulnerable')">Charger exemple vulnérable</button>
                <button class="btn btn-secondary" onclick="loadSampleConfig('hardened')">Charger exemple durci</button>
                <button class="btn btn-secondary" onclick="document.getElementById('sandbox-input').value=''">Effacer</button>
            </div>
            <div class="sandbox-result" id="sandbox-result"></div>
        </div>

        <!-- Section KPIs -->
        <section class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">Équipements Audités</div>
                <div class="kpi-val" id="kpi-total">{total_dev}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Score Moyen Conformité</div>
                <div class="kpi-val" id="kpi-score" style="color: {'#34d399' if avg_score >= 80 else '#fcd34d'};">{avg_score}%</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Règles Validées</div>
                <div class="kpi-val text-success" id="kpi-passed">{total_passed}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Vulnérabilités Détectées</div>
                <div class="kpi-val text-danger" id="kpi-failed">{total_failed}</div>
            </div>
        </section>

        <!-- Liste des Équipements Audités -->
        <section id="devices-list">
            {"".join(cards_html)}
        </section>
    </div>

    <!-- Modal Terminal de Simulation en direct -->
    <div class="terminal-overlay" id="terminal-modal">
        <div class="terminal-box">
            <div class="terminal-top">
                <div class="terminal-dots">
                    <span class="terminal-dot dot-red" onclick="closeTerminal()"></span>
                    <span class="terminal-dot dot-yellow"></span>
                    <span class="terminal-dot dot-green"></span>
                </div>
                <span style="font-size:0.85rem; color:#94a3b8; font-family:monospace;">PyNetAudit CLI Orchestrator — Live SSH Simulation</span>
                <button class="btn-copy-cli" onclick="closeTerminal()">Fermer</button>
            </div>
            <div class="terminal-body" id="terminal-console"></div>
        </div>
    </div>

    <!-- Notification Toast -->
    <div class="toast-notif" id="toast-notif">Commande CLI copiée dans le presse-papier !</div>

    <script>
        // Copy CLI remediation commands
        function copyCli(cmd, btn) {{
            const text = cmd.replace(/<br>/g, '\\n').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
            navigator.clipboard.writeText(text).then(() => {{
                showToast("Commande CLI copiée !");
                const oldText = btn.textContent;
                btn.textContent = "✓ Copié !";
                setTimeout(() => {{ btn.textContent = oldText; }}, 1800);
            }});
        }}

        function showToast(msg) {{
            const toast = document.getElementById('toast-notif');
            toast.textContent = msg;
            toast.style.display = 'block';
            setTimeout(() => {{ toast.style.display = 'none'; }}, 2200);
        }}

        // Filter devices
        function filterDevices(cat, btn) {{
            document.querySelectorAll('.filter-tab').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            document.querySelectorAll('.device-card').forEach(card => {{
                const risk = card.getAttribute('data-risk');
                if (cat === 'all' || risk === cat) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        // Terminal Live Simulation
        function startLiveSimulation() {{
            const modal = document.getElementById('terminal-modal');
            const con = document.getElementById('terminal-console');
            modal.style.display = 'flex';
            con.innerHTML = '';

            const logs = [
                "[INFO] Initialisation de PyNetAudit Orchestrator (Multi-threaded workers=5)...",
                "[INFO] Chargement de l'inventaire : 5 équipements réseau ciblés.",
                "[SSH] Connexion simultanée vers sw-core-01.corp (192.168.10.1:22)...",
                "[SSH] Connexion simultanée vers sw-access-floor1.corp (192.168.10.11:22)...",
                "[SSH] Connexion simultanée vers sw-access-floor2.corp (192.168.10.12:22)...",
                "[SSH] Connexion simultanée vers rtr-wan-gateway.corp (192.168.1.1:22)...",
                "[SSH] Connexion simultanée vers sw-dmz-leaf.corp (192.168.20.5:22)...",
                "[OK] sw-core-01.corp : Extraction 'show running-config' achevée en 0.42s.",
                "[OK] rtr-wan-gateway.corp : Extraction 'show running-config' achevée en 0.38s.",
                "[OK] Sauvegardes archivées dans backups/latest/",
                "[AUDIT] Démarrage de l'évaluation des 10 règles CIS Benchmarks / NIST...",
                "[AUDIT] sw-core-01.corp : Score 86.2% -> GRADE B (COMPLIANT)",
                "[ALERT] sw-access-floor1.corp : Telnet détecté sur lignes VTY (CRITICAL) !",
                "[ALERT] sw-access-floor1.corp : Mots de passe non chiffrés détectés (HIGH) !",
                "[ALERT] sw-access-floor1.corp : VLAN 1 utilisé sur interfaces d'accès (HIGH) !",
                "[AUDIT] sw-access-floor1.corp : Score 6.9% -> GRADE F (NON_COMPLIANT)",
                "[OK] sw-dmz-leaf.corp : Score 86.2% -> GRADE B (COMPLIANT)",
                "[DONE] Audit terminé avec succès ! 5/5 équipements traités en 1.84s.",
                "[+] Rapports prêts : audit_summary.md & audit_report.html synchronisés."
            ];

            let index = 0;
            const interval = setInterval(() => {{
                if (index < logs.length) {{
                    const line = document.createElement('div');
                    const text = logs[index];
                    if (text.startsWith('[ALERT]')) line.className = 'log-err';
                    else if (text.startsWith('[OK]') || text.startsWith('[DONE]')) line.className = 'log-ok';
                    else if (text.startsWith('[AUDIT]')) line.className = 'log-warn';
                    else line.className = 'log-info';
                    line.textContent = text;
                    con.appendChild(line);
                    con.scrollTop = con.scrollHeight;
                    index++;
                }} else {{
                    clearInterval(interval);
                    showToast("Simulation d'audit achevée avec succès !");
                }}
            }}, 120);
        }}

        function closeTerminal() {{
            document.getElementById('terminal-modal').style.display = 'none';
        }}

        // Sandbox Custom Config Auditor
        function toggleSandbox() {{
            const box = document.getElementById('sandbox-box');
            box.style.display = (box.style.display === 'block') ? 'none' : 'block';
            if (box.style.display === 'block') {{
                box.scrollIntoView({{ behavior: 'smooth' }});
                if (!document.getElementById('sandbox-input').value) {{
                    loadSampleConfig('vulnerable');
                }}
            }}
        }}

        function loadSampleConfig(type) {{
            const txt = document.getElementById('sandbox-input');
            if (type === 'vulnerable') {{
                txt.value = `! Switch Access Non Durci (Vulnérable)
version 15.0
no service password-encryption
hostname sw-vulnerable-test.corp
enable password cisco123
no aaa new-model
vlan 1
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 1
line vty 0 4
 transport input telnet ssh
end`;
            }} else {{
                txt.value = `! Switch Durci (Conforme CIS)
version 15.2
service password-encryption
hostname sw-hardened-test.corp
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
aaa new-model
ip ssh version 2
banner motd ^C AUTHORIZED ACCESS ONLY ^C
ntp server 192.168.10.254
logging host 192.168.10.250
vlan 10
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
 switchport port-security
line vty 0 4
 transport input ssh
end`;
            }}
            runSandboxAudit();
        }}

        function runSandboxAudit() {{
            const cfg = document.getElementById('sandbox-input').value;
            const res = document.getElementById('sandbox-result');
            res.style.display = 'block';

            const rules = [
                {{ id: 'SEC-001', name: 'Disable Telnet on VTY', pass: !/transport\\s+input.*telnet/i.test(cfg) && /transport\\s+input\\s+ssh/i.test(cfg), sev: 'CRITICAL', fix: 'line vty 0 15\\ntransport input ssh' }},
                {{ id: 'SEC-002', name: 'Enforce Enable Secret', pass: /enable secret/i.test(cfg) && !/enable password/i.test(cfg), sev: 'HIGH', fix: 'no enable password\\nenable secret <STRONG_PASSWORD>' }},
                {{ id: 'SEC-003', name: 'Password Encryption', pass: /service password-encryption/i.test(cfg), sev: 'MEDIUM', fix: 'service password-encryption' }},
                {{ id: 'SEC-004', name: 'Enforce SSH v2', pass: /ip ssh version 2/i.test(cfg), sev: 'HIGH', fix: 'ip ssh version 2' }},
                {{ id: 'SEC-005', name: 'Enable AAA Architecture', pass: /aaa new-model/i.test(cfg), sev: 'MEDIUM', fix: 'aaa new-model' }},
                {{ id: 'SEC-006', name: 'Legal Banner (MOTD)', pass: /banner motd/i.test(cfg), sev: 'LOW', fix: 'banner motd ^C AUTHORIZED ACCESS ONLY ^C' }},
                {{ id: 'SEC-007', name: 'NTP Synchronization', pass: /ntp server/i.test(cfg), sev: 'MEDIUM', fix: 'ntp server 192.168.10.254' }},
                {{ id: 'SEC-008', name: 'Remote Syslog Logging', pass: /logging host/i.test(cfg), sev: 'MEDIUM', fix: 'logging host <SYSLOG_IP>' }},
                {{ id: 'SEC-009', name: 'Avoid Default VLAN 1', pass: !/switchport access vlan 1\\b/i.test(cfg), sev: 'HIGH', fix: 'switchport access vlan <VLAN_ID>' }},
                {{ id: 'SEC-010', name: 'Port-Security Active', pass: /switchport port-security/i.test(cfg), sev: 'MEDIUM', fix: 'switchport port-security' }}
            ];

            let passed = 0;
            let rowsHtml = '';
            rules.forEach(r => {{
                if (r.pass) passed++;
                const statusBadge = r.pass ? '<span class="badge badge-success">CONFORME</span>' : '<span class="badge badge-danger">VULNÉRABLE</span>';
                rowsHtml += `<tr>
                    <td><strong>${{r.id}}</strong></td>
                    <td><span class="badge badge-${{r.sev.toLowerCase()}}">${{r.sev}}</span></td>
                    <td>${{r.name}}</td>
                    <td>${{statusBadge}}</td>
                    <td><code>${{r.fix.replace(/\\n/g, '<br>')}}</code></td>
                </tr>`;
            }});

            const score = Math.round((passed / rules.length) * 100);
            const grade = score >= 90 ? 'A' : (score >= 75 ? 'B' : (score >= 60 ? 'C' : (score >= 40 ? 'D' : 'F')));
            const gradeColor = score >= 75 ? '#34d399' : '#f87171';

            res.innerHTML = `
                <div style="background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:1.25rem;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                        <div>
                            <h4 style="font-size:1.15rem; color:#fff;">Résultat de l'analyse personnalisée</h4>
                            <span style="font-size:0.85rem; color:var(--muted);">${{passed}} / ${{rules.length}} règles de sécurité validées</span>
                        </div>
                        <div style="font-size:1.5rem; font-weight:800; color:${{gradeColor}};">Grade ${{grade}} (${{score}}%)</div>
                    </div>
                    <div class="table-wrap">
                        <table class="findings-table">
                            <thead>
                                <tr><th>ID</th><th>Sévérité</th><th>Règle CIS</th><th>Statut</th><th>Remédiation CLI Cisco</th></tr>
                            </thead>
                            <tbody>${{rowsHtml}}</tbody>
                        </table>
                    </div>
                </div>
            `;
        }}
    </script>
</body>
</html>
"""
        filepath = os.path.join(self.session_dir, "audit_report.html")
        with open(filepath, "w", encoding="utf-8") as hfile:
            hfile.write(html_content)

        return filepath
