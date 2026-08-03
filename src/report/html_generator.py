from __future__ import annotations
from datetime import datetime

from src.models import ScanReport, Finding, Severity
from src.report.compliance import evaluate_compliance

SEV_COLORS = {
    Severity.CRITICAL: "#DC143C",
    Severity.HIGH: "#FF4500",
    Severity.MEDIUM: "#FFA500",
    Severity.LOW: "#228B22",
}

SEV_BG = {
    Severity.CRITICAL: "#FDE8E8",
    Severity.HIGH: "#FFF3E0",
    Severity.MEDIUM: "#FFF8E1",
    Severity.LOW: "#E8F5E9",
}


def generate_html_report(report: ScanReport, output_path: str) -> None:
    sorted_findings = sorted(report.findings, key=lambda f: (f.severity.order, f.category, f.file_path))

    findings_html = ""
    for idx, f in enumerate(sorted_findings, 1):
        color = SEV_COLORS.get(f.severity, "#999")
        bg = SEV_BG.get(f.severity, "#f5f5f5")
        new_badge = '<span class="new-badge">NUEVO</span>' if f.is_new else ""
        cat_title = f.category.replace("_", " ").title()
        conf_labels = {"high": "Alta", "medium": "Media", "low": "Baja"}
        conf = conf_labels.get(f.confidence, f.confidence)
        code = f.code_snippet.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        if len(code) > 600:
            code = code[:600] + "\n..."

        findings_html += f"""
        <div class="finding" style="border-left-color:{color}">
            <div class="finding-header" style="background:{bg}">
                <span class="sev" style="color:{color}">[{str(f.severity).upper()}]</span>
                <span class="cat">{idx}. {cat_title} {new_badge}</span>
                <span class="cwe">{f.cwe}</span>
            </div>
            <div class="finding-body">
                <div class="meta">
                    <strong>Archivo:</strong> {f.file_path}:{f.line_number} &nbsp;
                    <strong>Confianza:</strong> {conf} &nbsp;
                    <strong>Lenguaje:</strong> {f.language}
                </div>
                <div class="desc"><strong>Descripción:</strong> {f.description}</div>
                <div class="code"><pre>{code}</pre></div>
                <div class="remediation"><strong>Remediación:</strong>
                    {"".join(f"<li>{line.strip().lstrip('0123456789. ')}</li>" for line in f.remediation.split(chr(10)) if line.strip())}
                </div>
            </div>
        </div>"""

    critical = len(report.by_severity[Severity.CRITICAL])
    high = len(report.by_severity[Severity.HIGH])
    medium = len(report.by_severity[Severity.MEDIUM])
    low = len(report.by_severity[Severity.LOW])

    compliance = evaluate_compliance(report)
    comp_sections = ""
    for std_label, std_data in compliance.items():
        comp_pct = std_data["compliance_percentage"]
        pct_color = "#228B22" if comp_pct >= 80 else ("#FFA500" if comp_pct >= 50 else "#DC143C")
        comp_rows = ""
        for cid, cinfo in std_data["details"].items():
            status_icon = "&#x2705;" if cinfo["status"] == "compliant" else "&#x274C;"
            status_class = "comp-ok" if cinfo["status"] == "compliant" else "comp-fail"
            comp_rows += f"""
            <tr class="{status_class}">
                <td><strong>{cid}</strong></td>
                <td>{cinfo["title"]}</td>
                <td>{status_icon} {"Cumplido" if cinfo["status"] == "compliant" else "Incumplido"}</td>
                <td>{cinfo["total_findings"]}</td>
            </tr>"""
        comp_sections += f"""
        <div class="comp-standard">
            <h3>{std_label} <span style="font-size:12px;color:{pct_color}">({comp_pct}% cumplimiento)</span></h3>
            <table class="comp-table">
            <thead><tr><th>Control</th><th>Título</th><th>Estado</th><th>Hallazgos</th></tr></thead>
            <tbody>{comp_rows}</tbody>
            </table>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Informe de Seguridad</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#1a1a2e; color:#c0c0d0; padding:20px; }}
.container {{ max-width:1100px; margin:0 auto; }}
h1 {{ text-align:center; color:#7ec8e3; font-size:24px; margin-bottom:5px; }}
.subtitle {{ text-align:center; color:#6a6a8a; font-size:14px; margin-bottom:25px; }}
.cards {{ display:flex; gap:12px; flex-wrap:wrap; justify-content:center; margin-bottom:25px; }}
.card {{ background:#22223a; border-radius:8px; padding:16px 24px; min-width:120px; text-align:center; border-top:3px solid transparent; }}
.card.crit {{ border-top-color:{SEV_COLORS[Severity.CRITICAL]}; }}
.card.high {{ border-top-color:{SEV_COLORS[Severity.HIGH]}; }}
.card.med {{ border-top-color:{SEV_COLORS[Severity.MEDIUM]}; }}
.card.low {{ border-top-color:{SEV_COLORS[Severity.LOW]}; }}
.card.total {{ border-top-color:#569cd6; }}
.card .number {{ font-size:28px; font-weight:bold; }}
.card .label {{ font-size:11px; text-transform:uppercase; color:#8a8aaa; }}
.info {{ text-align:center; font-size:12px; color:#6a6a8a; margin-bottom:20px; }}
.filters {{ display:flex; gap:10px; margin-bottom:15px; flex-wrap:wrap; }}
.filters input, .filters select {{ background:#22223a; border:1px solid #3a3a5c; color:#c0c0d0; padding:6px 10px; border-radius:4px; }}
.filters input {{ flex:1; min-width:180px; }}
.finding {{ background:#22223a; border-radius:6px; margin-bottom:12px; border-left:3px solid; overflow:hidden; }}
.finding-header {{ padding:10px 14px; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }}
.sev {{ font-weight:bold; font-size:12px; }}
.cat {{ font-weight:bold; font-size:13px; flex:1; }}
.cwe {{ font-size:11px; color:#8a8aaa; }}
.new-badge {{ background:#22aa44; color:#fff; font-size:10px; padding:2px 6px; border-radius:3px; margin-left:6px; }}
.finding-body {{ padding:10px 14px; }}
.meta {{ font-size:11px; color:#8a8aaa; margin-bottom:8px; }}
.desc {{ font-size:12px; margin-bottom:8px; }}
.code {{ background:#0d0d1a; border-radius:4px; padding:10px; margin-bottom:8px; overflow-x:auto; }}
.code pre {{ font-family:'Cascadia Code',Consolas,monospace; font-size:11px; color:#9cdcfe; white-space:pre-wrap; }}
.remediation {{ font-size:12px; }}
.remediation li {{ margin-left:18px; margin-bottom:3px; }}
.footer {{ text-align:center; font-size:11px; color:#5a5a7a; margin-top:30px; }}
.hidden {{ display:none; }}
.compliance-section {{ margin:20px 0; }}
.compliance-section h2 {{ font-size:18px; color:#7ec8e3; margin-bottom:10px; }}
.comp-table {{ width:100%; border-collapse:collapse; margin-bottom:20px; }}
.comp-table th,.comp-table td {{ padding:8px 12px; text-align:left; border-bottom:1px solid #3a3a5c; font-size:12px; }}
.comp-table th {{ color:#8a8aaa; text-transform:uppercase; font-size:11px; }}
.comp-ok {{ color:#228b22; }}
.comp-fail {{ color:#dc143c; }}
.comp-standard {{ margin-bottom:18px; }}
.comp-standard h3 {{ font-size:14px; color:#7ec8e3; margin-bottom:8px; }}
</style>
</head>
<body>
<div class="container">
<h1>Informe de Análisis de Seguridad</h1>
<p class="subtitle">{report.target_path} &mdash; {report.total_files_scanned} archivos analizados en {report.scan_duration_seconds:.1f}s</p>
<div class="cards">
    <div class="card crit"><div class="number" style="color:{SEV_COLORS[Severity.CRITICAL]}">{critical}</div><div class="label">Críticas</div></div>
    <div class="card high"><div class="number" style="color:{SEV_COLORS[Severity.HIGH]}">{high}</div><div class="label">Altas</div></div>
    <div class="card med"><div class="number" style="color:{SEV_COLORS[Severity.MEDIUM]}">{medium}</div><div class="label">Medias</div></div>
    <div class="card low"><div class="number" style="color:{SEV_COLORS[Severity.LOW]}">{low}</div><div class="label">Bajas</div></div>
    <div class="card total"><div class="number" style="color:#569cd6">{report.total_findings}</div><div class="label">Total</div></div>
</div>
<p class="info">{datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
<div class="compliance-section">
<h2>Cumplimiento de Normas</h2>
{comp_sections}
</div>
<div class="filters">
    <input type="text" id="search" placeholder="Buscar archivo, categoría, CWE..." oninput="filter()">
    <select id="sevFilter" onchange="filter()">
        <option value="">Todas</option>
        <option value="CRÍTICA">Crítica</option>
        <option value="ALTA">Alta</option>
        <option value="MEDIA">Media</option>
        <option value="BAJA">Baja</option>
    </select>
</div>
<div id="findings">
{findings_html}
</div>
<p class="footer">Generado por Analizador de Seguridad de Código &mdash; {datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
</div>
<script>
function filter() {{
    var q = document.getElementById('search').value.toLowerCase();
    var sev = document.getElementById('sevFilter').value;
    var items = document.querySelectorAll('.finding');
    items.forEach(function(item) {{
        var show = true;
        if (sev && item.querySelector('.sev').textContent.indexOf(sev) === -1) show = false;
        if (q) {{
            var txt = item.textContent.toLowerCase();
            if (txt.indexOf(q) === -1) show = false;
        }}
        item.classList.toggle('hidden', !show);
    }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
