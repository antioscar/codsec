from __future__ import annotations
import sys
import os
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import track

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.discovery import detect_languages
from src.models import Severity
from src.scanner import scan_project
from src.report.pdf_generator import generate_pdf_report
from src.report.json_output import save_json
from src.report.html_generator import generate_html_report
from src.report.sarif_output import save_sarif

console = Console(force_terminal=True)

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
}


def _progress_rich(current: int, total: int, file_path: str):
    pass


@click.command(help="Herramienta de análisis de seguridad estática para webapps")
@click.option("-p", "--path", default=".", help="Ruta del proyecto a analizar")
@click.option("-o", "--output", default="informe_seguridad.pdf", help="Archivo PDF de salida")
@click.option("-j", "--json-output", default=None, help="Archivo JSON de salida intermedia")
@click.option("-l", "--lang", default=None, help="Lenguajes separados por coma (python,js,typescript,php,java,go,csharp,ruby)")
@click.option("-s", "--min-severity", default="low", help="Severidad mínima (critical, high, medium, low)")
@click.option("-e", "--exclude", default=None, help="Directorios adicionales a excluir, separados por coma")
@click.option("--llm/--no-llm", default=None, help="Habilitar/deshabilitar análisis con IA (sobrescribe config)")
@click.option("--baseline", default=None, help="Archivo JSON de baseline para comparación delta")
@click.option("--new-only", is_flag=True, default=False, help="Mostrar solo hallazgos nuevos (requiere --baseline)")
@click.option("--html", default=None, help="Archivo HTML de salida")
@click.option("--sarif", default=None, help="Archivo SARIF de salida (v2.1.0)")
@click.option("--online-cve", is_flag=True, default=False, help="Consultar CVE online (OSV) además de la base local")
@click.option("--rules-dir", default=None, help="Directorio con reglas YAML personalizadas")
@click.option("--fail-on", default="high", help="Umbral de severidad para exit code 1: critical, high, medium, low, none")
@click.option("--gitlab", default=None, help="Archivo GitLab Code Quality de salida")
@click.option("--compliance-json", default=None, help="Archivo JSON de cumplimiento ISO 27001")
@click.option("--gui", is_flag=True, default=False, help="Iniciar interfaz gráfica (GUI)")
def scan(path, output, json_output, lang, min_severity, exclude, llm, baseline, new_only, html, sarif, online_cve, rules_dir, fail_on, gitlab, compliance_json, gui):
    if gui:
        import subprocess
        import sys
        subprocess.Popen([sys.executable, "main_gui.py"], cwd=os.path.dirname(os.path.abspath(__file__)))
        return

    from src.config import load_config, merge_exclude_dirs

    target = str(Path(path).resolve())
    if not Path(target).exists():
        console.print(f"[red]Error:[/red] La ruta '{target}' no existe.")
        raise SystemExit(1)

    languages: Optional[list[str]] = None
    if lang:
        languages = [l.strip().lower() for l in lang.split(",")]

    config = load_config()
    min_severity = min_severity or config.get("min_severity", "low")

    cli_exclude = set(d.strip() for d in exclude.split(",")) if exclude else None
    exclude_dirs = merge_exclude_dirs(config, cli_exclude)

    console.print(f"\n[bold cyan][*] Analizando:[/bold cyan] {target}")
    console.print("[dim]Descubriendo archivos...[/dim]")

    from src.discovery import discover_files
    files = discover_files(target, languages=languages, exclude_dirs=exclude_dirs)
    if not files:
        console.print("[yellow]No se encontraron archivos para analizar.[/yellow]")
        return

    lang_counts = detect_languages(files)
    table = Table(title="Archivos encontrados")
    table.add_column("Lenguaje", style="cyan")
    table.add_column("Archivos", style="green")
    for lang_name, count in lang_counts.items():
        table.add_row(lang_name, str(count))
    table.add_row("Total", str(len(files)), style="bold")
    console.print(table)

    from src.llm.provider import is_llm_enabled
    use_llm = is_llm_enabled() if llm is None else llm
    if use_llm:
        console.print("[bold blue][IA][/bold blue] Análisis con inteligencia artificial habilitado")

    console.print("\n[dim]Ejecutando reglas de seguridad...[/dim]")
    progress = track(files, description="Analizando archivos")

    report = scan_project(
        target_path=target,
        languages=languages,
        min_severity=Severity(min_severity.lower()),
        exclude_dirs=exclude_dirs,
        on_progress=lambda c, t, f: progress.__next__(),
        use_llm=use_llm,
        baseline_path=baseline,
        new_only=new_only,
        online_cve=online_cve,
        rules_dir=rules_dir,
    )
    progress.close()

    sev_counts = report.by_severity
    sev_table = Table(title="Resultados del escaneo")
    sev_table.add_column("Severidad", style="bold")
    sev_table.add_column("Hallazgos", justify="right")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        sev_table.add_row(
            f"[{SEVERITY_COLORS[sev]}]{str(sev)}[/{SEVERITY_COLORS[sev]}]",
            str(len(sev_counts[sev])),
        )
    sev_table.add_row("[bold]Total[/bold]", f"[bold]{report.total_findings}[/bold]")
    console.print(sev_table)

    if json_output:
        save_json(report, json_output)
        console.print(f"[green]OK[/green] JSON guardado: {json_output}")

    console.print(f"[dim]Generando informe PDF...[/dim]")
    generate_pdf_report(report, output)
    console.print(f"[green]OK[/green] Informe PDF guardado: [bold]{output}[/bold]")

    if html:
        generate_html_report(report, html)
        console.print(f"[green]OK[/green] Informe HTML guardado: [bold]{html}[/bold]")

    if sarif:
        save_sarif(report, sarif)
        console.print(f"[green]OK[/green] Informe SARIF guardado: [bold]{sarif}[/bold]")

    if gitlab:
        from src.report.gitlab_output import save_gitlab
        save_gitlab(report, gitlab)
        console.print(f"[green]OK[/green] GitLab Code Quality guardado: [bold]{gitlab}[/bold]")

    if compliance_json:
        from src.report.compliance import save_compliance_json
        save_compliance_json(report, compliance_json)
        console.print(f"[green]OK[/green] Cumplimiento ISO guardado: [bold]{compliance_json}[/bold]")

    console.print(f"\n[dim]Escaneo completado en {report.scan_duration_seconds:.2f}s[/dim]\n")

    if fail_on.lower() == "none":
        raise SystemExit(0)

    fail_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    threshold = fail_order.get(fail_on.lower())
    if threshold is None:
        console.print(f"[yellow]Advertencia:[/yellow] --fail-on '{fail_on}' no reconocido. Usando 'high'.")
        threshold = 1

    has_fail = any(f.severity.order <= threshold for f in report.findings)
    raise SystemExit(1 if has_fail else 0)


if __name__ == "__main__":
    scan()
