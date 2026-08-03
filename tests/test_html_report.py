from __future__ import annotations
import tempfile
import os

from src.models import ScanReport, Finding, Severity


def _make_report() -> ScanReport:
    f = Finding(
        id="SQL_-0001", category="sql_injection", severity=Severity.CRITICAL,
        cwe="CWE-89", language="python", file_path="/tmp/test.py", line_number=5,
        code_snippet="cursor.execute('SELECT * FROM users WHERE id = '+uid)",
        description="SQL injection detected",
        remediation="1. Use prepared statements\n2. Sanitize input",
        confidence="high",
    )
    return ScanReport(
        target_path="/tmp", total_files_scanned=1, total_findings=1,
        findings=[f], scan_duration_seconds=0.1,
    )


def test_html_report_generation():
    from src.report.html_generator import generate_html_report

    report = _make_report()
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "report.html")
        generate_html_report(report, out)
        assert os.path.exists(out)
        content = open(out, encoding="utf-8").read()
        assert "<!DOCTYPE html>" in content
        assert "Sql Injection" in content or "SQL injection" in content or "CWE-89" in content
        assert "CWE-89" in content
        assert "CRÍTICA" in content or "Crítica" in content


def test_html_report_empty():
    from src.report.html_generator import generate_html_report

    report = ScanReport(target_path="/tmp", total_files_scanned=0, total_findings=0, scan_duration_seconds=0)
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "report.html")
        generate_html_report(report, out)
        assert os.path.exists(out)
