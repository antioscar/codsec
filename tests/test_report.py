from __future__ import annotations
import tempfile
import os
from pathlib import Path

from src.models import Finding, Severity, ScanReport
from src.report.pdf_generator import generate_pdf_report
from src.report.json_output import to_json, save_json


def test_json_output():
    findings = [
        Finding(
            id="SQLI-0001", category="sql_injection", severity=Severity.CRITICAL,
            cwe="CWE-89", language="python", file_path="app.py",
            line_number=10, code_snippet='query = "SELECT * FROM" + x',
            description="SQLi detectada", remediation="Usa parámetros",
            confidence="medium",
        ),
    ]
    report = ScanReport(
        target_path="/tmp/test",
        total_files_scanned=5,
        total_findings=1,
        findings=findings,
        scan_duration_seconds=0.5,
    )
    json_str = to_json(report)
    assert "sql_injection" in json_str
    assert "CWE-89" in json_str
    assert "5" in json_str


def test_save_json():
    findings = [
        Finding(
            id="XSS-0002", category="xss", severity=Severity.HIGH,
            cwe="CWE-79", language="javascript", file_path="view.js",
            line_number=20, code_snippet='el.innerHTML = data;',
            description="XSS detectada", remediation="No usar innerHTML",
            confidence="high",
        ),
    ]
    report = ScanReport(
        target_path="/tmp/test",
        total_files_scanned=2,
        total_findings=1,
        findings=findings,
        scan_duration_seconds=0.1,
    )
    with tempfile.TemporaryDirectory() as tmp:
        out = str(Path(tmp, "report.json"))
        save_json(report, out)
        assert os.path.exists(out)
        content = Path(out).read_text()
        assert "XSS" in content


def test_pdf_generation():
    findings = [
        Finding(
            id="SQLI-0001", category="sql_injection", severity=Severity.CRITICAL,
            cwe="CWE-89", language="python", file_path="app.py",
            line_number=10, code_snippet='query = "SELECT * FROM" + x',
            description="SQLi detectada", remediation="Usa parámetros",
            confidence="medium",
        ),
        Finding(
            id="XSS-0002", category="xss", severity=Severity.HIGH,
            cwe="CWE-79", language="javascript", file_path="view.js",
            line_number=20, code_snippet='el.innerHTML = data;',
            description="XSS detectada", remediation="No usar innerHTML",
            confidence="high",
        ),
    ]
    report = ScanReport(
        target_path="/tmp/test",
        total_files_scanned=3,
        total_findings=2,
        findings=findings,
        scan_duration_seconds=0.3,
    )
    with tempfile.TemporaryDirectory() as tmp:
        out = str(Path(tmp, "report.pdf"))
        generate_pdf_report(report, out)
        assert os.path.exists(out)
        assert os.path.getsize(out) > 100
