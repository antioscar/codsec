from __future__ import annotations
import tempfile
import json
import subprocess
import sys
from pathlib import Path

from src.report.gitlab_output import to_gitlab, save_gitlab
from src.models import ScanReport, Severity, Finding


def _make_report(findings: list[Finding]):
    return ScanReport(
        target_path=".",
        total_files_scanned=1,
        total_findings=len(findings),
        findings=findings,
        scan_duration_seconds=0.1,
    )


def test_gitlab_output_empty():
    report = _make_report([])
    issues = to_gitlab(report)
    assert issues == []


def test_gitlab_output_with_findings():
    f = Finding(
        id="TEST-001", category="sql_injection", severity=Severity.CRITICAL,
        cwe="CWE-89", language="python", file_path="app.py", line_number=42,
        code_snippet="c.execute(q)", description="SQL injection detected",
        remediation="Use prepared statements.", confidence="high",
    )
    report = _make_report([f])
    issues = to_gitlab(report)
    assert len(issues) == 1
    assert issues[0]["check_name"] == "sql_injection"
    assert issues[0]["severity"] == "blocker"
    assert issues[0]["location"]["lines"]["begin"] == 42


def test_gitlab_output_save():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp, "gl.json")
        f = Finding(
            id="T-1", category="xss", severity=Severity.HIGH,
            cwe="CWE-79", language="javascript", file_path="app.js", line_number=10,
            code_snippet="", description="XSS", remediation="Escape output.",
            confidence="medium",
        )
        report = _make_report([f])
        save_gitlab(report, str(out))
        with open(out) as fo:
            data = json.load(fo)
        assert len(data) == 1
        assert data[0]["check_name"] == "xss"


def test_cli_exit_code_none():
    result = subprocess.run(
        [sys.executable, "main.py", "-p", ".", "--fail-on", "none", "--min-severity", "medium", "--lang", "python"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0


def test_cli_fail_on_critical():
    result = subprocess.run(
        [sys.executable, "main.py", "-p", "tests/samples/python", "--fail-on", "critical", "--min-severity", "high", "--lang", "python"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 1
