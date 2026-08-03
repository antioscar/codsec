from __future__ import annotations
import json
import tempfile
import os

from src.models import ScanReport, Finding, Severity


def _make_report() -> ScanReport:
    f = Finding(
        id="SQL_-0001", category="sql_injection", severity=Severity.CRITICAL,
        cwe="CWE-89", language="python", file_path="/tmp/test.py", line_number=5,
        code_snippet="x", description="SQL injection in execute()",
        remediation="Use prepared statements",
    )
    return ScanReport(
        target_path="/tmp", total_files_scanned=1, total_findings=1,
        findings=[f], scan_duration_seconds=0.1,
    )


def test_sarif_structure():
    from src.report.sarif_output import to_sarif

    report = _make_report()
    data = to_sarif(report)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    runs = data["runs"]
    assert len(runs) == 1
    run = runs[0]
    assert "tool" in run
    assert "results" in run
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "sql_injection"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 5


def test_sarif_severity_mapping():
    from src.report.sarif_output import to_sarif
    from src.report.sarif_output import SEV_TO_LEVEL

    assert SEV_TO_LEVEL[Severity.CRITICAL] == "error"
    assert SEV_TO_LEVEL[Severity.HIGH] == "error"
    assert SEV_TO_LEVEL[Severity.MEDIUM] == "warning"
    assert SEV_TO_LEVEL[Severity.LOW] == "note"


def test_save_sarif():
    from src.report.sarif_output import save_sarif

    report = _make_report()
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "report.sarif")
        save_sarif(report, out)
        assert os.path.exists(out)
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
