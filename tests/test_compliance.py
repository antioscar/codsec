from __future__ import annotations
from pathlib import Path
import json
import tempfile
from unittest.mock import patch

from src.models import Finding, Severity, ScanReport
from src.report.compliance import (
    evaluate_compliance,
    compliance_summary,
    to_compliance_json,
    _load_all_standards,
    save_compliance_json,
)


def test_all_standards_loaded():
    standards = _load_all_standards()
    assert "iso27001_controls" in standards
    assert "iso27034_controls" in standards
    assert "nist80053_controls" in standards
    assert "owasp_top10_2021" in standards


def test_compliance_all_controls_loaded():
    compliance = evaluate_compliance(ScanReport(
        target_path="test", total_files_scanned=1, total_findings=0,
        findings=[], scan_duration_seconds=0,
    ))
    assert "ISO/IEC 27001:2022" in compliance
    assert "OWASP Top 10 (2021)" in compliance
    assert "ISO/IEC 27034" in compliance
    assert "NIST SP 800-53" in compliance
    assert all(v["controls_evaluated"] > 0 for v in compliance.values())


def test_compliance_no_findings_all_compliant():
    report = ScanReport(
        target_path="test", total_files_scanned=5, total_findings=0,
        findings=[], scan_duration_seconds=0.5,
    )
    summary = compliance_summary(report)
    assert summary["controls_total_evaluated"] > 0
    assert summary["controls_total_compliant"] == summary["controls_total_evaluated"]
    assert summary["compliance_percentage"] == 100.0


def test_compliance_sqli_breaks_controls():
    finding = Finding(
        id="SQLI-0001", category="sql_injection", severity=Severity.HIGH,
        cwe="CWE-89", language="python", file_path="app.py",
        line_number=10, code_snippet="execute(query)", description="SQLi",
        remediation="Use params", confidence="high",
    )
    report = ScanReport(
        target_path="test", total_files_scanned=1, total_findings=1,
        findings=[finding], scan_duration_seconds=0.1,
    )
    evaluation = evaluate_compliance(report)
    iso27001 = evaluation["ISO/IEC 27001:2022"]
    a828 = iso27001["details"]["A.8.28"]
    assert a828["status"] == "non_compliant"
    assert a828["total_findings"] >= 1

    owasp = evaluation["OWASP Top 10 (2021)"]
    a03 = owasp["details"]["A03"]
    assert a03["status"] == "non_compliant"


def test_compliance_weak_hash_crypto_controls():
    finding = Finding(
        id="WH-0001", category="weak_hash", severity=Severity.HIGH,
        cwe="CWE-328", language="python", file_path="auth.py",
        line_number=5, code_snippet="md5(pwd)", description="Weak hash",
        remediation="Use bcrypt", confidence="high",
    )
    report = ScanReport(
        target_path="test", total_files_scanned=1, total_findings=1,
        findings=[finding], scan_duration_seconds=0.1,
    )
    evaluation = evaluate_compliance(report)
    assert evaluation["ISO/IEC 27001:2022"]["details"]["A.8.24"]["status"] == "non_compliant"
    assert evaluation["NIST SP 800-53"]["details"]["SC-13"]["status"] == "non_compliant"


def test_compliance_json_output():
    finding = Finding(
        id="XSS-0001", category="xss", severity=Severity.MEDIUM,
        cwe="CWE-79", language="javascript", file_path="app.js",
        line_number=3, code_snippet="innerHTML = x", description="XSS",
        remediation="textContent", confidence="high",
    )
    report = ScanReport(
        target_path="test", total_files_scanned=1, total_findings=1,
        findings=[finding], scan_duration_seconds=0.1,
    )
    json_str = to_compliance_json(report)
    data = json.loads(json_str)
    assert "standards" in data
    assert "ISO/IEC 27001:2022" in data["standards"]
    assert data["controls_total_evaluated"] > 0


def test_compliance_vulnerable_dependency():
    finding = Finding(
        id="DEPS-0001", category="vulnerable_dependency", severity=Severity.CRITICAL,
        cwe="CWE-1104", language="", file_path=".",
        line_number=0, code_snippet="", description="Vuln dep",
        remediation="Update", confidence="medium",
    )
    report = ScanReport(
        target_path="test", total_files_scanned=1, total_findings=1,
        findings=[finding], scan_duration_seconds=0.1,
    )
    evaluation = evaluate_compliance(report)
    assert evaluation["ISO/IEC 27001:2022"]["details"]["A.8.25"]["status"] == "non_compliant"
    nist_eval = evaluation["NIST SP 800-53"]
    assert nist_eval["details"]["SA-22"]["status"] == "non_compliant"
    assert nist_eval["details"]["SI-5"]["status"] == "non_compliant"


def test_compliance_owasp_a03_multiple():
    sqli = Finding(
        id="SQLI-0001", category="sql_injection", severity=Severity.CRITICAL,
        cwe="CWE-89", language="python", file_path="app.py",
        line_number=5, code_snippet="execute(sql)", description="SQLi",
        remediation="params", confidence="high",
    )
    xss = Finding(
        id="XSS-0001", category="xss", severity=Severity.HIGH,
        cwe="CWE-79", language="javascript", file_path="app.js",
        line_number=3, code_snippet="innerHTML", description="XSS",
        remediation="textContent", confidence="high",
    )
    report = ScanReport(
        target_path="test", total_files_scanned=2, total_findings=2,
        findings=[sqli, xss], scan_duration_seconds=0.1,
    )
    evaluation = evaluate_compliance(report)
    a03 = evaluation["OWASP Top 10 (2021)"]["details"]["A03"]
    assert a03["status"] == "non_compliant"
    assert a03["total_findings"] == 2


@patch("src.report.compliance.COMPLIANCE_DIR")
def test_missing_compliance_dir(mock_compliance_dir):
    mock_compliance_dir.exists.return_value = False
    standards = _load_all_standards()
    assert standards == {}


def test_save_compliance_json():
    finding = Finding(
        id="SQLI-0001", category="sql_injection", severity=Severity.HIGH,
        cwe="CWE-89", language="python", file_path="app.py",
        line_number=10, code_snippet="execute(query)", description="SQLi",
        remediation="Use params", confidence="high",
    )
    report = ScanReport(
        target_path="test", total_files_scanned=1, total_findings=1,
        findings=[finding], scan_duration_seconds=0.1,
    )

    with tempfile.TemporaryDirectory() as tmp:
        output_path = str(Path(tmp, "compliance.json"))
        save_compliance_json(report, output_path)
        assert Path(output_path).exists()
        with open(output_path, "r") as f:
            data = json.load(f)
        assert "standards" in data
        assert "controls_total_evaluated" in data
