from __future__ import annotations
import json
import tempfile
import os

from src.models import Finding, Severity


def _make_finding(category="sql_injection", file="/tmp/test.py", line=10, is_new=True) -> Finding:
    return Finding(
        id="T-0001", category=category, severity=Severity.CRITICAL,
        cwe="CWE-89", language="python", file_path=file, line_number=line,
        code_snippet="x", description="d", remediation="r",
        is_new=is_new,
    )


def test_load_baseline():
    from src.baseline import load_baseline

    data = {
        "findings": [
            {"file_path": "/tmp/a.py", "category": "sql_injection", "line_number": 5},
            {"file_path": "/tmp/a.py", "category": "xss", "line_number": 10},
        ]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name

    try:
        baseline = load_baseline(path)
        assert baseline == {("/tmp/a.py", "sql_injection", 5), ("/tmp/a.py", "xss", 10)}
    finally:
        os.unlink(path)


def test_load_baseline_empty():
    from src.baseline import load_baseline

    data = {"findings": []}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name

    try:
        baseline = load_baseline(path)
        assert baseline == set()
    finally:
        os.unlink(path)


def test_load_baseline_missing():
    from src.baseline import load_baseline

    baseline = load_baseline("/nonexistent/baseline.json")
    assert baseline == set()


def test_mark_findings():
    from src.baseline import mark_findings

    findings = [
        _make_finding(category="sql_injection", file="/tmp/a.py", line=5),
        _make_finding(category="xss", file="/tmp/b.py", line=20),
        _make_finding(category="ssrf", file="/tmp/a.py", line=5),
    ]
    baseline = {("/tmp/a.py", "sql_injection", 5)}

    mark_findings(findings, baseline)
    assert findings[0].is_new is False
    assert findings[1].is_new is True
    assert findings[2].is_new is True


def test_filter_new():
    from src.baseline import filter_new

    findings = [
        _make_finding(is_new=True),
        _make_finding(is_new=False),
        _make_finding(is_new=True),
    ]
    result = filter_new(findings)
    assert len(result) == 2


def test_scan_with_baseline():
    from src.scanner import scan_project

    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("password = 'supersecret12345'\n")

        baseline_data = {
            "findings": [
                {"file_path": py_file.replace("\\", "/"), "category": "hardcoded_secrets", "line_number": 1}
            ]
        }
        baseline_file = os.path.join(tmp, "baseline.json")
        with open(baseline_file, "w") as f:
            json.dump(baseline_data, f)

        report = scan_project(tmp, baseline_path=baseline_file)
        hc_findings = [f for f in report.findings if f.category == "hardcoded_secrets"]
        assert len(hc_findings) == 1
        assert hc_findings[0].is_new is False


def test_scan_with_baseline_new_only():
    from src.scanner import scan_project

    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("password = 'supersecret12345'\n")

        baseline_data = {
            "findings": [
                {"file_path": py_file.replace("\\", "/"), "category": "hardcoded_secrets", "line_number": 1}
            ]
        }
        baseline_file = os.path.join(tmp, "baseline.json")
        with open(baseline_file, "w") as f:
            json.dump(baseline_data, f)

        report = scan_project(tmp, baseline_path=baseline_file, new_only=True)
        assert len(report.findings) == 0
