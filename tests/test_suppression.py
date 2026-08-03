from __future__ import annotations
import tempfile
import os
from pathlib import Path


def _analyze(code: str, language: str) -> list:
    from src.rules.engine import load_rules, analyze_file
    with tempfile.TemporaryDirectory() as tmp:
        ext = {"python": ".py", "javascript": ".js", "go": ".go"}[language]
        file_path = os.path.join(tmp, f"test{ext}")
        with open(file_path, "w") as f:
            f.write(code)
        rules = load_rules()
        return analyze_file(file_path, language, rules)


def test_nosemgrep_suppresses_same_line():
    findings = _analyze(
        "password = 'supersecret12345'  # nosemgrep\n",
        "python",
    )
    assert len(findings) == 0


def test_nosemgrep_suppresses_line_above():
    findings = _analyze(
        "# nosemgrep\npassword = 'supersecret12345'\n",
        "python",
    )
    assert len(findings) == 0


def test_nosemgrep_does_not_suppress_two_lines_away():
    findings = _analyze(
        "# nosemgrep\n\npassword = 'supersecret12345'\n",
        "python",
    )
    assert len(findings) >= 1


def test_nosemgrep_specific_category():
    code = (
        "# nosemgrep: hardcoded_secrets\n"
        "api_key = 'sk-1234567890abcdefghijkl'\n"
    )
    findings = _analyze(code, "python")
    assert len(findings) == 0


def test_nosemgrep_wrong_category_not_suppressed():
    code = (
        "# nosemgrep: sql_injection\n"
        "api_key = 'sk-1234567890abcdefghijkl'\n"
    )
    findings = _analyze(code, "python")
    assert len(findings) >= 1
    assert any("hardcoded_secrets" in f.category for f in findings)


def test_nosemgrep_js_style():
    findings = _analyze(
        "var apiKey = 'sk-1234567890abcdefghijkl'; // nosemgrep\n",
        "javascript",
    )
    assert len(findings) == 0


def test_nosemgrep_go_style():
    findings = _analyze(
        'package main\nfunc main() {\n    password := "superSecret1234" // nosemgrep\n}\n',
        "go",
    )
    assert len(findings) == 0


def test_no_nosemgrep_does_not_suppress():
    findings = _analyze(
        "password = 'supersecret12345'\n",
        "python",
    )
    assert len(findings) >= 1
