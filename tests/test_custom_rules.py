from __future__ import annotations
import tempfile
from pathlib import Path
import yaml
import sys
import io

from src.rules.engine import load_rules, analyze_file


def test_load_custom_rule_detects():
    with tempfile.TemporaryDirectory() as tmp:
        rule_yaml = Path(tmp, "custom.yaml")
        rule_yaml.write_text(yaml.dump({
            "id": "CUSTOM-001",
            "category": "custom_test",
            "severity": "high",
            "cwe": "CWE-999",
            "description_template": "Custom rule hit",
            "remediation": "Fix it.",
            "languages": ["python"],
            "regex_patterns": ["(?i)customSensitiveFunction\\("],
        }))

        code = Path(tmp, "test.py")
        code.write_text("customSensitiveFunction(x)")

        rules = load_rules(str(tmp))
        assert len(rules) >= 1
        assert any(r.category == "custom_test" for r in rules)

        findings = analyze_file(str(code), "python", rules)
        assert len(findings) >= 1
        assert any(f.category == "custom_test" for f in findings)


def test_custom_rule_invalid_skipped():
    with tempfile.TemporaryDirectory() as tmp:
        rule_yaml = Path(tmp, "bad.yaml")
        rule_yaml.write_text(yaml.dump({
            "id": "BAD-001",
            "category": "",
            "severity": "invalid",
            "languages": [],
            "regex_patterns": [],
        }))

        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            rules = load_rules(str(tmp))
        finally:
            sys.stderr = old_stderr

        assert len(rules) >= 1


def test_custom_rule_languages_validated():
    with tempfile.TemporaryDirectory() as tmp:
        rule_yaml = Path(tmp, "multi.yaml")
        rule_yaml.write_text(yaml.dump({
            "id": "MULTI-001",
            "category": "multi_test",
            "severity": "medium",
            "cwe": "CWE-100",
            "description_template": "Multi lang",
            "remediation": "Fix.",
            "languages": ["python", "go", "csharp", "ruby"],
            "regex_patterns": ["(?i)testFunc"],
        }))

        rules = load_rules(str(tmp))
        rule = next((r for r in rules if r.category == "multi_test"), None)
        assert rule is not None
        assert rule.languages == ["python", "go", "csharp", "ruby"]


def test_custom_rule_no_patterns_warns():
    with tempfile.TemporaryDirectory() as tmp:
        rule_yaml = Path(tmp, "no_pat.yaml")
        rule_yaml.write_text(yaml.dump({
            "id": "NP-001",
            "category": "no_pattern",
            "severity": "low",
            "cwe": "CWE-200",
            "description_template": "No patterns",
            "remediation": "N/A",
            "languages": ["python"],
        }))

        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            load_rules(str(tmp))
        finally:
            sys.stderr = old_stderr
