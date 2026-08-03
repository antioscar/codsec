from __future__ import annotations
import os
import tempfile
from pathlib import Path

from src.models import Severity


class FakeLLMClient:
    def __init__(self, responses: list[str] | None = None):
        self.responses = responses or []
        self._idx = 0
        self.calls: list[list[dict]] = []

    def chat(self, messages, temperature=None):
        self.calls.append(messages)
        if self._idx < len(self.responses):
            resp = self.responses[self._idx]
            self._idx += 1
            return resp
        return "[]"

    def close(self):
        pass


def _write_simple_vuln(tmp: str) -> str:
    py_file = os.path.join(tmp, "test.py")
    with open(py_file, "w") as f:
        f.write("import sqlite3\nq = 'test'\ncursor = sqlite3.connect(':memory:').cursor()\ncursor.execute('SELECT * FROM t WHERE name = ' + q)\n")
    return py_file


def test_scan_with_llm_verify_confirmed():
    from src.scanner import scan_project

    with tempfile.TemporaryDirectory() as tmp:
        _write_simple_vuln(tmp)
        client = FakeLLMClient([
            b'{"verdict": "confirmed", "reason": "real SQLi"}',
        ])
        report = scan_project(tmp, use_llm=True, llm_client=client)
        sql_findings = [f for f in report.findings if f.category == "sql_injection"]
        assert len(sql_findings) >= 1
        for f in sql_findings:
            assert f.confidence == "high"


def test_scan_with_llm_verify_false_positive():
    from src.scanner import scan_project

    with tempfile.TemporaryDirectory() as tmp:
        _write_simple_vuln(tmp)
        client = FakeLLMClient([
            b'{"verdict": "false_positive", "reason": "test"}',
        ])
        report = scan_project(tmp, use_llm=True, llm_client=client)
        assert len(report.findings) == 0


def test_scan_without_llm_no_calls():
    from src.scanner import scan_project

    with tempfile.TemporaryDirectory() as tmp:
        _write_simple_vuln(tmp)
        client = FakeLLMClient()
        report = scan_project(tmp, use_llm=False, llm_client=client)
        assert len(report.findings) > 0
        assert len(client.calls) == 0


def test_scan_llm_semantic_adds_findings():
    from src.scanner import scan_project

    with tempfile.TemporaryDirectory() as tmp:
        _write_simple_vuln(tmp)
        client = FakeLLMClient([
            b'{"verdict": "confirmed", "reason": "real"}',
            b'[{"category": "ssti", "cwe": "CWE-94", "severity": "critical", "line_number": 2, "description": "SSTI", "remediation": "fix", "confidence": "high"}]',
            b'{"remediation": "ok"}',
        ])
        report = scan_project(tmp, use_llm=True, llm_client=client)
        sem_findings = [f for f in report.findings if f.category == "ssti"]
        assert len(sem_findings) == 1
        assert sem_findings[0].cwe == "CWE-94"


def test_scan_llm_progress_callback():
    from src.scanner import scan_project

    progress = []

    with tempfile.TemporaryDirectory() as tmp:
        _write_simple_vuln(tmp)
        client = FakeLLMClient([
            b'{"verdict": "confirmed", "reason": "ok"}',
        ])
        report = scan_project(
            tmp, use_llm=True, llm_client=client,
            on_progress=lambda c, t, f: progress.append(f),
        )
        ia_msgs = [p for p in progress if "IA" in p]
        assert len(ia_msgs) > 0


def test_scan_llm_closes_client():
    from src.scanner import scan_project

    closed = []

    class CloseableFake:
        def chat(self, messages, temperature=None):
            return "[]"

        def close(self):
            closed.append(True)

    with tempfile.TemporaryDirectory() as tmp:
        _write_simple_vuln(tmp)
        scan_project(tmp, use_llm=True, llm_client=CloseableFake())
        assert len(closed) == 1
