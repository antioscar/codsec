from __future__ import annotations
import tempfile
import os
from pathlib import Path

from src.models import Finding, Severity


class FakeLLMClient:
    def __init__(self, responses: list[str] | None = None):
        self.responses = responses or []
        self.calls: list[list[dict]] = []
        self._idx = 0

    def chat(self, messages, temperature=None):
        self.calls.append(messages)
        if self._idx < len(self.responses):
            resp = self.responses[self._idx]
            self._idx += 1
            return resp
        return '{"verdict": "confirmed", "reason": "looks real"}'

    def close(self):
        pass


def _make_finding(id_str="T-0001", file_path=None, line=10) -> Finding:
    import tempfile
    if file_path is None:
        fd, file_path = tempfile.mkstemp(suffix=".py")
        os.close(fd)
        with open(file_path, "w") as f:
            f.write("def func():\n    x = request.args.get('id')\n    sql.execute(x)\n")
    return Finding(
        id=id_str,
        category="sql_injection",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        language="python",
        file_path=file_path,
        line_number=line,
        code_snippet="sql.execute(x)",
        description="SQL injection detected: sql.execute()",
        remediation="Use parameterized queries",
        confidence="medium",
    )


def test_verify_confirmed():
    from src.llm.verifier import verify_findings, apply_verdicts

    client = FakeLLMClient([b'{"verdict": "confirmed", "reason": "real SQLi"}'])
    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("def func():\n    x = request.args.get('id')\n    execute(x)\n")
        finding = _make_finding("T-0001", py_file, 3)

        verdicts = verify_findings([finding], client)
        assert verdicts == {"T-0001": "confirmed"}

        result = apply_verdicts([finding], verdicts)
        assert len(result) == 1
        assert result[0].confidence == "high"


def test_verify_false_positive():
    from src.llm.verifier import verify_findings, apply_verdicts

    client = FakeLLMClient([b'{"verdict": "false_positive", "reason": "test code"}'])
    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("logger.info('SELECT * FROM users')\n")
        finding = _make_finding("T-0002", py_file, 1)

        verdicts = verify_findings([finding], client)
        assert verdicts == {"T-0002": "false_positive"}

        result = apply_verdicts([finding], verdicts)
        assert len(result) == 0


def test_verify_non_code_file():
    from src.llm.verifier import verify_findings

    client = FakeLLMClient()
    finding = Finding(
        id="DEPS-0001",
        category="vulnerable_dependency",
        severity=Severity.HIGH,
        cwe="CWE-1104",
        language="javascript",
        file_path="/tmp/package.json",
        line_number=0,
        code_snippet="lodash 3.0.0",
        description="lodash vulnerable",
        remediation="Upgrade",
        confidence="high",
    )

    verdicts = verify_findings([finding], client)
    assert "DEPS-0001" not in verdicts


def test_apply_verdicts_unknown():
    from src.llm.verifier import apply_verdicts

    finding = _make_finding("T-0003")
    result = apply_verdicts([finding], {"T-0003": "unknown"})
    assert len(result) == 1
    assert result[0].confidence == "medium"


def test_apply_verdicts_error():
    from src.llm.verifier import apply_verdicts

    finding = _make_finding("T-0004")
    result = apply_verdicts([finding], {"T-0004": "error"})
    assert len(result) == 1


def test_verify_multiple():
    from src.llm.verifier import verify_findings, apply_verdicts

    client = FakeLLMClient([
        b'{"verdict": "confirmed", "reason": "r1"}',
        b'{"verdict": "false_positive", "reason": "r2"}',
        b'{"verdict": "confirmed", "reason": "r3"}',
    ])
    with tempfile.TemporaryDirectory() as tmp:
        findings = []
        for i in range(3):
            py_file = os.path.join(tmp, f"test{i}.py")
            with open(py_file, "w") as f:
                f.write(f"x = input()\n")
            findings.append(_make_finding(f"T-{i:04d}", py_file, 1))

        verdicts = verify_findings(findings, client)
        assert verdicts == {
            "T-0000": "confirmed",
            "T-0001": "false_positive",
            "T-0002": "confirmed",
        }

        result = apply_verdicts(findings, verdicts)
        assert len(result) == 2


def test_read_context_manifest_file():
    from src.llm.verifier import _read_context

    result = _read_context("/tmp/package.json", 0)
    assert result == "(archivo de manifiesto de dependencias — no hay código fuente)"


def test_read_context_file_not_found():
    from src.llm.verifier import _read_context

    result = _read_context("/tmp/nonexistent_file_xyz_123.py", 5)
    assert result == "(no se pudo leer el archivo)"


def test_verify_findings_sorts_by_severity():
    from src.llm.verifier import verify_findings

    client = FakeLLMClient()
    with tempfile.TemporaryDirectory() as tmp:
        findings = []
        for i in range(4):
            py_file = os.path.join(tmp, f"high{i}.py")
            with open(py_file, "w") as f:
                f.write("x = input()\n")
            fnd = _make_finding(f"T-HIGH-{i:04d}", py_file, 1)
            fnd.severity = Severity.HIGH
            findings.append(fnd)
        for i in range(3):
            py_file = os.path.join(tmp, f"crit{i}.py")
            with open(py_file, "w") as f:
                f.write("x = input()\n")
            fnd = _make_finding(f"T-CRIT-{i:04d}", py_file, 1)
            fnd.severity = Severity.CRITICAL
            findings.append(fnd)
        for i in range(4):
            py_file = os.path.join(tmp, f"med{i}.py")
            with open(py_file, "w") as f:
                f.write("x = input()\n")
            fnd = _make_finding(f"T-MED-{i:04d}", py_file, 1)
            fnd.severity = Severity.MEDIUM
            findings.append(fnd)
        for i in range(4):
            py_file = os.path.join(tmp, f"low{i}.py")
            with open(py_file, "w") as f:
                f.write("x = input()\n")
            fnd = _make_finding(f"T-LOW-{i:04d}", py_file, 1)
            fnd.severity = Severity.LOW
            findings.append(fnd)

        total = len(findings)
        assert total == 15

        verdicts = verify_findings(findings, client, max_findings=5)
        assert len(verdicts) == 5
        for i in range(3):
            assert f"T-CRIT-{i:04d}" in verdicts
        assert "T-HIGH-0000" in verdicts
        assert "T-HIGH-0001" in verdicts


def test_verify_findings_chat_error():
    from src.llm.verifier import verify_findings

    class ErrorLLMClient:
        def chat(self, messages, temperature=None):
            raise Exception("Chat error")

        def close(self):
            pass

    client = ErrorLLMClient()
    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("x = input()\n")
        finding = _make_finding("T-ERR-0001", py_file, 1)

        verdicts = verify_findings([finding], client)
        assert verdicts == {"T-ERR-0001": "error"}
