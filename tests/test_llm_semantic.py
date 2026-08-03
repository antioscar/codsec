from __future__ import annotations
import tempfile
import os


class FakeLLMClient:
    def __init__(self, response: str = ""):
        self.response = response
        self.calls: list[list[dict]] = []

    def chat(self, messages, temperature=None):
        self.calls.append(messages)
        return self.response

    def close(self):
        pass


def test_semantic_scan_finds_issues():
    from src.llm.semantic import semantic_scan

    resp = (
        b'[{"category": "ssti", "cwe": "CWE-94", "severity": "critical", '
        b'"line_number": 5, "description": "Template injection via user input", '
        b'"remediation": "Sandbox template engine", "confidence": "high"}]'
    )
    client = FakeLLMClient(resp)

    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write(
                "from flask import request, render_template_string\n"
                "x = request.args.get('tpl')\n"
                "render_template_string(x)\n"
            )
        findings = semantic_scan([py_file], client)
        assert len(findings) == 1
        f = findings[0]
        assert f.category == "ssti"
        assert f.cwe == "CWE-94"
        assert f.severity.value == "critical"


def test_semantic_scan_empty():
    from src.llm.semantic import semantic_scan

    client = FakeLLMClient(b"[]")
    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("print('hello world')\n")
        findings = semantic_scan([py_file], client)
        assert len(findings) == 0


def test_semantic_scan_only_relevant_languages():
    from src.llm.semantic import semantic_scan

    client = FakeLLMClient(b"[{}]")
    with tempfile.TemporaryDirectory() as tmp:
        txt_file = os.path.join(tmp, "README.md")
        with open(txt_file, "w") as f:
            f.write("# hello\n")
        findings = semantic_scan([txt_file], client)
        assert len(findings) == 0


def test_semantic_scan_truncates_large_files():
    from src.llm.semantic import semantic_scan

    client = FakeLLMClient(b"[]")
    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "huge.py")
        with open(py_file, "w") as f:
            f.write("x = 1\n" * 5000)
        findings = semantic_scan([py_file], client)
        assert len(findings) == 0


def test_semantic_scan_respects_max_files():
    from src.llm.semantic import semantic_scan

    client = FakeLLMClient(b"[]")
    with tempfile.TemporaryDirectory() as tmp:
        files = []
        for i in range(5):
            py_file = os.path.join(tmp, f"test{i}.py")
            with open(py_file, "w") as f:
                f.write("print(1)\n")
            files.append(py_file)
        findings = semantic_scan(files, client, max_files=2)
        assert len(findings) == 0
        assert len(client.calls) == 2


def test_semantic_scan_progress():
    from src.llm.semantic import semantic_scan

    client = FakeLLMClient(b"[]")
    progress_calls = []

    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("print(1)\n")
        semantic_scan([py_file], client, on_progress=lambda c, t, m: progress_calls.append((c, t, m)))

    assert len(progress_calls) == 1
    assert progress_calls[0][0] == 1
    assert progress_calls[0][1] == 1


def test_semantic_scan_skips_empty_file():
    from src.llm.semantic import semantic_scan

    client = FakeLLMClient(b"[]")
    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "empty.py")
        with open(py_file, "w") as f:
            f.write("   \n\t\n   ")
        findings = semantic_scan([py_file], client)
        assert len(findings) == 0
        assert len(client.calls) == 0


def test_semantic_scan_skips_nondict_item():
    from src.llm.semantic import semantic_scan

    resp = (
        b'[{"category": "ssti", "cwe": "CWE-94", "severity": "critical", '
        b'"line_number": 5, "description": "SSTI", "remediation": "Fix", '
        b'"confidence": "high"}, "just a string"]'
    )
    client = FakeLLMClient(resp)
    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("print('hello')\n")
        findings = semantic_scan([py_file], client)
        assert len(findings) == 1
        assert findings[0].category == "ssti"


def test_semantic_scan_invalid_severity_fallback():
    from src.llm.semantic import semantic_scan

    resp = (
        b'[{"category": "test", "severity": "invalid", "cwe": "CWE-20", '
        b'"line_number": 1, "description": "test", "remediation": "fix", '
        b'"confidence": "high"}]'
    )
    client = FakeLLMClient(resp)
    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("print('hello')\n")
        findings = semantic_scan([py_file], client)
        assert len(findings) == 1
        assert findings[0].severity.value == "medium"


def test_semantic_scan_invalid_confidence_fallback():
    from src.llm.semantic import semantic_scan

    resp = (
        b'[{"category": "test", "severity": "high", "cwe": "CWE-20", '
        b'"line_number": 1, "description": "test", "remediation": "fix", '
        b'"confidence": "nuclear"}]'
    )
    client = FakeLLMClient(resp)
    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("print('hello')\n")
        findings = semantic_scan([py_file], client)
        assert len(findings) == 1
        assert findings[0].confidence == "medium"


def test_semantic_scan_invalid_line_number_fallback():
    from src.llm.semantic import semantic_scan

    resp = (
        b'[{"category": "test", "severity": "high", "cwe": "CWE-20", '
        b'"line_number": "abc", "description": "test", "remediation": "fix", '
        b'"confidence": "high"}]'
    )
    client = FakeLLMClient(resp)
    with tempfile.TemporaryDirectory() as tmp:
        py_file = os.path.join(tmp, "test.py")
        with open(py_file, "w") as f:
            f.write("print('hello')\n")
        findings = semantic_scan([py_file], client)
        assert len(findings) == 1
        assert findings[0].line_number == 1
