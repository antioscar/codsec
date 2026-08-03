from __future__ import annotations

from src.models import Finding, Severity


class FakeLLMClient:
    def __init__(self, response: str = ""):
        self.response = response
        self.calls: list[list[dict]] = []

    def chat(self, messages, temperature=None):
        self.calls.append(messages)
        return self.response

    def close(self):
        pass


def _make_finding() -> Finding:
    return Finding(
        id="T-0001",
        category="sql_injection",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        language="python",
        file_path="/tmp/test.py",
        line_number=3,
        code_snippet="cursor.execute(query)",
        description="SQL injection in execute()",
        remediation="Use parameterized queries",
        confidence="medium",
    )


def test_enhance_remediation():
    from src.llm.remediation import enhance_remediation

    new_rem = "1. Replace string formatting with placeholders\n2. Use cursor.execute(sql, params)\n3. Validate input types"
    client = FakeLLMClient(
        b'{"remediation": "1. Replace string formatting with placeholders\\n2. Use cursor.execute(sql, params)\\n3. Validate input types"}'
    )
    finding = _make_finding()
    result = enhance_remediation(finding, client)
    assert result == new_rem
    assert len(client.calls) == 1


def test_enhance_remediation_fallback():
    from src.llm.remediation import enhance_remediation

    client = FakeLLMClient(b"garbage not json")
    finding = _make_finding()
    original = finding.remediation
    result = enhance_remediation(finding, client)
    assert result == original


def test_enhance_all_remediations():
    from src.llm.remediation import enhance_all_remediations

    new_rem = "1. Fix issue\n2. Add validation"
    client = FakeLLMClient(
        b'{"remediation": "1. Fix issue\\n2. Add validation"}'
    )
    findings = [_make_finding(), _make_finding()]
    enhance_all_remediations(findings, client)
    assert findings[0].remediation == new_rem
    assert findings[1].remediation == new_rem
    assert len(client.calls) == 2


def test_enhance_all_skips_deps():
    from src.llm.remediation import enhance_all_remediations

    client = FakeLLMClient(b'{"remediation": "ok"}')
    dep = Finding(
        id="DEPS-0001",
        category="vulnerable_dependency",
        severity=Severity.HIGH,
        cwe="CWE-1104",
        language="javascript",
        file_path="/tmp/package.json",
        line_number=0,
        code_snippet="lodash 3.0.0",
        description="lodash vulnerable",
        remediation="Upgrade to latest",
        confidence="high",
    )
    findings = [_make_finding(), dep]
    enhance_all_remediations(findings, client)
    assert len(client.calls) == 1
    assert dep.remediation == "Upgrade to latest"


def test_enhance_all_progress():
    from src.llm.remediation import enhance_all_remediations

    client = FakeLLMClient(b'{"remediation": "ok"}')
    progress_calls = []
    findings = [_make_finding()]
    enhance_all_remediations(findings, client, on_progress=lambda c, t, m: progress_calls.append((c, t)))
    assert progress_calls == [(1, 1)]


def test_enhance_one_chat_error_fallback():
    from src.llm.remediation import enhance_remediation

    finding = _make_finding()
    original = finding.remediation

    class ErrorClient:
        def chat(self, messages, temperature=None):
            raise Exception("Chat error")

        def close(self):
            pass

    client = ErrorClient()
    result = enhance_remediation(finding, client)
    assert result == original
