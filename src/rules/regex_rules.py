from __future__ import annotations
import os
import re
from src.models import Rule, Finding, Severity

_FALSE_POSITIVE_SECRET_VALUES = re.compile(
    r'(?i)(example|your[_-]?|test[_-]?|xxx+|placeholder|changeme|todo|fake|dummy|sample[_-]?|my[_-]?secret[_-]?)'
)


def _is_false_positive_secret(matched_text: str) -> bool:
    if _FALSE_POSITIVE_SECRET_VALUES.search(matched_text):
        return True
    return False


def apply_regex_rule(
    rule: Rule,
    file_path: str,
    language: str,
    lines: list[str],
    source_text: str,
) -> list[Finding]:
    findings: list[Finding] = []
    counter = 0

    for pattern in rule.regex_patterns:
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue

        for match in compiled.finditer(source_text):
            matched_text = match.group(0)
            if not matched_text.strip():
                continue

            if rule.category == "hardcoded_secrets":
                if _is_false_positive_secret(matched_text):
                    continue

            line_number = source_text[: match.start()].count("\n") + 1
            line_idx = line_number - 1
            line_text = lines[line_idx] if line_idx < len(lines) else ""

            if rule.category in ("hardcoded_secrets", "info_disclosure"):
                if "/test/" in file_path or os.path.basename(file_path).startswith("test_"):
                    continue

            stripped_line = line_text.strip()
            if stripped_line.startswith(("#", "//", "/*", "*")) or "*/" in stripped_line:
                continue

            _filename = os.path.basename(file_path).lower()
            if _filename.endswith((".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env")):
                if rule.category not in ("sql_injection", "command_injection", "xss"):
                    continue

            placeholders = ('= "password"', '= "test"', '= "changeme"', '= "admin"')
            if any(p in line_text for p in placeholders):
                continue

            context_start = max(0, line_idx - 1)
            context_end = min(len(lines), line_idx + 2)
            snippet = "\n".join(lines[context_start:context_end]).strip()

            description = rule.description_template
            if rule.id == "SEC-001":
                sanitized = re.sub(
                    r'["\x27]([A-Za-z0-9_\-.]{8,})["\x27]',
                    '"***REDACTED***"',
                    matched_text,
                )
                description = f"{rule.description_template}: `{sanitized[:120]}`"
            else:
                description = f"{rule.description_template}: `{matched_text[:120]}`"

            counter += 1
            finding = Finding(
                id=f"{rule.id}-{counter}",
                category=rule.category,
                severity=rule.severity,
                cwe=rule.cwe,
                language=language,
                file_path=file_path,
                line_number=line_number,
                code_snippet=snippet,
                description=description,
                remediation=rule.remediation,
                confidence="medium",
            )
            findings.append(finding)

    return findings
