from __future__ import annotations
import os
import re
from tree_sitter import Node
from src.models import Rule, Finding, Severity

_FALSE_POSITIVE_SECRET_VALUES = re.compile(
    r'(?i)(example|your[_-]?|test[_-]?|xxx+|placeholder|changeme|todo|fake|dummy|sample[_-]?|my[_-]?secret[_-]?)'
)


def _is_false_positive_secret(matched_text: str) -> bool:
    if _FALSE_POSITIVE_SECRET_VALUES.search(matched_text):
        return True
    return False


def _find_containing_string_node(node: Node | None, byte_pos: int) -> Node | None:
    if node is None:
        return None
    node_type = node.type
    if ("string" in node_type or node_type in (
        "string_literal", "raw_string_literal", "interpreted_string_literal",
        "encapsed_string", "heredoc", "template_string", "template_literal",
    )) and node.start_byte <= byte_pos <= node.end_byte:
        return node
    for child in node.children:
        result = _find_containing_string_node(child, byte_pos)
        if result:
            return result
    return None


def _is_in_string_or_comment(node: Node | None, start_byte: int, end_byte: int) -> bool:
    """Check if a byte range falls inside a string or comment AST node."""
    if node is None:
        return False
    node_type = node.type
    if node_type in ("comment", "block_comment", "line_comment") or "comment" in node_type:
        if node.start_byte <= start_byte and node.end_byte >= end_byte:
            return True
    if "string" in node_type or node_type in (
        "string_literal", "string_content", "template_string",
        "template_literal", "raw_string_literal", "interpreted_string_literal",
        "encapsed_string", "heredoc", "heredoc_body", "nowdoc_body",
        "charliteral", "character_literal", "string_fragment",
    ):
        if node.start_byte <= start_byte and node.end_byte >= end_byte:
            return True

    for child in node.children:
        if _is_in_string_or_comment(child, start_byte, end_byte):
            return True
    return False


def apply_regex_rule(
    rule: Rule,
    file_path: str,
    language: str,
    lines: list[str],
    source_text: str,
    parsed_root: Node | None = None,
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

            if parsed_root is not None and rule.category == "hardcoded_secrets":
                match_start_byte = match.start()
                match_end_byte = match.end()
                if _is_in_string_or_comment(parsed_root, match_start_byte, match_end_byte):
                    node = _find_containing_string_node(parsed_root, match_start_byte)
                    if node and node.end_byte - node.start_byte > 100:
                        continue

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
