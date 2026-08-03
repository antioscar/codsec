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


def _find_node_at_position(root_node: Node, byte_pos: int) -> Node | None:
    if root_node.start_byte > byte_pos or root_node.end_byte < byte_pos:
        return None
    for child in root_node.children:
        result = _find_node_at_position(child, byte_pos)
        if result is not None:
            return result
    return root_node


def _is_match_in_code(root_node: Node, start_byte: int, end_byte: int, source_text: str) -> bool:
    node = _find_node_at_position(root_node, start_byte)
    if node is None:
        return True

    current = node
    while current is not None:
        node_type = (current.type or "").lower()

        if "comment" in node_type:
            return False

        if "string" in node_type and current.end_byte - current.start_byte > 100:
            return False

        if "string" in node_type:
            for target in ("write_text", "write", "send"):
                parent = current.parent
                while parent is not None:
                    ptype = (parent.type or "").lower()
                    if "call" in ptype:
                        source_bytes = source_text.encode("utf-8", errors="replace")
                        func_name = None
                        for child in parent.children:
                            if child.type in ("identifier", "name"):
                                func_name = source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                                break
                        if func_name == target:
                            return False
                        break
                    parent = parent.parent

        current = current.parent

    return True


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

            if parsed_root is not None:
                if not _is_match_in_code(parsed_root, match.start(), match.end(), source_text):
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
