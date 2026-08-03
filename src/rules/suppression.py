from __future__ import annotations
import re

from src.rules.parser import ParsedFile
from src.models import Finding


NOSEMGREP_RE = re.compile(r"nosemgrep(?::\s*([\w_,\-\s]+))?", re.IGNORECASE)


def collect_suppressions(parsed: ParsedFile) -> dict[int, set[str]]:
    suppressions: dict[int, set[str]] = {}

    comment_types = {"comment", "block_comment", "line_comment"}

    def _walk(node):
        if node.type in comment_types:
            text = parsed.source[node.start_byte:node.end_byte].decode(
                "utf-8", errors="replace"
            )
            m = NOSEMGREP_RE.search(text)
            if m:
                line = node.start_point[0] + 1
                cats_str = (m.group(1) or "").strip()
                if cats_str:
                    categories = {c.strip().lower() for c in cats_str.split(",") if c.strip()}
                else:
                    categories = set()
                suppressions[line] = categories
        for child in node.children:
            _walk(child)

    _walk(parsed.root_node)
    return suppressions


def apply_suppressions(
    findings: list[Finding],
    suppressions: dict[int, set[str]],
) -> list[Finding]:
    result: list[Finding] = []
    for f in findings:
        suppressed = False
        for check_line in (f.line_number, f.line_number - 1):
            if check_line in suppressions:
                cats = suppressions[check_line]
                if not cats or f.category in cats:
                    suppressed = True
                    break
        if not suppressed:
            result.append(f)
    return result
