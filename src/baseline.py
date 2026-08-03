from __future__ import annotations
import json
from pathlib import Path
from typing import Optional

from src.models import Finding


def load_baseline(baseline_path: str) -> set[tuple[str, str, int]]:
    path = Path(baseline_path)
    if not path.exists():
        return set()

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", [])
    baseline: set[tuple[str, str, int]] = set()
    for item in findings:
        fp = item.get("file_path", "").replace("\\", "/")
        key = (fp, item.get("category", ""), item.get("line_number", 0))
        baseline.add(key)
    return baseline


def mark_findings(findings: list[Finding], baseline: set[tuple[str, str, int]]) -> None:
    for f in findings:
        key = (f.file_path.replace("\\", "/"), f.category, f.line_number)
        if key in baseline:
            f.is_new = False


def filter_new(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.is_new]
