from __future__ import annotations
import json
from pathlib import Path

from src.models import ScanReport, Severity

SEV_TO_GITLAB = {
    Severity.CRITICAL: "blocker",
    Severity.HIGH: "critical",
    Severity.MEDIUM: "major",
    Severity.LOW: "minor",
}


def to_gitlab(report: ScanReport) -> list[dict]:
    issues: list[dict] = []
    for f in report.findings:
        location = {
            "path": f.file_path,
            "lines": {"begin": f.line_number or 1},
        }
        issues.append({
            "type": "issue",
            "check_name": f.category,
            "description": f"{f.description}\n\nRemediación: {f.remediation}",
            "categories": ["Security"],
            "severity": SEV_TO_GITLAB.get(f.severity, "minor"),
            "location": location,
            "fingerprint": f"{f.file_path}:{f.line_number}:{f.category}",
        })
    return issues


def save_gitlab(report: ScanReport, output_path: str):
    data = to_gitlab(report)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
