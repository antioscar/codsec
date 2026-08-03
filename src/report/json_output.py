from __future__ import annotations
import json
from dataclasses import asdict
from src.models import ScanReport
from src.report.compliance import compliance_summary


def to_json(report: ScanReport, indent: int = 2) -> str:
    data = {
        "target_path": report.target_path,
        "total_files_scanned": report.total_files_scanned,
        "total_findings": report.total_findings,
        "scan_duration_seconds": report.scan_duration_seconds,
        "summary_by_severity": {
            sev.value: len(findings)
            for sev, findings in report.by_severity.items()
        },
        "findings": [asdict(f) for f in report.findings],
        "compliance": compliance_summary(report),
    }
    return json.dumps(data, indent=indent, ensure_ascii=False)


def save_json(report: ScanReport, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(to_json(report))
