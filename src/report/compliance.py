from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional

import yaml

from src.models import ScanReport, Finding

COMPLIANCE_DIR = Path(__file__).resolve().parent.parent.parent / "config" / "compliance"


def _load_all_standards() -> dict[str, dict]:
    standards: dict[str, dict] = {}
    if not COMPLIANCE_DIR.exists():
        return standards
    for filename in sorted(os.listdir(str(COMPLIANCE_DIR))):
        if not filename.endswith((".yaml", ".yml")):
            continue
        filepath = COMPLIANCE_DIR / filename
        with open(str(filepath), "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for key, value in data.items():
            if isinstance(value, dict):
                standards[key] = value
    return standards


def _standard_label(standard_key: str) -> str:
    labels = {
        "iso27001_controls": "ISO/IEC 27001:2022",
        "iso27034_controls": "ISO/IEC 27034",
        "nist80053_controls": "NIST SP 800-53",
        "owasp_top10_2021": "OWASP Top 10 (2021)",
    }
    return labels.get(standard_key, standard_key)


def _evaluate_standard(controls: dict, findings_by_cat: dict[str, list[Finding]]) -> dict:
    result: dict[str, dict] = {}

    for control_id, control in controls.items():
        categories = control.get("categories", [])
        total_findings = 0
        severity_hits: dict[str, int] = {}
        sample_findings: list[dict] = []

        for cat in categories:
            cat_findings = findings_by_cat.get(cat, [])
            total_findings += len(cat_findings)
            for cf in cat_findings:
                sev = cf.severity.value
                severity_hits[sev] = severity_hits.get(sev, 0) + 1
                if len(sample_findings) < 5:
                    sample_findings.append({
                        "category": cf.category,
                        "severity": sev,
                        "file": cf.file_path,
                        "line": cf.line_number,
                        "cwe": cf.cwe,
                    })

        status = "non_compliant" if total_findings > 0 else "compliant"
        result[control_id] = {
            "title": control.get("title", control.get("component", "")),
            "description": control.get("description", ""),
            "status": status,
            "total_findings": total_findings,
            "by_severity": severity_hits,
            "categories_checked": categories,
            "sample_findings": sample_findings,
        }

    return result


def evaluate_compliance(report: ScanReport) -> dict[str, dict]:
    all_standards = _load_all_standards()

    findings_by_cat: dict[str, list[Finding]] = {}
    for f in report.findings:
        findings_by_cat.setdefault(f.category, []).append(f)

    result: dict[str, dict] = {}
    for standard_key, controls in all_standards.items():
        label = _standard_label(standard_key)
        evaluation = _evaluate_standard(controls, findings_by_cat)
        total = len(evaluation)
        compliant = sum(1 for c in evaluation.values() if c["status"] == "compliant")
        non_compliant = total - compliant

        result[label] = {
            "key": standard_key,
            "controls_evaluated": total,
            "controls_compliant": compliant,
            "controls_non_compliant": non_compliant,
            "compliance_percentage": round(compliant / total * 100, 1) if total else 100,
            "details": evaluation,
        }

    return result


def compliance_summary(report: ScanReport) -> dict:
    evaluation = evaluate_compliance(report)
    total_evaluated = sum(s["controls_evaluated"] for s in evaluation.values())
    total_compliant = sum(s["controls_compliant"] for s in evaluation.values())

    return {
        "standards": list(evaluation.keys()),
        "controls_total_evaluated": total_evaluated,
        "controls_total_compliant": total_compliant,
        "compliance_percentage": round(total_compliant / total_evaluated * 100, 1) if total_evaluated else 100,
        "details": evaluation,
    }


def to_compliance_json(report: ScanReport, indent: int = 2) -> str:
    return json.dumps(compliance_summary(report), indent=indent, ensure_ascii=False)


def save_compliance_json(report: ScanReport, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(to_compliance_json(report))
