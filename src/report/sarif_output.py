from __future__ import annotations
from datetime import datetime

from src.models import ScanReport, Severity

SEV_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def to_sarif(report: ScanReport) -> dict:
    rules = {}
    results = []
    seen_categories = set()

    for f in report.findings:
        if f.category not in seen_categories:
            seen_categories.add(f.category)
            rules[f.category] = {
                "id": f.category,
                "shortDescription": {"text": f.category.replace("_", " ").title()},
            }

        result = {
            "ruleId": f.category,
            "level": SEV_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path.replace("\\", "/"),
                        },
                        "region": {
                            "startLine": f.line_number,
                        },
                    }
                }
            ],
        }
        if f.is_new is False:
            result.setdefault("annotations", [])

        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": SCHEMA_URI,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Analizador de Seguridad de Código",
                        "informationUri": "https://github.com/example/sast",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def save_sarif(report: ScanReport, output_path: str) -> None:
    import json
    data = to_sarif(report)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
