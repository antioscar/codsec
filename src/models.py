from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __str__(self) -> str:
        labels = {
            Severity.CRITICAL: "Crítica",
            Severity.HIGH: "Alta",
            Severity.MEDIUM: "Media",
            Severity.LOW: "Baja",
        }
        return labels[self]

    @property
    def order(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }[self]


@dataclass
class Finding:
    id: str
    category: str
    severity: Severity
    cwe: str
    language: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    remediation: str
    confidence: str = "medium"  # high, medium, low
    is_new: bool = True


@dataclass
class ScanReport:
    target_path: str
    total_files_scanned: int
    total_findings: int
    findings: list[Finding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: [],
        }
        for f in self.findings:
            result[f.severity].append(f)
        return result

    @property
    def by_category(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.category, []).append(f)
        return result


@dataclass
class Rule:
    id: str
    category: str
    severity: Severity
    cwe: str
    description_template: str
    remediation: str
    languages: list[str]
    patterns: list[str] = field(default_factory=list)
    ast_node_types: list[str] = field(default_factory=list)
    ast_function_names: list[str] = field(default_factory=list)
    regex_patterns: list[str] = field(default_factory=list)
