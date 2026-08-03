from __future__ import annotations
import os
from pathlib import Path
from typing import Optional

import yaml

from src.models import Rule, Severity, Finding
from src.rules.parser import parse_file, find_function_calls, ParsedFile, mask_comments
from src.rules.regex_rules import apply_regex_rule
from src.rules.taint import run_taint_analysis
from src.rules.suppression import collect_suppressions, apply_suppressions


RULES_DIR = Path(__file__).resolve().parent.parent.parent / "config" / "rules"


def load_rules(rules_dir: Optional[str] = None, validate: bool = True) -> list[Rule]:
    if rules_dir is None:
        rules_dir = str(RULES_DIR)

    rules: list[Rule] = []
    errors: list[str] = []
    seen_ids: set[str] = set()
    valid_severities = {"critical", "high", "medium", "low"}
    valid_languages = {"python", "javascript", "typescript", "php", "java", "go", "csharp", "ruby"}

    for filename in sorted(os.listdir(rules_dir)):
        if not filename.endswith((".yaml", ".yml")):
            continue
        filepath = os.path.join(rules_dir, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if data is None:
                continue
            rid = str(data.get("id", ""))
            category = str(data.get("category", "")).strip()
            severity = str(data.get("severity", "low"))
            languages = list(data.get("languages", []))
            ast_funcs = list(data.get("ast_function_names", []))
            patterns = list(data.get("patterns", []))
            regex_pats = list(data.get("regex_patterns", []))

            if validate:
                if not rid:
                    errors.append(f"{filename}: falta el campo 'id'")
                elif rid in seen_ids:
                    errors.append(f"{filename}: 'id' duplicado '{rid}'")
                else:
                    seen_ids.add(rid)

                if not category:
                    errors.append(f"{filename}: falta el campo 'category'")
                if severity not in valid_severities:
                    errors.append(f"{filename}: 'severity' inválida '{severity}'")
                if not languages:
                    errors.append(f"{filename}: falta 'languages'")
                else:
                    unknown = [l for l in languages if l not in valid_languages]
                    if unknown:
                        errors.append(f"{filename}: lenguajes desconocidos: {unknown}")

                has_patterns = bool(ast_funcs or patterns or regex_pats)
                if not has_patterns:
                    errors.append(f"{filename}: debe tener al menos ast_function_names, patterns o regex_patterns")

            try:
                rule_sev = Severity(severity)
            except ValueError:
                rule_sev = Severity.LOW
                if validate:
                    errors.append(f"{filename}: 'severity' inválida '{severity}', usando 'low'")

            rule = Rule(
                id=rid,
                category=category,
                severity=rule_sev,
                cwe=str(data.get("cwe", "")),
                description_template=str(data.get("description_template", "")),
                remediation=str(data.get("remediation", "")),
                languages=languages,
                patterns=patterns,
                ast_node_types=list(data.get("ast_node_types", [])),
                ast_function_names=ast_funcs,
                regex_patterns=regex_pats,
            )
            rules.append(rule)

    if validate and errors:
        for err in errors:
            import sys
            print(f"[ADVERTENCIA] regla inválida: {err}", file=sys.stderr)

    return rules


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.category)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def analyze_file(
    file_path: str,
    language: str,
    rules: list[Rule],
) -> list[Finding]:
    findings: list[Finding] = []

    parsed = parse_file(file_path, language)

    if parsed is None:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source_text = f.read()
        lines = source_text.split("\n")
        masked_text = source_text
    else:
        source_text = parsed.source.decode("utf-8", errors="replace")
        lines = parsed.lines
        masked_text = mask_comments(parsed)

    applicable_rules = [r for r in rules if language in r.languages]

    for rule in applicable_rules:
        regex_findings = apply_regex_rule(rule, file_path, language, lines, masked_text)
        findings.extend(regex_findings)

    if parsed and any(r.ast_function_names for r in applicable_rules):
        func_calls = find_function_calls(parsed.root_node, parsed.source)
        ast_rules = [r for r in applicable_rules if r.ast_function_names]
        for rule in ast_rules:
            findings.extend(
                _apply_ast_rule(rule, parsed, func_calls)
            )

    if parsed:
        taint_findings = run_taint_analysis(parsed, applicable_rules)
        findings = _merge_taint_findings(findings, taint_findings)

    findings = _dedupe_findings(findings)

    if parsed:
        sups = collect_suppressions(parsed)
        findings = apply_suppressions(findings, sups)

    return findings


def _merge_taint_findings(
    existing: list[Finding], taint_findings: list[Finding]
) -> list[Finding]:
    for tf in taint_findings:
        matched = False
        for ef in existing:
            if (ef.file_path == tf.file_path
                    and abs(ef.line_number - tf.line_number) <= 2
                    and ef.category == tf.category
                    and ef.confidence != "high"):
                ef.confidence = "high"
                matched = True
                break
        if not matched:
            for ef in existing:
                if (ef.file_path == tf.file_path
                        and abs(ef.line_number - tf.line_number) <= 2
                        and ef.confidence != "high"):
                    ef.confidence = tf.confidence
                    matched = True
                    break
        if not matched:
            existing.append(tf)
    return existing


def _apply_ast_rule(
    rule: Rule,
    parsed: ParsedFile,
    func_calls: list[tuple[str, int, int]],
) -> list[Finding]:
    findings: list[Finding] = []
    counter = 0

    for func_name, line_no, _col in func_calls:
        if func_name not in rule.ast_function_names:
            continue

        line_idx = line_no - 1
        context_start = max(0, line_idx - 1)
        context_end = min(len(parsed.lines), line_idx + 2)
        snippet = "\n".join(parsed.lines[context_start:context_end]).strip()

        counter += 1
        findings.append(Finding(
            id=f"{rule.id}-{counter}",
            category=rule.category,
            severity=rule.severity,
            cwe=rule.cwe,
            language=parsed.language,
            file_path=parsed.path,
            line_number=line_no,
            code_snippet=snippet,
            description=f"{rule.description_template}: llamada a `{func_name}()`",
            remediation=rule.remediation,
            confidence="low",
        ))

    return findings


def run_scan(file_paths: list[str], rules_dir: Optional[str] = None) -> list[Finding]:
    rules = load_rules(rules_dir)
    all_findings: list[Finding] = []

    from src.discovery import language_from_extension

    for file_path in file_paths:
        language = language_from_extension(file_path)
        if language is None:
            continue
        file_findings = analyze_file(file_path, language, rules)
        all_findings.extend(file_findings)

    counter = 0
    for f in all_findings:
        counter += 1
        f.id = f"{f.category[:4].upper()}-{counter:04d}"

    return all_findings
